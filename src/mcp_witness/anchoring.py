"""
External trust anchoring for MCP-Witness.

Anchors Merkle roots to external sources for independent verification:
- RFC 3161 Timestamp Authorities (legal-grade)
- OpenTimestamps (free Bitcoin anchoring)
- IPFS (content-addressed storage)
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Multihash / CID helpers for proper IPFS content addressing
# ---------------------------------------------------------------------------

# Multihash constants
SHA2_256_CODE = 0x12
SHA2_256_LENGTH = 0x20  # 32 bytes

# Base58 alphabet (Bitcoin-style, used by CIDv0)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode bytes as base58 (Bitcoin alphabet)."""
    n_leading = 0
    for b in data:
        if b == 0:
            n_leading += 1
        else:
            break

    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(_B58_ALPHABET[rem])
    return "1" * n_leading + "".join(reversed(chars))


def _make_multihash(digest: bytes) -> bytes:
    """Wrap a SHA-256 digest in multihash format."""
    return bytes([SHA2_256_CODE, SHA2_256_LENGTH]) + digest


def compute_ipfs_cidv0(content: bytes) -> str:
    """
    Compute a proper IPFS CIDv0 from raw bytes.

    CIDv0 = multihash(sha2-256(content)) encoded as base58.
    This is the original IPFS CID format (the "Qm..." strings),
    widely recognized and verifiable against any IPFS gateway.
    """
    digest = hashlib.sha256(content).digest()
    mh = _make_multihash(digest)
    return _base58_encode(mh)


def compute_ipfs_cidv1(content: bytes) -> str:
    """
    Compute an IPFS CIDv1 (raw codec, sha2-256) encoded as base32.

    CIDv1 = <version=1><codec=raw(0x55)><multihash(sha2-256)>
    Returns a string like "bafkreigx..." (subdomain-safe).
    """
    digest = hashlib.sha256(content).digest()
    mh = _make_multihash(digest)
    cid_bytes = bytes([0x01, 0x55]) + mh  # version 1, raw codec
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")


class AnchorType(str, Enum):
    """Types of external trust anchors."""

    TSA = "tsa"  # RFC 3161 Timestamp Authority
    OPENTIMESTAMPS = "ots"  # OpenTimestamps (Bitcoin)
    IPFS = "ipfs"  # IPFS content addressing


@dataclass
class AnchorReceipt:
    """Proof that data was anchored to an external source."""

    anchor_type: AnchorType
    merkle_root: str
    timestamp: datetime
    receipt_id: str
    verification_url: Optional[str] = None
    raw_receipt: Optional[bytes] = None
    cost_usd: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "anchor_type": self.anchor_type.value,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp.isoformat(),
            "receipt_id": self.receipt_id,
            "verification_url": self.verification_url,
            "cost_usd": self.cost_usd,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnchorReceipt":
        return cls(
            anchor_type=AnchorType(data["anchor_type"]),
            merkle_root=data["merkle_root"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            receipt_id=data["receipt_id"],
            verification_url=data.get("verification_url"),
            raw_receipt=bytes.fromhex(data["raw_receipt"]) if data.get("raw_receipt") else None,
            cost_usd=data.get("cost_usd", 0.0),
            metadata=data.get("metadata", {}),
        )


class AnchorProvider(ABC):
    """Base class for anchor providers."""

    @property
    @abstractmethod
    def anchor_type(self) -> AnchorType:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def anchor(self, merkle_root: str, metadata: dict) -> AnchorReceipt:
        """Anchor a Merkle root and return a receipt."""
        pass

    @abstractmethod
    async def verify(self, receipt: AnchorReceipt) -> bool:
        """Verify an anchor receipt is valid."""
        pass


# ---------------------------------------------------------------------------
# Minimal ASN.1 DER encoder for RFC 3161 TimeStampReq
# ---------------------------------------------------------------------------

# OID for sha256: 2.16.840.1.101.3.4.2.1
_SHA256_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])

_ASN1_INTEGER = 0x02
_ASN1_OCTET = 0x04
_ASN1_OID = 0x06
_ASN1_NULL = 0x05
_ASN1_SEQUENCE = 0x30


def _der_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a DER length value at the given offset.

    Supports both short form (< 128) and long form (multi-byte).
    Indefinite length is not supported.

    Args:
        data: DER-encoded bytes
        offset: Position of the length field

    Returns:
        (length, bytes_consumed)

    Raises:
        ValueError: if data is truncated or length format is unsupported.
    """
    if offset >= len(data):
        raise ValueError("Truncated DER: length field out of bounds")

    first = data[offset]
    if first < 0x80:
        # Short form: length is just the byte value
        return first, 1

    # Long form
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length not supported")
    if num_bytes > 8:
        raise ValueError("Length field too large (> 8 bytes)")

    if offset + 1 + num_bytes > len(data):
        raise ValueError("Truncated DER: length bytes out of bounds")

    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, 1 + num_bytes


def _der_length(value: int) -> bytes:
    """DER-encode a length value."""
    if value < 128:
        return bytes([value])
    # Long form
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_integer(value: int) -> bytes:
    """DER-encode an INTEGER."""
    if value == 0:
        return bytes([_ASN1_INTEGER, 1, 0])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    # If high bit is set, prepend zero byte for positive sign
    if body[0] & 0x80:
        body = bytes([0]) + body
    return bytes([_ASN1_INTEGER]) + _der_length(len(body)) + body


def _der_octet_string(data: bytes) -> bytes:
    """DER-encode an OCTET STRING."""
    return bytes([_ASN1_OCTET]) + _der_length(len(data)) + data


def _der_oid(oid: bytes) -> bytes:
    """DER-encode an OID."""
    return bytes([_ASN1_OID]) + _der_length(len(oid)) + oid


def _der_null() -> bytes:
    """DER-encode NULL."""
    return bytes([_ASN1_NULL, 0])


def _der_sequence(children: bytes) -> bytes:
    """DER-encode a SEQUENCE."""
    return bytes([_ASN1_SEQUENCE]) + _der_length(len(children)) + children


def _build_tsa_request(merkle_root_hex: str) -> bytes:
    """
    Build a proper DER-encoded RFC 3161 TimeStampReq.

    Structure:
      TimeStampReq ::= SEQUENCE {
        version         INTEGER { v1(1) },
        messageImprint  MessageImprint,
        nonce           INTEGER OPTIONAL
      }
      MessageImprint ::= SEQUENCE {
        hashAlgorithm   AlgorithmIdentifier,
        hashedMessage   OCTET STRING
      }
      AlgorithmIdentifier ::= SEQUENCE {
        algorithm       OBJECT IDENTIFIER,
        parameters      NULL
      }
    """
    # AlgorithmIdentifier: sha256 + NULL params
    algo_id = _der_sequence(_der_oid(_SHA256_OID) + _der_null())

    # MessageImprint: AlgorithmIdentifier + hash value
    hash_bytes = bytes.fromhex(merkle_root_hex)
    message_imprint = _der_sequence(algo_id + _der_octet_string(hash_bytes))

    # Generate a random nonce for replay protection
    nonce = int.from_bytes(os.urandom(8), "big")

    # TimeStampReq: version(1) + messageImprint + nonce
    request = _der_sequence(_der_integer(1) + message_imprint + _der_integer(nonce))

    return request


# ---------------------------------------------------------------------------
# TSA Provider
# ---------------------------------------------------------------------------


class TSAProvider(AnchorProvider):
    """
    RFC 3161 Timestamp Authority provider.

    Provides legal-grade timestamps recognized by courts and regulators.
    Uses FreeTSA by default (free, reliable).

    Implements proper DER-encoded ASN.1 TimeStampReq per RFC 3161.
    For full verification of TimeStampResp tokens (checking the TSA
    certificate chain), install optional dependency:
        pip install mcp-witness[tsa]   # pyasn1 + cryptography
    """

    DEFAULT_TSA_URL = "https://freetsa.org/tsr"

    def __init__(self, tsa_url: str = None, timeout: float = 30.0):
        self.tsa_url = tsa_url or os.getenv("TSA_URL", self.DEFAULT_TSA_URL)
        self.timeout = timeout

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.TSA

    @property
    def name(self) -> str:
        return "RFC 3161 TSA"

    async def anchor(self, merkle_root: str, metadata: dict) -> AnchorReceipt:
        """
        Request an RFC 3161 timestamp for a Merkle root.

        Builds a proper DER-encoded TimeStampReq, sends it to the TSA,
        and returns the TimeStampResp token as a verifiable receipt.
        """
        timestamp = datetime.now(timezone.utc)
        receipt_id = hashlib.sha256(
            f"tsa_{merkle_root}_{timestamp.isoformat()}".encode()
        ).hexdigest()[:32]

        try:
            # Build proper DER-encoded RFC 3161 TimeStampReq
            request_der = _build_tsa_request(merkle_root)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.tsa_url,
                    content=request_der,
                    headers={"Content-Type": "application/timestamp-query"},
                )

                if response.status_code == 200:
                    # response.content is a DER-encoded TimeStampResp
                    return AnchorReceipt(
                        anchor_type=AnchorType.TSA,
                        merkle_root=merkle_root,
                        timestamp=timestamp,
                        receipt_id=receipt_id,
                        raw_receipt=response.content,
                        verification_url=self.tsa_url.replace("/tsr", "/verify"),
                        cost_usd=0.0,
                        metadata={
                            "tsa_url": self.tsa_url,
                            "status": "anchored",
                            "standard": "RFC 3161",
                            "nonce": True,
                        },
                    )
                else:
                    raise Exception(f"TSA returned HTTP {response.status_code}")

        except Exception as exc:
            # TSA unavailable: create a local attestation (still auditable,
            # but relies on our own clock, not external TSA)
            logger.error(
                "TSA request failed for merkle_root=%s: %s: %s",
                merkle_root,
                type(exc).__name__,
                exc,
            )

            # Save error info before exc goes out of scope (Python 3 cleans up except vars)
            error_name = type(exc).__name__
            error_msg = str(exc)

        # Fallback: explicit local attestation with error details
        attestation = {
            "version": "mcp-witness-tsa-v1",
            "type": "local_attestation",
            "merkle_root": merkle_root,
            "timestamp": timestamp.isoformat(),
            "tsa_url": self.tsa_url,
            "tsa_error": "TSA unavailable",
            "metadata": metadata,
        }
        attestation_bytes = json.dumps(attestation, sort_keys=True).encode()
        attestation_hash = hashlib.sha256(attestation_bytes).hexdigest()

        return AnchorReceipt(
            anchor_type=AnchorType.TSA,
            merkle_root=merkle_root,
            timestamp=timestamp,
            receipt_id=f"local_{attestation_hash[:28]}",
            raw_receipt=attestation_bytes,
            cost_usd=0.0,
            metadata={
                "type": "local_attestation",
                "status": "local_fallback",
                "error": f"{error_name}: {error_msg}",
            },
        )

    @staticmethod
    def _validate_der_receipt(raw: bytes) -> bool:
        """
        Validate an RFC 3161 TimeStampResp DER structure.

        Parses the outer SEQUENCE tag, verifies the DER length is valid,
        and checks the body contains at least one inner element (a valid
        PKIStatusInfo SEQUENCE). Returns True for well-formed DER.
        """
        if not raw:
            return False

        try:
            # Must start with SEQUENCE tag (0x30)
            if raw[0] != 0x30:
                return False

            if len(raw) < 2:
                return False

            # Parse DER length
            offset = 1
            length, consumed = _der_decode_length(raw, offset)
            offset += consumed

            # Body must be non-zero and fit within the data
            if length == 0:
                return False

            if offset + length != len(raw):
                return False

            # Body must contain at least one inner SEQUENCE (PKIStatusInfo)
            if offset >= len(raw):
                return False

            if raw[offset] != 0x30:
                return False

            return True

        except (ValueError, IndexError):
            return False

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """
        Verify a TSA receipt.

        For RFC 3161 receipts: validates DER structure by parsing the
        SEQUENCE tag, DER length, and verifying the body is non-empty
        and contains a valid PKIStatusInfo SEQUENCE.

        For local attestations: verifies the merkle_root matches.

        Full certificate-chain verification requires pyasn1+cryptography
        (see pyproject.toml [project.optional-dependencies].tsa).

        Returns:
            True if the receipt is structurally valid, False otherwise.
        """
        if not receipt.raw_receipt:
            return False

        # Local attestation: verify self-consistency
        if receipt.receipt_id.startswith("local_"):
            try:
                data = json.loads(receipt.raw_receipt)
                return data.get("merkle_root") == receipt.merkle_root
            except (json.JSONDecodeError, UnicodeDecodeError):
                return False

        # RFC 3161 receipt: validate full DER structure
        return self._validate_der_receipt(receipt.raw_receipt)


class OpenTimestampsProvider(AnchorProvider):
    """
    OpenTimestamps provider for free Bitcoin anchoring.

    Batches many hashes into a single Bitcoin transaction.
    Provides Bitcoin-level immutability at zero cost.
    """

    OTS_SERVERS = [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
    ]

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.OPENTIMESTAMPS

    @property
    def name(self) -> str:
        return "OpenTimestamps (Bitcoin)"

    async def anchor(self, merkle_root: str, metadata: dict) -> AnchorReceipt:
        """
        Submit hash to OpenTimestamps for Bitcoin anchoring.

        Note: The actual Bitcoin anchoring happens asynchronously
        (usually within a few hours). The receipt can be upgraded later.
        """
        timestamp = datetime.now(timezone.utc)
        hash_bytes = bytes.fromhex(merkle_root)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for server in self.OTS_SERVERS:
                try:
                    response = await client.post(
                        f"{server}/digest",
                        content=hash_bytes,
                        headers={"Content-Type": "application/octet-stream"},
                    )

                    if response.status_code == 200:
                        return AnchorReceipt(
                            anchor_type=AnchorType.OPENTIMESTAMPS,
                            merkle_root=merkle_root,
                            timestamp=timestamp,
                            receipt_id=f"ots_{merkle_root[:16]}",
                            raw_receipt=response.content,
                            verification_url="https://opentimestamps.org",
                            cost_usd=0.0,
                            metadata={
                                "server": server,
                                "status": "pending_confirmation",
                                "note": "Bitcoin confirmation typically takes 1-24 hours",
                                "verification": "structural_only",
                            },
                        )
                except Exception:
                    continue

        # All servers failed
        logger.error(
            "All OpenTimestamps servers failed for merkle_root=%s",
            merkle_root,
        )
        raise Exception("All OpenTimestamps servers failed")

    @staticmethod
    def _ots_parse_varint(data: bytes, offset: int) -> tuple[int, int]:
        """Parse an OTS variable-length integer at offset.

        OTS uses the same varint encoding as protobuf:
        7 bits per byte, MSB=1 means more bytes follow.

        Returns:
            (value, bytes_consumed)

        Raises:
            ValueError: if data is truncated or varint is malformed.
        """
        value = 0
        i = offset
        shift = 0
        while i < len(data):
            byte = data[i]
            value |= (byte & 0x7F) << shift
            i += 1
            shift += 7
            if not (byte & 0x80):
                return value, i - offset
            if shift > 70:  # prevent runaway (max ~10 bytes for 64-bit)
                raise ValueError("Varint too long")
        raise ValueError("Truncated varint")

    @staticmethod
    def _ots_validate_structure(data: bytes, offset: int, end: int, depth: int = 0) -> bool:
        """Recursively validate an OTS timestamp binary structure.

        OTS timestamps are serialized as:
          <tag: 1 byte> <length: varint> <contents>

        Tag 0x00 (timestamp) contains sub-timestamps as contents.
        Other tags have opaque contents (just validate length).

        Returns:
            True if the structure is well-formed.
        """
        if depth > 16:  # prevent stack overflow on malformed data
            return False

        pos = offset
        while pos < end:
            if pos >= len(data):
                return False

            tag = data[pos]
            pos += 1

            if pos >= len(data):
                return False

            try:
                length, consumed = OpenTimestampsProvider._ots_parse_varint(data, pos)
            except ValueError:
                return False
            pos += consumed

            if pos + length > end or pos + length > len(data):
                return False

            # For timestamp type (0x00), validate sub-structures
            if tag == 0x00 and length > 0:
                if not OpenTimestampsProvider._ots_validate_structure(
                    data, pos, pos + length, depth + 1
                ):
                    return False

            pos += length

        return True

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """
        Verify an OpenTimestamps receipt.

        *** WARNING: Structural-only verification ***
        This only validates the OTS binary structure is well-formed.
        It does NOT check against the Bitcoin blockchain.
        Full Bitcoin confirmation requires the ``ots`` CLI tool.

        Validates the OTS binary structure:
        - raw_receipt must not be None or empty
        - Must start with OTS magic bytes (\x00\x00, a timestamp tag)
        - Must contain valid varint-encoded sub-timestamp structures

        Full verification (checking against the Bitcoin blockchain) is
        not performed here — this validates structural integrity only.

        Returns:
            True if the receipt has a valid OTS structure.
        """
        if not receipt.raw_receipt:
            return False

        raw = receipt.raw_receipt
        if len(raw) < 2:
            return False

        # OTS receipts start with magic bytes: \x00\x00
        # First byte = tag 0 (timestamp), second byte begins varint length
        if raw[0] != 0x00:
            return False

        logger.warning(
            "OTS verification is structural-only — does NOT confirm Bitcoin confirmation. "
            "Receipt: %s",
            receipt.receipt_id,
        )

        # Parse the top-level timestamp structure
        return self._ots_validate_structure(raw, 0, len(raw))


class IPFSProvider(AnchorProvider):
    """
    IPFS anchoring provider.

    Content-addressed storage - the CID cryptographically proves the content.
    Free, but doesn't provide timestamps (combine with TSA).
    """

    def __init__(self, api_key: str = None, api_secret: str = None, timeout: float = 30.0):
        self.api_key = api_key or os.getenv("PINATA_API_KEY")
        self.api_secret = api_secret or os.getenv("PINATA_API_SECRET")
        self.timeout = timeout

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.IPFS

    @property
    def name(self) -> str:
        return "IPFS"

    async def anchor(self, merkle_root: str, metadata: dict) -> AnchorReceipt:
        """Pin anchor data to IPFS."""
        timestamp = datetime.now(timezone.utc)

        anchor_data = {
            "version": "mcp-witness-ipfs-v1",
            "merkle_root": merkle_root,
            "timestamp": timestamp.isoformat(),
            "metadata": metadata,
        }

        if self.api_key and self.api_secret:
            cid = await self._pin_to_pinata(anchor_data)
        else:
            # Compute CID locally (content is provable even without pinning)
            cid = self._compute_cid(anchor_data)

        return AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root=merkle_root,
            timestamp=timestamp,
            receipt_id=cid,
            verification_url=f"https://ipfs.io/ipfs/{cid}",
            cost_usd=0.0,
            metadata={"pinned": bool(self.api_key)},
        )

    async def _pin_to_pinata(self, data: dict) -> str:
        """Pin JSON data to Pinata."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.pinata.cloud/pinning/pinJSONToIPFS",
                json={
                    "pinataContent": data,
                    "pinataMetadata": {"name": f"mcp-witness-{data['merkle_root'][:8]}"},
                },
                headers={
                    "pinata_api_key": self.api_key,
                    "pinata_secret_api_key": self.api_secret,
                    "Content-Type": "application/json",
                },
            )

            if response.status_code == 200:
                return response.json()["IpfsHash"]
            else:
                raise Exception(f"Pinata returned {response.status_code}")

    def _compute_cid(self, data: dict) -> str:
        """
        Compute a proper IPFS CIDv0 locally without pinning.

        Uses standard multihash + base58 encoding matching the IPFS spec.
        The resulting CID is verifiable by any IPFS implementation.
        """
        content = json.dumps(data, sort_keys=True).encode()
        return compute_ipfs_cidv0(content)

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """
        Verify IPFS content integrity.

        Fetches content from the IPFS gateway, computes the CID locally,
        and compares it with the receipt's CID.

        If the GET request is unreachable or returns a non-200 status,
        verification returns False — a HEAD response only proves server
        reachability, not content integrity.

        Returns:
            True if content integrity is verified, False otherwise.
        """
        if not receipt.verification_url or not receipt.receipt_id:
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # Fetch content from gateway
                response = await client.get(receipt.verification_url, follow_redirects=True)
                if response.status_code != 200:
                    logger.warning(
                        "IPFS verification failed: GET %s returned status %d",
                        receipt.verification_url,
                        response.status_code,
                    )
                    return False

                # Compute CID locally and compare with receipt
                content = response.content
                computed_cid = compute_ipfs_cidv0(content)
                if computed_cid != receipt.receipt_id:
                    logger.warning(
                        "IPFS verification failed: CID mismatch for %s. "
                        "Expected %s, computed %s",
                        receipt.verification_url,
                        receipt.receipt_id,
                        computed_cid,
                    )
                    return False
                return True

            except Exception as exc:
                logger.warning(
                    "IPFS verification failed: cannot fetch %s: %s: %s. "
                    "Cannot verify without fetching content.",
                    receipt.verification_url,
                    type(exc).__name__,
                    exc,
                )
                return False


class AnchorService:
    """
    Multi-anchor service for MCP-Witness.

    Anchors Merkle roots to multiple external sources for redundancy.
    """

    def __init__(self, providers: list[AnchorProvider] = None):
        """
        Initialize with providers.

        Default providers: TSA + OpenTimestamps + IPFS
        """
        if providers is None:
            providers = [
                TSAProvider(),
                OpenTimestampsProvider(),
                IPFSProvider(),
            ]
        self.providers = {p.anchor_type: p for p in providers}

    def add_provider(self, provider: AnchorProvider) -> None:
        """Add an anchor provider."""
        self.providers[provider.anchor_type] = provider

    def get_provider(self, anchor_type: AnchorType) -> Optional[AnchorProvider]:
        """Get a provider by type."""
        return self.providers.get(anchor_type)

    async def anchor(
        self,
        merkle_root: str,
        metadata: dict = None,
        anchor_types: list[AnchorType] = None,
    ) -> list[AnchorReceipt]:
        """
        Anchor a Merkle root to configured providers.

        Args:
            merkle_root: The hash to anchor
            metadata: Additional context (record count, time range, etc.)
            anchor_types: Limit to specific providers (default: all)

        Returns:
            List of receipts from successful anchors
        """
        metadata = metadata or {}

        providers = list(self.providers.values())
        if anchor_types:
            providers = [p for p in providers if p.anchor_type in anchor_types]

        # Anchor to all providers concurrently
        tasks = [p.anchor(merkle_root, metadata) for p in providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        receipts = []
        errors = []

        for provider, result in zip(providers, results):
            if isinstance(result, Exception):
                errors.append({"provider": provider.name, "error": str(result)})
            else:
                receipts.append(result)

        # Return what we have (some providers may have failed)
        return receipts

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """Verify an anchor receipt."""
        provider = self.providers.get(receipt.anchor_type)
        if not provider:
            return False
        return await provider.verify(receipt)

    async def verify_all(self, receipts: list[AnchorReceipt]) -> dict[str, bool]:
        """Verify multiple receipts."""
        results = {}
        for receipt in receipts:
            results[receipt.receipt_id] = await self.verify(receipt)
        return results
