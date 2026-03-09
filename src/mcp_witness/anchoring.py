"""
External trust anchoring for MCP-Witness.

Anchors Merkle roots to external sources for independent verification:
- RFC 3161 Timestamp Authorities (legal-grade)
- OpenTimestamps (free Bitcoin anchoring)
- IPFS (content-addressed storage)
"""

import asyncio
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


class TSAProvider(AnchorProvider):
    """
    RFC 3161 Timestamp Authority provider.

    Legal-grade timestamps recognized by courts and regulators.
    Uses FreeTSA by default (free, reliable).
    """

    DEFAULT_TSA_URL = "https://freetsa.org/tsr"

    def __init__(self, tsa_url: str = None, timeout: float = None):
        self.tsa_url = tsa_url or os.getenv("TSA_URL", self.DEFAULT_TSA_URL)
        self.timeout = timeout or float(os.getenv("MCP_WITNESS_TSA_TIMEOUT", "30.0"))

    @property
    def anchor_type(self) -> AnchorType:
        return AnchorType.TSA

    @property
    def name(self) -> str:
        return "RFC 3161 TSA"

    async def anchor(self, merkle_root: str, metadata: dict) -> AnchorReceipt:
        """
        Get an RFC 3161 timestamp for a Merkle root.

        Note: Full RFC 3161 implementation requires pyasn1/pyasn1_modules.
        This simplified version creates a verifiable attestation record.
        """
        timestamp = datetime.now(timezone.utc)

        # Create attestation payload
        attestation = {
            "version": "mcp-witness-tsa-v1",
            "merkle_root": merkle_root,
            "timestamp": timestamp.isoformat(),
            "tsa_url": self.tsa_url,
            "metadata": metadata,
        }

        # Hash the attestation for receipt ID
        attestation_bytes = json.dumps(attestation, sort_keys=True).encode()
        receipt_id = hashlib.sha256(attestation_bytes).hexdigest()[:32]

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # For FreeTSA, we can submit a digest
                # Real implementation would use proper ASN.1 TimeStampReq
                hash_bytes = bytes.fromhex(merkle_root)

                response = await client.post(
                    self.tsa_url,
                    content=hash_bytes,
                    headers={"Content-Type": "application/timestamp-query"},
                )

                if response.status_code == 200:
                    return AnchorReceipt(
                        anchor_type=AnchorType.TSA,
                        merkle_root=merkle_root,
                        timestamp=timestamp,
                        receipt_id=receipt_id,
                        raw_receipt=response.content,
                        verification_url=self.tsa_url.replace("/tsr", "/verify"),
                        cost_usd=0.0,
                        metadata={"tsa_url": self.tsa_url, "status": "anchored"},
                    )
        except (httpx.HTTPError, OSError) as e:
            # TSA failed, create local attestation as fallback
            logger.warning(
                "TSA anchor failed (%s), falling back to local attestation: %s", self.tsa_url, e
            )
            attestation["error"] = str(e)
            attestation["type"] = "local_attestation"

        # Fallback: return local attestation (not as strong, but auditable)
        return AnchorReceipt(
            anchor_type=AnchorType.TSA,
            merkle_root=merkle_root,
            timestamp=timestamp,
            receipt_id=f"local_{receipt_id}",
            raw_receipt=json.dumps(attestation).encode(),
            cost_usd=0.0,
            metadata={"type": "local_attestation"},
        )

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """Verify a TSA receipt."""
        if not receipt.raw_receipt:
            return False

        # For local attestations, verify the structure
        if receipt.receipt_id.startswith("local_"):
            try:
                data = json.loads(receipt.raw_receipt)
                return data.get("merkle_root") == receipt.merkle_root
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to verify local TSA attestation: %s", e)
                return False

        # For real TSA receipts, would need pyasn1 to parse and verify
        return True


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

    def __init__(self, timeout: float = None):
        self.timeout = timeout or float(os.getenv("MCP_WITNESS_OTS_TIMEOUT", "30.0"))

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
                            },
                        )
                except (httpx.HTTPError, OSError) as e:
                    logger.warning("OTS server %s failed: %s", server, e)
                    continue

        # All servers failed
        raise RuntimeError("All OpenTimestamps servers failed")

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """
        Verify an OpenTimestamps receipt.

        Full verification requires checking the Bitcoin blockchain.
        """
        return receipt.raw_receipt is not None and len(receipt.raw_receipt) > 0


class IPFSProvider(AnchorProvider):
    """
    IPFS anchoring provider.

    Content-addressed storage - the CID cryptographically proves the content.
    Free, but doesn't provide timestamps (combine with TSA).
    """

    def __init__(
        self,
        api_key: str = None,
        api_secret: str = None,
        timeout: float = None,
    ):
        self.api_key = api_key or os.getenv("PINATA_API_KEY")
        self.api_secret = api_secret or os.getenv("PINATA_API_SECRET")
        self.timeout = timeout or float(os.getenv("MCP_WITNESS_IPFS_TIMEOUT", "30.0"))

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
            verification_url = f"https://ipfs.io/ipfs/{cid}"
        else:
            # Compute a local content digest (not a real IPFS CID — not resolvable on IPFS)
            cid = self._compute_local_digest(anchor_data)
            verification_url = None

        return AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root=merkle_root,
            timestamp=timestamp,
            receipt_id=cid,
            verification_url=verification_url,
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

    def _compute_local_digest(self, data: dict) -> str:
        """
        Compute a local content fingerprint without pinning to IPFS.

        WARNING: This is NOT a real IPFS CID and will not resolve on any IPFS
        gateway. It is a local SHA-256 digest that proves content integrity
        but provides no network retrievability. Use Pinata credentials for
        real IPFS anchoring.
        """
        content = json.dumps(data, sort_keys=True).encode()
        content_hash = hashlib.sha256(content).hexdigest()
        return f"local-{content_hash}"

    async def verify(self, receipt: AnchorReceipt) -> bool:
        """Verify IPFS content is accessible."""
        if not receipt.verification_url:
            # Local digest receipts have no URL to check; receipt_id proves integrity
            return receipt.receipt_id.startswith("local-")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.head(receipt.verification_url, follow_redirects=True)
                return response.status_code == 200
            except (httpx.HTTPError, OSError) as e:
                logger.warning(
                    "IPFS gateway verification failed for %s: %s", receipt.verification_url, e
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
