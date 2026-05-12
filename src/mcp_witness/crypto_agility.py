"""Cryptographic algorithm identifiers and versioned signature helpers."""

import json
from enum import Enum
from typing import Optional


class SigningAlgorithm(str, Enum):
    """Supported signing algorithms with versioning."""

    ED25519_SHA256_V1 = "ed25519+sha256:v1"
    NONE = "none"  # no signing configured


class HashChainAlgorithm(str, Enum):
    """Supported hash chain algorithms with versioning."""

    SHA256_V1 = "sha256:v1"
    HMAC_SHA256_V1 = "hmac-sha256:v1"


# Current defaults
CURRENT_SIGNING_ALGO = SigningAlgorithm.ED25519_SHA256_V1
CURRENT_HASH_ALGO = HashChainAlgorithm.HMAC_SHA256_V1


def versioned_sign(
    record_hash: str,
    signing_key,
    algo: str,
    key_id: Optional[str] = None,
) -> dict:
    """Sign a record hash with algorithm versioning.

    The record hash (a hex-encoded SHA-256 digest) is signed to provide
    non-repudiation. Returns a versioned signature dict that includes
    the algorithm identifier.

    Args:
        record_hash: Hex-encoded SHA-256 hash of the record.
        signing_key: An ``Ed25519PrivateKey`` instance from
            ``cryptography.hazmat.primitives.asymmetric.ed25519``.
        algo: Algorithm identifier string (e.g. "ed25519+sha256:v1").
        key_id: Optional identifier for the signing key.

    Returns:
        Dict with keys:
        - "algo": algorithm identifier
        - "signature": hex-encoded signature
        - "key_id": key identifier (if provided)

    Raises:
        ValueError: If algo is unsupported.
    """
    if algo == SigningAlgorithm.NONE:
        return {
            "algo": algo,
            "signature": "",
        }

    if algo != SigningAlgorithm.ED25519_SHA256_V1:
        raise ValueError(f"Unsupported signing algorithm: {algo}")

    data = record_hash.encode("utf-8")
    raw_sig = signing_key.sign(data)
    sig_hex = raw_sig.hex()

    result: dict = {
        "algo": algo,
        "signature": sig_hex,
    }
    if key_id is not None:
        result["key_id"] = key_id
    return result


def versioned_verify(
    record_hash: str,
    sig_data: dict,
    public_key_bytes: bytes,
) -> bool:
    """Verify a versioned signature. Handles legacy bare hex signatures.

    If ``sig_data`` is a dict with an ``algo`` key, it's a versioned
    signature. Otherwise it falls back to bare hex signature verification.

    Args:
        record_hash: The hex-encoded SHA-256 hash that was signed.
        sig_data: Dict with ``algo``, ``signature``, and optionally
            ``key_id`` keys, OR a bare hex signature string.
        public_key_bytes: Raw Ed25519 public key bytes (32 bytes).

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # Detect and extract signature hex
    if isinstance(sig_data, dict) and "algo" in sig_data:
        algo = sig_data["algo"]
        sig_hex = sig_data.get("signature", "")

        if algo == SigningAlgorithm.NONE:
            return True  # No signing configured — trivially valid

        if algo != SigningAlgorithm.ED25519_SHA256_V1:
            return False  # Unknown algorithm — reject
    elif isinstance(sig_data, str):
        # Legacy bare hex signature
        sig_hex = sig_data
    else:
        return False

    if not sig_hex:
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(bytes.fromhex(sig_hex), record_hash.encode("utf-8"))
        return True
    except Exception:
        return False


def detect_signature_format(signature_value: str) -> str:
    """Detect if a stored signature is legacy hex or versioned JSON.

    Args:
        signature_value: The stored signature string.

    Returns:
        ``'legacy'`` if the value is a bare hex string (128 hex chars),
        ``'versioned'`` if it starts with ``{`` (JSON dict),
        ``'unknown'`` otherwise.
    """
    if not signature_value:
        return "unknown"

    stripped = signature_value.strip()
    if stripped.startswith("{"):
        return "versioned"

    # Legacy Ed25519: 64 bytes = 128 hex characters
    if len(stripped) == 128 and all(c in "0123456789abcdef" for c in stripped.lower()):
        return "legacy"

    return "unknown"


def _parse_sig_data(signature_value: str) -> dict:
    """Parse signature value to dict if versioned, or legacy format dict."""
    fmt = detect_signature_format(signature_value)
    if fmt == "versioned":
        return json.loads(signature_value)
    if fmt == "legacy":
        return {"algo": "ed25519+sha256:v1", "signature": signature_value.strip()}
    return {"algo": SigningAlgorithm.NONE, "signature": ""}
