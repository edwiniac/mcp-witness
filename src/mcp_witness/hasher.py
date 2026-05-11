"""Cryptographic hashing and chain integrity for mcp-witness."""

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Optional
from uuid import UUID


def _serialize_value(value: Any) -> str:
    """Serialize a value to a consistent string representation."""
    if value is None:
        return "null"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def hash_data(data: Any) -> str:
    """
    Compute SHA-256 hash of arbitrary data.

    Args:
        data: Any JSON-serializable data

    Returns:
        Hex-encoded SHA-256 hash
    """
    serialized = _serialize_value(data)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_record_hash(
    prev_hash: str,
    sequence: int,
    timestamp: datetime,
    action_type: str,
    actor_id: str,
    input_hash: str,
    output_hash: str,
    tool_name: Optional[str] = None,
    hmac_key: Optional[bytes] = None,
) -> str:
    """
    Compute the hash of a witness record.

    The hash is computed over key fields that establish the chain:
    - Previous hash (chain link)
    - Sequence number (ordering)
    - Timestamp (when)
    - Action type (what kind)
    - Actor ID (who)
    - Input/output hashes (what)
    - Tool name (which tool)

    When an ``hmac_key`` is provided, HMAC-SHA256 is used instead of plain
    SHA-256, making the hash chain depend on a server-side secret. This
    prevents an attacker with DB read access from recomputing valid hashes.

    Args:
        prev_hash: Hash of the previous record in the chain
        sequence: Monotonic sequence number
        timestamp: When the action occurred
        action_type: Type of action (tool_call, decision, etc.)
        actor_id: Identifier of the actor
        input_hash: SHA-256 of input data
        output_hash: SHA-256 of output data
        tool_name: Optional name of the tool called
        hmac_key: Optional HMAC key for server-secret-protected hashing

    Returns:
        Hex-encoded SHA-256 (or HMAC-SHA256) hash of the record
    """
    components = [
        prev_hash,
        str(sequence),
        timestamp.isoformat(),
        action_type,
        actor_id,
        input_hash,
        output_hash,
        tool_name or "",
    ]

    # Join with a delimiter that won't appear in the data
    payload = "|".join(components)

    if hmac_key is not None:
        return hmac.new(hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_record_hash(
    record_hash: str,
    prev_hash: str,
    sequence: int,
    timestamp: datetime,
    action_type: str,
    actor_id: str,
    input_hash: str,
    output_hash: str,
    tool_name: Optional[str] = None,
    hmac_key: Optional[bytes] = None,
) -> bool:
    """
    Verify that a record's hash is correct.

    When an ``hmac_key`` is provided, the hash is verified using
    HMAC-SHA256 with that key; otherwise plain SHA-256 is used.

    Args:
        record_hash: The hash to verify
        hmac_key: Optional HMAC key for server-secret-protected verification
        ... (same as compute_record_hash)

    Returns:
        True if the hash is valid, False otherwise
    """
    expected = compute_record_hash(
        prev_hash=prev_hash,
        sequence=sequence,
        timestamp=timestamp,
        action_type=action_type,
        actor_id=actor_id,
        input_hash=input_hash,
        output_hash=output_hash,
        tool_name=tool_name,
        hmac_key=hmac_key,
    )
    return record_hash == expected


def verify_chain_link(current_hash: str, next_prev_hash: str) -> bool:
    """
    Verify that two adjacent records are properly linked.

    Args:
        current_hash: Hash of the current record
        next_prev_hash: prev_hash field of the next record

    Returns:
        True if the chain link is valid
    """
    return current_hash == next_prev_hash


# Genesis hash for the first record in a chain.
# Uses a deterministic, purpose-bound hash (not all-zeros) so that a
# naturally-occurring zero-hash can never be confused with the chain origin.
GENESIS_HASH = hashlib.sha256(b"MCP_WITNESS_GENESIS_V1").hexdigest()


def is_genesis_record(prev_hash: str) -> bool:
    """Check if a record is the first in the chain."""
    return prev_hash == GENESIS_HASH


def redact_field(data: dict, field_path: str) -> dict:
    """
    Redact a field by replacing its value with a hash.

    Args:
        data: The data dictionary
        field_path: Dot-separated path to the field (e.g., "user.ssn")

    Returns:
        Modified dict with the field redacted
    """
    if not data:
        return data

    result = data.copy()
    parts = field_path.split(".")

    # Navigate to the parent
    current = result
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            if isinstance(current[part], dict):
                current[part] = current[part].copy()
                current = current[part]
            else:
                return result  # Can't navigate further
        else:
            return result  # Path doesn't exist

    # Redact the final field
    final_key = parts[-1]
    if isinstance(current, dict) and final_key in current:
        original_value = current[final_key]
        current[final_key] = f"[REDACTED:sha256:{hash_data(original_value)[:16]}]"

    return result


def redact_fields(data: dict, field_paths: list[str]) -> dict:
    """Redact multiple fields from data."""
    result = data
    for path in field_paths:
        result = redact_field(result, path)
    return result


# ---------------------------------------------------------------------------
# Ed25519 Record Signing — Non-Repudiation
# ---------------------------------------------------------------------------


def sign_record_hash(record_hash: str, signing_key) -> str:
    """Sign a record hash with an Ed25519 signing key.

    The record hash (a hex-encoded SHA-256 digest) is signed to provide
    non-repudiation: the signer cannot later deny having created this
    record. The signature is additive — it does NOT replace the hash
    chain or HMAC protection.

    Args:
        record_hash: Hex-encoded SHA-256 hash of the record.
        signing_key: An ``Ed25519PrivateKey`` instance from
            ``cryptography.hazmat.primitives.asymmetric.ed25519``.

    Returns:
        Hex-encoded Ed25519 signature.

    Raises:
        TypeError: If ``signing_key`` is not an Ed25519 private key.
    """
    data = record_hash.encode("utf-8")
    signature = signing_key.sign(data)
    return signature.hex()


def verify_record_signature(
    record_hash: str,
    signature: str,
    public_key_bytes: bytes,
) -> bool:
    """Verify an Ed25519 signature against a record hash.

    Args:
        record_hash: The hex-encoded SHA-256 hash that was signed.
        signature: Hex-encoded Ed25519 signature to verify.
        public_key_bytes: Raw Ed25519 public key bytes (32 bytes).

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(bytes.fromhex(signature), record_hash.encode("utf-8"))
        return True
    except Exception:
        return False
