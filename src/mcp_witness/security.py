"""
Security utilities for mcp-witness.

Provides:
- HMAC key management for hash chain protection
- Database-backed rate limiting (token bucket)
- Database-backed idempotency (nonce store)
- Error sanitization to prevent stack trace leakage
- Path traversal protection for exports
- Payload input validation
"""

import base64
import hashlib
import logging
import os
import re
import warnings
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import Sensitivity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Anchor Strict Mode
# ---------------------------------------------------------------------------

ANCHOR_STRICT_MODE = os.getenv("MCP_WITNESS_ANCHOR_STRICT", "true").lower() == "true"


def is_anchor_strict_mode() -> bool:
    """Check if anchoring strict mode is enabled.

    When strict mode is ON (default), any provider failure in
    AnchorService.anchor() raises AnchorFailureError.
    When OFF, partial results are returned.

    Configure via ``MCP_WITNESS_ANCHOR_STRICT=false`` for degraded operation.
    """
    return ANCHOR_STRICT_MODE


# ---------------------------------------------------------------------------
# Envelope Encryption for Sensitive Fields (AES-256-GCM)
# ---------------------------------------------------------------------------

_DEK: Optional[bytes] = None


def get_data_encryption_key() -> bytes:
    """Get or generate the data encryption key for AES-256-GCM.

    Reads from ``MCP_WITNESS_DEK`` env var (32 bytes hex-encoded).
    If not set, generates a random key (ephemeral per process).
    """
    global _DEK
    if _DEK is not None:
        return _DEK
    key_hex = os.getenv("MCP_WITNESS_DEK")
    if key_hex:
        _DEK = bytes.fromhex(key_hex)
        if len(_DEK) != 32:
            raise ValueError("MCP_WITNESS_DEK must be 32 bytes (64 hex chars)")
    else:
        _DEK = AESGCM.generate_key(bit_length=256)
        logger.warning(
            "MCP_WITNESS_DEK not set — using EPHEMERAL encryption key. "
            "Sensitive fields encrypted this session CANNOT be decrypted after restart. "
            "Set MCP_WITNESS_DEK to a persistent 32-byte hex key (openssl rand -hex 32) "
            "for durable field-level encryption."
        )
    return _DEK


def encrypt_field(plaintext: str) -> str:
    """Encrypt a sensitive string field with AES-256-GCM.

    Returns base64(nonce || ciphertext).
    """
    if not plaintext:
        return plaintext
    key = get_data_encryption_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_field(encrypted: str) -> str:
    """Decrypt a field encrypted with encrypt_field().

    Returns the original plaintext. If decryption fails (tampered data,
    different key, or plaintext that was never encrypted), returns the
    input as-is for backward compatibility with unencrypted records.
    """
    if not encrypted:
        return encrypted
    try:
        key = get_data_encryption_key()
        raw = base64.b64decode(encrypted)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception as exc:
        logger.warning("decrypt_field failure: %s", exc)
        return encrypted


_SENSITIVE_FIELD_PATTERNS = {
    "email",
    "phone",
    "ssn",
    "dob",
    "address",
    "name",
    "creditcard",
    "bankaccount",
    "medicalrecord",
    "patientid",
    "apikey",
    "password",
    "secret",
    "token",
}


def should_encrypt_field(field_name: str, sensitivity_level: Sensitivity) -> bool:
    """Check if a field should be encrypted based on sensitivity and name.

    All fields for PII/PHI/CONFIDENTIAL sensitivity levels are encrypted.
    For lower levels, only known sensitive field names are encrypted.
    Field name comparison is case-insensitive and ignores underscores.
    """
    if sensitivity_level in (Sensitivity.PII, Sensitivity.PHI, Sensitivity.CONFIDENTIAL):
        return True
    field_lower = field_name.lower().replace("_", "")
    return any(s in field_lower for s in _SENSITIVE_FIELD_PATTERNS)


# ---------------------------------------------------------------------------
# HMAC Key for Hash Chain Protection
# ---------------------------------------------------------------------------

# HMAC key state: ``None`` = no key (plain SHA-256 mode), sentinel = uninitialised
_HMAC_KEY_UNSET = object()
_hmac_key: object = _HMAC_KEY_UNSET


def get_hmac_key() -> Optional[bytes]:
    """Get the HMAC key for hash chain protection.

    Reads from the ``MCP_WITNESS_HMAC_KEY`` environment variable.
    When set, the value must be a hex-encoded 32-byte (64 hex char) key.
    When NOT set, returns ``None`` for backward-compatible plain SHA-256 mode.

    The key is resolved ONCE per process lifetime (module-level lazy singleton).

    Returns:
        The HMAC key bytes, or ``None`` if no key is configured.
    """
    global _hmac_key
    if _hmac_key is not _HMAC_KEY_UNSET:
        return _hmac_key  # type: ignore[return-value]

    env_key = os.getenv("MCP_WITNESS_HMAC_KEY", "").strip()
    if env_key:
        _hmac_key = bytes.fromhex(env_key)
        if len(_hmac_key) != 32:
            raise ValueError(
                f"MCP_WITNESS_HMAC_KEY must be 32 bytes hex-encoded, got {len(_hmac_key)} bytes"
            )
    else:
        _hmac_key = None

    return _hmac_key


# ---------------------------------------------------------------------------
# Rate Limiting — DB-backed token bucket
# ---------------------------------------------------------------------------

MAX_RECORDS_PER_SECOND = int(
    os.getenv(
        "MCP_WITNESS_RATE_LIMIT",
        "1000",
    )
)

MAX_RECORDS_PER_MINUTE = MAX_RECORDS_PER_SECOND * 60


async def check_rate_limit(
    storage: object,
    bucket_id: str = "default",
    max_tokens: float = 1000.0,
    refill_rate: float = 1000.0,
) -> None:
    """Check and consume a rate limit token.

    Uses the storage backend's token bucket implementation.
    Raises ValueError if rate limit exceeded.

    Args:
        storage: StorageBackend instance to perform the check.
        bucket_id: Token bucket identifier (typically the actor_id).
        max_tokens: Maximum tokens the bucket can hold.
        refill_rate: Tokens added per second.
    """
    allowed = await storage.check_rate_limit(  # type: ignore[attr-defined]
        bucket_id=bucket_id,
        max_tokens=max_tokens,
        refill_rate=refill_rate,
    )
    if not allowed:
        raise ValueError(
            f"Rate limit exceeded ({max_tokens:.0f}/s) for bucket '{bucket_id}'. "
            f"Configure MCP_WITNESS_RATE_LIMIT to adjust."
        )


# ---------------------------------------------------------------------------
# RBAC (Role-Based Access Control)
# ---------------------------------------------------------------------------

# NOTE: RBAC has moved to src/mcp_witness/auth.py.
# The deprecated READ_ONLY_MODE is now handled there.
# This module retains only the import compatibility shim.


def enforce_read_only(tool_name: str) -> None:
    """DEPRECATED. Use auth.authenticate() + auth.authorize() instead.

    Raises a deprecation warning and delegates to the new auth module.
    """
    warnings.warn(
        "enforce_read_only() is deprecated. Use auth.authenticate() and "
        "auth.authorize() from mcp_witness.auth instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    from .auth import authenticate, authorize

    role = authenticate()
    authorize(role, tool_name)


# ---------------------------------------------------------------------------
# Ed25519 Signing Key — Non-Repudiation
# ---------------------------------------------------------------------------

_SIGNING_KEY_UNSET = object()
_signing_key: object = _SIGNING_KEY_UNSET
_public_key_bytes: object = _SIGNING_KEY_UNSET
_signing_key_id: Optional[str] = None


def get_signing_key() -> Optional[object]:
    """Get the Ed25519 signing key for record non-repudiation.

    Reads from the ``MCP_WITNESS_SIGNING_KEY`` environment variable.
    When set, the value must be a hex-encoded 32-byte (64 hex char) seed
    for Ed25519 key generation.
    When NOT set, returns ``None`` — signing is disabled and records are
    created without signatures (backward-compatible mode).

    If the key is not set on first call, a new keypair is generated and
    cached for the process lifetime. The public key is logged at startup
    so operators can capture it for external verification.

    When a trust store is configured (MCP_WITNESS_TRUST_STORE), the key_id
    from the trust store's current key is used.

    The key is resolved ONCE per process lifetime (module-level lazy singleton).

    Returns:
        The Ed25519 private key, or ``None`` if no signing key is configured
        and auto-generation is disabled.
    """
    global _signing_key, _public_key_bytes, _signing_key_id
    if _signing_key is not _SIGNING_KEY_UNSET:
        return _signing_key

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    env_key = os.getenv("MCP_WITNESS_SIGNING_KEY", "").strip()
    if env_key:
        seed = bytes.fromhex(env_key)
        if len(seed) != 32:
            raise ValueError(
                f"MCP_WITNESS_SIGNING_KEY must be 32 bytes hex-encoded, got {len(seed)} bytes"
            )
        _signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    else:
        # Auto-generate a random keypair for the process lifetime.
        # WARNING: This means EVERY PROCESS RESTART uses a DIFFERENT key.
        # Records signed in one session CANNOT be verified in another.
        # No persistent identity = NO NON-REPUDIATION.
        # Set MCP_WITNESS_SIGNING_KEY for deterministic signing.
        _signing_key = ed25519.Ed25519PrivateKey.generate()
        logger.warning(
            "MCP_WITNESS_SIGNING_KEY not set — using EPHEMERAL keypair. "
            "Non-repudiation is NOT provided. Records signed this session "
            "cannot be verified after restart. "
            "Set MCP_WITNESS_SIGNING_KEY to a persistent 32-byte hex key "
            "for deterministic signing with non-repudiation."
        )

    # Extract public key bytes
    _public_key_bytes = _signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    logger.info(
        "Ed25519 public key: %s",
        _public_key_bytes.hex(),
    )

    # If trust store is configured, try to resolve key_id from current key
    try:
        from .key_lifecycle import get_trust_store

        trust_store = get_trust_store()
        current_key_id = trust_store.get_current_key_id()
        if current_key_id:
            # Verify our actual public key matches the trust store entry
            key_meta = trust_store.get_key(current_key_id)
            if key_meta and key_meta.public_key_hex == _public_key_bytes.hex():
                _signing_key_id = current_key_id
            else:
                logger.warning(
                    "Current signing key doesn't match trust store key '%s' — "
                    "will not assign key_id",
                    current_key_id,
                )
    except Exception:
        pass  # nosec B110 — key resolution failure is non-fatal; signing degrades gracefully

    return _signing_key


def get_signing_key_id() -> Optional[str]:
    """Get the key_id for the active signing key, if known.

    Returns:
        The key ID string, or ``None`` if not configured or no trust store.
    """
    global _signing_key_id
    if _signing_key is _SIGNING_KEY_UNSET:
        # Trigger lazy load
        get_signing_key()
    return _signing_key_id


def get_public_key_bytes() -> Optional[bytes]:
    """Get the Ed25519 public key bytes for external verification.

    Returns the public key derived from the configured signing key, or
    ``None`` if signing is disabled.

    Returns:
        Raw public key bytes (32 bytes), or ``None`` if signing is disabled.
    """
    if _public_key_bytes is _SIGNING_KEY_UNSET:
        # Trigger lazy loading
        get_signing_key()
    return _public_key_bytes  # type: ignore[return-value]


def get_public_key_hex() -> Optional[str]:
    """Get the Ed25519 public key as a hex string.

    Returns:
        Hex-encoded public key, or ``None`` if signing is disabled.
    """
    pk_bytes = get_public_key_bytes()
    return pk_bytes.hex() if pk_bytes else None


# ---------------------------------------------------------------------------
# Error Sanitization
# ---------------------------------------------------------------------------


def sanitize_error(exc: Exception) -> dict:
    """
    Convert an exception to a safe error dict.

    NEVER leaks stack traces, file paths, or SQL details to the client.
    """
    # Known safe exceptions - include their message
    safe_types = (ValueError, PermissionError, FileNotFoundError)

    if isinstance(exc, safe_types):
        return {
            "error": str(exc),
            "type": type(exc).__name__,
        }

    # Everything else: generic message, log the real error server-side
    logger.error("Internal error: %s", exc, exc_info=True)
    return {
        "error": "Internal server error. Check server logs for details.",
        "type": "InternalError",
    }


# ---------------------------------------------------------------------------
# Idempotency — DB-backed nonce store
# ---------------------------------------------------------------------------


async def check_idempotency(
    storage: object,
    nonce_hash: str,
    ttl_seconds: int = 3600,
) -> bool:
    """Check and record an idempotency nonce.

    Uses the storage backend's persistent nonce store.
    Returns True if this is a NEW payload (allow it),
    False if it's a duplicate (reject it).
    """
    return await storage.check_and_record_nonce(  # type: ignore[attr-defined, no-any-return]
        nonce_hash=nonce_hash,
        ttl_seconds=ttl_seconds,
    )


def compute_action_fingerprint(
    action_type: str,
    session_id: str,
    input_hash: str,
    output_hash: str,
    timestamp: str,
) -> str:
    """
    Compute a fingerprint for idempotency checking.

    Uses fields that, if identical within a short window, indicate a replay.
    """
    payload = f"{action_type}|{session_id}|{input_hash}|{output_hash}|{timestamp}"
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Path Traversal Protection
# ---------------------------------------------------------------------------

# Allowed export directory (default: current working directory)
ALLOWED_EXPORT_DIR = Path(os.getenv("MCP_WITNESS_EXPORT_DIR", str(Path.cwd()))).resolve()


def validate_export_path(output_path: str) -> Path:
    """
    Validate and sanitize an export path.

    Prevents path traversal attacks where an attacker could write
    to arbitrary files (e.g., ~/.ssh/authorized_keys).

    Returns a safe, resolved Path object.
    """
    path = Path(output_path).expanduser()

    # Reject paths with null bytes
    if "\x00" in str(path):
        raise ValueError("Path contains null bytes")

    # Resolve symlinks and relative paths
    resolved = path.resolve()

    # Must be within allowed directory
    try:
        resolved.relative_to(ALLOWED_EXPORT_DIR)
    except ValueError:
        raise ValueError(f"Export path must be within {ALLOWED_EXPORT_DIR}. " f"Got: {output_path}")

    # Create parent directories if needed
    resolved.parent.mkdir(parents=True, exist_ok=True)

    return resolved


# ---------------------------------------------------------------------------
# Payload Validation
# ---------------------------------------------------------------------------

SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]*$")
TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]*$")
MAX_SESSION_ID_LENGTH = 256
MAX_ACTOR_ID_LENGTH = 256
MAX_TOOL_NAME_LENGTH = 256
MAX_REASONING_LENGTH = 10000  # 10KB of reasoning text


def validate_inputs(
    session_id: str = "",
    actor_id: str = "unknown",
    reasoning: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> None:
    """
    Validate all user-supplied string inputs.

    Raises ValueError for invalid inputs.
    """
    if session_id and len(session_id) > MAX_SESSION_ID_LENGTH:
        raise ValueError(f"session_id exceeds max length {MAX_SESSION_ID_LENGTH}")
    if session_id and not SESSION_ID_PATTERN.match(session_id):
        raise ValueError("session_id contains invalid characters")

    if actor_id and len(actor_id) > MAX_ACTOR_ID_LENGTH:
        raise ValueError(f"actor_id exceeds max length {MAX_ACTOR_ID_LENGTH}")

    if tool_name is not None:
        if len(tool_name) > MAX_TOOL_NAME_LENGTH:
            raise ValueError(f"tool_name exceeds max length {MAX_TOOL_NAME_LENGTH}")
        if tool_name and not TOOL_NAME_PATTERN.match(tool_name):
            raise ValueError("tool_name contains invalid characters")

    if reasoning and len(reasoning) > MAX_REASONING_LENGTH:
        raise ValueError(f"reasoning exceeds max length {MAX_REASONING_LENGTH}")
