"""
Security utilities for mcp-witness.

Provides:
- Rate limiting to prevent audit trail flooding
- Role-based access control (read-only vs read-write modes)
- Error sanitization to prevent stack trace leakage
- Path traversal protection for exports
- Idempotency checks to prevent replay attacks
"""

import hashlib
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

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
        return _hmac_key

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
# Rate Limiting
# ---------------------------------------------------------------------------

MAX_RECORDS_PER_SECOND = int(os.getenv(
    "MCP_WITNESS_RATE_LIMIT",
    "1000",
))

MAX_RECORDS_PER_MINUTE = MAX_RECORDS_PER_SECOND * 60


class RateLimiter:
    """Simple in-memory token bucket rate limiter."""

    def __init__(self, max_per_second: int = MAX_RECORDS_PER_SECOND):
        self.max_per_second = max_per_second
        self._window_start = time.monotonic()
        self._count = 0

    def allow(self) -> bool:
        """Check if another request is allowed. Returns True if OK."""
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._count = 0
        if self._count >= self.max_per_second:
            return False
        self._count += 1
        return True

    @property
    def remaining(self) -> int:
        """Remaining requests in current window."""
        return max(0, self.max_per_second - self._count)


_rate_limiter = RateLimiter()


def check_rate_limit() -> None:
    """
    Raise ValueError if rate limit exceeded.

    Call before every witness_record.
    """
    if not _rate_limiter.allow():
        raise ValueError(
            f"Rate limit exceeded ({_rate_limiter.max_per_second}/s). "
            f"Configure MCP_WITNESS_RATE_LIMIT to adjust."
        )


# ---------------------------------------------------------------------------
# RBAC (Role-Based Access Control)
# ---------------------------------------------------------------------------

READ_ONLY_MODE = os.getenv("MCP_WITNESS_READ_ONLY", "false").lower() == "true"


def enforce_read_only(tool_name: str) -> None:
    """
    Raise PermissionError if in read-only mode and tool writes.

    Tools that modify state: witness_record, witness_attest,
    witness_anchor, witness_backfill, witness_configure_compliance.
    """
    if not READ_ONLY_MODE:
        return

    write_tools = {
        "witness_record",
        "witness_attest",
        "witness_anchor",
        "witness_backfill",
        "witness_configure_compliance",
    }

    if tool_name in write_tools:
        raise PermissionError(
            "Server is in read-only mode. "
            "Set MCP_WITNESS_READ_ONLY=false to enable writes."
        )


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
# Idempotency
# ---------------------------------------------------------------------------

# In-memory set of recent record hashes to prevent replay attacks
# In production this should be a bounded LRU cache
_idempotency_cache: set[str] = set()
_idempotency_max_size = int(os.getenv("MCP_WITNESS_IDEMPOTENCY_CACHE", "10000"))


def check_idempotency(payload_hash: str) -> bool:
    """
    Check if a payload was already recorded recently.

    Returns True if this is a NEW payload (allow it),
    False if it's a duplicate (reject it).
    """
    if payload_hash in _idempotency_cache:
        logger.warning("Duplicate payload rejected: %s", payload_hash[:16])
        return False

    # Evict if cache grows too large
    if len(_idempotency_cache) >= _idempotency_max_size:
        _idempotency_cache.clear()
        logger.info("Idempotency cache evicted (size limit reached)")

    _idempotency_cache.add(payload_hash)
    return True


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
ALLOWED_EXPORT_DIR = Path(
    os.getenv("MCP_WITNESS_EXPORT_DIR", str(Path.cwd()))
).resolve()


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
        raise ValueError(
            f"Export path must be within {ALLOWED_EXPORT_DIR}. "
            f"Got: {output_path}"
        )

    # Create parent directories if needed
    resolved.parent.mkdir(parents=True, exist_ok=True)

    return resolved


# ---------------------------------------------------------------------------
# Payload Validation
# ---------------------------------------------------------------------------

SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]*$")
MAX_SESSION_ID_LENGTH = 256
MAX_ACTOR_ID_LENGTH = 256
MAX_REASONING_LENGTH = 10000  # 10KB of reasoning text


def validate_inputs(
    session_id: str = "",
    actor_id: str = "unknown",
    reasoning: Optional[str] = None,
) -> None:
    """
    Validate all user-supplied string inputs.

    Raises ValueError for invalid inputs.
    """
    if session_id and len(session_id) > MAX_SESSION_ID_LENGTH:
        raise ValueError(
            f"session_id exceeds max length {MAX_SESSION_ID_LENGTH}"
        )
    if session_id and not SESSION_ID_PATTERN.match(session_id):
        raise ValueError(
            "session_id contains invalid characters"
        )

    if actor_id and len(actor_id) > MAX_ACTOR_ID_LENGTH:
        raise ValueError(
            f"actor_id exceeds max length {MAX_ACTOR_ID_LENGTH}"
        )

    if reasoning and len(reasoning) > MAX_REASONING_LENGTH:
        raise ValueError(
            f"reasoning exceeds max length {MAX_REASONING_LENGTH}"
        )
