"""
Authentication and authorization module for mcp-witness.

Provides:
- JWT assertion authentication (Ed25519-signed)
- API key-based authentication (MCP_WITNESS_API_KEY env var)
- Three-role RBAC: admin, auditor, writer
- Tool-level permission scoping
- Backward compatibility with deprecated READ_ONLY_MODE
"""

import json
import logging
import os
import time
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)


class AuthRole(str, Enum):
    """Role-based access control levels."""

    ADMIN = "admin"
    AUDITOR = "auditor"
    WRITER = "writer"


# ---------------------------------------------------------------------------
# Tool Permissions
# ---------------------------------------------------------------------------

_READ_TOOLS = frozenset(
    {
        "witness_verify",
        "witness_verify_fast",
        "witness_verify_anchors",
        "witness_query",
        "witness_chain",
        "witness_stats",
        "witness_export",
        "witness_checkpoints",
        "witness_proof",
        "witness_metrics",
    }
)

_WRITE_TOOLS = frozenset(
    {
        "witness_record",
        "witness_attest",
        "witness_anchor",
        "witness_backfill",
        "witness_configure_compliance",
    }
)

ALL_TOOLS = _READ_TOOLS | _WRITE_TOOLS

ROLE_PERMISSIONS: dict[AuthRole, frozenset[str]] = {
    AuthRole.ADMIN: ALL_TOOLS,
    AuthRole.AUDITOR: _READ_TOOLS,
    AuthRole.WRITER: _WRITE_TOOLS,
}


# ---------------------------------------------------------------------------
# JWT Configuration
# ---------------------------------------------------------------------------

MCP_WITNESS_JWT_PUBLIC_KEY = os.getenv("MCP_WITNESS_JWT_PUBLIC_KEY", "")
# Format: hex-encoded Ed25519 public key (64 hex chars = 32 bytes)

MCP_WITNESS_JWT_MAX_AGE = int(os.getenv("MCP_WITNESS_JWT_MAX_AGE", "3600"))
# Maximum token age in seconds (default: 1 hour)


def verify_jwt_assertion(token: str) -> Optional[dict]:
    """
    Verify an Ed25519-signed JWT assertion token.

    Token format: base64(header).base64(payload).base64(signature)
    - header: {"alg":"EdDSA","typ":"JWT"}
    - payload: {"sub":"<client_id>","iat":<issued_at>,"exp":<expiry>,"role":"auditor"|"writer"|"reader"}
    - signature: Ed25519 signature of header.payload

    Returns the payload dict if valid (with sub, role, iat, exp), None otherwise.
    """
    if not MCP_WITNESS_JWT_PUBLIC_KEY:
        return None  # JWT auth not configured

    try:
        pubkey_bytes = bytes.fromhex(MCP_WITNESS_JWT_PUBLIC_KEY)
        if len(pubkey_bytes) != 32:
            logger.error("Invalid JWT public key length")
            return None

        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts

        # Decode and verify
        import base64

        def b64url_decode(s: str) -> bytes:
            s = s.replace("-", "+").replace("_", "/")
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            return base64.b64decode(s)

        payload_bytes = b64url_decode(payload_b64)
        sig_bytes = b64url_decode(sig_b64)

        # Verify Ed25519 signature
        try:
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            message = f"{header_b64}.{payload_b64}".encode()
            pubkey.verify(sig_bytes, message)
        except Exception:
            return None  # Invalid signature

        # Parse payload
        payload = json.loads(payload_bytes)

        # Check expiry
        now = int(time.time())
        if payload.get("exp", 0) < now:
            logger.warning("JWT token expired at %d, now is %d", payload["exp"], now)
            return None

        # Check not-before (optional)
        if payload.get("nbf", 0) > now:
            logger.warning("JWT token not yet valid (nbf=%d)", payload["nbf"])
            return None

        # Check max age
        iat = payload.get("iat", 0)
        if now - iat > MCP_WITNESS_JWT_MAX_AGE:
            logger.warning("JWT token exceeds max age (%ds)", MCP_WITNESS_JWT_MAX_AGE)
            return None

        return payload

    except Exception as e:
        logger.warning("JWT verification failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------


def load_api_keys() -> dict[str, AuthRole]:
    """Load API keys from MCP_WITNESS_API_KEYS env var.

    Format: ``key1:role,key2:role``
    Valid roles: admin, auditor, writer

    Returns:
        Dict mapping API key → AuthRole, or empty dict if env var not set.
    """
    raw = os.getenv("MCP_WITNESS_API_KEYS", "").strip()
    if not raw:
        return {}

    keys: dict[str, AuthRole] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            logger.warning("Skipping malformed API key entry (missing ':'): %s", pair[:8])
            continue
        key, role_str = pair.split(":", 1)
        key = key.strip()
        role_str = role_str.strip().lower()

        if role_str not in ("admin", "auditor", "writer"):
            logger.warning("Skipping API key with unknown role: %s", role_str)
            continue

        if len(key) < 16:
            logger.warning("API key %s... is too short (min 16 chars)", key[:8])
            continue

        keys[key] = AuthRole(role_str)

    return keys


def _lookup_api_key(token: str) -> Optional[AuthRole]:
    """Check if a token matches a configured API key. Returns role or None."""
    if not token:
        return None
    api_keys = load_api_keys()
    return api_keys.get(token)


def authenticate(token: Optional[str] = None) -> Optional[AuthRole]:
    """Authenticate the current request.

    Supports:
    1. JWT assertions (Ed25519-signed) — checked first
    2. API key tokens (shared secret) — fallback
    3. Environment variable MCP_WITNESS_API_KEY — legacy
    4. Open mode (no keys configured) — full admin access

    Args:
        token: Authentication token (JWT or API key).
               If None, reads from MCP_WITNESS_API_KEY env var.

    Returns:
        AuthRole if authenticated, None for open mode (full admin access).
    """
    # Resolve token from argument or environment
    if token is None:
        token = os.getenv("MCP_WITNESS_API_KEY", "").strip()

    # 1. Try JWT assertion first
    if token:
        jwt_payload = verify_jwt_assertion(token)
        if jwt_payload is not None:
            role_str = jwt_payload.get("role", "writer")
            try:
                return AuthRole(role_str)
            except ValueError:
                logger.warning("JWT has unknown role: %s", role_str)
                return AuthRole.AUDITOR

    # 2. Fall back to API key
    if token:
        role = _lookup_api_key(token)
        if role is not None:
            return role

    # 3. Handle no-key / open mode / anonymous
    api_keys = load_api_keys()

    # Deprecated READ_ONLY_MODE handling
    read_only = os.getenv("MCP_WITNESS_READ_ONLY", "false").lower() == "true"
    if read_only:
        logger.warning(
            "MCP_WITNESS_READ_ONLY is deprecated. "
            "Use MCP_WITNESS_API_KEYS for fine-grained RBAC instead."
        )

    if not api_keys:
        # Open mode: no API key config
        if read_only:
            return AuthRole.AUDITOR
        return None  # Full admin access

    # Anonymous / invalid key
    allow_anon_writes = os.getenv("MCP_WITNESS_ALLOW_ANON_WRITES", "false").lower() == "true"
    if allow_anon_writes:
        return AuthRole.WRITER
    return AuthRole.AUDITOR


def authorize(role: Optional[AuthRole], tool_name: str) -> None:
    """Check if the given role has permission for the specified tool.

    Args:
        role: Authenticated role, or None for open mode.
        tool_name: Name of the tool being invoked.

    Raises:
        PermissionError: If the role does not have permission.
    """
    if role is None:
        # Open mode: full access (admin)
        return

    allowed = ROLE_PERMISSIONS.get(role, frozenset())
    if tool_name not in allowed:
        raise PermissionError(
            f"Role '{role.value}' does not have permission for tool '{tool_name}'. "
            f"Allowed tools for this role: {', '.join(sorted(allowed))}"
        )
