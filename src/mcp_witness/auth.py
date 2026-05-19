"""
Authentication and authorization module for mcp-witness.

Provides:
- JWT assertion authentication (Ed25519-signed)
- JWT token minting (create_jwt_token)
- API key-based authentication (MCP_WITNESS_API_KEYS env var)
- Three-role RBAC: admin, auditor, writer
- Tool-level permission scoping
- Deny-by-default when auth is unconfigured

Environment variables:
  ``MCP_WITNESS_JWT_PUBLIC_KEY`` — hex Ed25519 public key (64 hex chars)
  ``MCP_WITNESS_JWT_PRIVATE_KEY`` — hex Ed25519 private key (64 hex chars)
  ``MCP_WITNESS_JWT_MAX_AGE`` — max token age in seconds (default 3600)
  ``MCP_WITNESS_JWT_ISSUER`` — expected JWT ``iss`` claim
  ``MCP_WITNESS_JWT_AUDIENCE`` — expected JWT ``aud`` claim
  ``MCP_WITNESS_API_KEYS`` — ``key:role,key:role`` format
  ``MCP_WITNESS_DEFAULT_ACCESS`` — ``deny`` (default), ``read_only``, or ``admin``
  ``MCP_WITNESS_REQUIRE_AUTH`` — if ``true``, refuse startup with no keys

.. note::

   mTLS is not supported because MCP uses stdio transport (no TLS layer).
   For network deployments, use an external TLS-terminating proxy (nginx/caddy)
   in front of the dashboard/metrics server, and rely on JWT assertions or
   API keys for client authentication over stdio.
"""

import base64
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
MCP_WITNESS_JWT_PRIVATE_KEY = os.getenv("MCP_WITNESS_JWT_PRIVATE_KEY", "")
MCP_WITNESS_JWT_MAX_AGE = int(os.getenv("MCP_WITNESS_JWT_MAX_AGE", "3600"))
MCP_WITNESS_JWT_ISSUER = os.getenv("MCP_WITNESS_JWT_ISSUER", "")
MCP_WITNESS_JWT_AUDIENCE = os.getenv("MCP_WITNESS_JWT_AUDIENCE", "")

# Deny-by-default access mode when no authentication is configured.
# Valid values:
#   "deny"      — (default) refuse all access; explicit opt-in required
#   "read_only" — allow AUDITOR role (read tools only)
#   "admin"     — allow ADMIN role (all tools) — ONLY for local dev
DEFAULT_ACCESS_MODE = os.getenv("MCP_WITNESS_DEFAULT_ACCESS", "deny").lower()

# Require authentication to be configured before starting the server.
# If true and no API keys or JWT keys are configured, raise RuntimeError.
REQUIRE_AUTH = os.getenv("MCP_WITNESS_REQUIRE_AUTH", "false").lower() == "true"


def check_auth_configured() -> None:
    """Verify authentication is configured if required.

    Raises RuntimeError if REQUIRE_AUTH is true and no keys are configured.
    Call this AFTER environment variables are loaded, BEFORE server start.
    """
    if not REQUIRE_AUTH:
        return
    api_keys = load_api_keys()
    if not api_keys and not MCP_WITNESS_JWT_PUBLIC_KEY:
        raise RuntimeError(
            "MCP_WITNESS_REQUIRE_AUTH=true but no authentication is configured. "
            "Set MCP_WITNESS_API_KEYS or MCP_WITNESS_JWT_PUBLIC_KEY to enable auth. "
            "Or set MCP_WITNESS_REQUIRE_AUTH=false to allow unauthenticated access "
            "(not recommended for production)."
        )
    if not api_keys and MCP_WITNESS_JWT_PUBLIC_KEY:
        logger.info(
            "JWT authentication configured (no API keys). "
            "MCP_WITNESS_DEFAULT_ACCESS=%s", DEFAULT_ACCESS_MODE
        )
    if api_keys and not MCP_WITNESS_JWT_PUBLIC_KEY:
        logger.info(
            "API key authentication configured (%d keys).", len(api_keys)
        )


def create_jwt_token(
    subject: str,
    role: str = "writer",
    ttl_seconds: int = 3600,
    private_key_hex: Optional[str] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
) -> Optional[str]:
    """
    Create an Ed25519-signed JWT assertion token.

    Token format: base64url(header).base64url(payload).base64url(signature)

    Args:
        subject: Client identifier (stored in JWT 'sub' claim)
        role: One of 'admin', 'auditor', 'writer'
        ttl_seconds: Token lifetime in seconds (default 1 hour)
        private_key_hex: 64-char hex Ed25519 private key.
                         Defaults to ``MCP_WITNESS_JWT_PRIVATE_KEY`` env var.
        issuer: JWT issuer claim. Defaults to ``MCP_WITNESS_JWT_ISSUER``.
        audience: JWT audience claim. Defaults to ``MCP_WITNESS_JWT_AUDIENCE``.

    Returns:
        JWT token string, or None if no private key is configured.
    """
    sk_hex = private_key_hex or MCP_WITNESS_JWT_PRIVATE_KEY
    if not sk_hex:
        logger.error("Cannot create JWT: no private key configured")
        return None

    try:
        sk_bytes = bytes.fromhex(sk_hex)
        if len(sk_bytes) != 32:
            logger.error("Invalid JWT private key length: %d (expected 32)", len(sk_bytes))
            return None
    except ValueError:
        logger.error("Invalid JWT private key format (must be hex)")
        return None

    now = int(time.time())

    header = {"alg": "EdDSA", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl_seconds,
        "role": role,
    }

    # Include issuer/audience if configured
    iss = issuer or MCP_WITNESS_JWT_ISSUER
    aud = audience or MCP_WITNESS_JWT_AUDIENCE
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()

    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
        signature = private_key.sign(message)
    except Exception as e:
        logger.error("Failed to sign JWT: %s", e)
        return None

    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jwt_assertion(token: str) -> Optional[dict]:
    """
    Verify an Ed25519-signed JWT assertion token with strict claim validation.

    Checks:
    1. Header claims: ``alg`` must be ``EdDSA``, ``typ`` must be ``JWT``
    2. Required payload claims: ``sub``, ``iat``, ``exp``, ``role``
    3. Token expiry (``exp`` < now)
    4. Not-before (``nbf`` > now, if present)
    5. Future ``iat`` (issued-at must not be in the future)
    6. Max age (now - ``iat`` < ``MCP_WITNESS_JWT_MAX_AGE``)
    7. Issuer (``iss`` must match ``MCP_WITNESS_JWT_ISSUER``, if configured)
    8. Audience (``aud`` must match ``MCP_WITNESS_JWT_AUDIENCE``, if configured)
    9. Ed25519 signature validity

    Returns the full payload dict if valid, None otherwise.
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

        def b64url_decode(s: str) -> bytes:
            s = s.replace("-", "+").replace("_", "/")
            padding = 4 - len(s) % 4
            if padding != 4:
                s += "=" * padding
            return base64.b64decode(s)

        # ── 1. Validate header claims ──────────────────────────────
        try:
            header_bytes = b64url_decode(header_b64)
            header = json.loads(header_bytes)
        except (json.JSONDecodeError, ValueError):
            logger.warning("JWT header is not valid JSON")
            return None

        if header.get("alg") != "EdDSA":
            logger.warning("JWT has invalid alg: %s", header.get("alg"))
            return None
        if header.get("typ") != "JWT":
            logger.warning("JWT has invalid typ: %s", header.get("typ"))
            return None

        # ── 2. Verify Ed25519 signature ────────────────────────────
        payload_bytes = b64url_decode(payload_b64)
        sig_bytes = b64url_decode(sig_b64)

        try:
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            message = f"{header_b64}.{payload_b64}".encode()
            pubkey.verify(sig_bytes, message)
        except Exception:
            return None  # Invalid signature

        # ── 3. Parse & validate payload claims ─────────────────────
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError:
            logger.warning("JWT payload is not valid JSON")
            return None

        # Required claims
        required = ("sub", "iat", "exp", "role")
        if any(k not in payload for k in required):
            missing = [k for k in required if k not in payload]
            logger.warning("JWT missing required claims: %s", missing)
            return None

        # Issuer check
        if MCP_WITNESS_JWT_ISSUER:
            if payload.get("iss") != MCP_WITNESS_JWT_ISSUER:
                logger.warning(
                    "JWT issuer mismatch: got %s, expected %s",
                    payload.get("iss"),
                    MCP_WITNESS_JWT_ISSUER,
                )
                return None

        # Audience check
        if MCP_WITNESS_JWT_AUDIENCE:
            aud = payload.get("aud")
            if isinstance(aud, list):
                if MCP_WITNESS_JWT_AUDIENCE not in aud:
                    logger.warning(
                        "JWT audience mismatch: expected %s not in %s",
                        MCP_WITNESS_JWT_AUDIENCE,
                        aud,
                    )
                    return None
            elif aud != MCP_WITNESS_JWT_AUDIENCE:
                logger.warning(
                    "JWT audience mismatch: got %s, expected %s",
                    aud,
                    MCP_WITNESS_JWT_AUDIENCE,
                )
                return None

        # ── 4. Temporal checks ─────────────────────────────────────
        now = int(time.time())

        # Expiry
        if payload.get("exp", 0) < now:
            logger.warning("JWT token expired at %d, now is %d", payload["exp"], now)
            return None

        # Not-before
        if payload.get("nbf", 0) > now:
            logger.warning("JWT token not yet valid (nbf=%d)", payload["nbf"])
            return None

        # Future iat: tokens must not be issued in the future
        iat = payload.get("iat", 0)
        if iat > now + 30:  # 30s clock skew tolerance
            logger.warning("JWT iat is in the future: %d > %d", iat, now)
            return None

        # Max age
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


def authenticate(token: Optional[str] = None) -> AuthRole:
    """Authenticate the current request.

    Supports:
    1. JWT assertions (Ed25519-signed) — checked first
    2. API key tokens (shared secret) — fallback
    3. Environment variable MCP_WITNESS_API_KEY — legacy
    4. Default access mode when no keys are configured

    Args:
        token: Authentication token (JWT or API key).
               If None, reads from MCP_WITNESS_API_KEY env var.

    Returns:
        AuthRole for the authenticated caller.

    Raises:
        PermissionError: If authentication fails in deny-by-default mode.
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
                logger.warning("JWT has unknown role: %s, defaulting to AUDITOR", role_str)
                return AuthRole.AUDITOR

    # 2. Fall back to API key
    if token:
        role = _lookup_api_key(token)
        if role is not None:
            return role

    # 3. Handle default access when no keys are configured
    api_keys = load_api_keys()

    if api_keys or MCP_WITNESS_JWT_PUBLIC_KEY:
        # Auth IS configured — if we got here without a valid token, check legacy modes
        read_only = os.getenv("MCP_WITNESS_READ_ONLY", "false").lower() == "true"
        if read_only:
            logger.warning(
                "MCP_WITNESS_READ_ONLY is deprecated. "
                "Use MCP_WITNESS_API_KEYS for fine-grained RBAC instead."
            )
            return AuthRole.AUDITOR

        allow_anon_writes = os.getenv("MCP_WITNESS_ALLOW_ANON_WRITES", "false").lower() == "true"
        if allow_anon_writes:
            return AuthRole.WRITER

        # Valid token required but not provided
        raise PermissionError(
            "Authentication required. Provide a valid JWT or API key. "
            "See https://github.com/edwiniac/mcp-witness#authentication for setup instructions."
        )

    # No keys configured: use default access mode
    if DEFAULT_ACCESS_MODE == "deny":
        raise PermissionError(
            "Authentication is not configured and MCP_WITNESS_DEFAULT_ACCESS=deny. "
            "Set MCP_WITNESS_API_KEYS to enable authentication, "
            "or set MCP_WITNESS_DEFAULT_ACCESS=read_only for read-only access, "
            "or MCP_WITNESS_DEFAULT_ACCESS=admin for local development only."
        )
    if DEFAULT_ACCESS_MODE == "read_only":
        logger.warning(
            "No authentication configured — running in READ-ONLY mode. "
            "All write operations will be denied. "
            "Set MCP_WITNESS_API_KEYS for full access control."
        )
        return AuthRole.AUDITOR
    if DEFAULT_ACCESS_MODE == "admin":
        logger.warning(
            "⚠️  No authentication configured — running in OPEN ADMIN mode. "
            "This is UNSAFE for production. ALL tools are accessible without authentication. "
            "Set MCP_WITNESS_API_KEYS or MCP_WITNESS_DEFAULT_ACCESS=deny for production use."
        )
        return AuthRole.ADMIN

    raise PermissionError(
        f"Invalid MCP_WITNESS_DEFAULT_ACCESS value: '{DEFAULT_ACCESS_MODE}'. "
        f"Valid options: deny, read_only, admin"
    )


def authorize(role: Optional[AuthRole], tool_name: str) -> None:
    """Check if the given role has permission for the specified tool.

    Args:
        role: Authenticated role.  Must be a concrete AuthRole.
        tool_name: Name of the tool being invoked.

    Raises:
        PermissionError: If the role does not have permission.
        TypeError: If role is None (programming error — authenticate()
                   must always return a concrete AuthRole).
    """
    if role is None:
        raise PermissionError(
            "Cannot authorize request: no role assigned. "
            "This is a server configuration error — authenticate() should "
            "never return None. Verify authentication is configured."
        )
    allowed = ROLE_PERMISSIONS.get(role, frozenset())
    if tool_name not in allowed:
        raise PermissionError(
            f"Role '{role.value}' does not have permission for tool '{tool_name}'. "
            f"Allowed tools for this role: {', '.join(sorted(allowed))}"
        )
