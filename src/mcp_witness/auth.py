"""
Authentication and authorization module for mcp-witness.

Provides:
- API key-based authentication (MCP_WITNESS_API_KEY env var)
- Three-role RBAC: admin, auditor, writer
- Tool-level permission scoping
- Backward compatibility with deprecated READ_ONLY_MODE
"""

import logging
import os
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class AuthRole(str, Enum):
    """Role-based access control levels."""

    ADMIN = "admin"
    AUDITOR = "auditor"
    WRITER = "writer"


# ---------------------------------------------------------------------------
# Tool Permissions
# ---------------------------------------------------------------------------

_READ_TOOLS = frozenset({
    "witness_verify",
    "witness_verify_fast",
    "witness_verify_anchors",
    "witness_query",
    "witness_chain",
    "witness_stats",
    "witness_export",
    "witness_checkpoints",
    "witness_proof",
})

_WRITE_TOOLS = frozenset({
    "witness_record",
    "witness_attest",
    "witness_anchor",
    "witness_backfill",
    "witness_configure_compliance",
})

ALL_TOOLS = _READ_TOOLS | _WRITE_TOOLS

ROLE_PERMISSIONS: dict[AuthRole, frozenset[str]] = {
    AuthRole.ADMIN: ALL_TOOLS,
    AuthRole.AUDITOR: _READ_TOOLS,
    AuthRole.WRITER: _WRITE_TOOLS,
}


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


def authenticate() -> Optional[AuthRole]:
    """Authenticate the current request from environment variables.

    Flow:
    1. If MCP_WITNESS_API_KEYS is not set → open mode (returns None == admin)
    2. If set, check MCP_WITNESS_API_KEY against loaded keys
    3. Anonymous (no key) defaults to auditor unless ALLOW_ANON_WRITES=true

    Handles deprecated MCP_WITNESS_READ_ONLY with a warning.

    Returns:
        AuthRole if authenticated, None for open mode (full access).
    """
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

    # API keys are configured — authenticate
    provided_key = os.getenv("MCP_WITNESS_API_KEY", "").strip()
    if provided_key and provided_key in api_keys:
        return api_keys[provided_key]

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
