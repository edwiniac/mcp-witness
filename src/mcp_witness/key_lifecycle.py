"""Signing key lifecycle: rotation, revocation, trust store."""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SigningKeyMetadata:
    """Metadata for a single signing key."""

    key_id: str
    public_key_hex: str
    not_before: datetime
    not_after: Optional[datetime] = None
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    next_key_id: Optional[str] = None


class KeyTrustStore:
    """Loads key trust from JSON file (MCP_WITNESS_TRUST_STORE env var).

    Trust store JSON format::

        {
          "keys": {
            "key-001": {
              "public_key_hex": "...",
              "not_before": "2026-01-01T00:00:00+00:00",
              "not_after": "2026-12-31T23:59:59+00:00",
              "revoked": false,
              "next_key_id": "key-002"
            },
            "key-002": {
              "public_key_hex": "...",
              "not_before": "2026-06-01T00:00:00+00:00",
              "not_after": null,
              "revoked": false
            }
          },
          "current_key_id": "key-002"
        }
    """

    def __init__(self, store_path: Optional[str] = None):
        """Initialize the trust store.

        Args:
            store_path: Path to the trust store JSON file. Falls back to
                ``MCP_WITNESS_TRUST_STORE`` env var. If neither is set,
                the store is empty (no-op mode).
        """
        self._path = store_path or os.getenv("MCP_WITNESS_TRUST_STORE")
        self._keys: dict[str, SigningKeyMetadata] = {}
        self._current_key_id: Optional[str] = None
        if self._path and os.path.exists(self._path):
            self._load()
            if self._current_key_id:
                logger.info(
                    "KeyTrustStore: loaded %d keys from %s, current=%s",
                    len(self._keys),
                    self._path,
                    self._current_key_id,
                )
            else:
                logger.info(
                    "KeyTrustStore: loaded %d keys from %s (no current key)",
                    len(self._keys),
                    self._path,
                )
        elif self._path:
            logger.warning(
                "KeyTrustStore: path %s does not exist — operating without trust store",
                self._path,
            )

    def _load(self) -> None:
        """Load and parse the trust store JSON file."""
        try:
            with open(self._path) as f:  # type: ignore[arg-type]
                data = json.load(f)

            self._current_key_id = data.get("current_key_id")

            for key_id, key_data in data.get("keys", {}).items():
                metadata = SigningKeyMetadata(
                    key_id=key_id,
                    public_key_hex=key_data["public_key_hex"],
                    not_before=datetime.fromisoformat(key_data["not_before"]),
                    not_after=(
                        datetime.fromisoformat(key_data["not_after"])
                        if key_data.get("not_after")
                        else None
                    ),
                    revoked=bool(key_data.get("revoked", False)),
                    revoked_at=(
                        datetime.fromisoformat(key_data["revoked_at"])
                        if key_data.get("revoked_at")
                        else None
                    ),
                    next_key_id=key_data.get("next_key_id"),
                )
                self._keys[key_id] = metadata
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error("KeyTrustStore: failed to load %s: %s", self._path, e)
            self._keys = {}
            self._current_key_id = None

    def get_active_keys(self) -> list[SigningKeyMetadata]:
        """Get all keys that are currently active (not revoked, within validity window).

        Returns:
            List of active signing key metadata.
        """
        now = datetime.now(timezone.utc)
        active = []
        for key in self._keys.values():
            if key.revoked:
                continue
            if key.not_before and key.not_before > now:
                continue
            if key.not_after and key.not_after < now:
                continue
            active.append(key)
        return active

    def is_revoked(self, key_id: str) -> bool:
        """Check if a key is revoked.

        Args:
            key_id: The key identifier to check.

        Returns:
            ``True`` if the key exists and is revoked.
        """
        key = self._keys.get(key_id)
        if key is None:
            return False
        return key.revoked

    def verify_key_chain(self, key_id: str) -> bool:
        """Verify that the key chain from the current key leads back to this key_id.

        Starting from the current key, follows ``next_key_id`` references
        backwards (via the chain). Returns ``True`` if ``key_id`` is found
        in the chain. This ensures the key used to sign is part of the
        authorised rotation lineage.

        Args:
            key_id: The key identifier to trace.

        Returns:
            ``True`` if the key is in the authorised key chain.
        """
        if not self._current_key_id:
            return False

        # Build a set of all keys in the chain (forward from start)
        chain_keys: set[str] = set()
        current: Optional[str] = self._current_key_id
        while current and current in self._keys:
            chain_keys.add(current)
            current = self._keys[current].next_key_id

        return key_id in chain_keys

    def get_current_key_id(self) -> Optional[str]:
        """Get the current (active) key identifier.

        Returns:
            The current key ID, or ``None`` if not set or the store is empty.
        """
        return self._current_key_id

    def get_key(self, key_id: str) -> Optional[SigningKeyMetadata]:
        """Get metadata for a specific key.

        Args:
            key_id: The key identifier.

        Returns:
            SigningKeyMetadata or ``None`` if not found.
        """
        return self._keys.get(key_id)

    def get_public_key_bytes(self, key_id: str) -> Optional[bytes]:
        """Get the public key bytes for a specific key.

        Args:
            key_id: The key identifier.

        Returns:
            Raw public key bytes (32 bytes), or ``None`` if not found.
        """
        key = self._keys.get(key_id)
        if key is None:
            return None
        try:
            return bytes.fromhex(key.public_key_hex)
        except ValueError:
            return None


# Global singleton
_TRUST_STORE: Optional[KeyTrustStore] = None


def get_trust_store() -> KeyTrustStore:
    """Get the global KeyTrustStore singleton.

    Returns:
        The shared KeyTrustStore instance (lazy-loaded on first call).
    """
    global _TRUST_STORE
    if _TRUST_STORE is None:
        _TRUST_STORE = KeyTrustStore()
    return _TRUST_STORE


def reset_trust_store() -> None:
    """Reset the global trust store singleton (useful for testing)."""
    global _TRUST_STORE
    _TRUST_STORE = None
