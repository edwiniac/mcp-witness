"""Tests for key lifecycle management."""

import json
import os
import tempfile

from mcp_witness.key_lifecycle import (
    KeyTrustStore,
    get_trust_store,
    reset_trust_store,
)

SAMPLE_TRUST_STORE = {
    "keys": {
        "key-001": {
            "public_key_hex": "a" * 64,
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-12-31T23:59:59+00:00",
            "revoked": False,
            "next_key_id": "key-002",
        },
        "key-002": {
            "public_key_hex": "b" * 64,
            "not_before": "2026-06-01T00:00:00+00:00",
            "not_after": None,
            "revoked": False,
        },
        "key-003": {
            "public_key_hex": "c" * 64,
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2024-12-31T23:59:59+00:00",
            "revoked": True,
            "revoked_at": "2025-03-01T00:00:00+00:00",
        },
    },
    "current_key_id": "key-002",
}


def _make_store_file(data: dict) -> str:
    """Write a trust store JSON file and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


class TestKeyTrustStore:
    """Tests for KeyTrustStore."""

    def test_trust_store_load(self):
        """Test loading a trust store from a JSON file."""
        path = _make_store_file(SAMPLE_TRUST_STORE)
        try:
            store = KeyTrustStore(path)

            # All 3 keys loaded
            assert len(store._keys) == 3

            # Current key
            assert store.get_current_key_id() == "key-002"

            # Check metadata
            key_001 = store._keys["key-001"]
            assert key_001.key_id == "key-001"
            assert key_001.revoked is False
            assert key_001.next_key_id == "key-002"
            assert key_001.public_key_hex == "a" * 64

            key_003 = store._keys["key-003"]
            assert key_003.revoked is True
            assert key_003.revoked_at is not None
        finally:
            os.unlink(path)

    def test_is_revoked(self):
        """Test checking if a key is revoked."""
        path = _make_store_file(SAMPLE_TRUST_STORE)
        try:
            store = KeyTrustStore(path)

            # key-003 is revoked
            assert store.is_revoked("key-003") is True

            # key-001 and key-002 are not revoked
            assert store.is_revoked("key-001") is False
            assert store.is_revoked("key-002") is False

            # Non-existent key is not revoked
            assert store.is_revoked("nonexistent") is False
        finally:
            os.unlink(path)

    def test_verify_key_chain(self):
        """Test verifying a key is in the authorised chain."""
        path = _make_file(SAMPLE_TRUST_STORE)
        try:
            store = KeyTrustStore(path)

            # key-001 is in the chain (current=key-002, key-002.next=key-001... actually no)
            # key-001.next_key_id = "key-002" so key-001 -> key-002
            # current = key-002
            # chain from current: key-002, key-002.next=... none
            # So key-001 is NOT in the forward chain from current
            # Actually, let me reconsider:
            # The chain starts from current_key_id (key-002) and follows next_key_id forward
            # key-002 has no next_key_id, so chain = {key-002}
            assert store.verify_key_chain("key-002") is True
            assert (
                store.verify_key_chain("key-001") is False
            )  # key-001 is before current, not after
        finally:
            os.unlink(path)

    def test_get_active_keys(self):
        """Test getting active keys filters out revoked and expired."""
        # Use dates that include current time for the test
        data = {
            "keys": {
                "active-key": {
                    "public_key_hex": "a" * 64,
                    "not_before": "2020-01-01T00:00:00+00:00",
                    "not_after": None,
                    "revoked": False,
                },
                "revoked-key": {
                    "public_key_hex": "b" * 64,
                    "not_before": "2020-01-01T00:00:00+00:00",
                    "not_after": None,
                    "revoked": True,
                },
                "future-key": {
                    "public_key_hex": "c" * 64,
                    "not_before": "2099-01-01T00:00:00+00:00",
                    "not_after": None,
                    "revoked": False,
                },
            },
            "current_key_id": "active-key",
        }
        path = _make_file(data)
        try:
            store = KeyTrustStore(path)
            active = store.get_active_keys()
            key_ids = [k.key_id for k in active]

            # active-key is not revoked and not_before is in the past
            assert "active-key" in key_ids
            # revoked-key is revoked
            assert "revoked-key" not in key_ids
            # future-key has not_before in the future
            assert "future-key" not in key_ids
        finally:
            os.unlink(path)

    def test_no_trust_store_works_without(self):
        """Test that KeyTrustStore works when no path is provided."""
        # Clear env var too
        old_env = os.environ.pop("MCP_WITNESS_TRUST_STORE", None)
        try:
            store = KeyTrustStore()
            # Should not crash - empty store is fine
            assert store.get_current_key_id() is None
            assert len(store._keys) == 0
            assert store.get_active_keys() == []
            assert store.is_revoked("anything") is False
        finally:
            if old_env is not None:
                os.environ["MCP_WITNESS_TRUST_STORE"] = old_env

    def test_missing_file_logs_warning(self):
        """Non-existent trust store path should log a warning but not crash."""
        store = KeyTrustStore("/tmp/nonexistent_trust_store.json")
        assert len(store._keys) == 0
        assert store.get_current_key_id() is None

    def test_get_key_returns_metadata(self):
        """Test get_key returns SigningKeyMetadata."""
        path = _make_file(SAMPLE_TRUST_STORE)
        try:
            store = KeyTrustStore(path)
            meta = store.get_key("key-001")
            assert meta is not None
            assert meta.key_id == "key-001"
            assert meta.public_key_hex == "a" * 64

            # Non-existent key returns None
            assert store.get_key("nonexistent") is None
        finally:
            os.unlink(path)

    def test_get_public_key_bytes(self):
        """Test get_public_key_bytes returns decoded bytes."""
        path = _make_file(SAMPLE_TRUST_STORE)
        try:
            store = KeyTrustStore(path)
            pk_bytes = store.get_public_key_bytes("key-001")
            assert pk_bytes is not None
            assert len(pk_bytes) == 32  # 64 hex chars = 32 bytes
            assert pk_bytes.hex() == "a" * 64

            # Non-existent key returns None
            assert store.get_public_key_bytes("nonexistent") is None

            # Invalid hex in key
            corrupt_data = SAMPLE_TRUST_STORE.copy()
            corrupt_data["keys"] = {
                "bad-key": {
                    "public_key_hex": "not-hex!!",
                    "not_before": "2025-01-01T00:00:00+00:00",
                }
            }
            corrupt_path = _make_file(corrupt_data)
            try:
                corrupt_store = KeyTrustStore(corrupt_path)
                assert corrupt_store.get_public_key_bytes("bad-key") is None
            finally:
                os.unlink(corrupt_path)
        finally:
            os.unlink(path)

    def test_get_active_keys_filters_expired(self):
        """Keys past not_after should not be active."""
        data = {
            "keys": {
                "expired-key": {
                    "public_key_hex": "d" * 64,
                    "not_before": "2020-01-01T00:00:00+00:00",
                    "not_after": "2021-01-01T00:00:00+00:00",
                    "revoked": False,
                }
            },
            "current_key_id": "expired-key",
        }
        path = _make_file(data)
        try:
            store = KeyTrustStore(path)
            active = store.get_active_keys()
            assert len(active) == 0  # Expired key should not be active
        finally:
            os.unlink(path)

    def test_global_singleton(self):
        """Test get_trust_store returns a singleton."""
        reset_trust_store()
        s1 = get_trust_store()
        s2 = get_trust_store()
        assert s1 is s2  # Same instance

    def test_reset_trust_store(self):
        """Test reset clears singleton."""
        reset_trust_store()
        s1 = get_trust_store()
        reset_trust_store()
        s2 = get_trust_store()
        assert s1 is not s2  # Different instances after reset


def _make_file(data: dict) -> str:
    """Write a JSON file for testing."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


class TestRevokedKeyLineage:
    """Revoked keys must not be part of the authorised key chain."""

    def test_revoked_key_in_chain_rejected(self):
        data = {
            "keys": {
                "key-a": {
                    "public_key_hex": "a" * 64,
                    "not_before": "2025-01-01T00:00:00+00:00",
                    "revoked": True,
                    "revoked_at": "2025-06-01T00:00:00+00:00",
                    "next_key_id": "key-b",
                },
                "key-b": {
                    "public_key_hex": "b" * 64,
                    "not_before": "2025-06-01T00:00:00+00:00",
                    "revoked": False,
                },
            },
            "current_key_id": "key-a",
        }
        path = _make_store_file(data)
        try:
            store = KeyTrustStore(path)
            # key-a is revoked: not authorised even though it heads the chain
            assert store.verify_key_chain("key-a") is False
            # key-b is in the lineage and not revoked
            assert store.verify_key_chain("key-b") is True
        finally:
            os.unlink(path)

    def test_cyclic_chain_terminates(self):
        data = {
            "keys": {
                "key-a": {
                    "public_key_hex": "a" * 64,
                    "not_before": "2025-01-01T00:00:00+00:00",
                    "revoked": False,
                    "next_key_id": "key-b",
                },
                "key-b": {
                    "public_key_hex": "b" * 64,
                    "not_before": "2025-06-01T00:00:00+00:00",
                    "revoked": False,
                    "next_key_id": "key-a",
                },
            },
            "current_key_id": "key-a",
        }
        path = _make_store_file(data)
        try:
            store = KeyTrustStore(path)
            assert store.verify_key_chain("key-a") is True
            assert store.verify_key_chain("key-b") is True
            assert store.verify_key_chain("key-missing") is False
        finally:
            os.unlink(path)
