"""Tests for hasher module."""

from datetime import datetime, timezone

from mcp_witness.hasher import (
    GENESIS_HASH,
    compute_record_hash,
    hash_data,
    is_genesis_record,
    redact_field,
    redact_fields,
    sign_record_hash,
    verify_chain_link,
    verify_record_hash,
    verify_record_signature,
)


class TestHashData:
    """Tests for hash_data function."""

    def test_hash_string(self):
        result = hash_data("hello")
        assert len(result) == 64  # SHA-256 = 64 hex chars
        assert result == hash_data("hello")  # Deterministic

    def test_hash_dict(self):
        data = {"key": "value", "number": 42}
        result = hash_data(data)
        assert len(result) == 64
        # Order shouldn't matter
        data2 = {"number": 42, "key": "value"}
        assert hash_data(data) == hash_data(data2)

    def test_hash_list(self):
        result = hash_data([1, 2, 3])
        assert len(result) == 64

    def test_hash_none(self):
        result = hash_data(None)
        assert len(result) == 64

    def test_different_data_different_hash(self):
        assert hash_data("hello") != hash_data("world")
        assert hash_data({"a": 1}) != hash_data({"a": 2})


class TestComputeRecordHash:
    """Tests for compute_record_hash function."""

    def test_compute_hash(self):
        timestamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = compute_record_hash(
            prev_hash=GENESIS_HASH,
            sequence=0,
            timestamp=timestamp,
            action_type="tool_call",
            actor_id="test_agent",
            input_hash="abc123",
            output_hash="def456",
            tool_name="test_tool",
        )
        assert len(result) == 64

    def test_deterministic(self):
        timestamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        args = {
            "prev_hash": GENESIS_HASH,
            "sequence": 0,
            "timestamp": timestamp,
            "action_type": "tool_call",
            "actor_id": "test_agent",
            "input_hash": "abc123",
            "output_hash": "def456",
        }
        assert compute_record_hash(**args) == compute_record_hash(**args)

    def test_different_inputs_different_hash(self):
        timestamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        base_args = {
            "prev_hash": GENESIS_HASH,
            "sequence": 0,
            "timestamp": timestamp,
            "action_type": "tool_call",
            "actor_id": "test_agent",
            "input_hash": "abc123",
            "output_hash": "def456",
        }

        hash1 = compute_record_hash(**base_args)

        # Different sequence
        modified = {**base_args, "sequence": 1}
        hash2 = compute_record_hash(**modified)
        assert hash1 != hash2

        # Different actor
        modified = {**base_args, "actor_id": "other_agent"}
        hash3 = compute_record_hash(**modified)
        assert hash1 != hash3


class TestVerifyRecordHash:
    """Tests for verify_record_hash function."""

    def test_valid_hash(self):
        timestamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        args = {
            "prev_hash": GENESIS_HASH,
            "sequence": 0,
            "timestamp": timestamp,
            "action_type": "tool_call",
            "actor_id": "test_agent",
            "input_hash": "abc123",
            "output_hash": "def456",
        }
        expected_hash = compute_record_hash(**args)
        assert verify_record_hash(record_hash=expected_hash, **args) is True

    def test_invalid_hash(self):
        timestamp = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        args = {
            "prev_hash": GENESIS_HASH,
            "sequence": 0,
            "timestamp": timestamp,
            "action_type": "tool_call",
            "actor_id": "test_agent",
            "input_hash": "abc123",
            "output_hash": "def456",
        }
        assert verify_record_hash(record_hash="invalid_hash", **args) is False


class TestHMACChainProtection:
    """Tests for HMAC-based hash chain protection."""

    _test_key = b"this-is-a-32-byte-test-key-123456"  # exactly 32 bytes
    _wrong_key = b"this-is-a-different-32-byte-key-789a"  # exactly 32 bytes

    def make_args(self):
        return {
            "prev_hash": GENESIS_HASH,
            "sequence": 0,
            "timestamp": datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
            "action_type": "tool_call",
            "actor_id": "test_agent",
            "input_hash": "abc123",
            "output_hash": "def456",
        }

    def test_hmac_produces_different_hash_than_plain(self):
        """HMAC with a key produces a different hash than plain SHA-256."""
        args = self.make_args()
        plain_hash = compute_record_hash(**args)
        hmac_hash = compute_record_hash(**args, hmac_key=self._test_key)
        assert len(hmac_hash) == 64
        assert hmac_hash != plain_hash

    def test_hmac_deterministic_with_same_key(self):
        """Same key produces same HMAC hash (deterministic)."""
        args = self.make_args()
        h1 = compute_record_hash(**args, hmac_key=self._test_key)
        h2 = compute_record_hash(**args, hmac_key=self._test_key)
        assert h1 == h2

    def test_hmac_different_key_different_hash(self):
        """Different HMAC keys produce different hashes for same input."""
        args = self.make_args()
        h1 = compute_record_hash(**args, hmac_key=self._test_key)
        h2 = compute_record_hash(**args, hmac_key=self._wrong_key)
        assert h1 != h2

    def test_hmac_verify_valid(self):
        """verify_record_hash returns True when HMAC hash is correct."""
        args = self.make_args()
        h = compute_record_hash(**args, hmac_key=self._test_key)
        assert verify_record_hash(record_hash=h, **args, hmac_key=self._test_key) is True

    def test_hmac_verify_with_wrong_key(self):
        """verify_record_hash returns False when HMAC key is wrong (forgery detection)."""
        args = self.make_args()
        h = compute_record_hash(**args, hmac_key=self._test_key)
        # Verify with a different key should fail
        assert verify_record_hash(record_hash=h, **args, hmac_key=self._wrong_key) is False

    def test_hmac_verify_with_no_key_after_keyed(self):
        """verify without key after keyed creation should fail (backward compat safe)."""
        args = self.make_args()
        h = compute_record_hash(**args, hmac_key=self._test_key)
        # Passing no key (None) should NOT verify a keyed hash
        assert verify_record_hash(record_hash=h, **args) is False

    def test_plain_verify_still_works_without_key(self):
        """Backward compat: plain SHA-256 hash verifies fine when no key passed."""
        args = self.make_args()
        h = compute_record_hash(**args)  # no hmac_key
        assert verify_record_hash(record_hash=h, **args) is True  # no hmac_key

    def test_plain_verify_fails_with_key_present(self):
        """A plain SHA-256 hash should fail verification when a key IS provided."""
        args = self.make_args()
        h = compute_record_hash(**args)  # plain SHA-256
        assert verify_record_hash(record_hash=h, **args, hmac_key=self._test_key) is False


class TestChainLink:
    """Tests for chain link verification."""

    def test_valid_chain_link(self):
        assert verify_chain_link("abc123", "abc123") is True

    def test_invalid_chain_link(self):
        assert verify_chain_link("abc123", "def456") is False

    def test_genesis_check(self):
        assert is_genesis_record(GENESIS_HASH) is True
        assert is_genesis_record("abc123") is False


class TestRedaction:
    """Tests for field redaction."""

    def test_redact_simple_field(self):
        data = {"name": "John", "ssn": "123-45-6789"}
        result = redact_field(data, "ssn")
        assert "REDACTED" in result["ssn"]
        assert result["name"] == "John"

    def test_redact_nested_field(self):
        data = {"user": {"name": "John", "ssn": "123-45-6789"}}
        result = redact_field(data, "user.ssn")
        assert "REDACTED" in result["user"]["ssn"]
        assert result["user"]["name"] == "John"

    def test_redact_nonexistent_field(self):
        data = {"name": "John"}
        result = redact_field(data, "ssn")
        assert result == data

    def test_redact_multiple_fields(self):
        data = {"name": "John", "ssn": "123", "phone": "555-1234"}
        result = redact_fields(data, ["ssn", "phone"])
        assert "REDACTED" in result["ssn"]
        assert "REDACTED" in result["phone"]
        assert result["name"] == "John"

    def test_redact_empty_data(self):
        assert redact_field({}, "field") == {}
        assert redact_field(None, "field") is None


class TestEd25519Signing:
    """Tests for Ed25519 record signing."""

    def _make_keypair(self):
        """Create a fresh Ed25519 keypair for testing."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return private_key, public_key_bytes

    def test_sign_and_verify_roundtrip(self):
        """Sign a record hash and verify it with the matching public key."""
        private_key, public_key = self._make_keypair()
        record_hash = hash_data({"action": "test", "value": 42})

        signature = sign_record_hash(record_hash, private_key)
        assert isinstance(signature, str)
        assert len(signature) > 0

        assert verify_record_signature(record_hash, signature, public_key) is True

    def test_signature_deterministic(self):
        """Same key and same hash produce the same signature."""
        private_key, _ = self._make_keypair()
        record_hash = hash_data("deterministic test")

        sig1 = sign_record_hash(record_hash, private_key)
        sig2 = sign_record_hash(record_hash, private_key)
        assert sig1 == sig2

    def test_wrong_key_fails_verification(self):
        """Signature created with one key cannot be verified with a different key."""
        key_a, pub_a = self._make_keypair()
        key_b, pub_b = self._make_keypair()
        record_hash = hash_data("who signed this?")

        sig_a = sign_record_hash(record_hash, key_a)
        # Key B cannot verify Key A's signature
        assert verify_record_signature(record_hash, sig_a, pub_b) is False

    def test_wrong_hash_fails_verification(self):
        """Signature valid for one hash fails for a different hash."""
        private_key, public_key = self._make_keypair()
        hash_a = hash_data("original data")
        hash_b = hash_data("tampered data")

        sig = sign_record_hash(hash_a, private_key)
        assert verify_record_signature(hash_b, sig, public_key) is False

    def test_corrupted_signature_fails(self):
        """A corrupted signature string fails verification."""
        private_key, public_key = self._make_keypair()
        record_hash = hash_data("important decision")

        valid_sig = sign_record_hash(record_hash, private_key)
        corrupted = "00" + valid_sig[2:]  # flip first byte
        assert verify_record_signature(record_hash, corrupted, public_key) is False

    def test_invalid_hex_signature_fails(self):
        """Non-hex signature string fails gracefully."""
        _, public_key = self._make_keypair()
        record_hash = hash_data("test")
        assert verify_record_signature(record_hash, "not-hex-data!!", public_key) is False

    def test_empty_public_key_fails(self):
        """Invalid public key bytes fail gracefully."""
        private_key, _ = self._make_keypair()
        record_hash = hash_data("test")
        sig = sign_record_hash(record_hash, private_key)
        assert verify_record_signature(record_hash, sig, b"") is False

    def test_sign_record_hash_length(self):
        """Ed25519 signature is exactly 128 hex characters (64 bytes)."""
        private_key, _ = self._make_keypair()
        record_hash = hash_data({"action": "tool_call"})
        sig = sign_record_hash(record_hash, private_key)
        # Ed25519 signature is 64 bytes = 128 hex chars
        assert len(sig) == 128


class TestCryptoAgility:
    """Tests for crypto_agility module (TASK 2.1)."""

    def _make_keypair(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return private_key, public_key_bytes

    def test_versioned_sign_includes_algo(self):
        """versioned_sign returns dict with algo and signature keys."""
        from mcp_witness.crypto_agility import (
            CURRENT_SIGNING_ALGO,
            versioned_sign,
        )

        private_key, _ = self._make_keypair()
        record_hash = "abc123def456"

        result = versioned_sign(record_hash, private_key, CURRENT_SIGNING_ALGO.value)

        assert isinstance(result, dict)
        assert "algo" in result
        assert result["algo"] == "ed25519+sha256:v1"
        assert "signature" in result
        assert len(result["signature"]) == 128  # Ed25519 sig = 128 hex chars

    def test_versioned_sign_includes_key_id(self):
        """versioned_sign includes key_id when provided."""
        from mcp_witness.crypto_agility import (
            CURRENT_SIGNING_ALGO,
            versioned_sign,
        )

        private_key, _ = self._make_keypair()
        record_hash = "abc123"

        result = versioned_sign(record_hash, private_key, CURRENT_SIGNING_ALGO.value, key_id="key-001")

        assert result["key_id"] == "key-001"

    def test_versioned_verify_rejects_wrong_algo(self):
        """versioned_verify returns False for unsupported algorithm."""
        from mcp_witness.crypto_agility import versioned_verify

        _, public_key = self._make_keypair()

        sig_data = {"algo": "unsupported:v999", "signature": "aa" * 64}
        result = versioned_verify("some_hash", sig_data, public_key)
        assert result is False

    def test_versioned_verify_rejects_none_algo(self):
        """versioned_verify trivially passes for 'none' algo."""
        from mcp_witness.crypto_agility import versioned_verify

        _, public_key = self._make_keypair()
        sig_data = {"algo": "none", "signature": ""}
        result = versioned_verify("some_hash", sig_data, public_key)
        assert result is True

    def test_backward_compat_bare_signature(self):
        """versioned_verify handles legacy bare hex signatures."""
        from mcp_witness.crypto_agility import versioned_verify

        private_key, public_key = self._make_keypair()
        record_hash = "abc123"
        bare_sig = private_key.sign(record_hash.encode()).hex()

        # Legacy: pass the hex string directly instead of a dict
        assert versioned_verify(record_hash, bare_sig, public_key) is True

        # Wrong hash should fail
        assert versioned_verify("wrong_hash", bare_sig, public_key) is False

    def test_detect_legacy_signature(self):
        """detect_signature_format detects legacy 128-char hex."""
        from mcp_witness.crypto_agility import detect_signature_format

        assert detect_signature_format("a" * 128) == "legacy"
        assert detect_signature_format("deadbeef" * 16) == "legacy"
        assert detect_signature_format("a" * 64) == "unknown"  # Too short

    def test_detect_versioned_signature(self):
        """detect_signature_format detects JSON versioned format."""
        import json

        from mcp_witness.crypto_agility import detect_signature_format
        sig = json.dumps({"algo": "ed25519+sha256:v1", "signature": "aa" * 64})
        assert detect_signature_format(sig) == "versioned"

    def test_detect_empty_or_unknown(self):
        """detect_signature_format handles empty and unknown formats."""
        from mcp_witness.crypto_agility import detect_signature_format

        assert detect_signature_format("") == "unknown"
        assert detect_signature_format("not-a-signature") == "unknown"


class TestCanonicalPayload:
    """Tests for canonicalized signing payload (TASK 2.2)."""

    def test_canonicalize_deterministic(self):
        """Same inputs produce same canonical bytes."""
        from mcp_witness.hasher import canonicalize_record_fields

        b1 = canonicalize_record_fields(
            prev_hash="abc",
            sequence=0,
            timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call",
            actor_id="agent-1",
            input_hash="in123",
            output_hash="out456",
        )
        b2 = canonicalize_record_fields(
            prev_hash="abc",
            sequence=0,
            timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call",
            actor_id="agent-1",
            input_hash="in123",
            output_hash="out456",
        )
        assert b1 == b2

    def test_canonicalize_different_records(self):
        """Different inputs produce different canonical bytes."""
        from mcp_witness.hasher import canonicalize_record_fields

        b1 = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )
        b2 = canonicalize_record_fields(
            prev_hash="def", sequence=1, timestamp="2026-01-02T00:00:00+00:00",
            action_type="decision", actor_id="agent-2",
            input_hash="in999", output_hash="out000",
        )
        assert b1 != b2

    def test_canonicalize_includes_tool_name(self):
        """Tool name is included when provided."""
        from mcp_witness.hasher import canonicalize_record_fields

        b1 = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )
        b2 = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
            tool_name="search_tool",
        )
        assert b1 != b2

    def test_canonical_contains_version_field(self):
        """Canonical payload includes version field 'v'."""
        import json

        from mcp_witness.hasher import canonicalize_record_fields

        b = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )
        payload = json.loads(b.decode())
        assert payload["v"] == 1

    def test_sign_canonical_roundtrip(self):
        """Sign and verify canonical payload roundtrip."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from mcp_witness.crypto_agility import CURRENT_SIGNING_ALGO
        from mcp_witness.hasher import (
            canonicalize_record_fields,
            sign_canonical_payload,
            verify_canonical_signature,
        )

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        canonical_bytes = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )

        sig_data = sign_canonical_payload(canonical_bytes, private_key, CURRENT_SIGNING_ALGO.value)
        assert sig_data["algo"] == "ed25519+sha256:v1"

        # Verify with same canonical bytes
        assert verify_canonical_signature(canonical_bytes, sig_data, public_key_bytes) is True

        # Verify with wrong canonical bytes
        wrong_bytes = canonicalize_record_fields(
            prev_hash="wrong", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )
        assert verify_canonical_signature(wrong_bytes, sig_data, public_key_bytes) is False

    def test_sign_canonical_with_key_id(self):
        """Canonical signing includes key_id when provided."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from mcp_witness.crypto_agility import CURRENT_SIGNING_ALGO
        from mcp_witness.hasher import (
            canonicalize_record_fields,
            sign_canonical_payload,
        )

        private_key = ed25519.Ed25519PrivateKey.generate()

        canonical_bytes = canonicalize_record_fields(
            prev_hash="abc", sequence=0, timestamp="2026-01-01T00:00:00+00:00",
            action_type="tool_call", actor_id="agent-1",
            input_hash="in123", output_hash="out456",
        )

        sig_data = sign_canonical_payload(canonical_bytes, private_key, CURRENT_SIGNING_ALGO.value, key_id="key-001")
        assert sig_data.get("key_id") == "key-001"
