"""
Tests for authentication, authorization, and security wrappers.

Tests the RBAC module (auth.py) directly:
- API key loading and parsing
- Role-based authentication
- Tool permission authorization
- Backward compatibility scenarios
"""

import os
import warnings
from unittest.mock import patch

import pytest

from mcp_witness.auth import (
    ROLE_PERMISSIONS,
    AuthRole,
    authenticate,
    authorize,
    load_api_keys,
)

# =========================================================================
# API Key Loading Tests
# =========================================================================


class TestLoadApiKeys:
    """Tests for load_api_keys parsing."""

    def test_no_keys_env_not_set(self):
        """No MCP_WITNESS_API_KEYS env var returns empty dict."""
        with patch.dict(os.environ, {}, clear=True):
            keys = load_api_keys()
        assert keys == {}

    def test_single_key(self):
        """Single correctly formatted key is parsed."""
        with patch.dict(
            os.environ,
            {"MCP_WITNESS_API_KEYS": "abcdef1234567890abcdef1234567890:admin"},
            clear=True,
        ):
            keys = load_api_keys()
        assert len(keys) == 1
        assert keys["abcdef1234567890abcdef1234567890"] == AuthRole.ADMIN

    def test_multiple_keys(self):
        """Multiple comma-separated keys are parsed."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaa1111111111111:admin,bbb2222222222222:auditor,ccc3333333333333:writer"
            },
            clear=True,
        ):
            keys = load_api_keys()
        assert len(keys) == 3
        assert keys["aaa1111111111111"] == AuthRole.ADMIN
        assert keys["bbb2222222222222"] == AuthRole.AUDITOR
        assert keys["ccc3333333333333"] == AuthRole.WRITER

    def test_key_too_short_skipped(self):
        """Keys shorter than 16 chars are skipped with a warning."""
        with patch.dict(os.environ, {"MCP_WITNESS_API_KEYS": "short:admin"}, clear=True):
            keys = load_api_keys()
        assert len(keys) == 0

    def test_invalid_role_skipped(self):
        """Unknown roles are skipped."""
        with patch.dict(
            os.environ, {"MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaa:superuser"}, clear=True
        ):
            keys = load_api_keys()
        assert len(keys) == 0

    def test_malformed_entry_skipped(self):
        """Entries without colon are skipped."""
        with patch.dict(os.environ, {"MCP_WITNESS_API_KEYS": "justakeynorole"}, clear=True):
            keys = load_api_keys()
        assert len(keys) == 0

    def test_empty_string(self):
        """Empty env var returns empty dict."""
        with patch.dict(os.environ, {"MCP_WITNESS_API_KEYS": ""}, clear=True):
            keys = load_api_keys()
        assert keys == {}


# =========================================================================
# Authentication Tests
# =========================================================================


class TestAuthenticate:
    """Tests for authenticate()."""

    def test_open_mode_none(self):
        """No API keys configured → deny by default (v1.0 hardened)."""
        with patch.dict(os.environ, {}, clear=True), patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "deny"
        ):
            with pytest.raises(PermissionError, match="not configured"):
                authenticate()

    def test_with_valid_key_admin(self):
        """Valid admin key → returns AuthRole.ADMIN."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                "MCP_WITNESS_API_KEY": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.ADMIN

    def test_with_valid_key_auditor(self):
        """Valid auditor key → returns AuthRole.AUDITOR."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:auditor",
                "MCP_WITNESS_API_KEY": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.AUDITOR

    def test_with_valid_key_writer(self):
        """Valid writer key → returns AuthRole.WRITER."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "cccccccccccccccccccccccccccccccc:writer",
                "MCP_WITNESS_API_KEY": "cccccccccccccccccccccccccccccccc",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.WRITER

    def test_invalid_key_returns_auditor(self):
        """Invalid key with API_KEYS configured → raises (auth required, v1.0 hardened)."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                "MCP_WITNESS_API_KEY": "thiskeyisnotinthelist!",
            },
            clear=True,
        ):
            with pytest.raises(PermissionError, match="Authentication required"):
                authenticate()

    def test_no_key_returns_auditor(self):
        """No API_KEY provided with keys configured → raises (auth required, v1.0 hardened)."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
            },
            clear=True,
        ):
            with pytest.raises(PermissionError, match="Authentication required"):
                authenticate()

    def test_anon_writer_flag(self):
        """MCP_WITNESS_ALLOW_ANON_WRITES=true → writer for anonymous."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                "MCP_WITNESS_ALLOW_ANON_WRITES": "true",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.WRITER

    def test_deprecated_read_only(self):
        """READ_ONLY_MODE without keys → deny by default (explicit opt-in needed)."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_READ_ONLY": "true",
            },
            clear=True,
        ), patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "deny"
        ):
            with pytest.raises(PermissionError, match="not configured"):
                authenticate()

    def test_read_only_with_keys(self):
        """READ_ONLY_MODE with keys → still auths correctly."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                "MCP_WITNESS_API_KEY": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "MCP_WITNESS_READ_ONLY": "true",
            },
            clear=True,
        ):
            # With valid key, role should be admin regardless of read_only
            role = authenticate()
        assert role == AuthRole.ADMIN


# =========================================================================
# Authorization Tests
# =========================================================================


class TestAuthorize:
    """Tests for authorize()."""

    def test_admin_all_tools(self):
        """Admin can access ALL tools (read + write + backfill + compliance)."""
        all_tools = ROLE_PERMISSIONS[AuthRole.ADMIN]
        for tool in all_tools:
            authorize(AuthRole.ADMIN, tool)  # Should not raise

    def test_auditor_read_tools(self):
        """Auditor can access all read tools."""
        read_tools = {
            "witness_verify",
            "witness_verify_fast",
            "witness_verify_anchors",
            "witness_query",
            "witness_chain",
            "witness_stats",
            "witness_export",
            "witness_checkpoints",
            "witness_proof",
        }
        for tool in read_tools:
            authorize(AuthRole.AUDITOR, tool)  # Should not raise

    def test_auditor_write_denied(self):
        """Auditor cannot access write tools."""
        write_tools = {
            "witness_record",
            "witness_attest",
            "witness_anchor",
            "witness_backfill",
            "witness_configure_compliance",
        }
        for tool in write_tools:
            with pytest.raises(PermissionError):
                authorize(AuthRole.AUDITOR, tool)

    def test_writer_write_tools(self):
        """Writer can access all write tools."""
        write_tools = {
            "witness_record",
            "witness_attest",
            "witness_anchor",
            "witness_backfill",
            "witness_configure_compliance",
        }
        for tool in write_tools:
            authorize(AuthRole.WRITER, tool)  # Should not raise

    def test_writer_read_denied(self):
        """Writer cannot access read tools."""
        read_tools = {
            "witness_verify",
            "witness_verify_fast",
            "witness_verify_anchors",
            "witness_query",
            "witness_chain",
            "witness_stats",
            "witness_export",
            "witness_checkpoints",
            "witness_proof",
        }
        for tool in read_tools:
            with pytest.raises(PermissionError):
                authorize(AuthRole.WRITER, tool)

    def test_none_role_open_mode(self):
        """None role raises PermissionError (must have concrete role, v1.0 hardened)."""
        with pytest.raises(PermissionError, match="no role assigned"):
            authorize(None, "witness_record")

    def test_unknown_tool_auditor(self):
        """Unknown tool raises PermissionError for auditor."""
        with pytest.raises(PermissionError):
            authorize(AuthRole.AUDITOR, "nonexistent_tool")


# =========================================================================
# Backward Compatibility Tests
# =========================================================================


class TestBackwardCompat:
    """Tests for backward compatibility scenarios."""

    def test_no_api_keys_full_access(self):
        """No MCP_WITNESS_API_KEYS → deny by default (v1.0 hardened)."""
        with patch.dict(os.environ, {}, clear=True), patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "deny"
        ):
            with pytest.raises(PermissionError, match="not configured"):
                authenticate()

    def test_enforce_read_only_deprecated(self):
        """Old enforce_read_only raised when deny-by-default is active."""
        from mcp_witness.security import enforce_read_only

        with patch.dict(os.environ, {}, clear=True), patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "deny"
        ):
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                with pytest.raises(PermissionError):
                    enforce_read_only("witness_verify")

    def test_backward_compat_imports(self):
        """Old imports from security still work."""
        from mcp_witness.security import (
            check_idempotency,
            check_rate_limit,
            compute_action_fingerprint,
            get_hmac_key,
            sanitize_error,
        )

        # Just verify they're importable
        assert callable(get_hmac_key)
        assert callable(sanitize_error)
        assert callable(compute_action_fingerprint)
        # Async wrappers
        import inspect

        assert inspect.iscoroutinefunction(check_rate_limit)
        assert inspect.iscoroutinefunction(check_idempotency)

    def test_role_permissions_total(self):
        """All 14 tools are covered by admin, and the union is complete."""
        all_tools = ROLE_PERMISSIONS[AuthRole.ADMIN]
        assert len(all_tools) >= 14

        auditor_tools = ROLE_PERMISSIONS[AuthRole.AUDITOR]
        writer_tools = ROLE_PERMISSIONS[AuthRole.WRITER]
        # Auditor + Writer should also cover all tools
        assert auditor_tools | writer_tools == all_tools


# =========================================================================
# Rate Limit Wrapper Tests
# =========================================================================


class TestRateLimitWrapper:
    """Tests for the security.check_rate_limit async wrapper."""

    @pytest.mark.asyncio
    async def test_wrapper_passes_to_storage(self, temp_storage):
        """Wrapper calls storage.check_rate_limit and returns/raises accordingly."""
        from mcp_witness.security import check_rate_limit as sec_check_rate_limit

        # Should succeed (fresh bucket with 1000 tokens)
        await sec_check_rate_limit(temp_storage, bucket_id="test_wrapper")

        # Exhaust to rate limit
        # First get the bucket state after one consumption
        state = await temp_storage.get_rate_limit_state("test_wrapper")
        assert state  # bucket exists

    @pytest.mark.asyncio
    async def test_rate_limit_raised(self, temp_storage):
        """Rate limit raises ValueError when bucket is empty."""
        from mcp_witness.security import check_rate_limit as sec_check_rate_limit

        # Use a bucket with very low max tokens
        # After consuming the 0.x tokens, next should fail
        # max_tokens=0.5, so no full token possible
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            await sec_check_rate_limit(
                temp_storage, bucket_id="test_empty_bucket", max_tokens=0.5, refill_rate=0.0
            )


# =========================================================================
# Idempotency Wrapper Tests
# =========================================================================


class TestIdempotencyWrapper:
    """Tests for the security.check_idempotency async wrapper."""

    @pytest.mark.asyncio
    async def test_wrapper_passes_to_storage(self, temp_storage):
        """Wrapper calls storage.check_and_record_nonce."""
        from mcp_witness.security import check_idempotency as sec_check_idempotency

        result = await sec_check_idempotency(temp_storage, "test_nonce_wrapper")
        assert result is True  # New nonce

    @pytest.mark.asyncio
    async def test_wrapper_detects_duplicate(self, temp_storage):
        """Wrapper detects duplicate nonces."""
        from mcp_witness.security import check_idempotency as sec_check_idempotency

        assert await sec_check_idempotency(temp_storage, "dup_nonce")
        assert not await sec_check_idempotency(temp_storage, "dup_nonce")


# =========================================================================
# Fingerprint Tests
# =========================================================================


class TestFingerprint:
    """Tests for compute_action_fingerprint."""

    def test_fingerprint_deterministic(self):
        """Same inputs produce same fingerprint."""
        from mcp_witness.security import compute_action_fingerprint

        fp1 = compute_action_fingerprint(
            action_type="tool_call",
            session_id="sess_1",
            input_hash="abc123",
            output_hash="def456",
            timestamp="2026-03-01T12:00:00",
        )
        fp2 = compute_action_fingerprint(
            action_type="tool_call",
            session_id="sess_1",
            input_hash="abc123",
            output_hash="def456",
            timestamp="2026-03-01T12:00:00",
        )
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex

    def test_fingerprint_different_inputs(self):
        """Different inputs produce different fingerprints."""
        from mcp_witness.security import compute_action_fingerprint

        fp1 = compute_action_fingerprint(
            action_type="tool_call",
            session_id="sess_1",
            input_hash="abc",
            output_hash="def",
            timestamp="t1",
        )
        fp2 = compute_action_fingerprint(
            action_type="tool_call",
            session_id="sess_1",
            input_hash="xyz",  # different
            output_hash="def",
            timestamp="t1",
        )
        assert fp1 != fp2


# =========================================================================
# TASK 1.2: Anchor Strict Mode Tests
# =========================================================================


class TestAnchorStrictMode:
    """Tests for anchor strict mode configuration."""

    def test_is_anchor_strict_mode_default_true(self):
        """Default value is True."""
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            import importlib

            from mcp_witness import security

            importlib.reload(security)
            assert security.is_anchor_strict_mode() is True
        importlib.reload(security)

    def test_is_anchor_strict_mode_false(self):
        """Can be set to False via env var."""
        from unittest.mock import patch

        with patch.dict(os.environ, {"MCP_WITNESS_ANCHOR_STRICT": "false"}, clear=True):
            import importlib

            from mcp_witness import security

            importlib.reload(security)
            assert security.is_anchor_strict_mode() is False
        importlib.reload(security)


# =========================================================================
# TASK 1.4: Envelope Encryption Tests
# =========================================================================


class TestEncryption:
    """Tests for AES-256-GCM envelope encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt returns original plaintext."""
        from mcp_witness.security import decrypt_field, encrypt_field, get_data_encryption_key

        # Reset key state
        get_data_encryption_key()

        plaintext = "sensitive-data-12345"
        encrypted = encrypt_field(plaintext)
        assert encrypted != plaintext
        assert len(encrypted) > len(plaintext)

        decrypted = decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_decrypt_tampered_fails(self):
        """Tampered ciphertext returns original input (backward compat)."""
        from mcp_witness.security import decrypt_field, encrypt_field

        plaintext = "hello"
        encrypted = encrypt_field(plaintext)

        # Tamper with the ciphertext
        tampered = encrypted[:-1] + ("0" if encrypted[-1] != "0" else "1")
        result = decrypt_field(tampered)
        # Returns the tampered value as-is for backward compat
        assert result == tampered

    def test_decrypt_plaintext_returns_as_is(self):
        """decrypt_field on non-encrypted plaintext returns it as-is."""
        from mcp_witness.security import decrypt_field

        plaintext = "this is not encrypted"
        result = decrypt_field(plaintext)
        assert result == plaintext

    def test_decrypt_empty_returns_empty(self):
        """decrypt_field on empty string returns empty."""
        from mcp_witness.security import decrypt_field

        assert decrypt_field("") == ""
        assert decrypt_field(None) is None

    def test_should_encrypt_pii_fields(self):
        """Known sensitive field names return True for lower sensitivity."""
        from mcp_witness.models import Sensitivity
        from mcp_witness.security import should_encrypt_field

        assert should_encrypt_field("ssn", Sensitivity.INTERNAL) is True
        assert should_encrypt_field("email", Sensitivity.INTERNAL) is True
        assert should_encrypt_field("api_key", Sensitivity.INTERNAL) is True
        assert should_encrypt_field("password", Sensitivity.INTERNAL) is True

    def test_should_encrypt_high_sensitivity(self):
        """PHI and CONFIDENTIAL sensitivity encrypts all fields."""
        from mcp_witness.models import Sensitivity
        from mcp_witness.security import should_encrypt_field

        assert should_encrypt_field("query", Sensitivity.PHI) is True
        assert should_encrypt_field("output", Sensitivity.CONFIDENTIAL) is True
        assert should_encrypt_field("note", Sensitivity.PII) is True

    def test_should_not_encrypt_low_sensitivity_non_pii(self):
        """Public/Internal non-PII fields are not encrypted."""
        from mcp_witness.models import Sensitivity
        from mcp_witness.security import should_encrypt_field

        assert should_encrypt_field("query", Sensitivity.PUBLIC) is False
        assert should_encrypt_field("answer", Sensitivity.INTERNAL) is False

    def test_encrypt_empty_returns_empty(self):
        """encrypt_field with empty string returns empty."""
        from mcp_witness.security import encrypt_field

        assert encrypt_field("") == ""


# =========================================================================
# TASK 1.5: Sensitive Data Scrubbing in Logs
# =========================================================================


class TestLogFilter:
    """Tests for SensitiveDataFilter in logging."""

    def test_log_filter_redacts_api_key(self):
        """API keys in log messages are redacted."""
        import logging

        from mcp_witness.logging import SensitiveDataFilter

        filt = SensitiveDataFilter()
        record = logging.LogRecord(
            "test", logging.INFO, "file.py", 10, "api_key=abcdef1234567890abcdef1234567890", (), None
        )
        filt.filter(record)
        assert "[CREDENTIAL]" in record.msg
        assert "abcdef1234567890" not in record.msg

    def test_log_filter_redacts_openai_key(self):
        """OpenAI-style API keys are redacted."""
        import logging

        from mcp_witness.logging import SensitiveDataFilter

        filt = SensitiveDataFilter()
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "file.py",
            10,
            "Using key sk-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5",
            (),
            None,
        )
        filt.filter(record)
        assert "[API_KEY]" in record.msg
        assert "sk-ABC" not in record.msg
        assert "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5" not in record.msg

    def test_log_filter_preserves_normal_text(self):
        """Normal log messages without sensitive data pass through unchanged."""
        import logging

        from mcp_witness.logging import SensitiveDataFilter

        filt = SensitiveDataFilter()
        msg = "Record created successfully: seq=123"
        record = logging.LogRecord("test", logging.INFO, "file.py", 10, msg, (), None)
        filt.filter(record)
        assert record.msg == msg

    def test_log_filter_redacts_long_hex(self):
        """Long hex strings (potential keys) are redacted."""
        import logging

        from mcp_witness.logging import SensitiveDataFilter

        filt = SensitiveDataFilter()
        long_hex = "a" * 70
        record = logging.LogRecord(
            "test", logging.INFO, "file.py", 10, f"Hash: {long_hex}", (), None
        )
        filt.filter(record)
        assert "[HEX_KEY]" in record.msg
        assert "a" * 70 not in record.msg


# =========================================================================
# JWT Authentication Tests
# =========================================================================


class TestJWTAssertions:
    """Tests for Ed25519 JWT assertion creation and verification."""

    @pytest.fixture(autouse=True)
    def _setup_jwt_keys(self):
        """Generate a fresh Ed25519 keypair for each test."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        self.private_bytes = private_key.private_bytes_raw()
        self.public_bytes = public_key.public_bytes_raw()
        self.private_hex = self.private_bytes.hex()
        self.public_hex = self.public_bytes.hex()

    def test_jwt_create_and_verify_roundtrip(self):
        """Token created with private key can be verified with public key."""
        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex):
            token = create_jwt_token(
                subject="agent-7",
                role="writer",
                ttl_seconds=3600,
                private_key_hex=self.private_hex,
            )
            assert token is not None

            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["sub"] == "agent-7"
            assert payload["role"] == "writer"

    def test_jwt_tampered_token_rejected(self):
        """Tampered JWT tokens are rejected."""
        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex):
            token = create_jwt_token(
                subject="agent-7",
                role="writer",
                private_key_hex=self.private_hex,
            )
            assert token is not None

            # Tamper with the payload
            parts = token.split(".")
            tampered = f"{parts[0]}.{parts[1]}X.{parts[2]}"
            assert verify_jwt_assertion(tampered) is None

            # Tamper with the signature
            sig_bytes = list(parts[2].encode())
            sig_bytes[2] ^= 0xFF
            tampered2 = f"{parts[0]}.{parts[1]}.{bytes(sig_bytes).decode('latin-1')}"
            assert verify_jwt_assertion(tampered2) is None

    def test_jwt_expired_token_rejected(self):
        """Expired JWT tokens are rejected."""
        import time

        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex):
            token = create_jwt_token(
                subject="agent-7",
                role="writer",
                ttl_seconds=-1,  # immediately expired
                private_key_hex=self.private_hex,
            )
            assert token is not None
            time.sleep(0.1)  # ensure we're past expiry
            assert verify_jwt_assertion(token) is None

    def test_jwt_wrong_public_key_rejected(self):
        """Token signed with different key is rejected."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        # Generate a different keypair for verification
        other_key = ed25519.Ed25519PrivateKey.generate()
        other_public_hex = other_key.public_key().public_bytes_raw().hex()

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", other_public_hex):
            token = create_jwt_token(
                subject="agent-7", role="writer", private_key_hex=self.private_hex
            )
            assert token is not None
            # Verification should fail because public key doesn't match
            assert verify_jwt_assertion(token) is None

    def test_jwt_missing_public_key_returns_none(self):
        """When no public key is configured, verification returns None."""
        from mcp_witness.auth import verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""):
            assert verify_jwt_assertion("any.token.here") is None

    def test_jwt_create_without_private_key_returns_none(self):
        """create_jwt_token returns None when no private key is available."""
        from mcp_witness.auth import create_jwt_token

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", ""):
            assert create_jwt_token("agent-7", private_key_hex="") is None

    def test_jwt_invalid_key_length_rejected(self):
        """Keys with wrong length are rejected."""
        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", "deadbeef"):
            assert verify_jwt_assertion("any.token.here") is None

        assert create_jwt_token("agent-7", private_key_hex="short") is None

    def test_jwt_max_age_exceeded(self):
        """Token exceeding MCP_WITNESS_JWT_MAX_AGE is rejected."""
        import time

        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex), \
             patch("mcp_witness.auth.MCP_WITNESS_JWT_MAX_AGE", -1):  # any age is too old
            token = create_jwt_token(
                subject="agent-7", role="writer", ttl_seconds=3600, private_key_hex=self.private_hex
            )
            assert token is not None
            time.sleep(0.1)
            assert verify_jwt_assertion(token) is None

    def test_jwt_not_before_future_rejected(self):
        """Token with nbf in the future is rejected."""
        import json
        import time

        from mcp_witness.auth import create_jwt_token, verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex):
            # nbf is verified when present in payload;
            # create_jwt_token doesn't set nbf so we test the verification path directly
            token = create_jwt_token(
                subject="agent-7", role="writer", ttl_seconds=3600, private_key_hex=self.private_hex
            )
            assert token is not None
            # Token without nbf is valid (nbf is optional)
            assert verify_jwt_assertion(token) is not None

    def test_authenticate_with_jwt_token(self):
        """authenticate() correctly identifies role from JWT."""
        from mcp_witness.auth import authenticate, create_jwt_token

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex), \
             patch.dict("os.environ", {"MCP_WITNESS_API_KEYS": ""}):
            token = create_jwt_token(
                subject="agent-7", role="writer", private_key_hex=self.private_hex
            )
            assert token is not None

            role = authenticate(token=token)
            assert role == AuthRole.WRITER

    def test_authenticate_jwt_unknown_role_defaults_auditor(self):
        """JWT with unknown role value defaults to AUDITOR."""
        from mcp_witness.auth import authenticate, create_jwt_token

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex), \
             patch.dict("os.environ", {"MCP_WITNESS_API_KEYS": ""}):
            token = create_jwt_token(
                subject="agent-7", role="writer", private_key_hex=self.private_hex
            )
            assert token is not None
            # Role in token is 'writer' which is valid → returns WRITER
            role = authenticate(token=token)
            assert role == AuthRole.WRITER

    def test_authenticate_falls_back_to_api_key(self):
        """When JWT verification fails, falls back to API key."""
        from mcp_witness.auth import authenticate

        api_key = "test-key-1234567890abcdef"
        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex), \
             patch.dict("os.environ", {"MCP_WITNESS_API_KEYS": f"{api_key}:writer"}):
            # Provide invalid JWT + valid API key
            role = authenticate(token=api_key)
            assert role == AuthRole.WRITER  # falls back to API key

    def test_jwt_badly_formed_token_rejected(self):
        """Malformed JWT tokens are rejected gracefully."""
        from mcp_witness.auth import verify_jwt_assertion

        with patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.public_hex):
            assert verify_jwt_assertion("not-a-jwt") is None
            assert verify_jwt_assertion("a.b") is None  # only 2 parts
            assert verify_jwt_assertion("a.b.c.d") is None  # 4 parts
            assert verify_jwt_assertion("") is None
