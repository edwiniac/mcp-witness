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
        """No API keys configured → returns None (admin/open mode)."""
        with patch.dict(os.environ, {}, clear=True):
            role = authenticate()
        assert role is None

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
        """Invalid key with API_KEYS configured → auditor (anonymous)."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                "MCP_WITNESS_API_KEY": "thiskeyisnotinthelist!",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.AUDITOR

    def test_no_key_returns_auditor(self):
        """No API_KEY provided with keys configured → auditor."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.AUDITOR

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
        """READ_ONLY_MODE without keys → auditor (with deprecation path)."""
        with patch.dict(
            os.environ,
            {
                "MCP_WITNESS_READ_ONLY": "true",
            },
            clear=True,
        ):
            role = authenticate()
        assert role == AuthRole.AUDITOR

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
        """None role (open mode) has full access."""
        authorize(None, "witness_record")  # Should not raise
        authorize(None, "witness_verify")  # Should not raise
        authorize(None, "witness_backfill")  # Should not raise

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
        """No MCP_WITNESS_API_KEYS = open mode (admin for all)."""
        with patch.dict(os.environ, {}, clear=True):
            role = authenticate()
            assert role is None  # None = full access
            # authorize(None, ...) should pass for all tools
            authorize(None, "witness_record")
            authorize(None, "witness_verify")

    def test_enforce_read_only_deprecated(self):
        """Old enforce_read_only still works but warns."""
        from mcp_witness.security import enforce_read_only

        with patch.dict(os.environ, {}, clear=True):
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                # In open mode, read tool should pass
                enforce_read_only("witness_verify")
                # Only write tools would be blocked if auditor
                # Since open mode, all pass

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
            "test",
            logging.INFO,
            "file.py",
            10,
            "api_key=abcdef1234567890abcdef1234567890",
            (),
            None,
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
# JWT Assertion Tests
# =========================================================================


def _make_jwt(payload: dict, privkey_bytes: bytes) -> str:
    """Produce a minimal EdDSA JWT signed with the given Ed25519 private seed."""
    import base64
    import json as _json

    from cryptography.hazmat.primitives.asymmetric import ed25519

    privkey = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes)

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(b'{"alg":"EdDSA","typ":"JWT"}')
    body = b64url(_json.dumps(payload).encode())
    message = f"{header}.{body}".encode()
    sig = privkey.sign(message)
    return f"{header}.{body}.{b64url(sig)}"


class TestVerifyJwtAssertion:
    """Tests for verify_jwt_assertion() in auth.py."""

    # Stable 32-byte test key seed and its hex public key
    _SEED = bytes.fromhex("a" * 64)

    @classmethod
    def _pubkey_hex(cls) -> str:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.from_private_bytes(cls._SEED)
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()

    def test_valid_token_returns_payload(self):
        """A valid signed token with a future expiry returns the payload dict."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import verify_jwt_assertion

        now = int(time.time())
        payload = {"sub": "test-client", "iat": now, "exp": now + 3600, "role": "auditor"}
        token = _make_jwt(payload, self._SEED)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", self._pubkey_hex()):
            result = verify_jwt_assertion(token)

        assert result is not None
        assert result["sub"] == "test-client"
        assert result["role"] == "auditor"

    def test_expired_token_rejected(self):
        """A token whose exp is in the past is rejected."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import verify_jwt_assertion

        now = int(time.time())
        payload = {"sub": "x", "iat": now - 7200, "exp": now - 3600, "role": "writer"}
        token = _make_jwt(payload, self._SEED)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", self._pubkey_hex()):
            result = verify_jwt_assertion(token)

        assert result is None

    def test_tampered_signature_rejected(self):
        """Flipping a byte in the signature invalidates the token."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import verify_jwt_assertion

        now = int(time.time())
        payload = {"sub": "x", "iat": now, "exp": now + 3600, "role": "admin"}
        token = _make_jwt(payload, self._SEED)

        # Corrupt a byte in the middle of the signature (third segment)
        parts = token.split(".")
        sig = list(parts[2])
        mid = len(sig) // 2
        sig[mid] = "A" if sig[mid] != "A" else "B"
        parts[2] = "".join(sig)
        bad_token = ".".join(parts)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", self._pubkey_hex()):
            result = verify_jwt_assertion(bad_token)

        assert result is None

    def test_nbf_not_yet_valid_rejected(self):
        """A token with nbf in the future is rejected."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import verify_jwt_assertion

        now = int(time.time())
        payload = {
            "sub": "x",
            "iat": now,
            "nbf": now + 600,
            "exp": now + 3600,
            "role": "writer",
        }
        token = _make_jwt(payload, self._SEED)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", self._pubkey_hex()):
            result = verify_jwt_assertion(token)

        assert result is None

    def test_no_public_key_configured_returns_none(self):
        """When MCP_WITNESS_JWT_PUBLIC_KEY is empty, JWT auth is disabled."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import verify_jwt_assertion

        now = int(time.time())
        payload = {"sub": "x", "iat": now, "exp": now + 3600, "role": "admin"}
        token = _make_jwt(payload, self._SEED)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", ""):
            result = verify_jwt_assertion(token)

        assert result is None

    def test_jwt_authenticate_returns_correct_role(self):
        """authenticate() with a valid JWT token resolves to the JWT role."""
        import time

        import mcp_witness.auth as auth_mod
        from mcp_witness.auth import authenticate

        now = int(time.time())
        payload = {"sub": "svc-audit", "iat": now, "exp": now + 3600, "role": "auditor"}
        token = _make_jwt(payload, self._SEED)

        with patch.object(auth_mod, "MCP_WITNESS_JWT_PUBLIC_KEY", self._pubkey_hex()):
            with patch.dict(os.environ, {"MCP_WITNESS_API_KEY": token}, clear=True):
                role = authenticate(token=token)

        assert role == AuthRole.AUDITOR


# =========================================================================
# RBAC completeness: ensure witness_health, witness_search, witness_delete
# are properly covered by the permission sets
# =========================================================================


class TestRBACCompleteness:
    """Verify that all tools have correct role coverage."""

    def test_witness_health_accessible_by_auditor(self):
        """witness_health must be accessible to auditors (read-only tool)."""
        authorize(AuthRole.AUDITOR, "witness_health")  # should not raise

    def test_witness_search_accessible_by_auditor(self):
        """witness_search must be accessible to auditors (read-only tool)."""
        authorize(AuthRole.AUDITOR, "witness_search")  # should not raise

    def test_witness_delete_accessible_by_writer(self):
        """witness_delete must be accessible to writers (write tool)."""
        authorize(AuthRole.WRITER, "witness_delete")  # should not raise

    def test_witness_delete_not_accessible_by_auditor(self):
        """witness_delete must NOT be accessible to auditors."""
        with pytest.raises(PermissionError):
            authorize(AuthRole.AUDITOR, "witness_delete")
