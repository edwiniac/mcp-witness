"""Extra coverage for security helpers: encryption-key env handling, export-path
validation, field-encryption heuristics, error sanitization, and the SSRF guard.

These complement tests/test_security.py without duplicating its cases.
"""

from pathlib import Path

import pytest

from mcp_witness import security
from mcp_witness.models import Sensitivity

_KEY_HEX = "11" * 32  # 32-byte key, 64 hex chars


@pytest.fixture(autouse=True)
def _reset_dek(monkeypatch):
    """Reset the cached data-encryption key around each test."""
    monkeypatch.setattr(security, "_DEK", None)
    yield
    monkeypatch.setattr(security, "_DEK", None)


class TestEncryptionKeyEnv:
    def test_encryption_key_env_used(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_DEK", raising=False)
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", _KEY_HEX)
        key = security.get_data_encryption_key()
        assert key == bytes.fromhex(_KEY_HEX)

    def test_dek_alias_still_supported(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_ENCRYPTION_KEY", raising=False)
        monkeypatch.setenv("MCP_WITNESS_DEK", _KEY_HEX)
        assert security.get_data_encryption_key() == bytes.fromhex(_KEY_HEX)

    def test_encryption_key_takes_precedence_over_dek(self, monkeypatch):
        other = "22" * 32
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", _KEY_HEX)
        monkeypatch.setenv("MCP_WITNESS_DEK", other)
        assert security.get_data_encryption_key() == bytes.fromhex(_KEY_HEX)

    def test_wrong_length_key_raises(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_DEK", raising=False)
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", "abcd")  # 2 bytes
        with pytest.raises(ValueError, match="32 bytes"):
            security.get_data_encryption_key()

    def test_ephemeral_key_generated_when_unset(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("MCP_WITNESS_DEK", raising=False)
        key = security.get_data_encryption_key()
        assert isinstance(key, bytes) and len(key) == 32


class TestEncryptDecryptRoundTrip:
    def test_round_trip(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", _KEY_HEX)
        ct = security.encrypt_field("secret-value")
        assert ct != "secret-value"
        assert security.decrypt_field(ct) == "secret-value"

    def test_empty_passthrough(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", _KEY_HEX)
        assert security.encrypt_field("") == ""
        assert security.decrypt_field("") == ""

    def test_decrypt_non_encrypted_returns_input(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_ENCRYPTION_KEY", _KEY_HEX)
        # Plain text that was never encrypted is returned unchanged (back-compat).
        assert security.decrypt_field("not-base64-cipher!") == "not-base64-cipher!"


class TestShouldEncryptField:
    @pytest.mark.parametrize("level", [Sensitivity.PII, Sensitivity.PHI, Sensitivity.CONFIDENTIAL])
    def test_high_sensitivity_always_encrypts(self, level):
        assert security.should_encrypt_field("anything", level) is True

    def test_sensitive_name_at_low_sensitivity(self):
        assert security.should_encrypt_field("email", Sensitivity.INTERNAL) is True
        assert security.should_encrypt_field("patient_id", Sensitivity.INTERNAL) is True

    def test_non_sensitive_name_at_low_sensitivity(self):
        assert security.should_encrypt_field("widget_count", Sensitivity.PUBLIC) is False


class TestValidateExportPath:
    def test_rejects_null_byte(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "ALLOWED_EXPORT_DIR", tmp_path.resolve())
        with pytest.raises(ValueError, match="null"):
            security.validate_export_path("foo\x00.json")

    def test_rejects_outside_allowed_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "ALLOWED_EXPORT_DIR", (tmp_path / "allowed").resolve())
        (tmp_path / "allowed").mkdir()
        with pytest.raises(ValueError, match="within"):
            security.validate_export_path(str(tmp_path / "elsewhere" / "out.json"))

    def test_allows_inside_dir(self, tmp_path, monkeypatch):
        allowed = (tmp_path / "allowed").resolve()
        allowed.mkdir()
        monkeypatch.setattr(security, "ALLOWED_EXPORT_DIR", allowed)
        resolved = security.validate_export_path(str(allowed / "sub" / "out.json"))
        assert isinstance(resolved, Path)
        assert str(resolved).startswith(str(allowed))


class TestSanitizeError:
    def test_value_error_message_preserved(self):
        out = security.sanitize_error(ValueError("bad input value"))
        assert out["type"] == "ValueError"
        assert "bad input value" in out["error"]

    def test_generic_error_is_masked(self):
        out = security.sanitize_error(RuntimeError("secret internal detail"))
        assert out["type"] == "InternalError"
        assert "secret internal detail" not in out["error"]


class TestComputeActionFingerprint:
    def test_deterministic(self):
        a = security.compute_action_fingerprint(
            "tool_call", "s1", "ih", "oh", "2026-01-01T00:00:00"
        )
        b = security.compute_action_fingerprint(
            "tool_call", "s1", "ih", "oh", "2026-01-01T00:00:00"
        )
        assert a == b
        assert len(a) == 64  # sha256 hex

    def test_changes_with_input(self):
        a = security.compute_action_fingerprint("tool_call", "s1", "ih", "oh", "t")
        b = security.compute_action_fingerprint("tool_call", "s2", "ih", "oh", "t")
        assert a != b


class TestValidateExternalUrlGuard:
    def test_loopback_blocked(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with pytest.raises(ValueError):
            security.validate_external_url("http://127.0.0.1/hook")

    def test_override_allows_internal(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", "true")
        assert security.validate_external_url("http://127.0.0.1/hook") == "http://127.0.0.1/hook"

    def test_bad_scheme_rejected(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with pytest.raises(ValueError, match="http"):
            security.validate_external_url("ftp://example.com/x")
