"""Tests for authentication module — JWT claims, access modes, RBAC."""

import os
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from mcp_witness.auth import (
    AuthRole,
    authenticate,
    authorize,
    create_jwt_token,
    load_api_keys,
    verify_jwt_assertion,
)


# ── Real Ed25519 keypair for testing ─────────────────────────────────────
@pytest.fixture(scope="module")
def keypair():
    """Generate a real Ed25519 keypair for JWT tests."""
    sk = ed25519.Ed25519PrivateKey.generate()
    sk_hex = sk.private_bytes_raw().hex()
    pk = sk.public_key()
    pk_raw = pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    pk_hex = pk_raw.hex()
    return sk_hex, pk_hex


class TestJWTTokenCreation:
    """Tests for create_jwt_token."""

    def test_creates_valid_token(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ):
            token = create_jwt_token("test-agent", role="writer", ttl_seconds=3600)
            assert token is not None
            parts = token.split(".")
            assert len(parts) == 3

    def test_returns_none_without_private_key(self):
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", ""):
            token = create_jwt_token("test-agent")
            assert token is None

    def test_created_token_can_be_verified(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ):
            token = create_jwt_token("agent-7", role="auditor", ttl_seconds=60)
            assert token is not None
            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["sub"] == "agent-7"
            assert payload["role"] == "auditor"

    def test_includes_issuer_when_configured(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_ISSUER", "mcp-witness"):
            token = create_jwt_token("agent-1", issuer="mcp-witness")
            assert token is not None
            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["iss"] == "mcp-witness"


class TestJWTVerification:
    """Tests for verify_jwt_assertion with strict claim checks."""

    def test_rejects_if_public_key_not_configured(self):
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""):
            assert verify_jwt_assertion("fake.token.here") is None

    def test_rejects_bad_signature(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ):
            token = create_jwt_token("agent", ttl_seconds=60)
            assert token
            parts = token.split(".")
            bad_token = f"{parts[0]}.badpayload.{parts[2]}"
            assert verify_jwt_assertion(bad_token) is None

    def test_rejects_expired_token(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ):
            token = create_jwt_token("agent", ttl_seconds=-60)
            assert token
            assert verify_jwt_assertion(token) is None

    def test_valid_token_passes(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ):
            token = create_jwt_token("agent", ttl_seconds=60)
            assert token
            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["sub"] == "agent"

    def test_rejects_issuer_mismatch(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_ISSUER", "expected-issuer"):
            token = create_jwt_token("agent", issuer="wrong-issuer")
            assert token
            assert verify_jwt_assertion(token) is None

    def test_rejects_audience_mismatch(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_AUDIENCE", "expected-audience"):
            token = create_jwt_token("agent", audience="wrong-audience")
            assert token
            assert verify_jwt_assertion(token) is None

    def test_accepts_matching_issuer_and_audience(self, keypair):
        sk, pk = keypair
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", sk), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_ISSUER", "my-issuer"), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_AUDIENCE", "my-aud"
        ):
            token = create_jwt_token("agent", issuer="my-issuer", audience="my-aud")
            assert token
            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["iss"] == "my-issuer"
            assert payload["aud"] == "my-aud"


class TestDefaultAccessModes:
    """Tests for deny-by-default access control."""

    def test_deny_by_default_when_no_keys(self):
        with mock.patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "deny"
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""), mock.patch.dict(
            os.environ, {}, clear=True
        ), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            with pytest.raises(PermissionError, match="not configured"):
                authenticate()

    def test_admin_mode_for_local_dev(self):
        with mock.patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "admin"
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            role = authenticate()
            assert role == AuthRole.ADMIN

    def test_read_only_mode(self):
        with mock.patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "read_only"
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            role = authenticate()
            assert role == AuthRole.AUDITOR

    def test_invalid_default_access_raises(self):
        with mock.patch(
            "mcp_witness.auth.DEFAULT_ACCESS_MODE", "wide_open"
        ), mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            with pytest.raises(PermissionError):
                authenticate()

    def test_auth_required_raises_when_token_missing(self):
        """When API keys ARE configured but no token provided, should raise."""
        pk = "3b6a27bcceb6a42d62a3a8d02a6f0d7365321571de243a63ac048a18b59da29d"
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", pk), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            with mock.patch.dict(os.environ, {}, clear=False):
                with pytest.raises(PermissionError, match="Authentication required"):
                    authenticate()


class TestRBAC:
    """Tests for role-based access control."""

    def test_admin_can_use_all_tools(self):
        authorize(AuthRole.ADMIN, "witness_record")
        authorize(AuthRole.ADMIN, "witness_verify")
        authorize(AuthRole.ADMIN, "witness_export")

    def test_auditor_cannot_write(self):
        with pytest.raises(PermissionError):
            authorize(AuthRole.AUDITOR, "witness_record")

    def test_auditor_can_read(self):
        authorize(AuthRole.AUDITOR, "witness_query")
        authorize(AuthRole.AUDITOR, "witness_stats")

    def test_writer_can_write(self):
        authorize(AuthRole.WRITER, "witness_record")

    def test_writer_cannot_read(self):
        with pytest.raises(PermissionError):
            authorize(AuthRole.WRITER, "witness_query")


class TestAPIKeys:
    """Tests for API key loading."""

    def test_loads_valid_keys(self):
        with mock.patch.dict(os.environ, {
            "MCP_WITNESS_API_KEYS": (
                "key-admin-1234567890abcd:admin,"
                "key-audit-1234567890abcd:auditor,"
                "key-write-1234567890abcd:writer"
            )
        }):
            keys = load_api_keys()
            assert len(keys) == 3
            assert keys["key-admin-1234567890abcd"] == AuthRole.ADMIN
            assert keys["key-audit-1234567890abcd"] == AuthRole.AUDITOR
            assert keys["key-write-1234567890abcd"] == AuthRole.WRITER

    def test_skips_short_keys(self):
        with mock.patch.dict(os.environ, {
            "MCP_WITNESS_API_KEYS": "short:admin,good-key-1234567890:writer"
        }):
            keys = load_api_keys()
            assert "short" not in keys
            assert "good-key-1234567890" in keys

    def test_skips_unknown_roles(self):
        with mock.patch.dict(os.environ, {
            "MCP_WITNESS_API_KEYS": "test-key-1234567890:superuser"
        }):
            keys = load_api_keys()
            assert len(keys) == 0


class TestCheckAuthConfigured:
    """Tests for check_auth_configured startup guard."""

    def test_noop_when_not_required(self):
        from mcp_witness.auth import check_auth_configured

        with mock.patch("mcp_witness.auth.REQUIRE_AUTH", False):
            check_auth_configured()  # Should not raise

    def test_raises_when_required_but_no_keys(self):
        from mcp_witness.auth import check_auth_configured

        with mock.patch(
            "mcp_witness.auth.REQUIRE_AUTH", True
        ), mock.patch(
            "mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""
        ), mock.patch(
            "mcp_witness.auth.load_api_keys", return_value={}
        ):
            with pytest.raises(RuntimeError, match="no authentication is configured"):
                check_auth_configured()

    def test_passes_when_required_and_api_keys_configured(self):
        from mcp_witness.auth import check_auth_configured

        with mock.patch(
            "mcp_witness.auth.REQUIRE_AUTH", True
        ), mock.patch(
            "mcp_witness.auth.load_api_keys",
            return_value={"test-key-1234567890": AuthRole.WRITER},
        ):
            check_auth_configured()  # Should not raise
