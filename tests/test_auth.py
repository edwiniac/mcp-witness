"""Tests for authentication module — JWT claims, access modes, RBAC."""

import base64
import json
import os
import time
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


# ── Helper: construct a raw JWT with full control over claims ───────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_raw_jwt(
    private_key: ed25519.Ed25519PrivateKey,
    header: dict,
    payload: dict,
) -> str:
    """Construct and sign a JWT with arbitrary header and payload."""
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()
    signature = private_key.sign(message)
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ── Comprehensive JWT Boundary Tests ────────────────────────────────────

class TestJWTBoundaryCases:
    """Comprehensive boundary tests for verify_jwt_assertion strict claim validation.

    Each test verifies a specific rejection path in verify_jwt_assertion().
    These cover edge cases that go beyond basic create-then-verify roundtrips.
    """

    @pytest.fixture(autouse=True)
    def _setup_keys(self):
        """Generate a fresh Ed25519 keypair for each test."""
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.pk_hex = self.pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        self.sk_hex = self.sk.private_bytes_raw().hex()

    # ── Expired token ────────────────────────────────────────────────

    def test_jwt_rejects_expired_token(self):
        """Token with exp in the past is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex):
            token = create_jwt_token("agent", ttl_seconds=-1)
            assert token is not None
            assert verify_jwt_assertion(token) is None

    # ── Future iat ───────────────────────────────────────────────────

    def test_jwt_rejects_future_iat(self):
        """Token with iat > now+30s is rejected (future issuance)."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now + 120, "exp": now + 600, "role": "writer"}
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    def test_jwt_accepts_iat_within_clock_skew(self):
        """Token with iat slightly in future (≤30s) is accepted (clock skew tolerance)."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now + 15, "exp": now + 600, "role": "writer"}
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            result = verify_jwt_assertion(token)
            assert result is not None
            assert result["sub"] == "agent"

    # ── Wrong issuer ─────────────────────────────────────────────────

    def test_jwt_rejects_wrong_issuer(self):
        """Token with mismatched iss is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_ISSUER", "expected-issuer"):
            token = create_jwt_token("agent", issuer="wrong-issuer")
            assert token is not None
            assert verify_jwt_assertion(token) is None

    # ── Wrong audience ───────────────────────────────────────────────

    def test_jwt_rejects_wrong_audience(self):
        """Token with mismatched aud is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_AUDIENCE", "expected-audience"):
            token = create_jwt_token("agent", audience="wrong-audience")
            assert token is not None
            assert verify_jwt_assertion(token) is None

    # ── Missing required claims ──────────────────────────────────────

    @pytest.mark.parametrize("missing_claim", ["sub", "iat", "exp", "role"])
    def test_jwt_rejects_missing_required_claims(self, missing_claim):
        """Token without sub/iat/exp/role is rejected."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "writer"}
        del payload[missing_claim]
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    # ── Wrong algorithm ──────────────────────────────────────────────

    def test_jwt_rejects_wrong_alg(self):
        """Token with alg != 'EdDSA' is rejected."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "writer"}
        header = {"alg": "RS256", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    def test_jwt_rejects_none_alg(self):
        """Token with alg='none' is rejected (alg:none attack prevention)."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "writer"}
        header = {"alg": "none", "typ": "JWT"}
        # Sign anyway — the verifier rejects based on header, not signature
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    # ── Wrong type ───────────────────────────────────────────────────

    def test_jwt_rejects_wrong_typ(self):
        """Token with typ != 'JWT' is rejected."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "writer"}
        header = {"alg": "EdDSA", "typ": "JWE"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    # ── Tampered signature ───────────────────────────────────────────

    def test_jwt_rejects_tampered_signature(self):
        """Modify one byte of signature — token MUST be rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex):
            token = create_jwt_token("agent", ttl_seconds=600)
            assert token is not None
            # Modify one byte in the signature part
            parts = token.split(".")
            sig_raw = base64.urlsafe_b64decode(parts[2] + "==")
            sig_bytes = bytearray(sig_raw)
            sig_bytes[5] ^= 0x01  # flip one bit
            tampered_sig = _b64url_encode(bytes(sig_bytes))
            tampered = f"{parts[0]}.{parts[1]}.{tampered_sig}"
            assert verify_jwt_assertion(tampered) is None

    def test_jwt_rejects_payload_tampering(self):
        """Modify payload — token MUST be rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex):
            token = create_jwt_token("agent", ttl_seconds=600)
            assert token is not None
            parts = token.split(".")
            tampered = f"{parts[0]}.{parts[1]}X.{parts[2]}"
            assert verify_jwt_assertion(tampered) is None

    # ── nbf in future ────────────────────────────────────────────────

    def test_jwt_rejects_nbf_in_future(self):
        """Token with nbf > now is rejected (not-before constraint)."""
        now = int(time.time())
        payload = {
            "sub": "agent",
            "iat": now,
            "exp": now + 600,
            "role": "writer",
            "nbf": now + 300,  # not valid for another 5 minutes
        }
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    def test_jwt_accepts_past_nbf(self):
        """Token with nbf in the past is accepted."""
        now = int(time.time())
        payload = {
            "sub": "agent",
            "iat": now - 60,
            "exp": now + 600,
            "role": "writer",
            "nbf": now - 30,
        }
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            result = verify_jwt_assertion(token)
            assert result is not None
            assert result["sub"] == "agent"

    # ── Unknown role graceful degradation ────────────────────────────

    def test_jwt_rejects_unknown_role_graceful_degradation(self):
        """Token with role='superuser' defaults to AUDITOR via authenticate()."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "superuser"}
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.load_api_keys", return_value={}):
            # verify_jwt_assertion returns the payload as-is — it's authenticate()
            # that degrades unknown roles to AUDITOR
            result = verify_jwt_assertion(token)
            assert result is not None
            assert result["role"] == "superuser"  # verification succeeds

            # authenticate() degrades unknown roles
            role = authenticate(token=token)
            assert role == AuthRole.AUDITOR

    # ── Create-and-verify roundtrip with payload check ───────────────

    def test_jwt_create_and_verify_roundtrip(self):
        """Create token with create_jwt_token(), verify with verify_jwt_assertion()."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PRIVATE_KEY", self.sk_hex), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_ISSUER", "test-issuer"), \
             mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_AUDIENCE", "test-aud"):
            token = create_jwt_token("agent-42", role="admin", ttl_seconds=3600,
                                     issuer="test-issuer", audience="test-aud")
            assert token is not None
            payload = verify_jwt_assertion(token)
            assert payload is not None
            assert payload["sub"] == "agent-42"
            assert payload["role"] == "admin"
            assert payload["iss"] == "test-issuer"
            assert payload["aud"] == "test-aud"
            # Verify temporal claims are valid
            now = int(time.time())
            assert payload["iat"] <= now
            assert payload["exp"] > now

    # ── Max age exceeded ─────────────────────────────────────────────

    def test_jwt_max_age_exceeded(self):
        """Token older than MCP_WITNESS_JWT_MAX_AGE is rejected."""
        now = int(time.time())
        # Create a token issued in the past
        old_iat = now - 7200  # 2 hours ago
        payload = {"sub": "agent", "iat": old_iat, "exp": now + 600, "role": "writer"}
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        # Default max age is 3600 — our token is 7200s old → rejected
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    def test_jwt_within_max_age_accepted(self):
        """Token within MCP_WITNESS_JWT_MAX_AGE is accepted."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now - 1800, "exp": now + 600, "role": "writer"}
        header = {"alg": "EdDSA", "typ": "JWT"}
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            result = verify_jwt_assertion(token)
            assert result is not None

    # ── Malformed token edge cases ───────────────────────────────────

    def test_jwt_rejects_malformed_with_4_parts(self):
        """Token with 4 dot-separated parts is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion("a.b.c.d") is None

    def test_jwt_rejects_empty_token(self):
        """Empty token string is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion("") is None

    def test_jwt_rejects_garbage_header(self):
        """Token with non-JSON header is rejected."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            garbage_header = _b64url_encode(b"not-json")
            assert verify_jwt_assertion(f"{garbage_header}.payload.sig") is None

    def test_jwt_rejects_garbage_payload(self):
        """Token with non-JSON payload is rejected."""
        now = int(time.time())
        header_b64 = _b64url_encode(
            json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
        )
        garbage_payload = _b64url_encode(b"not-json")
        message = f"{header_b64}.{garbage_payload}".encode()
        sig_b64 = _b64url_encode(self.sk.sign(message))
        token = f"{header_b64}.{garbage_payload}.{sig_b64}"

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    # ── Missing header claims ────────────────────────────────────────

    def test_jwt_rejects_missing_alg_in_header(self):
        """Token without alg in header is rejected."""
        now = int(time.time())
        payload = {"sub": "agent", "iat": now, "exp": now + 600, "role": "writer"}
        header = {"typ": "JWT"}  # missing alg
        token = _make_raw_jwt(self.sk, header, payload)

        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", self.pk_hex):
            assert verify_jwt_assertion(token) is None

    # ── Public key not configured ────────────────────────────────────

    def test_jwt_rejects_when_public_key_empty(self):
        """Verification returns None when no public key is configured."""
        with mock.patch("mcp_witness.auth.MCP_WITNESS_JWT_PUBLIC_KEY", ""):
            assert verify_jwt_assertion("any.token.here") is None
