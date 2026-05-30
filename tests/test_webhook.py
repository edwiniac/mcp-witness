"""
Tests for outbound webhook notifications (webhook.py) and the SSRF
validator they depend on (security.validate_external_url).

Covers:
- validate_external_url: blocks internal/loopback/link-local IP literals,
  rejects bad schemes / missing host, honors the allow-internal override,
  and handles the DNS resolution success/failure paths (mocked — no real DNS).
- notify_chain_failure: no-op when unconfigured, SSRF guard, and the
  success / non-success / timeout / request-error HTTP paths (mocked).
- SlackNotifier: is_configured, send_alert paths, chain-failure formatting.
- notify_chain_failure_slack convenience function.
"""

import os
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_witness.models import VerificationResult
from mcp_witness.security import validate_external_url
from mcp_witness.webhook import (
    SlackNotifier,
    notify_chain_failure,
    notify_chain_failure_slack,
)

# A fake public address tuple list shaped like socket.getaddrinfo output.
# (family, type, proto, canonname, sockaddr)
PUBLIC_ADDRINFO = [(2, 1, 6, "", ("8.8.8.8", 443))]


def _public_addrinfo(*_args, **_kwargs):
    """Stand-in for socket.getaddrinfo returning a public address."""
    return PUBLIC_ADDRINFO


def _make_result(records_checked=10, issues=None, valid=False):
    """Build a VerificationResult for notification tests."""
    return VerificationResult(
        valid=valid,
        records_checked=records_checked,
        first_invalid_sequence=3 if not valid else None,
        issues=issues if issues is not None else ["seq 3 hash mismatch"],
    )


# =========================================================================
# validate_external_url — SSRF guard
# =========================================================================


class TestValidateExternalUrl:
    """Tests for security.validate_external_url and its IP filter."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/x",  # loopback
            "http://10.0.0.5",  # private
            "http://192.168.1.1",  # private
            "http://172.16.0.1",  # private
            "http://169.254.169.254/",  # link-local / cloud metadata
            "http://0.0.0.0",  # unspecified
        ],
    )
    def test_blocks_internal_ip_literals(self, url, monkeypatch):
        """Internal/loopback/link-local IP literals raise ValueError."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with pytest.raises(ValueError):
            validate_external_url(url)

    def test_rejects_non_http_scheme(self, monkeypatch):
        """Non-http(s) schemes are rejected."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with pytest.raises(ValueError, match="http or https"):
            validate_external_url("ftp://example.com/x")

    def test_rejects_missing_host(self, monkeypatch):
        """A URL with no host is rejected."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with pytest.raises(ValueError, match="no host"):
            validate_external_url("https:///path-only")

    def test_allow_internal_override(self, monkeypatch):
        """MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS=true returns the URL unchanged."""
        monkeypatch.setenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", "true")
        url = "http://127.0.0.1/internal"
        assert validate_external_url(url) == url

    def test_public_host_resolution_passes(self, monkeypatch):
        """A host resolving to a public address passes (DNS mocked)."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr(
            "mcp_witness.security.socket.getaddrinfo",
            _public_addrinfo,
        )
        url = "https://hooks.example.com/services/abc"
        assert validate_external_url(url) == url

    def test_dns_resolution_failure(self, monkeypatch):
        """A host that fails to resolve raises ValueError."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)

        def _boom(*_args, **_kwargs):
            raise socket.gaierror("name resolution failed")

        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _boom)
        with pytest.raises(ValueError, match="could not be resolved"):
            validate_external_url("https://does-not-exist.invalid/x")

    def test_public_host_resolving_to_internal_blocked(self, monkeypatch):
        """A public hostname that resolves to an internal IP is blocked."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr(
            "mcp_witness.security.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))],
        )
        with pytest.raises(ValueError, match="blocked"):
            validate_external_url("https://rebind.example.com/x")


# =========================================================================
# notify_chain_failure
# =========================================================================


def _mock_response(is_success=True, status_code=200, text="ok"):
    resp = MagicMock()
    resp.is_success = is_success
    resp.status_code = status_code
    resp.text = text
    return resp


class TestNotifyChainFailure:
    """Tests for notify_chain_failure()."""

    async def test_no_op_when_unconfigured(self):
        """Returns True (no-op) when no webhook URL is configured."""
        with patch("mcp_witness.webhook.WEBHOOK_URL", ""):
            assert await notify_chain_failure(_make_result()) is True

    async def test_internal_url_blocked_returns_false(self, monkeypatch):
        """An internal webhook URL is refused by the SSRF guard (no request)."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        with (
            patch("mcp_witness.webhook.WEBHOOK_URL", "http://169.254.169.254/"),
            patch("httpx.AsyncClient.post", new=AsyncMock()) as mock_post,
        ):
            assert await notify_chain_failure(_make_result()) is False
            mock_post.assert_not_called()

    async def test_success(self, monkeypatch):
        """A public webhook URL with a successful response returns True."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        with (
            patch("mcp_witness.webhook.WEBHOOK_URL", "https://hooks.example.com/x"),
            patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=_mock_response(True, 200)),
            ) as mock_post,
        ):
            assert await notify_chain_failure(_make_result(), context={"db": "x"}) is True
            mock_post.assert_awaited_once()

    async def test_non_success_status(self, monkeypatch):
        """A non-success HTTP status returns False."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        with (
            patch("mcp_witness.webhook.WEBHOOK_URL", "https://hooks.example.com/x"),
            patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=_mock_response(False, 500, "boom")),
            ),
        ):
            assert await notify_chain_failure(_make_result()) is False

    async def test_timeout_returns_false(self, monkeypatch):
        """A request timeout returns False."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        with (
            patch("mcp_witness.webhook.WEBHOOK_URL", "https://hooks.example.com/x"),
            patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(side_effect=httpx.TimeoutException("timed out")),
            ),
        ):
            assert await notify_chain_failure(_make_result()) is False

    async def test_request_error_returns_false(self, monkeypatch):
        """A transport-level RequestError returns False."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        with (
            patch("mcp_witness.webhook.WEBHOOK_URL", "https://hooks.example.com/x"),
            patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(side_effect=httpx.RequestError("conn refused")),
            ),
        ):
            assert await notify_chain_failure(_make_result()) is False


# =========================================================================
# SlackNotifier
# =========================================================================


class TestSlackNotifier:
    """Tests for the SlackNotifier class."""

    def test_is_configured_with_url(self):
        """is_configured() is True when a URL is passed to the constructor."""
        assert SlackNotifier("https://hooks.slack.com/services/xxx").is_configured() is True

    def test_is_configured_unset(self):
        """is_configured() is False when no URL is provided or in env."""
        with patch.dict(os.environ, {}, clear=True):
            assert SlackNotifier().is_configured() is False

    def test_is_configured_from_env(self):
        """is_configured() reads the URL from the environment."""
        with patch.dict(
            os.environ,
            {"MCP_WITNESS_SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/env"},
            clear=True,
        ):
            assert SlackNotifier().is_configured() is True

    async def test_send_alert_unconfigured_returns_false(self):
        """send_alert returns False when not configured (no request)."""
        with patch.dict(os.environ, {}, clear=True):
            notifier = SlackNotifier()
            assert await notifier.send_alert("title", "body") is False

    async def test_send_alert_success(self, monkeypatch):
        """send_alert returns True on a successful response."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        notifier = SlackNotifier("https://hooks.slack.com/services/abc")
        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=_mock_response(True, 200)),
        ) as mock_post:
            assert await notifier.send_alert("Title", "Body", severity="critical") is True
            mock_post.assert_awaited_once()

    async def test_send_alert_non_success(self, monkeypatch):
        """send_alert returns False on a non-success response."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        notifier = SlackNotifier("https://hooks.slack.com/services/abc")
        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=_mock_response(False, 404, "no channel")),
        ):
            assert await notifier.send_alert("Title", "Body") is False

    async def test_send_alert_timeout(self, monkeypatch):
        """send_alert returns False on timeout."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        notifier = SlackNotifier("https://hooks.slack.com/services/abc")
        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(side_effect=httpx.TimeoutException("slow")),
        ):
            assert await notifier.send_alert("Title", "Body") is False

    async def test_send_alert_request_error(self, monkeypatch):
        """send_alert returns False on a request error."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        notifier = SlackNotifier("https://hooks.slack.com/services/abc")
        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(side_effect=httpx.RequestError("refused")),
        ):
            assert await notifier.send_alert("Title", "Body") is False

    async def test_send_alert_internal_url_blocked(self, monkeypatch):
        """send_alert refuses an internal URL via the SSRF guard."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        notifier = SlackNotifier("http://10.0.0.5/hook")
        with patch("httpx.AsyncClient.post", new=AsyncMock()) as mock_post:
            assert await notifier.send_alert("Title", "Body") is False
            mock_post.assert_not_called()

    async def test_send_chain_failure_alert(self, monkeypatch):
        """send_chain_failure_alert builds text from the result and sends it."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        notifier = SlackNotifier("https://hooks.slack.com/services/abc")
        result = _make_result(records_checked=42, issues=[f"issue {i}" for i in range(7)])
        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=_mock_response(True, 200)),
        ) as mock_post:
            assert await notifier.send_chain_failure_alert(result, context={"host": "h"}) is True

        # Inspect the payload that was POSTed.
        _, kwargs = mock_post.call_args
        text = kwargs["json"]["attachments"][0]["text"]
        assert "Records checked:* 42" in text
        assert "Issues found:* 7" in text
        assert "and 2 more issues" in text  # only first 5 listed
        assert kwargs["json"]["attachments"][0]["title"].endswith("mcp-witness")


# =========================================================================
# notify_chain_failure_slack convenience function
# =========================================================================


class TestNotifyChainFailureSlack:
    """Tests for the notify_chain_failure_slack convenience function."""

    async def test_no_op_when_unconfigured(self):
        """Returns False (no-op) when Slack is not configured."""
        with patch.dict(os.environ, {}, clear=True):
            assert await notify_chain_failure_slack(_make_result()) is False

    async def test_sends_when_configured(self, monkeypatch):
        """Sends the chain-failure alert when Slack is configured."""
        monkeypatch.delenv("MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS", raising=False)
        monkeypatch.setattr("mcp_witness.security.socket.getaddrinfo", _public_addrinfo)
        with (
            patch.dict(
                os.environ,
                {"MCP_WITNESS_SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/abc"},
                clear=True,
            ),
            patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=_mock_response(True, 200)),
            ) as mock_post,
        ):
            assert await notify_chain_failure_slack(_make_result()) is True
            mock_post.assert_awaited_once()
