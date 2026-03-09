"""Tests for mcp_witness.anchoring module."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_witness.anchoring import (
    AnchorReceipt,
    AnchorService,
    AnchorType,
    IPFSProvider,
    OpenTimestampsProvider,
    TSAProvider,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_ROOT = "a" * 64  # 64-char hex string (valid merkle root)


def _make_receipt(
    anchor_type: AnchorType = AnchorType.TSA,
    receipt_id: str = "abc123",
    raw_receipt: bytes = b"data",
    verification_url: str = None,
) -> AnchorReceipt:
    return AnchorReceipt(
        anchor_type=anchor_type,
        merkle_root=FAKE_ROOT,
        timestamp=datetime.now(timezone.utc),
        receipt_id=receipt_id,
        raw_receipt=raw_receipt,
        verification_url=verification_url,
    )


# ---------------------------------------------------------------------------
# TSAProvider
# ---------------------------------------------------------------------------


class TestTSAProvider:
    def test_default_timeout_from_default(self):
        provider = TSAProvider()
        assert provider.timeout == 30.0

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TSA_TIMEOUT", "15.0")
        provider = TSAProvider()
        assert provider.timeout == 15.0

    def test_explicit_timeout_overrides_env(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TSA_TIMEOUT", "15.0")
        provider = TSAProvider(timeout=5.0)
        assert provider.timeout == 5.0

    @pytest.mark.asyncio
    async def test_anchor_success_returns_receipt(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"tsa-response-bytes"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            provider = TSAProvider()
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.anchor_type == AnchorType.TSA
        assert receipt.merkle_root == FAKE_ROOT
        assert receipt.raw_receipt == b"tsa-response-bytes"
        assert not receipt.receipt_id.startswith("local_")

    @pytest.mark.asyncio
    async def test_anchor_network_failure_returns_local_fallback(self):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("unreachable"))
            mock_client_cls.return_value = mock_client

            provider = TSAProvider()
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.anchor_type == AnchorType.TSA
        assert receipt.receipt_id.startswith("local_")
        assert receipt.metadata.get("type") == "local_attestation"

    @pytest.mark.asyncio
    async def test_anchor_non_200_response_returns_local_fallback(self):
        mock_response = MagicMock()
        mock_response.status_code = 503

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            provider = TSAProvider()
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.receipt_id.startswith("local_")

    @pytest.mark.asyncio
    async def test_verify_local_attestation_valid(self):
        attestation = json.dumps({"merkle_root": FAKE_ROOT}).encode()
        receipt = _make_receipt(receipt_id="local_abc", raw_receipt=attestation)
        provider = TSAProvider()
        assert await provider.verify(receipt) is True

    @pytest.mark.asyncio
    async def test_verify_local_attestation_wrong_root(self):
        attestation = json.dumps({"merkle_root": "b" * 64}).encode()
        receipt = _make_receipt(receipt_id="local_abc", raw_receipt=attestation)
        provider = TSAProvider()
        assert await provider.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_local_attestation_invalid_json(self):
        receipt = _make_receipt(receipt_id="local_abc", raw_receipt=b"not-json")
        provider = TSAProvider()
        assert await provider.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_no_raw_receipt_returns_false(self):
        receipt = _make_receipt(raw_receipt=None)
        receipt.raw_receipt = None
        provider = TSAProvider()
        assert await provider.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_real_tsa_receipt_returns_true(self):
        receipt = _make_receipt(receipt_id="real_receipt", raw_receipt=b"asn1bytes")
        provider = TSAProvider()
        # Real receipts return True (full ASN.1 verification is out of scope)
        assert await provider.verify(receipt) is True


# ---------------------------------------------------------------------------
# OpenTimestampsProvider
# ---------------------------------------------------------------------------


class TestOpenTimestampsProvider:
    def test_default_timeout(self):
        provider = OpenTimestampsProvider()
        assert provider.timeout == 30.0

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_OTS_TIMEOUT", "20.0")
        provider = OpenTimestampsProvider()
        assert provider.timeout == 20.0

    @pytest.mark.asyncio
    async def test_anchor_first_server_succeeds(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"ots-receipt"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            provider = OpenTimestampsProvider()
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.anchor_type == AnchorType.OPENTIMESTAMPS
        assert receipt.merkle_root == FAKE_ROOT
        assert receipt.raw_receipt == b"ots-receipt"

    @pytest.mark.asyncio
    async def test_anchor_first_server_fails_falls_to_second(self):
        good_response = MagicMock()
        good_response.status_code = 200
        good_response.content = b"ots-receipt-server2"

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("server 1 down")
            return good_response

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = mock_post
            mock_client_cls.return_value = mock_client

            provider = OpenTimestampsProvider()
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.raw_receipt == b"ots-receipt-server2"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_anchor_all_servers_fail_raises(self):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("all down"))
            mock_client_cls.return_value = mock_client

            provider = OpenTimestampsProvider()
            with pytest.raises(RuntimeError, match="All OpenTimestamps servers failed"):
                await provider.anchor(FAKE_ROOT, {})

    @pytest.mark.asyncio
    async def test_verify_non_empty_receipt_is_true(self):
        receipt = _make_receipt(anchor_type=AnchorType.OPENTIMESTAMPS, raw_receipt=b"ots-data")
        provider = OpenTimestampsProvider()
        assert await provider.verify(receipt) is True

    @pytest.mark.asyncio
    async def test_verify_empty_receipt_is_false(self):
        receipt = _make_receipt(anchor_type=AnchorType.OPENTIMESTAMPS, raw_receipt=b"")
        provider = OpenTimestampsProvider()
        assert await provider.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_none_receipt_is_false(self):
        receipt = _make_receipt(anchor_type=AnchorType.OPENTIMESTAMPS, raw_receipt=None)
        receipt.raw_receipt = None
        provider = OpenTimestampsProvider()
        assert await provider.verify(receipt) is False


# ---------------------------------------------------------------------------
# IPFSProvider
# ---------------------------------------------------------------------------


class TestIPFSProvider:
    def test_default_timeout(self):
        provider = IPFSProvider()
        assert provider.timeout == 30.0

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_IPFS_TIMEOUT", "10.0")
        provider = IPFSProvider()
        assert provider.timeout == 10.0

    def test_local_digest_prefix(self):
        provider = IPFSProvider()
        digest = provider._compute_local_digest({"merkle_root": FAKE_ROOT})
        assert digest.startswith("local-")
        assert len(digest) > 10

    def test_local_digest_is_deterministic(self):
        provider = IPFSProvider()
        data = {"merkle_root": FAKE_ROOT, "ts": "2026"}
        assert provider._compute_local_digest(data) == provider._compute_local_digest(data)

    def test_local_digest_differs_for_different_data(self):
        provider = IPFSProvider()
        d1 = provider._compute_local_digest({"a": 1})
        d2 = provider._compute_local_digest({"a": 2})
        assert d1 != d2

    @pytest.mark.asyncio
    async def test_anchor_without_credentials_uses_local_digest(self):
        provider = IPFSProvider(api_key=None, api_secret=None)
        receipt = await provider.anchor(FAKE_ROOT, {})
        assert receipt.anchor_type == AnchorType.IPFS
        assert receipt.receipt_id.startswith("local-")
        assert receipt.verification_url is None

    @pytest.mark.asyncio
    async def test_anchor_with_pinata_credentials_calls_api(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={"IpfsHash": "QmRealHash123"})

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            provider = IPFSProvider(api_key="key", api_secret="secret")
            receipt = await provider.anchor(FAKE_ROOT, {})

        assert receipt.receipt_id == "QmRealHash123"
        assert receipt.verification_url == "https://ipfs.io/ipfs/QmRealHash123"

    @pytest.mark.asyncio
    async def test_anchor_pinata_non_200_raises(self):
        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            provider = IPFSProvider(api_key="key", api_secret="secret")
            with pytest.raises(Exception, match="Pinata"):
                await provider.anchor(FAKE_ROOT, {})

    @pytest.mark.asyncio
    async def test_verify_local_digest_no_url_returns_true(self):
        receipt = _make_receipt(
            anchor_type=AnchorType.IPFS,
            receipt_id="local-abc123",
            verification_url=None,
        )
        provider = IPFSProvider()
        assert await provider.verify(receipt) is True

    @pytest.mark.asyncio
    async def test_verify_non_local_no_url_returns_false(self):
        receipt = _make_receipt(
            anchor_type=AnchorType.IPFS,
            receipt_id="QmSomeRealHash",
            verification_url=None,
        )
        provider = IPFSProvider()
        assert await provider.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_with_url_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.head = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            receipt = _make_receipt(
                anchor_type=AnchorType.IPFS,
                receipt_id="QmHash",
                verification_url="https://ipfs.io/ipfs/QmHash",
            )
            provider = IPFSProvider()
            result = await provider.verify(receipt)

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_with_url_network_failure_returns_false(self):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.head = AsyncMock(side_effect=httpx.ConnectError("gateway down"))
            mock_client_cls.return_value = mock_client

            receipt = _make_receipt(
                anchor_type=AnchorType.IPFS,
                receipt_id="QmHash",
                verification_url="https://ipfs.io/ipfs/QmHash",
            )
            provider = IPFSProvider()
            result = await provider.verify(receipt)

        assert result is False


# ---------------------------------------------------------------------------
# AnchorService
# ---------------------------------------------------------------------------


class TestAnchorService:
    @pytest.mark.asyncio
    async def test_anchor_all_providers(self):
        receipt1 = _make_receipt(anchor_type=AnchorType.TSA, receipt_id="r1")
        receipt2 = _make_receipt(anchor_type=AnchorType.OPENTIMESTAMPS, receipt_id="r2")
        receipt3 = _make_receipt(anchor_type=AnchorType.IPFS, receipt_id="r3")

        p1 = AsyncMock()
        p1.anchor_type = AnchorType.TSA
        p1.anchor = AsyncMock(return_value=receipt1)

        p2 = AsyncMock()
        p2.anchor_type = AnchorType.OPENTIMESTAMPS
        p2.anchor = AsyncMock(return_value=receipt2)

        p3 = AsyncMock()
        p3.anchor_type = AnchorType.IPFS
        p3.anchor = AsyncMock(return_value=receipt3)

        service = AnchorService(providers=[p1, p2, p3])
        receipts = await service.anchor(FAKE_ROOT, {})
        assert len(receipts) == 3

    @pytest.mark.asyncio
    async def test_anchor_partial_failure_returns_successes(self):
        receipt1 = _make_receipt(anchor_type=AnchorType.TSA, receipt_id="r1")

        p1 = AsyncMock()
        p1.anchor_type = AnchorType.TSA
        p1.anchor = AsyncMock(return_value=receipt1)

        p2 = AsyncMock()
        p2.anchor_type = AnchorType.OPENTIMESTAMPS
        p2.name = "OTS"
        p2.anchor = AsyncMock(side_effect=RuntimeError("OTS failed"))

        service = AnchorService(providers=[p1, p2])
        receipts = await service.anchor(FAKE_ROOT, {})
        # Only the successful receipt is returned
        assert len(receipts) == 1
        assert receipts[0].receipt_id == "r1"

    @pytest.mark.asyncio
    async def test_anchor_with_type_filter(self):
        receipt_tsa = _make_receipt(anchor_type=AnchorType.TSA, receipt_id="tsa")

        p_tsa = AsyncMock()
        p_tsa.anchor_type = AnchorType.TSA
        p_tsa.anchor = AsyncMock(return_value=receipt_tsa)

        p_ots = AsyncMock()
        p_ots.anchor_type = AnchorType.OPENTIMESTAMPS
        p_ots.anchor = AsyncMock(return_value=_make_receipt(anchor_type=AnchorType.OPENTIMESTAMPS))

        service = AnchorService(providers=[p_tsa, p_ots])
        receipts = await service.anchor(FAKE_ROOT, {}, anchor_types=[AnchorType.TSA])
        assert len(receipts) == 1
        assert receipts[0].receipt_id == "tsa"

    @pytest.mark.asyncio
    async def test_verify_delegates_to_provider(self):
        mock_provider = AsyncMock()
        mock_provider.anchor_type = AnchorType.TSA
        mock_provider.verify = AsyncMock(return_value=True)

        service = AnchorService(providers=[mock_provider])
        receipt = _make_receipt(anchor_type=AnchorType.TSA)
        assert await service.verify(receipt) is True
        mock_provider.verify.assert_awaited_once_with(receipt)

    @pytest.mark.asyncio
    async def test_verify_unknown_provider_returns_false(self):
        service = AnchorService(providers=[])
        receipt = _make_receipt(anchor_type=AnchorType.TSA)
        assert await service.verify(receipt) is False

    @pytest.mark.asyncio
    async def test_verify_all(self):
        mock_provider = AsyncMock()
        mock_provider.anchor_type = AnchorType.TSA
        mock_provider.verify = AsyncMock(return_value=True)

        service = AnchorService(providers=[mock_provider])
        r1 = _make_receipt(anchor_type=AnchorType.TSA, receipt_id="r1")
        r2 = _make_receipt(anchor_type=AnchorType.TSA, receipt_id="r2")

        results = await service.verify_all([r1, r2])
        assert results == {"r1": True, "r2": True}

    def test_add_provider(self):
        service = AnchorService(providers=[])
        provider = MagicMock()
        provider.anchor_type = AnchorType.IPFS
        service.add_provider(provider)
        assert service.get_provider(AnchorType.IPFS) is provider

    def test_get_provider_missing_returns_none(self):
        service = AnchorService(providers=[])
        assert service.get_provider(AnchorType.TSA) is None
