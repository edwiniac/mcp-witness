"""Tests for anchoring module."""

import hashlib
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_witness.anchoring import (
    SHA2_256_CODE,
    SHA2_256_LENGTH,
    AnchorReceipt,
    AnchorType,
    IPFSProvider,
    OpenTimestampsProvider,
    TSAProvider,
    _base58_encode,
    _build_tsa_request,
    _der_decode_length,
    _make_multihash,
    compute_ipfs_cidv0,
    compute_ipfs_cidv1,
)


class TestIPFSCID:
    """Tests for proper IPFS CID computation."""

    def test_cidv0_format(self):
        """CIDv0 should start with Qm and be base58 encoded multihash."""
        data = b"hello ipfs"
        cid = compute_ipfs_cidv0(data)
        assert cid.startswith("Qm"), f"CIDv0 should start with Qm, got {cid}"
        assert len(cid) == 46, f"CIDv0 should be 46 chars, got {len(cid)}"

    def test_cidv0_deterministic(self):
        """Same input always produces same CID."""
        data = json.dumps({"test": "data"}, sort_keys=True).encode()
        cid1 = compute_ipfs_cidv0(data)
        cid2 = compute_ipfs_cidv0(data)
        assert cid1 == cid2

    def test_cidv0_different_data_different_cid(self):
        """Different data produces different CIDs."""
        cid1 = compute_ipfs_cidv0(b"hello")
        cid2 = compute_ipfs_cidv0(b"world")
        assert cid1 != cid2

    def test_cidv1_format(self):
        """CIDv1 should start with b and be base32 encoded."""
        data = b"hello ipfs"
        cid = compute_ipfs_cidv1(data)
        assert cid.startswith("b"), f"CIDv1 should start with b, got {cid}"
        # base32 characters only (lowercase a-z, 2-7)
        for c in cid[1:]:
            assert c in "abcdefghijklmnopqrstuvwxyz234567", f"Invalid CIDv1 char: {c}"

    def test_cidv1_deterministic(self):
        """CIDv1 is also deterministic."""
        data = json.dumps({"test": "data"}, sort_keys=True).encode()
        cid1 = compute_ipfs_cidv1(data)
        cid2 = compute_ipfs_cidv1(data)
        assert cid1 == cid2

    def test_cids_match_between_formats(self):
        """CIDv0 and CIDv1 represent the same content hash."""
        data = json.dumps({"merkle_root": "abc123"}, sort_keys=True).encode()
        cid0 = compute_ipfs_cidv0(data)
        cid1 = compute_ipfs_cidv1(data)
        # Both should exist and be different formats of same data
        assert len(cid0) > 0
        assert len(cid1) > 0
        assert cid0 != cid1  # Different encodings

    def test_cidv0_no_slash_in_content(self):
        """CIDs should never contain slashes (path safety)."""
        for i in range(100):
            data = f"test_data_{i}".encode()
            cid = compute_ipfs_cidv0(data)
            assert "/" not in cid, f"CID should not contain slash: {cid}"
            assert "\\" not in cid, f"CID should not contain backslash: {cid}"


class TestBase58:
    """Tests for base58 encoding (used by CIDv0)."""

    def test_base58_empty_like(self):
        """Simple values encode correctly."""
        # Just verify it produces valid chars
        result = _base58_encode(b"test")
        for c in result:
            assert c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def test_base58_deterministic(self):
        """base58 is deterministic."""
        assert _base58_encode(b"abc") == _base58_encode(b"abc")

    def test_base58_different(self):
        """Different input = different encoding."""
        assert _base58_encode(b"abc") != _base58_encode(b"abd")


class TestMultihash:
    """Tests for multihash encoding."""

    def test_multihash_format(self):
        """Multihash wraps digest with type and length prefix."""
        digest = hashlib.sha256(b"test").digest()
        mh = _make_multihash(digest)

        # First byte = sha2-256 code (0x12)
        assert mh[0] == SHA2_256_CODE
        # Second byte = digest length (32)
        assert mh[1] == SHA2_256_LENGTH
        # Rest = digest
        assert mh[2:] == digest
        # Total length = 2 + 32 = 34
        assert len(mh) == 34


class TestTSADEREncoding:
    """Tests for RFC 3161 TimeStampReq DER encoding."""

    def test_tsa_request_structure(self):
        """TimeStampReq should be a valid DER SEQUENCE."""
        req = _build_tsa_request("a" * 64)
        # Must start with SEQUENCE tag (0x30)
        assert req[0] == 0x30, f"Expected 0x30 SEQUENCE tag, got {req[0]:#x}"

    def test_tsa_request_deterministic_nonce(self):
        """Each request should have a different nonce (different request)."""
        req1 = _build_tsa_request("a" * 64)
        req2 = _build_tsa_request("a" * 64)
        # Nonce makes them different
        assert req1 != req2, "Requests should differ due to random nonce"

    def test_tsa_request_different_hashes(self):
        """Different merkle roots produce different requests."""
        req1 = _build_tsa_request("a" * 64)
        req2 = _build_tsa_request("b" * 64)
        assert req1 != req2, "Different hashes should produce different requests"

    def test_tsa_request_size(self):
        """Request should be reasonable size (not huge)."""
        req = _build_tsa_request("0" * 64)
        # A TimeStampReq with SHA-256 should be under 100 bytes
        assert len(req) < 100, f"Request too large: {len(req)} bytes"

    def test_tsa_request_contains_hash(self):
        """Request should contain the merkle root hash."""
        merkle_root = "ab" * 32  # 64 hex chars
        req = _build_tsa_request(merkle_root)
        hash_bytes = bytes.fromhex(merkle_root)
        assert hash_bytes in req, "Request must contain the hash bytes"


class TestAnchorReceipt:
    """Tests for AnchorReceipt model."""

    def test_receipt_to_dict(self):
        """Receipt serializes to dict correctly."""
        from datetime import datetime, timezone

        receipt = AnchorReceipt(
            anchor_type=AnchorType.TSA,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="rec_001",
            verification_url="https://example.com/verify",
        )
        d = receipt.to_dict()
        assert d["anchor_type"] == "tsa"
        assert d["merkle_root"] == "abc123"
        assert d["receipt_id"] == "rec_001"

    def test_receipt_roundtrip(self):
        """Receipt survives dict roundtrip."""
        from datetime import datetime, timezone

        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="def456",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="QmTest123",
            metadata={"pinned": True},
        )
        d = receipt.to_dict()
        restored = AnchorReceipt.from_dict(d)
        assert restored.anchor_type == receipt.anchor_type
        assert restored.merkle_root == receipt.merkle_root
        assert restored.receipt_id == receipt.receipt_id


class TestDERDecodeLength:
    """Tests for DER length decoding."""

    def test_short_form(self):
        """Short form length (< 128)."""
        length, consumed = _der_decode_length(b"\x05", 0)
        assert length == 5
        assert consumed == 1

    def test_short_form_zero(self):
        """Short form zero length."""
        length, consumed = _der_decode_length(b"\x00", 0)
        assert length == 0
        assert consumed == 1

    def test_long_form_two_bytes(self):
        """Long form with 2 length bytes."""
        length, consumed = _der_decode_length(b"\x82\x01\x00", 0)
        assert length == 256
        assert consumed == 3

    def test_long_form_large(self):
        """Long form with larger value."""
        length, consumed = _der_decode_length(b"\x83\x10\x00\x01", 0)
        assert length == 0x100001
        assert consumed == 4

    def test_truncated_raises(self):
        """Truncated long form raises ValueError."""
        with pytest.raises(ValueError, match="out of bounds"):
            _der_decode_length(b"\x82", 0)

    def test_indefinite_raises(self):
        """Indefinite length (0x80) raises ValueError."""
        with pytest.raises(ValueError, match="Indefinite"):
            _der_decode_length(b"\x80\x00", 0)


class TestTSAVerify:
    """Tests for TSAProvider.verify()."""

    def _make_tsa_receipt(self, raw_receipt: bytes) -> AnchorReceipt:
        from datetime import datetime, timezone

        return AnchorReceipt(
            anchor_type=AnchorType.TSA,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="rec_001",
            raw_receipt=raw_receipt,
        )

    @pytest.mark.asyncio
    async def test_verify_none_receipt(self):
        """None raw_receipt should return False."""
        provider = TSAProvider()
        receipt = self._make_tsa_receipt(None)
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_empty_receipt(self):
        """Empty raw_receipt should return False."""
        provider = TSAProvider()
        receipt = self._make_tsa_receipt(b"")
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_valid_der_sequence(self):
        """Valid DER SEQUENCE with non-zero body should return True.

        A minimal valid TimeStampResp DER:
          SEQUENCE (0x30) {
            SEQUENCE (0x30) {  -- PKIStatusInfo
              INTEGER (0x02) { 0 }  -- status = granted
            }
          }
        """
        # Build: SEQUENCE { SEQUENCE { INTEGER 0 } }
        inner = bytes([0x30, 0x03, 0x02, 0x01, 0x00])
        raw = bytes([0x30]) + bytes([len(inner)]) + inner
        provider = TSAProvider()
        receipt = self._make_tsa_receipt(raw)
        assert await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_local_attestation(self):
        """Local attestation with matching merkle_root should return True."""
        provider = TSAProvider()
        attestation = json.dumps(
            {
                "version": "mcp-witness-tsa-v1",
                "merkle_root": "abc123",
                "timestamp": "2026-01-01T00:00:00+00:00",
            },
            sort_keys=True,
        ).encode()
        receipt = self._make_tsa_receipt(attestation)
        receipt.receipt_id = "local_test123"
        assert await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_local_attestation_wrong_root(self):
        """Local attestation with wrong merkle_root should return False."""
        provider = TSAProvider()
        attestation = json.dumps(
            {
                "version": "mcp-witness-tsa-v1",
                "merkle_root": "wrong_root",
                "timestamp": "2026-01-01T00:00:00+00:00",
            },
            sort_keys=True,
        ).encode()
        receipt = self._make_tsa_receipt(attestation)
        receipt.receipt_id = "local_test123"
        receipt.merkle_root = "abc123"
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_invalid_der_not_sequence(self):
        """DER data not starting with SEQUENCE should return False."""
        provider = TSAProvider()
        receipt = self._make_tsa_receipt(b"\x02\x01\x00")  # INTEGER, not SEQUENCE
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_der_zero_length_body(self):
        """SEQUENCE with zero-length body should return False."""
        provider = TSAProvider()
        receipt = self._make_tsa_receipt(b"\x30\x00")  # empty SEQUENCE
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_validate_der_receipt_rfc_example(self):
        """_validate_der_receipt properly validates a DER structure.

        Tests the static helper directly for structural validation.
        """
        # Valid: SEQUENCE { SEQUENCE { INTEGER 0 } }
        inner = bytes([0x30, 0x03, 0x02, 0x01, 0x00])
        raw = bytes([0x30]) + bytes([len(inner)]) + inner
        assert TSAProvider._validate_der_receipt(raw)

        # Invalid: not SEQUENCE
        assert not TSAProvider._validate_der_receipt(b"\x02\x01\x00")

        # Invalid: empty
        assert not TSAProvider._validate_der_receipt(b"")

        # Invalid: None-like (empty)
        assert not TSAProvider._validate_der_receipt(b"\x30")  # truncated


class TestOTSVerify:
    """Tests for OpenTimestampsProvider.verify()."""

    def _make_ots_receipt(self, raw_receipt: bytes) -> AnchorReceipt:
        from datetime import datetime, timezone

        return AnchorReceipt(
            anchor_type=AnchorType.OPENTIMESTAMPS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="ots_abc123",
            raw_receipt=raw_receipt,
        )

    def test_ots_parse_varint_small(self):
        """Small varint (< 128) parses correctly."""
        value, consumed = OpenTimestampsProvider._ots_parse_varint(b"\x2a", 0)
        assert value == 42
        assert consumed == 1

    def test_ots_parse_varint_multi_byte(self):
        """Multi-byte varint parses correctly."""
        # 0x80 | 0x01 = 128 + 1 = 129 in 7-bit chunks = 0x81 0x01
        value, consumed = OpenTimestampsProvider._ots_parse_varint(b"\x81\x01", 0)
        assert value == 129
        assert consumed == 2

    def test_ots_parse_varint_large(self):
        """Larger varint parses correctly."""
        # 0xAC 0x02 = (0x2C << 7) | 0x02 = 5632... no
        # 0xAC = 0b10101100 -> low 7 = 0b0101100 = 44, more = yes
        # 0x02 = 0b00000010 -> low 7 = 2, more = no
        # value = 44 | (2 << 7) = 44 + 256 = 300
        value, consumed = OpenTimestampsProvider._ots_parse_varint(b"\xac\x02", 0)
        assert value == 300
        assert consumed == 2

    def test_ots_parse_varint_truncated(self):
        """Truncated varint raises ValueError."""
        with pytest.raises(ValueError):
            OpenTimestampsProvider._ots_parse_varint(b"\x81", 0)

    @pytest.mark.asyncio
    async def test_verify_none_receipt(self):
        """None raw_receipt returns False."""
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(None)
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_empty_receipt(self):
        """Empty raw_receipt returns False."""
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(b"")
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_valid_ots_magic_bytes(self):
        """Receipt starting with OTS magic bytes returns True.

        A minimal OTS receipt: tag=0x00 (timestamp), varint length,
        empty sub-structure.
        """
        # tag=0x00, length=0 (empty timestamp)
        raw = b"\x00\x00"
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(raw)
        assert await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_valid_ots_with_content(self):
        """Receipt with valid OTS sub-structures returns True.

        Top-level timestamp containing a sub-timestamp:
          tag=0x00, varint length=2, sub: tag=0x01, varint length=0
        """
        # Top: tag=0x00, length=2, Sub: tag=0x01, length=0
        raw = b"\x00\x02\x01\x00"
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(raw)
        assert await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_invalid_ots_no_magic(self):
        """Receipt without OTS magic bytes returns False."""
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(b"\xff\x00random")
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_invalid_ots_truncated(self):
        """Truncated OTS structure returns False."""
        provider = OpenTimestampsProvider()
        # Tag says length 5 but only 3 bytes available
        raw = b"\x00\x05\x01"
        receipt = self._make_ots_receipt(raw)
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_ots_deeply_nested_valid(self):
        """Deeply nested but valid OTS structure returns True.

        Structure: timestamp( tag=0x00, len=4 ) ->
                     timestamp( tag=0x00, len=2 ) ->
                       attestation( tag=0x01, len=0 )
        """
        # Outer: tag=0x00, length=4, contains sub-timestamp
        # Sub:   tag=0x00, length=2, contains attestation
        # Att:   tag=0x01, length=0
        raw = b"\x00\x04\x00\x02\x01\x00"
        provider = OpenTimestampsProvider()
        receipt = self._make_ots_receipt(raw)
        assert await provider.verify(receipt)


class TestIPFSVerify:
    """Tests for IPFSProvider.verify()."""

    @pytest.mark.asyncio
    async def test_verify_no_url(self):
        """Receipt without verification_url returns False."""
        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="QmTest123",
            verification_url=None,
        )
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_no_receipt_id(self):
        """Receipt without receipt_id returns False."""
        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="",
            verification_url="https://ipfs.io/ipfs/QmTest123",
        )
        assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_fetch_success_cid_matches(self):
        """When content is fetched and CID matches, returns True."""
        content = json.dumps({"merkle_root": "abc123"}, sort_keys=True).encode()
        cid = compute_ipfs_cidv0(content)

        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id=cid,
            verification_url=f"https://ipfs.io/ipfs/{cid}",
        )

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.content = content
            mock_get.return_value = mock_response

            assert await provider.verify(receipt)
            mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_fetch_success_cid_mismatch(self):
        """When fetched content CID doesn't match receipt, returns False."""
        content = json.dumps({"merkle_root": "different"}, sort_keys=True).encode()

        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="QmTestDifferent",
            verification_url="https://ipfs.io/ipfs/QmTestDifferent",
        )

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.content = content
            mock_get.return_value = mock_response

            assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_fetch_fails_returns_false(self):
        """When GET fails, returns False (HEAD proves nothing)."""
        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="QmTestFallback",
            verification_url="https://ipfs.io/ipfs/QmTestFallback",
        )

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Connection failed")

            assert not await provider.verify(receipt)

    @pytest.mark.asyncio
    async def test_verify_fetch_fails_head_fails_too(self):
        """When GET fails, returns False (HEAD fallback removed)."""
        from datetime import datetime, timezone

        provider = IPFSProvider()
        receipt = AnchorReceipt(
            anchor_type=AnchorType.IPFS,
            merkle_root="abc123",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            receipt_id="QmTestFailAll",
            verification_url="https://ipfs.io/ipfs/QmTestFailAll",
        )

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Connection failed")

            assert not await provider.verify(receipt)


# =========================================================================
# TASK 1.1: TSA Fake Fallback Removal Tests
# =========================================================================


class TestTSAFailClosed:
    """Tests for TSA fail-closed behavior (TASK 1.1)."""

    @pytest.mark.asyncio
    async def test_tsa_fails_closed(self):
        """TSAProvider.anchor() must raise on failure, not create local attestation."""
        provider = TSAProvider(tsa_url="https://nonexistent-tsa.example.com/tsr", timeout=0.1)

        with pytest.raises(Exception):
            await provider.anchor("a" * 64, {})

    @pytest.mark.asyncio
    async def test_tsa_anchor_or_none_returns_none_on_failure(self):
        """TSAProvider.anchor_or_none() returns None on failure."""
        provider = TSAProvider(tsa_url="https://nonexistent-tsa.example.com/tsr", timeout=0.1)

        result = await provider.anchor_or_none("a" * 64, {})
        assert result is None

    def test_local_anchor_type_distinct_from_tsa(self):
        """AnchorType.LOCAL is distinct from AnchorType.TSA."""
        assert AnchorType.LOCAL != AnchorType.TSA
        assert AnchorType.LOCAL.value == "local"


# =========================================================================
# TASK 1.2: Anchor Strict Mode Tests
# =========================================================================


class TestAnchorStrictMode:
    """Tests for anchoring strict mode (TASK 1.2)."""

    @pytest.mark.asyncio
    async def test_tsa_strict_mode_fails_on_provider_error(self):
        """AnchorService.anchor() raises AnchorFailureError in strict mode."""
        from unittest.mock import patch

        from mcp_witness.anchoring import AnchorFailureError, AnchorService

        with patch.dict("os.environ", {"MCP_WITNESS_ANCHOR_STRICT": "true"}, clear=False):
            # Reload the module to pick up new env var
            import importlib

            import mcp_witness.security

            importlib.reload(mcp_witness.security)

            service = AnchorService()
            # Force TSA provider to fail by using unreachable URL
            provider = TSAProvider(tsa_url="https://nonexistent-tsa.example.com/tsr", timeout=0.1)
            service.add_provider(provider)

            with pytest.raises(AnchorFailureError) as exc_info:
                await service.anchor("a" * 64, {}, anchor_types=[AnchorType.TSA])
            assert len(exc_info.value.failures) > 0

        # Reset
        importlib.reload(mcp_witness.security)

    @pytest.mark.asyncio
    async def test_non_strict_mode_returns_partial_results(self):
        """With strict mode off, AnchorService returns partial results on failure."""
        from unittest.mock import patch

        from mcp_witness.anchoring import AnchorService

        with patch.dict(
            "os.environ", {"MCP_WITNESS_ANCHOR_STRICT": "false"}, clear=False
        ):
            import importlib

            import mcp_witness.security

            importlib.reload(mcp_witness.security)

            service = AnchorService()
            provider = TSAProvider(
                tsa_url="https://nonexistent-tsa.example.com/tsr", timeout=0.1
            )
            service.add_provider(provider)

            # Should not raise, should return empty receipts list (since all providers fail)
            receipts = await service.anchor(
                "a" * 64, {}, anchor_types=[AnchorType.TSA]
            )
            # In non-strict mode, partial results (possibly empty) are returned
            assert isinstance(receipts, list)

        importlib.reload(mcp_witness.security)
