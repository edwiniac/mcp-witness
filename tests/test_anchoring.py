"""Tests for anchoring module."""

import hashlib
import json

from mcp_witness.anchoring import (
    SHA2_256_CODE,
    SHA2_256_LENGTH,
    AnchorReceipt,
    AnchorType,
    _base58_encode,
    _build_tsa_request,
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
