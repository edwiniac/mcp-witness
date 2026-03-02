"""Tests for hasher module."""

import pytest
from datetime import datetime, timezone

from mcp_witness.hasher import (
    GENESIS_HASH,
    compute_record_hash,
    hash_data,
    is_genesis_record,
    redact_field,
    redact_fields,
    verify_chain_link,
    verify_record_hash,
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
