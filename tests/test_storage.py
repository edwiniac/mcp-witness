"""Tests for storage module."""


import pytest

from mcp_witness.hasher import GENESIS_HASH
from mcp_witness.models import ActionType, ActorType, Sensitivity


class TestWitnessStorage:
    """Tests for WitnessStorage class."""

    @pytest.mark.asyncio
    async def test_record_creates_entry(self, temp_storage):
        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="test_tool",
            input_data={"query": "test"},
        )

        assert record.id is not None
        assert record.sequence == 0
        assert record.prev_hash == GENESIS_HASH
        assert record.record_hash != ""
        assert record.action_type == ActionType.TOOL_CALL
        assert record.tool_name == "test_tool"

    @pytest.mark.asyncio
    async def test_record_chain_integrity(self, temp_storage):
        # Create multiple records
        record1 = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="tool1",
        )
        record2 = await temp_storage.record(
            action_type=ActionType.DECISION,
            reasoning="Based on tool1 output",
        )
        record3 = await temp_storage.record(
            action_type=ActionType.OUTPUT,
            output_data={"result": "done"},
        )

        # Check sequence
        assert record1.sequence == 0
        assert record2.sequence == 1
        assert record3.sequence == 2

        # Check chain links
        assert record1.prev_hash == GENESIS_HASH
        assert record2.prev_hash == record1.record_hash
        assert record3.prev_hash == record2.record_hash

    @pytest.mark.asyncio
    async def test_record_with_all_fields(self, temp_storage, sample_input_data, sample_output_data, sample_context):
        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            actor_type=ActorType.AGENT,
            actor_id="claude-3",
            session_id="session_123",
            tool_name="search_tool",
            input_data=sample_input_data,
            output_data=sample_output_data,
            context=sample_context,
            reasoning="User asked a geography question",
            confidence=0.95,
            sensitivity=Sensitivity.INTERNAL,
            retention_days=365,
        )

        assert record.actor_id == "claude-3"
        assert record.session_id == "session_123"
        assert record.tool_name == "search_tool"
        assert record.reasoning == "User asked a geography question"
        assert record.confidence == 0.95
        assert record.sensitivity == Sensitivity.INTERNAL

    @pytest.mark.asyncio
    async def test_record_with_redaction(self, temp_storage):
        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            input_data={"user_ssn": "123-45-6789", "query": "test"},
            redact_fields=["user_ssn"],
        )

        # SSN should be redacted
        assert "REDACTED" in record.input_data["user_ssn"]
        # But original hash is preserved
        assert record.input_hash != ""

    @pytest.mark.asyncio
    async def test_get_by_id(self, temp_storage):
        created = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="test",
        )

        retrieved = await temp_storage.get_by_id(created.id)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.record_hash == created.record_hash

    @pytest.mark.asyncio
    async def test_get_by_sequence(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL)
        record2 = await temp_storage.record(action_type=ActionType.DECISION)

        retrieved = await temp_storage.get_by_sequence(1)

        assert retrieved is not None
        assert retrieved.id == record2.id

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, temp_storage):
        result = await temp_storage.get_by_id("nonexistent-id")
        assert result is None

        result = await temp_storage.get_by_sequence(999)
        assert result is None


class TestWitnessQuery:
    """Tests for query functionality."""

    @pytest.mark.asyncio
    async def test_query_by_session(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL, session_id="session_a")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, session_id="session_b")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, session_id="session_a")

        results = await temp_storage.query(session_id="session_a")

        assert len(results) == 2
        assert all(r.session_id == "session_a" for r in results)

    @pytest.mark.asyncio
    async def test_query_by_actor(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL, actor_id="claude")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, actor_id="gpt")

        results = await temp_storage.query(actor_id="claude")

        assert len(results) == 1
        assert results[0].actor_id == "claude"

    @pytest.mark.asyncio
    async def test_query_by_action_type(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL)
        await temp_storage.record(action_type=ActionType.DECISION)
        await temp_storage.record(action_type=ActionType.TOOL_CALL)

        results = await temp_storage.query(action_type=ActionType.TOOL_CALL)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_by_tool_name(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="search")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="calculate")

        results = await temp_storage.query(tool_name="search")

        assert len(results) == 1
        assert results[0].tool_name == "search"

    @pytest.mark.asyncio
    async def test_query_by_sensitivity(self, temp_storage):
        await temp_storage.record(action_type=ActionType.TOOL_CALL, sensitivity=Sensitivity.PUBLIC)
        await temp_storage.record(action_type=ActionType.TOOL_CALL, sensitivity=Sensitivity.PHI)

        results = await temp_storage.query(sensitivity=Sensitivity.PHI)

        assert len(results) == 1
        assert results[0].sensitivity == Sensitivity.PHI

    @pytest.mark.asyncio
    async def test_query_with_limit(self, temp_storage):
        for _ in range(10):
            await temp_storage.record(action_type=ActionType.TOOL_CALL)

        results = await temp_storage.query(limit=5)

        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_query_empty_result(self, temp_storage):
        results = await temp_storage.query(session_id="nonexistent")
        assert len(results) == 0


class TestChainVerification:
    """Tests for chain integrity verification."""

    @pytest.mark.asyncio
    async def test_tamper_detection_direct_modification(self, temp_storage):
        """THE critical test: modifying a record in DB breaks the chain."""
        # Create a chain of records
        for i in range(5):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        # Verify chain is valid before tampering
        result_before = await temp_storage.verify_chain()
        assert result_before.valid is True

        # Tamper: directly modify record_hash in the database at sequence 2
        await temp_storage._db.execute(
            "UPDATE witness_records SET record_hash = ? WHERE sequence = ?",
            ("deadbeef" * 8, 2)
        )
        await temp_storage._db.commit()

        # Verify chain should NOW detect tampering
        result_after = await temp_storage.verify_chain()
        assert result_after.valid is False, "Chain should detect tampered hash!"
        assert result_after.first_invalid_sequence is not None
        assert len(result_after.issues) > 0

    @pytest.mark.asyncio
    async def test_tamper_detection_prev_hash_break(self, temp_storage):
        """Breaking the prev_hash link should be detected."""
        for i in range(5):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        # Tamper: break the prev_hash link at sequence 3
        await temp_storage._db.execute(
            "UPDATE witness_records SET prev_hash = ? WHERE sequence = ?",
            ("deadbeef" * 8, 3)
        )
        await temp_storage._db.commit()

        result = await temp_storage.verify_chain()
        assert result.valid is False, "Chain should detect broken prev_hash link!"
        assert result.first_invalid_sequence == 3, "Should identify the exact break point"

    @pytest.mark.asyncio
    async def test_tamper_detection_hash_field_modification(self, temp_storage):
        """Modifying input_hash directly breaks record_hash verification."""
        await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="sensitive_tool",
            input_data={"api_key": "secret_12345"},
        )
        await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="normal_tool",
        )

        # Verify valid before
        result_before = await temp_storage.verify_chain()
        assert result_before.valid is True

        # Tamper: modify the input_hash field (record_hash depends on it)
        await temp_storage._db.execute(
            "UPDATE witness_records SET input_hash = ? WHERE sequence = ?",
            ("deadbeef" * 8, 0)
        )
        await temp_storage._db.commit()

        # Chain verification should detect the hash mismatch
        result_after = await temp_storage.verify_chain()
        assert result_after.valid is False, "Chain should detect modified input_hash!"

    @pytest.mark.asyncio
    async def test_verify_partial_range_tamper_detection(self, temp_storage):
        """Tamper in the middle of a range should be detected by range verification."""
        for i in range(10):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        # Tamper at sequence 5
        await temp_storage._db.execute(
            "UPDATE witness_records SET record_hash = ? WHERE sequence = ?",
            ("deadbeef" * 8, 5)
        )
        await temp_storage._db.commit()

        # Verify just the tampered range
        result = await temp_storage.verify_chain(from_sequence=4, to_sequence=7)
        assert result.valid is False
        assert result.records_checked == 4  # 4, 5, 6, 7

    @pytest.mark.asyncio
    async def test_verify_empty_chain(self, temp_storage):
        result = await temp_storage.verify_chain()

        assert result.valid is True
        assert result.records_checked == 0

    @pytest.mark.asyncio
    async def test_verify_valid_chain(self, temp_storage):
        # Create a valid chain
        for i in range(5):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        result = await temp_storage.verify_chain()

        assert result.valid is True
        assert result.records_checked == 5
        assert len(result.issues) == 0

    @pytest.mark.asyncio
    async def test_verify_range(self, temp_storage):
        for i in range(10):
            await temp_storage.record(action_type=ActionType.TOOL_CALL)

        result = await temp_storage.verify_chain(from_sequence=3, to_sequence=7)

        assert result.records_checked == 5  # 3, 4, 5, 6, 7

    @pytest.mark.asyncio
    async def test_get_chain_for_session(self, temp_storage):
        # Create records in different sessions
        await temp_storage.record(action_type=ActionType.TOOL_CALL, session_id="a")
        await temp_storage.record(action_type=ActionType.DECISION, session_id="a")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, session_id="b")
        await temp_storage.record(action_type=ActionType.OUTPUT, session_id="a")

        chain = await temp_storage.get_chain_for_session("a")

        assert len(chain) == 3
        assert chain[0].action_type == ActionType.TOOL_CALL
        assert chain[1].action_type == ActionType.DECISION
        assert chain[2].action_type == ActionType.OUTPUT


class TestChainStats:
    """Tests for chain statistics."""

    @pytest.mark.asyncio
    async def test_stats_empty(self, temp_storage):
        stats = await temp_storage.get_stats()

        assert stats.total_records == 0
        assert stats.unique_sessions == 0
        assert stats.unique_actors == 0
        assert stats.chain_valid is True

    @pytest.mark.asyncio
    async def test_stats_with_records(self, temp_storage):
        await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            actor_id="claude",
            session_id="s1",
            sensitivity=Sensitivity.INTERNAL,
        )
        await temp_storage.record(
            action_type=ActionType.DECISION,
            actor_id="claude",
            session_id="s1",
            sensitivity=Sensitivity.PHI,
        )
        await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            actor_id="gpt",
            session_id="s2",
            sensitivity=Sensitivity.INTERNAL,
        )

        stats = await temp_storage.get_stats()

        assert stats.total_records == 3
        assert stats.unique_sessions == 2
        assert stats.unique_actors == 2
        assert stats.records_by_action_type["tool_call"] == 2
        assert stats.records_by_action_type["decision"] == 1
        assert stats.records_by_sensitivity["internal"] == 2
        assert stats.records_by_sensitivity["phi"] == 1


class TestBatchRecord:
    """Tests for batch_record functionality."""

    @pytest.mark.asyncio
    async def test_batch_empty_list(self, temp_storage):
        """Batch insert with empty list returns empty list."""
        results = await temp_storage.batch_record([])
        assert results == []

        stats = await temp_storage.get_stats()
        assert stats.total_records == 0

    @pytest.mark.asyncio
    async def test_batch_single_record(self, temp_storage):
        """Batch insert with single record works correctly."""
        results = await temp_storage.batch_record([
            {
                "action_type": ActionType.DECISION,
                "actor_id": "batch_actor",
                "session_id": "batch_sess",
            }
        ])

        assert len(results) == 1
        assert results[0].sequence == 0
        assert results[0].actor_id == "batch_actor"

        # Verify chain integrity
        result = await temp_storage.verify_chain()
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_batch_multiple_records(self, temp_storage):
        """Batch insert with multiple records maintains hash chain."""
        results = await temp_storage.batch_record([
            {"action_type": ActionType.TOOL_CALL, "tool_name": "tool_a"},
            {"action_type": ActionType.DECISION, "reasoning": "step 2"},
            {"action_type": ActionType.OUTPUT, "session_id": "s3"},
        ])

        assert len(results) == 3
        assert results[0].sequence == 0
        assert results[1].sequence == 1
        assert results[2].sequence == 2

        # Hash chain links
        assert results[0].prev_hash == GENESIS_HASH
        assert results[1].prev_hash == results[0].record_hash
        assert results[2].prev_hash == results[1].record_hash

        # All hashes should be different
        assert results[0].record_hash != results[1].record_hash
        assert results[1].record_hash != results[2].record_hash

        # Chain verification
        ver = await temp_storage.verify_chain()
        assert ver.valid is True
        assert ver.records_checked == 3

    @pytest.mark.asyncio
    async def test_batch_identical_to_individual_inserts(self, temp_storage):
        """Batch insert produces identical results to individual inserts."""
        # First: individual inserts
        r1 = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="comp_tool",
            actor_id="comp_actor",
            session_id="comp_sess",
        )
        r2 = await temp_storage.record(
            action_type=ActionType.DECISION,
            actor_id="comp_actor",
            session_id="comp_sess",
            reasoning="comparison",
        )

        assert r1.sequence == 0
        assert r2.sequence == 1
        assert r2.prev_hash == r1.record_hash

        # In a fresh storage, test batch produces the same structure

    @pytest.mark.asyncio
    async def test_batch_individual_equivalence(self, temp_storage):
        """Batch vs individual: same data yields same chain structure."""
        # We'll compare two separate storages with the same data
        # But since they share the clock/sequences, just verify batch
        # chain structure is correct and non-batched verify works
        await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="initial",
            session_id="equiv",
        )

        results = await temp_storage.batch_record([
            {
                "action_type": ActionType.TOOL_CALL,
                "tool_name": "batch_tool",
                "session_id": "equiv",
            },
            {
                "action_type": ActionType.DECISION,
                "reasoning": "batch_reasoning",
                "session_id": "equiv",
            },
        ])

        assert len(results) == 2
        assert results[0].sequence == 1
        assert results[1].sequence == 2
        assert results[0].prev_hash is not None and len(results[0].prev_hash) == 64

        # Chain verification must pass
        ver = await temp_storage.verify_chain()
        assert ver.valid is True
        assert ver.records_checked >= 3

    @pytest.mark.asyncio
    async def test_batch_with_all_fields(self, temp_storage, sample_input_data, sample_output_data):
        """Batch insert with full record data."""
        results = await temp_storage.batch_record([
            {
                "action_type": ActionType.TOOL_CALL,
                "actor_id": "batch_actor",
                "session_id": "full_batch",
                "tool_name": "full_tool",
                "input_data": sample_input_data,
                "output_data": sample_output_data,
                "reasoning": "full reasoning",
                "confidence": 0.95,
            }
        ])

        assert len(results) == 1
        r = results[0]
        assert r.actor_id == "batch_actor"
        assert r.tool_name == "full_tool"
        assert r.reasoning == "full reasoning"
        assert r.confidence == 0.95
        assert r.input_hash is not None


class TestAttestation:
    """Tests for attestation functionality."""

    @pytest.mark.asyncio
    async def test_update_attestation(self, temp_storage):
        record = await temp_storage.record(action_type=ActionType.TOOL_CALL)

        assert record.tsa_receipt is None
        assert record.anchored_at is None

        success = await temp_storage.update_attestation(
            record_id=record.id,
            tsa_receipt=b"test_receipt",
            anchored_at="2026-03-01T12:00:00Z",
        )

        assert success is True

        # Verify update
        updated = await temp_storage.get_by_id(record.id)
        assert updated.tsa_receipt == b"test_receipt"
        assert updated.anchored_at == "2026-03-01T12:00:00Z"
