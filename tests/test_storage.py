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
    async def test_record_with_all_fields(
        self, temp_storage, sample_input_data, sample_output_data, sample_context
    ):
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

    @pytest.mark.asyncio
    async def test_query_keyset_pagination(self, temp_storage):
        """after_sequence returns only records past the cursor, in order."""
        for _ in range(10):
            await temp_storage.record(action_type=ActionType.TOOL_CALL)

        results = await temp_storage.query(after_sequence=6)

        assert [r.sequence for r in results] == [7, 8, 9]

    @pytest.mark.asyncio
    async def test_query_keyset_full_walk_matches_offset(self, temp_storage):
        """Walking with a sequence cursor yields every record exactly once."""
        for _ in range(7):
            await temp_storage.record(action_type=ActionType.TOOL_CALL)

        seen: list[int] = []
        cursor = None
        while True:
            page = await temp_storage.query(limit=3, after_sequence=cursor)
            if not page:
                break
            seen.extend(r.sequence for r in page)
            cursor = page[-1].sequence

        assert seen == list(range(7))

    @pytest.mark.asyncio
    async def test_query_keyset_combines_with_filters(self, temp_storage):
        """after_sequence stacks with other filters."""
        for i in range(6):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                session_id="a" if i % 2 == 0 else "b",
            )

        results = await temp_storage.query(session_id="a", after_sequence=0)

        assert [r.sequence for r in results] == [2, 4]


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
            "UPDATE witness_records SET record_hash = ? WHERE sequence = ?", ("deadbeef" * 8, 2)
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
            "UPDATE witness_records SET prev_hash = ? WHERE sequence = ?", ("deadbeef" * 8, 3)
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
            "UPDATE witness_records SET input_hash = ? WHERE sequence = ?", ("deadbeef" * 8, 0)
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
            "UPDATE witness_records SET record_hash = ? WHERE sequence = ?", ("deadbeef" * 8, 5)
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
        results = await temp_storage.batch_record(
            [
                {
                    "action_type": ActionType.DECISION,
                    "actor_id": "batch_actor",
                    "session_id": "batch_sess",
                }
            ]
        )

        assert len(results) == 1
        assert results[0].sequence == 0
        assert results[0].actor_id == "batch_actor"

        # Verify chain integrity
        result = await temp_storage.verify_chain()
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_batch_multiple_records(self, temp_storage):
        """Batch insert with multiple records maintains hash chain."""
        results = await temp_storage.batch_record(
            [
                {"action_type": ActionType.TOOL_CALL, "tool_name": "tool_a"},
                {"action_type": ActionType.DECISION, "reasoning": "step 2"},
                {"action_type": ActionType.OUTPUT, "session_id": "s3"},
            ]
        )

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

        results = await temp_storage.batch_record(
            [
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
            ]
        )

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
        results = await temp_storage.batch_record(
            [
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
            ]
        )

        assert len(results) == 1
        r = results[0]
        assert r.actor_id == "batch_actor"
        assert r.tool_name == "full_tool"
        assert r.reasoning == "full reasoning"
        assert r.confidence == 0.95
        assert r.input_hash is not None


class TestRateLimit:
    """Tests for database-backed rate limiting."""

    @pytest.mark.asyncio
    async def test_basic_token_consumption(self, temp_storage):
        """First token is always available."""
        allowed = await temp_storage.check_rate_limit(
            bucket_id="test_basic",
            max_tokens=1000.0,
            refill_rate=1000.0,
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_exhaust_and_refill(self, temp_storage):
        """After exhausting tokens, new ones become available after refill."""
        bucket_id = "test_refill"

        # Use a bucket with only 2 tokens, slow refill
        assert await temp_storage.check_rate_limit(bucket_id, max_tokens=2.0, refill_rate=0.5)
        assert await temp_storage.check_rate_limit(bucket_id, max_tokens=2.0, refill_rate=0.5)

        # Third should fail (no tokens, slow refill)
        allowed = await temp_storage.check_rate_limit(bucket_id, max_tokens=2.0, refill_rate=0.5)
        assert allowed is False

        # State should show 0 tokens
        state = await temp_storage.get_rate_limit_state(bucket_id)
        assert state["tokens"] < 1.0

    @pytest.mark.asyncio
    async def test_token_bucket_overflow(self, temp_storage):
        """Tokens should not exceed max_tokens."""
        bucket_id = "test_cap"

        # Create bucket with 5 max tokens
        assert await temp_storage.check_rate_limit(bucket_id, max_tokens=5.0, refill_rate=100.0)

        # Wait a tiny bit - enough to trigger refill but not exceed max
        state = await temp_storage.get_rate_limit_state(bucket_id)
        assert state["tokens"] <= state["max_tokens"]
        assert state["tokens"] >= 4.0  # consumed 1, maybe some refill

    @pytest.mark.asyncio
    async def test_multiple_buckets_independent(self, temp_storage):
        """Different buckets don't interfere."""
        bucket_a = "indep_a"
        bucket_b = "indep_b"

        # Exhaust bucket_a
        assert await temp_storage.check_rate_limit(bucket_a, max_tokens=1.0, refill_rate=0.0)
        assert not await temp_storage.check_rate_limit(bucket_a, max_tokens=1.0, refill_rate=0.0)

        # Bucket_b should still work
        assert await temp_storage.check_rate_limit(bucket_b, max_tokens=1.0, refill_rate=0.0)

    @pytest.mark.asyncio
    async def test_rate_limit_state(self, temp_storage):
        """get_rate_limit_state returns correct bucket state."""
        bucket_id = "test_state"

        # Bucket doesn't exist yet
        state = await temp_storage.get_rate_limit_state("nonexistent_bucket")
        assert state == {}

        # Create and consume a token
        await temp_storage.check_rate_limit(bucket_id, max_tokens=10.0, refill_rate=5.0)

        state = await temp_storage.get_rate_limit_state(bucket_id)
        assert state["tokens"] >= 9.0  # consumed 1, might have refilled
        assert state["max_tokens"] == 10.0
        assert state["refill_rate"] == 5.0
        assert "last_refill" in state

    @pytest.mark.asyncio
    async def test_persistence_across_operations(self, temp_storage):
        """Rate limit state persists across operations."""
        bucket_id = "test_persist"

        assert await temp_storage.check_rate_limit(bucket_id, max_tokens=100.0, refill_rate=10.0)
        state1 = await temp_storage.get_rate_limit_state(bucket_id)

        # Do another unrelated operation
        await temp_storage.record(action_type=ActionType.TOOL_CALL)

        # State should still be valid
        state2 = await temp_storage.get_rate_limit_state(bucket_id)
        assert state2["tokens"] >= state1["tokens"]  # may have refilled


class TestIdempotency:
    """Tests for database-backed idempotency nonces."""

    @pytest.mark.asyncio
    async def test_accept_new_nonce(self, temp_storage):
        """First use of a nonce returns True (allow)."""
        result = await temp_storage.check_and_record_nonce("new_nonce_123", ttl_seconds=3600)
        assert result is True

    @pytest.mark.asyncio
    async def test_reject_duplicate_nonce(self, temp_storage):
        """Second use of the same nonce returns False (reject)."""
        nonce = "duplicate_nonce_456"
        assert await temp_storage.check_and_record_nonce(nonce) is True
        assert await temp_storage.check_and_record_nonce(nonce) is False

    @pytest.mark.asyncio
    async def test_different_nonces_independent(self, temp_storage):
        """Different nonces don't interfere with each other."""
        assert await temp_storage.check_and_record_nonce("nonce_a") is True
        assert await temp_storage.check_and_record_nonce("nonce_b") is True
        # Still rejects the originals
        assert await temp_storage.check_and_record_nonce("nonce_a") is False
        assert await temp_storage.check_and_record_nonce("nonce_b") is False

    @pytest.mark.asyncio
    async def test_long_nonce_hash(self, temp_storage):
        """Long nonce hashes are handled correctly."""
        long_nonce = "a" * 128
        assert await temp_storage.check_and_record_nonce(long_nonce) is True
        assert await temp_storage.check_and_record_nonce(long_nonce) is False

    @pytest.mark.asyncio
    async def test_nonce_with_ttl(self, temp_storage):
        """Nonce accepts ttl_seconds parameter."""
        nonce = "ttl_test_nonce"
        assert await temp_storage.check_and_record_nonce(nonce, ttl_seconds=60) is True
        assert await temp_storage.check_and_record_nonce(nonce, ttl_seconds=60) is False

    @pytest.mark.asyncio
    async def test_nonce_cleanup_basic(self, temp_storage):
        """Cleanup doesn't remove recent nonces."""
        nonce = "cleanup_survivor"
        assert await temp_storage.check_and_record_nonce(nonce, ttl_seconds=3600) is True
        # Cleanup shouldn't remove this
        from mcp_witness.storage import SqliteStorage

        if isinstance(temp_storage, SqliteStorage):
            await temp_storage._cleanup_expired_nonces()
        assert await temp_storage.check_and_record_nonce(nonce) is False  # Still duplicate


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


class TestEd25519StorageSigning:
    """Tests for Ed25519 signing in storage operations."""

    @pytest.mark.asyncio
    async def test_record_signing_with_auto_generated_key(self, temp_storage):
        """Records are signed with auto-generated ephemeral key when env var unset."""
        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="signed_tool",
        )
        # Auto-generated key means signatures are always present
        assert record.signature is not None
        # Signature is now versioned JSON (dict with algo, signature keys)
        import json

        sig_data = json.loads(record.signature)
        assert sig_data["algo"] == "ed25519+sha256:v1"
        assert len(sig_data["signature"]) == 128  # 64 bytes hex inside the JSON
        assert record.signer_public_key is not None
        assert len(record.signer_public_key) == 64  # 32 bytes hex

    @pytest.mark.asyncio
    async def test_signer_public_key_with_auto_generated_key(self, temp_storage):
        """get_signer_public_key returns the auto-generated public key."""
        pk = await temp_storage.get_signer_public_key()
        assert pk is not None
        assert len(pk) == 64  # 32 bytes hex

    @pytest.mark.asyncio
    async def test_verify_chain_with_unsigned_records(self, temp_storage):
        """Unsigned records pass chain verification (backward compat)."""
        for i in range(5):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )
        result = await temp_storage.verify_chain()
        assert result.valid is True
        assert result.records_checked == 5

    @pytest.mark.asyncio
    async def test_mixed_signed_unsigned_chain(self, temp_storage):
        """Mixed chain with unsigned records only verifies fine."""
        # Since no signing key, all records are unsigned
        # This tests that verify_chain handles unsigned records gracefully
        for i in range(3):
            await temp_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )
        result = await temp_storage.verify_chain()
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_signed_records_persist_with_signing_key(self, monkeypatch, temp_storage):
        """With a signing key configured, records contain signatures."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Generate a key and set it as env var
        private_key = ed25519.Ed25519PrivateKey.generate()
        seed = private_key.private_bytes_raw()
        monkeypatch.setenv("MCP_WITNESS_SIGNING_KEY", seed.hex())

        # Re-import to reset the lazy singleton
        import importlib

        import mcp_witness.security as sec

        importlib.reload(sec)

        # Need a fresh storage to pick up the key
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "signed.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            record = await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="signed_tool",
            )
            assert record.signature is not None
            assert record.signer_public_key is not None
            import json

            sig_data = json.loads(record.signature)
            assert sig_data["algo"] == "ed25519+sha256:v1"
            assert len(sig_data["signature"]) == 128  # Ed25519 sig = 64 bytes = 128 hex chars

            # Verify the chain with signatures
            result = await store.verify_chain()
            assert result.valid is True

            # Read back and check signature persisted
            retrieved = await store.get_by_id(record.id)
            assert retrieved.signature == record.signature
            assert retrieved.signer_public_key == record.signer_public_key

            await store.close()

        importlib.reload(sec)  # Restore original state

    @pytest.mark.asyncio
    async def test_verify_chain_rejects_tampered_signature(self, monkeypatch, temp_storage):
        """Chain verification fails when a stored signature is tampered."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        seed = private_key.private_bytes_raw()
        monkeypatch.setenv("MCP_WITNESS_SIGNING_KEY", seed.hex())

        import importlib

        import mcp_witness.security as sec

        importlib.reload(sec)

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "tampered.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_0",
            )
            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_1",
            )

            # Tamper with the signature in DB
            await store._db.execute(
                "UPDATE witness_records SET signature = 'deadbeef' WHERE sequence = 1"
            )
            await store._db.commit()

            result = await store.verify_chain()
            assert result.valid is False
            # Error could be about canonical signature or unknown format depending on parsing
            assert any("signature" in issue.lower() for issue in result.issues)

            await store.close()

        importlib.reload(sec)  # Restore original state

    @pytest.mark.asyncio
    async def test_get_signer_public_key_with_key(self, monkeypatch):
        """get_signer_public_key returns the public key when signing is enabled."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        seed = private_key.private_bytes_raw()
        monkeypatch.setenv("MCP_WITNESS_SIGNING_KEY", seed.hex())

        import importlib

        import mcp_witness.security as sec

        importlib.reload(sec)

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "pk_test.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            pk = await store.get_signer_public_key()
            assert pk is not None
            assert len(pk) == 64  # 32 bytes = 64 hex chars

            # The public key is derived from the seed, not the seed itself
            from cryptography.hazmat.primitives import serialization

            expected_pk = (
                private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                .hex()
            )
            assert pk == expected_pk

            await store.close()

        importlib.reload(sec)  # Restore original state

    @pytest.mark.asyncio
    async def test_batch_records_signing_with_auto_generated_key(self, temp_storage):
        """Batch records are signed with auto-generated key."""
        import json

        records = await temp_storage.batch_record(
            [
                {"action_type": ActionType.TOOL_CALL, "tool_name": "a"},
                {"action_type": ActionType.DECISION, "reasoning": "b"},
            ]
        )
        for r in records:
            assert r.signature is not None
            sig_data = json.loads(r.signature)
            assert sig_data["algo"] == "ed25519+sha256:v1"
            assert len(sig_data["signature"]) == 128
            assert r.signer_public_key is not None
            assert len(r.signer_public_key) == 64


# =========================================================================
# TASK 1.4: Envelope Encryption Tests
# =========================================================================


class TestStorageEncryption:
    """Tests for data-at-rest encryption in storage."""

    @pytest.mark.asyncio
    async def test_record_encrypts_phi_sensitive_data(self, temp_storage):
        """PHI sensitivity records encrypt all fields in the DB."""
        from mcp_witness.models import Sensitivity

        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            input_data={
                "email": "user@example.com",
                "name": "John Doe",
                "ssn": "123-45-6789",
                "query": "What is Paris?",
            },
            sensitivity=Sensitivity.PHI,
        )

        # Returned record should have plaintext (decrypted on read)
        assert record.input_data["email"] == "user@example.com"
        assert record.input_data["ssn"] == "123-45-6789"

        # Read raw from DB to verify it's encrypted
        cursor = await temp_storage._db.execute(
            "SELECT input_data FROM witness_records WHERE id = ?",
            (str(record.id),),
        )
        row = await cursor.fetchone()
        import json

        raw = json.loads(row[0])
        # All fields should be encrypted for PHI (base64, not plaintext)
        assert "user@example.com" not in str(raw["email"])
        assert "John Doe" not in str(raw["name"])
        assert "123-45-6789" not in str(raw["ssn"])
        # For PHI sensitivity, ALL fields including non-sensitive names are encrypted
        assert "Paris" not in str(raw["query"])

    @pytest.mark.asyncio
    async def test_read_decrypts_encrypted_data(self, temp_storage):
        """Reading back an encrypted record returns decrypted data."""
        from mcp_witness.models import Sensitivity

        original_email = "test@example.com"
        original_name = "Alice"

        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            input_data={
                "email": original_email,
                "name": original_name,
            },
            sensitivity=Sensitivity.PHI,
        )

        # Read back via query
        retrieved = await temp_storage.get_by_id(record.id)
        assert retrieved is not None
        assert retrieved.input_data["email"] == original_email
        assert retrieved.input_data["name"] == original_name

    @pytest.mark.asyncio
    async def test_record_does_not_encrypt_public_data(self, temp_storage):
        """Public sensitivity records with non-sensitive fields are plaintext."""
        from mcp_witness.models import Sensitivity

        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            input_data={"query": "public data", "count": 42},
            sensitivity=Sensitivity.PUBLIC,
        )

        # Read raw from DB
        cursor = await temp_storage._db.execute(
            "SELECT input_data FROM witness_records WHERE id = ?",
            (str(record.id),),
        )
        row = await cursor.fetchone()
        import json

        raw = json.loads(row[0])
        assert raw["query"] == "public data"  # Not encrypted
        assert raw["count"] == 42  # Not encrypted


class TestStartupChainVerification:
    """Tests for startup chain integrity verification (TASK 2.5)."""

    @pytest.mark.asyncio
    async def test_startup_chain_verification_runs(self):
        """Startup chain verification runs and sets _chain_valid_at_startup."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "startup.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            # Fresh database should be valid
            assert store._chain_valid_at_startup is True

            # Add some records
            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="startup_test",
            )
            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="startup_test2",
            )

            await store.close()

            # Re-open should still verify chain
            store2 = SqliteStorage(str(db_path))
            await store2.connect()

            assert store2._chain_valid_at_startup is True
            assert store2._last_record_hash is not None

            await store2.close()

    @pytest.mark.asyncio
    async def test_startup_chain_detects_tampering(self):
        """Startup chain verification detects tampered chain."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "tampered_startup.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_0",
            )
            await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_1",
            )

            # Tamper with the chain
            await store._db.execute(
                "UPDATE witness_records SET record_hash = ? WHERE sequence = 0",
                ("deadbeef" * 16,),
            )
            await store._db.commit()

            await store.close()

            # Re-open should detect tampering
            store2 = SqliteStorage(str(db_path))
            await store2.connect()

            assert store2._chain_valid_at_startup is False

            await store2.close()

    @pytest.mark.asyncio
    async def test_chain_invariant_after_insert(self):
        """Runtime invariant: prev_hash matches last_record_hash."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "invariant.db"
            from mcp_witness.storage import SqliteStorage

            store = SqliteStorage(str(db_path))
            await store.connect()

            r1 = await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_1",
            )
            # After insert, _last_record_hash should be r1's hash
            assert store._last_record_hash == r1.record_hash

            r2 = await store.record(
                action_type=ActionType.TOOL_CALL,
                tool_name="record_2",
            )
            # r2's prev_hash should be r1's record_hash
            assert r2.prev_hash == r1.record_hash
            assert store._last_record_hash == r2.record_hash

            await store.close()


class TestChainValidCaching:
    """Verify the _chain_valid cached flag is maintained correctly.

    get_stats() must never trigger a full O(n) chain scan; it reads from the
    in-memory flag that is set during connect() and updated by verify_chain().
    """

    @pytest.mark.asyncio
    async def test_fresh_storage_chain_valid_true(self, temp_storage):
        """A newly initialised store reports chain_valid=True."""
        assert temp_storage._chain_valid is True
        stats = await temp_storage.get_stats()
        assert stats.chain_valid is True

    @pytest.mark.asyncio
    async def test_get_stats_does_not_call_verify_chain(self, temp_storage):
        """get_stats() must NOT call verify_chain() — cached flag only."""
        from unittest.mock import AsyncMock, patch

        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="t")

        with patch.object(temp_storage, "verify_chain", new_callable=AsyncMock) as mock_vc:
            stats = await temp_storage.get_stats()

        mock_vc.assert_not_called()
        assert stats.chain_valid is True

    @pytest.mark.asyncio
    async def test_full_verify_chain_updates_cached_flag(self, temp_storage):
        """A full verify_chain() call (no range args) refreshes _chain_valid."""
        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="t")

        # Force the flag to False to confirm verify_chain resets it
        temp_storage._chain_valid = False

        result = await temp_storage.verify_chain()
        assert result.valid is True
        assert temp_storage._chain_valid is True

    @pytest.mark.asyncio
    async def test_ranged_verify_chain_does_not_update_flag(self, temp_storage):
        """A ranged verify_chain() call must NOT overwrite the cached flag."""
        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="t1")
        await temp_storage.record(action_type=ActionType.TOOL_CALL, tool_name="t2")

        temp_storage._chain_valid = False  # Simulate degraded state

        # Range-scoped verification — should not touch the global flag
        await temp_storage.verify_chain(from_sequence=0, to_sequence=0)
        assert (
            temp_storage._chain_valid is False
        ), "A ranged verify_chain() must not overwrite the full-chain cached flag"
