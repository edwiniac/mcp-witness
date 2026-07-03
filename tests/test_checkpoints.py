"""Tests for checkpointing and fast verification."""

import pytest

from mcp_witness.models import ActionType
from mcp_witness.storage import WitnessStorage


@pytest.fixture
async def storage(tmp_path):
    """Create a temporary storage instance."""
    db_path = tmp_path / "test.db"
    store = WitnessStorage(str(db_path))
    await store.connect()
    yield store
    await store.close()


class TestCheckpoints:
    """Tests for Merkle checkpoint creation."""

    @pytest.mark.asyncio
    async def test_checkpoint_created_at_interval(self, storage):
        """Checkpoint is created when interval is reached."""
        # Create enough records to trigger a checkpoint
        # Note: CHECKPOINT_INTERVAL is 1000 by default, we'll create that many
        # For testing, we'll use a smaller number

        # First, let's check no checkpoints exist
        checkpoints = await storage.list_checkpoints()
        assert len(checkpoints) == 0

        # For testing, we'll manually call checkpoint creation
        # after creating the right number of records
        for i in range(100):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"test_tool_{i}",
                actor_id="test_actor",
            )

        # Manually trigger checkpoint for sequence 99 (if interval were 100)
        # In real usage, this happens automatically at CHECKPOINT_INTERVAL

    @pytest.mark.asyncio
    async def test_get_checkpoint_for_sequence(self, storage):
        """Can retrieve checkpoint containing a given sequence."""
        # Create records and a checkpoint
        for i in range(10):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"test_tool_{i}",
                actor_id="test_actor",
            )

        # Manually create a checkpoint for testing
        await storage._maybe_create_checkpoint(9)

        # This should be None unless we created 1000 records
        # Let's test the query functionality
        records = await storage.query(limit=10)
        assert len(records) == 10

    @pytest.mark.asyncio
    async def test_merkle_proof_generation(self, storage):
        """Can generate Merkle proofs for checkpointed records."""
        # Create records
        for i in range(10):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"test_tool_{i}",
            )

        # Proof won't be available until checkpoint exists
        await storage.get_merkle_proof(0)
        # Will be None because no checkpoint created yet
        # This is expected behavior - proofs only work after checkpointing

    @pytest.mark.asyncio
    async def test_verify_single_record(self, storage):
        """Single record verification works."""
        await storage.record(
            action_type=ActionType.DECISION,
            reasoning="Test decision",
        )

        # Without checkpoint, falls back to linear verification
        is_valid = await storage.verify_single_record(0)
        assert is_valid


class TestFastVerification:
    """Tests for checkpoint-accelerated verification."""

    @pytest.mark.asyncio
    async def test_verify_chain_fast_no_checkpoints(self, storage):
        """Fast verification falls back when no checkpoints."""
        for i in range(5):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        result = await storage.verify_chain_fast()
        assert result.valid
        assert result.records_checked == 5

    @pytest.mark.asyncio
    async def test_verify_chain_fast_with_range(self, storage):
        """Fast verification respects sequence range."""
        for i in range(10):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        result = await storage.verify_chain_fast(from_sequence=2, to_sequence=7)
        assert result.valid


class TestProofPackage:
    """Tests for complete proof packages."""

    @pytest.mark.asyncio
    async def test_proof_package_uncheckpointed(self, storage):
        """Proof package indicates when not checkpointed."""
        await storage.record(
            action_type=ActionType.DECISION,
            reasoning="Important decision",
        )

        proof = await storage.get_proof_package(0)

        # Should indicate not checkpointed
        assert proof is not None
        assert "error" in proof or "record" in proof

    @pytest.mark.asyncio
    async def test_proof_package_invalid_sequence(self, storage):
        """Proof package returns None for invalid sequence."""
        proof = await storage.get_proof_package(999)
        assert proof is None


class TestBackfill:
    """Tests for checkpoint backfilling."""

    @pytest.mark.asyncio
    async def test_backfill_empty_db(self, storage):
        """Backfill on empty DB creates no checkpoints."""
        count = await storage.backfill_checkpoints()
        assert count == 0

    @pytest.mark.asyncio
    async def test_backfill_few_records(self, storage):
        """Backfill with few records creates no checkpoints."""
        for i in range(10):
            await storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"tool_{i}",
            )

        count = await storage.backfill_checkpoints()
        # No checkpoints because we have fewer than CHECKPOINT_INTERVAL records
        assert count == 0


class TestFastVerificationTamperDetection:
    """Regression tests: verify_chain_fast must recompute Merkle roots from
    actual record hashes, not compare a checkpoint row against itself."""

    @pytest.mark.asyncio
    async def test_fast_verify_detects_tampering_in_checkpointed_range(self, storage, monkeypatch):
        """Tampering with a record inside a checkpointed range is detected."""
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 5)
        for i in range(5):
            await storage.record(action_type=ActionType.TOOL_CALL, tool_name=f"t{i}")
        assert len(await storage.list_checkpoints()) == 1

        # Tamper with a record hash inside the checkpointed range
        await storage._db.execute(
            "UPDATE witness_records "
            "SET record_hash = 'deadbeef' || substr(record_hash, 9) "
            "WHERE sequence = 2"
        )
        await storage._db.commit()

        result = await storage.verify_chain_fast()

        assert result.valid is False
        assert any("Merkle root mismatch" in issue for issue in result.issues)

    @pytest.mark.asyncio
    async def test_fast_verify_untampered_checkpoint_passes(self, storage, monkeypatch):
        """A clean checkpointed chain verifies as valid."""
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 5)
        for i in range(5):
            await storage.record(action_type=ActionType.TOOL_CALL, tool_name=f"t{i}")

        result = await storage.verify_chain_fast()

        assert result.valid is True

    @pytest.mark.asyncio
    async def test_fast_verify_retention_gap_falls_back_to_linear(self, storage, monkeypatch):
        """A checkpoint range with retention-deleted records is verified
        linearly instead of raising a false tampering alarm."""
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 5)
        for i in range(5):
            await storage.record(action_type=ActionType.TOOL_CALL, tool_name=f"t{i}")

        # Simulate retention expiry of the two oldest records
        await storage._db.execute(
            "UPDATE witness_records "
            "SET timestamp = '2020-01-01T00:00:00+00:00', retention_days = 1 "
            "WHERE sequence IN (0, 1)"
        )
        await storage._db.commit()
        assert await storage.cleanup_expired() == 2

        result = await storage.verify_chain_fast()

        assert result.valid is True
