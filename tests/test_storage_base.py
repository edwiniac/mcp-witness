"""Contract tests for the StorageBackend interface.

Any StorageBackend implementation must pass these tests.
"""
import pytest

from mcp_witness.models import ActionType, Sensitivity


@pytest.mark.asyncio
async def test_connect_and_close(temp_storage):
    """Backend can connect and close cleanly."""
    assert temp_storage._db is not None or hasattr(temp_storage, '_pool')


@pytest.mark.asyncio
async def test_record_and_retrieve(temp_storage):
    """Record can be written and read back."""
    record = await temp_storage.record(
        action_type=ActionType.DECISION,
        actor_id="test_actor",
        session_id="test_session",
        reasoning="test reasoning",
    )
    assert record.sequence == 0
    assert record.actor_id == "test_actor"

    retrieved = await temp_storage.get_by_id(record.id)
    assert retrieved is not None
    assert retrieved.sequence == 0
    assert retrieved.reasoning == "test reasoning"


@pytest.mark.asyncio
async def test_chain_integrity(temp_storage):
    """Hash chain links records correctly."""
    r1 = await temp_storage.record(action_type=ActionType.DECISION, actor_id="a")
    r2 = await temp_storage.record(action_type=ActionType.DECISION, actor_id="b")

    assert r1.sequence == 0
    assert r2.sequence == 1
    assert r2.prev_hash == r1.record_hash
    assert r1.record_hash and r2.record_hash
    assert r1.record_hash != r2.record_hash


@pytest.mark.asyncio
async def test_verify_valid_chain(temp_storage):
    """Verification passes on a valid chain."""
    for i in range(10):
        await temp_storage.record(action_type=ActionType.DECISION, actor_id=str(i))

    result = await temp_storage.verify_chain()
    assert result.valid is True
    assert result.records_checked >= 10


@pytest.mark.asyncio
async def test_verify_empty_chain(temp_storage):
    """Verification on empty chain returns valid."""
    result = await temp_storage.verify_chain()
    assert result.valid is True
    assert result.records_checked == 0


@pytest.mark.asyncio
async def test_query_by_session(temp_storage):
    """Query filters by session_id."""
    for _ in range(5):
        await temp_storage.record(action_type=ActionType.DECISION, session_id="s1")
    for _ in range(3):
        await temp_storage.record(action_type=ActionType.DECISION, session_id="s2")

    results_s1 = await temp_storage.query(session_id="s1")
    assert len(results_s1) == 5

    results_s2 = await temp_storage.query(session_id="s2")
    assert len(results_s2) == 3


@pytest.mark.asyncio
async def test_query_by_action_type(temp_storage):
    """Query filters by action_type."""
    for _ in range(3):
        await temp_storage.record(action_type=ActionType.DECISION)
    for _ in range(2):
        await temp_storage.record(action_type=ActionType.ERROR)

    decisions = await temp_storage.query(action_type=ActionType.DECISION)
    assert len(decisions) == 3

    errors = await temp_storage.query(action_type=ActionType.ERROR)
    assert len(errors) == 2


@pytest.mark.asyncio
async def test_query_with_limit(temp_storage):
    """Query respects limit parameter."""
    for _ in range(20):
        await temp_storage.record(action_type=ActionType.DECISION)

    results = await temp_storage.query(limit=5)
    assert len(results) == 5


@pytest.mark.asyncio
async def test_get_stats(temp_storage):
    """Stats reflect stored records."""
    for _ in range(5):
        await temp_storage.record(
            action_type=ActionType.DECISION,
            session_id="stats_session",
            actor_id="stats_actor",
        )

    stats = await temp_storage.get_stats()
    assert stats.total_records == 5
    assert stats.unique_sessions == 1
    assert stats.unique_actors == 1
    assert stats.chain_valid is True


@pytest.mark.asyncio
async def test_get_chain_for_session(temp_storage):
    """Chain returns records in order for a session."""
    for i in range(5):
        await temp_storage.record(
            action_type=ActionType.DECISION,
            session_id="chain_sess",
        )

    chain = await temp_storage.get_chain_for_session("chain_sess")
    assert len(chain) == 5
    for i, r in enumerate(chain):
        assert r.sequence == i


@pytest.mark.asyncio
async def test_tamper_detection(temp_storage):
    """Tampered record is detected by verify_chain."""
    for _ in range(5):
        await temp_storage.record(action_type=ActionType.DECISION)

    # Tamper with record 2's record_hash directly
    async with temp_storage._db.execute(
        "UPDATE witness_records SET record_hash = 'deadbeef' WHERE sequence = 2"
    ):
        pass
    await temp_storage._db.commit()

    result = await temp_storage.verify_chain()
    assert result.valid is False


@pytest.mark.asyncio
async def test_sensitivity_filtering(temp_storage):
    """Query filters by sensitivity level."""
    await temp_storage.record(action_type=ActionType.DECISION, sensitivity=Sensitivity.PUBLIC)
    await temp_storage.record(action_type=ActionType.DECISION, sensitivity=Sensitivity.PII)

    public = await temp_storage.query(sensitivity=Sensitivity.PUBLIC)
    assert len(public) == 1

    pii = await temp_storage.query(sensitivity=Sensitivity.PII)
    assert len(pii) == 1


# =========================================================================
# Rate Limiting Contract Tests
# =========================================================================

@pytest.mark.asyncio
async def test_check_rate_limit_exists(temp_storage):
    """Backend implements check_rate_limit."""
    assert hasattr(temp_storage, "check_rate_limit")
    result = await temp_storage.check_rate_limit(bucket_id="contract_test")
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_get_rate_limit_state_exists(temp_storage):
    """Backend implements get_rate_limit_state."""
    assert hasattr(temp_storage, "get_rate_limit_state")
    state = await temp_storage.get_rate_limit_state("contract_test")
    assert isinstance(state, dict)


@pytest.mark.asyncio
async def test_rate_limit_state_nonexistent(temp_storage):
    """Nonexistent bucket returns empty dict."""
    state = await temp_storage.get_rate_limit_state("does_not_exist")
    assert state == {}


# =========================================================================
# Idempotency Contract Tests
# =========================================================================

@pytest.mark.asyncio
async def test_check_and_record_nonce_exists(temp_storage):
    """Backend implements check_and_record_nonce."""
    assert hasattr(temp_storage, "check_and_record_nonce")
    result = await temp_storage.check_and_record_nonce("contract_nonce")
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_nonce_new_is_true(temp_storage):
    """New nonces return True."""
    result = await temp_storage.check_and_record_nonce("contract_new_nonce")
    assert result is True


@pytest.mark.asyncio
async def test_nonce_duplicate_is_false(temp_storage):
    """Duplicate nonces return False."""
    nonce = "contract_dup_nonce"
    assert await temp_storage.check_and_record_nonce(nonce) is True
    assert await temp_storage.check_and_record_nonce(nonce) is False
