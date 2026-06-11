"""Tests for the BufferedStorage wrapper."""

import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from mcp_witness.models import ActionType
from mcp_witness.storage import SqliteStorage
from mcp_witness.storage_base import StorageBackend

# Import BufferedStorage — may fail if asyncpg not installed
try:
    from mcp_witness.buffered import BufferedStorage

    BUFFERED_AVAILABLE = True
except ImportError:
    BUFFERED_AVAILABLE = False


@pytest_asyncio.fixture
async def buffered_storage():
    """Create a BufferedStorage wrapping a temporary SQLite backend."""
    if not BUFFERED_AVAILABLE:
        pytest.skip("BufferedStorage not available (missing dependency)")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_buffered.db"
        backend = SqliteStorage(db_path)
        await backend.connect()
        buffered = BufferedStorage(
            backend=backend,
            batch_size=10,
            flush_interval=0.1,
        )
        await buffered.connect()
        yield buffered
        await buffered.close()
        await backend.close()


@pytest.mark.asyncio
async def test_buffered_record_returns_immediately(buffered_storage):
    """BufferedStorage.record() returns a placeholder immediately."""
    placeholder = await buffered_storage.record(
        action_type=ActionType.DECISION,
        actor_id="test",
        session_id="buf_test",
    )
    assert placeholder is not None
    assert placeholder.actor_id == "test"


@pytest.mark.asyncio
async def test_buffered_records_eventually_persist(buffered_storage):
    """Records are flushed to backend after interval."""
    for i in range(5):
        await buffered_storage.record(
            action_type=ActionType.DECISION,
            actor_id=f"actor_{i}",
            session_id="persist_test",
        )
    await asyncio.sleep(0.5)
    stats = await buffered_storage.backend.get_stats()
    assert stats.total_records == 5


@pytest.mark.asyncio
async def test_buffered_query_proxies_to_backend(buffered_storage):
    """Query goes directly to backend."""
    for i in range(3):
        await buffered_storage.record(
            action_type=ActionType.DECISION,
            session_id="query_test",
        )
    await asyncio.sleep(0.5)
    results = await buffered_storage.query(session_id="query_test")
    assert len(results) == 3


@pytest.mark.asyncio
async def test_buffered_verify_chain(buffered_storage):
    """Verification works through buffered wrapper."""
    for i in range(20):
        await buffered_storage.record(action_type=ActionType.DECISION)
    await asyncio.sleep(0.5)
    result = await buffered_storage.verify_chain()
    assert result.valid is True


@pytest.mark.asyncio
async def test_buffered_flush_on_stop(buffered_storage):
    """Stop flushes all remaining records."""
    for i in range(25):
        await buffered_storage.record(action_type=ActionType.DECISION)
    # Record stats before closing (close() flushes then closes the backend)
    await asyncio.sleep(0.5)
    await buffered_storage.close()
    # Reconnect backend to verify persistence
    await buffered_storage.backend.connect()
    stats = await buffered_storage.backend.get_stats()
    assert stats.total_records == 25


@pytest.mark.asyncio
async def test_buffered_get_stats(buffered_storage):
    """Stats are proxied to backend."""
    for i in range(5):
        await buffered_storage.record(action_type=ActionType.DECISION)
    await asyncio.sleep(0.5)
    stats = await buffered_storage.get_stats()
    assert stats.total_records == 5


@pytest.mark.asyncio
async def test_buffered_is_subclass_of_storage_backend(buffered_storage):
    """BufferedStorage implements StorageBackend."""
    assert isinstance(buffered_storage, StorageBackend)


@pytest.mark.asyncio
async def test_close_drains_queue_larger_than_batch_size():
    """close() flushes ALL queued records, even beyond one batch."""
    if not BUFFERED_AVAILABLE:
        pytest.skip("BufferedStorage not available (missing dependency)")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_drain.db"
        backend = SqliteStorage(db_path)
        await backend.connect()
        buffered = BufferedStorage(backend=backend, batch_size=3, flush_interval=60.0)
        await buffered.connect()

        tasks = [
            asyncio.create_task(
                buffered.record(
                    action_type=ActionType.DECISION,
                    actor_id="drain-test",
                    session_id="drain",
                )
            )
            for _ in range(10)
        ]
        # Let all records enqueue before shutdown (long interval: no auto-flush)
        await asyncio.sleep(0.05)

        await buffered.close()
        records = await asyncio.gather(*tasks)
        assert len(records) == 10
        assert all(r.record_hash for r in records)

        await backend.connect()
        stats = await backend.get_stats()
        assert stats.total_records == 10
        await backend.close()


@pytest.mark.asyncio
async def test_flush_loop_idles_without_busy_spin(buffered_storage):
    """The flush loop sleeps between intervals instead of spinning."""
    flushes = 0
    original = buffered_storage._flush_now

    async def counting_flush():
        nonlocal flushes
        flushes += 1
        await original()

    buffered_storage._flush_now = counting_flush
    await asyncio.sleep(0.35)
    # flush_interval is 0.1s: expect ~3 wakeups, not hundreds
    assert flushes <= 10
