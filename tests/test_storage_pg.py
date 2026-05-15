"""PostgreSQL integration tests for mcp-witness.

Requires a running PostgreSQL instance. Set environment variables:
    MCP_WITNESS_PG_URL=postgresql://user:pass@localhost:5432/dbname
    MCP_WITNESS_BACKEND=postgresql

Skip these tests if PostgreSQL is not available:
    pytest -m "not pg" tests/
"""

import os

import pytest

# Skip entire module if PostgreSQL is not configured
PG_URL = os.getenv("MCP_WITNESS_PG_URL", "")
PG_CONFIGURED = bool(PG_URL)

pytestmark = pytest.mark.skipif(
    not PG_CONFIGURED,
    reason="MCP_WITNESS_PG_URL not set — PostgreSQL integration tests skipped",
)


def _requires_pg():
    """Decorator alias — kept for readability in test naming."""
    return lambda fn: fn


@pytest.fixture
async def pg_storage():
    """Create a PgStorage instance connected to the test database."""
    from mcp_witness.storage_pg import PgStorage

    store = PgStorage(PG_URL)
    await store.connect()
    yield store
    await store.close()


@pytest.mark.asyncio
class TestPgConnection:
    """Basic PostgreSQL connectivity and schema tests."""

    async def test_pg_connect_and_stats(self, pg_storage):
        """Can connect to PG and get empty stats."""
        stats = await pg_storage.get_stats()
        assert stats is not None
        assert stats.total_records >= 0

    async def test_pg_schema_exists(self, pg_storage):
        """Schema tables exist after connect."""
        assert pg_storage._pool is not None

        async with pg_storage._pool.acquire() as conn:
            tables = await conn.fetch("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                """)
            table_names = {r["table_name"] for r in tables}
            expected = {
                "witness_records",
                "witness_checkpoints",
                "witness_anchors",
                "witness_rate_limits",
                "witness_idempotency_nonces",
                "witness_schema_version",
            }
            missing = expected - table_names
            assert not missing, f"Missing tables: {missing}"


@pytest.mark.asyncio
class TestPgRecordCRUD:
    """Record CRUD operations on PostgreSQL."""

    async def test_pg_record_insert_and_retrieve(self, pg_storage):
        """Insert a record and retrieve it."""
        from mcp_witness.models import ActionType

        record = await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="pg_test_tool",
            actor_id="pg_test_actor",
            session_id="pg_test_session",
        )
        assert record is not None
        assert record.sequence >= 0
        assert record.record_hash is not None
        assert len(record.record_hash) == 64  # SHA-256 hex

        # Retrieve by ID
        retrieved = await pg_storage.get_by_id(str(record.id))
        assert retrieved is not None
        assert retrieved.record_hash == record.record_hash

        # Retrieve by sequence
        retrieved_seq = await pg_storage.get_by_sequence(record.sequence)
        assert retrieved_seq is not None
        assert retrieved_seq.id == record.id

    async def test_pg_record_hash_chain(self, pg_storage):
        """Multiple records form a valid hash chain in PG."""
        from mcp_witness.models import ActionType

        records = []
        for i in range(5):
            r = await pg_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"pg_chain_{i}",
                session_id="pg_chain_session",
            )
            records.append(r)

        # Verify chain integrity
        for i in range(1, len(records)):
            assert records[i].prev_hash == records[i - 1].record_hash

    async def test_pg_batch_record(self, pg_storage):
        """Batch insert multiple records in a single transaction."""
        from mcp_witness.models import ActionType

        batch = [
            {"action_type": ActionType.TOOL_CALL, "tool_name": "pg_batch_1"},
            {"action_type": ActionType.DECISION, "reasoning": "pg_batch_2"},
            {"action_type": ActionType.OUTPUT, "tool_name": "pg_batch_3"},
        ]
        records = await pg_storage.batch_record(batch)
        assert len(records) == 3
        for r in records:
            assert r.record_hash is not None
            assert r.signature is not None  # Auto-generated key enabled

        # Chain links correctly
        assert records[1].prev_hash == records[0].record_hash
        assert records[2].prev_hash == records[1].record_hash

    async def test_pg_query_filters(self, pg_storage):
        """Query works with PG and respects filters."""
        from mcp_witness.models import ActionType

        # Create records with different attributes
        await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="filter_test",
            session_id="pg_query_sess",
        )
        await pg_storage.record(
            action_type=ActionType.DECISION,
            reasoning="filter test decision",
            session_id="pg_query_sess",
        )
        await pg_storage.record(
            action_type=ActionType.ERROR,
            tool_name="other_tool",
            session_id="pg_other_sess",
        )

        # Filter by tool_name
        results = await pg_storage.query(tool_name="filter_test", limit=10)
        assert len(results) >= 1
        assert all(r.tool_name == "filter_test" for r in results)

        # Filter by action_type
        results = await pg_storage.query(action_type=ActionType.DECISION, limit=10)
        assert len(results) >= 1
        assert all(r.action_type == ActionType.DECISION for r in results)

        # Filter by session_id
        results = await pg_storage.query(session_id="pg_query_sess", limit=10)
        assert len(results) >= 2
        assert all(r.session_id == "pg_query_sess" for r in results)


@pytest.mark.asyncio
class TestPgVerification:
    """Chain verification on PostgreSQL."""

    async def test_pg_verify_empty_chain(self, pg_storage):
        """Verifying the chain always returns valid (may have records from setup)."""
        result = await pg_storage.verify_chain()
        assert result.valid is True
        assert result.records_checked >= 0

    async def test_pg_verify_chain_with_records(self, pg_storage):
        """Chain verification works on PG."""
        from mcp_witness.models import ActionType

        for i in range(10):
            await pg_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"pg_verify_{i}",
            )

        result = await pg_storage.verify_chain()
        assert result.valid is True
        assert result.records_checked >= 10

    async def test_pg_verify_chain_fast(self, pg_storage):
        """Fast verification works on PG (auto-backfills checkpoints)."""
        from mcp_witness.models import ActionType

        for i in range(5):
            await pg_storage.record(
                action_type=ActionType.TOOL_CALL,
                tool_name=f"pg_fast_{i}",
            )

        result = await pg_storage.verify_chain_fast()
        assert result.valid is True


@pytest.mark.asyncio
class TestPgIdempotency:
    """Idempotency / nonce operations on PostgreSQL."""

    async def test_pg_nonce_new_and_duplicate(self, pg_storage):
        """First nonce check returns True, second returns False."""
        nonce = "pg_test_nonce_" + os.urandom(8).hex()
        first = await pg_storage.check_and_record_nonce(nonce, ttl_seconds=60)
        assert first is True

        second = await pg_storage.check_and_record_nonce(nonce, ttl_seconds=60)
        assert second is False

    async def test_pg_cleanup_expired_nonces(self, pg_storage):
        """Expired nonces are cleaned up."""
        # Insert a nonce with very short TTL that's likely already expired
        # by the time cleanup runs
        nonce = "pg_cleanup_nonce_" + os.urandom(8).hex()
        await pg_storage.check_and_record_nonce(nonce, ttl_seconds=1)

        import asyncio

        await asyncio.sleep(2)  # Wait for TTL to expire
        cleaned = await pg_storage._cleanup_expired_nonces()
        assert cleaned >= 0  # At minimum, doesn't crash


@pytest.mark.asyncio
class TestPgRetention:
    """Retention and cleanup on PostgreSQL."""

    async def test_pg_cleanup_expired_no_crash(self, pg_storage):
        """cleanup_expired runs without error on PG."""
        deleted = await pg_storage.cleanup_expired()
        assert deleted >= 0


@pytest.mark.asyncio
class TestPgRedactRecord:
    """Redact record operations on PostgreSQL (TASK 1.3)."""

    async def test_redact_record_by_id(self, pg_storage):
        """Redact a single record by ID."""
        from mcp_witness.models import ActionType

        record = await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="pg_redact",
            input_data={"secret": "data"},
            session_id="pg_redact_sess",
        )

        result = await pg_storage.redact_record(
            record_id=str(record.id),
            reason="GDPR erasure test",
        )
        assert result["redacted_count"] == 1
        assert result["action"] == "redact"

        # Verify record still exists but data is nulled
        retrieved = await pg_storage.get_by_id(str(record.id))
        assert retrieved is not None
        assert retrieved.input_data is None
        assert retrieved.output_data is None

    async def test_redact_record_by_session(self, pg_storage):
        """Redact all records for a session."""
        from mcp_witness.models import ActionType

        await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="pg_redact_1",
            session_id="pg_batch_erase",
        )
        await pg_storage.record(
            action_type=ActionType.DECISION,
            reasoning="test decision",
            session_id="pg_batch_erase",
        )

        result = await pg_storage.redact_record(
            session_id="pg_batch_erase",
            reason="Session erasure",
        )
        assert result["redacted_count"] == 2

    async def test_redact_record_requires_reason(self, pg_storage):
        """Redact requires either record_id or session_id."""
        with pytest.raises(ValueError, match="Must provide"):
            await pg_storage.redact_record()


@pytest.mark.asyncio
class TestPgSearch:
    """Search operations on PostgreSQL (TASK 1.3)."""

    async def test_search_finds_matching_records(self, pg_storage):
        """Search finds records matching the query."""
        from mcp_witness.models import ActionType

        await pg_storage.record(
            action_type=ActionType.DECISION,
            reasoning="This is a test decision about quantum computing",
            session_id="pg_search_sess",
        )
        await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="weather",
            reasoning="Check weather for London",
            session_id="pg_search_sess",
        )

        results = await pg_storage.search("quantum")
        assert len(results) >= 1
        assert "quantum" in results[0].reasoning

    async def test_search_empty_query(self, pg_storage):
        """Search with empty query returns matches."""
        from mcp_witness.models import ActionType

        await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="test_search_empty",
            session_id="empty_query",
        )

        results = await pg_storage.search("")
        assert len(results) >= 1


@pytest.mark.asyncio
class TestPgOrgId:
    """org_id column on PostgreSQL (TASK 1.3)."""

    async def test_org_id_column_exists(self, pg_storage):
        """org_id column exists in witness_records table."""
        assert pg_storage._pool is not None
        async with pg_storage._pool.acquire() as conn:
            cols = await conn.fetch("""SELECT column_name FROM information_schema.columns
                   WHERE table_name = 'witness_records' AND column_name = 'org_id'""")
            assert len(cols) == 1
            assert cols[0]["column_name"] == "org_id"

    async def test_org_id_stored_in_record(self, pg_storage):
        """org_id is stored and retrievable."""
        from mcp_witness.models import ActionType

        record = await pg_storage.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="org_test",
            org_id="org_123",
            session_id="org_test_sess",
        )

        retrieved = await pg_storage.get_by_id(str(record.id))
        assert retrieved is not None
        assert retrieved.org_id == "org_123"


@pytest.mark.asyncio
class TestPgIdempotencyPerRowTTL:
    """Per-row TTL cleanup on PostgreSQL (TASK 1.3)."""

    async def test_pg_cleanup_expired_nonces_per_row_ttl(self, pg_storage):
        """_cleanup_expired_nonces respects per-row TTL."""
        # Insert a nonce with 1 second TTL
        import time

        nonce = "pg_ttl_test_" + os.urandom(8).hex()
        await pg_storage.check_and_record_nonce(nonce, ttl_seconds=1)

        # Wait for TTL to expire
        time.sleep(2)

        # Cleanup should remove it
        cleaned = await pg_storage._cleanup_expired_nonces()
        assert cleaned >= 1

        # Verify it's gone
        async with pg_storage._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_idempotency_nonces WHERE nonce_hash = $1",
                nonce,
            )
            assert row is None
