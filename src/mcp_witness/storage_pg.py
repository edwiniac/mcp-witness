"""PostgreSQL storage backend for mcp-witness using asyncpg."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import asyncpg

from .anchoring import AnchorReceipt, AnchorService, AnchorType
from .hasher import GENESIS_HASH, compute_record_hash, hash_data
from .merkle import (
    MerkleTree,
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
)
from .models import (
    ActionType,
    ActorType,
    Anchor,
    ChainStats,
    Checkpoint,
    Sensitivity,
    VerificationResult,
    WitnessRecord,
)
from .security import (
    check_idempotency,
    check_rate_limit,
    compute_action_fingerprint,
    validate_inputs,
)
from .storage_base import StorageBackend

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHECKPOINT_INTERVAL = int(os.getenv("MCP_WITNESS_CHECKPOINT_INTERVAL", "1000"))
AUTO_ANCHOR = os.getenv("MCP_WITNESS_AUTO_ANCHOR", "false").lower() == "true"

# Payload size limit (10 MB default)
MAX_PAYLOAD_SIZE = int(os.getenv("MCP_WITNESS_MAX_PAYLOAD_SIZE", str(10 * 1024 * 1024)))

# Session ID validation
MAX_SESSION_ID_LENGTH = 256
ALLOWED_SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]*$")

# Connection pool settings
PG_POOL_MIN_SIZE = int(os.getenv("MCP_WITNESS_PG_POOL_MIN", "2"))
PG_POOL_MAX_SIZE = int(os.getenv("MCP_WITNESS_PG_POOL_MAX", "10"))

# Default connection URL
DEFAULT_PG_URL = os.getenv("MCP_WITNESS_PG_URL", "postgresql://user:pass@localhost:5432/witness")


def _validate_session_id(session_id: str) -> None:
    """Validate session_id to prevent storage anomalies."""
    if not session_id:
        return  # Empty is allowed
    if len(session_id) > MAX_SESSION_ID_LENGTH:
        raise ValueError(
            f"session_id exceeds maximum length of {MAX_SESSION_ID_LENGTH}"
        )
    if not ALLOWED_SESSION_ID_PATTERN.match(session_id):
        raise ValueError(
            "session_id contains invalid characters; "
            "allowed: alphanumeric, underscore, hyphen, colon, period"
        )


def _validate_payload_size(data: Optional[dict], label: str = "data") -> None:
    """Validate payload does not exceed size limit."""
    if data is None:
        return
    size = len(json.dumps(data, default=str).encode())
    if size > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"{label} size ({size} bytes) exceeds limit ({MAX_PAYLOAD_SIZE} bytes)"
        )


def _serialize_json(value: Optional[dict | list]) -> Optional[str]:
    """Serialize a dict/list to JSON string for storage, or None."""
    if value is None:
        return None
    return json.dumps(value, default=str)


def _deserialize_json(value: Optional[str | bytes]) -> Optional[dict | list]:
    """Deserialize a JSON string/bytes from storage, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return json.loads(value.decode())
    return json.loads(value)


class PgStorage(StorageBackend):
    """PostgreSQL-backed storage for witness records with hash chain integrity.

    Implements the StorageBackend interface using asyncpg with connection
    pooling. Provides the same feature set as SqliteStorage but for
    production PostgreSQL deployments.
    """

    def __init__(self, dsn: str | None = None):
        """
        Initialize the storage.

        Args:
            dsn: PostgreSQL connection string. Defaults to MCP_WITNESS_PG_URL env var.
        """
        self.dsn = dsn or DEFAULT_PG_URL
        self._pool: Optional[asyncpg.Pool] = None
        self._anchor_service: Optional[AnchorService] = None

    async def connect(self) -> None:
        """Connect to PostgreSQL and ensure schema exists."""
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=PG_POOL_MIN_SIZE,
            max_size=PG_POOL_MAX_SIZE,
        )
        await self._create_schema()
        self._anchor_service = AnchorService()

    async def close(self) -> None:
        """Close the PostgreSQL connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def _create_schema(self) -> None:
        """Create database tables and indexes if they don't exist."""
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS witness_records (
                    id UUID PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    sequence BIGSERIAL UNIQUE NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,

                    actor_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,

                    action_type TEXT NOT NULL,
                    tool_name TEXT,
                    input_data JSONB,
                    output_data JSONB,
                    input_hash TEXT NOT NULL,
                    output_hash TEXT NOT NULL,

                    context JSONB,
                    reasoning TEXT,
                    confidence DOUBLE PRECISION,

                    sensitivity TEXT NOT NULL,
                    retention_days INTEGER NOT NULL,
                    tsa_receipt BYTEA,
                    anchored_at TEXT,

                    redacted_fields JSONB,

                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_pg_sequence ON witness_records(sequence);
                CREATE INDEX IF NOT EXISTS idx_pg_timestamp ON witness_records(timestamp);
                CREATE INDEX IF NOT EXISTS idx_pg_session_id ON witness_records(session_id);
                CREATE INDEX IF NOT EXISTS idx_pg_actor_id ON witness_records(actor_id);
                CREATE INDEX IF NOT EXISTS idx_pg_action_type ON witness_records(action_type);
                CREATE INDEX IF NOT EXISTS idx_pg_tool_name ON witness_records(tool_name);
                CREATE INDEX IF NOT EXISTS idx_pg_sensitivity ON witness_records(sensitivity);

                CREATE TABLE IF NOT EXISTS witness_checkpoints (
                    id SERIAL PRIMARY KEY,
                    from_sequence BIGINT NOT NULL,
                    to_sequence BIGINT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    record_count INTEGER NOT NULL,
                    last_record_hash TEXT NOT NULL,
                    tree_data JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW(),

                    UNIQUE(from_sequence, to_sequence)
                );

                CREATE INDEX IF NOT EXISTS idx_pg_checkpoint_range
                    ON witness_checkpoints(from_sequence, to_sequence);

                CREATE TABLE IF NOT EXISTS witness_anchors (
                    id SERIAL PRIMARY KEY,
                    checkpoint_id INTEGER NOT NULL,
                    anchor_type TEXT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    verification_url TEXT,
                    raw_receipt BYTEA,
                    cost_usd DOUBLE PRECISION DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    verified_at TIMESTAMPTZ,
                    is_valid BOOLEAN DEFAULT TRUE,
                    metadata JSONB,

                    FOREIGN KEY (checkpoint_id) REFERENCES witness_checkpoints(id)
                );

                CREATE INDEX IF NOT EXISTS idx_pg_anchor_checkpoint ON witness_anchors(checkpoint_id);
                CREATE INDEX IF NOT EXISTS idx_pg_anchor_type ON witness_anchors(anchor_type);
            """)

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    async def _get_last_record(self, conn: asyncpg.Connection) -> Optional[asyncpg.Record]:
        """Get the last record in the chain within an open connection."""
        return await conn.fetchrow(
            "SELECT * FROM witness_records ORDER BY sequence DESC LIMIT 1"
        )

    async def _get_next_sequence(self, conn: asyncpg.Connection) -> int:
        """Get the next sequence number."""
        last = await self._get_last_record(conn)
        if last:
            return last["sequence"] + 1
        return 0

    def _row_to_record(self, row: asyncpg.Record) -> WitnessRecord:
        """Convert a PostgreSQL row to a WitnessRecord."""
        return WitnessRecord(
            id=row["id"],
            timestamp=row["timestamp"],
            sequence=row["sequence"],
            prev_hash=row["prev_hash"],
            record_hash=row["record_hash"],
            actor_type=ActorType(row["actor_type"]),
            actor_id=row["actor_id"],
            session_id=row["session_id"],
            action_type=ActionType(row["action_type"]),
            tool_name=row["tool_name"],
            input_data=_deserialize_json(row["input_data"]),
            output_data=_deserialize_json(row["output_data"]),
            input_hash=row["input_hash"],
            output_hash=row["output_hash"],
            context=_deserialize_json(row["context"]),
            reasoning=row["reasoning"],
            confidence=row.get("confidence"),
            sensitivity=Sensitivity(row["sensitivity"]),
            retention_days=row["retention_days"],
            tsa_receipt=row.get("tsa_receipt"),
            anchored_at=row.get("anchored_at"),
            redacted_fields=_deserialize_json(row.get("redacted_fields")) or [],
        )

    # =========================================================================
    # Record CRUD
    # =========================================================================

    async def record(
        self,
        action_type: ActionType,
        actor_type: ActorType = ActorType.AGENT,
        actor_id: str = "unknown",
        session_id: str = "",
        tool_name: Optional[str] = None,
        input_data: Optional[dict] = None,
        output_data: Optional[dict] = None,
        context: Optional[dict] = None,
        reasoning: Optional[str] = None,
        confidence: Optional[float] = None,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        retention_days: int = 365,
        redact_fields: Optional[list[str]] = None,
    ) -> WitnessRecord:
        """
        Record a new action to the witness chain.

        Uses explicit transactions to prevent race conditions where concurrent
        writers could create duplicate sequence numbers and fork the chain.
        """
        from uuid import uuid4

        from .hasher import redact_fields as do_redact

        # Input validation
        _validate_session_id(session_id)
        _validate_payload_size(input_data, "input_data")
        _validate_payload_size(output_data, "output_data")
        _validate_payload_size(context, "context")
        validate_inputs(session_id, actor_id, reasoning)

        # Rate limiting
        check_rate_limit()

        # Compute hashes early (needed for idempotency check)
        input_hash = hash_data(input_data) if input_data else ""
        output_hash = hash_data(output_data) if output_data else ""
        timestamp = datetime.now(timezone.utc)

        # Idempotency check (prevent replay attacks)
        action_fp = compute_action_fingerprint(
            action_type=action_type.value,
            session_id=session_id,
            input_hash=input_hash,
            output_hash=output_hash,
            timestamp=timestamp.isoformat(),
        )
        if not check_idempotency(action_fp):
            raise ValueError("Duplicate action detected. Action already recorded recently.")

        # Process data
        redacted_fields = redact_fields or []
        processed_input = do_redact(input_data, redacted_fields) if input_data else None
        processed_output = do_redact(output_data, redacted_fields) if output_data else None

        record_id = uuid4()

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Get chain state inside the transaction
                last_record = await self._get_last_record(conn)
                prev_hash = last_record["record_hash"] if last_record else GENESIS_HASH
                sequence = (last_record["sequence"] + 1) if last_record else 0

                record_hash = compute_record_hash(
                    prev_hash=prev_hash,
                    sequence=sequence,
                    timestamp=timestamp,
                    action_type=action_type.value,
                    actor_id=actor_id,
                    input_hash=input_hash,
                    output_hash=output_hash,
                    tool_name=tool_name,
                )

                await conn.execute(
                    """
                    INSERT INTO witness_records (
                        id, timestamp, sequence, prev_hash, record_hash,
                        actor_type, actor_id, session_id,
                        action_type, tool_name, input_data, output_data,
                        input_hash, output_hash,
                        context, reasoning, confidence,
                        sensitivity, retention_days, tsa_receipt, anchored_at,
                        redacted_fields
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                              $11, $12, $13, $14, $15, $16, $17, $18, $19,
                              $20, $21, $22)
                    """,
                    record_id,
                    timestamp,
                    sequence,
                    prev_hash,
                    record_hash,
                    actor_type.value,
                    actor_id,
                    session_id,
                    action_type.value,
                    tool_name,
                    _serialize_json(processed_input),
                    _serialize_json(processed_output),
                    input_hash,
                    output_hash,
                    _serialize_json(context),
                    reasoning,
                    confidence,
                    sensitivity.value,
                    retention_days,
                    None,  # tsa_receipt
                    None,  # anchored_at
                    _serialize_json(redacted_fields),
                )

        # Create record object
        record = WitnessRecord(
            id=record_id,
            timestamp=timestamp,
            sequence=sequence,
            prev_hash=prev_hash,
            record_hash=record_hash,
            actor_type=actor_type,
            actor_id=actor_id,
            session_id=session_id,
            action_type=action_type,
            tool_name=tool_name,
            input_data=processed_input,
            output_data=processed_output,
            input_hash=input_hash,
            output_hash=output_hash,
            context=context,
            reasoning=reasoning,
            confidence=confidence,
            sensitivity=sensitivity,
            retention_days=retention_days,
            redacted_fields=redacted_fields,
        )

        # Check if we should create a checkpoint (outside the transaction)
        await self._maybe_create_checkpoint(record.sequence)

        return record

    async def get_by_id(self, record_id: str | UUID) -> Optional[WitnessRecord]:
        """Get a record by its ID."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_records WHERE id = $1",
                UUID(str(record_id)),
            )
            return self._row_to_record(row) if row else None

    async def get_by_sequence(self, sequence: int) -> Optional[WitnessRecord]:
        """Get a record by its sequence number."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_records WHERE sequence = $1",
                sequence,
            )
            return self._row_to_record(row) if row else None

    async def query(
        self,
        session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        sensitivity: Optional[Sensitivity] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[WitnessRecord]:
        """Query records with filters."""
        conditions: list[str] = []
        params: list = []
        param_idx = 1

        def add_param(value) -> str:
            nonlocal param_idx
            placeholder = f"${param_idx}"
            param_idx += 1
            params.append(value)
            return placeholder

        if session_id is not None:
            conditions.append(f"session_id = {add_param(session_id)}")
        if actor_id is not None:
            conditions.append(f"actor_id = {add_param(actor_id)}")
        if tool_name is not None:
            conditions.append(f"tool_name = {add_param(tool_name)}")
        if action_type is not None:
            conditions.append(f"action_type = {add_param(action_type.value)}")
        if sensitivity is not None:
            conditions.append(f"sensitivity = {add_param(sensitivity.value)}")
        if from_time is not None:
            conditions.append(f"timestamp >= {add_param(from_time)}")
        if to_time is not None:
            conditions.append(f"timestamp <= {add_param(to_time)}")

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        limit_ph = add_param(limit)
        offset_ph = add_param(offset)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT * FROM witness_records
                WHERE {where_clause}
                ORDER BY sequence ASC
                LIMIT {limit_ph} OFFSET {offset_ph}
                """,
                *params,
            )
            return [self._row_to_record(row) for row in rows]

    # =========================================================================
    # Chain Verification
    # =========================================================================

    async def verify_chain(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """Verify the integrity of the hash chain."""
        conditions: list[str] = []
        params: list = []
        param_idx = 1

        def add_param(value) -> str:
            nonlocal param_idx
            placeholder = f"${param_idx}"
            param_idx += 1
            params.append(value)
            return placeholder

        if from_sequence is not None:
            conditions.append(f"sequence >= {add_param(from_sequence)}")
        if to_sequence is not None:
            conditions.append(f"sequence <= {add_param(to_sequence)}")

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM witness_records WHERE {where_clause} ORDER BY sequence ASC",
                *params,
            )

            if not rows:
                return VerificationResult(valid=True, records_checked=0)

            issues: list[str] = []
            records_checked = 0
            first_invalid = None

            # Determine expected prev_hash for the first record in range
            first_record = self._row_to_record(rows[0])
            first_sequence = first_record.sequence
            if first_sequence > 0:
                prev_row = await conn.fetchrow(
                    "SELECT record_hash FROM witness_records WHERE sequence = $1",
                    first_sequence - 1,
                )
                prev_hash = prev_row["record_hash"] if prev_row else GENESIS_HASH
            else:
                prev_hash = GENESIS_HASH

            for row in rows:
                record = self._row_to_record(row)
                records_checked += 1

                # Check chain link
                if record.prev_hash != prev_hash:
                    if first_invalid is None:
                        first_invalid = record.sequence
                    issues.append(
                        f"Chain break at sequence {record.sequence}: "
                        f"expected prev_hash {prev_hash[:16]}..., got {record.prev_hash[:16]}..."
                    )

                # Verify record hash
                expected_hash = compute_record_hash(
                    prev_hash=record.prev_hash,
                    sequence=record.sequence,
                    timestamp=record.timestamp,
                    action_type=record.action_type.value,
                    actor_id=record.actor_id,
                    input_hash=record.input_hash,
                    output_hash=record.output_hash,
                    tool_name=record.tool_name,
                )

                if record.record_hash != expected_hash:
                    if first_invalid is None:
                        first_invalid = record.sequence
                    issues.append(
                        f"Hash mismatch at sequence {record.sequence}: "
                        f"expected {expected_hash[:16]}..., got {record.record_hash[:16]}..."
                    )

                prev_hash = record.record_hash

        return VerificationResult(
            valid=len(issues) == 0,
            records_checked=records_checked,
            first_invalid_sequence=first_invalid,
            issues=issues,
        )

    async def verify_chain_fast(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """Fast verification using Merkle checkpoints."""
        conditions: list[str] = ["TRUE"]
        params: list = []
        param_idx = 1

        def add_param(value) -> str:
            nonlocal param_idx
            placeholder = f"${param_idx}"
            param_idx += 1
            params.append(value)
            return placeholder

        if from_sequence is not None:
            conditions.append(f"to_sequence >= {add_param(from_sequence)}")
        if to_sequence is not None:
            conditions.append(f"from_sequence <= {add_param(to_sequence)}")

        async with self._pool.acquire() as conn:
            checkpoints = await conn.fetch(
                f"SELECT * FROM witness_checkpoints WHERE {' AND '.join(conditions)} ORDER BY id",
                *params,
            )

            if not checkpoints:
                return await self.verify_chain(from_sequence, to_sequence)

            issues: list[str] = []
            records_checked = 0

            for cp in checkpoints:
                hashes = await conn.fetch(
                    "SELECT record_hash FROM witness_records WHERE sequence >= $1 AND sequence <= $2 ORDER BY sequence",
                    cp["from_sequence"], cp["to_sequence"],
                )
                record_hashes = [r["record_hash"] for r in hashes]

                tree = build_merkle_tree(record_hashes)

                if tree.root != cp["merkle_root"]:
                    issues.append(
                        f"Checkpoint {cp['id']} Merkle root mismatch: "
                        f"tampering detected in records {cp['from_sequence']}-{cp['to_sequence']}"
                    )

                records_checked += cp["record_count"]

            last_checkpointed = checkpoints[-1]["to_sequence"]
            if to_sequence is None or to_sequence > last_checkpointed:
                remainder_result = await self.verify_chain(
                    from_sequence=last_checkpointed + 1,
                    to_sequence=to_sequence,
                )
                issues.extend(remainder_result.issues)
                records_checked += remainder_result.records_checked

        return VerificationResult(
            valid=len(issues) == 0,
            records_checked=records_checked,
            issues=issues,
        )

    # =========================================================================
    # Session & Stats
    # =========================================================================

    async def get_chain_for_session(self, session_id: str) -> list[WitnessRecord]:
        """Get all records for a session in order."""
        return await self.query(session_id=session_id, limit=10000)

    async def get_stats(self) -> ChainStats:
        """Get statistics about the witness chain."""
        async with self._pool.acquire() as conn:
            total_row = await conn.fetchval("SELECT COUNT(*) FROM witness_records")
            total = total_row or 0

            if total == 0:
                return ChainStats(
                    total_records=0,
                    unique_sessions=0,
                    unique_actors=0,
                    attested_records=0,
                    chain_valid=True,
                )

            # Time range
            row = await conn.fetchrow(
                "SELECT MIN(timestamp), MAX(timestamp) FROM witness_records"
            )
            first_time = row["min"] if row and row["min"] else None
            last_time = row["max"] if row and row["max"] else None

            # Unique counts
            unique_sessions = await conn.fetchval(
                "SELECT COUNT(DISTINCT session_id) FROM witness_records WHERE session_id != ''"
            ) or 0

            unique_actors = await conn.fetchval(
                "SELECT COUNT(DISTINCT actor_id) FROM witness_records"
            ) or 0

            # By action type
            rows = await conn.fetch(
                "SELECT action_type, COUNT(*) as cnt FROM witness_records GROUP BY action_type"
            )
            by_action: dict[str, int] = {r["action_type"]: r["cnt"] for r in rows}

            # By sensitivity
            rows = await conn.fetch(
                "SELECT sensitivity, COUNT(*) as cnt FROM witness_records GROUP BY sensitivity"
            )
            by_sensitivity: dict[str, int] = {r["sensitivity"]: r["cnt"] for r in rows}

            # Attested
            attested = await conn.fetchval(
                "SELECT COUNT(*) FROM witness_records WHERE tsa_receipt IS NOT NULL"
            ) or 0

            # Chain validity (quick check - just verify last 10)
            verification = await self.verify_chain()

        return ChainStats(
            total_records=total,
            first_record_time=first_time,
            last_record_time=last_time,
            unique_sessions=unique_sessions,
            unique_actors=unique_actors,
            records_by_action_type=by_action,
            records_by_sensitivity=by_sensitivity,
            attested_records=attested,
            chain_valid=verification.valid,
        )

    # =========================================================================
    # Attestation
    # =========================================================================

    async def update_attestation(
        self,
        record_id: str | UUID,
        tsa_receipt: bytes,
        anchored_at: str,
    ) -> bool:
        """Update a record with attestation data."""
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE witness_records
                SET tsa_receipt = $1, anchored_at = $2
                WHERE id = $3
                """,
                tsa_receipt,
                anchored_at,
                UUID(str(record_id)),
            )
            # result is "UPDATE X" string in asyncpg
            parts = result.split()
            return len(parts) == 2 and int(parts[1]) > 0

    # =========================================================================
    # Retention
    # =========================================================================

    async def cleanup_expired(self) -> int:
        """Delete records past their retention period."""
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                DELETE FROM witness_records
                WHERE (created_at + (retention_days || ' days')::INTERVAL) < NOW()
                """
            )
            parts = result.split()
            return int(parts[1]) if len(parts) == 2 else 0

    # =========================================================================
    # Checkpoint Methods
    # =========================================================================

    async def _maybe_create_checkpoint(self, sequence: int) -> Optional[Checkpoint]:
        """Create a checkpoint if we've hit the interval."""
        if (sequence + 1) % CHECKPOINT_INTERVAL != 0:
            return None

        from_seq = sequence - CHECKPOINT_INTERVAL + 1
        to_seq = sequence

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT record_hash FROM witness_records WHERE sequence >= $1 AND sequence <= $2 ORDER BY sequence",
                from_seq, to_seq,
            )
            record_hashes = [r["record_hash"] for r in rows]

            if len(record_hashes) != CHECKPOINT_INTERVAL:
                return None  # Something's wrong, skip

            tree = build_merkle_tree(record_hashes)

            cp_row = await conn.fetchrow(
                """
                INSERT INTO witness_checkpoints
                (from_sequence, to_sequence, merkle_root, record_count, last_record_hash, tree_data)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, created_at
                """,
                from_seq,
                to_seq,
                tree.root,
                len(record_hashes),
                record_hashes[-1],
                _serialize_json(tree.to_dict()),
            )

        checkpoint_id = cp_row["id"]

        checkpoint = Checkpoint(
            id=checkpoint_id,
            from_sequence=from_seq,
            to_sequence=to_seq,
            merkle_root=tree.root,
            record_count=len(record_hashes),
            last_record_hash=record_hashes[-1],
        )

        # Auto-anchor if enabled
        if AUTO_ANCHOR:
            try:
                await self.anchor_checkpoint(checkpoint_id)
            except Exception:
                pass  # Don't fail record creation if anchoring fails

        return checkpoint

    async def get_checkpoint(self, checkpoint_id: int) -> Optional[Checkpoint]:
        """Get a checkpoint by ID."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_checkpoints WHERE id = $1",
                checkpoint_id,
            )
            if not row:
                return None

            return Checkpoint(
                id=row["id"],
                from_sequence=row["from_sequence"],
                to_sequence=row["to_sequence"],
                merkle_root=row["merkle_root"],
                record_count=row["record_count"],
                last_record_hash=row["last_record_hash"],
                created_at=row["created_at"],
            )

    async def get_checkpoint_for_sequence(self, sequence: int) -> Optional[Checkpoint]:
        """Get the checkpoint containing a given sequence."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_checkpoints WHERE from_sequence <= $1 AND to_sequence >= $2",
                sequence, sequence,
            )
            if not row:
                return None

            return Checkpoint(
                id=row["id"],
                from_sequence=row["from_sequence"],
                to_sequence=row["to_sequence"],
                merkle_root=row["merkle_root"],
                record_count=row["record_count"],
                last_record_hash=row["last_record_hash"],
                created_at=row["created_at"],
            )

    async def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]:
        """List all checkpoints."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM witness_checkpoints ORDER BY id DESC LIMIT $1",
                limit,
            )

            return [
                Checkpoint(
                    id=row["id"],
                    from_sequence=row["from_sequence"],
                    to_sequence=row["to_sequence"],
                    merkle_root=row["merkle_root"],
                    record_count=row["record_count"],
                    last_record_hash=row["last_record_hash"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    async def get_merkle_proof(self, sequence: int) -> Optional[dict]:
        """
        Get a Merkle proof for a specific record.

        Returns proof that can verify the record without checking entire chain.
        The leaf_hash in the proof is domain-separated (0x00 prefix).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM witness_checkpoints WHERE from_sequence <= $1 AND to_sequence >= $2",
                sequence, sequence,
            )

            if not row:
                return None

            tree_data = _deserialize_json(row["tree_data"])
            tree = MerkleTree.from_dict(tree_data)

            index_in_checkpoint = sequence - row["from_sequence"]
            proof = get_merkle_proof(tree, index_in_checkpoint)

            if not proof:
                return None

            record = await self.get_by_sequence(sequence)
            if not record:
                return None

            return {
                "record_hash": record.record_hash,
                "domain_separated_leaf_hash": proof.leaf_hash,
                "merkle_root": row["merkle_root"],
                "checkpoint_id": row["id"],
                "proof_path": proof.proof_path,
                "leaf_index": proof.leaf_index,
            }

    async def verify_single_record(self, sequence: int) -> bool:
        """Verify a single record using Merkle proof (O(log n))."""
        proof_data = await self.get_merkle_proof(sequence)

        if not proof_data:
            # Fallback to linear verification for uncheckpointed records
            result = await self.verify_chain(from_sequence=sequence, to_sequence=sequence)
            return result.valid

        return verify_merkle_proof(
            proof_data["domain_separated_leaf_hash"],
            proof_data["proof_path"],
            proof_data["merkle_root"],
        )

    async def backfill_checkpoints(self) -> int:
        """Create checkpoints for existing records that don't have them."""
        async with self._pool.acquire() as conn:
            max_seq = await conn.fetchval("SELECT MAX(sequence) FROM witness_records")

            if max_seq is None:
                return 0

            last_checkpointed = await conn.fetchval(
                "SELECT COALESCE(MAX(to_sequence), -1) FROM witness_checkpoints"
            ) or -1

        checkpoints_created = 0

        for checkpoint_end in range(
            ((last_checkpointed // CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL + CHECKPOINT_INTERVAL - 1,
            max_seq + 1,
            CHECKPOINT_INTERVAL,
        ):
            if checkpoint_end <= last_checkpointed:
                continue
            if checkpoint_end > max_seq:
                break

            checkpoint = await self._maybe_create_checkpoint(checkpoint_end)
            if checkpoint:
                checkpoints_created += 1

        return checkpoints_created

    # =========================================================================
    # Anchoring Methods
    # =========================================================================

    async def anchor_checkpoint(
        self,
        checkpoint_id: int,
        anchor_types: list[AnchorType] | None = None,
    ) -> list[AnchorReceipt]:
        """Anchor a checkpoint to external trust sources."""
        checkpoint = await self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            raise ValueError(f"Checkpoint {checkpoint_id} not found")

        receipts = await self._anchor_service.anchor(
            merkle_root=checkpoint.merkle_root,
            metadata={
                "checkpoint_id": checkpoint_id,
                "from_sequence": checkpoint.from_sequence,
                "to_sequence": checkpoint.to_sequence,
                "record_count": checkpoint.record_count,
            },
            anchor_types=anchor_types,
        )

        async with self._pool.acquire() as conn:
            for receipt in receipts:
                await conn.execute(
                    """
                    INSERT INTO witness_anchors
                    (checkpoint_id, anchor_type, merkle_root, receipt_id,
                     verification_url, raw_receipt, cost_usd, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    """,
                    checkpoint_id,
                    receipt.anchor_type.value,
                    receipt.merkle_root,
                    receipt.receipt_id,
                    receipt.verification_url,
                    receipt.raw_receipt,
                    receipt.cost_usd,
                    _serialize_json(receipt.metadata),
                )

        return receipts

    async def get_anchors_for_checkpoint(self, checkpoint_id: int) -> list[Anchor]:
        """Get all anchors for a checkpoint."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM witness_anchors WHERE checkpoint_id = $1",
                checkpoint_id,
            )

            return [
                Anchor(
                    id=row["id"],
                    checkpoint_id=row["checkpoint_id"],
                    anchor_type=row["anchor_type"],
                    merkle_root=row["merkle_root"],
                    receipt_id=row["receipt_id"],
                    verification_url=row["verification_url"],
                    raw_receipt=row["raw_receipt"],
                    cost_usd=row["cost_usd"] or 0.0,
                    created_at=row["created_at"],
                    verified_at=row["verified_at"],
                    is_valid=bool(row["is_valid"]),
                    metadata=_deserialize_json(row["metadata"]) or {},
                )
                for row in rows
            ]

    async def verify_anchors(self, checkpoint_id: int) -> dict:
        """Verify all anchors for a checkpoint."""
        anchors = await self.get_anchors_for_checkpoint(checkpoint_id)

        results = []
        async with self._pool.acquire() as conn:
            for anchor in anchors:
                receipt = AnchorReceipt(
                    anchor_type=AnchorType(anchor.anchor_type),
                    merkle_root=anchor.merkle_root,
                    timestamp=anchor.created_at,
                    receipt_id=anchor.receipt_id,
                    verification_url=anchor.verification_url,
                    raw_receipt=anchor.raw_receipt,
                )

                is_valid = await self._anchor_service.verify(receipt)

                await conn.execute(
                    "UPDATE witness_anchors SET verified_at = $1, is_valid = $2 WHERE id = $3",
                    datetime.now(timezone.utc),
                    is_valid,
                    anchor.id,
                )

                results.append({
                    "type": anchor.anchor_type,
                    "receipt_id": anchor.receipt_id,
                    "verification_url": anchor.verification_url,
                    "valid": is_valid,
                })

        return {
            "checkpoint_id": checkpoint_id,
            "anchors": results,
        }

    async def get_proof_package(self, sequence: int) -> Optional[dict]:
        """
        Get complete proof package for a single record.

        Returns everything needed to prove a record existed and hasn't been tampered with:
        - The record itself
        - Merkle proof to checkpoint root
        - External anchor receipts
        """
        record = await self.get_by_sequence(sequence)
        if not record:
            return None

        proof = await self.get_merkle_proof(sequence)
        if not proof:
            return {
                "error": "Record not yet checkpointed",
                "hint": f"Checkpoints are created every {CHECKPOINT_INTERVAL} records",
            }

        checkpoint = await self.get_checkpoint(proof["checkpoint_id"])
        anchors = await self.get_anchors_for_checkpoint(proof["checkpoint_id"])

        return {
            "record": {
                "id": str(record.id),
                "sequence": record.sequence,
                "record_hash": record.record_hash,
                "timestamp": record.timestamp.isoformat(),
                "action_type": record.action_type.value,
                "tool_name": record.tool_name,
                "actor_id": record.actor_id,
            },
            "merkle_proof": {
                "record_hash": proof["record_hash"],
                "merkle_root": proof["merkle_root"],
                "proof_path": proof["proof_path"],
                "leaf_index": proof["leaf_index"],
            },
            "checkpoint": {
                "id": checkpoint.id,
                "from_record": checkpoint.from_sequence,
                "to_record": checkpoint.to_sequence,
                "created_at": checkpoint.created_at.isoformat(),
            },
            "external_anchors": [
                {
                    "type": a.anchor_type,
                    "receipt_id": a.receipt_id,
                    "verification_url": a.verification_url,
                    "timestamp": a.created_at.isoformat(),
                }
                for a in anchors
            ],
            "verification_instructions": {
                "step_1": "Verify record_hash by hashing record fields",
                "step_2": "Verify merkle_proof path leads to merkle_root",
                "step_3": "Verify merkle_root matches external anchors",
                "step_4": "Verify external anchors via verification_url",
            },
        }

    async def get_anchor_stats(self) -> dict:
        """Get anchoring statistics."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    anchor_type,
                    COUNT(*) as count,
                    COALESCE(SUM(cost_usd), 0) as total_cost,
                    SUM(CASE WHEN is_valid = TRUE THEN 1 ELSE 0 END) as valid_count
                FROM witness_anchors
                GROUP BY anchor_type
            """)

            by_type: dict = {}
            total_anchors = 0
            total_cost = 0.0

            for row in rows:
                by_type[row["anchor_type"]] = {
                    "count": row["count"],
                    "cost_usd": float(row["total_cost"]),
                    "valid": row["valid_count"],
                }
                total_anchors += row["count"]
                total_cost += float(row["total_cost"])

            checkpoint_count = await conn.fetchval(
                "SELECT COUNT(*) FROM witness_checkpoints"
            ) or 0

        return {
            "total_checkpoints": checkpoint_count,
            "total_anchors": total_anchors,
            "total_cost_usd": total_cost,
            "by_type": by_type,
        }
