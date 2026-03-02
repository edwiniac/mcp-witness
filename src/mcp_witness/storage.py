"""SQLite storage backend for mcp-witness."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import aiosqlite

from .hasher import GENESIS_HASH, compute_record_hash, hash_data, verify_record_hash
from .models import (
    ActionType,
    ActorType,
    ChainStats,
    Sensitivity,
    VerificationResult,
    WitnessRecord,
)


class WitnessStorage:
    """SQLite-backed storage for witness records with hash chain integrity."""
    
    def __init__(self, db_path: str | Path = "~/.mcp-witness/witness.db"):
        """
        Initialize the storage.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db: Optional[aiosqlite.Connection] = None
    
    async def connect(self) -> None:
        """Connect to the database and ensure schema exists."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._create_schema()
    
    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None
    
    async def _create_schema(self) -> None:
        """Create database tables if they don't exist."""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS witness_records (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                sequence INTEGER NOT NULL UNIQUE,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                
                actor_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                
                action_type TEXT NOT NULL,
                tool_name TEXT,
                input_data TEXT,
                output_data TEXT,
                input_hash TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                
                context TEXT,
                reasoning TEXT,
                confidence REAL,
                
                sensitivity TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                tsa_receipt BLOB,
                anchored_at TEXT,
                
                redacted_fields TEXT,
                
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_sequence ON witness_records(sequence);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON witness_records(timestamp);
            CREATE INDEX IF NOT EXISTS idx_session_id ON witness_records(session_id);
            CREATE INDEX IF NOT EXISTS idx_actor_id ON witness_records(actor_id);
            CREATE INDEX IF NOT EXISTS idx_action_type ON witness_records(action_type);
            CREATE INDEX IF NOT EXISTS idx_tool_name ON witness_records(tool_name);
            CREATE INDEX IF NOT EXISTS idx_sensitivity ON witness_records(sensitivity);
        """)
        await self._db.commit()
    
    async def _get_last_record(self) -> Optional[dict]:
        """Get the last record in the chain."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_records ORDER BY sequence DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    
    async def _get_next_sequence(self) -> int:
        """Get the next sequence number."""
        last = await self._get_last_record()
        return (last["sequence"] + 1) if last else 0
    
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
        
        Returns:
            The created WitnessRecord with computed hashes
        """
        from uuid import uuid4
        from .hasher import redact_fields as do_redact
        
        # Get chain state
        last_record = await self._get_last_record()
        prev_hash = last_record["record_hash"] if last_record else GENESIS_HASH
        sequence = (last_record["sequence"] + 1) if last_record else 0
        
        # Process data
        redacted_fields = redact_fields or []
        processed_input = do_redact(input_data, redacted_fields) if input_data else None
        processed_output = do_redact(output_data, redacted_fields) if output_data else None
        
        # Compute hashes
        input_hash = hash_data(input_data) if input_data else ""
        output_hash = hash_data(output_data) if output_data else ""
        
        timestamp = datetime.now(timezone.utc)
        record_id = uuid4()
        
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
        
        # Create record
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
        
        # Insert into database
        await self._db.execute(
            """
            INSERT INTO witness_records (
                id, timestamp, sequence, prev_hash, record_hash,
                actor_type, actor_id, session_id,
                action_type, tool_name, input_data, output_data, input_hash, output_hash,
                context, reasoning, confidence,
                sensitivity, retention_days, tsa_receipt, anchored_at,
                redacted_fields
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(record.id),
                record.timestamp.isoformat(),
                record.sequence,
                record.prev_hash,
                record.record_hash,
                record.actor_type.value,
                record.actor_id,
                record.session_id,
                record.action_type.value,
                record.tool_name,
                json.dumps(record.input_data) if record.input_data else None,
                json.dumps(record.output_data) if record.output_data else None,
                record.input_hash,
                record.output_hash,
                json.dumps(record.context) if record.context else None,
                record.reasoning,
                record.confidence,
                record.sensitivity.value,
                record.retention_days,
                record.tsa_receipt,
                record.anchored_at,
                json.dumps(record.redacted_fields),
            )
        )
        await self._db.commit()
        
        return record
    
    async def get_by_id(self, record_id: str | UUID) -> Optional[WitnessRecord]:
        """Get a record by its ID."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_records WHERE id = ?",
            (str(record_id),)
        )
        row = await cursor.fetchone()
        return self._row_to_record(row) if row else None
    
    async def get_by_sequence(self, sequence: int) -> Optional[WitnessRecord]:
        """Get a record by its sequence number."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_records WHERE sequence = ?",
            (sequence,)
        )
        row = await cursor.fetchone()
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
        conditions = []
        params = []
        
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if action_type:
            conditions.append("action_type = ?")
            params.append(action_type.value)
        if sensitivity:
            conditions.append("sensitivity = ?")
            params.append(sensitivity.value)
        if from_time:
            conditions.append("timestamp >= ?")
            params.append(from_time.isoformat())
        if to_time:
            conditions.append("timestamp <= ?")
            params.append(to_time.isoformat())
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        cursor = await self._db.execute(
            f"""
            SELECT * FROM witness_records 
            WHERE {where_clause}
            ORDER BY sequence ASC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset)
        )
        rows = await cursor.fetchall()
        return [self._row_to_record(row) for row in rows]
    
    async def verify_chain(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """
        Verify the integrity of the hash chain.
        
        Returns:
            VerificationResult with validation details
        """
        conditions = []
        params = []
        
        if from_sequence is not None:
            conditions.append("sequence >= ?")
            params.append(from_sequence)
        if to_sequence is not None:
            conditions.append("sequence <= ?")
            params.append(to_sequence)
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        cursor = await self._db.execute(
            f"SELECT * FROM witness_records WHERE {where_clause} ORDER BY sequence ASC",
            params
        )
        rows = await cursor.fetchall()
        
        if not rows:
            return VerificationResult(valid=True, records_checked=0)
        
        issues = []
        records_checked = 0
        first_invalid = None
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
    
    async def get_chain_for_session(self, session_id: str) -> list[WitnessRecord]:
        """Get all records for a session in order."""
        return await self.query(session_id=session_id, limit=10000)
    
    async def get_stats(self) -> ChainStats:
        """Get statistics about the witness chain."""
        # Total records
        cursor = await self._db.execute("SELECT COUNT(*) FROM witness_records")
        total = (await cursor.fetchone())[0]
        
        if total == 0:
            return ChainStats(
                total_records=0,
                unique_sessions=0,
                unique_actors=0,
                attested_records=0,
                chain_valid=True,
            )
        
        # Time range
        cursor = await self._db.execute(
            "SELECT MIN(timestamp), MAX(timestamp) FROM witness_records"
        )
        row = await cursor.fetchone()
        first_time = datetime.fromisoformat(row[0]) if row[0] else None
        last_time = datetime.fromisoformat(row[1]) if row[1] else None
        
        # Unique counts
        cursor = await self._db.execute(
            "SELECT COUNT(DISTINCT session_id) FROM witness_records WHERE session_id != ''"
        )
        unique_sessions = (await cursor.fetchone())[0]
        
        cursor = await self._db.execute(
            "SELECT COUNT(DISTINCT actor_id) FROM witness_records"
        )
        unique_actors = (await cursor.fetchone())[0]
        
        # By action type
        cursor = await self._db.execute(
            "SELECT action_type, COUNT(*) FROM witness_records GROUP BY action_type"
        )
        by_action = {row[0]: row[1] for row in await cursor.fetchall()}
        
        # By sensitivity
        cursor = await self._db.execute(
            "SELECT sensitivity, COUNT(*) FROM witness_records GROUP BY sensitivity"
        )
        by_sensitivity = {row[0]: row[1] for row in await cursor.fetchall()}
        
        # Attested
        cursor = await self._db.execute(
            "SELECT COUNT(*) FROM witness_records WHERE tsa_receipt IS NOT NULL"
        )
        attested = (await cursor.fetchone())[0]
        
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
    
    async def update_attestation(
        self,
        record_id: str | UUID,
        tsa_receipt: bytes,
        anchored_at: str,
    ) -> bool:
        """Update a record with attestation data."""
        cursor = await self._db.execute(
            """
            UPDATE witness_records 
            SET tsa_receipt = ?, anchored_at = ?
            WHERE id = ?
            """,
            (tsa_receipt, anchored_at, str(record_id))
        )
        await self._db.commit()
        return cursor.rowcount > 0
    
    async def cleanup_expired(self) -> int:
        """Delete records past their retention period."""
        cursor = await self._db.execute(
            """
            DELETE FROM witness_records 
            WHERE date(timestamp, '+' || retention_days || ' days') < date('now')
            """
        )
        await self._db.commit()
        return cursor.rowcount
    
    def _row_to_record(self, row: aiosqlite.Row) -> WitnessRecord:
        """Convert a database row to a WitnessRecord."""
        return WitnessRecord(
            id=UUID(row["id"]),
            timestamp=datetime.fromisoformat(row["timestamp"]),
            sequence=row["sequence"],
            prev_hash=row["prev_hash"],
            record_hash=row["record_hash"],
            actor_type=ActorType(row["actor_type"]),
            actor_id=row["actor_id"],
            session_id=row["session_id"],
            action_type=ActionType(row["action_type"]),
            tool_name=row["tool_name"],
            input_data=json.loads(row["input_data"]) if row["input_data"] else None,
            output_data=json.loads(row["output_data"]) if row["output_data"] else None,
            input_hash=row["input_hash"],
            output_hash=row["output_hash"],
            context=json.loads(row["context"]) if row["context"] else None,
            reasoning=row["reasoning"],
            confidence=row["confidence"],
            sensitivity=Sensitivity(row["sensitivity"]),
            retention_days=row["retention_days"],
            tsa_receipt=row["tsa_receipt"],
            anchored_at=row["anchored_at"],
            redacted_fields=json.loads(row["redacted_fields"]) if row["redacted_fields"] else [],
        )
