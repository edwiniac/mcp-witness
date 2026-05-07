"""SQLite storage backend for mcp-witness."""

import asyncio
import json
import logging
import os
import re
import time as time_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import aiosqlite

from .hasher import GENESIS_HASH, compute_record_hash, hash_data
from .merkle import (
    MerkleTree,
    MerkleProof,
    build_merkle_tree,
    get_merkle_proof,
    hash_leaf,
    verify_merkle_proof,
)
from .anchoring import AnchorService, AnchorReceipt, AnchorType
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

# Retry settings for SQLITE_BUSY
MAX_RETRIES = 3
RETRY_BASE_DELAY = 0.05  # 50ms


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
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
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
            
            -- Merkle checkpoints for O(log n) verification
            CREATE TABLE IF NOT EXISTS witness_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_sequence INTEGER NOT NULL,
                to_sequence INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                last_record_hash TEXT NOT NULL,
                tree_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(from_sequence, to_sequence)
            );
            
            CREATE INDEX IF NOT EXISTS idx_checkpoint_range 
                ON witness_checkpoints(from_sequence, to_sequence);
            
            -- External trust anchors
            CREATE TABLE IF NOT EXISTS witness_anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_id INTEGER NOT NULL,
                anchor_type TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                verification_url TEXT,
                raw_receipt BLOB,
                cost_usd REAL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                verified_at TEXT,
                is_valid INTEGER DEFAULT 1,
                metadata TEXT,
                
                FOREIGN KEY (checkpoint_id) REFERENCES witness_checkpoints(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_anchor_checkpoint ON witness_anchors(checkpoint_id);
            CREATE INDEX IF NOT EXISTS idx_anchor_type ON witness_anchors(anchor_type);
        """)
        await self._db.commit()
        
        # Initialize anchor service
        self._anchor_service = AnchorService()
    
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
    
    async def _retry_on_busy(self, operation, *args, **kwargs):
        """
        Retry an operation on SQLITE_BUSY with exponential backoff.

        SQLite in WAL mode can still return SQLITE_BUSY under concurrent
        write pressure. This retry loop provides a safety net.
        """
        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                return await operation(*args, **kwargs)
            except aiosqlite.OperationalError as e:
                if "database is locked" in str(e).lower():
                    last_exc = e
                    delay = RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "SQLITE_BUSY on attempt %d/%d, retrying in %.2fs",
                        attempt + 1, MAX_RETRIES, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    raise
        raise last_exc  # type: ignore[misc]

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

        Uses BEGIN IMMEDIATE to prevent race conditions where concurrent
        writers could create duplicate sequence numbers and fork the chain.
        Includes input validation and SQLITE_BUSY retry logic.

        Returns:
            The created WitnessRecord with computed hashes
        """
        from uuid import uuid4
        from .hasher import redact_fields as do_redact

        # Input validation
        _validate_session_id(session_id)
        _validate_payload_size(input_data, "input_data")
        _validate_payload_size(output_data, "output_data")
        _validate_payload_size(context, "context")

        # Process data
        redacted_fields = redact_fields or []
        processed_input = do_redact(input_data, redacted_fields) if input_data else None
        processed_output = do_redact(output_data, redacted_fields) if output_data else None

        # Compute hashes
        input_hash = hash_data(input_data) if input_data else ""
        output_hash = hash_data(output_data) if output_data else ""

        timestamp = datetime.now(timezone.utc)
        record_id = uuid4()

        async def _do_insert():
            # BEGIN IMMEDIATE locks the write transaction upfront, preventing
            # concurrent writers from reading stale sequence numbers.
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                # Get chain state inside the transaction
                last_record = await self._get_last_record()
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

                await self._db.execute(
                    """
                    INSERT INTO witness_records (
                        id, timestamp, sequence, prev_hash, record_hash,
                        actor_type, actor_id, session_id,
                        action_type, tool_name, input_data, output_data,
                        input_hash, output_hash,
                        context, reasoning, confidence,
                        sensitivity, retention_days, tsa_receipt, anchored_at,
                        redacted_fields
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(record_id),
                        timestamp.isoformat(),
                        sequence,
                        prev_hash,
                        record_hash,
                        actor_type.value,
                        actor_id,
                        session_id,
                        action_type.value,
                        tool_name,
                        json.dumps(processed_input) if processed_input else None,
                        json.dumps(processed_output) if processed_output else None,
                        input_hash,
                        output_hash,
                        json.dumps(context) if context else None,
                        reasoning,
                        confidence,
                        sensitivity.value,
                        retention_days,
                        None,  # tsa_receipt
                        None,  # anchored_at
                        json.dumps(redacted_fields),
                    )
                )
                await self._db.commit()
                return sequence, prev_hash, record_hash
            except Exception:
                await self._db.execute("ROLLBACK")
                raise

        sequence, prev_hash, record_hash = await self._retry_on_busy(_do_insert)

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
        
        # Determine expected prev_hash for the first record in range
        first_sequence = self._row_to_record(rows[0]).sequence
        if first_sequence > 0:
            # Look up the previous record to get the expected prev_hash
            cursor = await self._db.execute(
                "SELECT record_hash FROM witness_records WHERE sequence = ?",
                (first_sequence - 1,)
            )
            prev_row = await cursor.fetchone()
            prev_hash = prev_row[0] if prev_row else GENESIS_HASH
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
    
    # =========================================================================
    # Checkpoint Methods
    # =========================================================================
    
    async def _maybe_create_checkpoint(self, sequence: int) -> Optional[Checkpoint]:
        """Create a checkpoint if we've hit the interval."""
        if (sequence + 1) % CHECKPOINT_INTERVAL != 0:
            return None
        
        from_seq = sequence - CHECKPOINT_INTERVAL + 1
        to_seq = sequence
        
        # Get all records in this range
        cursor = await self._db.execute(
            "SELECT record_hash FROM witness_records WHERE sequence >= ? AND sequence <= ? ORDER BY sequence",
            (from_seq, to_seq)
        )
        rows = await cursor.fetchall()
        record_hashes = [row[0] for row in rows]
        
        if len(record_hashes) != CHECKPOINT_INTERVAL:
            return None  # Something's wrong, skip
        
        # Build Merkle tree
        tree = build_merkle_tree(record_hashes)
        
        # Store checkpoint
        cursor = await self._db.execute(
            """
            INSERT INTO witness_checkpoints 
            (from_sequence, to_sequence, merkle_root, record_count, last_record_hash, tree_data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                from_seq,
                to_seq,
                tree.root,
                len(record_hashes),
                record_hashes[-1],
                json.dumps(tree.to_dict()),
            )
        )
        await self._db.commit()
        
        checkpoint_id = cursor.lastrowid
        
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
            except Exception as e:
                pass  # Don't fail record creation if anchoring fails
        
        return checkpoint
    
    async def get_checkpoint(self, checkpoint_id: int) -> Optional[Checkpoint]:
        """Get a checkpoint by ID."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_checkpoints WHERE id = ?",
            (checkpoint_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        
        return Checkpoint(
            id=row["id"],
            from_sequence=row["from_sequence"],
            to_sequence=row["to_sequence"],
            merkle_root=row["merkle_root"],
            record_count=row["record_count"],
            last_record_hash=row["last_record_hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
    
    async def get_checkpoint_for_sequence(self, sequence: int) -> Optional[Checkpoint]:
        """Get the checkpoint containing a given sequence."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_checkpoints WHERE from_sequence <= ? AND to_sequence >= ?",
            (sequence, sequence)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        
        return Checkpoint(
            id=row["id"],
            from_sequence=row["from_sequence"],
            to_sequence=row["to_sequence"],
            merkle_root=row["merkle_root"],
            record_count=row["record_count"],
            last_record_hash=row["last_record_hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
    
    async def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]:
        """List all checkpoints."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_checkpoints ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = await cursor.fetchall()
        
        return [
            Checkpoint(
                id=row["id"],
                from_sequence=row["from_sequence"],
                to_sequence=row["to_sequence"],
                merkle_root=row["merkle_root"],
                record_count=row["record_count"],
                last_record_hash=row["last_record_hash"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]
    
    async def get_merkle_proof(self, sequence: int) -> Optional[dict]:
        """
        Get a Merkle proof for a specific record.
        
        Returns proof that can verify the record without checking entire chain.
        The leaf_hash in the proof is domain-separated (0x00 prefix).
        """
        # Find checkpoint containing this record
        cursor = await self._db.execute(
            "SELECT * FROM witness_checkpoints WHERE from_sequence <= ? AND to_sequence >= ?",
            (sequence, sequence)
        )
        row = await cursor.fetchone()
        
        if not row:
            return None  # Record not yet checkpointed
        
        tree_data = json.loads(row["tree_data"])
        tree = MerkleTree.from_dict(tree_data)
        
        index_in_checkpoint = sequence - row["from_sequence"]
        proof = get_merkle_proof(tree, index_in_checkpoint)
        
        if not proof:
            return None
        
        # Get the record's hash and apply domain separation to match the tree
        record = await self.get_by_sequence(sequence)
        if not record:
            return None

        # The Merkle tree stores domain-separated leaf hashes.
        # proof.leaf_hash is the domain-separated version from the tree,
        # which is what verify_merkle_proof expects.
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
            proof_data["merkle_root"]
        )
    
    async def verify_chain_fast(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """
        Fast verification using Merkle checkpoints.
        
        - Verifies checkpoint Merkle roots (O(1) per checkpoint)
        - Only walks records between checkpoints (O(n) for remainder)
        """
        # Get checkpoints in range
        conditions = ["1=1"]
        params = []
        
        if from_sequence is not None:
            conditions.append("to_sequence >= ?")
            params.append(from_sequence)
        if to_sequence is not None:
            conditions.append("from_sequence <= ?")
            params.append(to_sequence)
        
        cursor = await self._db.execute(
            f"SELECT * FROM witness_checkpoints WHERE {' AND '.join(conditions)} ORDER BY id",
            params
        )
        checkpoints = await cursor.fetchall()
        
        if not checkpoints:
            # No checkpoints, fall back to linear verification
            return await self.verify_chain(from_sequence, to_sequence)
        
        issues = []
        records_checked = 0
        
        # Verify each checkpoint's Merkle root
        for cp in checkpoints:
            # Get record hashes for this checkpoint
            cursor = await self._db.execute(
                "SELECT record_hash FROM witness_records WHERE sequence >= ? AND sequence <= ? ORDER BY sequence",
                (cp["from_sequence"], cp["to_sequence"])
            )
            hashes = [r[0] for r in await cursor.fetchall()]
            
            # Rebuild tree and check root
            tree = build_merkle_tree(hashes)
            
            if tree.root != cp["merkle_root"]:
                issues.append(
                    f"Checkpoint {cp['id']} Merkle root mismatch: "
                    f"tampering detected in records {cp['from_sequence']}-{cp['to_sequence']}"
                )
            
            records_checked += cp["record_count"]
        
        # Verify records after last checkpoint (linear walk for remainder)
        last_checkpointed = checkpoints[-1]["to_sequence"]
        if to_sequence is None or to_sequence > last_checkpointed:
            remainder_result = await self.verify_chain(
                from_sequence=last_checkpointed + 1,
                to_sequence=to_sequence
            )
            issues.extend(remainder_result.issues)
            records_checked += remainder_result.records_checked
        
        return VerificationResult(
            valid=len(issues) == 0,
            records_checked=records_checked,
            issues=issues,
        )
    
    # =========================================================================
    # Anchoring Methods
    # =========================================================================
    
    async def anchor_checkpoint(
        self,
        checkpoint_id: int,
        anchor_types: list[AnchorType] = None,
    ) -> list[AnchorReceipt]:
        """
        Anchor a checkpoint to external trust sources.
        
        Args:
            checkpoint_id: Which checkpoint to anchor
            anchor_types: Specific providers to use (default: all)
        
        Returns:
            List of anchor receipts
        """
        # Get checkpoint
        checkpoint = await self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            raise ValueError(f"Checkpoint {checkpoint_id} not found")
        
        # Anchor
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
        
        # Store receipts
        for receipt in receipts:
            await self._db.execute(
                """
                INSERT INTO witness_anchors 
                (checkpoint_id, anchor_type, merkle_root, receipt_id,
                 verification_url, raw_receipt, cost_usd, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint_id,
                    receipt.anchor_type.value,
                    receipt.merkle_root,
                    receipt.receipt_id,
                    receipt.verification_url,
                    receipt.raw_receipt,
                    receipt.cost_usd,
                    json.dumps(receipt.metadata),
                )
            )
        
        await self._db.commit()
        return receipts
    
    async def get_anchors_for_checkpoint(self, checkpoint_id: int) -> list[Anchor]:
        """Get all anchors for a checkpoint."""
        cursor = await self._db.execute(
            "SELECT * FROM witness_anchors WHERE checkpoint_id = ?",
            (checkpoint_id,)
        )
        rows = await cursor.fetchall()
        
        return [
            Anchor(
                id=row["id"],
                checkpoint_id=row["checkpoint_id"],
                anchor_type=row["anchor_type"],
                merkle_root=row["merkle_root"],
                receipt_id=row["receipt_id"],
                verification_url=row["verification_url"],
                raw_receipt=row["raw_receipt"],
                cost_usd=row["cost_usd"],
                created_at=datetime.fromisoformat(row["created_at"]),
                verified_at=datetime.fromisoformat(row["verified_at"]) if row["verified_at"] else None,
                is_valid=bool(row["is_valid"]),
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            )
            for row in rows
        ]
    
    async def verify_anchors(self, checkpoint_id: int) -> dict:
        """Verify all anchors for a checkpoint."""
        anchors = await self.get_anchors_for_checkpoint(checkpoint_id)
        
        results = []
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
            
            # Update verification status
            await self._db.execute(
                "UPDATE witness_anchors SET verified_at = ?, is_valid = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), int(is_valid), anchor.id)
            )
            
            results.append({
                "type": anchor.anchor_type,
                "receipt_id": anchor.receipt_id,
                "verification_url": anchor.verification_url,
                "valid": is_valid,
            })
        
        await self._db.commit()
        
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
        # Get the record
        record = await self.get_by_sequence(sequence)
        if not record:
            return None
        
        # Get Merkle proof
        proof = await self.get_merkle_proof(sequence)
        if not proof:
            return {
                "error": "Record not yet checkpointed",
                "hint": f"Checkpoints are created every {CHECKPOINT_INTERVAL} records",
            }
        
        # Get checkpoint
        checkpoint = await self.get_checkpoint(proof["checkpoint_id"])
        
        # Get anchors for this checkpoint
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
            }
        }
    
    async def get_anchor_stats(self) -> dict:
        """Get anchoring statistics."""
        cursor = await self._db.execute("""
            SELECT 
                anchor_type,
                COUNT(*) as count,
                COALESCE(SUM(cost_usd), 0) as total_cost,
                SUM(CASE WHEN is_valid = 1 THEN 1 ELSE 0 END) as valid_count
            FROM witness_anchors
            GROUP BY anchor_type
        """)
        rows = await cursor.fetchall()
        
        by_type = {}
        total_anchors = 0
        total_cost = 0.0
        
        for row in rows:
            by_type[row["anchor_type"]] = {
                "count": row["count"],
                "cost_usd": row["total_cost"],
                "valid": row["valid_count"],
            }
            total_anchors += row["count"]
            total_cost += row["total_cost"]
        
        # Get checkpoint count
        cursor = await self._db.execute("SELECT COUNT(*) FROM witness_checkpoints")
        checkpoint_count = (await cursor.fetchone())[0]
        
        return {
            "total_checkpoints": checkpoint_count,
            "total_anchors": total_anchors,
            "total_cost_usd": total_cost,
            "by_type": by_type,
        }
    
    async def backfill_checkpoints(self) -> int:
        """Create checkpoints for existing records that don't have them."""
        # Get max sequence
        cursor = await self._db.execute("SELECT MAX(sequence) FROM witness_records")
        max_seq = (await cursor.fetchone())[0]
        
        if max_seq is None:
            return 0
        
        # Get last checkpointed sequence
        cursor = await self._db.execute("SELECT MAX(to_sequence) FROM witness_checkpoints")
        last_checkpointed = (await cursor.fetchone())[0] or -1
        
        checkpoints_created = 0
        
        # Create checkpoints for each complete interval
        for checkpoint_end in range(
            ((last_checkpointed // CHECKPOINT_INTERVAL) + 1) * CHECKPOINT_INTERVAL + CHECKPOINT_INTERVAL - 1,
            max_seq + 1,
            CHECKPOINT_INTERVAL
        ):
            if checkpoint_end <= last_checkpointed:
                continue
            if checkpoint_end > max_seq:
                break
            
            checkpoint = await self._maybe_create_checkpoint(checkpoint_end)
            if checkpoint:
                checkpoints_created += 1
        
        return checkpoints_created
    
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
