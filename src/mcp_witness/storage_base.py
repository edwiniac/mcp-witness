"""
Storage backend abstraction for mcp-witness.

Defines the StorageBackend interface that all storage backends must implement.
Allows pluggable backends (SQLite, PostgreSQL, etc.) while keeping the MCP
server tools agnostic to the underlying storage engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import UUID

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


class StorageBackend(ABC):
    """Abstract interface for witness storage backends.

    All storage backends (SQLite, PostgreSQL, etc.) must implement this
    interface. The MCP server uses this interface exclusively, never
    referencing concrete backend types directly.

    Design decisions for ORDER's architecture:
    - async throughout (streaming-first write path)
    - idempotent close (safe to call multiple times)
    - no raw SQL leakage through the interface
    - all methods return domain models, never DB rows
    """

    @abstractmethod
    async def connect(self) -> None:
        """Connect to the storage backend and initialize schema."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close the storage backend connection(s)."""
        ...

    # ── Record CRUD ──────────────────────────────────────────────────────

    @abstractmethod
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
        """Record a new action to the witness chain."""
        ...

    @abstractmethod
    async def batch_record(
        self,
        records: list[dict],
    ) -> list[WitnessRecord]:
        """
        Batch insert multiple records in a single transaction.

        Each dict in ``records`` must have at least ``action_type``.
        Other keys follow the same kwargs as ``record()``.

        The hash chain must be maintained sequentially across all records
        in the batch. Returns created WitnessRecords in the same order.

        Args:
            records: List of record kwargs dicts

        Returns:
            List of created WitnessRecords
        """
        ...

    @abstractmethod
    async def get_by_id(self, record_id: str | UUID) -> Optional[WitnessRecord]:
        """Get a record by its ID."""
        ...

    @abstractmethod
    async def get_by_sequence(self, sequence: int) -> Optional[WitnessRecord]:
        """Get a record by its sequence number."""
        ...

    @abstractmethod
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
        ...

    # ── Chain Verification ───────────────────────────────────────────────

    @abstractmethod
    async def verify_chain(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """Verify the integrity of the hash chain."""
        ...

    @abstractmethod
    async def verify_chain_fast(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        """Fast verification using Merkle checkpoints."""
        ...

    # ── Session & Stats ──────────────────────────────────────────────────

    @abstractmethod
    async def get_chain_for_session(self, session_id: str) -> list[WitnessRecord]:
        """Get all records for a session in order."""
        ...

    @abstractmethod
    async def get_stats(self) -> ChainStats:
        """Get statistics about the witness chain."""
        ...

    # ── Attestation ──────────────────────────────────────────────────────

    @abstractmethod
    async def update_attestation(
        self,
        record_id: str | UUID,
        tsa_receipt: bytes,
        anchored_at: str,
    ) -> bool:
        """Update a record with attestation data."""
        ...

    # ── Retention ────────────────────────────────────────────────────────

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Delete records past their retention period."""
        ...

    # ── Checkpoints ──────────────────────────────────────────────────────

    @abstractmethod
    async def get_checkpoint(self, checkpoint_id: int) -> Optional[Checkpoint]:
        """Get a checkpoint by ID."""
        ...

    @abstractmethod
    async def get_checkpoint_for_sequence(self, sequence: int) -> Optional[Checkpoint]:
        """Get the checkpoint containing a given sequence."""
        ...

    @abstractmethod
    async def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]:
        """List all checkpoints."""
        ...

    @abstractmethod
    async def get_merkle_proof(self, sequence: int) -> Optional[dict]:
        """Get a Merkle proof for a specific record."""
        ...

    @abstractmethod
    async def verify_single_record(self, sequence: int) -> bool:
        """Verify a single record using Merkle proof (O(log n))."""
        ...

    @abstractmethod
    async def backfill_checkpoints(self) -> int:
        """Create checkpoints for existing records that don't have them."""
        ...

    # ── Signing / Non-Repudiation ────────────────────────────────────────

    @abstractmethod
    async def get_signer_public_key(self) -> Optional[str]:
        """Get the current signer's Ed25519 public key (hex), or None if signing is disabled.

        Returns the hex-encoded public key of the signer configured via
        ``MCP_WITNESS_SIGNING_KEY``. If signing is not configured, returns
        ``None`` for backward compatibility.
        """
        ...

    # ── Anchoring ────────────────────────────────────────────────────────

    @abstractmethod
    async def anchor_checkpoint(
        self,
        checkpoint_id: int,
        anchor_types: list | None = None,
    ) -> list:
        """Anchor a checkpoint to external trust sources."""
        ...

    @abstractmethod
    async def get_anchors_for_checkpoint(self, checkpoint_id: int) -> list[Anchor]:
        """Get all anchors for a checkpoint."""
        ...

    @abstractmethod
    async def verify_anchors(self, checkpoint_id: int) -> dict:
        """Verify all anchors for a checkpoint."""
        ...

    @abstractmethod
    async def get_proof_package(self, sequence: int) -> Optional[dict]:
        """Get complete proof package for a single record."""
        ...

    @abstractmethod
    async def get_anchor_stats(self) -> dict:
        """Get anchoring statistics."""
        ...

    # ── Rate Limiting ─────────────────────────────────────────────────────

    @abstractmethod
    async def check_rate_limit(
        self,
        bucket_id: str = "default",
        max_tokens: float = 1000.0,
        refill_rate: float = 1000.0,
    ) -> bool:
        """Atomically check and consume a token.

        Implements a token bucket algorithm backed by the database.
        Returns True if a token was available and consumed (request allowed),
        False if the bucket is empty (rate limited).

        The bucket is auto-created on first access with the given parameters.
        """
        ...

    @abstractmethod
    async def get_rate_limit_state(self, bucket_id: str = "default") -> dict:
        """Get current bucket state.

        Returns:
            dict with keys: tokens, max_tokens, refill_rate, last_refill
            Returns an empty dict if the bucket doesn't exist yet.
        """
        ...

    # ── Idempotency ───────────────────────────────────────────────────────

    @abstractmethod
    async def check_and_record_nonce(self, nonce_hash: str, ttl_seconds: int = 3600) -> bool:
        """Atomically check and record an idempotency nonce.

        Returns True if this is a NEW nonce (allow the operation),
        False if it's a DUPLICATE (reject the operation).

        Periodically cleans up expired nonces to prevent unbounded growth.
        """
        ...
