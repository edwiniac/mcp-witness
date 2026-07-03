"""Buffered storage wrapper for mcp-witness.

Wraps any StorageBackend and provides asynchronous buffering of
record() calls. record() returns immediately by enqueueing to an
asyncio.Queue, and a background task flushes batches on a configurable
interval.

This is useful for high-throughput scenarios where you want to decouple
the write path from the storage backend's latency.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
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
from .storage_base import StorageBackend

logger = logging.getLogger(__name__)


@dataclass
class _BufferedRecord:
    """Internal representation of a queued record call."""

    kwargs: dict
    future: asyncio.Future


class BufferedStorage(StorageBackend):
    """A buffering wrapper around any StorageBackend.

    record() pushes to an internal asyncio.Queue and returns immediately.
    A background flush task drains the queue in batches and writes them
    to the underlying storage backend.

    All other methods (read, verify, anchor, etc.) pass through directly
    to the wrapped backend.

    The buffer provides:
    - Low-latency record() calls (O(1) enqueue)
    - Configurable batch size for efficient writes
    - Configurable flush interval for latency guarantees
    - Graceful error handling (logs errors, does not lose records)
    - Proper start/stop lifecycle
    """

    def __init__(
        self,
        backend: StorageBackend,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue_size: int = 0,
    ):
        """
        Initialize the buffered storage wrapper.

        Args:
            backend: The underlying StorageBackend to wrap
            batch_size: Maximum number of records per flush batch
            flush_interval: Maximum seconds between flushes (latency guarentee)
            max_queue_size: Maximum queue size (0 = unlimited).
                            If set and the queue is full, record() will block.
        """
        self._backend = backend
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_queue_size = max_queue_size

        self._queue: asyncio.Queue[_BufferedRecord] = asyncio.Queue(
            maxsize=max_queue_size if max_queue_size > 0 else 0
        )
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def backend(self) -> StorageBackend:
        """Expose the underlying storage backend for inspection."""
        return self._backend

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Connect the underlying backend and start the flush task."""
        await self._backend.connect()
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info(
            "BufferedStorage started (batch_size=%d, flush_interval=%.2fs)",
            self._batch_size,
            self._flush_interval,
        )

    async def close(self) -> None:
        """Flush remaining records and shut down the flush task."""
        self._running = False

        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

        # Flush any remaining records synchronously
        await self._flush_now()

        await self._backend.close()
        logger.info("BufferedStorage shut down")

    # ------------------------------------------------------------------
    # Flush Loop
    # ------------------------------------------------------------------

    async def _flush_loop(self) -> None:
        """Background task: periodically flushes the queue."""
        while self._running:
            try:
                await asyncio.wait_for(
                    self._flush_now(),
                    timeout=self._flush_interval,
                )
            except asyncio.TimeoutError:
                # Timeout means no records to flush within interval,
                # which is expected when idle. Continue loop.
                pass
            except Exception:
                logger.exception("Unexpected error in flush loop")
                await asyncio.sleep(self._flush_interval)

    async def _flush_now(self) -> None:
        """Drain the queue and write all pending records.

        Uses the underlying backend's ``batch_record()`` for efficient
        batch insertion in a single transaction. Handles errors gracefully:
        records that fail to write are logged and their futures are
        completed with the exception, allowing callers to handle failures.
        """
        batch: list[_BufferedRecord] = []

        # Drain the queue without blocking
        try:
            while len(batch) < self._batch_size:
                item = self._queue.get_nowait()
                batch.append(item)
        except asyncio.QueueEmpty:
            pass

        if not batch:
            return

        logger.debug("Flushing %d buffered records", len(batch))

        # Collect all kwargs and batch-insert in one transaction
        kwargs_list = [item.kwargs for item in batch]
        try:
            records = await self._backend.batch_record(kwargs_list)
            for item, record in zip(batch, records):
                item.future.set_result(record)
        except Exception as e:
            logger.error("Failed to flush buffered records: %s", e)
            for item in batch:
                if not item.future.done():
                    item.future.set_exception(e)

    # ------------------------------------------------------------------
    # Record (buffered)
    # ------------------------------------------------------------------

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
        """Enqueue a record and return immediately.

        Returns a WitnessRecord resolved when the record is actually flushed
        to the backend.
        """
        kwargs = dict(
            action_type=action_type,
            actor_type=actor_type,
            actor_id=actor_id,
            session_id=session_id,
            tool_name=tool_name,
            input_data=input_data,
            output_data=output_data,
            context=context,
            reasoning=reasoning,
            confidence=confidence,
            sensitivity=sensitivity,
            retention_days=retention_days,
            redact_fields=redact_fields,
        )

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        item = _BufferedRecord(kwargs=kwargs, future=future)

        await self._queue.put(item)
        return await future  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Passthrough methods (all other StorageBackend methods)
    #
    # These delegate directly to the underlying backend without buffering.
    # ------------------------------------------------------------------

    async def batch_record(
        self,
        records: list[dict],
    ) -> list[WitnessRecord]:
        """Batch-insert multiple records via the underlying backend."""
        return await self._backend.batch_record(records)

    async def get_by_id(self, record_id: str | UUID) -> Optional[WitnessRecord]:
        return await self._backend.get_by_id(record_id)

    async def get_by_sequence(self, sequence: int) -> Optional[WitnessRecord]:
        return await self._backend.get_by_sequence(sequence)

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
        after_sequence: Optional[int] = None,
    ) -> list[WitnessRecord]:
        return await self._backend.query(
            session_id=session_id,
            actor_id=actor_id,
            tool_name=tool_name,
            action_type=action_type,
            sensitivity=sensitivity,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
            offset=offset,
            after_sequence=after_sequence,
        )

    async def verify_chain(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        return await self._backend.verify_chain(from_sequence, to_sequence)

    async def verify_chain_fast(
        self,
        from_sequence: Optional[int] = None,
        to_sequence: Optional[int] = None,
    ) -> VerificationResult:
        return await self._backend.verify_chain_fast(from_sequence, to_sequence)

    async def get_chain_for_session(self, session_id: str) -> list[WitnessRecord]:
        return await self._backend.get_chain_for_session(session_id)

    async def get_stats(self) -> ChainStats:
        return await self._backend.get_stats()

    async def update_attestation(
        self,
        record_id: str | UUID,
        tsa_receipt: bytes,
        anchored_at: str,
    ) -> bool:
        return await self._backend.update_attestation(record_id, tsa_receipt, anchored_at)

    async def cleanup_expired(self) -> int:
        return await self._backend.cleanup_expired()

    async def get_checkpoint(self, checkpoint_id: int) -> Optional[Checkpoint]:
        return await self._backend.get_checkpoint(checkpoint_id)

    async def get_checkpoint_for_sequence(self, sequence: int) -> Optional[Checkpoint]:
        return await self._backend.get_checkpoint_for_sequence(sequence)

    async def list_checkpoints(self, limit: int = 100) -> list[Checkpoint]:
        return await self._backend.list_checkpoints(limit)

    async def get_merkle_proof(self, sequence: int) -> Optional[dict]:
        return await self._backend.get_merkle_proof(sequence)

    async def verify_single_record(self, sequence: int) -> bool:
        return await self._backend.verify_single_record(sequence)

    async def backfill_checkpoints(self) -> int:
        return await self._backend.backfill_checkpoints()

    async def anchor_checkpoint(
        self,
        checkpoint_id: int,
        anchor_types: list | None = None,
    ) -> list:
        return await self._backend.anchor_checkpoint(checkpoint_id, anchor_types)

    async def get_anchors_for_checkpoint(self, checkpoint_id: int) -> list[Anchor]:
        return await self._backend.get_anchors_for_checkpoint(checkpoint_id)

    async def verify_anchors(self, checkpoint_id: int) -> dict:
        return await self._backend.verify_anchors(checkpoint_id)

    async def get_proof_package(self, sequence: int) -> Optional[dict]:
        return await self._backend.get_proof_package(sequence)

    async def get_anchor_stats(self) -> dict:
        return await self._backend.get_anchor_stats()

    # ── Rate Limiting ──────────────────────────────────────────────────

    async def check_rate_limit(
        self, bucket_id: str = "default", max_tokens: float = 1000.0, refill_rate: float = 1000.0
    ) -> bool:
        return await self._backend.check_rate_limit(
            bucket_id=bucket_id, max_tokens=max_tokens, refill_rate=refill_rate
        )

    async def get_rate_limit_state(self, bucket_id: str = "default") -> dict:
        return await self._backend.get_rate_limit_state(bucket_id)

    # ── Idempotency ────────────────────────────────────────────────────

    # ── Signing / Non-Repudiation ────────────────────────────────────────

    async def get_signer_public_key(self) -> Optional[str]:
        return await self._backend.get_signer_public_key()

    async def check_and_record_nonce(self, nonce_hash: str, ttl_seconds: int = 3600) -> bool:
        return await self._backend.check_and_record_nonce(
            nonce_hash=nonce_hash, ttl_seconds=ttl_seconds
        )
