#!/usr/bin/env python3
"""
MCP Witness Server - Immutable audit trail for AI decisions.

Provides cryptographic proof of what your AI did, when, and why.
Designed for SOC2, HIPAA, and GDPR compliance.
"""

import asyncio
import json
import logging
import os
import signal
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from uuid import uuid4

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from . import metrics as _metrics
from .auth import authenticate, authorize
from .models import (
    ActionType,
    ActorType,
    Sensitivity,
    WitnessRecord,
)
from .security import (
    sanitize_error,
    validate_export_path,
)
from .storage import SqliteStorage
from .storage_base import StorageBackend

logger = logging.getLogger(__name__)

# Initialize MCP server
server = Server("mcp-witness")

# Global storage instance (initialized on startup)
storage: Optional[StorageBackend] = None
_storage_lock = asyncio.Lock()

# Pagination ceilings
MAX_QUERY_LIMIT = 10000
MAX_OFFSET = 100000

# Default database path
DEFAULT_DB_PATH = os.getenv("MCP_WITNESS_DB", "~/.mcp-witness/witness.db")

# Backend selection: "sqlite" (default) or "postgresql"
MCP_WITNESS_BACKEND = os.getenv("MCP_WITNESS_BACKEND", "sqlite").lower()
# PostgreSQL connection URL (required when backend is postgresql)
MCP_WITNESS_PG_URL = os.getenv("MCP_WITNESS_PG_URL", "")

# Graceful shutdown timeout (seconds to wait for in-flight writes)
SHUTDOWN_TIMEOUT = int(os.getenv("MCP_WITNESS_SHUTDOWN_TIMEOUT", "30"))

# Prometheus metrics port (0 = disabled); empty string treated as 0
_raw_metrics_port = os.getenv("MCP_WITNESS_METRICS_PORT", "0").strip()
METRICS_PORT = int(_raw_metrics_port) if _raw_metrics_port.isdigit() else 0

# Prometheus metrics host (default: loopback only — do not expose to the network)
METRICS_HOST = os.getenv("MCP_WITNESS_METRICS_HOST", "127.0.0.1")

# When true, refuse to start without a persistent MCP_WITNESS_SIGNING_KEY
REQUIRE_PERSISTENT_KEY = os.getenv("MCP_WITNESS_REQUIRE_PERSISTENT_KEY", "false").lower() == "true"

# Shutdown state
_shutting_down = False


def _create_storage() -> StorageBackend:
    """Factory: create the configured storage backend.

    Returns the appropriate StorageBackend implementation based on
    MCP_WITNESS_BACKEND environment variable.
    """
    if MCP_WITNESS_BACKEND == "postgresql":
        if not MCP_WITNESS_PG_URL:
            raise ValueError("MCP_WITNESS_BACKEND=postgresql requires MCP_WITNESS_PG_URL to be set")
        try:
            from .storage_pg import PgStorage

            return PgStorage(MCP_WITNESS_PG_URL)
        except ImportError as e:
            raise ImportError(
                "PostgreSQL backend requires asyncpg. Install with: pip install mcp-witness[postgres]"
            ) from e
    else:
        return SqliteStorage(DEFAULT_DB_PATH)


def record_to_dict(r: WitnessRecord) -> dict:
    """Serialize a WitnessRecord to a JSON-safe dict for export."""
    return {
        "id": str(r.id),
        "sequence": r.sequence,
        "timestamp": r.timestamp.isoformat(),
        "prev_hash": r.prev_hash,
        "record_hash": r.record_hash,
        "actor_type": r.actor_type.value,
        "actor_id": r.actor_id,
        "session_id": r.session_id,
        "action_type": r.action_type.value,
        "tool_name": r.tool_name,
        "input_hash": r.input_hash,
        "output_hash": r.output_hash,
        "reasoning": r.reasoning,
        "confidence": r.confidence,
        "sensitivity": r.sensitivity.value,
        "retention_days": r.retention_days,
        "attested": r.tsa_receipt is not None,
        "anchored_at": r.anchored_at,
    }


async def get_storage() -> StorageBackend:
    """Get or create the storage instance (lazy singleton with lock).

    Uses double-checked locking to prevent races during concurrent
    first-connection from multiple asyncio tasks.
    """
    global storage
    if storage is not None:
        return storage
    async with _storage_lock:
        if storage is None:
            s = _create_storage()
            await s.connect()
            storage = s
        return storage


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available witness tools."""
    return [
        Tool(
            name="witness_record",
            description="Record an AI action/decision to the immutable audit trail. "
            "Use for logging tool calls, decisions, outputs, and errors. "
            "Creates a cryptographically-linked record for compliance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": ["tool_call", "decision", "output", "error", "snapshot"],
                        "description": "Type of action being recorded",
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool called (for tool_call actions)",
                    },
                    "input_data": {
                        "type": "object",
                        "description": "Input data/arguments for the action",
                    },
                    "output_data": {"type": "object", "description": "Output/result of the action"},
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation of why this action was taken",
                    },
                    "context": {
                        "type": "object",
                        "description": "Additional context (conversation state, etc.)",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence score (0.0 to 1.0)",
                    },
                    "sensitivity": {
                        "type": "string",
                        "enum": ["public", "internal", "pii", "phi", "confidential"],
                        "description": "Data sensitivity level for compliance",
                        "default": "internal",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to group related actions",
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Identifier for the actor (agent name, user ID)",
                    },
                    "redact_fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Field paths to redact (e.g., ['user.ssn', 'patient.mrn'])",
                    },
                    "retention_days": {
                        "type": "integer",
                        "description": "Days to retain this record (GDPR compliance)",
                        "default": 365,
                    },
                },
                "required": ["action_type"],
            },
        ),
        Tool(
            name="witness_verify",
            description="Verify the integrity of the audit trail. "
            "Checks hash chain continuity and detects any tampering.",
            inputSchema={
                "type": "object",
                "properties": {
                    "from_sequence": {
                        "type": "integer",
                        "description": "Start sequence number for verification",
                    },
                    "to_sequence": {
                        "type": "integer",
                        "description": "End sequence number for verification",
                    },
                    "full_chain": {
                        "type": "boolean",
                        "description": "Verify the entire chain from genesis",
                        "default": False,
                    },
                },
            },
        ),
        Tool(
            name="witness_query",
            description="Search the audit trail with filters. "
            "Find records by session, actor, tool, time range, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Filter by session ID"},
                    "actor_id": {"type": "string", "description": "Filter by actor ID"},
                    "tool_name": {"type": "string", "description": "Filter by tool name"},
                    "action_type": {
                        "type": "string",
                        "enum": ["tool_call", "decision", "output", "error", "snapshot"],
                        "description": "Filter by action type",
                    },
                    "sensitivity": {
                        "type": "string",
                        "enum": ["public", "internal", "pii", "phi", "confidential"],
                        "description": "Filter by sensitivity level",
                    },
                    "from_time": {"type": "string", "description": "Start time (ISO 8601 format)"},
                    "to_time": {"type": "string", "description": "End time (ISO 8601 format)"},
                    "limit": {
                        "type": "integer",
                        "description": "Maximum records to return",
                        "default": 100,
                    },
                },
            },
        ),
        Tool(
            name="witness_chain",
            description="Get the full decision chain for a session. "
            "Shows all linked actions in chronological order.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session ID to get chain for"},
                    "record_id": {
                        "type": "string",
                        "description": "Get chain containing this record",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="witness_stats",
            description="Get statistics about the audit trail. "
            "Shows record counts, time ranges, chain health, etc.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="witness_attest",
            description="Get an RFC 3161 timestamp from an external authority. "
            "Creates legal-grade proof that records existed at a specific time. "
            "Requires FREETSA_URL environment variable (default: https://freetsa.org/tsr).",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {"type": "string", "description": "Specific record ID to attest"},
                    "batch": {
                        "type": "boolean",
                        "description": "Attest all unattested records",
                        "default": True,
                    },
                },
            },
        ),
        Tool(
            name="witness_export",
            description="Export audit records for compliance reporting. "
            "Generates JSON output suitable for auditors. "
            "Use the output parameter to write to a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["json", "summary"],
                        "description": "Export format",
                        "default": "json",
                    },
                    "output": {
                        "type": "string",
                        "description": "Safe output file path (must be within allowed directory)",
                    },
                    "from_time": {"type": "string", "description": "Start time (ISO 8601 format)"},
                    "to_time": {"type": "string", "description": "End time (ISO 8601 format)"},
                    "session_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by specific sessions",
                    },
                    "include_verification": {
                        "type": "boolean",
                        "description": "Include chain verification in report",
                        "default": True,
                    },
                },
            },
        ),
        # =====================================================================
        # New: Checkpoint and Anchoring Tools
        # =====================================================================
        Tool(
            name="witness_checkpoints",
            description="List Merkle checkpoints. Checkpoints group records into "
            "Merkle trees for O(log n) verification instead of O(n).",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum checkpoints to return",
                        "default": 20,
                    }
                },
            },
        ),
        Tool(
            name="witness_verify_fast",
            description="Fast chain verification using Merkle checkpoints. "
            "Much faster than full verification for large chains.",
            inputSchema={
                "type": "object",
                "properties": {
                    "from_sequence": {"type": "integer", "description": "Start sequence number"},
                    "to_sequence": {"type": "integer", "description": "End sequence number"},
                },
            },
        ),
        Tool(
            name="witness_anchor",
            description="Anchor a checkpoint to external trust sources (TSA, Bitcoin, IPFS). "
            "Creates cryptographic proof verifiable by third parties.",
            inputSchema={
                "type": "object",
                "properties": {
                    "checkpoint_id": {
                        "type": "integer",
                        "description": "Checkpoint to anchor (default: latest)",
                    },
                    "anchor_types": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["tsa", "ots", "ipfs"]},
                        "description": "Anchor providers to use (default: all)",
                    },
                },
            },
        ),
        Tool(
            name="witness_verify_anchors",
            description="Verify external anchors for a checkpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "checkpoint_id": {
                        "type": "integer",
                        "description": "Checkpoint to verify anchors for (default: latest)",
                    }
                },
            },
        ),
        Tool(
            name="witness_proof",
            description="Get complete proof package for a single record. "
            "Includes Merkle proof and external anchor receipts - "
            "everything needed for third-party verification.",
            inputSchema={
                "type": "object",
                "properties": {
                    "sequence": {
                        "type": "integer",
                        "description": "Record sequence number to get proof for",
                    }
                },
                "required": ["sequence"],
            },
        ),
        Tool(
            name="witness_backfill",
            description="Create checkpoints for existing records that don't have them. "
            "Run this after upgrading to enable fast verification.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="witness_configure_compliance",
            description="Apply a compliance preset (HIPAA, GDPR, SOX, FedRAMP, SOC2, PCI DSS). "
            "Automatically configures retention, redaction, attestation, and audit settings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "preset": {
                        "type": "string",
                        "enum": ["hipaa", "gdpr", "sox", "fedramp", "soc2", "pci_dss"],
                        "description": "Compliance framework to apply",
                    }
                },
                "required": ["preset"],
            },
        ),
        Tool(
            name="witness_health",
            description="Check the operational status of the witness system. "
            "Returns DB connectivity, chain stats, anchor status, "
            "signing status, and server version.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="witness_delete",
            description="Redact records for GDPR right to erasure. "
            "Instead of deleting (which breaks chain integrity), data fields "
            "are nulled and the record is marked as redacted. "
            "Provide record_id for single deletion or session_id for "
            "GDPR right to erasure (deletes all records in a session). "
            "The 'reason' field is required for audit trail.",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "ID of the specific record to redact",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to redact all records for (GDPR right to erasure)",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for deletion/redaction (required for audit)",
                    },
                },
                "required": ["reason"],
            },
        ),
        Tool(
            name="witness_search",
            description="Full-text search across audit records. "
            "Searches reasoning, input_data, and output_data fields "
            "using LIKE pattern matching. "
            "Respects limit/offset for pagination.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search text to find in reasoning, input_data, or output_data",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum records to return",
                        "default": 50,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="witness_metrics",
            description="Get operational metrics for the witness system. "
            "Returns counters for chain breaks, signature failures, "
            "rate limit hits, idempotency duplicates, and more.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


# ── Argument validators ────────────────────────────────────────────────


def _require_int(value: object, field: str, minimum: int = 0) -> int:
    """Validate that *value* is a non-negative integer >= *minimum*."""
    if not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be integer >= {minimum}")
    return value


def _require_str(value: object, field: str, max_len: int = 0) -> str:
    """Validate that *value* is a string, optionally capped at *max_len*."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if max_len and len(value) > max_len:
        raise ValueError(f"{field} exceeds max length {max_len}")
    return value


# ── Tool handler registry ──────────────────────────────────────────────
# Replaces the giant if/elif chain. Register handlers by tool name.

_TOOL_HANDLERS: dict[str, Callable] = {}


def _register(name: str):
    """Decorator: register a tool handler by name."""

    def decorator(handler: Callable) -> Callable:
        _TOOL_HANDLERS[name] = handler
        return handler

    return decorator


@server.call_tool()
async def call_tool(name: str, arguments: object) -> list[TextContent]:
    """Handle tool calls via registry dispatch.

    All arguments are runtime-validated before reaching handlers.
    """
    try:
        # Strict argument type validation
        if not isinstance(arguments, dict):
            return [
                TextContent(
                    type="text",
                    text=json.dumps({"error": "Tool arguments must be a JSON object"}),
                )
            ]

        # Authenticate and authorize
        role = authenticate()
        authorize(role, name)

        store = await get_storage()

        handler = _TOOL_HANDLERS.get(name)
        if handler is None:
            return [
                TextContent(
                    type="text",
                    text=json.dumps({"error": f"Unknown tool: {name}"}),
                )
            ]

        result = await handler(store, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except Exception as e:
        safe = sanitize_error(e)
        return [TextContent(type="text", text=json.dumps(safe, indent=2))]


@_register("witness_record")
async def handle_record(store: StorageBackend, args: dict) -> dict:
    """Handle witness_record tool call."""
    action_type = ActionType(args["action_type"])

    record = await store.record(
        action_type=action_type,
        actor_type=ActorType(args.get("actor_type", "agent")),
        actor_id=args.get("actor_id", "unknown"),
        session_id=args.get("session_id", str(uuid4())[:8]),
        tool_name=args.get("tool_name"),
        input_data=args.get("input_data"),
        output_data=args.get("output_data"),
        context=args.get("context"),
        reasoning=args.get("reasoning"),
        confidence=args.get("confidence"),
        sensitivity=Sensitivity(args.get("sensitivity", "internal")),
        retention_days=_require_int(args.get("retention_days", 365), "retention_days", minimum=1),
        redact_fields=args.get("redact_fields"),
    )

    return {
        "recorded": True,
        "record_id": str(record.id),
        "sequence": record.sequence,
        "record_hash": record.record_hash,
        "timestamp": record.timestamp.isoformat(),
        "prev_hash": record.prev_hash[:16] + "...",
    }


@_register("witness_verify")
async def handle_verify(store: StorageBackend, args: dict) -> dict:
    """Handle witness_verify tool call."""
    from_seq = args.get("from_sequence")
    to_seq = args.get("to_sequence")

    if args.get("full_chain"):
        from_seq = None
        to_seq = None

    result = await store.verify_chain(from_sequence=from_seq, to_sequence=to_seq)

    return {
        "valid": result.valid,
        "records_checked": result.records_checked,
        "first_invalid_sequence": result.first_invalid_sequence,
        "issues": result.issues,
        "verified_at": result.verified_at.isoformat(),
        "status": "✅ Chain integrity verified" if result.valid else "❌ Chain integrity FAILED",
    }


@_register("witness_query")
async def handle_query(store: StorageBackend, args: dict) -> dict:
    """Handle witness_query tool call."""
    from_time = None
    to_time = None

    if args.get("from_time"):
        from_time = datetime.fromisoformat(args["from_time"].replace("Z", "+00:00"))
    if args.get("to_time"):
        to_time = datetime.fromisoformat(args["to_time"].replace("Z", "+00:00"))

    action_type = ActionType(args["action_type"]) if args.get("action_type") else None
    sensitivity = Sensitivity(args["sensitivity"]) if args.get("sensitivity") else None

    limit = _require_int(args.get("limit", 100), "limit")
    offset = _require_int(args.get("offset", 0), "offset")
    limit = min(limit, MAX_QUERY_LIMIT)
    offset = min(offset, MAX_OFFSET)

    records = await store.query(
        session_id=args.get("session_id"),
        actor_id=args.get("actor_id"),
        tool_name=args.get("tool_name"),
        action_type=action_type,
        sensitivity=sensitivity,
        from_time=from_time,
        to_time=to_time,
        limit=limit,
        offset=offset,
    )

    return {
        "count": len(records),
        "records": [
            {
                "id": str(r.id),
                "sequence": r.sequence,
                "timestamp": r.timestamp.isoformat(),
                "action_type": r.action_type.value,
                "tool_name": r.tool_name,
                "actor_id": r.actor_id,
                "session_id": r.session_id,
                "sensitivity": r.sensitivity.value,
                "reasoning": r.reasoning,
                "record_hash": r.record_hash[:16] + "...",
            }
            for r in records
        ],
    }


@_register("witness_chain")
async def handle_chain(store: StorageBackend, args: dict) -> dict:
    """Handle witness_chain tool call."""
    session_id = args.get("session_id")
    record_id = args.get("record_id")

    if record_id:
        record = await store.get_by_id(record_id)
        if record:
            session_id = record.session_id

    if not session_id:
        return {"error": "session_id or record_id required"}

    records = await store.get_chain_for_session(session_id)

    return {
        "session_id": session_id,
        "chain_length": len(records),
        "chain": [
            {
                "sequence": r.sequence,
                "timestamp": r.timestamp.isoformat(),
                "action_type": r.action_type.value,
                "tool_name": r.tool_name,
                "reasoning": r.reasoning,
                "record_hash": r.record_hash[:16] + "...",
                "prev_hash": r.prev_hash[:16] + "...",
            }
            for r in records
        ],
    }


@_register("witness_stats")
async def handle_stats(store: StorageBackend, args: dict) -> dict:
    """Handle witness_stats tool call."""
    stats = await store.get_stats()
    anchor_stats = await store.get_anchor_stats()

    return {
        "total_records": stats.total_records,
        "first_record": stats.first_record_time.isoformat() if stats.first_record_time else None,
        "last_record": stats.last_record_time.isoformat() if stats.last_record_time else None,
        "unique_sessions": stats.unique_sessions,
        "unique_actors": stats.unique_actors,
        "records_by_action_type": stats.records_by_action_type,
        "records_by_sensitivity": stats.records_by_sensitivity,
        "attested_records": stats.attested_records,
        "chain_valid": stats.chain_valid,
        "chain_status": "✅ Healthy" if stats.chain_valid else "❌ Integrity issues detected",
        # Checkpoint and anchor stats
        "checkpoints": {
            "total": anchor_stats["total_checkpoints"],
            "anchored": anchor_stats["total_anchors"],
            "anchor_cost_usd": anchor_stats["total_cost_usd"],
            "by_anchor_type": anchor_stats["by_type"],
        },
    }


@_register("witness_attest")
async def handle_attest(store: StorageBackend, args: dict) -> dict:
    """Handle witness_attest tool call — uses real RFC 3161 TSA when available."""
    from .anchoring import AnchorService, AnchorType, TSAProvider

    record_id = args.get("record_id")
    batch = args.get("batch", True)

    # Initialize anchor service (TSA only for attest tool)
    anchor_service = AnchorService(providers=[TSAProvider()])

    if record_id:
        record = await store.get_by_id(record_id)
        if not record:
            return {"error": f"Record not found: {record_id}"}

        try:
            receipts = await anchor_service.anchor(
                merkle_root=record.record_hash,
                metadata={"record_id": str(record.id), "sequence": record.sequence},
                anchor_types=[AnchorType.TSA],
            )
            receipt = receipts[0] if receipts else None
        except Exception as e:
            logger.warning("TSA attestation failed for record %s: %s", record_id, e)
            return {
                "success": False,
                "error": f"TSA attestation failed: {e}",
                "note": "Ensure TSA is reachable or disable strict mode with MCP_WITNESS_ANCHOR_STRICT=false",
            }

        if receipt and receipt.raw_receipt:
            await store.update_attestation(
                record_id=record_id,
                tsa_receipt=receipt.raw_receipt,
                anchored_at=receipt.timestamp.isoformat(),
            )
            return {
                "success": True,
                "records_attested": 1,
                "anchor_time": receipt.timestamp.isoformat(),
                "receipt_id": receipt.receipt_id,
                "tsa_provider": "RFC 3161 TSA",
            }

        return {"error": "TSA returned no receipt"}

    if batch:
        records = await store.query(limit=1000)
        unattested = [r for r in records if r.tsa_receipt is None]

        if not unattested:
            return {"success": True, "records_attested": 0, "note": "No unattested records"}

        success_count = 0
        errors = []
        for record in unattested:
            try:
                receipts = await anchor_service.anchor(
                    merkle_root=record.record_hash,
                    metadata={"record_id": str(record.id), "sequence": record.sequence},
                    anchor_types=[AnchorType.TSA],
                )
                receipt = receipts[0] if receipts else None
                if receipt and receipt.raw_receipt:
                    await store.update_attestation(
                        record_id=str(record.id),
                        tsa_receipt=receipt.raw_receipt,
                        anchored_at=receipt.timestamp.isoformat(),
                    )
                    success_count += 1
                else:
                    errors.append(f"Record {record.id}: TSA returned no receipt")
            except Exception as e:
                errors.append(f"Record {record.id}: {e}")

        return {
            "success": True,
            "records_attested": success_count,
            "errors": errors[:10] if errors else None,  # Limit error list
            "note": f"Attested {success_count}/{len(unattested)} records via RFC 3161 TSA",
        }

    return {"error": "Specify record_id or set batch=true"}


@_register("witness_export")
async def handle_export(store: StorageBackend, args: dict) -> dict:
    """Handle witness_export tool call."""
    from_time = None
    to_time = None
    output_path = args.get("output")

    if args.get("from_time"):
        from_time = datetime.fromisoformat(args["from_time"].replace("Z", "+00:00"))
    if args.get("to_time"):
        to_time = datetime.fromisoformat(args["to_time"].replace("Z", "+00:00"))

    records = await store.query(
        from_time=from_time,
        to_time=to_time,
        limit=MAX_QUERY_LIMIT,
    )

    # Filter by session if specified
    session_ids = args.get("session_ids", [])
    if session_ids:
        records = [r for r in records if r.session_id in session_ids]

    include_verification = args.get("include_verification", True)
    verification = None
    if include_verification:
        verification = await store.verify_chain()

    export_format = args.get("format", "json")

    if export_format == "summary":
        return {
            "export_format": "summary",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(records),
            "time_range": {
                "from": records[0].timestamp.isoformat() if records else None,
                "to": records[-1].timestamp.isoformat() if records else None,
            },
            "unique_sessions": len(set(r.session_id for r in records)),
            "unique_actors": len(set(r.actor_id for r in records)),
            "actions_by_type": {
                at.value: sum(1 for r in records if r.action_type == at)
                for at in ActionType
                if any(r.action_type == at for r in records)
            },
            "chain_verification": (
                {
                    "valid": verification.valid if verification else None,
                    "records_checked": verification.records_checked if verification else None,
                    "issues": verification.issues if verification else None,
                }
                if include_verification
                else None
            ),
        }

    # Full JSON export
    if output_path:
        # Streaming export: paginate and write incrementally to avoid
        # materializing all records in memory at once.
        safe_path = validate_export_path(output_path)
        record_count = 0
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write("{\n")
            f.write('  "export_format": "json",\n')
            now_iso = datetime.now(timezone.utc).isoformat()
            f.write(f'  "generated_at": "{now_iso}",\n')
            if verification:
                v = {
                    "valid": verification.valid,
                    "records_checked": verification.records_checked,
                    "issues": verification.issues,
                }
                f.write(f'  "chain_verification": {json.dumps(v)},\n')
            else:
                f.write('  "chain_verification": null,\n')
            f.write('  "records": [\n')

            first = True
            offset = 0
            page_size = 1000
            while True:
                rows = await store.query(
                    from_time=from_time,
                    to_time=to_time,
                    limit=page_size,
                    offset=offset,
                )
                if not rows:
                    break
                for r in rows:
                    if session_ids and r.session_id not in session_ids:
                        continue
                    if not first:
                        f.write(",\n")
                    first = False
                    f.write(f"    {json.dumps(record_to_dict(r), default=str)}")
                    record_count += 1
                offset += page_size

            f.write("\n  ]\n")
            f.write("}\n")

        return {
            "exported": True,
            "output_path": str(safe_path),
            "record_count": record_count,
            "size_bytes": safe_path.stat().st_size,
        }

    # In-memory export (no output file) — keep backward-compatible behaviour
    records = await store.query(
        from_time=from_time,
        to_time=to_time,
        limit=MAX_QUERY_LIMIT,
    )
    if session_ids:
        records = [r for r in records if r.session_id in session_ids]

    export_data = {
        "export_format": "json",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain_verification": (
            {
                "valid": verification.valid,
                "records_checked": verification.records_checked,
                "issues": verification.issues,
            }
            if verification
            else None
        ),
        "records": [record_to_dict(r) for r in records],
    }

    return export_data


# =========================================================================
# New Handlers: Checkpoints and Anchoring
# =========================================================================


@_register("witness_checkpoints")
async def handle_checkpoints(store: StorageBackend, args: dict) -> dict:
    """Handle witness_checkpoints tool call."""
    limit = _require_int(args.get("limit", 20), "limit")
    limit = min(limit, MAX_QUERY_LIMIT)
    checkpoints = await store.list_checkpoints(limit=limit)

    return {
        "count": len(checkpoints),
        "checkpoints": [
            {
                "id": cp.id,
                "from_sequence": cp.from_sequence,
                "to_sequence": cp.to_sequence,
                "merkle_root": cp.merkle_root[:16] + "...",
                "record_count": cp.record_count,
                "created_at": cp.created_at.isoformat(),
            }
            for cp in checkpoints
        ],
    }


@_register("witness_verify_fast")
async def handle_verify_fast(store: StorageBackend, args: dict) -> dict:
    """Handle witness_verify_fast tool call."""
    from_seq = args.get("from_sequence")
    to_seq = args.get("to_sequence")

    result = await store.verify_chain_fast(from_sequence=from_seq, to_sequence=to_seq)

    return {
        "valid": result.valid,
        "records_checked": result.records_checked,
        "issues": result.issues,
        "verified_at": result.verified_at.isoformat(),
        "status": (
            "✅ Chain integrity verified (fast mode)"
            if result.valid
            else "❌ Chain integrity FAILED"
        ),
        "note": "Used Merkle checkpoints for O(log n) verification",
    }


@_register("witness_anchor")
async def handle_anchor(store: StorageBackend, args: dict) -> dict:
    """Handle witness_anchor tool call."""
    from .anchoring import AnchorFailureError, AnchorType

    checkpoint_id = args.get("checkpoint_id")

    # Get latest checkpoint if not specified
    if checkpoint_id is None:
        checkpoints = await store.list_checkpoints(limit=1)
        if not checkpoints:
            return {
                "error": "No checkpoints exist yet",
                "hint": "Checkpoints are created every 1000 records",
            }
        checkpoint_id = checkpoints[0].id

    # Parse anchor types
    anchor_types = None
    if args.get("anchor_types"):
        anchor_types = [AnchorType(t) for t in args["anchor_types"]]

    try:
        receipts = await store.anchor_checkpoint(
            checkpoint_id=checkpoint_id,
            anchor_types=anchor_types,
        )

        return {
            "checkpoint_id": checkpoint_id,
            "anchors_created": len(receipts),
            "anchors": [r.to_dict() for r in receipts],
        }
    except AnchorFailureError as e:
        return {
            "error": str(e),
            "type": "AnchorFailureError",
            "failures": e.failures,
            "hint": "Set MCP_WITNESS_ANCHOR_STRICT=false for degraded operation",
        }


@_register("witness_verify_anchors")
async def handle_verify_anchors(store: StorageBackend, args: dict) -> dict:
    """Handle witness_verify_anchors tool call."""
    checkpoint_id = args.get("checkpoint_id")

    # Get latest checkpoint if not specified
    if checkpoint_id is None:
        checkpoints = await store.list_checkpoints(limit=1)
        if not checkpoints:
            return {"error": "No checkpoints exist yet"}
        checkpoint_id = checkpoints[0].id

    result = await store.verify_anchors(checkpoint_id)

    all_valid = all(a["valid"] for a in result["anchors"]) if result["anchors"] else True

    return {
        **result,
        "status": "✅ All anchors valid" if all_valid else "⚠️ Some anchors failed verification",
    }


@_register("witness_proof")
async def handle_proof(store: StorageBackend, args: dict) -> dict:
    """Handle witness_proof tool call."""
    sequence = args.get("sequence")
    if sequence is None:
        return {"error": "sequence is required"}
    sequence = _require_int(sequence, "sequence")

    proof = await store.get_proof_package(sequence)

    if proof is None:
        return {"error": f"Record with sequence {sequence} not found"}

    return proof


@_register("witness_backfill")
async def handle_backfill(store: StorageBackend, args: dict) -> dict:
    """Handle witness_backfill tool call."""
    checkpoints_created = await store.backfill_checkpoints()

    return {
        "checkpoints_created": checkpoints_created,
        "status": (
            f"✅ Created {checkpoints_created} checkpoints"
            if checkpoints_created > 0
            else "No new checkpoints needed"
        ),
    }


@_register("witness_configure_compliance")
async def handle_compliance(store: StorageBackend, args: dict) -> dict:
    """Handle witness_configure_compliance tool call."""
    from .compliance import get_preset, get_preset_summary

    preset_name = args["preset"]
    preset = get_preset(preset_name)

    if not preset:
        return {
            "error": f"Unknown preset: {preset_name}",
            "available": ["hipaa", "gdpr", "sox", "fedramp", "soc2", "pci_dss"],
        }

    summary = get_preset_summary(preset_name)

    return {
        "applied": preset_name,
        "preset": {
            "name": preset.name,
            "description": preset.description,
            "retention_days": preset.retention_days,
            "retention_human": summary["retention_human"] if summary else None,
            "anchor_frequency": preset.anchor_frequency,
            "auto_redact_fields": preset.auto_redact,
            "redact_field_count": len(preset.auto_redact),
            "requires_attestation": preset.require_attestation,
            "immutable": preset.immutable,
            "encryption": preset.encryption or "none specified",
            "recommended_audit_frequency": preset.audit_frequency,
        },
        "next_steps": [
            "Set MCP_WITNESS_CHECKPOINT_INTERVAL to match your throughput",
            "Set MCP_WITNESS_AUTO_ANCHOR=true to auto-anchor checkpoints",
            "Configure MCP_WITNESS_EXPORT_DIR for secure export paths",
            f"Review {preset.audit_frequency} audit schedule",
        ],
        "note": "Preset configuration is advisory. Actual compliance requires organizational policies "
        "and auditor review. This tool helps technical compliance — it doesn't replace legal review.",
    }


@_register("witness_health")
async def handle_health(store: StorageBackend, args: dict) -> dict:
    """Handle witness_health tool call.

    Returns a comprehensive health check of the witness system.
    """
    import importlib.metadata

    # Server version
    try:
        version = importlib.metadata.version("mcp-witness")
    except Exception:
        version = "unknown"

    # DB connectivity
    db_ok = False
    try:
        stats = await store.get_stats()
        db_ok = True
    except Exception:
        pass  # nosec B110 — health check; DB failure is surfaced via db_ok flag

    # Anchor stats
    try:
        anchor_stats = await store.get_anchor_stats()
    except Exception:
        anchor_stats = {
            "total_checkpoints": 0,
            "total_anchors": 0,
            "total_cost_usd": 0.0,
            "by_type": {},
        }

    # Checkpoint stats
    try:
        checkpoints = await store.list_checkpoints(limit=1)
        latest_checkpoint = checkpoints[0].id if checkpoints else None
        checkpoint_count = len(checkpoints)
    except Exception:
        checkpoint_count = 0
        latest_checkpoint = None

    # Signing status
    try:
        signing_pk = await store.get_signer_public_key()
        signing_enabled = signing_pk is not None
    except Exception:
        signing_pk = None
        signing_enabled = False

    # Chain validity
    chain_valid = stats.chain_valid if db_ok else False

    # Startup chain verification status
    chain_verified_at_startup = getattr(store, "_chain_valid_at_startup", None)

    return {
        "status": "healthy" if db_ok else "unhealthy",
        "version": version,
        "chain_verified_at_startup": chain_verified_at_startup,
        "database": {
            "connected": db_ok,
            "total_records": stats.total_records if db_ok else 0,
            "chain_valid": chain_valid,
            "chain_status": "✅ Valid" if chain_valid else "❌ Integrity issues detected",
        },
        "signing": {
            "enabled": signing_enabled,
            "public_key": signing_pk,
        },
        "checkpoints": {
            "total": checkpoint_count,
            "latest_id": latest_checkpoint,
        },
        "anchors": {
            "total": anchor_stats["total_anchors"],
            "total_cost_usd": anchor_stats["total_cost_usd"],
            "by_type": anchor_stats["by_type"],
        },
        "compliance_presets": ["hipaa", "gdpr", "sox", "fedramp", "soc2", "pci_dss"],
    }


@_register("witness_delete")
async def handle_delete(store: StorageBackend, args: dict) -> dict:
    """Handle witness_delete tool call (GDPR right to erasure).

    Redacts records instead of deleting to preserve chain integrity.
    """
    record_id = args.get("record_id")
    session_id = args.get("session_id")
    reason = _require_str(args.get("reason", ""), "reason", max_len=4096)

    if not reason:
        return {"error": "'reason' is required for deletion/redaction (audit trail)"}

    if not record_id and not session_id:
        return {"error": "Provide record_id or session_id"}

    if record_id and session_id:
        return {"error": "Provide record_id or session_id, not both"}

    try:
        # SqliteStorage has redact_record, PgStorage does not yet.
        # Use duck typing with a fallback.
        redact_method = getattr(store, "redact_record", None)
        if redact_method is None:
            return {"error": "This storage backend does not support record redaction"}

        result = await redact_method(
            record_id=record_id,
            session_id=session_id,
            reason=reason,
        )

        return {
            "success": result["redacted_count"] > 0,
            "action": result["action"],
            "reason": result["reason"],
            "redacted_count": result["redacted_count"],
            "redacted_ids": result["redacted_ids"],
            "note": result["note"],
            "gdpr_notice": "This operation is logged for GDPR compliance. "
            "Data fields are nulled; hash chain integrity is preserved.",
        }
    except Exception as e:
        return sanitize_error(e)


@_register("witness_metrics")
async def handle_metrics(_store: StorageBackend, _args: dict) -> dict:
    """Handle witness_metrics tool call."""
    return _metrics.get_metrics()


@_register("witness_search")
async def handle_search(store: StorageBackend, args: dict) -> dict:
    """Handle witness_search tool call.

    Full-text search (LIKE-based) across reasoning, input_data, output_data.
    """
    query = _require_str(args.get("query", ""), "query", max_len=1024)
    limit = _require_int(args.get("limit", 50), "limit")
    limit = min(limit, MAX_QUERY_LIMIT)

    if not query:
        return {"error": "'query' is required"}

    try:
        search_method = getattr(store, "search", None)
        if search_method is None:
            return {"error": "This storage backend does not support search"}

        records = await search_method(query=query, limit=limit)

        return {
            "count": len(records),
            "query": query,
            "records": [
                {
                    "id": str(r.id),
                    "sequence": r.sequence,
                    "timestamp": r.timestamp.isoformat(),
                    "action_type": r.action_type.value,
                    "tool_name": r.tool_name,
                    "actor_id": r.actor_id,
                    "session_id": r.session_id,
                    "sensitivity": r.sensitivity.value,
                    "reasoning": (
                        r.reasoning[:200] + "..."
                        if r.reasoning and len(r.reasoning) > 200
                        else r.reasoning
                    ),
                    "record_hash": r.record_hash[:16] + "...",
                }
                for r in records
            ],
        }
    except Exception as e:
        return sanitize_error(e)


async def _handle_shutdown(sig: signal.Signals) -> None:
    """Handle SIGTERM/SIGINT gracefully, waiting for in-flight writes."""
    global _shutting_down
    if _shutting_down:
        logger.info("Shutdown already in progress, ignoring signal %s", sig)
        return  # Already shutting down
    _shutting_down = True
    sig_name = signal.Signals(sig).name if isinstance(sig, int) else sig.name
    logger.info("Received signal %s, shutting down gracefully", sig_name)

    # Wait for in-flight writes
    if storage is None:
        return
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT
    while time.monotonic() < deadline:
        if not await storage.has_inflight_writes():
            break
        await asyncio.sleep(0.1)

    if storage:
        await storage.close()
    logger.info("Shutdown complete")


async def main():
    """Run the MCP server."""
    global storage
    storage = _create_storage()

    # Verify authentication is configured (if required)
    from .auth import check_auth_configured

    check_auth_configured()

    # Register signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(_handle_shutdown(s)))

    # Enforce persistent signing key before touching the database.
    # Checked here (before connect) so no cleanup is needed on failure.
    if REQUIRE_PERSISTENT_KEY and not os.getenv("MCP_WITNESS_SIGNING_KEY", "").strip():
        raise RuntimeError(
            "MCP_WITNESS_REQUIRE_PERSISTENT_KEY=true but MCP_WITNESS_SIGNING_KEY is not set. "
            "Non-repudiation requires a persistent 32-byte hex seed. "
            "Generate one with: openssl rand -hex 32"
        )

    await storage.connect()

    # Warn on startup chain verification failure (degraded operation)
    chain_ok = getattr(storage, "_chain_valid_at_startup", None)
    if chain_ok is False:
        logger.warning(
            "STARTUP CHAIN VERIFICATION FAILED — continuing in degraded mode. "
            "Chain integrity issues detected; signature verification may fail. "
            "Run witness_verify to diagnose."
        )

    # Start Prometheus metrics endpoint if configured
    metrics_server = None
    if METRICS_PORT:
        from .metrics_server import start_metrics_server

        metrics_server = await start_metrics_server(host=METRICS_HOST, port=METRICS_PORT)

    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        if metrics_server:
            metrics_server.close()
            await metrics_server.wait_closed()
        if storage:
            await storage.close()


if __name__ == "__main__":
    asyncio.run(main())
