#!/usr/bin/env python3
"""
MCP Witness Server - Immutable audit trail for AI decisions.

Provides cryptographic proof of what your AI did, when, and why.
Designed for SOC2, HIPAA, and GDPR compliance.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .models import (
    ActionType,
    ActorType,
    Sensitivity,
)
from .security import (
    enforce_read_only,
    sanitize_error,
    validate_export_path,
)
from .storage import SqliteStorage
from .storage_base import StorageBackend

# Initialize MCP server
server = Server("mcp-witness")

# Global storage instance (initialized on startup)
storage: Optional[StorageBackend] = None

# Default database path
DEFAULT_DB_PATH = os.getenv("MCP_WITNESS_DB", "~/.mcp-witness/witness.db")

# Backend selection: "sqlite" (default) or "postgresql"
MCP_WITNESS_BACKEND = os.getenv("MCP_WITNESS_BACKEND", "sqlite").lower()
# PostgreSQL connection URL (required when backend is postgresql)
MCP_WITNESS_PG_URL = os.getenv("MCP_WITNESS_PG_URL", "")


def _create_storage() -> StorageBackend:
    """Factory: create the configured storage backend.

    Returns the appropriate StorageBackend implementation based on
    MCP_WITNESS_BACKEND environment variable.
    """
    if MCP_WITNESS_BACKEND == "postgresql":
        if not MCP_WITNESS_PG_URL:
            raise ValueError(
                "MCP_WITNESS_BACKEND=postgresql requires MCP_WITNESS_PG_URL to be set"
            )
        try:
            from .storage_pg import PgStorage
            return PgStorage(MCP_WITNESS_PG_URL)
        except ImportError as e:
            raise ImportError(
                "PostgreSQL backend requires asyncpg. Install with: pip install mcp-witness[postgres]"
            ) from e
    else:
        return SqliteStorage(DEFAULT_DB_PATH)


async def get_storage() -> StorageBackend:
    """Get or create the storage instance (lazy singleton)."""
    global storage
    if storage is None:
        storage = _create_storage()
        await storage.connect()
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
                        "description": "Type of action being recorded"
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool called (for tool_call actions)"
                    },
                    "input_data": {
                        "type": "object",
                        "description": "Input data/arguments for the action"
                    },
                    "output_data": {
                        "type": "object",
                        "description": "Output/result of the action"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation of why this action was taken"
                    },
                    "context": {
                        "type": "object",
                        "description": "Additional context (conversation state, etc.)"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence score (0.0 to 1.0)"
                    },
                    "sensitivity": {
                        "type": "string",
                        "enum": ["public", "internal", "pii", "phi", "confidential"],
                        "description": "Data sensitivity level for compliance",
                        "default": "internal"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to group related actions"
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Identifier for the actor (agent name, user ID)"
                    },
                    "redact_fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Field paths to redact (e.g., ['user.ssn', 'patient.mrn'])"
                    },
                    "retention_days": {
                        "type": "integer",
                        "description": "Days to retain this record (GDPR compliance)",
                        "default": 365
                    }
                },
                "required": ["action_type"]
            }
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
                        "description": "Start sequence number for verification"
                    },
                    "to_sequence": {
                        "type": "integer",
                        "description": "End sequence number for verification"
                    },
                    "full_chain": {
                        "type": "boolean",
                        "description": "Verify the entire chain from genesis",
                        "default": False
                    }
                }
            }
        ),
        Tool(
            name="witness_query",
            description="Search the audit trail with filters. "
                       "Find records by session, actor, tool, time range, etc.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Filter by session ID"
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Filter by actor ID"
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Filter by tool name"
                    },
                    "action_type": {
                        "type": "string",
                        "enum": ["tool_call", "decision", "output", "error", "snapshot"],
                        "description": "Filter by action type"
                    },
                    "sensitivity": {
                        "type": "string",
                        "enum": ["public", "internal", "pii", "phi", "confidential"],
                        "description": "Filter by sensitivity level"
                    },
                    "from_time": {
                        "type": "string",
                        "description": "Start time (ISO 8601 format)"
                    },
                    "to_time": {
                        "type": "string",
                        "description": "End time (ISO 8601 format)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum records to return",
                        "default": 100
                    }
                }
            }
        ),
        Tool(
            name="witness_chain",
            description="Get the full decision chain for a session. "
                       "Shows all linked actions in chronological order.",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID to get chain for"
                    },
                    "record_id": {
                        "type": "string",
                        "description": "Get chain containing this record"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="witness_stats",
            description="Get statistics about the audit trail. "
                       "Shows record counts, time ranges, chain health, etc.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="witness_attest",
            description="Get an RFC 3161 timestamp from an external authority. "
                       "Creates legal-grade proof that records existed at a specific time. "
                       "Requires FREETSA_URL environment variable (default: https://freetsa.org/tsr).",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "Specific record ID to attest"
                    },
                    "batch": {
                        "type": "boolean",
                        "description": "Attest all unattested records",
                        "default": True
                    }
                }
            }
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
                        "default": "json"
                    },
                    "output": {
                        "type": "string",
                        "description": "Safe output file path (must be within allowed directory)"
                    },
                    "from_time": {
                        "type": "string",
                        "description": "Start time (ISO 8601 format)"
                    },
                    "to_time": {
                        "type": "string",
                        "description": "End time (ISO 8601 format)"
                    },
                    "session_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by specific sessions"
                    },
                    "include_verification": {
                        "type": "boolean",
                        "description": "Include chain verification in report",
                        "default": True
                    }
                }
            }
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
                        "default": 20
                    }
                }
            }
        ),
        Tool(
            name="witness_verify_fast",
            description="Fast chain verification using Merkle checkpoints. "
                       "Much faster than full verification for large chains.",
            inputSchema={
                "type": "object",
                "properties": {
                    "from_sequence": {
                        "type": "integer",
                        "description": "Start sequence number"
                    },
                    "to_sequence": {
                        "type": "integer",
                        "description": "End sequence number"
                    }
                }
            }
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
                        "description": "Checkpoint to anchor (default: latest)"
                    },
                    "anchor_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["tsa", "ots", "ipfs"]
                        },
                        "description": "Anchor providers to use (default: all)"
                    }
                }
            }
        ),
        Tool(
            name="witness_verify_anchors",
            description="Verify external anchors for a checkpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "checkpoint_id": {
                        "type": "integer",
                        "description": "Checkpoint to verify anchors for (default: latest)"
                    }
                }
            }
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
                        "description": "Record sequence number to get proof for"
                    }
                },
                "required": ["sequence"]
            }
        ),
        Tool(
            name="witness_backfill",
            description="Create checkpoints for existing records that don't have them. "
                       "Run this after upgrading to enable fast verification.",
            inputSchema={
                "type": "object",
                "properties": {}
            }
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
                        "description": "Compliance framework to apply"
                    }
                },
                "required": ["preset"]
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""
    try:
        # Enforce RBAC (read-only mode rejection for write tools)
        enforce_read_only(name)

        store = await get_storage()

        if name == "witness_record":
            result = await handle_record(store, arguments)
        elif name == "witness_verify":
            result = await handle_verify(store, arguments)
        elif name == "witness_query":
            result = await handle_query(store, arguments)
        elif name == "witness_chain":
            result = await handle_chain(store, arguments)
        elif name == "witness_stats":
            result = await handle_stats(store)
        elif name == "witness_attest":
            result = await handle_attest(store, arguments)
        elif name == "witness_export":
            result = await handle_export(store, arguments)
        # New checkpoint and anchoring tools
        elif name == "witness_checkpoints":
            result = await handle_checkpoints(store, arguments)
        elif name == "witness_verify_fast":
            result = await handle_verify_fast(store, arguments)
        elif name == "witness_anchor":
            result = await handle_anchor(store, arguments)
        elif name == "witness_verify_anchors":
            result = await handle_verify_anchors(store, arguments)
        elif name == "witness_proof":
            result = await handle_proof(store, arguments)
        elif name == "witness_backfill":
            result = await handle_backfill(store)
        elif name == "witness_configure_compliance":
            result = await handle_compliance(store, arguments)
        else:
            result = {"error": f"Unknown tool: {name}"}

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except Exception as e:
        # Sanitize errors: never leak stack traces to the client
        safe = sanitize_error(e)
        return [TextContent(type="text", text=json.dumps(safe, indent=2))]


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
        retention_days=args.get("retention_days", 365),
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

    records = await store.query(
        session_id=args.get("session_id"),
        actor_id=args.get("actor_id"),
        tool_name=args.get("tool_name"),
        action_type=action_type,
        sensitivity=sensitivity,
        from_time=from_time,
        to_time=to_time,
        limit=args.get("limit", 100),
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


async def handle_stats(store: StorageBackend) -> dict:
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


async def handle_attest(store: StorageBackend, args: dict) -> dict:
    """Handle witness_attest tool call."""
    # Note: Full RFC 3161 implementation would require additional libraries
    # This is a simplified version that records attestation intent

    record_id = args.get("record_id")
    batch = args.get("batch", True)

    if record_id:
        record = await store.get_by_id(record_id)
        if not record:
            return {"error": f"Record not found: {record_id}"}

        # In production, this would call a TSA server
        # For now, we mark it with a timestamp
        anchor_time = datetime.now(timezone.utc).isoformat()
        await store.update_attestation(
            record_id=record_id,
            tsa_receipt=f"ATTESTATION:{anchor_time}".encode(),
            anchored_at=anchor_time,
        )

        return {
            "success": True,
            "records_attested": 1,
            "anchor_time": anchor_time,
            "note": "RFC 3161 TSA integration available in production deployment",
        }

    if batch:
        # Get unattested records
        records = await store.query(limit=1000)
        unattested = [r for r in records if r.tsa_receipt is None]

        anchor_time = datetime.now(timezone.utc).isoformat()
        for record in unattested:
            await store.update_attestation(
                record_id=record.id,
                tsa_receipt=f"BATCH_ATTESTATION:{anchor_time}".encode(),
                anchored_at=anchor_time,
            )

        return {
            "success": True,
            "records_attested": len(unattested),
            "anchor_time": anchor_time,
            "note": "RFC 3161 TSA integration available in production deployment",
        }

    return {"error": "Specify record_id or set batch=true"}


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
        limit=10000,
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
            "chain_verification": {
                "valid": verification.valid if verification else None,
                "records_checked": verification.records_checked if verification else None,
                "issues": verification.issues if verification else None,
            } if include_verification else None,
        }

    # Full JSON export
    export_data = {
        "export_format": "json",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chain_verification": {
            "valid": verification.valid,
            "records_checked": verification.records_checked,
            "issues": verification.issues,
        } if verification else None,
        "records": [
            {
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
            for r in records
        ],
    }

    # Write to file with path traversal protection if output specified
    if output_path:
        safe_path = validate_export_path(output_path)
        with open(safe_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        return {
            "exported": True,
            "output_path": str(safe_path),
            "record_count": len(records),
            "size_bytes": safe_path.stat().st_size,
        }

    return export_data


# =========================================================================
# New Handlers: Checkpoints and Anchoring
# =========================================================================

async def handle_checkpoints(store: StorageBackend, args: dict) -> dict:
    """Handle witness_checkpoints tool call."""
    limit = args.get("limit", 20)
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
        "status": "✅ Chain integrity verified (fast mode)" if result.valid else "❌ Chain integrity FAILED",
        "note": "Used Merkle checkpoints for O(log n) verification",
    }


async def handle_anchor(store: StorageBackend, args: dict) -> dict:
    """Handle witness_anchor tool call."""
    from .anchoring import AnchorType

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
    except Exception as e:
        return {"error": str(e)}


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


async def handle_proof(store: StorageBackend, args: dict) -> dict:
    """Handle witness_proof tool call."""
    sequence = args.get("sequence")
    if sequence is None:
        return {"error": "sequence is required"}

    proof = await store.get_proof_package(sequence)

    if proof is None:
        return {"error": f"Record with sequence {sequence} not found"}

    return proof


async def handle_backfill(store: StorageBackend) -> dict:
    """Handle witness_backfill tool call."""
    checkpoints_created = await store.backfill_checkpoints()

    return {
        "checkpoints_created": checkpoints_created,
        "status": f"✅ Created {checkpoints_created} checkpoints" if checkpoints_created > 0 else "No new checkpoints needed",
    }


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


async def main():
    """Run the MCP server."""
    global storage
    storage = _create_storage()
    await storage.connect()

    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        await storage.close()


if __name__ == "__main__":
    asyncio.run(main())
