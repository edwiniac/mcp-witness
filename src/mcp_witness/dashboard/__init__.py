#!/usr/bin/env python3
"""
mcp-witness Web Dashboard — Standalone HTML viewer for witness databases.

Open this file in a browser, or serve via:
    python3 -m http.server 8080 --directory src/mcp_witness/dashboard

The dashboard reads the witness database via a lightweight JSON API
(served by mcp-witness itself or a simple file export).
"""

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Dashboard data provider (reads witness DB)
# ---------------------------------------------------------------------------


def get_dashboard_data(db_path: str = "~/.mcp-witness/witness.db") -> dict:
    """Extract dashboard statistics from the witness database."""
    import asyncio

    from ..storage import WitnessStorage

    store = WitnessStorage(Path(db_path))

    async def _get():
        await store.connect()
        try:
            stats = await store.get_stats()
            anchor_stats = await store.get_anchor_stats()
            checkpoints = await store.list_checkpoints(limit=5)

            # Get recent records
            records = await store.query(limit=20)

            # Chain integrity
            verification = await store.verify_chain_fast()

            return stats, anchor_stats, checkpoints, records, verification
        finally:
            await store.close()

    stats, anchor_stats, checkpoints, records, verification = asyncio.run(_get())

    return {
        "total_records": stats.total_records,
        "chain_valid": stats.chain_valid,
        "unique_sessions": stats.unique_sessions,
        "unique_actors": stats.unique_actors,
        "first_record": stats.first_record_time.isoformat() if stats.first_record_time else None,
        "last_record": stats.last_record_time.isoformat() if stats.last_record_time else None,
        "attested_records": stats.attested_records,
        "actions_by_type": stats.records_by_action_type,
        "sensitivity_levels": stats.records_by_sensitivity,
        "total_checkpoints": anchor_stats.get("total_checkpoints", 0),
        "total_anchors": anchor_stats.get("total_anchors", 0),
        "anchor_by_type": anchor_stats.get("by_type", {}),
        "recent_checkpoints": [
            {
                "id": cp.id,
                "merkle_root": cp.merkle_root[:16] + "...",
                "from_sequence": cp.from_sequence,
                "to_sequence": cp.to_sequence,
                "record_count": cp.record_count,
                "created_at": cp.created_at.isoformat(),
            }
            for cp in checkpoints
        ],
        "recent_records": [
            {
                "sequence": r.sequence,
                "record_hash": r.record_hash[:16] + "...",
                "action_type": r.action_type.value,
                "tool_name": r.tool_name,
                "actor_id": r.actor_id,
                "sensitivity": r.sensitivity.value,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in records
        ],
        "verification": {
            "valid": verification.valid,
            "records_checked": verification.records_checked,
            "issues": verification.issues,
        },
    }
