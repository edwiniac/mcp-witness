#!/usr/bin/env python3
"""
Dashboard HTTP server for mcp-witness.

Serves the web dashboard (index.html) and JSON API endpoint.
"""

import json
import logging
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_PORT = int(os.getenv("MCP_WITNESS_DASHBOARD_PORT", "9090"))
DASHBOARD_DIR = Path(__file__).parent

# Configurable CORS origin (empty string = no CORS header sent)
DASHBOARD_CORS_ORIGIN = os.getenv("MCP_WITNESS_DASHBOARD_ORIGIN", "").strip()


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves the dashboard and API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/dashboard":
            self.handle_api()
        elif self.path == "/" or self.path == "":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def handle_api(self):
        """Serve dashboard data as JSON.

        Uses a single connect/close boundary — no nested asyncio.run loops.
        """
        import asyncio

        try:
            from ..storage import SqliteStorage

            db_path = os.getenv(
                "MCP_WITNESS_DB",
                "~/.mcp-witness/witness.db",
            )
            store = SqliteStorage(Path(db_path).expanduser())

            data = asyncio.run(_load_dashboard(store))
            self._send_json(data)
        except Exception:
            logger.exception("Dashboard API error")
            self._send_json({"error": "internal_error"}, status=500)

    def _send_json(self, data, status=200):
        """Send a JSON response with security headers."""
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if DASHBOARD_CORS_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", DASHBOARD_CORS_ORIGIN)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Use structured logging if configured, else default."""
        logger.debug("HTTP %s", format % args)


async def _load_dashboard(store) -> dict:
    """Load all dashboard data within a single connect/close boundary."""
    await store.connect()
    try:
        stats = await store.get_stats()
        anchor_stats = await store.get_anchor_stats()
        checkpoints = await store.list_checkpoints(limit=5)
        records = await store.query(limit=20)
        verification = await store.verify_chain_fast()

        return {
            "total_records": stats.total_records,
            "chain_valid": stats.chain_valid,
            "unique_sessions": stats.unique_sessions,
            "unique_actors": stats.unique_actors,
            "first_record": (
                stats.first_record_time.isoformat()
                if stats.first_record_time
                else None
            ),
            "last_record": (
                stats.last_record_time.isoformat()
                if stats.last_record_time
                else None
            ),
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
    finally:
        await store.close()


def run_dashboard(host="127.0.0.1", port=None):
    """Start the dashboard HTTP server."""
    if port is None:
        port = DEFAULT_PORT

    server = HTTPServer((host, port), DashboardHandler)
    print("📊 MCP Witness Dashboard")
    print(f"   URL:  http://localhost:{port}")
    print(f"   API:  http://localhost:{port}/api/dashboard")
    print("   Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard server...")
        server.shutdown()
