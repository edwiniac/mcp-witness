"""Tests for the dashboard HTTP server."""

import json
import os
import threading
import time
import urllib.request
from pathlib import Path

import pytest


class TestDashboardServer:
    """Integration tests for the dashboard HTTP server."""

    @pytest.mark.integration
    def test_dashboard_api_returns_200(self, tmp_path: Path):
        """Dashboard API endpoint should return 200 with expected JSON keys.

        Starts a temporary dashboard server with an empty database, hits
        /api/dashboard, and validates the response contract.
        """
        from mcp_witness.dashboard.server import DashboardHandler, HTTPServer

        # Use a temp database so the test doesn't touch real data
        db_path = tmp_path / "witness.db"
        os.environ["MCP_WITNESS_DB"] = str(db_path)

        port = 19990
        server = HTTPServer(("127.0.0.1", port), DashboardHandler)

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.3)  # Let the server start

        try:
            url = f"http://127.0.0.1:{port}/api/dashboard"
            resp = urllib.request.urlopen(url, timeout=10)
            assert resp.status == 200

            body = json.loads(resp.read())
            # Core stats keys
            assert "total_records" in body
            assert "chain_valid" in body
            assert "unique_sessions" in body
            assert "unique_actors" in body
            assert isinstance(body["total_records"], int)
            assert isinstance(body["chain_valid"], bool)
            # Ancillary keys
            assert "first_record" in body
            assert "last_record" in body
            assert "attested_records" in body
            assert "actions_by_type" in body
            assert "sensitivity_levels" in body
            assert "total_checkpoints" in body
            assert "total_anchors" in body
            assert "anchor_by_type" in body
            # Collection keys
            assert "recent_checkpoints" in body
            assert "recent_records" in body
            assert isinstance(body["recent_checkpoints"], list)
            assert isinstance(body["recent_records"], list)
            # Verification sub-document
            assert "verification" in body
            assert "valid" in body["verification"]
            assert "records_checked" in body["verification"]
        finally:
            server.shutdown()
            thread.join(timeout=2)
