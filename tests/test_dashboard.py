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
        """Dashboard API endpoint should return valid JSON snapshot."""
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
            assert "total_records" in body
            assert "chain_valid" in body
            assert isinstance(body["total_records"], int)
        finally:
            server.shutdown()
            thread.join(timeout=2)
