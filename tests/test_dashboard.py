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


class TestDashboardHardening:
    """Auth, ordering and escaping regressions."""

    @staticmethod
    def _serve(port):
        from mcp_witness.dashboard.server import DashboardHandler, HTTPServer

        server = HTTPServer(("127.0.0.1", port), DashboardHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_api_requires_token_when_configured(self, tmp_path: Path, monkeypatch):
        import urllib.error

        monkeypatch.setenv("MCP_WITNESS_DB", str(tmp_path / "witness.db"))
        monkeypatch.setenv("MCP_WITNESS_DASHBOARD_TOKEN", "s3cret-token")
        server, thread = self._serve(19991)
        try:
            url = "http://127.0.0.1:19991/api/dashboard"
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(url, timeout=10)
            assert exc.value.code == 401

            bad = urllib.request.Request(url, headers={"Authorization": "Bearer wrong"})
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(bad, timeout=10)
            assert exc.value.code == 401

            good = urllib.request.Request(url, headers={"Authorization": "Bearer s3cret-token"})
            resp = urllib.request.urlopen(good, timeout=10)
            assert resp.status == 200
        finally:
            server.shutdown()
            thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_recent_records_are_newest(self, tmp_path: Path):
        from mcp_witness.dashboard.server import _load_dashboard
        from mcp_witness.models import ActionType
        from mcp_witness.storage import SqliteStorage

        store = SqliteStorage(tmp_path / "w.db")
        await store.connect()
        for i in range(25):
            await store.record(ActionType.TOOL_CALL, session_id=f"s{i}")
        await store.close()

        data = await _load_dashboard(SqliteStorage(tmp_path / "w.db"))
        seqs = [r["sequence"] for r in data["recent_records"]]
        assert len(seqs) == 20
        assert max(seqs) == 24
        assert min(seqs) == 5

    @pytest.mark.asyncio
    async def test_recent_records_fallback_without_order_desc(self):
        from types import SimpleNamespace

        from mcp_witness.dashboard.server import _recent_records

        class OldStore:
            async def query(self, limit=100, offset=0):
                return [SimpleNamespace(sequence=i) for i in range(offset, min(offset + limit, 30))]

            async def get_stats(self):
                return SimpleNamespace(total_records=30)

        recs = await _recent_records(OldStore(), limit=5)
        assert [r.sequence for r in recs] == [29, 28, 27, 26, 25]

    def test_index_escapes_interpolations(self):
        html = (
            Path(__file__).parent.parent / "src" / "mcp_witness" / "dashboard" / "index.html"
        ).read_text()
        assert "function esc(" in html
        assert "${r.tool_name || '—'}" not in html
        assert "esc(r.tool_name)" in html

    def test_non_loopback_warning(self, monkeypatch, caplog):
        from mcp_witness.dashboard import server as dash

        monkeypatch.delenv("MCP_WITNESS_DASHBOARD_TOKEN", raising=False)

        class FakeServer:
            def __init__(self, *a, **k):
                pass

            def serve_forever(self):
                raise KeyboardInterrupt

            def shutdown(self):
                pass

        monkeypatch.setattr(dash, "HTTPServer", FakeServer)
        with caplog.at_level("WARNING"):
            dash.run_dashboard(host="0.0.0.0", port=1)  # nosec B104 - test only
        assert any("WITHOUT authentication" in r.message for r in caplog.records)
        assert dash._is_loopback("127.0.0.1")
        assert dash._is_loopback("localhost")
        assert not dash._is_loopback("0.0.0.0")  # nosec B104
