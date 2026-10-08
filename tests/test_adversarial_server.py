"""Adversarial regression tests for server-level defects.

Covers:
- BufferedStorage busy-spin / event-loop hang (connect + record + close)
- WRITER role able to erase its own records via witness_delete
- witness_delete claiming to be logged without writing a chain record
- witness_configure_compliance reporting "applied" while changing nothing
"""

import asyncio
import json
import time
from pathlib import Path

import pytest

from mcp_witness import server
from mcp_witness.buffered import BufferedStorage
from mcp_witness.models import ActionType
from mcp_witness.storage import SqliteStorage

WRITER_KEY = "writer-key-0123456789abcdef"
ADMIN_KEY = "admin-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def _reset_compliance():
    server.set_active_compliance(None)
    yield
    server.set_active_compliance(None)


@pytest.fixture
def as_role(monkeypatch, temp_storage):
    """Route call_tool through real auth with a given API key."""
    monkeypatch.setenv("MCP_WITNESS_API_KEYS", f"{WRITER_KEY}:writer,{ADMIN_KEY}:admin")

    async def _get_storage():
        return temp_storage

    monkeypatch.setattr(server, "get_storage", _get_storage)

    def _use(key: str):
        monkeypatch.setenv("MCP_WITNESS_API_KEY", key)

    return _use


async def _call(name: str, args: dict) -> dict:
    result = await server.call_tool(name, args)
    return json.loads(result[0].text)


# ---------------------------------------------------------------------------
# BufferedStorage
# ---------------------------------------------------------------------------


class TestBufferedNoHang:
    @pytest.mark.asyncio
    async def test_connect_record_close_completes(self, tmp_path: Path):
        async def scenario():
            buf = BufferedStorage(SqliteStorage(tmp_path / "w.db"), flush_interval=0.5)
            await buf.connect()
            rec = await buf.record(ActionType.TOOL_CALL, actor_id="x", session_id="s")
            await buf.close()
            return rec

        cpu0 = time.process_time()
        rec = await asyncio.wait_for(scenario(), timeout=5)
        assert rec.sequence == 0
        # An idle flush loop must not burn CPU while waiting.
        assert time.process_time() - cpu0 < 2.0

    @pytest.mark.asyncio
    async def test_idle_loop_does_not_spin(self, tmp_path: Path):
        buf = BufferedStorage(SqliteStorage(tmp_path / "w.db"), flush_interval=0.05)
        await buf.connect()
        try:
            cpu0 = time.process_time()
            await asyncio.sleep(0.5)
            assert time.process_time() - cpu0 < 0.25
        finally:
            await asyncio.wait_for(buf.close(), timeout=5)

    @pytest.mark.asyncio
    async def test_close_flushes_pending_records(self, tmp_path: Path):
        buf = BufferedStorage(SqliteStorage(tmp_path / "w.db"), flush_interval=10, batch_size=3)
        await buf.connect()
        tasks = [
            asyncio.create_task(buf.record(ActionType.DECISION, session_id=f"s{i}"))
            for i in range(7)
        ]
        await asyncio.sleep(0)  # let them enqueue
        await asyncio.wait_for(buf.close(), timeout=5)
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
        assert sorted(r.sequence for r in results) == list(range(7))

    @pytest.mark.asyncio
    async def test_backend_failure_fails_all_futures(self, tmp_path: Path):
        backend = SqliteStorage(tmp_path / "w.db")
        buf = BufferedStorage(backend, flush_interval=0.05)
        await buf.connect()

        async def boom(_records, **_kw):
            raise RuntimeError("disk full")

        backend.batch_record = boom  # type: ignore[method-assign]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(buf.record(ActionType.DECISION, session_id="f") for _ in range(3)),
                    return_exceptions=True,
                ),
                timeout=5,
            )
            assert all(isinstance(r, RuntimeError) for r in results)
        finally:
            await asyncio.wait_for(buf.close(), timeout=5)

    @pytest.mark.asyncio
    async def test_record_after_close_raises(self, tmp_path: Path):
        buf = BufferedStorage(SqliteStorage(tmp_path / "w.db"), flush_interval=0.05)
        await buf.connect()
        await buf.close()
        with pytest.raises(RuntimeError):
            await buf.record(ActionType.DECISION, session_id="late")

    @pytest.mark.asyncio
    async def test_passthroughs_and_org_id(self, tmp_path: Path):
        buf = BufferedStorage(SqliteStorage(tmp_path / "w.db"), flush_interval=0.05)
        await buf.connect()
        try:
            rec = await asyncio.wait_for(
                buf.record(
                    ActionType.DECISION,
                    session_id="org",
                    reasoning="findme",
                    org_id="acme",
                ),
                timeout=5,
            )
            assert rec.sequence == 0
            hits = await buf.search("findme")
            assert len(hits) == 1
            result = await buf.redact_record(session_id="org", reason="test")
            assert result["redacted_count"] == 1
        finally:
            await asyncio.wait_for(buf.close(), timeout=5)


# ---------------------------------------------------------------------------
# RBAC: writer must be append-only
# ---------------------------------------------------------------------------


class TestWriterCannotErase:
    @pytest.mark.asyncio
    async def test_writer_cannot_delete(self, as_role, temp_storage):
        as_role(WRITER_KEY)
        rec = await _call(
            "witness_record",
            {"action_type": "tool_call", "session_id": "victim", "input_data": {"q": "evidence"}},
        )
        assert rec.get("recorded") is True

        denied = await _call("witness_delete", {"session_id": "victim", "reason": "cover tracks"})
        assert denied.get("type") == "PermissionError"

        stored = await temp_storage.get_by_sequence(rec["sequence"])
        assert stored is not None
        assert stored.input_data == {"q": "evidence"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "tool,args",
        [("witness_configure_compliance", {"preset": "hipaa"}), ("witness_backfill", {})],
    )
    async def test_writer_cannot_reconfigure(self, as_role, tool, args):
        as_role(WRITER_KEY)
        denied = await _call(tool, args)
        assert denied.get("type") == "PermissionError"
        assert server.get_active_compliance() is None

    @pytest.mark.asyncio
    async def test_admin_can_delete(self, as_role):
        as_role(ADMIN_KEY)
        await _call("witness_record", {"action_type": "tool_call", "session_id": "victim"})
        result = await _call("witness_delete", {"session_id": "victim", "reason": "GDPR request"})
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Erasure is recorded on the chain
# ---------------------------------------------------------------------------


class TestDeleteAppendsErasureRecord:
    @pytest.mark.asyncio
    async def test_erasure_record_appended(self, temp_storage):
        r1 = await temp_storage.record(
            ActionType.TOOL_CALL, session_id="subject", input_data={"email": "a@b.c"}
        )
        await temp_storage.record(ActionType.TOOL_CALL, session_id="subject")
        before = (await temp_storage.get_stats()).total_records

        result = await server.handle_delete(
            temp_storage, {"session_id": "subject", "reason": "Art. 17 request"}
        )
        assert result["redacted_count"] == 2
        assert "erasure_record_sequence" in result

        after = (await temp_storage.get_stats()).total_records
        assert after == before + 1

        erasure = await temp_storage.get_by_sequence(result["erasure_record_sequence"])
        assert erasure.tool_name == "witness_delete"
        assert erasure.session_id == server.ADMIN_SESSION_ID
        assert erasure.input_data["reason"] == "Art. 17 request"
        assert erasure.input_data["count"] == 2
        assert str(r1.id) in erasure.input_data["redacted_ids"]
        # No erased content leaks into the erasure record.
        assert "a@b.c" not in json.dumps(erasure.input_data)

        # Erasing the subject session again must not erase the erasure record.
        await server.handle_delete(temp_storage, {"session_id": "subject", "reason": "again"})
        still = await temp_storage.get_by_sequence(result["erasure_record_sequence"])
        assert still.input_data is not None

        assert (await temp_storage.verify_chain()).valid


# ---------------------------------------------------------------------------
# Compliance presets are enforced
# ---------------------------------------------------------------------------


class TestCompliancePresetEnforced:
    @pytest.mark.asyncio
    async def test_hipaa_redacts_phi(self, temp_storage):
        cfg = await server.handle_compliance(temp_storage, {"preset": "hipaa"})
        assert cfg["applied"] == "hipaa"
        assert cfg["enforced"]
        assert server.get_active_compliance() is not None

        out = await server.handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "session_id": "p1",
                "input_data": {"ssn": "123-45-6789", "patient_name": "Jane", "ok": "keep"},
            },
        )
        stored = await temp_storage.get_by_sequence(out["sequence"])
        assert stored.input_data["ok"] == "keep"
        assert "123-45-6789" not in json.dumps(stored.input_data)
        assert "Jane" not in json.dumps(stored.input_data)
        assert stored.retention_days == 2190

    @pytest.mark.asyncio
    async def test_preset_change_is_recorded(self, temp_storage):
        cfg = await server.handle_compliance(temp_storage, {"preset": "gdpr"})
        rec = await temp_storage.get_by_sequence(cfg["config_change_sequence"])
        assert rec.tool_name == "witness_configure_compliance"
        assert rec.input_data["preset"] == "gdpr"

    @pytest.mark.asyncio
    async def test_caller_retention_respected(self, temp_storage):
        await server.handle_compliance(temp_storage, {"preset": "hipaa"})
        out = await server.handle_record(
            temp_storage,
            {"action_type": "decision", "session_id": "p2", "retention_days": 30},
        )
        stored = await temp_storage.get_by_sequence(out["sequence"])
        assert stored.retention_days == 30

    @pytest.mark.asyncio
    async def test_immutable_preset_blocks_delete(self, temp_storage):
        await temp_storage.record(ActionType.TOOL_CALL, session_id="fin")
        await server.handle_compliance(temp_storage, {"preset": "sox"})
        result = await server.handle_delete(temp_storage, {"session_id": "fin", "reason": "x"})
        assert "error" in result
        assert "immutable" in result["error"]

    @pytest.mark.asyncio
    async def test_env_preset(self, temp_storage, monkeypatch):
        monkeypatch.setattr(server, "_compliance_env_loaded", False)
        monkeypatch.setattr(server, "_active_compliance", None)
        monkeypatch.setenv("MCP_WITNESS_COMPLIANCE_PRESET", "hipaa")
        assert server.get_active_compliance().name == "HIPAA"

    @pytest.mark.asyncio
    async def test_redact_fields_type_checked(self, temp_storage):
        with pytest.raises(ValueError):
            await server.handle_record(
                temp_storage,
                {"action_type": "decision", "session_id": "p3", "redact_fields": "ssn"},
            )
