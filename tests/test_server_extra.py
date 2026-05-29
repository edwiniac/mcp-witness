"""Additional tests for server.py covering handler and dispatch gaps.

These tests target handlers and helpers not exercised by tests/test_server.py:
health, delete, search, proof, checkpoints, fast/anchor verification,
anchor/backfill (with mocked anchoring), compliance configuration, export
variants, argument validators, call_tool dispatch, and the _int_env helper.
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from mcp_witness.server import (
    _int_env,
    _require_int,
    _require_str,
    call_tool,
    handle_anchor,
    handle_backfill,
    handle_checkpoints,
    handle_compliance,
    handle_delete,
    handle_export,
    handle_health,
    handle_proof,
    handle_record,
    handle_search,
    handle_verify_anchors,
    handle_verify_fast,
    record_to_dict,
)


def _fake_receipt(merkle_root="deadbeef"):
    """Build a deterministic AnchorReceipt for mocked anchoring."""
    from mcp_witness.anchoring import AnchorReceipt, AnchorType

    return AnchorReceipt(
        anchor_type=AnchorType.TSA,
        merkle_root=merkle_root,
        timestamp=datetime.now(timezone.utc),
        receipt_id="fake-receipt-id",
        raw_receipt=b"\x00fake-tsa-receipt",
    )


# =========================================================================
# handle_health
# =========================================================================


class TestHandleHealth:
    """Tests for handle_health."""

    @pytest.mark.asyncio
    async def test_health_db_ok_and_chain(self, temp_storage):
        result = await handle_health(temp_storage, {})

        assert result["status"] == "healthy"
        assert result["database"]["connected"] is True
        assert result["database"]["chain_valid"] is True
        assert "✅" in result["database"]["chain_status"]
        assert "signing" in result
        assert "checkpoints" in result
        assert "anchors" in result

    @pytest.mark.asyncio
    async def test_health_db_failure_marks_unhealthy(self, temp_storage):
        """When get_stats raises, db_ok is False and status is unhealthy."""
        with patch.object(temp_storage, "get_stats", AsyncMock(side_effect=RuntimeError("boom"))):
            result = await handle_health(temp_storage, {})

        assert result["status"] == "unhealthy"
        assert result["database"]["connected"] is False
        assert result["database"]["chain_valid"] is False


# =========================================================================
# handle_delete (GDPR erasure)
# =========================================================================


class TestHandleDelete:
    """Tests for handle_delete."""

    @pytest.mark.asyncio
    async def test_delete_by_record_id(self, temp_storage):
        rec = await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_delete(
            temp_storage,
            {"record_id": rec["record_id"], "reason": "user requested erasure"},
        )

        assert result["success"] is True
        assert result["redacted_count"] == 1
        assert result["action"] == "redact"
        assert rec["record_id"] in result["redacted_ids"]

    @pytest.mark.asyncio
    async def test_delete_by_session(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call", "session_id": "gdpr_sess"})
        await handle_record(temp_storage, {"action_type": "decision", "session_id": "gdpr_sess"})

        result = await handle_delete(
            temp_storage,
            {"session_id": "gdpr_sess", "reason": "right to erasure"},
        )

        assert result["success"] is True
        assert result["redacted_count"] == 2

    @pytest.mark.asyncio
    async def test_delete_missing_reason(self, temp_storage):
        result = await handle_delete(temp_storage, {"record_id": "abc"})
        assert "error" in result
        assert "reason" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_no_target(self, temp_storage):
        result = await handle_delete(temp_storage, {"reason": "x"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_delete_both_targets(self, temp_storage):
        result = await handle_delete(
            temp_storage, {"record_id": "a", "session_id": "b", "reason": "x"}
        )
        assert "error" in result


# =========================================================================
# handle_search
# =========================================================================


class TestHandleSearch:
    """Tests for handle_search."""

    @pytest.mark.asyncio
    async def test_search_finds_reasoning(self, temp_storage):
        await handle_record(
            temp_storage,
            {"action_type": "decision", "reasoning": "elephants are large mammals"},
        )
        await handle_record(
            temp_storage,
            {"action_type": "decision", "reasoning": "sparrows are small birds"},
        )

        result = await handle_search(temp_storage, {"query": "elephants"})

        assert result["count"] == 1
        assert result["query"] == "elephants"
        assert result["records"][0]["reasoning"] == "elephants are large mammals"

    @pytest.mark.asyncio
    async def test_search_empty_query(self, temp_storage):
        result = await handle_search(temp_storage, {"query": ""})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_search_no_match(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "decision", "reasoning": "hello world"})
        result = await handle_search(temp_storage, {"query": "nonexistentterm"})
        assert result["count"] == 0


# =========================================================================
# Checkpoint / proof / fast / anchors helpers
# =========================================================================


class TestCheckpointsAndProof:
    """Tests for checkpoint, proof, fast verify, and anchor verify handlers."""

    @pytest.mark.asyncio
    async def test_checkpoints_empty(self, temp_storage):
        result = await handle_checkpoints(temp_storage, {})
        assert result["count"] == 0
        assert result["checkpoints"] == []

    @pytest.mark.asyncio
    async def test_verify_fast_empty(self, temp_storage):
        result = await handle_verify_fast(temp_storage, {})
        assert result["valid"] is True
        assert "fast mode" in result["status"]

    @pytest.mark.asyncio
    async def test_proof_missing_sequence(self, temp_storage):
        result = await handle_proof(temp_storage, {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_proof_not_found(self, temp_storage):
        result = await handle_proof(temp_storage, {"sequence": 999})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_checkpoints_and_proof_with_small_interval(self, temp_storage, monkeypatch):
        """Backfill with a tiny checkpoint interval, then fetch a real proof."""
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 2)

        for _ in range(4):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        # With interval=2, checkpoints are auto-created during record(), so a
        # subsequent backfill has nothing left to do (creates 0). Either way the
        # checkpoints must exist.
        backfill = await handle_backfill(temp_storage, {})
        assert backfill["checkpoints_created"] >= 0
        assert "status" in backfill

        cps = await handle_checkpoints(temp_storage, {})
        assert cps["count"] >= 1

        # Sequence 0 is in the first checkpoint range.
        proof = await handle_proof(temp_storage, {"sequence": 0})
        assert "merkle_proof" in proof
        assert proof["record"]["sequence"] == 0

    @pytest.mark.asyncio
    async def test_backfill_no_records(self, temp_storage):
        result = await handle_backfill(temp_storage, {})
        assert result["checkpoints_created"] == 0
        assert "No new checkpoints" in result["status"]

    @pytest.mark.asyncio
    async def test_verify_anchors_no_checkpoints(self, temp_storage):
        result = await handle_verify_anchors(temp_storage, {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_verify_anchors_unanchored_checkpoint(self, temp_storage, monkeypatch):
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 2)
        for _ in range(2):
            await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_backfill(temp_storage, {})

        result = await handle_verify_anchors(temp_storage, {})
        # No anchors present → all_valid defaults True.
        assert "status" in result
        assert "✅" in result["status"]


# =========================================================================
# handle_anchor (mocked anchoring — no network)
# =========================================================================


class TestHandleAnchor:
    """Tests for handle_anchor."""

    @pytest.mark.asyncio
    async def test_anchor_no_checkpoints(self, temp_storage):
        result = await handle_anchor(temp_storage, {})
        assert "error" in result
        assert "checkpoint" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_anchor_latest_checkpoint(self, temp_storage, monkeypatch):
        monkeypatch.setattr("mcp_witness.storage.CHECKPOINT_INTERVAL", 2)
        for _ in range(2):
            await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_backfill(temp_storage, {})

        async def _anchor(merkle_root, metadata=None, anchor_types=None):
            return [_fake_receipt(merkle_root)]

        # Patch the storage's anchor service to avoid real network calls.
        with patch.object(temp_storage._anchor_service, "anchor", AsyncMock(side_effect=_anchor)):
            result = await handle_anchor(temp_storage, {})

        assert result["anchors_created"] == 1
        assert result["anchors"][0]["anchor_type"] == "tsa"


# =========================================================================
# handle_compliance
# =========================================================================


class TestHandleCompliance:
    """Tests for handle_configure_compliance."""

    @pytest.mark.asyncio
    async def test_compliance_hipaa(self, temp_storage):
        result = await handle_compliance(temp_storage, {"preset": "hipaa"})
        assert result["applied"] == "hipaa"
        assert result["preset"]["retention_days"] > 0
        assert isinstance(result["preset"]["auto_redact_fields"], list)
        assert "next_steps" in result

    @pytest.mark.asyncio
    async def test_compliance_unknown_preset(self, temp_storage):
        result = await handle_compliance(temp_storage, {"preset": "nope"})
        assert "error" in result
        assert "available" in result


# =========================================================================
# handle_export variants
# =========================================================================


class TestHandleExportExtra:
    """Tests for export summary and file output."""

    @pytest.mark.asyncio
    async def test_export_summary_with_records(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})

        result = await handle_export(temp_storage, {"format": "summary"})

        assert result["export_format"] == "summary"
        assert result["record_count"] == 2
        assert result["chain_verification"]["valid"] is True
        assert "actions_by_type" in result

    @pytest.mark.asyncio
    async def test_export_to_file(self, temp_storage, tmp_path, monkeypatch):
        """Export streams to a file inside the allowed export dir."""
        monkeypatch.setenv("MCP_WITNESS_EXPORT_DIR", str(tmp_path))
        monkeypatch.setattr("mcp_witness.security.ALLOWED_EXPORT_DIR", tmp_path.resolve())

        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})

        out = tmp_path / "export.json"
        result = await handle_export(temp_storage, {"output": str(out)})

        assert result["exported"] is True
        assert result["record_count"] == 2
        assert out.exists()

        data = json.loads(out.read_text())
        assert data["export_format"] == "json"
        assert len(data["records"]) == 2


# =========================================================================
# Argument validators
# =========================================================================


class TestArgValidators:
    """Tests for _require_int / _require_str."""

    def test_require_int_valid(self):
        assert _require_int(5, "x") == 5
        assert _require_int(0, "x") == 0

    def test_require_int_min(self):
        assert _require_int(3, "x", minimum=3) == 3
        with pytest.raises(ValueError, match="must be integer"):
            _require_int(2, "x", minimum=3)

    def test_require_int_rejects_non_int(self):
        with pytest.raises(ValueError, match="must be integer"):
            _require_int("5", "x")
        with pytest.raises(ValueError, match="must be integer"):
            _require_int(-1, "x")

    def test_require_str_valid(self):
        assert _require_str("hello", "x") == "hello"

    def test_require_str_rejects_non_str(self):
        with pytest.raises(ValueError, match="must be a string"):
            _require_str(123, "x")

    def test_require_str_max_len(self):
        assert _require_str("ab", "x", max_len=2) == "ab"
        with pytest.raises(ValueError, match="exceeds max length"):
            _require_str("abc", "x", max_len=2)

    @pytest.mark.asyncio
    async def test_handler_bad_arg_type_raises(self, temp_storage):
        """A bad limit type bubbles a ValueError out of the handler."""
        with pytest.raises(ValueError):
            await handle_search(temp_storage, {"query": "x", "limit": "not-int"})

    @pytest.mark.asyncio
    async def test_proof_bad_sequence_type(self, temp_storage):
        with pytest.raises(ValueError):
            await handle_proof(temp_storage, {"sequence": "abc"})


# =========================================================================
# _int_env helper
# =========================================================================


class TestIntEnv:
    """Tests for _int_env."""

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("MCP_WITNESS_TEST_INT", raising=False)
        assert _int_env("MCP_WITNESS_TEST_INT", 42) == 42

    def test_default_when_blank(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TEST_INT", "   ")
        assert _int_env("MCP_WITNESS_TEST_INT", 7) == 7

    def test_parses_valid(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TEST_INT", " 100 ")
        assert _int_env("MCP_WITNESS_TEST_INT", 0) == 100

    def test_rejects_non_int(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TEST_INT", "abc")
        with pytest.raises(ValueError, match="must be an integer"):
            _int_env("MCP_WITNESS_TEST_INT", 0)

    def test_rejects_below_min(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TEST_INT", "-5")
        with pytest.raises(ValueError, match="must be"):
            _int_env("MCP_WITNESS_TEST_INT", 0, minimum=0)

    def test_rejects_above_max(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_TEST_INT", "70000")
        with pytest.raises(ValueError, match="must be"):
            _int_env("MCP_WITNESS_TEST_INT", 0, minimum=0, maximum=65535)


# =========================================================================
# record_to_dict
# =========================================================================


class TestRecordToDict:
    """Tests for record_to_dict serialization."""

    @pytest.mark.asyncio
    async def test_serialization(self, temp_storage):
        from mcp_witness.models import ActionType, ActorType, Sensitivity

        record = await temp_storage.record(
            action_type=ActionType.TOOL_CALL,
            actor_type=ActorType.AGENT,
            actor_id="claude",
            session_id="sess1",
            tool_name="search",
            reasoning="because",
            sensitivity=Sensitivity.INTERNAL,
        )

        d = record_to_dict(record)

        assert d["id"] == str(record.id)
        assert d["sequence"] == record.sequence
        assert d["actor_type"] == "agent"
        assert d["action_type"] == "tool_call"
        assert d["sensitivity"] == "internal"
        assert d["attested"] is False
        # Must be JSON-serializable.
        json.dumps(d)


# =========================================================================
# call_tool dispatch
# =========================================================================


class TestCallToolDispatch:
    """Tests for call_tool registry dispatch and error handling."""

    @pytest.mark.asyncio
    async def test_non_dict_arguments(self, temp_storage):
        result = await call_tool("witness_stats", ["not", "a", "dict"])
        data = json.loads(result[0].text)
        assert "error" in data
        assert "JSON object" in data["error"]

    @pytest.mark.asyncio
    async def test_unknown_tool(self, temp_storage):
        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict("os.environ", {"MCP_WITNESS_DEFAULT_ACCESS": "admin"}, clear=True):
                result = await call_tool("witness_does_not_exist", {})

        data = json.loads(result[0].text)
        assert "error" in data
        assert "Unknown tool" in data["error"]

    @pytest.mark.asyncio
    async def test_valid_call_admin_mode(self, temp_storage):
        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict("os.environ", {"MCP_WITNESS_DEFAULT_ACCESS": "admin"}, clear=True):
                result = await call_tool("witness_health", {})

        data = json.loads(result[0].text)
        assert "status" in data
        assert "error" not in data

    @pytest.mark.asyncio
    async def test_permission_denied_writer_reads(self, temp_storage):
        """A writer role calling a read-only tool is denied."""
        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict(
                "os.environ",
                {
                    "MCP_WITNESS_API_KEYS": "cccccccccccccccccccccccccccccccc:writer",
                    "MCP_WITNESS_API_KEY": "cccccccccccccccccccccccccccccccc",
                },
                clear=True,
            ):
                result = await call_tool("witness_query", {})

        data = json.loads(result[0].text)
        assert "error" in data


class TestRbacRegistryConsistency:
    """Regression: every registered tool must be authorizable by some role.

    Previously witness_health/witness_delete/witness_search were registered as
    handlers but absent from every role in ROLE_PERMISSIONS, making them
    uncallable via call_tool even for admin.
    """

    def test_every_registered_tool_is_in_all_tools(self):
        from mcp_witness import server
        from mcp_witness.auth import ALL_TOOLS

        registered = set(server._TOOL_HANDLERS.keys())
        missing = registered - ALL_TOOLS
        assert not missing, f"Tools registered but not authorizable by any role: {sorted(missing)}"

    def test_admin_can_authorize_every_tool(self):
        from mcp_witness import server
        from mcp_witness.auth import AuthRole, authorize

        for name in server._TOOL_HANDLERS:
            # Should not raise for the admin role.
            authorize(AuthRole.ADMIN, name)
