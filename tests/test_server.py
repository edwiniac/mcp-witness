"""Tests for MCP server tools."""

import pytest

from mcp_witness.server import (
    handle_attest,
    handle_chain,
    handle_export,
    handle_query,
    handle_record,
    handle_stats,
    handle_verify,
    list_tools,
)


class TestListTools:
    """Tests for list_tools."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_all_tools(self):
        tools = await list_tools()

        assert len(tools) >= 17
        tool_names = [t.name for t in tools]
        # Original tools
        assert "witness_record" in tool_names
        assert "witness_verify" in tool_names
        assert "witness_query" in tool_names
        assert "witness_chain" in tool_names
        assert "witness_stats" in tool_names
        assert "witness_attest" in tool_names
        assert "witness_export" in tool_names
        # v0.2.0: Merkle checkpoint and anchoring tools
        assert "witness_checkpoints" in tool_names
        assert "witness_verify_fast" in tool_names
        assert "witness_anchor" in tool_names
        assert "witness_verify_anchors" in tool_names
        assert "witness_proof" in tool_names
        assert "witness_backfill" in tool_names
        # v0.4.0: Health, Delete, Search
        assert "witness_health" in tool_names
        assert "witness_delete" in tool_names
        assert "witness_search" in tool_names

    @pytest.mark.asyncio
    async def test_tools_have_schemas(self):
        tools = await list_tools()

        for tool in tools:
            assert tool.name
            assert tool.description
            assert tool.inputSchema


class TestHandleRecord:
    """Tests for handle_record."""

    @pytest.mark.asyncio
    async def test_record_basic(self, temp_storage):
        result = await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "tool_name": "test_tool",
            },
        )

        assert result["recorded"] is True
        assert "record_id" in result
        assert result["sequence"] == 0
        assert "record_hash" in result

    @pytest.mark.asyncio
    async def test_record_with_data(self, temp_storage):
        result = await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "tool_name": "search",
                "input_data": {"query": "test"},
                "output_data": {"results": [1, 2, 3]},
                "reasoning": "User requested search",
                "confidence": 0.9,
                "sensitivity": "internal",
                "session_id": "session_abc",
                "actor_id": "claude-3",
            },
        )

        assert result["recorded"] is True

    @pytest.mark.asyncio
    async def test_record_with_redaction(self, temp_storage):
        result = await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "input_data": {"ssn": "123-45-6789"},
                "redact_fields": ["ssn"],
            },
        )

        assert result["recorded"] is True


class TestHandleVerify:
    """Tests for handle_verify."""

    @pytest.mark.asyncio
    async def test_verify_empty_chain(self, temp_storage):
        result = await handle_verify(temp_storage, {})

        assert result["valid"] is True
        assert result["records_checked"] == 0

    @pytest.mark.asyncio
    async def test_verify_valid_chain(self, temp_storage):
        # Create records
        for _ in range(3):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_verify(temp_storage, {"full_chain": True})

        assert result["valid"] is True
        assert result["records_checked"] == 3
        assert "✅" in result["status"]

    @pytest.mark.asyncio
    async def test_verify_range(self, temp_storage):
        for _ in range(5):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_verify(
            temp_storage,
            {
                "from_sequence": 1,
                "to_sequence": 3,
            },
        )

        assert result["records_checked"] == 3


class TestHandleQuery:
    """Tests for handle_query."""

    @pytest.mark.asyncio
    async def test_query_all(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})

        result = await handle_query(temp_storage, {})

        assert result["count"] == 2
        assert len(result["records"]) == 2

    @pytest.mark.asyncio
    async def test_query_by_session(self, temp_storage):
        await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "session_id": "session_a",
            },
        )
        await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "session_id": "session_b",
            },
        )

        result = await handle_query(temp_storage, {"session_id": "session_a"})

        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_query_by_action_type(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})
        await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_query(temp_storage, {"action_type": "tool_call"})

        assert result["count"] == 2

    @pytest.mark.asyncio
    async def test_query_with_limit(self, temp_storage):
        for _ in range(10):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_query(temp_storage, {"limit": 5})

        assert result["count"] == 5


class TestHandleChain:
    """Tests for handle_chain."""

    @pytest.mark.asyncio
    async def test_chain_by_session(self, temp_storage):
        await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "session_id": "my_session",
            },
        )
        await handle_record(
            temp_storage,
            {
                "action_type": "decision",
                "session_id": "my_session",
            },
        )

        result = await handle_chain(temp_storage, {"session_id": "my_session"})

        assert result["session_id"] == "my_session"
        assert result["chain_length"] == 2

    @pytest.mark.asyncio
    async def test_chain_missing_session(self, temp_storage):
        result = await handle_chain(temp_storage, {})

        assert "error" in result


class TestHandleStats:
    """Tests for handle_stats."""

    @pytest.mark.asyncio
    async def test_stats_empty(self, temp_storage):
        result = await handle_stats(temp_storage, {})

        assert result["total_records"] == 0
        assert result["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_stats_with_records(self, temp_storage):
        await handle_record(
            temp_storage,
            {
                "action_type": "tool_call",
                "actor_id": "claude",
                "session_id": "s1",
            },
        )
        await handle_record(
            temp_storage,
            {
                "action_type": "decision",
                "actor_id": "claude",
                "session_id": "s1",
            },
        )

        result = await handle_stats(temp_storage, {})

        assert result["total_records"] == 2
        assert result["unique_sessions"] == 1
        assert result["unique_actors"] == 1
        assert "✅" in result["chain_status"]


class TestHandleAttest:
    """Tests for handle_attest."""

    @staticmethod
    def _fake_anchor():
        """Return an AsyncMock that produces a deterministic TSA receipt.

        Avoids hitting a live RFC 3161 TSA during unit tests.
        """
        from datetime import datetime, timezone
        from unittest.mock import AsyncMock

        from mcp_witness.anchoring import AnchorReceipt, AnchorType

        async def _anchor(merkle_root, metadata=None, anchor_types=None):
            return [
                AnchorReceipt(
                    anchor_type=AnchorType.TSA,
                    merkle_root=merkle_root,
                    timestamp=datetime.now(timezone.utc),
                    receipt_id="test-receipt",
                    raw_receipt=b"\x00fake-tsa-receipt",
                )
            ]

        return AsyncMock(side_effect=_anchor)

    @pytest.mark.asyncio
    async def test_attest_specific_record(self, temp_storage):
        from unittest.mock import patch

        record_result = await handle_record(temp_storage, {"action_type": "tool_call"})
        record_id = record_result["record_id"]

        with patch("mcp_witness.anchoring.AnchorService.anchor", self._fake_anchor()):
            result = await handle_attest(temp_storage, {"record_id": record_id})

        assert result["success"] is True
        assert result["records_attested"] == 1

    @pytest.mark.asyncio
    async def test_attest_batch(self, temp_storage):
        from unittest.mock import patch

        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})

        with patch("mcp_witness.anchoring.AnchorService.anchor", self._fake_anchor()):
            result = await handle_attest(temp_storage, {"batch": True})

        assert result["success"] is True
        assert result["records_attested"] == 2

    @pytest.mark.asyncio
    async def test_attest_nonexistent(self, temp_storage):
        result = await handle_attest(temp_storage, {"record_id": "nonexistent"})

        assert "error" in result


# =========================================================================
# Auth Integration Tests
# =========================================================================


class TestCallToolAuth:
    """Tests for auth integration in call_tool."""

    @pytest.mark.asyncio
    async def test_call_tool_open_mode(self, temp_storage):
        """Explicit open/admin mode (no keys) allows all tools."""
        from unittest.mock import patch

        from mcp_witness.server import call_tool

        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            # MCP_WITNESS_DEFAULT_ACCESS=admin is resolved at call time, opting
            # out of the secure deny-by-default behavior for local development.
            with patch.dict("os.environ", {"MCP_WITNESS_DEFAULT_ACCESS": "admin"}, clear=True):
                result = await call_tool("witness_stats", {})

        import json

        data = json.loads(result[0].text)
        assert "total_records" in data or "error" not in data

    @pytest.mark.asyncio
    async def test_call_tool_deny_by_default(self, temp_storage):
        """With no auth configured and no override, access is denied (secure default)."""
        import json
        from unittest.mock import patch

        from mcp_witness.server import call_tool

        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict("os.environ", {}, clear=True):
                result = await call_tool("witness_stats", {})

        data = json.loads(result[0].text)
        assert "error" in data
        assert "deny" in data["error"].lower() or "authentication" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_call_tool_with_auth_admin(self, temp_storage):
        """Admin key can call any tool."""
        from unittest.mock import patch

        from mcp_witness.server import call_tool

        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict(
                "os.environ",
                {
                    "MCP_WITNESS_API_KEYS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:admin",
                    "MCP_WITNESS_API_KEY": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
                clear=True,
            ):
                result = await call_tool("witness_stats", {})

        import json

        data = json.loads(result[0].text)
        assert "total_records" in data

    @pytest.mark.asyncio
    async def test_call_tool_with_auth_read_only(self, temp_storage):
        """Auditor cannot call write tools."""
        from unittest.mock import patch

        from mcp_witness.server import call_tool

        with patch("mcp_witness.server.get_storage", return_value=temp_storage):
            with patch.dict(
                "os.environ",
                {
                    "MCP_WITNESS_API_KEYS": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:auditor",
                    "MCP_WITNESS_API_KEY": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
                clear=True,
            ):
                result = await call_tool("witness_record", {"action_type": "tool_call"})

        import json

        data = json.loads(result[0].text)
        assert "error" in data or "PermissionError" in str(data)
        # Should have error (PermissionError is safe and gets type+message)
        if "error" in data:
            assert (
                "permission" in data.get("error", "").lower()
                or "role" in data.get("error", "").lower()
            )


class TestHandleExport:
    """Tests for handle_export."""

    @pytest.mark.asyncio
    async def test_export_json(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})

        result = await handle_export(temp_storage, {"format": "json"})

        assert result["export_format"] == "json"
        assert len(result["records"]) == 2
        assert result["chain_verification"]["valid"] is True

    @pytest.mark.asyncio
    async def test_export_summary(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_export(temp_storage, {"format": "summary"})

        assert result["export_format"] == "summary"
        assert result["record_count"] == 1

    @pytest.mark.asyncio
    async def test_export_empty(self, temp_storage):
        result = await handle_export(temp_storage, {})

        assert len(result["records"]) == 0


class TestPaginationClamping:
    """Tests for pagination clamping (TASK 1.8)."""

    @pytest.mark.asyncio
    async def test_query_limit_clamped(self, temp_storage):
        """Query limit is clamped to MAX_QUERY_LIMIT."""
        from mcp_witness.server import MAX_QUERY_LIMIT

        result = await handle_query(temp_storage, {"limit": MAX_QUERY_LIMIT + 99999})
        # Should not error - limit gets clamped
        assert "count" in result

    @pytest.mark.asyncio
    async def test_query_limit_normal(self, temp_storage):
        """Normal query limit is not affected."""
        for _ in range(5):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_query(temp_storage, {"limit": 3})
        assert result["count"] == 3

    @pytest.mark.asyncio
    async def test_export_limit_clamped(self, temp_storage):
        """Export query uses MAX_QUERY_LIMIT."""
        # Create a few records
        for _ in range(3):
            await handle_record(temp_storage, {"action_type": "tool_call"})

        result = await handle_export(temp_storage, {})
        assert "records" in result
        assert len(result["records"]) == 3


class TestHealthCheck:
    """Tests for health check endpoint (TASK 2.5)."""

    @pytest.mark.asyncio
    async def test_health_includes_chain_verification_status(self, temp_storage):
        """Health endpoint includes chain_verified_at_startup field."""
        from mcp_witness.server import handle_health

        result = await handle_health(temp_storage, {})

        assert "chain_verified_at_startup" in result
        # Fresh storage should have valid chain at startup or None if not yet checked
        assert (
            result["chain_verified_at_startup"] is True
            or result["chain_verified_at_startup"] is None
        )

    @pytest.mark.asyncio
    async def test_health_returns_status(self, temp_storage):
        """Health endpoint returns operation status."""
        from mcp_witness.server import handle_health

        result = await handle_health(temp_storage, {})

        assert "status" in result
        assert result["status"] in ("healthy", "unhealthy")
        assert "version" in result
        assert "database" in result
        assert "signing" in result
