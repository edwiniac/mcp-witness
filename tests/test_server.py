"""Tests for MCP server tools."""

import pytest
import json
from datetime import datetime, timezone

from mcp_witness.server import (
    handle_record,
    handle_verify,
    handle_query,
    handle_chain,
    handle_stats,
    handle_attest,
    handle_export,
    list_tools,
)
from mcp_witness.models import ActionType


class TestListTools:
    """Tests for list_tools."""

    @pytest.mark.asyncio
    async def test_list_tools_returns_all_tools(self):
        tools = await list_tools()
        
        assert len(tools) == 7
        tool_names = [t.name for t in tools]
        assert "witness_record" in tool_names
        assert "witness_verify" in tool_names
        assert "witness_query" in tool_names
        assert "witness_chain" in tool_names
        assert "witness_stats" in tool_names
        assert "witness_attest" in tool_names
        assert "witness_export" in tool_names

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
        result = await handle_record(temp_storage, {
            "action_type": "tool_call",
            "tool_name": "test_tool",
        })
        
        assert result["recorded"] is True
        assert "record_id" in result
        assert result["sequence"] == 0
        assert "record_hash" in result

    @pytest.mark.asyncio
    async def test_record_with_data(self, temp_storage):
        result = await handle_record(temp_storage, {
            "action_type": "tool_call",
            "tool_name": "search",
            "input_data": {"query": "test"},
            "output_data": {"results": [1, 2, 3]},
            "reasoning": "User requested search",
            "confidence": 0.9,
            "sensitivity": "internal",
            "session_id": "session_abc",
            "actor_id": "claude-3",
        })
        
        assert result["recorded"] is True

    @pytest.mark.asyncio
    async def test_record_with_redaction(self, temp_storage):
        result = await handle_record(temp_storage, {
            "action_type": "tool_call",
            "input_data": {"ssn": "123-45-6789"},
            "redact_fields": ["ssn"],
        })
        
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
        
        result = await handle_verify(temp_storage, {
            "from_sequence": 1,
            "to_sequence": 3,
        })
        
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
        await handle_record(temp_storage, {
            "action_type": "tool_call",
            "session_id": "session_a",
        })
        await handle_record(temp_storage, {
            "action_type": "tool_call",
            "session_id": "session_b",
        })
        
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
        await handle_record(temp_storage, {
            "action_type": "tool_call",
            "session_id": "my_session",
        })
        await handle_record(temp_storage, {
            "action_type": "decision",
            "session_id": "my_session",
        })
        
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
        result = await handle_stats(temp_storage)
        
        assert result["total_records"] == 0
        assert result["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_stats_with_records(self, temp_storage):
        await handle_record(temp_storage, {
            "action_type": "tool_call",
            "actor_id": "claude",
            "session_id": "s1",
        })
        await handle_record(temp_storage, {
            "action_type": "decision",
            "actor_id": "claude",
            "session_id": "s1",
        })
        
        result = await handle_stats(temp_storage)
        
        assert result["total_records"] == 2
        assert result["unique_sessions"] == 1
        assert result["unique_actors"] == 1
        assert "✅" in result["chain_status"]


class TestHandleAttest:
    """Tests for handle_attest."""

    @pytest.mark.asyncio
    async def test_attest_specific_record(self, temp_storage):
        record_result = await handle_record(temp_storage, {"action_type": "tool_call"})
        record_id = record_result["record_id"]
        
        result = await handle_attest(temp_storage, {"record_id": record_id})
        
        assert result["success"] is True
        assert result["records_attested"] == 1

    @pytest.mark.asyncio
    async def test_attest_batch(self, temp_storage):
        await handle_record(temp_storage, {"action_type": "tool_call"})
        await handle_record(temp_storage, {"action_type": "decision"})
        
        result = await handle_attest(temp_storage, {"batch": True})
        
        assert result["success"] is True
        assert result["records_attested"] == 2

    @pytest.mark.asyncio
    async def test_attest_nonexistent(self, temp_storage):
        result = await handle_attest(temp_storage, {"record_id": "nonexistent"})
        
        assert "error" in result


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
