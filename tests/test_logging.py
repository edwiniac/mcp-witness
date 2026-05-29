"""Tests for structured JSON logging and sensitive-data scrubbing."""

import json
import logging

import pytest

from mcp_witness.logging import (
    JSONFormatter,
    SensitiveDataFilter,
    setup_structured_logging,
)


def _make_record(msg, exc_info=None):
    return logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg=msg,
        args=(),
        exc_info=exc_info,
    )


class TestJSONFormatter:
    def test_basic_fields(self):
        out = JSONFormatter().format(_make_record("hello world"))
        data = json.loads(out)
        assert data["message"] == "hello world"
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert "timestamp" in data and "line" in data

    def test_extra_fields_included(self):
        rec = _make_record("with extra")
        rec.extra_fields = {"request_id": "abc123"}
        data = json.loads(JSONFormatter().format(rec))
        assert data["request_id"] == "abc123"

    def test_exception_info(self):
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            rec = _make_record("failed", exc_info=sys.exc_info())
        data = json.loads(JSONFormatter().format(rec))
        assert data["exception"]["type"] == "ValueError"
        assert "boom" in data["exception"]["message"]


class TestSensitiveDataFilter:
    def test_redacts_credentials(self):
        rec = _make_record("api_key=ABCDEFGHIJKLMNOPQRSTUVWX")
        SensitiveDataFilter().filter(rec)
        assert "[CREDENTIAL]" in rec.msg
        assert "ABCDEFGHIJKLMNOPQRSTUVWX" not in rec.msg

    def test_redacts_long_hex(self):
        rec = _make_record("key " + "a" * 64)
        SensitiveDataFilter().filter(rec)
        assert "[HEX_KEY]" in rec.msg

    def test_redacts_openai_style_key(self):
        rec = _make_record("token sk-" + "a" * 24)
        SensitiveDataFilter().filter(rec)
        assert "[API_KEY]" in rec.msg or "[CREDENTIAL]" in rec.msg

    def test_non_string_msg_passes_through(self):
        rec = _make_record(12345)
        assert SensitiveDataFilter().filter(rec) is True


class TestSetupStructuredLogging:
    @pytest.fixture(autouse=True)
    def _restore_root(self):
        root = logging.getLogger()
        saved = root.handlers[:]
        saved_level = root.level
        yield
        root.handlers[:] = saved
        root.setLevel(saved_level)

    def test_json_format(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_LOG_FORMAT", "json")
        setup_structured_logging()
        root = logging.getLogger()
        assert any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)
        # Sensitive filter registered on the handler.
        assert any(
            any(isinstance(f, SensitiveDataFilter) for f in h.filters) for h in root.handlers
        )

    def test_text_format_default(self, monkeypatch):
        monkeypatch.setenv("MCP_WITNESS_LOG_FORMAT", "text")
        monkeypatch.setenv("MCP_WITNESS_LOG_LEVEL", "DEBUG")
        setup_structured_logging()
        root = logging.getLogger()
        assert root.level == logging.DEBUG
        assert root.handlers
