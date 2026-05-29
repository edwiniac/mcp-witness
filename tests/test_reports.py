"""Tests for HTML/PDF compliance report generation (mcp_witness.reports)."""

import pytest

from mcp_witness.reports import (
    escape_html,
    generate_html_report,
    generate_pdf_report,
    get_bar_color,
    get_sensitivity_color,
    tag_class_for_action,
)
from mcp_witness.storage import SqliteStorage


@pytest.fixture
async def populated(tmp_path):
    store = SqliteStorage(tmp_path / "r.db")
    await store.connect()
    from mcp_witness.models import ActionType, Sensitivity

    await store.record(action_type=ActionType.TOOL_CALL, tool_name="t", reasoning="<b>hi</b>")
    await store.record(action_type=ActionType.DECISION, sensitivity=Sensitivity.PII)
    records = await store.query(limit=100)
    s = await store.get_stats()
    stats = {
        "unique_sessions": s.unique_sessions,
        "unique_actors": s.unique_actors,
        "attested_records": s.attested_records,
        "actions_by_type": s.records_by_action_type,
        "sensitivity_levels": s.records_by_sensitivity,
    }
    verification = await store.verify_chain()
    yield records, stats, verification
    await store.close()


class TestHtmlReport:
    @pytest.mark.asyncio
    async def test_generates_html_string(self, populated):
        records, stats, verification = populated
        html = generate_html_report(records, stats, verification)
        assert "<!DOCTYPE html>" in html or "<html" in html
        assert "Valid" in html
        # Reasoning is HTML-escaped (no raw tags injected).
        assert "<b>hi</b>" not in html

    @pytest.mark.asyncio
    async def test_writes_html_file(self, populated, tmp_path):
        records, stats, verification = populated
        out = tmp_path / "report.html"
        generate_html_report(records, stats, verification, output_path=str(out))
        assert out.exists()
        assert out.read_text(encoding="utf-8")

    @pytest.mark.asyncio
    async def test_pdf_falls_back_to_html_without_weasyprint(self, populated, tmp_path):
        records, stats, verification = populated
        out = tmp_path / "report.pdf"
        # weasyprint is not installed in the test env; the function should not raise.
        result = generate_pdf_report(records, stats, verification, output_path=str(out))
        # Either a path is returned or None (fallback); must not raise.
        assert result is None or isinstance(result, str)


class TestHelpers:
    def test_escape_html(self):
        assert escape_html("<script>") == "&lt;script&gt;"
        assert escape_html("a & b") == "a &amp; b"

    def test_color_helpers_return_strings(self):
        assert isinstance(get_bar_color("tool_call"), str)
        assert isinstance(get_sensitivity_color("pii"), str)
        assert isinstance(tag_class_for_action("decision"), str)

    def test_color_helpers_handle_unknown(self):
        # Unknown keys must still return a (default) color/class, not raise.
        assert isinstance(get_bar_color("totally_unknown"), str)
        assert isinstance(get_sensitivity_color("totally_unknown"), str)
        assert isinstance(tag_class_for_action("totally_unknown"), str)
