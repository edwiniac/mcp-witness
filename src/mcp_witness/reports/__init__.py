"""
Report generators for mcp-witness.

Generates HTML compliance reports and (optionally) PDF reports.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models import VerificationResult, WitnessRecord

logger = logging.getLogger(__name__)


def generate_html_report(
    records: list[WitnessRecord],
    stats: dict,
    verification: VerificationResult,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate standalone HTML compliance report.

    Args:
        records: List of WitnessRecord objects
        stats: Dictionary with summary statistics
        verification: Chain verification result
        output_path: Optional file path to write the HTML to

    Returns:
        The HTML string
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    record_count = len(records)
    chain_status = "✅ Valid" if verification.valid else "❌ Broken"
    chain_badge = "badge-ok" if verification.valid else "badge-err"

    # Summary statistics
    unique_sessions = stats.get("unique_sessions", 0)
    unique_actors = stats.get("unique_actors", 0)
    attested = stats.get("attested_records", 0)
    first_record = stats.get("first_record", "N/A")
    last_record = stats.get("last_record", "N/A")

    # Action types breakdown
    actions_by_type = stats.get("actions_by_type", {})
    action_rows = ""
    for atype, count in sorted(actions_by_type.items()):
        pct = round(count / max(record_count, 1) * 100, 1)
        color = get_bar_color(atype)
        action_rows += f"""
        <div class="bar-group">
            <div class="bar-label"><span>{escape_html(atype)}</span><span>{count} ({pct}%)</span></div>
            <div class="bar-track"><div class="bar-fill" style="width:{max(pct,2)}%;background:{color}"></div></div>
        </div>"""

    # Sensitivity breakdown
    sensitivity_levels = stats.get("sensitivity_levels", {})
    sensitivity_rows = ""
    for sens, count in sorted(sensitivity_levels.items()):
        pct = round(count / max(record_count, 1) * 100, 1)
        color = get_sensitivity_color(sens)
        sensitivity_rows += f"""
        <div class="bar-group">
            <div class="bar-label"><span>{escape_html(sens)}</span><span>{count} ({pct}%)</span></div>
            <div class="bar-track"><div class="bar-fill" style="width:{max(pct,2)}%;background:{color}"></div></div>
        </div>"""

    # Chain issues
    chain_issues = ""
    if not verification.valid and verification.issues:
        chain_issues = """
        <div class="section">
            <h2>⚠️ Chain Issues</h2>
            <div class="issues-list">"""
        for issue in verification.issues:
            chain_issues += f'<div class="issue-item">{escape_html(issue)}</div>'
        chain_issues += """
            </div>
        </div>"""

    # Records table
    records_table_rows = ""
    for r in records:
        ts = (
            r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(r.timestamp, "strftime")
            else str(r.timestamp)[:19]
        )
        sens_tag_class = (
            f"tag-{r.sensitivity.value}" if hasattr(r.sensitivity, "value") else "tag-internal"
        )
        records_table_rows += f"""
                <tr>
                    <td>{r.sequence}</td>
                    <td>{ts}</td>
                    <td><span class="tag {tag_class_for_action(r.action_type.value if hasattr(r.action_type, 'value') else r.action_type)}">{escape_html(r.action_type.value if hasattr(r.action_type, 'value') else r.action_type)}</span></td>
                    <td>{escape_html(r.tool_name or '—')}</td>
                    <td>{escape_html(r.actor_id)}</td>
                    <td><span class="tag {sens_tag_class}">{escape_html(r.sensitivity.value if hasattr(r.sensitivity, 'value') else r.sensitivity)}</span></td>
                    <td class="hash">{r.record_hash[:16] if r.record_hash else '—'}...</td>
                </tr>"""

    records_section = ""
    if not records:
        records_section = '<div class="empty">No records in the database.</div>'
    else:
        records_section = f"""
        <table>
            <thead>
                <tr>
                    <th>Seq</th>
                    <th>Timestamp</th>
                    <th>Action Type</th>
                    <th>Tool</th>
                    <th>Actor</th>
                    <th>Sensitivity</th>
                    <th>Hash</th>
                </tr>
            </thead>
            <tbody>
                {records_table_rows}
            </tbody>
        </table>"""

    # Checkpoints
    checkpoints = stats.get("checkpoints", [])
    checkpoints_section = ""
    if checkpoints:
        cp_rows = ""
        for cp in checkpoints:
            cp_rows += f"""
            <div class="checkpoint-item">
                <div class="cp-header"><strong>Checkpoint #{cp.get('id', '?')}</strong></div>
                <div class="cp-detail">Records {cp.get('from_sequence', '?')}–{cp.get('to_sequence', '?')}</div>
                <div class="cp-detail">Count: {cp.get('record_count', 0)} records</div>
                <div class="cp-detail hash">Root: {cp.get('merkle_root', '?')[:24]}...</div>
            </div>"""
        checkpoints_section = cp_rows
    else:
        checkpoints_section = '<div class="empty">No checkpoints created yet.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📋 MCP Witness Compliance Report</title>
<style>
  :root {{
    --bg: #0a0e14;
    --surface: #141b22;
    --surface2: #1c2430;
    --border: #2a3340;
    --text: #cdd6e0;
    --text2: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d2991d;
    --purple: #a371f7;
    --radius: 8px;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    line-height: 1.6;
    padding: 20px;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; }}
  h2 {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 12px; color: var(--accent); }}
  .meta {{ color: var(--text2); font-size: 0.85rem; margin-bottom: 24px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 28px; }}
  .meta-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }}
  .meta-card .label {{ font-size: 0.7rem; color: var(--text2); text-transform: uppercase; letter-spacing: 0.05em; }}
  .meta-card .value {{ font-size: 1.3rem; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--accent); }}
  .badge {{ display: inline-block; padding: 4px 14px; border-radius: 20px; font-weight: 600; font-size: 0.85rem; }}
  .badge-ok {{ background: #1a3a1a; color: var(--green); border: 1px solid #2a5a2a; }}
  .badge-err {{ background: #3a1a1a; color: var(--red); border: 1px solid #5a2a2a; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 20px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
  @media (max-width: 768px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  th {{ text-align: left; padding: 10px 12px; color: var(--text2); font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; background: #111820; }}
  td {{ padding: 8px 12px; border-top: 1px solid var(--border); }}
  tr:hover td {{ background: #1a2230; }}
  .hash {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.75rem; color: var(--text2); }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 500; }}
  .tag-tool_call {{ background: #1a2a3a; color: var(--accent); }}
  .tag-decision {{ background: #2a1a3a; color: var(--purple); }}
  .tag-output {{ background: #1a3a2a; color: var(--green); }}
  .tag-error {{ background: #3a1a1a; color: var(--red); }}
  .tag-snapshot {{ background: #3a3a1a; color: var(--yellow); }}
  .tag-pii, .tag-phi, .tag-confidential {{ background: #3a1a1a; color: var(--red); }}
  .tag-internal {{ background: #1a2a3a; color: var(--accent); }}
  .tag-public {{ background: #1a3a2a; color: var(--green); }}
  .bar-group {{ margin-bottom: 10px; }}
  .bar-label {{ display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 0.8rem; }}
  .bar-track {{ height: 8px; background: var(--surface2); border-radius: 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; }}
  .checkpoint-item {{ padding: 12px 0; border-bottom: 1px solid var(--border); }}
  .checkpoint-item:last-child {{ border-bottom: none; }}
  .cp-header {{ font-size: 0.85rem; }}
  .cp-detail {{ font-size: 0.8rem; color: var(--text2); }}
  .issues-list {{ margin-top: 8px; }}
  .issue-item {{ padding: 8px 12px; background: #3a1a1a; border: 1px solid #5a2a2a; border-radius: 4px; margin-bottom: 6px; font-size: 0.8rem; color: var(--red); }}
  .empty {{ padding: 30px; text-align: center; color: var(--text2); font-size: 0.85rem; }}
  footer {{ margin-top: 30px; text-align: center; font-size: 0.75rem; color: var(--text2); }}
</style>
</head>
<body>
<div class="container">
  <h1>📋 MCP Witness Compliance Report</h1>
  <p class="meta">Generated: {escape_html(generated_at)} · Records: {record_count} · Chain: <span class="badge {chain_badge}">{chain_status}</span></p>

  <div class="meta-grid">
    <div class="meta-card"><div class="label">Total Records</div><div class="value">{record_count}</div></div>
    <div class="meta-card"><div class="label">Sessions</div><div class="value">{unique_sessions}</div></div>
    <div class="meta-card"><div class="label">Actors</div><div class="value">{unique_actors}</div></div>
    <div class="meta-card"><div class="label">Attested</div><div class="value">{attested}</div></div>
    <div class="meta-card"><div class="label">First Record</div><div class="value" style="font-size:0.85rem;">{escape_html(str(first_record)[:19])}</div></div>
    <div class="meta-card"><div class="label">Last Record</div><div class="value" style="font-size:0.85rem;">{escape_html(str(last_record)[:19])}</div></div>
  </div>

  <div class="grid-2">
    <div class="section">
      <h2>📊 Actions by Type</h2>
      {action_rows if action_rows else '<div class="empty">No data</div>'}
    </div>
    <div class="section">
      <h2>🛡️ Sensitivity Distribution</h2>
      {sensitivity_rows if sensitivity_rows else '<div class="empty">No data</div>'}
    </div>
  </div>

  <div class="section">
    <h2>🔗 Chain Integrity</h2>
    <p>Status: <span class="badge {chain_badge}">{chain_status}</span></p>
    <p style="font-size:0.85rem;color:var(--text2);margin-top:4px;">Records verified: {verification.records_checked}</p>
    {chain_issues}
  </div>

  <div class="section">
    <h2>📋 Records</h2>
    {records_section}
  </div>

  <div class="section">
    <h2>📦 Checkpoints</h2>
    {checkpoints_section}
  </div>

  <footer>
    Generated by mcp-witness · {escape_html(generated_at)}
  </footer>
</div>
</body>
</html>"""

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html)
        logger.info("HTML report written to %s", path)

    return html


def generate_pdf_report(
    records: list[WitnessRecord],
    stats: dict,
    verification: VerificationResult,
    output_path: Optional[str] = None,
) -> Optional[str]:
    """
    Generate a PDF compliance report.

    First generates HTML, then attempts to convert to PDF using weasyprint.
    Falls back to generating HTML only if weasyprint is not available.

    Args:
        records: List of WitnessRecord objects
        stats: Dictionary with summary statistics
        verification: Chain verification result
        output_path: Optional file path for the PDF

    Returns:
        Path to the generated PDF file, or None if PDF generation failed
    """
    html = generate_html_report(records, stats, verification)

    if output_path is None:
        output_path = (
            f"mcp-witness-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.pdf"
        )

    path = Path(output_path)

    try:
        import weasyprint

        weasyprint.HTML(string=html).write_pdf(path)
        logger.info("PDF report written to %s", path)
        return str(path)
    except ImportError:
        logger.warning(
            "weasyprint not installed. Install with: pip install weasyprint. "
            "Falling back to HTML report."
        )
        # Generate HTML report instead
        html_path = path.with_suffix(".html")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)
        logger.info("HTML report written to %s (weasyprint not available for PDF)", html_path)
        return None
    except Exception as e:
        logger.error("PDF generation failed: %s", e, exc_info=True)
        # Generate HTML as fallback
        html_path = path.with_suffix(".html")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)
        logger.info("HTML fallback report written to %s", html_path)
        return None


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def get_bar_color(action_type: str) -> str:
    """Get a bar chart color for an action type."""
    colors = {
        "tool_call": "#58a6ff",
        "decision": "#a371f7",
        "output": "#3fb950",
        "error": "#f85149",
        "snapshot": "#d2991d",
    }
    return colors.get(action_type.lower(), "#58a6ff")


def get_sensitivity_color(sensitivity: str) -> str:
    """Get a bar chart color for a sensitivity level."""
    colors = {
        "public": "#3fb950",
        "internal": "#58a6ff",
        "pii": "#d2991d",
        "phi": "#f85149",
        "confidential": "#f85149",
    }
    return colors.get(sensitivity.lower(), "#58a6ff")


def tag_class_for_action(action_type: str) -> str:
    """Get the CSS tag class for an action type."""
    return f"tag-{action_type}"
