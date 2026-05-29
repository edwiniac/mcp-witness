"""Unit tests for the mcp-witness CLI (mcp_witness.cli)."""

import asyncio
import json
import types
from pathlib import Path

import pytest

from mcp_witness import __version__, cli
from mcp_witness.models import ActionType, Sensitivity
from mcp_witness.storage import SqliteStorage

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def make_args(**kwargs):
    """Build a fake argparse-like namespace with sensible defaults.

    Every attribute the various cmd_* functions might read is given a default
    so individual tests only need to override what matters to them.
    """
    defaults = {
        "db": None,
        "fast": False,
        "from_seq": None,
        "to_seq": None,
        "format": "json",
        "output": None,
        "sequence": 0,
        "limit": 20,
        "query": "",
        "action": None,
        "checkpoint_id": 0,
        "tsa": False,
        "ots": False,
        "ipfs": False,
        "no_serve": False,
        "host": "127.0.0.1",
        "port": None,
        "dry_run": False,
        "to_version": None,
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


async def _seed_records(db_path, count=3):
    """Insert a few records directly into a fresh DB at db_path."""
    store = SqliteStorage(Path(db_path))
    await store.connect()
    try:
        await store.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="search_tool",
            actor_id="claude",
            session_id="sess_a",
            reasoning="Looking up the capital of France for the user",
            sensitivity=Sensitivity.INTERNAL,
        )
        await store.record(
            action_type=ActionType.DECISION,
            actor_id="claude",
            session_id="sess_a",
            reasoning="Decided Paris based on tool output",
        )
        await store.record(
            action_type=ActionType.OUTPUT,
            actor_id="gpt",
            session_id="sess_b",
            output_data={"answer": "Paris"},
        )
    finally:
        await store.close()


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Provide an isolated, initialized witness DB path via MCP_WITNESS_DB."""
    db_path = tmp_path / "witness.db"
    monkeypatch.setenv("MCP_WITNESS_DB", str(db_path))
    # Initialize the schema by running cmd_init.
    cli.cmd_init(make_args())
    return str(db_path)


@pytest.fixture
def db_with_records(db):
    """An initialized DB pre-populated with a few records."""
    asyncio.run(_seed_records(db))
    return db


# ---------------------------------------------------------------------------
# Helper-function tests
# ---------------------------------------------------------------------------


def test_pads_truncates_long_string():
    assert cli._pads("abcdefghijklmnop") == "abcdefgh..."


def test_pads_keeps_short_string():
    assert cli._pads("abc") == "abc"


def test_get_db_path_from_args():
    assert cli._get_db_path(make_args(db="/tmp/explicit.db")) == "/tmp/explicit.db"


def test_get_db_path_from_env(monkeypatch):
    monkeypatch.setenv("MCP_WITNESS_DB", "/tmp/from_env.db")
    assert cli._get_db_path(make_args()) == "/tmp/from_env.db"


def test_get_db_path_expands_user(monkeypatch):
    monkeypatch.delenv("MCP_WITNESS_DB", raising=False)
    path = cli._get_db_path(make_args())
    assert "~" not in path
    assert path.endswith(".mcp-witness/witness.db")


# ---------------------------------------------------------------------------
# cmd_init
# ---------------------------------------------------------------------------


def test_cmd_init_creates_db(tmp_path, monkeypatch, capsys):
    db_path = tmp_path / "init.db"
    monkeypatch.setenv("MCP_WITNESS_DB", str(db_path))
    cli.cmd_init(make_args())
    out = capsys.readouterr().out
    assert "✅ Witness database initialized" in out
    assert "Records: 0" in out
    assert db_path.exists()


def test_cmd_init_failure_exits(tmp_path, monkeypatch, capsys):
    # Point --db at a directory: connect() then fails inside the try/except,
    # exercising the "Failed to initialize" branch.
    a_dir = tmp_path / "iam_a_dir"
    a_dir.mkdir()
    with pytest.raises(SystemExit) as exc:
        cli.cmd_init(make_args(db=str(a_dir)))
    assert exc.value.code == 1
    assert "❌ Failed to initialize" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# cmd_verify
# ---------------------------------------------------------------------------


def test_cmd_verify_valid(db_with_records, capsys):
    cli.cmd_verify(make_args())
    out = capsys.readouterr().out
    assert "✅ Chain integrity VERIFIED" in out
    assert "3 records" in out


def test_cmd_verify_range(db_with_records, capsys):
    cli.cmd_verify(make_args(from_seq=0, to_seq=1))
    out = capsys.readouterr().out
    assert "✅ Chain integrity VERIFIED" in out


def test_cmd_verify_fast(db_with_records, capsys):
    cli.cmd_verify(make_args(fast=True))
    out = capsys.readouterr().out
    assert "Chain integrity" in out


def test_cmd_verify_detects_tamper(db_with_records, capsys):
    async def _tamper():
        store = SqliteStorage(Path(db_with_records))
        await store.connect()
        await store._db.execute(
            "UPDATE witness_records SET record_hash = ? WHERE sequence = ?",
            ("deadbeef" * 8, 1),
        )
        await store._db.commit()
        await store.close()

    asyncio.run(_tamper())

    with pytest.raises(SystemExit) as exc:
        cli.cmd_verify(make_args())
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "❌ Chain integrity FAILED" in out


# ---------------------------------------------------------------------------
# cmd_stats
# ---------------------------------------------------------------------------


def test_cmd_stats_empty(db, capsys):
    cli.cmd_stats(make_args())
    out = capsys.readouterr().out
    assert "Chain Statistics" in out
    assert "Total Records:      0" in out


def test_cmd_stats_with_records(db_with_records, capsys):
    cli.cmd_stats(make_args())
    out = capsys.readouterr().out
    assert "Total Records:      3" in out
    assert "Unique Sessions:    2" in out
    assert "Unique Actors:      2" in out
    assert "Actions by Type:" in out
    assert "Sensitivity Levels:" in out


# ---------------------------------------------------------------------------
# cmd_export
# ---------------------------------------------------------------------------


def test_cmd_export_json_stdout(db_with_records, capsys):
    cli.cmd_export(make_args(format="json"))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["record_count"] == 3
    assert data["chain_verification"]["valid"] is True
    assert len(data["records"]) == 3


def test_cmd_export_summary(db_with_records, capsys):
    cli.cmd_export(make_args(format="summary"))
    out = capsys.readouterr().out
    assert "Total Records:    3" in out
    assert "Chain Valid:" in out


def test_cmd_export_to_file(db_with_records, tmp_path, monkeypatch, capsys):
    # validate_export_path requires output within MCP_WITNESS_EXPORT_DIR.
    monkeypatch.setenv("MCP_WITNESS_EXPORT_DIR", str(tmp_path))
    import importlib

    import mcp_witness.security as sec

    importlib.reload(sec)
    try:
        out_file = tmp_path / "report.json"
        cli.cmd_export(make_args(format="json", output=str(out_file)))
        out = capsys.readouterr().out
        assert "✅ Exported 3 records" in out
        assert out_file.exists()
        saved = json.loads(out_file.read_text())
        assert saved["record_count"] == 3
    finally:
        importlib.reload(sec)


# ---------------------------------------------------------------------------
# cmd_proof
# ---------------------------------------------------------------------------


def test_cmd_proof_not_checkpointed_exits(db_with_records, capsys):
    # With only a few records, no checkpoint exists -> get_proof_package
    # returns an "error" dict and cmd_proof exits 1.
    with pytest.raises(SystemExit) as exc:
        cli.cmd_proof(make_args(sequence=0))
    assert exc.value.code == 1
    assert "❌" in capsys.readouterr().out


def test_cmd_proof_missing_record_exits(db, capsys):
    # No records at all -> get_proof_package returns None.
    with pytest.raises(SystemExit) as exc:
        cli.cmd_proof(make_args(sequence=99))
    assert exc.value.code == 1
    assert "❌" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# cmd_checkpoints
# ---------------------------------------------------------------------------


def test_cmd_checkpoints_empty(db_with_records, capsys):
    cli.cmd_checkpoints(make_args(limit=20))
    out = capsys.readouterr().out
    assert "No checkpoints found" in out


# ---------------------------------------------------------------------------
# cmd_search
# ---------------------------------------------------------------------------


def test_cmd_search_finds_records(db_with_records, capsys):
    cli.cmd_search(make_args(query="Paris", limit=50))
    out = capsys.readouterr().out
    assert "Search results for 'Paris'" in out


def test_cmd_search_no_results(db_with_records, capsys):
    cli.cmd_search(make_args(query="zzzznomatchzzzz", limit=50))
    out = capsys.readouterr().out
    assert "0 records" in out


# ---------------------------------------------------------------------------
# cmd_metrics
# ---------------------------------------------------------------------------


def test_cmd_metrics(capsys):
    cli.cmd_metrics(make_args())
    out = capsys.readouterr().out
    assert "Operational Metrics" in out
    assert "Chain Breaks:" in out
    assert "Records Written:" in out
    assert "Lock Contention:" in out


# ---------------------------------------------------------------------------
# cmd_migrate / cmd_migrations
# ---------------------------------------------------------------------------


def test_cmd_migrate_dry_run(db, capsys):
    cli.cmd_migrate(make_args(dry_run=True))
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "No migrations applied" in out


def test_cmd_migrate_apply(db, capsys):
    cli.cmd_migrate(make_args(dry_run=False))
    out = capsys.readouterr().out
    assert "Schema version before:" in out
    assert "Schema version after:" in out


def test_cmd_migrations_list(db, capsys):
    cli.cmd_migrations(make_args())
    out = capsys.readouterr().out
    assert "Schema Versions:" in out


# ---------------------------------------------------------------------------
# cmd_jwt_sign
# ---------------------------------------------------------------------------


def _gen_ed25519_hex():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes_raw().hex()


def test_cmd_jwt_sign_emits_token(capsys):
    priv = _gen_ed25519_hex()
    cli.cmd_jwt_sign(["--private-key", priv, "--sub", "client-1", "--role", "reader"])
    out = capsys.readouterr().out.strip()
    # A JWT has three dot-separated base64url segments.
    parts = out.split(".")
    assert len(parts) == 3
    # Header decodes to EdDSA JWT.
    import base64

    header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_raw))
    assert header["alg"] == "EdDSA"


def test_cmd_jwt_sign_public_key(capsys):
    priv = _gen_ed25519_hex()
    cli.cmd_jwt_sign(["--private-key", priv, "--sub", "client-1", "--public-key"])
    out = capsys.readouterr().out
    assert "Public key" in out
    # Last line is 64 hex chars (32-byte public key).
    pub = out.strip().splitlines()[-1]
    assert len(pub) == 64
    int(pub, 16)  # valid hex


# ---------------------------------------------------------------------------
# cmd_sbom
# ---------------------------------------------------------------------------


def test_cmd_sbom_fallback_to_pip_freeze(monkeypatch, capsys):
    """When cyclonedx is unavailable, falls back to pip freeze."""
    import subprocess as real_subprocess

    real_run = real_subprocess.run

    def fake_run(cmd, *args, **kwargs):
        if "cyclonedx_bom" in cmd:
            raise FileNotFoundError("cyclonedx not installed")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    cli.cmd_sbom(make_args())
    out = capsys.readouterr().out
    assert "Falling back to pip freeze" in out


def test_cmd_sbom_success(monkeypatch, capsys):
    """When cyclonedx is available, reports success."""
    import subprocess as real_subprocess

    monkeypatch.setattr(real_subprocess, "run", lambda *a, **k: None)
    cli.cmd_sbom(make_args())
    out = capsys.readouterr().out
    assert "✅ SBOM generated" in out


# ---------------------------------------------------------------------------
# cmd_dashboard (mock the blocking server)
# ---------------------------------------------------------------------------


def test_cmd_dashboard_starts(monkeypatch, capsys):
    import mcp_witness.dashboard.server as dash_server

    called = {}

    def fake_run(host, port):
        called["host"] = host
        called["port"] = port

    monkeypatch.setattr(dash_server, "run_dashboard", fake_run)
    cli.cmd_dashboard(make_args(host="0.0.0.0", port=12345))
    out = capsys.readouterr().out
    assert "MCP Witness Dashboard" in out
    assert called == {"host": "0.0.0.0", "port": 12345}


# ---------------------------------------------------------------------------
# cmd_report (mock the report generators)
# ---------------------------------------------------------------------------


def test_cmd_report_html(db_with_records, monkeypatch, capsys):
    import mcp_witness.reports as reports

    monkeypatch.setattr(reports, "generate_html_report", lambda *a, **k: "/tmp/report.html")
    cli.cmd_report(make_args(format="html"))
    out = capsys.readouterr().out
    assert "HTML report saved" in out
    assert "Records: 3" in out


def test_cmd_report_pdf(db_with_records, monkeypatch, capsys):
    import mcp_witness.reports as reports

    monkeypatch.setattr(reports, "generate_pdf_report", lambda *a, **k: "/tmp/report.pdf")
    cli.cmd_report(make_args(format="pdf"))
    out = capsys.readouterr().out
    assert "PDF report saved" in out


# ---------------------------------------------------------------------------
# cmd_anchors
# ---------------------------------------------------------------------------


def test_cmd_anchors_verify(db_with_records, monkeypatch, capsys):
    from mcp_witness.storage import SqliteStorage as _Store

    async def fake_verify_anchors(self, checkpoint_id):
        return {"anchors": [{"valid": True}, {"valid": True}]}

    monkeypatch.setattr(_Store, "verify_anchors", fake_verify_anchors)
    cli.cmd_anchors(make_args(action="verify", checkpoint_id=1))
    out = capsys.readouterr().out
    assert "2/2 valid" in out
    assert "✅" in out


def test_cmd_anchors_create(db_with_records, monkeypatch, capsys):
    from mcp_witness.anchoring import AnchorType
    from mcp_witness.storage import SqliteStorage as _Store

    class FakeReceipt:
        anchor_type = AnchorType.TSA
        receipt_id = "receipt-123"

    async def fake_anchor_checkpoint(self, checkpoint_id, anchor_types):
        assert anchor_types == [AnchorType.TSA]
        return [FakeReceipt()]

    monkeypatch.setattr(_Store, "anchor_checkpoint", fake_anchor_checkpoint)
    cli.cmd_anchors(make_args(action="create", checkpoint_id=1, tsa=True))
    out = capsys.readouterr().out
    assert "Anchored checkpoint #1" in out
    assert "receipt-123" in out


# ---------------------------------------------------------------------------
# cmd_serve / cmd_quickstart — must NOT block; assert behavior without serving
# ---------------------------------------------------------------------------


def test_cmd_serve_propagates_server_error(db, monkeypatch):
    """cmd_serve should surface a RuntimeError from server.main (e.g. missing key)."""
    import mcp_witness.server as server

    async def boom():
        raise RuntimeError("MCP_WITNESS_SIGNING_KEY is required")

    monkeypatch.setattr(server, "main", boom)
    with pytest.raises(RuntimeError, match="SIGNING_KEY"):
        cli.cmd_serve(make_args())


def test_cmd_quickstart_no_serve(db, capsys):
    """quickstart with no_serve=True initializes but never starts the server."""
    cli.cmd_quickstart(make_args(no_serve=True))
    out = capsys.readouterr().out
    assert "Quickstart" in out
    assert "Database ready" in out
    assert "Next Steps" in out
    # Server section must not have run.
    assert "Starting MCP Witness server" not in out


def test_cmd_quickstart_serves_when_enabled(db, monkeypatch, capsys):
    import mcp_witness.server as server

    started = {}

    async def fake_main():
        started["ran"] = True

    monkeypatch.setattr(server, "main", fake_main)
    cli.cmd_quickstart(make_args(no_serve=False))
    out = capsys.readouterr().out
    assert "Starting MCP Witness server" in out
    assert started.get("ran") is True


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------


def test_main_version(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["mcp-witness", "--version"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_main_no_command_prints_help(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["mcp-witness"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "commands" in capsys.readouterr().out


def test_main_dispatch_stats(db_with_records, monkeypatch, capsys):
    # --db is a global option and must precede the subcommand in argparse.
    monkeypatch.setattr("sys.argv", ["mcp-witness", "--db", db_with_records, "stats"])
    cli.main()
    out = capsys.readouterr().out
    assert "Total Records:      3" in out


def test_main_catches_runtime_error_exits_1(monkeypatch, capsys):
    """main() wraps dispatch and converts RuntimeError/ValueError into exit(1)."""

    def boom(args):
        raise RuntimeError("missing signing key")

    # main() builds its command table from module-level cmd_* names at call
    # time, so patching the attribute is enough.
    monkeypatch.setattr(cli, "cmd_serve", boom)
    monkeypatch.setattr("sys.argv", ["mcp-witness", "serve"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "❌" in err
    assert "missing signing key" in err


def test_main_catches_value_error_exits_1(monkeypatch, capsys):
    def boom(args):
        raise ValueError("bad config")

    monkeypatch.setattr(cli, "cmd_stats", boom)
    monkeypatch.setattr("sys.argv", ["mcp-witness", "stats"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "bad config" in capsys.readouterr().err


def test_main_keyboard_interrupt_exits_130(monkeypatch):
    def boom(args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(cli, "cmd_stats", boom)
    monkeypatch.setattr("sys.argv", ["mcp-witness", "stats"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 130
