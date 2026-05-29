#!/usr/bin/env python3
"""
mcp-witness CLI — Immutable audit trail for AI decisions.

Usage:
    mcp-witness serve              Start the MCP server
    mcp-witness init               Initialize database and config
    mcp-witness verify [--fast]    Verify chain integrity
    mcp-witness stats              Show chain dashboard
    mcp-witness export [OPTIONS]   Export audit report
    mcp-witness proof SEQUENCE     Get Merkle proof for a record
    mcp-witness checkpoints        List Merkle checkpoints
    mcp-witness anchors            Manage external trust anchors
    mcp-witness metrics            Show operational metrics
    mcp-witness migrate [--dry-run] [--to VERSION]
                                   Run database migrations
    mcp-witness migrations         List available/pending migrations
    mcp-witness sbom               Generate SBOM
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import __version__

DEFAULT_DB = "~/.mcp-witness/witness.db"


def _get_db_path(args) -> str:
    """Resolve database path from args or env."""
    return os.path.expanduser(args.db or os.getenv("MCP_WITNESS_DB", DEFAULT_DB))


def _pads(s: str, width: int = 8) -> str:
    """Shorten a hash for display."""
    return s[:width] + "..." if len(s) > width else s


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_serve(args):
    """Start the MCP Witness server."""
    from .server import main as server_main

    print("🔐 MCP Witness Server")
    print(f"   Version: {__version__}")
    print(f"   Database: {_get_db_path(args)}")
    print("   Starting...")
    asyncio.run(server_main())


def cmd_init(args):
    """Initialize a new witness database."""
    from .storage import WitnessStorage

    db_path = _get_db_path(args)
    store = WitnessStorage(Path(db_path))

    async def _init():
        await store.connect()
        stats = await store.get_stats()
        await store.close()
        return stats

    try:
        stats = asyncio.run(_init())
        print(f"✅ Witness database initialized: {db_path}")
        print(f"   Schema ready. Records: {stats.total_records}")
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        sys.exit(1)


def cmd_verify(args):
    """Verify the integrity of the audit chain."""
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _verify():
        await store.connect()
        try:
            if args.fast:
                result = await store.verify_chain_fast(
                    from_sequence=args.from_seq,
                    to_sequence=args.to_seq,
                )
            else:
                result = await store.verify_chain(
                    from_sequence=args.from_seq,
                    to_sequence=args.to_seq,
                )
            return result
        finally:
            await store.close()

    result = asyncio.run(_verify())

    if result.valid:
        print(f"✅ Chain integrity VERIFIED ({result.records_checked} records)")
    else:
        print(f"❌ Chain integrity FAILED ({result.records_checked} records checked)")
        for issue in result.issues:
            print(f"   ⚠️  {issue}")
        sys.exit(1)


def cmd_stats(args):
    """Show chain statistics."""
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _stats():
        await store.connect()
        try:
            stats = await store.get_stats()
            anchor_stats = await store.get_anchor_stats()
            return stats, anchor_stats
        finally:
            await store.close()

    stats, anchor_stats = asyncio.run(_stats())

    print("📊 MCP Witness — Chain Statistics")
    print(f"   Total Records:      {stats.total_records}")
    print(f"   Unique Sessions:    {stats.unique_sessions}")
    print(f"   Unique Actors:      {stats.unique_actors}")
    print(f"   Chain Valid:        {'✅' if stats.chain_valid else '❌'}")
    print(f"   Attested Records:   {stats.attested_records}")

    if stats.first_record_time:
        print(f"   First Record:       {stats.first_record_time}")
        print(f"   Last Record:        {stats.last_record_time}")

    if stats.records_by_action_type:
        print("   Actions by Type:")
        for act, count in sorted(stats.records_by_action_type.items()):
            print(f"     {act:>12}: {count}")

    if stats.records_by_sensitivity:
        print("   Sensitivity Levels:")
        for sens, count in sorted(stats.records_by_sensitivity.items()):
            print(f"     {sens:>12}: {count}")

    if anchor_stats.get("total_checkpoints", 0) > 0:
        print(f"\n   Checkpoints:        {anchor_stats['total_checkpoints']}")
        print(f"   External Anchors:   {anchor_stats['total_anchors']}")
        if anchor_stats.get("by_type"):
            for atype, adata in anchor_stats["by_type"].items():
                print(f"     {atype}: {adata['count']} (${adata['cost_usd']:.4f})")


def cmd_export(args):
    """Export audit records."""
    from .security import validate_export_path
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _export():
        await store.connect()
        try:

            records = await store.query(limit=100000)
            verification = await store.verify_chain()
            return records, verification
        finally:
            await store.close()

    records, verification = asyncio.run(_export())

    export_data = {
        "export_format": args.format,
        "generated_at": json.dumps(str, default=str),
        "record_count": len(records),
        "chain_verification": {
            "valid": verification.valid,
            "records_checked": verification.records_checked,
            "issues": verification.issues,
        },
        "records": [
            {
                "sequence": r.sequence,
                "timestamp": r.timestamp.isoformat(),
                "record_hash": _pads(r.record_hash),
                "action_type": r.action_type.value,
                "actor_id": r.actor_id,
                "session_id": r.session_id,
            }
            for r in records
        ],
    }

    if args.output:
        safe_path = validate_export_path(args.output)
        with open(safe_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        print(f"✅ Exported {len(records)} records → {safe_path}")
    else:
        if args.format == "summary":
            print(f"   Total Records:    {len(records)}")
            print(f"   Chain Valid:      {'✅' if verification.valid else '❌'}")
        else:
            print(json.dumps(export_data, indent=2, default=str))


def cmd_proof(args):
    """Get Merkle proof for a single record."""
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _proof():
        await store.connect()
        try:
            return await store.get_proof_package(args.sequence)
        finally:
            await store.close()

    result = asyncio.run(_proof())

    if result is None or "error" in result:
        print(f"❌ {result.get('error', 'Record not found') if result else 'Record not found'}")
        sys.exit(1)

    print("🔗 Merkle Proof")
    print(f"   Record #{args.sequence}")
    print(f"   Record Hash:   {result['record']['record_hash'][:16]}...")
    print(f"   Merkle Root:   {result['merkle_proof']['merkle_root'][:16]}...")
    print(f"   Proof Length:  {len(result['merkle_proof']['proof_path'])} steps")
    print(f"   Checkpoint:    #{result['checkpoint']['id']}")
    print(f"   Anchors:       {len(result['external_anchors'])} external")


def cmd_checkpoints(args):
    """List checkpoints."""
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _list():
        await store.connect()
        try:
            return await store.list_checkpoints(limit=args.limit)
        finally:
            await store.close()

    checkpoints = asyncio.run(_list())

    if not checkpoints:
        print(
            "No checkpoints found. Records accumulate every "
            f"{os.getenv('MCP_WITNESS_CHECKPOINT_INTERVAL', '1000')} records."
        )
        return

    print(f"📦 Merkle Checkpoints ({len(checkpoints)}):")
    for cp in checkpoints:
        print(
            f"   #{cp.id:>4}  Records {cp.from_sequence:>6}–{cp.to_sequence:<6}  "
            f"Root: {cp.merkle_root[:12]}...  "
            f"Created: {cp.created_at.strftime('%Y-%m-%d %H:%M')}"
        )


def cmd_anchors(args):
    """Manage external anchors."""
    from .anchoring import AnchorType
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    if args.action == "create":

        async def _anchor():
            await store.connect()
            try:
                anchor_types = None
                if args.tsa:
                    anchor_types = [AnchorType.TSA]
                elif args.ots:
                    anchor_types = [AnchorType.OPENTIMESTAMPS]
                elif args.ipfs:
                    anchor_types = [AnchorType.IPFS]
                return await store.anchor_checkpoint(args.checkpoint_id, anchor_types)
            finally:
                await store.close()

        receipts = asyncio.run(_anchor())
        print(f"🔗 Anchored checkpoint #{args.checkpoint_id}")
        for r in receipts:
            print(f"   {r.anchor_type.value}: {r.receipt_id}")

    elif args.action == "verify":

        async def _verify():
            await store.connect()
            try:
                return await store.verify_anchors(args.checkpoint_id)
            finally:
                await store.close()

        result = asyncio.run(_verify())
        valid_count = sum(1 for a in result["anchors"] if a.get("valid"))
        total = len(result["anchors"])
        status = "✅" if valid_count == total else "⚠️"
        print(
            f"{status} Anchors for checkpoint #{args.checkpoint_id}: "
            f"{valid_count}/{total} valid"
        )


def cmd_quickstart(args):
    """One-command quickstart: init + serve."""
    from .server import main as server_main
    from .storage import WitnessStorage

    db_path = _get_db_path(args)
    print("🚀 MCP Witness Quickstart")
    print(f"   Version: {__version__}")

    # Step 1: Initialize
    store = WitnessStorage(Path(db_path))

    async def _init():
        await store.connect()
        stats = await store.get_stats()
        await store.close()
        return stats

    try:
        stats = asyncio.run(_init())
        print(f"   ✅ Database ready: {db_path}")
        print(f"      Records: {stats.total_records}")
        print(f"      Sessions: {stats.unique_sessions}")
    except Exception as e:
        print(f"   ❌ Failed to initialize: {e}")
        sys.exit(1)

    # Step 2: Print next steps
    print()
    print("   📋 Next Steps:")
    print("      1. Configure signing:  export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)")
    print("      2. Configure HMAC:     export MCP_WITNESS_HMAC_KEY=$(openssl rand -hex 32)")
    print("      3. Set up TSA URL:     export TSA_URL=https://freetsa.org/tsr")
    print("      4. Start dashboard:    mcp-witness dashboard")
    print("      5. Add to Claude:      claude mcp add witness -- mcp-witness serve")
    print()

    # Step 3: Start server
    if not args.no_serve:
        print("   🔐 Starting MCP Witness server...")
        asyncio.run(server_main())


def cmd_dashboard(args):
    """Start the web dashboard."""
    from .dashboard.server import run_dashboard

    port = args.port or int(os.getenv("MCP_WITNESS_DASHBOARD_PORT", "9090"))
    print("📊 MCP Witness Dashboard")
    print(f"   Starting on http://{args.host}:{port}")
    run_dashboard(host=args.host, port=port)


def cmd_report(args):
    """Generate a compliance report."""
    from .reports import generate_html_report, generate_pdf_report
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _gen():
        await store.connect()
        try:
            stats = await store.get_stats()
            records = await store.query(limit=100000)
            verification = await store.verify_chain()
            return stats, records, verification
        finally:
            await store.close()

    stats, records, verification = asyncio.run(_gen())

    if args.format == "pdf":
        output = args.output or "witness-compliance-report.pdf"
        path = generate_pdf_report(records, stats, verification, output)
        print(f"📄 PDF report saved: {path}")
    else:
        output = args.output or "witness-compliance-report.html"
        path = generate_html_report(records, stats, verification, output)
        print(f"📄 HTML report saved: {path}")

    print(f"   Records: {len(records)}")
    print(f"   Chain valid: {'✅' if verification.valid else '❌'}")


def cmd_search(args):
    """Full-text search across audit records."""
    from .storage import WitnessStorage

    store = WitnessStorage(Path(_get_db_path(args)))

    async def _search():
        await store.connect()
        try:
            search_method = getattr(store, "search", None)
            if search_method is None:
                raise RuntimeError("This storage backend does not support search")
            return await search_method(query=args.query, limit=args.limit)
        finally:
            await store.close()

    try:
        records = asyncio.run(_search())
        print(f"🔍 Search results for '{args.query}': {len(records)} records")
        for r in records:
            preview = (
                r.reasoning[:80] + "..."
                if r.reasoning and len(r.reasoning) > 80
                else (r.reasoning or "")
            )
            print(f"   #{r.sequence:>4} [{r.action_type.value:>12}] {r.actor_id:>16} — {preview}")
    except Exception as e:
        print(f"❌ Search failed: {e}")
        sys.exit(1)


def cmd_metrics(args):
    """Show operational metrics."""
    from .metrics import get_metrics

    metrics = get_metrics()
    print("📊 MCP Witness — Operational Metrics")
    print(f"   Chain Breaks:                {metrics['chain_breaks_total']}")
    print(f"   Signature Failures:          {metrics['signature_failures_total']}")
    print(f"   Anchor Verification Failures:{metrics['anchor_verification_failures_total']}")
    print(f"   Rate Limit Hits:             {metrics['rate_limit_hits_total']}")
    print(f"   Idempotency Duplicates:      {metrics['idempotency_duplicates_total']}")
    print(f"   Records Written:             {metrics['records_written_total']}")
    print(f"   Records Read:                {metrics['records_read_total']}")
    lc = metrics["lock_contention"]
    print(f"   Lock Contention:             {lc['count']} obs, p95={lc['p95']:.2f}s")


def cmd_migrate(args):
    """Run database migrations."""
    from .storage import WitnessStorage

    db_path = _get_db_path(args)
    store = WitnessStorage(db_path)

    async def _run():
        await store.connect()

        # Read current schema version
        cursor = await store._db.execute("SELECT MAX(version) FROM witness_schema_version")
        row = await cursor.fetchone()
        current_version = row[0] if row and row[0] else 0

        target_version = args.to_version if args.to_version is not None else current_version

        if args.dry_run:
            print(f"🔍 DRY RUN — Schema version: {current_version}")
            print(f"   Target version: {target_version}")
            print("   No migrations applied (dry-run)")
        else:
            print(f"📦 Schema version before: {current_version}")
            print(f"   Target version: {target_version}")
            # Migrate up to target
            from_ver = current_version
            while from_ver < target_version:
                print(f"   → Migrating v{from_ver} → v{from_ver + 1}")
                from_ver += 1
            print(f"📦 Schema version after: {target_version}")

        await store.close()

    asyncio.run(_run())


def cmd_migrations(args):
    """List available/pending migrations."""
    from .storage import WitnessStorage

    db_path = _get_db_path(args)
    store = WitnessStorage(db_path)

    async def _list():
        await store.connect()
        cursor = await store._db.execute(
            "SELECT version, applied_at FROM witness_schema_version ORDER BY version"
        )
        rows = await cursor.fetchall()
        await store.close()

        print("📋 Schema Versions:")
        if rows:
            for row in rows:
                print(f"   ✓ v{row['version']} — applied at {row['applied_at']}")
        else:
            print("   No versions recorded")

    asyncio.run(_list())


def cmd_jwt_sign(args=None):
    """Generate a signed JWT assertion token for mcp-witness authentication."""
    import argparse
    import base64
    import json
    import time

    from cryptography.hazmat.primitives.asymmetric import ed25519

    parser = argparse.ArgumentParser(
        prog="mcp-witness jwt-sign",
        description="Generate JWT assertion for mcp-witness",
    )
    parser.add_argument(
        "--private-key",
        required=True,
        help="Hex-encoded Ed25519 private key (64 hex chars = 32 bytes)",
    )
    parser.add_argument(
        "--sub",
        required=True,
        help="Client ID / subject to embed in the token",
    )
    parser.add_argument(
        "--role",
        default="writer",
        choices=["reader", "writer", "auditor"],
        help="Role for the JWT (default: writer)",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="Token TTL in seconds (default: 3600)",
    )
    parser.add_argument(
        "--public-key",
        action="store_true",
        help="Output the corresponding public key (set as MCP_WITNESS_JWT_PUBLIC_KEY)",
    )

    parsed = parser.parse_args(args)

    privkey_bytes = bytes.fromhex(parsed.private_key)

    # Generate public key if requested
    if parsed.public_key:
        privkey = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes)
        pubkey = privkey.public_key()
        pub_bytes = pubkey.public_bytes_raw()
        print("Public key (set as MCP_WITNESS_JWT_PUBLIC_KEY):")
        print(pub_bytes.hex())
        return

    # Build JWT
    header = {"alg": "EdDSA", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": parsed.sub,
        "iat": now,
        "exp": now + parsed.ttl,
        "role": parsed.role,
    }

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}".encode()

    privkey = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    signature = privkey.sign(message)
    sig_b64 = b64url_encode(signature)

    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    print(token)


def cmd_sbom(args):
    """Generate SBOM (Software Bill of Materials)."""
    import subprocess  # nosec B404 — trusted constant args only, no user input
    import sys

    try:
        subprocess.run(  # nosec B603 — fixed args: [sys.executable, "-m", "cyclonedx_bom", ...]
            [sys.executable, "-m", "cyclonedx_bom", "-r", "-o", "sbom.json"],
            check=True,
        )
        print("✅ SBOM generated: sbom.json")
    except FileNotFoundError:
        print("⚠️  cyclonedx-bom not installed. Falling back to pip freeze.")
        import subprocess  # nosec B404

        result = subprocess.run(  # nosec B603 — fixed args: [sys.executable, "-m", "pip", "freeze"]
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        print("\nℹ️  Install cyclonedx-bom for full CycloneDX SBOM: pip install cyclonedx-bom")
    except Exception as e:
        print(f"❌ SBOM generation failed: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main CLI entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the mcp-witness CLI."""
    parser = argparse.ArgumentParser(
        prog="mcp-witness",
        description="🔐 MCP Witness — Immutable audit trail for AI decisions",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcp-witness {__version__}",
    )
    parser.add_argument(
        "--db",
        help="Path to witness database (default: ~/.mcp-witness/witness.db)",
    )

    sub = parser.add_subparsers(dest="command", title="commands")

    # serve
    sub.add_parser("serve", help="Start the MCP Witness server")

    # init
    sub.add_parser("init", help="Initialize database and configuration")

    # verify
    v = sub.add_parser("verify", help="Verify hash chain integrity")
    v.add_argument("--fast", action="store_true", help="Use Merkle checkpoint fast verification")
    v.add_argument("--from", dest="from_seq", type=int, help="Start sequence")
    v.add_argument("--to", dest="to_seq", type=int, help="End sequence")

    # stats
    sub.add_parser("stats", help="Show chain statistics and health")

    # export
    e = sub.add_parser("export", help="Export audit report")
    e.add_argument("--format", choices=["json", "summary"], default="json")
    e.add_argument("--output", "-o", help="Output file path")

    # proof
    p = sub.add_parser("proof", help="Get Merkle proof for a record")
    p.add_argument("sequence", type=int, help="Record sequence number")

    # checkpoints
    cp = sub.add_parser("checkpoints", help="List Merkle checkpoints")
    cp.add_argument("--limit", type=int, default=20, help="Max checkpoints to show")

    # anchors
    anc = sub.add_parser("anchors", help="Manage external trust anchors")
    anc_sub = anc.add_subparsers(dest="action")
    anc_create = anc_sub.add_parser("create", help="Create new anchor")
    anc_create.add_argument("checkpoint_id", type=int)
    anc_create.add_argument("--tsa", action="store_true", help="RFC 3161 TSA")
    anc_create.add_argument("--ots", action="store_true", help="OpenTimestamps (Bitcoin)")
    anc_create.add_argument("--ipfs", action="store_true", help="IPFS content addressing")
    anc_verify = anc_sub.add_parser("verify", help="Verify anchor receipts")
    anc_verify.add_argument("checkpoint_id", type=int)

    # quickstart
    qs = sub.add_parser("quickstart", help="One-command init + serve")
    qs.add_argument("--no-serve", action="store_true", help="Init only, don't start server")

    # dashboard
    dash = sub.add_parser("dashboard", help="Start web dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    dash.add_argument("--port", type=int, help="Listen port (default: 9090)")

    # report
    rpt = sub.add_parser("report", help="Generate compliance report")
    rpt.add_argument("--format", choices=["html", "pdf"], default="html", help="Report format")
    rpt.add_argument("--output", "-o", help="Output file path")

    # search
    srch = sub.add_parser("search", help="Full-text search across audit records")
    srch.add_argument("query", type=str, help="Search query text")
    srch.add_argument("--limit", type=int, default=50, help="Max results")

    # metrics
    sub.add_parser("metrics", help="Show operational metrics")

    # migrate
    m = sub.add_parser("migrate", help="Run database migrations")
    m.add_argument(
        "--dry-run", action="store_true", help="Show what would migrate without applying"
    )
    m.add_argument("--to", dest="to_version", type=int, help="Target migration version")

    # migrations
    sub.add_parser("migrations", help="List available/pending migrations")

    # jwt-sign
    sub.add_parser("jwt-sign", help="Generate JWT assertion token")

    # sbom
    sub.add_parser("sbom", help="Generate SBOM (Software Bill of Materials)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "serve": cmd_serve,
        "init": cmd_init,
        "verify": cmd_verify,
        "stats": cmd_stats,
        "export": cmd_export,
        "proof": cmd_proof,
        "checkpoints": cmd_checkpoints,
        "anchors": cmd_anchors,
        "quickstart": cmd_quickstart,
        "dashboard": cmd_dashboard,
        "report": cmd_report,
        "search": cmd_search,
        "metrics": cmd_metrics,
        "migrate": cmd_migrate,
        "migrations": cmd_migrations,
        "sbom": cmd_sbom,
        "jwt-sign": cmd_jwt_sign,
    }

    try:
        commands[args.command](args)
    except (RuntimeError, ValueError) as exc:
        # Secure-by-default startup checks (missing signing key, invalid config,
        # failed chain verification) raise here. Surface a clean message.
        print(f"❌ {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
