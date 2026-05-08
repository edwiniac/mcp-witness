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
    return os.path.expanduser(
        args.db or os.getenv("MCP_WITNESS_DB", DEFAULT_DB)
    )


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
    from .storage import WitnessStorage
    from .security import validate_export_path

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
        print("No checkpoints found. Records accumulate every "
              f"{os.getenv('MCP_WITNESS_CHECKPOINT_INTERVAL', '1000')} records.")
        return

    print(f"📦 Merkle Checkpoints ({len(checkpoints)}):")
    for cp in checkpoints:
        print(f"   #{cp.id:>4}  Records {cp.from_sequence:>6}–{cp.to_sequence:<6}  "
              f"Root: {cp.merkle_root[:12]}...  "
              f"Created: {cp.created_at.strftime('%Y-%m-%d %H:%M')}")


def cmd_anchors(args):
    """Manage external anchors."""
    from .storage import WitnessStorage
    from .anchoring import AnchorType

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
        print(f"{status} Anchors for checkpoint #{args.checkpoint_id}: "
              f"{valid_count}/{total} valid")


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
        "--version", action="version",
        version=f"mcp-witness {__version__}",
    )
    parser.add_argument(
        "--db", help="Path to witness database (default: ~/.mcp-witness/witness.db)",
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
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
