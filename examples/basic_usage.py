"""
Example: Basic witness recording and verification.

This shows the simplest possible integration — record actions
and verify the chain. Copy-paste this to get started.
"""

import asyncio
from pathlib import Path
from mcp_witness import WitnessStorage, ActionType, Sensitivity


async def main():
    # Initialize storage (creates DB if it doesn't exist)
    db_path = Path("example_witness.db")
    store = WitnessStorage(db_path)
    await store.connect()

    try:
        # Record some actions
        for i in range(5):
            record = await store.record(
                action_type=ActionType.TOOL_CALL,
                session_id="example-session",
                actor_id="example-agent",
                tool_name="search_tool",
                input_data={"query": f"example query {i}"},
                output_data={"result": f"result {i}"},
                reasoning=f"Searching for example {i}",
                sensitivity=Sensitivity.INTERNAL,
            )
            print(f"  ✅ Recorded #{record.sequence}: {record.record_hash[:16]}...")

        # Verify the chain
        result = await store.verify_chain()
        print(f"  {'✅' if result.valid else '❌'} Chain valid: {result.records_checked} records checked")

        # Check stats
        stats = await store.get_stats()
        print(f"  📊 Total records: {stats.total_records}")
    finally:
        await store.close()
        # Clean up example DB
        if db_path.exists():
            db_path.unlink()


if __name__ == "__main__":
    asyncio.run(main())
