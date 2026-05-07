"""
Example: PII redaction and compliance configuration.

Shows how to redact sensitive fields and apply a compliance preset.
"""

import asyncio
from pathlib import Path
from mcp_witness import WitnessStorage, ActionType, Sensitivity
from mcp_witness.compliance import get_preset, get_preset_summary


async def main():
    store = WitnessStorage(Path("example_compliance.db"))
    await store.connect()

    try:
        # Apply GDPR preset
        preset = get_preset("gdpr")
        print(f"📋 Applied: {preset.name}")
        print(f"   Retention: {preset.retention_days} days")
        print(f"   Auto-redact fields: {len(preset.auto_redact)}")
        print(f"   Attestation required: {preset.require_attestation}")
        print()

        # Record with PII that gets redacted
        record = await store.record(
            action_type=ActionType.TOOL_CALL,
            session_id="patient-lookup",
            actor_id="medical-agent",
            tool_name="lookup_patient",
            input_data={
                "patient_name": "Jane Doe",
                "patient_email": "jane@example.com",
                "patient_phone": "+1-555-0123",
                "query": "recent lab results",
                "mrn": "MRN-12345",
            },
            output_data={"result": "normal"},
            reasoning="Checking recent labs for annual review",
            sensitivity=Sensitivity.PII,
            redact_fields=preset.auto_redact,  # GDPR fields auto-redacted
            retention_days=365 * 2,  # Explicit retention per GDPR
        )

        print(f"✅ Recorded (with redaction)")
        print(f"   Record hash: {record.record_hash[:16]}...")
        print(f"   Redacted fields: {record.redacted_fields}")
        if record.input_data:
            for k, v in record.input_data.items():
                if "REDACTED" in str(v):
                    print(f"   🔒 {k}: {v}")

        # Verify integrity
        result = await store.verify_chain()
        print(f"\n   Chain: {'✅ Valid' if result.valid else '❌ Broken'}")
    finally:
        await store.close()
        Path("example_compliance.db").unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
