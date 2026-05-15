"""
Compliance presets for mcp-witness.

One-command configuration for major regulations. Apply a preset and every
subsequent record automatically follows the correct retention, redaction,
and attestation rules.

Available presets:
    hipaa    — Health Insurance Portability and Accountability Act
    gdpr     — General Data Protection Regulation
    sox      — Sarbanes-Oxley Act
    fedramp  — Federal Risk and Authorization Management Program
    soc2     — Service Organization Control 2
    pci_dss  — Payment Card Industry Data Security Standard
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CompliancePreset:
    """Configuration preset for a specific regulatory framework."""

    name: str
    description: str
    retention_days: Optional[int]
    anchor_frequency: str  # "daily", "hourly", "per_decision"
    auto_redact: list[str] = field(default_factory=list)
    require_attestation: bool = False
    immutable: bool = False  # No deletion allowed
    require_consent_record: bool = False
    encryption: Optional[str] = None
    audit_frequency: str = "quarterly"


# ---------------------------------------------------------------------------
# Preset Definitions
# ---------------------------------------------------------------------------

COMPLIANCE_PRESETS: dict[str, CompliancePreset] = {
    "hipaa": CompliancePreset(
        name="HIPAA",
        description="Health Insurance Portability and Accountability Act — protects patient health information (PHI)",
        retention_days=2190,  # 6 years (HIPAA §164.316(b)(2)(i))
        anchor_frequency="daily",
        auto_redact=[
            "patient_name",
            "patient_dob",
            "mrn",  # Medical Record Number
            "ssn",
            "patient_address",
            "patient_phone",
            "insurance_id",
            "diagnosis",
            "treatment_notes",
            "patient_email",
            "patient_photo",
        ],
        require_attestation=True,
        immutable=False,
        encryption="aes-256-gcm",
        audit_frequency="monthly",
    ),
    "gdpr": CompliancePreset(
        name="GDPR",
        description="General Data Protection Regulation — EU personal data protection",
        retention_days=None,  # Must be explicitly set per-purpose
        anchor_frequency="daily",
        auto_redact=[
            "email",
            "phone",
            "ip_address",
            "physical_address",
            "full_name",
            "date_of_birth",
            "national_id",
            "bank_details",
            "biometric_data",
            "location_data",
            "cookie_id",
            "device_fingerprint",
        ],
        require_attestation=True,
        require_consent_record=True,
        immutable=False,  # Right to erasure (Article 17)
        audit_frequency="monthly",
    ),
    "sox": CompliancePreset(
        name="SOX",
        description="Sarbanes-Oxley Act — financial reporting integrity for public companies",
        retention_days=2555,  # 7 years (SEC rule 17a-4)
        anchor_frequency="daily",
        auto_redact=[
            "account_number",
            "routing_number",
            "tax_id",
            "salary",
            "equity_grants",
            "financial_projections",
            "merger_details",
            "insider_info",
        ],
        require_attestation=True,
        immutable=True,  # Records must not be deleted
        encryption="aes-256-gcm",
        audit_frequency="quarterly",
    ),
    "fedramp": CompliancePreset(
        name="FedRAMP",
        description="Federal Risk and Authorization Management Program — US government cloud security",
        retention_days=1095,  # 3 years minimum
        anchor_frequency="daily",
        auto_redact=[
            "ssn",
            "passport_number",
            "classified_info",
            "clearance_level",
            "facility_code",
            "cui_marking",
        ],
        require_attestation=True,
        immutable=False,
        encryption="fips-140-2",
        audit_frequency="monthly",
    ),
    "soc2": CompliancePreset(
        name="SOC 2",
        description="Service Organization Control 2 — security, availability, confidentiality, privacy",
        retention_days=365,  # Typically 1 year, check with auditor
        anchor_frequency="daily",
        auto_redact=[
            "password_hash",
            "api_key",
            "access_token",
            "session_token",
            "private_key",
            "credit_card",
            "customer_pii",
        ],
        require_attestation=True,
        immutable=False,
        encryption="aes-256-gcm",
        audit_frequency="quarterly",
    ),
    "pci_dss": CompliancePreset(
        name="PCI DSS",
        description="Payment Card Industry Data Security Standard — credit card data protection",
        retention_days=365,
        anchor_frequency="daily",
        auto_redact=[
            "card_number",
            "pan",
            "cvv",
            "cvc",
            "pin",
            "cardholder_name",
            "expiry_date",
            "track_data",
            "service_code",
        ],
        require_attestation=True,
        immutable=False,
        encryption="aes-256-gcm",
        audit_frequency="quarterly",
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_preset(name: str) -> Optional[CompliancePreset]:
    """Get a compliance preset by name (case-insensitive)."""
    return COMPLIANCE_PRESETS.get(name.lower())


def list_presets() -> list[str]:
    """List all available preset names."""
    return list(COMPLIANCE_PRESETS.keys())


def get_preset_summary(name: str) -> Optional[dict]:
    """Get a human-readable summary of a preset."""
    preset = get_preset(name)
    if not preset:
        return None

    return {
        "name": preset.name,
        "description": preset.description,
        "retention_days": preset.retention_days,
        "retention_human": (
            f"{preset.retention_days // 365} years"
            if preset.retention_days
            else "must be set per-purpose (GDPR)"
        ),
        "anchor_frequency": preset.anchor_frequency,
        "auto_redact_count": len(preset.auto_redact),
        "requires_attestation": preset.require_attestation,
        "immutable": preset.immutable,
        "encryption": preset.encryption or "not specified",
        "recommended_audit_frequency": preset.audit_frequency,
    }


def validate_retention(preset_name: str, retention_days: int) -> Optional[str]:
    """
    Validate that a retention period meets the preset's minimum.

    Returns None if valid, or an error message string.
    """
    preset = get_preset(preset_name)
    if not preset:
        return f"Unknown preset: {preset_name}"

    if preset.retention_days is None:
        return "GDPR requires retention to be explicitly set per-purpose"

    if retention_days < preset.retention_days:
        return (
            f"Retention ({retention_days} days) is below "
            f"{preset.name} minimum ({preset.retention_days} days)"
        )

    return None
