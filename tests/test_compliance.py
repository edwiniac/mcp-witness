"""
Tests for compliance presets (compliance.py).

Covers:
- get_preset() for every supported framework (case-insensitive)
- list_presets()
- The CompliancePreset dataclass fields (retention, redaction, encryption, etc.)
- get_preset_summary() and validate_retention() helpers
- Error handling for unknown preset names
"""

from mcp_witness.compliance import (
    COMPLIANCE_PRESETS,
    CompliancePreset,
    get_preset,
    get_preset_summary,
    list_presets,
    validate_retention,
)

# =========================================================================
# get_preset() — every supported framework
# =========================================================================


class TestGetPreset:
    """Tests for get_preset()."""

    def test_hipaa(self):
        """HIPAA preset has the declared retention and redaction fields."""
        preset = get_preset("hipaa")
        assert isinstance(preset, CompliancePreset)
        assert preset.name == "HIPAA"
        assert preset.retention_days == 2190  # 6 years
        assert preset.anchor_frequency == "daily"
        assert preset.require_attestation is True
        assert preset.immutable is False
        assert preset.encryption == "aes-256-gcm"
        assert preset.audit_frequency == "monthly"
        assert set(preset.auto_redact) == {
            "patient_name",
            "patient_dob",
            "mrn",
            "ssn",
            "patient_address",
            "patient_phone",
            "insurance_id",
            "diagnosis",
            "treatment_notes",
            "patient_email",
            "patient_photo",
        }

    def test_gdpr(self):
        """GDPR preset has no fixed retention and requires consent records."""
        preset = get_preset("gdpr")
        assert preset.name == "GDPR"
        assert preset.retention_days is None  # set per-purpose
        assert preset.anchor_frequency == "daily"
        assert preset.require_attestation is True
        assert preset.require_consent_record is True
        assert preset.immutable is False  # right to erasure
        assert preset.audit_frequency == "monthly"
        assert set(preset.auto_redact) == {
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
        }

    def test_sox(self):
        """SOX preset is immutable with a 7-year retention."""
        preset = get_preset("sox")
        assert preset.name == "SOX"
        assert preset.retention_days == 2555  # 7 years
        assert preset.immutable is True
        assert preset.require_attestation is True
        assert preset.encryption == "aes-256-gcm"
        assert preset.audit_frequency == "quarterly"
        assert set(preset.auto_redact) == {
            "account_number",
            "routing_number",
            "tax_id",
            "salary",
            "equity_grants",
            "financial_projections",
            "merger_details",
            "insider_info",
        }

    def test_fedramp(self):
        """FedRAMP preset uses FIPS encryption and 3-year retention."""
        preset = get_preset("fedramp")
        assert preset.name == "FedRAMP"
        assert preset.retention_days == 1095  # 3 years
        assert preset.encryption == "fips-140-2"
        assert preset.require_attestation is True
        assert preset.immutable is False
        assert preset.audit_frequency == "monthly"
        assert set(preset.auto_redact) == {
            "ssn",
            "passport_number",
            "classified_info",
            "clearance_level",
            "facility_code",
            "cui_marking",
        }

    def test_soc2(self):
        """SOC 2 preset has a 1-year retention."""
        preset = get_preset("soc2")
        assert preset.name == "SOC 2"
        assert preset.retention_days == 365
        assert preset.encryption == "aes-256-gcm"
        assert preset.require_attestation is True
        assert preset.immutable is False
        assert preset.audit_frequency == "quarterly"
        assert set(preset.auto_redact) == {
            "password_hash",
            "api_key",
            "access_token",
            "session_token",
            "private_key",
            "credit_card",
            "customer_pii",
        }

    def test_pci_dss(self):
        """PCI DSS preset protects cardholder data with a 1-year retention."""
        preset = get_preset("pci_dss")
        assert preset.name == "PCI DSS"
        assert preset.retention_days == 365
        assert preset.encryption == "aes-256-gcm"
        assert preset.require_attestation is True
        assert preset.immutable is False
        assert preset.audit_frequency == "quarterly"
        assert set(preset.auto_redact) == {
            "card_number",
            "pan",
            "cvv",
            "cvc",
            "pin",
            "cardholder_name",
            "expiry_date",
            "track_data",
            "service_code",
        }

    def test_case_insensitive(self):
        """Preset lookup is case-insensitive."""
        assert get_preset("HIPAA") is get_preset("hipaa")
        assert get_preset("Gdpr") is get_preset("gdpr")
        assert get_preset("PCI_DSS").name == "PCI DSS"

    def test_unknown_preset_returns_none(self):
        """Unknown preset name returns None."""
        assert get_preset("nonexistent") is None
        assert get_preset("iso27001") is None
        assert get_preset("") is None


# =========================================================================
# list_presets()
# =========================================================================


class TestListPresets:
    """Tests for list_presets()."""

    def test_lists_all_presets(self):
        """All six supported presets are listed."""
        names = list_presets()
        assert set(names) == {"hipaa", "gdpr", "sox", "fedramp", "soc2", "pci_dss"}

    def test_matches_registry_keys(self):
        """The list matches the underlying registry keys."""
        assert set(list_presets()) == set(COMPLIANCE_PRESETS.keys())


# =========================================================================
# CompliancePreset dataclass
# =========================================================================


class TestCompliancePresetDataclass:
    """Tests for the CompliancePreset dataclass defaults."""

    def test_defaults(self):
        """Optional fields use the documented defaults."""
        preset = CompliancePreset(
            name="Test",
            description="A test preset",
            retention_days=30,
            anchor_frequency="hourly",
        )
        assert preset.auto_redact == []
        assert preset.require_attestation is False
        assert preset.immutable is False
        assert preset.require_consent_record is False
        assert preset.encryption is None
        assert preset.audit_frequency == "quarterly"

    def test_auto_redact_default_factory_isolated(self):
        """Each instance gets its own auto_redact list (no shared mutable default)."""
        a = CompliancePreset(name="A", description="", retention_days=1, anchor_frequency="daily")
        b = CompliancePreset(name="B", description="", retention_days=1, anchor_frequency="daily")
        a.auto_redact.append("field")
        assert b.auto_redact == []


# =========================================================================
# get_preset_summary()
# =========================================================================


class TestGetPresetSummary:
    """Tests for get_preset_summary()."""

    def test_hipaa_summary(self):
        """HIPAA summary reports years and redaction count."""
        summary = get_preset_summary("hipaa")
        assert summary["name"] == "HIPAA"
        assert summary["retention_days"] == 2190
        assert summary["retention_human"] == "6 years"
        assert summary["auto_redact_count"] == 11
        assert summary["requires_attestation"] is True
        assert summary["immutable"] is False
        assert summary["encryption"] == "aes-256-gcm"
        assert summary["recommended_audit_frequency"] == "monthly"

    def test_gdpr_summary_per_purpose_retention(self):
        """GDPR summary explains per-purpose retention."""
        summary = get_preset_summary("gdpr")
        assert summary["retention_days"] is None
        assert summary["retention_human"] == "must be set per-purpose (GDPR)"
        assert summary["encryption"] == "not specified"

    def test_unknown_summary_returns_none(self):
        """Unknown preset summary returns None."""
        assert get_preset_summary("bogus") is None


# =========================================================================
# validate_retention()
# =========================================================================


class TestValidateRetention:
    """Tests for validate_retention()."""

    def test_valid_meets_minimum(self):
        """Retention at or above the minimum is valid (returns None)."""
        assert validate_retention("hipaa", 2190) is None
        assert validate_retention("hipaa", 3000) is None

    def test_below_minimum(self):
        """Retention below the minimum returns an error message."""
        msg = validate_retention("sox", 100)
        assert msg is not None
        assert "below" in msg
        assert "SOX" in msg

    def test_unknown_preset(self):
        """Unknown preset returns an error message."""
        msg = validate_retention("nope", 100)
        assert msg == "Unknown preset: nope"

    def test_gdpr_requires_explicit_retention(self):
        """GDPR (None minimum) requires retention to be set per-purpose."""
        msg = validate_retention("gdpr", 365)
        assert msg is not None
        assert "per-purpose" in msg
