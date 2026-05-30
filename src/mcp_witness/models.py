"""Data models for mcp-witness."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_serializer


class ActionType(str, Enum):
    """Types of actions that can be recorded."""

    TOOL_CALL = "tool_call"
    DECISION = "decision"
    OUTPUT = "output"
    ERROR = "error"
    SNAPSHOT = "snapshot"


class ActorType(str, Enum):
    """Types of actors that can perform actions."""

    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


class Sensitivity(str, Enum):
    """Data sensitivity levels for compliance."""

    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information (HIPAA)
    CONFIDENTIAL = "confidential"


class WitnessRecord(BaseModel):
    """An immutable audit record in the witness chain."""

    # Identity
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence: int = Field(ge=0, description="Monotonic sequence number")

    # Hash chain
    prev_hash: str = Field(description="SHA-256 hash of previous record")
    record_hash: str = Field(default="", description="SHA-256 hash of this record")

    # Who
    actor_type: ActorType = ActorType.AGENT
    actor_id: str = Field(default="unknown", description="Identifier for the actor")
    session_id: str = Field(default="", description="Groups related actions")

    # What
    action_type: ActionType
    tool_name: Optional[str] = None
    input_data: Optional[dict[str, Any]] = None
    output_data: Optional[dict[str, Any]] = None
    input_hash: str = Field(default="", description="SHA-256 of input for privacy")
    output_hash: str = Field(default="", description="SHA-256 of output for privacy")

    # Why
    context: Optional[dict[str, Any]] = None
    reasoning: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # Tenant / Multi-tenant support
    org_id: Optional[str] = Field(
        default=None, description="Organization/tenant ID for multi-tenant deployments"
    )

    # Compliance
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    retention_days: int = Field(default=365, ge=1, description="Days to retain record")
    tsa_receipt: Optional[bytes] = None
    anchored_at: Optional[str] = None

    # Signatures (Ed25519, optional)
    signature: Optional[str] = Field(
        default=None, description="Ed25519 signature of record_hash, hex-encoded"
    )
    signer_public_key: Optional[str] = Field(
        default=None, description="Ed25519 public key of signer, hex-encoded"
    )

    # Crypto hardening v0.7.0
    canonical_payload: Optional[str] = Field(
        default=None,
        description="Canonical JSON payload that was signed, hex-encoded bytes",
    )
    signer_key_id: Optional[str] = Field(
        default=None,
        description="Identifier of the signing key (for key rotation/revocation)",
    )

    # Metadata
    redacted_fields: list[str] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, _info):
        data = serializer(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, UUID):
                data[key] = str(value)
            elif isinstance(value, bytes):
                data[key] = value.hex() if value else None
        return data


class VerificationResult(BaseModel):
    """Result of verifying audit trail integrity."""

    valid: bool
    records_checked: int
    first_invalid_sequence: Optional[int] = None
    issues: list[str] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttestationResult(BaseModel):
    """Result of external timestamping."""

    success: bool
    records_attested: int
    tsa_provider: str
    anchor_time: Optional[datetime] = None
    receipt_hash: Optional[str] = None
    error: Optional[str] = None


class ReportResult(BaseModel):
    """Result of generating a compliance report."""

    success: bool
    format: str
    report_path: Optional[str] = None
    records_included: int
    integrity_verified: bool
    from_time: Optional[datetime] = None
    to_time: Optional[datetime] = None
    error: Optional[str] = None


class ChainStats(BaseModel):
    """Statistics about the witness chain."""

    total_records: int
    first_record_time: Optional[datetime] = None
    last_record_time: Optional[datetime] = None
    unique_sessions: int
    unique_actors: int
    records_by_action_type: dict[str, int] = Field(default_factory=dict)
    records_by_sensitivity: dict[str, int] = Field(default_factory=dict)
    attested_records: int
    chain_valid: bool
    # Checkpoint stats
    total_checkpoints: int = 0
    total_anchors: int = 0


class Checkpoint(BaseModel):
    """A Merkle checkpoint over a range of records."""

    id: int = Field(description="Checkpoint sequence number")
    from_sequence: int = Field(description="First record in checkpoint")
    to_sequence: int = Field(description="Last record in checkpoint")
    merkle_root: str = Field(description="Merkle root of records")
    record_count: int
    last_record_hash: str = Field(description="Links to main chain")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, _info):
        data = serializer(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


class Anchor(BaseModel):
    """An external trust anchor for a checkpoint."""

    id: Optional[int] = None
    checkpoint_id: int
    anchor_type: str
    merkle_root: str
    receipt_id: str
    verification_url: Optional[str] = None
    raw_receipt: Optional[bytes] = None
    cost_usd: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None
    is_valid: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _serialize(self, serializer, _info):
        data = serializer(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, bytes):
                data[key] = value.hex() if value else None
        return data


class ProofPackage(BaseModel):
    """Complete proof package for a single record."""

    record: dict[str, Any]
    merkle_proof: dict[str, Any]
    checkpoint: dict[str, Any]
    external_anchors: list[dict[str, Any]]
    verification_instructions: dict[str, str]


class AuditExport(BaseModel):
    """Complete audit export for compliance review."""

    export_metadata: dict[str, Any]
    chain_integrity: dict[str, Any]
    checkpoints: list[dict[str, Any]]
    external_anchors: list[dict[str, Any]]
    records: list[dict[str, Any]]
