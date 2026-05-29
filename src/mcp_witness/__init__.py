"""MCP Witness - Immutable audit trail for AI decisions."""

__version__ = "0.9.0"

from . import metrics
from .anchoring import (
    AnchorError,
    AnchorFailureError,
    AnchorProviderError,
    AnchorReceipt,
    AnchorService,
    AnchorType,
    IPFSError,
    IPFSProvider,
    OpenTimestampsError,
    OpenTimestampsProvider,
    TSAError,
    TSAProvider,
)
from .auth import (
    AuthRole,
    authenticate,
    authorize,
    create_jwt_token,
    load_api_keys,
    verify_jwt_assertion,
)
from .buffered import BufferedStorage
from .compliance import CompliancePreset, get_preset, list_presets
from .crypto_agility import (
    HashChainAlgorithm,
    SigningAlgorithm,
    detect_signature_format,
    versioned_sign,
    versioned_verify,
)
from .hasher import sign_record_hash, verify_record_signature
from .key_lifecycle import KeyTrustStore, get_trust_store
from .merkle import (
    MerkleProof,
    MerkleTree,
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
    verify_merkle_proof_strict,
)
from .metrics import Counter, Histogram, get_metrics
from .models import (
    ActionType,
    ActorType,
    Anchor,
    ChainStats,
    Checkpoint,
    Sensitivity,
    VerificationResult,
    WitnessRecord,
)
from .security import decrypt_field, encrypt_field
from .storage import SqliteStorage, WitnessStorage  # WitnessStorage is alias for SqliteStorage
from .storage_base import StorageBackend

# PgStorage is loaded lazily — requires asyncpg (optional postgres extra)
PgStorage = None  # type: ignore[assignment]


def _load_pg_storage():
    """Lazy-load PgStorage so asyncpg is only imported when needed."""
    global PgStorage
    if PgStorage is None:
        try:
            from .storage_pg import PgStorage as _Pg

            PgStorage = _Pg
        except ImportError:
            pass
    return PgStorage


__all__ = [
    # Version
    "__version__",
    # Auth / RBAC
    "AuthRole",
    "authenticate",
    "authorize",
    "load_api_keys",
    "create_jwt_token",
    "verify_jwt_assertion",
    # Crypto agility
    "SigningAlgorithm",
    "HashChainAlgorithm",
    "versioned_sign",
    "versioned_verify",
    "detect_signature_format",
    # Key lifecycle
    "KeyTrustStore",
    "get_trust_store",
    # Compliance
    "CompliancePreset",
    "get_preset",
    "list_presets",
    # Models
    "ActionType",
    "ActorType",
    "Anchor",
    "ChainStats",
    "Checkpoint",
    "Sensitivity",
    "VerificationResult",
    "WitnessRecord",
    # Storage abstraction
    "StorageBackend",
    # Storage backends
    "SqliteStorage",
    "WitnessStorage",  # backward-compatible alias
    "PgStorage",
    "BufferedStorage",
    # Merkle
    "MerkleTree",
    "MerkleProof",
    "build_merkle_tree",
    "get_merkle_proof",
    "verify_merkle_proof",
    "verify_merkle_proof_strict",
    # Signing / Non-repudiation
    "sign_record_hash",
    "verify_record_signature",
    # Envelope encryption
    "encrypt_field",
    "decrypt_field",
    # Metrics
    "Counter",
    "Histogram",
    "get_metrics",
    "metrics",
    # Anchoring
    "AnchorService",
    "AnchorReceipt",
    "AnchorType",
    "TSAProvider",
    "OpenTimestampsProvider",
    "IPFSProvider",
    # Anchoring exceptions
    "AnchorError",
    "AnchorProviderError",
    "AnchorFailureError",
    "TSAError",
    "OpenTimestampsError",
    "IPFSError",
]
