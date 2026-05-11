"""MCP Witness - Immutable audit trail for AI decisions."""

__version__ = "0.6.0"

from .anchoring import (
    AnchorReceipt,
    AnchorService,
    AnchorType,
    IPFSProvider,
    OpenTimestampsProvider,
    TSAProvider,
)
from .auth import AuthRole, authenticate, authorize, load_api_keys
from .buffered import BufferedStorage
from .hasher import sign_record_hash, verify_record_signature
from .merkle import (
    MerkleProof,
    MerkleTree,
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
)
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
from .storage import SqliteStorage, WitnessStorage  # WitnessStorage is alias for SqliteStorage
from .storage_base import StorageBackend
from .storage_pg import PgStorage

__all__ = [
    # Version
    "__version__",
    # Auth / RBAC
    "AuthRole",
    "authenticate",
    "authorize",
    "load_api_keys",
    # Models
    "ActionType",
    "ActorType",
    "Anchor",
    "Checkpoint",
    "ChainStats",
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
    # Signing / Non-repudiation
    "sign_record_hash",
    "verify_record_signature",
    # Anchoring
    "AnchorService",
    "AnchorReceipt",
    "AnchorType",
    "TSAProvider",
    "OpenTimestampsProvider",
    "IPFSProvider",
]
