"""MCP Witness - Immutable audit trail for AI decisions."""

__version__ = "0.4.0"

from .anchoring import (
    AnchorReceipt,
    AnchorService,
    AnchorType,
    IPFSProvider,
    OpenTimestampsProvider,
    TSAProvider,
)
from .buffered import BufferedStorage
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
    # Anchoring
    "AnchorService",
    "AnchorReceipt",
    "AnchorType",
    "TSAProvider",
    "OpenTimestampsProvider",
    "IPFSProvider",
]
