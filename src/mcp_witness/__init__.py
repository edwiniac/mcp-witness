"""MCP Witness - Immutable audit trail for AI decisions."""

__version__ = "0.2.0"

from .anchoring import (
    AnchorReceipt,
    AnchorService,
    AnchorType,
    IPFSProvider,
    OpenTimestampsProvider,
    TSAProvider,
)
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
from .storage import WitnessStorage

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
    # Storage
    "WitnessStorage",
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
