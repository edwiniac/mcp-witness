"""MCP Witness - Immutable audit trail for AI decisions."""

__version__ = "0.2.0"

from .models import (
    ActionType,
    ActorType,
    Anchor,
    Checkpoint,
    ChainStats,
    Sensitivity,
    VerificationResult,
    WitnessRecord,
)
from .storage import WitnessStorage
from .merkle import MerkleTree, MerkleProof, build_merkle_tree, get_merkle_proof, verify_merkle_proof
from .anchoring import AnchorService, AnchorReceipt, AnchorType, TSAProvider, OpenTimestampsProvider, IPFSProvider

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
