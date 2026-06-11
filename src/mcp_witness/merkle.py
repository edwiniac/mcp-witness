"""Merkle tree utilities for efficient verification.

Domain separation: Leaf and internal-node hashes use distinct prefixes
(0x00 for leaves, 0x01 for internal nodes) to prevent second-preimage
attacks where a leaf could be presented as an internal-node proof.

See: https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

# Domain separation prefixes to prevent second-preimage attacks
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# SHA-256 hex digest: exactly 64 lowercase hex characters. Proof hashes must
# match this exactly — hash_pair() concatenates the two hex strings, so
# variable-length inputs would make the (left, right) split ambiguous.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _is_valid_hash(value: object) -> bool:
    """Check that a proof element is a full-length SHA-256 hex digest."""
    return isinstance(value, str) and bool(_SHA256_HEX.match(value))


# Zero-leaf constant for Merkle tree padding.
# Used instead of duplicating the last leaf when padding to a power of 2.
# This prevents collision attacks where two different record sets with
# trailing duplicates produce the same Merkle root.
MERKLE_ZERO_LEAF = hashlib.sha256(LEAF_PREFIX + b"MCP_WITNESS_MERKLE_NULL_V1").hexdigest()


def hash_leaf(data: str) -> str:
    """Hash a leaf node (single record hash). Prepends 0x00 prefix."""
    return hashlib.sha256(LEAF_PREFIX + data.encode()).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Hash two internal nodes together. Prepends 0x01 prefix."""
    combined = NODE_PREFIX + left.encode() + right.encode()
    return hashlib.sha256(combined).hexdigest()


@dataclass
class MerkleTree:
    """A Merkle tree built from record hashes."""

    root: str
    levels: list[list[str]]
    leaf_count: int

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "levels": self.levels,
            "leaf_count": self.leaf_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MerkleTree":
        return cls(
            root=data["root"],
            levels=data["levels"],
            leaf_count=data["leaf_count"],
        )


@dataclass
class MerkleProof:
    """Proof that a leaf belongs to a Merkle tree."""

    leaf_hash: str
    leaf_index: int
    proof_path: list[dict]  # [{"hash": "...", "position": "left"|"right"}, ...]
    root: str

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "proof_path": self.proof_path,
            "root": self.root,
        }


def build_merkle_tree(record_hashes: list[str]) -> MerkleTree:
    """
    Build a Merkle tree from record hashes.

    Applies domain separation: leaves are hashed with a 0x00 prefix
    before being inserted; internal nodes use 0x01 prefix (via hash_pair).

    Args:
        record_hashes: List of SHA-256 hashes (leaves)

    Returns:
        MerkleTree with root and all levels
    """
    if not record_hashes:
        return MerkleTree(root="", levels=[], leaf_count=0)

    leaf_count = len(record_hashes)

    # Apply domain separation to leaves
    domain_separated_leaves = [hash_leaf(h) for h in record_hashes]

    # Pad to power of 2 for balanced tree
    n = len(record_hashes)
    next_pow2 = 1
    while next_pow2 < n:
        next_pow2 *= 2

    # Pad with zero leaves (not duplicate last leaf) to prevent
    # collision attacks where trailing duplicates produce same root
    leaves = domain_separated_leaves + [MERKLE_ZERO_LEAF] * (next_pow2 - n)

    levels = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(hash_pair(left, right))
        levels.append(next_level)
        current = next_level

    return MerkleTree(
        root=current[0] if current else "",
        levels=levels,
        leaf_count=leaf_count,
    )


def get_merkle_proof(tree: MerkleTree, index: int) -> Optional[MerkleProof]:
    """
    Get the proof path for a leaf at given index.

    Args:
        tree: The Merkle tree
        index: Index of the leaf to prove

    Returns:
        MerkleProof with the path from leaf to root
    """
    if not tree.levels or index < 0 or index >= tree.leaf_count:
        return None

    proof_path = []
    idx = index

    for level in tree.levels[:-1]:  # Exclude root level
        sibling_idx = idx ^ 1  # XOR to get sibling index

        if sibling_idx < len(level):
            proof_path.append(
                {"hash": level[sibling_idx], "position": "right" if idx % 2 == 0 else "left"}
            )

        idx //= 2

    return MerkleProof(
        leaf_hash=tree.levels[0][index],
        leaf_index=index,
        proof_path=proof_path,
        root=tree.root,
    )


def verify_merkle_proof(leaf_hash: str, proof_path: list[dict], expected_root: str) -> bool:
    """
    Verify that a leaf belongs to a tree with the given root.

    Performs basic validation: rejects empty proof paths for non-trivial
    trees, rejects negative indices, and validates malformed entries.

    Args:
        leaf_hash: The hash of the leaf to verify
        proof_path: The proof path from get_merkle_proof
        expected_root: The expected Merkle root

    Returns:
        True if the proof is valid
    """
    if not _is_valid_hash(leaf_hash):
        return False

    # Validate proof_path entries
    for step in proof_path:
        if not isinstance(step, dict):
            return False
        if "hash" not in step or "position" not in step:
            return False
        if step["position"] not in ("left", "right"):
            return False
        if not _is_valid_hash(step["hash"]):
            return False

    current = leaf_hash

    for step in proof_path:
        sibling = step["hash"]
        if step["position"] == "right":
            # Sibling is on the right, we're on the left
            current = hash_pair(current, sibling)
        else:
            # Sibling is on the left, we're on the right
            current = hash_pair(sibling, current)

    return current == expected_root


def verify_merkle_proof_strict(
    leaf_hash: str,
    leaf_index: int,
    proof_path: list[dict],
    expected_root: str,
    tree_size: int,
) -> bool:
    """
    Strict Merkle proof verification with ALL validation checks.

    1. Rejects empty proof_path for non-trivial trees (> 1 leaf).
    2. Rejects negative leaf_index.
    3. Validates proof depth matches ceil(log2(tree_size)).
    4. Rejects proof_path with malformed entries.
    5. Validates position is 'left' or 'right' only.

    Args:
        leaf_hash: The domain-separated hash of the leaf.
        leaf_index: The index of the leaf in the tree (0-based).
        proof_path: The proof path from get_merkle_proof.
        expected_root: The expected Merkle root.
        tree_size: The number of leaves in the tree.

    Returns:
        True if the proof is valid under all strict checks.
    """
    # Reject out-of-range leaf_index
    if leaf_index < 0 or leaf_index >= tree_size:
        return False

    if not _is_valid_hash(leaf_hash):
        return False

    # Reject empty proof_path for non-trivial trees
    if tree_size > 1 and not proof_path:
        return False

    # Validate proof depth matches ceil(log2(tree_size))
    if tree_size > 1:
        import math

        expected_depth = math.ceil(math.log2(tree_size))
        if len(proof_path) != expected_depth:
            return False

    # Validate all entries in proof_path
    for step in proof_path:
        if not isinstance(step, dict):
            return False
        if "hash" not in step or "position" not in step:
            return False
        if step["position"] not in ("left", "right"):
            return False
        if not _is_valid_hash(step["hash"]):
            return False

    # Compute the root
    current = leaf_hash
    for step in proof_path:
        sibling = step["hash"]
        if step["position"] == "right":
            current = hash_pair(current, sibling)
        else:
            current = hash_pair(sibling, current)

    return current == expected_root


def verify_tree_integrity(tree: MerkleTree) -> bool:
    """
    Verify that a Merkle tree's internal structure is consistent.

    Args:
        tree: The tree to verify

    Returns:
        True if all internal hashes are correct
    """
    if not tree.levels:
        return tree.root == ""

    # Verify each level computes to the next
    for i in range(len(tree.levels) - 1):
        current = tree.levels[i]
        expected_next = tree.levels[i + 1]

        computed_next = []
        for j in range(0, len(current), 2):
            left = current[j]
            right = current[j + 1] if j + 1 < len(current) else current[j]
            computed_next.append(hash_pair(left, right))

        if computed_next != expected_next:
            return False

    # Verify root
    return tree.levels[-1] == [tree.root]
