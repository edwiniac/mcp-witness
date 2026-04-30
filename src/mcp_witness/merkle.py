"""Merkle tree utilities for efficient verification."""

import hashlib
from dataclasses import dataclass
from typing import Optional

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(leaf_hash: str) -> str:
    """Domain-separated hash for a leaf value."""
    return hashlib.sha256(LEAF_PREFIX + leaf_hash.encode()).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Hash two internal nodes together with domain separation."""
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
    
    Args:
        record_hashes: List of SHA-256 hashes (leaves)
    
    Returns:
        MerkleTree with root and all levels
    """
    if not record_hashes:
        return MerkleTree(root="", levels=[], leaf_count=0)
    
    leaf_count = len(record_hashes)
    
    # Pad to power of 2 for balanced tree
    n = len(record_hashes)
    next_pow2 = 1
    while next_pow2 < n:
        next_pow2 *= 2
    
    # Duplicate last hash to pad (standard Merkle tree behavior)
    leaf_hashes = [hash_leaf(record_hash) for record_hash in record_hashes]
    leaves = leaf_hashes + [leaf_hashes[-1]] * (next_pow2 - n)
    
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
            proof_path.append({
                "hash": level[sibling_idx],
                "position": "right" if idx % 2 == 0 else "left"
            })
        
        idx //= 2
    
    return MerkleProof(
        leaf_hash=tree.levels[0][index],
        leaf_index=index,
        proof_path=proof_path,
        root=tree.root,
    )


def verify_merkle_proof(
    leaf_hash: str,
    proof_path: list[dict],
    expected_root: str
) -> bool:
    """
    Verify that a leaf belongs to a tree with the given root.
    
    Args:
        leaf_hash: The hash of the leaf to verify
        proof_path: The proof path from get_merkle_proof
        expected_root: The expected Merkle root
    
    Returns:
        True if the proof is valid
    """
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
