"""Tests for Merkle tree utilities."""

import pytest
from mcp_witness.merkle import (
    build_merkle_tree,
    get_merkle_proof,
    verify_merkle_proof,
    verify_tree_integrity,
    hash_pair,
)


class TestMerkleTree:
    """Tests for Merkle tree building."""
    
    def test_empty_tree(self):
        """Empty input produces empty tree."""
        tree = build_merkle_tree([])
        assert tree.root == ""
        assert tree.levels == []
        assert tree.leaf_count == 0
    
    def test_single_leaf(self):
        """Single leaf tree has that leaf as root."""
        hashes = ["abc123"]
        tree = build_merkle_tree(hashes)
        assert tree.leaf_count == 1
        assert len(tree.levels) >= 1
    
    def test_two_leaves(self):
        """Two leaves produce expected root."""
        hashes = ["hash1", "hash2"]
        tree = build_merkle_tree(hashes)
        
        expected_root = hash_pair("hash1", "hash2")
        assert tree.root == expected_root
        assert tree.leaf_count == 2
    
    def test_four_leaves(self):
        """Four leaves produce balanced tree."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        # Level 0: leaves
        # Level 1: hash(h1,h2), hash(h3,h4)
        # Level 2: root
        assert len(tree.levels) == 3
        assert tree.leaf_count == 4
    
    def test_odd_number_leaves(self):
        """Odd number of leaves pads correctly."""
        hashes = ["h1", "h2", "h3"]
        tree = build_merkle_tree(hashes)
        
        # Should pad to 4 leaves
        assert tree.leaf_count == 3
        assert len(tree.levels[0]) == 4  # Padded to power of 2
    
    def test_tree_integrity(self):
        """Tree integrity verification works."""
        hashes = ["a", "b", "c", "d", "e", "f", "g", "h"]
        tree = build_merkle_tree(hashes)
        
        assert verify_tree_integrity(tree)
    
    def test_deterministic(self):
        """Same input produces same tree."""
        hashes = ["hash1", "hash2", "hash3", "hash4"]
        
        tree1 = build_merkle_tree(hashes)
        tree2 = build_merkle_tree(hashes)
        
        assert tree1.root == tree2.root


class TestMerkleProof:
    """Tests for Merkle proofs."""
    
    def test_proof_for_first_leaf(self):
        """Can generate proof for first leaf."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        proof = get_merkle_proof(tree, 0)
        
        assert proof is not None
        assert proof.leaf_hash == "h1"
        assert proof.leaf_index == 0
        assert proof.root == tree.root
    
    def test_proof_for_last_leaf(self):
        """Can generate proof for last leaf."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        proof = get_merkle_proof(tree, 3)
        
        assert proof is not None
        assert proof.leaf_hash == "h4"
        assert proof.leaf_index == 3
    
    def test_proof_verification(self):
        """Proofs verify correctly."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        for i in range(4):
            proof = get_merkle_proof(tree, i)
            assert verify_merkle_proof(
                proof.leaf_hash,
                proof.proof_path,
                tree.root
            )
    
    def test_invalid_proof_fails(self):
        """Modified proof fails verification."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        proof = get_merkle_proof(tree, 0)
        
        # Modify the leaf hash
        assert not verify_merkle_proof(
            "wrong_hash",
            proof.proof_path,
            tree.root
        )
    
    def test_wrong_root_fails(self):
        """Wrong root fails verification."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)
        
        proof = get_merkle_proof(tree, 0)
        
        assert not verify_merkle_proof(
            proof.leaf_hash,
            proof.proof_path,
            "wrong_root"
        )
    
    def test_invalid_index_returns_none(self):
        """Invalid index returns None."""
        hashes = ["h1", "h2"]
        tree = build_merkle_tree(hashes)
        
        assert get_merkle_proof(tree, -1) is None
        assert get_merkle_proof(tree, 10) is None
    
    def test_large_tree_proof(self):
        """Proofs work for larger trees."""
        hashes = [f"hash_{i}" for i in range(1000)]
        tree = build_merkle_tree(hashes)
        
        # Verify random samples
        for i in [0, 100, 500, 999]:
            proof = get_merkle_proof(tree, i)
            assert verify_merkle_proof(
                proof.leaf_hash,
                proof.proof_path,
                tree.root
            )
