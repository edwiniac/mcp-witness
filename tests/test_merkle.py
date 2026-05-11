"""Tests for Merkle tree utilities."""

from mcp_witness.merkle import (
    MERKLE_ZERO_LEAF,
    build_merkle_tree,
    get_merkle_proof,
    hash_leaf,
    hash_pair,
    verify_merkle_proof,
    verify_tree_integrity,
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
        """Two leaves produce expected root (with domain separation)."""
        hashes = ["hash1", "hash2"]
        tree = build_merkle_tree(hashes)

        # Domain separation applies hash_leaf to each leaf before building
        expected_root = hash_pair(hash_leaf("hash1"), hash_leaf("hash2"))
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
        # Leaf hash is domain-separated
        assert proof.leaf_hash == hash_leaf("h1")
        assert proof.leaf_index == 0
        assert proof.root == tree.root

    def test_proof_for_last_leaf(self):
        """Can generate proof for last leaf."""
        hashes = ["h1", "h2", "h3", "h4"]
        tree = build_merkle_tree(hashes)

        proof = get_merkle_proof(tree, 3)

        assert proof is not None
        assert proof.leaf_hash == hash_leaf("h4")
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


class TestMerkleZeroLeaf:
    """Tests for zero-leaf Merkle padding."""

    def test_zero_leaf_is_constant(self):
        """MERKLE_ZERO_LEAF should be a fixed, deterministic hash.

        This constant must never change between runs to maintain
        cryptographic consistency.
        """
        assert isinstance(MERKLE_ZERO_LEAF, str)
        assert len(MERKLE_ZERO_LEAF) == 64  # SHA-256 hex
        assert MERKLE_ZERO_LEAF == MERKLE_ZERO_LEAF  # deterministic

    def test_zero_leaf_is_valid_hash(self):
        """MERKLE_ZERO_LEAF should be a hex string."""
        assert all(c in "0123456789abcdef" for c in MERKLE_ZERO_LEAF)

    def test_zero_leaf_differs_from_arbitrary_leaf(self):
        """Zero leaf should not clash with a hash of arbitrary data."""
        arbitrary = hash_leaf("SOME_ARBITRARY_SEED")
        assert MERKLE_ZERO_LEAF != arbitrary

    def test_odd_leaves_padded_with_zero_leaf(self):
        """Odd number of leaves should pad with zero leaf, not duplicate."""
        hashes = ["a", "b", "c"]  # 3 leaves, padded to 4
        tree = build_merkle_tree(hashes)

        assert tree.leaf_count == 3
        assert len(tree.levels[0]) == 4  # padded to power of 2
        # Index 3 should be zero leaf, not a duplicate of leaf 2
        assert tree.levels[0][3] == MERKLE_ZERO_LEAF
        assert tree.levels[0][3] != tree.levels[0][2]  # Different from real leaf

    def test_zero_leaf_prefix_domain_separated(self):
        """Zero leaf should have the 0x00 domain separation prefix."""
        import hashlib
        expected = hashlib.sha256(
            b"\x00" + b"MCP_WITNESS_MERKLE_NULL_V1"
        ).hexdigest()
        assert MERKLE_ZERO_LEAF == expected

    def test_trailing_duplicates_no_collision(self):
        """Two record sets differing only by trailing duplicates
        should produce different Merkle roots with zero-leaf padding.

        Before fix: [A, B, B, B] and [A, B, C, D] would collide
        on the padded leaves if B appeared enough times.
        """
        tree1 = build_merkle_tree(["A", "B", "B"])
        tree2 = build_merkle_tree(["A", "B", "C"])

        assert tree1.root != tree2.root

    def test_power_of_two_no_padding_needed(self):
        """Power-of-two leaf counts should not add zero leaves."""
        hashes = ["a", "b", "c", "d"]
        tree = build_merkle_tree(hashes)

        expected_root = hash_pair(
            hash_pair(hash_leaf("a"), hash_leaf("b")),
            hash_pair(hash_leaf("c"), hash_leaf("d")),
        )
        assert tree.root == expected_root

    def test_proofs_still_work_with_zero_leaf_padding(self):
        """Merkle proofs should still verify correctly with zero-leaf padding.

        This ensures the padding change doesn't break proof verification
        for real (non-padding) leaves.
        """
        for count in [1, 2, 3, 5, 7, 10, 15, 100]:
            hashes = [f"h{i}" for i in range(count)]
            tree = build_merkle_tree(hashes)

            for i in range(count):
                proof = get_merkle_proof(tree, i)
                assert proof is not None
                assert verify_merkle_proof(
                    proof.leaf_hash,
                    proof.proof_path,
                    tree.root,
                ), f"Proof failed for leaf {i} in {count}-leaf tree"

            assert verify_tree_integrity(tree)

    def test_edge_case_single_leaf(self):
        """Single leaf tree (already power of 2, needs no padding)."""
        tree = build_merkle_tree(["solo"])
        assert tree.leaf_count == 1
        assert tree.root == hash_leaf("solo")

        proof = get_merkle_proof(tree, 0)
        assert proof is not None
        assert proof.proof_path == []  # No siblings needed
        assert verify_merkle_proof(proof.leaf_hash, proof.proof_path, tree.root)
