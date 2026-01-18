//! Merkle tree implementation for efficient content verification.
//!
//! This module provides Merkle trees for:
//! - Efficient chunk integrity verification
//! - Proving a chunk is part of larger content
//! - Incremental verification as chunks are received
//! - Supporting partial downloads with proof of correctness
//!
//! # Example
//!
//! ```
//! use chie_crypto::merkle::{MerkleTree, MerkleProof};
//!
//! // Build tree from chunks
//! let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];
//! let tree = MerkleTree::from_leaves(&chunks);
//!
//! // Get root hash
//! let root = tree.root();
//!
//! // Generate proof for chunk 1
//! let proof = tree.generate_proof(1).unwrap();
//!
//! // Verify the proof
//! assert!(proof.verify(root, &chunks[1], 1));
//! ```

use crate::hash::{Hash, hash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Merkle tree error types.
#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Invalid leaf index: {0}")]
    InvalidLeafIndex(usize),

    #[error("Empty tree")]
    EmptyTree,

    #[error("Proof verification failed")]
    VerificationFailed,

    #[error("Invalid proof length")]
    InvalidProofLength,

    #[error("Tree size mismatch")]
    TreeSizeMismatch,
}

pub type MerkleResult<T> = Result<T, MerkleError>;

/// A Merkle tree for efficient content verification.
///
/// The tree is built from leaf nodes (content chunks) and allows
/// generating proofs that a specific chunk is part of the content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Tree levels, stored from leaves to root.
    /// levels[0] contains leaf hashes, levels[last] contains root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Create a Merkle tree from leaf data.
    ///
    /// # Arguments
    /// * `leaves` - The leaf data (e.g., content chunks)
    ///
    /// # Returns
    /// A new Merkle tree.
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        assert!(!leaves.is_empty(), "Cannot create tree from empty leaves");

        // Hash all leaves
        let leaf_hashes: Vec<Hash> = leaves.iter().map(|leaf| hash(leaf)).collect();

        Self::from_leaf_hashes(&leaf_hashes)
    }

    /// Create a Merkle tree from pre-hashed leaves.
    pub fn from_leaf_hashes(leaf_hashes: &[Hash]) -> Self {
        assert!(
            !leaf_hashes.is_empty(),
            "Cannot create tree from empty leaves"
        );

        let mut levels = vec![leaf_hashes.to_vec()];
        let mut current_level = leaf_hashes.to_vec();

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    // Odd number of nodes, duplicate the last one
                    left
                };

                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(left);
                data.extend_from_slice(right);
                next_level.push(hash(&data));
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { levels }
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> &Hash {
        &self.levels.last().unwrap()[0]
    }

    /// Get the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Generate a Merkle proof for a specific leaf.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to generate proof for
    ///
    /// # Returns
    /// A Merkle proof that can be used to verify the leaf.
    pub fn generate_proof(&self, leaf_index: usize) -> MerkleResult<MerkleProof> {
        if leaf_index >= self.leaf_count() {
            return Err(MerkleError::InvalidLeafIndex(leaf_index));
        }

        let mut proof_hashes = Vec::new();
        let mut proof_positions = Vec::new(); // true = left, false = right
        let mut index = leaf_index;

        // Traverse up the tree, collecting sibling hashes
        for level in &self.levels[..self.levels.len() - 1] {
            if index % 2 == 0 {
                // Current node is on the left
                let sibling_index = index + 1;
                if sibling_index < level.len() {
                    // Normal case: sibling exists
                    proof_hashes.push(level[sibling_index]);
                    proof_positions.push(true);
                } else {
                    // Odd case: we're the last node, duplicate ourselves
                    proof_hashes.push(level[index]);
                    proof_positions.push(true);
                }
            } else {
                // Current node is on the right, sibling is on the left
                let sibling_index = index - 1;
                proof_hashes.push(level[sibling_index]);
                proof_positions.push(false);
            }

            index /= 2;
        }

        Ok(MerkleProof {
            hashes: proof_hashes,
            positions: proof_positions,
            leaf_index,
        })
    }

    /// Verify that a leaf with given data exists at the specified index.
    ///
    /// # Arguments
    /// * `leaf_data` - The leaf data to verify
    /// * `leaf_index` - The claimed index of the leaf
    ///
    /// # Returns
    /// `true` if the leaf exists at the index, `false` otherwise.
    pub fn verify_leaf(&self, leaf_data: &[u8], leaf_index: usize) -> bool {
        if leaf_index >= self.leaf_count() {
            return false;
        }

        let leaf_hash = hash(leaf_data);
        self.levels[0][leaf_index] == leaf_hash
    }
}

/// A Merkle proof that a specific leaf is part of a Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root.
    hashes: Vec<Hash>,
    /// Positions indicating whether the node is on left (true) or right (false).
    positions: Vec<bool>,
    /// Index of the leaf this proof is for.
    leaf_index: usize,
}

impl MerkleProof {
    /// Verify this proof against a root hash and leaf data.
    ///
    /// # Arguments
    /// * `root` - The expected root hash of the tree
    /// * `leaf_data` - The leaf data to verify
    /// * `leaf_index` - The claimed index of the leaf
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(&self, root: &Hash, leaf_data: &[u8], leaf_index: usize) -> bool {
        if self.leaf_index != leaf_index {
            return false;
        }

        let mut current_hash = hash(leaf_data);

        for (sibling_hash, is_left) in self.hashes.iter().zip(&self.positions) {
            let mut data = Vec::with_capacity(64);

            if *is_left {
                // Current node is on the left
                data.extend_from_slice(&current_hash);
                data.extend_from_slice(sibling_hash);
            } else {
                // Current node is on the right
                data.extend_from_slice(sibling_hash);
                data.extend_from_slice(&current_hash);
            }

            current_hash = hash(&data);
        }

        &current_hash == root
    }

    /// Get the leaf index this proof is for.
    pub fn leaf_index(&self) -> usize {
        self.leaf_index
    }

    /// Get the number of hashes in the proof (proof depth).
    pub fn depth(&self) -> usize {
        self.hashes.len()
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).expect("serialization should not fail")
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> MerkleResult<Self> {
        crate::codec::decode(bytes).map_err(|_| MerkleError::InvalidProofLength)
    }
}

/// Multi-proof for verifying multiple leaves at once.
///
/// This is more efficient than individual proofs when verifying
/// multiple chunks from the same content.
#[derive(Debug, Clone)]
pub struct MultiProof {
    /// Minimal set of hashes needed to verify all leaves.
    hashes: Vec<Hash>,
    /// Instructions for combining hashes.
    instructions: Vec<ProofInstruction>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ProofInstruction {
    /// Use a hash from the proof at the given index.
    UseProofHash(usize),
    /// Use a leaf hash at the given index.
    UseLeafHash(usize),
    /// Combine two previous results.
    Combine { left_idx: usize, right_idx: usize },
}

impl MultiProof {
    /// Verify multiple leaves at once.
    ///
    /// # Arguments
    /// * `root` - The expected root hash
    /// * `leaves` - The leaf data to verify (index, data) pairs
    ///
    /// # Returns
    /// `true` if all leaves are valid, `false` otherwise.
    #[allow(dead_code)]
    pub fn verify(&self, root: &Hash, leaves: &[(usize, &[u8])]) -> bool {
        let mut stack = Vec::new();

        for instruction in &self.instructions {
            match instruction {
                ProofInstruction::UseProofHash(idx) => {
                    stack.push(self.hashes[*idx]);
                }
                ProofInstruction::UseLeafHash(idx) => {
                    let leaf_hash = hash(leaves[*idx].1);
                    stack.push(leaf_hash);
                }
                ProofInstruction::Combine {
                    left_idx,
                    right_idx,
                } => {
                    let left = stack[*left_idx];
                    let right = stack[*right_idx];

                    let mut data = Vec::with_capacity(64);
                    data.extend_from_slice(&left);
                    data.extend_from_slice(&right);

                    stack.push(hash(&data));
                }
            }
        }

        stack.last() == Some(root)
    }
}

/// Incremental Merkle tree builder for streaming content.
///
/// This allows building a Merkle tree as chunks arrive,
/// without needing all chunks in memory at once.
#[derive(Debug)]
pub struct IncrementalMerkleBuilder {
    /// Accumulated leaf hashes.
    leaf_hashes: Vec<Hash>,
}

impl Default for IncrementalMerkleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalMerkleBuilder {
    /// Create a new incremental builder.
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
        }
    }

    /// Add a leaf to the tree.
    pub fn add_leaf(&mut self, data: &[u8]) {
        self.leaf_hashes.push(hash(data));
    }

    /// Add a pre-hashed leaf.
    pub fn add_leaf_hash(&mut self, leaf_hash: Hash) {
        self.leaf_hashes.push(leaf_hash);
    }

    /// Get the current number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_hashes.len()
    }

    /// Finalize the tree.
    pub fn finalize(self) -> MerkleResult<MerkleTree> {
        if self.leaf_hashes.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        Ok(MerkleTree::from_leaf_hashes(&self.leaf_hashes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let chunks = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk3".to_vec(),
            b"chunk4".to_vec(),
        ];

        let tree = MerkleTree::from_leaves(&chunks);
        assert_eq!(tree.leaf_count(), 4);

        let root = tree.root();
        assert_ne!(root, &[0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_generation() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];

        let tree = MerkleTree::from_leaves(&chunks);

        for i in 0..chunks.len() {
            let proof = tree.generate_proof(i);
            assert!(proof.is_ok());
        }

        let invalid_proof = tree.generate_proof(10);
        assert!(invalid_proof.is_err());
    }

    #[test]
    fn test_merkle_proof_verification() {
        let chunks = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk3".to_vec(),
            b"chunk4".to_vec(),
        ];

        let tree = MerkleTree::from_leaves(&chunks);
        let root = tree.root();

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(root, chunk, i));
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];

        let tree = MerkleTree::from_leaves(&chunks);
        let root = tree.root();

        let proof = tree.generate_proof(0).unwrap();

        // Wrong data
        assert!(!proof.verify(root, b"wrong", 0));

        // Wrong index
        assert!(!proof.verify(root, &chunks[0], 1));
    }

    #[test]
    fn test_verify_leaf() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];

        let tree = MerkleTree::from_leaves(&chunks);

        assert!(tree.verify_leaf(b"chunk1", 0));
        assert!(tree.verify_leaf(b"chunk2", 1));
        assert!(tree.verify_leaf(b"chunk3", 2));

        assert!(!tree.verify_leaf(b"chunk1", 1));
        assert!(!tree.verify_leaf(b"wrong", 0));
    }

    #[test]
    fn test_incremental_builder() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];

        let mut builder = IncrementalMerkleBuilder::new();
        for chunk in &chunks {
            builder.add_leaf(chunk);
        }

        let tree = builder.finalize().unwrap();
        assert_eq!(tree.leaf_count(), 3);

        let expected_tree = MerkleTree::from_leaves(&chunks);
        assert_eq!(tree.root(), expected_tree.root());
    }

    #[test]
    fn test_single_leaf() {
        let chunks = vec![b"single".to_vec()];
        let tree = MerkleTree::from_leaves(&chunks);

        assert_eq!(tree.leaf_count(), 1);

        let proof = tree.generate_proof(0).unwrap();
        assert!(proof.verify(tree.root(), b"single", 0));
    }

    #[test]
    fn test_proof_serialization() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];

        let tree = MerkleTree::from_leaves(&chunks);
        let proof = tree.generate_proof(1).unwrap();

        let bytes = proof.to_bytes();
        let deserialized = MerkleProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.leaf_index(), deserialized.leaf_index());
        assert_eq!(proof.depth(), deserialized.depth());

        let root = tree.root();
        assert!(deserialized.verify(root, &chunks[1], 1));
    }

    #[test]
    fn test_large_tree() {
        let chunks: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("chunk{}", i).into_bytes())
            .collect();

        let tree = MerkleTree::from_leaves(&chunks);
        assert_eq!(tree.leaf_count(), 1000);

        // Verify random chunks
        for i in [0, 100, 500, 999] {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(tree.root(), &chunks[i], i));
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let chunks = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk3".to_vec(),
            b"chunk4".to_vec(),
            b"chunk5".to_vec(),
        ];

        let tree = MerkleTree::from_leaves(&chunks);
        assert_eq!(tree.leaf_count(), 5);

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(tree.root(), chunk, i));
        }
    }

    #[test]
    fn test_two_leaves() {
        let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec()];

        let tree = MerkleTree::from_leaves(&chunks);
        assert_eq!(tree.leaf_count(), 2);

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(tree.root(), chunk, i));
        }
    }
}
