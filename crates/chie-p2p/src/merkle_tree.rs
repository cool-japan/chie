//! Merkle Tree Content Verification System
//!
//! This module provides cryptographic integrity verification for content chunks using
//! Merkle trees. It enables efficient verification of individual chunks without requiring
//! the entire content, supports incremental updates, and integrates with the existing
//! chunk encryption and integrity systems.
//!
//! # Features
//!
//! - **Efficient Verification**: Verify any chunk with O(log n) proof size
//! - **Incremental Updates**: Update tree when content changes without full rebuild
//! - **Cryptographic Security**: BLAKE3-based hashing for speed and security
//! - **Partial Content Support**: Verify subsets of content efficiently
//! - **Proof Generation**: Create inclusion proofs for any chunk
//! - **Batch Operations**: Build trees from multiple chunks at once
//! - **Flexible Storage**: Serialize/deserialize trees for persistence
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{MerkleTree, MerkleProof};
//!
//! // Build Merkle tree from content chunks
//! let chunks = vec![
//!     vec![1, 2, 3, 4],
//!     vec![5, 6, 7, 8],
//!     vec![9, 10, 11, 12],
//!     vec![13, 14, 15, 16],
//! ];
//!
//! let tree = MerkleTree::from_chunks(&chunks);
//!
//! // Get root hash for content identity
//! let root_hash = tree.root_hash();
//! println!("Content hash: {}", hex::encode(root_hash));
//!
//! // Generate proof for chunk 2
//! let proof = tree.generate_proof(2).unwrap();
//!
//! // Verify the proof
//! assert!(proof.verify(&chunks[2], root_hash));
//!
//! // Update a chunk and rebuild
//! let new_chunk = vec![9, 10, 99, 99];
//! let updated_tree = tree.update_chunk(2, &new_chunk);
//! assert_ne!(tree.root_hash(), updated_tree.root_hash());
//! ```
//!
//! # Integration Points
//!
//! - **Chunk Encryption**: Verify encrypted chunks after decryption
//! - **Content Router**: Verify content before routing
//! - **Integrity Checker**: Enhanced integrity verification
//! - **DHT**: Store root hashes for content discovery
//! - **Bandwidth Proof**: Include proofs in bandwidth verification
//!
//! # Performance
//!
//! - Tree construction: O(n) where n is number of chunks
//! - Proof generation: O(log n)
//! - Proof verification: O(log n)
//! - Memory usage: O(n) for tree storage
//! - Update: O(log n) for single chunk update

use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Size of BLAKE3 hash in bytes (256 bits)
pub const HASH_SIZE: usize = 32;

/// Type alias for hash values
pub type Hash = [u8; HASH_SIZE];

/// Merkle tree structure for content verification
///
/// The tree is built bottom-up from content chunks, with each internal node
/// containing the hash of its children. The root hash serves as a cryptographic
/// commitment to the entire content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Tree nodes stored level by level, with leaves at level 0
    levels: Vec<Vec<Hash>>,
    /// Number of leaf nodes (content chunks)
    leaf_count: usize,
}

/// Merkle inclusion proof for a specific chunk
///
/// Contains the sibling hashes needed to reconstruct the path from
/// a leaf to the root, proving that the chunk is part of the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the chunk being proven
    chunk_index: usize,
    /// Sibling hashes along the path to root
    siblings: Vec<Hash>,
    /// Total number of leaves in the tree
    leaf_count: usize,
}

/// Statistics about Merkle tree operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleStats {
    /// Number of trees created
    pub trees_created: u64,
    /// Number of proofs generated
    pub proofs_generated: u64,
    /// Number of proofs verified (successful)
    pub proofs_verified: u64,
    /// Number of proof verifications failed
    pub verifications_failed: u64,
    /// Number of tree updates performed
    pub trees_updated: u64,
    /// Total chunks processed
    pub chunks_processed: u64,
}

impl MerkleTree {
    /// Create a new Merkle tree from content chunks
    ///
    /// # Arguments
    ///
    /// * `chunks` - Slice of byte vectors representing content chunks
    ///
    /// # Returns
    ///
    /// A Merkle tree with root hash committing to all chunks
    ///
    /// # Panics
    ///
    /// Panics if chunks is empty
    pub fn from_chunks(chunks: &[Vec<u8>]) -> Self {
        assert!(!chunks.is_empty(), "Cannot build tree from empty chunks");

        let leaf_count = chunks.len();
        let mut levels = Vec::new();

        // Level 0: Hash all leaf nodes
        let leaves: Vec<Hash> = chunks.iter().map(|chunk| Self::hash_leaf(chunk)).collect();
        levels.push(leaves);

        // Build tree bottom-up
        while levels.last().unwrap().len() > 1 {
            let current_level = levels.last().unwrap();
            let next_level = Self::build_parent_level(current_level);
            levels.push(next_level);
        }

        Self { levels, leaf_count }
    }

    /// Create an empty tree (for testing/placeholder)
    pub fn empty() -> Self {
        let empty_hash = [0u8; HASH_SIZE];
        Self {
            levels: vec![vec![empty_hash]],
            leaf_count: 0,
        }
    }

    /// Get the root hash of the tree
    ///
    /// The root hash serves as a cryptographic commitment to all content
    pub fn root_hash(&self) -> &Hash {
        self.levels.last().unwrap().first().unwrap()
    }

    /// Get the number of leaf nodes (chunks)
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get the height of the tree (number of levels)
    pub fn height(&self) -> usize {
        self.levels.len()
    }

    /// Generate an inclusion proof for a specific chunk
    ///
    /// # Arguments
    ///
    /// * `chunk_index` - Index of the chunk to prove (0-based)
    ///
    /// # Returns
    ///
    /// A Merkle proof that can be used to verify the chunk, or None if index is invalid
    pub fn generate_proof(&self, chunk_index: usize) -> Option<MerkleProof> {
        if chunk_index >= self.leaf_count {
            return None;
        }

        let mut siblings = Vec::new();
        let mut index = chunk_index;

        // Traverse from leaf to root, collecting sibling hashes
        for level in 0..self.levels.len() - 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            // Get sibling hash (or duplicate if at edge)
            let sibling = if sibling_index < self.levels[level].len() {
                self.levels[level][sibling_index]
            } else {
                self.levels[level][index]
            };

            siblings.push(sibling);
            index /= 2;
        }

        Some(MerkleProof {
            chunk_index,
            siblings,
            leaf_count: self.leaf_count,
        })
    }

    /// Update a chunk and return a new tree
    ///
    /// # Arguments
    ///
    /// * `chunk_index` - Index of the chunk to update
    /// * `new_chunk` - New content for the chunk
    ///
    /// # Returns
    ///
    /// A new Merkle tree with the updated chunk
    ///
    /// # Panics
    ///
    /// Panics if chunk_index is out of bounds
    pub fn update_chunk(&self, chunk_index: usize, new_chunk: &[u8]) -> Self {
        assert!(
            chunk_index < self.leaf_count,
            "Chunk index out of bounds: {} >= {}",
            chunk_index,
            self.leaf_count
        );

        let mut new_levels = self.levels.clone();
        let new_hash = Self::hash_leaf(new_chunk);

        // Update leaf
        new_levels[0][chunk_index] = new_hash;

        // Propagate changes up the tree
        let mut index = chunk_index;
        for level in 0..new_levels.len() - 1 {
            let parent_index = index / 2;
            let left_index = parent_index * 2;
            let right_index = left_index + 1;

            let left = new_levels[level][left_index];
            let right = if right_index < new_levels[level].len() {
                new_levels[level][right_index]
            } else {
                left
            };

            new_levels[level + 1][parent_index] = Self::hash_node(&left, &right);
            index = parent_index;
        }

        Self {
            levels: new_levels,
            leaf_count: self.leaf_count,
        }
    }

    /// Get all leaf hashes
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.levels[0]
    }

    /// Verify that a chunk matches a leaf hash
    pub fn verify_chunk(&self, chunk_index: usize, chunk: &[u8]) -> bool {
        if chunk_index >= self.leaf_count {
            return false;
        }

        let computed_hash = Self::hash_leaf(chunk);
        computed_hash == self.levels[0][chunk_index]
    }

    // Internal: Hash a leaf node (chunk)
    fn hash_leaf(data: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"leaf:");
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    // Internal: Hash an internal node
    fn hash_node(left: &Hash, right: &Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"node:");
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }

    // Internal: Build parent level from current level
    fn build_parent_level(current: &[Hash]) -> Vec<Hash> {
        let mut parent = Vec::new();

        for i in (0..current.len()).step_by(2) {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                left // Duplicate if odd number of nodes
            };

            parent.push(Self::hash_node(left, right));
        }

        parent
    }
}

impl MerkleProof {
    /// Verify that the proof is valid for the given chunk and root hash
    ///
    /// # Arguments
    ///
    /// * `chunk` - The chunk data to verify
    /// * `expected_root` - The expected root hash to verify against
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, chunk: &[u8], expected_root: &Hash) -> bool {
        let mut current_hash = MerkleTree::hash_leaf(chunk);
        let mut index = self.chunk_index;

        // Traverse up the tree using sibling hashes
        for sibling in &self.siblings {
            current_hash = if index % 2 == 0 {
                MerkleTree::hash_node(&current_hash, sibling)
            } else {
                MerkleTree::hash_node(sibling, &current_hash)
            };
            index /= 2;
        }

        &current_hash == expected_root
    }

    /// Get the chunk index this proof is for
    pub fn chunk_index(&self) -> usize {
        self.chunk_index
    }

    /// Get the number of sibling hashes in the proof
    pub fn proof_size(&self) -> usize {
        self.siblings.len()
    }
}

/// Merkle tree manager with statistics tracking
pub struct MerkleTreeManager {
    /// Cache of trees by content ID
    trees: HashMap<String, MerkleTree>,
    /// Statistics
    stats: MerkleStats,
}

impl MerkleTreeManager {
    /// Create a new Merkle tree manager
    pub fn new() -> Self {
        Self {
            trees: HashMap::new(),
            stats: MerkleStats::default(),
        }
    }

    /// Create and cache a tree for content
    pub fn create_tree(&mut self, content_id: String, chunks: &[Vec<u8>]) -> &MerkleTree {
        let tree = MerkleTree::from_chunks(chunks);
        self.stats.trees_created += 1;
        self.stats.chunks_processed += chunks.len() as u64;
        self.trees.insert(content_id.clone(), tree);
        self.trees.get(&content_id).unwrap()
    }

    /// Get a cached tree
    pub fn get_tree(&self, content_id: &str) -> Option<&MerkleTree> {
        self.trees.get(content_id)
    }

    /// Generate and track proof
    pub fn generate_proof(&mut self, content_id: &str, chunk_index: usize) -> Option<MerkleProof> {
        let tree = self.trees.get(content_id)?;
        let proof = tree.generate_proof(chunk_index)?;
        self.stats.proofs_generated += 1;
        Some(proof)
    }

    /// Verify proof and update statistics
    pub fn verify_proof(&mut self, proof: &MerkleProof, chunk: &[u8], root: &Hash) -> bool {
        let result = proof.verify(chunk, root);
        if result {
            self.stats.proofs_verified += 1;
        } else {
            self.stats.verifications_failed += 1;
        }
        result
    }

    /// Update a chunk in cached tree
    pub fn update_chunk(&mut self, content_id: &str, chunk_index: usize, new_chunk: &[u8]) -> bool {
        if let Some(tree) = self.trees.get(content_id) {
            let updated = tree.update_chunk(chunk_index, new_chunk);
            self.trees.insert(content_id.to_string(), updated);
            self.stats.trees_updated += 1;
            true
        } else {
            false
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &MerkleStats {
        &self.stats
    }

    /// Clear cache
    pub fn clear(&mut self) {
        self.trees.clear();
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.trees.len()
    }
}

impl Default for MerkleTreeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_from_chunks() {
        let chunks = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];

        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.height(), 3); // 4 leaves -> 2 -> 1
    }

    #[test]
    fn test_single_chunk_tree() {
        let chunks = vec![vec![1, 2, 3, 4, 5]];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.height(), 1);
    }

    #[test]
    fn test_root_hash_consistency() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree1 = MerkleTree::from_chunks(&chunks);
        let tree2 = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_root_hash_changes_with_data() {
        let chunks1 = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let chunks2 = vec![vec![1, 2, 3], vec![4, 5, 7]];
        let tree1 = MerkleTree::from_chunks(&chunks1);
        let tree2 = MerkleTree::from_chunks(&chunks2);
        assert_ne!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_generate_proof() {
        let chunks = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];
        let tree = MerkleTree::from_chunks(&chunks);

        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.chunk_index(), 0);
        assert_eq!(proof.proof_size(), 2); // log2(4) = 2
    }

    #[test]
    fn test_proof_verification_valid() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let tree = MerkleTree::from_chunks(&chunks);
        let root = *tree.root_hash();

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(
                proof.verify(chunk, &root),
                "Proof verification failed for chunk {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_verification_invalid_chunk() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);
        let proof = tree.generate_proof(0).unwrap();
        let root = *tree.root_hash();

        let wrong_chunk = vec![99, 99, 99];
        assert!(!proof.verify(&wrong_chunk, &root));
    }

    #[test]
    fn test_proof_verification_invalid_root() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);
        let proof = tree.generate_proof(0).unwrap();

        let wrong_root = [0u8; HASH_SIZE];
        assert!(!proof.verify(&chunks[0], &wrong_root));
    }

    #[test]
    fn test_update_chunk() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let tree = MerkleTree::from_chunks(&chunks);
        let old_root = *tree.root_hash();

        let new_chunk = vec![99, 99, 99];
        let updated_tree = tree.update_chunk(1, &new_chunk);
        let new_root = *updated_tree.root_hash();

        assert_ne!(old_root, new_root);
        assert!(updated_tree.verify_chunk(1, &new_chunk));
    }

    #[test]
    fn test_verify_chunk() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);

        assert!(tree.verify_chunk(0, &chunks[0]));
        assert!(tree.verify_chunk(1, &chunks[1]));
        assert!(!tree.verify_chunk(0, &[99, 99, 99]));
    }

    #[test]
    fn test_leaf_hashes() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);
        let leaves = tree.leaf_hashes();

        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0], MerkleTree::hash_leaf(&chunks[0]));
        assert_eq!(leaves[1], MerkleTree::hash_leaf(&chunks[1]));
    }

    #[test]
    fn test_tree_with_odd_chunks() {
        let chunks = vec![vec![1], vec![2], vec![3]];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count(), 3);

        // All proofs should verify
        let root = *tree.root_hash();
        for (i, chunk) in chunks.iter().enumerate().take(3) {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(chunk, &root));
        }
    }

    #[test]
    fn test_tree_with_power_of_two_chunks() {
        let chunks = vec![
            vec![1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
        ];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count(), 8);
        assert_eq!(tree.height(), 4); // 8 -> 4 -> 2 -> 1
    }

    #[test]
    fn test_manager_create_and_get() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        manager.create_tree("content1".to_string(), &chunks);
        assert!(manager.get_tree("content1").is_some());
        assert!(manager.get_tree("content2").is_none());
    }

    #[test]
    fn test_manager_generate_proof() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        manager.create_tree("content1".to_string(), &chunks);
        let proof = manager.generate_proof("content1", 0);
        assert!(proof.is_some());
        assert_eq!(manager.stats().proofs_generated, 1);
    }

    #[test]
    fn test_manager_verify_proof() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let tree = manager.create_tree("content1".to_string(), &chunks);
        let root = *tree.root_hash();
        let proof = manager.generate_proof("content1", 0).unwrap();

        assert!(manager.verify_proof(&proof, &chunks[0], &root));
        assert_eq!(manager.stats().proofs_verified, 1);
    }

    #[test]
    fn test_manager_verify_proof_invalid() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let tree = manager.create_tree("content1".to_string(), &chunks);
        let root = *tree.root_hash();
        let proof = manager.generate_proof("content1", 0).unwrap();

        let wrong_chunk = vec![99, 99, 99];
        assert!(!manager.verify_proof(&proof, &wrong_chunk, &root));
        assert_eq!(manager.stats().verifications_failed, 1);
    }

    #[test]
    fn test_manager_update_chunk() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        manager.create_tree("content1".to_string(), &chunks);
        let new_chunk = vec![99, 99, 99];

        assert!(manager.update_chunk("content1", 0, &new_chunk));
        assert_eq!(manager.stats().trees_updated, 1);

        let tree = manager.get_tree("content1").unwrap();
        assert!(tree.verify_chunk(0, &new_chunk));
    }

    #[test]
    fn test_manager_cache_operations() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3]];

        manager.create_tree("content1".to_string(), &chunks);
        manager.create_tree("content2".to_string(), &chunks);
        assert_eq!(manager.cache_size(), 2);

        manager.clear();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_manager_statistics() {
        let mut manager = MerkleTreeManager::new();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];

        manager.create_tree("content1".to_string(), &chunks);
        let stats = manager.stats();
        assert_eq!(stats.trees_created, 1);
        assert_eq!(stats.chunks_processed, 2);
    }

    #[test]
    #[should_panic(expected = "Cannot build tree from empty chunks")]
    fn test_empty_chunks_panics() {
        let chunks: Vec<Vec<u8>> = vec![];
        MerkleTree::from_chunks(&chunks);
    }

    #[test]
    #[should_panic(expected = "Chunk index out of bounds")]
    fn test_update_invalid_index_panics() {
        let chunks = vec![vec![1, 2, 3]];
        let tree = MerkleTree::from_chunks(&chunks);
        tree.update_chunk(5, &[99]);
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let chunks = vec![vec![1, 2, 3]];
        let tree = MerkleTree::from_chunks(&chunks);
        assert!(tree.generate_proof(5).is_none());
    }

    #[test]
    fn test_serialization() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);

        let serialized = crate::serde_helpers::encode(&tree).unwrap();
        let deserialized: MerkleTree = crate::serde_helpers::decode(&serialized).unwrap();

        assert_eq!(tree.root_hash(), deserialized.root_hash());
        assert_eq!(tree.leaf_count(), deserialized.leaf_count());
    }

    #[test]
    fn test_proof_serialization() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let tree = MerkleTree::from_chunks(&chunks);
        let proof = tree.generate_proof(0).unwrap();

        let serialized = crate::serde_helpers::encode(&proof).unwrap();
        let deserialized: MerkleProof = crate::serde_helpers::decode(&serialized).unwrap();

        let root = *tree.root_hash();
        assert!(deserialized.verify(&chunks[0], &root));
    }
}
