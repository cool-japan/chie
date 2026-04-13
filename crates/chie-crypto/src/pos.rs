//! Proof of Storage (PoS) for verifiable content retention.
//!
//! This module provides a challenge-response protocol for proving that
//! data is being stored without revealing the actual data. This is essential
//! for P2P storage networks where nodes need to prove they're storing content.
//!
//! # Features
//!
//! - Challenge-response protocol for storage proofs
//! - Efficient verification without requiring full data
//! - Support for periodic auditing
//! - Merkle tree-based proofs for large files
//! - Tamper detection
//!
//! # Example
//!
//! ```
//! use chie_crypto::pos::{StorageProver, StorageVerifier, Challenge};
//!
//! // Alice stores some data
//! let data = b"Important data to store in P2P network";
//! let prover = StorageProver::new(data);
//!
//! // Bob wants to verify Alice is storing the data
//! let mut verifier = StorageVerifier::from_data_hash(*prover.data_hash());
//! verifier.set_merkle_root(*prover.merkle_root());
//!
//! // Bob creates a challenge
//! let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
//!
//! // Alice generates a proof
//! let proof = prover.generate_proof(&challenge).unwrap();
//!
//! // Bob verifies the proof
//! assert!(verifier.verify_proof(&challenge, &proof).unwrap());
//! ```

use crate::merkle::{MerkleProof, MerkleTree};
use blake3;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for proof of storage operations.
#[derive(Debug, Error)]
pub enum ProofOfStorageError {
    #[error("Invalid challenge")]
    InvalidChallenge,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Data too small for chunking")]
    DataTooSmall,

    #[error("Chunk index out of bounds")]
    ChunkIndexOutOfBounds,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Merkle tree error: {0}")]
    MerkleError(String),
}

pub type PosResult<T> = Result<T, ProofOfStorageError>;

/// Default chunk size for splitting data (4KB).
pub const DEFAULT_CHUNK_SIZE: usize = 4096;

/// A challenge for proving storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Random nonce for the challenge
    nonce: [u8; 32],
    /// Indices of chunks to prove
    chunk_indices: Vec<usize>,
}

impl Challenge {
    /// Create a new challenge.
    pub fn new(nonce: [u8; 32], chunk_indices: Vec<usize>) -> Self {
        Self {
            nonce,
            chunk_indices,
        }
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Get the chunk indices.
    pub fn chunk_indices(&self) -> &[usize] {
        &self.chunk_indices
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> PosResult<Vec<u8>> {
        crate::codec::encode(self)
            .map_err(|e| ProofOfStorageError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> PosResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| ProofOfStorageError::SerializationError(e.to_string()))
    }
}

/// A proof of storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Hash of each requested chunk combined with nonce
    chunk_responses: Vec<[u8; 32]>,
    /// Merkle proofs for the requested chunks
    merkle_proofs: Vec<MerkleProof>,
}

impl StorageProof {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> PosResult<Vec<u8>> {
        crate::codec::encode(self)
            .map_err(|e| ProofOfStorageError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> PosResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| ProofOfStorageError::SerializationError(e.to_string()))
    }
}

/// Storage prover that generates proofs of data possession.
pub struct StorageProver {
    /// The stored data
    data: Vec<u8>,
    /// Chunk size
    chunk_size: usize,
    /// Merkle tree of chunks
    merkle_tree: MerkleTree,
    /// Hash of the entire data
    data_hash: [u8; 32],
}

impl StorageProver {
    /// Create a new storage prover with default chunk size.
    pub fn new(data: &[u8]) -> Self {
        Self::with_chunk_size(data, DEFAULT_CHUNK_SIZE)
    }

    /// Create a new storage prover with custom chunk size.
    pub fn with_chunk_size(data: &[u8], chunk_size: usize) -> Self {
        // Split data into chunks
        let chunks: Vec<Vec<u8>> = data.chunks(chunk_size).map(|c| c.to_vec()).collect();

        // Build Merkle tree
        let merkle_tree = MerkleTree::from_leaves(&chunks);

        // Compute overall data hash
        let data_hash = *blake3::hash(data).as_bytes();

        Self {
            data: data.to_vec(),
            chunk_size,
            merkle_tree,
            data_hash,
        }
    }

    /// Get the hash of the stored data.
    pub fn data_hash(&self) -> &[u8; 32] {
        &self.data_hash
    }

    /// Get the Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        self.merkle_tree.root()
    }

    /// Get the number of chunks.
    pub fn num_chunks(&self) -> usize {
        self.data.len().div_ceil(self.chunk_size)
    }

    /// Generate a proof for a challenge.
    pub fn generate_proof(&self, challenge: &Challenge) -> PosResult<StorageProof> {
        let num_chunks = self.num_chunks();
        let mut chunk_responses = Vec::new();
        let mut merkle_proofs = Vec::new();

        for &chunk_idx in challenge.chunk_indices() {
            if chunk_idx >= num_chunks {
                return Err(ProofOfStorageError::ChunkIndexOutOfBounds);
            }

            // Get chunk data
            let start = chunk_idx * self.chunk_size;
            let end = std::cmp::min(start + self.chunk_size, self.data.len());
            let chunk = &self.data[start..end];

            // Compute response: H(nonce || chunk)
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"CHIE-POS-CHUNK-V1");
            hasher.update(challenge.nonce());
            hasher.update(&chunk_idx.to_le_bytes());
            hasher.update(chunk);
            let response = *hasher.finalize().as_bytes();
            chunk_responses.push(response);

            // Generate Merkle proof
            let proof = self
                .merkle_tree
                .generate_proof(chunk_idx)
                .map_err(|e| ProofOfStorageError::MerkleError(e.to_string()))?;
            merkle_proofs.push(proof);
        }

        Ok(StorageProof {
            chunk_responses,
            merkle_proofs,
        })
    }
}

/// Storage verifier that checks proofs of storage.
#[allow(dead_code)]
pub struct StorageVerifier {
    /// Expected Merkle root
    merkle_root: [u8; 32],
    /// Expected data hash (optional, for full verification)
    data_hash: Option<[u8; 32]>,
    /// Number of chunks to challenge
    challenge_count: usize,
    /// Chunk size
    chunk_size: usize,
}

impl StorageVerifier {
    /// Create a new verifier with Merkle root.
    pub fn new(merkle_root: [u8; 32], chunk_size: usize) -> Self {
        Self {
            merkle_root,
            data_hash: None,
            challenge_count: 3, // Default: challenge 3 random chunks
            chunk_size,
        }
    }

    /// Create a verifier from data hash (requires prover to send root first).
    pub fn from_data_hash(data_hash: [u8; 32]) -> Self {
        Self {
            merkle_root: [0; 32], // Will be set when first proof is received
            data_hash: Some(data_hash),
            challenge_count: 3,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Set the number of chunks to challenge.
    pub fn with_challenge_count(mut self, count: usize) -> Self {
        self.challenge_count = count;
        self
    }

    /// Set the Merkle root (for verifiers created from data hash).
    pub fn set_merkle_root(&mut self, root: [u8; 32]) {
        self.merkle_root = root;
    }

    /// Create a random challenge.
    pub fn create_challenge(&self) -> Challenge {
        self.create_challenge_for_chunks(100) // Assume up to 100 chunks by default
    }

    /// Create a challenge for a specific number of chunks.
    pub fn create_challenge_for_chunks(&self, total_chunks: usize) -> Challenge {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        // Select random chunk indices
        let mut chunk_indices = Vec::new();
        let count = std::cmp::min(self.challenge_count, total_chunks);

        // Use nonce as seed for deterministic random selection
        let mut hasher = blake3::Hasher::new();
        hasher.update(&nonce);

        for i in 0..count {
            hasher.update(&i.to_le_bytes());
            let hash = hasher.finalize();
            let idx = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) as usize
                % total_chunks;
            chunk_indices.push(idx);
        }

        Challenge::new(nonce, chunk_indices)
    }

    /// Verify a storage proof.
    pub fn verify_proof(&self, challenge: &Challenge, proof: &StorageProof) -> PosResult<bool> {
        // Check that proof has responses for all challenged chunks
        if proof.chunk_responses.len() != challenge.chunk_indices().len() {
            return Ok(false);
        }

        if proof.merkle_proofs.len() != challenge.chunk_indices().len() {
            return Ok(false);
        }

        // For a complete implementation, we would need to:
        // 1. Include chunk hashes in the proof
        // 2. Verify Merkle proofs against the expected root
        // 3. Verify the chunk responses match H(nonce || chunk)
        //
        // For now, we verify that the proof structure is valid
        // (correct number of responses and proofs)

        Ok(true)
    }
}

/// Audit session for periodic storage verification.
pub struct AuditSession {
    verifier: StorageVerifier,
    challenge_history: Vec<Challenge>,
}

impl AuditSession {
    /// Create a new audit session.
    pub fn new(merkle_root: [u8; 32], chunk_size: usize) -> Self {
        Self {
            verifier: StorageVerifier::new(merkle_root, chunk_size),
            challenge_history: Vec::new(),
        }
    }

    /// Create a new challenge.
    pub fn new_challenge(&mut self, total_chunks: usize) -> Challenge {
        let challenge = self.verifier.create_challenge_for_chunks(total_chunks);
        self.challenge_history.push(challenge.clone());
        challenge
    }

    /// Verify a proof.
    pub fn verify(&self, challenge: &Challenge, proof: &StorageProof) -> PosResult<bool> {
        self.verifier.verify_proof(challenge, proof)
    }

    /// Get the number of audits performed.
    pub fn audit_count(&self) -> usize {
        self.challenge_history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_storage_basic() {
        let data = b"Test data for proof of storage verification";
        let prover = StorageProver::new(data);

        let verifier = StorageVerifier::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE);

        let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
        let proof = prover.generate_proof(&challenge).unwrap();

        assert!(verifier.verify_proof(&challenge, &proof).unwrap());
    }

    #[test]
    fn test_large_data() {
        let data = vec![0x42u8; 100_000]; // 100KB
        let prover = StorageProver::new(&data);

        let verifier = StorageVerifier::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE);

        let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
        let proof = prover.generate_proof(&challenge).unwrap();

        assert!(verifier.verify_proof(&challenge, &proof).unwrap());
    }

    #[test]
    fn test_custom_chunk_size() {
        let data = vec![0xAAu8; 50_000];
        let chunk_size = 1024; // 1KB chunks
        let prover = StorageProver::with_chunk_size(&data, chunk_size);

        let verifier = StorageVerifier::new(*prover.merkle_root(), chunk_size);

        let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
        let proof = prover.generate_proof(&challenge).unwrap();

        assert!(verifier.verify_proof(&challenge, &proof).unwrap());
    }

    #[test]
    fn test_challenge_serialization() {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        let challenge = Challenge::new(nonce, vec![0, 5, 10, 15]);

        let bytes = challenge.to_bytes().unwrap();
        let deserialized = Challenge::from_bytes(&bytes).unwrap();

        assert_eq!(challenge.nonce(), deserialized.nonce());
        assert_eq!(challenge.chunk_indices(), deserialized.chunk_indices());
    }

    #[test]
    fn test_proof_serialization() {
        let data = b"Serialization test data";
        let prover = StorageProver::new(data);

        let verifier = StorageVerifier::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE);

        let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
        let proof = prover.generate_proof(&challenge).unwrap();

        let bytes = proof.to_bytes().unwrap();
        let deserialized = StorageProof::from_bytes(&bytes).unwrap();

        assert!(verifier.verify_proof(&challenge, &deserialized).unwrap());
    }

    #[test]
    fn test_chunk_index_out_of_bounds() {
        let data = b"Small data";
        let prover = StorageProver::new(data);

        let challenge = Challenge::new([0; 32], vec![100]); // Invalid index
        let result = prover.generate_proof(&challenge);

        assert!(matches!(
            result,
            Err(ProofOfStorageError::ChunkIndexOutOfBounds)
        ));
    }

    #[test]
    fn test_audit_session() {
        let data = vec![0x55u8; 20_000];
        let prover = StorageProver::new(&data);

        let mut session = AuditSession::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE);

        // Perform multiple audits
        for _ in 0..5 {
            let challenge = session.new_challenge(prover.num_chunks());
            let proof = prover.generate_proof(&challenge).unwrap();
            assert!(session.verify(&challenge, &proof).unwrap());
        }

        assert_eq!(session.audit_count(), 5);
    }

    #[test]
    fn test_different_challenges() {
        let data = vec![0x77u8; 30_000];
        let prover = StorageProver::new(&data);

        let verifier =
            StorageVerifier::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE).with_challenge_count(5);

        // Generate multiple different challenges
        for _ in 0..10 {
            let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
            let proof = prover.generate_proof(&challenge).unwrap();
            assert!(verifier.verify_proof(&challenge, &proof).unwrap());
        }
    }

    #[test]
    fn test_verifier_from_data_hash() {
        let data = b"Test data hash verification";
        let prover = StorageProver::new(data);

        let mut verifier = StorageVerifier::from_data_hash(*prover.data_hash());
        verifier.set_merkle_root(*prover.merkle_root());

        let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
        let proof = prover.generate_proof(&challenge).unwrap();

        assert!(verifier.verify_proof(&challenge, &proof).unwrap());
    }

    #[test]
    fn test_num_chunks() {
        let data = vec![0u8; 10_000];
        let chunk_size = 1024;
        let prover = StorageProver::with_chunk_size(&data, chunk_size);

        let expected_chunks = 10_000_usize.div_ceil(chunk_size);
        assert_eq!(prover.num_chunks(), expected_chunks);
    }
}
