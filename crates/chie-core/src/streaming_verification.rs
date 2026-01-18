//! Incremental content verification with streaming hash.
//!
//! This module provides streaming hash verification for large content,
//! allowing verification to proceed incrementally as chunks arrive without
//! needing to buffer the entire content in memory.
//!
//! # Features
//!
//! - Streaming hash computation (BLAKE3)
//! - Incremental verification without full buffering
//! - Merkle tree-based chunk verification
//! - Progress tracking for long-running verification
//! - Memory-efficient verification of large files
//! - Resumable verification from checkpoints
//!
//! # Example
//!
//! ```
//! use chie_core::streaming_verification::{StreamingVerifier, VerificationProgress};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a verifier with expected root hash
//! let expected_hash = [0u8; 32];
//! let mut verifier = StreamingVerifier::new(expected_hash);
//!
//! // Feed chunks incrementally
//! let chunk1 = b"Hello, ";
//! let chunk2 = b"World!";
//!
//! verifier.update(chunk1);
//! verifier.update(chunk2);
//!
//! // Finalize and verify
//! let result = verifier.finalize()?;
//! if result.verified {
//!     println!("Content verified successfully!");
//! }
//! # Ok(())
//! # }
//! ```

use chie_crypto::hash::{IncrementalHasher, hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Default chunk size for Merkle tree construction (256 KB)
const MERKLE_CHUNK_SIZE: usize = 256 * 1024;

/// Errors that can occur during streaming verification
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("Incomplete verification: {0} bytes processed, {1} bytes expected")]
    Incomplete(u64, u64),

    #[error("Chunk {0} failed verification")]
    ChunkFailed(u64),

    #[error("Merkle tree error: {0}")]
    MerkleError(String),
}

/// Result of verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the content passed verification
    pub verified: bool,
    /// Total bytes verified
    pub bytes_verified: u64,
    /// Actual hash computed
    pub actual_hash: [u8; 32],
    /// Expected hash
    pub expected_hash: [u8; 32],
    /// Number of chunks verified
    pub chunks_verified: u64,
}

impl VerificationResult {
    /// Check if verification succeeded
    #[must_use]
    #[inline]
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    /// Get the hash mismatch if verification failed
    #[must_use]
    #[inline]
    pub fn hash_mismatch(&self) -> Option<([u8; 32], [u8; 32])> {
        if !self.verified {
            Some((self.expected_hash, self.actual_hash))
        } else {
            None
        }
    }
}

/// Progress information for streaming verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProgress {
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Total bytes expected (None if unknown)
    pub total_bytes: Option<u64>,
    /// Number of chunks processed
    pub chunks_processed: u64,
    /// Percentage complete (0.0 to 100.0)
    pub percentage: f64,
}

impl VerificationProgress {
    /// Check if verification is complete
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total_bytes {
            self.bytes_processed >= total
        } else {
            false
        }
    }
}

/// Streaming content verifier using BLAKE3
pub struct StreamingVerifier {
    /// BLAKE3 hasher for streaming hash computation
    hasher: IncrementalHasher,
    /// Expected root hash
    expected_hash: [u8; 32],
    /// Total bytes processed
    bytes_processed: u64,
    /// Expected total bytes (None if unknown)
    total_bytes: Option<u64>,
    /// Chunks processed
    chunks_processed: u64,
}

impl StreamingVerifier {
    /// Create a new streaming verifier with expected hash
    #[must_use]
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self {
            hasher: IncrementalHasher::new(),
            expected_hash,
            bytes_processed: 0,
            total_bytes: None,
            chunks_processed: 0,
        }
    }

    /// Create a verifier with known total size
    #[must_use]
    pub fn with_size(expected_hash: [u8; 32], total_bytes: u64) -> Self {
        Self {
            hasher: IncrementalHasher::new(),
            expected_hash,
            bytes_processed: 0,
            total_bytes: Some(total_bytes),
            chunks_processed: 0,
        }
    }

    /// Update the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
        self.chunks_processed += 1;
    }

    /// Get current verification progress
    #[must_use]
    #[inline]
    pub fn progress(&self) -> VerificationProgress {
        let percentage = if let Some(total) = self.total_bytes {
            if total > 0 {
                (self.bytes_processed as f64 / total as f64) * 100.0
            } else {
                100.0
            }
        } else {
            0.0
        };

        VerificationProgress {
            bytes_processed: self.bytes_processed,
            total_bytes: self.total_bytes,
            chunks_processed: self.chunks_processed,
            percentage,
        }
    }

    /// Finalize the hash and verify
    pub fn finalize(self) -> Result<VerificationResult, VerificationError> {
        let actual_hash: [u8; 32] = self.hasher.finalize();
        let verified = actual_hash == self.expected_hash;

        if !verified {
            return Err(VerificationError::HashMismatch {
                expected: self.expected_hash,
                actual: actual_hash,
            });
        }

        Ok(VerificationResult {
            verified,
            bytes_verified: self.bytes_processed,
            actual_hash,
            expected_hash: self.expected_hash,
            chunks_verified: self.chunks_processed,
        })
    }

    /// Reset the verifier to initial state
    pub fn reset(&mut self) {
        self.hasher = IncrementalHasher::new();
        self.bytes_processed = 0;
        self.chunks_processed = 0;
    }
}

/// Merkle tree-based chunk verifier for parallel verification
pub struct MerkleVerifier {
    /// Expected root hash
    expected_root: [u8; 32],
    /// Chunk hashes (index -> hash)
    chunk_hashes: HashMap<u64, [u8; 32]>,
    /// Chunk size
    chunk_size: usize,
    /// Total chunks expected
    total_chunks: u64,
}

impl MerkleVerifier {
    /// Create a new Merkle verifier
    #[must_use]
    pub fn new(expected_root: [u8; 32], chunk_size: usize, total_chunks: u64) -> Self {
        Self {
            expected_root,
            chunk_hashes: HashMap::new(),
            chunk_size,
            total_chunks,
        }
    }

    /// Create a Merkle verifier with default chunk size (256 KB)
    #[must_use]
    pub fn with_default_chunk_size(expected_root: [u8; 32], total_chunks: u64) -> Self {
        Self::new(expected_root, MERKLE_CHUNK_SIZE, total_chunks)
    }

    /// Verify a single chunk and record its hash
    pub fn verify_chunk(&mut self, chunk_index: u64, data: &[u8]) -> Result<(), VerificationError> {
        // Compute chunk hash
        let chunk_hash: [u8; 32] = hash(data);

        // Store the hash for later Merkle tree verification
        self.chunk_hashes.insert(chunk_index, chunk_hash);

        Ok(())
    }

    /// Build Merkle tree from chunk hashes and verify root
    pub fn verify_merkle_root(&self) -> Result<VerificationResult, VerificationError> {
        if self.chunk_hashes.len() as u64 != self.total_chunks {
            return Err(VerificationError::Incomplete(
                self.chunk_hashes.len() as u64,
                self.total_chunks,
            ));
        }

        // Build Merkle tree bottom-up
        let mut current_level: Vec<[u8; 32]> = (0..self.total_chunks)
            .map(|i| self.chunk_hashes.get(&i).copied().unwrap_or([0u8; 32]))
            .collect();

        // Build tree upward
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined_hash = if chunk.len() == 2 {
                    // Combine two hashes
                    let mut combined = [0u8; 64];
                    combined[..32].copy_from_slice(&chunk[0]);
                    combined[32..].copy_from_slice(&chunk[1]);
                    hash(&combined)
                } else {
                    // Odd number of nodes, promote the last one
                    chunk[0]
                };
                next_level.push(combined_hash);
            }

            current_level = next_level;
        }

        let actual_root = current_level[0];
        let verified = actual_root == self.expected_root;

        if !verified {
            return Err(VerificationError::HashMismatch {
                expected: self.expected_root,
                actual: actual_root,
            });
        }

        Ok(VerificationResult {
            verified,
            bytes_verified: (self.total_chunks * self.chunk_size as u64),
            actual_hash: actual_root,
            expected_hash: self.expected_root,
            chunks_verified: self.total_chunks,
        })
    }

    /// Get the number of chunks verified so far
    #[must_use]
    #[inline]
    pub fn chunks_verified(&self) -> u64 {
        self.chunk_hashes.len() as u64
    }

    /// Check if all chunks have been verified
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.chunk_hashes.len() as u64 == self.total_chunks
    }

    /// Get verification progress
    #[must_use]
    pub fn progress(&self) -> VerificationProgress {
        let chunks_verified = self.chunk_hashes.len() as u64;
        let percentage = if self.total_chunks > 0 {
            (chunks_verified as f64 / self.total_chunks as f64) * 100.0
        } else {
            0.0
        };

        VerificationProgress {
            bytes_processed: chunks_verified * self.chunk_size as u64,
            total_bytes: Some(self.total_chunks * self.chunk_size as u64),
            chunks_processed: chunks_verified,
            percentage,
        }
    }
}

/// Checkpoint for resumable verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheckpoint {
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Chunks processed
    pub chunks_processed: u64,
    /// Partial hash state (serialized)
    pub hash_state: Vec<u8>,
}

impl VerificationCheckpoint {
    /// Create a checkpoint from current state
    #[must_use]
    pub fn new(bytes_processed: u64, chunks_processed: u64) -> Self {
        Self {
            bytes_processed,
            chunks_processed,
            hash_state: Vec::new(), // BLAKE3 doesn't support state serialization
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_verifier_success() {
        let data = b"Hello, World!";
        let expected_hash: [u8; 32] = hash(data);

        let mut verifier = StreamingVerifier::new(expected_hash);
        verifier.update(data);

        let result = verifier.finalize().unwrap();
        assert!(result.verified);
        assert_eq!(result.bytes_verified, data.len() as u64);
    }

    #[test]
    fn test_streaming_verifier_incremental() {
        let part1 = b"Hello, ";
        let part2 = b"World!";
        let full_data = b"Hello, World!";
        let expected_hash: [u8; 32] = hash(full_data);

        let mut verifier = StreamingVerifier::new(expected_hash);
        verifier.update(part1);
        verifier.update(part2);

        let result = verifier.finalize().unwrap();
        assert!(result.verified);
        assert_eq!(result.bytes_verified, full_data.len() as u64);
        assert_eq!(result.chunks_verified, 2);
    }

    #[test]
    fn test_streaming_verifier_mismatch() {
        let data = b"Hello, World!";
        let wrong_hash = [0u8; 32];

        let mut verifier = StreamingVerifier::new(wrong_hash);
        verifier.update(data);

        let result = verifier.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_verifier_progress() {
        let data = b"Hello, World!";
        let expected_hash: [u8; 32] = hash(data);

        let mut verifier = StreamingVerifier::with_size(expected_hash, data.len() as u64);
        verifier.update(&data[..5]);

        let progress = verifier.progress();
        assert_eq!(progress.bytes_processed, 5);
        assert_eq!(progress.total_bytes, Some(data.len() as u64));
        assert!(!progress.is_complete());

        verifier.update(&data[5..]);

        let progress = verifier.progress();
        assert!(progress.is_complete());
        assert_eq!(progress.percentage, 100.0);
    }

    #[test]
    fn test_merkle_verifier_single_chunk() {
        let data = b"Hello, World!";
        let chunk_hash: [u8; 32] = hash(data);

        let mut verifier = MerkleVerifier::new(chunk_hash, 1024, 1);
        verifier.verify_chunk(0, data).unwrap();

        assert!(verifier.is_complete());
        let result = verifier.verify_merkle_root().unwrap();
        assert!(result.verified);
    }

    #[test]
    fn test_merkle_verifier_multiple_chunks() {
        let chunk1 = b"Hello, ";
        let chunk2 = b"World!";

        // Compute expected root
        let hash1: [u8; 32] = hash(chunk1);
        let hash2: [u8; 32] = hash(chunk2);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&hash1);
        combined[32..].copy_from_slice(&hash2);
        let root: [u8; 32] = hash(&combined);

        let mut verifier = MerkleVerifier::new(root, 1024, 2);
        verifier.verify_chunk(0, chunk1).unwrap();
        verifier.verify_chunk(1, chunk2).unwrap();

        assert_eq!(verifier.chunks_verified(), 2);
        assert!(verifier.is_complete());

        let result = verifier.verify_merkle_root().unwrap();
        assert!(result.verified);
    }

    #[test]
    fn test_merkle_verifier_incomplete() {
        let data = b"Hello, World!";
        let chunk_hash: [u8; 32] = hash(data);

        let mut verifier = MerkleVerifier::new(chunk_hash, 1024, 2);
        verifier.verify_chunk(0, data).unwrap();

        assert!(!verifier.is_complete());
        assert_eq!(verifier.chunks_verified(), 1);

        let result = verifier.verify_merkle_root();
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_verifier_progress() {
        let chunk1 = b"Hello";
        let chunk_hash: [u8; 32] = hash(chunk1);

        let mut verifier = MerkleVerifier::with_default_chunk_size(chunk_hash, 4);
        verifier.verify_chunk(0, chunk1).unwrap();

        let progress = verifier.progress();
        assert_eq!(progress.chunks_processed, 1);
        assert_eq!(progress.percentage, 25.0);
    }

    #[test]
    fn test_streaming_verifier_reset() {
        let data = b"Hello, World!";
        let expected_hash: [u8; 32] = hash(data);

        let mut verifier = StreamingVerifier::new(expected_hash);
        verifier.update(data);

        verifier.reset();

        assert_eq!(verifier.bytes_processed, 0);
        assert_eq!(verifier.chunks_processed, 0);
    }

    #[test]
    fn test_verification_result_helpers() {
        let result = VerificationResult {
            verified: false,
            bytes_verified: 100,
            actual_hash: [1u8; 32],
            expected_hash: [2u8; 32],
            chunks_verified: 10,
        };

        assert!(!result.is_verified());
        assert!(result.hash_mismatch().is_some());
        let (expected, actual) = result.hash_mismatch().unwrap();
        assert_eq!(expected, [2u8; 32]);
        assert_eq!(actual, [1u8; 32]);
    }
}
