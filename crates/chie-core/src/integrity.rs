//! Content integrity verification for CHIE Protocol.
//!
//! This module provides:
//! - Chunk hash verification
//! - Merkle tree construction and verification
//! - Content manifest validation

use chie_crypto::{ChunkHasher, Hash, IncrementalHasher, hash};
use std::io::{self, Read};
use thiserror::Error;

/// Default chunk size for integrity verification (256 KB).
pub const DEFAULT_CHUNK_SIZE: usize = 262_144;

/// Integrity verification error.
#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("Chunk hash mismatch at index {index}: expected {expected}, got {actual}")]
    ChunkHashMismatch {
        index: usize,
        expected: String,
        actual: String,
    },

    #[error("Root hash mismatch: expected {expected}, got {actual}")]
    RootHashMismatch { expected: String, actual: String },

    #[error("Invalid chunk count: expected {expected}, got {actual}")]
    InvalidChunkCount { expected: usize, actual: usize },

    #[error("Content too large: {size} bytes exceeds maximum {max} bytes")]
    ContentTooLarge { size: u64, max: u64 },

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// Content manifest with integrity information.
#[derive(Debug, Clone)]
pub struct ContentManifest {
    /// Content identifier (CID).
    pub cid: String,
    /// Total size in bytes.
    pub size_bytes: u64,
    /// Chunk size used.
    pub chunk_size: usize,
    /// Number of chunks.
    pub chunk_count: usize,
    /// Per-chunk hashes.
    pub chunk_hashes: Vec<Hash>,
    /// Root hash (hash of all chunk hashes).
    pub root_hash: Hash,
}

impl ContentManifest {
    /// Verify that a chunk matches its expected hash.
    pub fn verify_chunk(&self, index: usize, chunk_data: &[u8]) -> Result<(), IntegrityError> {
        if index >= self.chunk_count {
            return Err(IntegrityError::InvalidChunkCount {
                expected: self.chunk_count,
                actual: index + 1,
            });
        }

        let expected = &self.chunk_hashes[index];
        let actual = hash(chunk_data);

        if expected != &actual {
            return Err(IntegrityError::ChunkHashMismatch {
                index,
                expected: hex::encode(expected),
                actual: hex::encode(actual),
            });
        }

        Ok(())
    }

    /// Verify that the chunk hashes produce the expected root hash.
    pub fn verify_root_hash(&self) -> Result<(), IntegrityError> {
        let mut hasher = IncrementalHasher::new();
        for chunk_hash in &self.chunk_hashes {
            hasher.update(chunk_hash);
        }
        let actual = hasher.finalize();

        if actual != self.root_hash {
            return Err(IntegrityError::RootHashMismatch {
                expected: hex::encode(self.root_hash),
                actual: hex::encode(actual),
            });
        }

        Ok(())
    }

    /// Get the expected chunk size for a specific index.
    #[must_use]
    pub fn expected_chunk_size(&self, index: usize) -> usize {
        if index >= self.chunk_count {
            return 0;
        }

        if index == self.chunk_count - 1 {
            // Last chunk may be smaller
            let remaining = self.size_bytes as usize % self.chunk_size;
            if remaining == 0 {
                self.chunk_size
            } else {
                remaining
            }
        } else {
            self.chunk_size
        }
    }
}

/// Builder for content manifests.
pub struct ManifestBuilder {
    cid: Option<String>,
    chunk_size: usize,
    chunk_hasher: ChunkHasher,
    total_bytes: u64,
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new(DEFAULT_CHUNK_SIZE)
    }
}

impl ManifestBuilder {
    /// Create a new manifest builder with custom chunk size.
    pub fn new(chunk_size: usize) -> Self {
        Self {
            cid: None,
            chunk_size,
            chunk_hasher: ChunkHasher::new(),
            total_bytes: 0,
        }
    }

    /// Set the content CID.
    pub fn cid(mut self, cid: impl Into<String>) -> Self {
        self.cid = Some(cid.into());
        self
    }

    /// Add a chunk to the manifest.
    pub fn add_chunk(&mut self, chunk_data: &[u8]) -> Hash {
        self.total_bytes += chunk_data.len() as u64;
        self.chunk_hasher.add_chunk(chunk_data)
    }

    /// Build the manifest from a reader.
    pub fn from_reader<R: Read>(mut self, reader: &mut R) -> io::Result<Self> {
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let mut total_read = 0;

            while total_read < self.chunk_size {
                let bytes_read = reader.read(&mut buffer[total_read..])?;
                if bytes_read == 0 {
                    break;
                }
                total_read += bytes_read;
            }

            if total_read == 0 {
                break;
            }

            self.add_chunk(&buffer[..total_read]);

            if total_read < self.chunk_size {
                break;
            }
        }

        Ok(self)
    }

    /// Finalize and build the manifest.
    pub fn build(self) -> ContentManifest {
        let result = self.chunk_hasher.finalize();

        ContentManifest {
            cid: self.cid.unwrap_or_default(),
            size_bytes: self.total_bytes,
            chunk_size: self.chunk_size,
            chunk_count: result.chunk_count(),
            chunk_hashes: result.chunk_hashes,
            root_hash: result.root_hash,
        }
    }
}

/// Content verifier for streaming verification.
pub struct ContentVerifier {
    manifest: ContentManifest,
    current_chunk: usize,
    verified_bytes: u64,
    failed_chunks: Vec<usize>,
}

impl ContentVerifier {
    /// Create a new content verifier.
    pub fn new(manifest: ContentManifest) -> Self {
        Self {
            manifest,
            current_chunk: 0,
            verified_bytes: 0,
            failed_chunks: Vec::new(),
        }
    }

    /// Verify the next chunk in sequence.
    pub fn verify_next(&mut self, chunk_data: &[u8]) -> Result<(), IntegrityError> {
        if self.current_chunk >= self.manifest.chunk_count {
            return Err(IntegrityError::InvalidChunkCount {
                expected: self.manifest.chunk_count,
                actual: self.current_chunk + 1,
            });
        }

        let result = self.manifest.verify_chunk(self.current_chunk, chunk_data);

        if result.is_err() {
            self.failed_chunks.push(self.current_chunk);
        } else {
            self.verified_bytes += chunk_data.len() as u64;
        }

        self.current_chunk += 1;
        result
    }

    /// Verify a specific chunk (out of order).
    pub fn verify_chunk(&mut self, index: usize, chunk_data: &[u8]) -> Result<(), IntegrityError> {
        let result = self.manifest.verify_chunk(index, chunk_data);

        if result.is_err() {
            if !self.failed_chunks.contains(&index) {
                self.failed_chunks.push(index);
            }
        } else {
            self.verified_bytes += chunk_data.len() as u64;
        }

        result
    }

    /// Check if all chunks have been verified.
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.current_chunk >= self.manifest.chunk_count && self.failed_chunks.is_empty()
    }

    /// Get the number of chunks verified.
    #[must_use]
    #[inline]
    pub const fn chunks_verified(&self) -> usize {
        self.current_chunk
    }

    /// Get the number of bytes verified.
    #[must_use]
    #[inline]
    pub const fn bytes_verified(&self) -> u64 {
        self.verified_bytes
    }

    /// Get the indices of failed chunks.
    #[must_use]
    #[inline]
    pub fn failed_chunks(&self) -> &[usize] {
        &self.failed_chunks
    }

    /// Get the manifest.
    #[must_use]
    #[inline]
    pub fn manifest(&self) -> &ContentManifest {
        &self.manifest
    }
}

/// Verify complete content from a reader against a manifest.
pub fn verify_content<R: Read>(
    manifest: &ContentManifest,
    reader: &mut R,
) -> Result<(), IntegrityError> {
    let mut buffer = vec![0u8; manifest.chunk_size];
    let mut chunk_index = 0;

    loop {
        let mut total_read = 0;

        while total_read < manifest.chunk_size {
            let bytes_read = reader.read(&mut buffer[total_read..])?;
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        if total_read == 0 {
            break;
        }

        manifest.verify_chunk(chunk_index, &buffer[..total_read])?;
        chunk_index += 1;
    }

    if chunk_index != manifest.chunk_count {
        return Err(IntegrityError::InvalidChunkCount {
            expected: manifest.chunk_count,
            actual: chunk_index,
        });
    }

    Ok(())
}

/// Quick verification helper for single chunk.
#[inline]
pub fn verify_single_chunk(chunk_data: &[u8], expected_hash: &Hash) -> bool {
    &hash(chunk_data) == expected_hash
}

/// Repair strategy for corrupted chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairStrategy {
    /// Skip corrupted chunks (no repair).
    Skip,
    /// Attempt to repair from a single alternative source.
    SingleSource,
    /// Attempt to repair from multiple sources (voting/consensus).
    MultiSource,
}

/// Result of an integrity repair operation.
#[derive(Debug, Clone)]
pub struct IntegrityRepairResult {
    /// Total chunks that needed repair.
    pub corrupted_count: usize,
    /// Chunks successfully repaired.
    pub repaired_count: usize,
    /// Chunks that could not be repaired.
    pub failed_repairs: Vec<usize>,
    /// Time taken for repair operation.
    pub repair_duration_ms: u64,
}

impl IntegrityRepairResult {
    /// Check if all corrupted chunks were successfully repaired.
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.failed_repairs.is_empty()
    }

    /// Get the repair success rate (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        if self.corrupted_count == 0 {
            return 1.0;
        }
        self.repaired_count as f64 / self.corrupted_count as f64
    }
}

/// Automatic integrity repair system.
///
/// This system detects corrupted chunks and attempts to repair them
/// by requesting valid data from alternative sources.
pub struct IntegrityRepairer {
    /// The content manifest with expected hashes.
    manifest: ContentManifest,
    /// Repair strategy to use.
    strategy: RepairStrategy,
    /// Maximum repair attempts per chunk.
    max_attempts: usize,
    /// Repair statistics.
    repair_stats: RepairStats,
}

/// Statistics for repair operations.
#[derive(Debug, Clone, Default)]
pub struct RepairStats {
    /// Total repair operations performed.
    pub total_operations: usize,
    /// Total chunks repaired successfully.
    pub total_repaired: usize,
    /// Total chunks that failed repair.
    pub total_failed: usize,
    /// Average repair time in milliseconds.
    pub avg_repair_time_ms: f64,
}

impl RepairStats {
    /// Get the overall success rate.
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_repaired + self.total_failed;
        if total == 0 {
            return 1.0;
        }
        self.total_repaired as f64 / total as f64
    }
}

impl IntegrityRepairer {
    /// Create a new integrity repairer.
    #[must_use]
    pub fn new(manifest: ContentManifest, strategy: RepairStrategy) -> Self {
        Self {
            manifest,
            strategy,
            max_attempts: 3,
            repair_stats: RepairStats::default(),
        }
    }

    /// Set the maximum repair attempts per chunk.
    pub fn set_max_attempts(&mut self, max_attempts: usize) {
        self.max_attempts = max_attempts;
    }

    /// Verify a chunk and attempt repair if corrupted.
    ///
    /// The `fetch_fn` is called to retrieve alternative chunk data when corruption is detected.
    /// It receives the chunk index and should return the chunk data, or None if unavailable.
    pub fn verify_and_repair<F>(
        &mut self,
        index: usize,
        chunk_data: &[u8],
        fetch_fn: F,
    ) -> Result<Vec<u8>, IntegrityError>
    where
        F: FnMut(usize) -> Option<Vec<u8>>,
    {
        // First, verify the provided chunk
        if self.manifest.verify_chunk(index, chunk_data).is_ok() {
            return Ok(chunk_data.to_vec());
        }

        // Chunk is corrupted, attempt repair
        match self.strategy {
            RepairStrategy::Skip => Err(IntegrityError::ChunkHashMismatch {
                index,
                expected: hex::encode(self.manifest.chunk_hashes[index]),
                actual: hex::encode(hash(chunk_data)),
            }),
            RepairStrategy::SingleSource | RepairStrategy::MultiSource => {
                self.attempt_repair(index, fetch_fn)
            }
        }
    }

    /// Attempt to repair a corrupted chunk.
    fn attempt_repair<F>(
        &mut self,
        index: usize,
        mut fetch_fn: F,
    ) -> Result<Vec<u8>, IntegrityError>
    where
        F: FnMut(usize) -> Option<Vec<u8>>,
    {
        let start_time = std::time::Instant::now();

        for attempt in 0..self.max_attempts {
            if let Some(candidate_data) = fetch_fn(index) {
                // Verify the candidate data
                if self.manifest.verify_chunk(index, &candidate_data).is_ok() {
                    // Repair successful
                    let duration_ms = start_time.elapsed().as_millis() as u64;
                    self.repair_stats.total_operations += 1;
                    self.repair_stats.total_repaired += 1;
                    self.update_avg_repair_time(duration_ms);

                    return Ok(candidate_data);
                }
            }

            // For multi-source strategy, we could aggregate multiple sources here
            if self.strategy == RepairStrategy::SingleSource && attempt > 0 {
                break; // Single source only tries once
            }
        }

        // Repair failed
        self.repair_stats.total_operations += 1;
        self.repair_stats.total_failed += 1;

        Err(IntegrityError::ChunkHashMismatch {
            index,
            expected: hex::encode(self.manifest.chunk_hashes[index]),
            actual: "repair_failed".to_string(),
        })
    }

    /// Update the average repair time.
    fn update_avg_repair_time(&mut self, new_time_ms: u64) {
        let total_ops = self.repair_stats.total_operations;
        let old_avg = self.repair_stats.avg_repair_time_ms;
        self.repair_stats.avg_repair_time_ms =
            (old_avg * (total_ops - 1) as f64 + new_time_ms as f64) / total_ops as f64;
    }

    /// Batch verify and repair multiple chunks.
    ///
    /// Returns an IntegrityRepairResult with statistics about the operation.
    pub fn batch_verify_and_repair<F>(
        &mut self,
        chunks: &[(usize, Vec<u8>)],
        fetch_fn: F,
    ) -> IntegrityRepairResult
    where
        F: Fn(usize) -> Option<Vec<u8>>,
    {
        let start_time = std::time::Instant::now();
        let mut corrupted_count = 0;
        let mut repaired_count = 0;
        let mut failed_repairs = Vec::new();

        for (index, chunk_data) in chunks {
            // Check if chunk is corrupted
            if self.manifest.verify_chunk(*index, chunk_data).is_err() {
                corrupted_count += 1;

                // Attempt repair
                match self.verify_and_repair(*index, chunk_data, &fetch_fn) {
                    Ok(_) => repaired_count += 1,
                    Err(_) => failed_repairs.push(*index),
                }
            }
        }

        let repair_duration_ms = start_time.elapsed().as_millis() as u64;

        IntegrityRepairResult {
            corrupted_count,
            repaired_count,
            failed_repairs,
            repair_duration_ms,
        }
    }

    /// Get current repair statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &RepairStats {
        &self.repair_stats
    }

    /// Get the manifest.
    #[must_use]
    #[inline]
    pub fn manifest(&self) -> &ContentManifest {
        &self.manifest
    }

    /// Get the current repair strategy.
    #[must_use]
    #[inline]
    pub const fn strategy(&self) -> RepairStrategy {
        self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_manifest_builder() {
        let data = b"Hello, CHIE Protocol! This is test data for integrity verification.";
        let mut cursor = Cursor::new(data);

        let manifest = ManifestBuilder::new(20)
            .cid("QmTest123")
            .from_reader(&mut cursor)
            .unwrap()
            .build();

        assert_eq!(manifest.cid, "QmTest123");
        assert_eq!(manifest.size_bytes, data.len() as u64);
        assert_eq!(manifest.chunk_size, 20);
        assert_eq!(manifest.chunk_count, 4); // 68 bytes / 20 = 4 chunks (20, 20, 20, 8)
    }

    #[test]
    fn test_chunk_verification() {
        let chunk1 = b"Chunk 1 data here..";
        let chunk2 = b"Chunk 2 data here..";

        let mut builder = ManifestBuilder::new(20);
        builder.add_chunk(chunk1);
        builder.add_chunk(chunk2);
        let manifest = builder.build();

        assert!(manifest.verify_chunk(0, chunk1).is_ok());
        assert!(manifest.verify_chunk(1, chunk2).is_ok());
        assert!(manifest.verify_chunk(0, chunk2).is_err()); // Wrong data
    }

    #[test]
    fn test_content_verifier() {
        let chunk1 = b"Chunk 1";
        let chunk2 = b"Chunk 2";
        let chunk3 = b"Chunk 3";

        let mut builder = ManifestBuilder::new(10);
        builder.add_chunk(chunk1);
        builder.add_chunk(chunk2);
        builder.add_chunk(chunk3);
        let manifest = builder.build();

        let mut verifier = ContentVerifier::new(manifest);

        assert!(verifier.verify_next(chunk1).is_ok());
        assert!(verifier.verify_next(chunk2).is_ok());
        assert!(verifier.verify_next(chunk3).is_ok());
        assert!(verifier.is_complete());
        assert_eq!(verifier.failed_chunks().len(), 0);
    }

    #[test]
    fn test_verify_content() {
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut cursor = Cursor::new(data);

        let manifest = ManifestBuilder::new(10)
            .from_reader(&mut cursor)
            .unwrap()
            .build();

        let mut cursor2 = Cursor::new(data);
        assert!(verify_content(&manifest, &mut cursor2).is_ok());

        // Verify with wrong data fails
        let wrong_data = b"ABCDEFGHIJKLMNOPQRSTUVWXYz"; // Last char different
        let mut cursor3 = Cursor::new(wrong_data);
        assert!(verify_content(&manifest, &mut cursor3).is_err());
    }

    #[test]
    fn test_root_hash_verification() {
        let mut builder = ManifestBuilder::new(10);
        builder.add_chunk(b"Chunk 1");
        builder.add_chunk(b"Chunk 2");
        let manifest = builder.build();

        assert!(manifest.verify_root_hash().is_ok());
    }

    #[test]
    fn test_integrity_repairer_no_corruption() {
        let chunk = b"Valid chunk data";
        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(chunk);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::SingleSource);

        // Valid chunk should not trigger repair
        let result = repairer.verify_and_repair(0, chunk, |_| None);
        assert!(result.is_ok());
        assert_eq!(repairer.stats().total_operations, 0);
    }

    #[test]
    fn test_integrity_repairer_successful_repair() {
        let valid_chunk = b"Valid chunk data";
        let corrupted_chunk = b"Corrupted chunk!";

        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(valid_chunk);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::SingleSource);

        // Corrupted chunk should trigger repair
        let result = repairer.verify_and_repair(0, corrupted_chunk, |_| Some(valid_chunk.to_vec()));
        assert!(result.is_ok());
        assert_eq!(repairer.stats().total_repaired, 1);
        assert_eq!(repairer.stats().success_rate(), 1.0);
    }

    #[test]
    fn test_integrity_repairer_failed_repair() {
        let valid_chunk = b"Valid chunk data";
        let corrupted_chunk = b"Corrupted chunk!";

        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(valid_chunk);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::SingleSource);

        // Repair should fail when fetch_fn returns None
        let result = repairer.verify_and_repair(0, corrupted_chunk, |_| None);
        assert!(result.is_err());
        assert_eq!(repairer.stats().total_failed, 1);
        assert_eq!(repairer.stats().success_rate(), 0.0);
    }

    #[test]
    fn test_integrity_repairer_batch_repair() {
        let chunk1 = b"Chunk 1 valid!!!";
        let chunk2 = b"Chunk 2 valid!!!";
        let chunk3 = b"Chunk 3 valid!!!";

        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(chunk1);
        builder.add_chunk(chunk2);
        builder.add_chunk(chunk3);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::MultiSource);

        // Mix of valid and corrupted chunks
        let chunks = vec![
            (0, chunk1.to_vec()),              // Valid
            (1, b"Corrupted!!!!!!!".to_vec()), // Corrupted
            (2, b"Also corrupted!".to_vec()),  // Corrupted
        ];

        // Fetch function that returns valid data
        let fetch_fn = |index: usize| match index {
            1 => Some(chunk2.to_vec()),
            2 => Some(chunk3.to_vec()),
            _ => None,
        };

        let result = repairer.batch_verify_and_repair(&chunks, fetch_fn);
        assert_eq!(result.corrupted_count, 2);
        assert_eq!(result.repaired_count, 2);
        assert!(result.is_complete());
        assert_eq!(result.success_rate(), 1.0);
    }

    #[test]
    fn test_repair_strategy_skip() {
        let valid_chunk = b"Valid chunk data";
        let corrupted_chunk = b"Corrupted chunk!";

        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(valid_chunk);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::Skip);

        // Skip strategy should not attempt repair
        let result = repairer.verify_and_repair(0, corrupted_chunk, |_| Some(valid_chunk.to_vec()));
        assert!(result.is_err());
        assert_eq!(repairer.stats().total_operations, 0); // No repair attempted
    }

    #[test]
    fn test_repair_result_success_rate() {
        let result = IntegrityRepairResult {
            corrupted_count: 10,
            repaired_count: 7,
            failed_repairs: vec![2, 5, 8],
            repair_duration_ms: 100,
        };

        assert_eq!(result.success_rate(), 0.7);
        assert!(!result.is_complete());

        let perfect_result = IntegrityRepairResult {
            corrupted_count: 5,
            repaired_count: 5,
            failed_repairs: vec![],
            repair_duration_ms: 50,
        };

        assert_eq!(perfect_result.success_rate(), 1.0);
        assert!(perfect_result.is_complete());
    }

    #[test]
    fn test_repair_stats() {
        let valid_chunk = b"Valid chunk data";
        let corrupted_chunk = b"Corrupted chunk!";

        let mut builder = ManifestBuilder::new(16);
        builder.add_chunk(valid_chunk);
        let manifest = builder.build();

        let mut repairer = IntegrityRepairer::new(manifest, RepairStrategy::MultiSource);
        repairer.set_max_attempts(2);

        // First repair - success
        let _ = repairer.verify_and_repair(0, corrupted_chunk, |_| Some(valid_chunk.to_vec()));

        // Second repair - failure
        let _ = repairer.verify_and_repair(0, corrupted_chunk, |_| None);

        let stats = repairer.stats();
        assert_eq!(stats.total_operations, 2);
        assert_eq!(stats.total_repaired, 1);
        assert_eq!(stats.total_failed, 1);
        assert_eq!(stats.success_rate(), 0.5);
        assert!(stats.avg_repair_time_ms >= 0.0);
    }
}
