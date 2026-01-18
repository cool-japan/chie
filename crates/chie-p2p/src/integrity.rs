//! Data integrity verification module.
//!
//! This module provides mechanisms for verifying data integrity,
//! detecting corruption, and validating content authenticity.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hash algorithm for integrity verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3 hash (fast, cryptographically secure)
    Blake3,
    /// SHA-256 hash
    Sha256,
    /// SHA-512 hash
    Sha512,
    /// XXHash (very fast, not cryptographically secure)
    XxHash,
}

/// Integrity check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    /// Data is valid and matches expected hash
    Valid,
    /// Data is corrupted (hash mismatch)
    Corrupted,
    /// Hash not found for validation
    HashNotFound,
    /// Checksum mismatch
    ChecksumMismatch,
}

/// Chunk verification information.
#[derive(Debug, Clone)]
pub struct ChunkVerification {
    /// Chunk identifier
    pub chunk_id: String,
    /// Expected hash
    pub expected_hash: Vec<u8>,
    /// Actual hash (if computed)
    pub actual_hash: Option<Vec<u8>>,
    /// Verification result
    pub result: IntegrityResult,
    /// When verification was performed
    pub verified_at: Instant,
    /// Time taken to verify
    pub verification_time: Duration,
}

/// Configuration for integrity checker.
#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    /// Hash algorithm to use
    pub hash_algorithm: HashAlgorithm,
    /// Whether to cache verification results
    pub cache_results: bool,
    /// Maximum cache size (number of entries)
    pub max_cache_size: usize,
    /// Cache entry TTL
    pub cache_ttl: Duration,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Blake3,
            cache_results: true,
            max_cache_size: 10000,
            cache_ttl: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Cache entry for verification results.
#[derive(Debug, Clone)]
struct CacheEntry {
    result: IntegrityResult,
    timestamp: Instant,
}

/// Manages data integrity verification.
pub struct IntegrityChecker {
    config: IntegrityConfig,
    known_hashes: HashMap<String, Vec<u8>>,
    verification_cache: HashMap<String, CacheEntry>,
    stats: IntegrityStats,
}

impl IntegrityChecker {
    /// Creates a new integrity checker with default configuration.
    pub fn new() -> Self {
        Self::with_config(IntegrityConfig::default())
    }

    /// Creates a new integrity checker with custom configuration.
    pub fn with_config(config: IntegrityConfig) -> Self {
        Self {
            config,
            known_hashes: HashMap::new(),
            verification_cache: HashMap::new(),
            stats: IntegrityStats::default(),
        }
    }

    /// Registers a known hash for a chunk.
    pub fn register_hash(&mut self, chunk_id: String, hash: Vec<u8>) {
        self.known_hashes.insert(chunk_id, hash);
    }

    /// Computes hash of data using the configured algorithm.
    pub fn compute_hash(&self, data: &[u8]) -> Vec<u8> {
        match self.config.hash_algorithm {
            HashAlgorithm::Blake3 => {
                use blake3::Hasher;
                let mut hasher = Hasher::new();
                hasher.update(data);
                hasher.finalize().as_bytes().to_vec()
            }
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::XxHash => {
                use xxhash_rust::xxh3::xxh3_64;
                xxh3_64(data).to_le_bytes().to_vec()
            }
        }
    }

    /// Verifies data integrity against registered hash.
    pub fn verify(&mut self, chunk_id: &str, data: &[u8]) -> ChunkVerification {
        let start = Instant::now();

        // Check cache first
        if self.config.cache_results {
            if let Some(cached_result) = self.get_cached_result(chunk_id) {
                self.stats.cache_hits += 1;
                return cached_result;
            }
            self.stats.cache_misses += 1;
        }

        let expected_hash = match self.known_hashes.get(chunk_id) {
            Some(hash) => hash.clone(),
            None => {
                self.stats.hash_not_found += 1;
                self.stats.total_checks += 1; // Count this check
                let verification_time = start.elapsed();
                return ChunkVerification {
                    chunk_id: chunk_id.to_string(),
                    expected_hash: vec![],
                    actual_hash: None,
                    result: IntegrityResult::HashNotFound,
                    verified_at: Instant::now(),
                    verification_time,
                };
            }
        };

        // Compute actual hash
        let actual_hash = self.compute_hash(data);
        let result = if actual_hash == expected_hash {
            IntegrityResult::Valid
        } else {
            IntegrityResult::Corrupted
        };

        let verification_time = start.elapsed();

        // Update stats
        match result {
            IntegrityResult::Valid => self.stats.valid_checks += 1,
            IntegrityResult::Corrupted => self.stats.corrupted_checks += 1,
            _ => {}
        }
        self.stats.total_checks += 1;
        self.stats.total_verification_time += verification_time;

        // Cache result
        if self.config.cache_results {
            self.add_to_cache(chunk_id.to_string(), result.clone());
        }

        ChunkVerification {
            chunk_id: chunk_id.to_string(),
            expected_hash,
            actual_hash: Some(actual_hash),
            result,
            verified_at: Instant::now(),
            verification_time,
        }
    }

    /// Verifies data with an explicit expected hash (without registration).
    pub fn verify_with_hash(
        &mut self,
        chunk_id: &str,
        data: &[u8],
        expected_hash: &[u8],
    ) -> ChunkVerification {
        let start = Instant::now();
        let actual_hash = self.compute_hash(data);
        let result = if actual_hash == expected_hash {
            IntegrityResult::Valid
        } else {
            IntegrityResult::Corrupted
        };

        let verification_time = start.elapsed();

        // Update stats
        match result {
            IntegrityResult::Valid => self.stats.valid_checks += 1,
            IntegrityResult::Corrupted => self.stats.corrupted_checks += 1,
            _ => {}
        }
        self.stats.total_checks += 1;
        self.stats.total_verification_time += verification_time;

        ChunkVerification {
            chunk_id: chunk_id.to_string(),
            expected_hash: expected_hash.to_vec(),
            actual_hash: Some(actual_hash),
            result,
            verified_at: Instant::now(),
            verification_time,
        }
    }

    /// Computes and verifies checksum using simple algorithm.
    pub fn verify_checksum(&mut self, data: &[u8], expected_checksum: u32) -> IntegrityResult {
        let actual_checksum = self.compute_simple_checksum(data);

        let result = if actual_checksum == expected_checksum {
            IntegrityResult::Valid
        } else {
            IntegrityResult::ChecksumMismatch
        };

        // Update stats
        match result {
            IntegrityResult::Valid => self.stats.valid_checks += 1,
            IntegrityResult::ChecksumMismatch => self.stats.checksum_mismatches += 1,
            _ => {}
        }
        self.stats.total_checks += 1;

        result
    }

    /// Computes a simple checksum (CRC32-like).
    fn compute_simple_checksum(&self, data: &[u8]) -> u32 {
        let mut checksum: u32 = 0;
        for &byte in data {
            checksum = checksum.wrapping_add(byte as u32);
            checksum = checksum.rotate_left(1);
        }
        checksum
    }

    /// Batch verification of multiple chunks.
    pub fn verify_batch(&mut self, chunks: &[(String, Vec<u8>)]) -> Vec<ChunkVerification> {
        chunks
            .iter()
            .map(|(chunk_id, data)| self.verify(chunk_id, data))
            .collect()
    }

    /// Gets statistics about integrity checks.
    pub fn stats(&self) -> &IntegrityStats {
        &self.stats
    }

    /// Clears all cached verification results.
    pub fn clear_cache(&mut self) {
        self.verification_cache.clear();
    }

    /// Removes a registered hash.
    pub fn remove_hash(&mut self, chunk_id: &str) -> Option<Vec<u8>> {
        self.known_hashes.remove(chunk_id)
    }

    /// Gets a cached result if available and not expired.
    fn get_cached_result(&self, chunk_id: &str) -> Option<ChunkVerification> {
        if let Some(entry) = self.verification_cache.get(chunk_id) {
            if entry.timestamp.elapsed() < self.config.cache_ttl {
                return Some(ChunkVerification {
                    chunk_id: chunk_id.to_string(),
                    expected_hash: self.known_hashes.get(chunk_id).cloned().unwrap_or_default(),
                    actual_hash: None,
                    result: entry.result.clone(),
                    verified_at: entry.timestamp,
                    verification_time: Duration::from_secs(0),
                });
            }
        }
        None
    }

    /// Adds a result to cache.
    fn add_to_cache(&mut self, chunk_id: String, result: IntegrityResult) {
        // Limit cache size
        if self.verification_cache.len() >= self.config.max_cache_size {
            // Remove oldest entry
            if let Some(oldest_key) = self
                .verification_cache
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(key, _)| key.clone())
            {
                self.verification_cache.remove(&oldest_key);
            }
        }

        self.verification_cache.insert(
            chunk_id,
            CacheEntry {
                result,
                timestamp: Instant::now(),
            },
        );
    }

    /// Validates integrity rate (percentage of valid checks).
    pub fn integrity_rate(&self) -> f64 {
        if self.stats.total_checks == 0 {
            return 1.0;
        }
        self.stats.valid_checks as f64 / self.stats.total_checks as f64
    }

    /// Gets average verification time.
    pub fn avg_verification_time(&self) -> Duration {
        if self.stats.total_checks == 0 {
            return Duration::from_secs(0);
        }
        self.stats.total_verification_time / self.stats.total_checks as u32
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about integrity verification.
#[derive(Debug, Clone, Default)]
pub struct IntegrityStats {
    /// Total number of integrity checks performed
    pub total_checks: usize,
    /// Number of valid checks
    pub valid_checks: usize,
    /// Number of corrupted data detections
    pub corrupted_checks: usize,
    /// Number of checksum mismatches
    pub checksum_mismatches: usize,
    /// Number of times hash was not found
    pub hash_not_found: usize,
    /// Number of cache hits
    pub cache_hits: usize,
    /// Number of cache misses
    pub cache_misses: usize,
    /// Total time spent on verification
    pub total_verification_time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_checker_new() {
        let checker = IntegrityChecker::new();
        assert_eq!(checker.stats().total_checks, 0);
    }

    #[test]
    fn test_register_and_verify_valid() {
        let mut checker = IntegrityChecker::new();
        let data = b"Hello, world!";
        let hash = checker.compute_hash(data);

        checker.register_hash("chunk1".to_string(), hash);
        let result = checker.verify("chunk1", data);

        assert_eq!(result.result, IntegrityResult::Valid);
        assert_eq!(checker.stats().valid_checks, 1);
    }

    #[test]
    fn test_verify_corrupted_data() {
        let mut checker = IntegrityChecker::new();
        let original_data = b"Hello, world!";
        let corrupted_data = b"Hallo, world!";

        let hash = checker.compute_hash(original_data);
        checker.register_hash("chunk1".to_string(), hash);

        let result = checker.verify("chunk1", corrupted_data);
        assert_eq!(result.result, IntegrityResult::Corrupted);
        assert_eq!(checker.stats().corrupted_checks, 1);
    }

    #[test]
    fn test_verify_hash_not_found() {
        let mut checker = IntegrityChecker::new();
        let data = b"Hello, world!";

        let result = checker.verify("unknown_chunk", data);
        assert_eq!(result.result, IntegrityResult::HashNotFound);
        assert_eq!(checker.stats().hash_not_found, 1);
    }

    #[test]
    fn test_verify_with_hash() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test data";
        let hash = checker.compute_hash(data);

        let result = checker.verify_with_hash("chunk1", data, &hash);
        assert_eq!(result.result, IntegrityResult::Valid);
    }

    #[test]
    fn test_checksum_verification() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test data";
        let checksum = checker.compute_simple_checksum(data);

        let result = checker.verify_checksum(data, checksum);
        assert_eq!(result, IntegrityResult::Valid);
    }

    #[test]
    fn test_checksum_mismatch() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test data";

        let result = checker.verify_checksum(data, 12345);
        assert_eq!(result, IntegrityResult::ChecksumMismatch);
        assert_eq!(checker.stats().checksum_mismatches, 1);
    }

    #[test]
    fn test_batch_verification() {
        let mut checker = IntegrityChecker::new();
        let data1 = b"Data 1";
        let data2 = b"Data 2";

        let hash1 = checker.compute_hash(data1);
        let hash2 = checker.compute_hash(data2);

        checker.register_hash("chunk1".to_string(), hash1);
        checker.register_hash("chunk2".to_string(), hash2);

        let chunks = vec![
            ("chunk1".to_string(), data1.to_vec()),
            ("chunk2".to_string(), data2.to_vec()),
        ];

        let results = checker.verify_batch(&chunks);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].result, IntegrityResult::Valid);
        assert_eq!(results[1].result, IntegrityResult::Valid);
    }

    #[test]
    fn test_cache_hit() {
        let config = IntegrityConfig {
            cache_results: true,
            ..Default::default()
        };
        let mut checker = IntegrityChecker::with_config(config);

        let data = b"Cached data";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash);

        // First verify - cache miss
        checker.verify("chunk1", data);
        assert_eq!(checker.stats().cache_misses, 1);

        // Second verify - cache hit
        checker.verify("chunk1", data);
        assert_eq!(checker.stats().cache_hits, 1);
    }

    #[test]
    fn test_clear_cache() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash);

        checker.verify("chunk1", data);
        checker.clear_cache();

        // After clearing cache, should get cache miss
        checker.verify("chunk1", data);
        assert!(checker.stats().cache_misses > 0);
    }

    #[test]
    fn test_remove_hash() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash.clone());

        let removed = checker.remove_hash("chunk1");
        assert_eq!(removed, Some(hash));

        let result = checker.verify("chunk1", data);
        assert_eq!(result.result, IntegrityResult::HashNotFound);
    }

    #[test]
    fn test_integrity_rate() {
        let config = IntegrityConfig {
            cache_results: false, // Disable cache to get accurate stats
            ..Default::default()
        };
        let mut checker = IntegrityChecker::with_config(config);
        let data = b"Test data";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash);

        checker.verify("chunk1", data);
        checker.verify("chunk1", b"wrong data");

        let rate = checker.integrity_rate();
        assert!(rate > 0.0 && rate < 1.0);
    }

    #[test]
    fn test_avg_verification_time() {
        let mut checker = IntegrityChecker::new();
        let data = b"Test";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash);

        checker.verify("chunk1", data);
        let avg_time = checker.avg_verification_time();
        assert!(avg_time.as_nanos() > 0);
    }

    #[test]
    fn test_different_hash_algorithms() {
        let algorithms = vec![
            HashAlgorithm::Blake3,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
            HashAlgorithm::XxHash,
        ];

        let data = b"Test data for different algorithms";

        for algo in algorithms {
            let config = IntegrityConfig {
                hash_algorithm: algo,
                ..Default::default()
            };
            let checker = IntegrityChecker::with_config(config);

            let hash = checker.compute_hash(data);
            assert!(!hash.is_empty());
        }
    }

    #[test]
    fn test_cache_size_limit() {
        let config = IntegrityConfig {
            max_cache_size: 2,
            ..Default::default()
        };
        let mut checker = IntegrityChecker::with_config(config);

        for i in 0..5 {
            let chunk_id = format!("chunk{}", i);
            let data = format!("data{}", i);
            let hash = checker.compute_hash(data.as_bytes());
            checker.register_hash(chunk_id.clone(), hash);
            checker.verify(&chunk_id, data.as_bytes());
        }

        // Cache should not exceed max size
        assert!(checker.verification_cache.len() <= 2);
    }

    #[test]
    fn test_stats_accumulation() {
        let config = IntegrityConfig {
            cache_results: false, // Disable cache to get accurate stats
            ..Default::default()
        };
        let mut checker = IntegrityChecker::with_config(config);
        let data = b"Test";
        let hash = checker.compute_hash(data);
        checker.register_hash("chunk1".to_string(), hash);

        checker.verify("chunk1", data);
        checker.verify("chunk1", b"wrong");
        checker.verify("unknown", data);

        let stats = checker.stats();
        assert_eq!(stats.total_checks, 3);
        assert_eq!(stats.valid_checks, 1);
        assert_eq!(stats.corrupted_checks, 1);
        assert_eq!(stats.hash_not_found, 1);
    }
}
