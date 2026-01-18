//! Erasure coding for data redundancy using Reed-Solomon codes.
//!
//! This module provides efficient data redundancy through erasure coding,
//! allowing content to be reconstructed even when some shards are unavailable.
//! This is more storage-efficient than full replication.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::erasure_coding::ErasureCoder;
//!
//! let coder = ErasureCoder::new(4, 2).unwrap(); // 4 data shards, 2 parity shards
//! let data = b"Hello, CHIE Protocol! This is test data for erasure coding.";
//!
//! // Encode data into shards
//! let shards = coder.encode(data).unwrap();
//! assert_eq!(shards.len(), 6); // 4 data + 2 parity
//!
//! // Can reconstruct from any 4 out of 6 shards
//! let mut partial_shards = shards.clone();
//! partial_shards[1] = None; // Simulate lost shard
//! partial_shards[3] = None; // Simulate another lost shard
//!
//! let reconstructed = coder.decode(&partial_shards).unwrap();
//! assert_eq!(&reconstructed[..data.len()], data);
//! ```

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// Errors that can occur during erasure coding operations.
#[derive(Debug, Error)]
pub enum ErasureError {
    /// Invalid shard configuration.
    #[error("Invalid shard configuration: {0}")]
    InvalidConfig(String),

    /// Encoding failed.
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    /// Decoding failed.
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    /// Not enough shards for reconstruction.
    #[error("Not enough shards: need {needed}, got {available}")]
    InsufficientShards { needed: usize, available: usize },

    /// Shard size mismatch.
    #[error("Shard size mismatch: expected {expected}, got {actual}")]
    ShardSizeMismatch { expected: usize, actual: usize },
}

/// Configuration for erasure coding.
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of data shards.
    pub data_shards: usize,
    /// Number of parity shards.
    pub parity_shards: usize,
    /// Target shard size in bytes (data will be padded if needed).
    pub shard_size: usize,
}

impl ErasureConfig {
    /// Create a new erasure coding configuration.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, ErasureError> {
        if data_shards == 0 {
            return Err(ErasureError::InvalidConfig(
                "Data shards must be > 0".to_string(),
            ));
        }
        if parity_shards == 0 {
            return Err(ErasureError::InvalidConfig(
                "Parity shards must be > 0".to_string(),
            ));
        }
        if data_shards + parity_shards > 256 {
            return Err(ErasureError::InvalidConfig(
                "Total shards must be <= 256".to_string(),
            ));
        }

        Ok(Self {
            data_shards,
            parity_shards,
            shard_size: 64 * 1024, // 64 KB default
        })
    }

    /// Set the target shard size.
    pub fn with_shard_size(mut self, size: usize) -> Self {
        self.shard_size = size;
        self
    }

    /// Get total number of shards.
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Get minimum shards needed for reconstruction.
    pub fn min_shards_for_recovery(&self) -> usize {
        self.data_shards
    }
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self::new(10, 4).unwrap() // 10 data + 4 parity = recover from 4 failures
    }
}

/// Statistics for erasure coding operations.
#[derive(Debug, Default, Clone)]
pub struct ErasureStats {
    /// Total encode operations.
    pub encode_count: u64,
    /// Total decode operations.
    pub decode_count: u64,
    /// Total bytes encoded.
    pub bytes_encoded: u64,
    /// Total bytes decoded.
    pub bytes_decoded: u64,
    /// Total encoding time in microseconds.
    pub encode_time_us: u64,
    /// Total decoding time in microseconds.
    pub decode_time_us: u64,
    /// Number of successful reconstructions.
    pub successful_reconstructions: u64,
    /// Number of failed reconstructions.
    pub failed_reconstructions: u64,
}

impl ErasureStats {
    /// Get average encoding throughput in MB/s.
    pub fn avg_encode_throughput_mbps(&self) -> f64 {
        if self.encode_time_us == 0 {
            return 0.0;
        }
        (self.bytes_encoded as f64 / (self.encode_time_us as f64 / 1_000_000.0)) / (1024.0 * 1024.0)
    }

    /// Get average decoding throughput in MB/s.
    pub fn avg_decode_throughput_mbps(&self) -> f64 {
        if self.decode_time_us == 0 {
            return 0.0;
        }
        (self.bytes_decoded as f64 / (self.decode_time_us as f64 / 1_000_000.0)) / (1024.0 * 1024.0)
    }

    /// Get reconstruction success rate.
    pub fn reconstruction_success_rate(&self) -> f64 {
        let total = self.successful_reconstructions + self.failed_reconstructions;
        if total == 0 {
            return 0.0;
        }
        self.successful_reconstructions as f64 / total as f64
    }
}

/// Erasure coder using Reed-Solomon codes.
pub struct ErasureCoder {
    config: ErasureConfig,
    encoder: Arc<ReedSolomon>,
    stats: Arc<parking_lot::RwLock<ErasureStats>>,
}

impl ErasureCoder {
    /// Create a new erasure coder with the given configuration.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, ErasureError> {
        let config = ErasureConfig::new(data_shards, parity_shards)?;
        let encoder = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| ErasureError::InvalidConfig(e.to_string()))?;

        Ok(Self {
            config,
            encoder: Arc::new(encoder),
            stats: Arc::new(parking_lot::RwLock::new(ErasureStats::default())),
        })
    }

    /// Create a new erasure coder with custom configuration.
    pub fn with_config(config: ErasureConfig) -> Result<Self, ErasureError> {
        let encoder = ReedSolomon::new(config.data_shards, config.parity_shards)
            .map_err(|e| ErasureError::InvalidConfig(e.to_string()))?;

        Ok(Self {
            config,
            encoder: Arc::new(encoder),
            stats: Arc::new(parking_lot::RwLock::new(ErasureStats::default())),
        })
    }

    /// Get the configuration.
    pub fn config(&self) -> &ErasureConfig {
        &self.config
    }

    /// Get statistics.
    pub fn stats(&self) -> ErasureStats {
        self.stats.read().clone()
    }

    /// Encode data into shards.
    ///
    /// Returns a vector of shards where the first `data_shards` are data shards
    /// and the remaining are parity shards. All shards are of equal size.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Option<Vec<u8>>>, ErasureError> {
        let start = Instant::now();

        // Calculate shard size based on data length
        let shard_size = data.len().div_ceil(self.config.data_shards);

        // Create data shards (pad if necessary)
        let mut shards: Vec<Vec<u8>> = (0..self.config.data_shards)
            .map(|i| {
                let start_idx = i * shard_size;
                let end_idx = std::cmp::min(start_idx + shard_size, data.len());
                let mut shard = if start_idx < data.len() {
                    data[start_idx..end_idx].to_vec()
                } else {
                    vec![]
                };
                // Pad to shard_size
                shard.resize(shard_size, 0);
                shard
            })
            .collect();

        // Add parity shards
        for _ in 0..self.config.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode
        self.encoder
            .encode(&mut shards)
            .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;

        // Update stats
        let elapsed = start.elapsed();
        let mut stats = self.stats.write();
        stats.encode_count += 1;
        stats.bytes_encoded += data.len() as u64;
        stats.encode_time_us += elapsed.as_micros() as u64;

        Ok(shards.into_iter().map(Some).collect())
    }

    /// Decode shards back into data.
    ///
    /// Shards should be a vector where `None` represents a missing shard.
    /// At least `data_shards` shards must be present.
    pub fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>, ErasureError> {
        let start = Instant::now();

        if shards.len() != self.config.total_shards() {
            return Err(ErasureError::InvalidConfig(format!(
                "Expected {} shards, got {}",
                self.config.total_shards(),
                shards.len()
            )));
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.config.data_shards {
            let mut stats = self.stats.write();
            stats.decode_count += 1;
            stats.failed_reconstructions += 1;
            return Err(ErasureError::InsufficientShards {
                needed: self.config.data_shards,
                available,
            });
        }

        // Clone shards for reconstruction
        let mut shards_copy: Vec<Option<Vec<u8>>> = shards.to_vec();

        // Reconstruct
        if self
            .encoder
            .reconstruct(&mut shards_copy)
            .map_err(|e| ErasureError::DecodingFailed(e.to_string()))
            .is_err()
        {
            let mut stats = self.stats.write();
            stats.decode_count += 1;
            stats.failed_reconstructions += 1;
            return Err(ErasureError::DecodingFailed(
                "Reconstruction failed".to_string(),
            ));
        }

        // Concatenate data shards
        let mut data = Vec::new();
        for shard in shards_copy.iter().take(self.config.data_shards) {
            if let Some(s) = shard {
                data.extend_from_slice(s);
            } else {
                let mut stats = self.stats.write();
                stats.decode_count += 1;
                stats.failed_reconstructions += 1;
                return Err(ErasureError::DecodingFailed(
                    "Data shard missing after reconstruction".to_string(),
                ));
            }
        }

        // Update stats
        let elapsed = start.elapsed();
        let mut stats = self.stats.write();
        stats.decode_count += 1;
        stats.bytes_decoded += data.len() as u64;
        stats.decode_time_us += elapsed.as_micros() as u64;
        stats.successful_reconstructions += 1;

        Ok(data)
    }

    /// Verify that a shard is valid for the given position.
    pub fn verify_shard(
        &self,
        shards: &[Option<Vec<u8>>],
        _shard_index: usize,
    ) -> Result<bool, ErasureError> {
        if _shard_index >= self.config.total_shards() {
            return Err(ErasureError::InvalidConfig(format!(
                "Shard index {} out of bounds",
                _shard_index
            )));
        }

        // Convert Option<Vec<u8>> to Vec<Vec<u8>> for verification
        let shard_refs: Vec<Vec<u8>> = shards.iter().filter_map(|s| s.clone()).collect();

        if shard_refs.len() < self.config.data_shards {
            return Ok(false); // Not enough shards to verify
        }

        Ok(self.encoder.verify(&shard_refs).is_ok())
    }

    /// Calculate storage efficiency (original size / total encoded size).
    pub fn storage_efficiency(&self, original_size: usize) -> f64 {
        let shard_size = original_size.div_ceil(self.config.data_shards);
        let total_size = shard_size * self.config.total_shards();
        original_size as f64 / total_size as f64
    }

    /// Get redundancy factor (total shards / data shards).
    pub fn redundancy_factor(&self) -> f64 {
        self.config.total_shards() as f64 / self.config.data_shards as f64
    }
}

impl Clone for ErasureCoder {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            encoder: Arc::clone(&self.encoder),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_config_new() {
        let config = ErasureConfig::new(10, 4).unwrap();
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 4);
        assert_eq!(config.total_shards(), 14);
        assert_eq!(config.min_shards_for_recovery(), 10);
    }

    #[test]
    fn test_erasure_config_invalid() {
        assert!(ErasureConfig::new(0, 4).is_err());
        assert!(ErasureConfig::new(10, 0).is_err());
        assert!(ErasureConfig::new(200, 100).is_err()); // > 256 total
    }

    #[test]
    fn test_erasure_coder_new() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        assert_eq!(coder.config().data_shards, 4);
        assert_eq!(coder.config().parity_shards, 2);
    }

    #[test]
    fn test_encode_decode_small_data() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Hello, CHIE!";

        let shards = coder.encode(data).unwrap();
        assert_eq!(shards.len(), 6);

        let decoded = coder.decode(&shards).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_encode_decode_large_data() {
        let coder = ErasureCoder::new(10, 4).unwrap();
        let data = vec![42u8; 1024 * 1024]; // 1 MB

        let shards = coder.encode(&data).unwrap();
        assert_eq!(shards.len(), 14);

        let decoded = coder.decode(&shards).unwrap();
        assert_eq!(&decoded[..data.len()], data.as_slice());
    }

    #[test]
    fn test_reconstruction_with_missing_shards() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Test data for reconstruction";

        let mut shards = coder.encode(data).unwrap();
        assert_eq!(shards.len(), 6);

        // Lose 2 shards (within tolerance)
        shards[1] = None;
        shards[4] = None;

        let decoded = coder.decode(&shards).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_reconstruction_fails_with_too_many_missing() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Test data";

        let mut shards = coder.encode(data).unwrap();

        // Lose 3 shards (too many - need at least 4)
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;

        assert!(coder.decode(&shards).is_err());
    }

    #[test]
    fn test_stats_tracking() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Test data for stats";

        // Encode
        let shards = coder.encode(data).unwrap();
        let stats = coder.stats();
        assert_eq!(stats.encode_count, 1);
        assert_eq!(stats.bytes_encoded, data.len() as u64);

        // Decode
        let _ = coder.decode(&shards).unwrap();
        let stats = coder.stats();
        assert_eq!(stats.decode_count, 1);
        assert_eq!(stats.successful_reconstructions, 1);
        assert_eq!(stats.failed_reconstructions, 0);
    }

    #[test]
    fn test_storage_efficiency() {
        let coder = ErasureCoder::new(10, 4).unwrap(); // 14 total shards
        let efficiency = coder.storage_efficiency(1000);
        // Efficiency should be around 10/14 = 0.714
        assert!(efficiency > 0.7 && efficiency < 0.72);
    }

    #[test]
    fn test_redundancy_factor() {
        let coder = ErasureCoder::new(10, 4).unwrap();
        assert_eq!(coder.redundancy_factor(), 1.4); // 14/10
    }

    #[test]
    fn test_throughput_calculation() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = vec![42u8; 1024 * 100]; // 100 KB

        let shards = coder.encode(&data).unwrap();
        let _ = coder.decode(&shards).unwrap();

        let stats = coder.stats();
        // Just check that throughput is positive
        assert!(stats.avg_encode_throughput_mbps() > 0.0);
        assert!(stats.avg_decode_throughput_mbps() > 0.0);
    }

    #[test]
    fn test_reconstruction_success_rate() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Test";

        // Successful reconstruction
        let shards = coder.encode(data).unwrap();
        let _ = coder.decode(&shards).unwrap();

        // Failed reconstruction (too many missing)
        let mut bad_shards = shards.clone();
        bad_shards[0] = None;
        bad_shards[1] = None;
        bad_shards[2] = None;
        let _ = coder.decode(&bad_shards);

        let stats = coder.stats();
        assert_eq!(stats.reconstruction_success_rate(), 0.5); // 1 success, 1 failure
    }

    #[test]
    fn test_verify_shard() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"Verify this";

        let shards = coder.encode(data).unwrap();
        assert!(coder.verify_shard(&shards, 0).unwrap());
    }

    #[test]
    fn test_clone() {
        let coder1 = ErasureCoder::new(4, 2).unwrap();
        let data = b"Test";
        let _ = coder1.encode(data).unwrap();

        let coder2 = coder1.clone();
        // Stats should be shared
        assert_eq!(coder1.stats().encode_count, coder2.stats().encode_count);
    }

    #[test]
    fn test_config_with_shard_size() {
        let config = ErasureConfig::new(4, 2).unwrap().with_shard_size(1024);
        assert_eq!(config.shard_size, 1024);
    }

    #[test]
    fn test_empty_data() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"";

        // Empty data should fail encoding (Reed-Solomon requires non-zero data)
        assert!(coder.encode(data).is_err());
    }

    #[test]
    fn test_single_byte_data() {
        let coder = ErasureCoder::new(4, 2).unwrap();
        let data = b"X";

        let shards = coder.encode(data).unwrap();
        let decoded = coder.decode(&shards).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }
}
