//! Protocol message compression for efficient network communication.
//!
//! This module provides compression for protocol messages to reduce bandwidth
//! usage and improve transfer efficiency.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Compression algorithm for protocol messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageCompressionAlgorithm {
    /// No compression
    None,
    /// LZ4 compression (fast)
    Lz4,
    /// Zstd compression (balanced)
    Zstd,
    /// Snappy compression (very fast)
    Snappy,
}

impl MessageCompressionAlgorithm {
    /// Get compression level recommendation
    pub fn recommended_level(&self) -> i32 {
        match self {
            Self::None => 0,
            Self::Lz4 => 1,
            Self::Zstd => 3,
            Self::Snappy => 0,
        }
    }
}

/// Message type for selective compression
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Chunk data (large, should compress)
    ChunkData,
    /// Chunk request (small, may skip)
    ChunkRequest,
    /// Chunk response metadata (small)
    ChunkResponse,
    /// Bandwidth proof (medium)
    BandwidthProof,
    /// Peer advertisement (small)
    PeerAdvertisement,
    /// DHT query/response (medium)
    DhtMessage,
    /// Gossip message (variable)
    GossipMessage,
    /// Control message (small)
    ControlMessage,
}

impl MessageType {
    /// Get size threshold for compression (bytes)
    pub fn compression_threshold(&self) -> usize {
        match self {
            Self::ChunkData => 512,          // Always compress chunks > 512 bytes
            Self::ChunkRequest => 2048,      // Rarely compress requests
            Self::ChunkResponse => 1024,     // Compress if > 1KB
            Self::BandwidthProof => 1024,    // Compress if > 1KB
            Self::PeerAdvertisement => 2048, // Rarely compress
            Self::DhtMessage => 1024,        // Compress if > 1KB
            Self::GossipMessage => 512,      // Compress gossip > 512 bytes
            Self::ControlMessage => 4096,    // Almost never compress
        }
    }

    /// Should always compress this message type
    pub fn always_compress(&self) -> bool {
        matches!(self, Self::ChunkData)
    }
}

/// Protocol message compression configuration
#[derive(Debug, Clone)]
pub struct ProtocolCompressionConfig {
    /// Default compression algorithm
    pub algorithm: MessageCompressionAlgorithm,
    /// Enable adaptive algorithm selection
    pub adaptive: bool,
    /// Minimum size to consider compression (bytes)
    pub min_size: usize,
    /// Track compression statistics
    pub enable_stats: bool,
}

impl Default for ProtocolCompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: MessageCompressionAlgorithm::Lz4,
            adaptive: true,
            min_size: 256,
            enable_stats: true,
        }
    }
}

/// Compression result
#[derive(Debug, Clone)]
pub struct CompressionResult {
    pub compressed: Vec<u8>,
    pub algorithm: MessageCompressionAlgorithm,
    pub original_size: usize,
    pub compressed_size: usize,
    pub ratio: f64,
}

/// Message compression statistics
#[derive(Debug, Clone, Default)]
struct CompressionStats {
    total_messages: u64,
    compressed_messages: u64,
    total_original_bytes: u64,
    total_compressed_bytes: u64,
    algorithm_usage: HashMap<MessageCompressionAlgorithm, u64>,
}

/// Protocol message compressor
pub struct ProtocolCompressor {
    config: ProtocolCompressionConfig,
    stats: Arc<RwLock<CompressionStats>>,
}

impl ProtocolCompressor {
    /// Create a new protocol compressor
    pub fn new(config: ProtocolCompressionConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(CompressionStats::default())),
        }
    }

    /// Compress a protocol message
    pub fn compress(
        &self,
        data: &[u8],
        message_type: MessageType,
    ) -> Result<CompressionResult, String> {
        let original_size = data.len();

        // Check if should compress
        let threshold = if self.config.adaptive {
            message_type.compression_threshold()
        } else {
            self.config.min_size
        };

        if original_size < threshold && !message_type.always_compress() {
            // Skip compression for small messages
            // Update stats for skipped message
            if self.config.enable_stats {
                if let Ok(mut stats) = self.stats.write() {
                    stats.total_messages += 1;
                    stats.total_original_bytes += original_size as u64;
                    stats.total_compressed_bytes += original_size as u64;
                }
            }

            return Ok(CompressionResult {
                compressed: data.to_vec(),
                algorithm: MessageCompressionAlgorithm::None,
                original_size,
                compressed_size: original_size,
                ratio: 1.0,
            });
        }

        // Select algorithm
        let algorithm = if self.config.adaptive {
            self.select_algorithm(data, message_type)
        } else {
            self.config.algorithm
        };

        // Compress
        let compressed = match algorithm {
            MessageCompressionAlgorithm::None => data.to_vec(),
            MessageCompressionAlgorithm::Lz4 => self.compress_lz4(data)?,
            MessageCompressionAlgorithm::Zstd => self.compress_zstd(data)?,
            MessageCompressionAlgorithm::Snappy => self.compress_snappy(data)?,
        };

        let compressed_size = compressed.len();
        let ratio = original_size as f64 / compressed_size as f64;

        // Update stats
        if self.config.enable_stats {
            if let Ok(mut stats) = self.stats.write() {
                stats.total_messages += 1;
                stats.total_original_bytes += original_size as u64;
                stats.total_compressed_bytes += compressed_size as u64;
                if algorithm != MessageCompressionAlgorithm::None {
                    stats.compressed_messages += 1;
                    *stats.algorithm_usage.entry(algorithm).or_insert(0) += 1;
                }
            }
        }

        Ok(CompressionResult {
            compressed,
            algorithm,
            original_size,
            compressed_size,
            ratio,
        })
    }

    /// Decompress a protocol message
    pub fn decompress(
        &self,
        data: &[u8],
        algorithm: MessageCompressionAlgorithm,
    ) -> Result<Vec<u8>, String> {
        match algorithm {
            MessageCompressionAlgorithm::None => Ok(data.to_vec()),
            MessageCompressionAlgorithm::Lz4 => self.decompress_lz4(data),
            MessageCompressionAlgorithm::Zstd => self.decompress_zstd(data),
            MessageCompressionAlgorithm::Snappy => self.decompress_snappy(data),
        }
    }

    /// Select best compression algorithm for data
    fn select_algorithm(
        &self,
        data: &[u8],
        message_type: MessageType,
    ) -> MessageCompressionAlgorithm {
        match message_type {
            MessageType::ChunkData => {
                // For large chunk data, use Zstd for best compression
                if data.len() > 65536 {
                    MessageCompressionAlgorithm::Zstd
                } else {
                    MessageCompressionAlgorithm::Lz4
                }
            }
            MessageType::GossipMessage | MessageType::DhtMessage => {
                // For network messages, prioritize speed
                MessageCompressionAlgorithm::Lz4
            }
            _ => self.config.algorithm,
        }
    }

    /// Compress with LZ4 (oxiarc-lz4 frame format)
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        oxiarc_lz4::compress(data).map_err(|e| format!("LZ4 compression failed: {e}"))
    }

    /// Decompress with LZ4 (oxiarc-lz4 frame format)
    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let max_output = data.len().saturating_mul(255).min(256 * 1024 * 1024);
        oxiarc_lz4::decompress(data, max_output)
            .map_err(|e| format!("LZ4 decompression failed: {e}"))
    }

    /// Compress with Zstd (oxiarc-zstd)
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        oxiarc_zstd::compress_with_level(data, 3)
            .map_err(|e| format!("Zstd compression failed: {e}"))
    }

    /// Decompress with Zstd (oxiarc-zstd)
    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        oxiarc_zstd::decompress(data).map_err(|e| format!("Zstd decompression failed: {e}"))
    }

    /// Compress with Snappy (oxiarc-snappy block format)
    fn compress_snappy(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(oxiarc_snappy::compress(data))
    }

    /// Decompress with Snappy (oxiarc-snappy block format)
    fn decompress_snappy(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        oxiarc_snappy::decompress(data).map_err(|e| format!("Snappy decompression failed: {e}"))
    }

    /// Get compression statistics
    pub fn get_stats(&self) -> ProtocolCompressionStats {
        // Use a default snapshot if the lock is poisoned
        let snapshot = self.stats.read().map(|s| s.clone()).unwrap_or_default();

        let compression_ratio = if snapshot.total_original_bytes > 0 {
            snapshot.total_original_bytes as f64 / snapshot.total_compressed_bytes as f64
        } else {
            1.0
        };

        let compression_rate = if snapshot.total_messages > 0 {
            snapshot.compressed_messages as f64 / snapshot.total_messages as f64
        } else {
            0.0
        };

        ProtocolCompressionStats {
            total_messages: snapshot.total_messages,
            compressed_messages: snapshot.compressed_messages,
            total_original_bytes: snapshot.total_original_bytes,
            total_compressed_bytes: snapshot.total_compressed_bytes,
            compression_ratio,
            compression_rate,
            algorithm_usage: snapshot.algorithm_usage,
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        if let Ok(mut stats) = self.stats.write() {
            *stats = CompressionStats::default();
        }
    }
}

/// Protocol compression statistics
#[derive(Debug, Clone)]
pub struct ProtocolCompressionStats {
    pub total_messages: u64,
    pub compressed_messages: u64,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
    pub compression_ratio: f64,
    pub compression_rate: f64,
    pub algorithm_usage: HashMap<MessageCompressionAlgorithm, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_algorithm_recommended_level() {
        assert_eq!(MessageCompressionAlgorithm::None.recommended_level(), 0);
        assert_eq!(MessageCompressionAlgorithm::Lz4.recommended_level(), 1);
        assert_eq!(MessageCompressionAlgorithm::Zstd.recommended_level(), 3);
    }

    #[test]
    fn test_message_type_thresholds() {
        assert_eq!(MessageType::ChunkData.compression_threshold(), 512);
        assert_eq!(MessageType::ChunkRequest.compression_threshold(), 2048);
        assert!(MessageType::ChunkData.always_compress());
        assert!(!MessageType::ChunkRequest.always_compress());
    }

    #[test]
    fn test_compressor_new() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);
        let stats = compressor.get_stats();
        assert_eq!(stats.total_messages, 0);
    }

    #[test]
    fn test_compress_small_message_skipped() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Lz4,
            adaptive: true,
            min_size: 256,
            enable_stats: true,
        };
        let compressor = ProtocolCompressor::new(config);

        let data = b"Small message";
        let result = compressor
            .compress(data, MessageType::ControlMessage)
            .unwrap();

        assert_eq!(result.algorithm, MessageCompressionAlgorithm::None);
        assert_eq!(result.compressed, data);
    }

    #[test]
    fn test_compress_large_message_lz4() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'A'; 1024];
        let result = compressor.compress(&data, MessageType::ChunkData).unwrap();

        assert_ne!(result.algorithm, MessageCompressionAlgorithm::None);
        assert!(result.compressed_size < result.original_size);
        assert!(result.ratio > 1.0);
    }

    #[test]
    fn test_compress_decompress_lz4() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Lz4,
            adaptive: false,
            min_size: 10,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        let original = b"Hello, World! This is a test message for LZ4 compression.";
        let result = compressor
            .compress(original, MessageType::ChunkData)
            .unwrap();
        let decompressed = compressor
            .decompress(&result.compressed, result.algorithm)
            .unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_decompress_zstd() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Zstd,
            adaptive: false,
            min_size: 10,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        let original = b"Hello, World! This is a test message for Zstd compression.";
        let result = compressor
            .compress(original, MessageType::ChunkData)
            .unwrap();
        let decompressed = compressor
            .decompress(&result.compressed, result.algorithm)
            .unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_decompress_snappy() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Snappy,
            adaptive: false,
            min_size: 10,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        let original = b"Hello, World! This is a test message for Snappy compression.";
        let result = compressor
            .compress(original, MessageType::ChunkData)
            .unwrap();
        let decompressed = compressor
            .decompress(&result.compressed, result.algorithm)
            .unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_adaptive_algorithm_selection() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Lz4,
            adaptive: true,
            min_size: 10,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        // Large chunk should use Zstd
        let large_data = vec![b'X'; 100000];
        let result = compressor
            .compress(&large_data, MessageType::ChunkData)
            .unwrap();
        assert_eq!(result.algorithm, MessageCompressionAlgorithm::Zstd);

        // Small chunk should use LZ4
        let small_data = vec![b'Y'; 1000];
        let result = compressor
            .compress(&small_data, MessageType::ChunkData)
            .unwrap();
        assert_eq!(result.algorithm, MessageCompressionAlgorithm::Lz4);
    }

    #[test]
    fn test_stats_tracking() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'A'; 1024];
        compressor.compress(&data, MessageType::ChunkData).unwrap();
        compressor.compress(&data, MessageType::ChunkData).unwrap();

        let stats = compressor.get_stats();
        assert_eq!(stats.total_messages, 2);
        assert_eq!(stats.compressed_messages, 2);
        assert!(stats.total_original_bytes > 0);
        assert!(stats.total_compressed_bytes > 0);
        assert!(stats.compression_ratio > 1.0);
    }

    #[test]
    fn test_reset_stats() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'A'; 1024];
        compressor.compress(&data, MessageType::ChunkData).unwrap();

        compressor.reset_stats();
        let stats = compressor.get_stats();
        assert_eq!(stats.total_messages, 0);
    }

    #[test]
    fn test_compression_ratio_calculation() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        // Highly compressible data
        let data = vec![b'A'; 10000];
        let result = compressor.compress(&data, MessageType::ChunkData).unwrap();

        assert!(result.ratio > 5.0); // Should compress well
    }

    #[test]
    fn test_message_type_selective_compression() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::Lz4,
            adaptive: true,
            min_size: 256,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        // Small control message should skip compression
        let small = vec![b'X'; 512];
        let result = compressor
            .compress(&small, MessageType::ControlMessage)
            .unwrap();
        assert_eq!(result.algorithm, MessageCompressionAlgorithm::None);

        // Same size chunk data should compress (always_compress)
        let result = compressor.compress(&small, MessageType::ChunkData).unwrap();
        assert_ne!(result.algorithm, MessageCompressionAlgorithm::None);
    }

    #[test]
    fn test_algorithm_usage_stats() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'A'; 1024];
        compressor
            .compress(&data, MessageType::GossipMessage)
            .unwrap();
        compressor
            .compress(&data, MessageType::GossipMessage)
            .unwrap();

        let stats = compressor.get_stats();
        let lz4_usage = stats
            .algorithm_usage
            .get(&MessageCompressionAlgorithm::Lz4)
            .copied()
            .unwrap_or(0);
        assert_eq!(lz4_usage, 2);
    }

    #[test]
    fn test_config_default() {
        let config = ProtocolCompressionConfig::default();
        assert_eq!(config.algorithm, MessageCompressionAlgorithm::Lz4);
        assert!(config.adaptive);
        assert_eq!(config.min_size, 256);
    }

    #[test]
    fn test_compression_result_fields() {
        let config = ProtocolCompressionConfig::default();
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'B'; 2048];
        let result = compressor.compress(&data, MessageType::ChunkData).unwrap();

        assert_eq!(result.original_size, 2048);
        assert!(result.compressed_size < 2048);
        assert_eq!(result.ratio, 2048.0 / result.compressed_size as f64);
    }

    #[test]
    fn test_no_compression_passthrough() {
        let config = ProtocolCompressionConfig {
            algorithm: MessageCompressionAlgorithm::None,
            adaptive: false,
            min_size: 0,
            enable_stats: false,
        };
        let compressor = ProtocolCompressor::new(config);

        let data = vec![b'C'; 1024];
        let result = compressor.compress(&data, MessageType::ChunkData).unwrap();

        assert_eq!(result.algorithm, MessageCompressionAlgorithm::None);
        assert_eq!(result.compressed, data);
        assert_eq!(result.ratio, 1.0);
    }

    #[test]
    fn test_compression_rate_calculation() {
        let config = ProtocolCompressionConfig {
            adaptive: true,
            min_size: 256,
            ..Default::default()
        };
        let compressor = ProtocolCompressor::new(config);

        let large_data = vec![b'D'; 1024];
        let small_data = vec![b'S'; 100]; // Below ChunkRequest threshold of 2048, and small enough

        compressor
            .compress(&large_data, MessageType::ChunkData)
            .unwrap(); // Should compress (always_compress)
        compressor
            .compress(&small_data, MessageType::ChunkRequest)
            .unwrap(); // Should skip (below threshold)

        let stats = compressor.get_stats();
        assert!(stats.compression_rate > 0.0 && stats.compression_rate <= 1.0);
        assert_eq!(stats.compression_rate, 0.5); // 1 out of 2 compressed
    }
}
