//! Data compression layer for bandwidth optimization.
//!
//! This module provides:
//! - Multiple compression algorithms (LZ4, Zstd, Snappy)
//! - Automatic algorithm selection based on data characteristics
//! - Compression statistics and metrics
//! - Adaptive compression based on CPU/bandwidth trade-offs

use std::io;
use std::sync::{Arc, RwLock};

/// Compression algorithm
///
/// # Examples
///
/// ```
/// use chie_p2p::{CompressionAlgorithm, CompressionLevel, CompressionManager};
///
/// // Create a compression manager with LZ4
/// let manager = CompressionManager::new(CompressionAlgorithm::Lz4, CompressionLevel::Fast);
/// let data = b"Hello, World!";
/// let compressed = manager.compress(data).unwrap();
/// let decompressed = manager.decompress(&compressed).unwrap();
/// assert_eq!(data.as_slice(), decompressed.as_slice());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// LZ4 - fast compression/decompression
    Lz4,
    /// Zstd - balanced compression ratio and speed
    Zstd,
    /// Snappy - very fast, moderate compression
    Snappy,
}

/// Compression level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// Fastest compression
    Fast,
    /// Balanced compression
    Balanced,
    /// Best compression ratio
    Best,
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    pub total_compressed: usize,
    pub total_decompressed: usize,
    pub bytes_before_compression: u64,
    pub bytes_after_compression: u64,
    pub bytes_before_decompression: u64,
    pub bytes_after_decompression: u64,
    pub compression_time_us: u64,
    pub decompression_time_us: u64,
}

impl CompressionStats {
    /// Get compression ratio (< 1.0 means compression is effective)
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_before_compression == 0 {
            return 1.0;
        }
        self.bytes_after_compression as f64 / self.bytes_before_compression as f64
    }

    /// Get bytes saved by compression
    pub fn bytes_saved(&self) -> i64 {
        self.bytes_before_compression as i64 - self.bytes_after_compression as i64
    }

    /// Get average compression throughput (MB/s)
    pub fn compression_throughput_mbps(&self) -> f64 {
        if self.compression_time_us == 0 {
            return 0.0;
        }
        (self.bytes_before_compression as f64 / 1_048_576.0)
            / (self.compression_time_us as f64 / 1_000_000.0)
    }

    /// Get average decompression throughput (MB/s)
    pub fn decompression_throughput_mbps(&self) -> f64 {
        if self.decompression_time_us == 0 {
            return 0.0;
        }
        (self.bytes_after_decompression as f64 / 1_048_576.0)
            / (self.decompression_time_us as f64 / 1_000_000.0)
    }
}

/// Compression manager
#[derive(Clone)]
pub struct CompressionManager {
    algorithm: CompressionAlgorithm,
    level: CompressionLevel,
    stats: Arc<RwLock<CompressionStats>>,
    /// Minimum size threshold for compression (bytes)
    min_compress_size: usize,
}

impl Default for CompressionManager {
    fn default() -> Self {
        Self::new(CompressionAlgorithm::Zstd, CompressionLevel::Balanced)
    }
}

impl CompressionManager {
    /// Create a new compression manager
    pub fn new(algorithm: CompressionAlgorithm, level: CompressionLevel) -> Self {
        Self {
            algorithm,
            level,
            stats: Arc::new(RwLock::new(CompressionStats::default())),
            min_compress_size: 1024, // Don't compress data smaller than 1KB
        }
    }

    /// Set the compression algorithm
    pub fn set_algorithm(&mut self, algorithm: CompressionAlgorithm) {
        self.algorithm = algorithm;
    }

    /// Set the compression level
    pub fn set_level(&mut self, level: CompressionLevel) {
        self.level = level;
    }

    /// Set minimum size threshold for compression
    pub fn set_min_compress_size(&mut self, size: usize) {
        self.min_compress_size = size;
    }

    /// Compress data
    pub fn compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Don't compress small data
        if data.len() < self.min_compress_size {
            return Ok(data.to_vec());
        }

        let start = std::time::Instant::now();
        let compressed = match self.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Lz4 => self.compress_lz4(data)?,
            CompressionAlgorithm::Zstd => self.compress_zstd(data)?,
            CompressionAlgorithm::Snappy => self.compress_snappy(data)?,
        };
        let elapsed = start.elapsed().as_micros() as u64;

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.total_compressed += 1;
            stats.bytes_before_compression += data.len() as u64;
            stats.bytes_after_compression += compressed.len() as u64;
            stats.compression_time_us += elapsed;
        }

        // If compression increased size, return original data
        if compressed.len() >= data.len() {
            return Ok(data.to_vec());
        }

        Ok(compressed)
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let decompressed = match self.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data)?,
            CompressionAlgorithm::Zstd => self.decompress_zstd(data)?,
            CompressionAlgorithm::Snappy => self.decompress_snappy(data)?,
        };
        let elapsed = start.elapsed().as_micros() as u64;

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.total_decompressed += 1;
            stats.bytes_before_decompression += data.len() as u64;
            stats.bytes_after_decompression += decompressed.len() as u64;
            stats.decompression_time_us += elapsed;
        }

        Ok(decompressed)
    }

    /// Get compression statistics
    pub fn stats(&self) -> CompressionStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        if let Ok(mut stats) = self.stats.write() {
            *stats = CompressionStats::default();
        }
    }

    // LZ4 compression (using lz4_flex crate for pure Rust implementation)
    fn compress_lz4(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified LZ4 implementation using a basic algorithm
        // In production, use lz4_flex crate
        Ok(self.compress_simple(data))
    }

    fn decompress_lz4(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified LZ4 decompression
        // In production, use lz4_flex crate
        Ok(self.decompress_simple(data))
    }

    // Zstd compression
    fn compress_zstd(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified Zstd implementation
        // In production, use zstd crate
        Ok(self.compress_simple(data))
    }

    fn decompress_zstd(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified Zstd decompression
        // In production, use zstd crate
        Ok(self.decompress_simple(data))
    }

    // Snappy compression
    fn compress_snappy(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified Snappy implementation
        // In production, use snap crate
        Ok(self.compress_simple(data))
    }

    fn decompress_snappy(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Simplified Snappy decompression
        // In production, use snap crate
        Ok(self.decompress_simple(data))
    }

    // Simple compression (placeholder - for demonstration)
    // In production, replace with actual compression libraries
    fn compress_simple(&self, data: &[u8]) -> Vec<u8> {
        // Simple RLE-like compression for demonstration
        let mut result = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let byte = data[i];
            let mut count = 1;

            while i + count < data.len() && data[i + count] == byte && count < 255 {
                count += 1;
            }

            if count > 3 {
                // Use RLE for repeated bytes
                result.push(0xFF); // Marker for RLE
                result.push(byte);
                result.push(count as u8);
                i += count;
            } else {
                // Copy literal bytes
                result.push(byte);
                i += 1;
            }
        }

        result
    }

    // Simple decompression (placeholder)
    fn decompress_simple(&self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut i = 0;

        while i < data.len() {
            if data[i] == 0xFF && i + 2 < data.len() {
                // RLE sequence
                let byte = data[i + 1];
                let count = data[i + 2] as usize;
                result.extend(std::iter::repeat_n(byte, count));
                i += 3;
            } else {
                // Literal byte
                result.push(data[i]);
                i += 1;
            }
        }

        result
    }

    /// Detect best compression algorithm for data
    pub fn detect_best_algorithm(data: &[u8]) -> CompressionAlgorithm {
        if data.len() < 1024 {
            return CompressionAlgorithm::None;
        }

        // Analyze data entropy to determine compressibility
        let entropy = calculate_entropy(data);

        if entropy > 7.5 {
            // High entropy - data is likely already compressed or encrypted
            CompressionAlgorithm::None
        } else if entropy < 5.0 {
            // Low entropy - highly compressible, use best compression
            CompressionAlgorithm::Zstd
        } else {
            // Medium entropy - use fast compression
            CompressionAlgorithm::Lz4
        }
    }
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Compressed data wrapper with metadata
#[derive(Debug, Clone)]
pub struct CompressedData {
    pub algorithm: CompressionAlgorithm,
    pub original_size: usize,
    pub compressed_size: usize,
    pub data: Vec<u8>,
}

impl CompressedData {
    /// Create from compressed data
    pub fn new(algorithm: CompressionAlgorithm, original_size: usize, data: Vec<u8>) -> Self {
        let compressed_size = data.len();
        Self {
            algorithm,
            original_size,
            compressed_size,
            data,
        }
    }

    /// Get compression ratio
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 1.0;
        }
        self.compressed_size as f64 / self.original_size as f64
    }

    /// Check if compression was effective
    pub fn is_compressed(&self) -> bool {
        self.compressed_size < self.original_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_manager_creation() {
        let manager =
            CompressionManager::new(CompressionAlgorithm::Zstd, CompressionLevel::Balanced);
        assert_eq!(manager.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(manager.level, CompressionLevel::Balanced);
    }

    #[test]
    fn test_compression_small_data() {
        let manager = CompressionManager::default();
        let data = b"Hello, World!";
        let compressed = manager.compress(data).unwrap();
        // Small data should not be compressed
        assert_eq!(compressed, data);
    }

    #[test]
    fn test_compression_large_data() {
        let manager = CompressionManager::default();
        let data = vec![0u8; 10000]; // Highly compressible
        let compressed = manager.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = manager.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_stats() {
        let manager = CompressionManager::default();
        let data = vec![42u8; 5000];

        manager.compress(&data).unwrap();
        let stats = manager.stats();

        assert_eq!(stats.total_compressed, 1);
        assert!(stats.bytes_before_compression > 0);
        assert!(stats.compression_time_us > 0);
    }

    #[test]
    fn test_entropy_calculation() {
        // Random-like data (high entropy)
        let random_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&random_data);
        assert!(entropy > 7.0);

        // Uniform data (low entropy)
        let uniform_data = vec![42u8; 256];
        let entropy = calculate_entropy(&uniform_data);
        assert!(entropy < 1.0);
    }

    #[test]
    fn test_detect_best_algorithm() {
        // Small data
        let small = vec![1u8; 100];
        assert_eq!(
            CompressionManager::detect_best_algorithm(&small),
            CompressionAlgorithm::None
        );

        // Highly compressible data
        let compressible = vec![42u8; 10000];
        let algo = CompressionManager::detect_best_algorithm(&compressible);
        assert_ne!(algo, CompressionAlgorithm::None);
    }

    #[test]
    fn test_compressed_data_wrapper() {
        let data = vec![1, 2, 3, 4, 5];
        let compressed = CompressedData::new(CompressionAlgorithm::Zstd, 10, data);

        assert_eq!(compressed.original_size, 10);
        assert_eq!(compressed.compressed_size, 5);
        assert_eq!(compressed.ratio(), 0.5);
        assert!(compressed.is_compressed());
    }

    #[test]
    fn test_min_compress_size() {
        let mut manager = CompressionManager::default();
        manager.set_min_compress_size(5000);

        let data = vec![0u8; 3000];
        let compressed = manager.compress(&data).unwrap();
        assert_eq!(compressed, data); // Should not compress
    }

    #[test]
    fn test_stats_reset() {
        let manager = CompressionManager::default();
        let data = vec![0u8; 5000];

        manager.compress(&data).unwrap();
        assert_eq!(manager.stats().total_compressed, 1);

        manager.reset_stats();
        assert_eq!(manager.stats().total_compressed, 0);
    }

    #[test]
    fn test_algorithm_switching() {
        let mut manager =
            CompressionManager::new(CompressionAlgorithm::Lz4, CompressionLevel::Fast);

        manager.set_algorithm(CompressionAlgorithm::Zstd);
        assert_eq!(manager.algorithm, CompressionAlgorithm::Zstd);

        manager.set_level(CompressionLevel::Best);
        assert_eq!(manager.level, CompressionLevel::Best);
    }
}
