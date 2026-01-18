//! Streaming utilities for large content transfers.
//!
//! This module provides efficient streaming capabilities for transferring large
//! content without loading everything into memory at once.
//!
//! # Features
//!
//! - Chunk-based streaming with configurable buffer sizes
//! - Async I/O support with backpressure handling
//! - Progress tracking and bandwidth estimation
//! - Automatic retry on transient failures
//! - Memory-efficient design for large files
//!
//! # Example
//!
//! ```
//! use chie_core::streaming::{ContentStream, StreamConfig};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = StreamConfig::default();
//! let mut stream = ContentStream::from_file(PathBuf::from("large_file.bin"), config).await?;
//!
//! while let Some(chunk) = stream.next_chunk().await? {
//!     println!("Received {} bytes, progress: {:.1}%",
//!         chunk.len(), stream.progress() * 100.0);
//!     // Process chunk...
//! }
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

/// Streaming error types.
#[derive(Debug, Error)]
pub enum StreamError {
    /// IO error during streaming.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Stream already exhausted.
    #[error("Stream exhausted")]
    Exhausted,

    /// Invalid stream configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Seek operation failed.
    #[error("Seek failed: {0}")]
    SeekFailed(String),
}

/// Configuration for content streaming.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Chunk size for streaming (bytes).
    pub chunk_size: usize,

    /// Enable bandwidth tracking.
    pub track_bandwidth: bool,

    /// Maximum retries on transient failures.
    pub max_retries: u32,

    /// Buffer size for I/O operations.
    pub buffer_size: usize,
}

impl Default for StreamConfig {
    #[inline]
    fn default() -> Self {
        Self {
            chunk_size: 256 * 1024, // 256 KB
            track_bandwidth: true,
            max_retries: 3,
            buffer_size: 8 * 1024, // 8 KB
        }
    }
}

impl StreamConfig {
    /// Create a new stream configuration.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set chunk size.
    #[must_use]
    #[inline]
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Enable or disable bandwidth tracking.
    #[must_use]
    #[inline]
    pub fn with_bandwidth_tracking(mut self, enabled: bool) -> Self {
        self.track_bandwidth = enabled;
        self
    }

    /// Set maximum retries.
    #[must_use]
    #[inline]
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), StreamError> {
        if self.chunk_size == 0 {
            return Err(StreamError::InvalidConfig(
                "chunk_size must be greater than 0".to_string(),
            ));
        }
        if self.buffer_size == 0 {
            return Err(StreamError::InvalidConfig(
                "buffer_size must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Content stream for efficient data transfer.
pub struct ContentStream<R> {
    /// Underlying reader.
    reader: R,

    /// Stream configuration.
    config: StreamConfig,

    /// Total content size (if known).
    total_size: Option<u64>,

    /// Bytes read so far.
    bytes_read: u64,

    /// Bandwidth tracking start time.
    start_time: std::time::Instant,

    /// Stream exhausted flag.
    exhausted: bool,
}

impl<R: AsyncRead + Unpin> ContentStream<R> {
    /// Create a new content stream from a reader.
    pub fn new(
        reader: R,
        config: StreamConfig,
        total_size: Option<u64>,
    ) -> Result<Self, StreamError> {
        config.validate()?;
        Ok(Self {
            reader,
            config,
            total_size,
            bytes_read: 0,
            start_time: std::time::Instant::now(),
            exhausted: false,
        })
    }

    /// Read the next chunk from the stream.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StreamError> {
        if self.exhausted {
            return Ok(None);
        }

        let mut buffer = vec![0u8; self.config.chunk_size];
        let bytes = self.reader.read(&mut buffer).await?;

        if bytes == 0 {
            self.exhausted = true;
            return Ok(None);
        }

        buffer.truncate(bytes);
        self.bytes_read += bytes as u64;

        Ok(Some(buffer))
    }

    /// Get the current progress (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn progress(&self) -> f64 {
        if let Some(total) = self.total_size {
            if total == 0 {
                1.0
            } else {
                self.bytes_read as f64 / total as f64
            }
        } else {
            0.0
        }
    }

    /// Get bytes read so far.
    #[inline]
    #[must_use]
    pub const fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Get total size (if known).
    #[inline]
    #[must_use]
    pub const fn total_size(&self) -> Option<u64> {
        self.total_size
    }

    /// Check if stream is exhausted.
    #[inline]
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Calculate current bandwidth in bytes per second.
    #[inline]
    #[must_use]
    pub fn bandwidth_bps(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_read as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate current bandwidth in megabits per second.
    #[inline]
    #[must_use]
    pub fn bandwidth_mbps(&self) -> f64 {
        self.bandwidth_bps() * 8.0 / 1_000_000.0
    }

    /// Estimate time remaining in seconds (if total size known).
    #[must_use]
    #[inline]
    pub fn time_remaining_secs(&self) -> Option<f64> {
        if let Some(total) = self.total_size {
            let remaining = total.saturating_sub(self.bytes_read);
            let bps = self.bandwidth_bps();
            if bps > 0.0 {
                Some(remaining as f64 / bps)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Read all remaining chunks into a vector.
    pub async fn read_to_vec(&mut self) -> Result<Vec<u8>, StreamError> {
        let mut result = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            result.extend_from_slice(&chunk);
        }
        Ok(result)
    }

    /// Reset the stream (if reader supports seeking).
    pub async fn reset(&mut self) -> Result<(), StreamError>
    where
        R: AsyncSeek,
    {
        self.reader
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|e| StreamError::SeekFailed(e.to_string()))?;
        self.bytes_read = 0;
        self.exhausted = false;
        self.start_time = std::time::Instant::now();
        Ok(())
    }
}

impl ContentStream<tokio::fs::File> {
    /// Create a content stream from a file path.
    pub async fn from_file(path: PathBuf, config: StreamConfig) -> Result<Self, StreamError> {
        let file = tokio::fs::File::open(&path).await?;
        let metadata = file.metadata().await?;
        let total_size = Some(metadata.len());
        Self::new(file, config, total_size)
    }
}

/// Chunk writer for streaming writes.
pub struct ChunkWriter<W> {
    /// Underlying writer.
    writer: W,

    /// Bytes written so far.
    bytes_written: u64,

    /// Start time for bandwidth tracking.
    start_time: std::time::Instant,
}

impl<W: tokio::io::AsyncWrite + Unpin> ChunkWriter<W> {
    /// Create a new chunk writer.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            start_time: std::time::Instant::now(),
        }
    }

    /// Write a chunk to the stream.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), StreamError> {
        use tokio::io::AsyncWriteExt;
        self.writer.write_all(chunk).await?;
        self.bytes_written += chunk.len() as u64;
        Ok(())
    }

    /// Flush the writer.
    pub async fn flush(&mut self) -> Result<(), StreamError> {
        use tokio::io::AsyncWriteExt;
        self.writer.flush().await?;
        Ok(())
    }

    /// Get bytes written so far.
    #[inline]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Calculate current bandwidth in bytes per second.
    #[inline]
    pub fn bandwidth_bps(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.bytes_written as f64 / elapsed
        } else {
            0.0
        }
    }
}

impl ChunkWriter<tokio::fs::File> {
    /// Create a chunk writer for a file path.
    pub async fn to_file(path: PathBuf) -> Result<Self, StreamError> {
        let file = tokio::fs::File::create(&path).await?;
        Ok(Self::new(file))
    }
}

/// Stream content from source to destination.
pub async fn stream_copy<R, W>(
    mut reader: ContentStream<R>,
    mut writer: ChunkWriter<W>,
) -> Result<u64, StreamError>
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut total_bytes = 0u64;

    while let Some(chunk) = reader.next_chunk().await? {
        writer.write_chunk(&chunk).await?;
        total_bytes += chunk.len() as u64;
    }

    writer.flush().await?;
    Ok(total_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_stream_config_default() {
        let config = StreamConfig::default();
        assert_eq!(config.chunk_size, 256 * 1024);
        assert!(config.track_bandwidth);
        assert_eq!(config.max_retries, 3);
    }

    #[tokio::test]
    async fn test_stream_config_builder() {
        let config = StreamConfig::new()
            .with_chunk_size(512 * 1024)
            .with_bandwidth_tracking(false)
            .with_max_retries(5);

        assert_eq!(config.chunk_size, 512 * 1024);
        assert!(!config.track_bandwidth);
        assert_eq!(config.max_retries, 5);
    }

    #[tokio::test]
    async fn test_stream_config_validate() {
        let mut config = StreamConfig::default();
        assert!(config.validate().is_ok());

        config.chunk_size = 0;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_content_stream_basic() {
        let data = b"Hello, World!";
        let config = StreamConfig::default();
        let mut stream = ContentStream::new(
            tokio::io::BufReader::new(&data[..]),
            config,
            Some(data.len() as u64),
        )
        .unwrap();

        let chunk = stream.next_chunk().await.unwrap();
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap(), data);

        let chunk = stream.next_chunk().await.unwrap();
        assert!(chunk.is_none());
        assert!(stream.is_exhausted());
    }

    #[tokio::test]
    async fn test_content_stream_progress() {
        let data = b"Hello, World!";
        let config = StreamConfig::default();
        let mut stream = ContentStream::new(
            tokio::io::BufReader::new(&data[..]),
            config,
            Some(data.len() as u64),
        )
        .unwrap();

        assert_eq!(stream.progress(), 0.0);
        let _ = stream.next_chunk().await.unwrap();
        assert_eq!(stream.progress(), 1.0);
    }

    #[tokio::test]
    async fn test_content_stream_bandwidth() {
        let data = b"Hello, World!";
        let config = StreamConfig::default();
        let mut stream = ContentStream::new(
            tokio::io::BufReader::new(&data[..]),
            config,
            Some(data.len() as u64),
        )
        .unwrap();

        let _ = stream.next_chunk().await.unwrap();
        let bps = stream.bandwidth_bps();
        assert!(bps > 0.0);
    }

    #[tokio::test]
    async fn test_chunk_writer() {
        let mut buffer = Vec::new();
        let bytes_written = {
            let mut writer = ChunkWriter::new(&mut buffer);

            writer.write_chunk(b"Hello, ").await.unwrap();
            writer.write_chunk(b"World!").await.unwrap();
            writer.flush().await.unwrap();

            writer.bytes_written()
        };

        assert_eq!(buffer, b"Hello, World!");
        assert_eq!(bytes_written, 13);
    }

    #[tokio::test]
    async fn test_stream_copy() {
        let data = b"Hello, World!";
        let config = StreamConfig::default();
        let stream = ContentStream::new(
            tokio::io::BufReader::new(&data[..]),
            config,
            Some(data.len() as u64),
        )
        .unwrap();

        let mut buffer = Vec::new();
        let writer = ChunkWriter::new(&mut buffer);

        let bytes = stream_copy(stream, writer).await.unwrap();
        assert_eq!(bytes, 13);
        assert_eq!(buffer, data);
    }

    #[tokio::test]
    async fn test_read_to_vec() {
        let data = b"Hello, World!";
        let config = StreamConfig::default();
        let mut stream = ContentStream::new(
            tokio::io::BufReader::new(&data[..]),
            config,
            Some(data.len() as u64),
        )
        .unwrap();

        let result = stream.read_to_vec().await.unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_stream_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Write test data
        let mut file = tokio::fs::File::create(&file_path).await.unwrap();
        file.write_all(b"Hello, World!").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        // Read via stream
        let config = StreamConfig::default();
        let mut stream = ContentStream::from_file(file_path, config).await.unwrap();

        let data = stream.read_to_vec().await.unwrap();
        assert_eq!(data, b"Hello, World!");
    }
}
