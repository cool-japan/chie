//! Compact binary encoding with versioning
//!
//! This module provides efficient binary encoding/decoding for protocol messages
//! with version support for backward/forward compatibility.

use crate::{ChieError, ChieResult};
use std::io::{Read, Write};

/// Binary protocol version identifier
pub const BINARY_PROTOCOL_VERSION: u8 = 1;

/// Magic bytes to identify CHIE protocol messages
pub const MAGIC_BYTES: &[u8; 4] = b"CHIE";

/// CRC32 polynomial (IEEE 802.3)
const CRC32_POLYNOMIAL: u32 = 0xEDB8_8320;

/// Calculate CRC32 checksum for data integrity
#[must_use]
pub fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;

    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC32_POLYNOMIAL
            } else {
                crc >> 1
            };
        }
    }

    crc ^ 0xFFFF_FFFF
}

/// Verify CRC32 checksum
#[must_use]
pub fn verify_crc32(data: &[u8], expected_crc: u32) -> bool {
    calculate_crc32(data) == expected_crc
}

/// Compression algorithm trait for pluggable compression
pub trait CompressionAlgorithm: Send + Sync {
    /// Compress data
    ///
    /// # Errors
    ///
    /// Returns error if compression fails
    fn compress(&self, data: &[u8]) -> ChieResult<Vec<u8>>;

    /// Decompress data
    ///
    /// # Errors
    ///
    /// Returns error if decompression fails
    fn decompress(&self, data: &[u8]) -> ChieResult<Vec<u8>>;

    /// Get the compression algorithm identifier (e.g., "none", "gzip", "zstd")
    fn algorithm_id(&self) -> &str;

    /// Check if data should be compressed based on size threshold
    #[must_use]
    fn should_compress(&self, data_len: usize) -> bool {
        // Default: compress if data is larger than 1KB
        data_len > 1024
    }
}

/// No-op compression (passthrough)
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCompression;

impl CompressionAlgorithm for NoCompression {
    fn compress(&self, data: &[u8]) -> ChieResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decompress(&self, data: &[u8]) -> ChieResult<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn algorithm_id(&self) -> &str {
        "none"
    }

    fn should_compress(&self, _data_len: usize) -> bool {
        false
    }
}

/// Compression configuration
#[derive(Debug, Clone, Copy)]
pub struct CompressionConfig {
    /// Minimum size in bytes before compression is applied
    pub min_size: usize,
    /// Enable compression
    pub enabled: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            min_size: 1024, // 1 KB
            enabled: true,
        }
    }
}

impl CompressionConfig {
    /// Create a new compression configuration
    #[must_use]
    pub const fn new(min_size: usize, enabled: bool) -> Self {
        Self { min_size, enabled }
    }

    /// Check if data should be compressed
    #[must_use]
    pub const fn should_compress(&self, data_len: usize) -> bool {
        self.enabled && data_len >= self.min_size
    }

    /// Disable compression
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            min_size: usize::MAX,
            enabled: false,
        }
    }
}

/// Binary encoder with versioning support
pub struct BinaryEncoder<W: Write> {
    writer: W,
    version: u8,
}

impl<W: Write> BinaryEncoder<W> {
    /// Create a new encoder with the current protocol version
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            version: BINARY_PROTOCOL_VERSION,
        }
    }

    /// Create an encoder with a specific protocol version
    pub fn with_version(writer: W, version: u8) -> Self {
        Self { writer, version }
    }

    /// Write the message header (magic bytes + version)
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_header(&mut self) -> ChieResult<()> {
        self.writer
            .write_all(MAGIC_BYTES)
            .map_err(|e| ChieError::serialization(format!("Failed to write magic bytes: {e}")))?;
        self.writer
            .write_all(&[self.version])
            .map_err(|e| ChieError::serialization(format!("Failed to write version: {e}")))?;
        Ok(())
    }

    /// Write a u8 value
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_u8(&mut self, value: u8) -> ChieResult<()> {
        self.writer
            .write_all(&[value])
            .map_err(|e| ChieError::serialization(format!("Failed to write u8: {e}")))
    }

    /// Write a u32 value (little-endian)
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_u32(&mut self, value: u32) -> ChieResult<()> {
        self.writer
            .write_all(&value.to_le_bytes())
            .map_err(|e| ChieError::serialization(format!("Failed to write u32: {e}")))
    }

    /// Write a u64 value (little-endian)
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_u64(&mut self, value: u64) -> ChieResult<()> {
        self.writer
            .write_all(&value.to_le_bytes())
            .map_err(|e| ChieError::serialization(format!("Failed to write u64: {e}")))
    }

    /// Write a variable-length byte array (length prefix + data)
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_bytes(&mut self, bytes: &[u8]) -> ChieResult<()> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| ChieError::serialization("Byte array too large"))?;
        self.write_u32(len)?;
        self.writer
            .write_all(bytes)
            .map_err(|e| ChieError::serialization(format!("Failed to write bytes: {e}")))
    }

    /// Write a string (UTF-8 encoded with length prefix)
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_string(&mut self, s: &str) -> ChieResult<()> {
        self.write_bytes(s.as_bytes())
    }

    /// Write a boolean as a single byte
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_bool(&mut self, value: bool) -> ChieResult<()> {
        self.write_u8(u8::from(value))
    }

    /// Write a CRC32 checksum for the given data
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_checksum(&mut self, data: &[u8]) -> ChieResult<()> {
        let checksum = calculate_crc32(data);
        self.write_u32(checksum)
    }

    /// Get a mutable reference to the underlying writer
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume the encoder and return the underlying writer
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Write large byte array in chunks to avoid excessive memory allocation
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::encoding::BinaryEncoder;
    ///
    /// let data = vec![1u8; 10_000]; // 10KB of data
    /// let mut reader = &data[..];
    /// let mut buf = Vec::new();
    /// let mut encoder = BinaryEncoder::new(&mut buf);
    ///
    /// // Write in 1KB chunks
    /// encoder.write_bytes_chunked(&mut reader, 10_000, 1024).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if writing fails
    pub fn write_bytes_chunked<R: Read>(
        &mut self,
        reader: &mut R,
        total_size: u64,
        chunk_size: usize,
    ) -> ChieResult<()> {
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| ChieError::serialization("Total size too large for u32"))?;
        self.write_u32(total_size_u32)?;

        let mut buffer = vec![0u8; chunk_size];
        let mut remaining = total_size;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, chunk_size as u64) as usize;
            reader
                .read_exact(&mut buffer[..to_read])
                .map_err(|e| ChieError::serialization(format!("Failed to read chunk: {e}")))?;

            self.writer
                .write_all(&buffer[..to_read])
                .map_err(|e| ChieError::serialization(format!("Failed to write chunk: {e}")))?;

            remaining -= to_read as u64;
        }

        Ok(())
    }

    /// Stream data directly from a reader without buffering entire payload
    ///
    /// # Errors
    ///
    /// Returns error if copying fails
    pub fn copy_from_reader<R: Read>(&mut self, reader: &mut R) -> ChieResult<u64> {
        std::io::copy(reader, &mut self.writer)
            .map_err(|e| ChieError::serialization(format!("Failed to copy from reader: {e}")))
    }
}

/// Binary decoder with versioning support
pub struct BinaryDecoder<R: Read> {
    reader: R,
    version: u8,
}

impl<R: Read> BinaryDecoder<R> {
    /// Create a new decoder
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            version: BINARY_PROTOCOL_VERSION,
        }
    }

    /// Read and verify the message header (magic bytes + version)
    ///
    /// # Errors
    ///
    /// Returns error if header is invalid or unsupported
    pub fn read_header(&mut self) -> ChieResult<u8> {
        let mut magic = [0u8; 4];
        self.reader
            .read_exact(&mut magic)
            .map_err(|e| ChieError::serialization(format!("Failed to read magic bytes: {e}")))?;

        if &magic != MAGIC_BYTES {
            return Err(ChieError::serialization(format!(
                "Invalid magic bytes: expected {MAGIC_BYTES:?}, got {magic:?}"
            )));
        }

        let mut version_buf = [0u8; 1];
        self.reader
            .read_exact(&mut version_buf)
            .map_err(|e| ChieError::serialization(format!("Failed to read version: {e}")))?;

        self.version = version_buf[0];

        // Validate version compatibility
        if self.version > BINARY_PROTOCOL_VERSION {
            return Err(ChieError::serialization(format!(
                "Unsupported protocol version: {}. Current version: {}",
                self.version, BINARY_PROTOCOL_VERSION
            )));
        }

        Ok(self.version)
    }

    /// Read a u8 value
    ///
    /// # Errors
    ///
    /// Returns error if reading fails
    pub fn read_u8(&mut self) -> ChieResult<u8> {
        let mut buf = [0u8; 1];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| ChieError::serialization(format!("Failed to read u8: {e}")))?;
        Ok(buf[0])
    }

    /// Read a u32 value (little-endian)
    ///
    /// # Errors
    ///
    /// Returns error if reading fails
    pub fn read_u32(&mut self) -> ChieResult<u32> {
        let mut buf = [0u8; 4];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| ChieError::serialization(format!("Failed to read u32: {e}")))?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a u64 value (little-endian)
    ///
    /// # Errors
    ///
    /// Returns error if reading fails
    pub fn read_u64(&mut self) -> ChieResult<u64> {
        let mut buf = [0u8; 8];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| ChieError::serialization(format!("Failed to read u64: {e}")))?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a variable-length byte array (length prefix + data)
    ///
    /// # Errors
    ///
    /// Returns error if reading fails or length is invalid
    pub fn read_bytes(&mut self) -> ChieResult<Vec<u8>> {
        let len = self.read_u32()?;
        let mut buf = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut buf)
            .map_err(|e| ChieError::serialization(format!("Failed to read bytes: {e}")))?;
        Ok(buf)
    }

    /// Read a string (UTF-8 encoded with length prefix)
    ///
    /// # Errors
    ///
    /// Returns error if reading fails or string is invalid UTF-8
    pub fn read_string(&mut self) -> ChieResult<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes)
            .map_err(|e| ChieError::serialization(format!("Invalid UTF-8 string: {e}")))
    }

    /// Read a boolean from a single byte
    ///
    /// # Errors
    ///
    /// Returns error if reading fails
    pub fn read_bool(&mut self) -> ChieResult<bool> {
        let value = self.read_u8()?;
        Ok(value != 0)
    }

    /// Read and verify CRC32 checksum for the given data
    ///
    /// # Errors
    ///
    /// Returns error if checksum doesn't match or reading fails
    pub fn verify_checksum(&mut self, data: &[u8]) -> ChieResult<()> {
        let expected_checksum = self.read_u32()?;
        if !verify_crc32(data, expected_checksum) {
            return Err(ChieError::serialization(format!(
                "Checksum mismatch: expected {expected_checksum}, got {}",
                calculate_crc32(data)
            )));
        }
        Ok(())
    }

    /// Get the protocol version from the header
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get a mutable reference to the underlying reader
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the decoder and return the underlying reader
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Read large byte array in chunks with a callback to process each chunk
    ///
    /// # Errors
    ///
    /// Returns error if reading fails or callback returns error
    pub fn read_bytes_chunked<F>(&mut self, chunk_size: usize, mut callback: F) -> ChieResult<u64>
    where
        F: FnMut(&[u8]) -> ChieResult<()>,
    {
        let total_size = u64::from(self.read_u32()?);
        let mut buffer = vec![0u8; chunk_size];
        let mut remaining = total_size;
        let mut total_read = 0u64;

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, chunk_size as u64) as usize;
            self.reader
                .read_exact(&mut buffer[..to_read])
                .map_err(|e| ChieError::serialization(format!("Failed to read chunk: {e}")))?;

            callback(&buffer[..to_read])?;

            remaining -= to_read as u64;
            total_read += to_read as u64;
        }

        Ok(total_read)
    }

    /// Stream data directly to a writer without buffering entire payload
    ///
    /// # Errors
    ///
    /// Returns error if copying fails
    pub fn copy_to_writer<W: Write>(&mut self, writer: &mut W, size: u64) -> ChieResult<u64> {
        let mut limited_reader = self.reader.by_ref().take(size);
        std::io::copy(&mut limited_reader, writer)
            .map_err(|e| ChieError::serialization(format!("Failed to copy to writer: {e}")))
    }
}

/// Trait for types that can be encoded to binary format
pub trait BinaryEncode {
    /// Encode to binary format
    ///
    /// # Errors
    ///
    /// Returns error if encoding fails
    fn encode<W: Write>(&self, encoder: &mut BinaryEncoder<W>) -> ChieResult<()>;

    /// Convenience method to encode to a byte vector
    ///
    /// # Errors
    ///
    /// Returns error if encoding fails
    fn encode_to_vec(&self) -> ChieResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header()?;
        self.encode(&mut encoder)?;
        Ok(buf)
    }
}

/// Trait for types that can be decoded from binary format
pub trait BinaryDecode: Sized {
    /// Decode from binary format
    ///
    /// # Errors
    ///
    /// Returns error if decoding fails
    fn decode<R: Read>(decoder: &mut BinaryDecoder<R>) -> ChieResult<Self>;

    /// Convenience method to decode from a byte slice
    ///
    /// # Errors
    ///
    /// Returns error if decoding fails
    fn decode_from_slice(bytes: &[u8]) -> ChieResult<Self> {
        let mut decoder = BinaryDecoder::new(bytes);
        decoder.read_header()?;
        Self::decode(&mut decoder)
    }
}

/// Batch encoding utilities for efficient bulk operations
///
/// # Examples
///
/// ```
/// use chie_shared::encoding::BatchEncoder;
///
/// // Encode multiple strings at once
/// let strings = vec!["hello", "world", "chie"];
/// let encoded = BatchEncoder::encode_strings(&strings).unwrap();
/// assert!(!encoded.is_empty());
/// ```
pub struct BatchEncoder;

impl BatchEncoder {
    /// Encode multiple items to a single buffer with length prefix
    ///
    /// # Errors
    ///
    /// Returns error if encoding fails
    pub fn encode_batch<T: BinaryEncode>(items: &[T]) -> ChieResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header()?;

        // Write count
        let count = u32::try_from(items.len())
            .map_err(|_| ChieError::serialization("Too many items for batch"))?;
        encoder.write_u32(count)?;

        // Write each item
        for item in items {
            item.encode(&mut encoder)?;
        }

        Ok(buf)
    }

    /// Encode multiple strings efficiently
    ///
    /// # Errors
    ///
    /// Returns error if encoding fails
    pub fn encode_strings(strings: &[&str]) -> ChieResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header()?;

        let count = u32::try_from(strings.len())
            .map_err(|_| ChieError::serialization("Too many strings for batch"))?;
        encoder.write_u32(count)?;

        for s in strings {
            encoder.write_string(s)?;
        }

        Ok(buf)
    }

    /// Encode multiple u64 values efficiently
    ///
    /// # Errors
    ///
    /// Returns error if encoding fails
    pub fn encode_u64_batch(values: &[u64]) -> ChieResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header()?;

        let count = u32::try_from(values.len())
            .map_err(|_| ChieError::serialization("Too many values for batch"))?;
        encoder.write_u32(count)?;

        for &value in values {
            encoder.write_u64(value)?;
        }

        Ok(buf)
    }
}

/// Batch decoding utilities for efficient bulk operations
///
/// # Examples
///
/// ```
/// use chie_shared::encoding::{BatchEncoder, BatchDecoder};
///
/// // Encode and decode a batch of strings
/// let original = vec!["foo", "bar", "baz"];
/// let encoded = BatchEncoder::encode_strings(&original).unwrap();
/// let decoded = BatchDecoder::decode_strings(&encoded).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub struct BatchDecoder;

impl BatchDecoder {
    /// Decode a batch of items with a factory function
    ///
    /// # Errors
    ///
    /// Returns error if decoding fails
    pub fn decode_batch<T, F>(bytes: &[u8], mut decode_fn: F) -> ChieResult<Vec<T>>
    where
        F: FnMut(&mut BinaryDecoder<&[u8]>) -> ChieResult<T>,
    {
        let mut decoder = BinaryDecoder::new(bytes);
        decoder.read_header()?;

        let count = decoder.read_u32()?;
        let mut items = Vec::with_capacity(count as usize);

        for _ in 0..count {
            items.push(decode_fn(&mut decoder)?);
        }

        Ok(items)
    }

    /// Decode a batch of strings
    ///
    /// # Errors
    ///
    /// Returns error if decoding fails
    pub fn decode_strings(bytes: &[u8]) -> ChieResult<Vec<String>> {
        Self::decode_batch(bytes, |decoder| decoder.read_string())
    }

    /// Decode a batch of u64 values
    ///
    /// # Errors
    ///
    /// Returns error if decoding fails
    pub fn decode_u64_batch(bytes: &[u8]) -> ChieResult<Vec<u64>> {
        Self::decode_batch(bytes, |decoder| decoder.read_u64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_u8() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u8(42).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        assert_eq!(decoder.read_u8().unwrap(), 42);
    }

    #[test]
    fn test_encode_decode_u32() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u32(123_456).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        assert_eq!(decoder.read_u32().unwrap(), 123_456);
    }

    #[test]
    fn test_encode_decode_u64() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u64(987_654_321).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        assert_eq!(decoder.read_u64().unwrap(), 987_654_321);
    }

    #[test]
    fn test_encode_decode_bytes() {
        let data = b"Hello, World!";
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bytes(data).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_bytes().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_string() {
        let s = "Hello, CHIE!";
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_string(s).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_string().unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn test_encode_decode_bool() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bool(true).unwrap();
        encoder.write_bool(false).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        assert!(decoder.read_bool().unwrap());
        assert!(!decoder.read_bool().unwrap());
    }

    #[test]
    fn test_header_roundtrip() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header().unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let version = decoder.read_header().unwrap();
        assert_eq!(version, BINARY_PROTOCOL_VERSION);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let buf = b"FAKE\x01";
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let result = decoder.read_header();
        assert!(result.is_err());
    }

    #[test]
    fn test_version_compatibility() {
        // Test that we can read older versions
        let buf = b"CHIE\x01"; // Version 1
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let version = decoder.read_header().unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn test_unsupported_version() {
        // Test that we reject future versions
        let buf = b"CHIE\xFF"; // Version 255
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let result = decoder.read_header();
        assert!(result.is_err());
    }

    #[test]
    fn test_encoder_into_inner() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u32(42).unwrap();
        let inner = encoder.into_inner();
        assert_eq!(inner.len(), 4);
    }

    #[test]
    fn test_decoder_version() {
        let buf = b"CHIE\x01";
        let mut decoder = BinaryDecoder::new(&buf[..]);
        decoder.read_header().unwrap();
        assert_eq!(decoder.version(), 1);
    }

    #[test]
    fn test_complex_message() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_header().unwrap();
        encoder.write_string("content_id").unwrap();
        encoder.write_u32(12345).unwrap();
        encoder.write_u64(67890).unwrap();
        encoder.write_bool(true).unwrap();
        encoder.write_bytes(&[1, 2, 3, 4]).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        decoder.read_header().unwrap();
        assert_eq!(decoder.read_string().unwrap(), "content_id");
        assert_eq!(decoder.read_u32().unwrap(), 12345);
        assert_eq!(decoder.read_u64().unwrap(), 67890);
        assert!(decoder.read_bool().unwrap());
        assert_eq!(decoder.read_bytes().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_empty_bytes() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bytes(&[]).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_bytes().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_empty_string() {
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_string("").unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_string().unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn test_crc32_calculation() {
        let data = b"Hello, World!";
        let crc = calculate_crc32(data);
        assert_ne!(crc, 0);

        // Same data should produce same checksum
        assert_eq!(calculate_crc32(data), crc);

        // Different data should produce different checksum
        let different_data = b"Hello, CHIE!";
        assert_ne!(calculate_crc32(different_data), crc);
    }

    #[test]
    fn test_crc32_verification() {
        let data = b"Test data";
        let crc = calculate_crc32(data);

        assert!(verify_crc32(data, crc));
        assert!(!verify_crc32(data, crc + 1));
        assert!(!verify_crc32(b"Different data", crc));
    }

    #[test]
    fn test_write_verify_checksum() {
        let data = b"Important message";
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        // Write data and its checksum
        encoder.write_bytes(data).unwrap();
        encoder.write_checksum(data).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded_data = decoder.read_bytes().unwrap();
        assert_eq!(decoded_data, data);

        // Verify checksum
        decoder.verify_checksum(&decoded_data).unwrap();
    }

    #[test]
    fn test_checksum_mismatch() {
        let data = b"Original data";
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        encoder.write_bytes(data).unwrap();
        encoder.write_checksum(data).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let _decoded_data = decoder.read_bytes().unwrap();

        // Modify data to cause checksum mismatch
        let modified_data = b"Modified data";
        let result = decoder.verify_checksum(modified_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_data_checksum() {
        let data = b"";
        let crc = calculate_crc32(data);
        // CRC32 of empty data is a specific constant
        assert!(verify_crc32(data, crc));

        // Different empty data should have same checksum
        assert_eq!(calculate_crc32(b""), crc);
    }

    // Compression tests
    #[test]
    fn test_no_compression() {
        let compressor = NoCompression;
        let data = b"Hello, World!";

        let compressed = compressor.compress(data).unwrap();
        assert_eq!(compressed, data);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);

        assert_eq!(compressor.algorithm_id(), "none");
        assert!(!compressor.should_compress(10_000));
    }

    #[test]
    fn test_compression_config_default() {
        let config = CompressionConfig::default();
        assert_eq!(config.min_size, 1024);
        assert!(config.enabled);

        assert!(!config.should_compress(512)); // Below threshold
        assert!(config.should_compress(2048)); // Above threshold
    }

    #[test]
    fn test_compression_config_disabled() {
        let config = CompressionConfig::disabled();
        assert!(!config.enabled);
        assert!(!config.should_compress(10_000)); // Never compress when disabled
    }

    #[test]
    fn test_compression_config_custom() {
        let config = CompressionConfig::new(2048, true);
        assert_eq!(config.min_size, 2048);
        assert!(config.enabled);

        assert!(!config.should_compress(1024)); // Below threshold
        assert!(config.should_compress(4096)); // Above threshold
    }

    // Streaming serialization tests
    #[test]
    fn test_write_bytes_chunked() {
        let data = vec![1u8; 10_000]; // 10KB of data
        let mut reader = &data[..];
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        encoder
            .write_bytes_chunked(&mut reader, 10_000, 1024)
            .unwrap();

        // Verify: 4 bytes for length + 10,000 bytes of data
        assert_eq!(buf.len(), 4 + 10_000);

        // Decode and verify
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_bytes().unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_read_bytes_chunked() {
        let data = vec![42u8; 5_000];
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bytes(&data).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let mut chunks_received = Vec::new();

        let total_read = decoder
            .read_bytes_chunked(1024, |chunk| {
                chunks_received.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();

        assert_eq!(total_read, 5_000);
        assert_eq!(chunks_received, data);
    }

    #[test]
    fn test_copy_from_reader() {
        let data = b"Stream this data!";
        let mut reader = &data[..];
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        let bytes_copied = encoder.copy_from_reader(&mut reader).unwrap();
        assert_eq!(bytes_copied, data.len() as u64);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_copy_to_writer() {
        let data = b"Output this data!";
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bytes(data).unwrap();

        // Now decode and copy to writer
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let _len = decoder.read_u32().unwrap(); // Read length prefix

        let mut output = Vec::new();
        let bytes_copied = decoder
            .copy_to_writer(&mut output, data.len() as u64)
            .unwrap();

        assert_eq!(bytes_copied, data.len() as u64);
        assert_eq!(output, data);
    }

    #[test]
    fn test_chunked_roundtrip() {
        // Test large payload roundtrip
        let data = (0..10_000).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let mut reader = &data[..];
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        // Write chunked
        encoder
            .write_bytes_chunked(&mut reader, data.len() as u64, 512)
            .unwrap();

        // Read chunked
        let mut decoder = BinaryDecoder::new(&buf[..]);
        let mut result = Vec::new();
        decoder
            .read_bytes_chunked(512, |chunk| {
                result.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_chunked_with_exact_chunk_size() {
        // Test when data size is exactly a multiple of chunk size
        let data = vec![99u8; 2048];
        let mut reader = &data[..];
        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);

        encoder.write_bytes_chunked(&mut reader, 2048, 512).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let mut result = Vec::new();
        decoder
            .read_bytes_chunked(512, |chunk| {
                result.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();

        assert_eq!(result, data);
    }

    // Batch encoding/decoding tests
    #[test]
    fn test_batch_encode_decode_strings() {
        let strings = vec!["hello", "world", "chie", "protocol"];
        let encoded = BatchEncoder::encode_strings(&strings).unwrap();
        let decoded = BatchDecoder::decode_strings(&encoded).unwrap();

        assert_eq!(decoded.len(), strings.len());
        for (original, decoded) in strings.iter().zip(decoded.iter()) {
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_batch_encode_decode_u64() {
        let values = vec![1, 2, 3, 100, 1000, 10_000, u64::MAX];
        let encoded = BatchEncoder::encode_u64_batch(&values).unwrap();
        let decoded = BatchDecoder::decode_u64_batch(&encoded).unwrap();

        assert_eq!(decoded, values);
    }

    #[test]
    fn test_batch_empty() {
        let strings: Vec<&str> = vec![];
        let encoded = BatchEncoder::encode_strings(&strings).unwrap();
        let decoded = BatchDecoder::decode_strings(&encoded).unwrap();

        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_batch_single_item() {
        let strings = vec!["single"];
        let encoded = BatchEncoder::encode_strings(&strings).unwrap();
        let decoded = BatchDecoder::decode_strings(&encoded).unwrap();

        assert_eq!(decoded, vec!["single"]);
    }

    #[test]
    fn test_batch_large_count() {
        // Test with many items
        let values: Vec<u64> = (0..1000).collect();
        let encoded = BatchEncoder::encode_u64_batch(&values).unwrap();
        let decoded = BatchDecoder::decode_u64_batch(&encoded).unwrap();

        assert_eq!(decoded, values);
    }
}
