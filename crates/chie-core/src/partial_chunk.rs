//! Partial chunk support for range requests.
//!
//! This module provides functionality for serving partial content requests,
//! enabling efficient byte-range retrieval for streaming scenarios.
//!
//! # Features
//!
//! - HTTP-style range request support (bytes=0-1023)
//! - Multi-range requests
//! - Chunk-aligned range calculations
//! - Efficient partial reads without loading full chunks
//! - Content-Length and Content-Range header generation
//!
//! # Example
//!
//! ```
//! use chie_core::partial_chunk::{RangeRequest, RangeHandler};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse a range request
//! let range = RangeRequest::parse("bytes=0-1023")?;
//!
//! // Create a range handler for content
//! let handler = RangeHandler::new(1_000_000, 262_144); // 1MB total, 256KB chunks
//!
//! // Get the chunks needed for this range
//! let chunks = handler.get_required_chunks(&range)?;
//!
//! println!("Need chunks: {:?}", chunks);
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Default chunk size for range calculations (256 KB)
const DEFAULT_CHUNK_SIZE: u64 = 256 * 1024;

/// Errors that can occur during range request processing
#[derive(Debug, Error)]
pub enum RangeError {
    #[error("Invalid range syntax: {0}")]
    InvalidSyntax(String),

    #[error("Range not satisfiable: {0}")]
    NotSatisfiable(String),

    #[error("Invalid range bounds: start={0}, end={1}")]
    InvalidBounds(u64, u64),

    #[error("Range exceeds content length: {0} > {1}")]
    ExceedsContent(u64, u64),
}

/// Represents a byte range request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    /// Start byte (inclusive)
    pub start: u64,
    /// End byte (inclusive, None means to end of content)
    pub end: Option<u64>,
}

impl ByteRange {
    /// Create a new byte range
    #[must_use]
    pub const fn new(start: u64, end: Option<u64>) -> Self {
        Self { start, end }
    }

    /// Create a range from start to end (inclusive)
    #[must_use]
    pub const fn from_to(start: u64, end: u64) -> Self {
        Self {
            start,
            end: Some(end),
        }
    }

    /// Create a range from start to end of content
    #[must_use]
    pub const fn from_start(start: u64) -> Self {
        Self { start, end: None }
    }

    /// Create a range for the last N bytes
    #[must_use]
    pub const fn suffix(count: u64) -> Self {
        Self {
            start: 0,
            end: Some(count),
        }
    }

    /// Normalize the range to absolute positions given content length
    pub fn normalize(&self, content_length: u64) -> Result<(u64, u64), RangeError> {
        let start = self.start;
        let end = self.end.unwrap_or(content_length.saturating_sub(1));

        // Validate bounds
        if start > end {
            return Err(RangeError::InvalidBounds(start, end));
        }

        if end >= content_length {
            return Err(RangeError::ExceedsContent(end, content_length));
        }

        Ok((start, end))
    }

    /// Calculate the length of this range (inclusive)
    #[must_use]
    pub const fn length(&self) -> u64 {
        match self.end {
            Some(end) => end.saturating_sub(self.start) + 1,
            None => u64::MAX, // Unknown until normalized
        }
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bytes {}-", self.start)?;
        if let Some(end) = self.end {
            write!(f, "{end}")
        } else {
            write!(f, "*")
        }
    }
}

/// A range request (may contain multiple ranges)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeRequest {
    /// List of requested byte ranges
    pub ranges: Vec<ByteRange>,
}

impl RangeRequest {
    /// Create a new range request with a single range
    #[must_use]
    pub fn new(range: ByteRange) -> Self {
        Self {
            ranges: vec![range],
        }
    }

    /// Create a range request with multiple ranges
    #[must_use]
    pub fn multi(ranges: Vec<ByteRange>) -> Self {
        Self { ranges }
    }

    /// Parse an HTTP Range header value (e.g., "bytes=0-1023")
    pub fn parse(header: &str) -> Result<Self, RangeError> {
        let header = header.trim();

        // Check for "bytes=" prefix
        if !header.starts_with("bytes=") {
            return Err(RangeError::InvalidSyntax(
                "Range must start with 'bytes='".to_string(),
            ));
        }

        let range_str = &header[6..]; // Skip "bytes="
        let mut ranges = Vec::new();

        // Parse comma-separated ranges
        for part in range_str.split(',') {
            let part = part.trim();

            if part.is_empty() {
                continue;
            }

            // Parse individual range (e.g., "0-1023" or "1024-" or "-500")
            if let Some((start_str, end_str)) = part.split_once('-') {
                let range = if start_str.is_empty() {
                    // Suffix range: "-500" means last 500 bytes
                    let count: u64 = end_str
                        .parse()
                        .map_err(|_| RangeError::InvalidSyntax(part.to_string()))?;
                    ByteRange::suffix(count)
                } else if end_str.is_empty() {
                    // Open-ended range: "1024-" means from 1024 to end
                    let start: u64 = start_str
                        .parse()
                        .map_err(|_| RangeError::InvalidSyntax(part.to_string()))?;
                    ByteRange::from_start(start)
                } else {
                    // Full range: "0-1023"
                    let start: u64 = start_str
                        .parse()
                        .map_err(|_| RangeError::InvalidSyntax(part.to_string()))?;
                    let end: u64 = end_str
                        .parse()
                        .map_err(|_| RangeError::InvalidSyntax(part.to_string()))?;
                    ByteRange::from_to(start, end)
                };

                ranges.push(range);
            } else {
                return Err(RangeError::InvalidSyntax(part.to_string()));
            }
        }

        if ranges.is_empty() {
            return Err(RangeError::InvalidSyntax(
                "No valid ranges found".to_string(),
            ));
        }

        Ok(Self { ranges })
    }

    /// Check if this is a multi-range request
    #[must_use]
    #[inline]
    pub fn is_multi_range(&self) -> bool {
        self.ranges.len() > 1
    }

    /// Get the total number of bytes requested across all ranges
    pub fn total_bytes(&self, content_length: u64) -> Result<u64, RangeError> {
        let mut total = 0u64;
        for range in &self.ranges {
            let (start, end) = range.normalize(content_length)?;
            total = total.saturating_add(end.saturating_sub(start) + 1);
        }
        Ok(total)
    }
}

/// Information about a chunk that needs to be read for a range
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRange {
    /// Chunk index
    pub chunk_index: u64,
    /// Byte offset within the chunk to start reading
    pub offset_in_chunk: u64,
    /// Number of bytes to read from this chunk
    pub length: u64,
}

/// Handles range requests for chunked content
pub struct RangeHandler {
    /// Total content length in bytes
    content_length: u64,
    /// Chunk size in bytes
    chunk_size: u64,
}

impl RangeHandler {
    /// Create a new range handler
    #[must_use]
    pub const fn new(content_length: u64, chunk_size: u64) -> Self {
        Self {
            content_length,
            chunk_size,
        }
    }

    /// Create a range handler with default chunk size (256 KB)
    #[must_use]
    pub const fn with_default_chunk_size(content_length: u64) -> Self {
        Self::new(content_length, DEFAULT_CHUNK_SIZE)
    }

    /// Get the chunks required to satisfy a range request
    pub fn get_required_chunks(
        &self,
        request: &RangeRequest,
    ) -> Result<Vec<ChunkRange>, RangeError> {
        let mut chunk_ranges = Vec::new();

        for range in &request.ranges {
            let (start, end) = range.normalize(self.content_length)?;

            // Calculate which chunks we need
            let start_chunk = start / self.chunk_size;
            let end_chunk = end / self.chunk_size;

            for chunk_idx in start_chunk..=end_chunk {
                let chunk_start = chunk_idx * self.chunk_size;
                let chunk_end = ((chunk_idx + 1) * self.chunk_size).min(self.content_length) - 1;

                // Calculate the intersection of requested range and this chunk
                let read_start = start.max(chunk_start);
                let read_end = end.min(chunk_end);

                let offset_in_chunk = read_start - chunk_start;
                let length = read_end - read_start + 1;

                chunk_ranges.push(ChunkRange {
                    chunk_index: chunk_idx,
                    offset_in_chunk,
                    length,
                });
            }
        }

        Ok(chunk_ranges)
    }

    /// Generate Content-Range header value
    #[must_use]
    pub fn content_range_header(&self, start: u64, end: u64) -> String {
        format!("bytes {start}-{end}/{}", self.content_length)
    }

    /// Check if a range request is satisfiable
    #[must_use]
    #[inline]
    pub fn is_satisfiable(&self, request: &RangeRequest) -> bool {
        request
            .ranges
            .iter()
            .all(|r| r.normalize(self.content_length).is_ok())
    }

    /// Get content length
    #[must_use]
    #[inline]
    pub const fn content_length(&self) -> u64 {
        self.content_length
    }

    /// Get chunk size
    #[must_use]
    #[inline]
    pub const fn chunk_size(&self) -> u64 {
        self.chunk_size
    }
}

/// Response for a partial content request
#[derive(Debug, Clone)]
pub struct PartialResponse {
    /// HTTP status code (206 for partial content, 416 for not satisfiable)
    pub status_code: u16,
    /// Content-Range header value
    pub content_range: Option<String>,
    /// Content-Length header value
    pub content_length: u64,
    /// Actual data (assembled from chunks)
    pub data: Vec<u8>,
}

impl PartialResponse {
    /// Create a successful partial response (206)
    #[must_use]
    pub fn partial_content(content_range: String, data: Vec<u8>) -> Self {
        let content_length = data.len() as u64;
        Self {
            status_code: 206,
            content_range: Some(content_range),
            content_length,
            data,
        }
    }

    /// Create a range not satisfiable response (416)
    #[must_use]
    pub fn not_satisfiable(total_length: u64) -> Self {
        Self {
            status_code: 416,
            content_range: Some(format!("bytes */{total_length}")),
            content_length: 0,
            data: Vec::new(),
        }
    }

    /// Create a full content response (200)
    #[must_use]
    pub fn full_content(data: Vec<u8>) -> Self {
        let content_length = data.len() as u64;
        Self {
            status_code: 200,
            content_range: None,
            content_length,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_range_new() {
        let range = ByteRange::new(0, Some(1023));
        assert_eq!(range.start, 0);
        assert_eq!(range.end, Some(1023));
    }

    #[test]
    fn test_byte_range_normalize() {
        let range = ByteRange::from_to(0, 1023);
        let (start, end) = range.normalize(10_000).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 1023);

        // Test range exceeding content length
        let range = ByteRange::from_to(0, 20_000);
        assert!(range.normalize(10_000).is_err());
    }

    #[test]
    fn test_byte_range_length() {
        let range = ByteRange::from_to(0, 1023);
        assert_eq!(range.length(), 1024);

        let range = ByteRange::from_start(1000);
        assert_eq!(range.length(), u64::MAX); // Unknown until normalized
    }

    #[test]
    fn test_range_request_parse_simple() {
        let request = RangeRequest::parse("bytes=0-1023").unwrap();
        assert_eq!(request.ranges.len(), 1);
        assert_eq!(request.ranges[0].start, 0);
        assert_eq!(request.ranges[0].end, Some(1023));
    }

    #[test]
    fn test_range_request_parse_open_ended() {
        let request = RangeRequest::parse("bytes=1024-").unwrap();
        assert_eq!(request.ranges.len(), 1);
        assert_eq!(request.ranges[0].start, 1024);
        assert_eq!(request.ranges[0].end, None);
    }

    #[test]
    fn test_range_request_parse_suffix() {
        let request = RangeRequest::parse("bytes=-500").unwrap();
        assert_eq!(request.ranges.len(), 1);
        assert_eq!(request.ranges[0].start, 0);
        assert_eq!(request.ranges[0].end, Some(500));
    }

    #[test]
    fn test_range_request_parse_multi() {
        let request = RangeRequest::parse("bytes=0-1023,2048-3071").unwrap();
        assert_eq!(request.ranges.len(), 2);
        assert_eq!(request.ranges[0].start, 0);
        assert_eq!(request.ranges[0].end, Some(1023));
        assert_eq!(request.ranges[1].start, 2048);
        assert_eq!(request.ranges[1].end, Some(3071));
    }

    #[test]
    fn test_range_request_parse_invalid() {
        assert!(RangeRequest::parse("invalid").is_err());
        assert!(RangeRequest::parse("bytes=").is_err());
        assert!(RangeRequest::parse("bytes=abc-def").is_err());
    }

    #[test]
    fn test_range_handler_simple_range() {
        let handler = RangeHandler::new(1_000_000, 256_000);
        let request = RangeRequest::parse("bytes=0-255999").unwrap();
        let chunks = handler.get_required_chunks(&request).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].offset_in_chunk, 0);
        assert_eq!(chunks[0].length, 256_000);
    }

    #[test]
    fn test_range_handler_multi_chunk() {
        let handler = RangeHandler::new(1_000_000, 256_000);
        let request = RangeRequest::parse("bytes=200000-600000").unwrap();
        let chunks = handler.get_required_chunks(&request).unwrap();

        // Should span chunks 0, 1, 2
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[2].chunk_index, 2);
    }

    #[test]
    fn test_range_handler_content_range_header() {
        let handler = RangeHandler::new(1_000_000, 256_000);
        let header = handler.content_range_header(0, 1023);
        assert_eq!(header, "bytes 0-1023/1000000");
    }

    #[test]
    fn test_range_handler_is_satisfiable() {
        let handler = RangeHandler::new(1_000_000, 256_000);

        let good_request = RangeRequest::parse("bytes=0-1023").unwrap();
        assert!(handler.is_satisfiable(&good_request));

        let bad_request = RangeRequest::parse("bytes=0-2000000").unwrap();
        assert!(!handler.is_satisfiable(&bad_request));
    }

    #[test]
    fn test_partial_response_partial_content() {
        let data = vec![1u8, 2, 3, 4];
        let response = PartialResponse::partial_content("bytes 0-3/100".to_string(), data);
        assert_eq!(response.status_code, 206);
        assert_eq!(response.content_length, 4);
        assert_eq!(response.content_range.unwrap(), "bytes 0-3/100");
    }

    #[test]
    fn test_partial_response_not_satisfiable() {
        let response = PartialResponse::not_satisfiable(100);
        assert_eq!(response.status_code, 416);
        assert_eq!(response.content_range.unwrap(), "bytes */100");
    }

    #[test]
    fn test_partial_response_full_content() {
        let data = vec![1u8; 100];
        let response = PartialResponse::full_content(data);
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_length, 100);
        assert!(response.content_range.is_none());
    }

    #[test]
    fn test_range_request_total_bytes() {
        let request = RangeRequest::parse("bytes=0-1023,2048-3071").unwrap();
        let total = request.total_bytes(10_000).unwrap();
        assert_eq!(total, 2048); // 1024 + 1024
    }
}
