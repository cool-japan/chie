//! HTTP-style range request support for partial content delivery.
//!
//! This module provides range request handling capabilities essential for
//! video streaming, large file downloads, and resume functionality. Supports
//! HTTP Range header semantics including multi-part ranges.
//!
//! # Features
//!
//! - Single and multi-part range requests
//! - Byte range validation and normalization
//! - Content-Length and Content-Range header generation
//! - Efficient partial content delivery
//! - Range request merging and optimization
//! - Cache-friendly range handling
//! - Comprehensive range statistics
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{RangeRequest, ByteRange, RangeRequestHandler};
//!
//! let handler = RangeRequestHandler::new();
//! let content_length = 10000;
//!
//! // Parse range header
//! let range = RangeRequest::parse("bytes=0-499", content_length).unwrap();
//!
//! // Get byte ranges
//! if let Ok(ranges) = range.to_byte_ranges(content_length) {
//!     for byte_range in ranges {
//!         println!("Range: {}-{}", byte_range.start, byte_range.end);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors that can occur during range request processing
#[derive(Debug, Error, Clone, PartialEq)]
pub enum RangeError {
    /// Invalid range syntax
    #[error("Invalid range syntax: {0}")]
    InvalidSyntax(String),

    /// Range not satisfiable
    #[error("Range not satisfiable: requested {requested}, available {available}")]
    NotSatisfiable { requested: String, available: u64 },

    /// Multiple ranges not supported
    #[error("Multiple ranges not supported")]
    MultipleRangesNotSupported,

    /// Invalid range bounds
    #[error("Invalid range bounds: start={start}, end={end}")]
    InvalidBounds { start: u64, end: u64 },
}

/// A single byte range
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    /// Start byte (inclusive)
    pub start: u64,
    /// End byte (inclusive)
    pub end: u64,
}

impl ByteRange {
    /// Create a new byte range
    pub fn new(start: u64, end: u64) -> Result<Self, RangeError> {
        if start > end {
            return Err(RangeError::InvalidBounds { start, end });
        }
        Ok(Self { start, end })
    }

    /// Get the length of this range in bytes
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Check if this range is empty
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }

    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &ByteRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Check if this range contains a byte offset
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset <= self.end
    }

    /// Merge with another range if they overlap or are adjacent
    pub fn try_merge(&self, other: &ByteRange) -> Option<ByteRange> {
        if self.overlaps(other) || self.end + 1 == other.start || other.end + 1 == self.start {
            Some(ByteRange {
                start: self.start.min(other.start),
                end: self.end.max(other.end),
            })
        } else {
            None
        }
    }

    /// Split into smaller chunks of specified size
    pub fn split(&self, chunk_size: u64) -> Vec<ByteRange> {
        let mut chunks = Vec::new();
        let mut current = self.start;

        while current <= self.end {
            let chunk_end = (current + chunk_size - 1).min(self.end);
            chunks.push(ByteRange {
                start: current,
                end: chunk_end,
            });
            current = chunk_end + 1;
        }

        chunks
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// Range request specification
#[derive(Debug, Clone, PartialEq)]
pub enum RangeRequest {
    /// Bytes from start to end (inclusive)
    Range { start: u64, end: Option<u64> },
    /// Last N bytes
    Suffix { length: u64 },
    /// Multiple ranges
    Multiple(Vec<RangeRequest>),
}

impl RangeRequest {
    /// Parse HTTP Range header value
    ///
    /// Examples:
    /// - "bytes=0-499" -> first 500 bytes
    /// - "bytes=500-999" -> second 500 bytes
    /// - "bytes=-500" -> last 500 bytes
    /// - "bytes=500-" -> from byte 500 to end
    /// - "bytes=0-0,-1" -> first and last byte (multiple ranges)
    pub fn parse(range_header: &str, _content_length: u64) -> Result<Self, RangeError> {
        let range_header = range_header.trim();

        // Check if it starts with "bytes="
        if !range_header.starts_with("bytes=") {
            return Err(RangeError::InvalidSyntax(
                "Range must start with 'bytes='".to_string(),
            ));
        }

        let range_spec = &range_header[6..]; // Skip "bytes="

        // Check for multiple ranges
        if range_spec.contains(',') {
            let ranges: Result<Vec<_>, _> = range_spec
                .split(',')
                .map(|r| Self::parse_single_range(r.trim()))
                .collect();

            return Ok(RangeRequest::Multiple(ranges?));
        }

        Self::parse_single_range(range_spec)
    }

    fn parse_single_range(spec: &str) -> Result<Self, RangeError> {
        if let Some(suffix) = spec.strip_prefix('-') {
            // Suffix range (last N bytes)
            let length = suffix
                .parse::<u64>()
                .map_err(|_| RangeError::InvalidSyntax(format!("Invalid suffix: {}", spec)))?;

            Ok(RangeRequest::Suffix { length })
        } else {
            // Normal range
            let parts: Vec<&str> = spec.split('-').collect();
            if parts.len() != 2 {
                return Err(RangeError::InvalidSyntax(format!(
                    "Invalid range format: {}",
                    spec
                )));
            }

            let start = parts[0]
                .parse::<u64>()
                .map_err(|_| RangeError::InvalidSyntax(format!("Invalid start: {}", parts[0])))?;

            let end =
                if parts[1].is_empty() {
                    None
                } else {
                    Some(parts[1].parse::<u64>().map_err(|_| {
                        RangeError::InvalidSyntax(format!("Invalid end: {}", parts[1]))
                    })?)
                };

            if let Some(e) = end {
                if start > e {
                    return Err(RangeError::InvalidBounds { start, end: e });
                }
            }

            Ok(RangeRequest::Range { start, end })
        }
    }

    /// Convert to byte ranges for a given content length
    pub fn to_byte_ranges(&self, content_length: u64) -> Result<Vec<ByteRange>, RangeError> {
        match self {
            RangeRequest::Range { start, end } => {
                let actual_end = end.unwrap_or(content_length - 1);

                if *start >= content_length {
                    return Err(RangeError::NotSatisfiable {
                        requested: format!("{}-{}", start, actual_end),
                        available: content_length,
                    });
                }

                let bounded_end = actual_end.min(content_length - 1);
                Ok(vec![ByteRange {
                    start: *start,
                    end: bounded_end,
                }])
            }
            RangeRequest::Suffix { length } => {
                let start = content_length.saturating_sub(*length);
                Ok(vec![ByteRange {
                    start,
                    end: content_length - 1,
                }])
            }
            RangeRequest::Multiple(ranges) => {
                let mut byte_ranges = Vec::new();
                for range in ranges {
                    byte_ranges.extend(range.to_byte_ranges(content_length)?);
                }
                Ok(byte_ranges)
            }
        }
    }

    /// Check if this is a multi-part range
    pub fn is_multipart(&self) -> bool {
        matches!(self, RangeRequest::Multiple(_))
    }

    /// Get total bytes requested
    pub fn total_bytes(&self, content_length: u64) -> Result<u64, RangeError> {
        let ranges = self.to_byte_ranges(content_length)?;
        Ok(ranges.iter().map(|r| r.len()).sum())
    }
}

/// Response information for a range request
#[derive(Debug, Clone)]
pub struct RangeResponse {
    /// Byte ranges to serve
    pub ranges: Vec<ByteRange>,
    /// Total content length
    pub content_length: u64,
    /// Whether this is a partial response (206) or full (200)
    pub is_partial: bool,
    /// Content-Range header value (for single range)
    pub content_range: Option<String>,
}

impl RangeResponse {
    /// Generate Content-Range header value
    pub fn content_range_header(&self) -> Option<String> {
        if self.ranges.len() == 1 {
            let range = &self.ranges[0];
            Some(format!(
                "bytes {}-{}/{}",
                range.start, range.end, self.content_length
            ))
        } else {
            None
        }
    }

    /// Get total bytes in response
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.len()).sum()
    }
}

/// Statistics for range requests
#[derive(Debug, Clone, Default)]
pub struct RangeStats {
    /// Total range requests
    pub total_requests: u64,
    /// Single range requests
    pub single_range_requests: u64,
    /// Multi-part range requests
    pub multipart_requests: u64,
    /// Suffix requests (last N bytes)
    pub suffix_requests: u64,
    /// Total bytes served via ranges
    pub total_bytes_served: u64,
    /// Average range size
    pub avg_range_size: u64,
    /// Largest range served
    pub largest_range: u64,
    /// Smallest range served
    pub smallest_range: u64,
    /// Number of unsatisfiable ranges
    pub unsatisfiable_ranges: u64,
}

/// Range request handler with statistics and optimization
pub struct RangeRequestHandler {
    stats: parking_lot::RwLock<RangeStats>,
    /// Minimum range size for optimization (bytes)
    #[allow(dead_code)]
    min_range_size: u64,
    /// Maximum number of ranges in multi-part request
    max_ranges: usize,
}

impl RangeRequestHandler {
    /// Create a new range request handler
    pub fn new() -> Self {
        Self {
            stats: parking_lot::RwLock::new(RangeStats::default()),
            min_range_size: 1024, // 1 KB minimum
            max_ranges: 10,
        }
    }

    /// Create with custom configuration
    pub fn with_config(min_range_size: u64, max_ranges: usize) -> Self {
        Self {
            stats: parking_lot::RwLock::new(RangeStats::default()),
            min_range_size,
            max_ranges,
        }
    }

    /// Process a range request
    pub fn process(
        &self,
        range_header: Option<&str>,
        content_length: u64,
    ) -> Result<RangeResponse, RangeError> {
        let Some(header) = range_header else {
            // No range header, serve full content
            return Ok(RangeResponse {
                ranges: vec![ByteRange {
                    start: 0,
                    end: content_length - 1,
                }],
                content_length,
                is_partial: false,
                content_range: None,
            });
        };

        let request = RangeRequest::parse(header, content_length)?;

        // Update stats
        let mut stats = self.stats.write();
        stats.total_requests += 1;

        match &request {
            RangeRequest::Range { .. } => stats.single_range_requests += 1,
            RangeRequest::Suffix { .. } => stats.suffix_requests += 1,
            RangeRequest::Multiple(_) => stats.multipart_requests += 1,
        }

        drop(stats);

        // Convert to byte ranges
        let mut ranges = request.to_byte_ranges(content_length).inspect_err(|_| {
            self.stats.write().unsatisfiable_ranges += 1;
        })?;

        // Check max ranges limit
        if ranges.len() > self.max_ranges {
            return Err(RangeError::MultipleRangesNotSupported);
        }

        // Merge overlapping or adjacent ranges
        ranges = self.merge_ranges(ranges);

        // Update stats
        let total_bytes: u64 = ranges.iter().map(|r| r.len()).sum();
        let mut stats = self.stats.write();
        stats.total_bytes_served += total_bytes;

        if !ranges.is_empty() {
            let range_sizes: Vec<u64> = ranges.iter().map(|r| r.len()).collect();
            stats.largest_range = stats.largest_range.max(*range_sizes.iter().max().unwrap());
            stats.smallest_range = if stats.smallest_range == 0 {
                *range_sizes.iter().min().unwrap()
            } else {
                stats.smallest_range.min(*range_sizes.iter().min().unwrap())
            };

            if stats.total_requests > 0 {
                stats.avg_range_size = stats.total_bytes_served / stats.total_requests;
            }
        }

        drop(stats);

        Ok(RangeResponse {
            content_range: if ranges.len() == 1 {
                Some(format!(
                    "bytes {}-{}/{}",
                    ranges[0].start, ranges[0].end, content_length
                ))
            } else {
                None
            },
            ranges,
            content_length,
            is_partial: true,
        })
    }

    /// Merge overlapping or adjacent ranges
    fn merge_ranges(&self, mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
        if ranges.len() <= 1 {
            return ranges;
        }

        // Sort by start position
        ranges.sort_by_key(|r| r.start);

        let mut merged = Vec::new();
        let mut current = ranges[0];

        for range in ranges.iter().skip(1) {
            if let Some(combined) = current.try_merge(range) {
                current = combined;
            } else {
                merged.push(current);
                current = *range;
            }
        }

        merged.push(current);
        merged
    }

    /// Get current statistics
    pub fn stats(&self) -> RangeStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.write() = RangeStats::default();
    }
}

impl Default for RangeRequestHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_range_new() {
        let range = ByteRange::new(0, 499).unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, 499);
        assert_eq!(range.len(), 500);
    }

    #[test]
    fn test_byte_range_invalid_bounds() {
        let result = ByteRange::new(500, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_byte_range_overlaps() {
        let range1 = ByteRange::new(0, 100).unwrap();
        let range2 = ByteRange::new(50, 150).unwrap();
        assert!(range1.overlaps(&range2));

        let range3 = ByteRange::new(200, 300).unwrap();
        assert!(!range1.overlaps(&range3));
    }

    #[test]
    fn test_byte_range_merge() {
        let range1 = ByteRange::new(0, 100).unwrap();
        let range2 = ByteRange::new(50, 150).unwrap();
        let merged = range1.try_merge(&range2).unwrap();
        assert_eq!(merged.start, 0);
        assert_eq!(merged.end, 150);
    }

    #[test]
    fn test_byte_range_split() {
        let range = ByteRange::new(0, 999).unwrap();
        let chunks = range.split(100);
        assert_eq!(chunks.len(), 10);
        assert_eq!(chunks[0].len(), 100);
        assert_eq!(chunks[9].len(), 100);
    }

    #[test]
    fn test_parse_simple_range() {
        let request = RangeRequest::parse("bytes=0-499", 10000).unwrap();
        let ranges = request.to_byte_ranges(10000).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0);
        assert_eq!(ranges[0].end, 499);
    }

    #[test]
    fn test_parse_open_ended_range() {
        let request = RangeRequest::parse("bytes=500-", 10000).unwrap();
        let ranges = request.to_byte_ranges(10000).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 500);
        assert_eq!(ranges[0].end, 9999);
    }

    #[test]
    fn test_parse_suffix_range() {
        let request = RangeRequest::parse("bytes=-500", 10000).unwrap();
        let ranges = request.to_byte_ranges(10000).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 9500);
        assert_eq!(ranges[0].end, 9999);
    }

    #[test]
    fn test_parse_multiple_ranges() {
        let request = RangeRequest::parse("bytes=0-499,1000-1499", 10000).unwrap();
        assert!(request.is_multipart());
        let ranges = request.to_byte_ranges(10000).unwrap();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let result = RangeRequest::parse("invalid", 10000);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_not_satisfiable() {
        let request = RangeRequest::parse("bytes=10000-10999", 10000).unwrap();
        let result = request.to_byte_ranges(10000);
        assert!(result.is_err());
    }

    #[test]
    fn test_handler_full_content() {
        let handler = RangeRequestHandler::new();
        let response = handler.process(None, 10000).unwrap();
        assert!(!response.is_partial);
        assert_eq!(response.ranges.len(), 1);
        assert_eq!(response.ranges[0].start, 0);
        assert_eq!(response.ranges[0].end, 9999);
    }

    #[test]
    fn test_handler_partial_content() {
        let handler = RangeRequestHandler::new();
        let response = handler.process(Some("bytes=0-499"), 10000).unwrap();
        assert!(response.is_partial);
        assert_eq!(response.ranges.len(), 1);
        assert_eq!(
            response.content_range,
            Some("bytes 0-499/10000".to_string())
        );
    }

    #[test]
    fn test_handler_merge_ranges() {
        let handler = RangeRequestHandler::new();
        let response = handler.process(Some("bytes=0-100,50-150"), 10000).unwrap();
        // Should merge into single range
        assert_eq!(response.ranges.len(), 1);
        assert_eq!(response.ranges[0].start, 0);
        assert_eq!(response.ranges[0].end, 150);
    }

    #[test]
    fn test_handler_stats() {
        let handler = RangeRequestHandler::new();
        handler.process(Some("bytes=0-499"), 10000).unwrap();
        handler.process(Some("bytes=500-999"), 10000).unwrap();

        let stats = handler.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.single_range_requests, 2);
        assert_eq!(stats.total_bytes_served, 1000);
    }

    #[test]
    fn test_total_bytes() {
        let request = RangeRequest::parse("bytes=0-499,1000-1499", 10000).unwrap();
        let total = request.total_bytes(10000).unwrap();
        assert_eq!(total, 1000);
    }

    #[test]
    fn test_content_range_header() {
        let response = RangeResponse {
            ranges: vec![ByteRange::new(0, 499).unwrap()],
            content_length: 10000,
            is_partial: true,
            content_range: Some("bytes 0-499/10000".to_string()),
        };

        assert_eq!(
            response.content_range_header(),
            Some("bytes 0-499/10000".to_string())
        );
    }

    #[test]
    fn test_max_ranges_limit() {
        let handler = RangeRequestHandler::with_config(1024, 2);
        let result = handler.process(Some("bytes=0-100,200-300,400-500"), 10000);
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_stats() {
        let handler = RangeRequestHandler::new();
        handler.process(Some("bytes=0-499"), 10000).unwrap();
        handler.reset_stats();

        let stats = handler.stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_bytes_served, 0);
    }
}
