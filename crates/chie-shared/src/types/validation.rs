//! Validation types and utilities for CHIE Protocol.

use super::core::*;
use std::fmt;

/// Validation error for proof and content data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Public key has wrong length.
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// Signature has wrong length.
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Nonce has wrong length.
    InvalidNonceLength { expected: usize, actual: usize },
    /// Hash has wrong length.
    InvalidHashLength { expected: usize, actual: usize },
    /// Timestamp is in the future.
    TimestampInFuture { timestamp_ms: i64, now_ms: i64 },
    /// Timestamp is too old.
    TimestampTooOld {
        timestamp_ms: i64,
        now_ms: i64,
        tolerance_ms: i64,
    },
    /// Start timestamp is after end timestamp.
    InvalidTimestampOrder { start_ms: i64, end_ms: i64 },
    /// Latency is suspiciously low.
    LatencyTooLow { latency_ms: u32, min_ms: u32 },
    /// Latency is unreasonably high.
    LatencyTooHigh { latency_ms: u32, max_ms: u32 },
    /// Latency doesn't match timestamps.
    LatencyMismatch {
        calculated_ms: i64,
        reported_ms: u32,
    },
    /// Bytes transferred exceeds maximum.
    BytesExceedMax { bytes: u64, max: u64 },
    /// Provider and requester are the same.
    SelfTransfer,
    /// Content CID is empty.
    EmptyCid,
    /// Content size out of bounds.
    ContentSizeOutOfBounds { size: u64, min: u64, max: u64 },
    /// Title too long.
    TitleTooLong { length: usize, max: usize },
    /// Description too long.
    DescriptionTooLong { length: usize, max: usize },
    /// Too many tags.
    TooManyTags { count: usize, max: usize },
    /// Tag too long.
    TagTooLong {
        tag: String,
        length: usize,
        max: usize,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid public key length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "Invalid signature length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidNonceLength { expected, actual } => {
                write!(f, "Invalid nonce length: expected {expected}, got {actual}")
            }
            Self::InvalidHashLength { expected, actual } => {
                write!(f, "Invalid hash length: expected {expected}, got {actual}")
            }
            Self::TimestampInFuture {
                timestamp_ms,
                now_ms,
            } => {
                write!(
                    f,
                    "Timestamp {timestamp_ms} is in the future (now: {now_ms})"
                )
            }
            Self::TimestampTooOld {
                timestamp_ms,
                now_ms,
                tolerance_ms,
            } => {
                write!(
                    f,
                    "Timestamp {timestamp_ms} is too old (now: {now_ms}, tolerance: {tolerance_ms}ms)"
                )
            }
            Self::InvalidTimestampOrder { start_ms, end_ms } => {
                write!(
                    f,
                    "Start timestamp {start_ms} is after end timestamp {end_ms}"
                )
            }
            Self::LatencyTooLow { latency_ms, min_ms } => {
                write!(f, "Latency {latency_ms}ms is below minimum {min_ms}ms")
            }
            Self::LatencyTooHigh { latency_ms, max_ms } => {
                write!(f, "Latency {latency_ms}ms exceeds maximum {max_ms}ms")
            }
            Self::LatencyMismatch {
                calculated_ms,
                reported_ms,
            } => {
                write!(
                    f,
                    "Reported latency {reported_ms}ms doesn't match calculated {calculated_ms}ms"
                )
            }
            Self::BytesExceedMax { bytes, max } => {
                write!(f, "Bytes transferred {bytes} exceeds maximum {max}")
            }
            Self::SelfTransfer => write!(f, "Provider and requester cannot be the same"),
            Self::EmptyCid => write!(f, "Content CID cannot be empty"),
            Self::ContentSizeOutOfBounds { size, min, max } => {
                write!(f, "Content size {size} is out of bounds [{min}, {max}]")
            }
            Self::TitleTooLong { length, max } => {
                write!(f, "Title length {length} exceeds maximum {max}")
            }
            Self::DescriptionTooLong { length, max } => {
                write!(f, "Description length {length} exceeds maximum {max}")
            }
            Self::TooManyTags { count, max } => {
                write!(f, "Tag count {count} exceeds maximum {max}")
            }
            Self::TagTooLong { tag, length, max } => {
                write!(f, "Tag '{tag}' length {length} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation helpers for common operations.
pub mod helpers {
    use super::*;

    /// Validate a peer ID format.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::EmptyCid` if peer ID is empty or invalid
    pub fn validate_peer_id(peer_id: &str) -> Result<(), ValidationError> {
        if peer_id.is_empty() {
            return Err(ValidationError::EmptyCid); // Reusing error type
        }
        if !crate::utils::is_valid_peer_id(peer_id) {
            return Err(ValidationError::EmptyCid); // Could add specific error
        }
        Ok(())
    }

    /// Validate a content CID format.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::EmptyCid` if CID is empty or invalid
    pub fn validate_cid(cid: &str) -> Result<(), ValidationError> {
        if cid.is_empty() {
            return Err(ValidationError::EmptyCid);
        }
        if !crate::utils::is_valid_cid(cid) {
            return Err(ValidationError::EmptyCid);
        }
        Ok(())
    }

    /// Validate tag length and format.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::TagTooLong` if tag exceeds maximum length
    pub fn validate_tag(tag: &str) -> Result<(), ValidationError> {
        if tag.len() > MAX_TAG_LENGTH {
            return Err(ValidationError::TagTooLong {
                tag: tag.to_string(),
                length: tag.len(),
                max: MAX_TAG_LENGTH,
            });
        }
        Ok(())
    }

    /// Validate all tags in a collection.
    ///
    /// # Errors
    ///
    /// Returns `Vec<ValidationError>` with all validation errors found
    pub fn validate_tags(tags: &[String]) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        if tags.len() > MAX_TAGS_COUNT {
            errors.push(ValidationError::TooManyTags {
                count: tags.len(),
                max: MAX_TAGS_COUNT,
            });
        }

        for tag in tags {
            if let Err(e) = validate_tag(tag) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate content size bounds.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::ContentSizeOutOfBounds` if size is outside allowed range
    pub fn validate_content_size(size: u64) -> Result<(), ValidationError> {
        if !(MIN_CONTENT_SIZE..=MAX_CONTENT_SIZE).contains(&size) {
            return Err(ValidationError::ContentSizeOutOfBounds {
                size,
                min: MIN_CONTENT_SIZE,
                max: MAX_CONTENT_SIZE,
            });
        }
        Ok(())
    }

    /// Validate title length.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::TitleTooLong` if title exceeds maximum length
    pub fn validate_title(title: &str) -> Result<(), ValidationError> {
        if title.len() > MAX_TITLE_LENGTH {
            return Err(ValidationError::TitleTooLong {
                length: title.len(),
                max: MAX_TITLE_LENGTH,
            });
        }
        Ok(())
    }

    /// Validate description length.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::DescriptionTooLong` if description exceeds maximum length
    pub fn validate_description(description: &str) -> Result<(), ValidationError> {
        if description.len() > MAX_DESCRIPTION_LENGTH {
            return Err(ValidationError::DescriptionTooLong {
                length: description.len(),
                max: MAX_DESCRIPTION_LENGTH,
            });
        }
        Ok(())
    }

    /// Batch validate multiple values, collecting all errors.
    pub fn validate_all<T, F>(items: &[T], validator: F) -> Result<(), Vec<ValidationError>>
    where
        F: Fn(&T) -> Result<(), ValidationError>,
    {
        let errors: Vec<ValidationError> = items
            .iter()
            .filter_map(|item| validator(item).err())
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InvalidPublicKeyLength {
            expected: 32,
            actual: 16,
        };
        assert!(err.to_string().contains("Invalid public key length"));

        let err = ValidationError::SelfTransfer;
        assert!(err.to_string().contains("cannot be the same"));

        let err = ValidationError::EmptyCid;
        assert!(err.to_string().contains("cannot be empty"));
    }
}
