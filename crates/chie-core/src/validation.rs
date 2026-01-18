//! Content validation utilities for CHIE Protocol.
//!
//! This module provides comprehensive validation functions for content,
//! chunks, proofs, and other protocol elements.

use chie_shared::{BandwidthProof, CHUNK_SIZE, ChunkRequest, ChunkResponse};
use std::time::{Duration, SystemTime};

/// Content validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ContentValidationError {
    #[error("Invalid content size: {0} bytes")]
    InvalidContentSize(u64),

    #[error("Invalid chunk index: {index} out of {total}")]
    InvalidChunkIndex { index: u64, total: u64 },

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },

    #[error("Invalid bandwidth value: {0}")]
    InvalidBandwidth(String),

    #[error("Content too large: {size} bytes exceeds max {max} bytes")]
    ContentTooLarge { size: u64, max: u64 },

    #[error("Content too small: {size} bytes is below min {min} bytes")]
    ContentTooSmall { size: u64, min: u64 },
}

/// Content size limits.
pub struct ContentLimits {
    /// Minimum content size (1 KB).
    pub min_size: u64,
    /// Maximum content size (10 GB).
    pub max_size: u64,
    /// Maximum chunks per content.
    pub max_chunks: u64,
}

impl Default for ContentLimits {
    fn default() -> Self {
        Self {
            min_size: 1024,                    // 1 KB
            max_size: 10 * 1024 * 1024 * 1024, // 10 GB
            max_chunks: 100_000,               // ~400 GB at 4MB chunks
        }
    }
}

/// Validate content size against limits.
#[inline]
pub fn validate_content_size(
    size: u64,
    limits: &ContentLimits,
) -> Result<(), ContentValidationError> {
    if size < limits.min_size {
        return Err(ContentValidationError::ContentTooSmall {
            size,
            min: limits.min_size,
        });
    }

    if size > limits.max_size {
        return Err(ContentValidationError::ContentTooLarge {
            size,
            max: limits.max_size,
        });
    }

    Ok(())
}

/// Validate chunk index is within bounds.
#[inline]
pub fn validate_chunk_index(
    chunk_index: u64,
    total_chunks: u64,
) -> Result<(), ContentValidationError> {
    if chunk_index >= total_chunks {
        return Err(ContentValidationError::InvalidChunkIndex {
            index: chunk_index,
            total: total_chunks,
        });
    }

    Ok(())
}

/// Validate chunk request timestamp is within acceptable window.
#[inline]
pub fn validate_request_timestamp(
    request: &ChunkRequest,
    max_age: Duration,
) -> Result<(), ContentValidationError> {
    let now = SystemTime::now();
    let request_time = SystemTime::UNIX_EPOCH + Duration::from_millis(request.timestamp_ms as u64);

    let age = now.duration_since(request_time).map_err(|_| {
        ContentValidationError::InvalidTimestamp("Request timestamp is in the future".to_string())
    })?;

    if age > max_age {
        return Err(ContentValidationError::InvalidTimestamp(format!(
            "Request is too old: {:?} > {:?}",
            age, max_age
        )));
    }

    Ok(())
}

/// Validate chunk response has proper signature length.
#[inline]
pub fn validate_response_signature(response: &ChunkResponse) -> Result<(), ContentValidationError> {
    // Ed25519 signatures are 64 bytes
    const ED25519_SIG_LEN: usize = 64;

    if response.provider_signature.len() != ED25519_SIG_LEN {
        return Err(ContentValidationError::InvalidSignatureLength {
            expected: ED25519_SIG_LEN,
            actual: response.provider_signature.len(),
        });
    }

    if response.provider_public_key.len() != 32 {
        return Err(ContentValidationError::InvalidPublicKeyLength {
            expected: 32,
            actual: response.provider_public_key.len(),
        });
    }

    Ok(())
}

/// Validate bandwidth proof structure.
#[inline]
pub fn validate_proof_structure(proof: &BandwidthProof) -> Result<(), ContentValidationError> {
    // Validate signature lengths
    const ED25519_SIG_LEN: usize = 64;
    const ED25519_KEY_LEN: usize = 32;

    if proof.provider_signature.len() != ED25519_SIG_LEN {
        return Err(ContentValidationError::InvalidSignatureLength {
            expected: ED25519_SIG_LEN,
            actual: proof.provider_signature.len(),
        });
    }

    if proof.requester_signature.len() != ED25519_SIG_LEN {
        return Err(ContentValidationError::InvalidSignatureLength {
            expected: ED25519_SIG_LEN,
            actual: proof.requester_signature.len(),
        });
    }

    if proof.provider_public_key.len() != ED25519_KEY_LEN {
        return Err(ContentValidationError::InvalidPublicKeyLength {
            expected: ED25519_KEY_LEN,
            actual: proof.provider_public_key.len(),
        });
    }

    if proof.requester_public_key.len() != ED25519_KEY_LEN {
        return Err(ContentValidationError::InvalidPublicKeyLength {
            expected: ED25519_KEY_LEN,
            actual: proof.requester_public_key.len(),
        });
    }

    // Validate timestamps
    if proof.start_timestamp_ms >= proof.end_timestamp_ms {
        return Err(ContentValidationError::InvalidTimestamp(
            "Start timestamp must be before end timestamp".to_string(),
        ));
    }

    // Validate bytes transferred
    if proof.bytes_transferred == 0 {
        return Err(ContentValidationError::InvalidBandwidth(
            "Bytes transferred cannot be zero".to_string(),
        ));
    }

    Ok(())
}

/// Calculate expected number of chunks for content.
#[must_use]
#[inline]
pub const fn calculate_expected_chunks(content_size: u64) -> u64 {
    let chunks = content_size / CHUNK_SIZE as u64;
    let remainder = content_size % CHUNK_SIZE as u64;

    if remainder > 0 {
        chunks + 1
    } else if chunks == 0 {
        1
    } else {
        chunks
    }
}

/// Validate bandwidth calculation is reasonable.
#[inline]
pub fn validate_bandwidth(
    bytes: u64,
    duration_ms: u64,
    max_bandwidth_mbps: f64,
) -> Result<(), ContentValidationError> {
    if duration_ms == 0 {
        return Err(ContentValidationError::InvalidBandwidth(
            "Duration cannot be zero".to_string(),
        ));
    }

    // Calculate bandwidth in Mbps
    let bits = bytes as f64 * 8.0;
    let seconds = duration_ms as f64 / 1000.0;
    let mbps = bits / seconds / 1_000_000.0;

    // Check if bandwidth is suspiciously high (> 10 Gbps or specified max)
    let max_mbps = max_bandwidth_mbps.max(10_000.0);
    if mbps > max_mbps {
        return Err(ContentValidationError::InvalidBandwidth(format!(
            "Bandwidth {:.2} Mbps exceeds maximum {:.2} Mbps",
            mbps, max_mbps
        )));
    }

    Ok(())
}

/// Sanitize content ID (CID) for safe filesystem usage.
#[must_use]
#[inline]
pub fn sanitize_cid(cid: &str) -> String {
    // Remove any characters that might be problematic for filesystems
    cid.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chie_crypto::KeyPair;
    use chie_shared::ChunkRequest;

    #[test]
    fn test_validate_content_size() {
        let limits = ContentLimits::default();

        // Valid size
        assert!(validate_content_size(1024 * 1024, &limits).is_ok());

        // Too small
        assert!(validate_content_size(512, &limits).is_err());

        // Too large
        assert!(validate_content_size(20 * 1024 * 1024 * 1024, &limits).is_err());
    }

    #[test]
    fn test_validate_chunk_index() {
        assert!(validate_chunk_index(0, 10).is_ok());
        assert!(validate_chunk_index(9, 10).is_ok());
        assert!(validate_chunk_index(10, 10).is_err());
        assert!(validate_chunk_index(100, 10).is_err());
    }

    #[test]
    fn test_validate_request_timestamp() {
        let keypair = KeyPair::generate();
        let request = ChunkRequest {
            content_cid: "QmTest".to_string(),
            chunk_index: 0,
            challenge_nonce: [1u8; 32],
            requester_peer_id: "peer1".to_string(),
            requester_public_key: keypair.public_key(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };

        // Should be valid within 5 minutes
        assert!(validate_request_timestamp(&request, Duration::from_secs(300)).is_ok());

        // Old request
        let old_request = ChunkRequest {
            timestamp_ms: chrono::Utc::now().timestamp_millis() - 600_000, // 10 minutes ago
            ..request
        };
        assert!(validate_request_timestamp(&old_request, Duration::from_secs(300)).is_err());
    }

    #[test]
    fn test_calculate_expected_chunks() {
        assert_eq!(calculate_expected_chunks(0), 1);
        assert_eq!(calculate_expected_chunks(CHUNK_SIZE as u64), 1);
        assert_eq!(calculate_expected_chunks(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(calculate_expected_chunks(CHUNK_SIZE as u64 * 10), 10);
        assert_eq!(calculate_expected_chunks(CHUNK_SIZE as u64 * 10 + 100), 11);
    }

    #[test]
    fn test_validate_bandwidth() {
        // Valid bandwidth: 100 MB in 10 seconds = 80 Mbps
        assert!(validate_bandwidth(100_000_000, 10_000, 10_000.0).is_ok());

        // Zero duration
        assert!(validate_bandwidth(100_000_000, 0, 10_000.0).is_err());

        // Suspiciously high bandwidth: 10 GB in 1 second = 80 Gbps
        assert!(validate_bandwidth(10_000_000_000, 1_000, 10_000.0).is_err());
    }

    #[test]
    fn test_sanitize_cid() {
        assert_eq!(sanitize_cid("QmTest123"), "QmTest123");
        assert_eq!(sanitize_cid("Qm../../../etc/passwd"), "Qmetcpasswd");
        assert_eq!(sanitize_cid("Qm Test@123!"), "QmTest123");
        assert_eq!(sanitize_cid("valid-cid_123"), "valid-cid_123");
    }

    #[test]
    fn test_validate_response_signature() {
        let valid_response = ChunkResponse {
            encrypted_chunk: vec![1u8; 100],
            chunk_hash: [2u8; 32],
            provider_signature: vec![3u8; 64],
            provider_public_key: [4u8; 32],
            challenge_echo: [5u8; 32],
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };

        assert!(validate_response_signature(&valid_response).is_ok());

        // Invalid signature length
        let invalid_sig = ChunkResponse {
            provider_signature: vec![3u8; 32],
            ..valid_response.clone()
        };
        assert!(validate_response_signature(&invalid_sig).is_err());
    }
}
