//! Error types for CHIE Protocol.

use crate::ValidationError;
use thiserror::Error;

/// Protocol-level errors.
///
/// # Examples
///
/// ```
/// use chie_shared::ProtocolError;
///
/// // Network error example
/// fn connect_to_peer(peer_id: &str) -> Result<(), ProtocolError> {
///     if peer_id.is_empty() {
///         return Err(ProtocolError::PeerNotFound("empty peer ID".to_string()));
///     }
///     Ok(())
/// }
///
/// // Content lookup error
/// fn get_content(cid: &str) -> Result<Vec<u8>, ProtocolError> {
///     if cid.starts_with("Qm") {
///         Ok(vec![1, 2, 3])
///     } else {
///         Err(ProtocolError::ContentNotFound(cid.to_string()))
///     }
/// }
///
/// // Rate limiting
/// fn check_rate_limit(request_count: u32) -> Result<(), ProtocolError> {
///     if request_count > 100 {
///         Err(ProtocolError::RateLimitExceeded)
///     } else {
///         Ok(())
///     }
/// }
///
/// assert!(connect_to_peer("12D3Koo").is_ok());
/// assert!(get_content("QmTest").is_ok());
/// assert!(check_rate_limit(50).is_ok());
/// assert!(check_rate_limit(150).is_err());
/// ```
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Nonce already used (replay attack detected)")]
    NonceReused,

    #[error("Timestamp out of valid range")]
    TimestampOutdated,

    #[error("Content not found: {0}")]
    ContentNotFound(String),

    #[error("Chunk not found: index {0}")]
    ChunkNotFound(u64),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Insufficient storage space")]
    InsufficientStorage,

    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl From<ValidationError> for ProtocolError {
    fn from(err: ValidationError) -> Self {
        ProtocolError::ValidationError(err.to_string())
    }
}

/// Verification errors.
///
/// # Examples
///
/// ```
/// use chie_shared::VerificationError;
///
/// // Signature verification
/// fn verify_proof_signature(signature: &[u8]) -> Result<(), VerificationError> {
///     if signature.len() != 64 {
///         return Err(VerificationError::InvalidProviderSignature);
///     }
///     if signature.iter().all(|&b| b == 0) {
///         return Err(VerificationError::InvalidProviderSignature);
///     }
///     Ok(())
/// }
///
/// // Nonce validation
/// fn check_nonce(nonce: &str, used_nonces: &[&str]) -> Result<(), VerificationError> {
///     if used_nonces.contains(&nonce) {
///         Err(VerificationError::NonceReused)
///     } else {
///         Ok(())
///     }
/// }
///
/// // Latency check
/// fn validate_latency(latency_ms: u32) -> Result<(), VerificationError> {
///     if latency_ms > 5000 {
///         Err(VerificationError::InvalidLatency(latency_ms))
///     } else {
///         Ok(())
///     }
/// }
///
/// assert!(verify_proof_signature(&[1u8; 64]).is_ok());
/// assert!(verify_proof_signature(&[0u8; 64]).is_err());
/// assert!(check_nonce("abc123", &[]).is_ok());
/// assert!(check_nonce("abc123", &["abc123"]).is_err());
/// assert!(validate_latency(100).is_ok());
/// assert!(validate_latency(6000).is_err());
/// ```
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid provider signature")]
    InvalidProviderSignature,

    #[error("Invalid requester signature")]
    InvalidRequesterSignature,

    #[error("Nonce has already been used")]
    NonceReused,

    #[error("Timestamp is too old or in the future")]
    TimestampOutOfRange,

    #[error("Statistical anomaly detected: {0}")]
    AnomalyDetected(String),

    #[error("Peer is banned: {0}")]
    PeerBanned(String),

    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),

    #[error("Challenge nonce mismatch")]
    ChallengeMismatch,

    #[error("Chunk hash mismatch")]
    ChunkHashMismatch,

    #[error("Invalid latency: {0}ms")]
    InvalidLatency(u32),

    #[error("Blacklisted peer: {0}")]
    BlacklistedPeer(String),
}

impl From<ValidationError> for VerificationError {
    fn from(err: ValidationError) -> Self {
        VerificationError::InvalidProofStructure(err.to_string())
    }
}

/// Reward calculation errors.
///
/// # Examples
///
/// ```
/// use chie_shared::RewardError;
///
/// // Content registration check
/// fn calculate_reward(content_cid: &str, registered: bool) -> Result<u64, RewardError> {
///     if !registered {
///         return Err(RewardError::ContentNotRegistered(content_cid.to_string()));
///     }
///     Ok(100) // 100 points
/// }
///
/// // Balance check
/// fn withdraw_points(amount: u64, balance: u64) -> Result<u64, RewardError> {
///     if amount > balance {
///         Err(RewardError::InsufficientBalance)
///     } else {
///         Ok(balance - amount)
///     }
/// }
///
/// // Reward amount validation
/// fn validate_reward(amount: u64) -> Result<u64, RewardError> {
///     if amount > 1_000_000 {
///         Err(RewardError::InvalidRewardAmount(amount))
///     } else {
///         Ok(amount)
///     }
/// }
///
/// assert_eq!(calculate_reward("QmTest", true).unwrap(), 100);
/// assert!(calculate_reward("QmTest", false).is_err());
/// assert_eq!(withdraw_points(50, 100).unwrap(), 50);
/// assert!(withdraw_points(150, 100).is_err());
/// assert!(validate_reward(500).is_ok());
/// assert!(validate_reward(2_000_000).is_err());
/// ```
#[derive(Debug, Error)]
pub enum RewardError {
    #[error("Content not registered: {0}")]
    ContentNotRegistered(String),

    #[error("Invalid proof data")]
    InvalidProof,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Calculation failed: {0}")]
    CalculationFailed(String),

    #[error("Insufficient points balance")]
    InsufficientBalance,

    #[error("Creator not found: {0}")]
    CreatorNotFound(String),

    #[error("Invalid reward amount: {0}")]
    InvalidRewardAmount(u64),

    #[error("Reward distribution failed: {0}")]
    DistributionFailed(String),
}

/// Result type alias for protocol operations.
///
/// # Examples
///
/// ```
/// use chie_shared::{ProtocolResult, ProtocolError};
///
/// fn fetch_content(cid: &str) -> ProtocolResult<Vec<u8>> {
///     if cid.is_empty() {
///         return Err(ProtocolError::ContentNotFound("empty CID".to_string()));
///     }
///     Ok(vec![1, 2, 3, 4])
/// }
///
/// // Using the result
/// match fetch_content("QmTest") {
///     Ok(data) => assert_eq!(data.len(), 4),
///     Err(e) => panic!("Unexpected error: {}", e),
/// }
///
/// // Error case
/// assert!(fetch_content("").is_err());
/// ```
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Result type alias for verification operations.
///
/// # Examples
///
/// ```
/// use chie_shared::{VerificationResult, VerificationError};
///
/// fn verify_bandwidth_proof(latency_ms: u32) -> VerificationResult<()> {
///     if latency_ms > 5000 {
///         return Err(VerificationError::InvalidLatency(latency_ms));
///     }
///     Ok(())
/// }
///
/// // Chain operations
/// fn verify_and_process(latency: u32) -> VerificationResult<String> {
///     verify_bandwidth_proof(latency)?;
///     Ok("Proof verified".to_string())
/// }
///
/// assert!(verify_and_process(100).is_ok());
/// assert!(verify_and_process(6000).is_err());
/// ```
pub type VerificationResult<T> = Result<T, VerificationError>;

/// Result type alias for reward operations.
///
/// # Examples
///
/// ```
/// use chie_shared::{RewardResult, RewardError};
///
/// fn distribute_reward(provider_id: &str, amount: u64) -> RewardResult<u64> {
///     if amount > 1_000_000 {
///         return Err(RewardError::InvalidRewardAmount(amount));
///     }
///     Ok(amount)
/// }
///
/// // Combine multiple operations
/// fn process_rewards(providers: &[&str], amount: u64) -> RewardResult<u64> {
///     let mut total = 0;
///     for provider in providers {
///         total += distribute_reward(provider, amount)?;
///     }
///     Ok(total)
/// }
///
/// assert_eq!(distribute_reward("peer1", 100).unwrap(), 100);
/// assert_eq!(process_rewards(&["peer1", "peer2"], 100).unwrap(), 200);
/// assert!(distribute_reward("peer1", 2_000_000).is_err());
/// ```
pub type RewardResult<T> = Result<T, RewardError>;

/// Content validation errors.
///
/// # Examples
///
/// ```
/// use chie_shared::ContentValidationError;
///
/// // Content size validation
/// fn validate_content_size(size: u64) -> Result<(), ContentValidationError> {
///     const MAX_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
///     const MIN_SIZE: u64 = 1024; // 1 KB
///
///     if size > MAX_SIZE {
///         return Err(ContentValidationError::ContentTooLarge {
///             size,
///             max: MAX_SIZE,
///         });
///     }
///     if size < MIN_SIZE {
///         return Err(ContentValidationError::ContentTooSmall {
///             size,
///             min: MIN_SIZE,
///         });
///     }
///     Ok(())
/// }
///
/// // Chunk index validation
/// fn validate_chunk_index(index: u64, total_chunks: u64) -> Result<(), ContentValidationError> {
///     if index >= total_chunks {
///         Err(ContentValidationError::InvalidChunkIndex {
///             index,
///             total: total_chunks,
///         })
///     } else {
///         Ok(())
///     }
/// }
///
/// // Signature length validation
/// fn validate_signature(sig: &[u8]) -> Result<(), ContentValidationError> {
///     if sig.len() != 64 {
///         Err(ContentValidationError::InvalidSignatureLength {
///             expected: 64,
///             actual: sig.len(),
///         })
///     } else {
///         Ok(())
///     }
/// }
///
/// assert!(validate_content_size(50 * 1024).is_ok());
/// assert!(validate_content_size(500).is_err()); // Too small
/// assert!(validate_content_size(200 * 1024 * 1024).is_err()); // Too large
/// assert!(validate_chunk_index(5, 10).is_ok());
/// assert!(validate_chunk_index(15, 10).is_err());
/// assert!(validate_signature(&[0u8; 64]).is_ok());
/// assert!(validate_signature(&[0u8; 32]).is_err());
/// ```
#[derive(Debug, Error)]
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

    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("Invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },
}

/// Result type alias for content validation operations.
pub type ContentValidationResult<T> = Result<T, ContentValidationError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_error_display() {
        assert_eq!(
            ProtocolError::InvalidSignature.to_string(),
            "Invalid signature"
        );

        assert_eq!(
            ProtocolError::NonceReused.to_string(),
            "Nonce already used (replay attack detected)"
        );

        assert_eq!(
            ProtocolError::TimestampOutdated.to_string(),
            "Timestamp out of valid range"
        );

        assert_eq!(
            ProtocolError::ContentNotFound("QmTest123".to_string()).to_string(),
            "Content not found: QmTest123"
        );

        assert_eq!(
            ProtocolError::ChunkNotFound(42).to_string(),
            "Chunk not found: index 42"
        );

        assert_eq!(
            ProtocolError::EncryptionError("Key error".to_string()).to_string(),
            "Encryption error: Key error"
        );

        assert_eq!(
            ProtocolError::DecryptionError("Invalid data".to_string()).to_string(),
            "Decryption error: Invalid data"
        );

        assert_eq!(
            ProtocolError::NetworkError("Connection timeout".to_string()).to_string(),
            "Network error: Connection timeout"
        );

        assert_eq!(
            ProtocolError::DatabaseError("Query failed".to_string()).to_string(),
            "Database error: Query failed"
        );
    }

    #[test]
    fn test_verification_error_display() {
        assert_eq!(
            VerificationError::InvalidProviderSignature.to_string(),
            "Invalid provider signature"
        );

        assert_eq!(
            VerificationError::InvalidRequesterSignature.to_string(),
            "Invalid requester signature"
        );

        assert_eq!(
            VerificationError::NonceReused.to_string(),
            "Nonce has already been used"
        );

        assert_eq!(
            VerificationError::TimestampOutOfRange.to_string(),
            "Timestamp is too old or in the future"
        );

        assert_eq!(
            VerificationError::AnomalyDetected("Suspicious pattern".to_string()).to_string(),
            "Statistical anomaly detected: Suspicious pattern"
        );

        assert_eq!(
            VerificationError::PeerBanned("12D3Koo...".to_string()).to_string(),
            "Peer is banned: 12D3Koo..."
        );
    }

    #[test]
    fn test_reward_error_display() {
        assert_eq!(
            RewardError::ContentNotRegistered("QmAbc".to_string()).to_string(),
            "Content not registered: QmAbc"
        );

        assert_eq!(RewardError::InvalidProof.to_string(), "Invalid proof data");

        assert_eq!(
            RewardError::DatabaseError("Connection lost".to_string()).to_string(),
            "Database error: Connection lost"
        );

        assert_eq!(
            RewardError::CalculationFailed("Division by zero".to_string()).to_string(),
            "Calculation failed: Division by zero"
        );
    }

    #[test]
    fn test_error_source() {
        // Errors should be compatible with std::error::Error
        let err = ProtocolError::InvalidSignature;
        let _: &dyn std::error::Error = &err;

        let err = VerificationError::NonceReused;
        let _: &dyn std::error::Error = &err;

        let err = RewardError::InvalidProof;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_new_protocol_errors() {
        assert_eq!(
            ProtocolError::PeerNotFound("peer123".to_string()).to_string(),
            "Peer not found: peer123"
        );
        assert_eq!(
            ProtocolError::InsufficientStorage.to_string(),
            "Insufficient storage space"
        );
        assert_eq!(
            ProtocolError::BandwidthLimitExceeded.to_string(),
            "Bandwidth limit exceeded"
        );
        assert_eq!(
            ProtocolError::RateLimitExceeded.to_string(),
            "Rate limit exceeded"
        );
    }

    #[test]
    fn test_new_verification_errors() {
        assert_eq!(
            VerificationError::ChallengeMismatch.to_string(),
            "Challenge nonce mismatch"
        );
        assert_eq!(
            VerificationError::ChunkHashMismatch.to_string(),
            "Chunk hash mismatch"
        );
        assert_eq!(
            VerificationError::InvalidLatency(5000).to_string(),
            "Invalid latency: 5000ms"
        );
    }

    #[test]
    fn test_new_reward_errors() {
        assert_eq!(
            RewardError::InsufficientBalance.to_string(),
            "Insufficient points balance"
        );
        assert_eq!(
            RewardError::CreatorNotFound("creator123".to_string()).to_string(),
            "Creator not found: creator123"
        );
        assert_eq!(
            RewardError::InvalidRewardAmount(9999).to_string(),
            "Invalid reward amount: 9999"
        );
    }

    #[test]
    fn test_validation_error_conversion() {
        use crate::ValidationError;

        let val_err = ValidationError::EmptyCid;
        let proto_err: ProtocolError = val_err.into();
        assert!(
            proto_err
                .to_string()
                .contains("Content CID cannot be empty")
        );

        let val_err2 = ValidationError::SelfTransfer;
        let verif_err: VerificationError = val_err2.into();
        assert!(
            verif_err
                .to_string()
                .contains("Provider and requester cannot be the same")
        );
    }

    #[test]
    fn test_result_type_aliases() {
        fn test_protocol_result() -> ProtocolResult<String> {
            Ok("success".to_string())
        }

        fn test_verification_result() -> VerificationResult<i32> {
            Err(VerificationError::NonceReused)
        }

        fn test_reward_result() -> RewardResult<u64> {
            Ok(1000)
        }

        assert!(test_protocol_result().is_ok());
        assert!(test_verification_result().is_err());
        assert_eq!(test_reward_result().unwrap(), 1000);
    }

    #[test]
    fn test_content_validation_error_display() {
        assert_eq!(
            ContentValidationError::InvalidContentSize(1000).to_string(),
            "Invalid content size: 1000 bytes"
        );

        assert_eq!(
            ContentValidationError::InvalidChunkIndex { index: 5, total: 3 }.to_string(),
            "Invalid chunk index: 5 out of 3"
        );

        assert_eq!(
            ContentValidationError::InvalidTimestamp("future timestamp".to_string()).to_string(),
            "Invalid timestamp: future timestamp"
        );

        assert_eq!(
            ContentValidationError::InvalidSignatureLength {
                expected: 64,
                actual: 32
            }
            .to_string(),
            "Invalid signature length: expected 64, got 32"
        );

        assert_eq!(
            ContentValidationError::ContentTooLarge {
                size: 1_000_000_000,
                max: 500_000_000
            }
            .to_string(),
            "Content too large: 1000000000 bytes exceeds max 500000000 bytes"
        );
    }

    #[test]
    fn test_content_validation_result() {
        fn validate_size(size: u64) -> ContentValidationResult<u64> {
            if size > 1000 {
                Err(ContentValidationError::ContentTooLarge { size, max: 1000 })
            } else {
                Ok(size)
            }
        }

        assert!(validate_size(500).is_ok());
        assert!(validate_size(2000).is_err());
    }
}
