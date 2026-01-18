//! Bandwidth proof protocol implementation.

use chie_shared::{BandwidthProof, ChunkRequest, ChunkResponse};
use rand::RngCore;
use thiserror::Error;
use uuid::Uuid;

/// Protocol validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid content CID: {0}")]
    InvalidCid(String),

    #[error("Invalid chunk index: {0}")]
    InvalidChunkIndex(String),

    #[error("Invalid latency: {0}")]
    InvalidLatency(String),

    #[error("Timestamp out of range: {0}")]
    TimestampOutOfRange(String),
}

/// Generate a challenge nonce for a chunk request.
///
/// # Examples
///
/// ```
/// use chie_core::protocol::generate_challenge_nonce;
///
/// let nonce = generate_challenge_nonce();
/// assert_eq!(nonce.len(), 32);
/// ```
#[must_use]
pub fn generate_challenge_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Create a new chunk request.
#[must_use]
pub fn create_chunk_request(
    content_cid: String,
    chunk_index: u64,
    requester_peer_id: String,
    requester_public_key: [u8; 32],
) -> ChunkRequest {
    ChunkRequest {
        content_cid,
        chunk_index,
        challenge_nonce: generate_challenge_nonce(),
        requester_peer_id,
        requester_public_key,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    }
}

/// Create a bandwidth proof from a completed transfer.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn create_bandwidth_proof(
    request: &ChunkRequest,
    provider_peer_id: String,
    provider_public_key: Vec<u8>,
    bytes_transferred: u64,
    provider_signature: Vec<u8>,
    requester_signature: Vec<u8>,
    chunk_hash: Vec<u8>,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    latency_ms: u32,
) -> BandwidthProof {
    BandwidthProof {
        session_id: Uuid::new_v4(),
        content_cid: request.content_cid.clone(),
        chunk_index: request.chunk_index,
        bytes_transferred,
        provider_peer_id,
        requester_peer_id: request.requester_peer_id.clone(),
        provider_public_key,
        requester_public_key: request.requester_public_key.to_vec(),
        provider_signature,
        requester_signature,
        challenge_nonce: request.challenge_nonce.to_vec(),
        chunk_hash,
        start_timestamp_ms,
        end_timestamp_ms,
        latency_ms,
    }
}

/// Validate a chunk request.
pub fn validate_chunk_request(request: &ChunkRequest) -> Result<(), ValidationError> {
    // Validate CID format (basic check)
    if request.content_cid.is_empty() {
        return Err(ValidationError::InvalidCid(
            "CID cannot be empty".to_string(),
        ));
    }

    // Validate nonce
    if request.challenge_nonce == [0u8; 32] {
        return Err(ValidationError::InvalidNonce(
            "Nonce cannot be all zeros".to_string(),
        ));
    }

    // Validate timestamp (within reasonable range)
    let now = chrono::Utc::now().timestamp_millis();
    let five_minutes = 5 * 60 * 1000;

    if request.timestamp_ms > now + five_minutes {
        return Err(ValidationError::TimestampOutOfRange(
            "Request timestamp is too far in the future".to_string(),
        ));
    }

    if request.timestamp_ms < now - five_minutes {
        return Err(ValidationError::TimestampOutOfRange(
            "Request timestamp is too old".to_string(),
        ));
    }

    // Validate peer ID
    if request.requester_peer_id.is_empty() {
        return Err(ValidationError::InvalidSignature(
            "Requester peer ID cannot be empty".to_string(),
        ));
    }

    Ok(())
}

/// Validate a chunk response.
pub fn validate_chunk_response(
    response: &ChunkResponse,
    request: &ChunkRequest,
) -> Result<(), ValidationError> {
    // Validate challenge echo
    if response.challenge_echo != request.challenge_nonce {
        return Err(ValidationError::InvalidNonce(
            "Challenge echo does not match request nonce".to_string(),
        ));
    }

    // Validate encrypted chunk is not empty
    if response.encrypted_chunk.is_empty() {
        return Err(ValidationError::InvalidSignature(
            "Encrypted chunk cannot be empty".to_string(),
        ));
    }

    // Validate chunk hash
    if response.chunk_hash == [0u8; 32] {
        return Err(ValidationError::InvalidSignature(
            "Chunk hash cannot be all zeros".to_string(),
        ));
    }

    // Validate signature
    if response.provider_signature.is_empty() {
        return Err(ValidationError::InvalidSignature(
            "Provider signature cannot be empty".to_string(),
        ));
    }

    // Validate timestamp
    let now = chrono::Utc::now().timestamp_millis();
    if response.timestamp_ms > now {
        return Err(ValidationError::TimestampOutOfRange(
            "Response timestamp is in the future".to_string(),
        ));
    }

    Ok(())
}

/// Validate a bandwidth proof.
pub fn validate_bandwidth_proof(proof: &BandwidthProof) -> Result<(), ValidationError> {
    // Validate CID
    if proof.content_cid.is_empty() {
        return Err(ValidationError::InvalidCid(
            "CID cannot be empty".to_string(),
        ));
    }

    // Validate nonce
    if proof.challenge_nonce.is_empty() || proof.challenge_nonce == vec![0u8; 32] {
        return Err(ValidationError::InvalidNonce(
            "Invalid challenge nonce".to_string(),
        ));
    }

    // Validate signatures
    if proof.provider_signature.is_empty() {
        return Err(ValidationError::InvalidSignature(
            "Provider signature is empty".to_string(),
        ));
    }

    if proof.requester_signature.is_empty() {
        return Err(ValidationError::InvalidSignature(
            "Requester signature is empty".to_string(),
        ));
    }

    // Validate public keys
    if proof.provider_public_key.len() != 32 {
        return Err(ValidationError::InvalidSignature(
            "Invalid provider public key length".to_string(),
        ));
    }

    if proof.requester_public_key.len() != 32 {
        return Err(ValidationError::InvalidSignature(
            "Invalid requester public key length".to_string(),
        ));
    }

    // Validate timestamps
    if proof.start_timestamp_ms >= proof.end_timestamp_ms {
        return Err(ValidationError::InvalidTimestamp(
            "Start timestamp must be before end timestamp".to_string(),
        ));
    }

    // Validate latency is reasonable
    let duration_ms = (proof.end_timestamp_ms - proof.start_timestamp_ms) as u32;
    if proof.latency_ms > duration_ms {
        return Err(ValidationError::InvalidLatency(
            "Latency cannot exceed transfer duration".to_string(),
        ));
    }

    // Validate bytes transferred
    if proof.bytes_transferred == 0 {
        return Err(ValidationError::InvalidSignature(
            "Bytes transferred cannot be zero".to_string(),
        ));
    }

    Ok(())
}

/// Check if a CID format is valid (basic validation).
#[inline]
#[must_use]
pub fn is_valid_cid(cid: &str) -> bool {
    // Basic CID validation - starts with Qm and has reasonable length
    if cid.is_empty() {
        return false;
    }

    // Check if it's a valid base58 IPFS CID (simplified check)
    if cid.starts_with("Qm") && cid.len() >= 46 {
        return true;
    }

    // Check if it's a CIDv1 format (starts with b, z, f, etc.)
    if cid.len() > 10 && (cid.starts_with('b') || cid.starts_with('z') || cid.starts_with('f')) {
        return true;
    }

    false
}

/// Verify nonce uniqueness (in production, this would check against a database).
#[inline]
#[must_use]
#[allow(dead_code)]
pub fn is_nonce_unique(_nonce: &[u8], _peer_id: &str) -> bool {
    // In production, this would check against a nonce cache/database
    // For now, we assume all nonces are unique
    true
}

/// Calculate expected latency from timestamps.
#[inline]
pub const fn calculate_latency(start_ms: i64, end_ms: i64) -> u32 {
    let diff = end_ms.saturating_sub(start_ms);
    if diff < 0 { 0 } else { diff as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chie_crypto::KeyPair;

    #[test]
    fn test_generate_challenge_nonce() {
        let nonce1 = generate_challenge_nonce();
        let nonce2 = generate_challenge_nonce();

        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_create_chunk_request() {
        let keypair = KeyPair::generate();
        let request = create_chunk_request(
            "QmTest123".to_string(),
            5,
            "peer-abc".to_string(),
            keypair.public_key(),
        );

        assert_eq!(request.content_cid, "QmTest123");
        assert_eq!(request.chunk_index, 5);
        assert_eq!(request.requester_peer_id, "peer-abc");
        assert_eq!(request.challenge_nonce.len(), 32);
    }

    #[test]
    fn test_validate_chunk_request() {
        let keypair = KeyPair::generate();
        let request = create_chunk_request(
            "QmTest".to_string(),
            0,
            "peer".to_string(),
            keypair.public_key(),
        );

        assert!(validate_chunk_request(&request).is_ok());

        // Test empty CID
        let mut bad_request = request.clone();
        bad_request.content_cid = String::new();
        assert!(validate_chunk_request(&bad_request).is_err());

        // Test zero nonce
        let mut bad_request = request;
        bad_request.challenge_nonce = [0u8; 32];
        assert!(validate_chunk_request(&bad_request).is_err());
    }

    #[test]
    fn test_validate_bandwidth_proof() {
        let keypair = KeyPair::generate();
        let request = create_chunk_request(
            "QmTest".to_string(),
            0,
            "peer".to_string(),
            keypair.public_key(),
        );

        let proof = create_bandwidth_proof(
            &request,
            "provider".to_string(),
            vec![1u8; 32],
            1024,
            vec![1u8; 64],
            vec![2u8; 64],
            vec![3u8; 32],
            1000,
            2000,
            100,
        );

        assert!(validate_bandwidth_proof(&proof).is_ok());
    }

    #[test]
    fn test_is_valid_cid() {
        assert!(is_valid_cid(
            "QmTest1234567890123456789012345678901234567890"
        ));
        assert!(is_valid_cid(
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        ));
        assert!(!is_valid_cid(""));
        assert!(!is_valid_cid("invalid"));
    }

    #[test]
    fn test_calculate_latency() {
        assert_eq!(calculate_latency(1000, 1500), 500);
        assert_eq!(calculate_latency(2000, 2000), 0);
        assert_eq!(calculate_latency(2000, 1500), 0); // Handles negative
    }
}
