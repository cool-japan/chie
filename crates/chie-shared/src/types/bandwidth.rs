//! Bandwidth proof protocol types and validation.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::{
    Bytes, ContentCid, MAX_CONTENT_SIZE, MAX_LATENCY_MS, MIN_LATENCY_MS, PeerIdString,
    TIMESTAMP_TOLERANCE_MS,
};

// Used in tests
#[cfg(test)]
use super::core::CHUNK_SIZE;
use super::validation::ValidationError;

/// Chunk request for bandwidth proof protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ChunkRequest {
    /// IPFS CID of the content.
    pub content_cid: ContentCid,
    /// Index of the requested chunk.
    pub chunk_index: u64,
    /// Random nonce to prevent replay attacks.
    pub challenge_nonce: [u8; 32],
    /// Requester's peer ID.
    pub requester_peer_id: PeerIdString,
    /// Requester's public key for verification.
    pub requester_public_key: [u8; 32],
    /// Request timestamp (Unix timestamp milliseconds).
    pub timestamp_ms: i64,
}

impl ChunkRequest {
    /// Create a new chunk request with current timestamp.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::bandwidth::ChunkRequest;
    ///
    /// let nonce = [42u8; 32];
    /// let pubkey = [1u8; 32];
    ///
    /// let request = ChunkRequest::new(
    ///     "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
    ///     0,
    ///     nonce,
    ///     "12D3KooWRequesterPeerID",
    ///     pubkey,
    /// );
    ///
    /// assert_eq!(request.content_cid, "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    /// assert_eq!(request.chunk_index, 0);
    /// assert!(request.is_timestamp_valid());
    /// ```
    #[must_use]
    pub fn new(
        content_cid: impl Into<String>,
        chunk_index: u64,
        challenge_nonce: [u8; 32],
        requester_peer_id: impl Into<String>,
        requester_public_key: [u8; 32],
    ) -> Self {
        Self {
            content_cid: content_cid.into(),
            chunk_index,
            challenge_nonce,
            requester_peer_id: requester_peer_id.into(),
            requester_public_key,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Check if the request timestamp is still valid.
    #[must_use]
    pub fn is_timestamp_valid(&self) -> bool {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let age_ms = now_ms - self.timestamp_ms;
        (0..=TIMESTAMP_TOLERANCE_MS).contains(&age_ms)
    }
}

/// Chunk response for bandwidth proof protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ChunkResponse {
    /// Encrypted chunk data.
    pub encrypted_chunk: Vec<u8>,
    /// BLAKE3 hash of the chunk (before encryption).
    pub chunk_hash: [u8; 32],
    /// Provider's Ed25519 signature over (`challenge_nonce` || `chunk_hash`).
    pub provider_signature: Vec<u8>,
    /// Provider's public key for verification.
    pub provider_public_key: [u8; 32],
    /// Echo of the challenge nonce.
    pub challenge_echo: [u8; 32],
    /// Response timestamp.
    pub timestamp_ms: i64,
}

impl ChunkResponse {
    /// Create a new chunk response with current timestamp.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::bandwidth::ChunkResponse;
    ///
    /// let encrypted_data = vec![1, 2, 3, 4, 5];
    /// let chunk_hash = [7u8; 32];
    /// let signature = vec![9u8; 64];
    /// let provider_pubkey = [10u8; 32];
    /// let challenge_echo = [42u8; 32];
    ///
    /// let response = ChunkResponse::new(
    ///     encrypted_data.clone(),
    ///     chunk_hash,
    ///     signature,
    ///     provider_pubkey,
    ///     challenge_echo,
    /// );
    ///
    /// assert_eq!(response.chunk_size(), 5);
    /// assert!(response.verify_challenge_echo(&challenge_echo));
    /// ```
    #[must_use]
    pub fn new(
        encrypted_chunk: Vec<u8>,
        chunk_hash: [u8; 32],
        provider_signature: Vec<u8>,
        provider_public_key: [u8; 32],
        challenge_echo: [u8; 32],
    ) -> Self {
        Self {
            encrypted_chunk,
            chunk_hash,
            provider_signature,
            provider_public_key,
            challenge_echo,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Get the size of the encrypted chunk in bytes.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.encrypted_chunk.len()
    }

    /// Verify that the challenge nonce matches the expected value.
    #[must_use]
    pub fn verify_challenge_echo(&self, expected_nonce: &[u8; 32]) -> bool {
        &self.challenge_echo == expected_nonce
    }
}

/// Bandwidth proof submitted to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BandwidthProof {
    /// Unique session identifier.
    pub session_id: uuid::Uuid,
    /// Content CID.
    pub content_cid: ContentCid,
    /// Chunk index transferred.
    pub chunk_index: u64,
    /// Bytes transferred.
    pub bytes_transferred: Bytes,
    /// Provider's peer ID.
    pub provider_peer_id: PeerIdString,
    /// Requester's peer ID.
    pub requester_peer_id: PeerIdString,
    /// Provider's public key.
    pub provider_public_key: Vec<u8>,
    /// Requester's public key.
    pub requester_public_key: Vec<u8>,
    /// Provider's signature over the transfer data.
    pub provider_signature: Vec<u8>,
    /// Requester's signature confirming receipt.
    pub requester_signature: Vec<u8>,
    /// Challenge nonce used.
    pub challenge_nonce: Vec<u8>,
    /// Chunk hash for verification.
    pub chunk_hash: Vec<u8>,
    /// Transfer start timestamp (ms).
    pub start_timestamp_ms: i64,
    /// Transfer end timestamp (ms).
    pub end_timestamp_ms: i64,
    /// Transfer latency in milliseconds.
    pub latency_ms: u32,
}

impl BandwidthProof {
    /// Get the message that was signed by the provider.
    #[must_use]
    pub fn provider_sign_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.challenge_nonce);
        msg.extend_from_slice(&self.chunk_hash);
        msg.extend_from_slice(&self.requester_public_key);
        msg
    }

    /// Get the message that was signed by the requester.
    #[must_use]
    pub fn requester_sign_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.challenge_nonce);
        msg.extend_from_slice(&self.chunk_hash);
        msg.extend_from_slice(&self.provider_public_key);
        msg.extend_from_slice(&self.provider_signature);
        msg
    }

    /// Validate the proof structure (not cryptographic verification).
    ///
    /// # Errors
    ///
    /// Returns validation errors if:
    /// - Public key lengths are not 32 bytes
    /// - Signature lengths are not 64 bytes
    /// - Nonce or hash lengths are not 32 bytes
    /// - Timestamps are invalid or out of range
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::bandwidth::BandwidthProofBuilder;
    ///
    /// // Valid proof
    /// let valid_proof = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .timestamps(1000, 1100)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(valid_proof.validate().is_ok());
    ///
    /// // Invalid proof (wrong signature length)
    /// let invalid_proof = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 32])  // Wrong length!
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .timestamps(1000, 1100)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(invalid_proof.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        // Validate public key lengths
        if self.provider_public_key.len() != 32 {
            errors.push(ValidationError::InvalidPublicKeyLength {
                expected: 32,
                actual: self.provider_public_key.len(),
            });
        }
        if self.requester_public_key.len() != 32 {
            errors.push(ValidationError::InvalidPublicKeyLength {
                expected: 32,
                actual: self.requester_public_key.len(),
            });
        }

        // Validate signature lengths
        if self.provider_signature.len() != 64 {
            errors.push(ValidationError::InvalidSignatureLength {
                expected: 64,
                actual: self.provider_signature.len(),
            });
        }
        if self.requester_signature.len() != 64 {
            errors.push(ValidationError::InvalidSignatureLength {
                expected: 64,
                actual: self.requester_signature.len(),
            });
        }

        // Validate nonce length
        if self.challenge_nonce.len() != 32 {
            errors.push(ValidationError::InvalidNonceLength {
                expected: 32,
                actual: self.challenge_nonce.len(),
            });
        }

        // Validate hash length
        if self.chunk_hash.len() != 32 {
            errors.push(ValidationError::InvalidHashLength {
                expected: 32,
                actual: self.chunk_hash.len(),
            });
        }

        // Validate CID is not empty
        if self.content_cid.is_empty() {
            errors.push(ValidationError::EmptyCid);
        }

        // Validate self-transfer
        if self.provider_peer_id == self.requester_peer_id {
            errors.push(ValidationError::SelfTransfer);
        }

        // Validate timestamp order
        if self.start_timestamp_ms > self.end_timestamp_ms {
            errors.push(ValidationError::InvalidTimestampOrder {
                start_ms: self.start_timestamp_ms,
                end_ms: self.end_timestamp_ms,
            });
        }

        // Validate latency bounds
        if self.latency_ms < MIN_LATENCY_MS {
            errors.push(ValidationError::LatencyTooLow {
                latency_ms: self.latency_ms,
                min_ms: MIN_LATENCY_MS,
            });
        }
        if self.latency_ms > MAX_LATENCY_MS {
            errors.push(ValidationError::LatencyTooHigh {
                latency_ms: self.latency_ms,
                max_ms: MAX_LATENCY_MS,
            });
        }

        // Validate latency matches timestamps (with tolerance)
        let calculated_latency = self.end_timestamp_ms - self.start_timestamp_ms;
        let latency_diff = (calculated_latency - i64::from(self.latency_ms)).abs();
        if latency_diff > 100 {
            // 100ms tolerance for clock skew
            errors.push(ValidationError::LatencyMismatch {
                calculated_ms: calculated_latency,
                reported_ms: self.latency_ms,
            });
        }

        // Validate bytes transferred
        if self.bytes_transferred > MAX_CONTENT_SIZE {
            errors.push(ValidationError::BytesExceedMax {
                bytes: self.bytes_transferred,
                max: MAX_CONTENT_SIZE,
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate timestamp against current time.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError` if:
    /// - Timestamp is in the future
    /// - Timestamp is too old (beyond tolerance window)
    pub fn validate_timestamp(&self, now_ms: i64) -> Result<(), ValidationError> {
        if self.end_timestamp_ms > now_ms {
            return Err(ValidationError::TimestampInFuture {
                timestamp_ms: self.end_timestamp_ms,
                now_ms,
            });
        }
        if now_ms - self.end_timestamp_ms > TIMESTAMP_TOLERANCE_MS {
            return Err(ValidationError::TimestampTooOld {
                timestamp_ms: self.end_timestamp_ms,
                now_ms,
                tolerance_ms: TIMESTAMP_TOLERANCE_MS,
            });
        }
        Ok(())
    }

    /// Check if this proof is valid (basic structural validation).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Calculate the effective bandwidth in bytes per second.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn bandwidth_bps(&self) -> f64 {
        if self.latency_ms == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 * 1000.0) / f64::from(self.latency_ms)
    }

    /// Check if this transfer meets the minimum quality threshold.
    #[must_use]
    /// Latency should be under 500ms for full reward.
    pub fn meets_quality_threshold(&self) -> bool {
        self.latency_ms <= 500
    }

    /// Get a penalty multiplier based on latency (0.5x for high latency).
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::bandwidth::BandwidthProofBuilder;
    ///
    /// // Good quality transfer (low latency)
    /// let fast_proof = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .timestamps(1000, 1200)  // 200ms latency
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(fast_proof.quality_multiplier(), 1.0);
    /// assert!(fast_proof.meets_quality_threshold());
    ///
    /// // Poor quality transfer (high latency)
    /// let slow_proof = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .timestamps(1000, 1800)  // 800ms latency
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(slow_proof.quality_multiplier(), 0.5);
    /// assert!(!slow_proof.meets_quality_threshold());
    /// ```
    #[must_use]
    pub fn quality_multiplier(&self) -> f64 {
        if self.latency_ms <= 500 { 1.0 } else { 0.5 }
    }
}

/// Builder for `BandwidthProof`.
#[derive(Debug, Default)]
pub struct BandwidthProofBuilder {
    session_id: Option<uuid::Uuid>,
    content_cid: Option<ContentCid>,
    chunk_index: u64,
    bytes_transferred: Bytes,
    provider_peer_id: Option<PeerIdString>,
    requester_peer_id: Option<PeerIdString>,
    provider_public_key: Option<Vec<u8>>,
    requester_public_key: Option<Vec<u8>>,
    provider_signature: Option<Vec<u8>>,
    requester_signature: Option<Vec<u8>>,
    challenge_nonce: Option<Vec<u8>>,
    chunk_hash: Option<Vec<u8>>,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    latency_ms: u32,
}

impl BandwidthProofBuilder {
    /// Create a new builder.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::bandwidth::BandwidthProofBuilder;
    ///
    /// let proof = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .chunk_index(0)
    ///     .bytes_transferred(262_144)
    ///     .provider_peer_id("12D3KooWProviderPeerID")
    ///     .requester_peer_id("12D3KooWRequesterPeerID")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .timestamps(1000, 1100)
    ///     .build()
    ///     .expect("Failed to build bandwidth proof");
    ///
    /// assert_eq!(proof.bytes_transferred, 262_144);
    /// assert_eq!(proof.latency_ms, 100);
    /// assert!(proof.is_valid());
    /// assert_eq!(proof.bandwidth_bps(), 2_621_440.0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the session ID (auto-generated if not set).
    #[must_use]
    pub fn session_id(mut self, id: uuid::Uuid) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Set the content CID.
    #[must_use]
    pub fn content_cid(mut self, cid: impl Into<String>) -> Self {
        self.content_cid = Some(cid.into());
        self
    }

    /// Set the chunk index.
    #[must_use]
    pub fn chunk_index(mut self, index: u64) -> Self {
        self.chunk_index = index;
        self
    }

    /// Set bytes transferred.
    #[must_use]
    pub fn bytes_transferred(mut self, bytes: Bytes) -> Self {
        self.bytes_transferred = bytes;
        self
    }

    /// Set provider peer ID.
    #[must_use]
    pub fn provider_peer_id(mut self, peer_id: impl Into<String>) -> Self {
        self.provider_peer_id = Some(peer_id.into());
        self
    }

    /// Set requester peer ID.
    #[must_use]
    pub fn requester_peer_id(mut self, peer_id: impl Into<String>) -> Self {
        self.requester_peer_id = Some(peer_id.into());
        self
    }

    /// Set provider public key.
    #[must_use]
    pub fn provider_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.provider_public_key = Some(key.into());
        self
    }

    /// Set requester public key.
    #[must_use]
    pub fn requester_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.requester_public_key = Some(key.into());
        self
    }

    /// Set provider signature.
    #[must_use]
    pub fn provider_signature(mut self, sig: impl Into<Vec<u8>>) -> Self {
        self.provider_signature = Some(sig.into());
        self
    }

    /// Set requester signature.
    #[must_use]
    pub fn requester_signature(mut self, sig: impl Into<Vec<u8>>) -> Self {
        self.requester_signature = Some(sig.into());
        self
    }

    /// Set challenge nonce.
    #[must_use]
    pub fn challenge_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.challenge_nonce = Some(nonce.into());
        self
    }

    /// Set chunk hash.
    #[must_use]
    pub fn chunk_hash(mut self, hash: impl Into<Vec<u8>>) -> Self {
        self.chunk_hash = Some(hash.into());
        self
    }

    /// Set timestamps.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn timestamps(mut self, start_ms: i64, end_ms: i64) -> Self {
        self.start_timestamp_ms = start_ms;
        self.end_timestamp_ms = end_ms;
        self.latency_ms = (end_ms - start_ms).max(0) as u32;
        self
    }

    /// Set latency directly (overrides calculated from timestamps).
    #[must_use]
    pub fn latency_ms(mut self, latency: u32) -> Self {
        self.latency_ms = latency;
        self
    }

    /// Build the `BandwidthProof`.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing:
    /// - `content_cid`
    /// - `provider_peer_id`
    /// - `requester_peer_id`
    /// - `provider_public_key`
    /// - `requester_public_key`
    pub fn build(self) -> Result<BandwidthProof, &'static str> {
        Ok(BandwidthProof {
            session_id: self.session_id.unwrap_or_else(uuid::Uuid::new_v4),
            content_cid: self.content_cid.ok_or("content_cid is required")?,
            chunk_index: self.chunk_index,
            bytes_transferred: self.bytes_transferred,
            provider_peer_id: self
                .provider_peer_id
                .ok_or("provider_peer_id is required")?,
            requester_peer_id: self
                .requester_peer_id
                .ok_or("requester_peer_id is required")?,
            provider_public_key: self
                .provider_public_key
                .ok_or("provider_public_key is required")?,
            requester_public_key: self
                .requester_public_key
                .ok_or("requester_public_key is required")?,
            provider_signature: self
                .provider_signature
                .ok_or("provider_signature is required")?,
            requester_signature: self
                .requester_signature
                .ok_or("requester_signature is required")?,
            challenge_nonce: self.challenge_nonce.ok_or("challenge_nonce is required")?,
            chunk_hash: self.chunk_hash.ok_or("chunk_hash is required")?,
            start_timestamp_ms: self.start_timestamp_ms,
            end_timestamp_ms: self.end_timestamp_ms,
            latency_ms: self.latency_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BandwidthProof tests
    #[test]
    fn test_bandwidth_proof_builder() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest123")
            .chunk_index(0)
            .bytes_transferred(CHUNK_SIZE as u64)
            .provider_peer_id("12D3KooProvider")
            .requester_peer_id("12D3KooRequester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap();

        assert_eq!(proof.content_cid, "QmTest123");
        assert_eq!(proof.chunk_index, 0);
        assert_eq!(proof.bytes_transferred, CHUNK_SIZE as u64);
        assert_eq!(proof.latency_ms, 100);
        assert!(proof.is_valid());
    }

    #[test]
    fn test_bandwidth_proof_validation_invalid_key_length() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 16]) // Invalid length
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap();

        let result = proof.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidPublicKeyLength {
                expected: 32,
                actual: 16
            }
        )));
    }

    #[test]
    fn test_bandwidth_proof_validation_self_transfer() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("same_peer")
            .requester_peer_id("same_peer")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap();

        let result = proof.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::SelfTransfer))
        );
    }

    #[test]
    fn test_bandwidth_proof_validation_invalid_timestamp_order() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(2000, 1000) // End before start
            .build()
            .unwrap();

        let result = proof.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::InvalidTimestampOrder { .. }))
        );
    }

    #[test]
    fn test_bandwidth_proof_validation_latency_too_low() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1001)
            .latency_ms(0) // Too low
            .build()
            .unwrap();

        let result = proof.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::LatencyTooLow { .. }))
        );
    }

    #[test]
    fn test_bandwidth_proof_validation_latency_too_high() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .latency_ms(40_000) // Too high
            .build()
            .unwrap();

        let result = proof.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::LatencyTooHigh { .. }))
        );
    }

    #[test]
    fn test_bandwidth_proof_timestamp_validation() {
        let now_ms = chrono::Utc::now().timestamp_millis();

        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(now_ms - 1000, now_ms - 900)
            .build()
            .unwrap();

        // Should pass - timestamp is recent
        assert!(proof.validate_timestamp(now_ms).is_ok());

        // Should fail - timestamp in future
        assert!(proof.validate_timestamp(now_ms - 2000).is_err());

        // Should fail - timestamp too old
        assert!(
            proof
                .validate_timestamp(now_ms + TIMESTAMP_TOLERANCE_MS + 1000)
                .is_err()
        );
    }

    #[test]
    fn test_bandwidth_proof_sign_messages() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap();

        let provider_msg = proof.provider_sign_message();
        assert_eq!(provider_msg.len(), 32 + 32 + 32); // nonce + hash + requester_key

        let requester_msg = proof.requester_sign_message();
        assert_eq!(requester_msg.len(), 32 + 32 + 32 + 64); // nonce + hash + provider_key + provider_sig
    }

    #[test]
    fn test_bandwidth_proof_serialization() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: BandwidthProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.content_cid, deserialized.content_cid);
        assert_eq!(proof.chunk_index, deserialized.chunk_index);
    }

    #[test]
    fn test_chunk_request_serialization() {
        let request = ChunkRequest {
            content_cid: "QmTest".to_string(),
            chunk_index: 0,
            challenge_nonce: [1u8; 32],
            requester_peer_id: "12D3Koo".to_string(),
            requester_public_key: [2u8; 32],
            timestamp_ms: 1000,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ChunkRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.content_cid, deserialized.content_cid);
        assert_eq!(request.chunk_index, deserialized.chunk_index);
    }

    #[test]
    fn test_chunk_response_serialization() {
        let response = ChunkResponse {
            encrypted_chunk: vec![1, 2, 3],
            chunk_hash: [4u8; 32],
            provider_signature: vec![5u8; 64],
            provider_public_key: [6u8; 32],
            challenge_echo: [7u8; 32],
            timestamp_ms: 2000,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ChunkResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.encrypted_chunk, deserialized.encrypted_chunk);
    }

    #[test]
    fn test_chunk_request_timestamp_validation() {
        let request = ChunkRequest::new("QmTest", 0, [1u8; 32], "12D3Koo", [2u8; 32]);

        // Should be valid immediately after creation
        assert!(request.is_timestamp_valid());
    }

    #[test]
    fn test_chunk_response_verify_challenge_echo() {
        let nonce = [42u8; 32];
        let response =
            ChunkResponse::new(vec![1, 2, 3], [4u8; 32], vec![5u8; 64], [6u8; 32], nonce);

        assert!(response.verify_challenge_echo(&nonce));
        assert!(!response.verify_challenge_echo(&[0u8; 32]));
    }

    #[test]
    fn test_chunk_response_chunk_size() {
        let data = vec![1u8; CHUNK_SIZE];
        let response =
            ChunkResponse::new(data.clone(), [4u8; 32], vec![5u8; 64], [6u8; 32], [7u8; 32]);

        assert_eq!(response.chunk_size(), CHUNK_SIZE);
    }

    #[test]
    fn test_bandwidth_proof_bandwidth_bps() {
        let proof = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .bytes_transferred(1000)
            .timestamps(1000, 1100) // 100ms
            .build()
            .unwrap();

        // 1000 bytes in 100ms = 10,000 bytes/second
        assert_eq!(proof.bandwidth_bps(), 10_000.0);
    }

    #[test]
    fn test_bandwidth_proof_quality_threshold() {
        let proof_good = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1400) // 400ms
            .build()
            .unwrap();

        assert!(proof_good.meets_quality_threshold());
        assert_eq!(proof_good.quality_multiplier(), 1.0);

        let proof_bad = BandwidthProofBuilder::new()
            .content_cid("QmTest")
            .provider_peer_id("provider")
            .requester_peer_id("requester")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1600) // 600ms
            .build()
            .unwrap();

        assert!(!proof_bad.meets_quality_threshold());
        assert_eq!(proof_bad.quality_multiplier(), 0.5);
    }
}

/// Helper functions for creating test/mock data.
#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::types::content::ContentMetadataBuilder;
    use crate::types::enums::ContentCategory;

    /// Create a valid test BandwidthProof.
    #[must_use]
    pub fn create_test_proof() -> BandwidthProof {
        BandwidthProofBuilder::new()
            .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .chunk_index(0)
            .bytes_transferred(CHUNK_SIZE as u64)
            .provider_peer_id("12D3KooWProviderPeerTestID")
            .requester_peer_id("12D3KooWRequesterPeerTestID")
            .provider_public_key(vec![1u8; 32])
            .requester_public_key(vec![2u8; 32])
            .provider_signature(vec![3u8; 64])
            .requester_signature(vec![4u8; 64])
            .challenge_nonce(vec![5u8; 32])
            .chunk_hash(vec![6u8; 32])
            .timestamps(1000, 1100)
            .build()
            .unwrap()
    }

    /// Create a valid test ContentMetadata.
    #[must_use]
    pub fn create_test_content() -> crate::types::content::ContentMetadata {
        ContentMetadataBuilder::new()
            .cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .title("Test Content")
            .description("A test content item")
            .category(ContentCategory::ThreeDModels)
            .size_bytes(5 * 1024 * 1024)
            .price(1000)
            .creator_id(uuid::Uuid::new_v4())
            .build()
            .unwrap()
    }

    /// Create a valid test ChunkRequest.
    #[must_use]
    pub fn create_test_chunk_request() -> ChunkRequest {
        ChunkRequest::new(
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            0,
            [1u8; 32],
            "12D3KooWRequesterPeerTestID",
            [2u8; 32],
        )
    }

    /// Create a valid test ChunkResponse.
    #[must_use]
    pub fn create_test_chunk_response() -> ChunkResponse {
        ChunkResponse::new(
            vec![0u8; CHUNK_SIZE],
            [3u8; 32],
            vec![4u8; 64],
            [5u8; 32],
            [1u8; 32],
        )
    }
}
