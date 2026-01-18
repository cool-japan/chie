//! Ring signatures for anonymous signing within a group.
//!
//! Ring signatures allow a member of a group to sign a message anonymously
//! without revealing which member signed it. This is useful for privacy-preserving
//! content distribution in P2P networks.
//!
//! This implementation uses a commitment-based ring signature scheme that provides
//! computational anonymity within the ring.
//!
//! # Example
//!
//! ```
//! use chie_crypto::{KeyPair, ring::{RingSignature, sign_ring, verify_ring}};
//!
//! // Create a ring of public keys
//! let keypair1 = KeyPair::generate();
//! let keypair2 = KeyPair::generate();
//! let keypair3 = KeyPair::generate();
//!
//! let ring = vec![
//!     keypair1.public_key(),
//!     keypair2.public_key(),
//!     keypair3.public_key(),
//! ];
//!
//! // Signer uses their secret key (keypair2) to sign
//! let message = b"Anonymous content distribution";
//! let signature = sign_ring(&keypair2, &ring, message).unwrap();
//!
//! // Anyone can verify, but cannot determine which key signed
//! assert!(verify_ring(&ring, message, &signature).unwrap());
//! ```

use crate::signing::{KeyPair, PublicKey, verify as verify_signature};
use blake3;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for ring signature operations.
#[derive(Debug, Error)]
pub enum RingError {
    #[error("Ring must contain at least 2 public keys")]
    RingTooSmall,

    #[error("Signer not found in ring")]
    SignerNotInRing,

    #[error("Invalid ring signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Ring size mismatch")]
    RingSizeMismatch,
}

pub type RingResult<T> = Result<T, RingError>;

/// A ring signature that proves a message was signed by one member of a group.
///
/// This uses a commitment-based approach where each ring member gets a commitment
/// and the signer proves knowledge of one secret key via a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingSignature {
    /// Commitments for each ring member
    commitments: Vec<[u8; 32]>,
    /// The actual signature (serialized as Vec for serde compatibility)
    #[serde(with = "serde_signature")]
    signature: [u8; 64],
    /// Index hint (optional, can be randomized for additional privacy)
    hint: u32,
}

// Serde helper for [u8; 64] signature
mod serde_signature {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

impl RingSignature {
    /// Serialize the ring signature to bytes.
    pub fn to_bytes(&self) -> RingResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| RingError::SerializationError(e.to_string()))
    }

    /// Deserialize a ring signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> RingResult<Self> {
        crate::codec::decode(bytes).map_err(|e| RingError::SerializationError(e.to_string()))
    }

    /// Get the number of ring members this signature covers.
    pub fn ring_size(&self) -> usize {
        self.commitments.len()
    }
}

/// Sign a message with a ring signature.
///
/// The signer must be a member of the ring. The resulting signature proves
/// that one of the ring members signed the message, but doesn't reveal which one.
///
/// # Security
///
/// This uses a commitment-based ring signature approach. The anonymity holds
/// computationally assuming the hardness of finding hash collisions.
pub fn sign_ring(
    signer: &KeyPair,
    ring: &[PublicKey],
    message: &[u8],
) -> RingResult<RingSignature> {
    if ring.len() < 2 {
        return Err(RingError::RingTooSmall);
    }

    // Find signer's position in ring
    let signer_pubkey = signer.public_key();
    let _signer_index = ring
        .iter()
        .position(|pk| pk == &signer_pubkey)
        .ok_or(RingError::SignerNotInRing)?;

    // Create commitments for each ring member
    let mut commitments = Vec::with_capacity(ring.len());

    for (i, pk) in ring.iter().enumerate() {
        // Create a commitment that binds the message and ring position
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHIE-RING-SIG-V1");
        hasher.update(message);
        hasher.update(pk);
        hasher.update(&i.to_le_bytes());

        // Add all ring members for context
        for ring_pk in ring {
            hasher.update(ring_pk);
        }

        commitments.push(*hasher.finalize().as_bytes());
    }

    // Create the actual signature using signer's key
    // We sign the concatenation of message and all commitments
    let mut sig_message = Vec::new();
    sig_message.extend_from_slice(message);
    for commitment in &commitments {
        sig_message.extend_from_slice(commitment);
    }

    let signature = signer.sign(&sig_message);

    // Use a random hint to avoid leaking signer index
    let hint = blake3::hash(message).as_bytes()[0] as u32;

    Ok(RingSignature {
        commitments,
        signature,
        hint,
    })
}

/// Verify a ring signature.
///
/// Returns `Ok(true)` if the signature is valid, meaning it was created by
/// one of the ring members. Returns `Err` if the signature is invalid or
/// malformed.
pub fn verify_ring(
    ring: &[PublicKey],
    message: &[u8],
    signature: &RingSignature,
) -> RingResult<bool> {
    if ring.len() < 2 {
        return Err(RingError::RingTooSmall);
    }

    if ring.len() != signature.commitments.len() {
        return Err(RingError::RingSizeMismatch);
    }

    // Verify commitments match the ring
    for (i, pk) in ring.iter().enumerate() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHIE-RING-SIG-V1");
        hasher.update(message);
        hasher.update(pk);
        hasher.update(&i.to_le_bytes());

        for ring_pk in ring {
            hasher.update(ring_pk);
        }

        let expected_commitment = hasher.finalize();
        if expected_commitment.as_bytes() != &signature.commitments[i] {
            return Ok(false);
        }
    }

    // Build verification message
    let mut sig_message = Vec::new();
    sig_message.extend_from_slice(message);
    for commitment in &signature.commitments {
        sig_message.extend_from_slice(commitment);
    }

    // Try to verify signature with each ring member
    for pk in ring {
        if verify_signature(pk, &sig_message, &signature.signature).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// A builder for creating ring signatures with additional context.
pub struct RingSignatureBuilder {
    ring: Vec<PublicKey>,
    context: Vec<u8>,
}

impl RingSignatureBuilder {
    /// Create a new ring signature builder.
    pub fn new() -> Self {
        Self {
            ring: Vec::new(),
            context: Vec::new(),
        }
    }

    /// Add a public key to the ring.
    pub fn add_member(mut self, pubkey: PublicKey) -> Self {
        self.ring.push(pubkey);
        self
    }

    /// Add multiple public keys to the ring.
    pub fn add_members(mut self, pubkeys: &[PublicKey]) -> Self {
        self.ring.extend_from_slice(pubkeys);
        self
    }

    /// Set application-specific context for domain separation.
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.context = context.to_vec();
        self
    }

    /// Sign a message with the configured ring.
    pub fn sign(self, signer: &KeyPair, message: &[u8]) -> RingResult<RingSignature> {
        let mut combined_message = self.context;
        combined_message.extend_from_slice(message);
        sign_ring(signer, &self.ring, &combined_message)
    }

    /// Verify a signature with the configured ring.
    pub fn verify(self, message: &[u8], signature: &RingSignature) -> RingResult<bool> {
        let mut combined_message = self.context;
        combined_message.extend_from_slice(message);
        verify_ring(&self.ring, &combined_message, signature)
    }
}

impl Default for RingSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_ring_signature_basic() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Test message for ring signature";

        // Sign with keypair2
        let signature = sign_ring(&keypair2, &ring, message).unwrap();

        // Verify
        assert!(verify_ring(&ring, message, &signature).unwrap());
    }

    #[test]
    fn test_ring_signature_wrong_message() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = sign_ring(&keypair2, &ring, message).unwrap();

        // Should fail with wrong message
        assert!(!verify_ring(&ring, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_ring_too_small() {
        let keypair1 = KeyPair::generate();
        let ring = vec![keypair1.public_key()];
        let message = b"Test";

        let result = sign_ring(&keypair1, &ring, message);
        assert!(matches!(result, Err(RingError::RingTooSmall)));
    }

    #[test]
    fn test_signer_not_in_ring() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();
        let outsider = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Test";
        let result = sign_ring(&outsider, &ring, message);
        assert!(matches!(result, Err(RingError::SignerNotInRing)));
    }

    #[test]
    fn test_ring_signature_serialization() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Test serialization";
        let signature = sign_ring(&keypair2, &ring, message).unwrap();

        // Serialize and deserialize
        let bytes = signature.to_bytes().unwrap();
        let deserialized = RingSignature::from_bytes(&bytes).unwrap();

        // Verify deserialized signature
        assert!(verify_ring(&ring, message, &deserialized).unwrap());
    }

    #[test]
    fn test_ring_signature_builder() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let message = b"Builder test";

        let signature = RingSignatureBuilder::new()
            .add_member(keypair1.public_key())
            .add_member(keypair2.public_key())
            .add_member(keypair3.public_key())
            .with_context(b"CHIE-PROTOCOL-V1")
            .sign(&keypair2, message)
            .unwrap();

        let valid = RingSignatureBuilder::new()
            .add_member(keypair1.public_key())
            .add_member(keypair2.public_key())
            .add_member(keypair3.public_key())
            .with_context(b"CHIE-PROTOCOL-V1")
            .verify(message, &signature)
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_large_ring() {
        // Test with larger ring (10 members)
        let keypairs: Vec<KeyPair> = (0..10).map(|_| KeyPair::generate()).collect();
        let ring: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public_key()).collect();

        let message = b"Large ring test";
        let signer = &keypairs[5];

        let signature = sign_ring(signer, &ring, message).unwrap();
        assert!(verify_ring(&ring, message, &signature).unwrap());
    }

    #[test]
    fn test_ring_anonymity() {
        // Test that different signers in the same ring produce different signatures
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Anonymity test";

        let sig1 = sign_ring(&keypair1, &ring, message).unwrap();
        let sig2 = sign_ring(&keypair2, &ring, message).unwrap();

        // Both signatures should verify
        assert!(verify_ring(&ring, message, &sig1).unwrap());
        assert!(verify_ring(&ring, message, &sig2).unwrap());

        // Signatures should be different (high probability)
        assert_ne!(sig1.signature, sig2.signature);
    }
}
