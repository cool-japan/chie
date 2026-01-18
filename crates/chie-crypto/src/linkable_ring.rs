//! Linkable ring signatures for double-spend prevention.
//!
//! Linkable ring signatures are an extension of ring signatures that allow
//! detection of double-signing (when the same key signs twice with the same ring).
//! This is crucial for preventing double-spending in anonymous payment systems
//! while preserving signer anonymity for single uses.
//!
//! # Features
//!
//! - Anonymous signing within a group (like regular ring signatures)
//! - Double-signing detection via key images
//! - No linkability between different rings
//! - Perfect for preventing double-spending of anonymous tokens
//!
//! # Example
//!
//! ```
//! use chie_crypto::linkable_ring::{LinkableRingSignature, sign_linkable, verify_linkable, check_double_sign};
//! use chie_crypto::KeyPair;
//!
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
//! // Sign two different messages with the same key
//! let msg1 = b"Transaction 1";
//! let msg2 = b"Transaction 2";
//!
//! let sig1 = sign_linkable(&keypair2, &ring, msg1).unwrap();
//! let sig2 = sign_linkable(&keypair2, &ring, msg2).unwrap();
//!
//! // Both signatures verify
//! assert!(verify_linkable(&ring, msg1, &sig1).unwrap());
//! assert!(verify_linkable(&ring, msg2, &sig2).unwrap());
//!
//! // But we can detect they were signed by the same key!
//! assert!(check_double_sign(&sig1, &sig2));
//! ```

use crate::signing::{KeyPair, PublicKey, verify as verify_signature};
use blake3;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for linkable ring signature operations.
#[derive(Debug, Error)]
pub enum LinkableRingError {
    #[error("Ring must contain at least 2 public keys")]
    RingTooSmall,

    #[error("Signer not found in ring")]
    SignerNotInRing,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Ring size mismatch")]
    RingSizeMismatch,

    #[error("Invalid key image")]
    InvalidKeyImage,
}

pub type LinkableRingResult<T> = Result<T, LinkableRingError>;

/// A linkable ring signature with key image for double-sign detection.
///
/// The key image is a unique value derived from the signer's secret key
/// and the ring. The same key signing twice will produce the same key image,
/// allowing detection of double-signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkableRingSignature {
    /// Commitments for each ring member
    commitments: Vec<[u8; 32]>,
    /// The signature
    #[serde(with = "serde_signature")]
    signature: [u8; 64],
    /// Key image for linkability detection
    key_image: [u8; 32],
    /// Ring identifier hash
    ring_hash: [u8; 32],
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

impl LinkableRingSignature {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> LinkableRingResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| LinkableRingError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> LinkableRingResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| LinkableRingError::SerializationError(e.to_string()))
    }

    /// Get the key image for double-sign detection.
    pub fn key_image(&self) -> &[u8; 32] {
        &self.key_image
    }

    /// Get the ring identifier hash.
    pub fn ring_hash(&self) -> &[u8; 32] {
        &self.ring_hash
    }

    /// Get the number of ring members.
    pub fn ring_size(&self) -> usize {
        self.commitments.len()
    }
}

/// Compute a deterministic key image from a secret key and ring.
///
/// The key image is computed as: H(secret_key || ring_hash)
/// This ensures the same key produces the same image for the same ring,
/// but different images for different rings.
fn compute_key_image(secret_key: &[u8; 32], ring_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CHIE-KEY-IMAGE-V1");
    hasher.update(secret_key);
    hasher.update(ring_hash);
    *hasher.finalize().as_bytes()
}

/// Compute ring identifier hash.
fn compute_ring_hash(ring: &[PublicKey]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CHIE-RING-HASH-V1");
    for pk in ring {
        hasher.update(pk);
    }
    *hasher.finalize().as_bytes()
}

/// Sign a message with a linkable ring signature.
///
/// Creates a signature that can be verified as coming from one of the ring
/// members, and includes a key image that allows detecting if the same key
/// signs multiple messages with the same ring.
pub fn sign_linkable(
    signer: &KeyPair,
    ring: &[PublicKey],
    message: &[u8],
) -> LinkableRingResult<LinkableRingSignature> {
    if ring.len() < 2 {
        return Err(LinkableRingError::RingTooSmall);
    }

    // Verify signer is in ring
    let signer_pubkey = signer.public_key();
    let _signer_index = ring
        .iter()
        .position(|pk| pk == &signer_pubkey)
        .ok_or(LinkableRingError::SignerNotInRing)?;

    // Compute ring hash
    let ring_hash = compute_ring_hash(ring);

    // Compute key image
    let secret_key = signer.secret_key();
    let key_image = compute_key_image(&secret_key, &ring_hash);

    // Create commitments for each ring member
    let mut commitments = Vec::with_capacity(ring.len());

    for (i, pk) in ring.iter().enumerate() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHIE-LINKABLE-RING-V1");
        hasher.update(message);
        hasher.update(pk);
        hasher.update(&i.to_le_bytes());
        hasher.update(&ring_hash);
        hasher.update(&key_image);

        for ring_pk in ring {
            hasher.update(ring_pk);
        }

        commitments.push(*hasher.finalize().as_bytes());
    }

    // Create signature
    let mut sig_message = Vec::new();
    sig_message.extend_from_slice(message);
    sig_message.extend_from_slice(&key_image);
    sig_message.extend_from_slice(&ring_hash);
    for commitment in &commitments {
        sig_message.extend_from_slice(commitment);
    }

    let signature = signer.sign(&sig_message);

    Ok(LinkableRingSignature {
        commitments,
        signature,
        key_image,
        ring_hash,
    })
}

/// Verify a linkable ring signature.
///
/// Returns Ok(true) if the signature is valid and was created by one of
/// the ring members.
pub fn verify_linkable(
    ring: &[PublicKey],
    message: &[u8],
    signature: &LinkableRingSignature,
) -> LinkableRingResult<bool> {
    if ring.len() < 2 {
        return Err(LinkableRingError::RingTooSmall);
    }

    if ring.len() != signature.commitments.len() {
        return Err(LinkableRingError::RingSizeMismatch);
    }

    // Verify ring hash matches
    let expected_ring_hash = compute_ring_hash(ring);
    if expected_ring_hash != signature.ring_hash {
        return Ok(false);
    }

    // Verify commitments
    for (i, pk) in ring.iter().enumerate() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHIE-LINKABLE-RING-V1");
        hasher.update(message);
        hasher.update(pk);
        hasher.update(&i.to_le_bytes());
        hasher.update(&signature.ring_hash);
        hasher.update(&signature.key_image);

        for ring_pk in ring {
            hasher.update(ring_pk);
        }

        let expected_commitment = hasher.finalize();
        if expected_commitment.as_bytes() != &signature.commitments[i] {
            return Ok(false);
        }
    }

    // Verify signature
    let mut sig_message = Vec::new();
    sig_message.extend_from_slice(message);
    sig_message.extend_from_slice(&signature.key_image);
    sig_message.extend_from_slice(&signature.ring_hash);
    for commitment in &signature.commitments {
        sig_message.extend_from_slice(commitment);
    }

    for pk in ring {
        if verify_signature(pk, &sig_message, &signature.signature).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Check if two signatures were created by the same key (double-signing detection).
///
/// Returns true if both signatures have the same key image and ring hash,
/// indicating they were signed by the same key in the same ring.
pub fn check_double_sign(sig1: &LinkableRingSignature, sig2: &LinkableRingSignature) -> bool {
    sig1.key_image == sig2.key_image && sig1.ring_hash == sig2.ring_hash
}

/// Database for tracking used key images to prevent double-spending.
pub struct KeyImageDb {
    /// Set of used key images (ring_hash || key_image)
    used_images: std::collections::HashSet<Vec<u8>>,
}

impl KeyImageDb {
    /// Create a new key image database.
    pub fn new() -> Self {
        Self {
            used_images: std::collections::HashSet::new(),
        }
    }

    /// Check if a signature has already been used.
    pub fn is_used(&self, signature: &LinkableRingSignature) -> bool {
        let mut key = Vec::new();
        key.extend_from_slice(&signature.ring_hash);
        key.extend_from_slice(&signature.key_image);
        self.used_images.contains(&key)
    }

    /// Mark a signature as used.
    ///
    /// Returns false if the signature was already used (double-spend attempt).
    pub fn mark_used(&mut self, signature: &LinkableRingSignature) -> bool {
        let mut key = Vec::new();
        key.extend_from_slice(&signature.ring_hash);
        key.extend_from_slice(&signature.key_image);
        self.used_images.insert(key)
    }

    /// Get the number of used signatures.
    pub fn size(&self) -> usize {
        self.used_images.len()
    }

    /// Clear all used signatures.
    pub fn clear(&mut self) {
        self.used_images.clear();
    }
}

impl Default for KeyImageDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_linkable_ring_basic() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Test message";
        let signature = sign_linkable(&keypair2, &ring, message).unwrap();

        assert!(verify_linkable(&ring, message, &signature).unwrap());
    }

    #[test]
    fn test_double_sign_detection() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        // Same key signs two different messages
        let msg1 = b"Transaction 1";
        let msg2 = b"Transaction 2";

        let sig1 = sign_linkable(&keypair2, &ring, msg1).unwrap();
        let sig2 = sign_linkable(&keypair2, &ring, msg2).unwrap();

        // Key images should match (double-sign detected)
        assert!(check_double_sign(&sig1, &sig2));
        assert_eq!(sig1.key_image(), sig2.key_image());
    }

    #[test]
    fn test_different_signers_different_images() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let ring = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let message = b"Same message";

        let sig1 = sign_linkable(&keypair1, &ring, message).unwrap();
        let sig2 = sign_linkable(&keypair2, &ring, message).unwrap();

        // Different keys produce different images
        assert!(!check_double_sign(&sig1, &sig2));
        assert_ne!(sig1.key_image(), sig2.key_image());
    }

    #[test]
    fn test_different_rings_different_images() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();
        let keypair4 = KeyPair::generate();

        let ring1 = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let ring2 = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair4.public_key(),
        ];

        let message = b"Test";

        // Same key, different rings
        let sig1 = sign_linkable(&keypair1, &ring1, message).unwrap();
        let sig2 = sign_linkable(&keypair1, &ring2, message).unwrap();

        // Different rings produce different images
        assert!(!check_double_sign(&sig1, &sig2));
        assert_ne!(sig1.key_image(), sig2.key_image());
        assert_ne!(sig1.ring_hash(), sig2.ring_hash());
    }

    #[test]
    fn test_serialization() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let ring = vec![keypair1.public_key(), keypair2.public_key()];
        let message = b"Serialization test";

        let signature = sign_linkable(&keypair1, &ring, message).unwrap();

        let bytes = signature.to_bytes().unwrap();
        let deserialized = LinkableRingSignature::from_bytes(&bytes).unwrap();

        assert!(verify_linkable(&ring, message, &deserialized).unwrap());
        assert_eq!(signature.key_image(), deserialized.key_image());
    }

    #[test]
    fn test_key_image_db() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let ring = vec![keypair1.public_key(), keypair2.public_key()];

        let msg1 = b"Transaction 1";
        let msg2 = b"Transaction 2";

        let sig1 = sign_linkable(&keypair1, &ring, msg1).unwrap();
        let sig2 = sign_linkable(&keypair1, &ring, msg2).unwrap();

        let mut db = KeyImageDb::new();

        // First use should succeed
        assert!(db.mark_used(&sig1));
        assert_eq!(db.size(), 1);

        // Check if used
        assert!(db.is_used(&sig1));

        // Second use with same key should fail (double-spend)
        assert!(!db.mark_used(&sig2));

        // Different key should succeed
        let sig3 = sign_linkable(&keypair2, &ring, msg1).unwrap();
        assert!(db.mark_used(&sig3));
        assert_eq!(db.size(), 2);
    }

    #[test]
    fn test_wrong_message() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let ring = vec![keypair1.public_key(), keypair2.public_key()];

        let message = b"Original";
        let wrong_message = b"Wrong";

        let signature = sign_linkable(&keypair1, &ring, message).unwrap();

        assert!(!verify_linkable(&ring, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_ring_too_small() {
        let keypair = KeyPair::generate();
        let ring = vec![keypair.public_key()];
        let message = b"Test";

        let result = sign_linkable(&keypair, &ring, message);
        assert!(matches!(result, Err(LinkableRingError::RingTooSmall)));
    }

    #[test]
    fn test_signer_not_in_ring() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let outsider = KeyPair::generate();

        let ring = vec![keypair1.public_key(), keypair2.public_key()];
        let message = b"Test";

        let result = sign_linkable(&outsider, &ring, message);
        assert!(matches!(result, Err(LinkableRingError::SignerNotInRing)));
    }
}
