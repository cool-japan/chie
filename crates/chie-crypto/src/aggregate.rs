//! Aggregate signatures for multi-peer coordination in CHIE protocol.
//!
//! This module provides signature aggregation capabilities, allowing multiple
//! peers to sign a message and combine their signatures into a compact representation.
//!
//! # Features
//! - Aggregate multiple signatures from different signers
//! - Batch verification of aggregated signatures
//! - Compact representation for network efficiency
//! - Built on Ed25519 for compatibility with existing infrastructure
//!
//! # Example
//! ```
//! use chie_crypto::aggregate::{AggregateSignature, SignatureAggregator};
//! use chie_crypto::KeyPair;
//!
//! // Multiple peers sign the same message
//! let message = b"bandwidth proof for chunk 123";
//!
//! let keypair1 = KeyPair::generate();
//! let keypair2 = KeyPair::generate();
//! let keypair3 = KeyPair::generate();
//!
//! let sig1 = keypair1.sign(message);
//! let sig2 = keypair2.sign(message);
//! let sig3 = keypair3.sign(message);
//!
//! // Aggregate signatures
//! let mut aggregator = SignatureAggregator::new();
//! aggregator.add_signature(&keypair1.public_key(), &sig1);
//! aggregator.add_signature(&keypair2.public_key(), &sig2);
//! aggregator.add_signature(&keypair3.public_key(), &sig3);
//!
//! let aggregate = aggregator.finalize(message).unwrap();
//!
//! // Verify all signatures at once
//! assert!(aggregate.verify(message).is_ok());
//! ```

use crate::{PublicKey, SignatureBytes, SigningError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Type alias for signature in aggregate context.
pub type Signature = SignatureBytes;

/// Aggregate signature containing multiple signatures and their public keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateSignature {
    /// Public keys of all signers.
    #[serde(with = "serde_pubkey_vec")]
    public_keys: Vec<PublicKey>,
    /// Individual signatures (in same order as public keys).
    #[serde(with = "serde_signature_vec")]
    signatures: Vec<Signature>,
    /// Message that was signed (for verification).
    #[serde(with = "serde_bytes")]
    message_hash: Vec<u8>,
}

/// Builder for creating aggregate signatures.
#[derive(Default)]
pub struct SignatureAggregator {
    /// Collected (public key, signature) pairs.
    entries: Vec<(PublicKey, Signature)>,
}

/// Errors that can occur with aggregate signatures.
#[derive(Debug, Error)]
pub enum AggregateError {
    /// No signatures to aggregate.
    #[error("No signatures provided")]
    NoSignatures,

    /// Duplicate public key detected.
    #[error("Duplicate public key in aggregate")]
    DuplicatePublicKey,

    /// Verification failed for one or more signatures.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid signature format.
    #[error("Invalid signature: {0}")]
    InvalidSignature(#[from] SigningError),
}

pub type AggregateResult<T> = Result<T, AggregateError>;

// Serde helper for Vec<u8>
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Vec<u8>>::deserialize(deserializer)
    }
}

// Serde helper for Vec<[u8; 32]>
mod serde_pubkey_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(keys: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes_vec: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        bytes_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_of_vecs: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        vec_of_vecs
            .into_iter()
            .map(|v| {
                if v.len() != 32 {
                    return Err(serde::de::Error::custom("Expected 32 bytes"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect()
    }
}

// Serde helper for Vec<[u8; 64]>
mod serde_signature_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(sigs: &[[u8; 64]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes_vec: Vec<&[u8]> = sigs.iter().map(|s| s.as_slice()).collect();
        bytes_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec_of_vecs: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        vec_of_vecs
            .into_iter()
            .map(|v| {
                if v.len() != 64 {
                    return Err(serde::de::Error::custom("Expected 64 bytes"));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect()
    }
}

impl AggregateSignature {
    /// Create a new aggregate signature.
    ///
    /// # Arguments
    /// * `public_keys` - Public keys of all signers
    /// * `signatures` - Signatures from all signers (same order)
    /// * `message` - The message that was signed
    pub fn new(
        public_keys: Vec<PublicKey>,
        signatures: Vec<Signature>,
        message: &[u8],
    ) -> AggregateResult<Self> {
        if public_keys.is_empty() || signatures.is_empty() {
            return Err(AggregateError::NoSignatures);
        }

        if public_keys.len() != signatures.len() {
            return Err(AggregateError::VerificationFailed);
        }

        // Check for duplicate public keys
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                if public_keys[i] == public_keys[j] {
                    return Err(AggregateError::DuplicatePublicKey);
                }
            }
        }

        let message_hash = blake3::hash(message).as_bytes().to_vec();

        Ok(Self {
            public_keys,
            signatures,
            message_hash,
        })
    }

    /// Verify all signatures in the aggregate.
    ///
    /// # Arguments
    /// * `message` - The message to verify against
    ///
    /// # Returns
    /// `Ok(())` if all signatures are valid, error otherwise.
    pub fn verify(&self, message: &[u8]) -> AggregateResult<()> {
        // Check message hash
        let expected_hash = blake3::hash(message);
        if expected_hash.as_bytes() != self.message_hash.as_slice() {
            return Err(AggregateError::VerificationFailed);
        }

        // Verify each signature
        for (public_key, signature) in self.public_keys.iter().zip(self.signatures.iter()) {
            crate::verify(public_key, message, signature)?;
        }

        Ok(())
    }

    /// Get the number of signatures in this aggregate.
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Get all public keys.
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }

    /// Get all signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Check if a specific public key is included.
    pub fn contains_signer(&self, public_key: &PublicKey) -> bool {
        self.public_keys.contains(public_key)
    }
}

impl SignatureAggregator {
    /// Create a new signature aggregator.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a signature to the aggregator.
    ///
    /// # Arguments
    /// * `public_key` - The signer's public key
    /// * `signature` - The signature
    pub fn add_signature(&mut self, public_key: &PublicKey, signature: &Signature) {
        self.entries.push((*public_key, *signature));
    }

    /// Add multiple signatures at once.
    pub fn add_signatures(&mut self, entries: &[(PublicKey, Signature)]) {
        self.entries.extend_from_slice(entries);
    }

    /// Get the current number of signatures.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the aggregator is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Finalize the aggregation and create an AggregateSignature.
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    ///
    /// # Returns
    /// The aggregate signature.
    pub fn finalize(self, message: &[u8]) -> AggregateResult<AggregateSignature> {
        if self.entries.is_empty() {
            return Err(AggregateError::NoSignatures);
        }

        let (public_keys, signatures): (Vec<_>, Vec<_>) = self.entries.into_iter().unzip();

        AggregateSignature::new(public_keys, signatures, message)
    }

    /// Clear all accumulated signatures.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Verify a batch of signatures from different signers on the same message.
///
/// This is a convenience function that creates an aggregate and verifies it.
///
/// # Arguments
/// * `public_keys` - Public keys of all signers
/// * `signatures` - Signatures from all signers
/// * `message` - The message that was signed
///
/// # Returns
/// `Ok(())` if all signatures are valid.
pub fn verify_batch(
    public_keys: &[PublicKey],
    signatures: &[Signature],
    message: &[u8],
) -> AggregateResult<()> {
    let aggregate = AggregateSignature::new(public_keys.to_vec(), signatures.to_vec(), message)?;
    aggregate.verify(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_aggregate_signature_basic() {
        let message = b"test message";

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        let sig3 = keypair3.sign(message);

        let aggregate = AggregateSignature::new(
            vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ],
            vec![sig1, sig2, sig3],
            message,
        )
        .unwrap();

        assert!(aggregate.verify(message).is_ok());
        assert_eq!(aggregate.count(), 3);
    }

    #[test]
    fn test_signature_aggregator() {
        let message = b"bandwidth proof";

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);

        let mut aggregator = SignatureAggregator::new();
        aggregator.add_signature(&keypair1.public_key(), &sig1);
        aggregator.add_signature(&keypair2.public_key(), &sig2);

        assert_eq!(aggregator.len(), 2);

        let aggregate = aggregator.finalize(message).unwrap();
        assert!(aggregate.verify(message).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let message1 = b"message 1";
        let message2 = b"message 2";

        let keypair = KeyPair::generate();
        let sig = keypair.sign(message1);

        let aggregate =
            AggregateSignature::new(vec![keypair.public_key()], vec![sig], message1).unwrap();

        // Verifying with different message should fail
        assert!(aggregate.verify(message2).is_err());
    }

    #[test]
    fn test_duplicate_public_key_rejected() {
        let message = b"test";

        let keypair = KeyPair::generate();
        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        let result = AggregateSignature::new(
            vec![keypair.public_key(), keypair.public_key()],
            vec![sig1, sig2],
            message,
        );

        assert!(matches!(result, Err(AggregateError::DuplicatePublicKey)));
    }

    #[test]
    fn test_empty_aggregate_rejected() {
        let result = AggregateSignature::new(vec![], vec![], b"test");
        assert!(matches!(result, Err(AggregateError::NoSignatures)));
    }

    #[test]
    fn test_mismatched_lengths_rejected() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let sig = keypair1.sign(b"test");

        let result = AggregateSignature::new(
            vec![keypair1.public_key(), keypair2.public_key()],
            vec![sig],
            b"test",
        );

        assert!(matches!(result, Err(AggregateError::VerificationFailed)));
    }

    #[test]
    fn test_contains_signer() {
        let message = b"test";

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);

        let aggregate = AggregateSignature::new(
            vec![keypair1.public_key(), keypair2.public_key()],
            vec![sig1, sig2],
            message,
        )
        .unwrap();

        assert!(aggregate.contains_signer(&keypair1.public_key()));
        assert!(aggregate.contains_signer(&keypair2.public_key()));
        assert!(!aggregate.contains_signer(&keypair3.public_key()));
    }

    #[test]
    fn test_verify_batch() {
        let message = b"batch test";

        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);

        let result = verify_batch(
            &[keypair1.public_key(), keypair2.public_key()],
            &[sig1, sig2],
            message,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_aggregator_clear() {
        let mut aggregator = SignatureAggregator::new();

        let keypair = KeyPair::generate();
        let sig = keypair.sign(b"test");

        aggregator.add_signature(&keypair.public_key(), &sig);
        assert_eq!(aggregator.len(), 1);

        aggregator.clear();
        assert_eq!(aggregator.len(), 0);
        assert!(aggregator.is_empty());
    }

    #[test]
    fn test_serialization() {
        let message = b"serialize test";

        let keypair = KeyPair::generate();
        let sig = keypair.sign(message);

        let aggregate =
            AggregateSignature::new(vec![keypair.public_key()], vec![sig], message).unwrap();

        // Serialize and deserialize
        let serialized = crate::codec::encode(&aggregate).unwrap();
        let deserialized: AggregateSignature = crate::codec::decode(&serialized).unwrap();

        assert!(deserialized.verify(message).is_ok());
        assert_eq!(aggregate.count(), deserialized.count());
    }
}
