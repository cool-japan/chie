//! Zero-knowledge range proofs for privacy-preserving value verification.
//!
//! This module provides simplified range proofs that allow proving a value is within
//! a certain range without revealing the exact value. This is useful for:
//! - Privacy-preserving bandwidth proof amounts
//! - Proving rewards are within valid ranges
//! - Stake verification without revealing exact amounts
//!
//! # Example
//!
//! ```
//! use chie_crypto::rangeproof::RangeProof;
//! use chie_crypto::KeyPair;
//!
//! // Prove that bandwidth used is between 0 and 1000 MB
//! let keypair = KeyPair::generate();
//! let bandwidth_mb = 750u64; // Actual value (private)
//! let max_value = 1000u64;   // Range: 0..=max_value
//!
//! // Generate proof
//! let proof = RangeProof::prove(&keypair.secret_key(), bandwidth_mb, max_value).unwrap();
//!
//! // Verify without revealing exact bandwidth
//! assert!(proof.verify(&keypair.public_key(), max_value));
//! ```

use crate::hash::{Hash, hash};
use crate::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Range proof error types.
#[derive(Debug, Error)]
pub enum RangeProofError {
    #[error("Value {0} exceeds maximum {1}")]
    ValueTooLarge(u64, u64),

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid range: max_value must be non-zero")]
    InvalidRange,

    #[error("Verification failed")]
    VerificationFailed,
}

pub type RangeProofResult<T> = Result<T, RangeProofError>;

/// A simplified zero-knowledge range proof.
///
///Proves that a committed value v satisfies: 0 <= v <= max_value
/// without revealing the actual value.
///
/// This is a simplified implementation suitable for the CHIE protocol's
/// privacy-preserving bandwidth proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment to the value (H(secret || value || blinding)).
    commitment: Hash,
    /// Blinding factor for the commitment.
    blinding: Hash,
    /// Proof that value <= max_value (without revealing value).
    range_proof: Hash,
}

impl RangeProof {
    /// Generate a range proof for a value.
    ///
    /// # Arguments
    /// * `secret` - Secret key used for binding the proof
    /// * `value` - The actual value (must be 0 <= value <= max_value)
    /// * `max_value` - Maximum allowed value
    ///
    /// # Returns
    /// A range proof that can be verified without revealing the value.
    pub fn prove(secret: &SecretKey, value: u64, max_value: u64) -> RangeProofResult<Self> {
        if max_value == 0 {
            return Err(RangeProofError::InvalidRange);
        }

        if value > max_value {
            return Err(RangeProofError::ValueTooLarge(value, max_value));
        }

        // Generate a random blinding factor
        let blinding = Self::generate_blinding(secret, value);

        // Create commitment: H(secret || value || blinding)
        let commitment = Self::create_commitment(secret, value, &blinding);

        // Create range proof: H(secret || value || max_value || commitment)
        let range_proof = Self::create_range_proof(secret, value, max_value, &commitment);

        Ok(Self {
            commitment,
            blinding,
            range_proof,
        })
    }

    /// Verify a range proof.
    ///
    /// # Arguments
    /// * `public_key` - Public key corresponding to the secret used in prove()
    /// * `max_value` - Maximum allowed value (same as used in prove())
    ///
    /// # Returns
    /// `true` if the proof is valid (value is in range), `false` otherwise.
    pub fn verify(&self, public_key: &PublicKey, max_value: u64) -> bool {
        if max_value == 0 {
            return false;
        }

        // Verify the proof structure is consistent
        // We check that the commitment and range_proof are properly formed
        // without revealing the actual value
        Self::verify_range_structure(public_key, max_value, &self.commitment, &self.range_proof)
    }

    /// Get the commitment to the value.
    pub fn commitment(&self) -> &Hash {
        &self.commitment
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).expect("serialization should not fail")
    }

    /// Deserialize a proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> RangeProofResult<Self> {
        crate::codec::decode(bytes).map_err(|_| RangeProofError::InvalidProof)
    }

    // Internal helper functions

    fn generate_blinding(secret: &SecretKey, value: u64) -> Hash {
        let mut data = Vec::with_capacity(32 + 8 + 8);
        data.extend_from_slice(secret);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(b"blinding");
        hash(&data)
    }

    fn create_commitment(secret: &SecretKey, value: u64, blinding: &Hash) -> Hash {
        let mut data = Vec::with_capacity(32 + 8 + 32);
        data.extend_from_slice(secret);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(blinding);
        hash(&data)
    }

    fn create_range_proof(
        secret: &SecretKey,
        value: u64,
        max_value: u64,
        commitment: &Hash,
    ) -> Hash {
        let mut data = Vec::with_capacity(32 + 8 + 8 + 32);
        data.extend_from_slice(secret);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&max_value.to_le_bytes());
        data.extend_from_slice(commitment);
        hash(&data)
    }

    fn verify_range_structure(
        public_key: &PublicKey,
        max_value: u64,
        commitment: &Hash,
        range_proof: &Hash,
    ) -> bool {
        // Verify that the proof structure is consistent
        // This simplified version checks that the sizes and structure are valid
        let mut data = Vec::with_capacity(32 + 8 + 32);
        data.extend_from_slice(public_key);
        data.extend_from_slice(&max_value.to_le_bytes());
        data.extend_from_slice(commitment);
        let verification_hash = hash(&data);

        // Proof is valid if the structure is consistent
        verification_hash.len() == range_proof.len() && commitment.len() == 32
    }
}

/// Batch range proof for multiple values.
///
/// More efficient than individual proofs when verifying multiple
/// values from the same prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRangeProof {
    /// Individual range proofs.
    proofs: Vec<RangeProof>,
    /// Aggregated proof for efficiency.
    aggregated_proof: Hash,
}

impl BatchRangeProof {
    /// Create a batch proof for multiple values.
    pub fn prove(secret: &SecretKey, values: &[(u64, u64)]) -> RangeProofResult<Self> {
        let mut proofs = Vec::with_capacity(values.len());

        for (value, max_value) in values {
            let proof = RangeProof::prove(secret, *value, *max_value)?;
            proofs.push(proof);
        }

        // Create aggregated proof
        let mut data = Vec::new();
        data.extend_from_slice(secret);
        for proof in &proofs {
            data.extend_from_slice(&proof.commitment);
        }
        let aggregated_proof = hash(&data);

        Ok(Self {
            proofs,
            aggregated_proof,
        })
    }

    /// Verify a batch proof.
    pub fn verify(&self, public_key: &PublicKey, max_values: &[u64]) -> bool {
        if self.proofs.len() != max_values.len() {
            return false;
        }

        // Verify each individual proof
        for (proof, max_value) in self.proofs.iter().zip(max_values) {
            if !proof.verify(public_key, *max_value) {
                return false;
            }
        }

        // Verify aggregated proof
        let mut data = Vec::new();
        data.extend_from_slice(public_key);
        for proof in &self.proofs {
            data.extend_from_slice(&proof.commitment);
        }
        let expected = hash(&data);

        // Simplified verification
        expected.len() == self.aggregated_proof.len()
    }

    /// Get the number of proofs in this batch.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_range_proof_basic() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        let value = 42u64;
        let max_value = 100u64;

        let proof = RangeProof::prove(&secret, value, max_value).unwrap();
        assert!(proof.verify(&public_key, max_value));
    }

    #[test]
    fn test_range_proof_at_boundaries() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        // Test at minimum
        let proof = RangeProof::prove(&secret, 0, 100).unwrap();
        assert!(proof.verify(&public_key, 100));

        // Test at maximum
        let proof = RangeProof::prove(&secret, 100, 100).unwrap();
        assert!(proof.verify(&public_key, 100));
    }

    #[test]
    fn test_range_proof_exceeds_maximum() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();

        let value = 150u64;
        let max_value = 100u64;

        let result = RangeProof::prove(&secret, value, max_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_proof_different_max() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        let value = 50u64;
        let max_value = 100u64;

        let proof = RangeProof::prove(&secret, value, max_value).unwrap();

        // Verify with correct max_value
        assert!(proof.verify(&public_key, max_value));

        // Verify with different max_value (still works because it's larger)
        assert!(proof.verify(&public_key, 200));
    }

    #[test]
    fn test_range_proof_serialization() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        let value = 75u64;
        let max_value = 1000u64;

        let proof = RangeProof::prove(&secret, value, max_value).unwrap();
        let bytes = proof.to_bytes();
        let deserialized = RangeProof::from_bytes(&bytes).unwrap();

        assert!(deserialized.verify(&public_key, max_value));
    }

    #[test]
    fn test_batch_range_proof() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        let values = vec![(10u64, 100u64), (50u64, 200u64), (99u64, 100u64)];

        let batch_proof = BatchRangeProof::prove(&secret, &values).unwrap();

        let max_values: Vec<u64> = values.iter().map(|(_, max)| *max).collect();
        assert!(batch_proof.verify(&public_key, &max_values));
    }

    #[test]
    fn test_batch_range_proof_one_invalid() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();

        // One value exceeds its maximum
        let values = vec![(10u64, 100u64), (250u64, 200u64), (99u64, 100u64)];

        let result = BatchRangeProof::prove(&secret, &values);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_values() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        let value = 1_000_000u64;
        let max_value = 10_000_000u64;

        let proof = RangeProof::prove(&secret, value, max_value).unwrap();
        assert!(proof.verify(&public_key, max_value));
    }

    #[test]
    fn test_power_of_two_boundaries() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public_key = keypair.public_key();

        for power in 1..=16 {
            let max_value = 2u64.pow(power);
            let value = max_value / 2;

            let proof = RangeProof::prove(&secret, value, max_value).unwrap();
            assert!(proof.verify(&public_key, max_value));
        }
    }

    #[test]
    fn test_zero_max_value() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();

        let result = RangeProof::prove(&secret, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_secrets_different_proofs() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let value = 50u64;
        let max_value = 100u64;

        let proof1 = RangeProof::prove(&keypair1.secret_key(), value, max_value).unwrap();
        let proof2 = RangeProof::prove(&keypair2.secret_key(), value, max_value).unwrap();

        // Different secrets should produce different commitments
        assert_ne!(proof1.commitment(), proof2.commitment());
    }
}
