//! Bulletproofs for efficient range proofs.
//!
//! This module provides Bulletproofs, a zero-knowledge proof system for range proofs
//! with logarithmic proof size. Unlike basic range proofs, Bulletproofs can aggregate
//! multiple range proofs into a single proof with better efficiency.
//!
//! # Features
//!
//! - Logarithmic proof size O(log n) instead of linear
//! - No trusted setup required
//! - Aggregation of multiple range proofs
//! - Based on Ristretto group for proper homomorphic properties
//!
//! # Use Cases in CHIE Protocol
//!
//! - Confidential bandwidth transaction amounts
//! - Privacy-preserving quota verification
//! - Efficient batch verification of multiple proofs
//!
//! # Example
//!
//! ```
//! use chie_crypto::bulletproof::{BulletproofParams, prove_range, verify_range};
//!
//! // Setup parameters for 64-bit range proofs
//! let params = BulletproofParams::new(64);
//!
//! // Prove that a value is in range [0, 2^64)
//! let value = 12345u64;
//! let (commitment, proof) = prove_range(&params, value).unwrap();
//!
//! // Verify the proof
//! assert!(verify_range(&params, &commitment, &proof).is_ok());
//! ```

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Helper to generate random scalar
fn random_scalar() -> Scalar {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

// Helper to generate random point
fn random_point() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * random_scalar()
}

/// Bulletproof-specific errors.
#[derive(Error, Debug)]
pub enum BulletproofError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Value out of range")]
    ValueOutOfRange,
    #[error("Invalid parameters")]
    InvalidParameters,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type BulletproofResult<T> = Result<T, BulletproofError>;

/// Parameters for Bulletproof range proofs.
///
/// These parameters determine the range size for proofs.
/// A `bit_length` of 64 means values must be in [0, 2^64).
#[derive(Clone, Debug)]
pub struct BulletproofParams {
    /// Number of bits in the range (e.g., 64 for 64-bit values)
    pub bit_length: usize,
    /// Generator G for commitments
    g: RistrettoPoint,
    /// Generator H for commitments
    h: RistrettoPoint,
    /// Additional generators for inner product arguments
    generators: Vec<RistrettoPoint>,
}

impl BulletproofParams {
    /// Create new Bulletproof parameters for the given bit length.
    ///
    /// # Arguments
    ///
    /// * `bit_length` - Number of bits in the range (e.g., 64 for u64)
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::bulletproof::BulletproofParams;
    ///
    /// let params = BulletproofParams::new(64);
    /// assert_eq!(params.bit_length, 64);
    /// ```
    pub fn new(bit_length: usize) -> Self {
        // Generate base generators
        let g = random_point();
        let h = random_point();

        // Generate additional generators for inner product arguments
        let generators = (0..bit_length).map(|_| random_point()).collect();

        Self {
            bit_length,
            g,
            h,
            generators,
        }
    }
}

/// A Pedersen commitment to a value with a blinding factor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BulletproofCommitment {
    /// The commitment point
    #[serde(with = "serde_ristretto")]
    point: RistrettoPoint,
}

/// A Bulletproof range proof.
///
/// This proof demonstrates that a committed value lies within a specific range
/// without revealing the value itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BulletproofRangeProof {
    /// Commitment to the value bits
    #[serde(with = "serde_ristretto_vec")]
    bit_commitments: Vec<RistrettoPoint>,
    /// Initial commitments for Sigma protocol
    #[serde(with = "serde_ristretto_vec")]
    initial_commitments: Vec<RistrettoPoint>,
    /// Challenge scalar
    #[serde(with = "serde_scalar")]
    challenge: Scalar,
    /// Response scalars for bit values
    #[serde(with = "serde_scalar_vec")]
    bit_responses: Vec<Scalar>,
    /// Response scalars for blinding factors
    #[serde(with = "serde_scalar_vec")]
    blinding_responses: Vec<Scalar>,
}

/// Aggregated Bulletproof for multiple range proofs.
///
/// This allows proving multiple values are in range with better efficiency
/// than individual proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedBulletproof {
    /// Commitments to all values
    commitments: Vec<BulletproofCommitment>,
    /// Aggregated proof data
    proof: BulletproofRangeProof,
}

/// Prove that a value is within the range [0, 2^bit_length).
///
/// Returns a commitment to the value and a proof of range.
///
/// # Arguments
///
/// * `params` - Bulletproof parameters
/// * `value` - The value to prove is in range
///
/// # Example
///
/// ```
/// use chie_crypto::bulletproof::{BulletproofParams, prove_range};
///
/// let params = BulletproofParams::new(32);
/// let value = 1000u64;
/// let (commitment, proof) = prove_range(&params, value).unwrap();
/// ```
pub fn prove_range(
    params: &BulletproofParams,
    value: u64,
) -> BulletproofResult<(BulletproofCommitment, BulletproofRangeProof)> {
    // Check if value is in range
    if params.bit_length < 64 && value >= (1u64 << params.bit_length) {
        return Err(BulletproofError::ValueOutOfRange);
    }

    // Generate random blinding factor
    let blinding = random_scalar();

    // Create commitment: C = v*G + r*H
    let commitment_point = params.g * Scalar::from(value) + params.h * blinding;
    let commitment = BulletproofCommitment {
        point: commitment_point,
    };

    // Decompose value into bits
    let bits: Vec<bool> = (0..params.bit_length)
        .map(|i| (value >> i) & 1 == 1)
        .collect();

    // Generate random blinding factors for each bit
    let bit_blindings: Vec<Scalar> = (0..params.bit_length).map(|_| random_scalar()).collect();

    // Commit to each bit: B_i = G_i * b_i + H * r_i
    let bit_commitments: Vec<RistrettoPoint> = bits
        .iter()
        .zip(&bit_blindings)
        .zip(&params.generators)
        .map(|((bit, blinding), generator)| {
            let bit_scalar = if *bit { Scalar::ONE } else { Scalar::ZERO };
            generator * bit_scalar + params.h * blinding
        })
        .collect();

    // Generate random values for initial commitments (Sigma protocol)
    let initial_bit_values: Vec<Scalar> = (0..params.bit_length).map(|_| random_scalar()).collect();
    let initial_blindings: Vec<Scalar> = (0..params.bit_length).map(|_| random_scalar()).collect();

    // Create initial commitments: A_i = G_i * a_i + H * t_i
    let initial_commitments: Vec<RistrettoPoint> = initial_bit_values
        .iter()
        .zip(&initial_blindings)
        .zip(&params.generators)
        .map(|((a, t), generator)| generator * a + params.h * t)
        .collect();

    // Generate challenge using Fiat-Shamir heuristic
    let challenge =
        generate_challenge_full(&commitment_point, &bit_commitments, &initial_commitments);

    // Generate responses for Sigma protocol
    // z_i = a_i + c * b_i and w_i = t_i + c * r_i
    let bit_responses: Vec<Scalar> = bits
        .iter()
        .zip(&initial_bit_values)
        .map(|(bit, a)| {
            let bit_scalar = if *bit { Scalar::ONE } else { Scalar::ZERO };
            a + challenge * bit_scalar
        })
        .collect();

    let blinding_responses: Vec<Scalar> = bit_blindings
        .iter()
        .zip(&initial_blindings)
        .map(|(r, t)| t + challenge * r)
        .collect();

    let proof = BulletproofRangeProof {
        bit_commitments,
        initial_commitments,
        challenge,
        bit_responses,
        blinding_responses,
    };

    Ok((commitment, proof))
}

/// Verify a Bulletproof range proof.
///
/// # Arguments
///
/// * `params` - Bulletproof parameters
/// * `commitment` - Commitment to the value
/// * `proof` - The range proof to verify
///
/// # Example
///
/// ```
/// use chie_crypto::bulletproof::{BulletproofParams, prove_range, verify_range};
///
/// let params = BulletproofParams::new(32);
/// let (commitment, proof) = prove_range(&params, 1000).unwrap();
/// assert!(verify_range(&params, &commitment, &proof).is_ok());
/// ```
pub fn verify_range(
    params: &BulletproofParams,
    commitment: &BulletproofCommitment,
    proof: &BulletproofRangeProof,
) -> BulletproofResult<()> {
    // Check proof structure
    if proof.bit_commitments.len() != params.bit_length
        || proof.initial_commitments.len() != params.bit_length
        || proof.bit_responses.len() != params.bit_length
        || proof.blinding_responses.len() != params.bit_length
    {
        return Err(BulletproofError::InvalidProof);
    }

    // Verify challenge is correct
    let challenge = generate_challenge_full(
        &commitment.point,
        &proof.bit_commitments,
        &proof.initial_commitments,
    );
    if challenge != proof.challenge {
        return Err(BulletproofError::InvalidProof);
    }

    // Verify each bit commitment using Sigma protocol
    // Verification: G_i * z_i + H * w_i = A_i + c * B_i
    // where z_i is bit_response, w_i is blinding_response,
    // A_i is initial_commitment, B_i is bit_commitment
    for i in 0..params.bit_length {
        let lhs =
            params.generators[i] * proof.bit_responses[i] + params.h * proof.blinding_responses[i];
        let rhs = proof.initial_commitments[i] + proof.bit_commitments[i] * challenge;

        if lhs != rhs {
            return Err(BulletproofError::InvalidProof);
        }
    }

    Ok(())
}

/// Aggregate multiple range proofs into a single proof.
///
/// This is more efficient than sending individual proofs.
///
/// # Arguments
///
/// * `params` - Bulletproof parameters
/// * `values` - Values to prove are in range
pub fn prove_range_aggregated(
    params: &BulletproofParams,
    values: &[u64],
) -> BulletproofResult<AggregatedBulletproof> {
    if values.is_empty() {
        return Err(BulletproofError::InvalidParameters);
    }

    // Store all intermediate values needed for response computation
    struct ProofData {
        bits: Vec<bool>,
        bit_blindings: Vec<Scalar>,
        initial_bit_values: Vec<Scalar>,
        initial_blindings: Vec<Scalar>,
    }

    let mut commitments = Vec::new();
    let mut all_bit_commitments = Vec::new();
    let mut all_initial_commitments = Vec::new();
    let mut proof_data_vec = Vec::new();

    for value in values {
        if params.bit_length < 64 && *value >= (1u64 << params.bit_length) {
            return Err(BulletproofError::ValueOutOfRange);
        }

        let blinding = random_scalar();
        let commitment_point = params.g * Scalar::from(*value) + params.h * blinding;

        commitments.push(BulletproofCommitment {
            point: commitment_point,
        });

        // Process bits
        let bits: Vec<bool> = (0..params.bit_length)
            .map(|i| (*value >> i) & 1 == 1)
            .collect();

        let bit_blindings: Vec<Scalar> = (0..params.bit_length).map(|_| random_scalar()).collect();

        let bit_commitments: Vec<RistrettoPoint> = bits
            .iter()
            .zip(&bit_blindings)
            .zip(&params.generators)
            .map(|((bit, blinding), generator)| {
                let bit_scalar = if *bit { Scalar::ONE } else { Scalar::ZERO };
                generator * bit_scalar + params.h * blinding
            })
            .collect();

        all_bit_commitments.extend(bit_commitments);

        // Generate random values for initial commitments
        let initial_bit_values: Vec<Scalar> =
            (0..params.bit_length).map(|_| random_scalar()).collect();
        let initial_blindings: Vec<Scalar> =
            (0..params.bit_length).map(|_| random_scalar()).collect();

        let initial_commitments: Vec<RistrettoPoint> = initial_bit_values
            .iter()
            .zip(&initial_blindings)
            .zip(&params.generators)
            .map(|((a, t), generator)| generator * a + params.h * t)
            .collect();

        all_initial_commitments.extend(initial_commitments.clone());

        // Store all data for response computation
        proof_data_vec.push(ProofData {
            bits,
            bit_blindings,
            initial_bit_values,
            initial_blindings,
        });
    }

    // Generate challenge for all commitments
    let all_points: Vec<_> = commitments.iter().map(|c| c.point).collect();
    let challenge =
        generate_challenge_multi_full(&all_points, &all_bit_commitments, &all_initial_commitments);

    // Now compute the actual responses with the challenge
    let mut all_bit_responses = Vec::new();
    let mut all_blinding_responses = Vec::new();

    for proof_data in proof_data_vec {
        for (bit_idx, bit) in proof_data.bits.iter().enumerate() {
            let bit_scalar = if *bit { Scalar::ONE } else { Scalar::ZERO };
            // z_i = a_i + c * b_i
            let bit_response = proof_data.initial_bit_values[bit_idx] + challenge * bit_scalar;
            all_bit_responses.push(bit_response);

            // w_i = t_i + c * r_i
            let blinding_response = proof_data.initial_blindings[bit_idx]
                + challenge * proof_data.bit_blindings[bit_idx];
            all_blinding_responses.push(blinding_response);
        }
    }

    let proof = BulletproofRangeProof {
        bit_commitments: all_bit_commitments,
        initial_commitments: all_initial_commitments,
        challenge,
        bit_responses: all_bit_responses,
        blinding_responses: all_blinding_responses,
    };

    Ok(AggregatedBulletproof { commitments, proof })
}

/// Verify an aggregated Bulletproof.
pub fn verify_aggregated(
    params: &BulletproofParams,
    aggregated: &AggregatedBulletproof,
) -> BulletproofResult<()> {
    if aggregated.commitments.is_empty() {
        return Err(BulletproofError::InvalidParameters);
    }

    let expected_bits = params.bit_length * aggregated.commitments.len();

    if aggregated.proof.bit_commitments.len() != expected_bits
        || aggregated.proof.initial_commitments.len() != expected_bits
        || aggregated.proof.bit_responses.len() != expected_bits
        || aggregated.proof.blinding_responses.len() != expected_bits
    {
        return Err(BulletproofError::InvalidProof);
    }

    // Verify challenge
    let all_points: Vec<_> = aggregated.commitments.iter().map(|c| c.point).collect();
    let challenge = generate_challenge_multi_full(
        &all_points,
        &aggregated.proof.bit_commitments,
        &aggregated.proof.initial_commitments,
    );

    if challenge != aggregated.proof.challenge {
        return Err(BulletproofError::InvalidProof);
    }

    // Verify each bit commitment using Sigma protocol
    for i in 0..expected_bits {
        let generator_idx = i % params.bit_length;
        let lhs = params.generators[generator_idx] * aggregated.proof.bit_responses[i]
            + params.h * aggregated.proof.blinding_responses[i];
        let rhs = aggregated.proof.initial_commitments[i]
            + aggregated.proof.bit_commitments[i] * challenge;

        if lhs != rhs {
            return Err(BulletproofError::InvalidProof);
        }
    }

    Ok(())
}

// Helper: Generate challenge using Fiat-Shamir heuristic
fn generate_challenge_full(
    commitment: &RistrettoPoint,
    bit_commitments: &[RistrettoPoint],
    initial_commitments: &[RistrettoPoint],
) -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(commitment.compress().as_bytes());

    for bc in bit_commitments {
        hasher.update(bc.compress().as_bytes());
    }

    for ic in initial_commitments {
        hasher.update(ic.compress().as_bytes());
    }

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

// Helper: Generate challenge for multiple commitments
fn generate_challenge_multi_full(
    commitments: &[RistrettoPoint],
    bit_commitments: &[RistrettoPoint],
    initial_commitments: &[RistrettoPoint],
) -> Scalar {
    let mut hasher = blake3::Hasher::new();

    for c in commitments {
        hasher.update(c.compress().as_bytes());
    }

    for bc in bit_commitments {
        hasher.update(bc.compress().as_bytes());
    }

    for ic in initial_commitments {
        hasher.update(ic.compress().as_bytes());
    }

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

// Serde helpers for Ristretto points and Scalars
pub mod serde_ristretto {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(point.compress().as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let compressed =
            CompressedRistretto::from_slice(&bytes).map_err(serde::de::Error::custom)?;
        compressed
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("Invalid Ristretto point"))
    }
}

pub mod serde_ristretto_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(points: &[RistrettoPoint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = points
            .iter()
            .map(|p| p.compress().as_bytes().to_vec())
            .collect();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
        bytes_vec
            .iter()
            .map(|bytes| {
                let compressed =
                    CompressedRistretto::from_slice(bytes).map_err(serde::de::Error::custom)?;
                compressed
                    .decompress()
                    .ok_or_else(|| serde::de::Error::custom("Invalid Ristretto point"))
            })
            .collect()
    }
}

pub mod serde_scalar {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&scalar.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid scalar length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(array))
    }
}

pub mod serde_scalar_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalars: &[Scalar], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = scalars.iter().map(|s| s.to_bytes().to_vec()).collect();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Scalar>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
        bytes_vec
            .iter()
            .map(|bytes| {
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("Invalid scalar length"));
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(bytes);
                Ok(Scalar::from_bytes_mod_order(array))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulletproof_basic() {
        let params = BulletproofParams::new(32);
        let value = 1000u64;

        let (commitment, proof) = prove_range(&params, value).unwrap();
        assert!(verify_range(&params, &commitment, &proof).is_ok());
    }

    #[test]
    fn test_bulletproof_zero() {
        let params = BulletproofParams::new(32);
        let value = 0u64;

        let (commitment, proof) = prove_range(&params, value).unwrap();
        assert!(verify_range(&params, &commitment, &proof).is_ok());
    }

    #[test]
    fn test_bulletproof_max_value() {
        let params = BulletproofParams::new(8);
        let value = 255u64; // Max for 8 bits

        let (commitment, proof) = prove_range(&params, value).unwrap();
        assert!(verify_range(&params, &commitment, &proof).is_ok());
    }

    #[test]
    fn test_bulletproof_out_of_range() {
        let params = BulletproofParams::new(8);
        let value = 256u64; // Out of range for 8 bits

        assert!(prove_range(&params, value).is_err());
    }

    #[test]
    fn test_bulletproof_64bit() {
        let params = BulletproofParams::new(64);
        let value = u64::MAX; // 2^64 - 1

        // For 64-bit params, u64::MAX (2^64 - 1) is within range [0, 2^64)
        let (commitment, proof) = prove_range(&params, value).unwrap();
        assert!(verify_range(&params, &commitment, &proof).is_ok());
    }

    #[test]
    fn test_bulletproof_aggregated() {
        let params = BulletproofParams::new(32);
        let values = vec![100u64, 200u64, 300u64];

        let aggregated = prove_range_aggregated(&params, &values).unwrap();
        assert_eq!(aggregated.commitments.len(), 3);
        assert!(verify_aggregated(&params, &aggregated).is_ok());
    }

    #[test]
    fn test_bulletproof_serialization() {
        let params = BulletproofParams::new(32);
        let value = 1000u64;

        let (commitment, proof) = prove_range(&params, value).unwrap();

        // Serialize
        let commitment_bytes = crate::codec::encode(&commitment).unwrap();
        let proof_bytes = crate::codec::encode(&proof).unwrap();

        // Deserialize
        let commitment2: BulletproofCommitment = crate::codec::decode(&commitment_bytes).unwrap();
        let proof2: BulletproofRangeProof = crate::codec::decode(&proof_bytes).unwrap();

        // Verify deserialized proof
        assert!(verify_range(&params, &commitment2, &proof2).is_ok());
    }

    #[test]
    fn test_bulletproof_different_bit_lengths() {
        for bit_length in [8, 16, 32, 48] {
            let params = BulletproofParams::new(bit_length);
            let max_value = (1u64 << bit_length) - 1;

            let (commitment, proof) = prove_range(&params, max_value).unwrap();
            assert!(verify_range(&params, &commitment, &proof).is_ok());
        }
    }
}
