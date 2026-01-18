//! Pedersen commitments for privacy-preserving bandwidth proof aggregation.
//!
//! This module provides Pedersen commitments with homomorphic properties,
//! enabling privacy-preserving aggregation of bandwidth proofs in the CHIE protocol.
//!
//! # Features
//! - Homomorphic commitments: C(a) + C(b) = C(a+b)
//! - Privacy-preserving bandwidth aggregation
//! - Commitment verification without revealing values
//! - Batch commitment operations
//!
//! # Example
//! ```
//! use chie_crypto::pedersen::{PedersenCommitment, commit, verify};
//!
//! // Commit to bandwidth values
//! let (commitment1, opening1) = commit(100);  // 100 bytes
//! let (commitment2, opening2) = commit(200);  // 200 bytes
//!
//! // Aggregate commitments
//! let aggregated = commitment1.add(&commitment2);
//! let aggregated_opening = opening1.add(&opening2);
//!
//! // Verify aggregated commitment (300 bytes total)
//! assert!(verify(&aggregated, 300, &aggregated_opening));
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Pedersen commitment (mG + rH).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// Compressed commitment point (32 bytes).
    #[serde(with = "serde_bytes_32")]
    point: [u8; 32],
}

/// Opening information for a Pedersen commitment.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PedersenOpening {
    /// Blinding factor (scalar).
    #[serde(with = "serde_bytes_32")]
    blinding: [u8; 32],
}

/// Errors that can occur with Pedersen commitments.
#[derive(Debug, Error)]
pub enum PedersenError {
    /// Invalid commitment point.
    #[error("Invalid commitment point")]
    InvalidCommitment,

    /// Verification failed.
    #[error("Verification failed")]
    VerificationFailed,

    /// Invalid blinding factor.
    #[error("Invalid blinding factor")]
    InvalidBlinding,
}

pub type PedersenResult<T> = Result<T, PedersenError>;

// Serde helper for [u8; 32]
mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}

impl PedersenCommitment {
    /// Create a commitment from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> PedersenResult<Self> {
        // Verify the point is valid
        CompressedRistretto(bytes)
            .decompress()
            .ok_or(PedersenError::InvalidCommitment)?;
        Ok(Self { point: bytes })
    }

    /// Get the commitment as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.point
    }

    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point
    }

    /// Add two commitments (homomorphic property).
    ///
    /// C(a) + C(b) = C(a+b)
    ///
    /// # Example
    /// ```
    /// use chie_crypto::pedersen::commit;
    ///
    /// let (c1, _) = commit(100);
    /// let (c2, _) = commit(200);
    /// let sum = c1.add(&c2);
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        let p1 = CompressedRistretto(self.point).decompress().unwrap();
        let p2 = CompressedRistretto(other.point).decompress().unwrap();
        let sum = (p1 + p2).compress();
        Self {
            point: sum.to_bytes(),
        }
    }

    /// Subtract two commitments.
    ///
    /// C(a) - C(b) = C(a-b)
    pub fn sub(&self, other: &Self) -> Self {
        let p1 = CompressedRistretto(self.point).decompress().unwrap();
        let p2 = CompressedRistretto(other.point).decompress().unwrap();
        let diff = (p1 - p2).compress();
        Self {
            point: diff.to_bytes(),
        }
    }

    /// Multiply commitment by a scalar.
    ///
    /// n * C(a) = C(n*a)
    pub fn mul(&self, scalar: u64) -> Self {
        let p = CompressedRistretto(self.point).decompress().unwrap();
        let s = Scalar::from(scalar);
        let result = (s * p).compress();
        Self {
            point: result.to_bytes(),
        }
    }
}

impl PedersenOpening {
    /// Create an opening from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { blinding: bytes }
    }

    /// Get the blinding factor as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.blinding
    }

    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.blinding
    }

    /// Add two openings (homomorphic property).
    ///
    /// When combining commitments C(a) + C(b), combine openings too.
    ///
    /// # Example
    /// ```
    /// use chie_crypto::pedersen::commit;
    ///
    /// let (_, o1) = commit(100);
    /// let (_, o2) = commit(200);
    /// let combined = o1.add(&o2);
    /// ```
    pub fn add(&self, other: &Self) -> Self {
        let s1 = Scalar::from_bytes_mod_order(self.blinding);
        let s2 = Scalar::from_bytes_mod_order(other.blinding);
        let sum = s1 + s2;
        Self {
            blinding: sum.to_bytes(),
        }
    }

    /// Subtract two openings.
    pub fn sub(&self, other: &Self) -> Self {
        let s1 = Scalar::from_bytes_mod_order(self.blinding);
        let s2 = Scalar::from_bytes_mod_order(other.blinding);
        let diff = s1 - s2;
        Self {
            blinding: diff.to_bytes(),
        }
    }

    /// Multiply opening by a scalar.
    pub fn mul(&self, scalar: u64) -> Self {
        let s1 = Scalar::from_bytes_mod_order(self.blinding);
        let s2 = Scalar::from(scalar);
        let product = s1 * s2;
        Self {
            blinding: product.to_bytes(),
        }
    }
}

/// Commit to a value using Pedersen commitment.
///
/// Returns (commitment, opening) pair.
///
/// # Arguments
/// * `value` - The value to commit to (e.g., bandwidth in bytes)
///
/// # Example
/// ```
/// use chie_crypto::pedersen::commit;
///
/// let (commitment, opening) = commit(1024);
/// ```
pub fn commit(value: u64) -> (PedersenCommitment, PedersenOpening) {
    let mut rng = rand::thread_rng();
    let mut blinding_bytes = [0u8; 32];
    rng.fill(&mut blinding_bytes);
    let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

    let opening = PedersenOpening {
        blinding: blinding.to_bytes(),
    };
    let commitment = compute_commitment(value, &opening);

    (commitment, opening)
}

/// Commit to a value with a specific blinding factor.
///
/// # Arguments
/// * `value` - The value to commit to
/// * `blinding` - The blinding factor
///
/// # Returns
/// The Pedersen commitment.
pub fn commit_with_blinding(value: u64, blinding: &PedersenOpening) -> PedersenCommitment {
    compute_commitment(value, blinding)
}

/// Verify a Pedersen commitment.
///
/// # Arguments
/// * `commitment` - The commitment to verify
/// * `value` - The claimed value
/// * `opening` - The opening information
///
/// # Returns
/// `true` if the commitment is valid, `false` otherwise.
///
/// # Example
/// ```
/// use chie_crypto::pedersen::{commit, verify};
///
/// let (commitment, opening) = commit(1024);
/// assert!(verify(&commitment, 1024, &opening));
/// assert!(!verify(&commitment, 2048, &opening));
/// ```
pub fn verify(commitment: &PedersenCommitment, value: u64, opening: &PedersenOpening) -> bool {
    let expected = compute_commitment(value, opening);
    expected == *commitment
}

/// Verify a batch of commitments.
///
/// # Arguments
/// * `commitments` - Slice of commitments
/// * `values` - Slice of claimed values
/// * `openings` - Slice of openings
///
/// # Returns
/// `true` if all commitments are valid.
pub fn verify_batch(
    commitments: &[PedersenCommitment],
    values: &[u64],
    openings: &[PedersenOpening],
) -> bool {
    if commitments.len() != values.len() || commitments.len() != openings.len() {
        return false;
    }

    commitments
        .iter()
        .zip(values.iter())
        .zip(openings.iter())
        .all(|((c, v), o)| verify(c, *v, o))
}

/// Compute the Pedersen commitment: C = vG + rH.
fn compute_commitment(value: u64, opening: &PedersenOpening) -> PedersenCommitment {
    // G = Ristretto base point
    let g = RISTRETTO_BASEPOINT_POINT;

    // H = BLAKE3("pedersen-h") as Ristretto point
    let h = get_h_generator();

    // Convert value and blinding to scalars
    let value_scalar = Scalar::from(value);
    let blinding_scalar = Scalar::from_bytes_mod_order(opening.blinding);

    // Compute C = vG + rH
    let commitment_point = value_scalar * g + blinding_scalar * h;

    PedersenCommitment {
        point: commitment_point.compress().to_bytes(),
    }
}

/// Get the second generator H for Pedersen commitments.
///
/// H is derived by hashing a fixed string and converting to a Ristretto point.
fn get_h_generator() -> RistrettoPoint {
    // Use a deterministic hash to create the second generator
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"chie-pedersen-h-generator-v1");
    let hash = hasher.finalize();

    // Convert hash to scalar and multiply by base point to get H
    let scalar = Scalar::from_bytes_mod_order(*hash.as_bytes());
    scalar * RISTRETTO_BASEPOINT_POINT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_and_verify() {
        let (commitment, opening) = commit(1024);
        assert!(verify(&commitment, 1024, &opening));
        assert!(!verify(&commitment, 2048, &opening));
    }

    #[test]
    fn test_homomorphic_addition() {
        let (c1, o1) = commit(100);
        let (c2, o2) = commit(200);

        let sum_commitment = c1.add(&c2);
        let sum_opening = o1.add(&o2);

        assert!(verify(&sum_commitment, 300, &sum_opening));
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let (c1, o1) = commit(500);
        let (c2, o2) = commit(200);

        let diff_commitment = c1.sub(&c2);
        let diff_opening = o1.sub(&o2);

        assert!(verify(&diff_commitment, 300, &diff_opening));
    }

    #[test]
    fn test_scalar_multiplication() {
        let (commitment, opening) = commit(100);

        let scaled_commitment = commitment.mul(3);
        let scaled_opening = opening.mul(3);

        assert!(verify(&scaled_commitment, 300, &scaled_opening));
    }

    #[test]
    fn test_batch_verification() {
        let (c1, o1) = commit(100);
        let (c2, o2) = commit(200);
        let (c3, o3) = commit(300);

        let commitments = vec![c1, c2, c3];
        let values = vec![100, 200, 300];
        let openings = vec![o1, o2, o3];

        assert!(verify_batch(&commitments, &values, &openings));

        // Wrong values should fail
        let wrong_values = vec![100, 200, 400];
        assert!(!verify_batch(&commitments, &wrong_values, &openings));
    }

    #[test]
    fn test_commitment_serialization() {
        let (commitment, _) = commit(1024);

        let bytes = commitment.to_bytes();
        let restored = PedersenCommitment::from_bytes(bytes).unwrap();

        assert_eq!(commitment, restored);
    }

    #[test]
    fn test_opening_serialization() {
        let (_, opening) = commit(1024);

        let bytes = opening.to_bytes();
        let restored = PedersenOpening::from_bytes(bytes);

        // Should work with same commitment
        let commitment = commit_with_blinding(1024, &restored);
        assert!(verify(&commitment, 1024, &restored));
    }

    #[test]
    fn test_bandwidth_aggregation_scenario() {
        // Simulate 3 peers contributing bandwidth
        let (bandwidth1, opening1) = commit(1024); // 1 KB
        let (bandwidth2, opening2) = commit(2048); // 2 KB
        let (bandwidth3, opening3) = commit(4096); // 4 KB

        // Aggregate without revealing individual contributions
        let total_bandwidth = bandwidth1.add(&bandwidth2).add(&bandwidth3);
        let total_opening = opening1.add(&opening2).add(&opening3);

        // Coordinator can verify total is 7 KB without knowing individual amounts
        assert!(verify(&total_bandwidth, 7168, &total_opening));
    }

    #[test]
    fn test_different_values_different_commitments() {
        let (c1, _) = commit(100);
        let (c2, _) = commit(100);

        // Same value but different blinding = different commitments
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_zero_value_commitment() {
        let (commitment, opening) = commit(0);
        assert!(verify(&commitment, 0, &opening));
    }

    #[test]
    fn test_large_value() {
        let large_value = 1_000_000_000u64; // 1 GB
        let (commitment, opening) = commit(large_value);
        assert!(verify(&commitment, large_value, &opening));
    }

    #[test]
    fn test_commitment_commutativity() {
        let (c1, o1) = commit(100);
        let (c2, o2) = commit(200);

        let sum1 = c1.add(&c2);
        let sum2 = c2.add(&c1);

        assert_eq!(sum1, sum2);

        let opening_sum1 = o1.add(&o2);
        let opening_sum2 = o2.add(&o1);

        assert!(verify(&sum1, 300, &opening_sum1));
        assert!(verify(&sum2, 300, &opening_sum2));
    }
}
