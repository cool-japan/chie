//! Distributed Key Generation (DKG) using Feldman's VSS.
//!
//! This module provides distributed key generation without a trusted dealer.
//! Multiple parties can jointly generate a shared secret key where no single
//! party knows the full key, but any threshold of parties can reconstruct it.
//!
//! # Features
//!
//! - Feldman's Verifiable Secret Sharing (VSS)
//! - Joint public key derivation
//! - Threshold secret sharing (M-of-N)
//! - Verification of shares without revealing them
//!
//! # Use Cases in CHIE Protocol
//!
//! - Decentralized coordinator setup
//! - Threshold signing for governance
//! - Distributed key management
//!
//! # Example
//!
//! ```
//! use chie_crypto::dkg::{DkgParams, DkgParticipant, aggregate_public_key};
//!
//! // Setup: 3 participants, threshold of 2
//! let params = DkgParams::new(3, 2);
//!
//! // Each participant generates their contribution
//! let mut participants: Vec<_> = (0..3)
//!     .map(|i| DkgParticipant::new(&params, i))
//!     .collect();
//!
//! // Broadcast phase: each participant shares their commitments
//! let commitments: Vec<_> = participants
//!     .iter()
//!     .map(|p| p.get_commitments())
//!     .collect();
//!
//! // Each participant receives shares from others
//! for i in 0..3 {
//!     for j in 0..3 {
//!         if i != j {
//!             let share = participants[j].generate_share(i).unwrap();
//!             participants[i].receive_share(j, share, &commitments[j]).unwrap();
//!         }
//!     }
//! }
//!
//! // Compute joint public key
//! let public_key = aggregate_public_key(&commitments);
//! println!("Joint public key generated!");
//! ```

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
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
#[allow(dead_code)]
fn random_point() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * random_scalar()
}

/// DKG-specific errors.
#[derive(Error, Debug)]
pub enum DkgError {
    #[error("Invalid threshold: must have 1 <= threshold <= total_parties")]
    InvalidThreshold,
    #[error("Invalid participant ID")]
    InvalidParticipantId,
    #[error("Invalid share")]
    InvalidShare,
    #[error("Share verification failed")]
    ShareVerificationFailed,
    #[error("Insufficient shares for reconstruction")]
    InsufficientShares,
    #[error("Duplicate participant ID")]
    DuplicateParticipant,
}

pub type DkgResult<T> = Result<T, DkgError>;

/// Parameters for DKG protocol.
#[derive(Clone, Debug)]
pub struct DkgParams {
    /// Total number of participants
    pub total_parties: usize,
    /// Threshold: minimum parties needed to reconstruct secret
    pub threshold: usize,
    /// Generator point
    g: RistrettoPoint,
}

impl DkgParams {
    /// Create new DKG parameters.
    ///
    /// # Arguments
    ///
    /// * `total_parties` - Total number of participants
    /// * `threshold` - Minimum number of parties needed to reconstruct
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::dkg::DkgParams;
    ///
    /// // 5 parties, threshold of 3
    /// let params = DkgParams::new(5, 3);
    /// assert_eq!(params.total_parties, 5);
    /// assert_eq!(params.threshold, 3);
    /// ```
    pub fn new(total_parties: usize, threshold: usize) -> Self {
        assert!(threshold > 0 && threshold <= total_parties);

        // Use standard Ristretto basepoint for compatibility with other protocols (e.g., FROST)
        let g = RISTRETTO_BASEPOINT_POINT;

        Self {
            total_parties,
            threshold,
            g,
        }
    }
}

/// A participant in the DKG protocol.
pub struct DkgParticipant {
    /// Participant's ID (0-indexed)
    id: usize,
    /// DKG parameters
    params: DkgParams,
    /// Secret polynomial coefficients (a_0, a_1, ..., a_{t-1})
    coefficients: Vec<Scalar>,
    /// Commitments to polynomial coefficients (g^a_0, g^a_1, ...)
    commitments: Vec<RistrettoPoint>,
    /// Shares received from other participants
    received_shares: Vec<Option<Scalar>>,
}

/// Public commitments broadcast by a participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgCommitments {
    /// Participant ID
    pub participant_id: usize,
    /// Commitments to polynomial coefficients
    pub commitments: Vec<Vec<u8>>, // Compressed Ristretto points
}

/// A secret share for a participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgShare {
    /// Scalar value of the share
    value: Vec<u8>, // Scalar bytes
}

impl DkgParticipant {
    /// Create a new DKG participant.
    ///
    /// # Arguments
    ///
    /// * `params` - DKG parameters
    /// * `id` - Participant's ID (0-indexed)
    pub fn new(params: &DkgParams, id: usize) -> Self {
        assert!(id < params.total_parties);

        // Generate random polynomial of degree threshold-1
        // f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
        let coefficients: Vec<Scalar> = (0..params.threshold).map(|_| random_scalar()).collect();

        // Compute commitments: C_i = g^a_i
        let commitments: Vec<RistrettoPoint> =
            coefficients.iter().map(|coeff| params.g * coeff).collect();

        let received_shares = vec![None; params.total_parties];

        Self {
            id,
            params: params.clone(),
            coefficients,
            commitments,
            received_shares,
        }
    }

    /// Get public commitments to broadcast.
    pub fn get_commitments(&self) -> DkgCommitments {
        DkgCommitments {
            participant_id: self.id,
            commitments: self
                .commitments
                .iter()
                .map(|c| c.compress().as_bytes().to_vec())
                .collect(),
        }
    }

    /// Generate a share for participant `target_id`.
    ///
    /// # Arguments
    ///
    /// * `target_id` - ID of the participant to receive this share
    pub fn generate_share(&self, target_id: usize) -> DkgResult<DkgShare> {
        if target_id >= self.params.total_parties {
            return Err(DkgError::InvalidParticipantId);
        }

        // Evaluate polynomial at x = target_id + 1
        // (We add 1 to avoid evaluating at 0)
        let x = Scalar::from((target_id + 1) as u64);
        let share_value = evaluate_polynomial(&self.coefficients, x);

        Ok(DkgShare {
            value: share_value.to_bytes().to_vec(),
        })
    }

    /// Receive and verify a share from another participant.
    ///
    /// # Arguments
    ///
    /// * `from_id` - ID of the sending participant
    /// * `share` - The share received
    /// * `commitments` - Public commitments from the sender
    pub fn receive_share(
        &mut self,
        from_id: usize,
        share: DkgShare,
        commitments: &DkgCommitments,
    ) -> DkgResult<()> {
        if from_id >= self.params.total_parties {
            return Err(DkgError::InvalidParticipantId);
        }

        if commitments.participant_id != from_id {
            return Err(DkgError::InvalidShare);
        }

        if self.received_shares[from_id].is_some() {
            return Err(DkgError::DuplicateParticipant);
        }

        // Deserialize share
        if share.value.len() != 32 {
            return Err(DkgError::InvalidShare);
        }
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&share.value);
        let share_scalar = Scalar::from_bytes_mod_order(share_bytes);

        // Verify share using commitments
        // Check: g^share == C_0 * C_1^x * C_2^x^2 * ... * C_{t-1}^x^{t-1}
        let x = Scalar::from((self.id + 1) as u64);

        let mut expected = RistrettoPoint::identity();
        let mut x_power = Scalar::ONE;

        for commitment_bytes in &commitments.commitments {
            if commitment_bytes.len() != 32 {
                return Err(DkgError::InvalidShare);
            }

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(commitment_bytes);

            let commitment = curve25519_dalek::ristretto::CompressedRistretto(bytes)
                .decompress()
                .ok_or(DkgError::InvalidShare)?;

            expected += commitment * x_power;
            x_power *= x;
        }

        let actual = self.params.g * share_scalar;

        if actual != expected {
            return Err(DkgError::ShareVerificationFailed);
        }

        // Store verified share
        self.received_shares[from_id] = Some(share_scalar);

        Ok(())
    }

    /// Get the participant's secret share (sum of received shares + own share).
    ///
    /// This should only be called after receiving shares from all other participants.
    pub fn get_secret_share(&self) -> DkgResult<Scalar> {
        // Add own share
        let own_share = self.generate_share(self.id)?;
        let mut own_bytes = [0u8; 32];
        own_bytes.copy_from_slice(&own_share.value);
        let mut total = Scalar::from_bytes_mod_order(own_bytes);

        // Add received shares
        for share in self.received_shares.iter().flatten() {
            total += share;
        }

        Ok(total)
    }
}

/// Aggregate public keys from all participants to get joint public key.
///
/// # Arguments
///
/// * `all_commitments` - Commitments from all participants
///
/// # Example
///
/// ```
/// use chie_crypto::dkg::{DkgParams, DkgParticipant, aggregate_public_key};
///
/// let params = DkgParams::new(3, 2);
/// let participants: Vec<_> = (0..3)
///     .map(|i| DkgParticipant::new(&params, i))
///     .collect();
///
/// let commitments: Vec<_> = participants
///     .iter()
///     .map(|p| p.get_commitments())
///     .collect();
///
/// let public_key = aggregate_public_key(&commitments);
/// ```
pub fn aggregate_public_key(all_commitments: &[DkgCommitments]) -> RistrettoPoint {
    // Joint public key is the sum of all first commitments (C_0 from each party)
    let mut joint_pk = RistrettoPoint::identity();

    for commitments in all_commitments {
        if !commitments.commitments.is_empty() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&commitments.commitments[0]);

            if let Some(point) =
                curve25519_dalek::ristretto::CompressedRistretto(bytes).decompress()
            {
                joint_pk += point;
            }
        }
    }

    joint_pk
}

// Helper: Evaluate polynomial at point x
fn evaluate_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;

    for coeff in coefficients {
        result += coeff * x_power;
        x_power *= x;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_basic() {
        let params = DkgParams::new(3, 2);

        let mut participants: Vec<_> = (0..3).map(|i| DkgParticipant::new(&params, i)).collect();

        // Broadcast commitments
        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        // Distribute shares
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let share = participants[j].generate_share(i).unwrap();
                    participants[i]
                        .receive_share(j, share, &commitments[j])
                        .unwrap();
                }
            }
        }

        // Each participant gets their secret share
        let shares: Vec<_> = participants
            .iter()
            .map(|p| p.get_secret_share().unwrap())
            .collect();

        assert_eq!(shares.len(), 3);
    }

    #[test]
    fn test_dkg_aggregate_public_key() {
        let params = DkgParams::new(5, 3);

        let participants: Vec<_> = (0..5).map(|i| DkgParticipant::new(&params, i)).collect();

        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        let public_key = aggregate_public_key(&commitments);

        // Public key should not be identity
        assert_ne!(public_key, RistrettoPoint::identity());
    }

    #[test]
    fn test_dkg_invalid_threshold() {
        let params = DkgParams::new(3, 2);
        let participant = DkgParticipant::new(&params, 0);

        // Try to generate share for invalid participant
        assert!(participant.generate_share(10).is_err());
    }

    #[test]
    fn test_dkg_share_verification() {
        let params = DkgParams::new(3, 2);
        let mut participant0 = DkgParticipant::new(&params, 0);
        let participant1 = DkgParticipant::new(&params, 1);

        let commitments1 = participant1.get_commitments();
        let share = participant1.generate_share(0).unwrap();

        // Should verify correctly
        assert!(
            participant0
                .receive_share(1, share.clone(), &commitments1)
                .is_ok()
        );

        // Should reject duplicate
        assert!(participant0.receive_share(1, share, &commitments1).is_err());
    }

    #[test]
    fn test_dkg_different_thresholds() {
        for (total, threshold) in [(3, 2), (5, 3), (7, 4)] {
            let params = DkgParams::new(total, threshold);

            let mut participants: Vec<_> = (0..total)
                .map(|i| DkgParticipant::new(&params, i))
                .collect();

            let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

            // Distribute shares
            for i in 0..total {
                for j in 0..total {
                    if i != j {
                        let share = participants[j].generate_share(i).unwrap();
                        participants[i]
                            .receive_share(j, share, &commitments[j])
                            .unwrap();
                    }
                }
            }

            // Verify all participants can get their shares
            for p in &participants {
                assert!(p.get_secret_share().is_ok());
            }

            // Verify joint public key
            let pk = aggregate_public_key(&commitments);
            assert_ne!(pk, RistrettoPoint::identity());
        }
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coefficients = vec![
            Scalar::from(1u64), // constant term
            Scalar::from(2u64), // x term
            Scalar::from(3u64), // x^2 term
        ];

        // Evaluate at x=2: 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17
        let x = Scalar::from(2u64);
        let result = evaluate_polynomial(&coefficients, x);
        let expected = Scalar::from(17u64);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_dkg_partial_shares() {
        let params = DkgParams::new(5, 3);
        let mut participants: Vec<_> = (0..5).map(|i| DkgParticipant::new(&params, i)).collect();

        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        // Only distribute shares from 2 participants (less than threshold of 3)
        for i in 0..5 {
            for j in 0..2 {
                if i != j {
                    let share = participants[j].generate_share(i).unwrap();
                    participants[i]
                        .receive_share(j, share, &commitments[j])
                        .unwrap();
                }
            }
        }

        // Participant can still compute a share, but it won't be the full secret
        // This demonstrates that the protocol requires all participants
        let result = participants[0].get_secret_share();
        assert!(result.is_ok());

        // The computed share exists but would be different with all participants
        let partial_share = result.unwrap();
        assert_ne!(partial_share, Scalar::ZERO);
    }

    #[test]
    fn test_dkg_serialization() {
        let params = DkgParams::new(3, 2);
        let participant = DkgParticipant::new(&params, 0);

        let commitments = participant.get_commitments();

        // Serialize
        let serialized = crate::codec::encode(&commitments).unwrap();

        // Deserialize
        let deserialized: DkgCommitments = crate::codec::decode(&serialized).unwrap();

        assert_eq!(
            commitments.commitments.len(),
            deserialized.commitments.len()
        );
        for (orig, deser) in commitments
            .commitments
            .iter()
            .zip(deserialized.commitments.iter())
        {
            assert_eq!(orig, deser);
        }
    }

    #[test]
    fn test_dkg_invalid_share_verification() {
        let params = DkgParams::new(3, 2);
        let mut participant0 = DkgParticipant::new(&params, 0);
        let participant1 = DkgParticipant::new(&params, 1);

        let commitments1 = participant1.get_commitments();

        // Generate a valid share for participant 0
        let valid_share = participant1.generate_share(0).unwrap();

        // Create an invalid share by corrupting the value
        let mut corrupted_value = valid_share.value.clone();
        corrupted_value[0] = corrupted_value[0].wrapping_add(1); // Corrupt first byte
        let invalid_share = DkgShare {
            value: corrupted_value,
        };

        // Should reject invalid share
        let result = participant0.receive_share(1, invalid_share, &commitments1);
        assert!(result.is_err());
        assert!(matches!(result, Err(DkgError::ShareVerificationFailed)));
    }

    #[test]
    fn test_dkg_commitment_consistency() {
        let params = DkgParams::new(3, 2);

        // Create multiple participants
        let participants: Vec<_> = (0..3).map(|i| DkgParticipant::new(&params, i)).collect();

        // Get commitments from each participant
        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        // Verify all commitments have correct length (threshold)
        for commitment in &commitments {
            assert_eq!(commitment.commitments.len(), params.threshold);
        }

        // Verify commitment points are not identity (identity point has specific bytes)
        let identity_bytes = RistrettoPoint::identity().compress().to_bytes();
        for commitment in &commitments {
            for point_bytes in &commitment.commitments {
                assert_ne!(point_bytes.as_slice(), identity_bytes.as_slice());
            }
        }

        // Verify joint public key is deterministic from same commitments
        let pk1 = aggregate_public_key(&commitments);
        let pk2 = aggregate_public_key(&commitments);
        assert_eq!(pk1, pk2);
    }
}
