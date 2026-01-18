//! FROST: Flexible Round-Optimized Schnorr Threshold Signatures
//!
//! FROST is a threshold signature scheme that produces standard Schnorr signatures
//! with only 2 rounds of communication. It's significantly more efficient than
//! threshold ECDSA while maintaining strong security properties.
//!
//! # Features
//!
//! - **2-round signing protocol**: More efficient than threshold ECDSA (3+ rounds)
//! - **Standard Schnorr signatures**: Output is indistinguishable from single-party Schnorr
//! - **Robust against rogue-key attacks**: Using proof-of-possession
//! - **Supports any t-of-n threshold**: Flexible threshold configurations
//! - **Dealer-free key generation**: Based on Pedersen DKG
//!
//! # Protocol Overview
//!
//! 1. **Key Generation Phase** (one-time setup):
//!    - Run distributed key generation (DKG) to create shares
//!    - Each participant gets a secret share and the group public key
//!
//! 2. **Preprocessing Phase** (can be done in advance):
//!    - Each signer generates commitment pairs (d, e) and sends commitments
//!    - Stores (d, e, D, E) for later use
//!
//! 3. **Signing Round 1**:
//!    - Coordinator selects signing set and message
//!    - Each signer reveals one commitment pair (D_i, E_i)
//!
//! 4. **Signing Round 2**:
//!    - Coordinator computes binding value and challenge
//!    - Each signer computes partial signature z_i
//!    - Coordinator aggregates into full signature (R, z)
//!
//! # Example
//!
//! ```
//! use chie_crypto::frost::{FrostKeygen, FrostSigner, aggregate_frost_signatures, verify_frost_signature};
//!
//! // Setup: 2-of-3 threshold
//! let threshold = 2;
//! let num_signers = 3;
//!
//! // Key generation (one-time setup)
//! let mut keygen = FrostKeygen::new(threshold, num_signers);
//! let shares = keygen.generate_shares();
//!
//! // Create signers
//! let mut signers: Vec<_> = shares.iter().enumerate()
//!     .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), keygen.group_public_key()))
//!     .collect();
//!
//! // Preprocessing: Generate nonce commitments
//! for signer in &mut signers {
//!     signer.preprocess();
//! }
//!
//! let message = b"Transaction data";
//!
//! // Signing Round 1: Collect nonce commitments from threshold signers
//! let signing_set = vec![1, 2]; // Use signers 1 and 2
//! let commitments: Vec<_> = signing_set.iter()
//!     .map(|&id| signers[id - 1].get_nonce_commitment())
//!     .collect();
//!
//! // Signing Round 2: Generate partial signatures
//! let partial_sigs: Vec<_> = signing_set.iter()
//!     .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
//!     .collect::<Result<Vec<_>, _>>()
//!     .unwrap();
//!
//! // Aggregate into final signature
//! let signature = aggregate_frost_signatures(
//!     message,
//!     &signing_set,
//!     &commitments,
//!     &partial_sigs,
//! ).unwrap();
//!
//! // Verify with group public key
//! assert!(verify_frost_signature(&keygen.group_public_key(), message, &signature).is_ok());
//! ```

use crate::dkg::{DkgParams, DkgParticipant};
use crate::signing::{PublicKey, SignatureBytes};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FrostError {
    #[error("Invalid threshold: must be 1 <= t <= n")]
    InvalidThreshold,
    #[error("Insufficient signers: need at least {0} but got {1}")]
    InsufficientSigners(usize, usize),
    #[error("Invalid signer ID: {0}")]
    InvalidSignerId(usize),
    #[error("Duplicate signer ID: {0}")]
    DuplicateSignerId(usize),
    #[error("Missing nonce commitment for signer {0}")]
    MissingFrostNonceCommitment(usize),
    #[error("Nonce not preprocessed")]
    NonceNotPreprocessed,
    #[error("Invalid signature share")]
    InvalidSignatureShare,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type FrostResult<T> = Result<T, FrostError>;

/// Secret share for a FROST participant
#[derive(Clone, Serialize, Deserialize)]
pub struct FrostSecretShare {
    /// Participant index (1-indexed)
    pub index: usize,
    /// Secret share value
    pub secret: Scalar,
    /// Verification shares for other participants (for VSS verification)
    pub verification_shares: Vec<RistrettoPoint>,
}

/// Nonce commitment pair for FROST preprocessing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrostNonceCommitment {
    /// Hiding nonce commitment D = d * G
    pub hiding: RistrettoPoint,
    /// Binding nonce commitment E = e * G
    pub binding: RistrettoPoint,
}

/// Partial signature from a FROST signer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Signer index
    pub signer_id: usize,
    /// Signature share z_i
    pub z: Scalar,
}

/// FROST key generation using Pedersen DKG
pub struct FrostKeygen {
    threshold: usize,
    num_participants: usize,
    group_public_key: Option<PublicKey>,
    shares: Vec<FrostSecretShare>,
}

impl FrostKeygen {
    /// Create a new FROST key generation instance
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum number of signers required (t)
    /// * `num_participants` - Total number of participants (n)
    pub fn new(threshold: usize, num_participants: usize) -> Self {
        Self {
            threshold,
            num_participants,
            group_public_key: None,
            shares: Vec::new(),
        }
    }

    /// Generate secret shares using DKG
    pub fn generate_shares(&mut self) -> Vec<FrostSecretShare> {
        // Use DKG for key generation
        let params = DkgParams::new(self.num_participants, self.threshold);
        let mut participants: Vec<_> = (0..self.num_participants)
            .map(|i| DkgParticipant::new(&params, i))
            .collect();

        // Round 1: Broadcast commitments
        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        // Round 2: Distribute shares
        for i in 0..self.num_participants {
            for j in 0..self.num_participants {
                if i != j {
                    let share = participants[j].generate_share(i).unwrap();
                    participants[i]
                        .receive_share(j, share, &commitments[j])
                        .unwrap();
                }
            }
        }

        // Compute final shares
        self.shares = participants
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let secret = p.get_secret_share().unwrap();
                FrostSecretShare {
                    index: i + 1,
                    secret,
                    verification_shares: commitments
                        .iter()
                        .map(|c| {
                            use curve25519_dalek::ristretto::CompressedRistretto;
                            let mut bytes = [0u8; 32];
                            bytes.copy_from_slice(&c.commitments[0]);
                            CompressedRistretto(bytes).decompress().unwrap()
                        })
                        .collect(),
                }
            })
            .collect();

        // Compute group public key using DKG aggregate function
        let group_point = crate::dkg::aggregate_public_key(&commitments);
        self.group_public_key = Some(group_point.compress().to_bytes());

        self.shares.clone()
    }

    /// Get the group public key
    pub fn group_public_key(&self) -> PublicKey {
        self.group_public_key.unwrap()
    }
}

/// FROST signer instance
pub struct FrostSigner {
    /// Signer index (1-indexed)
    signer_id: usize,
    /// Secret share
    secret_share: FrostSecretShare,
    /// Group public key
    group_public_key: PublicKey,
    /// Preprocessed nonce pair (d, e)
    nonce_pair: Option<(Scalar, Scalar)>,
    /// Nonce commitment (D, E)
    nonce_commitment: Option<FrostNonceCommitment>,
}

impl FrostSigner {
    /// Create a new FROST signer
    pub fn new(
        signer_id: usize,
        secret_share: FrostSecretShare,
        group_public_key: PublicKey,
    ) -> Self {
        Self {
            signer_id,
            secret_share,
            group_public_key,
            nonce_pair: None,
            nonce_commitment: None,
        }
    }

    /// Preprocess: Generate nonce commitment pair
    ///
    /// This can be done in advance before knowing the message to be signed.
    /// Generates random nonces (d, e) and computes commitments (D, E).
    pub fn preprocess(&mut self) {
        let d = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let e = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());

        let hiding = d * RISTRETTO_BASEPOINT_POINT;
        let binding = e * RISTRETTO_BASEPOINT_POINT;

        self.nonce_pair = Some((d, e));
        self.nonce_commitment = Some(FrostNonceCommitment { hiding, binding });
    }

    /// Get nonce commitment for Round 1
    pub fn get_nonce_commitment(&self) -> FrostNonceCommitment {
        self.nonce_commitment
            .clone()
            .expect("Nonce not preprocessed")
    }

    /// Sign message in Round 2
    ///
    /// # Arguments
    ///
    /// * `message` - Message to sign
    /// * `signing_set` - List of signer IDs participating in this signature
    /// * `commitments` - Nonce commitments from all signers in signing_set
    pub fn sign(
        &self,
        message: &[u8],
        signing_set: &[usize],
        commitments: &[FrostNonceCommitment],
    ) -> FrostResult<PartialSignature> {
        if self.nonce_pair.is_none() {
            return Err(FrostError::NonceNotPreprocessed);
        }

        let (d, e) = self.nonce_pair.unwrap();

        // Compute binding value rho = H(message, commitments)
        let rho = compute_binding_value(message, commitments);

        // Compute group commitment R = sum(D_i + rho * E_i)
        let group_commitment: RistrettoPoint =
            commitments.iter().map(|c| c.hiding + rho * c.binding).sum();

        // Compute challenge c = H(group_public_key, R, message)
        let challenge = compute_challenge(&self.group_public_key, &group_commitment, message);

        // Compute Lagrange coefficient
        let lambda = compute_lagrange_coefficient(self.signer_id, signing_set);

        // Compute signature share: z_i = d_i + (rho * e_i) + (lambda_i * s_i * c)
        let z = d + (rho * e) + (lambda * self.secret_share.secret * challenge);

        Ok(PartialSignature {
            signer_id: self.signer_id,
            z,
        })
    }
}

/// Aggregate partial signatures into a full Schnorr signature
///
/// # Arguments
///
/// * `message` - Message that was signed
/// * `signing_set` - List of signer IDs that participated
/// * `commitments` - Nonce commitments from all signers
/// * `partial_sigs` - Partial signatures from all signers
pub fn aggregate_frost_signatures(
    message: &[u8],
    signing_set: &[usize],
    commitments: &[FrostNonceCommitment],
    partial_sigs: &[PartialSignature],
) -> FrostResult<SignatureBytes> {
    if partial_sigs.len() < signing_set.len() {
        return Err(FrostError::InsufficientSigners(
            signing_set.len(),
            partial_sigs.len(),
        ));
    }

    // Compute binding value
    let rho = compute_binding_value(message, commitments);

    // Compute group commitment R
    let group_commitment: RistrettoPoint =
        commitments.iter().map(|c| c.hiding + rho * c.binding).sum();

    // Aggregate signature shares: z = sum(z_i)
    let z: Scalar = partial_sigs.iter().map(|sig| sig.z).sum();

    // Construct signature (R, z)
    let r_bytes = group_commitment.compress().to_bytes();
    let z_bytes = z.to_bytes();

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&z_bytes);

    Ok(sig_bytes)
}

/// Compute binding value: rho = H(message, commitments)
fn compute_binding_value(message: &[u8], commitments: &[FrostNonceCommitment]) -> Scalar {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(message);

    for commitment in commitments {
        hasher.update(&commitment.hiding.compress().to_bytes());
        hasher.update(&commitment.binding.compress().to_bytes());
    }

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Compute challenge: c = H(group_public_key, R, message)
fn compute_challenge(group_pk: &PublicKey, r: &RistrettoPoint, message: &[u8]) -> Scalar {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(group_pk);
    hasher.update(&r.compress().to_bytes());
    hasher.update(message);

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Compute Lagrange coefficient for signer in signing set
///
/// lambda_i = prod_{j in S, j != i} (j / (j - i))
fn compute_lagrange_coefficient(signer_id: usize, signing_set: &[usize]) -> Scalar {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &j in signing_set {
        if j != signer_id {
            numerator *= Scalar::from(j as u64);
            denominator *= Scalar::from(j as u64) - Scalar::from(signer_id as u64);
        }
    }

    numerator * denominator.invert()
}

/// Verify a FROST signature
///
/// FROST signatures are standard Schnorr signatures, verified with the equation:
/// z * G = R + c * PK
///
/// where c = H(PK, R, message)
pub fn verify_frost_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &SignatureBytes,
) -> FrostResult<()> {
    use curve25519_dalek::ristretto::CompressedRistretto;

    // Parse signature (R || z)
    let mut r_bytes = [0u8; 32];
    let mut z_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    z_bytes.copy_from_slice(&signature[32..]);

    let r_point = CompressedRistretto(r_bytes)
        .decompress()
        .ok_or(FrostError::InvalidSignatureShare)?;
    let z = Scalar::from_bytes_mod_order(z_bytes);

    // Decompress public key
    let pk_point = CompressedRistretto(*public_key)
        .decompress()
        .ok_or(FrostError::InvalidSignatureShare)?;

    // Compute challenge: c = H(PK, R, message)
    let challenge = compute_challenge(public_key, &r_point, message);

    // Verify: z * G = R + c * PK
    let lhs = z * RISTRETTO_BASEPOINT_POINT;
    let rhs = r_point + (challenge * pk_point);

    if lhs == rhs {
        Ok(())
    } else {
        Err(FrostError::InvalidSignatureShare)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn test_frost_2_of_3_basic() {
        // 2-of-3 threshold setup
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        // Create signers
        let mut signers: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
            .collect();

        // Preprocess
        for signer in &mut signers {
            signer.preprocess();
        }

        let message = b"FROST test message";
        let signing_set = vec![1, 2];

        // Round 1: Collect commitments
        let commitments: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].get_nonce_commitment())
            .collect();

        // Round 2: Sign
        let partial_sigs: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Aggregate
        let signature =
            aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs).unwrap();

        // Verify
        assert!(verify_frost_signature(&group_pk, message, &signature).is_ok());
    }

    #[test]
    fn test_frost_different_signing_sets() {
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let message = b"Test message";

        // Try different combinations
        let signing_sets = vec![vec![1, 2], vec![1, 3], vec![2, 3]];

        for signing_set in signing_sets {
            let mut signers: Vec<_> = shares
                .iter()
                .enumerate()
                .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
                .collect();

            for signer in &mut signers {
                signer.preprocess();
            }

            let commitments: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].get_nonce_commitment())
                .collect();

            let partial_sigs: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            let signature =
                aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs)
                    .unwrap();

            assert!(verify_frost_signature(&group_pk, message, &signature).is_ok());
        }
    }

    #[test]
    fn test_frost_3_of_5() {
        let threshold = 3;
        let num_signers = 5;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let mut signers: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
            .collect();

        for signer in &mut signers {
            signer.preprocess();
        }

        let message = b"3-of-5 threshold test";
        let signing_set = vec![1, 3, 5];

        let commitments: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].get_nonce_commitment())
            .collect();

        let partial_sigs: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let signature =
            aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs).unwrap();

        assert!(verify_frost_signature(&group_pk, message, &signature).is_ok());
    }

    #[test]
    fn test_frost_wrong_message_fails() {
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let mut signers: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
            .collect();

        for signer in &mut signers {
            signer.preprocess();
        }

        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let signing_set = vec![1, 2];

        let commitments: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].get_nonce_commitment())
            .collect();

        let partial_sigs: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let signature =
            aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs).unwrap();

        // Should fail with wrong message
        assert!(verify_frost_signature(&group_pk, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_frost_multiple_signatures_same_key() {
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let messages = vec![b"Message 1".as_slice(), b"Message 2", b"Message 3"];

        for message in messages {
            let mut signers: Vec<_> = shares
                .iter()
                .enumerate()
                .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
                .collect();

            for signer in &mut signers {
                signer.preprocess();
            }

            let signing_set = vec![1, 2];

            let commitments: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].get_nonce_commitment())
                .collect();

            let partial_sigs: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            let signature =
                aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs)
                    .unwrap();

            assert!(verify_frost_signature(&group_pk, message, &signature).is_ok());
        }
    }

    #[test]
    fn test_frost_lagrange_coefficient() {
        let signing_set = vec![1, 2, 3];

        // Lagrange coefficients for a 3-of-3 setup
        let lambda1 = compute_lagrange_coefficient(1, &signing_set);
        let lambda2 = compute_lagrange_coefficient(2, &signing_set);
        let lambda3 = compute_lagrange_coefficient(3, &signing_set);

        // For a full set, coefficients should reconstruct to the secret
        // This is a basic sanity check
        assert_ne!(lambda1, Scalar::ZERO);
        assert_ne!(lambda2, Scalar::ZERO);
        assert_ne!(lambda3, Scalar::ZERO);
    }

    #[test]
    fn test_frost_nonce_not_preprocessed() {
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let signer = FrostSigner::new(1, shares[0].clone(), group_pk);

        // Try to sign without preprocessing
        let message = b"Test";
        let signing_set = vec![1, 2];
        let commitments = vec![];

        let result = signer.sign(message, &signing_set, &commitments);
        assert!(matches!(result, Err(FrostError::NonceNotPreprocessed)));
    }

    #[test]
    fn test_frost_serialization() {
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();

        // Test share serialization
        let share_bytes = crate::codec::encode(&shares[0]).unwrap();
        let deserialized_share: FrostSecretShare = crate::codec::decode(&share_bytes).unwrap();
        assert_eq!(shares[0].index, deserialized_share.index);

        // Test commitment serialization
        let mut signer = FrostSigner::new(1, shares[0].clone(), keygen.group_public_key());
        signer.preprocess();
        let commitment = signer.get_nonce_commitment();

        let commitment_bytes = crate::codec::encode(&commitment).unwrap();
        let deserialized_commitment: FrostNonceCommitment =
            crate::codec::decode(&commitment_bytes).unwrap();

        assert_eq!(
            commitment.hiding.compress().to_bytes(),
            deserialized_commitment.hiding.compress().to_bytes()
        );
    }

    #[test]
    fn test_frost_all_participants() {
        // Test with all participants (n-of-n)
        let threshold = 3;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        let mut signers: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
            .collect();

        for signer in &mut signers {
            signer.preprocess();
        }

        let message = b"All participants signing";
        let signing_set = vec![1, 2, 3];

        let commitments: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].get_nonce_commitment())
            .collect();

        let partial_sigs: Vec<_> = signing_set
            .iter()
            .map(|&id| signers[id - 1].sign(message, &signing_set, &commitments))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let signature =
            aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs).unwrap();

        assert!(verify_frost_signature(&group_pk, message, &signature).is_ok());
    }

    #[test]
    fn test_frost_deterministic_keygen() {
        // Multiple key generations should produce different keys (randomized)
        let threshold = 2;
        let num_signers = 3;

        let mut keygen1 = FrostKeygen::new(threshold, num_signers);
        let shares1 = keygen1.generate_shares();
        let pk1 = keygen1.group_public_key();

        let mut keygen2 = FrostKeygen::new(threshold, num_signers);
        let shares2 = keygen2.generate_shares();
        let pk2 = keygen2.group_public_key();

        // Should be different (random generation)
        assert_ne!(pk1, pk2);
        assert_ne!(shares1[0].secret, shares2[0].secret);
    }

    #[test]
    fn test_lagrange_interpolation_property() {
        // Verify that Lagrange interpolation of shares gives the group public key
        let threshold = 2;
        let num_signers = 3;

        let mut keygen = FrostKeygen::new(threshold, num_signers);
        let shares = keygen.generate_shares();
        let group_pk = keygen.group_public_key();

        // Test with different signing sets
        let signing_sets = vec![vec![1, 2], vec![1, 3], vec![2, 3]];

        for signing_set in signing_sets {
            // Compute sum(lambda_i * s_i * G)
            let mut interpolated_pk = RistrettoPoint::identity();

            for &signer_id in &signing_set {
                let lambda = compute_lagrange_coefficient(signer_id, &signing_set);
                let share_secret = shares[signer_id - 1].secret;
                interpolated_pk += lambda * share_secret * RISTRETTO_BASEPOINT_POINT;
            }

            // This should equal the group public key
            let interpolated_bytes = interpolated_pk.compress().to_bytes();

            use curve25519_dalek::ristretto::CompressedRistretto;
            let group_pk_point = CompressedRistretto(group_pk).decompress().unwrap();
            let group_pk_bytes = group_pk_point.compress().to_bytes();

            assert_eq!(
                interpolated_bytes, group_pk_bytes,
                "Lagrange interpolation failed for signing set {:?}",
                signing_set
            );
        }
    }
}
