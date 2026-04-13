//! Threshold ECDSA for distributed signature generation.
//!
//! This module implements a threshold ECDSA signature scheme where a group of
//! n signers can jointly generate an ECDSA-style signature with only t signers
//! participating (t-of-n threshold).
//!
//! # Protocol Overview
//!
//! 1. **Setup**: Distributed key generation to create key shares
//! 2. **Signing Round 1**: Each signer generates nonce shares
//! 3. **Signing Round 2**: Combine nonces and create partial signatures
//! 4. **Aggregation**: Combine partial signatures into final signature
//!
//! # Example
//!
//! ```
//! use chie_crypto::threshold_ecdsa::*;
//!
//! // Create a 2-of-3 threshold ECDSA setup
//! let threshold = 2;
//! let total = 3;
//!
//! // Generate threshold key shares (in practice, use DKG)
//! let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();
//!
//! // Create signers from shares
//! let signer1 = ThresholdEcdsaSigner::from_share(threshold, total, key_shares[0].1.clone(), key_shares[0].2);
//! let signer2 = ThresholdEcdsaSigner::from_share(threshold, total, key_shares[1].1.clone(), key_shares[1].2);
//! let signer3 = ThresholdEcdsaSigner::from_share(threshold, total, key_shares[2].1.clone(), key_shares[2].2);
//!
//! let message = b"Threshold ECDSA test";
//!
//! // Signing Round 1: Generate nonce shares (only 2 signers participate)
//! let nonce1 = signer1.generate_nonce_share();
//! let nonce2 = signer2.generate_nonce_share();
//!
//! let nonce_shares = vec![nonce1.public(), nonce2.public()];
//! let signer_ids = vec![1, 2];
//!
//! // Signing Round 2: Create partial signatures
//! let partial1 = signer1.partial_sign(message, &nonce1, &nonce_shares, &signer_ids).unwrap();
//! let partial2 = signer2.partial_sign(message, &nonce2, &nonce_shares, &signer_ids).unwrap();
//!
//! // Aggregate signatures
//! let signature = aggregate_threshold_signatures(&[partial1, partial2], &nonce_shares).unwrap();
//!
//! // Verify
//! assert!(verify_threshold_ecdsa(&group_pubkey, message, &signature));
//! ```

use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Helper function to evaluate polynomial at a point
fn eval_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_power = Scalar::ONE;

    for coeff in coefficients {
        result += coeff * x_power;
        x_power *= x;
    }

    result
}

/// Generate threshold key shares using polynomial secret sharing
pub fn generate_threshold_keys(
    threshold: u32,
    total: u32,
) -> ThresholdEcdsaResult<ThresholdKeyShares> {
    if threshold == 0 || threshold > total {
        return Err(ThresholdEcdsaError::InvalidThreshold(format!(
            "threshold={}, total={}",
            threshold, total
        )));
    }

    // Generate secret and polynomial coefficients
    let secret = random_scalar();
    let mut coefficients = vec![secret];
    for _ in 1..threshold {
        coefficients.push(random_scalar());
    }

    // Compute group public key
    let group_pubkey = RISTRETTO_BASEPOINT_POINT * secret;

    // Generate shares for each signer
    let mut shares = Vec::new();
    for id in 1..=total {
        let x = Scalar::from(id as u64);
        let share_value = eval_polynomial(&coefficients, x);
        let public_key = RISTRETTO_BASEPOINT_POINT * share_value;

        shares.push((
            id,
            SecretShare {
                signer_id: id,
                share: share_value,
            },
            PublicShare {
                signer_id: id,
                public_key,
            },
        ));
    }

    Ok((group_pubkey, shares))
}

#[derive(Debug, Error)]
pub enum ThresholdEcdsaError {
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),
    #[error("Invalid signer ID")]
    InvalidSignerId,
    #[error("Insufficient signers")]
    InsufficientSigners,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Mismatched lengths")]
    MismatchedLengths,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type ThresholdEcdsaResult<T> = Result<T, ThresholdEcdsaError>;

/// Generate a random scalar
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Secret share for a threshold ECDSA signer
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretShare {
    signer_id: u32,
    share: Scalar,
}

/// Public key share
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicShare {
    signer_id: u32,
    public_key: RistrettoPoint,
}

/// Type alias for threshold key generation result: (group_pubkey, key_shares)
pub type ThresholdKeyShares = (RistrettoPoint, Vec<(u32, SecretShare, PublicShare)>);

/// Threshold ECDSA signer
#[derive(Clone)]
pub struct ThresholdEcdsaSigner {
    signer_id: u32,
    threshold: u32,
    #[allow(dead_code)]
    total: u32,
    secret_share: SecretShare,
    public_share: PublicShare,
}

/// Nonce share (ephemeral key for signing)
#[derive(Clone)]
pub struct NonceShare {
    #[allow(dead_code)]
    signer_id: u32,
    secret: Scalar,
    public: PublicNonceShare,
}

/// Public nonce share
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicNonceShare {
    signer_id: u32,
    nonce_point: RistrettoPoint,
}

/// Partial signature from a signer
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ThresholdPartialSignature {
    signer_id: u32,
    s_share: Scalar,
}

/// Final threshold ECDSA signature
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ThresholdEcdsaSignature {
    r: RistrettoPoint,
    s: Scalar,
}

impl ThresholdEcdsaSigner {
    /// Create a new threshold ECDSA signer
    ///
    /// # Arguments
    /// * `signer_id` - Unique ID for this signer (1-indexed)
    /// * `threshold` - Minimum number of signers needed (t)
    /// * `total` - Total number of signers (n)
    pub fn new(signer_id: u32, threshold: u32, total: u32) -> Self {
        if threshold == 0 || threshold > total {
            panic!("Invalid threshold: {} (total: {})", threshold, total);
        }
        if signer_id == 0 || signer_id > total {
            panic!("Invalid signer ID: {} (total: {})", signer_id, total);
        }

        // Generate secret share (simplified - in practice use DKG)
        let secret = random_scalar();
        let public_key = RISTRETTO_BASEPOINT_POINT * secret;

        Self {
            signer_id,
            threshold,
            total,
            secret_share: SecretShare {
                signer_id,
                share: secret,
            },
            public_share: PublicShare {
                signer_id,
                public_key,
            },
        }
    }

    /// Create a signer from existing key shares
    pub fn from_share(
        threshold: u32,
        total: u32,
        secret_share: SecretShare,
        public_share: PublicShare,
    ) -> Self {
        Self {
            signer_id: secret_share.signer_id,
            threshold,
            total,
            secret_share,
            public_share,
        }
    }

    /// Get the public share for this signer
    pub fn public_share(&self) -> PublicShare {
        self.public_share
    }

    /// Generate a nonce share for signing
    pub fn generate_nonce_share(&self) -> NonceShare {
        let secret = random_scalar();
        let nonce_point = RISTRETTO_BASEPOINT_POINT * secret;

        NonceShare {
            signer_id: self.signer_id,
            secret,
            public: PublicNonceShare {
                signer_id: self.signer_id,
                nonce_point,
            },
        }
    }

    /// Create a partial signature
    ///
    /// # Arguments
    /// * `message` - Message to sign
    /// * `nonce` - This signer's nonce share
    /// * `nonce_shares` - Public nonce shares from all participating signers
    /// * `signer_ids` - IDs of participating signers
    pub fn partial_sign(
        &self,
        message: &[u8],
        nonce: &NonceShare,
        nonce_shares: &[PublicNonceShare],
        signer_ids: &[u32],
    ) -> ThresholdEcdsaResult<ThresholdPartialSignature> {
        if nonce_shares.len() < self.threshold as usize {
            return Err(ThresholdEcdsaError::InsufficientSigners);
        }

        if nonce_shares.len() != signer_ids.len() {
            return Err(ThresholdEcdsaError::MismatchedLengths);
        }

        // Aggregate nonce point
        let mut r = RistrettoPoint::default();
        for nonce_share in nonce_shares {
            r += nonce_share.nonce_point;
        }

        // Compute Lagrange coefficient for this signer
        let lambda = compute_lagrange_coefficient(self.signer_id, signer_ids)?;

        // Compute challenge
        let challenge = compute_challenge(&r, message);

        // Partial signature: s_i = k_i + lambda_i * c * x_i
        let s_share = nonce.secret + lambda * challenge * self.secret_share.share;

        Ok(ThresholdPartialSignature {
            signer_id: self.signer_id,
            s_share,
        })
    }
}

impl NonceShare {
    /// Get the public nonce share
    pub fn public(&self) -> PublicNonceShare {
        self.public
    }
}

/// Compute Lagrange coefficient for signer interpolation
fn compute_lagrange_coefficient(
    signer_id: u32,
    signer_ids: &[u32],
) -> ThresholdEcdsaResult<Scalar> {
    if !signer_ids.contains(&signer_id) {
        return Err(ThresholdEcdsaError::InvalidSignerId);
    }

    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    let id_scalar = Scalar::from(signer_id as u64);

    for &other_id in signer_ids {
        if other_id != signer_id {
            let other_scalar = Scalar::from(other_id as u64);
            numerator *= other_scalar;
            denominator *= other_scalar - id_scalar;
        }
    }

    // Compute denominator^-1
    let denom_inv = denominator.invert();

    Ok(numerator * denom_inv)
}

/// Aggregate public key shares into group public key
pub fn aggregate_threshold_public_key(
    shares: &[PublicShare],
) -> ThresholdEcdsaResult<RistrettoPoint> {
    if shares.is_empty() {
        return Err(ThresholdEcdsaError::InsufficientSigners);
    }

    let mut aggregated = RistrettoPoint::default();
    for share in shares {
        aggregated += share.public_key;
    }

    Ok(aggregated)
}

/// Aggregate partial signatures into final signature
pub fn aggregate_threshold_signatures(
    partials: &[ThresholdPartialSignature],
    nonce_shares: &[PublicNonceShare],
) -> ThresholdEcdsaResult<ThresholdEcdsaSignature> {
    if partials.is_empty() {
        return Err(ThresholdEcdsaError::InsufficientSigners);
    }

    // Aggregate nonce point
    let mut r = RistrettoPoint::default();
    for nonce_share in nonce_shares {
        r += nonce_share.nonce_point;
    }

    // Aggregate signature shares
    let mut s = Scalar::ZERO;
    for partial in partials {
        s += partial.s_share;
    }

    Ok(ThresholdEcdsaSignature { r, s })
}

/// Compute challenge for ECDSA-style signature
fn compute_challenge(r: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&r.compress().to_bytes());
    hasher.update(message);

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Verify a threshold ECDSA signature
pub fn verify_threshold_ecdsa(
    public_key: &RistrettoPoint,
    message: &[u8],
    signature: &ThresholdEcdsaSignature,
) -> bool {
    // Compute challenge
    let challenge = compute_challenge(&signature.r, message);

    // Verify: s*G = R + c*X
    let lhs = RISTRETTO_BASEPOINT_POINT * signature.s;
    let rhs = signature.r + challenge * public_key;

    lhs == rhs
}

impl ThresholdEcdsaSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.compress().to_bytes());
        bytes[32..].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> ThresholdEcdsaResult<Self> {
        let r = curve25519_dalek::ristretto::CompressedRistretto(bytes[..32].try_into().unwrap())
            .decompress()
            .ok_or(ThresholdEcdsaError::InvalidSignature)?;
        let s = Scalar::from_bytes_mod_order(bytes[32..].try_into().unwrap());

        Ok(Self { r, s })
    }
}

impl PublicShare {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..4].copy_from_slice(&self.signer_id.to_le_bytes());
        bytes[4..].copy_from_slice(&self.public_key.compress().to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 36]) -> ThresholdEcdsaResult<Self> {
        let signer_id = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let public_key =
            curve25519_dalek::ristretto::CompressedRistretto(bytes[4..].try_into().unwrap())
                .decompress()
                .ok_or(ThresholdEcdsaError::InvalidPublicKey)?;

        Ok(Self {
            signer_id,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_ecdsa_2_of_3() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        // Create signers from shares
        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );
        let _signer3 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[2].1.clone(),
            key_shares[2].2,
        );

        let message = b"Test message";

        // Only signers 1 and 2 participate
        let nonce1 = signer1.generate_nonce_share();
        let nonce2 = signer2.generate_nonce_share();

        let nonce_shares = vec![nonce1.public(), nonce2.public()];
        let signer_ids = vec![1, 2];

        let partial1 = signer1
            .partial_sign(message, &nonce1, &nonce_shares, &signer_ids)
            .unwrap();
        let partial2 = signer2
            .partial_sign(message, &nonce2, &nonce_shares, &signer_ids)
            .unwrap();

        let signature =
            aggregate_threshold_signatures(&[partial1, partial2], &nonce_shares).unwrap();

        assert!(verify_threshold_ecdsa(&group_pubkey, message, &signature));
    }

    #[test]
    fn test_threshold_ecdsa_different_signers() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        // Create signers from shares
        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let _signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );
        let signer3 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[2].1.clone(),
            key_shares[2].2,
        );

        let message = b"Test message";

        // Signers 1 and 3 participate (different subset)
        let nonce1 = signer1.generate_nonce_share();
        let nonce3 = signer3.generate_nonce_share();

        let nonce_shares = vec![nonce1.public(), nonce3.public()];
        let signer_ids = vec![1, 3];

        let partial1 = signer1
            .partial_sign(message, &nonce1, &nonce_shares, &signer_ids)
            .unwrap();
        let partial3 = signer3
            .partial_sign(message, &nonce3, &nonce_shares, &signer_ids)
            .unwrap();

        let signature =
            aggregate_threshold_signatures(&[partial1, partial3], &nonce_shares).unwrap();

        assert!(verify_threshold_ecdsa(&group_pubkey, message, &signature));
    }

    #[test]
    fn test_threshold_ecdsa_3_of_5() {
        let threshold = 3;
        let total = 5;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        // Create signers from shares
        let signers: Vec<ThresholdEcdsaSigner> = key_shares
            .iter()
            .map(|(_, secret_share, signer_id)| {
                ThresholdEcdsaSigner::from_share(threshold, total, secret_share.clone(), *signer_id)
            })
            .collect();

        let message = b"3-of-5 threshold test";

        // Signers 1, 3, and 5 participate
        let nonces: Vec<NonceShare> = vec![
            signers[0].generate_nonce_share(),
            signers[2].generate_nonce_share(),
            signers[4].generate_nonce_share(),
        ];

        let nonce_shares: Vec<PublicNonceShare> = nonces.iter().map(|n| n.public()).collect();
        let signer_ids = vec![1, 3, 5];

        let partials: Vec<ThresholdPartialSignature> = vec![
            signers[0]
                .partial_sign(message, &nonces[0], &nonce_shares, &signer_ids)
                .unwrap(),
            signers[2]
                .partial_sign(message, &nonces[1], &nonce_shares, &signer_ids)
                .unwrap(),
            signers[4]
                .partial_sign(message, &nonces[2], &nonce_shares, &signer_ids)
                .unwrap(),
        ];

        let signature = aggregate_threshold_signatures(&partials, &nonce_shares).unwrap();

        assert!(verify_threshold_ecdsa(&group_pubkey, message, &signature));
    }

    #[test]
    fn test_insufficient_signers() {
        let threshold = 3;
        let total = 5;

        // Generate threshold key shares properly
        let (_group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );

        let message = b"Test message";

        let nonce1 = signer1.generate_nonce_share();
        let nonce2 = signer2.generate_nonce_share();

        let nonce_shares = vec![nonce1.public(), nonce2.public()];
        let signer_ids = vec![1, 2];

        // Should fail because we need 3 signers but only have 2
        let result = signer1.partial_sign(message, &nonce1, &nonce_shares, &signer_ids);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_message() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );

        let message = b"Original message";

        let nonce1 = signer1.generate_nonce_share();
        let nonce2 = signer2.generate_nonce_share();

        let nonce_shares = vec![nonce1.public(), nonce2.public()];
        let signer_ids = vec![1, 2];

        let partial1 = signer1
            .partial_sign(message, &nonce1, &nonce_shares, &signer_ids)
            .unwrap();
        let partial2 = signer2
            .partial_sign(message, &nonce2, &nonce_shares, &signer_ids)
            .unwrap();

        let signature =
            aggregate_threshold_signatures(&[partial1, partial2], &nonce_shares).unwrap();

        // Should fail with wrong message
        assert!(!verify_threshold_ecdsa(
            &group_pubkey,
            b"Wrong message",
            &signature
        ));
    }

    #[test]
    fn test_signature_serialization() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );

        let message = b"Serialization test";

        let nonce1 = signer1.generate_nonce_share();
        let nonce2 = signer2.generate_nonce_share();

        let nonce_shares = vec![nonce1.public(), nonce2.public()];
        let signer_ids = vec![1, 2];

        let partial1 = signer1
            .partial_sign(message, &nonce1, &nonce_shares, &signer_ids)
            .unwrap();
        let partial2 = signer2
            .partial_sign(message, &nonce2, &nonce_shares, &signer_ids)
            .unwrap();

        let signature =
            aggregate_threshold_signatures(&[partial1, partial2], &nonce_shares).unwrap();

        let bytes = signature.to_bytes();
        let recovered = ThresholdEcdsaSignature::from_bytes(&bytes).unwrap();

        assert!(verify_threshold_ecdsa(&group_pubkey, message, &recovered));
    }

    #[test]
    fn test_public_share_serialization() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (_group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        let signer = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let pub_share = signer.public_share();

        let bytes = pub_share.to_bytes();
        let recovered = PublicShare::from_bytes(&bytes).unwrap();

        assert_eq!(pub_share.signer_id, recovered.signer_id);
        assert_eq!(pub_share.public_key, recovered.public_key);
    }

    #[test]
    fn test_all_signers_participate() {
        let threshold = 3;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        // Create signers from shares
        let signers: Vec<ThresholdEcdsaSigner> = key_shares
            .iter()
            .map(|(_, secret_share, signer_id)| {
                ThresholdEcdsaSigner::from_share(threshold, total, secret_share.clone(), *signer_id)
            })
            .collect();

        let message = b"All signers participate";

        let nonces: Vec<NonceShare> = signers.iter().map(|s| s.generate_nonce_share()).collect();
        let nonce_shares: Vec<PublicNonceShare> = nonces.iter().map(|n| n.public()).collect();
        let signer_ids = vec![1, 2, 3];

        let partials: Vec<ThresholdPartialSignature> = signers
            .iter()
            .zip(nonces.iter())
            .map(|(signer, nonce)| {
                signer
                    .partial_sign(message, nonce, &nonce_shares, &signer_ids)
                    .unwrap()
            })
            .collect();

        let signature = aggregate_threshold_signatures(&partials, &nonce_shares).unwrap();

        assert!(verify_threshold_ecdsa(&group_pubkey, message, &signature));
    }

    #[test]
    fn test_lagrange_coefficient() {
        // Test Lagrange coefficients for interpolation
        let signer_ids = vec![1, 2, 3];

        let lambda1 = compute_lagrange_coefficient(1, &signer_ids).unwrap();
        let lambda2 = compute_lagrange_coefficient(2, &signer_ids).unwrap();
        let lambda3 = compute_lagrange_coefficient(3, &signer_ids).unwrap();

        // Coefficients should not be zero
        assert_ne!(lambda1, Scalar::ZERO);
        assert_ne!(lambda2, Scalar::ZERO);
        assert_ne!(lambda3, Scalar::ZERO);
    }

    #[test]
    fn test_multiple_signatures_same_key() {
        let threshold = 2;
        let total = 3;

        // Generate threshold key shares properly
        let (group_pubkey, key_shares) = generate_threshold_keys(threshold, total).unwrap();

        let signer1 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[0].1.clone(),
            key_shares[0].2,
        );
        let signer2 = ThresholdEcdsaSigner::from_share(
            threshold,
            total,
            key_shares[1].1.clone(),
            key_shares[1].2,
        );

        // Sign two different messages with same key
        let message1 = b"First message";
        let message2 = b"Second message";

        // First signature
        let nonce1a = signer1.generate_nonce_share();
        let nonce2a = signer2.generate_nonce_share();
        let nonce_shares_a = vec![nonce1a.public(), nonce2a.public()];
        let signer_ids = vec![1, 2];

        let partial1a = signer1
            .partial_sign(message1, &nonce1a, &nonce_shares_a, &signer_ids)
            .unwrap();
        let partial2a = signer2
            .partial_sign(message1, &nonce2a, &nonce_shares_a, &signer_ids)
            .unwrap();
        let sig1 =
            aggregate_threshold_signatures(&[partial1a, partial2a], &nonce_shares_a).unwrap();

        // Second signature
        let nonce1b = signer1.generate_nonce_share();
        let nonce2b = signer2.generate_nonce_share();
        let nonce_shares_b = vec![nonce1b.public(), nonce2b.public()];

        let partial1b = signer1
            .partial_sign(message2, &nonce1b, &nonce_shares_b, &signer_ids)
            .unwrap();
        let partial2b = signer2
            .partial_sign(message2, &nonce2b, &nonce_shares_b, &signer_ids)
            .unwrap();
        let sig2 =
            aggregate_threshold_signatures(&[partial1b, partial2b], &nonce_shares_b).unwrap();

        // Both should verify
        assert!(verify_threshold_ecdsa(&group_pubkey, message1, &sig1));
        assert!(verify_threshold_ecdsa(&group_pubkey, message2, &sig2));

        // Cross-verification should fail
        assert!(!verify_threshold_ecdsa(&group_pubkey, message1, &sig2));
        assert!(!verify_threshold_ecdsa(&group_pubkey, message2, &sig1));
    }
}
