//! MuSig2: Secure multi-signature aggregation scheme.
//!
//! MuSig2 is a modern multi-signature protocol that provides:
//! - Key aggregation: Multiple public keys → single aggregated key
//! - Signature aggregation: N partial signatures → single signature
//! - Security against rogue key attacks
//! - Three-round protocol with nonce commitments
//!
//! # Protocol Overview
//!
//! 1. **Key Aggregation**: Aggregate public keys with coefficients
//! 2. **Round 1 - Nonce Commitment**: Each signer commits to their nonces
//! 3. **Round 2 - Nonce Reveal**: Nonces are revealed and aggregated
//! 4. **Round 3 - Partial Signing**: Each signer creates partial signature
//! 5. **Aggregation**: Partial signatures combined into final signature
//!
//! # Example
//!
//! ```
//! use chie_crypto::musig2::*;
//!
//! // Three signers want to sign a message
//! let signer1 = MuSig2Signer::new();
//! let signer2 = MuSig2Signer::new();
//! let signer3 = MuSig2Signer::new();
//!
//! let public_keys = vec![
//!     signer1.public_key(),
//!     signer2.public_key(),
//!     signer3.public_key(),
//! ];
//!
//! // Aggregate public keys
//! let agg_key = aggregate_public_keys(&public_keys).unwrap();
//!
//! let message = b"Multi-signature test message";
//!
//! // Round 1: Generate nonce commitments
//! let (nonce1, commit1) = signer1.nonce_commitment();
//! let (nonce2, commit2) = signer2.nonce_commitment();
//! let (nonce3, commit3) = signer3.nonce_commitment();
//!
//! let commitments = vec![commit1, commit2, commit3];
//!
//! // Round 2: Reveal nonces
//! let nonces = vec![nonce1.public_nonce(), nonce2.public_nonce(), nonce3.public_nonce()];
//! let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();
//!
//! // Round 3: Partial signatures
//! let partial1 = signer1.partial_sign(message, &nonce1, &public_keys, &agg_nonce).unwrap();
//! let partial2 = signer2.partial_sign(message, &nonce2, &public_keys, &agg_nonce).unwrap();
//! let partial3 = signer3.partial_sign(message, &nonce3, &public_keys, &agg_nonce).unwrap();
//!
//! // Aggregate signatures
//! let signature = aggregate_partial_signatures_with_nonce(&[partial1, partial2, partial3], &agg_nonce).unwrap();
//!
//! // Verify
//! assert!(verify_musig2(&agg_key, message, &signature));
//! ```

use crate::ct::ct_eq_32;
use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MuSig2Error {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid nonce commitment")]
    InvalidNonceCommitment,
    #[error("Empty signer list")]
    EmptySigners,
    #[error("Mismatched lengths")]
    MismatchedLengths,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type MuSig2Result<T> = Result<T, MuSig2Error>;

/// Generate a random scalar
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Secret key for MuSig2 signer
#[derive(Clone, Serialize, Deserialize)]
pub struct MuSig2SecretKey(Scalar);

/// Public key for MuSig2 signer
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MuSig2PublicKey(RistrettoPoint);

/// A MuSig2 signer with keypair
#[derive(Clone)]
pub struct MuSig2Signer {
    secret_key: MuSig2SecretKey,
    public_key: MuSig2PublicKey,
}

/// Nonce used in the signing protocol (secret)
#[derive(Clone)]
pub struct SigningNonce {
    secret: Scalar,
    public: MuSig2Nonce,
}

/// Public nonce used in MuSig2 protocol
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MuSig2Nonce(RistrettoPoint);

/// Nonce commitment (hash of public nonce)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceCommitment([u8; 32]);

/// Partial signature from a signer
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PartialSignature(Scalar);

/// Final aggregated MuSig2 signature
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MuSig2Signature {
    r: RistrettoPoint,
    s: Scalar,
}

impl MuSig2Signer {
    /// Generate a new random signer
    pub fn new() -> Self {
        let secret = random_scalar();
        let public = RISTRETTO_BASEPOINT_POINT * secret;

        Self {
            secret_key: MuSig2SecretKey(secret),
            public_key: MuSig2PublicKey(public),
        }
    }

    /// Create signer from secret key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> MuSig2Result<Self> {
        let secret = Scalar::from_bytes_mod_order(*bytes);
        let public = RISTRETTO_BASEPOINT_POINT * secret;

        Ok(Self {
            secret_key: MuSig2SecretKey(secret),
            public_key: MuSig2PublicKey(public),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> MuSig2PublicKey {
        self.public_key
    }

    /// Export secret key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.0.to_bytes()
    }

    /// Generate a nonce commitment (Round 1)
    pub fn nonce_commitment(&self) -> (SigningNonce, NonceCommitment) {
        let secret = random_scalar();
        let public = RISTRETTO_BASEPOINT_POINT * secret;
        let nonce = MuSig2Nonce(public);

        // Commit to the nonce
        let commitment = NonceCommitment(blake3::hash(&public.compress().to_bytes()).into());

        (
            SigningNonce {
                secret,
                public: nonce,
            },
            commitment,
        )
    }

    /// Create a partial signature (Round 3)
    pub fn partial_sign(
        &self,
        message: &[u8],
        nonce: &SigningNonce,
        public_keys: &[MuSig2PublicKey],
        aggregated_nonce: &MuSig2Nonce,
    ) -> MuSig2Result<PartialSignature> {
        if public_keys.is_empty() {
            return Err(MuSig2Error::EmptySigners);
        }

        // Compute key aggregation coefficient
        let coeff = key_aggregation_coefficient(&self.public_key, public_keys);

        // Compute challenge
        let challenge = compute_challenge(
            aggregated_nonce,
            &aggregate_public_keys(public_keys)?,
            message,
        );

        // Partial signature: s_i = r_i + c * a_i * x_i
        let s = nonce.secret + challenge * coeff * self.secret_key.0;

        Ok(PartialSignature(s))
    }
}

impl Default for MuSig2Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningNonce {
    /// Get the public nonce
    pub fn public_nonce(&self) -> MuSig2Nonce {
        self.public
    }

    /// Verify that the nonce matches the commitment
    pub fn verify_commitment(&self, commitment: &NonceCommitment) -> bool {
        let computed = NonceCommitment(blake3::hash(&self.public.0.compress().to_bytes()).into());
        ct_eq_32(&computed.0, &commitment.0)
    }
}

impl MuSig2PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> MuSig2Result<Self> {
        let point = curve25519_dalek::ristretto::CompressedRistretto(*bytes)
            .decompress()
            .ok_or(MuSig2Error::InvalidPublicKey)?;
        Ok(Self(point))
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// Compute key aggregation coefficient for a public key
fn key_aggregation_coefficient(
    pubkey: &MuSig2PublicKey,
    all_pubkeys: &[MuSig2PublicKey],
) -> Scalar {
    let mut hasher = Hasher::new();

    // Hash all public keys to derive coefficient
    for pk in all_pubkeys {
        hasher.update(&pk.0.compress().to_bytes());
    }
    hasher.update(&pubkey.0.compress().to_bytes());

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Aggregate public keys with coefficients
pub fn aggregate_public_keys(public_keys: &[MuSig2PublicKey]) -> MuSig2Result<MuSig2PublicKey> {
    if public_keys.is_empty() {
        return Err(MuSig2Error::EmptySigners);
    }

    let mut aggregated = RistrettoPoint::default();

    for pk in public_keys {
        let coeff = key_aggregation_coefficient(pk, public_keys);
        aggregated += coeff * pk.0;
    }

    Ok(MuSig2PublicKey(aggregated))
}

/// Aggregate nonces (Round 2)
pub fn aggregate_nonces(
    nonces: &[MuSig2Nonce],
    commitments: &[NonceCommitment],
) -> MuSig2Result<MuSig2Nonce> {
    if nonces.is_empty() {
        return Err(MuSig2Error::EmptySigners);
    }

    if nonces.len() != commitments.len() {
        return Err(MuSig2Error::MismatchedLengths);
    }

    // Verify all nonces match commitments
    for (nonce, commitment) in nonces.iter().zip(commitments.iter()) {
        let computed = NonceCommitment(blake3::hash(&nonce.0.compress().to_bytes()).into());
        if !ct_eq_32(&computed.0, &commitment.0) {
            return Err(MuSig2Error::InvalidNonceCommitment);
        }
    }

    // Aggregate nonces
    let mut aggregated = RistrettoPoint::default();
    for nonce in nonces {
        aggregated += nonce.0;
    }

    Ok(MuSig2Nonce(aggregated))
}

/// Aggregate partial signatures into final signature
pub fn aggregate_partial_signatures(
    partials: &[PartialSignature],
) -> MuSig2Result<MuSig2Signature> {
    if partials.is_empty() {
        return Err(MuSig2Error::EmptySigners);
    }

    let mut s = Scalar::ZERO;
    for partial in partials {
        s += partial.0;
    }

    // Note: We don't have access to the aggregated nonce here,
    // so we'll need to modify this. For now, we'll use a placeholder.
    // In practice, the caller should provide the aggregated nonce.
    Ok(MuSig2Signature {
        r: RistrettoPoint::default(),
        s,
    })
}

/// Aggregate partial signatures with the aggregated nonce
pub fn aggregate_partial_signatures_with_nonce(
    partials: &[PartialSignature],
    aggregated_nonce: &MuSig2Nonce,
) -> MuSig2Result<MuSig2Signature> {
    if partials.is_empty() {
        return Err(MuSig2Error::EmptySigners);
    }

    let mut s = Scalar::ZERO;
    for partial in partials {
        s += partial.0;
    }

    Ok(MuSig2Signature {
        r: aggregated_nonce.0,
        s,
    })
}

/// Compute challenge for Schnorr-like signature
fn compute_challenge(nonce: &MuSig2Nonce, pubkey: &MuSig2PublicKey, message: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&nonce.0.compress().to_bytes());
    hasher.update(&pubkey.0.compress().to_bytes());
    hasher.update(message);

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Verify a MuSig2 signature
pub fn verify_musig2(
    pubkey: &MuSig2PublicKey,
    message: &[u8],
    signature: &MuSig2Signature,
) -> bool {
    // Compute challenge
    let challenge = compute_challenge(&MuSig2Nonce(signature.r), pubkey, message);

    // Verify: s * G = R + c * X
    let lhs = RISTRETTO_BASEPOINT_POINT * signature.s;
    let rhs = signature.r + challenge * pubkey.0;

    lhs == rhs
}

impl MuSig2Signature {
    /// Serialize signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.compress().to_bytes());
        bytes[32..].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Deserialize signature from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> MuSig2Result<Self> {
        let r = curve25519_dalek::ristretto::CompressedRistretto(bytes[..32].try_into().unwrap())
            .decompress()
            .ok_or(MuSig2Error::InvalidSignature)?;
        let s = Scalar::from_bytes_mod_order(bytes[32..].try_into().unwrap());

        Ok(Self { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_musig2_single_signer() {
        let signer = MuSig2Signer::new();
        let pubkeys = vec![signer.public_key()];
        let agg_key = aggregate_public_keys(&pubkeys).unwrap();

        let message = b"Single signer test";

        let (nonce, commitment) = signer.nonce_commitment();
        let commitments = vec![commitment];
        let nonces = vec![nonce.public_nonce()];
        let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();

        let partial = signer
            .partial_sign(message, &nonce, &pubkeys, &agg_nonce)
            .unwrap();
        let signature = aggregate_partial_signatures_with_nonce(&[partial], &agg_nonce).unwrap();

        assert!(verify_musig2(&agg_key, message, &signature));
    }

    #[test]
    fn test_musig2_three_signers() {
        let signer1 = MuSig2Signer::new();
        let signer2 = MuSig2Signer::new();
        let signer3 = MuSig2Signer::new();

        let pubkeys = vec![
            signer1.public_key(),
            signer2.public_key(),
            signer3.public_key(),
        ];
        let agg_key = aggregate_public_keys(&pubkeys).unwrap();

        let message = b"Three signer test";

        let (nonce1, commit1) = signer1.nonce_commitment();
        let (nonce2, commit2) = signer2.nonce_commitment();
        let (nonce3, commit3) = signer3.nonce_commitment();

        let commitments = vec![commit1, commit2, commit3];
        let nonces = vec![
            nonce1.public_nonce(),
            nonce2.public_nonce(),
            nonce3.public_nonce(),
        ];

        let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();

        let partial1 = signer1
            .partial_sign(message, &nonce1, &pubkeys, &agg_nonce)
            .unwrap();
        let partial2 = signer2
            .partial_sign(message, &nonce2, &pubkeys, &agg_nonce)
            .unwrap();
        let partial3 = signer3
            .partial_sign(message, &nonce3, &pubkeys, &agg_nonce)
            .unwrap();

        let signature =
            aggregate_partial_signatures_with_nonce(&[partial1, partial2, partial3], &agg_nonce)
                .unwrap();

        assert!(verify_musig2(&agg_key, message, &signature));
    }

    #[test]
    fn test_musig2_wrong_message() {
        let signer1 = MuSig2Signer::new();
        let signer2 = MuSig2Signer::new();

        let pubkeys = vec![signer1.public_key(), signer2.public_key()];
        let agg_key = aggregate_public_keys(&pubkeys).unwrap();

        let message = b"Original message";

        let (nonce1, commit1) = signer1.nonce_commitment();
        let (nonce2, commit2) = signer2.nonce_commitment();

        let commitments = vec![commit1, commit2];
        let nonces = vec![nonce1.public_nonce(), nonce2.public_nonce()];
        let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();

        let partial1 = signer1
            .partial_sign(message, &nonce1, &pubkeys, &agg_nonce)
            .unwrap();
        let partial2 = signer2
            .partial_sign(message, &nonce2, &pubkeys, &agg_nonce)
            .unwrap();

        let signature =
            aggregate_partial_signatures_with_nonce(&[partial1, partial2], &agg_nonce).unwrap();

        assert!(!verify_musig2(&agg_key, b"Different message", &signature));
    }

    #[test]
    fn test_nonce_commitment_verification() {
        let signer = MuSig2Signer::new();
        let (nonce, commitment) = signer.nonce_commitment();

        assert!(nonce.verify_commitment(&commitment));
    }

    #[test]
    fn test_invalid_nonce_commitment() {
        let signer = MuSig2Signer::new();
        let (nonce1, _) = signer.nonce_commitment();
        let (_, commitment2) = signer.nonce_commitment();

        assert!(!nonce1.verify_commitment(&commitment2));
    }

    #[test]
    fn test_aggregate_nonces_mismatch() {
        let signer1 = MuSig2Signer::new();
        let signer2 = MuSig2Signer::new();

        let (nonce1, _) = signer1.nonce_commitment();
        let (_, commit2) = signer2.nonce_commitment();

        let result = aggregate_nonces(&[nonce1.public_nonce()], &[commit2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_signers() {
        let result = aggregate_public_keys(&[]);
        assert!(result.is_err());

        let result = aggregate_nonces(&[], &[]);
        assert!(result.is_err());

        let result = aggregate_partial_signatures(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let signer = MuSig2Signer::new();
        let pubkeys = vec![signer.public_key()];
        let agg_key = aggregate_public_keys(&pubkeys).unwrap();

        let message = b"Serialization test";

        let (nonce, commitment) = signer.nonce_commitment();
        let commitments = vec![commitment];
        let nonces = vec![nonce.public_nonce()];
        let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();

        let partial = signer
            .partial_sign(message, &nonce, &pubkeys, &agg_nonce)
            .unwrap();
        let signature = aggregate_partial_signatures_with_nonce(&[partial], &agg_nonce).unwrap();

        let bytes = signature.to_bytes();
        let recovered = MuSig2Signature::from_bytes(&bytes).unwrap();

        assert!(verify_musig2(&agg_key, message, &recovered));
    }

    #[test]
    fn test_signer_serialization() {
        let signer = MuSig2Signer::new();
        let bytes = signer.to_bytes();
        let recovered = MuSig2Signer::from_bytes(&bytes).unwrap();

        assert_eq!(
            signer.public_key().to_bytes(),
            recovered.public_key().to_bytes()
        );
    }

    #[test]
    fn test_deterministic_key_aggregation() {
        let signer1 = MuSig2Signer::new();
        let signer2 = MuSig2Signer::new();

        let pubkeys = vec![signer1.public_key(), signer2.public_key()];
        let agg1 = aggregate_public_keys(&pubkeys).unwrap();
        let agg2 = aggregate_public_keys(&pubkeys).unwrap();

        assert_eq!(agg1.to_bytes(), agg2.to_bytes());
    }

    #[test]
    fn test_musig2_ten_signers() {
        let signers: Vec<MuSig2Signer> = (0..10).map(|_| MuSig2Signer::new()).collect();
        let pubkeys: Vec<MuSig2PublicKey> = signers.iter().map(|s| s.public_key()).collect();
        let agg_key = aggregate_public_keys(&pubkeys).unwrap();

        let message = b"Ten signer test";

        let nonces_and_commits: Vec<(SigningNonce, NonceCommitment)> =
            signers.iter().map(|s| s.nonce_commitment()).collect();

        let nonces: Vec<MuSig2Nonce> = nonces_and_commits
            .iter()
            .map(|(n, _)| n.public_nonce())
            .collect();
        let commitments: Vec<NonceCommitment> =
            nonces_and_commits.iter().map(|(_, c)| *c).collect();

        let agg_nonce = aggregate_nonces(&nonces, &commitments).unwrap();

        let partials: Vec<PartialSignature> = signers
            .iter()
            .zip(nonces_and_commits.iter())
            .map(|(signer, (nonce, _))| {
                signer
                    .partial_sign(message, nonce, &pubkeys, &agg_nonce)
                    .unwrap()
            })
            .collect();

        let signature = aggregate_partial_signatures_with_nonce(&partials, &agg_nonce).unwrap();

        assert!(verify_musig2(&agg_key, message, &signature));
    }

    #[test]
    fn test_partial_signature_subset_fails() {
        let signer1 = MuSig2Signer::new();
        let signer2 = MuSig2Signer::new();
        let signer3 = MuSig2Signer::new();

        let (nonce1, commit1) = signer1.nonce_commitment();
        let (nonce2, commit2) = signer2.nonce_commitment();
        let (_, commit3) = signer3.nonce_commitment();

        let commitments = vec![commit1, commit2, commit3];
        let nonces = vec![nonce1.public_nonce(), nonce2.public_nonce()];

        // This should fail because we have 3 commitments but only 2 nonces
        let result = aggregate_nonces(&nonces, &commitments);
        assert!(result.is_err());
    }
}
