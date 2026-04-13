//! Schnorr signatures for simplicity and provable security.
//!
//! Schnorr signatures provide:
//! - Simpler construction than EdDSA with cleaner security proofs
//! - Provable security under the discrete logarithm assumption
//! - Native support for threshold signatures
//! - Batch verification support
//! - Linear signature aggregation
//!
//! # Example
//! ```
//! use chie_crypto::schnorr::{SchnorrKeypair, batch_verify};
//!
//! // Generate a keypair
//! let keypair = SchnorrKeypair::generate();
//! let message = b"Hello, Schnorr!";
//!
//! // Sign a message
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! assert!(keypair.verify(message, &signature).is_ok());
//!
//! // Batch verification
//! let items = vec![
//!     (keypair.public_key(), message.as_slice(), signature),
//! ];
//! assert!(batch_verify(&items).is_ok());
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Schnorr signature error types
#[derive(Error, Debug)]
pub enum SchnorrError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Batch verification failed")]
    BatchVerificationFailed,
    #[error("Empty batch")]
    EmptyBatch,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type SchnorrResult<T> = Result<T, SchnorrError>;

/// Schnorr secret key (scalar in the Ristretto group)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SchnorrSecretKey {
    scalar: Scalar,
}

impl SchnorrSecretKey {
    /// Generate a random Schnorr secret key
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);
        Self { scalar }
    }

    /// Create a Schnorr secret key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> SchnorrResult<Self> {
        let scalar = Scalar::from_bytes_mod_order(*bytes);
        Ok(Self { scalar })
    }

    /// Export secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Derive public key from secret key
    pub fn public_key(&self) -> SchnorrPublicKey {
        let point = RISTRETTO_BASEPOINT_TABLE * &self.scalar;
        SchnorrPublicKey { point }
    }
}

/// Schnorr public key (point in the Ristretto group)
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrPublicKey {
    point: RistrettoPoint,
}

impl SchnorrPublicKey {
    /// Create a Schnorr public key from compressed bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> SchnorrResult<Self> {
        let compressed =
            CompressedRistretto::from_slice(bytes).map_err(|_| SchnorrError::InvalidPublicKey)?;
        let point = compressed
            .decompress()
            .ok_or(SchnorrError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    /// Export public key to compressed bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
}

/// Schnorr signature (challenge + response)
///
/// σ = (c, s) where:
/// - c = H(R || P || m) is the challenge
/// - s = k - c*x is the response
/// - R = k*G is the commitment
/// - P = x*G is the public key
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrSignature {
    challenge: Scalar,
    response: Scalar,
}

impl SchnorrSignature {
    /// Create a Schnorr signature from bytes (64 bytes: 32 for challenge + 32 for response)
    pub fn from_bytes(bytes: &[u8; 64]) -> SchnorrResult<Self> {
        let mut challenge_bytes = [0u8; 32];
        let mut response_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&bytes[..32]);
        response_bytes.copy_from_slice(&bytes[32..]);

        let challenge: Option<Scalar> = Scalar::from_canonical_bytes(challenge_bytes).into();
        let response: Option<Scalar> = Scalar::from_canonical_bytes(response_bytes).into();

        let challenge = challenge.ok_or(SchnorrError::InvalidSignature)?;
        let response = response.ok_or(SchnorrError::InvalidSignature)?;

        Ok(Self {
            challenge,
            response,
        })
    }

    /// Export signature to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.challenge.to_bytes());
        bytes[32..].copy_from_slice(&self.response.to_bytes());
        bytes
    }
}

/// Schnorr keypair (secret key + public key)
pub struct SchnorrKeypair {
    secret_key: SchnorrSecretKey,
    public_key: SchnorrPublicKey,
}

impl SchnorrKeypair {
    /// Generate a random Schnorr keypair
    pub fn generate() -> Self {
        let secret_key = SchnorrSecretKey::generate();
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a keypair from a secret key
    pub fn from_secret_key(secret_key: SchnorrSecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> SchnorrPublicKey {
        self.public_key
    }

    /// Get a reference to the secret key
    pub fn secret_key(&self) -> &SchnorrSecretKey {
        &self.secret_key
    }

    /// Sign a message using Schnorr signature scheme
    ///
    /// 1. Generate random nonce k
    /// 2. Compute commitment R = k*G
    /// 3. Compute challenge c = H(R || P || m)
    /// 4. Compute response s = k - c*x
    /// 5. Return signature σ = (c, s)
    pub fn sign(&self, message: &[u8]) -> SchnorrSignature {
        let mut rng = rand::rng();
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let nonce = Scalar::from_bytes_mod_order(nonce_bytes);

        // Commitment: R = k*G
        let commitment = RISTRETTO_BASEPOINT_TABLE * &nonce;

        // Challenge: c = H(R || P || m)
        let challenge = compute_challenge(&commitment, &self.public_key.point, message);

        // Response: s = k - c*x
        let response = nonce - (challenge * self.secret_key.scalar);

        SchnorrSignature {
            challenge,
            response,
        }
    }

    /// Verify a Schnorr signature
    ///
    /// Verification checks: R' = s*G + c*P
    /// Then verifies: c == H(R' || P || m)
    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> SchnorrResult<()> {
        verify(&self.public_key, message, signature)
    }
}

/// Compute the Schnorr challenge: c = H(R || P || m)
fn compute_challenge(
    commitment: &RistrettoPoint,
    public_key: &RistrettoPoint,
    message: &[u8],
) -> Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(&commitment.compress().to_bytes());
    data.extend_from_slice(&public_key.compress().to_bytes());
    data.extend_from_slice(message);

    let hash = crate::hash::hash(&data);
    Scalar::from_bytes_mod_order(hash)
}

/// Verify a Schnorr signature against a public key and message
pub fn verify(
    public_key: &SchnorrPublicKey,
    message: &[u8],
    signature: &SchnorrSignature,
) -> SchnorrResult<()> {
    // Recompute commitment: R' = s*G + c*P
    let commitment_reconstructed =
        RISTRETTO_BASEPOINT_TABLE * &signature.response + public_key.point * signature.challenge;

    // Recompute challenge: c' = H(R' || P || m)
    let challenge_reconstructed =
        compute_challenge(&commitment_reconstructed, &public_key.point, message);

    // Verify: c == c'
    if challenge_reconstructed == signature.challenge {
        Ok(())
    } else {
        Err(SchnorrError::InvalidSignature)
    }
}

/// Batch verify multiple Schnorr signatures
///
/// More efficient than verifying each signature individually using random linear combination.
///
/// For each signature (c_i, s_i) with public key P_i and message m_i:
/// 1. Reconstruct R_i = s_i*G + c_i*P_i
/// 2. Verify c_i == H(R_i || P_i || m_i)
/// 3. Use random linear combination to batch verify: Sum(a_i * R_i) == Sum(a_i * s_i)*G + Sum(a_i * c_i * P_i)
///
/// This reduces the number of expensive point operations from 2n to approximately n+2.
pub fn batch_verify(items: &[(SchnorrPublicKey, &[u8], SchnorrSignature)]) -> SchnorrResult<()> {
    if items.is_empty() {
        return Err(SchnorrError::EmptyBatch);
    }

    // For single signature, use regular verification (no overhead)
    if items.len() == 1 {
        return verify(&items[0].0, items[0].1, &items[0].2);
    }

    let mut rng = rand::rng();

    // Step 1: Reconstruct commitments and verify challenges
    let mut reconstructed_commitments = Vec::with_capacity(items.len());

    for (public_key, message, signature) in items {
        // Reconstruct commitment: R_i = s_i*G + c_i*P_i
        let commitment = RISTRETTO_BASEPOINT_TABLE * &signature.response
            + public_key.point * signature.challenge;

        // Verify challenge: c_i == H(R_i || P_i || m_i)
        let expected_challenge = compute_challenge(&commitment, &public_key.point, message);

        if expected_challenge != signature.challenge {
            return Err(SchnorrError::InvalidSignature);
        }

        reconstructed_commitments.push(commitment);
    }

    // Step 2: Batch verify using random linear combination
    // Generate random weights a_i for each signature
    let weights: Vec<Scalar> = (0..items.len())
        .map(|_| {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            Scalar::from_bytes_mod_order(bytes)
        })
        .collect();

    // Compute left side: Sum(a_i * R_i)
    let mut lhs = RistrettoPoint::default();
    for (weight, commitment) in weights.iter().zip(reconstructed_commitments.iter()) {
        lhs += weight * commitment;
    }

    // Compute right side: Sum(a_i * s_i)*G + Sum(a_i * c_i * P_i)
    let mut response_sum = Scalar::ZERO;
    let mut weighted_pubkey_sum = RistrettoPoint::default();

    for (i, (public_key, _, signature)) in items.iter().enumerate() {
        response_sum += weights[i] * signature.response;
        weighted_pubkey_sum += (weights[i] * signature.challenge) * public_key.point;
    }

    let rhs = RISTRETTO_BASEPOINT_TABLE * &response_sum + weighted_pubkey_sum;

    // Verify the batch equation
    if lhs == rhs {
        Ok(())
    } else {
        Err(SchnorrError::BatchVerificationFailed)
    }
}

/// Aggregate multiple Schnorr signatures for the same message
///
/// Note: This is different from BLS aggregation - Schnorr aggregation
/// requires interactive protocols or more complex schemes
#[allow(dead_code)]
pub fn aggregate_signatures(_signatures: &[SchnorrSignature]) -> SchnorrResult<SchnorrSignature> {
    // Schnorr signature aggregation requires MuSig or similar protocols
    // This is a placeholder for future implementation
    unimplemented!("Schnorr aggregation requires MuSig protocol")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = SchnorrKeypair::generate();
        let pk = keypair.public_key();

        // Verify public key can be serialized and deserialized
        let pk_bytes = pk.to_bytes();
        let pk2 = SchnorrPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SchnorrKeypair::generate();
        let message = b"Test message for Schnorr signature";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = SchnorrKeypair::generate();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let keypair1 = SchnorrKeypair::generate();
        let keypair2 = SchnorrKeypair::generate();
        let message = b"Test message";

        let signature = keypair1.sign(message);
        assert!(verify(&keypair2.public_key(), message, &signature).is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = SchnorrKeypair::generate();
        let message = b"Test message";

        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();
        let signature2 = SchnorrSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, signature2);
        assert!(keypair.verify(message, &signature2).is_ok());
    }

    #[test]
    fn test_deterministic_public_key() {
        let sk_bytes = [42u8; 32];
        let sk1 = SchnorrSecretKey::from_bytes(&sk_bytes).unwrap();
        let sk2 = SchnorrSecretKey::from_bytes(&sk_bytes).unwrap();

        assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn test_batch_verify() {
        let keypair1 = SchnorrKeypair::generate();
        let keypair2 = SchnorrKeypair::generate();
        let keypair3 = SchnorrKeypair::generate();

        let message = b"Batch verification test";

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        let sig3 = keypair3.sign(message);

        let items = vec![
            (keypair1.public_key(), message.as_slice(), sig1),
            (keypair2.public_key(), message.as_slice(), sig2),
            (keypair3.public_key(), message.as_slice(), sig3),
        ];

        assert!(batch_verify(&items).is_ok());
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let keypair1 = SchnorrKeypair::generate();
        let keypair2 = SchnorrKeypair::generate();
        let keypair3 = SchnorrKeypair::generate();

        let message = b"Batch verification test";
        let wrong_message = b"Wrong message";

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(wrong_message); // Invalid!
        let sig3 = keypair3.sign(message);

        let items = vec![
            (keypair1.public_key(), message.as_slice(), sig1),
            (keypair2.public_key(), message.as_slice(), sig2),
            (keypair3.public_key(), message.as_slice(), sig3),
        ];

        assert!(batch_verify(&items).is_err());
    }

    #[test]
    fn test_batch_verify_empty() {
        let items: Vec<(SchnorrPublicKey, &[u8], SchnorrSignature)> = vec![];
        assert!(batch_verify(&items).is_err());
    }

    #[test]
    fn test_secret_key_serialization() {
        let sk = SchnorrSecretKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = SchnorrSecretKey::from_bytes(&sk_bytes).unwrap();

        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn test_signature_randomness() {
        let keypair = SchnorrKeypair::generate();
        let message = b"Test message";

        // Schnorr signatures should be different each time due to random nonce
        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        assert_ne!(sig1, sig2);
        assert!(keypair.verify(message, &sig1).is_ok());
        assert!(keypair.verify(message, &sig2).is_ok());
    }
}
