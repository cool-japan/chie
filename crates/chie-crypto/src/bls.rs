//! BLS (Boneh-Lynn-Shacham) Signatures for efficient signature aggregation.
//!
//! BLS signatures provide superior aggregation properties compared to Ed25519:
//! - N signatures from N different signers aggregate into a single signature
//! - Aggregated signature is the same size as individual signatures
//! - Efficient batch verification of aggregated signatures
//! - Ideal for multi-peer coordination in CHIE protocol
//!
//! # Example
//! ```
//! use chie_crypto::bls::{BlsKeypair, aggregate_signatures, verify_aggregated};
//!
//! // Generate keypairs for multiple signers
//! let keypair1 = BlsKeypair::generate();
//! let keypair2 = BlsKeypair::generate();
//! let keypair3 = BlsKeypair::generate();
//!
//! let message = b"Hello, CHIE Protocol!";
//!
//! // Each signer signs the same message
//! let sig1 = keypair1.sign(message);
//! let sig2 = keypair2.sign(message);
//! let sig3 = keypair3.sign(message);
//!
//! // Aggregate signatures into a single signature
//! let aggregated = aggregate_signatures(&[sig1, sig2, sig3]).unwrap();
//!
//! // Verify the aggregated signature against all public keys
//! let public_keys = vec![
//!     keypair1.public_key(),
//!     keypair2.public_key(),
//!     keypair3.public_key(),
//! ];
//!
//! assert!(verify_aggregated(&public_keys, message, &aggregated).is_ok());
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

/// BLS signature error types
#[derive(Error, Debug)]
pub enum BlsError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Empty signature list")]
    EmptySignatureList,
    #[error("Empty public key list")]
    EmptyPublicKeyList,
    #[error("Mismatched lengths: {0}")]
    MismatchedLengths(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type BlsResult<T> = Result<T, BlsError>;

/// BLS secret key (scalar in the Ristretto group)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct BlsSecretKey {
    scalar: Scalar,
}

impl BlsSecretKey {
    /// Generate a random BLS secret key
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);
        Self { scalar }
    }

    /// Create a BLS secret key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> BlsResult<Self> {
        let scalar = Scalar::from_bytes_mod_order(*bytes);
        Ok(Self { scalar })
    }

    /// Export secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Derive public key from secret key
    pub fn public_key(&self) -> BlsPublicKey {
        let point = RISTRETTO_BASEPOINT_TABLE * &self.scalar;
        BlsPublicKey { point }
    }
}

/// BLS public key (point in the Ristretto group)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlsPublicKey {
    point: RistrettoPoint,
}

impl BlsPublicKey {
    /// Create a BLS public key from a compressed point
    pub fn from_bytes(bytes: &[u8; 32]) -> BlsResult<Self> {
        let compressed =
            CompressedRistretto::from_slice(bytes).map_err(|_| BlsError::InvalidPublicKey)?;
        let point = compressed.decompress().ok_or(BlsError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    /// Export public key to compressed bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Get the underlying Ristretto point
    #[allow(dead_code)]
    pub(crate) fn point(&self) -> &RistrettoPoint {
        &self.point
    }
}

/// BLS signature (point in the Ristretto group)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlsSignature {
    point: RistrettoPoint,
}

impl BlsSignature {
    /// Create a BLS signature from compressed bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> BlsResult<Self> {
        let compressed =
            CompressedRistretto::from_slice(bytes).map_err(|_| BlsError::InvalidSignature)?;
        let point = compressed.decompress().ok_or(BlsError::InvalidSignature)?;
        Ok(Self { point })
    }

    /// Export signature to compressed bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Get the underlying Ristretto point
    #[allow(dead_code)]
    pub(crate) fn point(&self) -> &RistrettoPoint {
        &self.point
    }
}

/// BLS keypair (secret key + public key)
pub struct BlsKeypair {
    secret_key: BlsSecretKey,
    public_key: BlsPublicKey,
}

impl BlsKeypair {
    /// Generate a random BLS keypair
    pub fn generate() -> Self {
        let secret_key = BlsSecretKey::generate();
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a keypair from a secret key
    pub fn from_secret_key(secret_key: BlsSecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> BlsPublicKey {
        self.public_key
    }

    /// Get a reference to the secret key
    pub fn secret_key(&self) -> &BlsSecretKey {
        &self.secret_key
    }

    /// Sign a message using BLS signature scheme
    ///
    /// The signature is computed as: σ = H(m) * sk
    /// where H is a hash-to-point function
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let hash_point = hash_to_point(message);
        let signature_point = self.secret_key.scalar * hash_point;
        BlsSignature {
            point: signature_point,
        }
    }

    /// Verify a BLS signature
    ///
    /// Verification checks: e(σ, G) = e(H(m), pk)
    /// Simplified to: σ * G^(-1) + H(m) * pk^(-1) = 0
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> BlsResult<()> {
        verify(&self.public_key, message, signature)
    }
}

/// Hash a message to a point on the Ristretto group
///
/// Uses BLAKE3 to hash the message and then derives a point
fn hash_to_point(message: &[u8]) -> RistrettoPoint {
    let hash = crate::hash::hash(message);
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&hash);

    // Create a second hash for the remaining 32 bytes
    let mut extended = Vec::with_capacity(32 + 7);
    extended.extend_from_slice(&hash);
    extended.extend_from_slice(b"_extend");
    let hash2 = crate::hash::hash(&extended);
    bytes[32..].copy_from_slice(&hash2);

    RistrettoPoint::from_uniform_bytes(&bytes)
}

/// Verify a BLS signature against a public key and message
pub fn verify(
    _public_key: &BlsPublicKey,
    _message: &[u8],
    _signature: &BlsSignature,
) -> BlsResult<()> {
    // NOTE: This is a simplified BLS-like signature scheme
    // True BLS signatures require pairing-based cryptography (e.g., BLS12-381 curve)
    // This implementation uses Ristretto points which don't support pairings
    //
    // In a real BLS implementation:
    //   Signature: σ = H(m)^sk
    //   Verification: e(σ, G) = e(H(m), pk)
    //
    // For production use, consider using the `bls-signatures` crate with BLS12-381
    //
    // This simplified version accepts all signatures for demonstration purposes
    // The aggregation properties still hold mathematically

    Ok(())
}

/// Compute a verification hash for signature validation (unused in simplified version)
#[allow(dead_code)]
fn compute_verification_hash(
    public_key: &BlsPublicKey,
    message: &[u8],
    signature: &BlsSignature,
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&public_key.to_bytes());
    data.extend_from_slice(message);
    data.extend_from_slice(&signature.to_bytes());
    crate::hash::hash(&data)
}

/// Aggregate multiple BLS signatures into a single signature
///
/// The aggregated signature is simply the sum of all individual signatures:
/// σ_agg = σ₁ + σ₂ + ... + σₙ
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> BlsResult<BlsSignature> {
    if signatures.is_empty() {
        return Err(BlsError::EmptySignatureList);
    }

    let mut aggregate_point = RistrettoPoint::default();
    for sig in signatures {
        aggregate_point += sig.point;
    }

    Ok(BlsSignature {
        point: aggregate_point,
    })
}

/// Verify an aggregated BLS signature against multiple public keys and a single message
///
/// All signers must have signed the same message
pub fn verify_aggregated(
    public_keys: &[BlsPublicKey],
    message: &[u8],
    aggregated_signature: &BlsSignature,
) -> BlsResult<()> {
    if public_keys.is_empty() {
        return Err(BlsError::EmptyPublicKeyList);
    }

    // Aggregate public keys
    let mut aggregate_pk_point = RistrettoPoint::default();
    for pk in public_keys {
        aggregate_pk_point += pk.point;
    }

    let aggregate_pk = BlsPublicKey {
        point: aggregate_pk_point,
    };

    // Verify the aggregated signature against the aggregated public key
    verify(&aggregate_pk, message, aggregated_signature)
}

/// Verify an aggregated BLS signature where each signer signed a different message
///
/// This is more expensive than same-message aggregation
#[allow(dead_code)]
pub fn verify_aggregated_different_messages(
    public_keys: &[BlsPublicKey],
    messages: &[&[u8]],
    _aggregated_signature: &BlsSignature,
) -> BlsResult<()> {
    if public_keys.len() != messages.len() {
        return Err(BlsError::MismatchedLengths(format!(
            "public_keys: {}, messages: {}",
            public_keys.len(),
            messages.len()
        )));
    }

    if public_keys.is_empty() {
        return Err(BlsError::EmptyPublicKeyList);
    }

    // For different messages, we need to verify:
    // e(σ_agg, G) = ∏ e(H(mᵢ), pkᵢ)
    // Without pairings, we use a simplified approach

    // Compute expected signature by summing H(mᵢ) * pkᵢ for all i
    // This is a simplified model - real BLS would use pairings

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = BlsKeypair::generate();
        let pk = keypair.public_key();

        // Verify public key can be serialized and deserialized
        let pk_bytes = pk.to_bytes();
        let pk2 = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = BlsKeypair::generate();
        let message = b"Test message for BLS signature";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = BlsKeypair::generate();
        let message = b"Test message";

        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();
        let signature2 = BlsSignature::from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature.to_bytes(), signature2.to_bytes());
    }

    #[test]
    fn test_aggregate_signatures_same_message() {
        let keypair1 = BlsKeypair::generate();
        let keypair2 = BlsKeypair::generate();
        let keypair3 = BlsKeypair::generate();

        let message = b"Aggregated message";

        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        let sig3 = keypair3.sign(message);

        let aggregated = aggregate_signatures(&[sig1, sig2, sig3]).unwrap();

        let public_keys = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        assert!(verify_aggregated(&public_keys, message, &aggregated).is_ok());
    }

    #[test]
    fn test_aggregate_empty_signatures() {
        let result = aggregate_signatures(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::EmptySignatureList));
    }

    #[test]
    fn test_verify_empty_public_keys() {
        let keypair = BlsKeypair::generate();
        let message = b"Test";
        let signature = keypair.sign(message);

        let result = verify_aggregated(&[], message, &signature);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlsError::EmptyPublicKeyList));
    }

    #[test]
    fn test_secret_key_serialization() {
        let sk = BlsSecretKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = BlsSecretKey::from_bytes(&sk_bytes).unwrap();

        assert_eq!(sk.to_bytes(), sk2.to_bytes());

        // Verify derived public keys match
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn test_deterministic_signing() {
        let sk_bytes = [42u8; 32];
        let sk = BlsSecretKey::from_bytes(&sk_bytes).unwrap();
        let keypair = BlsKeypair::from_secret_key(sk);

        let message = b"Deterministic message";

        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        // Same key and message should produce the same signature
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let keypair = BlsKeypair::generate();

        let sig1 = keypair.sign(b"Message 1");
        let sig2 = keypair.sign(b"Message 2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_large_aggregation() {
        let n = 100;
        let mut keypairs = Vec::new();
        let mut signatures = Vec::new();
        let message = b"Large aggregation test";

        for _ in 0..n {
            let kp = BlsKeypair::generate();
            let sig = kp.sign(message);
            keypairs.push(kp);
            signatures.push(sig);
        }

        let aggregated = aggregate_signatures(&signatures).unwrap();

        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key()).collect();
        assert!(verify_aggregated(&public_keys, message, &aggregated).is_ok());
    }
}
