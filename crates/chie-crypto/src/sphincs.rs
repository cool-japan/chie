//! Stateless Hash-Based Signatures with SPHINCS+.
//!
//! This module implements SPHINCS+, a stateless hash-based post-quantum
//! signature scheme with minimal security assumptions. Unlike lattice-based
//! schemes, SPHINCS+ only relies on the security of hash functions.
//!
//! # Security Levels
//! - SPHINCS+-SHAKE-128f: Fast variant, security level 1 (AES-128 equivalent)
//! - SPHINCS+-SHAKE-192f: Fast variant, security level 3 (AES-192 equivalent)
//! - SPHINCS+-SHAKE-256f: Fast variant, security level 5 (AES-256 equivalent) - **Recommended**
//!
//! # Characteristics
//! - **Minimal assumptions**: Security relies only on hash functions
//! - **No quantum vulnerability**: Secure against quantum attacks
//! - **Larger signatures**: Trade-off for stronger security guarantees
//! - **Stateless**: No state management required (unlike XMSS)
//!
//! # Use Cases for CHIE Protocol
//! - Long-term archival signatures (decades of security)
//! - Maximum security for critical content
//! - Conservative post-quantum approach
//! - When signature size is less critical than security
//!
//! # Example
//! ```
//! use chie_crypto::sphincs::*;
//!
//! // Generate a keypair
//! let (pk, sk) = SphincsSHAKE256f::keypair();
//!
//! // Sign a message
//! let message = b"Critical archival content";
//! let signature = SphincsSHAKE256f::sign(message, &sk);
//!
//! // Verify the signature
//! assert!(SphincsSHAKE256f::verify(message, &signature, &pk).is_ok());
//!
//! // Invalid message should fail verification
//! let wrong_message = b"Different content";
//! assert!(SphincsSHAKE256f::verify(wrong_message, &signature, &pk).is_err());
//! ```

use pqcrypto_sphincsplus::{
    sphincsshake128fsimple, sphincsshake192fsimple, sphincsshake256fsimple,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Errors that can occur during SPHINCS+ operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SphincsError {
    /// Invalid public key length
    InvalidPublicKey,
    /// Invalid secret key length
    InvalidSecretKey,
    /// Invalid signature length
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
    /// Signing failed
    SigningFailed,
    /// Serialization/deserialization error
    SerializationError,
}

impl std::fmt::Display for SphincsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SphincsError::InvalidPublicKey => write!(f, "Invalid public key length"),
            SphincsError::InvalidSecretKey => write!(f, "Invalid secret key length"),
            SphincsError::InvalidSignature => write!(f, "Invalid signature length"),
            SphincsError::VerificationFailed => write!(f, "Signature verification failed"),
            SphincsError::SigningFailed => write!(f, "Signing failed"),
            SphincsError::SerializationError => write!(f, "Serialization/deserialization error"),
        }
    }
}

impl std::error::Error for SphincsError {}

/// Result type for SPHINCS+ operations.
pub type SphincsResult<T> = Result<T, SphincsError>;

/// SPHINCS+-SHAKE-128f public key (security level 1).
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE128fPublicKey(Vec<u8>);

/// SPHINCS+-SHAKE-128f secret key (security level 1).
#[derive(Clone)]
pub struct SphincsSHAKE128fSecretKey(Zeroizing<Vec<u8>>);

impl Serialize for SphincsSHAKE128fSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SphincsSHAKE128fSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(SphincsSHAKE128fSecretKey(Zeroizing::new(bytes)))
    }
}

/// SPHINCS+-SHAKE-128f signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE128fSignature(Vec<u8>);

/// SPHINCS+-SHAKE-192f public key (security level 3).
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE192fPublicKey(Vec<u8>);

/// SPHINCS+-SHAKE-192f secret key (security level 3).
#[derive(Clone)]
pub struct SphincsSHAKE192fSecretKey(Zeroizing<Vec<u8>>);

impl Serialize for SphincsSHAKE192fSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SphincsSHAKE192fSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(SphincsSHAKE192fSecretKey(Zeroizing::new(bytes)))
    }
}

/// SPHINCS+-SHAKE-192f signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE192fSignature(Vec<u8>);

/// SPHINCS+-SHAKE-256f public key (security level 5) - Recommended.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE256fPublicKey(Vec<u8>);

/// SPHINCS+-SHAKE-256f secret key (security level 5) - Recommended.
#[derive(Clone)]
pub struct SphincsSHAKE256fSecretKey(Zeroizing<Vec<u8>>);

impl Serialize for SphincsSHAKE256fSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SphincsSHAKE256fSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(SphincsSHAKE256fSecretKey(Zeroizing::new(bytes)))
    }
}

/// SPHINCS+-SHAKE-256f signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphincsSHAKE256fSignature(Vec<u8>);

/// SPHINCS+-SHAKE-128f - Fast variant, security level 1 (AES-128 equivalent).
pub struct SphincsSHAKE128f;

impl SphincsSHAKE128f {
    /// Generate a new keypair.
    pub fn keypair() -> (SphincsSHAKE128fPublicKey, SphincsSHAKE128fSecretKey) {
        let (pk, sk) = sphincsshake128fsimple::keypair();
        (
            SphincsSHAKE128fPublicKey(pk.as_bytes().to_vec()),
            SphincsSHAKE128fSecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &SphincsSHAKE128fSecretKey) -> SphincsSHAKE128fSignature {
        let secret_key = sphincsshake128fsimple::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = sphincsshake128fsimple::detached_sign(message, &secret_key);
        SphincsSHAKE128fSignature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &SphincsSHAKE128fSignature,
        pk: &SphincsSHAKE128fPublicKey,
    ) -> SphincsResult<()> {
        let public_key = sphincsshake128fsimple::PublicKey::from_bytes(&pk.0)
            .map_err(|_| SphincsError::InvalidPublicKey)?;
        let sig = sphincsshake128fsimple::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| SphincsError::InvalidSignature)?;

        sphincsshake128fsimple::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| SphincsError::VerificationFailed)
    }
}

/// SPHINCS+-SHAKE-192f - Fast variant, security level 3 (AES-192 equivalent).
pub struct SphincsSHAKE192f;

impl SphincsSHAKE192f {
    /// Generate a new keypair.
    pub fn keypair() -> (SphincsSHAKE192fPublicKey, SphincsSHAKE192fSecretKey) {
        let (pk, sk) = sphincsshake192fsimple::keypair();
        (
            SphincsSHAKE192fPublicKey(pk.as_bytes().to_vec()),
            SphincsSHAKE192fSecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &SphincsSHAKE192fSecretKey) -> SphincsSHAKE192fSignature {
        let secret_key = sphincsshake192fsimple::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = sphincsshake192fsimple::detached_sign(message, &secret_key);
        SphincsSHAKE192fSignature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &SphincsSHAKE192fSignature,
        pk: &SphincsSHAKE192fPublicKey,
    ) -> SphincsResult<()> {
        let public_key = sphincsshake192fsimple::PublicKey::from_bytes(&pk.0)
            .map_err(|_| SphincsError::InvalidPublicKey)?;
        let sig = sphincsshake192fsimple::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| SphincsError::InvalidSignature)?;

        sphincsshake192fsimple::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| SphincsError::VerificationFailed)
    }
}

/// SPHINCS+-SHAKE-256f - Fast variant, security level 5 (AES-256 equivalent) - **Recommended**.
pub struct SphincsSHAKE256f;

impl SphincsSHAKE256f {
    /// Generate a new keypair.
    pub fn keypair() -> (SphincsSHAKE256fPublicKey, SphincsSHAKE256fSecretKey) {
        let (pk, sk) = sphincsshake256fsimple::keypair();
        (
            SphincsSHAKE256fPublicKey(pk.as_bytes().to_vec()),
            SphincsSHAKE256fSecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &SphincsSHAKE256fSecretKey) -> SphincsSHAKE256fSignature {
        let secret_key = sphincsshake256fsimple::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = sphincsshake256fsimple::detached_sign(message, &secret_key);
        SphincsSHAKE256fSignature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &SphincsSHAKE256fSignature,
        pk: &SphincsSHAKE256fPublicKey,
    ) -> SphincsResult<()> {
        let public_key = sphincsshake256fsimple::PublicKey::from_bytes(&pk.0)
            .map_err(|_| SphincsError::InvalidPublicKey)?;
        let sig = sphincsshake256fsimple::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| SphincsError::InvalidSignature)?;

        sphincsshake256fsimple::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| SphincsError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs128_keypair_generation() {
        let (_pk, _sk) = SphincsSHAKE128f::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_sphincs128_sign_verify() {
        let (pk, sk) = SphincsSHAKE128f::keypair();
        let message = b"Test message";

        let signature = SphincsSHAKE128f::sign(message, &sk);
        assert!(SphincsSHAKE128f::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_sphincs128_wrong_message_fails() {
        let (pk, sk) = SphincsSHAKE128f::keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = SphincsSHAKE128f::sign(message, &sk);
        assert!(SphincsSHAKE128f::verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_sphincs128_wrong_public_key_fails() {
        let (_pk1, sk1) = SphincsSHAKE128f::keypair();
        let (pk2, _sk2) = SphincsSHAKE128f::keypair();
        let message = b"Test message";

        let signature = SphincsSHAKE128f::sign(message, &sk1);
        assert!(SphincsSHAKE128f::verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_sphincs192_keypair_generation() {
        let (_pk, _sk) = SphincsSHAKE192f::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_sphincs192_sign_verify() {
        let (pk, sk) = SphincsSHAKE192f::keypair();
        let message = b"Test message";

        let signature = SphincsSHAKE192f::sign(message, &sk);
        assert!(SphincsSHAKE192f::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_sphincs256_keypair_generation() {
        let (_pk, _sk) = SphincsSHAKE256f::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_sphincs256_sign_verify() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = b"Test message";

        let signature = SphincsSHAKE256f::sign(message, &sk);
        assert!(SphincsSHAKE256f::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_sphincs256_wrong_message_fails() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = SphincsSHAKE256f::sign(message, &sk);
        assert!(SphincsSHAKE256f::verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_sphincs256_wrong_public_key_fails() {
        let (_pk1, sk1) = SphincsSHAKE256f::keypair();
        let (pk2, _sk2) = SphincsSHAKE256f::keypair();
        let message = b"Test message";

        let signature = SphincsSHAKE256f::sign(message, &sk1);
        assert!(SphincsSHAKE256f::verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_sphincs256_serialization() {
        let (pk, sk) = SphincsSHAKE256f::keypair();

        let pk_serialized = crate::codec::encode(&pk).unwrap();
        let sk_serialized = crate::codec::encode(&sk).unwrap();

        let pk_deserialized: SphincsSHAKE256fPublicKey =
            crate::codec::decode(&pk_serialized).unwrap();
        let sk_deserialized: SphincsSHAKE256fSecretKey =
            crate::codec::decode(&sk_serialized).unwrap();

        let message = b"Test message";
        let signature = SphincsSHAKE256f::sign(message, &sk_deserialized);
        assert!(SphincsSHAKE256f::verify(message, &signature, &pk_deserialized).is_ok());
    }

    #[test]
    fn test_sphincs256_signature_serialization() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = b"Test message";
        let signature = SphincsSHAKE256f::sign(message, &sk);

        let sig_serialized = crate::codec::encode(&signature).unwrap();
        let sig_deserialized: SphincsSHAKE256fSignature =
            crate::codec::decode(&sig_serialized).unwrap();

        assert!(SphincsSHAKE256f::verify(message, &sig_deserialized, &pk).is_ok());
    }

    #[test]
    fn test_sphincs_all_levels_independent() {
        let (pk128, sk128) = SphincsSHAKE128f::keypair();
        let (pk192, sk192) = SphincsSHAKE192f::keypair();
        let (pk256, sk256) = SphincsSHAKE256f::keypair();

        let message = b"Test message";

        let sig128 = SphincsSHAKE128f::sign(message, &sk128);
        let sig192 = SphincsSHAKE192f::sign(message, &sk192);
        let sig256 = SphincsSHAKE256f::sign(message, &sk256);

        assert!(SphincsSHAKE128f::verify(message, &sig128, &pk128).is_ok());
        assert!(SphincsSHAKE192f::verify(message, &sig192, &pk192).is_ok());
        assert!(SphincsSHAKE256f::verify(message, &sig256, &pk256).is_ok());
    }

    #[test]
    fn test_sphincs256_empty_message() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = b"";

        let signature = SphincsSHAKE256f::sign(message, &sk);
        assert!(SphincsSHAKE256f::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_sphincs256_large_message() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = vec![42u8; 10_000];

        let signature = SphincsSHAKE256f::sign(&message, &sk);
        assert!(SphincsSHAKE256f::verify(&message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_sphincs256_multiple_signatures() {
        let (pk, sk) = SphincsSHAKE256f::keypair();
        let message = b"Test message";

        let sig1 = SphincsSHAKE256f::sign(message, &sk);
        let sig2 = SphincsSHAKE256f::sign(message, &sk);

        // SPHINCS+ may use randomization, so signatures might differ
        // But both should be valid
        assert!(SphincsSHAKE256f::verify(message, &sig1, &pk).is_ok());
        assert!(SphincsSHAKE256f::verify(message, &sig2, &pk).is_ok());
    }
}
