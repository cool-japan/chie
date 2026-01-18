//! Post-Quantum Signatures with CRYSTALS-Dilithium.
//!
//! This module implements CRYSTALS-Dilithium, a NIST-standardized post-quantum
//! digital signature scheme designed to be secure against attacks by quantum
//! computers.
//!
//! # Security Levels
//! - Dilithium2: Security level 2 (AES-128 equivalent)
//! - Dilithium3: Security level 3 (AES-192 equivalent) - **Recommended**
//! - Dilithium5: Security level 5 (AES-256 equivalent)
//!
//! # Use Cases for CHIE Protocol
//! - Future-proof digital signatures resistant to quantum attacks
//! - Long-term secure content signing and verification
//! - Migration path from Ed25519 to post-quantum signatures
//! - Hybrid signatures during transition period
//!
//! # Example
//! ```
//! use chie_crypto::dilithium::*;
//!
//! // Generate a keypair
//! let (pk, sk) = Dilithium3::keypair();
//!
//! // Sign a message
//! let message = b"Important content hash";
//! let signature = Dilithium3::sign(message, &sk);
//!
//! // Verify the signature
//! assert!(Dilithium3::verify(message, &signature, &pk).is_ok());
//!
//! // Invalid message should fail verification
//! let wrong_message = b"Different content";
//! assert!(Dilithium3::verify(wrong_message, &signature, &pk).is_err());
//! ```

use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Errors that can occur during Dilithium operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DilithiumError {
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

impl std::fmt::Display for DilithiumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DilithiumError::InvalidPublicKey => write!(f, "Invalid public key length"),
            DilithiumError::InvalidSecretKey => write!(f, "Invalid secret key length"),
            DilithiumError::InvalidSignature => write!(f, "Invalid signature length"),
            DilithiumError::VerificationFailed => write!(f, "Signature verification failed"),
            DilithiumError::SigningFailed => write!(f, "Signing failed"),
            DilithiumError::SerializationError => {
                write!(f, "Serialization/deserialization error")
            }
        }
    }
}

impl std::error::Error for DilithiumError {}

/// Result type for Dilithium operations.
pub type DilithiumResult<T> = Result<T, DilithiumError>;

/// Dilithium2 public key (security level 2).
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium2PublicKey(Vec<u8>);

/// Dilithium2 secret key (security level 2).
#[derive(Clone)]
pub struct Dilithium2SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Dilithium2SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Dilithium2SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Dilithium2SecretKey(Zeroizing::new(bytes)))
    }
}

/// Dilithium2 signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium2Signature(Vec<u8>);

/// Dilithium3 public key (security level 3) - Recommended.
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium3PublicKey(Vec<u8>);

/// Dilithium3 secret key (security level 3) - Recommended.
#[derive(Clone)]
pub struct Dilithium3SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Dilithium3SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Dilithium3SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Dilithium3SecretKey(Zeroizing::new(bytes)))
    }
}

/// Dilithium3 signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium3Signature(Vec<u8>);

/// Dilithium5 public key (security level 5).
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium5PublicKey(Vec<u8>);

/// Dilithium5 secret key (security level 5).
#[derive(Clone)]
pub struct Dilithium5SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Dilithium5SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Dilithium5SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Dilithium5SecretKey(Zeroizing::new(bytes)))
    }
}

/// Dilithium5 signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Dilithium5Signature(Vec<u8>);

/// Dilithium2 - Security level 2 (AES-128 equivalent).
pub struct Dilithium2;

impl Dilithium2 {
    /// Generate a new keypair.
    pub fn keypair() -> (Dilithium2PublicKey, Dilithium2SecretKey) {
        let (pk, sk) = dilithium2::keypair();
        (
            Dilithium2PublicKey(pk.as_bytes().to_vec()),
            Dilithium2SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &Dilithium2SecretKey) -> Dilithium2Signature {
        let secret_key = dilithium2::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = dilithium2::detached_sign(message, &secret_key);
        Dilithium2Signature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &Dilithium2Signature,
        pk: &Dilithium2PublicKey,
    ) -> DilithiumResult<()> {
        let public_key = dilithium2::PublicKey::from_bytes(&pk.0)
            .map_err(|_| DilithiumError::InvalidPublicKey)?;
        let sig = dilithium2::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| DilithiumError::InvalidSignature)?;

        dilithium2::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| DilithiumError::VerificationFailed)
    }
}

/// Dilithium3 - Security level 3 (AES-192 equivalent) - **Recommended**.
pub struct Dilithium3;

impl Dilithium3 {
    /// Generate a new keypair.
    pub fn keypair() -> (Dilithium3PublicKey, Dilithium3SecretKey) {
        let (pk, sk) = dilithium3::keypair();
        (
            Dilithium3PublicKey(pk.as_bytes().to_vec()),
            Dilithium3SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &Dilithium3SecretKey) -> Dilithium3Signature {
        let secret_key = dilithium3::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = dilithium3::detached_sign(message, &secret_key);
        Dilithium3Signature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &Dilithium3Signature,
        pk: &Dilithium3PublicKey,
    ) -> DilithiumResult<()> {
        let public_key = dilithium3::PublicKey::from_bytes(&pk.0)
            .map_err(|_| DilithiumError::InvalidPublicKey)?;
        let sig = dilithium3::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| DilithiumError::InvalidSignature)?;

        dilithium3::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| DilithiumError::VerificationFailed)
    }
}

/// Dilithium5 - Security level 5 (AES-256 equivalent).
pub struct Dilithium5;

impl Dilithium5 {
    /// Generate a new keypair.
    pub fn keypair() -> (Dilithium5PublicKey, Dilithium5SecretKey) {
        let (pk, sk) = dilithium5::keypair();
        (
            Dilithium5PublicKey(pk.as_bytes().to_vec()),
            Dilithium5SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Sign a message.
    pub fn sign(message: &[u8], sk: &Dilithium5SecretKey) -> Dilithium5Signature {
        let secret_key = dilithium5::SecretKey::from_bytes(&sk.0).unwrap();
        let sig = dilithium5::detached_sign(message, &secret_key);
        Dilithium5Signature(sig.as_bytes().to_vec())
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &Dilithium5Signature,
        pk: &Dilithium5PublicKey,
    ) -> DilithiumResult<()> {
        let public_key = dilithium5::PublicKey::from_bytes(&pk.0)
            .map_err(|_| DilithiumError::InvalidPublicKey)?;
        let sig = dilithium5::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| DilithiumError::InvalidSignature)?;

        dilithium5::verify_detached_signature(&sig, message, &public_key)
            .map_err(|_| DilithiumError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium2_keypair_generation() {
        let (_pk, _sk) = Dilithium2::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_dilithium2_sign_verify() {
        let (pk, sk) = Dilithium2::keypair();
        let message = b"Test message";

        let signature = Dilithium2::sign(message, &sk);
        assert!(Dilithium2::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_dilithium2_wrong_message_fails() {
        let (pk, sk) = Dilithium2::keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = Dilithium2::sign(message, &sk);
        assert!(Dilithium2::verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_dilithium2_wrong_public_key_fails() {
        let (_pk1, sk1) = Dilithium2::keypair();
        let (pk2, _sk2) = Dilithium2::keypair();
        let message = b"Test message";

        let signature = Dilithium2::sign(message, &sk1);
        assert!(Dilithium2::verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_dilithium3_keypair_generation() {
        let (_pk, _sk) = Dilithium3::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_dilithium3_sign_verify() {
        let (pk, sk) = Dilithium3::keypair();
        let message = b"Test message";

        let signature = Dilithium3::sign(message, &sk);
        assert!(Dilithium3::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_dilithium3_wrong_message_fails() {
        let (pk, sk) = Dilithium3::keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = Dilithium3::sign(message, &sk);
        assert!(Dilithium3::verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_dilithium3_wrong_public_key_fails() {
        let (_pk1, sk1) = Dilithium3::keypair();
        let (pk2, _sk2) = Dilithium3::keypair();
        let message = b"Test message";

        let signature = Dilithium3::sign(message, &sk1);
        assert!(Dilithium3::verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_dilithium5_keypair_generation() {
        let (_pk, _sk) = Dilithium5::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_dilithium5_sign_verify() {
        let (pk, sk) = Dilithium5::keypair();
        let message = b"Test message";

        let signature = Dilithium5::sign(message, &sk);
        assert!(Dilithium5::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_dilithium5_wrong_message_fails() {
        let (pk, sk) = Dilithium5::keypair();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = Dilithium5::sign(message, &sk);
        assert!(Dilithium5::verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_dilithium3_serialization() {
        let (pk, sk) = Dilithium3::keypair();

        let pk_serialized = crate::codec::encode(&pk).unwrap();
        let sk_serialized = crate::codec::encode(&sk).unwrap();

        let pk_deserialized: Dilithium3PublicKey = crate::codec::decode(&pk_serialized).unwrap();
        let sk_deserialized: Dilithium3SecretKey = crate::codec::decode(&sk_serialized).unwrap();

        let message = b"Test message";
        let signature = Dilithium3::sign(message, &sk_deserialized);
        assert!(Dilithium3::verify(message, &signature, &pk_deserialized).is_ok());
    }

    #[test]
    fn test_dilithium3_signature_serialization() {
        let (pk, sk) = Dilithium3::keypair();
        let message = b"Test message";
        let signature = Dilithium3::sign(message, &sk);

        let sig_serialized = crate::codec::encode(&signature).unwrap();
        let sig_deserialized: Dilithium3Signature = crate::codec::decode(&sig_serialized).unwrap();

        assert!(Dilithium3::verify(message, &sig_deserialized, &pk).is_ok());
    }

    #[test]
    fn test_dilithium3_deterministic_signatures() {
        let (pk, sk) = Dilithium3::keypair();
        let message = b"Test message";

        let sig1 = Dilithium3::sign(message, &sk);
        let sig2 = Dilithium3::sign(message, &sk);

        // Dilithium signatures are deterministic
        assert_eq!(sig1.0, sig2.0);

        assert!(Dilithium3::verify(message, &sig1, &pk).is_ok());
        assert!(Dilithium3::verify(message, &sig2, &pk).is_ok());
    }

    #[test]
    fn test_dilithium_all_levels_independent() {
        let (pk2, sk2) = Dilithium2::keypair();
        let (pk3, sk3) = Dilithium3::keypair();
        let (pk5, sk5) = Dilithium5::keypair();

        let message = b"Test message";

        let sig2 = Dilithium2::sign(message, &sk2);
        let sig3 = Dilithium3::sign(message, &sk3);
        let sig5 = Dilithium5::sign(message, &sk5);

        assert!(Dilithium2::verify(message, &sig2, &pk2).is_ok());
        assert!(Dilithium3::verify(message, &sig3, &pk3).is_ok());
        assert!(Dilithium5::verify(message, &sig5, &pk5).is_ok());
    }

    #[test]
    fn test_dilithium3_empty_message() {
        let (pk, sk) = Dilithium3::keypair();
        let message = b"";

        let signature = Dilithium3::sign(message, &sk);
        assert!(Dilithium3::verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_dilithium3_large_message() {
        let (pk, sk) = Dilithium3::keypair();
        let message = vec![42u8; 10_000];

        let signature = Dilithium3::sign(&message, &sk);
        assert!(Dilithium3::verify(&message, &signature, &pk).is_ok());
    }
}
