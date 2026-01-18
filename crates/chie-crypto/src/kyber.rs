//! Post-Quantum Key Encapsulation with CRYSTALS-Kyber.
//!
//! This module implements CRYSTALS-Kyber, a NIST-standardized post-quantum
//! Key Encapsulation Mechanism (KEM) designed to be secure against attacks
//! by quantum computers.
//!
//! # Security Levels
//! - Kyber512: Security level 1 (AES-128 equivalent)
//! - Kyber768: Security level 3 (AES-192 equivalent) - **Recommended**
//! - Kyber1024: Security level 5 (AES-256 equivalent)
//!
//! # Use Cases for CHIE Protocol
//! - Future-proof key exchange resistant to quantum attacks
//! - Hybrid encryption with classical algorithms during transition
//! - Long-term secure communication channels
//! - Drop-in replacement for X25519 key exchange
//!
//! # Example
//! ```
//! use chie_crypto::kyber::*;
//!
//! // Alice generates a keypair
//! let (alice_pk, alice_sk) = Kyber768::keypair();
//!
//! // Bob encapsulates a shared secret to Alice's public key
//! let (ciphertext, bob_shared_secret) = Kyber768::encapsulate(&alice_pk).unwrap();
//!
//! // Alice decapsulates to recover the same shared secret
//! let alice_shared_secret = Kyber768::decapsulate(&ciphertext, &alice_sk).unwrap();
//!
//! // Both parties now have the same shared secret
//! assert_eq!(bob_shared_secret.as_bytes(), alice_shared_secret.as_bytes());
//! ```

use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Errors that can occur during Kyber operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KyberError {
    /// Invalid public key length
    InvalidPublicKey,
    /// Invalid secret key length
    InvalidSecretKey,
    /// Invalid ciphertext length
    InvalidCiphertext,
    /// Encapsulation failed
    EncapsulationFailed,
    /// Decapsulation failed
    DecapsulationFailed,
    /// Serialization/deserialization error
    SerializationError,
}

impl std::fmt::Display for KyberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyberError::InvalidPublicKey => write!(f, "Invalid public key length"),
            KyberError::InvalidSecretKey => write!(f, "Invalid secret key length"),
            KyberError::InvalidCiphertext => write!(f, "Invalid ciphertext length"),
            KyberError::EncapsulationFailed => write!(f, "Encapsulation failed"),
            KyberError::DecapsulationFailed => write!(f, "Decapsulation failed"),
            KyberError::SerializationError => write!(f, "Serialization/deserialization error"),
        }
    }
}

impl std::error::Error for KyberError {}

/// Result type for Kyber operations.
pub type KyberResult<T> = Result<T, KyberError>;

/// Kyber512 public key (security level 1).
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber512PublicKey(Vec<u8>);

/// Kyber512 secret key (security level 1).
#[derive(Clone)]
pub struct Kyber512SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Kyber512SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Kyber512SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Kyber512SecretKey(Zeroizing::new(bytes)))
    }
}

/// Kyber512 ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber512Ciphertext(Vec<u8>);

/// Kyber512 shared secret.
#[derive(Clone)]
pub struct Kyber512SharedSecret(Zeroizing<Vec<u8>>);

/// Kyber768 public key (security level 3) - Recommended.
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber768PublicKey(Vec<u8>);

/// Kyber768 secret key (security level 3) - Recommended.
#[derive(Clone)]
pub struct Kyber768SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Kyber768SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Kyber768SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Kyber768SecretKey(Zeroizing::new(bytes)))
    }
}

/// Kyber768 ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber768Ciphertext(Vec<u8>);

/// Kyber768 shared secret.
#[derive(Clone)]
pub struct Kyber768SharedSecret(Zeroizing<Vec<u8>>);

/// Kyber1024 public key (security level 5).
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber1024PublicKey(Vec<u8>);

/// Kyber1024 secret key (security level 5).
#[derive(Clone)]
pub struct Kyber1024SecretKey(Zeroizing<Vec<u8>>);

impl Serialize for Kyber1024SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Kyber1024SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Kyber1024SecretKey(Zeroizing::new(bytes)))
    }
}

/// Kyber1024 ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct Kyber1024Ciphertext(Vec<u8>);

/// Kyber1024 shared secret.
#[derive(Clone)]
pub struct Kyber1024SharedSecret(Zeroizing<Vec<u8>>);

/// Kyber512 - Security level 1 (AES-128 equivalent).
pub struct Kyber512;

impl Kyber512 {
    /// Generate a new keypair.
    pub fn keypair() -> (Kyber512PublicKey, Kyber512SecretKey) {
        let (pk, sk) = kyber512::keypair();
        (
            Kyber512PublicKey(pk.as_bytes().to_vec()),
            Kyber512SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Encapsulate a shared secret to a public key.
    pub fn encapsulate(
        pk: &Kyber512PublicKey,
    ) -> KyberResult<(Kyber512Ciphertext, Kyber512SharedSecret)> {
        let public_key =
            kyber512::PublicKey::from_bytes(&pk.0).map_err(|_| KyberError::InvalidPublicKey)?;

        let (ss, ct) = kyber512::encapsulate(&public_key);

        Ok((
            Kyber512Ciphertext(ct.as_bytes().to_vec()),
            Kyber512SharedSecret(Zeroizing::new(ss.as_bytes().to_vec())),
        ))
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(
        ct: &Kyber512Ciphertext,
        sk: &Kyber512SecretKey,
    ) -> KyberResult<Kyber512SharedSecret> {
        let secret_key =
            kyber512::SecretKey::from_bytes(&sk.0).map_err(|_| KyberError::InvalidSecretKey)?;
        let ciphertext =
            kyber512::Ciphertext::from_bytes(&ct.0).map_err(|_| KyberError::InvalidCiphertext)?;

        let ss = kyber512::decapsulate(&ciphertext, &secret_key);

        Ok(Kyber512SharedSecret(Zeroizing::new(ss.as_bytes().to_vec())))
    }
}

/// Kyber768 - Security level 3 (AES-192 equivalent) - **Recommended**.
pub struct Kyber768;

impl Kyber768 {
    /// Generate a new keypair.
    pub fn keypair() -> (Kyber768PublicKey, Kyber768SecretKey) {
        let (pk, sk) = kyber768::keypair();
        (
            Kyber768PublicKey(pk.as_bytes().to_vec()),
            Kyber768SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Encapsulate a shared secret to a public key.
    pub fn encapsulate(
        pk: &Kyber768PublicKey,
    ) -> KyberResult<(Kyber768Ciphertext, Kyber768SharedSecret)> {
        let public_key =
            kyber768::PublicKey::from_bytes(&pk.0).map_err(|_| KyberError::InvalidPublicKey)?;

        let (ss, ct) = kyber768::encapsulate(&public_key);

        Ok((
            Kyber768Ciphertext(ct.as_bytes().to_vec()),
            Kyber768SharedSecret(Zeroizing::new(ss.as_bytes().to_vec())),
        ))
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(
        ct: &Kyber768Ciphertext,
        sk: &Kyber768SecretKey,
    ) -> KyberResult<Kyber768SharedSecret> {
        let secret_key =
            kyber768::SecretKey::from_bytes(&sk.0).map_err(|_| KyberError::InvalidSecretKey)?;
        let ciphertext =
            kyber768::Ciphertext::from_bytes(&ct.0).map_err(|_| KyberError::InvalidCiphertext)?;

        let ss = kyber768::decapsulate(&ciphertext, &secret_key);

        Ok(Kyber768SharedSecret(Zeroizing::new(ss.as_bytes().to_vec())))
    }
}

/// Kyber1024 - Security level 5 (AES-256 equivalent).
pub struct Kyber1024;

impl Kyber1024 {
    /// Generate a new keypair.
    pub fn keypair() -> (Kyber1024PublicKey, Kyber1024SecretKey) {
        let (pk, sk) = kyber1024::keypair();
        (
            Kyber1024PublicKey(pk.as_bytes().to_vec()),
            Kyber1024SecretKey(Zeroizing::new(sk.as_bytes().to_vec())),
        )
    }

    /// Encapsulate a shared secret to a public key.
    pub fn encapsulate(
        pk: &Kyber1024PublicKey,
    ) -> KyberResult<(Kyber1024Ciphertext, Kyber1024SharedSecret)> {
        let public_key =
            kyber1024::PublicKey::from_bytes(&pk.0).map_err(|_| KyberError::InvalidPublicKey)?;

        let (ss, ct) = kyber1024::encapsulate(&public_key);

        Ok((
            Kyber1024Ciphertext(ct.as_bytes().to_vec()),
            Kyber1024SharedSecret(Zeroizing::new(ss.as_bytes().to_vec())),
        ))
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(
        ct: &Kyber1024Ciphertext,
        sk: &Kyber1024SecretKey,
    ) -> KyberResult<Kyber1024SharedSecret> {
        let secret_key =
            kyber1024::SecretKey::from_bytes(&sk.0).map_err(|_| KyberError::InvalidSecretKey)?;
        let ciphertext =
            kyber1024::Ciphertext::from_bytes(&ct.0).map_err(|_| KyberError::InvalidCiphertext)?;

        let ss = kyber1024::decapsulate(&ciphertext, &secret_key);

        Ok(Kyber1024SharedSecret(Zeroizing::new(
            ss.as_bytes().to_vec(),
        )))
    }
}

// Implement as_bytes() for SharedSecret types
impl Kyber512SharedSecret {
    /// Get the shared secret as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Kyber768SharedSecret {
    /// Get the shared secret as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Kyber1024SharedSecret {
    /// Get the shared secret as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber512_keypair_generation() {
        let (_pk, _sk) = Kyber512::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_kyber512_encapsulation_decapsulation() {
        let (pk, sk) = Kyber512::keypair();
        let (ct, ss1) = Kyber512::encapsulate(&pk).unwrap();
        let ss2 = Kyber512::decapsulate(&ct, &sk).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber512_different_shared_secrets() {
        let (pk, _sk) = Kyber512::keypair();
        let (_ct1, ss1) = Kyber512::encapsulate(&pk).unwrap();
        let (_ct2, ss2) = Kyber512::encapsulate(&pk).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber768_keypair_generation() {
        let (_pk, _sk) = Kyber768::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_kyber768_encapsulation_decapsulation() {
        let (pk, sk) = Kyber768::keypair();
        let (ct, ss1) = Kyber768::encapsulate(&pk).unwrap();
        let ss2 = Kyber768::decapsulate(&ct, &sk).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber768_different_shared_secrets() {
        let (pk, _sk) = Kyber768::keypair();
        let (_ct1, ss1) = Kyber768::encapsulate(&pk).unwrap();
        let (_ct2, ss2) = Kyber768::encapsulate(&pk).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber1024_keypair_generation() {
        let (_pk, _sk) = Kyber1024::keypair();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_kyber1024_encapsulation_decapsulation() {
        let (pk, sk) = Kyber1024::keypair();
        let (ct, ss1) = Kyber1024::encapsulate(&pk).unwrap();
        let ss2 = Kyber1024::decapsulate(&ct, &sk).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber1024_different_shared_secrets() {
        let (pk, _sk) = Kyber1024::keypair();
        let (_ct1, ss1) = Kyber1024::encapsulate(&pk).unwrap();
        let (_ct2, ss2) = Kyber1024::encapsulate(&pk).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber768_wrong_key_decapsulation() {
        let (pk1, _sk1) = Kyber768::keypair();
        let (_pk2, sk2) = Kyber768::keypair();

        let (ct, ss1) = Kyber768::encapsulate(&pk1).unwrap();
        let ss2 = Kyber768::decapsulate(&ct, &sk2).unwrap();

        // Wrong key should produce different shared secret
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber768_serialization() {
        let (pk, sk) = Kyber768::keypair();

        let pk_serialized = crate::codec::encode(&pk).unwrap();
        let sk_serialized = crate::codec::encode(&sk).unwrap();

        let pk_deserialized: Kyber768PublicKey = crate::codec::decode(&pk_serialized).unwrap();
        let sk_deserialized: Kyber768SecretKey = crate::codec::decode(&sk_serialized).unwrap();

        // Verify deserialized keys work
        let (ct, ss1) = Kyber768::encapsulate(&pk_deserialized).unwrap();
        let ss2 = Kyber768::decapsulate(&ct, &sk_deserialized).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber768_ciphertext_serialization() {
        let (pk, sk) = Kyber768::keypair();
        let (ct, ss1) = Kyber768::encapsulate(&pk).unwrap();

        let ct_serialized = crate::codec::encode(&ct).unwrap();
        let ct_deserialized: Kyber768Ciphertext = crate::codec::decode(&ct_serialized).unwrap();

        let ss2 = Kyber768::decapsulate(&ct_deserialized, &sk).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_kyber_all_levels_independent() {
        let (pk512, sk512) = Kyber512::keypair();
        let (pk768, sk768) = Kyber768::keypair();
        let (pk1024, sk1024) = Kyber1024::keypair();

        let (ct512, ss512) = Kyber512::encapsulate(&pk512).unwrap();
        let (ct768, ss768) = Kyber768::encapsulate(&pk768).unwrap();
        let (ct1024, ss1024) = Kyber1024::encapsulate(&pk1024).unwrap();

        let ss512_dec = Kyber512::decapsulate(&ct512, &sk512).unwrap();
        let ss768_dec = Kyber768::decapsulate(&ct768, &sk768).unwrap();
        let ss1024_dec = Kyber1024::decapsulate(&ct1024, &sk1024).unwrap();

        assert_eq!(ss512.as_bytes(), ss512_dec.as_bytes());
        assert_eq!(ss768.as_bytes(), ss768_dec.as_bytes());
        assert_eq!(ss1024.as_bytes(), ss1024_dec.as_bytes());
    }
}
