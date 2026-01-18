//! WebCrypto API Compatibility Layer
//!
//! This module provides compatibility with the W3C WebCrypto API standard,
//! enabling interoperability between Rust cryptographic operations and
//! browser-based WebCrypto operations.
//!
//! # Examples
//!
//! ```
//! use chie_crypto::webcrypto::{WebCryptoKey, Algorithm, KeyUsage};
//! use chie_crypto::signing::KeyPair;
//!
//! // Create a WebCrypto-compatible key
//! let keypair = KeyPair::generate();
//! let web_key = WebCryptoKey::from_ed25519_keypair(&keypair, &[KeyUsage::Sign]);
//!
//! // Export to JWK (WebCrypto standard format)
//! let jwk = web_key.to_jwk().unwrap();
//! ```

use crate::key_formats::JwkKey;
use crate::signing::{KeyPair, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// WebCrypto API errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WebCryptoError {
    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Invalid key usage
    #[error("Invalid key usage: {0}")]
    InvalidKeyUsage(String),

    /// Key format error
    #[error("Key format error: {0}")]
    KeyFormatError(String),

    /// Operation not permitted
    #[error("Operation not permitted with current key usages")]
    OperationNotPermitted,
}

/// Result type for WebCrypto operations
pub type WebCryptoResult<T> = Result<T, WebCryptoError>;

/// WebCrypto algorithm identifiers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name")]
#[allow(non_snake_case)]
pub enum Algorithm {
    /// EdDSA (Ed25519) - Digital signatures
    #[serde(rename = "EdDSA")]
    EdDSA { namedCurve: String },

    /// ECDH (X25519) - Key agreement
    #[serde(rename = "ECDH")]
    ECDH { namedCurve: String },

    /// AES-GCM - Authenticated encryption
    #[serde(rename = "AES-GCM")]
    AesGcm { length: u32 },

    /// HMAC - Message authentication
    #[serde(rename = "HMAC")]
    Hmac { hash: String },

    /// HKDF - Key derivation
    #[serde(rename = "HKDF")]
    Hkdf { hash: String },

    /// PBKDF2 - Password-based key derivation
    #[serde(rename = "PBKDF2")]
    Pbkdf2 {
        hash: String,
        iterations: u32,
        salt: Vec<u8>,
    },
}

impl Algorithm {
    /// Create EdDSA algorithm with Ed25519 curve
    pub fn ed_dsa() -> Self {
        Self::EdDSA {
            namedCurve: "Ed25519".to_string(),
        }
    }

    /// Create ECDH algorithm with X25519 curve
    pub fn ecdh() -> Self {
        Self::ECDH {
            namedCurve: "X25519".to_string(),
        }
    }

    /// Create AES-GCM algorithm with specified key length
    pub fn aes_gcm(length: u32) -> Self {
        Self::AesGcm { length }
    }

    /// Create HMAC algorithm with specified hash
    pub fn hmac(hash: impl Into<String>) -> Self {
        Self::Hmac { hash: hash.into() }
    }

    /// Create HKDF algorithm with specified hash
    pub fn hkdf(hash: impl Into<String>) -> Self {
        Self::Hkdf { hash: hash.into() }
    }

    /// Create PBKDF2 algorithm
    pub fn pbkdf2(hash: impl Into<String>, iterations: u32, salt: Vec<u8>) -> Self {
        Self::Pbkdf2 {
            hash: hash.into(),
            iterations,
            salt,
        }
    }
}

/// WebCrypto key usage flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyUsage {
    /// Key can be used for encryption
    Encrypt,
    /// Key can be used for decryption
    Decrypt,
    /// Key can be used for signing
    Sign,
    /// Key can be used for verification
    Verify,
    /// Key can be used for key derivation
    DeriveKey,
    /// Key can be used to derive bits
    DeriveBits,
    /// Key can be wrapped
    WrapKey,
    /// Key can be unwrapped
    UnwrapKey,
}

impl KeyUsage {
    /// Check if usage is a signing operation
    pub fn is_signing(&self) -> bool {
        matches!(self, Self::Sign | Self::Verify)
    }

    /// Check if usage is an encryption operation
    pub fn is_encryption(&self) -> bool {
        matches!(self, Self::Encrypt | Self::Decrypt)
    }

    /// Check if usage is a key derivation operation
    pub fn is_derivation(&self) -> bool {
        matches!(self, Self::DeriveKey | Self::DeriveBits)
    }
}

/// WebCrypto-compatible key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCryptoKey {
    /// Algorithm
    pub algorithm: Algorithm,
    /// Key type (public, private, secret)
    #[serde(rename = "type")]
    pub key_type: KeyType,
    /// Extractable flag
    pub extractable: bool,
    /// Key usages
    pub usages: Vec<KeyUsage>,
    /// Internal key data (not exposed in serialization)
    #[serde(skip)]
    key_data: Vec<u8>,
}

/// WebCrypto key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Public key
    Public,
    /// Private key
    Private,
    /// Secret (symmetric) key
    Secret,
}

impl WebCryptoKey {
    /// Create WebCrypto key from Ed25519 keypair
    pub fn from_ed25519_keypair(keypair: &KeyPair, usages: &[KeyUsage]) -> Self {
        Self {
            algorithm: Algorithm::ed_dsa(),
            key_type: KeyType::Private,
            extractable: true,
            usages: usages.to_vec(),
            key_data: keypair.secret_key().to_vec(),
        }
    }

    /// Create WebCrypto key from Ed25519 public key
    pub fn from_ed25519_public_key(public_key: &PublicKey, usages: &[KeyUsage]) -> Self {
        Self {
            algorithm: Algorithm::ed_dsa(),
            key_type: KeyType::Public,
            extractable: true,
            usages: usages.to_vec(),
            key_data: public_key.to_vec(),
        }
    }

    /// Create WebCrypto key from symmetric key
    pub fn from_symmetric_key(key: &[u8], algorithm: Algorithm, usages: &[KeyUsage]) -> Self {
        Self {
            algorithm,
            key_type: KeyType::Secret,
            extractable: true,
            usages: usages.to_vec(),
            key_data: key.to_vec(),
        }
    }

    /// Set extractable flag
    pub fn with_extractable(mut self, extractable: bool) -> Self {
        self.extractable = extractable;
        self
    }

    /// Check if key can be used for operation
    pub fn can_use_for(&self, usage: KeyUsage) -> bool {
        self.usages.contains(&usage)
    }

    /// Export key to JWK format (WebCrypto standard)
    pub fn to_jwk(&self) -> WebCryptoResult<JwkKey> {
        if !self.extractable {
            return Err(WebCryptoError::OperationNotPermitted);
        }

        match (&self.algorithm, self.key_type) {
            (Algorithm::EdDSA { .. }, KeyType::Private) => {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&self.key_data);
                let keypair = KeyPair::from_secret_key(&secret).map_err(|_| {
                    WebCryptoError::KeyFormatError("Invalid secret key".to_string())
                })?;
                Ok(JwkKey::from_ed25519_keypair(&keypair))
            }
            (Algorithm::EdDSA { .. }, KeyType::Public) => {
                let mut public = [0u8; 32];
                public.copy_from_slice(&self.key_data);
                Ok(JwkKey::from_ed25519_public_key(&public))
            }
            _ => Err(WebCryptoError::UnsupportedAlgorithm(
                "Only EdDSA keys can be exported to JWK".to_string(),
            )),
        }
    }

    /// Import key from JWK format
    pub fn from_jwk(jwk: &JwkKey, usages: &[KeyUsage]) -> WebCryptoResult<Self> {
        if jwk.kty != "OKP" {
            return Err(WebCryptoError::UnsupportedAlgorithm(format!(
                "Unsupported key type: {}",
                jwk.kty
            )));
        }

        let crv = jwk
            .crv
            .as_ref()
            .ok_or_else(|| WebCryptoError::KeyFormatError("Missing curve parameter".to_string()))?;

        if crv != "Ed25519" {
            return Err(WebCryptoError::UnsupportedAlgorithm(format!(
                "Unsupported curve: {}",
                crv
            )));
        }

        let algorithm = Algorithm::ed_dsa();

        // Check if it's a private key
        if jwk.d.is_some() {
            let keypair = jwk.to_ed25519_keypair().map_err(|e| {
                WebCryptoError::KeyFormatError(format!("Failed to import keypair: {}", e))
            })?;

            Ok(Self {
                algorithm,
                key_type: KeyType::Private,
                extractable: true,
                usages: usages.to_vec(),
                key_data: keypair.secret_key().to_vec(),
            })
        } else {
            let public_key = jwk.to_ed25519_public_key().map_err(|e| {
                WebCryptoError::KeyFormatError(format!("Failed to import public key: {}", e))
            })?;

            Ok(Self {
                algorithm,
                key_type: KeyType::Public,
                extractable: true,
                usages: usages.to_vec(),
                key_data: public_key.to_vec(),
            })
        }
    }

    /// Get key data (for internal use)
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }
}

/// WebCrypto key pair (for asymmetric algorithms)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCryptoKeyPair {
    /// Public key
    #[serde(rename = "publicKey")]
    pub public_key: WebCryptoKey,
    /// Private key
    #[serde(rename = "privateKey")]
    pub private_key: WebCryptoKey,
}

impl WebCryptoKeyPair {
    /// Create from Ed25519 keypair
    pub fn from_ed25519(keypair: &KeyPair, usages: &[KeyUsage]) -> Self {
        let (sign_usages, verify_usages): (Vec<_>, Vec<_>) =
            usages.iter().partition(|u| **u == KeyUsage::Sign);

        Self {
            public_key: WebCryptoKey::from_ed25519_public_key(
                &keypair.public_key(),
                &verify_usages,
            ),
            private_key: WebCryptoKey::from_ed25519_keypair(keypair, &sign_usages),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_creation() {
        let algo = Algorithm::ed_dsa();
        match algo {
            Algorithm::EdDSA { namedCurve } => {
                assert_eq!(namedCurve, "Ed25519");
            }
            _ => panic!("Wrong algorithm type"),
        }
    }

    #[test]
    fn test_key_usage_checks() {
        assert!(KeyUsage::Sign.is_signing());
        assert!(KeyUsage::Verify.is_signing());
        assert!(KeyUsage::Encrypt.is_encryption());
        assert!(KeyUsage::Decrypt.is_encryption());
        assert!(KeyUsage::DeriveKey.is_derivation());
        assert!(KeyUsage::DeriveBits.is_derivation());
    }

    #[test]
    fn test_webcrypto_key_from_ed25519() {
        let keypair = KeyPair::generate();
        let usages = vec![KeyUsage::Sign];

        let web_key = WebCryptoKey::from_ed25519_keypair(&keypair, &usages);

        assert_eq!(web_key.key_type, KeyType::Private);
        assert!(web_key.extractable);
        assert_eq!(web_key.usages, usages);
        assert!(web_key.can_use_for(KeyUsage::Sign));
        assert!(!web_key.can_use_for(KeyUsage::Verify));
    }

    #[test]
    fn test_webcrypto_public_key() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();
        let usages = vec![KeyUsage::Verify];

        let web_key = WebCryptoKey::from_ed25519_public_key(&public_key, &usages);

        assert_eq!(web_key.key_type, KeyType::Public);
        assert!(web_key.can_use_for(KeyUsage::Verify));
    }

    #[test]
    fn test_jwk_export() {
        let keypair = KeyPair::generate();
        let usages = vec![KeyUsage::Sign];

        let web_key = WebCryptoKey::from_ed25519_keypair(&keypair, &usages);
        let jwk = web_key.to_jwk().unwrap();

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
        assert!(jwk.d.is_some()); // Private key
    }

    #[test]
    fn test_jwk_import_private() {
        let keypair = KeyPair::generate();
        let jwk = JwkKey::from_ed25519_keypair(&keypair);
        let usages = vec![KeyUsage::Sign];

        let web_key = WebCryptoKey::from_jwk(&jwk, &usages).unwrap();

        assert_eq!(web_key.key_type, KeyType::Private);
        assert_eq!(web_key.usages, usages);
    }

    #[test]
    fn test_jwk_import_public() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();
        let jwk = JwkKey::from_ed25519_public_key(&public_key);
        let usages = vec![KeyUsage::Verify];

        let web_key = WebCryptoKey::from_jwk(&jwk, &usages).unwrap();

        assert_eq!(web_key.key_type, KeyType::Public);
        assert_eq!(web_key.usages, usages);
    }

    #[test]
    fn test_extractable_flag() {
        let keypair = KeyPair::generate();
        let web_key =
            WebCryptoKey::from_ed25519_keypair(&keypair, &[KeyUsage::Sign]).with_extractable(false);

        assert!(!web_key.extractable);
        assert!(web_key.to_jwk().is_err());
    }

    #[test]
    fn test_keypair_creation() {
        let keypair = KeyPair::generate();
        let usages = vec![KeyUsage::Sign, KeyUsage::Verify];

        let web_keypair = WebCryptoKeyPair::from_ed25519(&keypair, &usages);

        assert_eq!(web_keypair.public_key.key_type, KeyType::Public);
        assert_eq!(web_keypair.private_key.key_type, KeyType::Private);
    }

    #[test]
    fn test_algorithm_serialization() {
        let algo = Algorithm::ed_dsa();
        let json = serde_json::to_string(&algo).unwrap();
        assert!(json.contains("EdDSA"));
        assert!(json.contains("Ed25519"));

        let deserialized: Algorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, algo);
    }

    #[test]
    fn test_key_usage_serialization() {
        let usage = KeyUsage::Sign;
        let json = serde_json::to_string(&usage).unwrap();
        assert_eq!(json, "\"sign\"");

        let deserialized: KeyUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, usage);
    }

    #[test]
    fn test_webcrypto_key_serialization() {
        let keypair = KeyPair::generate();
        let web_key = WebCryptoKey::from_ed25519_keypair(&keypair, &[KeyUsage::Sign]);

        // Use JSON serialization (more appropriate for WebCrypto)
        let serialized = serde_json::to_string(&web_key).unwrap();
        let deserialized: WebCryptoKey = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.key_type, web_key.key_type);
        assert_eq!(deserialized.extractable, web_key.extractable);
        assert_eq!(deserialized.usages, web_key.usages);
    }

    #[test]
    fn test_symmetric_key() {
        let key = [0x42u8; 32];
        let algo = Algorithm::aes_gcm(256);
        let usages = vec![KeyUsage::Encrypt, KeyUsage::Decrypt];

        let web_key = WebCryptoKey::from_symmetric_key(&key, algo.clone(), &usages);

        assert_eq!(web_key.key_type, KeyType::Secret);
        assert_eq!(web_key.algorithm, algo);
        assert!(web_key.can_use_for(KeyUsage::Encrypt));
        assert!(web_key.can_use_for(KeyUsage::Decrypt));
    }

    #[test]
    fn test_hmac_algorithm() {
        let algo = Algorithm::hmac("SHA-256");
        match algo {
            Algorithm::Hmac { hash } => {
                assert_eq!(hash, "SHA-256");
            }
            _ => panic!("Wrong algorithm type"),
        }
    }

    #[test]
    fn test_hkdf_algorithm() {
        let algo = Algorithm::hkdf("SHA-256");
        match algo {
            Algorithm::Hkdf { hash } => {
                assert_eq!(hash, "SHA-256");
            }
            _ => panic!("Wrong algorithm type"),
        }
    }

    #[test]
    fn test_pbkdf2_algorithm() {
        let salt = vec![1, 2, 3, 4];
        let algo = Algorithm::pbkdf2("SHA-256", 100000, salt.clone());
        match algo {
            Algorithm::Pbkdf2 {
                hash,
                iterations,
                salt: s,
            } => {
                assert_eq!(hash, "SHA-256");
                assert_eq!(iterations, 100000);
                assert_eq!(s, salt);
            }
            _ => panic!("Wrong algorithm type"),
        }
    }
}
