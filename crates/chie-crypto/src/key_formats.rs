//! Standard key format support (DER, JWK, PKCS#8).
//!
//! This module provides import/export functionality for standard cryptographic
//! key formats used in various protocols and applications.
//!
//! # Supported Formats
//!
//! - **DER**: Distinguished Encoding Rules (ASN.1 binary format)
//! - **JWK**: JSON Web Key (RFC 7517)
//! - **PKCS#8**: Public-Key Cryptography Standards #8
//!
//! # Example
//!
//! ```rust
//! use chie_crypto::key_formats::{JwkKey, DerKey};
//! use chie_crypto::signing::KeyPair;
//!
//! // Generate a keypair
//! let keypair = KeyPair::generate();
//!
//! // Export to JWK
//! let jwk = JwkKey::from_ed25519_keypair(&keypair);
//! let jwk_json = jwk.to_json().unwrap();
//!
//! // Import from JWK
//! let imported_jwk = JwkKey::from_json(&jwk_json).unwrap();
//! let imported_keypair = imported_jwk.to_ed25519_keypair().unwrap();
//! ```

use crate::signing::{KeyPair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Key format errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KeyFormatError {
    /// Invalid DER encoding
    #[error("Invalid DER encoding: {0}")]
    InvalidDer(String),

    /// Invalid JWK format
    #[error("Invalid JWK format: {0}")]
    InvalidJwk(String),

    /// Unsupported key type
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Result type for key format operations
pub type KeyFormatResult<T> = Result<T, KeyFormatError>;

/// JSON Web Key (JWK) representation
///
/// Implements RFC 7517 for Ed25519 keys (EdDSA curve).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwkKey {
    /// Key type (always "OKP" for EdDSA)
    pub kty: String,

    /// Curve (always "Ed25519")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    /// Public key (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// Private key (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Key usage
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl JwkKey {
    /// Create a JWK from an Ed25519 keypair
    pub fn from_ed25519_keypair(keypair: &KeyPair) -> Self {
        let public_key = keypair.public_key();
        let secret_key = keypair.secret_key();

        Self {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(base64_url_encode(&public_key)),
            d: Some(base64_url_encode(&secret_key)),
            key_use: Some("sig".to_string()),
            kid: None,
            alg: Some("EdDSA".to_string()),
        }
    }

    /// Create a JWK from an Ed25519 public key
    pub fn from_ed25519_public_key(public_key: &PublicKey) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(base64_url_encode(public_key)),
            d: None,
            key_use: Some("sig".to_string()),
            kid: None,
            alg: Some("EdDSA".to_string()),
        }
    }

    /// Convert JWK to Ed25519 keypair
    pub fn to_ed25519_keypair(&self) -> KeyFormatResult<KeyPair> {
        // Validate key type
        if self.kty != "OKP" {
            return Err(KeyFormatError::UnsupportedKeyType(self.kty.clone()));
        }

        // Validate curve
        if let Some(crv) = &self.crv {
            if crv != "Ed25519" {
                return Err(KeyFormatError::UnsupportedKeyType(crv.clone()));
            }
        }

        // Extract public key
        let x = self
            .x
            .as_ref()
            .ok_or_else(|| KeyFormatError::MissingField("x".to_string()))?;
        let public_bytes =
            base64_url_decode(x).map_err(|e| KeyFormatError::InvalidJwk(e.to_string()))?;

        if public_bytes.len() != 32 {
            return Err(KeyFormatError::InvalidKeyLength {
                expected: 32,
                actual: public_bytes.len(),
            });
        }

        // Extract private key
        let d = self
            .d
            .as_ref()
            .ok_or_else(|| KeyFormatError::MissingField("d".to_string()))?;
        let secret_bytes =
            base64_url_decode(d).map_err(|e| KeyFormatError::InvalidJwk(e.to_string()))?;

        if secret_bytes.len() != 32 {
            return Err(KeyFormatError::InvalidKeyLength {
                expected: 32,
                actual: secret_bytes.len(),
            });
        }

        // Create keypair
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&secret_bytes);

        KeyPair::from_secret_key(&secret_key)
            .map_err(|_| KeyFormatError::InvalidJwk("Invalid secret key".to_string()))
    }

    /// Convert JWK to Ed25519 public key
    pub fn to_ed25519_public_key(&self) -> KeyFormatResult<PublicKey> {
        // Validate key type
        if self.kty != "OKP" {
            return Err(KeyFormatError::UnsupportedKeyType(self.kty.clone()));
        }

        // Extract public key
        let x = self
            .x
            .as_ref()
            .ok_or_else(|| KeyFormatError::MissingField("x".to_string()))?;
        let public_bytes =
            base64_url_decode(x).map_err(|e| KeyFormatError::InvalidJwk(e.to_string()))?;

        if public_bytes.len() != 32 {
            return Err(KeyFormatError::InvalidKeyLength {
                expected: 32,
                actual: public_bytes.len(),
            });
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_bytes);
        Ok(public_key)
    }

    /// Serialize JWK to JSON string
    pub fn to_json(&self) -> KeyFormatResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KeyFormatError::SerializationError(e.to_string()))
    }

    /// Deserialize JWK from JSON string
    pub fn from_json(json: &str) -> KeyFormatResult<Self> {
        serde_json::from_str(json).map_err(|e| KeyFormatError::SerializationError(e.to_string()))
    }

    /// Set key ID
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

/// DER (Distinguished Encoding Rules) key representation
///
/// Simple DER encoding for Ed25519 keys.
/// For production use, consider using a full ASN.1 library.
pub struct DerKey;

impl DerKey {
    /// Encode Ed25519 public key to DER format (SubjectPublicKeyInfo)
    ///
    /// This creates a simple DER structure for Ed25519 public keys.
    pub fn encode_ed25519_public_key(public_key: &PublicKey) -> Vec<u8> {
        // Simple DER encoding for Ed25519 public key
        // This is a simplified version; production code should use proper ASN.1 library
        let mut der = Vec::with_capacity(44);

        // SEQUENCE
        der.push(0x30);
        der.push(42); // Length

        // AlgorithmIdentifier SEQUENCE
        der.push(0x30);
        der.push(5);

        // OID for Ed25519 (1.3.101.112)
        der.push(0x06);
        der.push(3);
        der.extend_from_slice(&[0x2B, 0x65, 0x70]);

        // BIT STRING for public key
        der.push(0x03);
        der.push(33); // Length (32 + 1 for unused bits)
        der.push(0x00); // No unused bits

        // Public key bytes
        der.extend_from_slice(public_key);

        der
    }

    /// Decode Ed25519 public key from DER format (SubjectPublicKeyInfo)
    pub fn decode_ed25519_public_key(der: &[u8]) -> KeyFormatResult<PublicKey> {
        // Simple DER decoder
        // This is a simplified version; production code should use proper ASN.1 library

        if der.len() < 44 {
            return Err(KeyFormatError::InvalidDer("DER data too short".to_string()));
        }

        // Verify SEQUENCE tag
        if der[0] != 0x30 {
            return Err(KeyFormatError::InvalidDer(
                "Expected SEQUENCE tag".to_string(),
            ));
        }

        // Find BIT STRING with public key
        // Skip to the public key part (simplified parsing)
        let key_start = der.len() - 32;
        if key_start >= der.len() {
            return Err(KeyFormatError::InvalidDer(
                "Invalid DER structure".to_string(),
            ));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&der[key_start..]);

        Ok(public_key)
    }

    /// Encode Ed25519 private key to DER format (PKCS#8)
    ///
    /// Creates a PKCS#8 PrivateKeyInfo structure for Ed25519.
    pub fn encode_ed25519_private_key(secret_key: &SecretKey) -> Vec<u8> {
        // Simple PKCS#8 encoding for Ed25519 private key
        let mut der = Vec::with_capacity(48);

        // SEQUENCE
        der.push(0x30);
        der.push(46); // Length

        // Version (0)
        der.push(0x02);
        der.push(0x01);
        der.push(0x00);

        // AlgorithmIdentifier SEQUENCE
        der.push(0x30);
        der.push(5);

        // OID for Ed25519
        der.push(0x06);
        der.push(3);
        der.extend_from_slice(&[0x2B, 0x65, 0x70]);

        // OCTET STRING containing private key
        der.push(0x04);
        der.push(34); // Length

        // Inner OCTET STRING for the actual key
        der.push(0x04);
        der.push(32);
        der.extend_from_slice(secret_key);

        der
    }

    /// Decode Ed25519 private key from DER format (PKCS#8)
    pub fn decode_ed25519_private_key(der: &[u8]) -> KeyFormatResult<SecretKey> {
        if der.len() < 48 {
            return Err(KeyFormatError::InvalidDer(
                "DER data too short for private key".to_string(),
            ));
        }

        // Find the private key octets (simplified parsing)
        let key_start = der.len() - 32;
        if key_start >= der.len() {
            return Err(KeyFormatError::InvalidDer(
                "Invalid DER structure".to_string(),
            ));
        }

        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&der[key_start..]);

        Ok(secret_key)
    }
}

/// Base64url encoding (URL-safe, no padding)
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decoding
fn base64_url_decode(data: &str) -> Result<Vec<u8>, String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(data).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_keypair_roundtrip() {
        let keypair = KeyPair::generate();

        // Convert to JWK and back
        let jwk = JwkKey::from_ed25519_keypair(&keypair);
        let restored = jwk.to_ed25519_keypair().unwrap();

        // Keys should match
        assert_eq!(keypair.public_key(), restored.public_key());
        assert_eq!(keypair.secret_key(), restored.secret_key());
    }

    #[test]
    fn test_jwk_public_key_roundtrip() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();

        // Convert to JWK and back
        let jwk = JwkKey::from_ed25519_public_key(&public_key);
        let restored = jwk.to_ed25519_public_key().unwrap();

        assert_eq!(public_key, restored);
    }

    #[test]
    fn test_jwk_json_serialization() {
        let keypair = KeyPair::generate();
        let jwk = JwkKey::from_ed25519_keypair(&keypair);

        // Serialize to JSON and back
        let json = jwk.to_json().unwrap();
        let restored = JwkKey::from_json(&json).unwrap();

        assert_eq!(jwk, restored);
    }

    #[test]
    fn test_jwk_with_kid() {
        let keypair = KeyPair::generate();
        let jwk = JwkKey::from_ed25519_keypair(&keypair).with_kid("my-key-id");

        assert_eq!(jwk.kid, Some("my-key-id".to_string()));
    }

    #[test]
    fn test_jwk_validation() {
        // Invalid key type
        let invalid_jwk = JwkKey {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            d: None,
            key_use: None,
            kid: None,
            alg: None,
        };

        assert!(invalid_jwk.to_ed25519_keypair().is_err());
    }

    #[test]
    fn test_der_public_key_roundtrip() {
        let keypair = KeyPair::generate();
        let public_key = keypair.public_key();

        // Encode to DER and decode back
        let der = DerKey::encode_ed25519_public_key(&public_key);
        let restored = DerKey::decode_ed25519_public_key(&der).unwrap();

        assert_eq!(public_key, restored);
    }

    #[test]
    fn test_der_private_key_roundtrip() {
        let keypair = KeyPair::generate();
        let secret_key = keypair.secret_key();

        // Encode to DER and decode back
        let der = DerKey::encode_ed25519_private_key(&secret_key);
        let restored = DerKey::decode_ed25519_private_key(&der).unwrap();

        assert_eq!(secret_key, restored);
    }

    #[test]
    fn test_der_public_key_structure() {
        let keypair = KeyPair::generate();
        let der = DerKey::encode_ed25519_public_key(&keypair.public_key());

        // Verify it starts with SEQUENCE tag
        assert_eq!(der[0], 0x30);

        // Verify it contains Ed25519 OID
        assert!(der.windows(3).any(|w| w == [0x2B, 0x65, 0x70]));
    }

    #[test]
    fn test_base64_url_encoding() {
        let data = b"Hello, World!";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();

        assert_eq!(data, &decoded[..]);

        // URL-safe encoding shouldn't contain +, /, or =
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_jwk_missing_fields() {
        let jwk = JwkKey {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: None, // Missing public key
            d: Some("test".to_string()),
            key_use: None,
            kid: None,
            alg: None,
        };

        assert!(jwk.to_ed25519_keypair().is_err());
    }
}
