//! Key serialization and deserialization utilities.
//!
//! Provides import/export of keys in various formats:
//! - PEM format for Ed25519 keys
//! - Hex encoding
//! - Base64 encoding

use crate::signing::{KeyPair, PublicKey, SecretKey, SigningError};
use thiserror::Error;

/// Key serialization error.
#[derive(Debug, Error)]
pub enum KeySerdeError {
    #[error("Invalid PEM format")]
    InvalidPemFormat,

    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Signing error: {0}")]
    SigningError(#[from] SigningError),

    #[error("Unknown key type: {0}")]
    UnknownKeyType(String),
}

/// PEM header for Ed25519 private keys.
const ED25519_PRIVATE_KEY_HEADER: &str = "-----BEGIN ED25519 PRIVATE KEY-----";
const ED25519_PRIVATE_KEY_FOOTER: &str = "-----END ED25519 PRIVATE KEY-----";

/// PEM header for Ed25519 public keys.
const ED25519_PUBLIC_KEY_HEADER: &str = "-----BEGIN ED25519 PUBLIC KEY-----";
const ED25519_PUBLIC_KEY_FOOTER: &str = "-----END ED25519 PUBLIC KEY-----";

/// Key serializer for various formats.
pub struct KeySerializer;

impl KeySerializer {
    // ========================================================================
    // Hex encoding
    // ========================================================================

    /// Encode a secret key as hexadecimal string.
    pub fn secret_key_to_hex(key: &SecretKey) -> String {
        hex::encode(key)
    }

    /// Decode a secret key from hexadecimal string.
    pub fn secret_key_from_hex(hex_str: &str) -> Result<SecretKey, KeySerdeError> {
        let bytes = hex::decode(hex_str).map_err(|e| KeySerdeError::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(KeySerdeError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Encode a public key as hexadecimal string.
    pub fn public_key_to_hex(key: &PublicKey) -> String {
        hex::encode(key)
    }

    /// Decode a public key from hexadecimal string.
    pub fn public_key_from_hex(hex_str: &str) -> Result<PublicKey, KeySerdeError> {
        let bytes = hex::decode(hex_str).map_err(|e| KeySerdeError::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(KeySerdeError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    // ========================================================================
    // Base64 encoding
    // ========================================================================

    /// Encode a secret key as base64 string.
    pub fn secret_key_to_base64(key: &SecretKey) -> String {
        base64_encode(key)
    }

    /// Decode a secret key from base64 string.
    pub fn secret_key_from_base64(b64_str: &str) -> Result<SecretKey, KeySerdeError> {
        let bytes = base64_decode(b64_str)?;

        if bytes.len() != 32 {
            return Err(KeySerdeError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Encode a public key as base64 string.
    pub fn public_key_to_base64(key: &PublicKey) -> String {
        base64_encode(key)
    }

    /// Decode a public key from base64 string.
    pub fn public_key_from_base64(b64_str: &str) -> Result<PublicKey, KeySerdeError> {
        let bytes = base64_decode(b64_str)?;

        if bytes.len() != 32 {
            return Err(KeySerdeError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    // ========================================================================
    // PEM encoding
    // ========================================================================

    /// Export a key pair to PEM format (private key).
    pub fn keypair_to_pem(keypair: &KeyPair) -> String {
        let secret = keypair.secret_key();
        Self::secret_key_to_pem(&secret)
    }

    /// Export a secret key to PEM format.
    pub fn secret_key_to_pem(key: &SecretKey) -> String {
        let b64 = base64_encode(key);
        let wrapped = wrap_base64(&b64, 64);
        format!(
            "{}\n{}\n{}",
            ED25519_PRIVATE_KEY_HEADER, wrapped, ED25519_PRIVATE_KEY_FOOTER
        )
    }

    /// Import a key pair from PEM format.
    pub fn keypair_from_pem(pem: &str) -> Result<KeyPair, KeySerdeError> {
        let secret = Self::secret_key_from_pem(pem)?;
        KeyPair::from_secret_key(&secret).map_err(KeySerdeError::SigningError)
    }

    /// Import a secret key from PEM format.
    pub fn secret_key_from_pem(pem: &str) -> Result<SecretKey, KeySerdeError> {
        let pem = pem.trim();

        if !pem.starts_with(ED25519_PRIVATE_KEY_HEADER) {
            return Err(KeySerdeError::InvalidPemFormat);
        }
        if !pem.ends_with(ED25519_PRIVATE_KEY_FOOTER) {
            return Err(KeySerdeError::InvalidPemFormat);
        }

        // Extract base64 content
        let content = pem
            .strip_prefix(ED25519_PRIVATE_KEY_HEADER)
            .and_then(|s| s.strip_suffix(ED25519_PRIVATE_KEY_FOOTER))
            .ok_or(KeySerdeError::InvalidPemFormat)?;

        // Remove whitespace
        let b64: String = content.chars().filter(|c| !c.is_whitespace()).collect();

        Self::secret_key_from_base64(&b64)
    }

    /// Export a public key to PEM format.
    pub fn public_key_to_pem(key: &PublicKey) -> String {
        let b64 = base64_encode(key);
        let wrapped = wrap_base64(&b64, 64);
        format!(
            "{}\n{}\n{}",
            ED25519_PUBLIC_KEY_HEADER, wrapped, ED25519_PUBLIC_KEY_FOOTER
        )
    }

    /// Import a public key from PEM format.
    pub fn public_key_from_pem(pem: &str) -> Result<PublicKey, KeySerdeError> {
        let pem = pem.trim();

        if !pem.starts_with(ED25519_PUBLIC_KEY_HEADER) {
            return Err(KeySerdeError::InvalidPemFormat);
        }
        if !pem.ends_with(ED25519_PUBLIC_KEY_FOOTER) {
            return Err(KeySerdeError::InvalidPemFormat);
        }

        // Extract base64 content
        let content = pem
            .strip_prefix(ED25519_PUBLIC_KEY_HEADER)
            .and_then(|s| s.strip_suffix(ED25519_PUBLIC_KEY_FOOTER))
            .ok_or(KeySerdeError::InvalidPemFormat)?;

        // Remove whitespace
        let b64: String = content.chars().filter(|c| !c.is_whitespace()).collect();

        Self::public_key_from_base64(&b64)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Encode bytes to base64 (standard alphabet, no padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(ALPHABET[(b0 >> 2) as usize] as char);
        result.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Decode base64 to bytes.
fn base64_decode(data: &str) -> Result<Vec<u8>, KeySerdeError> {
    const DECODE_TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let data = data.trim_end_matches('=');
    let len = data.len();

    if len == 0 {
        return Ok(Vec::new());
    }

    let output_len = (len * 3) / 4;
    let mut result = Vec::with_capacity(output_len);

    let bytes = data.as_bytes();
    let mut i = 0;

    while i + 3 < len {
        let b0 = decode_char(bytes[i], &DECODE_TABLE)?;
        let b1 = decode_char(bytes[i + 1], &DECODE_TABLE)?;
        let b2 = decode_char(bytes[i + 2], &DECODE_TABLE)?;
        let b3 = decode_char(bytes[i + 3], &DECODE_TABLE)?;

        result.push((b0 << 2) | (b1 >> 4));
        result.push((b1 << 4) | (b2 >> 2));
        result.push((b2 << 6) | b3);

        i += 4;
    }

    // Handle remaining bytes
    if i < len {
        let remaining = len - i;
        let b0 = decode_char(bytes[i], &DECODE_TABLE)?;
        let b1 = if i + 1 < len {
            decode_char(bytes[i + 1], &DECODE_TABLE)?
        } else {
            0
        };
        let b2 = if i + 2 < len {
            decode_char(bytes[i + 2], &DECODE_TABLE)?
        } else {
            0
        };

        result.push((b0 << 2) | (b1 >> 4));
        if remaining > 2 {
            result.push((b1 << 4) | (b2 >> 2));
        }
        if remaining > 3 {
            let b3 = decode_char(bytes[i + 3], &DECODE_TABLE)?;
            result.push((b2 << 6) | b3);
        }
    }

    Ok(result)
}

fn decode_char(c: u8, table: &[i8; 128]) -> Result<u8, KeySerdeError> {
    if c >= 128 {
        return Err(KeySerdeError::InvalidBase64(format!(
            "Invalid character: {}",
            c as char
        )));
    }
    let val = table[c as usize];
    if val < 0 {
        return Err(KeySerdeError::InvalidBase64(format!(
            "Invalid character: {}",
            c as char
        )));
    }
    Ok(val as u8)
}

/// Wrap base64 string at specified line length.
fn wrap_base64(b64: &str, line_len: usize) -> String {
    let mut result = String::new();
    let mut i = 0;

    while i < b64.len() {
        let end = (i + line_len).min(b64.len());
        result.push_str(&b64[i..end]);
        if end < b64.len() {
            result.push('\n');
        }
        i = end;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public = keypair.public_key();

        let secret_hex = KeySerializer::secret_key_to_hex(&secret);
        let public_hex = KeySerializer::public_key_to_hex(&public);

        let secret2 = KeySerializer::secret_key_from_hex(&secret_hex).unwrap();
        let public2 = KeySerializer::public_key_from_hex(&public_hex).unwrap();

        assert_eq!(secret, secret2);
        assert_eq!(public, public2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public = keypair.public_key();

        let secret_b64 = KeySerializer::secret_key_to_base64(&secret);
        let public_b64 = KeySerializer::public_key_to_base64(&public);

        let secret2 = KeySerializer::secret_key_from_base64(&secret_b64).unwrap();
        let public2 = KeySerializer::public_key_from_base64(&public_b64).unwrap();

        assert_eq!(secret, secret2);
        assert_eq!(public, public2);
    }

    #[test]
    fn test_pem_roundtrip() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let public = keypair.public_key();

        let secret_pem = KeySerializer::secret_key_to_pem(&secret);
        let public_pem = KeySerializer::public_key_to_pem(&public);

        let secret2 = KeySerializer::secret_key_from_pem(&secret_pem).unwrap();
        let public2 = KeySerializer::public_key_from_pem(&public_pem).unwrap();

        assert_eq!(secret, secret2);
        assert_eq!(public, public2);
    }

    #[test]
    fn test_keypair_pem_roundtrip() {
        let keypair = KeyPair::generate();
        let pem = KeySerializer::keypair_to_pem(&keypair);
        let keypair2 = KeySerializer::keypair_from_pem(&pem).unwrap();

        assert_eq!(keypair.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_invalid_hex_length() {
        // Too short
        let result = KeySerializer::secret_key_from_hex("0123456789abcdef");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidKeyLength { .. }
        ));

        // Too long
        let long_hex = "0".repeat(80);
        let result = KeySerializer::secret_key_from_hex(&long_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_characters() {
        let invalid_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = KeySerializer::secret_key_from_hex(invalid_hex);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeySerdeError::InvalidHex(_)));
    }

    #[test]
    fn test_invalid_base64_characters() {
        let invalid_b64 = "!!!invalid-base64!!!";
        let result = KeySerializer::secret_key_from_base64(invalid_b64);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidBase64(_)
        ));
    }

    #[test]
    fn test_invalid_base64_length() {
        // Valid base64 but wrong length (16 bytes instead of 32)
        let short_b64 = base64_encode(&[0u8; 16]);
        let result = KeySerializer::secret_key_from_base64(&short_b64);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidKeyLength { .. }
        ));
    }

    #[test]
    fn test_invalid_pem_format_missing_header() {
        let pem = "-----END ED25519 PRIVATE KEY-----";
        let result = KeySerializer::secret_key_from_pem(pem);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidPemFormat
        ));
    }

    #[test]
    fn test_invalid_pem_format_missing_footer() {
        let pem = "-----BEGIN ED25519 PRIVATE KEY-----\nYWJjZGVm";
        let result = KeySerializer::secret_key_from_pem(pem);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidPemFormat
        ));
    }

    #[test]
    fn test_invalid_pem_format_wrong_header() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nYWJjZGVm\n-----END RSA PRIVATE KEY-----";
        let result = KeySerializer::secret_key_from_pem(pem);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidPemFormat
        ));
    }

    #[test]
    fn test_pem_with_extra_whitespace() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();

        let pem = KeySerializer::secret_key_to_pem(&secret);
        // Add extra whitespace
        let pem_with_spaces = format!("  {}  \n\n", pem);

        let secret2 = KeySerializer::secret_key_from_pem(&pem_with_spaces).unwrap();
        assert_eq!(secret, secret2);
    }

    #[test]
    fn test_hex_case_insensitive() {
        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();

        let hex_lower = KeySerializer::secret_key_to_hex(&secret);
        let hex_upper = hex_lower.to_uppercase();

        let secret_from_lower = KeySerializer::secret_key_from_hex(&hex_lower).unwrap();
        let secret_from_upper = KeySerializer::secret_key_from_hex(&hex_upper).unwrap();

        assert_eq!(secret, secret_from_lower);
        assert_eq!(secret, secret_from_upper);
    }

    #[test]
    fn test_public_key_hex_roundtrip() {
        let keypair = KeyPair::generate();
        let public = keypair.public_key();

        let hex = KeySerializer::public_key_to_hex(&public);
        let public2 = KeySerializer::public_key_from_hex(&hex).unwrap();

        assert_eq!(public, public2);
        // Hex should be 64 characters (32 bytes * 2)
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_public_key_invalid_hex_length() {
        let result = KeySerializer::public_key_from_hex("0123");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidKeyLength { .. }
        ));
    }

    #[test]
    fn test_public_key_pem_invalid_format() {
        let pem = "-----BEGIN ED25519 PRIVATE KEY-----\ndata\n-----END ED25519 PRIVATE KEY-----";
        let result = KeySerializer::public_key_from_pem(pem);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidPemFormat
        ));
    }

    #[test]
    fn test_base64_empty_string() {
        let result = KeySerializer::secret_key_from_base64("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeySerdeError::InvalidKeyLength { .. }
        ));
    }
}
