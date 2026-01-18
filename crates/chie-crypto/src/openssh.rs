//! OpenSSH Key Format Support
//!
//! This module provides functionality to import and export Ed25519 keys in OpenSSH formats.
//! Supports both public key format (ssh-ed25519) and private key format (OpenSSH private key).
//!
//! # Examples
//!
//! ```
//! use chie_crypto::openssh::{SshPublicKey, SshPrivateKey};
//! use chie_crypto::signing::KeyPair;
//!
//! // Generate a keypair
//! let keypair = KeyPair::generate();
//!
//! // Export as SSH public key
//! let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());
//! let ssh_pub_str = ssh_pub.to_string_with_comment("user@host");
//!
//! // Parse SSH public key
//! let parsed = SshPublicKey::parse(&ssh_pub_str).unwrap();
//! assert_eq!(parsed.key_data, ssh_pub.key_data);
//!
//! // Export as SSH private key
//! let ssh_priv = SshPrivateKey::from_ed25519(&keypair);
//! let pem = ssh_priv.to_pem();
//! ```

use crate::signing::{KeyPair, PublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// SSH key format errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SshKeyError {
    /// Invalid SSH key format
    #[error("Invalid SSH key format: {0}")]
    InvalidFormat(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    /// Unexpected end of data
    #[error("Unexpected end of data")]
    UnexpectedEof,

    /// UTF-8 decode error
    #[error("UTF-8 decode error: {0}")]
    Utf8Error(String),

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,
}

/// Result type for SSH key operations
pub type SshKeyResult<T> = Result<T, SshKeyError>;

const SSH_ED25519_KEY_TYPE: &str = "ssh-ed25519";
const OPENSSH_PRIVATE_KEY_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_PRIVATE_KEY_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";
const OPENSSH_AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// SSH public key in OpenSSH format
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshPublicKey {
    /// Algorithm identifier (e.g., "ssh-ed25519")
    pub algorithm: String,
    /// Raw key data (32 bytes for Ed25519)
    pub key_data: Vec<u8>,
    /// Optional comment
    pub comment: Option<String>,
}

impl SshPublicKey {
    /// Create SSH public key from Ed25519 public key
    pub fn from_ed25519(public_key: &PublicKey) -> Self {
        Self {
            algorithm: SSH_ED25519_KEY_TYPE.to_string(),
            key_data: public_key.to_vec(),
            comment: None,
        }
    }

    /// Set comment for the SSH key
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Convert to OpenSSH public key format
    ///
    /// Format: `ssh-ed25519 <base64-encoded-key> [optional-comment]`
    pub fn to_openssh_format(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write algorithm length and data
        write_string(&mut buf, &self.algorithm);

        // Write key data length and data
        write_bytes(&mut buf, &self.key_data);

        buf
    }

    /// Encode as OpenSSH public key string
    pub fn to_string_with_comment(&self, comment: &str) -> String {
        let encoded = STANDARD.encode(self.to_openssh_format());
        format!("{} {} {}", self.algorithm, encoded, comment)
    }

    /// Encode as OpenSSH public key string without comment
    pub fn to_string_no_comment(&self) -> String {
        let encoded = STANDARD.encode(self.to_openssh_format());
        format!("{} {}", self.algorithm, encoded)
    }

    /// Parse OpenSSH public key from string
    ///
    /// Format: `ssh-ed25519 <base64-encoded-key> [optional-comment]`
    pub fn parse(s: &str) -> SshKeyResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(SshKeyError::InvalidFormat(
                "Invalid SSH public key format".to_string(),
            ));
        }

        let algorithm = parts[0].to_string();
        let encoded = parts[1];
        let comment = if parts.len() > 2 {
            Some(parts[2..].join(" "))
        } else {
            None
        };

        // Decode base64
        let data = STANDARD
            .decode(encoded)
            .map_err(|e| SshKeyError::Base64Error(e.to_string()))?;

        // Parse the binary format
        let mut offset = 0;
        let parsed_algo = read_string(&data, &mut offset)?;

        if parsed_algo != algorithm {
            return Err(SshKeyError::InvalidFormat(format!(
                "Algorithm mismatch: {} vs {}",
                parsed_algo, algorithm
            )));
        }

        let key_data = read_bytes(&data, &mut offset)?;

        if algorithm == SSH_ED25519_KEY_TYPE && key_data.len() != 32 {
            return Err(SshKeyError::InvalidLength {
                expected: 32,
                actual: key_data.len(),
            });
        }

        Ok(Self {
            algorithm,
            key_data,
            comment,
        })
    }

    /// Convert to Ed25519 public key
    pub fn to_ed25519(&self) -> SshKeyResult<PublicKey> {
        if self.algorithm != SSH_ED25519_KEY_TYPE {
            return Err(SshKeyError::UnsupportedAlgorithm(self.algorithm.clone()));
        }

        if self.key_data.len() != 32 {
            return Err(SshKeyError::InvalidLength {
                expected: 32,
                actual: self.key_data.len(),
            });
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.key_data);
        Ok(bytes)
    }
}

impl fmt::Display for SshPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(comment) = &self.comment {
            write!(f, "{}", self.to_string_with_comment(comment))
        } else {
            write!(f, "{}", self.to_string_no_comment())
        }
    }
}

/// SSH private key in OpenSSH format
#[derive(Clone, Serialize, Deserialize)]
pub struct SshPrivateKey {
    /// Public key data
    pub public_key: Vec<u8>,
    /// Private key data (64 bytes for Ed25519: 32 bytes seed + 32 bytes public)
    pub private_key: Vec<u8>,
    /// Optional comment
    pub comment: Option<String>,
}

impl SshPrivateKey {
    /// Create SSH private key from Ed25519 keypair
    pub fn from_ed25519(keypair: &KeyPair) -> Self {
        // OpenSSH format stores 64 bytes: 32-byte seed + 32-byte public key
        let secret = keypair.secret_key();
        let public = keypair.public_key();
        let mut private_key = Vec::with_capacity(64);
        private_key.extend_from_slice(&secret);
        private_key.extend_from_slice(&public);

        Self {
            public_key: public.to_vec(),
            private_key,
            comment: None,
        }
    }

    /// Set comment for the SSH key
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Convert to OpenSSH private key format (binary)
    pub fn to_openssh_format(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic header
        buf.extend_from_slice(OPENSSH_AUTH_MAGIC);

        // Cipher name (none - unencrypted)
        write_string(&mut buf, "none");

        // KDF name (none)
        write_string(&mut buf, "none");

        // KDF options (empty)
        write_string(&mut buf, "");

        // Number of keys (1)
        buf.extend_from_slice(&1u32.to_be_bytes());

        // Public key section
        let mut public_section = Vec::new();
        write_string(&mut public_section, SSH_ED25519_KEY_TYPE);
        write_bytes(&mut public_section, &self.public_key);
        write_bytes(&mut buf, &public_section);

        // Private key section
        let mut private_section = Vec::new();

        // Check integers (for encryption detection, both should be same)
        let check = rand::random::<u32>();
        private_section.extend_from_slice(&check.to_be_bytes());
        private_section.extend_from_slice(&check.to_be_bytes());

        // Algorithm
        write_string(&mut private_section, SSH_ED25519_KEY_TYPE);

        // Public key
        write_bytes(&mut private_section, &self.public_key);

        // Private key (Ed25519: 64 bytes)
        write_bytes(&mut private_section, &self.private_key);

        // Comment
        write_string(&mut private_section, self.comment.as_deref().unwrap_or(""));

        // Padding to block size (8 bytes)
        let padding_len = 8 - (private_section.len() % 8);
        for i in 1..=padding_len {
            private_section.push(i as u8);
        }

        write_bytes(&mut buf, &private_section);

        buf
    }

    /// Encode as PEM format
    pub fn to_pem(&self) -> String {
        let data = self.to_openssh_format();
        let encoded = STANDARD.encode(&data);

        // Split into 70-character lines
        let mut result = String::new();
        result.push_str(OPENSSH_PRIVATE_KEY_HEADER);
        result.push('\n');

        for chunk in encoded.as_bytes().chunks(70) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }

        result.push_str(OPENSSH_PRIVATE_KEY_FOOTER);
        result.push('\n');

        result
    }

    /// Parse OpenSSH private key from PEM format
    pub fn from_pem(pem: &str) -> SshKeyResult<Self> {
        // Remove headers and whitespace
        let pem = pem
            .lines()
            .filter(|line| {
                !line.contains("BEGIN OPENSSH PRIVATE KEY")
                    && !line.contains("END OPENSSH PRIVATE KEY")
            })
            .collect::<String>();

        let data = STANDARD
            .decode(pem.trim())
            .map_err(|e| SshKeyError::Base64Error(e.to_string()))?;

        Self::parse_binary(&data)
    }

    /// Parse binary OpenSSH private key format
    pub fn parse_binary(data: &[u8]) -> SshKeyResult<Self> {
        let mut offset = 0;

        // Check magic
        if data.len() < OPENSSH_AUTH_MAGIC.len()
            || &data[..OPENSSH_AUTH_MAGIC.len()] != OPENSSH_AUTH_MAGIC
        {
            return Err(SshKeyError::InvalidFormat(
                "Invalid OpenSSH private key magic".to_string(),
            ));
        }
        offset += OPENSSH_AUTH_MAGIC.len();

        // Read cipher (should be "none" for unencrypted)
        let cipher = read_string(data, &mut offset)?;
        if cipher != "none" {
            return Err(SshKeyError::InvalidFormat(
                "Encrypted SSH keys not supported yet".to_string(),
            ));
        }

        // Read KDF (should be "none")
        let _kdf = read_string(data, &mut offset)?;

        // Read KDF options (should be empty)
        let _kdf_options = read_bytes(data, &mut offset)?;

        // Read number of keys
        let num_keys = read_u32(data, &mut offset)?;
        if num_keys != 1 {
            return Err(SshKeyError::InvalidFormat(format!(
                "Expected 1 key, found {}",
                num_keys
            )));
        }

        // Read public key section
        let _public_section = read_bytes(data, &mut offset)?;

        // Read private key section
        let private_section = read_bytes(data, &mut offset)?;
        let mut priv_offset = 0;

        // Check integers
        let check1 = read_u32(&private_section, &mut priv_offset)?;
        let check2 = read_u32(&private_section, &mut priv_offset)?;
        if check1 != check2 {
            return Err(SshKeyError::InvalidFormat(
                "Checksum mismatch (possibly encrypted)".to_string(),
            ));
        }

        // Read algorithm
        let algorithm = read_string(&private_section, &mut priv_offset)?;
        if algorithm != SSH_ED25519_KEY_TYPE {
            return Err(SshKeyError::UnsupportedAlgorithm(algorithm));
        }

        // Read public key
        let public_key = read_bytes(&private_section, &mut priv_offset)?;

        // Read private key
        let private_key = read_bytes(&private_section, &mut priv_offset)?;

        // Read comment
        let comment = read_string(&private_section, &mut priv_offset)?;
        let comment = if comment.is_empty() {
            None
        } else {
            Some(comment)
        };

        Ok(Self {
            public_key,
            private_key,
            comment,
        })
    }

    /// Convert to Ed25519 keypair
    pub fn to_ed25519(&self) -> SshKeyResult<KeyPair> {
        if self.private_key.len() != 64 {
            return Err(SshKeyError::InvalidLength {
                expected: 64,
                actual: self.private_key.len(),
            });
        }

        // Extract the first 32 bytes (the seed/secret key)
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&self.private_key[..32]);

        KeyPair::from_secret_key(&secret).map_err(|_| SshKeyError::InvalidSecretKey)
    }
}

// Helper functions for SSH binary format

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_u32(data: &[u8], offset: &mut usize) -> SshKeyResult<u32> {
    if *offset + 4 > data.len() {
        return Err(SshKeyError::UnexpectedEof);
    }

    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[*offset..*offset + 4]);
    *offset += 4;

    Ok(u32::from_be_bytes(bytes))
}

fn read_string(data: &[u8], offset: &mut usize) -> SshKeyResult<String> {
    let bytes = read_bytes(data, offset)?;
    String::from_utf8(bytes).map_err(|e| SshKeyError::Utf8Error(e.to_string()))
}

fn read_bytes(data: &[u8], offset: &mut usize) -> SshKeyResult<Vec<u8>> {
    let len = read_u32(data, offset)? as usize;

    if *offset + len > data.len() {
        return Err(SshKeyError::UnexpectedEof);
    }

    let bytes = data[*offset..*offset + len].to_vec();
    *offset += len;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_public_key_roundtrip() {
        let keypair = KeyPair::generate();
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());

        let formatted = ssh_pub.to_string_with_comment("test@host");
        let parsed = SshPublicKey::parse(&formatted).unwrap();

        assert_eq!(parsed.algorithm, SSH_ED25519_KEY_TYPE);
        assert_eq!(parsed.key_data, ssh_pub.key_data);
        assert_eq!(parsed.comment, Some("test@host".to_string()));
    }

    #[test]
    fn test_ssh_public_key_no_comment() {
        let keypair = KeyPair::generate();
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());

        let formatted = ssh_pub.to_string_no_comment();
        let parsed = SshPublicKey::parse(&formatted).unwrap();

        assert_eq!(parsed.key_data, ssh_pub.key_data);
        assert_eq!(parsed.comment, None);
    }

    #[test]
    fn test_ssh_public_key_to_ed25519() {
        let keypair = KeyPair::generate();
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());

        let ed25519_pub = ssh_pub.to_ed25519().unwrap();
        assert_eq!(&ed25519_pub, &keypair.public_key());
    }

    #[test]
    fn test_ssh_private_key_pem_roundtrip() {
        let keypair = KeyPair::generate();
        let ssh_priv = SshPrivateKey::from_ed25519(&keypair).with_comment("test@host");

        let pem = ssh_priv.to_pem();
        assert!(pem.contains(OPENSSH_PRIVATE_KEY_HEADER));
        assert!(pem.contains(OPENSSH_PRIVATE_KEY_FOOTER));

        let parsed = SshPrivateKey::from_pem(&pem).unwrap();
        assert_eq!(parsed.public_key, ssh_priv.public_key);
        assert_eq!(parsed.private_key, ssh_priv.private_key);
        assert_eq!(parsed.comment, ssh_priv.comment);
    }

    #[test]
    fn test_ssh_private_key_to_ed25519() {
        let keypair = KeyPair::generate();
        let ssh_priv = SshPrivateKey::from_ed25519(&keypair);

        let recovered = ssh_priv.to_ed25519().unwrap();
        assert_eq!(&recovered.public_key(), &keypair.public_key());
        assert_eq!(recovered.secret_key(), keypair.secret_key());
    }

    #[test]
    fn test_ssh_keys_compatibility() {
        let keypair = KeyPair::generate();

        // Export both public and private
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());
        let ssh_priv = SshPrivateKey::from_ed25519(&keypair);

        // Ensure public keys match
        assert_eq!(ssh_pub.key_data, ssh_priv.public_key);

        // Recover keypair from private key
        let recovered = ssh_priv.to_ed25519().unwrap();
        assert_eq!(&recovered.public_key(), &keypair.public_key());
    }

    #[test]
    fn test_invalid_ssh_public_key() {
        assert!(SshPublicKey::parse("invalid").is_err());
        assert!(SshPublicKey::parse("ssh-ed25519").is_err());
        assert!(SshPublicKey::parse("ssh-ed25519 !!!invalid-base64!!!").is_err());
    }

    #[test]
    fn test_ssh_public_key_with_multiword_comment() {
        let keypair = KeyPair::generate();
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key());

        let formatted = ssh_pub.to_string_with_comment("user@host with spaces");
        let parsed = SshPublicKey::parse(&formatted).unwrap();

        assert_eq!(parsed.comment, Some("user@host with spaces".to_string()));
    }

    #[test]
    fn test_openssh_format_structure() {
        let keypair = KeyPair::generate();
        let ssh_priv = SshPrivateKey::from_ed25519(&keypair);

        let binary = ssh_priv.to_openssh_format();

        // Check magic
        assert_eq!(&binary[..OPENSSH_AUTH_MAGIC.len()], OPENSSH_AUTH_MAGIC);
    }

    #[test]
    fn test_write_read_string() {
        let mut buf = Vec::new();
        write_string(&mut buf, "test");

        let mut offset = 0;
        let s = read_string(&buf, &mut offset).unwrap();
        assert_eq!(s, "test");
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_write_read_bytes() {
        let mut buf = Vec::new();
        let data = vec![1, 2, 3, 4, 5];
        write_bytes(&mut buf, &data);

        let mut offset = 0;
        let read = read_bytes(&buf, &mut offset).unwrap();
        assert_eq!(read, data);
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_pem_line_wrapping() {
        let keypair = KeyPair::generate();
        let ssh_priv = SshPrivateKey::from_ed25519(&keypair);
        let pem = ssh_priv.to_pem();

        // Check that lines are wrapped (no line should be > 71 chars including newline)
        for line in pem.lines() {
            if !line.contains("BEGIN") && !line.contains("END") {
                assert!(line.len() <= 70, "Line too long: {}", line.len());
            }
        }
    }

    #[test]
    fn test_serialization() {
        let keypair = KeyPair::generate();
        let ssh_pub = SshPublicKey::from_ed25519(&keypair.public_key()).with_comment("test@host");

        let serialized = crate::codec::encode(&ssh_pub).unwrap();
        let deserialized: SshPublicKey = crate::codec::decode(&serialized).unwrap();

        assert_eq!(deserialized.algorithm, ssh_pub.algorithm);
        assert_eq!(deserialized.key_data, ssh_pub.key_data);
        assert_eq!(deserialized.comment, ssh_pub.comment);
    }
}
