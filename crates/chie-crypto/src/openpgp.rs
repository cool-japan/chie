//! OpenPGP Key Format Compatibility
//!
//! This module provides basic OpenPGP (RFC 4880) key format support for Ed25519 keys.
//! Supports key import/export and basic packet handling.
//!
//! # Examples
//!
//! ```
//! use chie_crypto::openpgp::{OpenPgpPublicKey, OpenPgpSecretKey};
//! use chie_crypto::signing::KeyPair;
//!
//! // Generate a keypair
//! let keypair = KeyPair::generate();
//!
//! // Export as OpenPGP public key
//! let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "user@example.com");
//! let armored = pgp_pub.to_armored();
//!
//! // Export as OpenPGP secret key
//! let pgp_sec = OpenPgpSecretKey::from_ed25519(&keypair, "user@example.com");
//! let armored_sec = pgp_sec.to_armored();
//! ```

use crate::signing::{KeyPair, PublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// OpenPGP key format errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpenPgpError {
    /// Invalid packet format
    #[error("Invalid packet format: {0}")]
    InvalidPacket(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    /// Invalid armor format
    #[error("Invalid armor format: {0}")]
    InvalidArmor(String),

    /// Unsupported packet type
    #[error("Unsupported packet type: {0}")]
    UnsupportedPacketType(u8),

    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,
}

/// Result type for OpenPGP operations
pub type OpenPgpResult<T> = Result<T, OpenPgpError>;

// OpenPGP constants
const PGP_PUBLIC_KEY_HEADER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_PUBLIC_KEY_FOOTER: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const PGP_PRIVATE_KEY_HEADER: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PGP_PRIVATE_KEY_FOOTER: &str = "-----END PGP PRIVATE KEY BLOCK-----";

// Packet tags (old format)
const TAG_PUBLIC_KEY: u8 = 6; // Public-Key Packet
const TAG_USER_ID: u8 = 13; // User ID Packet
const TAG_SECRET_KEY: u8 = 5; // Secret-Key Packet

// Public key algorithm IDs
const ALGO_EDDSA: u8 = 22; // EdDSA (RFC 6637)

// EdDSA curve OID for Ed25519
const ED25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// OpenPGP public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPgpPublicKey {
    /// Creation timestamp
    pub created: u32,
    /// Public key material
    pub key_material: Vec<u8>,
    /// User ID
    pub user_id: String,
}

impl OpenPgpPublicKey {
    /// Create OpenPGP public key from Ed25519 public key
    pub fn from_ed25519(public_key: &PublicKey, user_id: impl Into<String>) -> Self {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Self {
            created,
            key_material: public_key.to_vec(),
            user_id: user_id.into(),
        }
    }

    /// Encode as binary packet format
    pub fn to_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Public key packet
        let mut key_packet = Vec::new();

        // Version (4)
        key_packet.push(4);

        // Creation time (4 bytes)
        key_packet.extend_from_slice(&self.created.to_be_bytes());

        // Algorithm (EdDSA)
        key_packet.push(ALGO_EDDSA);

        // OID length
        key_packet.push(ED25519_OID.len() as u8);

        // OID
        key_packet.extend_from_slice(ED25519_OID);

        // MPI of EdDSA point (0x40 prefix + 32 bytes)
        write_mpi(&mut key_packet, &self.key_material);

        // Add packet header
        add_packet_header(&mut packet, TAG_PUBLIC_KEY, &key_packet);

        // User ID packet
        let user_id_bytes = self.user_id.as_bytes();
        add_packet_header(&mut packet, TAG_USER_ID, user_id_bytes);

        packet
    }

    /// Encode as ASCII-armored format
    pub fn to_armored(&self) -> String {
        let packet = self.to_packet();
        let encoded = STANDARD.encode(&packet);

        // Calculate CRC24 checksum
        let crc = crc24(&packet);
        let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
        let crc_encoded = STANDARD.encode(crc_bytes);

        let mut result = String::new();
        result.push_str(PGP_PUBLIC_KEY_HEADER);
        result.push_str("\n\n");

        // Split into 64-character lines
        for chunk in encoded.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }

        result.push('=');
        result.push_str(&crc_encoded);
        result.push('\n');
        result.push_str(PGP_PUBLIC_KEY_FOOTER);
        result.push('\n');

        result
    }

    /// Get key fingerprint (SHA-256 hash of key packet)
    pub fn fingerprint(&self) -> [u8; 32] {
        let packet = self.to_packet();
        let mut hasher = Sha256::new();
        hasher.update(&packet);
        hasher.finalize().into()
    }
}

impl fmt::Display for OpenPgpPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_armored())
    }
}

/// OpenPGP secret key
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenPgpSecretKey {
    /// Creation timestamp
    pub created: u32,
    /// Public key material
    pub public_key: Vec<u8>,
    /// Secret key material (32 bytes for Ed25519)
    pub secret_key: Vec<u8>,
    /// User ID
    pub user_id: String,
}

impl OpenPgpSecretKey {
    /// Create OpenPGP secret key from Ed25519 keypair
    pub fn from_ed25519(keypair: &KeyPair, user_id: impl Into<String>) -> Self {
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        Self {
            created,
            public_key: keypair.public_key().to_vec(),
            secret_key: keypair.secret_key().to_vec(),
            user_id: user_id.into(),
        }
    }

    /// Encode as binary packet format
    pub fn to_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Secret key packet
        let mut key_packet = Vec::new();

        // Version (4)
        key_packet.push(4);

        // Creation time (4 bytes)
        key_packet.extend_from_slice(&self.created.to_be_bytes());

        // Algorithm (EdDSA)
        key_packet.push(ALGO_EDDSA);

        // OID length
        key_packet.push(ED25519_OID.len() as u8);

        // OID
        key_packet.extend_from_slice(ED25519_OID);

        // MPI of EdDSA point (public key)
        write_mpi(&mut key_packet, &self.public_key);

        // String-to-key usage (0 = unencrypted)
        key_packet.push(0);

        // MPI of EdDSA secret scalar
        write_mpi(&mut key_packet, &self.secret_key);

        // Checksum (simple sum of secret key bytes)
        let checksum: u16 = self.secret_key.iter().map(|&b| b as u16).sum();
        key_packet.extend_from_slice(&checksum.to_be_bytes());

        // Add packet header
        add_packet_header(&mut packet, TAG_SECRET_KEY, &key_packet);

        // User ID packet
        let user_id_bytes = self.user_id.as_bytes();
        add_packet_header(&mut packet, TAG_USER_ID, user_id_bytes);

        packet
    }

    /// Encode as ASCII-armored format
    pub fn to_armored(&self) -> String {
        let packet = self.to_packet();
        let encoded = STANDARD.encode(&packet);

        // Calculate CRC24 checksum
        let crc = crc24(&packet);
        let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
        let crc_encoded = STANDARD.encode(crc_bytes);

        let mut result = String::new();
        result.push_str(PGP_PRIVATE_KEY_HEADER);
        result.push_str("\n\n");

        // Split into 64-character lines
        for chunk in encoded.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }

        result.push('=');
        result.push_str(&crc_encoded);
        result.push('\n');
        result.push_str(PGP_PRIVATE_KEY_FOOTER);
        result.push('\n');

        result
    }

    /// Convert to Ed25519 keypair
    pub fn to_ed25519(&self) -> OpenPgpResult<KeyPair> {
        if self.secret_key.len() != 32 {
            return Err(OpenPgpError::InvalidLength {
                expected: 32,
                actual: self.secret_key.len(),
            });
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&self.secret_key);

        KeyPair::from_secret_key(&secret).map_err(|_| OpenPgpError::InvalidSecretKey)
    }

    /// Get corresponding public key
    pub fn public_key(&self) -> OpenPgpPublicKey {
        OpenPgpPublicKey {
            created: self.created,
            key_material: self.public_key.clone(),
            user_id: self.user_id.clone(),
        }
    }
}

// Helper functions

/// Add OpenPGP packet header (old format)
fn add_packet_header(buf: &mut Vec<u8>, tag: u8, body: &[u8]) {
    let len = body.len();

    if len < 256 {
        // Old format, one-octet length
        buf.push(0x80 | (tag << 2));
        buf.push(len as u8);
    } else if len < 65536 {
        // Old format, two-octet length
        buf.push(0x80 | (tag << 2) | 0x01);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        // Old format, four-octet length
        buf.push(0x80 | (tag << 2) | 0x02);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }

    buf.extend_from_slice(body);
}

/// Write MPI (multiprecision integer) for EdDSA
fn write_mpi(buf: &mut Vec<u8>, data: &[u8]) {
    // MPI bit count (for 32-byte Ed25519 key, this is 0x0100 = 256 bits, but we use 0x0107 = 263 bits to account for the 0x40 prefix)
    let bit_count = (data.len() * 8 + 7) as u16;
    buf.extend_from_slice(&bit_count.to_be_bytes());

    // EdDSA point is prefixed with 0x40
    buf.push(0x40);
    buf.extend_from_slice(data);
}

/// Calculate CRC24 checksum for OpenPGP
fn crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0xB704CE;
    const CRC24_POLY: u32 = 0x1864CFB;

    let mut crc = CRC24_INIT;

    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0xFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pgp_public_key_creation() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        assert_eq!(pgp_pub.key_material.len(), 32);
        assert_eq!(pgp_pub.user_id, "test@example.com");
    }

    #[test]
    fn test_pgp_public_key_packet() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        let packet = pgp_pub.to_packet();
        assert!(!packet.is_empty());

        // Should start with packet header
        assert_eq!(packet[0] & 0x80, 0x80); // Old format bit
    }

    #[test]
    fn test_pgp_public_key_armor() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        let armored = pgp_pub.to_armored();
        assert!(armored.contains(PGP_PUBLIC_KEY_HEADER));
        assert!(armored.contains(PGP_PUBLIC_KEY_FOOTER));
        assert!(armored.contains("=")); // CRC24 checksum line
    }

    #[test]
    fn test_pgp_secret_key_creation() {
        let keypair = KeyPair::generate();
        let pgp_sec = OpenPgpSecretKey::from_ed25519(&keypair, "test@example.com");

        assert_eq!(pgp_sec.public_key.len(), 32);
        assert_eq!(pgp_sec.secret_key.len(), 32);
        assert_eq!(pgp_sec.user_id, "test@example.com");
    }

    #[test]
    fn test_pgp_secret_key_armor() {
        let keypair = KeyPair::generate();
        let pgp_sec = OpenPgpSecretKey::from_ed25519(&keypair, "test@example.com");

        let armored = pgp_sec.to_armored();
        assert!(armored.contains(PGP_PRIVATE_KEY_HEADER));
        assert!(armored.contains(PGP_PRIVATE_KEY_FOOTER));
    }

    #[test]
    fn test_pgp_secret_to_keypair() {
        let keypair = KeyPair::generate();
        let pgp_sec = OpenPgpSecretKey::from_ed25519(&keypair, "test@example.com");

        let recovered = pgp_sec.to_ed25519().unwrap();
        assert_eq!(recovered.public_key(), keypair.public_key());
        assert_eq!(recovered.secret_key(), keypair.secret_key());
    }

    #[test]
    fn test_pgp_public_from_secret() {
        let keypair = KeyPair::generate();
        let pgp_sec = OpenPgpSecretKey::from_ed25519(&keypair, "test@example.com");
        let pgp_pub = pgp_sec.public_key();

        assert_eq!(pgp_pub.key_material, pgp_sec.public_key);
        assert_eq!(pgp_pub.user_id, pgp_sec.user_id);
    }

    #[test]
    fn test_fingerprint() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        let fp1 = pgp_pub.fingerprint();
        let fp2 = pgp_pub.fingerprint();

        // Fingerprint should be deterministic
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 32);
    }

    #[test]
    fn test_crc24() {
        let data = b"hello";
        let crc = crc24(data);

        // CRC24 should be 24 bits
        assert!(crc < 0x1000000);

        // CRC should be deterministic
        assert_eq!(crc, crc24(data));
    }

    #[test]
    fn test_armor_line_length() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        let armored = pgp_pub.to_armored();

        // Check line lengths (should be <= 64 chars for data lines)
        for line in armored.lines() {
            if !line.contains("BEGIN") && !line.contains("END") && !line.starts_with('=') {
                assert!(line.len() <= 64, "Line too long: {}", line.len());
            }
        }
    }

    #[test]
    fn test_mpi_encoding() {
        let mut buf = Vec::new();
        let data = &[0x12, 0x34, 0x56, 0x78];

        write_mpi(&mut buf, data);

        // Should have bit count (2 bytes) + 0x40 prefix + data
        assert_eq!(buf.len(), 2 + 1 + data.len());
        assert_eq!(buf[2], 0x40); // EdDSA prefix
    }

    #[test]
    fn test_packet_header() {
        let mut buf = Vec::new();
        let body = b"test";

        add_packet_header(&mut buf, TAG_USER_ID, body);

        // Old format bit should be set
        assert_eq!(buf[0] & 0x80, 0x80);

        // Tag should be encoded
        assert_eq!((buf[0] >> 2) & 0x0F, TAG_USER_ID);
    }

    #[test]
    fn test_serialization() {
        let keypair = KeyPair::generate();
        let pgp_pub = OpenPgpPublicKey::from_ed25519(&keypair.public_key(), "test@example.com");

        let serialized = crate::codec::encode(&pgp_pub).unwrap();
        let deserialized: OpenPgpPublicKey = crate::codec::decode(&serialized).unwrap();

        assert_eq!(deserialized.key_material, pgp_pub.key_material);
        assert_eq!(deserialized.user_id, pgp_pub.user_id);
    }
}
