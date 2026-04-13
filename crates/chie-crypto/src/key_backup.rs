//! Key backup and recovery mechanisms for secure key management.
//!
//! This module provides secure backup and recovery of cryptographic keys using
//! Shamir's Secret Sharing for threshold-based recovery and encrypted backup files.
//!
//! # Features
//!
//! - **Shamir Secret Sharing Backup**: Split keys into N shares requiring M to recover
//! - **Encrypted Backup**: Password-based encryption for backup files
//! - **Multiple Key Types**: Support for signing keys, encryption keys, and generic secrets
//! - **Versioning**: Track backup versions for key rotation
//! - **Metadata**: Include timestamps, labels, and key types in backups
//!
//! # Example
//!
//! ```
//! use chie_crypto::key_backup::*;
//! use chie_crypto::signing::KeyPair;
//!
//! // Create a signing key
//! let keypair = KeyPair::generate();
//!
//! // Create a backup with 3-of-5 threshold
//! let backup_config = BackupConfig::new(3, 5)
//!     .with_label("my-signing-key")
//!     .with_description("Main signing key for node");
//!
//! let shares = backup_key_shamir(&keypair, &backup_config).unwrap();
//!
//! // Distribute shares to different locations/devices
//! // Later, recover with any 3 shares
//! let recovered_keypair = recover_key_shamir(&shares[0..3]).unwrap();
//!
//! // Verify recovery
//! assert_eq!(keypair.public_key(), recovered_keypair.public_key());
//! ```

use crate::encryption::{decrypt, encrypt, generate_nonce};
use crate::hash::hash;
use crate::kdf::hkdf_extract_expand;
use crate::shamir::{Share, reconstruct, split};
use crate::signing::KeyPair;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can occur during backup and recovery
#[derive(Debug)]
pub enum BackupError {
    /// Invalid threshold configuration
    InvalidThreshold(String),
    /// Insufficient shares for recovery
    InsufficientShares(String),
    /// Share corruption or tampering detected
    InvalidShare(String),
    /// Encryption/decryption error
    CryptoError(String),
    /// Serialization error
    SerializationError(String),
    /// Invalid password
    InvalidPassword,
    /// Version mismatch
    VersionMismatch(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::InvalidThreshold(msg) => write!(f, "Invalid threshold: {}", msg),
            BackupError::InsufficientShares(msg) => write!(f, "Insufficient shares: {}", msg),
            BackupError::InvalidShare(msg) => write!(f, "Invalid share: {}", msg),
            BackupError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            BackupError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            BackupError::InvalidPassword => write!(f, "Invalid password"),
            BackupError::VersionMismatch(msg) => write!(f, "Version mismatch: {}", msg),
        }
    }
}

impl std::error::Error for BackupError {}

pub type BackupResult<T> = Result<T, BackupError>;

/// Type of key being backed up
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 signing key
    SigningKey,
    /// ChaCha20-Poly1305 encryption key
    EncryptionKey,
    /// Generic secret data
    GenericSecret,
}

/// Configuration for key backup
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Threshold: number of shares required for recovery
    pub threshold: usize,
    /// Total number of shares to generate
    pub total_shares: usize,
    /// Optional label for the backup
    pub label: Option<String>,
    /// Optional description
    pub description: Option<String>,
    /// Key type
    pub key_type: KeyType,
    /// Backup version (for key rotation tracking)
    pub version: u32,
}

impl BackupConfig {
    /// Create a new backup configuration
    pub fn new(threshold: usize, total_shares: usize) -> Self {
        Self {
            threshold,
            total_shares,
            label: None,
            description: None,
            key_type: KeyType::GenericSecret,
            version: 1,
        }
    }

    /// Set the label for this backup
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    /// Set the description for this backup
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set the key type
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the version
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> BackupResult<()> {
        if self.threshold == 0 {
            return Err(BackupError::InvalidThreshold(
                "Threshold must be at least 1".to_string(),
            ));
        }
        if self.threshold > self.total_shares {
            return Err(BackupError::InvalidThreshold(format!(
                "Threshold ({}) cannot exceed total shares ({})",
                self.threshold, self.total_shares
            )));
        }
        if self.total_shares > 255 {
            return Err(BackupError::InvalidThreshold(
                "Total shares cannot exceed 255".to_string(),
            ));
        }
        Ok(())
    }
}

/// A single backup share with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupShare {
    /// Share index (1-based)
    pub index: u8,
    /// The actual share data (from Shamir's secret sharing)
    pub share_data: Vec<u8>,
    /// Configuration metadata
    pub config: BackupConfig,
    /// Creation timestamp
    pub created_at: u64,
    /// Checksum for integrity verification
    pub checksum: [u8; 32],
}

impl BackupShare {
    /// Create a new backup share
    fn new(index: u8, share: Share, config: BackupConfig) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let share_data = share.data.clone();

        let mut data = Vec::new();
        data.push(index);
        data.push(share.index);
        data.extend_from_slice(&share_data);
        data.extend_from_slice(&timestamp.to_le_bytes());

        let checksum = hash(&data);

        Self {
            index,
            share_data,
            config,
            created_at: timestamp,
            checksum,
        }
    }

    /// Verify the integrity of this share
    pub fn verify_integrity(&self) -> bool {
        let mut data = Vec::new();
        data.push(self.index);
        data.push(self.index); // Share index matches backup index
        data.extend_from_slice(&self.share_data);
        data.extend_from_slice(&self.created_at.to_le_bytes());

        let expected_checksum = hash(&data);
        expected_checksum == self.checksum
    }

    /// Convert to Shamir Share for recovery
    fn to_share(&self) -> BackupResult<Share> {
        Share::new(self.index, self.share_data.clone())
            .map_err(|e| BackupError::InvalidShare(e.to_string()))
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> BackupResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BackupError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> BackupResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BackupError::SerializationError(e.to_string()))
    }
}

/// Encrypted backup file containing a key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBackup {
    /// Encrypted key data
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption (12 bytes)
    pub nonce: [u8; 12],
    /// Salt for password derivation
    pub salt: [u8; 32],
    /// Configuration metadata
    pub config: BackupConfig,
    /// Creation timestamp
    pub created_at: u64,
}

impl EncryptedBackup {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> BackupResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BackupError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> BackupResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BackupError::SerializationError(e.to_string()))
    }
}

/// Backup a key using Shamir's Secret Sharing
pub fn backup_key_shamir(
    keypair: &KeyPair,
    config: &BackupConfig,
) -> BackupResult<Vec<BackupShare>> {
    config.validate()?;

    // Extract secret key bytes
    let secret = keypair.secret_key();

    // Split into shares
    let shares = split(&secret, config.threshold, config.total_shares)
        .map_err(|e| BackupError::CryptoError(e.to_string()))?;

    // Create backup shares with metadata
    let backup_shares: Vec<BackupShare> = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| BackupShare::new((i + 1) as u8, share, config.clone()))
        .collect();

    Ok(backup_shares)
}

/// Recover a key from Shamir shares
pub fn recover_key_shamir(shares: &[BackupShare]) -> BackupResult<KeyPair> {
    if shares.is_empty() {
        return Err(BackupError::InsufficientShares(
            "No shares provided".to_string(),
        ));
    }

    // Verify all shares have compatible configuration
    let config = &shares[0].config;
    if shares.len() < config.threshold {
        return Err(BackupError::InsufficientShares(format!(
            "Need {} shares but only {} provided",
            config.threshold,
            shares.len()
        )));
    }

    // Verify integrity of all shares
    for share in shares {
        if !share.verify_integrity() {
            return Err(BackupError::InvalidShare(format!(
                "Share {} failed integrity check",
                share.index
            )));
        }

        // Verify compatible configuration
        if share.config.threshold != config.threshold {
            return Err(BackupError::InvalidShare(
                "Incompatible share thresholds".to_string(),
            ));
        }
    }

    // Extract Share objects
    let raw_shares: Vec<Share> = shares
        .iter()
        .map(|bs| bs.to_share())
        .collect::<Result<Vec<_>, _>>()?;

    // Combine shares to recover secret
    let secret = reconstruct(&raw_shares).map_err(|e| BackupError::CryptoError(e.to_string()))?;

    // Reconstruct keypair from secret bytes
    if secret.len() != 32 {
        return Err(BackupError::CryptoError(
            "Invalid secret length".to_string(),
        ));
    }
    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret);
    KeyPair::from_secret_key(&secret_array).map_err(|e| BackupError::CryptoError(e.to_string()))
}

/// Backup a generic secret using Shamir's Secret Sharing
pub fn backup_secret_shamir(
    secret: &[u8],
    config: &BackupConfig,
) -> BackupResult<Vec<BackupShare>> {
    config.validate()?;

    // Split into shares
    let shares = split(secret, config.threshold, config.total_shares)
        .map_err(|e| BackupError::CryptoError(e.to_string()))?;

    // Create backup shares with metadata
    let backup_shares: Vec<BackupShare> = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| BackupShare::new((i + 1) as u8, share, config.clone()))
        .collect();

    Ok(backup_shares)
}

/// Recover a generic secret from Shamir shares
pub fn recover_secret_shamir(shares: &[BackupShare]) -> BackupResult<Vec<u8>> {
    if shares.is_empty() {
        return Err(BackupError::InsufficientShares(
            "No shares provided".to_string(),
        ));
    }

    // Verify all shares have compatible configuration
    let config = &shares[0].config;
    if shares.len() < config.threshold {
        return Err(BackupError::InsufficientShares(format!(
            "Need {} shares but only {} provided",
            config.threshold,
            shares.len()
        )));
    }

    // Verify integrity of all shares
    for share in shares {
        if !share.verify_integrity() {
            return Err(BackupError::InvalidShare(format!(
                "Share {} failed integrity check",
                share.index
            )));
        }
    }

    // Extract Share objects
    let raw_shares: Vec<Share> = shares
        .iter()
        .map(|bs| bs.to_share())
        .collect::<Result<Vec<_>, _>>()?;

    // Combine shares to recover secret
    reconstruct(&raw_shares).map_err(|e| BackupError::CryptoError(e.to_string()))
}

/// Create an encrypted backup of a key using password-based encryption
pub fn backup_key_encrypted(
    keypair: &KeyPair,
    password: &str,
    config: &BackupConfig,
) -> BackupResult<EncryptedBackup> {
    config.validate()?;

    // Generate random salt
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);

    // Derive encryption key from password
    let key_bytes = hkdf_extract_expand(password.as_bytes(), &salt, b"chie-backup-encryption-v1");

    // Extract secret key bytes
    let secret = keypair.secret_key();

    // Generate nonce
    let nonce = generate_nonce();

    // Encrypt the secret
    let ciphertext = encrypt(&secret, &key_bytes, &nonce)
        .map_err(|e| BackupError::CryptoError(e.to_string()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Convert nonce to array
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

    Ok(EncryptedBackup {
        ciphertext,
        nonce: nonce_bytes,
        salt,
        config: config.clone(),
        created_at: timestamp,
    })
}

/// Recover a key from an encrypted backup
pub fn recover_key_encrypted(backup: &EncryptedBackup, password: &str) -> BackupResult<KeyPair> {
    // Derive decryption key from password
    let key_bytes = hkdf_extract_expand(
        password.as_bytes(),
        &backup.salt,
        b"chie-backup-encryption-v1",
    );

    // Convert nonce bytes to Nonce
    let nonce = &backup.nonce;

    // Decrypt the secret
    let secret =
        decrypt(&backup.ciphertext, &key_bytes, nonce).map_err(|_| BackupError::InvalidPassword)?;

    // Reconstruct keypair from secret bytes
    if secret.len() != 32 {
        return Err(BackupError::CryptoError(
            "Invalid secret length".to_string(),
        ));
    }
    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret);
    KeyPair::from_secret_key(&secret_array).map_err(|e| BackupError::CryptoError(e.to_string()))
}

/// Create an encrypted backup of a generic secret
pub fn backup_secret_encrypted(
    secret: &[u8],
    password: &str,
    config: &BackupConfig,
) -> BackupResult<EncryptedBackup> {
    config.validate()?;

    // Generate random salt
    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);

    // Derive encryption key from password
    let key_bytes = hkdf_extract_expand(password.as_bytes(), &salt, b"chie-backup-encryption-v1");

    // Generate nonce
    let nonce = generate_nonce();

    // Encrypt the secret
    let ciphertext =
        encrypt(secret, &key_bytes, &nonce).map_err(|e| BackupError::CryptoError(e.to_string()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Convert nonce to array
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

    Ok(EncryptedBackup {
        ciphertext,
        nonce: nonce_bytes,
        salt,
        config: config.clone(),
        created_at: timestamp,
    })
}

/// Recover a generic secret from an encrypted backup
pub fn recover_secret_encrypted(backup: &EncryptedBackup, password: &str) -> BackupResult<Vec<u8>> {
    // Derive decryption key from password
    let key_bytes = hkdf_extract_expand(
        password.as_bytes(),
        &backup.salt,
        b"chie-backup-encryption-v1",
    );

    // Convert nonce bytes to Nonce
    let nonce = &backup.nonce;

    // Decrypt the secret
    decrypt(&backup.ciphertext, &key_bytes, nonce).map_err(|_| BackupError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_backup_recovery() {
        let keypair = KeyPair::generate();
        let config = BackupConfig::new(3, 5).with_label("test-key");

        // Create backup shares
        let shares = backup_key_shamir(&keypair, &config).unwrap();
        assert_eq!(shares.len(), 5);

        // Verify all shares have correct metadata
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.index, (i + 1) as u8);
            assert!(share.verify_integrity());
        }

        // Recover with exactly threshold shares
        let recovered = recover_key_shamir(&shares[0..3]).unwrap();
        assert_eq!(keypair.public_key(), recovered.public_key());

        // Recover with more than threshold shares
        let recovered = recover_key_shamir(&shares[1..5]).unwrap();
        assert_eq!(keypair.public_key(), recovered.public_key());
    }

    #[test]
    fn test_shamir_insufficient_shares() {
        let keypair = KeyPair::generate();
        let config = BackupConfig::new(3, 5);
        let shares = backup_key_shamir(&keypair, &config).unwrap();

        // Try to recover with only 2 shares (need 3)
        let result = recover_key_shamir(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_backup_recovery() {
        let keypair = KeyPair::generate();
        let password = "secure_password_123";
        let config = BackupConfig::new(1, 1).with_key_type(KeyType::SigningKey);

        // Create encrypted backup
        let backup = backup_key_encrypted(&keypair, password, &config).unwrap();

        // Recover with correct password
        let recovered = recover_key_encrypted(&backup, password).unwrap();
        assert_eq!(keypair.public_key(), recovered.public_key());
    }

    #[test]
    fn test_encrypted_backup_wrong_password() {
        let keypair = KeyPair::generate();
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let config = BackupConfig::new(1, 1);

        let backup = backup_key_encrypted(&keypair, password, &config).unwrap();

        // Try to recover with wrong password
        let result = recover_key_encrypted(&backup, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_backup_share_serialization() {
        let keypair = KeyPair::generate();
        let config = BackupConfig::new(2, 3);
        let shares = backup_key_shamir(&keypair, &config).unwrap();

        // Serialize and deserialize first share
        let bytes = shares[0].to_bytes().unwrap();
        let recovered_share = BackupShare::from_bytes(&bytes).unwrap();

        assert_eq!(shares[0].index, recovered_share.index);
        assert!(recovered_share.verify_integrity());
    }

    #[test]
    fn test_encrypted_backup_serialization() {
        let keypair = KeyPair::generate();
        let password = "test_password";
        let config = BackupConfig::new(1, 1);

        let backup = backup_key_encrypted(&keypair, password, &config).unwrap();

        // Serialize and deserialize
        let bytes = backup.to_bytes().unwrap();
        let recovered_backup = EncryptedBackup::from_bytes(&bytes).unwrap();

        // Verify we can still decrypt
        let recovered_key = recover_key_encrypted(&recovered_backup, password).unwrap();
        assert_eq!(keypair.public_key(), recovered_key.public_key());
    }

    #[test]
    fn test_generic_secret_shamir_backup() {
        let secret = b"my secret data that needs backup";
        let config = BackupConfig::new(2, 4).with_key_type(KeyType::GenericSecret);

        let shares = backup_secret_shamir(secret, &config).unwrap();
        assert_eq!(shares.len(), 4);

        // Recover with 2 shares
        let recovered = recover_secret_shamir(&shares[0..2]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());

        // Recover with 3 shares
        let recovered = recover_secret_shamir(&shares[1..4]).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_generic_secret_encrypted_backup() {
        let secret = b"confidential data";
        let password = "strong_password";
        let config = BackupConfig::new(1, 1);

        let backup = backup_secret_encrypted(secret, password, &config).unwrap();
        let recovered = recover_secret_encrypted(&backup, password).unwrap();

        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_invalid_threshold_config() {
        // Threshold = 0
        let config = BackupConfig::new(0, 5);
        assert!(config.validate().is_err());

        // Threshold > total
        let config = BackupConfig::new(6, 5);
        assert!(config.validate().is_err());

        // Total > 255
        let config = BackupConfig::new(128, 256);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_backup_config_builder() {
        let config = BackupConfig::new(3, 5)
            .with_label("main-key")
            .with_description("Primary signing key")
            .with_key_type(KeyType::SigningKey)
            .with_version(2);

        assert_eq!(config.label, Some("main-key".to_string()));
        assert_eq!(config.description, Some("Primary signing key".to_string()));
        assert_eq!(config.key_type, KeyType::SigningKey);
        assert_eq!(config.version, 2);
    }

    #[test]
    fn test_share_integrity_verification() {
        let keypair = KeyPair::generate();
        let config = BackupConfig::new(2, 3);
        let shares = backup_key_shamir(&keypair, &config).unwrap();

        // All shares should verify
        for share in &shares {
            assert!(share.verify_integrity());
        }

        // Corrupt a share
        let mut corrupted = shares[0].clone();
        corrupted.share_data[0] ^= 0xFF; // Flip some bits

        // Should fail integrity check
        assert!(!corrupted.verify_integrity());
    }

    #[test]
    fn test_different_passwords_different_ciphertexts() {
        let keypair = KeyPair::generate();
        let config = BackupConfig::new(1, 1);

        let backup1 = backup_key_encrypted(&keypair, "password1", &config).unwrap();
        let backup2 = backup_key_encrypted(&keypair, "password2", &config).unwrap();

        // Different passwords should produce different ciphertexts
        assert_ne!(backup1.ciphertext, backup2.ciphertext);
        assert_ne!(backup1.salt, backup2.salt);
    }

    #[test]
    fn test_empty_shares_recovery() {
        let shares: Vec<BackupShare> = vec![];
        let result = recover_key_shamir(&shares);
        assert!(result.is_err());

        let result = recover_secret_shamir(&shares);
        assert!(result.is_err());
    }
}
