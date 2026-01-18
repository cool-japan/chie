//! Key rotation utilities for secure key management.
//!
//! Provides:
//! - Key versioning and rotation scheduling
//! - Encrypted key storage and backup
//! - Key derivation for re-encryption
//! - Key revocation tracking

use crate::{EncryptionKey, EncryptionNonce, decrypt, encrypt, generate_key, generate_nonce, hash};
use crate::{KeyPair, PublicKey, SecretKey, SigningError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Key rotation error.
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key expired: version {0}")]
    KeyExpired(u32),

    #[error("Key revoked: version {0}")]
    KeyRevoked(u32),

    #[error("Encryption error")]
    EncryptionError,

    #[error("Decryption error")]
    DecryptionError,

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Signing error: {0}")]
    SigningError(#[from] SigningError),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Key version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Version number (monotonically increasing).
    pub version: u32,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Expiration timestamp (Unix seconds), None if no expiration.
    pub expires_at: Option<u64>,
    /// Whether this key has been revoked.
    pub revoked: bool,
    /// Revocation timestamp if revoked.
    pub revoked_at: Option<u64>,
    /// Reason for revocation if provided.
    pub revocation_reason: Option<String>,
    /// Key fingerprint (hash of public key).
    pub fingerprint: String,
}

impl KeyVersion {
    /// Create a new key version.
    pub fn new(version: u32, fingerprint: String, ttl: Option<Duration>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version,
            created_at: now,
            expires_at: ttl.map(|d| now + d.as_secs()),
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            fingerprint,
        }
    }

    /// Check if the key is valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expires_at {
                return false;
            }
        }

        true
    }

    /// Check if the key is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return now > expires_at;
        }
        false
    }

    /// Revoke this key version.
    pub fn revoke(&mut self, reason: Option<String>) {
        self.revoked = true;
        self.revoked_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.revocation_reason = reason;
    }
}

/// Encrypted key storage format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Encrypted key material.
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: [u8; 12],
    /// Key version this belongs to.
    pub version: u32,
    /// Salt for key derivation (if using password-based encryption).
    pub salt: Option<Vec<u8>>,
}

impl EncryptedKey {
    /// Encrypt a secret key with a master key.
    pub fn encrypt_secret_key(
        secret_key: &SecretKey,
        master_key: &EncryptionKey,
    ) -> Result<Self, RotationError> {
        let nonce = generate_nonce();
        let ciphertext =
            encrypt(secret_key, master_key, &nonce).map_err(|_| RotationError::EncryptionError)?;

        Ok(Self {
            ciphertext,
            nonce,
            version: 0,
            salt: None,
        })
    }

    /// Decrypt a secret key with a master key.
    pub fn decrypt_secret_key(
        &self,
        master_key: &EncryptionKey,
    ) -> Result<SecretKey, RotationError> {
        let decrypted = decrypt(&self.ciphertext, master_key, &self.nonce)
            .map_err(|_| RotationError::DecryptionError)?;

        if decrypted.len() != 32 {
            return Err(RotationError::InvalidKeyFormat);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    /// Encrypt an encryption key with a master key.
    pub fn encrypt_encryption_key(
        key: &EncryptionKey,
        master_key: &EncryptionKey,
    ) -> Result<Self, RotationError> {
        let nonce = generate_nonce();
        let ciphertext =
            encrypt(key, master_key, &nonce).map_err(|_| RotationError::EncryptionError)?;

        Ok(Self {
            ciphertext,
            nonce,
            version: 0,
            salt: None,
        })
    }

    /// Decrypt an encryption key with a master key.
    pub fn decrypt_encryption_key(
        &self,
        master_key: &EncryptionKey,
    ) -> Result<EncryptionKey, RotationError> {
        let decrypted = decrypt(&self.ciphertext, master_key, &self.nonce)
            .map_err(|_| RotationError::DecryptionError)?;

        if decrypted.len() != 32 {
            return Err(RotationError::InvalidKeyFormat);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }
}

/// Key rotation policy.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Maximum key age before rotation is required.
    pub max_age: Duration,
    /// Number of old keys to keep for decryption.
    pub retention_count: usize,
    /// Whether to automatically rotate expired keys.
    pub auto_rotate: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(30 * 24 * 3600), // 30 days
            retention_count: 3,
            auto_rotate: true,
        }
    }
}

/// Signing key ring for managing multiple key versions.
pub struct SigningKeyRing {
    /// Current active key version.
    current_version: u32,
    /// Key versions metadata.
    versions: HashMap<u32, KeyVersion>,
    /// Encrypted keys storage.
    encrypted_keys: HashMap<u32, EncryptedKey>,
    /// Public keys by version.
    public_keys: HashMap<u32, PublicKey>,
    /// Master key for encrypting stored keys.
    master_key: EncryptionKey,
    /// Rotation policy.
    policy: RotationPolicy,
}

impl SigningKeyRing {
    /// Create a new signing key ring with a master key.
    pub fn new(master_key: EncryptionKey, policy: RotationPolicy) -> Self {
        Self {
            current_version: 0,
            versions: HashMap::new(),
            encrypted_keys: HashMap::new(),
            public_keys: HashMap::new(),
            master_key,
            policy,
        }
    }

    /// Add a new key to the ring.
    pub fn add_key(
        &mut self,
        key_pair: &KeyPair,
        ttl: Option<Duration>,
    ) -> Result<u32, RotationError> {
        let version = self.current_version + 1;
        let public_key = key_pair.public_key();
        let secret_key = key_pair.secret_key();

        // Create fingerprint from public key.
        let fingerprint = hex::encode(&hash(&public_key)[..16]);

        // Create version metadata.
        let key_version = KeyVersion::new(version, fingerprint, ttl);

        // Encrypt and store the secret key.
        let encrypted = EncryptedKey::encrypt_secret_key(&secret_key, &self.master_key)?;

        self.versions.insert(version, key_version);
        self.encrypted_keys.insert(version, encrypted);
        self.public_keys.insert(version, public_key);
        self.current_version = version;

        // Cleanup old keys beyond retention count.
        self.cleanup_old_keys();

        Ok(version)
    }

    /// Generate and add a new key.
    pub fn generate_key(
        &mut self,
        ttl: Option<Duration>,
    ) -> Result<(u32, PublicKey), RotationError> {
        let key_pair = KeyPair::generate();
        let public_key = key_pair.public_key();
        let version = self.add_key(&key_pair, ttl)?;
        Ok((version, public_key))
    }

    /// Get the current key version.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Get a key version's metadata.
    pub fn get_version(&self, version: u32) -> Option<&KeyVersion> {
        self.versions.get(&version)
    }

    /// Get a public key by version.
    pub fn get_public_key(&self, version: u32) -> Option<&PublicKey> {
        self.public_keys.get(&version)
    }

    /// Get the current public key.
    pub fn current_public_key(&self) -> Option<&PublicKey> {
        self.public_keys.get(&self.current_version)
    }

    /// Get a decrypted key pair for signing.
    pub fn get_key_pair(&self, version: u32) -> Result<KeyPair, RotationError> {
        let version_meta = self
            .versions
            .get(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        if version_meta.revoked {
            return Err(RotationError::KeyRevoked(version));
        }

        if version_meta.is_expired() {
            return Err(RotationError::KeyExpired(version));
        }

        let encrypted = self
            .encrypted_keys
            .get(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        let secret_key = encrypted.decrypt_secret_key(&self.master_key)?;
        KeyPair::from_secret_key(&secret_key).map_err(RotationError::from)
    }

    /// Get the current key pair for signing.
    pub fn current_key_pair(&self) -> Result<KeyPair, RotationError> {
        self.get_key_pair(self.current_version)
    }

    /// Revoke a key version.
    pub fn revoke_key(
        &mut self,
        version: u32,
        reason: Option<String>,
    ) -> Result<(), RotationError> {
        let version_meta = self
            .versions
            .get_mut(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        version_meta.revoke(reason);
        Ok(())
    }

    /// Check if rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        if let Some(version) = self.versions.get(&self.current_version) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let age = now.saturating_sub(version.created_at);
            age > self.policy.max_age.as_secs() || version.revoked || version.is_expired()
        } else {
            true
        }
    }

    /// Rotate to a new key if needed.
    pub fn rotate_if_needed(&mut self) -> Result<Option<u32>, RotationError> {
        if self.needs_rotation() && self.policy.auto_rotate {
            let (version, _) = self.generate_key(Some(self.policy.max_age))?;
            Ok(Some(version))
        } else {
            Ok(None)
        }
    }

    /// List all key versions.
    pub fn list_versions(&self) -> Vec<&KeyVersion> {
        let mut versions: Vec<_> = self.versions.values().collect();
        versions.sort_by_key(|v| v.version);
        versions
    }

    /// Get all valid (non-revoked, non-expired) versions.
    pub fn valid_versions(&self) -> Vec<u32> {
        self.versions
            .iter()
            .filter(|(_, v)| v.is_valid())
            .map(|(k, _)| *k)
            .collect()
    }

    /// Clean up old keys beyond retention count.
    fn cleanup_old_keys(&mut self) {
        let mut versions: Vec<_> = self.versions.keys().copied().collect();
        versions.sort();

        // Keep the current key and retention_count older keys.
        let to_remove = versions
            .len()
            .saturating_sub(self.policy.retention_count + 1);
        for version in versions.into_iter().take(to_remove) {
            // Don't remove if it's the current version.
            if version != self.current_version {
                self.versions.remove(&version);
                self.encrypted_keys.remove(&version);
                self.public_keys.remove(&version);
            }
        }
    }
}

/// Encryption key ring for managing content encryption keys.
pub struct EncryptionKeyRing {
    /// Current active key version.
    current_version: u32,
    /// Key versions metadata.
    versions: HashMap<u32, KeyVersion>,
    /// Encrypted keys storage.
    encrypted_keys: HashMap<u32, EncryptedKey>,
    /// Master key for encrypting stored keys.
    master_key: EncryptionKey,
    /// Rotation policy.
    policy: RotationPolicy,
}

impl EncryptionKeyRing {
    /// Create a new encryption key ring with a master key.
    pub fn new(master_key: EncryptionKey, policy: RotationPolicy) -> Self {
        Self {
            current_version: 0,
            versions: HashMap::new(),
            encrypted_keys: HashMap::new(),
            master_key,
            policy,
        }
    }

    /// Add a new encryption key to the ring.
    pub fn add_key(
        &mut self,
        key: &EncryptionKey,
        ttl: Option<Duration>,
    ) -> Result<u32, RotationError> {
        let version = self.current_version + 1;

        // Create fingerprint from key hash.
        let fingerprint = hex::encode(&hash(key)[..16]);

        // Create version metadata.
        let key_version = KeyVersion::new(version, fingerprint, ttl);

        // Encrypt and store the key.
        let encrypted = EncryptedKey::encrypt_encryption_key(key, &self.master_key)?;

        self.versions.insert(version, key_version);
        self.encrypted_keys.insert(version, encrypted);
        self.current_version = version;

        // Cleanup old keys beyond retention count.
        self.cleanup_old_keys();

        Ok(version)
    }

    /// Generate and add a new random key.
    pub fn generate_key(&mut self, ttl: Option<Duration>) -> Result<u32, RotationError> {
        let key = generate_key();
        self.add_key(&key, ttl)
    }

    /// Get the current key version.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Get a decrypted key by version.
    pub fn get_key(&self, version: u32) -> Result<EncryptionKey, RotationError> {
        let version_meta = self
            .versions
            .get(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        if version_meta.revoked {
            return Err(RotationError::KeyRevoked(version));
        }

        // Allow decryption with expired keys (for reading old data).

        let encrypted = self
            .encrypted_keys
            .get(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        encrypted.decrypt_encryption_key(&self.master_key)
    }

    /// Get the current encryption key.
    pub fn current_key(&self) -> Result<EncryptionKey, RotationError> {
        let version_meta = self.versions.get(&self.current_version).ok_or_else(|| {
            RotationError::KeyNotFound(format!("version {}", self.current_version))
        })?;

        // For encryption, key must be valid.
        if !version_meta.is_valid() {
            if version_meta.is_expired() {
                return Err(RotationError::KeyExpired(self.current_version));
            }
            if version_meta.revoked {
                return Err(RotationError::KeyRevoked(self.current_version));
            }
        }

        self.get_key(self.current_version)
    }

    /// Revoke a key version.
    pub fn revoke_key(
        &mut self,
        version: u32,
        reason: Option<String>,
    ) -> Result<(), RotationError> {
        let version_meta = self
            .versions
            .get_mut(&version)
            .ok_or_else(|| RotationError::KeyNotFound(format!("version {}", version)))?;

        version_meta.revoke(reason);
        Ok(())
    }

    /// Check if rotation is needed.
    pub fn needs_rotation(&self) -> bool {
        if let Some(version) = self.versions.get(&self.current_version) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let age = now.saturating_sub(version.created_at);
            age > self.policy.max_age.as_secs() || version.revoked || version.is_expired()
        } else {
            true
        }
    }

    /// Rotate to a new key if needed.
    pub fn rotate_if_needed(&mut self) -> Result<Option<u32>, RotationError> {
        if self.needs_rotation() && self.policy.auto_rotate {
            let version = self.generate_key(Some(self.policy.max_age))?;
            Ok(Some(version))
        } else {
            Ok(None)
        }
    }

    /// List all key versions.
    pub fn list_versions(&self) -> Vec<&KeyVersion> {
        let mut versions: Vec<_> = self.versions.values().collect();
        versions.sort_by_key(|v| v.version);
        versions
    }

    /// Clean up old keys beyond retention count.
    fn cleanup_old_keys(&mut self) {
        let mut versions: Vec<_> = self.versions.keys().copied().collect();
        versions.sort();

        let to_remove = versions
            .len()
            .saturating_sub(self.policy.retention_count + 1);
        for version in versions.into_iter().take(to_remove) {
            if version != self.current_version {
                self.versions.remove(&version);
                self.encrypted_keys.remove(&version);
            }
        }
    }
}

/// Re-encryption helper for rotating content encryption.
pub struct ReEncryptor<'a> {
    /// Old key for decryption.
    old_key: EncryptionKey,
    /// New key for encryption.
    new_key: EncryptionKey,
    /// Old nonce.
    old_nonce: &'a EncryptionNonce,
}

impl<'a> ReEncryptor<'a> {
    /// Create a new re-encryptor.
    pub fn new(
        old_key: EncryptionKey,
        new_key: EncryptionKey,
        old_nonce: &'a EncryptionNonce,
    ) -> Self {
        Self {
            old_key,
            new_key,
            old_nonce,
        }
    }

    /// Re-encrypt data from old key to new key.
    pub fn re_encrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, EncryptionNonce), RotationError> {
        // Decrypt with old key.
        let plaintext = decrypt(ciphertext, &self.old_key, self.old_nonce)
            .map_err(|_| RotationError::DecryptionError)?;

        // Encrypt with new key.
        let new_nonce = generate_nonce();
        let new_ciphertext = encrypt(&plaintext, &self.new_key, &new_nonce)
            .map_err(|_| RotationError::EncryptionError)?;

        Ok((new_ciphertext, new_nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_version_validity() {
        let version = KeyVersion::new(1, "abc123".to_string(), Some(Duration::from_secs(3600)));
        assert!(version.is_valid());
        assert!(!version.is_expired());
        assert!(!version.revoked);
    }

    #[test]
    fn test_key_revocation() {
        let mut version = KeyVersion::new(1, "abc123".to_string(), None);
        assert!(version.is_valid());

        version.revoke(Some("Compromised".to_string()));
        assert!(!version.is_valid());
        assert!(version.revoked);
        assert!(version.revoked_at.is_some());
    }

    #[test]
    fn test_encrypted_key() {
        let master_key = generate_key();
        let secret_key: SecretKey = [1u8; 32];

        let encrypted = EncryptedKey::encrypt_secret_key(&secret_key, &master_key).unwrap();
        let decrypted = encrypted.decrypt_secret_key(&master_key).unwrap();

        assert_eq!(secret_key, decrypted);
    }

    #[test]
    fn test_signing_key_ring() {
        let master_key = generate_key();
        let policy = RotationPolicy::default();
        let mut ring = SigningKeyRing::new(master_key, policy);

        // Generate first key.
        let (v1, pk1) = ring.generate_key(None).unwrap();
        assert_eq!(v1, 1);
        assert_eq!(ring.current_version(), 1);

        // Generate second key.
        let (v2, pk2) = ring.generate_key(None).unwrap();
        assert_eq!(v2, 2);
        assert_ne!(pk1, pk2);

        // Can retrieve key pairs.
        let kp1 = ring.get_key_pair(1).unwrap();
        assert_eq!(kp1.public_key(), pk1);

        let kp2 = ring.current_key_pair().unwrap();
        assert_eq!(kp2.public_key(), pk2);
    }

    #[test]
    fn test_encryption_key_ring() {
        let master_key = generate_key();
        let policy = RotationPolicy::default();
        let mut ring = EncryptionKeyRing::new(master_key, policy);

        // Generate first key.
        let v1 = ring.generate_key(None).unwrap();
        assert_eq!(v1, 1);

        let key1 = ring.get_key(1).unwrap();
        let current = ring.current_key().unwrap();
        assert_eq!(key1, current);

        // Generate second key.
        let v2 = ring.generate_key(None).unwrap();
        assert_eq!(v2, 2);

        let key2 = ring.current_key().unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_re_encryption() {
        let old_key = generate_key();
        let new_key = generate_key();
        let old_nonce = generate_nonce();

        let plaintext = b"Secret data for re-encryption";
        let ciphertext = encrypt(plaintext, &old_key, &old_nonce).unwrap();

        let re_encryptor = ReEncryptor::new(old_key, new_key, &old_nonce);
        let (new_ciphertext, new_nonce) = re_encryptor.re_encrypt(&ciphertext).unwrap();

        // Decrypt with new key should work.
        let decrypted = decrypt(&new_ciphertext, &new_key, &new_nonce).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
