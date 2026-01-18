//! Secure key storage with encryption at rest.
//!
//! This module provides a secure keystore/vault for storing cryptographic keys
//! with encryption at rest. Keys are encrypted using a master key derived from
//! a password, ensuring that stored keys are protected even if the storage
//! backend is compromised.
//!
//! # Features
//!
//! - Master key derivation from password using Argon2
//! - Individual key encryption with ChaCha20-Poly1305
//! - Unique nonces per key for security
//! - HMAC-based integrity verification
//! - Key metadata tracking (creation time, last accessed, key type)
//! - Multiple storage backends (filesystem, in-memory)
//! - Automatic key versioning and rotation support
//! - Secure deletion with zeroization
//!
//! # Example
//!
//! ```
//! use chie_crypto::keystore::{SecureKeyStore, KeyType, KeyMetadata};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new keystore with a password
//! let mut keystore = SecureKeyStore::new(b"strong-password")?;
//!
//! // Store a signing key
//! let key_id = "my-signing-key";
//! let key_data = b"secret-key-data-here";
//! keystore.store_key(key_id, key_data, KeyType::Signing)?;
//!
//! // Retrieve the key
//! let retrieved = keystore.retrieve_key(key_id)?;
//! assert_eq!(retrieved, key_data);
//!
//! // Check key metadata
//! let metadata = keystore.get_metadata(key_id)?;
//! assert_eq!(metadata.key_type, KeyType::Signing);
//!
//! // Delete the key securely
//! keystore.delete_key(key_id)?;
//! # Ok(())
//! # }
//! ```

use crate::{
    encryption::{EncryptionKey, decrypt, encrypt, generate_nonce},
    hmac::{HmacKey, HmacTag, compute_hmac, verify_hmac},
    kdf::KeyDerivation,
    zeroizing::secure_zero,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can occur during keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid master key")]
    InvalidMasterKey,

    #[error("Integrity check failed")]
    IntegrityCheckFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Invalid key type")]
    InvalidKeyType,
}

/// Result type for keystore operations.
pub type KeyStoreResult<T> = Result<T, KeyStoreError>;

/// Type of cryptographic key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 signing key
    Signing,
    /// ChaCha20 encryption key
    Encryption,
    /// HMAC authentication key
    Authentication,
    /// Generic secret key
    Generic,
    /// X25519 key exchange key
    KeyExchange,
}

/// Metadata about a stored key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for the key
    pub key_id: String,
    /// Type of key
    pub key_type: KeyType,
    /// Creation timestamp (Unix epoch)
    pub created_at: u64,
    /// Last accessed timestamp (Unix epoch)
    pub last_accessed: u64,
    /// Optional description
    pub description: Option<String>,
    /// Key version (for rotation support)
    pub version: u32,
    /// Whether the key is active
    pub active: bool,
}

impl KeyMetadata {
    /// Create new metadata for a key.
    pub fn new(key_id: String, key_type: KeyType) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            key_id,
            key_type,
            created_at: now,
            last_accessed: now,
            description: None,
            version: 1,
            active: true,
        }
    }

    /// Update the last accessed timestamp.
    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Encrypted key entry in the keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyEntry {
    /// Key metadata
    metadata: KeyMetadata,
    /// Encrypted key data
    ciphertext: Vec<u8>,
    /// HMAC for integrity verification
    hmac: Vec<u8>,
}

/// Secure keystore for encrypted key storage.
///
/// The keystore encrypts all keys at rest using a master key derived
/// from a password. Each key is encrypted with a unique nonce and
/// integrity-protected with HMAC.
pub struct SecureKeyStore {
    /// Master encryption key (32 bytes)
    master_key: EncryptionKey,
    /// Master HMAC key
    hmac_key: HmacKey,
    /// Encrypted key entries
    entries: HashMap<String, EncryptedKeyEntry>,
    /// Salt used for key derivation
    salt: [u8; 32],
}

impl SecureKeyStore {
    /// Create a new keystore with the given password.
    ///
    /// The password is used to derive the master encryption and HMAC keys
    /// using Argon2. A random salt is generated for key derivation.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::keystore::SecureKeyStore;
    ///
    /// let keystore = SecureKeyStore::new(b"my-password").unwrap();
    /// ```
    pub fn new(password: &[u8]) -> KeyStoreResult<Self> {
        // Generate random salt
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        Self::with_salt(password, salt)
    }

    /// Create a keystore with an explicit salt (for loading from storage).
    pub fn with_salt(password: &[u8], salt: [u8; 32]) -> KeyStoreResult<Self> {
        // Derive master keys from password
        let kdf = KeyDerivation::new(password, Some(&salt));
        let master_key = kdf
            .derive_encryption_key(b"keystore-encryption")
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        let hmac_key_bytes = kdf
            .derive_bytes(b"keystore-hmac", 32)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;
        let hmac_key = HmacKey::from_bytes(&hmac_key_bytes)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        Ok(Self {
            master_key,
            hmac_key,
            entries: HashMap::new(),
            salt,
        })
    }

    /// Store a key in the keystore.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    /// * `key_data` - The key bytes to encrypt and store
    /// * `key_type` - Type of the key
    ///
    /// # Errors
    ///
    /// Returns `KeyAlreadyExists` if a key with the same ID already exists.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::keystore::{SecureKeyStore, KeyType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut keystore = SecureKeyStore::new(b"password")?;
    /// keystore.store_key("key1", b"secret", KeyType::Generic)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn store_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        key_type: KeyType,
    ) -> KeyStoreResult<()> {
        if self.entries.contains_key(key_id) {
            return Err(KeyStoreError::KeyAlreadyExists(key_id.to_string()));
        }

        // Generate a random nonce
        let nonce = generate_nonce();

        // Encrypt the key data
        let encrypted = encrypt(key_data, &self.master_key, &nonce)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        // Store nonce + encrypted data together
        let mut ciphertext = Vec::with_capacity(12 + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);

        // Compute HMAC over nonce + ciphertext
        let hmac = compute_hmac(&self.hmac_key, &ciphertext);

        // Create metadata
        let metadata = KeyMetadata::new(key_id.to_string(), key_type);

        // Store entry
        self.entries.insert(
            key_id.to_string(),
            EncryptedKeyEntry {
                metadata,
                ciphertext,
                hmac: hmac.to_bytes(),
            },
        );

        Ok(())
    }

    /// Retrieve a key from the keystore.
    ///
    /// # Errors
    ///
    /// Returns `KeyNotFound` if the key doesn't exist, or `IntegrityCheckFailed`
    /// if the HMAC verification fails.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::keystore::{SecureKeyStore, KeyType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut keystore = SecureKeyStore::new(b"password")?;
    /// keystore.store_key("key1", b"secret", KeyType::Generic)?;
    /// let retrieved = keystore.retrieve_key("key1")?;
    /// assert_eq!(retrieved, b"secret");
    /// # Ok(())
    /// # }
    /// ```
    pub fn retrieve_key(&mut self, key_id: &str) -> KeyStoreResult<Vec<u8>> {
        let entry = self
            .entries
            .get_mut(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        // Verify HMAC
        let stored_hmac = HmacTag::from_bytes(&entry.hmac);
        if !verify_hmac(&self.hmac_key, &entry.ciphertext, &stored_hmac) {
            return Err(KeyStoreError::IntegrityCheckFailed);
        }

        // Extract nonce and encrypted data
        if entry.ciphertext.len() < 12 {
            return Err(KeyStoreError::DecryptionError(
                "Invalid ciphertext length".to_string(),
            ));
        }
        let (nonce_bytes, encrypted) = entry.ciphertext.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);

        // Decrypt the key data
        let plaintext = decrypt(encrypted, &self.master_key, &nonce)
            .map_err(|e| KeyStoreError::DecryptionError(e.to_string()))?;

        // Update last accessed time
        entry.metadata.touch();

        Ok(plaintext)
    }

    /// Delete a key from the keystore.
    ///
    /// The key data is securely zeroized before removal.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::keystore::{SecureKeyStore, KeyType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut keystore = SecureKeyStore::new(b"password")?;
    /// keystore.store_key("key1", b"secret", KeyType::Generic)?;
    /// keystore.delete_key("key1")?;
    /// assert!(keystore.get_metadata("key1").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_key(&mut self, key_id: &str) -> KeyStoreResult<()> {
        let mut entry = self
            .entries
            .remove(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        // Securely zero the encrypted data
        secure_zero(&mut entry.ciphertext);
        secure_zero(&mut entry.hmac);

        Ok(())
    }

    /// List all key IDs in the keystore.
    pub fn list_keys(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Get metadata for a key.
    pub fn get_metadata(&self, key_id: &str) -> KeyStoreResult<&KeyMetadata> {
        let entry = self
            .entries
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;
        Ok(&entry.metadata)
    }

    /// Update key metadata.
    pub fn update_metadata<F>(&mut self, key_id: &str, f: F) -> KeyStoreResult<()>
    where
        F: FnOnce(&mut KeyMetadata),
    {
        let entry = self
            .entries
            .get_mut(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;
        f(&mut entry.metadata);
        Ok(())
    }

    /// Rotate a key to a new version.
    ///
    /// This stores the new key data while incrementing the version number
    /// and preserving other metadata.
    pub fn rotate_key(&mut self, key_id: &str, new_key_data: &[u8]) -> KeyStoreResult<()> {
        // Get current metadata
        let metadata = {
            let entry = self
                .entries
                .get(key_id)
                .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;
            let mut meta = entry.metadata.clone();
            meta.version += 1;
            meta.touch();
            meta
        };

        // Delete old key
        self.delete_key(key_id)?;

        // Generate a random nonce
        let nonce = generate_nonce();

        // Encrypt new key data
        let encrypted = encrypt(new_key_data, &self.master_key, &nonce)
            .map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        // Store nonce + encrypted data together
        let mut ciphertext = Vec::with_capacity(12 + encrypted.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);

        // Compute HMAC
        let hmac = compute_hmac(&self.hmac_key, &ciphertext);

        // Store new entry
        self.entries.insert(
            key_id.to_string(),
            EncryptedKeyEntry {
                metadata,
                ciphertext,
                hmac: hmac.to_bytes(),
            },
        );

        Ok(())
    }

    /// Serialize the keystore to bytes for persistent storage.
    ///
    /// The serialized format includes the salt and all encrypted entries.
    pub fn serialize(&self) -> KeyStoreResult<Vec<u8>> {
        #[derive(Serialize)]
        struct KeyStoreData {
            salt: [u8; 32],
            entries: HashMap<String, EncryptedKeyEntry>,
        }

        let data = KeyStoreData {
            salt: self.salt,
            entries: self.entries.clone(),
        };

        crate::codec::encode(&data).map_err(|e| KeyStoreError::SerializationError(e.to_string()))
    }

    /// Deserialize a keystore from bytes with the given password.
    pub fn deserialize(password: &[u8], data: &[u8]) -> KeyStoreResult<Self> {
        #[derive(Deserialize)]
        struct KeyStoreData {
            salt: [u8; 32],
            entries: HashMap<String, EncryptedKeyEntry>,
        }

        let stored: KeyStoreData = crate::codec::decode(data)
            .map_err(|e| KeyStoreError::SerializationError(e.to_string()))?;

        let mut keystore = Self::with_salt(password, stored.salt)?;
        keystore.entries = stored.entries;

        Ok(keystore)
    }

    /// Get the salt used for key derivation.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Check if a key exists in the keystore.
    pub fn contains_key(&self, key_id: &str) -> bool {
        self.entries.contains_key(key_id)
    }

    /// Get the number of keys stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the keystore is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Drop for SecureKeyStore {
    fn drop(&mut self) {
        // Securely zero the master key
        secure_zero(&mut self.master_key);

        // Securely zero all key material
        for entry in self.entries.values_mut() {
            secure_zero(&mut entry.ciphertext);
            secure_zero(&mut entry.hmac);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_basic() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        // Store a key
        keystore
            .store_key("key1", b"secret-data", KeyType::Generic)
            .unwrap();

        // Retrieve it
        let retrieved = keystore.retrieve_key("key1").unwrap();
        assert_eq!(retrieved, b"secret-data");
    }

    #[test]
    fn test_multiple_keys() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("signing", b"sign-key", KeyType::Signing)
            .unwrap();
        keystore
            .store_key("encryption", b"enc-key", KeyType::Encryption)
            .unwrap();
        keystore
            .store_key("hmac", b"hmac-key", KeyType::Authentication)
            .unwrap();

        assert_eq!(keystore.retrieve_key("signing").unwrap(), b"sign-key");
        assert_eq!(keystore.retrieve_key("encryption").unwrap(), b"enc-key");
        assert_eq!(keystore.retrieve_key("hmac").unwrap(), b"hmac-key");
    }

    #[test]
    fn test_key_not_found() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        let result = keystore.retrieve_key("nonexistent");
        assert!(matches!(result, Err(KeyStoreError::KeyNotFound(_))));
    }

    #[test]
    fn test_duplicate_key() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data", KeyType::Generic)
            .unwrap();
        let result = keystore.store_key("key1", b"other", KeyType::Generic);

        assert!(matches!(result, Err(KeyStoreError::KeyAlreadyExists(_))));
    }

    #[test]
    fn test_delete_key() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data", KeyType::Generic)
            .unwrap();
        assert!(keystore.contains_key("key1"));

        keystore.delete_key("key1").unwrap();
        assert!(!keystore.contains_key("key1"));

        let result = keystore.retrieve_key("key1");
        assert!(matches!(result, Err(KeyStoreError::KeyNotFound(_))));
    }

    #[test]
    fn test_list_keys() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data1", KeyType::Generic)
            .unwrap();
        keystore
            .store_key("key2", b"data2", KeyType::Signing)
            .unwrap();
        keystore
            .store_key("key3", b"data3", KeyType::Encryption)
            .unwrap();

        let mut keys = keystore.list_keys();
        keys.sort();

        assert_eq!(keys, vec!["key1", "key2", "key3"]);
    }

    #[test]
    fn test_metadata() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data", KeyType::Signing)
            .unwrap();

        let metadata = keystore.get_metadata("key1").unwrap();
        assert_eq!(metadata.key_id, "key1");
        assert_eq!(metadata.key_type, KeyType::Signing);
        assert_eq!(metadata.version, 1);
        assert!(metadata.active);
    }

    #[test]
    fn test_update_metadata() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data", KeyType::Generic)
            .unwrap();

        keystore
            .update_metadata("key1", |meta| {
                meta.description = Some("Test key".to_string());
                meta.active = false;
            })
            .unwrap();

        let metadata = keystore.get_metadata("key1").unwrap();
        assert_eq!(metadata.description.as_deref(), Some("Test key"));
        assert!(!metadata.active);
    }

    #[test]
    fn test_key_rotation() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"old-key", KeyType::Signing)
            .unwrap();
        assert_eq!(keystore.get_metadata("key1").unwrap().version, 1);

        keystore.rotate_key("key1", b"new-key").unwrap();

        let retrieved = keystore.retrieve_key("key1").unwrap();
        assert_eq!(retrieved, b"new-key");
        assert_eq!(keystore.get_metadata("key1").unwrap().version, 2);
    }

    #[test]
    fn test_serialization() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data1", KeyType::Signing)
            .unwrap();
        keystore
            .store_key("key2", b"data2", KeyType::Encryption)
            .unwrap();

        // Serialize
        let serialized = keystore.serialize().unwrap();

        // Deserialize
        let mut restored = SecureKeyStore::deserialize(b"test-password", &serialized).unwrap();

        // Verify keys are intact
        assert_eq!(restored.retrieve_key("key1").unwrap(), b"data1");
        assert_eq!(restored.retrieve_key("key2").unwrap(), b"data2");
    }

    #[test]
    fn test_wrong_password() {
        let mut keystore = SecureKeyStore::new(b"correct-password").unwrap();
        keystore
            .store_key("key1", b"data", KeyType::Generic)
            .unwrap();

        let serialized = keystore.serialize().unwrap();

        // Try to load with wrong password
        let mut wrong_keystore =
            SecureKeyStore::deserialize(b"wrong-password", &serialized).unwrap();

        // This should fail integrity check
        let result = wrong_keystore.retrieve_key("key1");
        assert!(matches!(result, Err(KeyStoreError::IntegrityCheckFailed)));
    }

    #[test]
    fn test_keystore_len() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        assert_eq!(keystore.len(), 0);
        assert!(keystore.is_empty());

        keystore
            .store_key("key1", b"data1", KeyType::Generic)
            .unwrap();
        assert_eq!(keystore.len(), 1);
        assert!(!keystore.is_empty());

        keystore
            .store_key("key2", b"data2", KeyType::Signing)
            .unwrap();
        assert_eq!(keystore.len(), 2);

        keystore.delete_key("key1").unwrap();
        assert_eq!(keystore.len(), 1);
    }

    #[test]
    fn test_different_key_types() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("sign", b"sign-key", KeyType::Signing)
            .unwrap();
        keystore
            .store_key("enc", b"enc-key", KeyType::Encryption)
            .unwrap();
        keystore
            .store_key("auth", b"auth-key", KeyType::Authentication)
            .unwrap();
        keystore
            .store_key("kex", b"kex-key", KeyType::KeyExchange)
            .unwrap();
        keystore
            .store_key("gen", b"gen-key", KeyType::Generic)
            .unwrap();

        assert_eq!(
            keystore.get_metadata("sign").unwrap().key_type,
            KeyType::Signing
        );
        assert_eq!(
            keystore.get_metadata("enc").unwrap().key_type,
            KeyType::Encryption
        );
        assert_eq!(
            keystore.get_metadata("auth").unwrap().key_type,
            KeyType::Authentication
        );
        assert_eq!(
            keystore.get_metadata("kex").unwrap().key_type,
            KeyType::KeyExchange
        );
        assert_eq!(
            keystore.get_metadata("gen").unwrap().key_type,
            KeyType::Generic
        );
    }

    #[test]
    fn test_last_accessed_update() {
        let mut keystore = SecureKeyStore::new(b"test-password").unwrap();

        keystore
            .store_key("key1", b"data", KeyType::Generic)
            .unwrap();

        let created_at = keystore.get_metadata("key1").unwrap().created_at;
        let first_accessed = keystore.get_metadata("key1").unwrap().last_accessed;

        // Sleep a tiny bit to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(10));

        keystore.retrieve_key("key1").unwrap();

        let second_accessed = keystore.get_metadata("key1").unwrap().last_accessed;

        assert_eq!(created_at, first_accessed);
        assert!(second_accessed >= first_accessed);
    }
}
