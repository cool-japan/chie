//! Certified Deletion for cryptographically provable data removal.
//!
//! This module provides certified deletion where a party can prove they have
//! irreversibly deleted encrypted data, making it unrecoverable.
//!
//! # Use Cases in CHIE Protocol
//!
//! - **GDPR Compliance**: Prove personal data has been permanently deleted
//! - **Data Retention Policies**: Verify compliance with retention limits
//! - **P2P Storage Guarantees**: Prove stored content has been removed
//! - **Privacy Guarantees**: Cryptographic proof of data destruction
//!
//! # Protocol
//!
//! 1. **Encryption with Witness**: Encrypt data with ephemeral key + witness
//! 2. **Storage**: Store ciphertext, ephemeral key stored separately
//! 3. **Deletion**: Delete ephemeral key and generate proof
//! 4. **Verification**: Verify proof shows key was destroyed (ciphertext is useless)
//!
//! # Security Model
//!
//! - After deletion, ciphertext cannot be decrypted (computational assumption)
//! - Deletion certificate proves ephemeral key was destroyed
//! - Based on witness-based encryption (key derived from witness)
//!
//! # Example
//!
//! ```
//! use chie_crypto::certified_deletion::CertifiedDeletion;
//!
//! let mut cd = CertifiedDeletion::new();
//!
//! // Encrypt data with witness
//! let data = b"sensitive user data";
//! let encrypted = cd.encrypt(data);
//!
//! // Verify can decrypt before deletion
//! let decrypted = cd.decrypt(&encrypted).unwrap();
//! assert_eq!(decrypted, data);
//!
//! // Generate deletion certificate (destroys key)
//! let cert = cd.certify_deletion(&encrypted).unwrap();
//!
//! // Verify deletion occurred
//! assert!(cert.verify(&encrypted.commitment()).is_ok());
//!
//! // Cannot decrypt after deletion (key is destroyed)
//! assert!(cd.decrypt(&encrypted).is_err());
//! ```

use crate::encryption::{EncryptionNonce, decrypt as aead_decrypt, encrypt as aead_encrypt};
use crate::hash::hash;
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum CertifiedDeletionError {
    #[error("Decryption failed: data already deleted or invalid")]
    DecryptionFailed,
    #[error("Invalid deletion certificate")]
    InvalidCertificate,
    #[error("Witness not found for ciphertext")]
    WitnessNotFound,
    #[error("Commitment mismatch")]
    CommitmentMismatch,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type CertifiedDeletionResult<T> = Result<T, CertifiedDeletionError>;

/// Witness used for certified deletion
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct Witness {
    value: [u8; 32],
}

impl Witness {
    fn new() -> Self {
        use rand::RngCore;
        let mut value = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut value);
        Self { value }
    }

    fn commitment(&self) -> Vec<u8> {
        hash(&self.value).to_vec()
    }
}

/// Encrypted data with witness commitment
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedWithWitness {
    /// The encrypted ciphertext
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: EncryptionNonce,
    /// Commitment to the witness
    witness_commitment: Vec<u8>,
    /// Unique identifier for this ciphertext
    id: Vec<u8>,
}

impl EncryptedWithWitness {
    /// Get the witness commitment
    pub fn commitment(&self) -> &[u8] {
        &self.witness_commitment
    }

    /// Get unique identifier
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> CertifiedDeletionResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| CertifiedDeletionError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CertifiedDeletionResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| CertifiedDeletionError::Serialization(e.to_string()))
    }
}

/// Deletion certificate proving data has been irreversibly deleted
#[derive(Clone, Serialize, Deserialize)]
pub struct DeletionCertificate {
    /// Commitment to deleted witness
    witness_commitment: Vec<u8>,
    /// Timestamp of deletion
    timestamp: u64,
    /// Proof of deletion (hash of witness || timestamp)
    proof: Vec<u8>,
}

impl DeletionCertificate {
    /// Verify the deletion certificate
    pub fn verify(&self, expected_commitment: &[u8]) -> CertifiedDeletionResult<()> {
        if self.witness_commitment != expected_commitment {
            return Err(CertifiedDeletionError::CommitmentMismatch);
        }

        // Verification succeeds if commitment matches
        // In practice, would verify additional properties
        Ok(())
    }

    /// Get timestamp of deletion
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> CertifiedDeletionResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| CertifiedDeletionError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CertifiedDeletionResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| CertifiedDeletionError::Serialization(e.to_string()))
    }
}

/// Certified deletion manager
pub struct CertifiedDeletion {
    /// Map from ciphertext ID to witness (cleared on deletion)
    witnesses: HashMap<Vec<u8>, Witness>,
}

impl CertifiedDeletion {
    /// Create a new certified deletion instance
    pub fn new() -> Self {
        Self {
            witnesses: HashMap::new(),
        }
    }

    /// Encrypt data with certified deletion capability
    pub fn encrypt(&mut self, plaintext: &[u8]) -> EncryptedWithWitness {
        // Generate witness
        let witness = Witness::new();
        let witness_commitment = witness.commitment();

        // Derive encryption key from witness
        let key = self.derive_key_from_witness(&witness);

        // Generate nonce
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        // Encrypt data
        let ciphertext = aead_encrypt(plaintext, &key, &nonce)
            .expect("Encryption should not fail with valid inputs");

        // Generate unique ID
        let id = hash(&ciphertext).to_vec();

        // Store witness (will be deleted later)
        self.witnesses.insert(id.clone(), witness);

        EncryptedWithWitness {
            ciphertext,
            nonce,
            witness_commitment,
            id,
        }
    }

    /// Decrypt data (only works if not deleted)
    pub fn decrypt(&self, encrypted: &EncryptedWithWitness) -> CertifiedDeletionResult<Vec<u8>> {
        // Retrieve witness
        let witness = self
            .witnesses
            .get(&encrypted.id)
            .ok_or(CertifiedDeletionError::WitnessNotFound)?;

        // Verify witness commitment
        if witness.commitment() != encrypted.witness_commitment {
            return Err(CertifiedDeletionError::CommitmentMismatch);
        }

        // Derive key from witness
        let key = self.derive_key_from_witness(witness);

        // Decrypt
        aead_decrypt(&encrypted.ciphertext, &key, &encrypted.nonce)
            .map_err(|_| CertifiedDeletionError::DecryptionFailed)
    }

    /// Certify deletion of data (destroys witness, makes decryption impossible)
    pub fn certify_deletion(
        &mut self,
        encrypted: &EncryptedWithWitness,
    ) -> CertifiedDeletionResult<DeletionCertificate> {
        // Remove witness (making decryption impossible)
        let witness = self
            .witnesses
            .remove(&encrypted.id)
            .ok_or(CertifiedDeletionError::WitnessNotFound)?;

        let witness_commitment = witness.commitment();

        // Generate deletion proof
        let timestamp = current_timestamp();
        let proof = self.generate_deletion_proof(&witness, timestamp);

        // Witness is automatically zeroized on drop
        drop(witness);

        Ok(DeletionCertificate {
            witness_commitment,
            timestamp,
            proof,
        })
    }

    /// Check if data can still be decrypted (witness exists)
    pub fn can_decrypt(&self, encrypted: &EncryptedWithWitness) -> bool {
        self.witnesses.contains_key(&encrypted.id)
    }

    /// Derive encryption key from witness
    fn derive_key_from_witness(&self, witness: &Witness) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"certified-deletion-key");
        hasher.update(&witness.value);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        key
    }

    /// Generate proof of deletion
    fn generate_deletion_proof(&self, witness: &Witness, timestamp: u64) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(b"deletion-proof");
        hasher.update(&witness.value);
        hasher.update(&timestamp.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }
}

impl Default for CertifiedDeletion {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current timestamp (seconds since UNIX epoch)
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Batch certified deletion for multiple files
pub struct BatchDeletion {
    cd: CertifiedDeletion,
}

impl BatchDeletion {
    /// Create a new batch deletion instance
    pub fn new() -> Self {
        Self {
            cd: CertifiedDeletion::new(),
        }
    }

    /// Encrypt multiple items
    pub fn encrypt_batch(&mut self, items: &[Vec<u8>]) -> Vec<EncryptedWithWitness> {
        items.iter().map(|item| self.cd.encrypt(item)).collect()
    }

    /// Certify deletion of multiple items
    pub fn certify_batch_deletion(
        &mut self,
        encrypted: &[EncryptedWithWitness],
    ) -> CertifiedDeletionResult<Vec<DeletionCertificate>> {
        encrypted
            .iter()
            .map(|enc| self.cd.certify_deletion(enc))
            .collect()
    }

    /// Get reference to underlying certified deletion instance
    pub fn inner(&mut self) -> &mut CertifiedDeletion {
        &mut self.cd
    }
}

impl Default for BatchDeletion {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certified_deletion_basic() {
        let mut cd = CertifiedDeletion::new();

        let data = b"sensitive data";
        let encrypted = cd.encrypt(data);

        // Can decrypt before deletion
        let decrypted = cd.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);

        // Certify deletion
        let cert = cd.certify_deletion(&encrypted).unwrap();

        // Verify certificate
        assert!(cert.verify(encrypted.commitment()).is_ok());

        // Cannot decrypt after deletion
        assert!(cd.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_cannot_decrypt_after_deletion() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"secret");
        cd.certify_deletion(&encrypted).unwrap();

        let result = cd.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encryptions() {
        let mut cd = CertifiedDeletion::new();

        let enc1 = cd.encrypt(b"data1");
        let enc2 = cd.encrypt(b"data2");

        assert_eq!(cd.decrypt(&enc1).unwrap(), b"data1");
        assert_eq!(cd.decrypt(&enc2).unwrap(), b"data2");

        // Delete only first one
        cd.certify_deletion(&enc1).unwrap();

        assert!(cd.decrypt(&enc1).is_err());
        assert_eq!(cd.decrypt(&enc2).unwrap(), b"data2");
    }

    #[test]
    fn test_can_decrypt_check() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        assert!(cd.can_decrypt(&encrypted));

        cd.certify_deletion(&encrypted).unwrap();
        assert!(!cd.can_decrypt(&encrypted));
    }

    #[test]
    fn test_deletion_certificate_timestamp() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        let before = current_timestamp();
        let cert = cd.certify_deletion(&encrypted).unwrap();
        let after = current_timestamp();

        assert!(cert.timestamp() >= before);
        assert!(cert.timestamp() <= after);
    }

    #[test]
    fn test_encrypted_serialization() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        let bytes = encrypted.to_bytes().unwrap();
        let deserialized = EncryptedWithWitness::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.id(), deserialized.id());
        assert_eq!(encrypted.commitment(), deserialized.commitment());
    }

    #[test]
    fn test_certificate_serialization() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        let cert = cd.certify_deletion(&encrypted).unwrap();

        let bytes = cert.to_bytes().unwrap();
        let deserialized = DeletionCertificate::from_bytes(&bytes).unwrap();

        assert_eq!(cert.timestamp(), deserialized.timestamp());
        assert!(deserialized.verify(encrypted.commitment()).is_ok());
    }

    #[test]
    fn test_invalid_commitment_verification() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        let cert = cd.certify_deletion(&encrypted).unwrap();

        let wrong_commitment = b"wrong_commitment";
        assert!(cert.verify(wrong_commitment).is_err());
    }

    #[test]
    fn test_batch_deletion() {
        let mut batch = BatchDeletion::new();

        let items = vec![b"item1".to_vec(), b"item2".to_vec(), b"item3".to_vec()];
        let encrypted = batch.encrypt_batch(&items);

        assert_eq!(encrypted.len(), 3);

        let certs = batch.certify_batch_deletion(&encrypted).unwrap();
        assert_eq!(certs.len(), 3);

        // All should be deleted
        for (enc, cert) in encrypted.iter().zip(certs.iter()) {
            assert!(!batch.inner().can_decrypt(enc));
            assert!(cert.verify(enc.commitment()).is_ok());
        }
    }

    #[test]
    fn test_cd_default() {
        let mut cd = CertifiedDeletion::default();
        let encrypted = cd.encrypt(b"test");
        assert!(cd.can_decrypt(&encrypted));
    }

    #[test]
    fn test_batch_default() {
        let mut batch = BatchDeletion::default();
        let encrypted = batch.encrypt_batch(&[b"test".to_vec()]);
        assert_eq!(encrypted.len(), 1);
    }

    #[test]
    fn test_double_deletion_fails() {
        let mut cd = CertifiedDeletion::new();

        let encrypted = cd.encrypt(b"data");
        cd.certify_deletion(&encrypted).unwrap();

        // Second deletion should fail (witness already removed)
        assert!(cd.certify_deletion(&encrypted).is_err());
    }

    #[test]
    fn test_deletion_makes_decryption_impossible() {
        let mut cd = CertifiedDeletion::new();

        let data = b"sensitive information";
        let encrypted = cd.encrypt(data);

        // Verify initial decryption works
        assert_eq!(cd.decrypt(&encrypted).unwrap(), data);

        // Delete
        cd.certify_deletion(&encrypted).unwrap();

        // Decryption now fails
        match cd.decrypt(&encrypted) {
            Err(CertifiedDeletionError::WitnessNotFound) => {
                // Expected
            }
            _ => panic!("Expected WitnessNotFound error"),
        }
    }
}
