//! Key derivation functions using HKDF.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use crate::EncryptionKey;

/// KDF error types.
#[derive(Debug, Error)]
pub enum KdfError {
    #[error("Output key material too long")]
    OutputTooLong,

    #[error("Invalid key length")]
    InvalidKeyLength,
}

/// HKDF context for deriving keys.
pub struct KeyDerivation {
    hkdf: Hkdf<Sha256>,
}

impl KeyDerivation {
    /// Create a new HKDF instance from input key material.
    ///
    /// # Arguments
    /// * `ikm` - Input key material (e.g., master key)
    /// * `salt` - Optional salt (use None for unsalted, not recommended)
    pub fn new(ikm: &[u8], salt: Option<&[u8]>) -> Self {
        let hkdf = Hkdf::<Sha256>::new(salt, ikm);
        Self { hkdf }
    }

    /// Derive an encryption key from the master key.
    ///
    /// # Arguments
    /// * `info` - Context/application-specific info (e.g., "content-encryption")
    pub fn derive_encryption_key(&self, info: &[u8]) -> Result<EncryptionKey, KdfError> {
        let mut okm = [0u8; 32];
        self.hkdf
            .expand(info, &mut okm)
            .map_err(|_| KdfError::OutputTooLong)?;
        Ok(okm)
    }

    /// Derive a key of arbitrary length.
    ///
    /// # Arguments
    /// * `info` - Context/application-specific info
    /// * `length` - Desired output length
    pub fn derive_bytes(&self, info: &[u8], length: usize) -> Result<Vec<u8>, KdfError> {
        let mut okm = vec![0u8; length];
        self.hkdf
            .expand(info, &mut okm)
            .map_err(|_| KdfError::OutputTooLong)?;
        Ok(okm)
    }
}

/// Derive a content encryption key from a master key and content ID.
///
/// This is the recommended way to derive per-content keys.
pub fn derive_content_key(
    master_key: &EncryptionKey,
    content_cid: &str,
    chunk_index: u64,
) -> Result<EncryptionKey, KdfError> {
    let kdf = KeyDerivation::new(master_key, Some(b"chie-content-v1"));

    // Create info with content ID and chunk index
    let mut info = Vec::new();
    info.extend_from_slice(content_cid.as_bytes());
    info.extend_from_slice(&chunk_index.to_le_bytes());

    kdf.derive_encryption_key(&info)
}

/// Derive a nonce for a specific chunk.
///
/// This ensures each chunk has a unique nonce without storing them.
pub fn derive_chunk_nonce(
    master_key: &EncryptionKey,
    content_cid: &str,
    chunk_index: u64,
) -> Result<[u8; 12], KdfError> {
    let kdf = KeyDerivation::new(master_key, Some(b"chie-nonce-v1"));

    let mut info = Vec::new();
    info.extend_from_slice(content_cid.as_bytes());
    info.extend_from_slice(&chunk_index.to_le_bytes());

    let bytes = kdf.derive_bytes(&info, 12)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Derive multiple chunk keys at once for efficiency.
pub fn derive_chunk_keys(
    master_key: &EncryptionKey,
    content_cid: &str,
    start_chunk: u64,
    count: usize,
) -> Result<Vec<EncryptionKey>, KdfError> {
    let mut keys = Vec::with_capacity(count);
    for i in 0..count as u64 {
        keys.push(derive_content_key(
            master_key,
            content_cid,
            start_chunk + i,
        )?);
    }
    Ok(keys)
}

/// Simple HKDF extract-and-expand in one operation.
///
/// # Arguments
/// * `ikm` - Input key material
/// * `salt` - Salt value
/// * `info` - Context information
///
/// # Returns
/// 32-byte derived key
pub fn hkdf_extract_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key;

    #[test]
    fn test_key_derivation_deterministic() {
        let master = generate_key();
        let kdf = KeyDerivation::new(&master, Some(b"test-salt"));

        let key1 = kdf.derive_encryption_key(b"test-info").unwrap();
        let key2 = kdf.derive_encryption_key(b"test-info").unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_info_different_keys() {
        let master = generate_key();
        let kdf = KeyDerivation::new(&master, Some(b"test-salt"));

        let key1 = kdf.derive_encryption_key(b"info-1").unwrap();
        let key2 = kdf.derive_encryption_key(b"info-2").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_content_key_derivation() {
        let master = generate_key();

        let key1 = derive_content_key(&master, "QmTest123", 0).unwrap();
        let key2 = derive_content_key(&master, "QmTest123", 1).unwrap();
        let key3 = derive_content_key(&master, "QmOther", 0).unwrap();

        // Different chunks = different keys
        assert_ne!(key1, key2);
        // Different content = different keys
        assert_ne!(key1, key3);

        // Same params = same key (deterministic)
        let key1_again = derive_content_key(&master, "QmTest123", 0).unwrap();
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_chunk_nonce_derivation() {
        let master = generate_key();

        let nonce1 = derive_chunk_nonce(&master, "QmTest", 0).unwrap();
        let nonce2 = derive_chunk_nonce(&master, "QmTest", 1).unwrap();

        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 12);
    }

    #[test]
    fn test_derive_bytes_various_lengths() {
        let master = generate_key();
        let kdf = KeyDerivation::new(&master, Some(b"test-salt"));

        // Test various output lengths
        for len in [16, 32, 64, 128] {
            let bytes = kdf.derive_bytes(b"test-info", len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_derive_bytes_different_lengths_different_output() {
        let master = generate_key();
        let kdf = KeyDerivation::new(&master, Some(b"test-salt"));

        let bytes32 = kdf.derive_bytes(b"test-info", 32).unwrap();
        let bytes64 = kdf.derive_bytes(b"test-info", 64).unwrap();

        // First 32 bytes should be the same
        assert_eq!(&bytes64[..32], &bytes32[..]);
    }

    #[test]
    fn test_derive_chunk_keys_batch() {
        let master = generate_key();
        let cid = "QmTestContent";

        // Derive keys individually
        let key0 = derive_content_key(&master, cid, 0).unwrap();
        let key1 = derive_content_key(&master, cid, 1).unwrap();
        let key2 = derive_content_key(&master, cid, 2).unwrap();

        // Derive keys in batch
        let batch_keys = derive_chunk_keys(&master, cid, 0, 3).unwrap();

        assert_eq!(batch_keys.len(), 3);
        assert_eq!(batch_keys[0], key0);
        assert_eq!(batch_keys[1], key1);
        assert_eq!(batch_keys[2], key2);
    }

    #[test]
    fn test_hkdf_extract_expand_deterministic() {
        let ikm = b"input-key-material";
        let salt = b"salt-value";
        let info = b"context-info";

        let key1 = hkdf_extract_expand(ikm, salt, info);
        let key2 = hkdf_extract_expand(ikm, salt, info);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_expand_different_inputs() {
        let ikm = b"input-key-material";
        let salt = b"salt-value";

        let key1 = hkdf_extract_expand(ikm, salt, b"info1");
        let key2 = hkdf_extract_expand(ikm, salt, b"info2");
        let key3 = hkdf_extract_expand(ikm, b"other-salt", b"info1");

        assert_ne!(key1, key2); // Different info
        assert_ne!(key1, key3); // Different salt
    }

    #[test]
    fn test_kdf_with_no_salt() {
        let master = generate_key();
        let kdf_with_salt = KeyDerivation::new(&master, Some(b"salt"));
        let kdf_no_salt = KeyDerivation::new(&master, None);

        let key_with_salt = kdf_with_salt.derive_encryption_key(b"info").unwrap();
        let key_no_salt = kdf_no_salt.derive_encryption_key(b"info").unwrap();

        // Keys should be different due to different salts
        assert_ne!(key_with_salt, key_no_salt);
    }

    #[test]
    fn test_content_key_with_large_chunk_index() {
        let master = generate_key();
        let cid = "QmTest";

        let key1 = derive_content_key(&master, cid, u64::MAX / 2).unwrap();
        let key2 = derive_content_key(&master, cid, u64::MAX / 2 + 1).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_bytes_empty_info() {
        let master = generate_key();
        let kdf = KeyDerivation::new(&master, Some(b"salt"));

        let key_empty = kdf.derive_bytes(b"", 32).unwrap();
        let key_nonempty = kdf.derive_bytes(b"info", 32).unwrap();

        assert_ne!(key_empty, key_nonempty);
        assert_eq!(key_empty.len(), 32);
    }
}
