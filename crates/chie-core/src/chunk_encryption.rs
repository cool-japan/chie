//! Chunk-level encryption with per-chunk nonces for CHIE Protocol.
//!
//! This module provides:
//! - Per-chunk encryption with unique nonces
//! - Chunk key derivation from master key
//! - Streaming chunk encryption/decryption

use chie_crypto::{
    Hash, decrypt, derive_chunk_nonce as crypto_derive_nonce, derive_content_key, encrypt, hash,
};
use std::io::{self, Read, Write};
use thiserror::Error;

/// Default chunk size for encryption (256 KB).
pub const ENCRYPTED_CHUNK_SIZE: usize = 262_144;

/// Nonce size (12 bytes for ChaCha20-Poly1305).
pub const NONCE_SIZE: usize = 12;

/// Chunk encryption error.
#[derive(Debug, Error)]
pub enum ChunkEncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid chunk index")]
    InvalidChunkIndex,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// Derive a deterministic nonce for a chunk.
#[inline]
pub fn derive_chunk_nonce(
    master_key: &[u8; 32],
    content_id: &str,
    chunk_index: u64,
) -> Result<[u8; NONCE_SIZE], ChunkEncryptionError> {
    crypto_derive_nonce(master_key, content_id, chunk_index)
        .map_err(|e| ChunkEncryptionError::KeyDerivationFailed(e.to_string()))
}

/// Derive a chunk-specific key from the master key.
#[inline]
pub fn derive_chunk_key(
    master_key: &[u8; 32],
    content_id: &str,
    chunk_index: u64,
) -> Result<[u8; 32], ChunkEncryptionError> {
    derive_content_key(master_key, content_id, chunk_index)
        .map_err(|e| ChunkEncryptionError::KeyDerivationFailed(e.to_string()))
}

/// Encrypted chunk with metadata.
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    /// Chunk index.
    pub index: u64,
    /// Encrypted data.
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: [u8; NONCE_SIZE],
    /// Hash of original plaintext.
    pub plaintext_hash: Hash,
}

impl EncryptedChunk {
    /// Get the size of the encrypted data.
    #[must_use]
    #[inline]
    pub fn size(&self) -> usize {
        self.ciphertext.len()
    }

    /// Serialize to bytes.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.plaintext_hash);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChunkEncryptionError> {
        if bytes.len() < 8 + NONCE_SIZE + 32 + 4 {
            return Err(ChunkEncryptionError::InvalidNonce);
        }

        let index = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[8..8 + NONCE_SIZE]);
        let mut plaintext_hash = [0u8; 32];
        plaintext_hash.copy_from_slice(&bytes[8 + NONCE_SIZE..8 + NONCE_SIZE + 32]);
        let ciphertext_len = u32::from_le_bytes(
            bytes[8 + NONCE_SIZE + 32..8 + NONCE_SIZE + 36]
                .try_into()
                .unwrap(),
        ) as usize;

        if bytes.len() < 8 + NONCE_SIZE + 36 + ciphertext_len {
            return Err(ChunkEncryptionError::InvalidNonce);
        }

        let ciphertext = bytes[8 + NONCE_SIZE + 36..8 + NONCE_SIZE + 36 + ciphertext_len].to_vec();

        Ok(Self {
            index,
            ciphertext,
            nonce,
            plaintext_hash,
        })
    }
}

/// Chunk encryptor for streaming encryption.
pub struct ChunkEncryptor {
    master_key: [u8; 32],
    content_id: String,
    chunk_size: usize,
    current_index: u64,
}

impl ChunkEncryptor {
    /// Create a new chunk encryptor.
    #[must_use]
    #[inline]
    pub fn new(master_key: [u8; 32], content_id: impl Into<String>, chunk_size: usize) -> Self {
        Self {
            master_key,
            content_id: content_id.into(),
            chunk_size,
            current_index: 0,
        }
    }

    /// Encrypt a chunk of data.
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
    ) -> Result<EncryptedChunk, ChunkEncryptionError> {
        let index = self.current_index;
        self.current_index += 1;

        encrypt_chunk_with_index(&self.master_key, &self.content_id, index, plaintext)
    }

    /// Get the current chunk index.
    #[must_use]
    #[inline]
    pub const fn current_index(&self) -> u64 {
        self.current_index
    }

    /// Get the chunk size.
    #[must_use]
    #[inline]
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Reset the chunk index.
    #[inline]
    pub fn reset(&mut self) {
        self.current_index = 0;
    }
}

/// Encrypt a single chunk with a specific index.
pub fn encrypt_chunk_with_index(
    master_key: &[u8; 32],
    content_id: &str,
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<EncryptedChunk, ChunkEncryptionError> {
    // Derive chunk-specific key
    let chunk_key = derive_chunk_key(master_key, content_id, chunk_index)?;

    // Generate deterministic nonce
    let nonce = derive_chunk_nonce(master_key, content_id, chunk_index)?;

    // Hash plaintext for integrity verification
    let plaintext_hash = hash(plaintext);

    // Encrypt (encrypt takes: data, key, nonce)
    let ciphertext = encrypt(plaintext, &chunk_key, &nonce)
        .map_err(|e| ChunkEncryptionError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedChunk {
        index: chunk_index,
        ciphertext,
        nonce,
        plaintext_hash,
    })
}

/// Decrypt a single chunk.
pub fn decrypt_chunk(
    master_key: &[u8; 32],
    content_id: &str,
    chunk: &EncryptedChunk,
) -> Result<Vec<u8>, ChunkEncryptionError> {
    // Derive chunk-specific key
    let chunk_key = derive_chunk_key(master_key, content_id, chunk.index)?;

    // Verify nonce matches expected
    let expected_nonce = derive_chunk_nonce(master_key, content_id, chunk.index)?;
    if chunk.nonce != expected_nonce {
        return Err(ChunkEncryptionError::InvalidNonce);
    }

    // Decrypt (decrypt takes: ciphertext, key, nonce)
    let plaintext = decrypt(&chunk.ciphertext, &chunk_key, &chunk.nonce)
        .map_err(|e| ChunkEncryptionError::DecryptionFailed(e.to_string()))?;

    // Verify plaintext hash
    let computed_hash = hash(&plaintext);
    if computed_hash != chunk.plaintext_hash {
        return Err(ChunkEncryptionError::DecryptionFailed(
            "Plaintext hash mismatch".to_string(),
        ));
    }

    Ok(plaintext)
}

/// Chunk decryptor for streaming decryption.
pub struct ChunkDecryptor {
    master_key: [u8; 32],
    content_id: String,
}

impl ChunkDecryptor {
    /// Create a new chunk decryptor.
    #[must_use]
    #[inline]
    pub fn new(master_key: [u8; 32], content_id: impl Into<String>) -> Self {
        Self {
            master_key,
            content_id: content_id.into(),
        }
    }

    /// Decrypt a chunk.
    pub fn decrypt_chunk(&self, chunk: &EncryptedChunk) -> Result<Vec<u8>, ChunkEncryptionError> {
        decrypt_chunk(&self.master_key, &self.content_id, chunk)
    }
}

/// Encrypt content from a reader to encrypted chunks.
pub fn encrypt_content<R: Read>(
    master_key: &[u8; 32],
    content_id: &str,
    reader: &mut R,
    chunk_size: usize,
) -> Result<Vec<EncryptedChunk>, ChunkEncryptionError> {
    let mut encryptor = ChunkEncryptor::new(*master_key, content_id, chunk_size);
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let mut total_read = 0;

        while total_read < chunk_size {
            let bytes_read = reader.read(&mut buffer[total_read..])?;
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        if total_read == 0 {
            break;
        }

        let chunk = encryptor.encrypt_chunk(&buffer[..total_read])?;
        chunks.push(chunk);

        if total_read < chunk_size {
            break;
        }
    }

    Ok(chunks)
}

/// Decrypt chunks to a writer.
pub fn decrypt_content<W: Write>(
    master_key: &[u8; 32],
    content_id: &str,
    chunks: &[EncryptedChunk],
    writer: &mut W,
) -> Result<u64, ChunkEncryptionError> {
    let decryptor = ChunkDecryptor::new(*master_key, content_id);
    let mut total_written = 0u64;

    for chunk in chunks {
        let plaintext = decryptor.decrypt_chunk(chunk)?;
        writer.write_all(&plaintext)?;
        total_written += plaintext.len() as u64;
    }

    Ok(total_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_derive_chunk_nonce() {
        let master_key = [0u8; 32];
        let content_id = "QmTest123";

        let nonce1 = derive_chunk_nonce(&master_key, content_id, 0).unwrap();
        let nonce2 = derive_chunk_nonce(&master_key, content_id, 1).unwrap();
        let nonce3 = derive_chunk_nonce(&master_key, content_id, 0).unwrap();

        assert_ne!(nonce1, nonce2); // Different indices = different nonces
        assert_eq!(nonce1, nonce3); // Same inputs = same nonce
    }

    #[test]
    fn test_derive_chunk_key() {
        let master_key = [0u8; 32];
        let content_id = "QmTest123";

        let key1 = derive_chunk_key(&master_key, content_id, 0).unwrap();
        let key2 = derive_chunk_key(&master_key, content_id, 1).unwrap();

        assert_ne!(key1, key2); // Different indices = different keys
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let master_key = [1u8; 32];
        let content_id = "QmTest123";
        let plaintext = b"Hello, CHIE Protocol!";

        let chunk = encrypt_chunk_with_index(&master_key, content_id, 0, plaintext).unwrap();
        let decrypted = decrypt_chunk(&master_key, content_id, &chunk).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chunk_encryptor() {
        let master_key = [2u8; 32];
        let content_id = "QmTest456";

        let mut encryptor = ChunkEncryptor::new(master_key, content_id, 1024);

        let chunk1 = encryptor.encrypt_chunk(b"Chunk 1").unwrap();
        let chunk2 = encryptor.encrypt_chunk(b"Chunk 2").unwrap();

        assert_eq!(chunk1.index, 0);
        assert_eq!(chunk2.index, 1);
        assert_ne!(chunk1.nonce, chunk2.nonce);
    }

    #[test]
    fn test_encrypt_content() {
        let master_key = [3u8; 32];
        let content_id = "QmContent";
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut cursor = Cursor::new(data);

        let chunks = encrypt_content(&master_key, content_id, &mut cursor, 10).unwrap();

        assert_eq!(chunks.len(), 3); // 26 bytes / 10 = 3 chunks

        // Decrypt and verify
        let mut output = Vec::new();
        decrypt_content(&master_key, content_id, &chunks, &mut output).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn test_encrypted_chunk_serialization() {
        let master_key = [4u8; 32];
        let content_id = "QmSerial";

        let chunk = encrypt_chunk_with_index(&master_key, content_id, 42, b"Test data").unwrap();

        let bytes = chunk.to_bytes();
        let deserialized = EncryptedChunk::from_bytes(&bytes).unwrap();

        assert_eq!(chunk.index, deserialized.index);
        assert_eq!(chunk.nonce, deserialized.nonce);
        assert_eq!(chunk.plaintext_hash, deserialized.plaintext_hash);
        assert_eq!(chunk.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_different_chunks_different_keys() {
        let master_key = [5u8; 32];
        let content_id = "QmDiffKeys";

        let chunk1 = encrypt_chunk_with_index(&master_key, content_id, 0, b"Same data").unwrap();
        let chunk2 = encrypt_chunk_with_index(&master_key, content_id, 1, b"Same data").unwrap();

        // Same plaintext but different chunks should produce different ciphertext
        assert_ne!(chunk1.ciphertext, chunk2.ciphertext);
    }
}
