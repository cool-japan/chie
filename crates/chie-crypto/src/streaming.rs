//! Streaming encryption for large content.
//!
//! This module provides chunk-by-chunk encryption/decryption for
//! processing large files without loading them entirely into memory.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use thiserror::Error;

use crate::{EncryptionKey, EncryptionNonce};

/// Default chunk size for streaming (256 KB).
pub const STREAM_CHUNK_SIZE: usize = 256 * 1024;

/// Authentication tag size (16 bytes for Poly1305).
pub const AUTH_TAG_SIZE: usize = 16;

/// Streaming encryption error.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid chunk index: expected {expected}, got {actual}")]
    InvalidChunkIndex { expected: u64, actual: u64 },

    #[error("Chunk too large: {size} bytes (max: {max})")]
    ChunkTooLarge { size: usize, max: usize },

    #[error("Invalid nonce")]
    InvalidNonce,
}

/// Streaming encryptor for large content.
pub struct StreamEncryptor {
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; 12],
    chunk_index: u64,
}

impl StreamEncryptor {
    /// Create a new streaming encryptor.
    ///
    /// # Arguments
    /// * `key` - 256-bit encryption key
    /// * `base_nonce` - Base nonce (will be XOR'd with chunk index for each chunk)
    pub fn new(key: &EncryptionKey, base_nonce: &EncryptionNonce) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            cipher,
            base_nonce: *base_nonce,
            chunk_index: 0,
        }
    }

    /// Encrypt the next chunk.
    ///
    /// Returns the ciphertext with authentication tag appended.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, StreamError> {
        if plaintext.len() > STREAM_CHUNK_SIZE {
            return Err(StreamError::ChunkTooLarge {
                size: plaintext.len(),
                max: STREAM_CHUNK_SIZE,
            });
        }

        let nonce = self.derive_chunk_nonce(self.chunk_index);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| StreamError::EncryptionFailed(e.to_string()))?;

        self.chunk_index += 1;
        Ok(ciphertext)
    }

    /// Encrypt a chunk at a specific index (for random access).
    pub fn encrypt_chunk_at(
        &self,
        plaintext: &[u8],
        chunk_index: u64,
    ) -> Result<Vec<u8>, StreamError> {
        if plaintext.len() > STREAM_CHUNK_SIZE {
            return Err(StreamError::ChunkTooLarge {
                size: plaintext.len(),
                max: STREAM_CHUNK_SIZE,
            });
        }

        let nonce = self.derive_chunk_nonce(chunk_index);
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| StreamError::EncryptionFailed(e.to_string()))
    }

    /// Get the current chunk index.
    pub fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    /// Reset the chunk index (for re-encrypting).
    pub fn reset(&mut self) {
        self.chunk_index = 0;
    }

    /// Derive a unique nonce for each chunk.
    fn derive_chunk_nonce(&self, chunk_index: u64) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        // XOR the chunk index into the last 8 bytes of the nonce
        let index_bytes = chunk_index.to_le_bytes();
        for (i, &b) in index_bytes.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }
}

/// Streaming decryptor for large content.
pub struct StreamDecryptor {
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; 12],
    chunk_index: u64,
}

impl StreamDecryptor {
    /// Create a new streaming decryptor.
    pub fn new(key: &EncryptionKey, base_nonce: &EncryptionNonce) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        Self {
            cipher,
            base_nonce: *base_nonce,
            chunk_index: 0,
        }
    }

    /// Decrypt the next chunk.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, StreamError> {
        let nonce = self.derive_chunk_nonce(self.chunk_index);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|e| StreamError::DecryptionFailed(e.to_string()))?;

        self.chunk_index += 1;
        Ok(plaintext)
    }

    /// Decrypt a chunk at a specific index (for random access).
    pub fn decrypt_chunk_at(
        &self,
        ciphertext: &[u8],
        chunk_index: u64,
    ) -> Result<Vec<u8>, StreamError> {
        let nonce = self.derive_chunk_nonce(chunk_index);
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|e| StreamError::DecryptionFailed(e.to_string()))
    }

    /// Get the current chunk index.
    pub fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    /// Reset the chunk index.
    pub fn reset(&mut self) {
        self.chunk_index = 0;
    }

    /// Derive a unique nonce for each chunk.
    fn derive_chunk_nonce(&self, chunk_index: u64) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        let index_bytes = chunk_index.to_le_bytes();
        for (i, &b) in index_bytes.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }
}

/// Encrypt an entire buffer in chunks, returning all encrypted chunks.
pub fn encrypt_chunked(
    data: &[u8],
    key: &EncryptionKey,
    base_nonce: &EncryptionNonce,
    chunk_size: usize,
) -> Result<Vec<Vec<u8>>, StreamError> {
    let mut encryptor = StreamEncryptor::new(key, base_nonce);
    let mut chunks = Vec::new();

    for chunk in data.chunks(chunk_size) {
        chunks.push(encryptor.encrypt_chunk(chunk)?);
    }

    Ok(chunks)
}

/// Decrypt encrypted chunks back into the original buffer.
pub fn decrypt_chunked(
    chunks: &[Vec<u8>],
    key: &EncryptionKey,
    base_nonce: &EncryptionNonce,
) -> Result<Vec<u8>, StreamError> {
    let mut decryptor = StreamDecryptor::new(key, base_nonce);
    let mut data = Vec::new();

    for chunk in chunks {
        data.extend(decryptor.decrypt_chunk(chunk)?);
    }

    Ok(data)
}

/// Calculate the encrypted size of a chunk (plaintext + auth tag).
pub fn encrypted_chunk_size(plaintext_size: usize) -> usize {
    plaintext_size + AUTH_TAG_SIZE
}

/// Calculate the number of chunks for a given data size.
pub fn chunk_count(data_size: usize, chunk_size: usize) -> usize {
    data_size.div_ceil(chunk_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_key, generate_nonce};

    #[test]
    fn test_streaming_encrypt_decrypt() {
        let key = generate_key();
        let nonce = generate_nonce();
        let data = b"Hello, World! This is a test of streaming encryption.";

        let mut encryptor = StreamEncryptor::new(&key, &nonce);
        let mut decryptor = StreamDecryptor::new(&key, &nonce);

        let ciphertext = encryptor.encrypt_chunk(data).unwrap();
        let plaintext = decryptor.decrypt_chunk(&ciphertext).unwrap();

        assert_eq!(plaintext, data);
    }

    #[test]
    fn test_multiple_chunks() {
        let key = generate_key();
        let nonce = generate_nonce();

        let chunks_data = vec![
            b"Chunk 1".to_vec(),
            b"Chunk 2 with more data".to_vec(),
            b"Chunk 3".to_vec(),
        ];

        let mut encryptor = StreamEncryptor::new(&key, &nonce);
        let mut encrypted: Vec<Vec<u8>> = Vec::new();

        for chunk in &chunks_data {
            encrypted.push(encryptor.encrypt_chunk(chunk).unwrap());
        }

        let mut decryptor = StreamDecryptor::new(&key, &nonce);
        for (i, ciphertext) in encrypted.iter().enumerate() {
            let plaintext = decryptor.decrypt_chunk(ciphertext).unwrap();
            assert_eq!(plaintext, chunks_data[i]);
        }
    }

    #[test]
    fn test_random_access() {
        let key = generate_key();
        let nonce = generate_nonce();

        let encryptor = StreamEncryptor::new(&key, &nonce);
        let decryptor = StreamDecryptor::new(&key, &nonce);

        let data = b"Test data for random access";

        // Encrypt at specific indices
        let ct0 = encryptor.encrypt_chunk_at(data, 0).unwrap();
        let ct5 = encryptor.encrypt_chunk_at(data, 5).unwrap();
        let ct10 = encryptor.encrypt_chunk_at(data, 10).unwrap();

        // Decrypt in different order
        assert_eq!(decryptor.decrypt_chunk_at(&ct10, 10).unwrap(), data);
        assert_eq!(decryptor.decrypt_chunk_at(&ct0, 0).unwrap(), data);
        assert_eq!(decryptor.decrypt_chunk_at(&ct5, 5).unwrap(), data);
    }

    #[test]
    fn test_chunked_encryption() {
        let key = generate_key();
        let nonce = generate_nonce();
        let data = vec![0u8; 1000]; // 1000 bytes

        let encrypted = encrypt_chunked(&data, &key, &nonce, 256).unwrap();
        assert_eq!(encrypted.len(), 4); // ceil(1000/256) = 4 chunks

        let decrypted = decrypt_chunked(&encrypted, &key, &nonce).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_different_nonces_per_chunk() {
        let key = generate_key();
        let nonce = generate_nonce();
        let data = b"Same data";

        let encryptor = StreamEncryptor::new(&key, &nonce);

        // Same data encrypted at different indices should produce different ciphertext
        let ct0 = encryptor.encrypt_chunk_at(data, 0).unwrap();
        let ct1 = encryptor.encrypt_chunk_at(data, 1).unwrap();

        assert_ne!(ct0, ct1);
    }
}
