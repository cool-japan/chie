//! Content encryption using ChaCha20-Poly1305.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::Rng as _;
use thiserror::Error;

/// Encryption key (256 bits).
pub type EncryptionKey = [u8; 32];

/// Nonce for encryption (96 bits).
pub type EncryptionNonce = [u8; 12];

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Generate a random encryption key.
pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Generate a random nonce.
pub fn generate_nonce() -> EncryptionNonce {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data using ChaCha20-Poly1305.
pub fn encrypt(
    data: &[u8],
    key: &EncryptionKey,
    nonce: &EncryptionNonce,
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, data)
        .map_err(|_| EncryptionError::EncryptionFailed)
}

/// Decrypt data using ChaCha20-Poly1305.
pub fn decrypt(
    ciphertext: &[u8],
    key: &EncryptionKey,
    nonce: &EncryptionNonce,
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, CHIE Protocol!";

        let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = generate_key();
        let key2 = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Secret message";

        let ciphertext = encrypt(plaintext, &key1, &nonce).unwrap();
        let result = decrypt(&ciphertext, &key2, &nonce);

        assert!(result.is_err());
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_with_wrong_nonce() {
        let key = generate_key();
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        let plaintext = b"Secret message";

        let ciphertext = encrypt(plaintext, &key, &nonce1).unwrap();
        let result = decrypt(&ciphertext, &key, &nonce2);

        assert!(result.is_err());
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_nonce_reuse_different_plaintexts() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext1 = b"First message";
        let plaintext2 = b"Second message";

        // Same nonce, different plaintexts produce different ciphertexts
        let ciphertext1 = encrypt(plaintext1, &key, &nonce).unwrap();
        let ciphertext2 = encrypt(plaintext2, &key, &nonce).unwrap();

        assert_ne!(ciphertext1, ciphertext2);

        // Both can be decrypted correctly (though nonce reuse is bad practice)
        let decrypted1 = decrypt(&ciphertext1, &key, &nonce).unwrap();
        let decrypted2 = decrypt(&ciphertext2, &key, &nonce).unwrap();

        assert_eq!(plaintext1.as_slice(), decrypted1.as_slice());
        assert_eq!(plaintext2.as_slice(), decrypted2.as_slice());
    }

    #[test]
    fn test_empty_data_encryption() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"";

        let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        // ChaCha20-Poly1305 adds authentication tag even for empty data
        assert!(!ciphertext.is_empty());
    }

    #[test]
    fn test_large_data_encryption() {
        let key = generate_key();
        let nonce = generate_nonce();
        // Test with 1MB of data
        let plaintext = vec![0x42u8; 1024 * 1024];

        let ciphertext = encrypt(&plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
        // Ciphertext should be plaintext + 16 bytes (Poly1305 tag)
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Important message";

        let mut ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        // Corrupt one byte
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_key_generation_randomness() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();

        // Keys should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);

        // Keys should not be all zeros
        assert_ne!(key1, [0u8; 32]);
        assert_ne!(key2, [0u8; 32]);
    }

    #[test]
    fn test_nonce_generation_randomness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        let nonce3 = generate_nonce();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);

        // Nonces should not be all zeros
        assert_ne!(nonce1, [0u8; 12]);
        assert_ne!(nonce2, [0u8; 12]);
    }

    #[test]
    fn test_deterministic_encryption_same_inputs() {
        let key = generate_key();
        let nonce = [0u8; 12]; // Fixed nonce for determinism test
        let plaintext = b"Deterministic test";

        let ciphertext1 = encrypt(plaintext, &key, &nonce).unwrap();
        let ciphertext2 = encrypt(plaintext, &key, &nonce).unwrap();

        // Same key, nonce, and plaintext should produce same ciphertext
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_truncated_ciphertext() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Test message for truncation";

        let mut ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        // Truncate the ciphertext (remove authentication tag)
        ciphertext.truncate(ciphertext.len() - 10);

        let result = decrypt(&ciphertext, &key, &nonce);
        assert!(result.is_err());
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }
}
