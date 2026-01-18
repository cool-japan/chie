//! Utility functions and convenience wrappers for common cryptographic operations.

use crate::{
    EncryptionError, EncryptionKey, EncryptionNonce, Hash, KeyPair, PublicKey, SignatureBytes,
    SigningError, decrypt, encrypt, generate_key, generate_nonce, hash, verify,
};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use thiserror::Error;

/// Errors for utility operations.
#[derive(Debug, Error)]
pub enum UtilError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),
}

/// Result type for utility operations.
pub type UtilResult<T> = Result<T, UtilError>;

/// Encrypted message with metadata.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// The ciphertext.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: EncryptionNonce,
    /// Optional hash of the original plaintext for integrity checking.
    pub plaintext_hash: Option<Hash>,
}

impl EncryptedMessage {
    /// Create a new encrypted message.
    pub fn new(ciphertext: Vec<u8>, nonce: EncryptionNonce) -> Self {
        Self {
            ciphertext,
            nonce,
            plaintext_hash: None,
        }
    }

    /// Create with plaintext hash.
    pub fn with_hash(ciphertext: Vec<u8>, nonce: EncryptionNonce, plaintext_hash: Hash) -> Self {
        Self {
            ciphertext,
            nonce,
            plaintext_hash: Some(plaintext_hash),
        }
    }

    /// Get the total size (ciphertext + nonce + optional hash).
    pub fn total_size(&self) -> usize {
        self.ciphertext.len() + 12 + if self.plaintext_hash.is_some() { 32 } else { 0 }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        if let Some(hash) = &self.plaintext_hash {
            bytes.extend_from_slice(hash);
        }
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8], with_hash: bool) -> UtilResult<Self> {
        if bytes.len() < 12 {
            return Err(UtilError::InvalidFormat(
                "Too short for encrypted message".to_string(),
            ));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[0..12]);

        let ciphertext_end = if with_hash {
            if bytes.len() < 44 {
                return Err(UtilError::InvalidFormat(
                    "Too short for encrypted message with hash".to_string(),
                ));
            }
            bytes.len() - 32
        } else {
            bytes.len()
        };

        let ciphertext = bytes[12..ciphertext_end].to_vec();

        let plaintext_hash = if with_hash {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[ciphertext_end..]);
            Some(hash)
        } else {
            None
        };

        Ok(Self {
            ciphertext,
            nonce,
            plaintext_hash,
        })
    }
}

/// Signed message with signature.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    /// The message content.
    pub message: Vec<u8>,
    /// The signature.
    pub signature: SignatureBytes,
    /// The public key of the signer.
    pub public_key: PublicKey,
}

impl SignedMessage {
    /// Create a new signed message.
    pub fn new(message: Vec<u8>, signature: SignatureBytes, public_key: PublicKey) -> Self {
        Self {
            message,
            signature,
            public_key,
        }
    }

    /// Sign a message with a keypair.
    pub fn sign(message: Vec<u8>, keypair: &KeyPair) -> Self {
        let signature = keypair.sign(&message);
        let public_key = keypair.public_key();
        Self::new(message, signature, public_key)
    }

    /// Verify the signature.
    pub fn verify(&self) -> Result<(), SigningError> {
        verify(&self.public_key, &self.message, &self.signature)
    }

    /// Serialize to bytes (message + signature + public_key).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.message.len() + 64 + 32);
        bytes.extend_from_slice(&(self.message.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.message);
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> UtilResult<Self> {
        if bytes.len() < 100 {
            // 4 (len) + at least 1 byte message + 64 (sig) + 32 (pubkey)
            return Err(UtilError::InvalidFormat(
                "Too short for signed message".to_string(),
            ));
        }

        let msg_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + msg_len + 64 + 32 {
            return Err(UtilError::InvalidFormat(
                "Invalid signed message length".to_string(),
            ));
        }

        let message = bytes[4..4 + msg_len].to_vec();

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[4 + msg_len..4 + msg_len + 64]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[4 + msg_len + 64..4 + msg_len + 96]);

        Ok(Self {
            message,
            signature,
            public_key,
        })
    }
}

/// Encrypt and sign a message (encrypt-then-sign pattern).
#[derive(Debug, Clone)]
pub struct EncryptedAndSigned {
    /// The encrypted message.
    pub encrypted: EncryptedMessage,
    /// The signature over the ciphertext.
    pub signature: SignatureBytes,
    /// The public key of the signer.
    pub signer_public_key: PublicKey,
}

impl EncryptedAndSigned {
    /// Create by encrypting and signing.
    pub fn create(
        plaintext: &[u8],
        encryption_key: &EncryptionKey,
        signing_keypair: &KeyPair,
    ) -> UtilResult<Self> {
        // Generate nonce and encrypt
        let nonce = generate_nonce();
        let ciphertext = encrypt(plaintext, encryption_key, &nonce)?;

        // Hash the plaintext for integrity
        let plaintext_hash = hash(plaintext);

        // Create encrypted message
        let encrypted = EncryptedMessage::with_hash(ciphertext, nonce, plaintext_hash);

        // Sign the ciphertext
        let signature = signing_keypair.sign(&encrypted.ciphertext);
        let signer_public_key = signing_keypair.public_key();

        Ok(Self {
            encrypted,
            signature,
            signer_public_key,
        })
    }

    /// Verify signature and decrypt.
    pub fn verify_and_decrypt(&self, decryption_key: &EncryptionKey) -> UtilResult<Vec<u8>> {
        // Verify signature first
        verify(
            &self.signer_public_key,
            &self.encrypted.ciphertext,
            &self.signature,
        )?;

        // Decrypt
        let plaintext = decrypt(
            &self.encrypted.ciphertext,
            decryption_key,
            &self.encrypted.nonce,
        )?;

        // Verify plaintext hash if available
        if let Some(expected_hash) = &self.encrypted.plaintext_hash {
            let actual_hash = hash(&plaintext);
            if &actual_hash != expected_hash {
                return Err(UtilError::InvalidFormat(
                    "Plaintext hash mismatch".to_string(),
                ));
            }
        }

        Ok(plaintext)
    }
}

/// Encrypt a file.
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &EncryptionKey,
) -> UtilResult<EncryptionNonce> {
    let mut file = File::open(input_path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    let nonce = generate_nonce();
    let ciphertext = encrypt(&plaintext, key, &nonce)?;

    let mut output = File::create(output_path)?;
    output.write_all(&nonce)?;
    output.write_all(&ciphertext)?;

    Ok(nonce)
}

/// Decrypt a file.
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &EncryptionKey,
) -> UtilResult<()> {
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < 12 {
        return Err(UtilError::InvalidFormat(
            "File too short to contain nonce".to_string(),
        ));
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[0..12]);

    let ciphertext = &data[12..];
    let plaintext = decrypt(ciphertext, key, &nonce)?;

    let mut output = File::create(output_path)?;
    output.write_all(&plaintext)?;

    Ok(())
}

/// Generate a random key and save it to a file (for testing/development).
pub fn generate_and_save_key(path: impl AsRef<Path>) -> UtilResult<EncryptionKey> {
    let key = generate_key();
    let mut file = File::create(path)?;
    file.write_all(&key)?;
    Ok(key)
}

/// Load a key from a file.
pub fn load_key(path: impl AsRef<Path>) -> UtilResult<EncryptionKey> {
    let mut file = File::open(path)?;
    let mut key = [0u8; 32];
    file.read_exact(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypted_message_roundtrip() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        let msg = EncryptedMessage::new(ciphertext, nonce);

        let bytes = msg.to_bytes();
        let restored = EncryptedMessage::from_bytes(&bytes, false).unwrap();

        assert_eq!(msg.nonce, restored.nonce);
        assert_eq!(msg.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_encrypted_message_with_hash() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";
        let plaintext_hash = hash(plaintext);

        let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
        let msg = EncryptedMessage::with_hash(ciphertext, nonce, plaintext_hash);

        let bytes = msg.to_bytes();
        let restored = EncryptedMessage::from_bytes(&bytes, true).unwrap();

        assert_eq!(msg.plaintext_hash, restored.plaintext_hash);
    }

    #[test]
    fn test_signed_message_roundtrip() {
        let keypair = KeyPair::generate();
        let message = b"Test message".to_vec();

        let signed = SignedMessage::sign(message.clone(), &keypair);
        assert!(signed.verify().is_ok());

        let bytes = signed.to_bytes();
        let restored = SignedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(signed.message, restored.message);
        assert_eq!(signed.signature, restored.signature);
        assert_eq!(signed.public_key, restored.public_key);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn test_encrypted_and_signed() {
        let encryption_key = generate_key();
        let signing_keypair = KeyPair::generate();
        let plaintext = b"Secure message";

        let encrypted_signed =
            EncryptedAndSigned::create(plaintext, &encryption_key, &signing_keypair).unwrap();

        let decrypted = encrypted_signed
            .verify_and_decrypt(&encryption_key)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_file_encryption() {
        let key = generate_key();

        // Create temp files
        let mut input_file = NamedTempFile::new().unwrap();
        let output_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        let plaintext = b"This is a test file content";
        input_file.write_all(plaintext).unwrap();
        input_file.flush().unwrap();

        // Encrypt
        encrypt_file(input_file.path(), output_file.path(), &key).unwrap();

        // Decrypt
        decrypt_file(output_file.path(), decrypted_file.path(), &key).unwrap();

        // Verify
        let mut decrypted = Vec::new();
        File::open(decrypted_file.path())
            .unwrap()
            .read_to_end(&mut decrypted)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_save_load() {
        let key_file = NamedTempFile::new().unwrap();

        let original_key = generate_and_save_key(key_file.path()).unwrap();
        let loaded_key = load_key(key_file.path()).unwrap();

        assert_eq!(original_key, loaded_key);
    }
}
