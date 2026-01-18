//! Identity-Based Encryption (IBE) for simplified key management.
//!
//! IBE allows deriving public keys directly from arbitrary identities (email, node ID, etc.)
//! without requiring a certificate infrastructure. This is particularly useful for P2P systems
//! where nodes join and leave dynamically.
//!
//! This implementation uses a simplified hash-based IBE scheme suitable for the CHIE protocol:
//! - Master key authority generates public parameters
//! - User secret keys are derived from identity strings using HKDF
//! - Encryption uses hybrid encryption (X25519 + ChaCha20-Poly1305)
//! - Identity-based key derivation simplifies key distribution
//!
//! # Example
//!
//! ```
//! use chie_crypto::ibe::{IbeMaster, IbeParams};
//!
//! // Setup: Master authority generates public parameters
//! let master = IbeMaster::generate();
//! let params = master.public_params();
//!
//! // Extract user secret key for an identity
//! let alice_id = "alice@example.com";
//! let alice_sk = master.extract_secret_key(alice_id);
//!
//! // Encrypt to Alice using only her identity
//! let plaintext = b"Secret message for Alice";
//! let ciphertext = params.encrypt(alice_id, plaintext).unwrap();
//!
//! // Alice decrypts using her secret key
//! let decrypted = alice_sk.decrypt(&ciphertext).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_bytes());
//! ```

use crate::zeroizing::SecureBuffer;
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for IBE operations.
pub type IbeResult<T> = Result<T, IbeError>;

/// Errors that can occur during IBE operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbeError {
    /// Invalid identity string
    InvalidIdentity,
    /// Decryption failed
    DecryptionFailed,
    /// Serialization failed
    SerializationFailed,
    /// Deserialization failed
    DeserializationFailed,
    /// Invalid ciphertext
    InvalidCiphertext,
}

impl fmt::Display for IbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IbeError::InvalidIdentity => write!(f, "Invalid identity string"),
            IbeError::DecryptionFailed => write!(f, "Decryption failed"),
            IbeError::SerializationFailed => write!(f, "Serialization failed"),
            IbeError::DeserializationFailed => write!(f, "Deserialization failed"),
            IbeError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
        }
    }
}

impl std::error::Error for IbeError {}

/// Master secret key for IBE system.
///
/// The master authority holds this key and uses it to extract user secret keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IbeMasterKey {
    /// Master secret scalar
    #[zeroize(skip)]
    master_secret: Scalar,
}

/// Public parameters for IBE system.
///
/// These parameters are public and used by anyone to encrypt messages to identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbeParams {
    /// Master public point = master_secret * G
    #[serde(with = "serde_ristretto_point")]
    master_public: RistrettoPoint,
}

/// IBE master authority.
///
/// Holds the master secret key and can extract user secret keys for any identity.
pub struct IbeMaster {
    /// Master secret key
    master_key: IbeMasterKey,
    /// Public parameters
    params: IbeParams,
}

/// User secret key for a specific identity.
///
/// Derived by the master authority from the user's identity string.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IbeSecretKey {
    /// Identity string
    identity: String,
    /// Derived secret scalar
    #[zeroize(skip)]
    secret: Scalar,
    /// Public parameters (needed for decryption)
    #[zeroize(skip)]
    params: IbeParams,
}

/// IBE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct IbeCiphertext {
    /// Ephemeral public point
    #[serde(with = "serde_ristretto_point")]
    ephemeral: RistrettoPoint,
    /// Encrypted data
    ciphertext: Vec<u8>,
    /// Nonce for ChaCha20-Poly1305
    nonce: [u8; 12],
}

impl IbeMaster {
    /// Generate a new IBE master authority.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut master_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut master_secret_bytes);
        let master_secret = Scalar::from_bytes_mod_order(master_secret_bytes);
        let master_public = master_secret * RISTRETTO_BASEPOINT_POINT;

        let master_key = IbeMasterKey { master_secret };
        let params = IbeParams { master_public };

        Self { master_key, params }
    }

    /// Get the public parameters.
    pub fn public_params(&self) -> IbeParams {
        self.params.clone()
    }

    /// Extract a secret key for a given identity.
    ///
    /// The identity can be any string (email, node ID, etc.).
    pub fn extract_secret_key(&self, identity: &str) -> IbeSecretKey {
        // Hash the identity to a scalar
        let identity_hash = hash_identity_to_scalar(identity);

        // Secret key = master_secret * H(identity)
        let secret = self.master_key.master_secret * identity_hash;

        IbeSecretKey {
            identity: identity.to_string(),
            secret,
            params: self.params.clone(),
        }
    }

    /// Get the master secret key (for serialization/backup).
    pub fn master_key(&self) -> &IbeMasterKey {
        &self.master_key
    }
}

impl IbeParams {
    /// Encrypt a message to a specific identity.
    pub fn encrypt(&self, identity: &str, plaintext: &[u8]) -> IbeResult<IbeCiphertext> {
        let mut rng = rand::thread_rng();

        // Generate ephemeral key pair
        let mut ephemeral_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = Scalar::from_bytes_mod_order(ephemeral_secret_bytes);
        let ephemeral = ephemeral_secret * RISTRETTO_BASEPOINT_POINT;

        // Compute identity point
        let identity_hash = hash_identity_to_scalar(identity);
        let identity_point = identity_hash * self.master_public;

        // Shared secret = ephemeral_secret * identity_point
        let shared_point = ephemeral_secret * identity_point;

        // Derive encryption key from shared point
        let encryption_key = derive_encryption_key(&shared_point);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&encryption_key.into());
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| IbeError::DecryptionFailed)?;

        Ok(IbeCiphertext {
            ephemeral,
            ciphertext,
            nonce: nonce_bytes,
        })
    }
}

impl IbeSecretKey {
    /// Decrypt a ciphertext using this secret key.
    pub fn decrypt(&self, ciphertext: &IbeCiphertext) -> IbeResult<SecureBuffer> {
        // Shared secret = secret * ephemeral
        let shared_point = self.secret * ciphertext.ephemeral;

        // Derive decryption key from shared point
        let decryption_key = derive_encryption_key(&shared_point);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&decryption_key.into());
        let nonce = chacha20poly1305::Nonce::from(ciphertext.nonce);

        let plaintext = cipher
            .decrypt(&nonce, ciphertext.ciphertext.as_ref())
            .map_err(|_| IbeError::DecryptionFailed)?;

        Ok(SecureBuffer::from(plaintext))
    }

    /// Get the identity associated with this secret key.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Serialize the secret key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(&(&self.identity, self.secret.to_bytes(), &self.params))
            .unwrap_or_default()
    }

    /// Deserialize a secret key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> IbeResult<Self> {
        let (identity, secret_bytes, params): (String, [u8; 32], IbeParams) =
            crate::codec::decode(bytes).map_err(|_| IbeError::DeserializationFailed)?;

        let secret = Scalar::from_bytes_mod_order(secret_bytes);

        Ok(Self {
            identity,
            secret,
            params,
        })
    }
}

impl IbeCiphertext {
    /// Serialize the ciphertext to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).unwrap_or_default()
    }

    /// Deserialize a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> IbeResult<Self> {
        crate::codec::decode(bytes).map_err(|_| IbeError::DeserializationFailed)
    }
}

/// Hash an identity string to a scalar using BLAKE3.
fn hash_identity_to_scalar(identity: &str) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(b"IBE-Identity-Hash:");
    hasher.update(identity.as_bytes());
    let hash = hasher.finalize();

    // Use first 32 bytes of hash as scalar
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash.as_bytes()[..32]);

    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Derive an encryption key from a shared point.
fn derive_encryption_key(point: &RistrettoPoint) -> [u8; 32] {
    let point_bytes = point.compress().to_bytes();

    let mut hasher = Hasher::new();
    hasher.update(b"IBE-Key-Derivation:");
    hasher.update(&point_bytes);
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.as_bytes()[..32]);
    key
}

// Custom serde for RistrettoPoint
mod serde_ristretto_point {
    use curve25519_dalek::RistrettoPoint;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        point.compress().to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(bytes);
        compressed
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("Invalid RistrettoPoint"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ibe_basic() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let alice_id = "alice@example.com";
        let alice_sk = master.extract_secret_key(alice_id);

        let plaintext = b"Secret message for Alice";
        let ciphertext = params.encrypt(alice_id, plaintext).unwrap();

        let decrypted = alice_sk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_bytes());
    }

    #[test]
    fn test_ibe_multiple_users() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let alice_sk = master.extract_secret_key("alice@example.com");
        let bob_sk = master.extract_secret_key("bob@example.com");

        let msg_for_alice = b"Message for Alice";
        let msg_for_bob = b"Message for Bob";

        let ct_alice = params.encrypt("alice@example.com", msg_for_alice).unwrap();
        let ct_bob = params.encrypt("bob@example.com", msg_for_bob).unwrap();

        let dec_alice = alice_sk.decrypt(&ct_alice).unwrap();
        let dec_bob = bob_sk.decrypt(&ct_bob).unwrap();

        assert_eq!(msg_for_alice.as_slice(), dec_alice.as_bytes());
        assert_eq!(msg_for_bob.as_slice(), dec_bob.as_bytes());
    }

    #[test]
    fn test_ibe_wrong_key() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let _alice_sk = master.extract_secret_key("alice@example.com");
        let bob_sk = master.extract_secret_key("bob@example.com");

        let ct = params.encrypt("alice@example.com", b"Secret").unwrap();

        // Bob should not be able to decrypt Alice's message
        assert!(bob_sk.decrypt(&ct).is_err());
    }

    #[test]
    fn test_ibe_node_ids() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let node1_sk = master.extract_secret_key("node-12345");
        let node2_sk = master.extract_secret_key("node-67890");

        let msg = b"P2P message";
        let ct = params.encrypt("node-12345", msg).unwrap();

        let decrypted = node1_sk.decrypt(&ct).unwrap();
        assert_eq!(msg.as_slice(), decrypted.as_bytes());

        assert!(node2_sk.decrypt(&ct).is_err());
    }

    #[test]
    fn test_ibe_empty_plaintext() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let sk = master.extract_secret_key("test@example.com");

        let ct = params.encrypt("test@example.com", b"").unwrap();
        let decrypted = sk.decrypt(&ct).unwrap();

        assert_eq!(decrypted.as_bytes(), b"");
    }

    #[test]
    fn test_ibe_large_plaintext() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let sk = master.extract_secret_key("test@example.com");

        let plaintext = vec![0x42u8; 10000];
        let ct = params.encrypt("test@example.com", &plaintext).unwrap();
        let decrypted = sk.decrypt(&ct).unwrap();

        assert_eq!(decrypted.as_bytes(), plaintext.as_slice());
    }

    #[test]
    fn test_ibe_different_encryptions() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let sk = master.extract_secret_key("test@example.com");
        let msg = b"Same message";

        let ct1 = params.encrypt("test@example.com", msg).unwrap();
        let ct2 = params.encrypt("test@example.com", msg).unwrap();

        // Ciphertexts should be different due to randomness
        assert_ne!(ct1.to_bytes(), ct2.to_bytes());

        // But both should decrypt correctly
        assert_eq!(sk.decrypt(&ct1).unwrap().as_bytes(), msg);
        assert_eq!(sk.decrypt(&ct2).unwrap().as_bytes(), msg);
    }

    #[test]
    fn test_ibe_secret_key_identity() {
        let master = IbeMaster::generate();
        let identity = "user@example.com";
        let sk = master.extract_secret_key(identity);

        assert_eq!(sk.identity(), identity);
    }

    #[test]
    fn test_ibe_ciphertext_serialization() {
        let master = IbeMaster::generate();
        let params = master.public_params();
        let sk = master.extract_secret_key("test@example.com");

        let plaintext = b"Test message";
        let ct = params.encrypt("test@example.com", plaintext).unwrap();

        let serialized = ct.to_bytes();
        let deserialized = IbeCiphertext::from_bytes(&serialized).unwrap();

        let decrypted = sk.decrypt(&deserialized).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_ibe_secret_key_serialization() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let sk = master.extract_secret_key("test@example.com");

        let serialized = sk.to_bytes();
        let deserialized = IbeSecretKey::from_bytes(&serialized).unwrap();

        assert_eq!(deserialized.identity(), sk.identity());

        // Test decryption with deserialized key
        let plaintext = b"Test message";
        let ct = params.encrypt("test@example.com", plaintext).unwrap();

        let decrypted = deserialized.decrypt(&ct).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_ibe_params_serialization() {
        let master = IbeMaster::generate();
        let params = master.public_params();
        let sk = master.extract_secret_key("test@example.com");

        // Serialize and deserialize params
        let serialized = crate::codec::encode(&params).unwrap();
        let deserialized: IbeParams = crate::codec::decode(&serialized).unwrap();

        // Encrypt with deserialized params
        let plaintext = b"Test message";
        let ct = deserialized.encrypt("test@example.com", plaintext).unwrap();

        let decrypted = sk.decrypt(&ct).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_ibe_deterministic_key_extraction() {
        let master = IbeMaster::generate();

        let sk1 = master.extract_secret_key("test@example.com");
        let sk2 = master.extract_secret_key("test@example.com");

        // Same identity should produce same secret key
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_ibe_corrupted_ciphertext() {
        let master = IbeMaster::generate();
        let params = master.public_params();
        let sk = master.extract_secret_key("test@example.com");

        let ct = params.encrypt("test@example.com", b"Test").unwrap();

        let mut corrupted_bytes = ct.to_bytes();
        corrupted_bytes[50] ^= 0xFF; // Flip some bits

        let corrupted_ct = IbeCiphertext::from_bytes(&corrupted_bytes).unwrap();
        assert!(sk.decrypt(&corrupted_ct).is_err());
    }

    #[test]
    fn test_ibe_special_characters_in_identity() {
        let master = IbeMaster::generate();
        let params = master.public_params();

        let identity = "user+tag@example.com";
        let sk = master.extract_secret_key(identity);

        let ct = params.encrypt(identity, b"Test").unwrap();
        let decrypted = sk.decrypt(&ct).unwrap();

        assert_eq!(decrypted.as_bytes(), b"Test");
    }
}
