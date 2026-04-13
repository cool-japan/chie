//! HMAC-based authentication for message integrity.
//!
//! This module provides HMAC (Hash-based Message Authentication Code) functionality
//! for ensuring message integrity and authenticity in the CHIE protocol.
//!
//! # Features
//!
//! - HMAC-SHA256 and HMAC-BLAKE3 support
//! - Constant-time MAC verification
//! - Key derivation for HMAC keys
//! - Tagged authentication for different message types
//!
//! # Examples
//!
//! ```
//! use chie_crypto::hmac::{HmacKey, HmacTag, compute_hmac, verify_hmac};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a random HMAC key
//! let key = HmacKey::generate();
//!
//! // Compute HMAC for a message
//! let message = b"Hello, CHIE!";
//! let tag = compute_hmac(&key, message);
//!
//! // Verify the HMAC tag
//! assert!(verify_hmac(&key, message, &tag));
//!
//! // Verification fails for wrong message
//! assert!(!verify_hmac(&key, b"Wrong message", &tag));
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - HMAC keys should be at least 32 bytes (256 bits)
//! - Use constant-time comparison for MAC verification
//! - Never reuse HMAC keys across different protocols
//! - Rotate HMAC keys periodically

use blake3;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ct::ct_eq;

// Serde helper for Vec<u8>
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Vec<u8>>::deserialize(deserializer)
    }
}

/// HMAC errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid tag size
    InvalidTagSize,
    /// Verification failed
    VerificationFailed,
    /// Serialization error
    SerializationError(String),
}

impl std::fmt::Display for HmacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid HMAC key size"),
            Self::InvalidTagSize => write!(f, "Invalid HMAC tag size"),
            Self::VerificationFailed => write!(f, "HMAC verification failed"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for HmacError {}

/// HMAC result type.
pub type HmacResult<T> = Result<T, HmacError>;

/// HMAC key size in bytes.
pub const HMAC_KEY_SIZE: usize = 32;

/// HMAC tag size for SHA256 in bytes.
pub const HMAC_SHA256_TAG_SIZE: usize = 32;

/// HMAC tag size for BLAKE3 in bytes.
pub const HMAC_BLAKE3_TAG_SIZE: usize = 32;

/// HMAC key for message authentication.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct HmacKey {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

impl HmacKey {
    /// Generate a random HMAC key.
    pub fn generate() -> Self {
        use rand::Rng as _;
        let mut rng = rand::rng();
        let mut key = vec![0u8; HMAC_KEY_SIZE];
        rng.fill_bytes(&mut key[..]);
        Self { key }
    }

    /// Create an HMAC key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `HmacError::InvalidKeySize` if the key is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> HmacResult<Self> {
        if bytes.len() != HMAC_KEY_SIZE {
            return Err(HmacError::InvalidKeySize);
        }
        Ok(Self {
            key: bytes.to_vec(),
        })
    }

    /// Get the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    /// Derive an HMAC key from a password using PBKDF2.
    pub fn derive_from_password(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        use pbkdf2::pbkdf2_hmac;
        let mut key = vec![0u8; HMAC_KEY_SIZE];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
        Self { key }
    }
}

impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// HMAC tag (authentication code).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HmacTag {
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
}

impl HmacTag {
    /// Create an HMAC tag from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            tag: bytes.to_vec(),
        }
    }

    /// Get the tag bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.tag
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.tag.clone()
    }

    /// Verify this tag against another tag in constant time.
    pub fn verify(&self, other: &Self) -> bool {
        ct_eq(&self.tag, &other.tag)
    }
}

/// Compute HMAC-SHA256 for a message.
pub fn compute_hmac_sha256(key: &HmacKey, message: &[u8]) -> HmacTag {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    HmacTag::from_bytes(&result.into_bytes())
}

/// Compute HMAC-BLAKE3 for a message (using keyed BLAKE3).
pub fn compute_hmac_blake3(key: &HmacKey, message: &[u8]) -> HmacTag {
    // BLAKE3 has native keyed hashing support
    let key_array: [u8; 32] = key.as_bytes().try_into().expect("key is 32 bytes");
    let hash = blake3::keyed_hash(&key_array, message);
    HmacTag::from_bytes(hash.as_bytes())
}

/// Compute HMAC for a message (defaults to BLAKE3 for performance).
pub fn compute_hmac(key: &HmacKey, message: &[u8]) -> HmacTag {
    compute_hmac_blake3(key, message)
}

/// Verify HMAC tag in constant time.
pub fn verify_hmac(key: &HmacKey, message: &[u8], tag: &HmacTag) -> bool {
    let computed = compute_hmac(key, message);
    computed.verify(tag)
}

/// Verify HMAC-SHA256 tag in constant time.
pub fn verify_hmac_sha256(key: &HmacKey, message: &[u8], tag: &HmacTag) -> bool {
    let computed = compute_hmac_sha256(key, message);
    computed.verify(tag)
}

/// Verify HMAC-BLAKE3 tag in constant time.
pub fn verify_hmac_blake3(key: &HmacKey, message: &[u8], tag: &HmacTag) -> bool {
    let computed = compute_hmac_blake3(key, message);
    computed.verify(tag)
}

/// Tagged HMAC for domain separation.
///
/// This adds a context tag to the message before computing HMAC,
/// preventing HMAC values from being reused across different contexts.
pub fn compute_tagged_hmac(key: &HmacKey, context: &[u8], message: &[u8]) -> HmacTag {
    let key_array: [u8; 32] = key.as_bytes().try_into().expect("key is 32 bytes");
    let mut hasher = blake3::Hasher::new_keyed(&key_array);
    hasher.update(context);
    hasher.update(message);
    HmacTag::from_bytes(hasher.finalize().as_bytes())
}

/// Verify tagged HMAC in constant time.
pub fn verify_tagged_hmac(key: &HmacKey, context: &[u8], message: &[u8], tag: &HmacTag) -> bool {
    let computed = compute_tagged_hmac(key, context, message);
    computed.verify(tag)
}

/// Authenticated message containing both data and HMAC tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedMessage {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    tag: HmacTag,
}

impl AuthenticatedMessage {
    /// Create a new authenticated message.
    pub fn new(key: &HmacKey, data: Vec<u8>) -> Self {
        let tag = compute_hmac(key, &data);
        Self { data, tag }
    }

    /// Create a new tagged authenticated message.
    pub fn new_tagged(key: &HmacKey, context: &[u8], data: Vec<u8>) -> Self {
        let tag = compute_tagged_hmac(key, context, &data);
        Self { data, tag }
    }

    /// Verify and extract the data.
    ///
    /// # Errors
    ///
    /// Returns `HmacError::VerificationFailed` if the HMAC tag is invalid.
    pub fn verify(self, key: &HmacKey) -> HmacResult<Vec<u8>> {
        if verify_hmac(key, &self.data, &self.tag) {
            Ok(self.data)
        } else {
            Err(HmacError::VerificationFailed)
        }
    }

    /// Verify and extract the data (tagged version).
    ///
    /// # Errors
    ///
    /// Returns `HmacError::VerificationFailed` if the HMAC tag is invalid.
    pub fn verify_tagged(self, key: &HmacKey, context: &[u8]) -> HmacResult<Vec<u8>> {
        if verify_tagged_hmac(key, context, &self.data, &self.tag) {
            Ok(self.data)
        } else {
            Err(HmacError::VerificationFailed)
        }
    }

    /// Get the data without verification (unsafe).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the HMAC tag.
    pub fn tag(&self) -> &HmacTag {
        &self.tag
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> HmacResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| HmacError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> HmacResult<Self> {
        crate::codec::decode(bytes).map_err(|e| HmacError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_basic() {
        let key = HmacKey::generate();
        let message = b"Hello, CHIE!";

        let tag = compute_hmac(&key, message);
        assert!(verify_hmac(&key, message, &tag));

        // Wrong message should fail
        assert!(!verify_hmac(&key, b"Wrong message", &tag));
    }

    #[test]
    fn test_hmac_sha256() {
        let key = HmacKey::generate();
        let message = b"Test message";

        let tag = compute_hmac_sha256(&key, message);
        assert!(verify_hmac_sha256(&key, message, &tag));
        assert_eq!(tag.as_bytes().len(), HMAC_SHA256_TAG_SIZE);
    }

    #[test]
    fn test_hmac_blake3() {
        let key = HmacKey::generate();
        let message = b"Test message";

        let tag = compute_hmac_blake3(&key, message);
        assert!(verify_hmac_blake3(&key, message, &tag));
        assert_eq!(tag.as_bytes().len(), HMAC_BLAKE3_TAG_SIZE);
    }

    #[test]
    fn test_tagged_hmac() {
        let key = HmacKey::generate();
        let context = b"CHIE:BandwidthProof";
        let message = b"1234567890";

        let tag = compute_tagged_hmac(&key, context, message);
        assert!(verify_tagged_hmac(&key, context, message, &tag));

        // Wrong context should fail
        assert!(!verify_tagged_hmac(&key, b"wrong", message, &tag));
    }

    #[test]
    fn test_authenticated_message() {
        let key = HmacKey::generate();
        let data = b"Secret data".to_vec();

        let msg = AuthenticatedMessage::new(&key, data.clone());
        let verified = msg.verify(&key).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn test_authenticated_message_fails() {
        let key1 = HmacKey::generate();
        let key2 = HmacKey::generate();
        let data = b"Secret data".to_vec();

        let msg = AuthenticatedMessage::new(&key1, data);
        assert!(msg.verify(&key2).is_err());
    }

    #[test]
    fn test_tagged_authenticated_message() {
        let key = HmacKey::generate();
        let context = b"CHIE:Chunk";
        let data = b"Chunk data".to_vec();

        let msg = AuthenticatedMessage::new_tagged(&key, context, data.clone());
        let verified = msg.verify_tagged(&key, context).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn test_hmac_key_from_bytes() {
        let bytes = [42u8; HMAC_KEY_SIZE];
        let key = HmacKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_hmac_key_invalid_size() {
        let bytes = [42u8; 16]; // Wrong size
        assert!(HmacKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_hmac_key_derive_from_password() {
        let password = b"my secret password";
        let salt = b"unique salt";
        let key1 = HmacKey::derive_from_password(password, salt, 10000);
        let key2 = HmacKey::derive_from_password(password, salt, 10000);

        // Same password and salt should give same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());

        // Different salt should give different key
        let key3 = HmacKey::derive_from_password(password, b"different salt", 10000);
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_serialization() {
        let key = HmacKey::generate();
        let data = b"Test data".to_vec();
        let msg = AuthenticatedMessage::new(&key, data);

        let bytes = msg.to_bytes().unwrap();
        let deserialized = AuthenticatedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.data, deserialized.data);
        assert_eq!(msg.tag, deserialized.tag);
    }

    #[test]
    fn test_constant_time_verification() {
        let key = HmacKey::generate();
        let message = b"Test message";
        let tag1 = compute_hmac(&key, message);
        let tag2 = compute_hmac(&key, message);

        assert!(tag1.verify(&tag2));

        // Create a modified tag
        let mut wrong_tag = tag1.clone();
        wrong_tag.tag[0] ^= 1;

        assert!(!tag1.verify(&wrong_tag));
    }
}
