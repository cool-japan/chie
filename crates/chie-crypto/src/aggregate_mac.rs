//! Aggregate MAC for efficient multi-message authentication.
//!
//! This module provides aggregate Message Authentication Codes (MACs) that allow
//! authenticating multiple messages with a single verification step. This is particularly
//! useful for:
//! - Batch verification of content chunks in P2P networks
//! - Reducing verification overhead when processing many messages
//! - Bandwidth-efficient authentication of large datasets
//!
//! The aggregate MAC scheme uses BLAKE3 keyed hashing with domain separation:
//! - Each message is tagged with its index for domain separation
//! - Individual MACs are combined via XOR aggregation
//! - Single aggregate tag can verify all messages at once
//! - Constant-size tags regardless of number of messages
//!
//! # Example
//!
//! ```
//! use chie_crypto::aggregate_mac::{AggregateMacKey, AggregateMacBuilder};
//!
//! // Generate a key
//! let key = AggregateMacKey::generate();
//!
//! // Authenticate multiple messages
//! let messages = vec![b"chunk1".as_slice(), b"chunk2".as_slice(), b"chunk3".as_slice()];
//! let builder = AggregateMacBuilder::new(&key);
//! let aggregate_tag = builder.authenticate_batch(&messages);
//!
//! // Verify all messages at once
//! let valid = key.verify_batch(&messages, &aggregate_tag);
//! assert!(valid);
//! ```

use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for aggregate MAC operations.
pub type AggregateMacResult<T> = Result<T, AggregateMacError>;

/// Errors that can occur during aggregate MAC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateMacError {
    /// Empty message list
    EmptyMessages,
    /// Invalid tag
    InvalidTag,
    /// Serialization failed
    SerializationFailed,
    /// Deserialization failed
    DeserializationFailed,
}

impl fmt::Display for AggregateMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AggregateMacError::EmptyMessages => write!(f, "Empty message list"),
            AggregateMacError::InvalidTag => write!(f, "Invalid tag"),
            AggregateMacError::SerializationFailed => write!(f, "Serialization failed"),
            AggregateMacError::DeserializationFailed => write!(f, "Deserialization failed"),
        }
    }
}

impl std::error::Error for AggregateMacError {}

/// Aggregate MAC key.
///
/// Used to authenticate multiple messages and verify aggregate tags.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct AggregateMacKey {
    key: [u8; 32],
}

/// Aggregate MAC tag.
///
/// Constant-size tag that authenticates multiple messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateTag {
    tag: [u8; 32],
    count: usize,
}

/// Builder for creating aggregate MACs.
pub struct AggregateMacBuilder<'a> {
    key: &'a AggregateMacKey,
}

/// Individual MAC tag for a single message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacTag {
    tag: [u8; 32],
}

impl AggregateMacKey {
    /// Generate a new random key.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Get the raw key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Authenticate a single message.
    pub fn authenticate(&self, message: &[u8]) -> MacTag {
        self.authenticate_with_index(message, 0)
    }

    /// Authenticate a message with an index for domain separation.
    pub fn authenticate_with_index(&self, message: &[u8], index: usize) -> MacTag {
        let mut hasher = Hasher::new_keyed(&self.key);
        hasher.update(b"AggregateMac-v1:");
        hasher.update(&index.to_le_bytes());
        hasher.update(b":");
        hasher.update(message);

        let hash = hasher.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(hash.as_bytes());

        MacTag { tag }
    }

    /// Authenticate multiple messages and return an aggregate tag.
    pub fn authenticate_batch(&self, messages: &[&[u8]]) -> AggregateMacResult<AggregateTag> {
        if messages.is_empty() {
            return Err(AggregateMacError::EmptyMessages);
        }

        let mut aggregate_tag = [0u8; 32];

        for (index, message) in messages.iter().enumerate() {
            let mac_tag = self.authenticate_with_index(message, index);
            // XOR aggregation
            for (i, byte) in aggregate_tag.iter_mut().enumerate() {
                *byte ^= mac_tag.tag[i];
            }
        }

        Ok(AggregateTag {
            tag: aggregate_tag,
            count: messages.len(),
        })
    }

    /// Verify a single message against a MAC tag.
    pub fn verify(&self, message: &[u8], tag: &MacTag) -> bool {
        let expected = self.authenticate(message);
        constant_time_eq(&expected.tag, &tag.tag)
    }

    /// Verify a message with an index against a MAC tag.
    pub fn verify_with_index(&self, message: &[u8], index: usize, tag: &MacTag) -> bool {
        let expected = self.authenticate_with_index(message, index);
        constant_time_eq(&expected.tag, &tag.tag)
    }

    /// Verify multiple messages against an aggregate tag.
    pub fn verify_batch(&self, messages: &[&[u8]], aggregate_tag: &AggregateTag) -> bool {
        if messages.is_empty() || messages.len() != aggregate_tag.count {
            return false;
        }

        let expected = match self.authenticate_batch(messages) {
            Ok(tag) => tag,
            Err(_) => return false,
        };

        constant_time_eq(&expected.tag, &aggregate_tag.tag)
    }

    /// Create a builder for aggregate MAC operations.
    pub fn builder(&self) -> AggregateMacBuilder<'_> {
        AggregateMacBuilder { key: self }
    }
}

impl<'a> AggregateMacBuilder<'a> {
    /// Create a new builder.
    pub fn new(key: &'a AggregateMacKey) -> Self {
        Self { key }
    }

    /// Authenticate multiple messages.
    pub fn authenticate_batch(&self, messages: &[&[u8]]) -> AggregateTag {
        self.key
            .authenticate_batch(messages)
            .expect("messages should not be empty")
    }

    /// Authenticate messages from an iterator.
    pub fn authenticate_iter<I>(&self, messages: I) -> AggregateMacResult<AggregateTag>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let messages: Vec<Vec<u8>> = messages.into_iter().collect();
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        self.key.authenticate_batch(&message_refs)
    }

    /// Verify a batch of messages.
    pub fn verify_batch(&self, messages: &[&[u8]], tag: &AggregateTag) -> bool {
        self.key.verify_batch(messages, tag)
    }
}

impl AggregateTag {
    /// Get the number of messages authenticated by this tag.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Serialize the tag to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).unwrap_or_default()
    }

    /// Deserialize a tag from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AggregateMacResult<Self> {
        crate::codec::decode(bytes).map_err(|_| AggregateMacError::DeserializationFailed)
    }
}

impl MacTag {
    /// Serialize the tag to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.tag
    }

    /// Deserialize a tag from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { tag: bytes }
    }
}

/// Constant-time equality comparison.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_message_authentication() {
        let key = AggregateMacKey::generate();
        let message = b"test message";

        let tag = key.authenticate(message);
        assert!(key.verify(message, &tag));
    }

    #[test]
    fn test_single_message_wrong_key() {
        let key1 = AggregateMacKey::generate();
        let key2 = AggregateMacKey::generate();

        let message = b"test message";
        let tag = key1.authenticate(message);

        assert!(!key2.verify(message, &tag));
    }

    #[test]
    fn test_single_message_tampered() {
        let key = AggregateMacKey::generate();
        let message = b"test message";

        let tag = key.authenticate(message);

        let tampered = b"tampered message";
        assert!(!key.verify(tampered, &tag));
    }

    #[test]
    fn test_batch_authentication() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();
        assert!(key.verify_batch(&messages, &tag));
    }

    #[test]
    fn test_batch_wrong_order() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();

        // Different order should fail
        let reordered = vec![b"msg2".as_slice(), b"msg1".as_slice(), b"msg3".as_slice()];
        assert!(!key.verify_batch(&reordered, &tag));
    }

    #[test]
    fn test_batch_tampered_message() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();

        let tampered = vec![
            b"msg1".as_slice(),
            b"TAMPERED".as_slice(),
            b"msg3".as_slice(),
        ];
        assert!(!key.verify_batch(&tampered, &tag));
    }

    #[test]
    fn test_batch_wrong_count() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();

        // Different number of messages should fail
        let fewer = vec![b"msg1".as_slice(), b"msg2".as_slice()];
        assert!(!key.verify_batch(&fewer, &tag));

        let more = vec![
            b"msg1".as_slice(),
            b"msg2".as_slice(),
            b"msg3".as_slice(),
            b"msg4".as_slice(),
        ];
        assert!(!key.verify_batch(&more, &tag));
    }

    #[test]
    fn test_batch_empty() {
        let key = AggregateMacKey::generate();
        let messages: Vec<&[u8]> = vec![];

        assert!(key.authenticate_batch(&messages).is_err());
    }

    #[test]
    fn test_indexed_authentication() {
        let key = AggregateMacKey::generate();
        let message = b"test message";

        let tag0 = key.authenticate_with_index(message, 0);
        let tag1 = key.authenticate_with_index(message, 1);

        // Different indices should produce different tags
        assert_ne!(tag0, tag1);

        assert!(key.verify_with_index(message, 0, &tag0));
        assert!(key.verify_with_index(message, 1, &tag1));

        // Wrong index should fail
        assert!(!key.verify_with_index(message, 0, &tag1));
        assert!(!key.verify_with_index(message, 1, &tag0));
    }

    #[test]
    fn test_builder_pattern() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice()];

        let builder = AggregateMacBuilder::new(&key);
        let tag = builder.authenticate_batch(&messages);

        assert!(builder.verify_batch(&messages, &tag));
    }

    #[test]
    fn test_aggregate_tag_count() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice(), b"msg3".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();
        assert_eq!(tag.count(), 3);
    }

    #[test]
    fn test_tag_serialization() {
        let key = AggregateMacKey::generate();
        let message = b"test message";

        let tag = key.authenticate(message);
        let bytes = tag.to_bytes();
        let deserialized = MacTag::from_bytes(bytes);

        assert_eq!(tag, deserialized);
        assert!(key.verify(message, &deserialized));
    }

    #[test]
    fn test_aggregate_tag_serialization() {
        let key = AggregateMacKey::generate();
        let messages = vec![b"msg1".as_slice(), b"msg2".as_slice()];

        let tag = key.authenticate_batch(&messages).unwrap();
        let bytes = tag.to_bytes();
        let deserialized = AggregateTag::from_bytes(&bytes).unwrap();

        assert_eq!(tag, deserialized);
        assert!(key.verify_batch(&messages, &deserialized));
    }

    #[test]
    fn test_key_serialization() {
        let key = AggregateMacKey::generate();
        let message = b"test message";

        let bytes = key.to_bytes();
        let deserialized = AggregateMacKey::from_bytes(bytes);

        let tag = key.authenticate(message);
        assert!(deserialized.verify(message, &tag));
    }

    #[test]
    fn test_large_batch() {
        let key = AggregateMacKey::generate();
        let messages: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("message{}", i).into_bytes())
            .collect();
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        let tag = key.authenticate_batch(&message_refs).unwrap();
        assert!(key.verify_batch(&message_refs, &tag));
        assert_eq!(tag.count(), 100);
    }

    #[test]
    fn test_deterministic_tags() {
        let key = AggregateMacKey::from_bytes([0x42; 32]);
        let message = b"test message";

        let tag1 = key.authenticate(message);
        let tag2 = key.authenticate(message);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_different_message_sizes() {
        let key = AggregateMacKey::generate();
        let large_msg = vec![0x42u8; 1000];
        let messages = vec![
            b"short".as_slice(),
            b"medium length message".as_slice(),
            large_msg.as_slice(),
        ];

        let tag = key.authenticate_batch(&messages).unwrap();
        assert!(key.verify_batch(&messages, &tag));
    }

    #[test]
    fn test_xor_properties() {
        let key = AggregateMacKey::generate();

        // Single message
        let msg1 = vec![b"msg1".as_slice()];
        let tag1 = key.authenticate_batch(&msg1).unwrap();

        // Same message twice should XOR to zero then XOR with itself
        let msg2 = vec![b"msg1".as_slice(), b"msg1".as_slice()];
        let tag2 = key.authenticate_batch(&msg2).unwrap();

        // Tags should be different
        assert_ne!(tag1.tag, tag2.tag);
    }
}
