//! Cryptographic accumulators for efficient set membership proofs.
//!
//! This module provides accumulator data structures that allow compact
//! representation of sets with efficient membership proofs. Useful for
//! tracking large sets of elements in the CHIE protocol (e.g., valid peers,
//! bandwidth proofs, revocation lists).
//!
//! # Features
//!
//! - Hash-based accumulators with constant-size digests
//! - Incremental accumulator updates
//! - Compact membership proofs
//! - Batch operations for multiple elements
//! - Serialization support
//!
//! # Examples
//!
//! ```
//! use chie_crypto::accumulator::{HashAccumulator, hash_element};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new accumulator
//! let mut acc = HashAccumulator::new();
//!
//! // Add elements
//! let elem1 = b"peer_id_1";
//! let elem2 = b"peer_id_2";
//! acc.add(elem1);
//! acc.add(elem2);
//!
//! // Generate membership proof
//! let proof = acc.prove(elem1)?;
//!
//! // Verify membership
//! assert!(acc.verify(elem1, &proof));
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! - Hash-based accumulators provide collision resistance
//! - Proofs are binding but not hiding (elements are revealed)
//! - Use appropriate hash function (BLAKE3) for performance and security
//! - Accumulator state must be protected from tampering

use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

// Serde helper for [u8; 32]
mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<u8>>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("Expected 32 bytes"))
    }
}

/// Accumulator errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulatorError {
    /// Element not found in accumulator
    ElementNotFound,
    /// Invalid proof
    InvalidProof,
    /// Accumulator is empty
    EmptyAccumulator,
    /// Serialization error
    SerializationError(String),
    /// Element already exists
    ElementExists,
}

impl std::fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ElementNotFound => write!(f, "Element not found in accumulator"),
            Self::InvalidProof => write!(f, "Invalid membership proof"),
            Self::EmptyAccumulator => write!(f, "Accumulator is empty"),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::ElementExists => write!(f, "Element already exists in accumulator"),
        }
    }
}

impl std::error::Error for AccumulatorError {}

/// Accumulator result type.
pub type AccumulatorResult<T> = Result<T, AccumulatorError>;

/// Size of accumulator digest in bytes.
pub const ACCUMULATOR_DIGEST_SIZE: usize = 32;

/// Hash an element for accumulator inclusion.
pub fn hash_element(element: &[u8]) -> [u8; 32] {
    blake3::hash(element).into()
}

/// Accumulator digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccumulatorDigest {
    #[serde(with = "serde_bytes_32")]
    digest: [u8; ACCUMULATOR_DIGEST_SIZE],
}

impl AccumulatorDigest {
    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; ACCUMULATOR_DIGEST_SIZE]) -> Self {
        Self { digest: bytes }
    }

    /// Get the digest bytes.
    pub fn as_bytes(&self) -> &[u8; ACCUMULATOR_DIGEST_SIZE] {
        &self.digest
    }
}

/// Membership proof for an element in the accumulator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipProof {
    element_hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    witness: Vec<u8>,
}

impl MembershipProof {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> AccumulatorResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| AccumulatorError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AccumulatorResult<Self> {
        crate::codec::decode(bytes).map_err(|e| AccumulatorError::SerializationError(e.to_string()))
    }
}

/// Hash-based accumulator using Merkle tree-like construction.
///
/// This accumulator maintains a set of elements and can generate
/// compact membership proofs. The accumulator value is a hash commitment
/// to all elements in the set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashAccumulator {
    elements: HashMap<[u8; 32], Vec<u8>>,
    digest: [u8; 32],
}

impl HashAccumulator {
    /// Create a new empty accumulator.
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
            digest: [0u8; 32],
        }
    }

    /// Create an accumulator from a set of elements.
    pub fn from_elements(elements: &[&[u8]]) -> Self {
        let mut acc = Self::new();
        for elem in elements {
            acc.add(elem);
        }
        acc
    }

    /// Update the accumulator digest.
    fn update_digest(&mut self) {
        if self.elements.is_empty() {
            self.digest = [0u8; 32];
            return;
        }

        // Combine all element hashes in a deterministic order
        let mut sorted_hashes: Vec<_> = self.elements.keys().collect();
        sorted_hashes.sort();

        let mut hasher = blake3::Hasher::new();
        for hash in sorted_hashes {
            hasher.update(hash);
        }
        self.digest = hasher.finalize().into();
    }

    /// Add an element to the accumulator.
    ///
    /// Returns `true` if the element was newly added, `false` if it already existed.
    pub fn add(&mut self, element: &[u8]) -> bool {
        let hash = hash_element(element);
        let newly_added = self.elements.insert(hash, element.to_vec()).is_none();
        if newly_added {
            self.update_digest();
        }
        newly_added
    }

    /// Remove an element from the accumulator.
    ///
    /// Returns `true` if the element was present and removed, `false` otherwise.
    pub fn remove(&mut self, element: &[u8]) -> bool {
        let hash = hash_element(element);
        let was_present = self.elements.remove(&hash).is_some();
        if was_present {
            self.update_digest();
        }
        was_present
    }

    /// Check if an element is in the accumulator.
    pub fn contains(&self, element: &[u8]) -> bool {
        let hash = hash_element(element);
        self.elements.contains_key(&hash)
    }

    /// Generate a membership proof for an element.
    ///
    /// # Errors
    ///
    /// Returns `AccumulatorError::ElementNotFound` if the element is not in the accumulator.
    pub fn prove(&self, element: &[u8]) -> AccumulatorResult<MembershipProof> {
        let element_hash = hash_element(element);

        if !self.elements.contains_key(&element_hash) {
            return Err(AccumulatorError::ElementNotFound);
        }

        // The witness is all other element hashes
        let mut witness_hashes: Vec<_> = self
            .elements
            .keys()
            .filter(|&&h| h != element_hash)
            .collect();
        witness_hashes.sort();

        let mut witness = Vec::new();
        for hash in witness_hashes {
            witness.extend_from_slice(hash);
        }

        Ok(MembershipProof {
            element_hash,
            witness,
        })
    }

    /// Verify a membership proof.
    pub fn verify(&self, element: &[u8], proof: &MembershipProof) -> bool {
        let element_hash = hash_element(element);

        if element_hash != proof.element_hash {
            return false;
        }

        // Reconstruct the digest from the proof
        let mut all_hashes = vec![element_hash];
        for chunk in proof.witness.chunks(32) {
            if chunk.len() == 32 {
                let hash: [u8; 32] = chunk.try_into().unwrap();
                all_hashes.push(hash);
            }
        }
        all_hashes.sort();

        let mut hasher = blake3::Hasher::new();
        for hash in all_hashes {
            hasher.update(&hash);
        }
        let computed_digest: [u8; 32] = hasher.finalize().into();

        computed_digest == self.digest
    }

    /// Get the current accumulator digest.
    pub fn digest(&self) -> AccumulatorDigest {
        AccumulatorDigest::from_bytes(self.digest)
    }

    /// Get the number of elements in the accumulator.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get all elements in the accumulator.
    pub fn elements(&self) -> Vec<Vec<u8>> {
        self.elements.values().cloned().collect()
    }

    /// Batch add multiple elements.
    pub fn add_batch(&mut self, elements: &[&[u8]]) -> usize {
        let mut added = 0;
        for elem in elements {
            let hash = hash_element(elem);
            if self.elements.insert(hash, elem.to_vec()).is_none() {
                added += 1;
            }
        }
        if added > 0 {
            self.update_digest();
        }
        added
    }

    /// Batch remove multiple elements.
    pub fn remove_batch(&mut self, elements: &[&[u8]]) -> usize {
        let mut removed = 0;
        for elem in elements {
            let hash = hash_element(elem);
            if self.elements.remove(&hash).is_some() {
                removed += 1;
            }
        }
        if removed > 0 {
            self.update_digest();
        }
        removed
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> AccumulatorResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| AccumulatorError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AccumulatorResult<Self> {
        crate::codec::decode(bytes).map_err(|e| AccumulatorError::SerializationError(e.to_string()))
    }
}

impl Default for HashAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact accumulator that only stores the digest and element count.
///
/// This is useful when you only need to verify proofs but don't need
/// to generate new proofs or track individual elements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactAccumulator {
    digest: [u8; 32],
    count: usize,
}

impl CompactAccumulator {
    /// Create from a full accumulator.
    pub fn from_accumulator(acc: &HashAccumulator) -> Self {
        Self {
            digest: acc.digest,
            count: acc.len(),
        }
    }

    /// Create from digest and count.
    pub fn new(digest: [u8; 32], count: usize) -> Self {
        Self { digest, count }
    }

    /// Get the digest.
    pub fn digest(&self) -> AccumulatorDigest {
        AccumulatorDigest::from_bytes(self.digest)
    }

    /// Get the element count.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Verify a membership proof against this compact accumulator.
    pub fn verify(&self, element: &[u8], proof: &MembershipProof) -> bool {
        let element_hash = hash_element(element);

        if element_hash != proof.element_hash {
            return false;
        }

        // Reconstruct the digest from the proof
        let mut all_hashes = vec![element_hash];
        for chunk in proof.witness.chunks(32) {
            if chunk.len() == 32 {
                let hash: [u8; 32] = chunk.try_into().unwrap();
                all_hashes.push(hash);
            }
        }

        // Check that we have the right number of elements
        if all_hashes.len() != self.count {
            return false;
        }

        all_hashes.sort();

        let mut hasher = blake3::Hasher::new();
        for hash in all_hashes {
            hasher.update(&hash);
        }
        let computed_digest: [u8; 32] = hasher.finalize().into();

        computed_digest == self.digest
    }
}

/// Bloom filter-based probabilistic accumulator for fast membership testing.
///
/// This is not cryptographically secure but provides very fast membership
/// testing with a small false positive rate.
#[derive(Clone, Debug)]
pub struct BloomAccumulator {
    bits: Vec<bool>,
    num_hashes: usize,
    count: usize,
}

impl BloomAccumulator {
    /// Create a new Bloom filter with given capacity and false positive rate.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Expected number of elements
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        let bits_per_element = -1.44 * false_positive_rate.log2();
        let num_bits = ((capacity as f64) * bits_per_element).ceil() as usize;
        let num_hashes = (bits_per_element * std::f64::consts::LN_2).ceil() as usize;

        Self {
            bits: vec![false; num_bits],
            num_hashes,
            count: 0,
        }
    }

    /// Add an element to the Bloom filter.
    pub fn add(&mut self, element: &[u8]) {
        let hash = blake3::hash(element);
        let hash_bytes = hash.as_bytes();

        for i in 0..self.num_hashes {
            let index = self.hash_index(hash_bytes, i);
            self.bits[index] = true;
        }
        self.count += 1;
    }

    /// Check if an element might be in the set (may have false positives).
    pub fn might_contain(&self, element: &[u8]) -> bool {
        let hash = blake3::hash(element);
        let hash_bytes = hash.as_bytes();

        for i in 0..self.num_hashes {
            let index = self.hash_index(hash_bytes, i);
            if !self.bits[index] {
                return false;
            }
        }
        true
    }

    fn hash_index(&self, hash: &[u8], i: usize) -> usize {
        let offset = (i * 8) % hash.len();
        let mut bytes = [0u8; 8];
        for j in 0..8 {
            bytes[j] = hash[(offset + j) % hash.len()];
        }
        let value = u64::from_le_bytes(bytes);
        (value as usize) % self.bits.len()
    }

    /// Get the number of elements added (approximate).
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the size of the Bloom filter in bits.
    pub fn size(&self) -> usize {
        self.bits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_accumulator_basic() {
        let mut acc = HashAccumulator::new();
        assert!(acc.is_empty());

        let elem1 = b"element1";
        let elem2 = b"element2";

        assert!(acc.add(elem1));
        assert!(acc.add(elem2));
        assert_eq!(acc.len(), 2);

        assert!(acc.contains(elem1));
        assert!(acc.contains(elem2));
        assert!(!acc.contains(b"element3"));
    }

    #[test]
    fn test_hash_accumulator_proof() {
        let mut acc = HashAccumulator::new();
        let elem1 = b"peer_id_1";
        let elem2 = b"peer_id_2";
        let elem3 = b"peer_id_3";

        acc.add(elem1);
        acc.add(elem2);
        acc.add(elem3);

        let proof1 = acc.prove(elem1).unwrap();
        assert!(acc.verify(elem1, &proof1));

        let proof2 = acc.prove(elem2).unwrap();
        assert!(acc.verify(elem2, &proof2));

        // Wrong element should fail
        assert!(!acc.verify(b"wrong", &proof1));
    }

    #[test]
    fn test_hash_accumulator_remove() {
        let mut acc = HashAccumulator::new();
        let elem1 = b"element1";
        let elem2 = b"element2";

        acc.add(elem1);
        acc.add(elem2);

        assert!(acc.remove(elem1));
        assert!(!acc.contains(elem1));
        assert!(acc.contains(elem2));

        // Removing again should return false
        assert!(!acc.remove(elem1));
    }

    #[test]
    fn test_hash_accumulator_from_elements() {
        let elements = vec![b"elem1".as_ref(), b"elem2".as_ref(), b"elem3".as_ref()];
        let acc = HashAccumulator::from_elements(&elements);

        assert_eq!(acc.len(), 3);
        for elem in &elements {
            assert!(acc.contains(elem));
        }
    }

    #[test]
    fn test_hash_accumulator_batch_operations() {
        let mut acc = HashAccumulator::new();
        let elements = vec![b"elem1".as_ref(), b"elem2".as_ref(), b"elem3".as_ref()];

        let added = acc.add_batch(&elements);
        assert_eq!(added, 3);
        assert_eq!(acc.len(), 3);

        let removed = acc.remove_batch(&elements[0..2]);
        assert_eq!(removed, 2);
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn test_compact_accumulator() {
        let mut acc = HashAccumulator::new();
        acc.add(b"elem1");
        acc.add(b"elem2");
        acc.add(b"elem3");

        let proof = acc.prove(b"elem1").unwrap();

        let compact = CompactAccumulator::from_accumulator(&acc);
        assert_eq!(compact.count(), 3);
        assert!(compact.verify(b"elem1", &proof));
    }

    #[test]
    fn test_bloom_accumulator() {
        let mut bloom = BloomAccumulator::new(1000, 0.01);

        let elements = vec![b"elem1", b"elem2", b"elem3"];
        for elem in &elements {
            bloom.add(*elem);
        }

        for elem in &elements {
            assert!(bloom.might_contain(*elem));
        }

        // Element not added should probably not be present
        // (may have false positives, but unlikely with low rate)
        let not_added = b"definitely_not_added_unique_12345";
        // We can't assert false here due to false positives, but we can test it exists
        let _ = bloom.might_contain(not_added);
    }

    #[test]
    fn test_accumulator_serialization() {
        let mut acc = HashAccumulator::new();
        acc.add(b"elem1");
        acc.add(b"elem2");

        let bytes = acc.to_bytes().unwrap();
        let restored = HashAccumulator::from_bytes(&bytes).unwrap();

        assert_eq!(acc.digest(), restored.digest());
        assert_eq!(acc.len(), restored.len());
        assert!(restored.contains(b"elem1"));
        assert!(restored.contains(b"elem2"));
    }

    #[test]
    fn test_proof_serialization() {
        let mut acc = HashAccumulator::new();
        acc.add(b"elem1");
        acc.add(b"elem2");

        let proof = acc.prove(b"elem1").unwrap();
        let bytes = proof.to_bytes().unwrap();
        let restored = MembershipProof::from_bytes(&bytes).unwrap();

        assert!(acc.verify(b"elem1", &restored));
    }

    #[test]
    fn test_accumulator_digest_changes() {
        let mut acc = HashAccumulator::new();
        let digest1 = acc.digest();

        acc.add(b"elem1");
        let digest2 = acc.digest();
        assert_ne!(digest1, digest2);

        acc.add(b"elem2");
        let digest3 = acc.digest();
        assert_ne!(digest2, digest3);

        acc.remove(b"elem1");
        let digest4 = acc.digest();
        assert_ne!(digest3, digest4);
    }

    #[test]
    fn test_proof_not_found() {
        let acc = HashAccumulator::new();
        assert!(acc.prove(b"nonexistent").is_err());
    }

    #[test]
    fn test_duplicate_add() {
        let mut acc = HashAccumulator::new();
        assert!(acc.add(b"elem1"));
        assert!(!acc.add(b"elem1")); // Second add should return false
        assert_eq!(acc.len(), 1);
    }
}
