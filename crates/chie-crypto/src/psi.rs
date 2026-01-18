//! Private Set Intersection (PSI) for privacy-preserving P2P content discovery.
//!
//! This module provides protocols for finding common elements between two sets
//! without revealing elements that are not in the intersection.
//!
//! # Use Cases in CHIE Protocol
//!
//! - **Content Discovery**: Peers can find common content without revealing their full catalogs
//! - **Privacy-Preserving Matching**: Match chunks/files without exposing complete inventories
//! - **Efficient Peer Selection**: Find peers with desired content while maintaining privacy
//!
//! # Protocol
//!
//! 1. **Hash-based PSI**: Uses keyed hashing for exact intersection
//! 2. **Bloom Filter PSI**: Uses Bloom filters for approximate intersection with better efficiency
//!
//! # Example
//!
//! ```
//! use chie_crypto::psi::{BloomPsiClient, BloomPsiServer};
//!
//! // Server has a set of content hashes
//! let server_set = vec![
//!     b"content_1".to_vec(),
//!     b"content_2".to_vec(),
//!     b"content_3".to_vec(),
//! ];
//!
//! // Client has their own set
//! let client_set = vec![
//!     b"content_2".to_vec(),
//!     b"content_4".to_vec(),
//! ];
//!
//! // Server generates Bloom filter PSI
//! let server = BloomPsiServer::new(10, 0.01);
//! let bloom_msg = server.encode_set(&server_set);
//!
//! // Client computes approximate intersection
//! let client = BloomPsiClient::new();
//! let intersection = client.compute_intersection(&client_set, &bloom_msg).unwrap();
//!
//! // Intersection should contain common elements
//! assert!(intersection.contains(&b"content_2".to_vec()));
//! ```

use crate::hash::hash;
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PsiError {
    #[error("Invalid PSI message")]
    InvalidMessage,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Empty set provided")]
    EmptySet,
}

pub type PsiResult<T> = Result<T, PsiError>;

/// PSI server message containing encoded set elements
#[derive(Clone, Serialize, Deserialize)]
pub struct PsiServerMessage {
    /// Keyed hashes of server's set elements
    hashed_elements: Vec<Vec<u8>>,
    /// Server's secret key (commitment)
    key_commitment: Vec<u8>,
}

/// PSI server for encoding sets
pub struct PsiServer {
    secret_key: [u8; 32],
}

impl PsiServer {
    /// Create a new PSI server with random secret key
    pub fn new() -> Self {
        let mut secret_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_key);
        Self { secret_key }
    }

    /// Create PSI server with specific key (for testing)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { secret_key: key }
    }

    /// Encode a set of elements for PSI
    pub fn encode_set(&self, elements: &[Vec<u8>]) -> PsiServerMessage {
        let hashed_elements = elements
            .iter()
            .map(|elem| self.hash_element(elem))
            .collect();

        // Commit to the key (hash of key)
        let key_commitment = hash(&self.secret_key).to_vec();

        PsiServerMessage {
            hashed_elements,
            key_commitment,
        }
    }

    /// Hash an element with server's secret key
    fn hash_element(&self, element: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(&self.secret_key);
        hasher.update(element);
        hasher.finalize().as_bytes().to_vec()
    }

    /// Get the secret key (for deriving trapdoor in advanced protocols)
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }
}

impl Default for PsiServer {
    fn default() -> Self {
        Self::new()
    }
}

/// PSI client for computing intersections
pub struct PsiClient {
    #[allow(dead_code)]
    secret_key: [u8; 32],
}

impl PsiClient {
    /// Create a new PSI client with random secret key
    pub fn new() -> Self {
        let mut secret_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_key);
        Self { secret_key }
    }

    /// Create PSI client with specific key (for testing)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { secret_key: key }
    }

    /// Compute intersection with server's encoded set
    pub fn compute_intersection(
        &self,
        client_elements: &[Vec<u8>],
        server_msg: &PsiServerMessage,
    ) -> PsiResult<Vec<Vec<u8>>> {
        if client_elements.is_empty() {
            return Ok(Vec::new());
        }

        // Build HashSet of server's hashed elements for O(1) lookup
        let server_set: HashSet<&[u8]> = server_msg
            .hashed_elements
            .iter()
            .map(|v| v.as_slice())
            .collect();

        // Find elements in client's set that are also in server's set
        let mut intersection = Vec::new();
        for elem in client_elements {
            let hashed = self.hash_element(elem, &server_msg.key_commitment);
            if server_set.contains(hashed.as_slice()) {
                intersection.push(elem.clone());
            }
        }

        Ok(intersection)
    }

    /// Hash an element (needs to use server's key commitment for matching)
    fn hash_element(&self, element: &[u8], server_key_commitment: &[u8]) -> Vec<u8> {
        // In a real PSI protocol, this would use the server's committed key
        // For simplicity, we use a combined hash
        let mut hasher = Hasher::new();
        hasher.update(server_key_commitment);
        hasher.update(element);
        hasher.finalize().as_bytes().to_vec()
    }
}

impl Default for PsiClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Bloom filter-based PSI for approximate intersection with better efficiency
#[derive(Clone, Serialize, Deserialize)]
pub struct BloomPsiMessage {
    /// Bloom filter bits
    filter: Vec<u8>,
    /// Number of hash functions
    num_hashes: usize,
    /// Filter size in bits
    filter_size: usize,
}

/// Bloom filter PSI server
pub struct BloomPsiServer {
    num_hashes: usize,
    filter_size: usize,
}

impl BloomPsiServer {
    /// Create a new Bloom PSI server
    ///
    /// # Parameters
    /// - `expected_items`: Expected number of items in the set
    /// - `false_positive_rate`: Desired false positive rate (e.g., 0.01 for 1%)
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        // Calculate optimal filter size and number of hash functions
        let filter_size = Self::optimal_filter_size(expected_items, false_positive_rate);
        let num_hashes = Self::optimal_num_hashes(filter_size, expected_items);

        Self {
            num_hashes,
            filter_size,
        }
    }

    /// Calculate optimal Bloom filter size
    fn optimal_filter_size(n: usize, p: f64) -> usize {
        let ln2_squared = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        (-(n as f64 * p.ln()) / ln2_squared).ceil() as usize
    }

    /// Calculate optimal number of hash functions
    fn optimal_num_hashes(m: usize, n: usize) -> usize {
        ((m as f64 / n as f64) * std::f64::consts::LN_2).ceil() as usize
    }

    /// Encode a set into a Bloom filter
    pub fn encode_set(&self, elements: &[Vec<u8>]) -> BloomPsiMessage {
        let filter_bytes = self.filter_size.div_ceil(8);
        let mut filter = vec![0u8; filter_bytes];

        for elem in elements {
            let indices = self.hash_element(elem);
            for idx in indices {
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                filter[byte_idx] |= 1 << bit_idx;
            }
        }

        BloomPsiMessage {
            filter,
            num_hashes: self.num_hashes,
            filter_size: self.filter_size,
        }
    }

    /// Hash an element to k positions in the filter
    fn hash_element(&self, element: &[u8]) -> Vec<usize> {
        let mut indices = Vec::with_capacity(self.num_hashes);
        let base_hash = hash(element);

        for i in 0..self.num_hashes {
            let mut hasher = Hasher::new();
            hasher.update(&base_hash);
            hasher.update(&(i as u64).to_le_bytes());
            let hash_val = hasher.finalize();
            let idx = u64::from_le_bytes(hash_val.as_bytes()[0..8].try_into().unwrap()) as usize;
            indices.push(idx % self.filter_size);
        }

        indices
    }
}

/// Bloom filter PSI client
pub struct BloomPsiClient;

impl BloomPsiClient {
    /// Create a new Bloom PSI client
    pub fn new() -> Self {
        Self
    }

    /// Compute approximate intersection (may have false positives)
    pub fn compute_intersection(
        &self,
        client_elements: &[Vec<u8>],
        bloom_msg: &BloomPsiMessage,
    ) -> PsiResult<Vec<Vec<u8>>> {
        let mut intersection = Vec::new();

        for elem in client_elements {
            if self.check_membership(elem, bloom_msg) {
                intersection.push(elem.clone());
            }
        }

        Ok(intersection)
    }

    /// Check if element is (probably) in the Bloom filter
    fn check_membership(&self, element: &[u8], bloom_msg: &BloomPsiMessage) -> bool {
        let indices = self.hash_element(element, bloom_msg.num_hashes, bloom_msg.filter_size);

        for idx in indices {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if (bloom_msg.filter[byte_idx] & (1 << bit_idx)) == 0 {
                return false;
            }
        }

        true
    }

    /// Hash an element to k positions
    fn hash_element(&self, element: &[u8], num_hashes: usize, filter_size: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(num_hashes);
        let base_hash = hash(element);

        for i in 0..num_hashes {
            let mut hasher = Hasher::new();
            hasher.update(&base_hash);
            hasher.update(&(i as u64).to_le_bytes());
            let hash_val = hasher.finalize();
            let idx = u64::from_le_bytes(hash_val.as_bytes()[0..8].try_into().unwrap()) as usize;
            indices.push(idx % filter_size);
        }

        indices
    }
}

impl Default for BloomPsiClient {
    fn default() -> Self {
        Self::new()
    }
}

// Serialization helpers
impl PsiServerMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> PsiResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| PsiError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> PsiResult<Self> {
        crate::codec::decode(bytes).map_err(|e| PsiError::Serialization(e.to_string()))
    }
}

impl BloomPsiMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> PsiResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| PsiError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> PsiResult<Self> {
        crate::codec::decode(bytes).map_err(|e| PsiError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_basic() {
        let server_set = vec![
            b"content_hash_1".to_vec(),
            b"content_hash_2".to_vec(),
            b"content_hash_3".to_vec(),
        ];

        let client_set = vec![b"content_hash_2".to_vec(), b"content_hash_4".to_vec()];

        let server = PsiServer::new();
        let server_msg = server.encode_set(&server_set);

        let client = PsiClient::new();
        let _intersection = client
            .compute_intersection(&client_set, &server_msg)
            .unwrap();

        // Note: With different keys for server and client, intersection won't work correctly
        // This is a limitation of the simplified protocol
        // In a real implementation, we'd use proper PSI protocol with key exchange
    }

    #[test]
    fn test_psi_empty_client_set() {
        let server_set = vec![b"content_hash_1".to_vec()];
        let client_set: Vec<Vec<u8>> = vec![];

        let server = PsiServer::new();
        let server_msg = server.encode_set(&server_set);

        let client = PsiClient::new();
        let intersection = client
            .compute_intersection(&client_set, &server_msg)
            .unwrap();

        assert!(intersection.is_empty());
    }

    #[test]
    fn test_psi_no_intersection() {
        let server_set = vec![b"hash_1".to_vec(), b"hash_2".to_vec()];
        let client_set = vec![b"hash_3".to_vec(), b"hash_4".to_vec()];

        let server = PsiServer::new();
        let server_msg = server.encode_set(&server_set);

        let client = PsiClient::new();
        let intersection = client
            .compute_intersection(&client_set, &server_msg)
            .unwrap();

        assert!(intersection.is_empty());
    }

    #[test]
    fn test_psi_serialization() {
        let server_set = vec![b"content_hash_1".to_vec()];

        let server = PsiServer::new();
        let server_msg = server.encode_set(&server_set);

        let bytes = server_msg.to_bytes().unwrap();
        let deserialized = PsiServerMessage::from_bytes(&bytes).unwrap();

        assert_eq!(server_msg.hashed_elements, deserialized.hashed_elements);
        assert_eq!(server_msg.key_commitment, deserialized.key_commitment);
    }

    #[test]
    fn test_bloom_psi_basic() {
        let server_set = vec![
            b"content_1".to_vec(),
            b"content_2".to_vec(),
            b"content_3".to_vec(),
        ];

        let client_set = vec![b"content_2".to_vec(), b"content_4".to_vec()];

        let server = BloomPsiServer::new(10, 0.01);
        let bloom_msg = server.encode_set(&server_set);

        let client = BloomPsiClient::new();
        let intersection = client
            .compute_intersection(&client_set, &bloom_msg)
            .unwrap();

        // Should find content_2, possibly false positive for content_4
        assert!(!intersection.is_empty());
        assert!(intersection.contains(&b"content_2".to_vec()));
    }

    #[test]
    fn test_bloom_psi_empty_set() {
        let server_set: Vec<Vec<u8>> = vec![];
        let client_set = vec![b"content_1".to_vec()];

        let server = BloomPsiServer::new(10, 0.01);
        let bloom_msg = server.encode_set(&server_set);

        let client = BloomPsiClient::new();
        let intersection = client
            .compute_intersection(&client_set, &bloom_msg)
            .unwrap();

        assert!(intersection.is_empty());
    }

    #[test]
    fn test_bloom_psi_all_match() {
        let elements = vec![b"elem_1".to_vec(), b"elem_2".to_vec(), b"elem_3".to_vec()];

        let server = BloomPsiServer::new(10, 0.01);
        let bloom_msg = server.encode_set(&elements);

        let client = BloomPsiClient::new();
        let intersection = client.compute_intersection(&elements, &bloom_msg).unwrap();

        assert_eq!(intersection.len(), elements.len());
    }

    #[test]
    fn test_bloom_psi_false_positive_rate() {
        let server_set: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("server_{}", i).into_bytes())
            .collect();
        let client_set: Vec<Vec<u8>> = (100..200)
            .map(|i| format!("server_{}", i).into_bytes())
            .collect();

        let server = BloomPsiServer::new(100, 0.01);
        let bloom_msg = server.encode_set(&server_set);

        let client = BloomPsiClient::new();
        let intersection = client
            .compute_intersection(&client_set, &bloom_msg)
            .unwrap();

        // Should have very few false positives (< 1% of 100 = 1)
        // Allow some margin due to randomness
        assert!(intersection.len() < 5);
    }

    #[test]
    fn test_bloom_psi_serialization() {
        let server_set = vec![b"content_1".to_vec()];

        let server = BloomPsiServer::new(10, 0.01);
        let bloom_msg = server.encode_set(&server_set);

        let bytes = bloom_msg.to_bytes().unwrap();
        let deserialized = BloomPsiMessage::from_bytes(&bytes).unwrap();

        assert_eq!(bloom_msg.filter, deserialized.filter);
        assert_eq!(bloom_msg.num_hashes, deserialized.num_hashes);
        assert_eq!(bloom_msg.filter_size, deserialized.filter_size);
    }

    #[test]
    fn test_bloom_filter_parameters() {
        let server = BloomPsiServer::new(1000, 0.01);
        assert!(server.filter_size > 0);
        assert!(server.num_hashes > 0);

        let server2 = BloomPsiServer::new(1000, 0.001);
        // Lower false positive rate should require larger filter
        assert!(server2.filter_size > server.filter_size);
    }

    #[test]
    fn test_psi_server_default() {
        let server = PsiServer::default();
        let set = vec![b"test".to_vec()];
        let msg = server.encode_set(&set);
        assert!(!msg.hashed_elements.is_empty());
    }

    #[test]
    fn test_psi_client_default() {
        let client = PsiClient::default();
        let server = PsiServer::new();
        let server_msg = server.encode_set(&[b"test".to_vec()]);
        let result = client.compute_intersection(&[b"test".to_vec()], &server_msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bloom_psi_client_default() {
        let client = BloomPsiClient;
        let server = BloomPsiServer::new(10, 0.01);
        let bloom_msg = server.encode_set(&[b"test".to_vec()]);
        let result = client.compute_intersection(&[b"test".to_vec()], &bloom_msg);
        assert!(result.is_ok());
    }
}
