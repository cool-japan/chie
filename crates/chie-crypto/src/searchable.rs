//! Searchable Encryption for privacy-preserving keyword search.
//!
//! This module provides searchable symmetric encryption (SSE) that allows
//! searching encrypted data without decrypting it.
//!
//! # Use Cases in CHIE Protocol
//!
//! - **Encrypted Content Catalogs**: Search encrypted file metadata without revealing content
//! - **Privacy-Preserving Discovery**: Find content by keywords without exposing search queries
//! - **Delegated Search**: Allow authorized parties to search encrypted data
//!
//! # Protocol
//!
//! 1. **Index Generation**: Create encrypted index of keywords in documents
//! 2. **Trapdoor Generation**: Generate search token for a keyword (requires secret key)
//! 3. **Search**: Match trapdoor against encrypted index without decryption
//! 4. **Result Retrieval**: Return matching document IDs
//!
//! # Security
//!
//! - Server cannot learn: keywords, queries, or plaintext document content
//! - Server can learn: search pattern (which queries match), access pattern (which documents match)
//! - This is a deterministic SSE scheme (same keyword always produces same trapdoor)
//!
//! # Example
//!
//! ```
//! use chie_crypto::searchable::{SearchableEncryption, EncryptedIndex};
//!
//! // Create searchable encryption instance
//! let sse = SearchableEncryption::new();
//!
//! // Build encrypted index
//! let mut index = EncryptedIndex::new(&sse);
//! index.add_document(1, &[b"rust".to_vec(), b"crypto".to_vec()]);
//! index.add_document(2, &[b"crypto".to_vec(), b"p2p".to_vec()]);
//! index.add_document(3, &[b"rust".to_vec(), b"p2p".to_vec()]);
//!
//! // Generate search trapdoor
//! let trapdoor = sse.generate_trapdoor(b"crypto");
//!
//! // Search the encrypted index
//! let results = index.search(&trapdoor);
//! assert_eq!(results.len(), 2); // Documents 1 and 2
//! assert!(results.contains(&1));
//! assert!(results.contains(&2));
//! ```

use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SearchableError {
    #[error("Invalid trapdoor")]
    InvalidTrapdoor,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Empty keyword")]
    EmptyKeyword,
}

pub type SearchableResult<T> = Result<T, SearchableError>;

/// Searchable symmetric encryption instance with master key
pub struct SearchableEncryption {
    master_key: [u8; 32],
}

impl SearchableEncryption {
    /// Create a new searchable encryption instance with random key
    pub fn new() -> Self {
        let mut master_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut master_key);
        Self { master_key }
    }

    /// Create instance with specific key (for testing/key sharing)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { master_key: key }
    }

    /// Generate a search trapdoor for a keyword
    ///
    /// The trapdoor allows searching for the keyword without revealing it
    pub fn generate_trapdoor(&self, keyword: &[u8]) -> Trapdoor {
        let token = self.compute_keyword_token(keyword);
        Trapdoor { token }
    }

    /// Encrypt a keyword for the index
    fn encrypt_keyword(&self, keyword: &[u8]) -> Vec<u8> {
        self.compute_keyword_token(keyword)
    }

    /// Compute deterministic token for keyword
    fn compute_keyword_token(&self, keyword: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(&self.master_key);
        hasher.update(b"keyword-token");
        hasher.update(keyword);
        hasher.finalize().as_bytes()[..].to_vec()
    }

    /// Get master key bytes (for serialization/backup)
    pub fn export_key(&self) -> [u8; 32] {
        self.master_key
    }
}

impl Default for SearchableEncryption {
    fn default() -> Self {
        Self::new()
    }
}

/// Search trapdoor that allows searching without revealing the keyword
#[derive(Clone, Serialize, Deserialize)]
pub struct Trapdoor {
    token: Vec<u8>,
}

impl Trapdoor {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> SearchableResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| SearchableError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> SearchableResult<Self> {
        crate::codec::decode(bytes).map_err(|e| SearchableError::Serialization(e.to_string()))
    }
}

/// Document ID type
pub type DocumentId = u64;

/// Encrypted searchable index
pub struct EncryptedIndex {
    /// Map from encrypted keyword to set of document IDs
    index: HashMap<Vec<u8>, HashSet<DocumentId>>,
    /// Reference to SSE instance
    sse_key: [u8; 32],
}

impl EncryptedIndex {
    /// Create a new encrypted index
    pub fn new(sse: &SearchableEncryption) -> Self {
        Self {
            index: HashMap::new(),
            sse_key: sse.master_key,
        }
    }

    /// Add a document with its keywords to the index
    ///
    /// # Parameters
    /// - `doc_id`: Unique document identifier
    /// - `keywords`: List of keywords associated with the document
    pub fn add_document(&mut self, doc_id: DocumentId, keywords: &[Vec<u8>]) {
        let sse = SearchableEncryption::with_key(self.sse_key);

        for keyword in keywords {
            let encrypted_keyword = sse.encrypt_keyword(keyword);
            self.index
                .entry(encrypted_keyword)
                .or_default()
                .insert(doc_id);
        }
    }

    /// Remove a document from the index
    pub fn remove_document(&mut self, doc_id: DocumentId) {
        // Remove document ID from all keyword entries
        for doc_set in self.index.values_mut() {
            doc_set.remove(&doc_id);
        }

        // Clean up empty entries
        self.index.retain(|_, doc_set| !doc_set.is_empty());
    }

    /// Search the index using a trapdoor
    ///
    /// Returns the set of document IDs that match the keyword
    pub fn search(&self, trapdoor: &Trapdoor) -> Vec<DocumentId> {
        self.index
            .get(&trapdoor.token)
            .map(|doc_set| doc_set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get total number of unique keywords in index
    pub fn keyword_count(&self) -> usize {
        self.index.len()
    }

    /// Get total number of documents in index
    pub fn document_count(&self) -> usize {
        let mut all_docs: HashSet<DocumentId> = HashSet::new();
        for doc_set in self.index.values() {
            all_docs.extend(doc_set);
        }
        all_docs.len()
    }
}

/// Multi-keyword search (AND operation)
pub struct MultiKeywordSearch<'a> {
    index: &'a EncryptedIndex,
}

impl<'a> MultiKeywordSearch<'a> {
    /// Create a new multi-keyword search instance
    pub fn new(index: &'a EncryptedIndex) -> Self {
        Self { index }
    }

    /// Search for documents containing ALL keywords (conjunction)
    pub fn search_and(&self, trapdoors: &[Trapdoor]) -> Vec<DocumentId> {
        if trapdoors.is_empty() {
            return Vec::new();
        }

        // Start with results from first trapdoor
        let mut result: HashSet<DocumentId> =
            self.index.search(&trapdoors[0]).into_iter().collect();

        // Intersect with results from other trapdoors
        for trapdoor in &trapdoors[1..] {
            let docs: HashSet<DocumentId> = self.index.search(trapdoor).into_iter().collect();
            result.retain(|doc_id| docs.contains(doc_id));
        }

        result.into_iter().collect()
    }

    /// Search for documents containing ANY keyword (disjunction)
    pub fn search_or(&self, trapdoors: &[Trapdoor]) -> Vec<DocumentId> {
        let mut result = HashSet::new();

        for trapdoor in trapdoors {
            let docs = self.index.search(trapdoor);
            result.extend(docs);
        }

        result.into_iter().collect()
    }
}

/// Builder for encrypted index with bulk operations
pub struct EncryptedIndexBuilder {
    index: HashMap<Vec<u8>, HashSet<DocumentId>>,
    sse_key: [u8; 32],
}

impl EncryptedIndexBuilder {
    /// Create a new index builder
    pub fn new(sse: &SearchableEncryption) -> Self {
        Self {
            index: HashMap::new(),
            sse_key: sse.master_key,
        }
    }

    /// Add a document
    pub fn add_document(mut self, doc_id: DocumentId, keywords: &[Vec<u8>]) -> Self {
        let sse = SearchableEncryption::with_key(self.sse_key);

        for keyword in keywords {
            let encrypted_keyword = sse.encrypt_keyword(keyword);
            self.index
                .entry(encrypted_keyword)
                .or_default()
                .insert(doc_id);
        }

        self
    }

    /// Build the final index
    pub fn build(self) -> EncryptedIndex {
        EncryptedIndex {
            index: self.index,
            sse_key: self.sse_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_searchable_basic() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"rust".to_vec(), b"crypto".to_vec()]);
        index.add_document(2, &[b"crypto".to_vec()]);

        let trapdoor = sse.generate_trapdoor(b"crypto");
        let results = index.search(&trapdoor);

        assert_eq!(results.len(), 2);
        assert!(results.contains(&1));
        assert!(results.contains(&2));
    }

    #[test]
    fn test_no_matches() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"rust".to_vec()]);

        let trapdoor = sse.generate_trapdoor(b"python");
        let results = index.search(&trapdoor);

        assert!(results.is_empty());
    }

    #[test]
    fn test_remove_document() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"keyword".to_vec()]);
        index.add_document(2, &[b"keyword".to_vec()]);

        let trapdoor = sse.generate_trapdoor(b"keyword");
        assert_eq!(index.search(&trapdoor).len(), 2);

        index.remove_document(1);
        let results = index.search(&trapdoor);
        assert_eq!(results.len(), 1);
        assert!(results.contains(&2));
    }

    #[test]
    fn test_keyword_count() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"key1".to_vec(), b"key2".to_vec()]);
        index.add_document(2, &[b"key2".to_vec(), b"key3".to_vec()]);

        assert_eq!(index.keyword_count(), 3);
    }

    #[test]
    fn test_document_count() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"key1".to_vec()]);
        index.add_document(2, &[b"key2".to_vec()]);
        index.add_document(3, &[b"key3".to_vec()]);

        assert_eq!(index.document_count(), 3);
    }

    #[test]
    fn test_multi_keyword_and() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"rust".to_vec(), b"crypto".to_vec()]);
        index.add_document(2, &[b"crypto".to_vec()]);
        index.add_document(3, &[b"rust".to_vec(), b"crypto".to_vec()]);

        let trapdoors = vec![
            sse.generate_trapdoor(b"rust"),
            sse.generate_trapdoor(b"crypto"),
        ];

        let search = MultiKeywordSearch::new(&index);
        let results = search.search_and(&trapdoors);

        assert_eq!(results.len(), 2);
        assert!(results.contains(&1));
        assert!(results.contains(&3));
    }

    #[test]
    fn test_multi_keyword_or() {
        let sse = SearchableEncryption::new();
        let mut index = EncryptedIndex::new(&sse);

        index.add_document(1, &[b"rust".to_vec()]);
        index.add_document(2, &[b"go".to_vec()]);
        index.add_document(3, &[b"python".to_vec()]);

        let trapdoors = vec![sse.generate_trapdoor(b"rust"), sse.generate_trapdoor(b"go")];

        let search = MultiKeywordSearch::new(&index);
        let results = search.search_or(&trapdoors);

        assert_eq!(results.len(), 2);
        assert!(results.contains(&1));
        assert!(results.contains(&2));
    }

    #[test]
    fn test_trapdoor_serialization() {
        let sse = SearchableEncryption::new();
        let trapdoor = sse.generate_trapdoor(b"keyword");

        let bytes = trapdoor.to_bytes().unwrap();
        let deserialized = Trapdoor::from_bytes(&bytes).unwrap();

        let mut index = EncryptedIndex::new(&sse);
        index.add_document(1, &[b"keyword".to_vec()]);

        let results1 = index.search(&trapdoor);
        let results2 = index.search(&deserialized);
        assert_eq!(results1, results2);
    }

    #[test]
    fn test_deterministic_trapdoor() {
        let sse = SearchableEncryption::new();

        let td1 = sse.generate_trapdoor(b"keyword");
        let td2 = sse.generate_trapdoor(b"keyword");

        let bytes1 = td1.to_bytes().unwrap();
        let bytes2 = td2.to_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_index_builder() {
        let sse = SearchableEncryption::new();

        let index = EncryptedIndexBuilder::new(&sse)
            .add_document(1, &[b"rust".to_vec()])
            .add_document(2, &[b"crypto".to_vec()])
            .build();

        assert_eq!(index.document_count(), 2);
        assert_eq!(index.keyword_count(), 2);
    }

    #[test]
    fn test_sse_default() {
        let sse = SearchableEncryption::default();
        let trapdoor = sse.generate_trapdoor(b"test");
        assert!(!trapdoor.to_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_export_import_key() {
        let sse1 = SearchableEncryption::new();
        let key = sse1.export_key();
        let sse2 = SearchableEncryption::with_key(key);

        let td1 = sse1.generate_trapdoor(b"test");
        let td2 = sse2.generate_trapdoor(b"test");

        assert_eq!(td1.to_bytes().unwrap(), td2.to_bytes().unwrap());
    }

    #[test]
    fn test_empty_trapdoors_and() {
        let sse = SearchableEncryption::new();
        let index = EncryptedIndex::new(&sse);
        let search = MultiKeywordSearch::new(&index);

        let results = search.search_and(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_empty_trapdoors_or() {
        let sse = SearchableEncryption::new();
        let index = EncryptedIndex::new(&sse);
        let search = MultiKeywordSearch::new(&index);

        let results = search.search_or(&[]);
        assert!(results.is_empty());
    }
}
