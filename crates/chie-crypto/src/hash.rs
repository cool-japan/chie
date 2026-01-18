//! Fast hashing using BLAKE3.
//!
//! This module provides:
//! - Simple one-shot hashing
//! - Incremental hashing for large files
//! - Keyed hashing for MACs
//! - Parallel chunk hashing

use std::io::{self, Read};

/// Hash output (256 bits).
pub type Hash = [u8; 32];

/// Default buffer size for incremental hashing (64 KB).
pub const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Compute BLAKE3 hash of data.
pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Compute BLAKE3 hash of multiple data chunks.
pub fn hash_multi(chunks: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

/// Verify that data matches the expected hash.
pub fn verify_hash(data: &[u8], expected: &Hash) -> bool {
    &hash(data) == expected
}

/// Compute keyed BLAKE3 hash (for MAC).
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Incremental hasher for streaming large data.
///
/// This allows hashing data piece by piece without loading
/// the entire content into memory.
///
/// # Example
///
/// ```
/// use chie_crypto::IncrementalHasher;
///
/// let mut hasher = IncrementalHasher::new();
/// hasher.update(b"Hello, ");
/// hasher.update(b"World!");
/// let hash = hasher.finalize();
/// ```
pub struct IncrementalHasher {
    inner: blake3::Hasher,
    bytes_processed: u64,
}

impl Default for IncrementalHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalHasher {
    /// Create a new incremental hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
            bytes_processed: 0,
        }
    }

    /// Create a keyed incremental hasher.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
            bytes_processed: 0,
        }
    }

    /// Update the hasher with more data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
        self.bytes_processed += data.len() as u64;
    }

    /// Get the number of bytes processed so far.
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Finalize and return the hash.
    pub fn finalize(self) -> Hash {
        *self.inner.finalize().as_bytes()
    }

    /// Finalize but keep the hasher state (for XOF usage).
    pub fn finalize_reset(&mut self) -> Hash {
        let hash = *self.inner.finalize().as_bytes();
        self.inner.reset();
        self.bytes_processed = 0;
        hash
    }

    /// Hash data from a reader incrementally.
    ///
    /// This is useful for hashing large files without loading
    /// them entirely into memory.
    pub fn update_reader<R: Read>(&mut self, reader: &mut R) -> io::Result<u64> {
        let mut buffer = [0u8; HASH_BUFFER_SIZE];
        let mut total = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            self.update(&buffer[..bytes_read]);
            total += bytes_read as u64;
        }

        Ok(total)
    }
}

/// Hash a reader (file, network stream, etc.) incrementally.
pub fn hash_reader<R: Read>(reader: &mut R) -> io::Result<Hash> {
    let mut hasher = IncrementalHasher::new();
    hasher.update_reader(reader)?;
    Ok(hasher.finalize())
}

/// Result of hashing with metadata.
#[derive(Debug, Clone)]
pub struct HashResult {
    /// The computed hash.
    pub hash: Hash,
    /// Total bytes processed.
    pub bytes_processed: u64,
}

/// Hash multiple chunks and return individual hashes plus root hash.
///
/// This is useful for content-addressed storage where we need
/// both per-chunk hashes and an overall content hash.
pub struct ChunkHasher {
    chunk_hashes: Vec<Hash>,
    root_hasher: IncrementalHasher,
}

impl Default for ChunkHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkHasher {
    /// Create a new chunk hasher.
    pub fn new() -> Self {
        Self {
            chunk_hashes: Vec::new(),
            root_hasher: IncrementalHasher::new(),
        }
    }

    /// Add a chunk and compute its hash.
    pub fn add_chunk(&mut self, chunk: &[u8]) -> Hash {
        let chunk_hash = hash(chunk);
        self.chunk_hashes.push(chunk_hash);
        self.root_hasher.update(&chunk_hash);
        chunk_hash
    }

    /// Get the number of chunks processed.
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }

    /// Get all chunk hashes.
    pub fn chunk_hashes(&self) -> &[Hash] {
        &self.chunk_hashes
    }

    /// Finalize and return the root hash (hash of all chunk hashes).
    pub fn finalize(self) -> ChunkHashResult {
        ChunkHashResult {
            chunk_hashes: self.chunk_hashes,
            root_hash: self.root_hasher.finalize(),
        }
    }
}

/// Result of chunk hashing.
#[derive(Debug, Clone)]
pub struct ChunkHashResult {
    /// Individual chunk hashes.
    pub chunk_hashes: Vec<Hash>,
    /// Root hash (hash of all chunk hashes).
    pub root_hash: Hash,
}

impl ChunkHashResult {
    /// Verify a specific chunk.
    pub fn verify_chunk(&self, index: usize, chunk: &[u8]) -> bool {
        if index >= self.chunk_hashes.len() {
            return false;
        }
        hash(chunk) == self.chunk_hashes[index]
    }

    /// Get the number of chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }
}

/// Hash content in chunks from a reader.
pub fn hash_chunked<R: Read>(reader: &mut R, chunk_size: usize) -> io::Result<ChunkHashResult> {
    let mut chunk_hasher = ChunkHasher::new();
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let mut total_read = 0;

        // Read a full chunk (or until EOF)
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

        chunk_hasher.add_chunk(&buffer[..total_read]);

        if total_read < chunk_size {
            // EOF reached mid-chunk
            break;
        }
    }

    Ok(chunk_hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_hash() {
        let data = b"Hello, CHIE Protocol!";
        let h = hash(data);

        assert!(verify_hash(data, &h));
        assert!(!verify_hash(b"Different data", &h));
    }

    #[test]
    fn test_hash_multi() {
        let chunk1 = b"Hello, ";
        let chunk2 = b"CHIE Protocol!";
        let combined = b"Hello, CHIE Protocol!";

        let h_multi = hash_multi(&[chunk1, chunk2]);
        let h_combined = hash(combined);

        assert_eq!(h_multi, h_combined);
    }

    #[test]
    fn test_incremental_hasher() {
        let data = b"Hello, CHIE Protocol!";

        // One-shot hash
        let h1 = hash(data);

        // Incremental hash
        let mut hasher = IncrementalHasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"CHIE ");
        hasher.update(b"Protocol!");
        let h2 = hasher.finalize();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_reader() {
        let data = b"Hello, CHIE Protocol!";
        let mut cursor = Cursor::new(data);

        let h1 = hash(data);
        let h2 = hash_reader(&mut cursor).unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_chunk_hasher() {
        let chunk1 = b"Chunk 1 data";
        let chunk2 = b"Chunk 2 data";
        let chunk3 = b"Chunk 3 data";

        let mut hasher = ChunkHasher::new();
        hasher.add_chunk(chunk1);
        hasher.add_chunk(chunk2);
        hasher.add_chunk(chunk3);

        let result = hasher.finalize();

        assert_eq!(result.chunk_count(), 3);
        assert!(result.verify_chunk(0, chunk1));
        assert!(result.verify_chunk(1, chunk2));
        assert!(result.verify_chunk(2, chunk3));
        assert!(!result.verify_chunk(0, chunk2));
    }

    #[test]
    fn test_hash_chunked() {
        let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut cursor = Cursor::new(data);

        let result = hash_chunked(&mut cursor, 10).unwrap();

        // 26 bytes / 10 = 3 chunks (10 + 10 + 6)
        assert_eq!(result.chunk_count(), 3);
        assert!(result.verify_chunk(0, b"ABCDEFGHIJ"));
        assert!(result.verify_chunk(1, b"KLMNOPQRST"));
        assert!(result.verify_chunk(2, b"UVWXYZ"));
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0u8; 32];
        let data = b"Hello, CHIE Protocol!";

        let h1 = keyed_hash(&key, data);
        let h2 = keyed_hash(&key, data);
        let h3 = keyed_hash(&[1u8; 32], data);

        assert_eq!(h1, h2);
        assert_ne!(h1, h3); // Different key = different hash
    }
}
