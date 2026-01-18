//! Content deduplication for storage efficiency.
//!
//! This module provides chunk-level deduplication using BLAKE3 hashes
//! to identify identical chunks across different content.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Deduplication configuration.
#[derive(Debug, Clone)]
pub struct DedupConfig {
    /// Minimum reference count before a chunk is eligible for dedup.
    pub min_ref_count: u32,
    /// Enable inline deduplication (during storage).
    pub enable_inline_dedup: bool,
    /// Enable background deduplication.
    pub enable_background_dedup: bool,
    /// Minimum chunk size for deduplication (bytes).
    pub min_chunk_size: usize,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            min_ref_count: 2,
            enable_inline_dedup: true,
            enable_background_dedup: true,
            min_chunk_size: 4096, // 4 KB minimum
        }
    }
}

/// Reference to a deduplicated chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkRef {
    /// BLAKE3 hash of the chunk (content-addressable key).
    pub hash: [u8; 32],
    /// Size of the chunk in bytes.
    pub size: u64,
    /// Reference count (how many content items reference this chunk).
    pub ref_count: u32,
    /// Path to the actual chunk data (relative to dedup store).
    pub storage_path: String,
}

/// Deduplication entry for tracking chunk usage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DedupEntry {
    /// Chunk hash.
    pub hash: [u8; 32],
    /// Content CIDs that reference this chunk.
    pub references: Vec<ChunkReference>,
    /// Total size saved by deduplication (bytes).
    pub bytes_saved: u64,
    /// When this entry was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Reference from content to a chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkReference {
    /// Content CID.
    pub cid: String,
    /// Chunk index within the content.
    pub chunk_index: u64,
}

/// Deduplication store for managing deduplicated chunks.
pub struct DedupStore {
    config: DedupConfig,
    /// Base path for dedup storage.
    base_path: PathBuf,
    /// In-memory index of chunk hashes to refs.
    index: Arc<RwLock<HashMap<[u8; 32], ChunkRef>>>,
    /// Reverse index: content CID -> chunk hashes.
    content_chunks: Arc<RwLock<HashMap<String, Vec<[u8; 32]>>>>,
    /// Deduplication statistics.
    stats: Arc<RwLock<DedupStats>>,
}

/// Deduplication statistics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DedupStats {
    /// Total unique chunks stored.
    pub unique_chunks: u64,
    /// Total chunk references (including duplicates).
    pub total_references: u64,
    /// Total bytes saved by deduplication.
    pub bytes_saved: u64,
    /// Total bytes stored (after dedup).
    pub bytes_stored: u64,
    /// Deduplication ratio (total_references / unique_chunks).
    pub dedup_ratio: f64,
    /// Space savings percentage.
    pub space_savings_percent: f64,
}

impl DedupStats {
    /// Update derived statistics.
    #[inline]
    pub fn update(&mut self) {
        if self.unique_chunks > 0 {
            self.dedup_ratio = self.total_references as f64 / self.unique_chunks as f64;
        }
        let total_logical = self.bytes_stored + self.bytes_saved;
        if total_logical > 0 {
            self.space_savings_percent = (self.bytes_saved as f64 / total_logical as f64) * 100.0;
        }
    }
}

/// Result of storing a chunk with deduplication.
#[derive(Debug, Clone)]
pub enum StoreResult {
    /// Chunk was new and stored.
    Stored { hash: [u8; 32], size: u64 },
    /// Chunk was a duplicate, reference added.
    Deduplicated { hash: [u8; 32], bytes_saved: u64 },
}

impl DedupStore {
    /// Create a new deduplication store.
    pub async fn new(base_path: PathBuf, config: DedupConfig) -> std::io::Result<Self> {
        // Create directories
        fs::create_dir_all(&base_path).await?;
        fs::create_dir_all(base_path.join("chunks")).await?;
        fs::create_dir_all(base_path.join("meta")).await?;

        let store = Self {
            config,
            base_path,
            index: Arc::new(RwLock::new(HashMap::new())),
            content_chunks: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DedupStats::default())),
        };

        // Load existing index
        store.load_index().await?;

        Ok(store)
    }

    /// Store a chunk with deduplication.
    pub async fn store_chunk(
        &self,
        cid: &str,
        _chunk_index: u64,
        data: &[u8],
    ) -> std::io::Result<StoreResult> {
        // Skip small chunks
        if data.len() < self.config.min_chunk_size {
            return Ok(StoreResult::Stored {
                hash: [0u8; 32],
                size: data.len() as u64,
            });
        }

        // Calculate hash
        let hash = chie_crypto::hash(data);

        let mut index = self.index.write().await;
        let mut content_chunks = self.content_chunks.write().await;
        let mut stats = self.stats.write().await;

        // Check if chunk already exists
        if let Some(chunk_ref) = index.get_mut(&hash) {
            // Duplicate found
            chunk_ref.ref_count += 1;
            let bytes_saved = data.len() as u64;

            // Add to content's chunk list
            content_chunks
                .entry(cid.to_string())
                .or_default()
                .push(hash);

            // Update stats
            stats.total_references += 1;
            stats.bytes_saved += bytes_saved;
            stats.update();

            debug!(
                "Deduplicated chunk: {} refs for hash {:?}",
                chunk_ref.ref_count,
                hex::encode(&hash[..8])
            );

            return Ok(StoreResult::Deduplicated { hash, bytes_saved });
        }

        // New chunk - store it
        let storage_path = self.chunk_path(&hash);
        // Ensure parent directory exists
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&storage_path, data).await?;

        let chunk_ref = ChunkRef {
            hash,
            size: data.len() as u64,
            ref_count: 1,
            storage_path: storage_path.to_string_lossy().to_string(),
        };

        index.insert(hash, chunk_ref);

        // Add to content's chunk list
        content_chunks
            .entry(cid.to_string())
            .or_default()
            .push(hash);

        // Update stats
        stats.unique_chunks += 1;
        stats.total_references += 1;
        stats.bytes_stored += data.len() as u64;
        stats.update();

        // Save index periodically
        drop(index);
        drop(content_chunks);
        drop(stats);
        self.save_index().await?;

        Ok(StoreResult::Stored {
            hash,
            size: data.len() as u64,
        })
    }

    /// Retrieve a chunk by hash.
    pub async fn get_chunk(&self, hash: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        let index = self.index.read().await;

        if let Some(chunk_ref) = index.get(hash) {
            let path = Path::new(&chunk_ref.storage_path);
            if path.exists() {
                let data = fs::read(path).await?;
                return Ok(Some(data));
            }
        }

        Ok(None)
    }

    /// Get a chunk by content CID and chunk index.
    pub async fn get_content_chunk(
        &self,
        cid: &str,
        chunk_index: u64,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let content_chunks = self.content_chunks.read().await;

        if let Some(hashes) = content_chunks.get(cid) {
            if let Some(hash) = hashes.get(chunk_index as usize) {
                return self.get_chunk(hash).await;
            }
        }

        Ok(None)
    }

    /// Remove references for a content item.
    pub async fn remove_content(&self, cid: &str) -> std::io::Result<u64> {
        let mut index = self.index.write().await;
        let mut content_chunks = self.content_chunks.write().await;
        let mut stats = self.stats.write().await;

        let mut bytes_freed = 0u64;

        if let Some(hashes) = content_chunks.remove(cid) {
            for hash in hashes {
                if let Some(chunk_ref) = index.get_mut(&hash) {
                    chunk_ref.ref_count -= 1;
                    stats.total_references -= 1;

                    if chunk_ref.ref_count == 0 {
                        // No more references, delete the chunk
                        let path = Path::new(&chunk_ref.storage_path);
                        if path.exists() {
                            fs::remove_file(path).await?;
                        }
                        bytes_freed += chunk_ref.size;
                        stats.unique_chunks -= 1;
                        stats.bytes_stored -= chunk_ref.size;
                        index.remove(&hash);
                    }
                }
            }
        }

        stats.update();

        drop(index);
        drop(content_chunks);
        drop(stats);
        self.save_index().await?;

        info!("Removed content {} - freed {} bytes", cid, bytes_freed);
        Ok(bytes_freed)
    }

    /// Get deduplication statistics.
    #[must_use]
    #[inline]
    pub async fn stats(&self) -> DedupStats {
        self.stats.read().await.clone()
    }

    /// Check if a chunk hash exists.
    #[must_use]
    #[inline]
    pub async fn contains(&self, hash: &[u8; 32]) -> bool {
        let index = self.index.read().await;
        index.contains_key(hash)
    }

    /// Get chunk reference count.
    #[must_use]
    #[inline]
    pub async fn ref_count(&self, hash: &[u8; 32]) -> Option<u32> {
        let index = self.index.read().await;
        index.get(hash).map(|r| r.ref_count)
    }

    /// List all content CIDs in the store.
    #[must_use]
    #[inline]
    pub async fn list_content(&self) -> Vec<String> {
        let content_chunks = self.content_chunks.read().await;
        content_chunks.keys().cloned().collect()
    }

    /// Get content info.
    #[must_use]
    #[inline]
    pub async fn content_info(&self, cid: &str) -> Option<ContentDedupInfo> {
        let index = self.index.read().await;
        let content_chunks = self.content_chunks.read().await;

        if let Some(hashes) = content_chunks.get(cid) {
            let mut total_size = 0u64;
            let mut unique_chunks = 0u64;
            let mut shared_chunks = 0u64;

            for hash in hashes {
                if let Some(chunk_ref) = index.get(hash) {
                    total_size += chunk_ref.size;
                    if chunk_ref.ref_count == 1 {
                        unique_chunks += 1;
                    } else {
                        shared_chunks += 1;
                    }
                }
            }

            return Some(ContentDedupInfo {
                cid: cid.to_string(),
                total_chunks: hashes.len() as u64,
                unique_chunks,
                shared_chunks,
                total_size,
            });
        }

        None
    }

    /// Run garbage collection to remove orphaned chunks.
    pub async fn gc(&self) -> std::io::Result<GcResult> {
        let mut index = self.index.write().await;
        let mut stats = self.stats.write().await;

        let mut orphaned: Vec<[u8; 32]> = Vec::new();
        let mut bytes_freed = 0u64;

        for (hash, chunk_ref) in index.iter() {
            if chunk_ref.ref_count == 0 {
                orphaned.push(*hash);
            }
        }

        for hash in &orphaned {
            if let Some(chunk_ref) = index.remove(hash) {
                let path = Path::new(&chunk_ref.storage_path);
                if path.exists() {
                    fs::remove_file(path).await?;
                }
                bytes_freed += chunk_ref.size;
                stats.unique_chunks -= 1;
                stats.bytes_stored -= chunk_ref.size;
            }
        }

        stats.update();

        info!(
            "GC completed: {} orphaned chunks removed, {} bytes freed",
            orphaned.len(),
            bytes_freed
        );

        Ok(GcResult {
            chunks_removed: orphaned.len() as u64,
            bytes_freed,
        })
    }

    // Internal methods

    fn chunk_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hash_hex = hex::encode(hash);
        // Use first 2 chars as subdirectory for better filesystem performance
        let subdir = &hash_hex[..2];
        self.base_path.join("chunks").join(subdir).join(&hash_hex)
    }

    async fn load_index(&self) -> std::io::Result<()> {
        let index_path = self.base_path.join("meta").join("index.json");
        if !index_path.exists() {
            return Ok(());
        }

        let data = fs::read(&index_path).await?;
        let saved: SavedIndex = serde_json::from_slice(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Convert hex strings back to byte arrays
        let mut index = self.index.write().await;
        for (hex_key, value) in saved.chunks {
            if let Ok(bytes) = hex::decode(&hex_key) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    index.insert(key, value);
                }
            }
        }

        let mut content_chunks = self.content_chunks.write().await;
        for (cid, hex_hashes) in saved.content_chunks {
            let hashes: Vec<[u8; 32]> = hex_hashes
                .iter()
                .filter_map(|h| {
                    hex::decode(h).ok().and_then(|bytes| {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                })
                .collect();
            content_chunks.insert(cid, hashes);
        }

        let mut stats = self.stats.write().await;
        *stats = saved.stats;

        Ok(())
    }

    async fn save_index(&self) -> std::io::Result<()> {
        let index = self.index.read().await;
        let content_chunks = self.content_chunks.read().await;
        let stats = self.stats.read().await;

        // Convert byte array keys to hex strings for JSON
        let chunks_hex: HashMap<String, ChunkRef> = index
            .iter()
            .map(|(k, v)| (hex::encode(k), v.clone()))
            .collect();

        let content_chunks_hex: HashMap<String, Vec<String>> = content_chunks
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().map(hex::encode).collect()))
            .collect();

        let saved = SavedIndex {
            chunks: chunks_hex,
            content_chunks: content_chunks_hex,
            stats: stats.clone(),
        };

        let data = serde_json::to_vec_pretty(&saved)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let index_path = self.base_path.join("meta").join("index.json");
        fs::write(&index_path, data).await?;

        Ok(())
    }
}

/// Content deduplication info.
#[derive(Debug, Clone)]
pub struct ContentDedupInfo {
    /// Content CID.
    pub cid: String,
    /// Total number of chunks.
    pub total_chunks: u64,
    /// Chunks unique to this content.
    pub unique_chunks: u64,
    /// Chunks shared with other content.
    pub shared_chunks: u64,
    /// Total logical size.
    pub total_size: u64,
}

/// Garbage collection result.
#[derive(Debug, Clone)]
pub struct GcResult {
    /// Number of chunks removed.
    pub chunks_removed: u64,
    /// Bytes freed.
    pub bytes_freed: u64,
}

/// Saved index structure (uses hex strings for JSON compatibility).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SavedIndex {
    chunks: HashMap<String, ChunkRef>,
    content_chunks: HashMap<String, Vec<String>>,
    stats: DedupStats,
}

/// Reference tracking entry for detailed auditing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReferenceEntry {
    /// Content CID that references this chunk.
    pub cid: String,
    /// Chunk index within the content.
    pub chunk_index: u64,
    /// When this reference was created.
    pub created_at: u64,
}

/// Enhanced chunk reference with detailed tracking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnhancedChunkRef {
    /// BLAKE3 hash of the chunk.
    pub hash: [u8; 32],
    /// Size of the chunk in bytes.
    pub size: u64,
    /// List of all references to this chunk.
    pub references: Vec<ReferenceEntry>,
    /// Path to the actual chunk data.
    pub storage_path: String,
}

impl EnhancedChunkRef {
    /// Get the reference count.
    #[must_use]
    #[inline]
    pub fn ref_count(&self) -> u32 {
        self.references.len() as u32
    }

    /// Check if a specific content references this chunk.
    #[must_use]
    #[inline]
    pub fn is_referenced_by(&self, cid: &str) -> bool {
        self.references.iter().any(|r| r.cid == cid)
    }

    /// Get all CIDs that reference this chunk.
    #[must_use]
    #[inline]
    pub fn get_referencing_cids(&self) -> Vec<String> {
        self.references.iter().map(|r| r.cid.clone()).collect()
    }
}

/// Result of a reference integrity check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityCheckResult {
    /// Number of chunks checked.
    pub chunks_checked: u64,
    /// Number of chunks with mismatched ref counts.
    pub mismatches_found: u64,
    /// Number of orphaned chunks (zero refs).
    pub orphaned_chunks: u64,
    /// Number of missing chunk files.
    pub missing_files: u64,
    /// Total bytes in orphaned chunks.
    pub orphaned_bytes: u64,
}

impl DedupStore {
    /// Get all references for a specific chunk hash.
    #[must_use]
    pub async fn get_chunk_references(&self, hash: &[u8; 32]) -> Option<Vec<ChunkReference>> {
        let content_chunks = self.content_chunks.read().await;

        let mut references = Vec::new();
        for (cid, hashes) in content_chunks.iter() {
            for (index, chunk_hash) in hashes.iter().enumerate() {
                if chunk_hash == hash {
                    references.push(ChunkReference {
                        cid: cid.clone(),
                        chunk_index: index as u64,
                    });
                }
            }
        }

        if references.is_empty() {
            None
        } else {
            Some(references)
        }
    }

    /// List all chunks referenced by a specific content.
    #[must_use]
    pub async fn get_content_chunks_detailed(&self, cid: &str) -> Option<Vec<EnhancedChunkRef>> {
        // First, collect the chunk data we need
        let chunk_data: Vec<([u8; 32], u64, String)> = {
            let index = self.index.read().await;
            let content_chunks = self.content_chunks.read().await;

            if let Some(hashes) = content_chunks.get(cid) {
                hashes
                    .iter()
                    .filter_map(|hash| {
                        index.get(hash).map(|chunk_ref| {
                            (*hash, chunk_ref.size, chunk_ref.storage_path.clone())
                        })
                    })
                    .collect()
            } else {
                return None;
            }
        };

        // Now get references for each chunk (locks are released)
        let mut result = Vec::new();
        for (hash, size, storage_path) in chunk_data {
            let refs = self.get_chunk_references(&hash).await.unwrap_or_default();
            let references: Vec<ReferenceEntry> = refs
                .into_iter()
                .map(|r| ReferenceEntry {
                    cid: r.cid,
                    chunk_index: r.chunk_index,
                    created_at: current_timestamp(),
                })
                .collect();

            result.push(EnhancedChunkRef {
                hash,
                size,
                references,
                storage_path,
            });
        }

        Some(result)
    }

    /// Verify reference count integrity across the store.
    pub async fn verify_integrity(&self) -> std::io::Result<IntegrityCheckResult> {
        let index = self.index.read().await;
        let content_chunks = self.content_chunks.read().await;

        let mut chunks_checked = 0u64;
        let mut mismatches_found = 0u64;
        let mut orphaned_chunks = 0u64;
        let mut missing_files = 0u64;
        let mut orphaned_bytes = 0u64;

        // Count actual references for each chunk
        let mut actual_refs: HashMap<[u8; 32], u32> = HashMap::new();
        for hashes in content_chunks.values() {
            for hash in hashes {
                *actual_refs.entry(*hash).or_insert(0) += 1;
            }
        }

        // Verify each chunk
        for (hash, chunk_ref) in index.iter() {
            chunks_checked += 1;

            let actual_count = actual_refs.get(hash).copied().unwrap_or(0);

            // Check if ref count matches
            if actual_count != chunk_ref.ref_count {
                mismatches_found += 1;
                tracing::warn!(
                    "Ref count mismatch for chunk {:?}: stored={}, actual={}",
                    hex::encode(&hash[..8]),
                    chunk_ref.ref_count,
                    actual_count
                );
            }

            // Check if orphaned
            if actual_count == 0 {
                orphaned_chunks += 1;
                orphaned_bytes += chunk_ref.size;
            }

            // Check if file exists
            let path = Path::new(&chunk_ref.storage_path);
            if !path.exists() {
                missing_files += 1;
                tracing::warn!(
                    "Missing chunk file for hash {:?}: {}",
                    hex::encode(&hash[..8]),
                    chunk_ref.storage_path
                );
            }
        }

        Ok(IntegrityCheckResult {
            chunks_checked,
            mismatches_found,
            orphaned_chunks,
            missing_files,
            orphaned_bytes,
        })
    }

    /// Repair reference counts based on actual references.
    pub async fn repair_references(&self) -> std::io::Result<u64> {
        let mut index = self.index.write().await;
        let content_chunks = self.content_chunks.read().await;

        // Count actual references for each chunk
        let mut actual_refs: HashMap<[u8; 32], u32> = HashMap::new();
        for hashes in content_chunks.values() {
            for hash in hashes {
                *actual_refs.entry(*hash).or_insert(0) += 1;
            }
        }

        let mut repaired = 0u64;

        // Update ref counts
        for (hash, chunk_ref) in index.iter_mut() {
            let actual_count = actual_refs.get(hash).copied().unwrap_or(0);

            if actual_count != chunk_ref.ref_count {
                tracing::info!(
                    "Repairing chunk {:?}: {} -> {}",
                    hex::encode(&hash[..8]),
                    chunk_ref.ref_count,
                    actual_count
                );
                chunk_ref.ref_count = actual_count;
                repaired += 1;
            }
        }

        drop(index);
        drop(content_chunks);

        if repaired > 0 {
            self.save_index().await?;
        }

        info!("Repaired {} reference counts", repaired);
        Ok(repaired)
    }

    /// Get reference count distribution statistics.
    #[must_use]
    pub async fn ref_count_distribution(&self) -> HashMap<u32, u64> {
        let index = self.index.read().await;

        let mut distribution: HashMap<u32, u64> = HashMap::new();
        for chunk_ref in index.values() {
            *distribution.entry(chunk_ref.ref_count).or_insert(0) += 1;
        }

        distribution
    }

    /// Find the most frequently referenced chunks.
    #[must_use]
    pub async fn most_referenced_chunks(&self, limit: usize) -> Vec<([u8; 32], u32, u64)> {
        let index = self.index.read().await;

        let mut chunks: Vec<_> = index
            .iter()
            .map(|(hash, chunk_ref)| (*hash, chunk_ref.ref_count, chunk_ref.size))
            .collect();

        chunks.sort_by(|a, b| b.1.cmp(&a.1));
        chunks.truncate(limit);

        chunks
    }

    /// Calculate potential savings if content were removed.
    #[must_use]
    pub async fn calculate_removal_impact(&self, cid: &str) -> Option<RemovalImpact> {
        let index = self.index.read().await;
        let content_chunks = self.content_chunks.read().await;

        if let Some(hashes) = content_chunks.get(cid) {
            let mut bytes_freed = 0u64;
            let mut exclusive_chunks = 0u64;
            let mut shared_chunks = 0u64;

            for hash in hashes {
                if let Some(chunk_ref) = index.get(hash) {
                    if chunk_ref.ref_count == 1 {
                        // This chunk would be deleted
                        bytes_freed += chunk_ref.size;
                        exclusive_chunks += 1;
                    } else {
                        // This chunk is shared
                        shared_chunks += 1;
                    }
                }
            }

            Some(RemovalImpact {
                cid: cid.to_string(),
                bytes_freed,
                exclusive_chunks,
                shared_chunks,
                total_chunks: hashes.len() as u64,
            })
        } else {
            None
        }
    }

    /// Batch add references for multiple chunks.
    pub async fn add_references_batch(
        &self,
        cid: &str,
        chunk_hashes: Vec<[u8; 32]>,
    ) -> std::io::Result<u64> {
        let mut index = self.index.write().await;
        let mut content_chunks = self.content_chunks.write().await;

        let mut refs_added = 0u64;

        for hash in &chunk_hashes {
            if let Some(chunk_ref) = index.get_mut(hash) {
                chunk_ref.ref_count += 1;
                refs_added += 1;
            }
        }

        content_chunks.insert(cid.to_string(), chunk_hashes);

        drop(index);
        drop(content_chunks);
        self.save_index().await?;

        Ok(refs_added)
    }
}

/// Impact analysis for content removal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemovalImpact {
    /// Content CID.
    pub cid: String,
    /// Bytes that would be freed.
    pub bytes_freed: u64,
    /// Number of exclusive chunks (would be deleted).
    pub exclusive_chunks: u64,
    /// Number of shared chunks (would remain).
    pub shared_chunks: u64,
    /// Total chunks in content.
    pub total_chunks: u64,
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Find duplicate chunks between two content items.
pub async fn find_duplicates(store: &DedupStore, cid1: &str, cid2: &str) -> Vec<[u8; 32]> {
    let content_chunks = store.content_chunks.read().await;

    let hashes1 = content_chunks.get(cid1);
    let hashes2 = content_chunks.get(cid2);

    match (hashes1, hashes2) {
        (Some(h1), Some(h2)) => {
            let set1: std::collections::HashSet<_> = h1.iter().collect();
            h2.iter().filter(|h| set1.contains(h)).copied().collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dedup_store() {
        let temp_dir = std::env::temp_dir().join("chie_dedup_test");
        let _ = fs::remove_dir_all(&temp_dir).await;

        let store = DedupStore::new(temp_dir.clone(), DedupConfig::default())
            .await
            .unwrap();

        // Store same chunk twice for different content
        let data = vec![0u8; 8192]; // 8KB chunk

        let result1 = store.store_chunk("cid1", 0, &data).await.unwrap();
        assert!(matches!(result1, StoreResult::Stored { .. }));

        let result2 = store.store_chunk("cid2", 0, &data).await.unwrap();
        assert!(matches!(result2, StoreResult::Deduplicated { .. }));

        let stats = store.stats().await;
        assert_eq!(stats.unique_chunks, 1);
        assert_eq!(stats.total_references, 2);
        assert!(stats.bytes_saved > 0);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir).await;
    }
}
