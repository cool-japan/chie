//! Chunk storage and retrieval for CHIE Protocol.

use chie_crypto::{EncryptionKey, EncryptionNonce, StreamDecryptor, StreamEncryptor, hash};
use chie_shared::CHUNK_SIZE;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;

/// Storage error types.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Content not found: {cid}")]
    ContentNotFound { cid: String },

    #[error("Chunk not found: {cid}:{chunk_index}")]
    ChunkNotFound { cid: String, chunk_index: u64 },

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Storage quota exceeded: used {used} bytes, max {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("Invalid chunk size: {size} bytes")]
    InvalidChunkSize { size: usize },
}

/// Chunk metadata stored alongside the chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkMetadata {
    /// Content CID this chunk belongs to.
    pub cid: String,
    /// Chunk index within the content.
    pub chunk_index: u64,
    /// Size of the plaintext chunk.
    pub plaintext_size: usize,
    /// Size of the encrypted chunk (with auth tag).
    pub encrypted_size: usize,
    /// BLAKE3 hash of plaintext.
    pub hash: [u8; 32],
}

/// Pinned content info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinnedContentInfo {
    /// Content CID.
    pub cid: String,
    /// Total size in bytes.
    pub total_size: u64,
    /// Number of chunks.
    pub chunk_count: u64,
    /// Encryption key (encrypted with user's key in production).
    pub encryption_key: EncryptionKey,
    /// Base nonce for streaming encryption.
    pub base_nonce: EncryptionNonce,
    /// When the content was pinned.
    pub pinned_at: chrono::DateTime<chrono::Utc>,
}

/// Storage health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageHealthStatus {
    /// Healthy - no issues detected.
    Healthy,
    /// Warning - minor issues detected.
    Warning,
    /// Degraded - performance issues detected.
    Degraded,
    /// Critical - storage failing.
    Critical,
}

impl StorageHealthStatus {
    /// Get a numeric score for this health status (higher is better).
    #[must_use]
    #[inline]
    pub const fn score(&self) -> u8 {
        match self {
            Self::Healthy => 100,
            Self::Warning => 75,
            Self::Degraded => 50,
            Self::Critical => 25,
        }
    }

    /// Get description of this health status.
    #[must_use]
    #[inline]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Healthy => "Storage is healthy",
            Self::Warning => "Minor storage issues detected",
            Self::Degraded => "Storage performance degraded",
            Self::Critical => "Critical storage failure",
        }
    }
}

/// Storage health metrics.
#[derive(Debug, Clone)]
pub struct StorageHealth {
    /// Current health status.
    pub status: StorageHealthStatus,
    /// Number of I/O errors in the last sampling period.
    pub io_errors: u64,
    /// Number of slow operations (> threshold).
    pub slow_operations: u64,
    /// Average operation latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Peak operation latency in milliseconds.
    pub peak_latency_ms: u64,
    /// Disk usage percentage (0.0 to 1.0).
    pub disk_usage: f64,
    /// Rate of disk usage growth (bytes/sec).
    pub growth_rate: f64,
    /// Predicted time until full (seconds), None if not growing.
    pub time_until_full: Option<u64>,
    /// Last health check timestamp.
    pub last_check: std::time::Instant,
}

impl Default for StorageHealth {
    fn default() -> Self {
        Self {
            status: StorageHealthStatus::Healthy,
            io_errors: 0,
            slow_operations: 0,
            avg_latency_ms: 0.0,
            peak_latency_ms: 0,
            disk_usage: 0.0,
            growth_rate: 0.0,
            time_until_full: None,
            last_check: std::time::Instant::now(),
        }
    }
}

impl StorageHealth {
    /// Calculate health score (0.0 to 1.0).
    #[must_use]
    pub fn health_score(&self) -> f64 {
        let mut score = 1.0;

        // Penalize for I/O errors
        if self.io_errors > 0 {
            score -= (self.io_errors as f64 * 0.1).min(0.5);
        }

        // Penalize for slow operations
        if self.slow_operations > 10 {
            score -= 0.2;
        } else if self.slow_operations > 5 {
            score -= 0.1;
        }

        // Penalize for high latency
        if self.avg_latency_ms > 100.0 {
            score -= 0.2;
        } else if self.avg_latency_ms > 50.0 {
            score -= 0.1;
        }

        // Penalize for high disk usage
        if self.disk_usage > 0.95 {
            score -= 0.3;
        } else if self.disk_usage > 0.90 {
            score -= 0.2;
        } else if self.disk_usage > 0.80 {
            score -= 0.1;
        }

        score.max(0.0)
    }

    /// Predict if storage failure is imminent.
    #[must_use]
    pub fn is_failure_imminent(&self) -> bool {
        // Failure is imminent if:
        // 1. Critical status
        // 2. Will be full within 1 hour
        // 3. Too many I/O errors
        self.status == StorageHealthStatus::Critical
            || self.time_until_full.is_some_and(|t| t < 3600)
            || self.io_errors > 100
    }
}

/// Chunk storage manager.
pub struct ChunkStorage {
    /// Base storage directory.
    base_path: PathBuf,
    /// In-memory index of pinned content.
    pinned_content: HashMap<String, PinnedContentInfo>,
    /// Current storage usage in bytes.
    used_bytes: u64,
    /// Maximum storage quota in bytes.
    max_bytes: u64,
    /// Storage health metrics.
    health: StorageHealth,
    /// Previous storage usage for growth rate calculation.
    previous_usage: Option<(u64, std::time::Instant)>,
}

impl ChunkStorage {
    /// Create a new chunk storage.
    pub async fn new(base_path: PathBuf, max_bytes: u64) -> Result<Self, StorageError> {
        // Create base directory if it doesn't exist
        fs::create_dir_all(&base_path).await?;
        fs::create_dir_all(base_path.join("chunks")).await?;
        fs::create_dir_all(base_path.join("metadata")).await?;

        let mut storage = Self {
            base_path,
            pinned_content: HashMap::new(),
            used_bytes: 0,
            max_bytes,
            health: StorageHealth::default(),
            previous_usage: None,
        };

        // Load existing index
        storage.load_index().await?;

        // Initialize health metrics
        storage.update_health_metrics();

        Ok(storage)
    }

    /// Get the storage path.
    #[inline]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Get current storage usage.
    #[inline]
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Get maximum storage quota.
    #[inline]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Get available storage.
    #[inline]
    pub fn available_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.used_bytes)
    }

    /// Check if a content is pinned.
    #[inline]
    pub fn is_pinned(&self, cid: &str) -> bool {
        self.pinned_content.contains_key(cid)
    }

    /// Get pinned content info.
    #[inline]
    pub fn get_pinned_info(&self, cid: &str) -> Option<&PinnedContentInfo> {
        self.pinned_content.get(cid)
    }

    /// List all pinned content CIDs.
    pub fn list_pinned(&self) -> Vec<&str> {
        self.pinned_content.keys().map(|s| s.as_str()).collect()
    }

    /// Pin new content (store all chunks).
    pub async fn pin_content(
        &mut self,
        cid: &str,
        chunks: &[Vec<u8>],
        key: &EncryptionKey,
        nonce: &EncryptionNonce,
    ) -> Result<PinnedContentInfo, StorageError> {
        // Calculate total size
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();

        // Check quota
        if self.used_bytes + total_size > self.max_bytes {
            return Err(StorageError::QuotaExceeded {
                used: self.used_bytes,
                max: self.max_bytes,
            });
        }

        // Create content directory
        let content_dir = self.chunk_dir(cid);
        fs::create_dir_all(&content_dir).await?;

        // Encrypt and store each chunk
        let encryptor = StreamEncryptor::new(key, nonce);
        let mut stored_size = 0u64;

        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_index = i as u64;

            // Hash plaintext
            let chunk_hash = hash(chunk);

            // Encrypt chunk
            let encrypted = encryptor
                .encrypt_chunk_at(chunk, chunk_index)
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

            // Store chunk
            let chunk_path = self.chunk_path(cid, chunk_index);
            fs::write(&chunk_path, &encrypted).await?;

            // Store metadata
            let metadata = ChunkMetadata {
                cid: cid.to_string(),
                chunk_index,
                plaintext_size: chunk.len(),
                encrypted_size: encrypted.len(),
                hash: chunk_hash,
            };
            let meta_path = self.chunk_meta_path(cid, chunk_index);
            let meta_json = serde_json::to_vec(&metadata)
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
            fs::write(&meta_path, meta_json).await?;

            stored_size += encrypted.len() as u64;
        }

        // Create content info
        let info = PinnedContentInfo {
            cid: cid.to_string(),
            total_size,
            chunk_count: chunks.len() as u64,
            encryption_key: *key,
            base_nonce: *nonce,
            pinned_at: chrono::Utc::now(),
        };

        // Store content metadata
        let content_meta_path = self.content_meta_path(cid);
        let meta_json =
            serde_json::to_vec(&info).map_err(|e| StorageError::EncryptionError(e.to_string()))?;
        fs::write(&content_meta_path, meta_json).await?;

        // Update index
        self.pinned_content.insert(cid.to_string(), info.clone());
        self.used_bytes += stored_size;

        // Save index
        self.save_index().await?;

        Ok(info)
    }

    /// Retrieve and decrypt a chunk.
    pub async fn get_chunk(&self, cid: &str, chunk_index: u64) -> Result<Vec<u8>, StorageError> {
        // Get content info
        let info = self
            .pinned_content
            .get(cid)
            .ok_or_else(|| StorageError::ContentNotFound {
                cid: cid.to_string(),
            })?;

        // Read encrypted chunk
        let chunk_path = self.chunk_path(cid, chunk_index);
        if !chunk_path.exists() {
            return Err(StorageError::ChunkNotFound {
                cid: cid.to_string(),
                chunk_index,
            });
        }

        let encrypted = fs::read(&chunk_path).await?;

        // Decrypt chunk
        let decryptor = StreamDecryptor::new(&info.encryption_key, &info.base_nonce);
        let plaintext = decryptor
            .decrypt_chunk_at(&encrypted, chunk_index)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Get chunk with verification (returns hash too).
    pub async fn get_chunk_verified(
        &self,
        cid: &str,
        chunk_index: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), StorageError> {
        let plaintext = self.get_chunk(cid, chunk_index).await?;
        let chunk_hash = hash(&plaintext);

        // Optionally verify against stored metadata
        let meta_path = self.chunk_meta_path(cid, chunk_index);
        if meta_path.exists() {
            let meta_json = fs::read(&meta_path).await?;
            let metadata: ChunkMetadata = serde_json::from_slice(&meta_json)
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

            if chunk_hash != metadata.hash {
                return Err(StorageError::HashMismatch {
                    expected: hex::encode(metadata.hash),
                    actual: hex::encode(chunk_hash),
                });
            }
        }

        Ok((plaintext, chunk_hash))
    }

    /// Batch retrieve multiple chunks concurrently for improved performance.
    pub async fn get_chunks_batch(
        &self,
        cid: &str,
        chunk_indices: &[u64],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        use tokio::task::JoinSet;

        let mut tasks = JoinSet::new();

        // Get content info once
        let info = self
            .pinned_content
            .get(cid)
            .ok_or_else(|| StorageError::ContentNotFound {
                cid: cid.to_string(),
            })?
            .clone();

        let cid = cid.to_string();
        let base_path = self.base_path.clone();

        // Spawn concurrent fetch tasks
        for &chunk_index in chunk_indices {
            let cid_clone = cid.clone();
            let info_clone = info.clone();
            let base_path_clone = base_path.clone();

            tasks.spawn(async move {
                // Read encrypted chunk
                let chunk_path = base_path_clone
                    .join("chunks")
                    .join(&cid_clone)
                    .join(format!("{}.enc", chunk_index));

                if !chunk_path.exists() {
                    return Err(StorageError::ChunkNotFound {
                        cid: cid_clone,
                        chunk_index,
                    });
                }

                let encrypted = fs::read(&chunk_path).await?;

                // Decrypt chunk
                let decryptor =
                    StreamDecryptor::new(&info_clone.encryption_key, &info_clone.base_nonce);
                let plaintext = decryptor
                    .decrypt_chunk_at(&encrypted, chunk_index)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                Ok((chunk_index, plaintext))
            });
        }

        // Collect results
        let mut results: Vec<(u64, Vec<u8>)> = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let (index, chunk) = result
                .map_err(|e| StorageError::IoError(std::io::Error::other(e.to_string())))??;
            results.push((index, chunk));
        }

        // Sort by chunk index to maintain order
        results.sort_by_key(|(idx, _)| *idx);

        Ok(results.into_iter().map(|(_, chunk)| chunk).collect())
    }

    /// Batch retrieve and verify multiple chunks concurrently.
    pub async fn get_chunks_batch_verified(
        &self,
        cid: &str,
        chunk_indices: &[u64],
    ) -> Result<Vec<(Vec<u8>, [u8; 32])>, StorageError> {
        use tokio::task::JoinSet;

        let mut tasks = JoinSet::new();

        // Get content info once
        let info = self
            .pinned_content
            .get(cid)
            .ok_or_else(|| StorageError::ContentNotFound {
                cid: cid.to_string(),
            })?
            .clone();

        let cid = cid.to_string();
        let base_path = self.base_path.clone();

        // Spawn concurrent fetch tasks
        for &chunk_index in chunk_indices {
            let cid_clone = cid.clone();
            let info_clone = info.clone();
            let base_path_clone = base_path.clone();

            tasks.spawn(async move {
                // Read encrypted chunk
                let chunk_path = base_path_clone
                    .join("chunks")
                    .join(&cid_clone)
                    .join(format!("{}.enc", chunk_index));

                if !chunk_path.exists() {
                    return Err(StorageError::ChunkNotFound {
                        cid: cid_clone.clone(),
                        chunk_index,
                    });
                }

                let encrypted = fs::read(&chunk_path).await?;

                // Decrypt chunk
                let decryptor =
                    StreamDecryptor::new(&info_clone.encryption_key, &info_clone.base_nonce);
                let plaintext = decryptor
                    .decrypt_chunk_at(&encrypted, chunk_index)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                let chunk_hash = hash(&plaintext);

                // Verify against stored metadata
                let meta_path = base_path_clone
                    .join("chunks")
                    .join(&cid_clone)
                    .join(format!("{}.meta", chunk_index));

                if meta_path.exists() {
                    let meta_json = fs::read(&meta_path).await?;
                    let metadata: ChunkMetadata = serde_json::from_slice(&meta_json)
                        .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                    if chunk_hash != metadata.hash {
                        return Err(StorageError::HashMismatch {
                            expected: hex::encode(metadata.hash),
                            actual: hex::encode(chunk_hash),
                        });
                    }
                }

                Ok((chunk_index, plaintext, chunk_hash))
            });
        }

        // Collect results
        let mut results: Vec<(u64, Vec<u8>, [u8; 32])> = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let (index, chunk, hash) = result
                .map_err(|e| StorageError::IoError(std::io::Error::other(e.to_string())))??;
            results.push((index, chunk, hash));
        }

        // Sort by chunk index to maintain order
        results.sort_by_key(|(idx, _, _)| *idx);

        Ok(results
            .into_iter()
            .map(|(_, chunk, hash)| (chunk, hash))
            .collect())
    }

    /// Unpin content (remove all chunks).
    pub async fn unpin_content(&mut self, cid: &str) -> Result<(), StorageError> {
        if !self.pinned_content.contains_key(cid) {
            return Ok(()); // Already not pinned
        }

        // Calculate freed space
        let content_dir = self.chunk_dir(cid);
        let mut freed_bytes = 0u64;

        if content_dir.exists() {
            let mut entries = fs::read_dir(&content_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let metadata = entry.metadata().await?;
                freed_bytes += metadata.len();
            }

            // Remove content directory
            fs::remove_dir_all(&content_dir).await?;
        }

        // Remove content metadata
        let meta_path = self.content_meta_path(cid);
        if meta_path.exists() {
            fs::remove_file(&meta_path).await?;
        }

        // Update index
        self.pinned_content.remove(cid);
        self.used_bytes = self.used_bytes.saturating_sub(freed_bytes);

        // Save index
        self.save_index().await?;

        Ok(())
    }

    /// Get storage statistics.
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            used_bytes: self.used_bytes,
            max_bytes: self.max_bytes,
            available_bytes: self.available_bytes(),
            pinned_content_count: self.pinned_content.len(),
            usage_percent: (self.used_bytes as f64 / self.max_bytes as f64) * 100.0,
        }
    }

    /// Perform storage health check to verify integrity.
    pub async fn health_check(&self) -> Result<StorageHealthReport, StorageError> {
        let mut report = StorageHealthReport {
            total_content: self.pinned_content.len(),
            healthy_content: 0,
            corrupted_chunks: Vec::new(),
            missing_chunks: Vec::new(),
            metadata_issues: Vec::new(),
        };

        for (cid, info) in &self.pinned_content {
            let mut content_healthy = true;

            // Check each chunk exists and is valid
            for chunk_index in 0..info.chunk_count {
                let chunk_path = self.chunk_path(cid, chunk_index);
                let meta_path = self.chunk_meta_path(cid, chunk_index);

                if !chunk_path.exists() {
                    report
                        .missing_chunks
                        .push(format!("{}:{}", cid, chunk_index));
                    content_healthy = false;
                    continue;
                }

                if !meta_path.exists() {
                    report
                        .metadata_issues
                        .push(format!("{}:{} - missing metadata", cid, chunk_index));
                    content_healthy = false;
                    continue;
                }

                // Verify chunk integrity
                match self.get_chunk_verified(cid, chunk_index).await {
                    Ok(_) => {} // Chunk is valid
                    Err(StorageError::HashMismatch { .. }) => {
                        report
                            .corrupted_chunks
                            .push(format!("{}:{}", cid, chunk_index));
                        content_healthy = false;
                    }
                    Err(e) => {
                        report
                            .metadata_issues
                            .push(format!("{}:{} - {}", cid, chunk_index, e));
                        content_healthy = false;
                    }
                }
            }

            if content_healthy {
                report.healthy_content += 1;
            }
        }

        Ok(report)
    }

    /// Repair corrupted or missing chunks (requires re-download from network).
    pub async fn repair(&mut self, cid: &str) -> Result<RepairResult, StorageError> {
        // This is a placeholder - actual repair would need network access
        // For now, we just identify what needs repair
        let info = self
            .pinned_content
            .get(cid)
            .ok_or_else(|| StorageError::ContentNotFound {
                cid: cid.to_string(),
            })?
            .clone();

        let mut chunks_needing_repair = Vec::new();

        #[allow(clippy::redundant_pattern_matching)]
        for chunk_index in 0..info.chunk_count {
            if self.get_chunk_verified(cid, chunk_index).await.is_err() {
                chunks_needing_repair.push(chunk_index);
            }
        }

        let status = if chunks_needing_repair.is_empty() {
            RepairStatus::Healthy
        } else {
            RepairStatus::NeedsRepair
        };

        Ok(RepairResult {
            cid: cid.to_string(),
            chunks_needing_repair,
            status,
        })
    }

    // Helper methods

    fn chunk_dir(&self, cid: &str) -> PathBuf {
        self.base_path.join("chunks").join(cid)
    }

    fn chunk_path(&self, cid: &str, chunk_index: u64) -> PathBuf {
        self.chunk_dir(cid).join(format!("{}.enc", chunk_index))
    }

    fn chunk_meta_path(&self, cid: &str, chunk_index: u64) -> PathBuf {
        self.chunk_dir(cid).join(format!("{}.meta", chunk_index))
    }

    fn content_meta_path(&self, cid: &str) -> PathBuf {
        self.base_path
            .join("metadata")
            .join(format!("{}.json", cid))
    }

    fn index_path(&self) -> PathBuf {
        self.base_path.join("index.json")
    }

    async fn load_index(&mut self) -> Result<(), StorageError> {
        let index_path = self.index_path();
        if !index_path.exists() {
            return Ok(());
        }

        let data = fs::read(&index_path).await?;
        let index: StorageIndex = serde_json::from_slice(&data)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

        self.used_bytes = index.used_bytes;

        // Load all pinned content metadata
        for cid in index.pinned_cids {
            let meta_path = self.content_meta_path(&cid);
            if meta_path.exists() {
                let meta_data = fs::read(&meta_path).await?;
                let info: PinnedContentInfo = serde_json::from_slice(&meta_data)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
                self.pinned_content.insert(cid, info);
            }
        }

        Ok(())
    }

    async fn save_index(&self) -> Result<(), StorageError> {
        let index = StorageIndex {
            used_bytes: self.used_bytes,
            pinned_cids: self.pinned_content.keys().cloned().collect(),
        };

        let data = serde_json::to_vec_pretty(&index)
            .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

        fs::write(self.index_path(), data).await?;
        Ok(())
    }

    /// Update storage health metrics.
    ///
    /// This should be called periodically to track storage health and detect issues early.
    pub fn update_health_metrics(&mut self) {
        let now = std::time::Instant::now();

        // Calculate disk usage
        let disk_usage = if self.max_bytes > 0 {
            self.used_bytes as f64 / self.max_bytes as f64
        } else {
            0.0
        };

        // Calculate growth rate if we have previous data
        let growth_rate = if let Some((prev_usage, prev_time)) = self.previous_usage {
            let duration_secs = now.duration_since(prev_time).as_secs_f64();
            if duration_secs > 0.0 {
                let bytes_change = self.used_bytes.saturating_sub(prev_usage) as f64;
                bytes_change / duration_secs
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Predict time until full
        let time_until_full = if growth_rate > 0.0 {
            let available = self.max_bytes.saturating_sub(self.used_bytes) as f64;
            Some((available / growth_rate) as u64)
        } else {
            None
        };

        // Determine health status
        let status = if self.health.io_errors > 100 || disk_usage > 0.98 {
            StorageHealthStatus::Critical
        } else if self.health.io_errors > 50 || disk_usage > 0.95 {
            StorageHealthStatus::Degraded
        } else if self.health.io_errors > 10 || disk_usage > 0.90 {
            StorageHealthStatus::Warning
        } else {
            StorageHealthStatus::Healthy
        };

        // Update health metrics
        self.health.status = status;
        self.health.disk_usage = disk_usage;
        self.health.growth_rate = growth_rate;
        self.health.time_until_full = time_until_full;
        self.health.last_check = now;

        // Update previous usage for next calculation
        self.previous_usage = Some((self.used_bytes, now));
    }

    /// Get current storage health.
    #[must_use]
    #[inline]
    pub fn health(&self) -> &StorageHealth {
        &self.health
    }

    /// Record an I/O error.
    pub fn record_io_error(&mut self) {
        self.health.io_errors += 1;
        self.update_health_metrics();
    }

    /// Record a slow operation.
    pub fn record_slow_operation(&mut self, latency_ms: u64) {
        self.health.slow_operations += 1;

        // Update peak latency
        if latency_ms > self.health.peak_latency_ms {
            self.health.peak_latency_ms = latency_ms;
        }

        // Update average latency (simple moving average)
        let alpha = 0.1; // Smoothing factor
        self.health.avg_latency_ms =
            alpha * latency_ms as f64 + (1.0 - alpha) * self.health.avg_latency_ms;

        self.update_health_metrics();
    }

    /// Reset health metrics (typically called after a health check period).
    pub fn reset_health_counters(&mut self) {
        self.health.io_errors = 0;
        self.health.slow_operations = 0;
        self.update_health_metrics();
    }

    /// Check if storage health is concerning.
    #[must_use]
    #[inline]
    pub fn is_health_concerning(&self) -> bool {
        self.health.status == StorageHealthStatus::Degraded
            || self.health.status == StorageHealthStatus::Critical
            || self.health.is_failure_imminent()
    }
}

/// Storage statistics.
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub available_bytes: u64,
    pub pinned_content_count: usize,
    pub usage_percent: f64,
}

/// Storage health check report.
#[derive(Debug, Clone)]
pub struct StorageHealthReport {
    pub total_content: usize,
    pub healthy_content: usize,
    pub corrupted_chunks: Vec<String>,
    pub missing_chunks: Vec<String>,
    pub metadata_issues: Vec<String>,
}

/// Repair operation result.
#[derive(Debug, Clone)]
pub struct RepairResult {
    pub cid: String,
    pub chunks_needing_repair: Vec<u64>,
    pub status: RepairStatus,
}

/// Repair status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairStatus {
    Healthy,
    NeedsRepair,
}

/// Persisted storage index.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StorageIndex {
    used_bytes: u64,
    pinned_cids: Vec<String>,
}

/// Helper function to split data into chunks.
///
/// # Examples
///
/// ```
/// use chie_core::storage::split_into_chunks;
///
/// let data = b"Hello, World!";
/// let chunks = split_into_chunks(data, 5);
///
/// assert_eq!(chunks.len(), 3);
/// assert_eq!(chunks[0], b"Hello");
/// assert_eq!(chunks[1], b", Wor");
/// assert_eq!(chunks[2], b"ld!");
/// ```
pub fn split_into_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    data.chunks(chunk_size).map(|c| c.to_vec()).collect()
}

/// Helper to calculate chunk count.
#[inline]
#[allow(clippy::manual_div_ceil)] // div_ceil not available in const context
pub const fn calculate_chunk_count(size: u64) -> u64 {
    let chunk_size = CHUNK_SIZE as u64;
    if size == 0 {
        0
    } else {
        (size + chunk_size - 1) / chunk_size
    }
}

/// Storage health monitoring with predictive failure detection.
///
/// Tracks storage metrics over time to detect anomalies and predict potential failures.
pub struct StorageHealthMonitor {
    /// Historical error rates (errors per hour).
    error_history: std::sync::Arc<std::sync::Mutex<Vec<(std::time::Instant, u32)>>>,
    /// Historical corruption rates (corruptions per check).
    corruption_history: std::sync::Arc<std::sync::Mutex<Vec<(std::time::Instant, u32)>>>,
    /// Historical I/O latencies (in microseconds).
    io_latency_history: std::sync::Arc<std::sync::Mutex<Vec<(std::time::Instant, u64)>>>,
    /// Total errors encountered.
    total_errors: std::sync::Arc<std::sync::Mutex<u64>>,
    /// Total corruptions detected.
    total_corruptions: std::sync::Arc<std::sync::Mutex<u64>>,
    /// History retention duration.
    retention_duration: std::time::Duration,
}

impl StorageHealthMonitor {
    /// Create a new storage health monitor.
    ///
    /// # Arguments
    ///
    /// * `retention_duration` - How long to keep historical data (e.g., 24 hours)
    #[must_use]
    pub fn new(retention_duration: std::time::Duration) -> Self {
        Self {
            error_history: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            corruption_history: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            io_latency_history: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            total_errors: std::sync::Arc::new(std::sync::Mutex::new(0)),
            total_corruptions: std::sync::Arc::new(std::sync::Mutex::new(0)),
            retention_duration,
        }
    }

    /// Record an I/O operation error.
    pub fn record_error(&self) {
        let mut errors = self.total_errors.lock().unwrap();
        *errors += 1;
        drop(errors);

        let mut history = self.error_history.lock().unwrap();
        history.push((std::time::Instant::now(), 1));
        self.cleanup_old_records(&mut history);
    }

    /// Record a corruption detection.
    pub fn record_corruption(&self) {
        let mut corruptions = self.total_corruptions.lock().unwrap();
        *corruptions += 1;
        drop(corruptions);

        let mut history = self.corruption_history.lock().unwrap();
        history.push((std::time::Instant::now(), 1));
        self.cleanup_old_records(&mut history);
    }

    /// Record an I/O operation latency (in microseconds).
    pub fn record_io_latency(&self, latency_us: u64) {
        let mut history = self.io_latency_history.lock().unwrap();
        history.push((std::time::Instant::now(), latency_us));
        self.cleanup_old_records(&mut history);
    }

    /// Clean up records older than retention duration.
    fn cleanup_old_records<T>(&self, history: &mut Vec<(std::time::Instant, T)>) {
        let cutoff = std::time::Instant::now() - self.retention_duration;
        history.retain(|(timestamp, _)| *timestamp > cutoff);
    }

    /// Get current error rate (errors per hour).
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let history = self.error_history.lock().unwrap();
        if history.is_empty() {
            return 0.0;
        }

        let window = std::time::Duration::from_secs(3600); // 1 hour
        let cutoff = std::time::Instant::now() - window;
        let recent_errors: u32 = history
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, count)| count)
            .sum();

        recent_errors as f64
    }

    /// Get current corruption rate (corruptions per hour).
    #[must_use]
    pub fn corruption_rate(&self) -> f64 {
        let history = self.corruption_history.lock().unwrap();
        if history.is_empty() {
            return 0.0;
        }

        let window = std::time::Duration::from_secs(3600); // 1 hour
        let cutoff = std::time::Instant::now() - window;
        let recent_corruptions: u32 = history
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, count)| count)
            .sum();

        recent_corruptions as f64
    }

    /// Get average I/O latency over the last hour (in microseconds).
    #[must_use]
    pub fn avg_io_latency(&self) -> f64 {
        let history = self.io_latency_history.lock().unwrap();
        if history.is_empty() {
            return 0.0;
        }

        let window = std::time::Duration::from_secs(3600); // 1 hour
        let cutoff = std::time::Instant::now() - window;
        let recent_latencies: Vec<u64> = history
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, latency)| *latency)
            .collect();

        if recent_latencies.is_empty() {
            return 0.0;
        }

        let sum: u64 = recent_latencies.iter().sum();
        sum as f64 / recent_latencies.len() as f64
    }

    /// Predict storage health status based on current trends.
    ///
    /// Uses historical data to predict if storage is likely to fail soon.
    ///
    /// # Returns
    ///
    /// A tuple of (predicted_status, confidence_score) where confidence is 0.0-1.0.
    #[must_use]
    pub fn predict_health(&self) -> (StorageHealthStatus, f64) {
        let error_rate = self.error_rate();
        let corruption_rate = self.corruption_rate();
        let avg_latency = self.avg_io_latency();

        // Calculate health score based on thresholds
        let mut score = 100.0;
        let mut confidence = 1.0;

        // Error rate thresholds (errors per hour)
        if error_rate > 100.0 {
            score -= 40.0;
        } else if error_rate > 50.0 {
            score -= 25.0;
        } else if error_rate > 10.0 {
            score -= 10.0;
        }

        // Corruption rate thresholds (corruptions per hour)
        if corruption_rate > 10.0 {
            score -= 50.0; // Corruptions are critical
        } else if corruption_rate > 5.0 {
            score -= 30.0;
        } else if corruption_rate > 1.0 {
            score -= 15.0;
        }

        // I/O latency thresholds (microseconds)
        // Normal disk I/O: ~100-500 µs for SSD, ~5000-15000 µs for HDD
        if avg_latency > 50_000.0 {
            score -= 30.0; // Very slow, indicating potential hardware failure
        } else if avg_latency > 20_000.0 {
            score -= 15.0;
        } else if avg_latency > 10_000.0 {
            score -= 5.0;
        }

        // Reduce confidence if we have limited data
        let history = self.io_latency_history.lock().unwrap();
        if history.len() < 10 {
            confidence = history.len() as f64 / 10.0;
        }

        // Determine status from score
        let status = if score >= 80.0 {
            StorageHealthStatus::Healthy
        } else if score >= 60.0 {
            StorageHealthStatus::Warning
        } else if score >= 40.0 {
            StorageHealthStatus::Degraded
        } else {
            StorageHealthStatus::Critical
        };

        (status, confidence)
    }

    /// Check if storage is predicted to fail soon.
    ///
    /// Returns true if failure is likely within the prediction window.
    #[must_use]
    pub fn is_failure_predicted(&self) -> bool {
        let (status, confidence) = self.predict_health();

        // Predict failure if status is Critical with high confidence,
        // or Degraded with very high confidence
        match (status, confidence) {
            (StorageHealthStatus::Critical, c) if c > 0.7 => true,
            (StorageHealthStatus::Degraded, c) if c > 0.9 => true,
            _ => false,
        }
    }

    /// Get a detailed health report with predictions.
    #[must_use]
    pub fn health_report(&self) -> StorageHealthPrediction {
        let (predicted_status, confidence) = self.predict_health();
        let total_errors = *self.total_errors.lock().unwrap();
        let total_corruptions = *self.total_corruptions.lock().unwrap();

        StorageHealthPrediction {
            current_status: predicted_status,
            confidence,
            error_rate_per_hour: self.error_rate(),
            corruption_rate_per_hour: self.corruption_rate(),
            avg_io_latency_us: self.avg_io_latency(),
            total_errors,
            total_corruptions,
            failure_predicted: self.is_failure_predicted(),
        }
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        self.error_history.lock().unwrap().clear();
        self.corruption_history.lock().unwrap().clear();
        self.io_latency_history.lock().unwrap().clear();
        *self.total_errors.lock().unwrap() = 0;
        *self.total_corruptions.lock().unwrap() = 0;
    }
}

/// Storage health prediction report.
#[derive(Debug, Clone)]
pub struct StorageHealthPrediction {
    /// Predicted health status.
    pub current_status: StorageHealthStatus,
    /// Confidence in prediction (0.0 to 1.0).
    pub confidence: f64,
    /// Current error rate (errors per hour).
    pub error_rate_per_hour: f64,
    /// Current corruption rate (corruptions per hour).
    pub corruption_rate_per_hour: f64,
    /// Average I/O latency in microseconds.
    pub avg_io_latency_us: f64,
    /// Total errors since monitoring started.
    pub total_errors: u64,
    /// Total corruptions detected since monitoring started.
    pub total_corruptions: u64,
    /// Whether failure is predicted to occur soon.
    pub failure_predicted: bool,
}

impl Default for StorageHealthMonitor {
    fn default() -> Self {
        Self::new(std::time::Duration::from_secs(24 * 3600)) // 24 hours default
    }
}

// Transaction support methods for ChunkStorage
impl ChunkStorage {
    /// Get chunk directory path (exposed for transactions).
    #[must_use]
    pub fn get_chunk_dir(&self, cid: &str) -> PathBuf {
        self.chunk_dir(cid)
    }

    /// Write chunks for a transaction.
    ///
    /// Returns list of (chunk_index, chunk_path, meta_path, size_bytes) for each written chunk.
    pub async fn write_chunks_for_transaction(
        &mut self,
        cid: &str,
        chunks: &[Vec<u8>],
        key: &EncryptionKey,
        nonce: &EncryptionNonce,
    ) -> Result<Vec<(u64, PathBuf, PathBuf, u64)>, StorageError> {
        let encryptor = StreamEncryptor::new(key, nonce);
        let mut written_chunks = Vec::new();

        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_index = i as u64;

            // Hash plaintext
            let chunk_hash = hash(chunk);

            // Encrypt chunk
            let encrypted = encryptor
                .encrypt_chunk_at(chunk, chunk_index)
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

            // Store chunk
            let chunk_path = self.chunk_path(cid, chunk_index);
            fs::write(&chunk_path, &encrypted).await?;

            // Store metadata
            let metadata = ChunkMetadata {
                cid: cid.to_string(),
                chunk_index,
                plaintext_size: chunk.len(),
                encrypted_size: encrypted.len(),
                hash: chunk_hash,
            };
            let meta_path = self.chunk_meta_path(cid, chunk_index);
            let meta_json = serde_json::to_vec(&metadata)
                .map_err(|e| StorageError::EncryptionError(e.to_string()))?;
            fs::write(&meta_path, &meta_json).await?;

            let size_bytes = encrypted.len() as u64;
            self.used_bytes += size_bytes;

            written_chunks.push((chunk_index, chunk_path, meta_path, size_bytes));
        }

        Ok(written_chunks)
    }

    /// Decrease used bytes (for transaction rollback).
    pub fn decrease_used_bytes(&mut self, bytes: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_chunk_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 1024 * 1024)
            .await
            .unwrap();

        assert_eq!(storage.used_bytes(), 0);
        assert_eq!(storage.max_bytes(), 1024 * 1024);
        assert_eq!(storage.available_bytes(), 1024 * 1024);
        assert_eq!(storage.list_pinned().len(), 0);
    }

    #[tokio::test]
    async fn test_pin_and_retrieve_content() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmTest123";
        let test_data = vec![b"Hello, World!".to_vec(), b"Second chunk".to_vec()];
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        // Pin content
        let info = storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();

        assert_eq!(info.cid, cid);
        assert_eq!(info.chunk_count, 2);
        assert!(storage.is_pinned(cid));
        assert_eq!(storage.list_pinned().len(), 1);

        // Retrieve chunks
        let chunk0 = storage.get_chunk(cid, 0).await.unwrap();
        let chunk1 = storage.get_chunk(cid, 1).await.unwrap();

        assert_eq!(chunk0, test_data[0]);
        assert_eq!(chunk1, test_data[1]);
    }

    #[tokio::test]
    async fn test_get_chunk_verified() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmVerified";
        let test_data = vec![b"Verified chunk data".to_vec()];
        let expected_hash = chie_crypto::hash(&test_data[0]);
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();

        let (chunk, hash) = storage.get_chunk_verified(cid, 0).await.unwrap();

        assert_eq!(chunk, test_data[0]);
        assert_eq!(hash, expected_hash);
    }

    #[tokio::test]
    async fn test_unpin_content() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmUnpin";
        let test_data = vec![b"Data to unpin".to_vec()];
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();
        assert!(storage.is_pinned(cid));
        let used_before = storage.used_bytes();
        assert!(used_before > 0);

        storage.unpin_content(cid).await.unwrap();
        assert!(!storage.is_pinned(cid));
        assert_eq!(storage.used_bytes(), 0);
    }

    #[tokio::test]
    async fn test_quota_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        let small_quota = 100; // Very small quota
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), small_quota)
            .await
            .unwrap();

        let cid = "QmTooBig";
        let large_data = vec![vec![0u8; 1000]]; // Larger than quota
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        let result = storage.pin_content(cid, &large_data, &key, &nonce).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StorageError::QuotaExceeded { .. }
        ));
    }

    #[tokio::test]
    async fn test_content_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let result = storage.get_chunk("QmNonExistent", 0).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StorageError::ContentNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_chunk_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmChunkTest";
        let test_data = vec![b"Only one chunk".to_vec()];
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();

        // Try to get non-existent chunk index
        let result = storage.get_chunk(cid, 99).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StorageError::ChunkNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let max_bytes = 10 * 1024 * 1024;
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), max_bytes)
            .await
            .unwrap();

        let stats_empty = storage.stats();
        assert_eq!(stats_empty.used_bytes, 0);
        assert_eq!(stats_empty.max_bytes, max_bytes);
        assert_eq!(stats_empty.available_bytes, max_bytes);
        assert_eq!(stats_empty.pinned_content_count, 0);
        assert_eq!(stats_empty.usage_percent, 0.0);

        // Pin some content
        let cid = "QmStats";
        let test_data = vec![b"Test data for stats".to_vec()];
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();

        let stats_used = storage.stats();
        assert!(stats_used.used_bytes > 0);
        assert_eq!(stats_used.max_bytes, max_bytes);
        assert!(stats_used.available_bytes < max_bytes);
        assert_eq!(stats_used.pinned_content_count, 1);
        assert!(stats_used.usage_percent > 0.0);
    }

    #[tokio::test]
    async fn test_multiple_content_pins() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        // Pin multiple pieces of content
        for i in 0..5 {
            let cid = format!("QmMulti{}", i);
            let data = vec![format!("Content {}", i).into_bytes()];
            storage
                .pin_content(&cid, &data, &key, &nonce)
                .await
                .unwrap();
        }

        assert_eq!(storage.list_pinned().len(), 5);
        assert!(storage.is_pinned("QmMulti0"));
        assert!(storage.is_pinned("QmMulti4"));
        assert!(!storage.is_pinned("QmMulti5"));
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();
        let cid = "QmPersist";
        let test_data = vec![b"Persistent data".to_vec()];

        // Create storage, pin content, then drop it
        {
            let mut storage = ChunkStorage::new(path.clone(), 10 * 1024 * 1024)
                .await
                .unwrap();
            let key = chie_crypto::generate_key();
            let nonce = chie_crypto::generate_nonce();
            storage
                .pin_content(cid, &test_data, &key, &nonce)
                .await
                .unwrap();
        }

        // Recreate storage and verify content is still there
        {
            let storage = ChunkStorage::new(path, 10 * 1024 * 1024).await.unwrap();
            assert!(storage.is_pinned(cid));
            assert_eq!(storage.list_pinned().len(), 1);
            assert!(storage.used_bytes() > 0);
        }
    }

    #[test]
    fn test_split_into_chunks() {
        let data = vec![1u8; 100]; // 100 bytes
        let chunk_size = 30;

        let chunks = split_into_chunks(&data, chunk_size);

        // 100 bytes split into chunks of 30 = 4 chunks (30, 30, 30, 10)
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].len(), 30);
        assert_eq!(chunks[1].len(), 30);
        assert_eq!(chunks[2].len(), 30);
        assert_eq!(chunks[3].len(), 10);

        // Verify we can reconstruct the data
        let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_calculate_chunk_count() {
        assert_eq!(calculate_chunk_count(0), 0);
        assert_eq!(calculate_chunk_count(1), 1);
        assert_eq!(calculate_chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(calculate_chunk_count(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(calculate_chunk_count(CHUNK_SIZE as u64 * 3), 3);
        assert_eq!(calculate_chunk_count(CHUNK_SIZE as u64 * 3 + 1), 4);
    }

    #[tokio::test]
    async fn test_get_pinned_info() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmInfo";
        let test_data = vec![b"Info test".to_vec()];
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        storage
            .pin_content(cid, &test_data, &key, &nonce)
            .await
            .unwrap();

        let info = storage.get_pinned_info(cid);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.cid, cid);
        assert_eq!(info.chunk_count, 1);
        assert_eq!(info.encryption_key, key);
        assert_eq!(info.base_nonce, nonce);

        assert!(storage.get_pinned_info("QmNonExistent").is_none());
    }

    #[tokio::test]
    async fn test_large_content() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 100 * 1024 * 1024)
            .await
            .unwrap();

        let cid = "QmLarge";
        // Create 10 chunks of 64KB each
        let chunks: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 64 * 1024]).collect();
        let key = chie_crypto::generate_key();
        let nonce = chie_crypto::generate_nonce();

        let info = storage
            .pin_content(cid, &chunks, &key, &nonce)
            .await
            .unwrap();

        assert_eq!(info.chunk_count, 10);
        assert_eq!(info.total_size, 64 * 1024 * 10);

        // Retrieve all chunks
        for i in 0..10 {
            let chunk = storage.get_chunk(cid, i).await.unwrap();
            assert_eq!(chunk.len(), 64 * 1024);
            assert_eq!(chunk[0], i as u8);
        }
    }
}
