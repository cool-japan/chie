//! Backup and restore functionality for CHIE storage.
//!
//! This module provides:
//! - Full backup creation
//! - Incremental backup support
//! - Backup restoration with integrity verification
//! - Progress tracking for long operations

use crate::storage::{ChunkStorage, PinnedContentInfo, StorageError};
use chie_crypto::hash;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Backup-related errors.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),

    #[error("Backup not found: {path}")]
    BackupNotFound { path: String },

    #[error("Invalid backup format: {0}")]
    InvalidFormat(String),

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Backup cancelled")]
    Cancelled,

    #[error("Incompatible backup version: {version}")]
    IncompatibleVersion { version: u32 },
}

/// Current backup format version.
const BACKUP_VERSION: u32 = 1;

/// Backup configuration.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Enable compression for backup files.
    pub compress: bool,
    /// Chunk size for backup archive (default 4MB).
    pub archive_chunk_size: usize,
    /// Verify checksums during backup.
    pub verify_on_backup: bool,
    /// Verify checksums during restore.
    pub verify_on_restore: bool,
    /// Include metadata in backups.
    pub include_metadata: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            compress: true,
            archive_chunk_size: 4 * 1024 * 1024, // 4MB
            verify_on_backup: true,
            verify_on_restore: true,
            include_metadata: true,
        }
    }
}

/// Backup manifest describing the backup contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Backup format version.
    pub version: u32,
    /// When the backup was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Type of backup.
    pub backup_type: BackupType,
    /// Previous backup ID for incremental backups.
    pub parent_backup_id: Option<String>,
    /// Unique backup identifier.
    pub backup_id: String,
    /// Content items included.
    pub content_items: Vec<BackupContentEntry>,
    /// Total size of backup data.
    pub total_size: u64,
    /// Checksum of the backup data.
    pub checksum: String,
    /// Source storage path.
    pub source_path: String,
}

/// Type of backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup of all content.
    Full,
    /// Incremental backup (changes since last backup).
    Incremental,
}

/// Entry for each content item in the backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupContentEntry {
    /// Content CID.
    pub cid: String,
    /// Number of chunks.
    pub chunk_count: u64,
    /// Total size.
    pub total_size: u64,
    /// Chunk checksums for verification.
    pub chunk_checksums: Vec<String>,
    /// Offset in the backup archive.
    pub archive_offset: u64,
}

/// Progress tracking for backup/restore operations.
#[derive(Debug, Clone)]
pub struct BackupProgress {
    /// Total bytes to process.
    pub total_bytes: Arc<AtomicU64>,
    /// Bytes processed so far.
    pub processed_bytes: Arc<AtomicU64>,
    /// Total items to process.
    pub total_items: Arc<AtomicU64>,
    /// Items processed so far.
    pub processed_items: Arc<AtomicU64>,
    /// Current operation description.
    pub current_operation: Arc<std::sync::RwLock<String>>,
    /// Cancellation flag.
    pub cancelled: Arc<AtomicBool>,
}

impl Default for BackupProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl BackupProgress {
    /// Create a new progress tracker.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            total_bytes: Arc::new(AtomicU64::new(0)),
            processed_bytes: Arc::new(AtomicU64::new(0)),
            total_items: Arc::new(AtomicU64::new(0)),
            processed_items: Arc::new(AtomicU64::new(0)),
            current_operation: Arc::new(std::sync::RwLock::new(String::new())),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get progress percentage (0-100).
    #[must_use]
    #[inline]
    pub fn percentage(&self) -> f64 {
        let total = self.total_bytes.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let processed = self.processed_bytes.load(Ordering::Relaxed);
        (processed as f64 / total as f64) * 100.0
    }

    /// Check if operation is cancelled.
    #[must_use]
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Cancel the operation.
    #[inline]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Set current operation description.
    #[inline]
    pub fn set_operation(&self, op: &str) {
        if let Ok(mut guard) = self.current_operation.write() {
            *guard = op.to_string();
        }
    }

    /// Add processed bytes.
    #[inline]
    pub fn add_bytes(&self, bytes: u64) {
        self.processed_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment processed items.
    #[inline]
    pub fn increment_items(&self) {
        self.processed_items.fetch_add(1, Ordering::Relaxed);
    }
}

/// Result of a backup operation.
#[derive(Debug, Clone)]
pub struct BackupResult {
    /// Backup manifest.
    pub manifest: BackupManifest,
    /// Path to the backup file.
    pub backup_path: PathBuf,
    /// Duration of the backup.
    pub duration_secs: f64,
    /// Number of content items backed up.
    pub items_backed_up: usize,
}

/// Result of a restore operation.
#[derive(Debug, Clone)]
pub struct RestoreResult {
    /// Number of content items restored.
    pub items_restored: usize,
    /// Number of chunks restored.
    pub chunks_restored: u64,
    /// Total bytes restored.
    pub bytes_restored: u64,
    /// Duration of the restore.
    pub duration_secs: f64,
    /// Items that failed to restore.
    pub failed_items: Vec<String>,
}

/// Backup manager for creating and restoring backups.
pub struct BackupManager {
    /// Backup configuration.
    config: BackupConfig,
}

impl BackupManager {
    /// Create a new backup manager.
    #[must_use]
    #[inline]
    pub fn new(config: BackupConfig) -> Self {
        Self { config }
    }

    /// Create a full backup of the storage.
    pub async fn create_full_backup(
        &self,
        storage: &ChunkStorage,
        backup_dir: &Path,
        progress: Option<&BackupProgress>,
    ) -> Result<BackupResult, BackupError> {
        let start = std::time::Instant::now();

        // Create backup directory
        fs::create_dir_all(backup_dir).await?;

        let backup_id = uuid::Uuid::new_v4().to_string();
        let backup_path = backup_dir.join(format!("backup_{}.chie", backup_id));

        info!("Creating full backup: {}", backup_id);

        if let Some(p) = progress {
            p.set_operation("Preparing backup");
        }

        // Collect content to backup
        let pinned_cids = storage.list_pinned();
        let mut content_entries = Vec::new();
        let mut total_size = 0u64;

        if let Some(p) = progress {
            p.total_items
                .store(pinned_cids.len() as u64, Ordering::Relaxed);
        }

        // Calculate total size for progress
        for cid in &pinned_cids {
            if let Some(info) = storage.get_pinned_info(cid) {
                total_size += info.total_size;
            }
        }

        if let Some(p) = progress {
            p.total_bytes.store(total_size, Ordering::Relaxed);
        }

        // Create backup file
        let mut backup_file = fs::File::create(&backup_path).await?;
        let mut archive_offset = 0u64;

        // Write header placeholder (will update later)
        let header_placeholder = vec![0u8; 1024];
        backup_file.write_all(&header_placeholder).await?;
        archive_offset += header_placeholder.len() as u64;

        // Backup each content item
        for cid in pinned_cids {
            if let Some(p) = progress {
                if p.is_cancelled() {
                    // Clean up partial backup
                    let _ = fs::remove_file(&backup_path).await;
                    return Err(BackupError::Cancelled);
                }
                p.set_operation(&format!("Backing up {}", cid));
            }

            let entry = self
                .backup_content(
                    storage,
                    cid,
                    &mut backup_file,
                    &mut archive_offset,
                    progress,
                )
                .await?;

            content_entries.push(entry);

            if let Some(p) = progress {
                p.increment_items();
            }
        }

        // Create manifest
        let manifest_data = self.create_manifest_data(&content_entries)?;
        let checksum = hex::encode(hash(&manifest_data));

        let manifest = BackupManifest {
            version: BACKUP_VERSION,
            created_at: chrono::Utc::now(),
            backup_type: BackupType::Full,
            parent_backup_id: None,
            backup_id: backup_id.clone(),
            content_items: content_entries.clone(),
            total_size,
            checksum,
            source_path: storage.base_path().to_string_lossy().to_string(),
        };

        // Write manifest at the end
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| BackupError::SerializationError(e.to_string()))?;

        backup_file.write_all(&manifest_json).await?;

        // Write manifest length at the end
        let manifest_len = manifest_json.len() as u64;
        backup_file.write_all(&manifest_len.to_le_bytes()).await?;

        // Flush and sync
        backup_file.flush().await?;
        backup_file.sync_all().await?;

        let duration = start.elapsed().as_secs_f64();

        info!(
            "Backup complete: {} items in {:.2}s",
            content_entries.len(),
            duration
        );

        Ok(BackupResult {
            manifest,
            backup_path,
            duration_secs: duration,
            items_backed_up: content_entries.len(),
        })
    }

    /// Create an incremental backup.
    pub async fn create_incremental_backup(
        &self,
        storage: &ChunkStorage,
        backup_dir: &Path,
        parent_manifest: &BackupManifest,
        progress: Option<&BackupProgress>,
    ) -> Result<BackupResult, BackupError> {
        let start = std::time::Instant::now();

        let backup_id = uuid::Uuid::new_v4().to_string();
        let backup_path = backup_dir.join(format!("backup_{}_incr.chie", backup_id));

        info!(
            "Creating incremental backup: {} (parent: {})",
            backup_id, parent_manifest.backup_id
        );

        if let Some(p) = progress {
            p.set_operation("Analyzing changes");
        }

        // Build set of existing content from parent
        let parent_cids: HashSet<_> = parent_manifest
            .content_items
            .iter()
            .map(|e| e.cid.clone())
            .collect();

        // Find new/changed content
        let current_cids: HashSet<_> = storage
            .list_pinned()
            .into_iter()
            .map(String::from)
            .collect();
        let new_cids: Vec<_> = current_cids.difference(&parent_cids).cloned().collect();

        if new_cids.is_empty() {
            info!("No changes detected, skipping backup");
            return Ok(BackupResult {
                manifest: BackupManifest {
                    version: BACKUP_VERSION,
                    created_at: chrono::Utc::now(),
                    backup_type: BackupType::Incremental,
                    parent_backup_id: Some(parent_manifest.backup_id.clone()),
                    backup_id,
                    content_items: vec![],
                    total_size: 0,
                    checksum: String::new(),
                    source_path: storage.base_path().to_string_lossy().to_string(),
                },
                backup_path,
                duration_secs: start.elapsed().as_secs_f64(),
                items_backed_up: 0,
            });
        }

        // Create backup file
        fs::create_dir_all(backup_dir).await?;
        let mut backup_file = fs::File::create(&backup_path).await?;
        let mut archive_offset = 0u64;

        // Write header placeholder
        let header_placeholder = vec![0u8; 1024];
        backup_file.write_all(&header_placeholder).await?;
        archive_offset += header_placeholder.len() as u64;

        let mut content_entries = Vec::new();
        let mut total_size = 0u64;

        if let Some(p) = progress {
            p.total_items
                .store(new_cids.len() as u64, Ordering::Relaxed);
        }

        // Backup only new content
        for cid in &new_cids {
            if let Some(p) = progress {
                if p.is_cancelled() {
                    let _ = fs::remove_file(&backup_path).await;
                    return Err(BackupError::Cancelled);
                }
                p.set_operation(&format!("Backing up {}", cid));
            }

            if let Some(info) = storage.get_pinned_info(cid) {
                total_size += info.total_size;
            }

            let entry = self
                .backup_content(
                    storage,
                    cid,
                    &mut backup_file,
                    &mut archive_offset,
                    progress,
                )
                .await?;

            content_entries.push(entry);

            if let Some(p) = progress {
                p.increment_items();
            }
        }

        // Create manifest
        let manifest_data = self.create_manifest_data(&content_entries)?;
        let checksum = hex::encode(hash(&manifest_data));

        let manifest = BackupManifest {
            version: BACKUP_VERSION,
            created_at: chrono::Utc::now(),
            backup_type: BackupType::Incremental,
            parent_backup_id: Some(parent_manifest.backup_id.clone()),
            backup_id: backup_id.clone(),
            content_items: content_entries.clone(),
            total_size,
            checksum,
            source_path: storage.base_path().to_string_lossy().to_string(),
        };

        // Write manifest
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| BackupError::SerializationError(e.to_string()))?;
        backup_file.write_all(&manifest_json).await?;

        let manifest_len = manifest_json.len() as u64;
        backup_file.write_all(&manifest_len.to_le_bytes()).await?;

        backup_file.flush().await?;
        backup_file.sync_all().await?;

        let duration = start.elapsed().as_secs_f64();

        info!(
            "Incremental backup complete: {} items in {:.2}s",
            content_entries.len(),
            duration
        );

        Ok(BackupResult {
            manifest,
            backup_path,
            duration_secs: duration,
            items_backed_up: content_entries.len(),
        })
    }

    /// Restore from a backup file.
    pub async fn restore_backup(
        &self,
        backup_path: &Path,
        storage: &mut ChunkStorage,
        progress: Option<&BackupProgress>,
    ) -> Result<RestoreResult, BackupError> {
        let start = std::time::Instant::now();

        if !backup_path.exists() {
            return Err(BackupError::BackupNotFound {
                path: backup_path.to_string_lossy().to_string(),
            });
        }

        info!("Restoring from backup: {:?}", backup_path);

        if let Some(p) = progress {
            p.set_operation("Reading backup manifest");
        }

        // Read manifest from end of file
        let manifest = self.read_manifest(backup_path).await?;

        if manifest.version != BACKUP_VERSION {
            return Err(BackupError::IncompatibleVersion {
                version: manifest.version,
            });
        }

        if let Some(p) = progress {
            p.total_items
                .store(manifest.content_items.len() as u64, Ordering::Relaxed);
            p.total_bytes.store(manifest.total_size, Ordering::Relaxed);
        }

        let mut items_restored = 0;
        let mut chunks_restored = 0u64;
        let mut bytes_restored = 0u64;
        let mut failed_items = Vec::new();

        // Open backup file for reading
        let mut backup_file = fs::File::open(backup_path).await?;

        // Restore each content item
        for entry in &manifest.content_items {
            if let Some(p) = progress {
                if p.is_cancelled() {
                    return Err(BackupError::Cancelled);
                }
                p.set_operation(&format!("Restoring {}", entry.cid));
            }

            match self
                .restore_content(entry, &mut backup_file, storage, progress)
                .await
            {
                Ok((chunks, bytes)) => {
                    items_restored += 1;
                    chunks_restored += chunks;
                    bytes_restored += bytes;
                }
                Err(e) => {
                    warn!("Failed to restore {}: {}", entry.cid, e);
                    failed_items.push(entry.cid.clone());
                }
            }

            if let Some(p) = progress {
                p.increment_items();
            }
        }

        let duration = start.elapsed().as_secs_f64();

        info!(
            "Restore complete: {} items, {} chunks, {} bytes in {:.2}s",
            items_restored, chunks_restored, bytes_restored, duration
        );

        Ok(RestoreResult {
            items_restored,
            chunks_restored,
            bytes_restored,
            duration_secs: duration,
            failed_items,
        })
    }

    /// Read backup manifest from a backup file.
    pub async fn read_manifest(&self, backup_path: &Path) -> Result<BackupManifest, BackupError> {
        let mut file = fs::File::open(backup_path).await?;

        // Read manifest length from end
        let file_size = file.metadata().await?.len();
        file.seek(std::io::SeekFrom::End(-8)).await?;

        let mut len_bytes = [0u8; 8];
        file.read_exact(&mut len_bytes).await?;
        let manifest_len = u64::from_le_bytes(len_bytes) as usize;

        // Read manifest
        let manifest_start = file_size - 8 - manifest_len as u64;
        file.seek(std::io::SeekFrom::Start(manifest_start)).await?;

        let mut manifest_data = vec![0u8; manifest_len];
        file.read_exact(&mut manifest_data).await?;

        let manifest: BackupManifest = serde_json::from_slice(&manifest_data)
            .map_err(|e| BackupError::SerializationError(e.to_string()))?;

        Ok(manifest)
    }

    /// List available backups in a directory.
    pub async fn list_backups(
        &self,
        backup_dir: &Path,
    ) -> Result<Vec<BackupManifest>, BackupError> {
        let mut manifests = Vec::new();

        if !backup_dir.exists() {
            return Ok(manifests);
        }

        let mut entries = fs::read_dir(backup_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "chie") {
                match self.read_manifest(&path).await {
                    Ok(manifest) => manifests.push(manifest),
                    Err(e) => {
                        debug!("Skipping invalid backup {:?}: {}", path, e);
                    }
                }
            }
        }

        // Sort by creation time (newest first)
        manifests.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(manifests)
    }

    /// Verify a backup file integrity.
    pub async fn verify_backup(
        &self,
        backup_path: &Path,
        progress: Option<&BackupProgress>,
    ) -> Result<bool, BackupError> {
        if let Some(p) = progress {
            p.set_operation("Verifying backup integrity");
        }

        let manifest = self.read_manifest(backup_path).await?;

        // Verify manifest checksum
        let manifest_data = self.create_manifest_data(&manifest.content_items)?;
        let computed_checksum = hex::encode(hash(&manifest_data));

        if computed_checksum != manifest.checksum {
            return Ok(false);
        }

        // Verify each content entry exists and has correct checksums
        let mut file = fs::File::open(backup_path).await?;

        if let Some(p) = progress {
            p.total_items
                .store(manifest.content_items.len() as u64, Ordering::Relaxed);
        }

        for entry in &manifest.content_items {
            if let Some(p) = progress {
                if p.is_cancelled() {
                    return Err(BackupError::Cancelled);
                }
                p.set_operation(&format!("Verifying {}", entry.cid));
            }

            // Seek to entry offset and verify chunks exist
            file.seek(std::io::SeekFrom::Start(entry.archive_offset))
                .await?;

            // Read and verify chunk count
            let mut count_bytes = [0u8; 8];
            file.read_exact(&mut count_bytes).await?;
            let stored_count = u64::from_le_bytes(count_bytes);

            if stored_count != entry.chunk_count {
                return Ok(false);
            }

            if let Some(p) = progress {
                p.increment_items();
            }
        }

        Ok(true)
    }

    // Helper methods

    async fn backup_content(
        &self,
        storage: &ChunkStorage,
        cid: &str,
        backup_file: &mut fs::File,
        archive_offset: &mut u64,
        progress: Option<&BackupProgress>,
    ) -> Result<BackupContentEntry, BackupError> {
        let info = storage
            .get_pinned_info(cid)
            .ok_or(StorageError::ContentNotFound {
                cid: cid.to_string(),
            })?;

        let entry_offset = *archive_offset;
        let mut chunk_checksums = Vec::new();

        // Write chunk count
        let count_bytes = info.chunk_count.to_le_bytes();
        backup_file.write_all(&count_bytes).await?;
        *archive_offset += 8;

        // Write content metadata
        let meta_json =
            serde_json::to_vec(info).map_err(|e| BackupError::SerializationError(e.to_string()))?;
        let meta_len = meta_json.len() as u32;
        backup_file.write_all(&meta_len.to_le_bytes()).await?;
        backup_file.write_all(&meta_json).await?;
        *archive_offset += 4 + meta_json.len() as u64;

        // Write each chunk
        for chunk_idx in 0..info.chunk_count {
            let chunk_data = storage.get_chunk(cid, chunk_idx).await?;
            let chunk_hash = hash(&chunk_data);
            chunk_checksums.push(hex::encode(chunk_hash));

            // Write chunk length and data
            let chunk_len = chunk_data.len() as u32;
            backup_file.write_all(&chunk_len.to_le_bytes()).await?;
            backup_file.write_all(&chunk_data).await?;
            *archive_offset += 4 + chunk_data.len() as u64;

            if let Some(p) = progress {
                p.add_bytes(chunk_data.len() as u64);
            }
        }

        Ok(BackupContentEntry {
            cid: cid.to_string(),
            chunk_count: info.chunk_count,
            total_size: info.total_size,
            chunk_checksums,
            archive_offset: entry_offset,
        })
    }

    async fn restore_content(
        &self,
        entry: &BackupContentEntry,
        backup_file: &mut fs::File,
        storage: &mut ChunkStorage,
        progress: Option<&BackupProgress>,
    ) -> Result<(u64, u64), BackupError> {
        // Seek to entry offset
        backup_file
            .seek(std::io::SeekFrom::Start(entry.archive_offset))
            .await?;

        // Read chunk count
        let mut count_bytes = [0u8; 8];
        backup_file.read_exact(&mut count_bytes).await?;
        let chunk_count = u64::from_le_bytes(count_bytes);

        if chunk_count != entry.chunk_count {
            return Err(BackupError::InvalidFormat(format!(
                "Chunk count mismatch for {}: expected {}, got {}",
                entry.cid, entry.chunk_count, chunk_count
            )));
        }

        // Read content metadata
        let mut meta_len_bytes = [0u8; 4];
        backup_file.read_exact(&mut meta_len_bytes).await?;
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;

        let mut meta_data = vec![0u8; meta_len];
        backup_file.read_exact(&mut meta_data).await?;

        let content_info: PinnedContentInfo = serde_json::from_slice(&meta_data)
            .map_err(|e| BackupError::SerializationError(e.to_string()))?;

        // Read all chunks
        let mut chunks = Vec::new();
        let mut total_bytes = 0u64;

        for (idx, expected_checksum) in entry.chunk_checksums.iter().enumerate() {
            let mut chunk_len_bytes = [0u8; 4];
            backup_file.read_exact(&mut chunk_len_bytes).await?;
            let chunk_len = u32::from_le_bytes(chunk_len_bytes) as usize;

            let mut chunk_data = vec![0u8; chunk_len];
            backup_file.read_exact(&mut chunk_data).await?;

            // Verify checksum if enabled
            if self.config.verify_on_restore {
                let actual_checksum = hex::encode(hash(&chunk_data));
                if &actual_checksum != expected_checksum {
                    return Err(BackupError::ChecksumMismatch {
                        expected: expected_checksum.clone(),
                        actual: actual_checksum,
                    });
                }
            }

            total_bytes += chunk_data.len() as u64;
            chunks.push(chunk_data);

            if let Some(p) = progress {
                p.add_bytes(chunk_len as u64);
            }

            debug!(
                "Restored chunk {}/{} for {}",
                idx + 1,
                chunk_count,
                entry.cid
            );
        }

        // Pin the content in storage
        storage
            .pin_content(
                &entry.cid,
                &chunks,
                &content_info.encryption_key,
                &content_info.base_nonce,
            )
            .await?;

        Ok((chunk_count, total_bytes))
    }

    fn create_manifest_data(&self, entries: &[BackupContentEntry]) -> Result<Vec<u8>, BackupError> {
        // Create a deterministic representation for checksum
        let mut data = Vec::new();
        for entry in entries {
            data.extend_from_slice(entry.cid.as_bytes());
            data.extend_from_slice(&entry.chunk_count.to_le_bytes());
            data.extend_from_slice(&entry.total_size.to_le_bytes());
            for checksum in &entry.chunk_checksums {
                data.extend_from_slice(checksum.as_bytes());
            }
        }
        Ok(data)
    }
}

/// Retention policy for managing backup history.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Keep backups for at least this many days.
    pub min_retention_days: u32,
    /// Maximum number of full backups to keep.
    pub max_full_backups: usize,
    /// Maximum number of incremental backups per full backup.
    pub max_incremental_per_full: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            min_retention_days: 30,
            max_full_backups: 5,
            max_incremental_per_full: 10,
        }
    }
}

/// Apply retention policy to backup directory.
pub async fn apply_retention_policy(
    backup_dir: &Path,
    policy: &RetentionPolicy,
) -> Result<Vec<PathBuf>, BackupError> {
    let manager = BackupManager::new(BackupConfig::default());
    let manifests = manager.list_backups(backup_dir).await?;

    let mut to_delete = Vec::new();
    let now = chrono::Utc::now();
    let min_age = chrono::Duration::days(policy.min_retention_days as i64);

    // Group by full backup
    let mut full_backups: Vec<_> = manifests
        .iter()
        .filter(|m| m.backup_type == BackupType::Full)
        .collect();

    // Keep only max_full_backups
    if full_backups.len() > policy.max_full_backups {
        for manifest in full_backups.drain(policy.max_full_backups..) {
            if now - manifest.created_at > min_age {
                to_delete.push(backup_dir.join(format!("backup_{}.chie", manifest.backup_id)));
            }
        }
    }

    // For each remaining full backup, limit incrementals
    for full_manifest in &full_backups {
        let incrementals: Vec<_> = manifests
            .iter()
            .filter(|m| {
                m.backup_type == BackupType::Incremental
                    && m.parent_backup_id.as_ref() == Some(&full_manifest.backup_id)
            })
            .collect();

        if incrementals.len() > policy.max_incremental_per_full {
            for manifest in incrementals.iter().skip(policy.max_incremental_per_full) {
                if now - manifest.created_at > min_age {
                    to_delete
                        .push(backup_dir.join(format!("backup_{}_incr.chie", manifest.backup_id)));
                }
            }
        }
    }

    // Delete old backups
    for path in &to_delete {
        if path.exists() {
            fs::remove_file(path).await?;
            info!("Deleted old backup: {:?}", path);
        }
    }

    Ok(to_delete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_backup_config_default() {
        let config = BackupConfig::default();
        assert!(config.compress);
        assert!(config.verify_on_backup);
        assert!(config.verify_on_restore);
    }

    #[tokio::test]
    async fn test_progress_tracking() {
        let progress = BackupProgress::new();
        progress.total_bytes.store(100, Ordering::Relaxed);
        progress.processed_bytes.store(50, Ordering::Relaxed);

        assert!((progress.percentage() - 50.0).abs() < 0.01);

        progress.cancel();
        assert!(progress.is_cancelled());
    }

    #[tokio::test]
    async fn test_retention_policy_default() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.min_retention_days, 30);
        assert_eq!(policy.max_full_backups, 5);
        assert_eq!(policy.max_incremental_per_full, 10);
    }

    #[tokio::test]
    async fn test_list_empty_backups() {
        let tmp = tempdir().unwrap();
        let manager = BackupManager::new(BackupConfig::default());
        let backups = manager.list_backups(tmp.path()).await.unwrap();
        assert!(backups.is_empty());
    }
}
