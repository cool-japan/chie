//! Chunked upload handler for large files.
//!
//! This module provides:
//! - Automatic chunking of large files
//! - Progress tracking with callbacks
//! - Resumable uploads with state persistence
//! - Parallel chunk uploads

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore, mpsc};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Chunked upload error.
#[derive(Debug, Error)]
pub enum ChunkedUploadError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Upload failed: {0}")]
    UploadFailed(String),

    #[error("Chunk verification failed: index={index}")]
    VerificationFailed { index: u64 },

    #[error("Upload cancelled")]
    Cancelled,

    #[error("Upload state not found: {0}")]
    StateNotFound(String),

    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(usize),

    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },
}

/// Configuration for chunked uploads.
#[derive(Debug, Clone)]
pub struct ChunkedUploadConfig {
    /// Size of each chunk (bytes).
    pub chunk_size: usize,
    /// Maximum concurrent uploads.
    pub max_concurrent: usize,
    /// Maximum file size (bytes).
    pub max_file_size: u64,
    /// Retry count for failed chunks.
    pub retry_count: u32,
    /// Timeout per chunk (seconds).
    pub chunk_timeout: Duration,
    /// Whether to verify chunks after upload.
    pub verify_chunks: bool,
}

impl Default for ChunkedUploadConfig {
    fn default() -> Self {
        Self {
            chunk_size: 4 * 1024 * 1024, // 4 MB chunks
            max_concurrent: 4,
            max_file_size: 10 * 1024 * 1024 * 1024, // 10 GB
            retry_count: 3,
            chunk_timeout: Duration::from_secs(120),
            verify_chunks: true,
        }
    }
}

/// Upload progress information.
#[derive(Debug, Clone)]
pub struct UploadProgress {
    /// Upload ID.
    pub upload_id: String,
    /// Total file size in bytes.
    pub total_size: u64,
    /// Bytes uploaded so far.
    pub uploaded_bytes: u64,
    /// Total number of chunks.
    pub total_chunks: u64,
    /// Number of completed chunks.
    pub completed_chunks: u64,
    /// Current upload rate (bytes per second).
    pub upload_rate: f64,
    /// Estimated time remaining (seconds).
    pub eta_seconds: f64,
    /// Current status.
    pub status: UploadStatus,
}

impl UploadProgress {
    /// Get progress percentage.
    pub fn percentage(&self) -> f64 {
        if self.total_size == 0 {
            return 100.0;
        }
        (self.uploaded_bytes as f64 / self.total_size as f64) * 100.0
    }
}

/// Upload status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UploadStatus {
    /// Upload is being prepared.
    Preparing,
    /// Upload is in progress.
    InProgress,
    /// Upload is paused.
    Paused,
    /// Upload completed successfully.
    Completed,
    /// Upload failed.
    Failed,
    /// Upload was cancelled.
    Cancelled,
}

/// State for a resumable upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadState {
    /// Upload ID.
    pub upload_id: String,
    /// Content identifier.
    pub content_id: String,
    /// Original filename.
    pub filename: String,
    /// Total file size.
    pub total_size: u64,
    /// Chunk size used.
    pub chunk_size: usize,
    /// Total number of chunks.
    pub total_chunks: u64,
    /// Completed chunk indices.
    pub completed_chunks: Vec<u64>,
    /// Upload status.
    pub status: UploadStatus,
    /// Created timestamp.
    pub created_at: u64,
    /// Last updated timestamp.
    pub updated_at: u64,
    /// Hash of completed chunks (for verification).
    pub chunk_hashes: HashMap<u64, String>,
}

impl UploadState {
    /// Create a new upload state.
    pub fn new(content_id: &str, filename: &str, total_size: u64, chunk_size: usize) -> Self {
        let total_chunks = total_size.div_ceil(chunk_size as u64);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            upload_id: Uuid::new_v4().to_string(),
            content_id: content_id.to_string(),
            filename: filename.to_string(),
            total_size,
            chunk_size,
            total_chunks,
            completed_chunks: Vec::new(),
            status: UploadStatus::Preparing,
            created_at: now,
            updated_at: now,
            chunk_hashes: HashMap::new(),
        }
    }

    /// Mark a chunk as completed.
    pub fn mark_completed(&mut self, index: u64, hash: String) {
        if !self.completed_chunks.contains(&index) {
            self.completed_chunks.push(index);
            self.chunk_hashes.insert(index, hash);
            self.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }

    /// Check if upload is complete.
    pub fn is_complete(&self) -> bool {
        self.completed_chunks.len() as u64 == self.total_chunks
    }

    /// Get remaining chunk indices.
    pub fn remaining_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|i| !self.completed_chunks.contains(i))
            .collect()
    }

    /// Get uploaded bytes.
    pub fn uploaded_bytes(&self) -> u64 {
        let full_chunks = self.completed_chunks.len().saturating_sub(1);
        let last_chunk_size = if self.completed_chunks.contains(&(self.total_chunks - 1)) {
            self.total_size % self.chunk_size as u64
        } else {
            0
        };

        (full_chunks * self.chunk_size) as u64
            + last_chunk_size
            + if !self.completed_chunks.is_empty()
                && !self.completed_chunks.contains(&(self.total_chunks - 1))
            {
                self.chunk_size as u64
            } else {
                0
            }
    }
}

/// Chunk upload callback trait.
pub trait ChunkUploader: Send + Sync {
    /// Upload a chunk and return its hash.
    fn upload_chunk(
        &self,
        content_id: &str,
        chunk_index: u64,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<String, ChunkedUploadError>> + Send;
}

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(UploadProgress) + Send + Sync>;

/// Chunked upload manager.
pub struct ChunkedUploadManager<U: ChunkUploader> {
    config: ChunkedUploadConfig,
    uploader: Arc<U>,
    states: Arc<RwLock<HashMap<String, UploadState>>>,
    semaphore: Arc<Semaphore>,
}

impl<U: ChunkUploader + 'static> ChunkedUploadManager<U> {
    /// Create a new upload manager.
    pub fn new(config: ChunkedUploadConfig, uploader: U) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            config,
            uploader: Arc::new(uploader),
            states: Arc::new(RwLock::new(HashMap::new())),
            semaphore,
        }
    }

    /// Start a new upload from a file.
    pub async fn upload_file<P: AsRef<Path>>(
        &self,
        path: P,
        content_id: &str,
        progress_tx: Option<mpsc::Sender<UploadProgress>>,
    ) -> Result<UploadState, ChunkedUploadError> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len();

        if file_size > self.config.max_file_size {
            return Err(ChunkedUploadError::FileTooLarge {
                size: file_size,
                max: self.config.max_file_size,
            });
        }

        let filename = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let state = UploadState::new(content_id, &filename, file_size, self.config.chunk_size);
        let upload_id = state.upload_id.clone();

        {
            let mut states = self.states.write().await;
            states.insert(upload_id.clone(), state.clone());
        }

        self.upload_chunks(path, &upload_id, progress_tx).await
    }

    /// Resume an upload.
    pub async fn resume_upload<P: AsRef<Path>>(
        &self,
        path: P,
        upload_id: &str,
        progress_tx: Option<mpsc::Sender<UploadProgress>>,
    ) -> Result<UploadState, ChunkedUploadError> {
        {
            let states = self.states.read().await;
            if !states.contains_key(upload_id) {
                return Err(ChunkedUploadError::StateNotFound(upload_id.to_string()));
            }
        }

        self.upload_chunks(path.as_ref(), upload_id, progress_tx)
            .await
    }

    /// Upload chunks from a file.
    async fn upload_chunks(
        &self,
        path: &Path,
        upload_id: &str,
        progress_tx: Option<mpsc::Sender<UploadProgress>>,
    ) -> Result<UploadState, ChunkedUploadError> {
        let start_time = Instant::now();

        // Get remaining chunks
        let (remaining, content_id, total_size, total_chunks, bytes_at_start) = {
            let mut states = self.states.write().await;
            let state = states.get_mut(upload_id).unwrap();
            state.status = UploadStatus::InProgress;
            (
                state.remaining_chunks(),
                state.content_id.clone(),
                state.total_size,
                state.total_chunks,
                state.uploaded_bytes(),
            )
        };

        info!(
            "Starting upload {} with {} remaining chunks",
            upload_id,
            remaining.len()
        );

        // Read file
        let file_data = std::fs::read(path)?;

        // Upload remaining chunks with retry logic
        let mut handles = Vec::new();

        for chunk_index in remaining {
            let sem = self.semaphore.clone();
            let uploader = self.uploader.clone();
            let states = self.states.clone();
            let upload_id = upload_id.to_string();
            let content_id = content_id.clone();
            let chunk_size = self.config.chunk_size;
            let retry_count = self.config.retry_count;
            let chunk_timeout = self.config.chunk_timeout;

            let start = (chunk_index as usize) * chunk_size;
            let end = std::cmp::min(start + chunk_size, file_data.len());
            let chunk_data = file_data[start..end].to_vec();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                // Retry loop with exponential backoff
                let mut last_error = None;
                for attempt in 0..=retry_count {
                    if attempt > 0 {
                        let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                        debug!("Retry attempt {} for chunk {}", attempt, chunk_index);
                    }

                    // Upload with timeout
                    let upload_future =
                        uploader.upload_chunk(&content_id, chunk_index, chunk_data.clone());
                    let result = tokio::time::timeout(chunk_timeout, upload_future).await;

                    match result {
                        Ok(Ok(hash)) => {
                            let mut states = states.write().await;
                            if let Some(state) = states.get_mut(&upload_id) {
                                state.mark_completed(chunk_index, hash);
                            }
                            return Ok(chunk_index);
                        }
                        Ok(Err(e)) => {
                            warn!("Chunk {} attempt {} failed: {}", chunk_index, attempt, e);
                            last_error = Some(ChunkedUploadError::UploadFailed(e.to_string()));
                        }
                        Err(_) => {
                            warn!("Chunk {} attempt {} timed out", chunk_index, attempt);
                            last_error =
                                Some(ChunkedUploadError::UploadFailed("timeout".to_string()));
                        }
                    }
                }

                Err((
                    chunk_index,
                    last_error.unwrap_or_else(|| {
                        ChunkedUploadError::UploadFailed("Unknown error".to_string())
                    }),
                ))
            });

            handles.push(handle);
        }

        // Collect results and send progress
        let mut failed_chunks: Vec<(u64, ChunkedUploadError)> = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Ok(chunk_index)) => {
                    debug!("Chunk {} completed", chunk_index);

                    // Send progress update
                    if let Some(tx) = &progress_tx {
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let state = self.states.read().await;
                        let s = state.get(upload_id).unwrap();
                        let uploaded = s.uploaded_bytes();
                        let rate = if elapsed > 0.0 {
                            (uploaded - bytes_at_start) as f64 / elapsed
                        } else {
                            0.0
                        };
                        let remaining_bytes = total_size - uploaded;
                        let eta = if rate > 0.0 {
                            remaining_bytes as f64 / rate
                        } else {
                            0.0
                        };

                        let progress = UploadProgress {
                            upload_id: upload_id.to_string(),
                            total_size,
                            uploaded_bytes: uploaded,
                            total_chunks,
                            completed_chunks: s.completed_chunks.len() as u64,
                            upload_rate: rate,
                            eta_seconds: eta,
                            status: UploadStatus::InProgress,
                        };

                        let _ = tx.send(progress).await;
                    }
                }
                Ok(Err((chunk_index, error))) => {
                    warn!("Chunk {} failed after all retries: {}", chunk_index, error);
                    failed_chunks.push((chunk_index, error));
                }
                Err(join_error) => {
                    warn!("Chunk task panicked: {}", join_error);
                    failed_chunks.push((
                        0,
                        ChunkedUploadError::UploadFailed("task panicked".to_string()),
                    ));
                }
            }
        }

        // Update final state
        let final_state = {
            let mut states = self.states.write().await;
            let state = states.get_mut(upload_id).unwrap();

            if state.is_complete() {
                state.status = UploadStatus::Completed;
                info!("Upload {} completed successfully", upload_id);
            } else if !failed_chunks.is_empty() {
                state.status = UploadStatus::Failed;
                warn!(
                    "Upload {} failed with {} errors",
                    upload_id,
                    failed_chunks.len()
                );
            }

            state.clone()
        };

        // Send final progress
        if let Some(tx) = progress_tx {
            let progress = UploadProgress {
                upload_id: upload_id.to_string(),
                total_size,
                uploaded_bytes: final_state.uploaded_bytes(),
                total_chunks,
                completed_chunks: final_state.completed_chunks.len() as u64,
                upload_rate: 0.0,
                eta_seconds: 0.0,
                status: final_state.status,
            };
            let _ = tx.send(progress).await;
        }

        if final_state.is_complete() {
            Ok(final_state)
        } else {
            Err(ChunkedUploadError::UploadFailed(
                "Some chunks failed to upload".to_string(),
            ))
        }
    }

    /// Pause an upload.
    pub async fn pause(&self, upload_id: &str) -> Result<(), ChunkedUploadError> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(upload_id) {
            state.status = UploadStatus::Paused;
            Ok(())
        } else {
            Err(ChunkedUploadError::StateNotFound(upload_id.to_string()))
        }
    }

    /// Cancel an upload.
    pub async fn cancel(&self, upload_id: &str) -> Result<(), ChunkedUploadError> {
        let mut states = self.states.write().await;
        if let Some(state) = states.get_mut(upload_id) {
            state.status = UploadStatus::Cancelled;
            Ok(())
        } else {
            Err(ChunkedUploadError::StateNotFound(upload_id.to_string()))
        }
    }

    /// Get upload state.
    pub async fn get_state(&self, upload_id: &str) -> Option<UploadState> {
        let states = self.states.read().await;
        states.get(upload_id).cloned()
    }

    /// List all uploads.
    pub async fn list_uploads(&self) -> Vec<UploadState> {
        let states = self.states.read().await;
        states.values().cloned().collect()
    }

    /// Remove upload state.
    pub async fn remove(&self, upload_id: &str) -> Option<UploadState> {
        let mut states = self.states.write().await;
        states.remove(upload_id)
    }
}

/// Read chunks from a reader.
pub struct ChunkReader<R: Read> {
    reader: R,
    chunk_size: usize,
    current_index: u64,
    total_size: u64,
    bytes_read: u64,
}

impl<R: Read> ChunkReader<R> {
    /// Create a new chunk reader.
    pub fn new(reader: R, chunk_size: usize, total_size: u64) -> Self {
        Self {
            reader,
            chunk_size,
            current_index: 0,
            total_size,
            bytes_read: 0,
        }
    }

    /// Read the next chunk.
    pub fn next_chunk(&mut self) -> std::io::Result<Option<(u64, Vec<u8>)>> {
        if self.bytes_read >= self.total_size {
            return Ok(None);
        }

        let mut buffer = vec![0u8; self.chunk_size];
        let mut total_read = 0;

        while total_read < self.chunk_size {
            let remaining = self.total_size - self.bytes_read;
            if remaining == 0 {
                break;
            }

            let to_read = std::cmp::min(self.chunk_size - total_read, remaining as usize);

            let read = self
                .reader
                .read(&mut buffer[total_read..total_read + to_read])?;
            if read == 0 {
                break;
            }

            total_read += read;
            self.bytes_read += read as u64;
        }

        if total_read == 0 {
            return Ok(None);
        }

        buffer.truncate(total_read);
        let index = self.current_index;
        self.current_index += 1;

        Ok(Some((index, buffer)))
    }

    /// Get current position.
    pub fn position(&self) -> u64 {
        self.bytes_read
    }

    /// Get current chunk index.
    pub fn current_index(&self) -> u64 {
        self.current_index
    }
}

impl<R: Read> Iterator for ChunkReader<R> {
    type Item = std::io::Result<(u64, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_chunk() {
            Ok(Some(chunk)) => Some(Ok(chunk)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_upload_state() {
        let state = UploadState::new("content123", "test.bin", 1024 * 1024, 256 * 1024);

        assert_eq!(state.total_chunks, 4);
        assert!(!state.is_complete());
        assert_eq!(state.remaining_chunks().len(), 4);
    }

    #[test]
    fn test_upload_state_completion() {
        let mut state = UploadState::new("content123", "test.bin", 1024, 256);

        assert_eq!(state.total_chunks, 4);

        state.mark_completed(0, "hash0".to_string());
        state.mark_completed(1, "hash1".to_string());
        state.mark_completed(2, "hash2".to_string());
        state.mark_completed(3, "hash3".to_string());

        assert!(state.is_complete());
        assert_eq!(state.remaining_chunks().len(), 0);
    }

    #[test]
    fn test_chunk_reader() {
        let data = vec![0u8; 1000];
        let cursor = Cursor::new(data);
        let mut reader = ChunkReader::new(cursor, 256, 1000);

        let mut chunks = Vec::new();
        while let Ok(Some((index, chunk))) = reader.next_chunk() {
            chunks.push((index, chunk.len()));
        }

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], (0, 256));
        assert_eq!(chunks[1], (1, 256));
        assert_eq!(chunks[2], (2, 256));
        assert_eq!(chunks[3], (3, 232)); // Remaining bytes
    }

    #[test]
    fn test_chunk_reader_iterator() {
        let data = vec![1u8; 500];
        let cursor = Cursor::new(data);
        let reader = ChunkReader::new(cursor, 100, 500);

        let chunks: Vec<_> = reader.filter_map(|r| r.ok()).collect();
        assert_eq!(chunks.len(), 5);
    }

    #[test]
    fn test_upload_config_default() {
        let config = ChunkedUploadConfig::default();
        assert_eq!(config.chunk_size, 4 * 1024 * 1024);
        assert_eq!(config.max_concurrent, 4);
    }
}
