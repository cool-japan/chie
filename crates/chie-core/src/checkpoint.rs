//! Checkpoint-based state recovery system.
//!
//! This module provides mechanisms for saving and restoring system state
//! to enable crash recovery and resilience. Checkpoints can be created
//! periodically and restored after a failure.
//!
//! # Example
//!
//! ```rust
//! use chie_core::checkpoint::{CheckpointManager, CheckpointConfig, Checkpointable};
//! use std::path::PathBuf;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize, Clone)]
//! struct MyState {
//!     counter: u64,
//!     name: String,
//! }
//!
//! impl Checkpointable for MyState {
//!     fn checkpoint_id(&self) -> String {
//!         format!("mystate_{}", self.counter)
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = CheckpointConfig {
//!     base_path: PathBuf::from("/tmp/checkpoints"),
//!     max_checkpoints: 5,
//!     compression_enabled: true,
//! };
//!
//! let mut manager = CheckpointManager::new(config)?;
//!
//! let state = MyState {
//!     counter: 42,
//!     name: "test".to_string(),
//! };
//!
//! // Save checkpoint
//! manager.save_checkpoint(&state)?;
//!
//! // Restore latest checkpoint
//! let restored: MyState = manager.restore_latest()?;
//! assert_eq!(restored.counter, 42);
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Checkpoint error types.
#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("No checkpoints available")]
    NoCheckpointsAvailable,

    #[error("Checkpoint not found: {0}")]
    CheckpointNotFound(String),

    #[error("Invalid checkpoint data")]
    InvalidCheckpointData,
}

/// Configuration for checkpoint management.
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// Base directory for storing checkpoints.
    pub base_path: PathBuf,
    /// Maximum number of checkpoints to retain (oldest are deleted).
    pub max_checkpoints: usize,
    /// Enable compression for checkpoint files.
    pub compression_enabled: bool,
}

impl Default for CheckpointConfig {
    #[inline]
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./checkpoints"),
            max_checkpoints: 10,
            compression_enabled: true,
        }
    }
}

/// Trait for objects that can be checkpointed.
pub trait Checkpointable: Serialize + for<'de> Deserialize<'de> {
    /// Get a unique identifier for this checkpoint.
    fn checkpoint_id(&self) -> String;
}

/// Metadata about a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Checkpoint identifier.
    pub id: String,
    /// Timestamp when created (Unix milliseconds).
    pub timestamp_ms: i64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Whether this checkpoint is compressed.
    pub compressed: bool,
}

impl CheckpointMetadata {
    /// Get the age of this checkpoint in milliseconds.
    #[must_use]
    #[inline]
    pub fn age_ms(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        now - self.timestamp_ms
    }
}

/// Manages checkpoint creation and restoration.
pub struct CheckpointManager {
    config: CheckpointConfig,
    checkpoints: Vec<CheckpointMetadata>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new(config: CheckpointConfig) -> Result<Self, CheckpointError> {
        // Create base directory if it doesn't exist
        fs::create_dir_all(&config.base_path)?;

        let mut manager = Self {
            config,
            checkpoints: Vec::new(),
        };

        // Load existing checkpoint metadata
        manager.scan_checkpoints()?;

        Ok(manager)
    }

    /// Scan the checkpoint directory and load metadata.
    fn scan_checkpoints(&mut self) -> Result<(), CheckpointError> {
        self.checkpoints.clear();

        let entries = fs::read_dir(&self.config.base_path)?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("meta") {
                if let Ok(meta_content) = fs::read_to_string(&path) {
                    if let Ok(metadata) = serde_json::from_str::<CheckpointMetadata>(&meta_content)
                    {
                        self.checkpoints.push(metadata);
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        self.checkpoints
            .sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));

        Ok(())
    }

    /// Save a checkpoint of the given state.
    pub fn save_checkpoint<T: Checkpointable>(&mut self, state: &T) -> Result<(), CheckpointError> {
        let id = state.checkpoint_id();
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Serialize the state
        let serialized =
            serde_json::to_vec(state).map_err(|e| CheckpointError::Serialization(e.to_string()))?;

        let data = if self.config.compression_enabled {
            // Simple compression placeholder (in production, use flate2 or zstd)
            serialized
        } else {
            serialized
        };

        // Write checkpoint data
        let checkpoint_path = self.config.base_path.join(format!("{}.ckpt", id));
        let mut file = File::create(&checkpoint_path)?;
        file.write_all(&data)?;

        let size_bytes = data.len() as u64;

        // Write metadata
        let metadata = CheckpointMetadata {
            id: id.clone(),
            timestamp_ms,
            size_bytes,
            compressed: self.config.compression_enabled,
        };

        let meta_path = self.config.base_path.join(format!("{}.meta", id));
        let meta_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
        fs::write(meta_path, meta_json)?;

        // Update checkpoint list
        self.checkpoints.insert(0, metadata);

        // Clean up old checkpoints
        self.cleanup_old_checkpoints()?;

        Ok(())
    }

    /// Restore state from the latest checkpoint.
    pub fn restore_latest<T: Checkpointable>(&self) -> Result<T, CheckpointError> {
        let metadata = self
            .checkpoints
            .first()
            .ok_or(CheckpointError::NoCheckpointsAvailable)?;

        self.restore_checkpoint(&metadata.id)
    }

    /// Restore state from a specific checkpoint.
    pub fn restore_checkpoint<T: Checkpointable>(&self, id: &str) -> Result<T, CheckpointError> {
        let checkpoint_path = self.config.base_path.join(format!("{}.ckpt", id));

        if !checkpoint_path.exists() {
            return Err(CheckpointError::CheckpointNotFound(id.to_string()));
        }

        // Read checkpoint data
        let mut file = File::open(&checkpoint_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // Decompress if needed
        let decompressed = if self.config.compression_enabled {
            // Simple decompression placeholder
            data
        } else {
            data
        };

        // Deserialize
        serde_json::from_slice(&decompressed)
            .map_err(|e| CheckpointError::Deserialization(e.to_string()))
    }

    /// Clean up old checkpoints beyond the configured limit.
    fn cleanup_old_checkpoints(&mut self) -> Result<(), CheckpointError> {
        while self.checkpoints.len() > self.config.max_checkpoints {
            if let Some(old_checkpoint) = self.checkpoints.pop() {
                // Delete checkpoint file
                let checkpoint_path = self
                    .config
                    .base_path
                    .join(format!("{}.ckpt", old_checkpoint.id));
                let _ = fs::remove_file(checkpoint_path);

                // Delete metadata file
                let meta_path = self
                    .config
                    .base_path
                    .join(format!("{}.meta", old_checkpoint.id));
                let _ = fs::remove_file(meta_path);
            }
        }

        Ok(())
    }

    /// Get metadata for all available checkpoints.
    #[must_use]
    #[inline]
    pub fn list_checkpoints(&self) -> &[CheckpointMetadata] {
        &self.checkpoints
    }

    /// Get the number of available checkpoints.
    #[must_use]
    #[inline]
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Delete a specific checkpoint.
    pub fn delete_checkpoint(&mut self, id: &str) -> Result<(), CheckpointError> {
        // Remove from list
        self.checkpoints.retain(|ckpt| ckpt.id != id);

        // Delete files
        let checkpoint_path = self.config.base_path.join(format!("{}.ckpt", id));
        let meta_path = self.config.base_path.join(format!("{}.meta", id));

        let _ = fs::remove_file(checkpoint_path);
        let _ = fs::remove_file(meta_path);

        Ok(())
    }

    /// Delete all checkpoints.
    pub fn clear_all(&mut self) -> Result<(), CheckpointError> {
        for checkpoint in &self.checkpoints {
            let checkpoint_path = self
                .config
                .base_path
                .join(format!("{}.ckpt", checkpoint.id));
            let meta_path = self
                .config
                .base_path
                .join(format!("{}.meta", checkpoint.id));

            let _ = fs::remove_file(checkpoint_path);
            let _ = fs::remove_file(meta_path);
        }

        self.checkpoints.clear();

        Ok(())
    }

    /// Get total size of all checkpoints in bytes.
    #[must_use]
    #[inline]
    pub fn total_size_bytes(&self) -> u64 {
        self.checkpoints.iter().map(|c| c.size_bytes).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestState {
        counter: u64,
        name: String,
        values: Vec<i32>,
    }

    impl Checkpointable for TestState {
        fn checkpoint_id(&self) -> String {
            format!("test_{}", self.counter)
        }
    }

    #[test]
    fn test_checkpoint_save_and_restore() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        let state = TestState {
            counter: 42,
            name: "test".to_string(),
            values: vec![1, 2, 3],
        };

        // Save checkpoint
        manager.save_checkpoint(&state).unwrap();
        assert_eq!(manager.checkpoint_count(), 1);

        // Restore checkpoint
        let restored: TestState = manager.restore_latest().unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn test_multiple_checkpoints() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 3,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        // Create multiple checkpoints
        for i in 0..5 {
            let state = TestState {
                counter: i,
                name: format!("state_{}", i),
                values: vec![i as i32],
            };
            manager.save_checkpoint(&state).unwrap();
        }

        // Should only keep the latest 3
        assert_eq!(manager.checkpoint_count(), 3);

        // Latest should be state 4
        let latest: TestState = manager.restore_latest().unwrap();
        assert_eq!(latest.counter, 4);
    }

    #[test]
    fn test_checkpoint_deletion() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        let state = TestState {
            counter: 100,
            name: "delete_me".to_string(),
            values: vec![],
        };

        manager.save_checkpoint(&state).unwrap();
        assert_eq!(manager.checkpoint_count(), 1);

        // Delete the checkpoint
        let id = state.checkpoint_id();
        manager.delete_checkpoint(&id).unwrap();
        assert_eq!(manager.checkpoint_count(), 0);
    }

    #[test]
    fn test_checkpoint_metadata() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        let state = TestState {
            counter: 999,
            name: "metadata_test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        manager.save_checkpoint(&state).unwrap();

        let checkpoints = manager.list_checkpoints();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].id, "test_999");
        assert!(checkpoints[0].size_bytes > 0);
        assert!(checkpoints[0].age_ms() >= 0);
    }

    #[test]
    fn test_total_size_calculation() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        for i in 0..3 {
            let state = TestState {
                counter: i,
                name: format!("state_{}", i),
                values: vec![i as i32; 10],
            };
            manager.save_checkpoint(&state).unwrap();
        }

        let total_size = manager.total_size_bytes();
        assert!(total_size > 0);
    }

    #[test]
    fn test_restore_specific_checkpoint() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let mut manager = CheckpointManager::new(config).unwrap();

        // Create multiple checkpoints
        let states: Vec<TestState> = (0..3)
            .map(|i| TestState {
                counter: i,
                name: format!("state_{}", i),
                values: vec![i as i32],
            })
            .collect();

        for state in &states {
            manager.save_checkpoint(state).unwrap();
        }

        // Restore specific checkpoint (state 1)
        let restored: TestState = manager.restore_checkpoint("test_1").unwrap();
        assert_eq!(restored.counter, 1);
        assert_eq!(restored.name, "state_1");
    }

    #[test]
    fn test_no_checkpoints_error() {
        let temp_dir = TempDir::new().unwrap();

        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 5,
            compression_enabled: false,
        };

        let manager = CheckpointManager::new(config).unwrap();

        // Should fail when no checkpoints exist
        let result: Result<TestState, _> = manager.restore_latest();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CheckpointError::NoCheckpointsAvailable
        ));
    }
}
