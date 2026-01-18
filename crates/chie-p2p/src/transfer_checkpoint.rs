//! Transfer checkpointing and resume functionality.
//!
//! This module provides the ability to checkpoint transfer progress and resume
//! interrupted transfers from the last successful checkpoint.
//!
//! # Example
//! ```
//! use chie_p2p::transfer_checkpoint::{CheckpointManager, CheckpointConfig, TransferId};
//! use std::time::Duration;
//!
//! let config = CheckpointConfig {
//!     checkpoint_interval: 100, // Checkpoint every 100 chunks
//!     retention: Duration::from_secs(3600),
//!     max_checkpoints: 100,
//!     enable_compression: true,
//! };
//!
//! let mut manager = CheckpointManager::new(config);
//! let transfer_id: TransferId = "transfer-123".to_string();
//! manager.start_transfer(transfer_id.clone(), 1000); // 1000 total chunks
//!
//! // Simulate progress
//! for chunk_id in 0..50 {
//!     manager.mark_completed(&transfer_id, chunk_id);
//! }
//!
//! // Save checkpoint
//! manager.checkpoint(&transfer_id);
//!
//! // Later, resume from checkpoint
//! if let Some(state) = manager.get_state(&transfer_id) {
//!     println!("Resume from chunk {}", state.completed_chunks.len());
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Transfer identifier
pub type TransferId = String;

/// Chunk identifier
pub type ChunkId = u64;

/// Transfer state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// Transfer is in progress
    InProgress,
    /// Transfer is paused
    Paused,
    /// Transfer has completed
    Completed,
    /// Transfer has failed
    Failed,
    /// Transfer was cancelled
    Cancelled,
}

/// Checkpoint data for a transfer
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Transfer identifier
    pub transfer_id: TransferId,
    /// Total number of chunks
    pub total_chunks: u64,
    /// Completed chunks
    pub completed_chunks: HashSet<ChunkId>,
    /// Failed chunks (with retry count)
    pub failed_chunks: HashMap<ChunkId, u32>,
    /// Current transfer state
    pub state: TransferState,
    /// When the checkpoint was created
    pub created_at: Instant,
    /// When the checkpoint was last updated
    pub updated_at: Instant,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Estimated bytes per chunk
    pub bytes_per_chunk: u64,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Checkpoint {
    /// Get progress percentage (0.0-1.0)
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        self.completed_chunks.len() as f64 / self.total_chunks as f64
    }

    /// Get remaining chunks
    pub fn remaining_chunks(&self) -> Vec<ChunkId> {
        let mut remaining = Vec::new();
        for chunk_id in 0..self.total_chunks {
            if !self.completed_chunks.contains(&chunk_id) {
                remaining.push(chunk_id);
            }
        }
        remaining
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        self.completed_chunks.len() as u64 >= self.total_chunks
    }

    /// Get checkpoint age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Estimate remaining bytes
    pub fn estimated_remaining_bytes(&self) -> u64 {
        let remaining = self.total_chunks - self.completed_chunks.len() as u64;
        remaining * self.bytes_per_chunk
    }
}

/// Checkpoint manager configuration
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// How often to auto-checkpoint (in chunks)
    pub checkpoint_interval: u64,
    /// How long to retain completed checkpoints
    pub retention: Duration,
    /// Maximum number of checkpoints to keep
    pub max_checkpoints: usize,
    /// Enable compression for checkpoint data
    pub enable_compression: bool,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 100,
            retention: Duration::from_secs(3600),
            max_checkpoints: 1000,
            enable_compression: false,
        }
    }
}

/// Checkpoint manager
pub struct CheckpointManager {
    /// Configuration
    config: CheckpointConfig,
    /// Active checkpoints
    checkpoints: HashMap<TransferId, Checkpoint>,
    /// Chunk counters for auto-checkpoint
    chunk_counters: HashMap<TransferId, u64>,
    /// Total checkpoints created
    total_checkpoints: u64,
    /// Total transfers resumed
    total_resumed: u64,
    /// Total transfers completed
    total_completed: u64,
    /// Total transfers failed
    total_failed: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new(config: CheckpointConfig) -> Self {
        Self {
            config,
            checkpoints: HashMap::new(),
            chunk_counters: HashMap::new(),
            total_checkpoints: 0,
            total_resumed: 0,
            total_completed: 0,
            total_failed: 0,
        }
    }

    /// Start a new transfer
    pub fn start_transfer(&mut self, transfer_id: TransferId, total_chunks: u64) -> bool {
        if self.checkpoints.contains_key(&transfer_id) {
            return false;
        }

        let now = Instant::now();
        let checkpoint = Checkpoint {
            transfer_id: transfer_id.clone(),
            total_chunks,
            completed_chunks: HashSet::new(),
            failed_chunks: HashMap::new(),
            state: TransferState::InProgress,
            created_at: now,
            updated_at: now,
            bytes_transferred: 0,
            bytes_per_chunk: 0,
            metadata: HashMap::new(),
        };

        self.checkpoints.insert(transfer_id.clone(), checkpoint);
        self.chunk_counters.insert(transfer_id, 0);
        true
    }

    /// Resume a transfer from checkpoint
    pub fn resume_transfer(&mut self, transfer_id: &TransferId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            if checkpoint.state == TransferState::Paused {
                checkpoint.state = TransferState::InProgress;
                checkpoint.updated_at = Instant::now();
                self.total_resumed += 1;
                return true;
            }
        }
        false
    }

    /// Mark a chunk as completed
    pub fn mark_completed(&mut self, transfer_id: &TransferId, chunk_id: ChunkId) -> bool {
        let should_checkpoint = if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            if checkpoint.state != TransferState::InProgress {
                return false;
            }

            checkpoint.completed_chunks.insert(chunk_id);
            checkpoint.failed_chunks.remove(&chunk_id);
            checkpoint.updated_at = Instant::now();

            // Check if transfer is complete
            if checkpoint.is_complete() {
                checkpoint.state = TransferState::Completed;
                self.total_completed += 1;
            }

            true
        } else {
            return false;
        };

        // Auto-checkpoint if needed
        if should_checkpoint {
            let should_do_checkpoint =
                if let Some(counter) = self.chunk_counters.get_mut(transfer_id) {
                    *counter += 1;
                    if *counter >= self.config.checkpoint_interval {
                        *counter = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

            if should_do_checkpoint {
                self.checkpoint(transfer_id);
            }
        }

        should_checkpoint
    }

    /// Mark a chunk as failed
    pub fn mark_failed(&mut self, transfer_id: &TransferId, chunk_id: ChunkId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            *checkpoint.failed_chunks.entry(chunk_id).or_insert(0) += 1;
            checkpoint.updated_at = Instant::now();
            true
        } else {
            false
        }
    }

    /// Update bytes transferred
    pub fn update_bytes(&mut self, transfer_id: &TransferId, bytes: u64) {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            checkpoint.bytes_transferred += bytes;

            // Update average bytes per chunk
            if !checkpoint.completed_chunks.is_empty() {
                checkpoint.bytes_per_chunk =
                    checkpoint.bytes_transferred / checkpoint.completed_chunks.len() as u64;
            }

            checkpoint.updated_at = Instant::now();
        }
    }

    /// Create a checkpoint
    pub fn checkpoint(&mut self, transfer_id: &TransferId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            checkpoint.updated_at = Instant::now();
            self.total_checkpoints += 1;
            true
        } else {
            false
        }
    }

    /// Pause a transfer
    pub fn pause_transfer(&mut self, transfer_id: &TransferId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            if checkpoint.state == TransferState::InProgress {
                checkpoint.state = TransferState::Paused;
                checkpoint.updated_at = Instant::now();
                self.checkpoint(transfer_id);
                return true;
            }
        }
        false
    }

    /// Cancel a transfer
    pub fn cancel_transfer(&mut self, transfer_id: &TransferId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            checkpoint.state = TransferState::Cancelled;
            checkpoint.updated_at = Instant::now();
            true
        } else {
            false
        }
    }

    /// Fail a transfer
    pub fn fail_transfer(&mut self, transfer_id: &TransferId) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            checkpoint.state = TransferState::Failed;
            checkpoint.updated_at = Instant::now();
            self.total_failed += 1;
            true
        } else {
            false
        }
    }

    /// Get transfer state
    pub fn get_state(&self, transfer_id: &TransferId) -> Option<&Checkpoint> {
        self.checkpoints.get(transfer_id)
    }

    /// Get all active transfers
    pub fn get_active_transfers(&self) -> Vec<&Checkpoint> {
        self.checkpoints
            .values()
            .filter(|c| c.state == TransferState::InProgress || c.state == TransferState::Paused)
            .collect()
    }

    /// Get chunks to retry
    pub fn get_retry_chunks(&self, transfer_id: &TransferId, max_retries: u32) -> Vec<ChunkId> {
        self.checkpoints
            .get(transfer_id)
            .map(|checkpoint| {
                checkpoint
                    .failed_chunks
                    .iter()
                    .filter(|&(_, count)| *count < max_retries)
                    .map(|(chunk_id, _)| *chunk_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update metadata
    pub fn update_metadata(
        &mut self,
        transfer_id: &TransferId,
        key: String,
        value: String,
    ) -> bool {
        if let Some(checkpoint) = self.checkpoints.get_mut(transfer_id) {
            checkpoint.metadata.insert(key, value);
            true
        } else {
            false
        }
    }

    /// Cleanup old checkpoints
    pub fn cleanup_old(&mut self) -> usize {
        let mut to_remove = Vec::new();

        for (id, checkpoint) in &self.checkpoints {
            if (checkpoint.state == TransferState::Completed
                || checkpoint.state == TransferState::Cancelled
                || checkpoint.state == TransferState::Failed)
                && checkpoint.age() > self.config.retention
            {
                to_remove.push(id.clone());
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.checkpoints.remove(&id);
            self.chunk_counters.remove(&id);
        }

        // Enforce max checkpoints limit
        while self.checkpoints.len() > self.config.max_checkpoints {
            if let Some(oldest_id) = self.find_oldest_completed() {
                self.checkpoints.remove(&oldest_id);
                self.chunk_counters.remove(&oldest_id);
            } else {
                break;
            }
        }

        count
    }

    /// Find oldest completed checkpoint
    fn find_oldest_completed(&self) -> Option<TransferId> {
        self.checkpoints
            .iter()
            .filter(|(_, c)| {
                c.state == TransferState::Completed
                    || c.state == TransferState::Cancelled
                    || c.state == TransferState::Failed
            })
            .min_by_key(|(_, c)| c.created_at)
            .map(|(id, _)| id.clone())
    }

    /// Get statistics
    pub fn stats(&self) -> CheckpointStats {
        let active = self
            .checkpoints
            .values()
            .filter(|c| c.state == TransferState::InProgress)
            .count();
        let paused = self
            .checkpoints
            .values()
            .filter(|c| c.state == TransferState::Paused)
            .count();

        CheckpointStats {
            total_checkpoints: self.checkpoints.len(),
            active_transfers: active,
            paused_transfers: paused,
            total_created: self.total_checkpoints,
            total_resumed: self.total_resumed,
            total_completed: self.total_completed,
            total_failed: self.total_failed,
        }
    }
}

/// Checkpoint statistics
#[derive(Debug, Clone)]
pub struct CheckpointStats {
    /// Total checkpoints currently stored
    pub total_checkpoints: usize,
    /// Active transfers
    pub active_transfers: usize,
    /// Paused transfers
    pub paused_transfers: usize,
    /// Total checkpoints created
    pub total_created: u64,
    /// Total transfers resumed
    pub total_resumed: u64,
    /// Total transfers completed
    pub total_completed: u64,
    /// Total transfers failed
    pub total_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_transfer() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        assert!(manager.start_transfer("transfer1".to_string(), 100));
        assert!(!manager.start_transfer("transfer1".to_string(), 100)); // Duplicate

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.total_chunks, 100);
        assert_eq!(state.state, TransferState::InProgress);
    }

    #[test]
    fn test_mark_completed() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.mark_completed(&"transfer1".to_string(), 0));
        assert!(manager.mark_completed(&"transfer1".to_string(), 1));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.completed_chunks.len(), 2);
        assert!(state.completed_chunks.contains(&0));
        assert!(state.completed_chunks.contains(&1));
    }

    #[test]
    fn test_mark_failed() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.mark_failed(&"transfer1".to_string(), 5));
        assert!(manager.mark_failed(&"transfer1".to_string(), 5));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.failed_chunks.get(&5), Some(&2));
    }

    #[test]
    fn test_transfer_progress() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 100);

        for i in 0..50 {
            manager.mark_completed(&"transfer1".to_string(), i);
        }

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.progress(), 0.5);
    }

    #[test]
    fn test_transfer_completion() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 5);

        for i in 0..5 {
            manager.mark_completed(&"transfer1".to_string(), i);
        }

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert!(state.is_complete());
        assert_eq!(state.state, TransferState::Completed);
    }

    #[test]
    fn test_remaining_chunks() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.mark_completed(&"transfer1".to_string(), 0);
        manager.mark_completed(&"transfer1".to_string(), 2);
        manager.mark_completed(&"transfer1".to_string(), 5);

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        let remaining = state.remaining_chunks();
        assert_eq!(remaining.len(), 7);
        assert!(!remaining.contains(&0));
        assert!(remaining.contains(&1));
    }

    #[test]
    fn test_pause_resume() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.pause_transfer(&"transfer1".to_string()));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.state, TransferState::Paused);

        assert!(manager.resume_transfer(&"transfer1".to_string()));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.state, TransferState::InProgress);
    }

    #[test]
    fn test_cancel_transfer() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.cancel_transfer(&"transfer1".to_string()));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.state, TransferState::Cancelled);
    }

    #[test]
    fn test_fail_transfer() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.fail_transfer(&"transfer1".to_string()));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.state, TransferState::Failed);
    }

    #[test]
    fn test_update_bytes() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.mark_completed(&"transfer1".to_string(), 0);
        manager.update_bytes(&"transfer1".to_string(), 1000);

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.bytes_transferred, 1000);
        assert_eq!(state.bytes_per_chunk, 1000);
    }

    #[test]
    fn test_estimated_remaining_bytes() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.mark_completed(&"transfer1".to_string(), 0);
        manager.update_bytes(&"transfer1".to_string(), 1000);

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.estimated_remaining_bytes(), 9000);
    }

    #[test]
    fn test_get_retry_chunks() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.mark_failed(&"transfer1".to_string(), 5);
        manager.mark_failed(&"transfer1".to_string(), 5);
        manager.mark_failed(&"transfer1".to_string(), 7);

        let retry = manager.get_retry_chunks(&"transfer1".to_string(), 3);
        assert_eq!(retry.len(), 2);
        assert!(retry.contains(&5));
        assert!(retry.contains(&7));

        let retry_limited = manager.get_retry_chunks(&"transfer1".to_string(), 2);
        assert_eq!(retry_limited.len(), 1);
        assert!(retry_limited.contains(&7));
    }

    #[test]
    fn test_get_active_transfers() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.start_transfer("transfer2".to_string(), 10);
        manager.start_transfer("transfer3".to_string(), 10);
        manager.pause_transfer(&"transfer2".to_string());
        manager.cancel_transfer(&"transfer3".to_string());

        let active = manager.get_active_transfers();
        assert_eq!(active.len(), 2); // transfer1 (in progress) and transfer2 (paused)
    }

    #[test]
    fn test_update_metadata() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        assert!(manager.update_metadata(
            &"transfer1".to_string(),
            "source".to_string(),
            "peer1".to_string()
        ));

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.metadata.get("source"), Some(&"peer1".to_string()));
    }

    #[test]
    fn test_cleanup_old() {
        let config = CheckpointConfig {
            retention: Duration::from_millis(50),
            ..Default::default()
        };
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 5);
        for i in 0..5 {
            manager.mark_completed(&"transfer1".to_string(), i);
        }

        std::thread::sleep(Duration::from_millis(100));

        let cleaned = manager.cleanup_old();
        assert_eq!(cleaned, 1);
        assert!(manager.get_state(&"transfer1".to_string()).is_none());
    }

    #[test]
    fn test_stats() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.start_transfer("transfer2".to_string(), 10);
        manager.pause_transfer(&"transfer2".to_string());

        let stats = manager.stats();
        assert_eq!(stats.total_checkpoints, 2);
        assert_eq!(stats.active_transfers, 1);
        assert_eq!(stats.paused_transfers, 1);
    }

    #[test]
    fn test_auto_checkpoint() {
        let config = CheckpointConfig {
            checkpoint_interval: 5,
            ..Default::default()
        };
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 20);

        for i in 0..10 {
            manager.mark_completed(&"transfer1".to_string(), i);
        }

        let stats = manager.stats();
        assert!(stats.total_created >= 2); // Should have auto-checkpointed at 5 and 10
    }

    #[test]
    fn test_mark_failed_then_complete() {
        let config = CheckpointConfig::default();
        let mut manager = CheckpointManager::new(config);

        manager.start_transfer("transfer1".to_string(), 10);
        manager.mark_failed(&"transfer1".to_string(), 5);
        manager.mark_failed(&"transfer1".to_string(), 5);

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert_eq!(state.failed_chunks.get(&5), Some(&2));

        manager.mark_completed(&"transfer1".to_string(), 5);

        let state = manager.get_state(&"transfer1".to_string()).unwrap();
        assert!(!state.failed_chunks.contains_key(&5));
        assert!(state.completed_chunks.contains(&5));
    }
}
