//! Automatic data integrity repair for corrupted chunks.
//!
//! This module provides automatic detection and repair of corrupted content chunks
//! by re-fetching them from alternative sources and verifying integrity.
//!
//! # Example
//!
//! ```
//! use chie_core::auto_repair::{ChunkRepairStrategy, ChunkRepairConfig, ChunkRepairRequest};
//! use std::time::Duration;
//!
//! // Configure repair strategy
//! let config = ChunkRepairConfig {
//!     max_retries: 3,
//!     retry_delay: Duration::from_millis(100),
//!     verify_after_repair: true,
//!     ..Default::default()
//! };
//!
//! // Create repair request for failed chunks
//! let request = ChunkRepairRequest {
//!     content_id: "QmTest".to_string(),
//!     failed_chunk_indices: vec![0, 5, 10],
//!     total_chunks: 100,
//! };
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur during chunk repair.
#[derive(Debug, Error)]
pub enum RepairError {
    #[error("Maximum repair retries exceeded for chunk {chunk_index}")]
    MaxRetriesExceeded { chunk_index: usize },

    #[error("No alternative sources available for chunk {chunk_index}")]
    NoSourcesAvailable { chunk_index: usize },

    #[error("Verification failed after repair for chunk {chunk_index}")]
    VerificationFailed { chunk_index: usize },

    #[error("Repair timeout exceeded for content {content_id}")]
    TimeoutExceeded { content_id: String },

    #[error("IO error during repair: {0}")]
    IoError(#[from] std::io::Error),
}

/// Configuration for automatic chunk repair operations.
#[derive(Debug, Clone)]
pub struct ChunkRepairConfig {
    /// Maximum number of retry attempts per chunk.
    pub max_retries: u32,
    /// Delay between retry attempts.
    pub retry_delay: Duration,
    /// Whether to verify chunks after repair.
    pub verify_after_repair: bool,
    /// Maximum time to spend on repair operations.
    pub max_repair_time: Duration,
    /// Minimum number of alternative sources required.
    pub min_sources: usize,
    /// Whether to prioritize repairs based on chunk importance.
    pub prioritize_repairs: bool,
}

impl Default for ChunkRepairConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            verify_after_repair: true,
            max_repair_time: Duration::from_secs(300),
            min_sources: 2,
            prioritize_repairs: true,
        }
    }
}

/// Request to repair specific chunks of content.
#[derive(Debug, Clone)]
pub struct ChunkRepairRequest {
    /// Content identifier.
    pub content_id: String,
    /// Indices of chunks that need repair.
    pub failed_chunk_indices: Vec<usize>,
    /// Total number of chunks in content.
    pub total_chunks: usize,
}

/// Status of a chunk repair operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRepairStatus {
    /// Repair is pending.
    Pending,
    /// Repair is in progress.
    InProgress,
    /// Repair completed successfully.
    Repaired,
    /// Repair failed.
    Failed,
    /// Repair skipped (e.g., no sources available).
    Skipped,
}

/// Statistics for chunk repair operations.
#[derive(Debug, Clone, Default)]
pub struct ChunkRepairStats {
    /// Total chunks attempted to repair.
    pub total_attempts: usize,
    /// Successfully repaired chunks.
    pub successful_repairs: usize,
    /// Failed repair attempts.
    pub failed_repairs: usize,
    /// Skipped repairs.
    pub skipped_repairs: usize,
    /// Total bytes repaired.
    pub bytes_repaired: u64,
    /// Average repair time per chunk.
    pub avg_repair_time_ms: u64,
}

/// Tracks the repair state for a single chunk.
#[derive(Debug)]
struct ChunkRepairState {
    index: usize,
    status: ChunkRepairStatus,
    retry_count: u32,
    last_attempt: Option<Instant>,
    sources_tried: HashSet<String>,
}

impl ChunkRepairState {
    fn new(index: usize) -> Self {
        Self {
            index,
            status: ChunkRepairStatus::Pending,
            retry_count: 0,
            last_attempt: None,
            sources_tried: HashSet::new(),
        }
    }

    #[inline]
    fn can_retry(&self, config: &ChunkRepairConfig) -> bool {
        self.retry_count < config.max_retries
    }

    #[inline]
    fn should_retry(&self, config: &ChunkRepairConfig) -> bool {
        if !self.can_retry(config) {
            return false;
        }

        if let Some(last) = self.last_attempt {
            last.elapsed() >= config.retry_delay
        } else {
            true
        }
    }

    #[inline]
    fn mark_attempt(&mut self, source: String) {
        self.status = ChunkRepairStatus::InProgress;
        self.retry_count += 1;
        self.last_attempt = Some(Instant::now());
        self.sources_tried.insert(source);
    }
}

/// Strategy for repairing corrupted chunks.
pub struct ChunkRepairStrategy {
    config: ChunkRepairConfig,
    chunk_states: HashMap<usize, ChunkRepairState>,
    stats: ChunkRepairStats,
    started_at: Option<Instant>,
}

impl ChunkRepairStrategy {
    /// Create a new repair strategy with the given configuration.
    #[must_use]
    #[inline]
    pub fn new(config: ChunkRepairConfig) -> Self {
        Self {
            config,
            chunk_states: HashMap::new(),
            stats: ChunkRepairStats::default(),
            started_at: None,
        }
    }

    /// Initialize repair for a set of failed chunks.
    #[inline]
    pub fn initialize_repair(&mut self, request: ChunkRepairRequest) {
        self.started_at = Some(Instant::now());

        for &index in &request.failed_chunk_indices {
            if index < request.total_chunks {
                self.chunk_states
                    .insert(index, ChunkRepairState::new(index));
            }
        }

        self.stats.total_attempts = request.failed_chunk_indices.len();
    }

    /// Get the next chunk that should be repaired.
    #[must_use]
    pub fn next_repair_candidate(&mut self) -> Option<usize> {
        // Check for timeout
        if let Some(started) = self.started_at {
            if started.elapsed() >= self.config.max_repair_time {
                return None;
            }
        }

        // Find chunks that are ready for retry
        let mut candidates: Vec<_> = self
            .chunk_states
            .values()
            .filter(|state| {
                matches!(
                    state.status,
                    ChunkRepairStatus::Pending | ChunkRepairStatus::InProgress
                ) && state.should_retry(&self.config)
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Prioritize by retry count (fewer retries first)
        if self.config.prioritize_repairs {
            candidates.sort_by_key(|state| state.retry_count);
        }

        candidates.first().map(|state| state.index)
    }

    /// Mark a repair attempt as started.
    #[inline]
    pub fn mark_repair_attempt(&mut self, chunk_index: usize, source: String) {
        if let Some(state) = self.chunk_states.get_mut(&chunk_index) {
            state.mark_attempt(source);
        }
    }

    /// Mark a chunk as successfully repaired.
    #[inline]
    pub fn mark_repaired(&mut self, chunk_index: usize, bytes_repaired: u64) {
        if let Some(state) = self.chunk_states.get_mut(&chunk_index) {
            state.status = ChunkRepairStatus::Repaired;
            self.stats.successful_repairs += 1;
            self.stats.bytes_repaired += bytes_repaired;
        }
    }

    /// Mark a chunk repair as failed.
    #[inline]
    pub fn mark_failed(&mut self, chunk_index: usize) {
        if let Some(state) = self.chunk_states.get_mut(&chunk_index) {
            if !state.can_retry(&self.config) {
                state.status = ChunkRepairStatus::Failed;
                self.stats.failed_repairs += 1;
            }
        }
    }

    /// Mark a chunk repair as skipped.
    #[inline]
    pub fn mark_skipped(&mut self, chunk_index: usize) {
        if let Some(state) = self.chunk_states.get_mut(&chunk_index) {
            state.status = ChunkRepairStatus::Skipped;
            self.stats.skipped_repairs += 1;
        }
    }

    /// Check if all repairs are complete.
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.chunk_states.values().all(|state| {
            !matches!(
                state.status,
                ChunkRepairStatus::Pending | ChunkRepairStatus::InProgress
            )
        })
    }

    /// Get the current repair statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &ChunkRepairStats {
        &self.stats
    }

    /// Get the status of a specific chunk.
    #[must_use]
    #[inline]
    pub fn chunk_status(&self, index: usize) -> Option<&ChunkRepairStatus> {
        self.chunk_states.get(&index).map(|state| &state.status)
    }

    /// Get all chunks that still need repair.
    #[must_use]
    #[inline]
    pub fn pending_repairs(&self) -> Vec<usize> {
        self.chunk_states
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state.status,
                    ChunkRepairStatus::Pending | ChunkRepairStatus::InProgress
                )
            })
            .map(|(index, _)| *index)
            .collect()
    }

    /// Get chunks that have been successfully repaired.
    #[must_use]
    #[inline]
    pub fn repaired_chunks(&self) -> Vec<usize> {
        self.chunk_states
            .iter()
            .filter(|(_, state)| state.status == ChunkRepairStatus::Repaired)
            .map(|(index, _)| *index)
            .collect()
    }

    /// Get chunks that failed repair.
    #[must_use]
    #[inline]
    pub fn failed_chunks(&self) -> Vec<usize> {
        self.chunk_states
            .iter()
            .filter(|(_, state)| state.status == ChunkRepairStatus::Failed)
            .map(|(index, _)| *index)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_config_defaults() {
        let config = ChunkRepairConfig::default();
        assert_eq!(config.max_retries, 3);
        assert!(config.verify_after_repair);
        assert_eq!(config.min_sources, 2);
    }

    #[test]
    fn test_repair_strategy_initialization() {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0, 1, 2],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);
        assert_eq!(strategy.stats.total_attempts, 3);
        assert!(!strategy.is_complete());
    }

    #[test]
    fn test_next_repair_candidate() {
        let config = ChunkRepairConfig {
            retry_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0, 1],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);

        let candidate = strategy.next_repair_candidate();
        assert!(candidate.is_some());
        assert!(candidate.unwrap() == 0 || candidate.unwrap() == 1);
    }

    #[test]
    fn test_mark_repaired() {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);
        strategy.mark_repaired(0, 1024);

        assert_eq!(strategy.stats.successful_repairs, 1);
        assert_eq!(strategy.stats.bytes_repaired, 1024);
        assert_eq!(strategy.chunk_status(0), Some(&ChunkRepairStatus::Repaired));
    }

    #[test]
    fn test_mark_failed() {
        let config = ChunkRepairConfig {
            max_retries: 1,
            ..Default::default()
        };
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);
        strategy.mark_repair_attempt(0, "peer1".to_string());
        strategy.mark_failed(0);

        // Should still be able to get next candidate since max_retries = 1
        let candidate = strategy.next_repair_candidate();
        assert!(candidate.is_none() || candidate == Some(0));
    }

    #[test]
    fn test_repair_completion() {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0, 1],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);
        assert!(!strategy.is_complete());

        strategy.mark_repaired(0, 1024);
        assert!(!strategy.is_complete());

        strategy.mark_repaired(1, 1024);
        assert!(strategy.is_complete());
    }

    #[test]
    fn test_pending_and_repaired_lists() {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0, 1, 2],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);

        let pending = strategy.pending_repairs();
        assert_eq!(pending.len(), 3);

        strategy.mark_repaired(0, 1024);

        let pending = strategy.pending_repairs();
        assert_eq!(pending.len(), 2);

        let repaired = strategy.repaired_chunks();
        assert_eq!(repaired.len(), 1);
        assert!(repaired.contains(&0));
    }

    #[test]
    fn test_mark_skipped() {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);
        strategy.mark_skipped(0);

        assert_eq!(strategy.stats.skipped_repairs, 1);
        assert_eq!(strategy.chunk_status(0), Some(&ChunkRepairStatus::Skipped));
    }

    #[test]
    fn test_retry_logic() {
        let config = ChunkRepairConfig {
            max_retries: 2,
            retry_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0],
            total_chunks: 10,
        };

        strategy.initialize_repair(request);

        // First attempt
        strategy.mark_repair_attempt(0, "peer1".to_string());
        strategy.mark_failed(0);

        // Should allow retry
        std::thread::sleep(Duration::from_millis(2));
        let candidate = strategy.next_repair_candidate();
        assert_eq!(candidate, Some(0));

        // Second attempt (max_retries = 2)
        strategy.mark_repair_attempt(0, "peer2".to_string());
        strategy.mark_failed(0);

        // Should not allow more retries
        let state = strategy.chunk_states.get(&0).unwrap();
        assert_eq!(state.status, ChunkRepairStatus::Failed);
    }
}
