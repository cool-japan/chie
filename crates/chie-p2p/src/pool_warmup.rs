// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection pool warmup for reducing startup latency
//!
//! This module provides connection pool warmup functionality to pre-establish
//! connections to known peers on startup, reducing first-request latency.
//!
//! # Features
//!
//! - Parallel connection warmup with configurable concurrency
//! - Priority-based warmup ordering
//! - Timeout and failure handling
//! - Progress tracking and reporting
//! - Selective warmup based on peer importance
//! - Staged warmup (critical first, then others)
//!
//! # Example
//!
//! ```
//! use chie_p2p::pool_warmup::{PoolWarmup, WarmupConfig, WarmupPeer, WarmupPriority};
//! use std::time::Duration;
//!
//! let config = WarmupConfig {
//!     max_concurrent: 10,
//!     connection_timeout: Duration::from_secs(5),
//!     enable_staged_warmup: true,
//!     ..Default::default()
//! };
//!
//! let mut warmup = PoolWarmup::new(config);
//!
//! // Add peers to warm up
//! warmup.add_peer(WarmupPeer {
//!     peer_id: "peer1".to_string(),
//!     priority: WarmupPriority::Critical,
//!     expected_latency: Some(Duration::from_millis(50)),
//! });
//!
//! // Get next batch of peers to warm up
//! let batch = warmup.next_batch(5);
//! ```

use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

/// Configuration for pool warmup
#[derive(Debug, Clone)]
pub struct WarmupConfig {
    /// Maximum concurrent warmup connections
    pub max_concurrent: usize,
    /// Timeout for individual connection attempts
    pub connection_timeout: Duration,
    /// Enable staged warmup (critical first, then high, etc.)
    pub enable_staged_warmup: bool,
    /// Minimum priority level to warm up
    pub min_priority: WarmupPriority,
    /// Enable retry on failure
    pub enable_retry: bool,
    /// Maximum retry attempts per peer
    pub max_retries: u32,
    /// Delay between stages in staged warmup
    pub stage_delay: Duration,
    /// Maximum total warmup time
    pub max_warmup_time: Duration,
}

impl Default for WarmupConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 20,
            connection_timeout: Duration::from_secs(5),
            enable_staged_warmup: true,
            min_priority: WarmupPriority::Low,
            enable_retry: true,
            max_retries: 2,
            stage_delay: Duration::from_millis(100),
            max_warmup_time: Duration::from_secs(30),
        }
    }
}

/// Priority level for warmup
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum WarmupPriority {
    /// Low priority (least important)
    Low = 1,
    /// Normal priority
    #[default]
    Normal = 2,
    /// High priority
    High = 3,
    /// Critical priority (bootstrap nodes, essential peers)
    Critical = 4,
}

/// Peer to warm up
#[derive(Debug, Clone)]
pub struct WarmupPeer {
    /// Peer ID
    pub peer_id: String,
    /// Warmup priority
    pub priority: WarmupPriority,
    /// Expected connection latency (for ordering within same priority)
    pub expected_latency: Option<Duration>,
}

impl PartialEq for WarmupPeer {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for WarmupPeer {}

impl PartialOrd for WarmupPeer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WarmupPeer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first (BinaryHeap is max-heap)
        match self.priority.cmp(&other.priority) {
            std::cmp::Ordering::Equal => {
                // Within same priority, lower latency first
                match (self.expected_latency, other.expected_latency) {
                    (Some(a), Some(b)) => b.cmp(&a), // Reverse for min-heap behavior on latency
                    (Some(_), None) => std::cmp::Ordering::Greater, // Has latency is better (larger)
                    (None, Some(_)) => std::cmp::Ordering::Less,    // No latency is worse (smaller)
                    (None, None) => std::cmp::Ordering::Equal,
                }
            }
            ord => ord,
        }
    }
}

/// Warmup result for a peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarmupResult {
    /// Successfully warmed up
    Success,
    /// Failed to warm up
    Failed,
    /// Timed out
    Timeout,
    /// In progress
    InProgress,
    /// Not started
    Pending,
}

/// Warmup statistics
#[derive(Debug, Clone, Default)]
pub struct WarmupStats {
    /// Total peers to warm up
    pub total_peers: usize,
    /// Successfully warmed up
    pub successful: usize,
    /// Failed warmup
    pub failed: usize,
    /// Timed out
    pub timed_out: usize,
    /// In progress
    pub in_progress: usize,
    /// Pending
    pub pending: usize,
    /// Total warmup time
    pub total_time: Duration,
    /// Average warmup time per peer
    pub avg_warmup_time: Duration,
    /// Current stage (if staged warmup)
    pub current_stage: Option<WarmupPriority>,
}

/// Warmup record for tracking
#[derive(Debug, Clone)]
struct WarmupRecord {
    peer: WarmupPeer,
    result: WarmupResult,
    attempts: u32,
    start_time: Option<Instant>,
    end_time: Option<Instant>,
}

/// Connection pool warmup manager
#[derive(Debug)]
pub struct PoolWarmup {
    config: WarmupConfig,
    /// Priority queue of peers to warm up
    queue: BinaryHeap<WarmupPeer>,
    /// Warmup records
    records: HashMap<String, WarmupRecord>,
    /// Currently in progress peers
    in_progress: HashMap<String, Instant>,
    /// Start time of warmup
    start_time: Option<Instant>,
    /// Current stage
    current_stage: Option<WarmupPriority>,
    /// Stage completion times
    stage_times: HashMap<WarmupPriority, Duration>,
}

impl PoolWarmup {
    /// Create a new pool warmup manager
    pub fn new(config: WarmupConfig) -> Self {
        Self {
            config,
            queue: BinaryHeap::new(),
            records: HashMap::new(),
            in_progress: HashMap::new(),
            start_time: None,
            current_stage: None,
            stage_times: HashMap::new(),
        }
    }

    /// Add a peer to warm up
    pub fn add_peer(&mut self, peer: WarmupPeer) {
        if peer.priority >= self.config.min_priority {
            let peer_id = peer.peer_id.clone();

            self.queue.push(peer.clone());
            self.records.insert(
                peer_id,
                WarmupRecord {
                    peer,
                    result: WarmupResult::Pending,
                    attempts: 0,
                    start_time: None,
                    end_time: None,
                },
            );
        }
    }

    /// Add multiple peers
    pub fn add_peers(&mut self, peers: Vec<WarmupPeer>) {
        for peer in peers {
            self.add_peer(peer);
        }
    }

    /// Start warmup process
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());

        if self.config.enable_staged_warmup {
            self.current_stage = Some(WarmupPriority::Critical);
        }
    }

    /// Get next batch of peers to warm up
    pub fn next_batch(&mut self, size: usize) -> Vec<WarmupPeer> {
        let mut batch = Vec::new();

        // Check if we should move to next stage
        if self.config.enable_staged_warmup {
            if let Some(current_stage) = self.current_stage {
                let stage_peers: Vec<_> = self
                    .records
                    .values()
                    .filter(|r| {
                        r.peer.priority == current_stage && r.result == WarmupResult::Pending
                    })
                    .collect();

                // If no more peers in current stage, move to next
                if stage_peers.is_empty() {
                    self.advance_stage();
                }
            }
        }

        while batch.len() < size && !self.queue.is_empty() {
            if let Some(peer) = self.queue.pop() {
                // Check if peer should be warmed up in current stage
                if self.should_warmup_peer(&peer) {
                    let peer_id = peer.peer_id.clone();

                    // Mark as in progress
                    if let Some(record) = self.records.get_mut(&peer_id) {
                        record.result = WarmupResult::InProgress;
                        record.start_time = Some(Instant::now());
                        record.attempts += 1;
                    }

                    self.in_progress.insert(peer_id, Instant::now());
                    batch.push(peer);
                } else {
                    // Put back in queue for later
                    self.queue.push(peer);
                    break; // Don't process more if staged
                }
            }
        }

        batch
    }

    /// Check if a peer should be warmed up now
    fn should_warmup_peer(&self, peer: &WarmupPeer) -> bool {
        if !self.config.enable_staged_warmup {
            return true;
        }

        if let Some(current_stage) = self.current_stage {
            peer.priority == current_stage
        } else {
            true
        }
    }

    /// Advance to next stage
    fn advance_stage(&mut self) {
        if let Some(current) = self.current_stage {
            // Record stage completion time
            if let Some(start) = self.start_time {
                self.stage_times.insert(current, start.elapsed());
            }

            // Move to next stage
            self.current_stage = match current {
                WarmupPriority::Critical => Some(WarmupPriority::High),
                WarmupPriority::High => Some(WarmupPriority::Normal),
                WarmupPriority::Normal => Some(WarmupPriority::Low),
                WarmupPriority::Low => None,
            };
        }
    }

    /// Record warmup result
    pub fn record_result(&mut self, peer_id: &str, result: WarmupResult) {
        self.in_progress.remove(peer_id);

        if let Some(record) = self.records.get_mut(peer_id) {
            record.result = result.clone();
            record.end_time = Some(Instant::now());

            // Retry on failure if enabled
            if self.config.enable_retry
                && matches!(result, WarmupResult::Failed | WarmupResult::Timeout)
                && record.attempts < self.config.max_retries
            {
                // Re-add to queue for retry
                self.queue.push(record.peer.clone());
                record.result = WarmupResult::Pending;
                record.end_time = None;
            }
        }
    }

    /// Check if warmup is complete
    pub fn is_complete(&self) -> bool {
        self.queue.is_empty() && self.in_progress.is_empty()
    }

    /// Check if warmup has timed out
    pub fn is_timed_out(&self) -> bool {
        if let Some(start) = self.start_time {
            start.elapsed() > self.config.max_warmup_time
        } else {
            false
        }
    }

    /// Get warmup result for a peer
    pub fn get_result(&self, peer_id: &str) -> Option<WarmupResult> {
        self.records.get(peer_id).map(|r| r.result.clone())
    }

    /// Get warmup statistics
    pub fn stats(&self) -> WarmupStats {
        let total_peers = self.records.len();
        let successful = self
            .records
            .values()
            .filter(|r| r.result == WarmupResult::Success)
            .count();
        let failed = self
            .records
            .values()
            .filter(|r| r.result == WarmupResult::Failed)
            .count();
        let timed_out = self
            .records
            .values()
            .filter(|r| r.result == WarmupResult::Timeout)
            .count();
        let in_progress = self
            .records
            .values()
            .filter(|r| r.result == WarmupResult::InProgress)
            .count();
        let pending = self
            .records
            .values()
            .filter(|r| r.result == WarmupResult::Pending)
            .count();

        let total_time = self.start_time.map(|t| t.elapsed()).unwrap_or_default();

        let completed_peers: Vec<_> = self
            .records
            .values()
            .filter(|r| r.start_time.is_some() && r.end_time.is_some())
            .collect();

        let avg_warmup_time = if !completed_peers.is_empty() {
            let total_duration: Duration = completed_peers
                .iter()
                .filter_map(|r| {
                    r.start_time
                        .and_then(|start| r.end_time.map(|end| end.duration_since(start)))
                })
                .sum();

            total_duration / completed_peers.len() as u32
        } else {
            Duration::ZERO
        };

        WarmupStats {
            total_peers,
            successful,
            failed,
            timed_out,
            in_progress,
            pending,
            total_time,
            avg_warmup_time,
            current_stage: self.current_stage,
        }
    }

    /// Get peers that failed warmup
    pub fn failed_peers(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, r)| r.result == WarmupResult::Failed)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get peers that timed out
    pub fn timed_out_peers(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, r)| r.result == WarmupResult::Timeout)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Cancel warmup
    pub fn cancel(&mut self) {
        self.queue.clear();
        self.in_progress.clear();

        for record in self.records.values_mut() {
            if record.result == WarmupResult::InProgress {
                record.result = WarmupResult::Failed;
                record.end_time = Some(Instant::now());
            }
        }
    }

    /// Get current stage
    pub fn current_stage(&self) -> Option<WarmupPriority> {
        self.current_stage
    }

    /// Get stage completion time
    pub fn stage_time(&self, stage: WarmupPriority) -> Option<Duration> {
        self.stage_times.get(&stage).copied()
    }

    /// Check timeouts and mark timed out peers
    pub fn check_timeouts(&mut self) {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (peer_id, start_time) in &self.in_progress {
            if now.duration_since(*start_time) > self.config.connection_timeout {
                timed_out.push(peer_id.clone());
            }
        }

        for peer_id in timed_out {
            self.record_result(&peer_id, WarmupResult::Timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_pool_warmup() {
        let config = WarmupConfig::default();
        let warmup = PoolWarmup::new(config);

        assert!(warmup.is_complete());
        assert!(!warmup.is_timed_out());
    }

    #[test]
    fn test_add_peer() {
        let mut warmup = PoolWarmup::new(WarmupConfig::default());

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        let stats = warmup.stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.pending, 1);
    }

    #[test]
    fn test_priority_ordering() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Low,
            expected_latency: None,
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer2".to_string(),
            priority: WarmupPriority::Critical,
            expected_latency: None,
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer3".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();

        let batch = warmup.next_batch(3);
        assert_eq!(batch[0].peer_id, "peer2"); // Critical first
        assert_eq!(batch[1].peer_id, "peer3"); // Normal second
        assert_eq!(batch[2].peer_id, "peer1"); // Low last
    }

    #[test]
    fn test_staged_warmup() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: true,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Critical,
            expected_latency: None,
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer2".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();

        // First batch should only return critical
        let batch1 = warmup.next_batch(10);
        assert_eq!(batch1.len(), 1);
        assert_eq!(batch1[0].priority, WarmupPriority::Critical);

        // Mark critical as done
        warmup.record_result("peer1", WarmupResult::Success);

        // Next batch should move to next stage
        let batch2 = warmup.next_batch(10);
        assert!(batch2.is_empty() || batch2[0].priority != WarmupPriority::Critical);
    }

    #[test]
    fn test_record_result() {
        let mut warmup = PoolWarmup::new(WarmupConfig::default());

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(1);

        warmup.record_result("peer1", WarmupResult::Success);

        let result = warmup.get_result("peer1");
        assert_eq!(result, Some(WarmupResult::Success));

        let stats = warmup.stats();
        assert_eq!(stats.successful, 1);
    }

    #[test]
    fn test_retry_on_failure() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_retry: true,
            max_retries: 2,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(1);

        // First attempt fails
        warmup.record_result("peer1", WarmupResult::Failed);

        // Should be back in queue for retry
        let batch = warmup.next_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].peer_id, "peer1");
    }

    #[test]
    fn test_max_retries() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_retry: true,
            max_retries: 2,
            enable_staged_warmup: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();

        // Attempt 1
        warmup.next_batch(1);
        warmup.record_result("peer1", WarmupResult::Failed);

        // Attempt 2
        warmup.next_batch(1);
        warmup.record_result("peer1", WarmupResult::Failed);

        // Should be marked as failed now (hit max retries)
        assert_eq!(warmup.get_result("peer1"), Some(WarmupResult::Failed));
    }

    #[test]
    fn test_is_complete() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: false,
            ..Default::default()
        });

        assert!(warmup.is_complete());

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        assert!(!warmup.is_complete());

        warmup.start();
        warmup.next_batch(1);
        warmup.record_result("peer1", WarmupResult::Success);

        assert!(warmup.is_complete());
    }

    #[test]
    fn test_timeout_detection() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            connection_timeout: Duration::from_millis(50),
            enable_staged_warmup: false,
            enable_retry: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(1);

        thread::sleep(Duration::from_millis(60));
        warmup.check_timeouts();

        assert_eq!(warmup.get_result("peer1"), Some(WarmupResult::Timeout));
    }

    #[test]
    fn test_failed_peers() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_retry: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer2".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(2);
        warmup.record_result("peer1", WarmupResult::Failed);
        warmup.record_result("peer2", WarmupResult::Success);

        let failed = warmup.failed_peers();
        assert_eq!(failed.len(), 1);
        assert!(failed.contains(&"peer1".to_string()));
    }

    #[test]
    fn test_cancel() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(1);

        assert!(!warmup.is_complete());

        warmup.cancel();

        assert!(warmup.is_complete());
        assert_eq!(warmup.get_result("peer1"), Some(WarmupResult::Failed));
    }

    #[test]
    fn test_stats() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: false,
            enable_retry: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer2".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: None,
        });

        warmup.start();
        warmup.next_batch(2);
        warmup.record_result("peer1", WarmupResult::Success);
        warmup.record_result("peer2", WarmupResult::Failed);

        let stats = warmup.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_latency_ordering() {
        let mut warmup = PoolWarmup::new(WarmupConfig {
            enable_staged_warmup: false,
            ..Default::default()
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer1".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: Some(Duration::from_millis(100)),
        });

        warmup.add_peer(WarmupPeer {
            peer_id: "peer2".to_string(),
            priority: WarmupPriority::Normal,
            expected_latency: Some(Duration::from_millis(50)),
        });

        warmup.start();

        let batch = warmup.next_batch(2);
        // Lower latency should come first within same priority
        assert_eq!(batch[0].peer_id, "peer2");
        assert_eq!(batch[1].peer_id, "peer1");
    }
}
