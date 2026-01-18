// SPDX-License-Identifier: MIT OR Apache-2.0
//! Automatic peer reconnection with exponential backoff
//!
//! This module provides automatic reconnection logic for peers that become
//! disconnected, using exponential backoff to prevent overwhelming the network.
//!
//! # Features
//!
//! - Exponential backoff with configurable multiplier
//! - Jitter to avoid thundering herd
//! - Maximum retry attempts with permanent failure detection
//! - Connection attempt history tracking
//! - Priority-based reconnection queue
//! - Configurable backoff limits
//!
//! # Example
//!
//! ```
//! use chie_p2p::peer_reconnect::{ReconnectionManager, ReconnectionConfig};
//! use std::time::Duration;
//!
//! let config = ReconnectionConfig {
//!     initial_backoff: Duration::from_secs(1),
//!     max_backoff: Duration::from_secs(300),
//!     backoff_multiplier: 2.0,
//!     max_attempts: 10,
//!     ..Default::default()
//! };
//!
//! let mut manager = ReconnectionManager::new(config);
//!
//! // Register a disconnected peer
//! manager.register_disconnection("peer1");
//!
//! // Check if we should retry
//! if manager.should_reconnect("peer1") {
//!     // Attempt reconnection
//!     // ...
//!     manager.record_attempt("peer1", true);
//! }
//! ```

use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

/// Configuration for reconnection manager
#[derive(Debug, Clone)]
pub struct ReconnectionConfig {
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential growth factor)
    pub backoff_multiplier: f64,
    /// Maximum number of reconnection attempts
    pub max_attempts: u32,
    /// Enable jitter to avoid thundering herd
    pub enable_jitter: bool,
    /// Maximum jitter as fraction of backoff (0.0-1.0)
    pub jitter_factor: f64,
    /// Grace period before first reconnection attempt
    pub grace_period: Duration,
    /// Enable priority-based reconnection
    pub enable_priority: bool,
}

impl Default for ReconnectionConfig {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(300), // 5 minutes
            backoff_multiplier: 2.0,
            max_attempts: 10,
            enable_jitter: true,
            jitter_factor: 0.2, // 20% jitter
            grace_period: Duration::from_millis(100),
            enable_priority: true,
        }
    }
}

/// Priority level for reconnection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ReconnectPriority {
    /// Low priority (least important)
    Low = 1,
    /// Normal priority
    #[default]
    Normal = 2,
    /// High priority
    High = 3,
    /// Critical priority (most important)
    Critical = 4,
}

/// State of reconnection attempts for a peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectionState {
    /// Waiting for reconnection
    Waiting,
    /// Currently attempting to reconnect
    Attempting,
    /// Successfully reconnected
    Connected,
    /// Permanently failed (max attempts reached)
    Failed,
}

/// Reconnection attempt record
#[derive(Debug, Clone)]
struct ReconnectionRecord {
    peer_id: String,
    attempts: u32,
    last_attempt: Option<Instant>,
    next_attempt: Instant,
    state: ReconnectionState,
    priority: ReconnectPriority,
    disconnection_time: Instant,
}

impl PartialEq for ReconnectionRecord {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for ReconnectionRecord {}

impl PartialOrd for ReconnectionRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReconnectionRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Priority first (higher priority first in max-heap)
        match self.priority.cmp(&other.priority) {
            std::cmp::Ordering::Equal => {
                // Then by next attempt time (earlier first = reverse order for max-heap)
                other.next_attempt.cmp(&self.next_attempt)
            }
            ord => ord,
        }
    }
}

/// Statistics for reconnection manager
#[derive(Debug, Clone, Default)]
pub struct ReconnectionStats {
    /// Total peers being tracked
    pub total_peers: usize,
    /// Peers waiting for reconnection
    pub waiting: usize,
    /// Peers currently attempting reconnection
    pub attempting: usize,
    /// Successfully reconnected peers
    pub connected: usize,
    /// Permanently failed peers
    pub failed: usize,
    /// Total reconnection attempts
    pub total_attempts: u64,
    /// Successful reconnections
    pub successful_reconnections: u64,
    /// Failed reconnections
    pub failed_reconnections: u64,
    /// Average attempts before success
    pub avg_attempts_to_success: f64,
}

/// Automatic peer reconnection manager
#[derive(Debug)]
pub struct ReconnectionManager {
    config: ReconnectionConfig,
    /// Peer reconnection records indexed by peer ID
    records: HashMap<String, ReconnectionRecord>,
    /// Priority queue for reconnection scheduling
    queue: BinaryHeap<ReconnectionRecord>,
    /// Statistics
    stats: ReconnectionStats,
}

impl ReconnectionManager {
    /// Create a new reconnection manager
    pub fn new(config: ReconnectionConfig) -> Self {
        Self {
            config,
            records: HashMap::new(),
            queue: BinaryHeap::new(),
            stats: ReconnectionStats::default(),
        }
    }

    /// Register a peer disconnection
    pub fn register_disconnection(&mut self, peer_id: impl Into<String>) {
        self.register_disconnection_with_priority(peer_id, ReconnectPriority::default());
    }

    /// Register a peer disconnection with priority
    pub fn register_disconnection_with_priority(
        &mut self,
        peer_id: impl Into<String>,
        priority: ReconnectPriority,
    ) {
        let peer_id = peer_id.into();

        // Remove from queue if already present
        if self.records.contains_key(&peer_id) {
            return; // Already tracking
        }

        let now = Instant::now();
        let record = ReconnectionRecord {
            peer_id: peer_id.clone(),
            attempts: 0,
            last_attempt: None,
            next_attempt: now + self.config.grace_period,
            state: ReconnectionState::Waiting,
            priority,
            disconnection_time: now,
        };

        self.records.insert(peer_id, record.clone());
        self.queue.push(record);
        self.update_stats();
    }

    /// Check if we should attempt reconnection to a peer
    pub fn should_reconnect(&self, peer_id: &str) -> bool {
        if let Some(record) = self.records.get(peer_id) {
            record.next_attempt <= Instant::now()
                && record.state == ReconnectionState::Waiting
                && record.attempts < self.config.max_attempts
        } else {
            false
        }
    }

    /// Get next peer that should be reconnected
    pub fn next_reconnection(&mut self) -> Option<String> {
        let now = Instant::now();

        while let Some(record) = self.queue.pop() {
            if let Some(stored) = self.records.get_mut(&record.peer_id) {
                if stored.next_attempt <= now
                    && stored.state == ReconnectionState::Waiting
                    && stored.attempts < self.config.max_attempts
                {
                    stored.state = ReconnectionState::Attempting;
                    self.update_stats();
                    return Some(record.peer_id);
                }
            }
        }

        None
    }

    /// Record a reconnection attempt
    pub fn record_attempt(&mut self, peer_id: &str, success: bool) {
        // Get attempts count and calculate backoff first
        let (attempts, should_retry) = if let Some(record) = self.records.get(peer_id) {
            (
                record.attempts + 1,
                record.attempts + 1 < self.config.max_attempts,
            )
        } else {
            return;
        };

        let backoff = if !success && should_retry {
            self.calculate_backoff(attempts)
        } else {
            Duration::ZERO
        };

        // Now mutate the record
        if let Some(record) = self.records.get_mut(peer_id) {
            record.attempts = attempts;
            record.last_attempt = Some(Instant::now());
            self.stats.total_attempts += 1;

            if success {
                record.state = ReconnectionState::Connected;
                self.stats.successful_reconnections += 1;
            } else {
                self.stats.failed_reconnections += 1;

                if !should_retry {
                    record.state = ReconnectionState::Failed;
                } else {
                    // Calculate next attempt with backoff
                    record.next_attempt = Instant::now() + backoff;
                    record.state = ReconnectionState::Waiting;

                    // Re-add to queue
                    self.queue.push(record.clone());
                }
            }

            self.update_stats();
        }
    }

    /// Calculate backoff duration with exponential growth and jitter
    fn calculate_backoff(&self, attempts: u32) -> Duration {
        let base_backoff = self.config.initial_backoff.as_secs_f64()
            * self.config.backoff_multiplier.powi(attempts as i32);

        let backoff = base_backoff.min(self.config.max_backoff.as_secs_f64());

        if self.config.enable_jitter {
            let jitter = backoff * self.config.jitter_factor;
            let random_jitter = rand::random::<f64>() * jitter * 2.0 - jitter;
            Duration::from_secs_f64((backoff + random_jitter).max(0.0))
        } else {
            Duration::from_secs_f64(backoff)
        }
    }

    /// Remove a peer from reconnection tracking (e.g., peer no longer needed)
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.records.remove(peer_id);
        // Note: Queue cleanup happens naturally as we process items
        self.update_stats();
    }

    /// Mark a peer as successfully connected
    pub fn mark_connected(&mut self, peer_id: &str) {
        if let Some(record) = self.records.get_mut(peer_id) {
            record.state = ReconnectionState::Connected;
            self.stats.successful_reconnections += 1;
            self.update_stats();
        }
    }

    /// Get reconnection state for a peer
    pub fn get_state(&self, peer_id: &str) -> Option<ReconnectionState> {
        self.records.get(peer_id).map(|r| r.state.clone())
    }

    /// Get number of attempts for a peer
    pub fn get_attempts(&self, peer_id: &str) -> u32 {
        self.records.get(peer_id).map(|r| r.attempts).unwrap_or(0)
    }

    /// Get time until next reconnection attempt for a peer
    pub fn time_until_next_attempt(&self, peer_id: &str) -> Option<Duration> {
        self.records.get(peer_id).map(|r| {
            let now = Instant::now();
            if r.next_attempt > now {
                r.next_attempt.duration_since(now)
            } else {
                Duration::ZERO
            }
        })
    }

    /// Get time since disconnection
    pub fn time_since_disconnection(&self, peer_id: &str) -> Option<Duration> {
        self.records
            .get(peer_id)
            .map(|r| r.disconnection_time.elapsed())
    }

    /// Get all peers in a given state
    pub fn peers_in_state(&self, state: ReconnectionState) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, r)| r.state == state)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get all failed peers (max attempts reached)
    pub fn failed_peers(&self) -> Vec<String> {
        self.peers_in_state(ReconnectionState::Failed)
    }

    /// Clear all reconnection records
    pub fn clear(&mut self) {
        self.records.clear();
        self.queue.clear();
        self.update_stats();
    }

    /// Get statistics
    pub fn stats(&self) -> &ReconnectionStats {
        &self.stats
    }

    /// Update statistics
    fn update_stats(&mut self) {
        self.stats.total_peers = self.records.len();
        self.stats.waiting = self
            .records
            .values()
            .filter(|r| r.state == ReconnectionState::Waiting)
            .count();
        self.stats.attempting = self
            .records
            .values()
            .filter(|r| r.state == ReconnectionState::Attempting)
            .count();
        self.stats.connected = self
            .records
            .values()
            .filter(|r| r.state == ReconnectionState::Connected)
            .count();
        self.stats.failed = self
            .records
            .values()
            .filter(|r| r.state == ReconnectionState::Failed)
            .count();

        // Calculate average attempts to success
        let successful_peers: Vec<_> = self
            .records
            .values()
            .filter(|r| r.state == ReconnectionState::Connected)
            .collect();

        if !successful_peers.is_empty() {
            let total_attempts: u32 = successful_peers.iter().map(|r| r.attempts).sum();
            self.stats.avg_attempts_to_success =
                total_attempts as f64 / successful_peers.len() as f64;
        }
    }

    /// Get priority of a peer
    pub fn get_priority(&self, peer_id: &str) -> Option<ReconnectPriority> {
        self.records.get(peer_id).map(|r| r.priority)
    }

    /// Update priority of a peer
    pub fn set_priority(&mut self, peer_id: &str, priority: ReconnectPriority) {
        if let Some(record) = self.records.get_mut(peer_id) {
            record.priority = priority;
            // Re-add to queue with new priority if waiting
            if record.state == ReconnectionState::Waiting {
                self.queue.push(record.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_reconnection_manager() {
        let config = ReconnectionConfig::default();
        let manager = ReconnectionManager::new(config);

        assert_eq!(manager.stats().total_peers, 0);
        assert_eq!(manager.stats().waiting, 0);
    }

    #[test]
    fn test_register_disconnection() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        assert_eq!(manager.stats().total_peers, 1);
        assert_eq!(manager.stats().waiting, 1);

        assert_eq!(manager.get_state("peer1"), Some(ReconnectionState::Waiting));
    }

    #[test]
    fn test_should_reconnect() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::from_millis(50),
            ..Default::default()
        });

        manager.register_disconnection("peer1");
        assert!(!manager.should_reconnect("peer1")); // Grace period

        thread::sleep(Duration::from_millis(60));
        assert!(manager.should_reconnect("peer1"));
    }

    #[test]
    fn test_record_successful_attempt() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            ..Default::default()
        });

        manager.register_disconnection("peer1");
        manager.record_attempt("peer1", true);

        assert_eq!(
            manager.get_state("peer1"),
            Some(ReconnectionState::Connected)
        );
        assert_eq!(manager.stats().successful_reconnections, 1);
        assert_eq!(manager.get_attempts("peer1"), 1);
    }

    #[test]
    fn test_record_failed_attempt() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            ..Default::default()
        });

        manager.register_disconnection("peer1");
        manager.record_attempt("peer1", false);

        assert_eq!(manager.get_state("peer1"), Some(ReconnectionState::Waiting));
        assert_eq!(manager.stats().failed_reconnections, 1);
        assert_eq!(manager.get_attempts("peer1"), 1);
    }

    #[test]
    fn test_max_attempts() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            max_attempts: 3,
            ..Default::default()
        });

        manager.register_disconnection("peer1");

        // Fail 3 times
        for _ in 0..3 {
            manager.record_attempt("peer1", false);
        }

        assert_eq!(manager.get_state("peer1"), Some(ReconnectionState::Failed));
        assert_eq!(manager.stats().failed, 1);
    }

    #[test]
    fn test_backoff_calculation() {
        let manager = ReconnectionManager::new(ReconnectionConfig {
            initial_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            max_backoff: Duration::from_secs(60),
            enable_jitter: false,
            ..Default::default()
        });

        let backoff1 = manager.calculate_backoff(0);
        assert_eq!(backoff1.as_secs(), 1);

        let backoff2 = manager.calculate_backoff(1);
        assert_eq!(backoff2.as_secs(), 2);

        let backoff3 = manager.calculate_backoff(2);
        assert_eq!(backoff3.as_secs(), 4);

        // Test max backoff
        let backoff_max = manager.calculate_backoff(10);
        assert_eq!(backoff_max.as_secs(), 60);
    }

    #[test]
    fn test_next_reconnection() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            ..Default::default()
        });

        manager.register_disconnection("peer1");
        manager.register_disconnection("peer2");

        let next = manager.next_reconnection();
        assert!(next.is_some());
        let peer_id = next.unwrap();
        assert!(peer_id == "peer1" || peer_id == "peer2");

        assert_eq!(
            manager.get_state(&peer_id),
            Some(ReconnectionState::Attempting)
        );
    }

    #[test]
    fn test_priority_ordering() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            ..Default::default()
        });

        manager.register_disconnection_with_priority("peer1", ReconnectPriority::Low);
        manager.register_disconnection_with_priority("peer2", ReconnectPriority::Critical);
        manager.register_disconnection_with_priority("peer3", ReconnectPriority::Normal);

        // Critical should come first
        let next1 = manager.next_reconnection();
        assert_eq!(next1, Some("peer2".to_string()));

        // Then normal
        let next2 = manager.next_reconnection();
        assert_eq!(next2, Some("peer3".to_string()));

        // Then low
        let next3 = manager.next_reconnection();
        assert_eq!(next3, Some("peer1".to_string()));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        assert_eq!(manager.stats().total_peers, 1);

        manager.remove_peer("peer1");
        assert_eq!(manager.stats().total_peers, 0);
    }

    #[test]
    fn test_mark_connected() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        manager.mark_connected("peer1");

        assert_eq!(
            manager.get_state("peer1"),
            Some(ReconnectionState::Connected)
        );
        assert_eq!(manager.stats().connected, 1);
    }

    #[test]
    fn test_time_since_disconnection() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        thread::sleep(Duration::from_millis(50));

        let elapsed = manager.time_since_disconnection("peer1");
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() >= Duration::from_millis(50));
    }

    #[test]
    fn test_peers_in_state() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        manager.register_disconnection("peer2");
        manager.mark_connected("peer2");

        let waiting = manager.peers_in_state(ReconnectionState::Waiting);
        assert_eq!(waiting.len(), 1);
        assert!(waiting.contains(&"peer1".to_string()));

        let connected = manager.peers_in_state(ReconnectionState::Connected);
        assert_eq!(connected.len(), 1);
        assert!(connected.contains(&"peer2".to_string()));
    }

    #[test]
    fn test_failed_peers() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            max_attempts: 2,
            ..Default::default()
        });

        manager.register_disconnection("peer1");

        for _ in 0..2 {
            manager.record_attempt("peer1", false);
        }

        let failed = manager.failed_peers();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], "peer1");
    }

    #[test]
    fn test_clear() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection("peer1");
        manager.register_disconnection("peer2");
        assert_eq!(manager.stats().total_peers, 2);

        manager.clear();
        assert_eq!(manager.stats().total_peers, 0);
    }

    #[test]
    fn test_avg_attempts_to_success() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::ZERO,
            ..Default::default()
        });

        manager.register_disconnection("peer1");
        manager.record_attempt("peer1", false);
        manager.record_attempt("peer1", true);

        manager.register_disconnection("peer2");
        manager.record_attempt("peer2", false);
        manager.record_attempt("peer2", false);
        manager.record_attempt("peer2", true);

        // peer1: 2 attempts, peer2: 3 attempts, avg = 2.5
        assert_eq!(manager.stats().avg_attempts_to_success, 2.5);
    }

    #[test]
    fn test_set_priority() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig::default());

        manager.register_disconnection_with_priority("peer1", ReconnectPriority::Low);
        assert_eq!(manager.get_priority("peer1"), Some(ReconnectPriority::Low));

        manager.set_priority("peer1", ReconnectPriority::Critical);
        assert_eq!(
            manager.get_priority("peer1"),
            Some(ReconnectPriority::Critical)
        );
    }

    #[test]
    fn test_time_until_next_attempt() {
        let mut manager = ReconnectionManager::new(ReconnectionConfig {
            grace_period: Duration::from_secs(10),
            ..Default::default()
        });

        manager.register_disconnection("peer1");

        let time_until = manager.time_until_next_attempt("peer1");
        assert!(time_until.is_some());
        assert!(time_until.unwrap() <= Duration::from_secs(10));
    }
}
