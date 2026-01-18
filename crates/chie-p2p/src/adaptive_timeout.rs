//! Adaptive timeout management for P2P connections.
//!
//! This module provides dynamic timeout adjustment based on network conditions,
//! historical performance, and peer quality. It helps maintain optimal connection
//! timeouts that adapt to varying network conditions.
//!
//! # Features
//!
//! - **Dynamic Adjustment**: Automatically adjusts timeouts based on observed latencies
//! - **Peer-specific Timeouts**: Maintains individual timeouts for each peer
//! - **Network Condition Awareness**: Adapts to current network conditions
//! - **Percentile-based Calculation**: Uses configurable percentiles for robust timeout values
//! - **Bounds Management**: Ensures timeouts stay within reasonable min/max bounds
//! - **Statistics Tracking**: Comprehensive metrics for monitoring and debugging
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::adaptive_timeout::{AdaptiveTimeoutManager, TimeoutConfig};
//! use std::time::Duration;
//!
//! let config = TimeoutConfig {
//!     initial_timeout: Duration::from_secs(5),
//!     min_timeout: Duration::from_secs(1),
//!     max_timeout: Duration::from_secs(30),
//!     target_percentile: 95.0,
//!     adjustment_factor: 1.5,
//!     sample_size: 100,
//! };
//!
//! let manager = AdaptiveTimeoutManager::new(config);
//!
//! // Record observed latencies
//! let peer_id = "peer1".to_string();
//! manager.record_latency(&peer_id, Duration::from_millis(150));
//! manager.record_latency(&peer_id, Duration::from_millis(200));
//!
//! // Get adaptive timeout for the peer
//! let timeout = manager.get_timeout(&peer_id);
//! println!("Adaptive timeout: {:?}", timeout);
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Configuration for adaptive timeout management.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Initial timeout value for new peers
    pub initial_timeout: Duration,
    /// Minimum allowed timeout
    pub min_timeout: Duration,
    /// Maximum allowed timeout
    pub max_timeout: Duration,
    /// Target percentile for timeout calculation (e.g., 95.0 for 95th percentile)
    pub target_percentile: f64,
    /// Adjustment factor for timeout calculation
    pub adjustment_factor: f64,
    /// Number of samples to keep per peer
    pub sample_size: usize,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            initial_timeout: Duration::from_secs(5),
            min_timeout: Duration::from_millis(500),
            max_timeout: Duration::from_secs(30),
            target_percentile: 95.0,
            adjustment_factor: 1.5,
            sample_size: 100,
        }
    }
}

/// Statistics for timeout manager
#[derive(Debug, Clone, Default)]
pub struct TimeoutStats {
    /// Total number of latency recordings
    pub total_recordings: u64,
    /// Number of peers being tracked
    pub tracked_peers: usize,
    /// Number of timeout calculations performed
    pub calculations: u64,
    /// Number of timeout adjustments (increases)
    pub increases: u64,
    /// Number of timeout adjustments (decreases)
    pub decreases: u64,
    /// Average timeout across all peers (milliseconds)
    pub avg_timeout_ms: f64,
    /// Minimum timeout in use (milliseconds)
    pub min_timeout_ms: u64,
    /// Maximum timeout in use (milliseconds)
    pub max_timeout_ms: u64,
}

/// Latency samples for a single peer
#[derive(Debug, Clone)]
struct PeerSamples {
    /// Circular buffer of latency samples
    samples: VecDeque<Duration>,
    /// Current adaptive timeout
    current_timeout: Duration,
    /// Last calculated timeout (for change tracking)
    last_timeout: Duration,
}

impl PeerSamples {
    fn new(initial_timeout: Duration, sample_size: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(sample_size),
            current_timeout: initial_timeout,
            last_timeout: initial_timeout,
        }
    }

    fn add_sample(&mut self, latency: Duration, max_samples: usize) {
        if self.samples.len() >= max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(latency);
    }

    fn calculate_percentile(&self, percentile: f64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }

        let mut sorted: Vec<Duration> = self.samples.iter().copied().collect();
        sorted.sort();

        let index = ((percentile / 100.0) * (sorted.len() as f64 - 1.0)).ceil() as usize;
        Some(sorted[index.min(sorted.len() - 1)])
    }

    fn average(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }

        let sum: Duration = self.samples.iter().sum();
        Some(sum / self.samples.len() as u32)
    }
}

/// Adaptive timeout manager that adjusts timeouts based on network conditions
pub struct AdaptiveTimeoutManager {
    config: TimeoutConfig,
    peers: Arc<RwLock<HashMap<String, PeerSamples>>>,
    stats: Arc<RwLock<TimeoutStats>>,
}

impl AdaptiveTimeoutManager {
    /// Creates a new adaptive timeout manager with the given configuration
    pub fn new(config: TimeoutConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TimeoutStats::default())),
        }
    }

    /// Records a latency observation for a peer
    pub fn record_latency(&self, peer_id: &str, latency: Duration) {
        let mut peers = self.peers.write().unwrap();
        let peer = peers.entry(peer_id.to_string()).or_insert_with(|| {
            PeerSamples::new(self.config.initial_timeout, self.config.sample_size)
        });

        peer.add_sample(latency, self.config.sample_size);

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_recordings += 1;
    }

    /// Gets the current adaptive timeout for a peer
    pub fn get_timeout(&self, peer_id: &str) -> Duration {
        let peers = self.peers.read().unwrap();

        if let Some(peer) = peers.get(peer_id) {
            peer.current_timeout
        } else {
            self.config.initial_timeout
        }
    }

    /// Recalculates timeouts for all peers based on current samples
    pub fn recalculate_timeouts(&self) {
        let mut peers = self.peers.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        let mut total_timeout_ms = 0u64;
        let mut min = u64::MAX;
        let mut max = 0u64;
        let mut increases = 0u64;
        let mut decreases = 0u64;

        for peer in peers.values_mut() {
            peer.last_timeout = peer.current_timeout;

            if let Some(percentile_latency) =
                peer.calculate_percentile(self.config.target_percentile)
            {
                // Calculate new timeout: percentile * adjustment_factor
                let raw_timeout_ms =
                    percentile_latency.as_millis() as f64 * self.config.adjustment_factor;
                let new_timeout = Duration::from_millis(raw_timeout_ms as u64);

                // Clamp to min/max bounds
                peer.current_timeout = new_timeout
                    .max(self.config.min_timeout)
                    .min(self.config.max_timeout);

                // Track increases/decreases
                if peer.current_timeout > peer.last_timeout {
                    increases += 1;
                } else if peer.current_timeout < peer.last_timeout {
                    decreases += 1;
                }
            }

            let timeout_ms = peer.current_timeout.as_millis() as u64;
            total_timeout_ms += timeout_ms;
            min = min.min(timeout_ms);
            max = max.max(timeout_ms);
        }

        stats.calculations += 1;
        stats.tracked_peers = peers.len();
        stats.increases += increases;
        stats.decreases += decreases;

        if !peers.is_empty() {
            stats.avg_timeout_ms = total_timeout_ms as f64 / peers.len() as f64;
            stats.min_timeout_ms = min;
            stats.max_timeout_ms = max;
        }
    }

    /// Recalculates timeout for a specific peer
    pub fn recalculate_peer_timeout(&self, peer_id: &str) -> Option<Duration> {
        let mut peers = self.peers.write().unwrap();

        if let Some(peer) = peers.get_mut(peer_id) {
            peer.last_timeout = peer.current_timeout;

            if let Some(percentile_latency) =
                peer.calculate_percentile(self.config.target_percentile)
            {
                let raw_timeout_ms =
                    percentile_latency.as_millis() as f64 * self.config.adjustment_factor;
                let new_timeout = Duration::from_millis(raw_timeout_ms as u64);

                peer.current_timeout = new_timeout
                    .max(self.config.min_timeout)
                    .min(self.config.max_timeout);

                // Update stats
                let mut stats = self.stats.write().unwrap();
                stats.calculations += 1;

                if peer.current_timeout > peer.last_timeout {
                    stats.increases += 1;
                } else if peer.current_timeout < peer.last_timeout {
                    stats.decreases += 1;
                }

                return Some(peer.current_timeout);
            }
        }

        None
    }

    /// Gets the average latency for a peer
    pub fn get_average_latency(&self, peer_id: &str) -> Option<Duration> {
        let peers = self.peers.read().unwrap();
        peers.get(peer_id).and_then(|p| p.average())
    }

    /// Gets the number of samples collected for a peer
    pub fn get_sample_count(&self, peer_id: &str) -> usize {
        let peers = self.peers.read().unwrap();
        peers.get(peer_id).map(|p| p.samples.len()).unwrap_or(0)
    }

    /// Removes a peer from tracking
    pub fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(peer_id);

        // Update tracked_peers stat
        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = peers.len();
    }

    /// Clears all peer data
    pub fn clear(&self) {
        let mut peers = self.peers.write().unwrap();
        peers.clear();

        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = 0;
    }

    /// Gets current statistics
    pub fn stats(&self) -> TimeoutStats {
        self.stats.read().unwrap().clone()
    }

    /// Gets the configuration
    pub fn config(&self) -> &TimeoutConfig {
        &self.config
    }

    /// Gets all peer IDs currently being tracked
    pub fn tracked_peer_ids(&self) -> Vec<String> {
        let peers = self.peers.read().unwrap();
        peers.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = TimeoutConfig::default();
        assert_eq!(config.initial_timeout, Duration::from_secs(5));
        assert_eq!(config.min_timeout, Duration::from_millis(500));
        assert_eq!(config.max_timeout, Duration::from_secs(30));
        assert_eq!(config.target_percentile, 95.0);
        assert_eq!(config.adjustment_factor, 1.5);
        assert_eq!(config.sample_size, 100);
    }

    #[test]
    fn test_new_manager() {
        let config = TimeoutConfig::default();
        let manager = AdaptiveTimeoutManager::new(config);
        let stats = manager.stats();

        assert_eq!(stats.total_recordings, 0);
        assert_eq!(stats.tracked_peers, 0);
        assert_eq!(stats.calculations, 0);
    }

    #[test]
    fn test_record_latency() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        manager.record_latency("peer1", Duration::from_millis(150));
        manager.record_latency("peer1", Duration::from_millis(200));

        let stats = manager.stats();
        assert_eq!(stats.total_recordings, 3);
        assert_eq!(manager.get_sample_count("peer1"), 3);
    }

    #[test]
    fn test_get_timeout_initial() {
        let config = TimeoutConfig::default();
        let initial = config.initial_timeout;
        let manager = AdaptiveTimeoutManager::new(config);

        // Should return initial timeout for unknown peer
        assert_eq!(manager.get_timeout("unknown"), initial);
    }

    #[test]
    fn test_get_timeout_after_recording() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));

        // Should return initial timeout until recalculation
        let timeout = manager.get_timeout("peer1");
        assert_eq!(timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_recalculate_timeouts() {
        let config = TimeoutConfig {
            initial_timeout: Duration::from_secs(5),
            min_timeout: Duration::from_millis(500),
            max_timeout: Duration::from_secs(30),
            target_percentile: 95.0,
            adjustment_factor: 1.5,
            sample_size: 100,
        };
        let manager = AdaptiveTimeoutManager::new(config);

        // Record several latencies
        for i in 0..10 {
            manager.record_latency("peer1", Duration::from_millis(100 + i * 10));
        }

        manager.recalculate_timeouts();

        let timeout = manager.get_timeout("peer1");
        assert!(timeout > Duration::from_millis(100));
        assert!(timeout < Duration::from_secs(1));

        let stats = manager.stats();
        assert_eq!(stats.calculations, 1);
        assert_eq!(stats.tracked_peers, 1);
    }

    #[test]
    fn test_recalculate_peer_timeout() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        for i in 0..10 {
            manager.record_latency("peer1", Duration::from_millis(100 + i * 10));
        }

        let new_timeout = manager.recalculate_peer_timeout("peer1");
        assert!(new_timeout.is_some());
        assert!(new_timeout.unwrap() > Duration::from_millis(100));
    }

    #[test]
    fn test_timeout_bounds() {
        let config = TimeoutConfig {
            initial_timeout: Duration::from_secs(5),
            min_timeout: Duration::from_secs(1),
            max_timeout: Duration::from_secs(10),
            target_percentile: 95.0,
            adjustment_factor: 1.5,
            sample_size: 100,
        };
        let manager = AdaptiveTimeoutManager::new(config);

        // Record very low latencies (should hit min bound)
        for _ in 0..10 {
            manager.record_latency("peer1", Duration::from_millis(10));
        }
        manager.recalculate_timeouts();
        assert_eq!(manager.get_timeout("peer1"), Duration::from_secs(1));

        // Record very high latencies (should hit max bound)
        for _ in 0..10 {
            manager.record_latency("peer2", Duration::from_secs(20));
        }
        manager.recalculate_timeouts();
        assert_eq!(manager.get_timeout("peer2"), Duration::from_secs(10));
    }

    #[test]
    fn test_get_average_latency() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        manager.record_latency("peer1", Duration::from_millis(200));
        manager.record_latency("peer1", Duration::from_millis(300));

        let avg = manager.get_average_latency("peer1");
        assert!(avg.is_some());
        assert_eq!(avg.unwrap(), Duration::from_millis(200));
    }

    #[test]
    fn test_get_average_latency_unknown_peer() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());
        assert!(manager.get_average_latency("unknown").is_none());
    }

    #[test]
    fn test_remove_peer() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        assert_eq!(manager.get_sample_count("peer1"), 1);

        manager.remove_peer("peer1");
        assert_eq!(manager.get_sample_count("peer1"), 0);

        let stats = manager.stats();
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_clear() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        manager.record_latency("peer2", Duration::from_millis(200));

        manager.clear();

        let stats = manager.stats();
        assert_eq!(stats.tracked_peers, 0);
        assert_eq!(manager.get_sample_count("peer1"), 0);
        assert_eq!(manager.get_sample_count("peer2"), 0);
    }

    #[test]
    fn test_tracked_peer_ids() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        manager.record_latency("peer2", Duration::from_millis(200));

        let mut peer_ids = manager.tracked_peer_ids();
        peer_ids.sort();

        assert_eq!(peer_ids, vec!["peer1", "peer2"]);
    }

    #[test]
    fn test_sample_size_limit() {
        let config = TimeoutConfig {
            sample_size: 5,
            ..Default::default()
        };
        let manager = AdaptiveTimeoutManager::new(config);

        // Record more samples than the limit
        for i in 0..10 {
            manager.record_latency("peer1", Duration::from_millis(100 + i * 10));
        }

        // Should only keep the last 5 samples
        assert_eq!(manager.get_sample_count("peer1"), 5);
    }

    #[test]
    fn test_percentile_calculation() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        // Create a known distribution
        let latencies = vec![100, 150, 200, 250, 300, 350, 400, 450, 500, 1000];
        for latency in latencies {
            manager.record_latency("peer1", Duration::from_millis(latency));
        }

        manager.recalculate_timeouts();

        // 95th percentile should be close to 1000ms * 1.5 = 1500ms
        let timeout = manager.get_timeout("peer1");
        assert!(timeout >= Duration::from_millis(1000));
    }

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(AdaptiveTimeoutManager::new(TimeoutConfig::default()));
        let mut handles = vec![];

        for i in 0..5 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                let peer_id = format!("peer{}", i);
                for j in 0..10 {
                    manager_clone.record_latency(&peer_id, Duration::from_millis(100 + j * 10));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Recalculate to update stats
        manager.recalculate_timeouts();

        let stats = manager.stats();
        assert_eq!(stats.total_recordings, 50);
        assert_eq!(stats.tracked_peers, 5);
    }

    #[test]
    fn test_adjustment_factor_effect() {
        let config1 = TimeoutConfig {
            adjustment_factor: 1.5,
            min_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let config2 = TimeoutConfig {
            adjustment_factor: 3.0,
            min_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_secs(60),
            ..Default::default()
        };

        let manager1 = AdaptiveTimeoutManager::new(config1);
        let manager2 = AdaptiveTimeoutManager::new(config2);

        // Same latencies for both - use values that won't hit bounds
        for i in 0..10 {
            manager1.record_latency("peer1", Duration::from_millis(1000 + i * 100));
            manager2.record_latency("peer1", Duration::from_millis(1000 + i * 100));
        }

        manager1.recalculate_timeouts();
        manager2.recalculate_timeouts();

        let timeout1 = manager1.get_timeout("peer1");
        let timeout2 = manager2.get_timeout("peer1");

        // Manager2 should have roughly 2x the timeout of manager1
        assert!(timeout2 > timeout1);

        // Verify approximate 2x relationship (within reasonable tolerance)
        let ratio = timeout2.as_millis() as f64 / timeout1.as_millis() as f64;
        assert!(ratio > 1.5); // Should be roughly 2x (3.0/1.5)
    }

    #[test]
    fn test_stats_tracking() {
        let manager = AdaptiveTimeoutManager::new(TimeoutConfig::default());

        manager.record_latency("peer1", Duration::from_millis(100));
        manager.record_latency("peer2", Duration::from_millis(500));
        manager.record_latency("peer3", Duration::from_millis(1000));

        manager.recalculate_timeouts();

        let stats = manager.stats();
        assert_eq!(stats.total_recordings, 3);
        assert_eq!(stats.tracked_peers, 3);
        assert_eq!(stats.calculations, 1);
        assert!(stats.avg_timeout_ms > 0.0);
        assert!(stats.min_timeout_ms > 0);
        assert!(stats.max_timeout_ms > 0);
    }
}
