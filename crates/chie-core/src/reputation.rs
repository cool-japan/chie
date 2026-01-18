//! Peer reputation tracking system for network reliability.
//!
//! This module provides a reputation scoring system to track peer reliability,
//! performance, and behavior in the P2P network.
//!
//! # Features
//!
//! - Dynamic reputation scoring based on peer behavior
//! - Decay mechanism for outdated scores
//! - Automatic banning of malicious peers
//! - Performance metrics tracking
//! - Configurable scoring weights
//!
//! # Example
//!
//! ```
//! use chie_core::reputation::{ReputationTracker, ReputationConfig};
//!
//! let config = ReputationConfig::default();
//! let mut tracker = ReputationTracker::new(config);
//!
//! // Record successful interaction
//! tracker.record_success("peer1".to_string(), 100);
//!
//! // Record failure
//! tracker.record_failure("peer2".to_string(), 50);
//!
//! // Check reputation
//! let score = tracker.get_reputation("peer1");
//! println!("Peer1 reputation: {:.2}", score);
//!
//! // Get trusted peers
//! let trusted = tracker.get_trusted_peers(0.7);
//! println!("Trusted peers: {:?}", trusted);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Reputation configuration.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Initial reputation score for new peers.
    pub initial_score: f64,

    /// Minimum reputation score (below this = banned).
    pub min_score: f64,

    /// Maximum reputation score.
    pub max_score: f64,

    /// Reputation decay rate per hour.
    pub decay_rate: f64,

    /// Weight for successful transactions.
    pub success_weight: f64,

    /// Weight for failed transactions.
    pub failure_weight: f64,

    /// Weight for latency (lower latency = higher score).
    pub latency_weight: f64,

    /// Maximum time before reputation decays to initial.
    pub max_decay_duration: Duration,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_score: 0.5,
            min_score: 0.0,
            max_score: 1.0,
            decay_rate: 0.1,
            success_weight: 0.01,
            failure_weight: 0.05,
            latency_weight: 0.001,
            max_decay_duration: Duration::from_secs(7 * 24 * 3600), // 7 days
        }
    }
}

/// Peer reputation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Peer ID.
    pub peer_id: String,

    /// Current reputation score (0.0 to 1.0).
    pub score: f64,

    /// Total successful interactions.
    pub successes: u64,

    /// Total failed interactions.
    pub failures: u64,

    /// Total bytes transferred.
    pub bytes_transferred: u64,

    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,

    /// Last interaction timestamp.
    pub last_seen: SystemTime,

    /// First interaction timestamp.
    pub first_seen: SystemTime,

    /// Is peer banned.
    pub is_banned: bool,
}

impl PeerReputation {
    /// Create a new peer reputation record.
    fn new(peer_id: String, initial_score: f64) -> Self {
        let now = SystemTime::now();
        Self {
            peer_id,
            score: initial_score,
            successes: 0,
            failures: 0,
            bytes_transferred: 0,
            avg_latency_ms: 0.0,
            last_seen: now,
            first_seen: now,
            is_banned: false,
        }
    }

    /// Get success rate.
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            0.0
        } else {
            self.successes as f64 / total as f64
        }
    }

    /// Get total interactions.
    #[must_use]
    #[inline]
    pub const fn total_interactions(&self) -> u64 {
        self.successes + self.failures
    }

    /// Check if peer is trusted (score above threshold).
    #[must_use]
    #[inline]
    pub const fn is_trusted(&self, threshold: f64) -> bool {
        !self.is_banned && self.score >= threshold
    }

    /// Get age in seconds.
    #[must_use]
    #[inline]
    pub fn age_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.first_seen)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    /// Get time since last interaction in seconds.
    #[must_use]
    #[inline]
    pub fn time_since_last_seen(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.last_seen)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }
}

/// Reputation tracker for managing peer reputations.
pub struct ReputationTracker {
    /// Configuration.
    config: ReputationConfig,

    /// Peer reputation records.
    peers: HashMap<String, PeerReputation>,

    /// Last decay timestamp.
    last_decay: SystemTime,
}

impl ReputationTracker {
    /// Create a new reputation tracker.
    #[must_use]
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            last_decay: SystemTime::now(),
        }
    }

    /// Get or create peer reputation.
    fn get_or_create(&mut self, peer_id: String) -> &mut PeerReputation {
        self.peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerReputation::new(peer_id, self.config.initial_score))
    }

    /// Record a successful interaction.
    pub fn record_success(&mut self, peer_id: String, bytes_transferred: u64) {
        let success_weight = self.config.success_weight;
        let max_score = self.config.max_score;

        let peer = self.get_or_create(peer_id);
        peer.successes += 1;
        peer.bytes_transferred += bytes_transferred;
        peer.last_seen = SystemTime::now();

        // Increase reputation
        peer.score = (peer.score + success_weight).min(max_score);
    }

    /// Record a failed interaction.
    pub fn record_failure(&mut self, peer_id: String, penalty: u64) {
        let failure_weight = self.config.failure_weight;
        let min_score = self.config.min_score;

        let peer = self.get_or_create(peer_id);
        peer.failures += 1;
        peer.last_seen = SystemTime::now();

        // Decrease reputation
        let penalty_score = failure_weight * (penalty as f64 / 100.0);
        peer.score = (peer.score - penalty_score).max(min_score);

        // Ban if score too low
        if peer.score <= min_score {
            peer.is_banned = true;
        }
    }

    /// Record latency measurement.
    pub fn record_latency(&mut self, peer_id: String, latency_ms: u64) {
        let latency_weight = self.config.latency_weight;
        let max_score = self.config.max_score;

        let peer = self.get_or_create(peer_id);

        // Update moving average
        let alpha = 0.3; // Smoothing factor
        peer.avg_latency_ms = alpha * latency_ms as f64 + (1.0 - alpha) * peer.avg_latency_ms;

        // Adjust reputation based on latency
        let latency_factor = 1.0 - (latency_ms as f64 / 1000.0).min(1.0);
        let latency_bonus = latency_weight * latency_factor;
        peer.score = (peer.score + latency_bonus).min(max_score);
    }

    /// Get peer reputation score.
    #[must_use]
    #[inline]
    pub fn get_reputation(&mut self, peer_id: &str) -> f64 {
        self.apply_decay();
        self.peers
            .get(peer_id)
            .map(|p| p.score)
            .unwrap_or(self.config.initial_score)
    }

    /// Get peer reputation data.
    #[must_use]
    #[inline]
    pub fn get_peer_data(&mut self, peer_id: &str) -> Option<&PeerReputation> {
        self.apply_decay();
        self.peers.get(peer_id)
    }

    /// Get all trusted peers above threshold.
    #[must_use]
    #[inline]
    pub fn get_trusted_peers(&mut self, threshold: f64) -> Vec<String> {
        self.apply_decay();
        self.peers
            .values()
            .filter(|p| p.is_trusted(threshold))
            .map(|p| p.peer_id.clone())
            .collect()
    }

    /// Get top N peers by reputation.
    #[must_use]
    #[inline]
    pub fn get_top_peers(&mut self, n: usize) -> Vec<String> {
        self.apply_decay();
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        peers.iter().take(n).map(|p| p.peer_id.clone()).collect()
    }

    /// Check if peer is banned.
    #[must_use]
    #[inline]
    pub fn is_banned(&self, peer_id: &str) -> bool {
        self.peers
            .get(peer_id)
            .map(|p| p.is_banned)
            .unwrap_or(false)
    }

    /// Manually ban a peer.
    #[inline]
    pub fn ban_peer(&mut self, peer_id: String) {
        let min_score = self.config.min_score;
        let peer = self.get_or_create(peer_id);
        peer.is_banned = true;
        peer.score = min_score;
    }

    /// Unban a peer.
    #[inline]
    pub fn unban_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.is_banned = false;
            peer.score = self.config.initial_score;
        }
    }

    /// Apply reputation decay to all peers.
    fn apply_decay(&mut self) {
        let now = SystemTime::now();
        let elapsed = now
            .duration_since(self.last_decay)
            .unwrap_or(Duration::from_secs(0));

        if elapsed < Duration::from_secs(3600) {
            // Only decay once per hour
            return;
        }

        let hours = elapsed.as_secs_f64() / 3600.0;
        let decay_factor = self.config.decay_rate * hours;

        for peer in self.peers.values_mut() {
            // Decay towards initial score
            let diff = peer.score - self.config.initial_score;
            peer.score -= diff * decay_factor;
            peer.score = peer
                .score
                .clamp(self.config.min_score, self.config.max_score);
        }

        self.last_decay = now;
    }

    /// Clean up old peer records.
    pub fn cleanup_old_peers(&mut self, max_age_secs: u64) {
        let now = SystemTime::now();
        self.peers.retain(|_, peer| {
            let age = now
                .duration_since(peer.last_seen)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
            age < max_age_secs
        });
    }

    #[must_use]
    /// Get reputation statistics.
    pub fn get_stats(&self) -> ReputationStats {
        let total_peers = self.peers.len();
        let banned_peers = self.peers.values().filter(|p| p.is_banned).count();
        let avg_score = if total_peers > 0 {
            self.peers.values().map(|p| p.score).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        ReputationStats {
            total_peers,
            banned_peers,
            trusted_peers: self.peers.values().filter(|p| p.is_trusted(0.7)).count(),
            avg_score,
            total_interactions: self.peers.values().map(|p| p.total_interactions()).sum(),
        }
    }

    /// Get all peer IDs.
    #[must_use]
    #[inline]
    pub fn get_all_peer_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Get peer count.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Reputation system statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationStats {
    /// Total number of peers tracked.
    pub total_peers: usize,

    /// Number of banned peers.
    pub banned_peers: usize,

    /// Number of trusted peers (score >= 0.7).
    pub trusted_peers: usize,

    /// Average reputation score.
    pub avg_score: f64,

    /// Total interactions across all peers.
    pub total_interactions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_config_default() {
        let config = ReputationConfig::default();
        assert_eq!(config.initial_score, 0.5);
        assert_eq!(config.min_score, 0.0);
        assert_eq!(config.max_score, 1.0);
    }

    #[test]
    fn test_peer_reputation_new() {
        let peer = PeerReputation::new("peer1".to_string(), 0.5);
        assert_eq!(peer.peer_id, "peer1");
        assert_eq!(peer.score, 0.5);
        assert_eq!(peer.successes, 0);
        assert_eq!(peer.failures, 0);
        assert!(!peer.is_banned);
    }

    #[test]
    fn test_record_success() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        let score = tracker.get_reputation("peer1");

        assert!(score > 0.5);
        let peer = tracker.get_peer_data("peer1").unwrap();
        assert_eq!(peer.successes, 1);
        assert_eq!(peer.bytes_transferred, 1024);
    }

    #[test]
    fn test_record_failure() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_failure("peer1".to_string(), 100);
        let score = tracker.get_reputation("peer1");

        assert!(score < 0.5);
        let peer = tracker.get_peer_data("peer1").unwrap();
        assert_eq!(peer.failures, 1);
    }

    #[test]
    fn test_record_latency() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_latency("peer1".to_string(), 50);
        let peer = tracker.get_peer_data("peer1").unwrap();

        assert!(peer.avg_latency_ms > 0.0);
    }

    #[test]
    fn test_ban_peer() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.ban_peer("peer1".to_string());
        assert!(tracker.is_banned("peer1"));

        tracker.unban_peer("peer1");
        assert!(!tracker.is_banned("peer1"));
    }

    #[test]
    fn test_get_trusted_peers() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_success("peer1".to_string(), 1024);

        tracker.record_failure("peer2".to_string(), 100);

        let trusted = tracker.get_trusted_peers(0.5);
        assert!(trusted.contains(&"peer1".to_string()));
    }

    #[test]
    fn test_get_top_peers() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_success("peer2".to_string(), 2048);
        tracker.record_success("peer2".to_string(), 2048); // More successes for peer2
        tracker.record_failure("peer3".to_string(), 50);

        let top = tracker.get_top_peers(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], "peer2"); // peer2 should have highest score
    }

    #[test]
    fn test_success_rate() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_failure("peer1".to_string(), 50);

        let peer = tracker.get_peer_data("peer1").unwrap();
        assert!((peer.success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_cleanup_old_peers() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        assert_eq!(tracker.peer_count(), 1);

        tracker.cleanup_old_peers(0);
        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn test_reputation_stats() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        tracker.record_success("peer1".to_string(), 1024);
        tracker.record_failure("peer2".to_string(), 50);

        let stats = tracker.get_stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_interactions, 2);
    }

    #[test]
    fn test_auto_ban_low_score() {
        let config = ReputationConfig::default();
        let mut tracker = ReputationTracker::new(config);

        // Record many failures to drive score to minimum
        for _ in 0..20 {
            tracker.record_failure("peer1".to_string(), 100);
        }

        assert!(tracker.is_banned("peer1"));
    }
}
