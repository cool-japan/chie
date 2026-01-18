//! Peer reputation system for CHIE Protocol.
//!
//! This module implements a reputation system that tracks peer behavior
//! and assigns scores based on:
//! - Successful/failed transfers
//! - Response latency
//! - Uptime
//! - Content availability

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for the reputation system.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Initial reputation score for new peers.
    pub initial_score: f64,
    /// Maximum reputation score.
    pub max_score: f64,
    /// Minimum reputation score.
    pub min_score: f64,
    /// Score below which a peer is considered bad.
    pub ban_threshold: f64,
    /// Points gained for successful transfer.
    pub success_reward: f64,
    /// Points lost for failed transfer.
    pub failure_penalty: f64,
    /// Points lost for timeout.
    pub timeout_penalty: f64,
    /// Decay factor per hour (0.0 to 1.0).
    pub hourly_decay: f64,
    /// Latency threshold for bonus (ms).
    pub low_latency_threshold_ms: u32,
    /// Bonus for low latency responses.
    pub low_latency_bonus: f64,
    /// Time window for rate limiting checks (seconds).
    pub rate_window_secs: u64,
    /// Maximum failures in rate window before penalty.
    pub max_failures_in_window: u32,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_score: 50.0,
            max_score: 100.0,
            min_score: 0.0,
            ban_threshold: 10.0,
            success_reward: 1.0,
            failure_penalty: 5.0,
            timeout_penalty: 3.0,
            hourly_decay: 0.99,
            low_latency_threshold_ms: 100,
            low_latency_bonus: 0.5,
            rate_window_secs: 3600, // 1 hour
            max_failures_in_window: 10,
        }
    }
}

/// Event types for reputation updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEvent {
    /// Successful chunk transfer.
    TransferSuccess,
    /// Failed chunk transfer.
    TransferFailure,
    /// Request timeout.
    Timeout,
    /// Low latency response.
    LowLatency,
    /// Invalid response (bad signature, wrong data, etc.).
    InvalidResponse,
    /// Connection established.
    Connected,
    /// Connection lost.
    Disconnected,
}

/// Statistics for a single peer.
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Current reputation score.
    pub score: f64,
    /// Total successful transfers.
    pub successes: u64,
    /// Total failed transfers.
    pub failures: u64,
    /// Total timeouts.
    pub timeouts: u64,
    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Latency samples for calculating average.
    latency_samples: Vec<u32>,
    /// First seen timestamp.
    pub first_seen: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Last decay timestamp.
    last_decay: Instant,
    /// Failure timestamps for rate limiting.
    recent_failures: Vec<Instant>,
    /// Whether the peer is currently banned.
    pub is_banned: bool,
    /// Ban expiry time (if banned).
    pub ban_until: Option<Instant>,
}

impl PeerStats {
    fn new(initial_score: f64) -> Self {
        let now = Instant::now();
        Self {
            score: initial_score,
            successes: 0,
            failures: 0,
            timeouts: 0,
            avg_latency_ms: 0.0,
            latency_samples: Vec::new(),
            first_seen: now,
            last_activity: now,
            last_decay: now,
            recent_failures: Vec::new(),
            is_banned: false,
            ban_until: None,
        }
    }

    /// Add a latency sample.
    fn add_latency(&mut self, latency_ms: u32) {
        self.latency_samples.push(latency_ms);
        // Keep only the last 100 samples
        if self.latency_samples.len() > 100 {
            self.latency_samples.remove(0);
        }
        // Recalculate average
        let sum: u64 = self.latency_samples.iter().map(|&l| l as u64).sum();
        self.avg_latency_ms = sum as f64 / self.latency_samples.len() as f64;
    }

    /// Prune old failure timestamps.
    fn prune_old_failures(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.recent_failures.retain(|&t| t > cutoff);
    }
}

/// Peer reputation manager.
pub struct ReputationManager {
    config: ReputationConfig,
    peers: HashMap<PeerId, PeerStats>,
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new(ReputationConfig::default())
    }
}

impl ReputationManager {
    /// Create a new reputation manager with custom config.
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Get or create stats for a peer.
    fn get_or_create(&mut self, peer: &PeerId) -> &mut PeerStats {
        if !self.peers.contains_key(peer) {
            self.peers
                .insert(*peer, PeerStats::new(self.config.initial_score));
        }
        self.peers.get_mut(peer).unwrap()
    }

    /// Apply time-based decay to a peer's score.
    fn apply_decay(&mut self, peer: &PeerId) {
        if let Some(stats) = self.peers.get_mut(peer) {
            let now = Instant::now();
            let hours_elapsed = now.duration_since(stats.last_decay).as_secs_f64() / 3600.0;
            if hours_elapsed >= 1.0 {
                // Apply decay
                let decay_factor = self.config.hourly_decay.powf(hours_elapsed);
                stats.score = self.config.initial_score
                    + (stats.score - self.config.initial_score) * decay_factor;
                stats.last_decay = now;
            }
        }
    }

    /// Record a reputation event for a peer.
    pub fn record_event(&mut self, peer: &PeerId, event: ReputationEvent) {
        self.apply_decay(peer);

        // Get config values we need
        let success_reward = self.config.success_reward;
        let failure_penalty = self.config.failure_penalty;
        let timeout_penalty = self.config.timeout_penalty;
        let low_latency_bonus = self.config.low_latency_bonus;
        let max_score = self.config.max_score;
        let min_score = self.config.min_score;
        let ban_threshold = self.config.ban_threshold;

        let stats = self.get_or_create(peer);
        stats.last_activity = Instant::now();

        match event {
            ReputationEvent::TransferSuccess => {
                stats.successes += 1;
                stats.score = (stats.score + success_reward).min(max_score);
            }
            ReputationEvent::TransferFailure => {
                stats.failures += 1;
                stats.recent_failures.push(Instant::now());
                stats.score = (stats.score - failure_penalty).max(min_score);
            }
            ReputationEvent::Timeout => {
                stats.timeouts += 1;
                stats.recent_failures.push(Instant::now());
                stats.score = (stats.score - timeout_penalty).max(min_score);
            }
            ReputationEvent::LowLatency => {
                stats.score = (stats.score + low_latency_bonus).min(max_score);
            }
            ReputationEvent::InvalidResponse => {
                stats.failures += 1;
                stats.recent_failures.push(Instant::now());
                stats.score = (stats.score - failure_penalty * 2.0).max(min_score);
            }
            ReputationEvent::Connected => {
                // No score change, just update activity
            }
            ReputationEvent::Disconnected => {
                // No score change
            }
        }

        // Check if peer should be banned
        let should_ban = stats.score <= ban_threshold && !stats.is_banned;
        if should_ban {
            stats.is_banned = true;
            stats.ban_until = Some(Instant::now() + Duration::from_secs(3600)); // 1 hour ban
        }
    }

    /// Record a transfer with latency.
    pub fn record_transfer(&mut self, peer: &PeerId, success: bool, latency_ms: u32) {
        if success {
            self.record_event(peer, ReputationEvent::TransferSuccess);
            if latency_ms <= self.config.low_latency_threshold_ms {
                self.record_event(peer, ReputationEvent::LowLatency);
            }
        } else {
            self.record_event(peer, ReputationEvent::TransferFailure);
        }

        if let Some(stats) = self.peers.get_mut(peer) {
            stats.add_latency(latency_ms);
        }
    }

    /// Get the reputation score for a peer.
    pub fn get_score(&mut self, peer: &PeerId) -> f64 {
        self.apply_decay(peer);
        self.peers
            .get(peer)
            .map(|s| s.score)
            .unwrap_or(self.config.initial_score)
    }

    /// Get full stats for a peer.
    pub fn get_stats(&self, peer: &PeerId) -> Option<&PeerStats> {
        self.peers.get(peer)
    }

    /// Check if a peer is banned.
    pub fn is_banned(&mut self, peer: &PeerId) -> bool {
        if let Some(stats) = self.peers.get_mut(peer) {
            if stats.is_banned {
                if let Some(until) = stats.ban_until {
                    if Instant::now() >= until {
                        // Ban expired
                        stats.is_banned = false;
                        stats.ban_until = None;
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    /// Ban a peer for a specified duration.
    pub fn ban_peer(&mut self, peer: &PeerId, duration: Duration) {
        let stats = self.get_or_create(peer);
        stats.is_banned = true;
        stats.ban_until = Some(Instant::now() + duration);
    }

    /// Unban a peer.
    pub fn unban_peer(&mut self, peer: &PeerId) {
        if let Some(stats) = self.peers.get_mut(peer) {
            stats.is_banned = false;
            stats.ban_until = None;
        }
    }

    /// Check if a peer has too many recent failures.
    pub fn has_excessive_failures(&mut self, peer: &PeerId) -> bool {
        if let Some(stats) = self.peers.get_mut(peer) {
            stats.prune_old_failures(Duration::from_secs(self.config.rate_window_secs));
            return stats.recent_failures.len() as u32 >= self.config.max_failures_in_window;
        }
        false
    }

    /// Get a list of peer IDs sorted by reputation score (highest first).
    pub fn get_peers_by_score(&mut self) -> Vec<(PeerId, f64)> {
        // Apply decay to all peers first
        let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer in &peer_ids {
            self.apply_decay(peer);
        }

        let mut peers: Vec<(PeerId, f64)> = self
            .peers
            .iter()
            .filter(|(_, stats)| !stats.is_banned)
            .map(|(peer, stats)| (*peer, stats.score))
            .collect();

        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        peers
    }

    /// Get the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of banned peers.
    pub fn banned_count(&self) -> usize {
        self.peers.values().filter(|s| s.is_banned).count()
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// Prune peers that haven't been active for the specified duration.
    pub fn prune_inactive(&mut self, max_inactive: Duration) {
        let cutoff = Instant::now() - max_inactive;
        self.peers.retain(|_, stats| stats.last_activity > cutoff);
    }

    /// Get a summary of reputation stats.
    pub fn get_summary(&self) -> ReputationSummary {
        let total_peers = self.peers.len();
        let banned_peers = self.peers.values().filter(|s| s.is_banned).count();
        let active_peers = self.peers.values().filter(|s| !s.is_banned).count();

        let scores: Vec<f64> = self
            .peers
            .values()
            .filter(|s| !s.is_banned)
            .map(|s| s.score)
            .collect();

        let avg_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };

        ReputationSummary {
            total_peers,
            active_peers,
            banned_peers,
            average_score: avg_score,
        }
    }
}

/// Summary of reputation statistics.
#[derive(Debug, Clone)]
pub struct ReputationSummary {
    /// Total number of tracked peers.
    pub total_peers: usize,
    /// Number of active (non-banned) peers.
    pub active_peers: usize,
    /// Number of banned peers.
    pub banned_peers: usize,
    /// Average reputation score.
    pub average_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(_id: u8) -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_initial_score() {
        let mut manager = ReputationManager::default();
        let peer = make_peer_id(1);

        let score = manager.get_score(&peer);
        assert_eq!(score, 50.0);
    }

    #[test]
    fn test_success_increases_score() {
        let mut manager = ReputationManager::default();
        let peer = make_peer_id(1);

        manager.record_event(&peer, ReputationEvent::TransferSuccess);
        let score = manager.get_score(&peer);

        assert!(score > 50.0);
    }

    #[test]
    fn test_failure_decreases_score() {
        let mut manager = ReputationManager::default();
        let peer = make_peer_id(1);

        manager.record_event(&peer, ReputationEvent::TransferFailure);
        let score = manager.get_score(&peer);

        assert!(score < 50.0);
    }

    #[test]
    fn test_score_bounds() {
        let mut manager = ReputationManager::default();
        let peer = make_peer_id(1);

        // Many successes shouldn't exceed max
        for _ in 0..1000 {
            manager.record_event(&peer, ReputationEvent::TransferSuccess);
        }
        assert!(manager.get_score(&peer) <= 100.0);

        // Many failures shouldn't go below min
        let peer2 = make_peer_id(2);
        for _ in 0..1000 {
            manager.record_event(&peer2, ReputationEvent::TransferFailure);
        }
        assert!(manager.get_score(&peer2) >= 0.0);
    }

    #[test]
    fn test_ban_on_low_score() {
        let config = ReputationConfig {
            initial_score: 20.0,
            ban_threshold: 10.0,
            failure_penalty: 5.0,
            ..Default::default()
        };
        let mut manager = ReputationManager::new(config);
        let peer = make_peer_id(1);

        // Should be banned after score drops below threshold
        manager.record_event(&peer, ReputationEvent::TransferFailure);
        manager.record_event(&peer, ReputationEvent::TransferFailure);
        manager.record_event(&peer, ReputationEvent::TransferFailure);

        assert!(manager.is_banned(&peer));
    }

    #[test]
    fn test_latency_tracking() {
        let mut manager = ReputationManager::default();
        let peer = make_peer_id(1);

        manager.record_transfer(&peer, true, 50);
        manager.record_transfer(&peer, true, 100);
        manager.record_transfer(&peer, true, 75);

        let stats = manager.get_stats(&peer).unwrap();
        assert_eq!(stats.avg_latency_ms, 75.0);
    }

    #[test]
    fn test_peers_by_score() {
        let mut manager = ReputationManager::default();
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);
        let peer3 = make_peer_id(3);

        // Give peer2 highest score
        for _ in 0..10 {
            manager.record_event(&peer2, ReputationEvent::TransferSuccess);
        }

        // Give peer1 some successes
        for _ in 0..5 {
            manager.record_event(&peer1, ReputationEvent::TransferSuccess);
        }

        // Give peer3 lowest score
        manager.record_event(&peer3, ReputationEvent::TransferFailure);

        let ranked = manager.get_peers_by_score();
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].0, peer2);
        assert_eq!(ranked[2].0, peer3);
    }
}
