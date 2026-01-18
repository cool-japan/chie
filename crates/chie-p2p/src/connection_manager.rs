//! Unified connection manager integrating health, circuit breaker, bandwidth, and reputation.
//!
//! This module provides a high-level connection management system that combines:
//! - Health monitoring
//! - Circuit breaker protection
//! - Bandwidth estimation
//! - Reputation tracking
//! - Peer persistence
//!
//! Use this for production deployments to get all advanced P2P features.

use crate::{
    BandwidthEstimatorConfig, BandwidthEstimatorManager, BandwidthStats, CircuitBreakerConfig,
    CircuitBreakerManager, CircuitCheck, CircuitState, HealthConfig, HealthMonitor,
    HealthMonitorStats, HealthStatus, ReputationConfig, ReputationManager,
};
use libp2p::PeerId;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for the connection manager.
#[derive(Debug, Clone)]
pub struct ConnectionManagerConfig {
    /// Health monitoring configuration.
    pub health_config: HealthConfig,
    /// Circuit breaker configuration.
    pub circuit_breaker_config: CircuitBreakerConfig,
    /// Bandwidth estimation configuration.
    pub bandwidth_config: BandwidthEstimatorConfig,
    /// Reputation tracking configuration.
    pub reputation_config: ReputationConfig,
    /// Automatically disconnect unhealthy peers.
    pub auto_disconnect_unhealthy: bool,
    /// Minimum reputation score to allow connections.
    pub min_reputation_score: f64,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            health_config: HealthConfig::default(),
            circuit_breaker_config: CircuitBreakerConfig::default(),
            bandwidth_config: BandwidthEstimatorConfig::default(),
            reputation_config: ReputationConfig::default(),
            auto_disconnect_unhealthy: true,
            min_reputation_score: 30.0,
        }
    }
}

/// Decision on whether to allow a connection or transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDecision {
    /// Allow the connection/transfer.
    Allow,
    /// Block due to circuit breaker.
    BlockedByCircuitBreaker,
    /// Block due to low reputation.
    BlockedByReputation,
    /// Block due to unhealthy connection.
    BlockedByHealth,
}

/// Unified connection manager.
pub struct ConnectionManager {
    config: ConnectionManagerConfig,
    health_monitor: HealthMonitor,
    circuit_breaker: CircuitBreakerManager,
    bandwidth_estimator: BandwidthEstimatorManager,
    reputation: ReputationManager,
}

impl ConnectionManager {
    /// Create a new connection manager with the given configuration.
    pub fn new(config: ConnectionManagerConfig) -> Self {
        Self {
            health_monitor: HealthMonitor::new(config.health_config.clone()),
            circuit_breaker: CircuitBreakerManager::new(config.circuit_breaker_config.clone()),
            bandwidth_estimator: BandwidthEstimatorManager::new(config.bandwidth_config.clone()),
            reputation: ReputationManager::new(config.reputation_config.clone()),
            config,
        }
    }

    /// Check if a connection to a peer should be allowed.
    pub fn check_connection(&mut self, peer_id: &PeerId) -> ConnectionDecision {
        // Check circuit breaker first (fast fail)
        if self.circuit_breaker.check(peer_id) == CircuitCheck::Blocked {
            debug!("Connection to {:?} blocked by circuit breaker", peer_id);
            return ConnectionDecision::BlockedByCircuitBreaker;
        }

        // Check reputation
        let score = self.reputation.get_score(peer_id);
        if score < self.config.min_reputation_score {
            debug!(
                "Connection to {:?} blocked by reputation (score: {:.2})",
                peer_id, score
            );
            return ConnectionDecision::BlockedByReputation;
        }

        // Check health status
        let health = self.health_monitor.get_health(peer_id);
        if health == HealthStatus::Unhealthy && self.config.auto_disconnect_unhealthy {
            debug!("Connection to {:?} blocked by health status", peer_id);
            return ConnectionDecision::BlockedByHealth;
        }

        ConnectionDecision::Allow
    }

    /// Record a successful transfer.
    pub fn record_success(&mut self, peer_id: &PeerId, bytes: u64, duration: Duration) {
        let latency_ms = duration.as_secs_f64() * 1000.0;

        // Update all tracking systems
        self.health_monitor.record_success(*peer_id, latency_ms);
        self.circuit_breaker.record_success(peer_id);
        self.bandwidth_estimator
            .record_transfer(peer_id, bytes, duration);
        self.reputation
            .record_transfer(peer_id, true, latency_ms as u32);

        debug!(
            "Recorded success for {:?}: {} bytes in {:?}",
            peer_id, bytes, duration
        );
    }

    /// Record a failed transfer.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        // Update all tracking systems
        self.health_monitor.record_failure(*peer_id);
        self.circuit_breaker.record_failure(peer_id);
        self.reputation.record_transfer(peer_id, false, 0);

        warn!("Recorded failure for {:?}", peer_id);
    }

    /// Get comprehensive peer information.
    pub fn get_peer_info(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        Some(PeerInfo {
            peer_id: *peer_id,
            health_status: self.health_monitor.get_health(peer_id),
            circuit_state: self.circuit_breaker.get_state(peer_id),
            reputation_score: Some(self.reputation.get_score(peer_id)),
            bandwidth_stats: self.bandwidth_estimator.get_stats(peer_id),
            is_banned: self.reputation.is_banned(peer_id),
        })
    }

    /// Get all peers that should be disconnected.
    pub fn get_peers_to_disconnect(&mut self) -> Vec<PeerId> {
        let mut to_disconnect = Vec::new();

        // Add unhealthy peers
        if self.config.auto_disconnect_unhealthy {
            to_disconnect.extend(self.health_monitor.get_unhealthy_peers());
        }

        // Add peers with open circuits
        to_disconnect.extend(self.circuit_breaker.get_open_circuits());

        // Add peers that have excessive failures (banned)
        let all_peers = self.reputation.get_peers_by_score();
        for (peer_id, _) in all_peers {
            if self.reputation.is_banned(&peer_id) {
                to_disconnect.push(peer_id);
            }
        }

        // Deduplicate
        to_disconnect.sort();
        to_disconnect.dedup();
        to_disconnect
    }

    /// Get top peers by overall quality (reputation + health + bandwidth).
    pub fn get_top_peers(&mut self, n: usize) -> Vec<PeerId> {
        let mut peer_scores: Vec<(PeerId, f64)> = Vec::new();

        // Get all peers we have data for
        let all_peers: Vec<PeerId> = self
            .reputation
            .get_peers_by_score()
            .into_iter()
            .map(|(peer, _)| peer)
            .collect();

        for peer in all_peers {
            // Skip banned or blocked peers
            if self.reputation.is_banned(&peer) {
                continue;
            }
            if self.circuit_breaker.get_state(&peer) == CircuitState::Open {
                continue;
            }

            // Calculate composite score
            let mut score = 0.0;

            // Reputation (0-100 scale, weight: 0.4)
            let rep = self.reputation.get_score(&peer);
            score += rep * 0.4;

            // Health (convert status to score, weight: 0.3)
            let health_score = match self.health_monitor.get_health(&peer) {
                HealthStatus::Healthy => 100.0,
                HealthStatus::Degraded => 60.0,
                HealthStatus::Unhealthy => 20.0,
                HealthStatus::Unknown => 50.0,
            };
            score += health_score * 0.3;

            // Bandwidth (normalize to 0-100, weight: 0.3)
            if let Some(bw_mbps) = self.bandwidth_estimator.estimate_bandwidth_mbps(&peer) {
                let bw_score = (bw_mbps * 10.0).min(100.0); // 10 Mbps = 100 score
                score += bw_score * 0.3;
            }

            peer_scores.push((peer, score));
        }

        // Sort by score descending
        peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        peer_scores
            .into_iter()
            .take(n)
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Remove a peer from all tracking systems.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.health_monitor.remove_peer(peer_id);
        self.circuit_breaker.remove(peer_id);
        self.bandwidth_estimator.remove_peer(peer_id);
        self.reputation.remove_peer(peer_id);
        info!("Removed peer {:?} from connection manager", peer_id);
    }

    /// Get comprehensive statistics.
    pub fn stats(&self) -> ConnectionManagerStats {
        ConnectionManagerStats {
            health_stats: self.health_monitor.stats(),
            circuit_stats: self.circuit_breaker.stats(),
            total_tracked_peers: self.reputation.peer_count(),
            banned_peers: self.reputation.banned_count(),
        }
    }

    /// Perform maintenance tasks (cleanup, etc.).
    pub fn maintenance(&mut self) {
        self.bandwidth_estimator.cleanup();
        debug!("Performed connection manager maintenance");
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new(ConnectionManagerConfig::default())
    }
}

/// Information about a peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID.
    pub peer_id: PeerId,
    /// Health status.
    pub health_status: HealthStatus,
    /// Circuit breaker state.
    pub circuit_state: CircuitState,
    /// Reputation score.
    pub reputation_score: Option<f64>,
    /// Bandwidth statistics.
    pub bandwidth_stats: Option<BandwidthStats>,
    /// Whether the peer is banned.
    pub is_banned: bool,
}

impl PeerInfo {
    /// Check if this peer is in good standing.
    pub fn is_good(&self) -> bool {
        !self.is_banned
            && self.circuit_state != CircuitState::Open
            && self.health_status != HealthStatus::Unhealthy
            && self.reputation_score.unwrap_or(0.0) >= 50.0
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Peer {:?}: Health={:?}, Circuit={:?}, Rep={:.2}, Banned={}",
            self.peer_id,
            self.health_status,
            self.circuit_state,
            self.reputation_score.unwrap_or(0.0),
            self.is_banned
        )
    }
}

/// Statistics about the connection manager.
#[derive(Debug, Clone)]
pub struct ConnectionManagerStats {
    /// Health monitoring statistics.
    pub health_stats: HealthMonitorStats,
    /// Circuit breaker statistics.
    pub circuit_stats: crate::CircuitBreakerStats,
    /// Total tracked peers.
    pub total_tracked_peers: usize,
    /// Number of banned peers.
    pub banned_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_creation() {
        let manager = ConnectionManager::default();
        let stats = manager.stats();
        assert_eq!(stats.total_tracked_peers, 0);
    }

    #[test]
    fn test_allow_new_peer() {
        let mut manager = ConnectionManager::default();
        let peer = PeerId::random();

        // New peer should be allowed
        assert_eq!(manager.check_connection(&peer), ConnectionDecision::Allow);
    }

    #[test]
    fn test_block_after_failures() {
        let config = ConnectionManagerConfig {
            circuit_breaker_config: CircuitBreakerConfig {
                failure_threshold: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut manager = ConnectionManager::new(config);
        let peer = PeerId::random();

        // Record failures to trigger circuit breaker
        for _ in 0..3 {
            manager.record_failure(&peer);
        }

        // Should be blocked now
        assert_eq!(
            manager.check_connection(&peer),
            ConnectionDecision::BlockedByCircuitBreaker
        );
    }

    #[test]
    fn test_record_success_updates_all_systems() {
        let mut manager = ConnectionManager::default();
        let peer = PeerId::random();

        manager.record_success(&peer, 1_000_000, Duration::from_secs(1));

        let info = manager.get_peer_info(&peer).unwrap();
        assert!(info.reputation_score.is_some());
        assert!(info.bandwidth_stats.is_some());
    }

    #[test]
    fn test_get_top_peers() {
        let mut manager = ConnectionManager::default();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        // Give different quality to each peer
        for _ in 0..10 {
            manager.record_success(&peer1, 1_000_000, Duration::from_millis(100)); // Fast, reliable
        }

        for _ in 0..5 {
            manager.record_success(&peer2, 500_000, Duration::from_millis(200)); // Medium
        }

        for _ in 0..3 {
            manager.record_success(&peer3, 100_000, Duration::from_millis(500)); // Slow
        }

        let top = manager.get_top_peers(2);
        assert_eq!(top.len(), 2);
        // peer1 should be first (best overall quality)
        assert_eq!(top[0], peer1);
    }

    #[test]
    fn test_peers_to_disconnect() {
        let mut manager = ConnectionManager::default();
        let peer = PeerId::random();

        // Trigger multiple failures to get banned
        for _ in 0..20 {
            manager.record_failure(&peer);
        }

        let to_disconnect = manager.get_peers_to_disconnect();
        assert!(to_disconnect.contains(&peer));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = ConnectionManager::default();
        let peer = PeerId::random();

        manager.record_success(&peer, 1_000_000, Duration::from_secs(1));
        let info_before = manager.get_peer_info(&peer).unwrap();
        assert!(info_before.bandwidth_stats.is_some());

        manager.remove_peer(&peer);
        let info_after = manager.get_peer_info(&peer).unwrap();
        // After removal, bandwidth stats should be gone
        assert!(info_after.bandwidth_stats.is_none());
        // Reputation should be back to default
        assert_eq!(info_after.reputation_score.unwrap(), 50.0);
    }

    #[test]
    fn test_peer_info_is_good() {
        let peer = PeerId::random();

        let good_peer = PeerInfo {
            peer_id: peer,
            health_status: HealthStatus::Healthy,
            circuit_state: CircuitState::Closed,
            reputation_score: Some(80.0),
            bandwidth_stats: None,
            is_banned: false,
        };

        assert!(good_peer.is_good());

        let bad_peer = PeerInfo {
            peer_id: peer,
            health_status: HealthStatus::Unhealthy,
            circuit_state: CircuitState::Open,
            reputation_score: Some(20.0),
            bandwidth_stats: None,
            is_banned: true,
        };

        assert!(!bad_peer.is_good());
    }

    #[test]
    fn test_block_by_reputation() {
        let config = ConnectionManagerConfig {
            min_reputation_score: 50.0,
            ..Default::default()
        };
        let mut manager = ConnectionManager::new(config);
        let peer = PeerId::random();

        // Lower reputation below threshold
        for _ in 0..15 {
            manager.record_failure(&peer);
        }

        // Should be blocked by reputation
        let decision = manager.check_connection(&peer);
        assert!(matches!(
            decision,
            ConnectionDecision::BlockedByReputation | ConnectionDecision::BlockedByCircuitBreaker
        ));
    }

    #[test]
    fn test_maintenance() {
        let mut manager = ConnectionManager::default();
        // Should not panic
        manager.maintenance();
    }
}
