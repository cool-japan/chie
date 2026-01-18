//! Real-time network state monitoring and management.
//!
//! This module provides:
//! - Network state tracking and aggregation
//! - Real-time health monitoring
//! - Network condition detection
//! - State change notifications
//! - Historical state tracking

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Overall network state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkState {
    /// Network is initializing
    #[default]
    Initializing,
    /// Network is healthy and operational
    Healthy,
    /// Network is degraded but functional
    Degraded,
    /// Network has critical issues
    Critical,
    /// Network is disconnected
    Disconnected,
}

/// Network condition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCondition {
    /// Excellent network conditions
    Excellent,
    /// Good network conditions
    Good,
    /// Fair network conditions
    Fair,
    /// Poor network conditions
    Poor,
    /// Very poor network conditions
    Critical,
}

/// Peer connection status
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// Peer ID
    pub peer_id: PeerId,
    /// Is connected
    pub connected: bool,
    /// Connection quality (0.0 - 1.0)
    pub quality: f64,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Bandwidth in bytes/sec
    pub bandwidth_bps: f64,
    /// Last seen time
    pub last_seen: Instant,
}

impl PeerStatus {
    /// Create new peer status
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            connected: false,
            quality: 0.0,
            latency_ms: 0.0,
            bandwidth_bps: 0.0,
            last_seen: Instant::now(),
        }
    }
}

/// Network metrics snapshot
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Total number of peers
    pub total_peers: usize,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Average latency across all peers
    pub avg_latency_ms: f64,
    /// Total bandwidth (bytes/sec)
    pub total_bandwidth_bps: f64,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f64,
    /// Connection success rate (0.0 - 1.0)
    pub connection_success_rate: f64,
    /// Timestamp of snapshot
    pub timestamp: Instant,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            total_peers: 0,
            connected_peers: 0,
            avg_latency_ms: 0.0,
            total_bandwidth_bps: 0.0,
            packet_loss_rate: 0.0,
            connection_success_rate: 1.0,
            timestamp: Instant::now(),
        }
    }
}

/// State change event
#[derive(Debug, Clone)]
pub struct StateChangeEvent {
    /// Previous state
    pub old_state: NetworkState,
    /// New state
    pub new_state: NetworkState,
    /// Timestamp of change
    pub timestamp: Instant,
    /// Reason for change
    pub reason: String,
}

/// Network state monitor
#[derive(Clone)]
pub struct NetworkStateMonitor {
    inner: Arc<RwLock<NetworkStateMonitorInner>>,
}

struct NetworkStateMonitorInner {
    /// Current network state
    current_state: NetworkState,
    /// Peer statuses
    peers: HashMap<PeerId, PeerStatus>,
    /// Metrics history
    metrics_history: VecDeque<NetworkMetrics>,
    /// State change history
    state_history: VecDeque<StateChangeEvent>,
    /// Maximum history size
    max_history_size: usize,
    /// Health check thresholds
    health_thresholds: HealthThresholds,
    /// Total connection attempts
    connection_attempts: u64,
    /// Successful connections
    successful_connections: u64,
    /// Failed connections
    failed_connections: u64,
}

/// Health check thresholds
#[derive(Debug, Clone)]
pub struct HealthThresholds {
    /// Minimum connected peers for healthy state
    pub min_healthy_peers: usize,
    /// Maximum latency for healthy state (ms)
    pub max_healthy_latency_ms: f64,
    /// Maximum packet loss for healthy state
    pub max_healthy_packet_loss: f64,
    /// Minimum connection success rate for healthy state
    pub min_healthy_success_rate: f64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            min_healthy_peers: 3,
            max_healthy_latency_ms: 200.0,
            max_healthy_packet_loss: 0.05,
            min_healthy_success_rate: 0.8,
        }
    }
}

impl Default for NetworkStateMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkStateMonitor {
    /// Create a new network state monitor
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(NetworkStateMonitorInner {
                current_state: NetworkState::Initializing,
                peers: HashMap::new(),
                metrics_history: VecDeque::new(),
                state_history: VecDeque::new(),
                max_history_size: 100,
                health_thresholds: HealthThresholds::default(),
                connection_attempts: 0,
                successful_connections: 0,
                failed_connections: 0,
            })),
        }
    }

    /// Set health thresholds
    pub fn set_thresholds(&self, thresholds: HealthThresholds) {
        if let Ok(mut inner) = self.inner.write() {
            inner.health_thresholds = thresholds;
        }
    }

    /// Update peer status
    pub fn update_peer(&self, peer_id: PeerId, connected: bool, quality: f64) {
        if let Ok(mut inner) = self.inner.write() {
            let mut status = inner
                .peers
                .get(&peer_id)
                .cloned()
                .unwrap_or_else(|| PeerStatus::new(peer_id));

            status.connected = connected;
            status.quality = quality.clamp(0.0, 1.0);
            status.last_seen = Instant::now();

            inner.peers.insert(peer_id, status);
        }
    }

    /// Update peer latency
    pub fn update_latency(&self, peer_id: &PeerId, latency_ms: f64) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(status) = inner.peers.get_mut(peer_id) {
                status.latency_ms = latency_ms;
            }
        }
    }

    /// Update peer bandwidth
    pub fn update_bandwidth(&self, peer_id: &PeerId, bandwidth_bps: f64) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(status) = inner.peers.get_mut(peer_id) {
                status.bandwidth_bps = bandwidth_bps;
            }
        }
    }

    /// Record connection attempt
    pub fn record_connection_attempt(&self, success: bool) {
        if let Ok(mut inner) = self.inner.write() {
            inner.connection_attempts += 1;
            if success {
                inner.successful_connections += 1;
            } else {
                inner.failed_connections += 1;
            }
        }
    }

    /// Remove peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.peers.remove(peer_id);
        }
    }

    /// Get current network state
    pub fn current_state(&self) -> NetworkState {
        self.inner
            .read()
            .map(|inner| inner.current_state)
            .unwrap_or(NetworkState::Disconnected)
    }

    /// Get current network condition
    pub fn current_condition(&self) -> NetworkCondition {
        let metrics = self.current_metrics();

        if metrics.connected_peers == 0 {
            return NetworkCondition::Critical;
        }

        let latency_score = if metrics.avg_latency_ms < 50.0 {
            1.0
        } else if metrics.avg_latency_ms < 100.0 {
            0.8
        } else if metrics.avg_latency_ms < 200.0 {
            0.6
        } else if metrics.avg_latency_ms < 500.0 {
            0.4
        } else {
            0.2
        };

        let packet_loss_score = 1.0 - metrics.packet_loss_rate.min(1.0);
        let connection_score = metrics.connection_success_rate;

        let overall_score = (latency_score + packet_loss_score + connection_score) / 3.0;

        if overall_score >= 0.9 {
            NetworkCondition::Excellent
        } else if overall_score >= 0.75 {
            NetworkCondition::Good
        } else if overall_score >= 0.5 {
            NetworkCondition::Fair
        } else if overall_score >= 0.25 {
            NetworkCondition::Poor
        } else {
            NetworkCondition::Critical
        }
    }

    /// Get current network metrics
    pub fn current_metrics(&self) -> NetworkMetrics {
        let Ok(inner) = self.inner.read() else {
            return NetworkMetrics::default();
        };

        let total_peers = inner.peers.len();
        let connected_peers = inner.peers.values().filter(|p| p.connected).count();

        let avg_latency_ms = if connected_peers > 0 {
            inner
                .peers
                .values()
                .filter(|p| p.connected)
                .map(|p| p.latency_ms)
                .sum::<f64>()
                / connected_peers as f64
        } else {
            0.0
        };

        let total_bandwidth_bps = inner
            .peers
            .values()
            .filter(|p| p.connected)
            .map(|p| p.bandwidth_bps)
            .sum();

        let connection_success_rate = if inner.connection_attempts > 0 {
            inner.successful_connections as f64 / inner.connection_attempts as f64
        } else {
            1.0
        };

        NetworkMetrics {
            total_peers,
            connected_peers,
            avg_latency_ms,
            total_bandwidth_bps,
            packet_loss_rate: 0.0, // Would be updated from actual measurements
            connection_success_rate,
            timestamp: Instant::now(),
        }
    }

    /// Update network state based on current metrics
    pub fn update_state(&self) {
        let metrics = self.current_metrics();

        let Ok(mut inner) = self.inner.write() else {
            return;
        };

        let old_state = inner.current_state;
        let new_state = self.determine_state(&metrics, &inner.health_thresholds);

        if old_state != new_state {
            let event = StateChangeEvent {
                old_state,
                new_state,
                timestamp: Instant::now(),
                reason: format!(
                    "State change based on metrics: {} connected peers, {:.1}ms latency",
                    metrics.connected_peers, metrics.avg_latency_ms
                ),
            };

            inner.state_history.push_back(event);
            if inner.state_history.len() > inner.max_history_size {
                inner.state_history.pop_front();
            }

            inner.current_state = new_state;
        }

        // Store metrics snapshot
        inner.metrics_history.push_back(metrics);
        if inner.metrics_history.len() > inner.max_history_size {
            inner.metrics_history.pop_front();
        }
    }

    /// Determine network state from metrics
    fn determine_state(
        &self,
        metrics: &NetworkMetrics,
        thresholds: &HealthThresholds,
    ) -> NetworkState {
        if metrics.connected_peers == 0 {
            return NetworkState::Disconnected;
        }

        if metrics.connected_peers < thresholds.min_healthy_peers {
            return NetworkState::Critical;
        }

        let mut issues = 0;

        if metrics.avg_latency_ms > thresholds.max_healthy_latency_ms {
            issues += 1;
        }

        if metrics.packet_loss_rate > thresholds.max_healthy_packet_loss {
            issues += 1;
        }

        if metrics.connection_success_rate < thresholds.min_healthy_success_rate {
            issues += 1;
        }

        match issues {
            0 => NetworkState::Healthy,
            1 => NetworkState::Degraded,
            _ => NetworkState::Critical,
        }
    }

    /// Get metrics history
    pub fn metrics_history(&self) -> Vec<NetworkMetrics> {
        self.inner
            .read()
            .map(|inner| inner.metrics_history.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get state change history
    pub fn state_history(&self) -> Vec<StateChangeEvent> {
        self.inner
            .read()
            .map(|inner| inner.state_history.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all peer statuses
    pub fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.inner
            .read()
            .map(|inner| inner.peers.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get statistics
    pub fn stats(&self) -> NetworkStateStats {
        let Ok(inner) = self.inner.read() else {
            return NetworkStateStats::default();
        };

        NetworkStateStats {
            current_state: inner.current_state,
            total_peers: inner.peers.len(),
            connected_peers: inner.peers.values().filter(|p| p.connected).count(),
            connection_attempts: inner.connection_attempts,
            successful_connections: inner.successful_connections,
            failed_connections: inner.failed_connections,
            metrics_snapshots: inner.metrics_history.len(),
            state_changes: inner.state_history.len(),
        }
    }
}

/// Network state statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStateStats {
    pub current_state: NetworkState,
    pub total_peers: usize,
    pub connected_peers: usize,
    pub connection_attempts: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub metrics_snapshots: usize,
    pub state_changes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_state_monitor_creation() {
        let monitor = NetworkStateMonitor::new();
        assert_eq!(monitor.current_state(), NetworkState::Initializing);
    }

    #[test]
    fn test_peer_status_update() {
        let monitor = NetworkStateMonitor::new();
        let peer_id = PeerId::random();

        monitor.update_peer(peer_id, true, 0.9);
        let statuses = monitor.peer_statuses();

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].peer_id, peer_id);
        assert!(statuses[0].connected);
        assert_eq!(statuses[0].quality, 0.9);
    }

    #[test]
    fn test_latency_bandwidth_update() {
        let monitor = NetworkStateMonitor::new();
        let peer_id = PeerId::random();

        monitor.update_peer(peer_id, true, 0.8);
        monitor.update_latency(&peer_id, 50.0);
        monitor.update_bandwidth(&peer_id, 1_000_000.0);

        let metrics = monitor.current_metrics();
        assert_eq!(metrics.avg_latency_ms, 50.0);
        assert_eq!(metrics.total_bandwidth_bps, 1_000_000.0);
    }

    #[test]
    fn test_connection_tracking() {
        let monitor = NetworkStateMonitor::new();

        monitor.record_connection_attempt(true);
        monitor.record_connection_attempt(true);
        monitor.record_connection_attempt(false);

        let stats = monitor.stats();
        assert_eq!(stats.connection_attempts, 3);
        assert_eq!(stats.successful_connections, 2);
        assert_eq!(stats.failed_connections, 1);
    }

    #[test]
    fn test_network_condition() {
        let monitor = NetworkStateMonitor::new();
        let peer_id = PeerId::random();

        monitor.update_peer(peer_id, true, 0.9);
        monitor.update_latency(&peer_id, 30.0);

        let condition = monitor.current_condition();
        assert!(matches!(
            condition,
            NetworkCondition::Excellent | NetworkCondition::Good
        ));
    }

    #[test]
    fn test_state_update() {
        let monitor = NetworkStateMonitor::new();

        // Add enough peers to transition from Initializing
        for _ in 0..5 {
            let peer_id = PeerId::random();
            monitor.update_peer(peer_id, true, 0.9);
            monitor.update_latency(&peer_id, 50.0);
        }

        monitor.update_state();
        assert_eq!(monitor.current_state(), NetworkState::Healthy);
    }

    #[test]
    fn test_state_change_history() {
        let monitor = NetworkStateMonitor::new();

        monitor.update_state();
        let peer_id = PeerId::random();
        monitor.update_peer(peer_id, true, 0.9);
        monitor.update_state();

        let history = monitor.state_history();
        assert!(!history.is_empty());
    }

    #[test]
    fn test_metrics_history() {
        let monitor = NetworkStateMonitor::new();
        let peer_id = PeerId::random();

        monitor.update_peer(peer_id, true, 0.9);
        monitor.update_state();
        monitor.update_state();

        let history = monitor.metrics_history();
        assert!(!history.is_empty());
    }

    #[test]
    fn test_remove_peer() {
        let monitor = NetworkStateMonitor::new();
        let peer_id = PeerId::random();

        monitor.update_peer(peer_id, true, 0.9);
        assert_eq!(monitor.peer_statuses().len(), 1);

        monitor.remove_peer(&peer_id);
        assert_eq!(monitor.peer_statuses().len(), 0);
    }

    #[test]
    fn test_health_thresholds() {
        let monitor = NetworkStateMonitor::new();
        let thresholds = HealthThresholds {
            min_healthy_peers: 5,
            max_healthy_latency_ms: 100.0,
            max_healthy_packet_loss: 0.01,
            min_healthy_success_rate: 0.95,
        };

        monitor.set_thresholds(thresholds);

        // Should be Disconnected with no peers
        assert_eq!(monitor.current_state(), NetworkState::Initializing);
    }

    #[test]
    fn test_stats() {
        let monitor = NetworkStateMonitor::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        monitor.update_peer(peer1, true, 0.9);
        monitor.update_peer(peer2, false, 0.5);
        monitor.record_connection_attempt(true);

        let stats = monitor.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.connected_peers, 1);
        assert_eq!(stats.connection_attempts, 1);
    }
}
