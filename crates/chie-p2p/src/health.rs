//! Connection health monitoring for P2P nodes.
//!
//! This module provides health checking for peer connections to detect
//! and handle degraded or failing connections proactively.

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Health status of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Connection is healthy.
    Healthy,
    /// Connection is degraded (high latency or packet loss).
    Degraded,
    /// Connection is unhealthy (failing checks).
    Unhealthy,
    /// Connection status is unknown (not enough data).
    Unknown,
}

/// Health check result for a peer.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Peer ID being checked.
    pub peer_id: PeerId,
    /// Health status.
    pub status: HealthStatus,
    /// Last successful check timestamp.
    pub last_success: Option<Instant>,
    /// Last failed check timestamp.
    pub last_failure: Option<Instant>,
    /// Consecutive failures.
    pub consecutive_failures: u32,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<f64>,
    /// Packet loss percentage (0-100).
    pub packet_loss_percent: Option<f64>,
}

/// Configuration for health monitoring.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between health checks.
    pub check_interval: Duration,
    /// Timeout for a single health check.
    pub check_timeout: Duration,
    /// Maximum consecutive failures before marking unhealthy.
    pub max_consecutive_failures: u32,
    /// Latency threshold for degraded status (ms).
    pub degraded_latency_threshold_ms: f64,
    /// Latency threshold for unhealthy status (ms).
    pub unhealthy_latency_threshold_ms: f64,
    /// Packet loss threshold for degraded status (%).
    pub degraded_packet_loss_threshold: f64,
    /// Packet loss threshold for unhealthy status (%).
    pub unhealthy_packet_loss_threshold: f64,
    /// Minimum checks required before determining status.
    pub min_checks_for_status: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(10),
            check_timeout: Duration::from_secs(5),
            max_consecutive_failures: 3,
            degraded_latency_threshold_ms: 500.0,
            unhealthy_latency_threshold_ms: 2000.0,
            degraded_packet_loss_threshold: 5.0,
            unhealthy_packet_loss_threshold: 20.0,
            min_checks_for_status: 3,
        }
    }
}

/// Health monitor for tracking peer connection health.
pub struct HealthMonitor {
    config: HealthConfig,
    peer_health: HashMap<PeerId, HealthCheck>,
    peer_stats: HashMap<PeerId, PeerHealthStats>,
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new(HealthConfig::default())
    }
}

/// Statistics for health monitoring.
#[derive(Debug, Clone)]
struct PeerHealthStats {
    checks_performed: u32,
    successful_checks: u32,
    failed_checks: u32,
    latency_samples: Vec<f64>,
    last_check: Option<Instant>,
}

impl PeerHealthStats {
    fn new() -> Self {
        Self {
            checks_performed: 0,
            successful_checks: 0,
            failed_checks: 0,
            latency_samples: Vec::new(),
            last_check: None,
        }
    }

    fn avg_latency(&self) -> Option<f64> {
        if self.latency_samples.is_empty() {
            None
        } else {
            Some(self.latency_samples.iter().sum::<f64>() / self.latency_samples.len() as f64)
        }
    }

    fn packet_loss(&self) -> Option<f64> {
        if self.checks_performed == 0 {
            None
        } else {
            Some((self.failed_checks as f64 / self.checks_performed as f64) * 100.0)
        }
    }
}

impl HealthMonitor {
    /// Create a new health monitor with the given configuration.
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            peer_health: HashMap::new(),
            peer_stats: HashMap::new(),
        }
    }

    /// Record a successful health check for a peer.
    pub fn record_success(&mut self, peer_id: PeerId, latency_ms: f64) {
        let stats = self
            .peer_stats
            .entry(peer_id)
            .or_insert_with(PeerHealthStats::new);
        stats.checks_performed += 1;
        stats.successful_checks += 1;
        stats.latency_samples.push(latency_ms);
        stats.last_check = Some(Instant::now());

        // Keep only recent samples (last 10)
        if stats.latency_samples.len() > 10 {
            stats.latency_samples.remove(0);
        }

        // Update health data first
        {
            let health = self
                .peer_health
                .entry(peer_id)
                .or_insert_with(|| HealthCheck {
                    peer_id,
                    status: HealthStatus::Unknown,
                    last_success: None,
                    last_failure: None,
                    consecutive_failures: 0,
                    avg_latency_ms: None,
                    packet_loss_percent: None,
                });

            health.last_success = Some(Instant::now());
            health.consecutive_failures = 0;
            health.avg_latency_ms = stats.avg_latency();
            health.packet_loss_percent = stats.packet_loss();
        }

        // Compute and update status after releasing mutable borrow
        let new_status = self.determine_status(peer_id);
        if let Some(health) = self.peer_health.get_mut(&peer_id) {
            health.status = new_status;
        }

        debug!(
            "Health check success for {:?}: latency={:.2}ms, status={:?}",
            peer_id, latency_ms, new_status
        );
    }

    /// Record a failed health check for a peer.
    pub fn record_failure(&mut self, peer_id: PeerId) {
        let stats = self
            .peer_stats
            .entry(peer_id)
            .or_insert_with(PeerHealthStats::new);
        stats.checks_performed += 1;
        stats.failed_checks += 1;
        stats.last_check = Some(Instant::now());

        // Update health data first
        let consecutive = {
            let health = self
                .peer_health
                .entry(peer_id)
                .or_insert_with(|| HealthCheck {
                    peer_id,
                    status: HealthStatus::Unknown,
                    last_success: None,
                    last_failure: None,
                    consecutive_failures: 0,
                    avg_latency_ms: None,
                    packet_loss_percent: None,
                });

            health.last_failure = Some(Instant::now());
            health.consecutive_failures += 1;
            health.packet_loss_percent = stats.packet_loss();
            health.consecutive_failures
        };

        // Compute and update status after releasing mutable borrow
        let new_status = self.determine_status(peer_id);
        if let Some(health) = self.peer_health.get_mut(&peer_id) {
            health.status = new_status;
        }

        warn!(
            "Health check failure for {:?}: consecutive_failures={}, status={:?}",
            peer_id, consecutive, new_status
        );
    }

    /// Get the health status for a peer.
    pub fn get_health(&self, peer_id: &PeerId) -> HealthStatus {
        self.peer_health
            .get(peer_id)
            .map(|h| h.status)
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Get detailed health check information for a peer.
    pub fn get_health_check(&self, peer_id: &PeerId) -> Option<&HealthCheck> {
        self.peer_health.get(peer_id)
    }

    /// Get all peers with their health status.
    pub fn get_all_health(&self) -> Vec<(PeerId, HealthStatus)> {
        self.peer_health
            .iter()
            .map(|(peer, check)| (*peer, check.status))
            .collect()
    }

    /// Get peers that need health checks.
    pub fn peers_needing_check(&self) -> Vec<PeerId> {
        let now = Instant::now();
        self.peer_stats
            .iter()
            .filter(|(_, stats)| {
                stats
                    .last_check
                    .map(|last| now.duration_since(last) >= self.config.check_interval)
                    .unwrap_or(true)
            })
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Remove a peer from health monitoring.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peer_health.remove(peer_id);
        self.peer_stats.remove(peer_id);
    }

    /// Get unhealthy peers that should be disconnected.
    pub fn get_unhealthy_peers(&self) -> Vec<PeerId> {
        self.peer_health
            .iter()
            .filter(|(_, check)| check.status == HealthStatus::Unhealthy)
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Determine the health status for a peer based on metrics.
    fn determine_status(&self, peer_id: PeerId) -> HealthStatus {
        let stats = match self.peer_stats.get(&peer_id) {
            Some(s) => s,
            None => return HealthStatus::Unknown,
        };

        // Not enough data yet
        if stats.checks_performed < self.config.min_checks_for_status {
            return HealthStatus::Unknown;
        }

        let health = match self.peer_health.get(&peer_id) {
            Some(h) => h,
            None => return HealthStatus::Unknown,
        };

        // Check consecutive failures
        if health.consecutive_failures >= self.config.max_consecutive_failures {
            return HealthStatus::Unhealthy;
        }

        // Check packet loss
        if let Some(packet_loss) = stats.packet_loss() {
            if packet_loss >= self.config.unhealthy_packet_loss_threshold {
                return HealthStatus::Unhealthy;
            } else if packet_loss >= self.config.degraded_packet_loss_threshold {
                return HealthStatus::Degraded;
            }
        }

        // Check latency
        if let Some(avg_latency) = stats.avg_latency() {
            if avg_latency >= self.config.unhealthy_latency_threshold_ms {
                return HealthStatus::Unhealthy;
            } else if avg_latency >= self.config.degraded_latency_threshold_ms {
                return HealthStatus::Degraded;
            }
        }

        HealthStatus::Healthy
    }

    /// Get statistics about the health monitor.
    pub fn stats(&self) -> HealthMonitorStats {
        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;
        let mut unknown = 0;

        for check in self.peer_health.values() {
            match check.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Unhealthy => unhealthy += 1,
                HealthStatus::Unknown => unknown += 1,
            }
        }

        HealthMonitorStats {
            total_peers: self.peer_health.len(),
            healthy_peers: healthy,
            degraded_peers: degraded,
            unhealthy_peers: unhealthy,
            unknown_peers: unknown,
        }
    }
}

/// Statistics for the health monitor.
#[derive(Debug, Clone)]
pub struct HealthMonitorStats {
    /// Total number of monitored peers.
    pub total_peers: usize,
    /// Number of healthy peers.
    pub healthy_peers: usize,
    /// Number of degraded peers.
    pub degraded_peers: usize,
    /// Number of unhealthy peers.
    pub unhealthy_peers: usize,
    /// Number of peers with unknown status.
    pub unknown_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_status() {
        let monitor = HealthMonitor::default();
        let peer = PeerId::random();
        assert_eq!(monitor.get_health(&peer), HealthStatus::Unknown);
    }

    #[test]
    fn test_successful_checks() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // Record multiple successful checks
        for _ in 0..5 {
            monitor.record_success(peer, 100.0);
        }

        assert_eq!(monitor.get_health(&peer), HealthStatus::Healthy);
        let check = monitor.get_health_check(&peer).unwrap();
        assert_eq!(check.consecutive_failures, 0);
        assert!(check.avg_latency_ms.is_some());
    }

    #[test]
    fn test_degraded_by_latency() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // Record checks with high latency
        for _ in 0..5 {
            monitor.record_success(peer, 600.0); // Above degraded threshold
        }

        assert_eq!(monitor.get_health(&peer), HealthStatus::Degraded);
    }

    #[test]
    fn test_unhealthy_by_latency() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // Record checks with very high latency
        for _ in 0..5 {
            monitor.record_success(peer, 2500.0); // Above unhealthy threshold
        }

        assert_eq!(monitor.get_health(&peer), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_consecutive_failures() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // First establish some baseline
        monitor.record_success(peer, 100.0);

        // Record consecutive failures
        for _ in 0..3 {
            monitor.record_failure(peer);
        }

        assert_eq!(monitor.get_health(&peer), HealthStatus::Unhealthy);
        assert!(monitor.get_unhealthy_peers().contains(&peer));
    }

    #[test]
    fn test_recovery_from_failures() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // Cause some failures
        monitor.record_failure(peer);
        monitor.record_failure(peer);

        // Then recover with enough successes to bring packet loss below threshold
        // Need many more successes to get packet loss < 5%
        for _ in 0..40 {
            monitor.record_success(peer, 100.0);
        }

        let check = monitor.get_health_check(&peer).unwrap();
        assert_eq!(check.consecutive_failures, 0);
        // With 2 failures and 40 successes, packet loss is ~4.76%, should be Healthy
        assert_eq!(check.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_packet_loss_calculation() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        // 5 success, 5 failures = 50% packet loss
        for _ in 0..5 {
            monitor.record_success(peer, 100.0);
            monitor.record_failure(peer);
        }

        let check = monitor.get_health_check(&peer).unwrap();
        assert!(check.packet_loss_percent.is_some());
        let loss = check.packet_loss_percent.unwrap();
        assert!((loss - 50.0).abs() < 1.0); // ~50% loss
    }

    #[test]
    fn test_remove_peer() {
        let mut monitor = HealthMonitor::default();
        let peer = PeerId::random();

        monitor.record_success(peer, 100.0);
        assert!(monitor.get_health_check(&peer).is_some());

        monitor.remove_peer(&peer);
        assert!(monitor.get_health_check(&peer).is_none());
    }

    #[test]
    fn test_stats() {
        let mut monitor = HealthMonitor::default();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        // Healthy peer
        for _ in 0..5 {
            monitor.record_success(peer1, 100.0);
        }

        // Degraded peer
        for _ in 0..5 {
            monitor.record_success(peer2, 600.0);
        }

        // Unhealthy peer
        for _ in 0..5 {
            monitor.record_failure(peer3);
        }

        let stats = monitor.stats();
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.healthy_peers, 1);
        assert_eq!(stats.degraded_peers, 1);
        assert_eq!(stats.unhealthy_peers, 1);
    }
}
