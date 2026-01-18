//! Network diagnostics and monitoring utilities.
//!
//! This module provides tools for monitoring network health, measuring latency,
//! detecting connectivity issues, and tracking network quality metrics.
//!
//! # Features
//!
//! - Latency measurement and tracking
//! - Connection quality monitoring
//! - Packet loss estimation
//! - Bandwidth estimation
//! - Network health scoring
//!
//! # Example
//!
//! ```
//! use chie_core::network_diag::{NetworkMonitor, ConnectionQuality};
//!
//! let mut monitor = NetworkMonitor::new();
//!
//! // Record latency measurements
//! monitor.record_latency("peer1".to_string(), 50);
//! monitor.record_latency("peer1".to_string(), 55);
//!
//! // Get connection quality
//! let quality = monitor.get_quality("peer1");
//! println!("Connection quality: {:?}", quality);
//!
//! // Get health score
//! let score = monitor.health_score("peer1");
//! println!("Health score: {:.2}", score);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Connection quality levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionQuality {
    /// Excellent connection (latency < 50ms).
    Excellent,
    /// Good connection (latency 50-150ms).
    Good,
    /// Fair connection (latency 150-300ms).
    Fair,
    /// Poor connection (latency 300-500ms).
    Poor,
    /// Very poor connection (latency > 500ms).
    VeryPoor,
}

impl ConnectionQuality {
    /// Get connection quality from latency.
    #[must_use]
    pub const fn from_latency(latency_ms: u64) -> Self {
        if latency_ms < 50 {
            Self::Excellent
        } else if latency_ms < 150 {
            Self::Good
        } else if latency_ms < 300 {
            Self::Fair
        } else if latency_ms < 500 {
            Self::Poor
        } else {
            Self::VeryPoor
        }
    }

    /// Get health score (0.0 to 1.0).
    #[must_use]
    pub const fn health_score(&self) -> f64 {
        match self {
            Self::Excellent => 1.0,
            Self::Good => 0.8,
            Self::Fair => 0.6,
            Self::Poor => 0.4,
            Self::VeryPoor => 0.2,
        }
    }
}

/// Network statistics for a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Peer ID.
    pub peer_id: String,

    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,

    /// Minimum latency observed.
    pub min_latency_ms: u64,

    /// Maximum latency observed.
    pub max_latency_ms: u64,

    /// Latency standard deviation.
    pub latency_stddev: f64,

    /// Total measurements.
    pub sample_count: u64,

    /// Estimated packet loss rate (0.0 to 1.0).
    pub packet_loss_rate: f64,

    /// Estimated bandwidth in bytes/sec.
    pub estimated_bandwidth_bps: f64,

    /// Connection quality.
    pub quality: ConnectionQuality,

    /// Last measurement timestamp.
    pub last_update: SystemTime,
}

impl NetworkStats {
    /// Create new network statistics.
    fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            avg_latency_ms: 0.0,
            min_latency_ms: u64::MAX,
            max_latency_ms: 0,
            latency_stddev: 0.0,
            sample_count: 0,
            packet_loss_rate: 0.0,
            estimated_bandwidth_bps: 0.0,
            quality: ConnectionQuality::Good,
            last_update: SystemTime::now(),
        }
    }

    /// Calculate health score (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn health_score(&self) -> f64 {
        let latency_score = self.quality.health_score();
        let packet_loss_penalty = self.packet_loss_rate;
        let stability_score = if self.sample_count > 10 {
            1.0 - (self.latency_stddev / 100.0).min(1.0)
        } else {
            0.5
        };

        (latency_score * 0.5 + (1.0 - packet_loss_penalty) * 0.3 + stability_score * 0.2)
            .clamp(0.0, 1.0)
    }

    /// Check if connection is stable.
    #[must_use]
    #[inline]
    pub const fn is_stable(&self) -> bool {
        self.latency_stddev < 50.0 && self.packet_loss_rate < 0.05
    }

    /// Check if connection is healthy.
    #[must_use]
    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.health_score() >= 0.6
    }
}

/// Network monitor for tracking connection health.
pub struct NetworkMonitor {
    /// Per-peer statistics.
    stats: HashMap<String, NetworkStats>,

    /// Maximum history size per peer.
    max_history: usize,

    /// Latency history for variance calculation.
    latency_history: HashMap<String, Vec<u64>>,
}

impl NetworkMonitor {
    /// Create a new network monitor.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::with_history_size(100)
    }

    /// Create a network monitor with custom history size.
    #[must_use]
    #[inline]
    pub fn with_history_size(max_history: usize) -> Self {
        Self {
            stats: HashMap::new(),
            max_history,
            latency_history: HashMap::new(),
        }
    }

    /// Record a latency measurement.
    pub fn record_latency(&mut self, peer_id: String, latency_ms: u64) {
        let stats = self
            .stats
            .entry(peer_id.clone())
            .or_insert_with(|| NetworkStats::new(peer_id.clone()));

        // Update basic stats
        stats.sample_count += 1;
        stats.min_latency_ms = stats.min_latency_ms.min(latency_ms);
        stats.max_latency_ms = stats.max_latency_ms.max(latency_ms);
        stats.last_update = SystemTime::now();

        // Update moving average
        let alpha = 0.3;
        if stats.sample_count == 1 {
            stats.avg_latency_ms = latency_ms as f64;
        } else {
            stats.avg_latency_ms = alpha * latency_ms as f64 + (1.0 - alpha) * stats.avg_latency_ms;
        }

        // Update quality
        stats.quality = ConnectionQuality::from_latency(stats.avg_latency_ms as u64);

        // Update history for variance calculation
        let history = self.latency_history.entry(peer_id).or_default();
        history.push(latency_ms);
        if history.len() > self.max_history {
            history.remove(0);
        }

        // Calculate standard deviation
        if history.len() > 1 {
            let mean = history.iter().sum::<u64>() as f64 / history.len() as f64;
            let variance = history
                .iter()
                .map(|&x| {
                    let diff = x as f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / history.len() as f64;
            stats.latency_stddev = variance.sqrt();
        }
    }

    /// Record bandwidth measurement.
    pub fn record_bandwidth(&mut self, peer_id: &str, bytes_per_sec: f64) {
        if let Some(stats) = self.stats.get_mut(peer_id) {
            // Update moving average
            let alpha = 0.2;
            if stats.estimated_bandwidth_bps == 0.0 {
                stats.estimated_bandwidth_bps = bytes_per_sec;
            } else {
                stats.estimated_bandwidth_bps =
                    alpha * bytes_per_sec + (1.0 - alpha) * stats.estimated_bandwidth_bps;
            }
        }
    }

    /// Record packet loss event.
    pub fn record_packet_loss(&mut self, peer_id: &str, lost_packets: u64, total_packets: u64) {
        if let Some(stats) = self.stats.get_mut(peer_id) {
            let loss_rate = lost_packets as f64 / total_packets as f64;

            // Update moving average
            let alpha = 0.3;
            stats.packet_loss_rate = alpha * loss_rate + (1.0 - alpha) * stats.packet_loss_rate;
        }
    }

    /// Get network statistics for a peer.
    #[must_use]
    #[inline]
    pub fn get_stats(&self, peer_id: &str) -> Option<&NetworkStats> {
        self.stats.get(peer_id)
    }

    /// Get connection quality for a peer.
    #[must_use]
    #[inline]
    pub fn get_quality(&self, peer_id: &str) -> ConnectionQuality {
        self.stats
            .get(peer_id)
            .map(|s| s.quality)
            .unwrap_or(ConnectionQuality::Good)
    }

    /// Get health score for a peer.
    #[must_use]
    #[inline]
    pub fn health_score(&self, peer_id: &str) -> f64 {
        self.stats
            .get(peer_id)
            .map(|s| s.health_score())
            .unwrap_or(0.5)
    }

    /// Get all healthy peers.
    #[must_use]
    #[inline]
    pub fn get_healthy_peers(&self) -> Vec<String> {
        self.stats
            .values()
            .filter(|s| s.is_healthy())
            .map(|s| s.peer_id.clone())
            .collect()
    }

    /// Get peers with excellent connections.
    #[must_use]
    #[inline]
    pub fn get_excellent_peers(&self) -> Vec<String> {
        self.stats
            .values()
            .filter(|s| s.quality == ConnectionQuality::Excellent)
            .map(|s| s.peer_id.clone())
            .collect()
    }

    /// Get average network health across all peers.
    #[must_use]
    #[inline]
    pub fn average_health(&self) -> f64 {
        if self.stats.is_empty() {
            return 0.5;
        }

        let sum: f64 = self.stats.values().map(|s| s.health_score()).sum();
        sum / self.stats.len() as f64
    }

    /// Clean up old peer statistics.
    pub fn cleanup_old_peers(&mut self, max_age_secs: u64) {
        let now = SystemTime::now();
        self.stats.retain(|peer_id, stats| {
            let age = now
                .duration_since(stats.last_update)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            if age >= max_age_secs {
                self.latency_history.remove(peer_id);
                false
            } else {
                true
            }
        });
    }

    /// Get total number of monitored peers.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.stats.len()
    }

    /// Get all peer IDs.
    #[must_use]
    #[inline]
    pub fn get_all_peer_ids(&self) -> Vec<String> {
        self.stats.keys().cloned().collect()
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_quality_from_latency() {
        assert_eq!(
            ConnectionQuality::from_latency(30),
            ConnectionQuality::Excellent
        );
        assert_eq!(
            ConnectionQuality::from_latency(100),
            ConnectionQuality::Good
        );
        assert_eq!(
            ConnectionQuality::from_latency(200),
            ConnectionQuality::Fair
        );
        assert_eq!(
            ConnectionQuality::from_latency(400),
            ConnectionQuality::Poor
        );
        assert_eq!(
            ConnectionQuality::from_latency(600),
            ConnectionQuality::VeryPoor
        );
    }

    #[test]
    fn test_connection_quality_health_score() {
        assert_eq!(ConnectionQuality::Excellent.health_score(), 1.0);
        assert_eq!(ConnectionQuality::Good.health_score(), 0.8);
        assert_eq!(ConnectionQuality::Fair.health_score(), 0.6);
        assert_eq!(ConnectionQuality::Poor.health_score(), 0.4);
        assert_eq!(ConnectionQuality::VeryPoor.health_score(), 0.2);
    }

    #[test]
    fn test_network_monitor_basic() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 50);
        monitor.record_latency("peer1".to_string(), 55);
        monitor.record_latency("peer1".to_string(), 45);

        let stats = monitor.get_stats("peer1").unwrap();
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.min_latency_ms, 45);
        assert_eq!(stats.max_latency_ms, 55);
    }

    #[test]
    fn test_network_monitor_quality() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 30);
        assert_eq!(monitor.get_quality("peer1"), ConnectionQuality::Excellent);

        monitor.record_latency("peer2".to_string(), 200);
        assert_eq!(monitor.get_quality("peer2"), ConnectionQuality::Fair);
    }

    #[test]
    fn test_bandwidth_tracking() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 50);
        monitor.record_bandwidth("peer1", 1_000_000.0);
        monitor.record_bandwidth("peer1", 1_500_000.0);

        let stats = monitor.get_stats("peer1").unwrap();
        assert!(stats.estimated_bandwidth_bps > 0.0);
    }

    #[test]
    fn test_packet_loss() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 50);
        monitor.record_packet_loss("peer1", 5, 100); // 5% loss

        let stats = monitor.get_stats("peer1").unwrap();
        assert!(stats.packet_loss_rate > 0.0);
    }

    #[test]
    fn test_health_score() {
        let mut monitor = NetworkMonitor::new();

        // Excellent connection
        for _ in 0..10 {
            monitor.record_latency("peer1".to_string(), 40);
        }

        let score = monitor.health_score("peer1");
        assert!(score > 0.8);
    }

    #[test]
    fn test_get_healthy_peers() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 40);
        monitor.record_latency("peer2".to_string(), 600);
        monitor.record_latency("peer3".to_string(), 80);

        let healthy = monitor.get_healthy_peers();
        assert!(healthy.contains(&"peer1".to_string()));
        assert!(healthy.contains(&"peer3".to_string()));
    }

    #[test]
    fn test_get_excellent_peers() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 30);
        monitor.record_latency("peer2".to_string(), 100);

        let excellent = monitor.get_excellent_peers();
        assert_eq!(excellent.len(), 1);
        assert_eq!(excellent[0], "peer1");
    }

    #[test]
    fn test_average_health() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 40);
        monitor.record_latency("peer2".to_string(), 150);

        let avg = monitor.average_health();
        assert!(avg > 0.5 && avg < 1.0);
    }

    #[test]
    fn test_cleanup_old_peers() {
        let mut monitor = NetworkMonitor::new();

        monitor.record_latency("peer1".to_string(), 50);
        assert_eq!(monitor.peer_count(), 1);

        monitor.cleanup_old_peers(0);
        assert_eq!(monitor.peer_count(), 0);
    }

    #[test]
    fn test_network_stats_stability() {
        let mut monitor = NetworkMonitor::new();

        // Stable connection
        for _ in 0..20 {
            monitor.record_latency("peer1".to_string(), 50);
        }

        let stats = monitor.get_stats("peer1").unwrap();
        assert!(stats.is_stable());

        // Unstable connection
        for i in 0..20 {
            monitor.record_latency("peer2".to_string(), 50 + (i * 20));
        }

        let stats2 = monitor.get_stats("peer2").unwrap();
        assert!(!stats2.is_stable());
    }
}
