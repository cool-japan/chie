//! Network diagnostics for real-time network quality measurement.
//!
//! This module provides comprehensive network quality metrics including latency,
//! jitter, packet loss, and bandwidth stability. Essential for making informed
//! routing and peer selection decisions in P2P networks.
//!
//! # Example
//!
//! ```
//! use chie_p2p::network_diagnostics::{NetworkDiagnostics, DiagnosticsConfig};
//! use std::time::Duration;
//!
//! let config = DiagnosticsConfig {
//!     ping_interval: Duration::from_secs(5),
//!     max_samples: 100,
//!     ..Default::default()
//! };
//!
//! let mut diagnostics = NetworkDiagnostics::with_config(config);
//!
//! // Record ping results
//! diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
//! diagnostics.record_ping("peer-1", Duration::from_millis(52), true);
//! diagnostics.record_ping("peer-1", Duration::from_millis(0), false); // Timeout
//!
//! // Get quality metrics
//! if let Some(quality) = diagnostics.get_quality("peer-1") {
//!     println!("Latency: {}ms, Jitter: {}ms, Loss: {:.2}%",
//!         quality.avg_latency.as_millis(),
//!         quality.jitter.as_millis(),
//!         quality.packet_loss_rate * 100.0);
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Configuration for network diagnostics
#[derive(Debug, Clone)]
pub struct DiagnosticsConfig {
    /// Interval between ping measurements
    pub ping_interval: Duration,
    /// Maximum number of samples to keep per peer
    pub max_samples: usize,
    /// Timeout for considering a ping failed
    pub ping_timeout: Duration,
    /// Minimum samples required for quality calculation
    pub min_samples: usize,
    /// Time window for quality assessment
    pub quality_window: Duration,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(5),
            max_samples: 100,
            ping_timeout: Duration::from_secs(5),
            min_samples: 5,
            quality_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Network quality classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkQuality {
    /// Excellent quality (< 50ms, < 1% loss)
    Excellent,
    /// Good quality (< 100ms, < 5% loss)
    Good,
    /// Fair quality (< 200ms, < 10% loss)
    Fair,
    /// Poor quality (< 500ms, < 20% loss)
    Poor,
    /// Very poor quality (>= 500ms or >= 20% loss)
    VeryPoor,
}

/// Ping measurement record
#[derive(Debug, Clone)]
struct PingRecord {
    timestamp: Instant,
    latency: Duration,
    success: bool,
}

/// Network quality metrics for a peer
#[derive(Debug, Clone)]
pub struct QualityMetrics {
    /// Average latency
    pub avg_latency: Duration,
    /// Minimum latency observed
    pub min_latency: Duration,
    /// Maximum latency observed
    pub max_latency: Duration,
    /// Jitter (variance in latency)
    pub jitter: Duration,
    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss_rate: f64,
    /// Network quality classification
    pub quality: NetworkQuality,
    /// Number of samples used for calculation
    pub sample_count: usize,
    /// Last measurement timestamp
    pub last_measured: Instant,
}

/// Peer diagnostics data
struct PeerDiagnostics {
    #[allow(dead_code)]
    peer_id: String,
    ping_history: VecDeque<PingRecord>,
    last_ping: Instant,
    total_pings: u64,
    successful_pings: u64,
}

/// Network diagnostics manager
pub struct NetworkDiagnostics {
    config: DiagnosticsConfig,
    peers: HashMap<String, PeerDiagnostics>,
}

impl NetworkDiagnostics {
    /// Creates a new network diagnostics manager with default configuration
    pub fn new() -> Self {
        Self::with_config(DiagnosticsConfig::default())
    }

    /// Creates a new network diagnostics manager with custom configuration
    pub fn with_config(config: DiagnosticsConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Records a ping result for a peer
    pub fn record_ping(&mut self, peer_id: impl Into<String>, latency: Duration, success: bool) {
        let peer_id = peer_id.into();
        let now = Instant::now();

        let peer_diag = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerDiagnostics {
                peer_id: peer_id.clone(),
                ping_history: VecDeque::new(),
                last_ping: now,
                total_pings: 0,
                successful_pings: 0,
            });

        peer_diag.ping_history.push_back(PingRecord {
            timestamp: now,
            latency,
            success,
        });

        peer_diag.last_ping = now;
        peer_diag.total_pings += 1;
        if success {
            peer_diag.successful_pings += 1;
        }

        // Limit history size
        while peer_diag.ping_history.len() > self.config.max_samples {
            peer_diag.ping_history.pop_front();
        }

        // Cleanup old records (must be done after releasing the borrow)
        let cutoff = now - self.config.quality_window;
        while let Some(record) = peer_diag.ping_history.front() {
            if record.timestamp < cutoff {
                peer_diag.ping_history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Gets quality metrics for a peer
    pub fn get_quality(&self, peer_id: &str) -> Option<QualityMetrics> {
        let peer_diag = self.peers.get(peer_id)?;

        if peer_diag.ping_history.len() < self.config.min_samples {
            return None;
        }

        let successful_pings: Vec<Duration> = peer_diag
            .ping_history
            .iter()
            .filter(|p| p.success)
            .map(|p| p.latency)
            .collect();

        if successful_pings.is_empty() {
            return Some(QualityMetrics {
                avg_latency: Duration::from_secs(0),
                min_latency: Duration::from_secs(0),
                max_latency: Duration::from_secs(0),
                jitter: Duration::from_secs(0),
                packet_loss_rate: 1.0,
                quality: NetworkQuality::VeryPoor,
                sample_count: peer_diag.ping_history.len(),
                last_measured: peer_diag.last_ping,
            });
        }

        let avg_latency = self.calculate_average(&successful_pings);
        let min_latency = *successful_pings.iter().min().unwrap();
        let max_latency = *successful_pings.iter().max().unwrap();
        let jitter = self.calculate_jitter(&successful_pings, avg_latency);

        let packet_loss_rate =
            1.0 - (successful_pings.len() as f64 / peer_diag.ping_history.len() as f64);

        let quality = self.classify_quality(avg_latency, packet_loss_rate);

        Some(QualityMetrics {
            avg_latency,
            min_latency,
            max_latency,
            jitter,
            packet_loss_rate,
            quality,
            sample_count: peer_diag.ping_history.len(),
            last_measured: peer_diag.last_ping,
        })
    }

    /// Checks if a peer needs a ping (based on interval)
    pub fn needs_ping(&self, peer_id: &str) -> bool {
        if let Some(peer_diag) = self.peers.get(peer_id) {
            let elapsed = Instant::now().duration_since(peer_diag.last_ping);
            elapsed >= self.config.ping_interval
        } else {
            true // New peer, needs initial ping
        }
    }

    /// Gets all peers with quality metrics
    pub fn get_all_qualities(&self) -> Vec<(String, QualityMetrics)> {
        self.peers
            .keys()
            .filter_map(|peer_id| {
                self.get_quality(peer_id)
                    .map(|quality| (peer_id.clone(), quality))
            })
            .collect()
    }

    /// Gets peers sorted by quality (best first)
    pub fn get_peers_by_quality(&self) -> Vec<String> {
        let mut peers: Vec<_> = self.get_all_qualities();
        peers.sort_by(|a, b| {
            // Sort by quality (lower latency = better)
            a.1.avg_latency.cmp(&b.1.avg_latency)
        });
        peers.into_iter().map(|(id, _)| id).collect()
    }

    /// Gets statistics about diagnostics
    pub fn stats(&self) -> DiagnosticsStats {
        let total_peers = self.peers.len();
        let total_pings: u64 = self.peers.values().map(|p| p.total_pings).sum();
        let successful_pings: u64 = self.peers.values().map(|p| p.successful_pings).sum();

        let quality_distribution = self.get_quality_distribution();

        DiagnosticsStats {
            total_peers,
            total_pings,
            successful_pings,
            overall_loss_rate: if total_pings > 0 {
                1.0 - (successful_pings as f64 / total_pings as f64)
            } else {
                0.0
            },
            quality_distribution,
        }
    }

    /// Removes a peer from diagnostics
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
    }

    /// Clears all diagnostics data
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    // Private helper methods

    fn calculate_average(&self, latencies: &[Duration]) -> Duration {
        if latencies.is_empty() {
            return Duration::from_secs(0);
        }

        let sum: Duration = latencies.iter().sum();
        sum / latencies.len() as u32
    }

    fn calculate_jitter(&self, latencies: &[Duration], avg: Duration) -> Duration {
        if latencies.len() < 2 {
            return Duration::from_secs(0);
        }

        let avg_nanos = avg.as_nanos() as f64;
        let variance: f64 = latencies
            .iter()
            .map(|l| {
                let diff = l.as_nanos() as f64 - avg_nanos;
                diff * diff
            })
            .sum::<f64>()
            / latencies.len() as f64;

        Duration::from_nanos(variance.sqrt() as u64)
    }

    fn classify_quality(&self, avg_latency: Duration, packet_loss: f64) -> NetworkQuality {
        let latency_ms = avg_latency.as_millis();

        if latency_ms < 50 && packet_loss < 0.01 {
            NetworkQuality::Excellent
        } else if latency_ms < 100 && packet_loss < 0.05 {
            NetworkQuality::Good
        } else if latency_ms < 200 && packet_loss < 0.10 {
            NetworkQuality::Fair
        } else if latency_ms < 500 && packet_loss < 0.20 {
            NetworkQuality::Poor
        } else {
            NetworkQuality::VeryPoor
        }
    }

    fn get_quality_distribution(&self) -> QualityDistribution {
        let mut distribution = QualityDistribution {
            excellent: 0,
            good: 0,
            fair: 0,
            poor: 0,
            very_poor: 0,
        };

        for (_, metrics) in self.get_all_qualities() {
            match metrics.quality {
                NetworkQuality::Excellent => distribution.excellent += 1,
                NetworkQuality::Good => distribution.good += 1,
                NetworkQuality::Fair => distribution.fair += 1,
                NetworkQuality::Poor => distribution.poor += 1,
                NetworkQuality::VeryPoor => distribution.very_poor += 1,
            }
        }

        distribution
    }
}

impl Default for NetworkDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about network diagnostics
#[derive(Debug, Clone)]
pub struct DiagnosticsStats {
    pub total_peers: usize,
    pub total_pings: u64,
    pub successful_pings: u64,
    pub overall_loss_rate: f64,
    pub quality_distribution: QualityDistribution,
}

/// Distribution of network quality across peers
#[derive(Debug, Clone)]
pub struct QualityDistribution {
    pub excellent: usize,
    pub good: usize,
    pub fair: usize,
    pub poor: usize,
    pub very_poor: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_new() {
        let diagnostics = NetworkDiagnostics::new();
        assert_eq!(diagnostics.peers.len(), 0);
    }

    #[test]
    fn test_record_ping() {
        let mut diagnostics = NetworkDiagnostics::new();
        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);

        assert_eq!(diagnostics.peers.len(), 1);
        let peer = diagnostics.peers.get("peer-1").unwrap();
        assert_eq!(peer.total_pings, 1);
        assert_eq!(peer.successful_pings, 1);
    }

    #[test]
    fn test_record_failed_ping() {
        let mut diagnostics = NetworkDiagnostics::new();
        diagnostics.record_ping("peer-1", Duration::from_secs(0), false);

        let peer = diagnostics.peers.get("peer-1").unwrap();
        assert_eq!(peer.total_pings, 1);
        assert_eq!(peer.successful_pings, 0);
    }

    #[test]
    fn test_quality_insufficient_samples() {
        let mut diagnostics = NetworkDiagnostics::new();
        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);

        // Not enough samples yet
        assert!(diagnostics.get_quality("peer-1").is_none());
    }

    #[test]
    fn test_quality_calculation() {
        let mut diagnostics = NetworkDiagnostics::new();

        // Record enough samples
        for _ in 0..10 {
            diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        }

        let quality = diagnostics.get_quality("peer-1").unwrap();
        assert_eq!(quality.avg_latency, Duration::from_millis(50));
        assert_eq!(quality.min_latency, Duration::from_millis(50));
        assert_eq!(quality.max_latency, Duration::from_millis(50));
        assert_eq!(quality.packet_loss_rate, 0.0);
        // 50ms with 0% loss should be excellent or good quality
        assert!(matches!(
            quality.quality,
            NetworkQuality::Excellent | NetworkQuality::Good
        ));
    }

    #[test]
    fn test_quality_with_loss() {
        let mut diagnostics = NetworkDiagnostics::new();

        // 7 successful, 3 failed = 30% loss
        for _ in 0..7 {
            diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        }
        for _ in 0..3 {
            diagnostics.record_ping("peer-1", Duration::from_secs(0), false);
        }

        let quality = diagnostics.get_quality("peer-1").unwrap();
        assert!((quality.packet_loss_rate - 0.3).abs() < 0.01); // Handle floating point precision
        assert_eq!(quality.quality, NetworkQuality::VeryPoor); // High loss
    }

    #[test]
    fn test_jitter_calculation() {
        let mut diagnostics = NetworkDiagnostics::new();

        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        diagnostics.record_ping("peer-1", Duration::from_millis(60), true);
        diagnostics.record_ping("peer-1", Duration::from_millis(40), true);
        diagnostics.record_ping("peer-1", Duration::from_millis(55), true);
        diagnostics.record_ping("peer-1", Duration::from_millis(45), true);

        let quality = diagnostics.get_quality("peer-1").unwrap();
        assert!(quality.jitter > Duration::from_secs(0));
    }

    #[test]
    fn test_quality_classification() {
        let diagnostics = NetworkDiagnostics::new();

        assert_eq!(
            diagnostics.classify_quality(Duration::from_millis(30), 0.005),
            NetworkQuality::Excellent
        );
        assert_eq!(
            diagnostics.classify_quality(Duration::from_millis(80), 0.03),
            NetworkQuality::Good
        );
        assert_eq!(
            diagnostics.classify_quality(Duration::from_millis(150), 0.08),
            NetworkQuality::Fair
        );
        assert_eq!(
            diagnostics.classify_quality(Duration::from_millis(300), 0.15),
            NetworkQuality::Poor
        );
        assert_eq!(
            diagnostics.classify_quality(Duration::from_millis(600), 0.05),
            NetworkQuality::VeryPoor
        );
    }

    #[test]
    fn test_needs_ping() {
        let mut diagnostics = NetworkDiagnostics::new();

        // New peer needs ping
        assert!(diagnostics.needs_ping("peer-1"));

        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);

        // Just pinged, doesn't need another yet
        assert!(!diagnostics.needs_ping("peer-1"));
    }

    #[test]
    fn test_get_all_qualities() {
        let mut diagnostics = NetworkDiagnostics::new();

        for _ in 0..10 {
            diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
            diagnostics.record_ping("peer-2", Duration::from_millis(100), true);
        }

        let qualities = diagnostics.get_all_qualities();
        assert_eq!(qualities.len(), 2);
    }

    #[test]
    fn test_get_peers_by_quality() {
        let mut diagnostics = NetworkDiagnostics::new();

        for _ in 0..10 {
            diagnostics.record_ping("peer-slow", Duration::from_millis(200), true);
            diagnostics.record_ping("peer-fast", Duration::from_millis(50), true);
        }

        let sorted = diagnostics.get_peers_by_quality();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0], "peer-fast"); // Better quality comes first
    }

    #[test]
    fn test_stats() {
        let mut diagnostics = NetworkDiagnostics::new();

        for _ in 0..10 {
            diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        }

        let stats = diagnostics.stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.total_pings, 10);
        assert_eq!(stats.successful_pings, 10);
        assert_eq!(stats.overall_loss_rate, 0.0);
    }

    #[test]
    fn test_remove_peer() {
        let mut diagnostics = NetworkDiagnostics::new();

        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        assert_eq!(diagnostics.peers.len(), 1);

        diagnostics.remove_peer("peer-1");
        assert_eq!(diagnostics.peers.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut diagnostics = NetworkDiagnostics::new();

        diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        diagnostics.record_ping("peer-2", Duration::from_millis(60), true);

        diagnostics.clear();
        assert_eq!(diagnostics.peers.len(), 0);
    }

    #[test]
    fn test_max_samples_limit() {
        let config = DiagnosticsConfig {
            max_samples: 5,
            ..Default::default()
        };
        let mut diagnostics = NetworkDiagnostics::with_config(config);

        for _ in 0..10 {
            diagnostics.record_ping("peer-1", Duration::from_millis(50), true);
        }

        let peer = diagnostics.peers.get("peer-1").unwrap();
        assert_eq!(peer.ping_history.len(), 5);
    }

    #[test]
    fn test_quality_distribution() {
        let mut diagnostics = NetworkDiagnostics::new();

        // Excellent peer
        for _ in 0..10 {
            diagnostics.record_ping("peer-excellent", Duration::from_millis(30), true);
        }

        // Good peer
        for _ in 0..10 {
            diagnostics.record_ping("peer-good", Duration::from_millis(80), true);
        }

        // Poor peer
        for _ in 0..10 {
            diagnostics.record_ping("peer-poor", Duration::from_millis(400), true);
        }

        let stats = diagnostics.stats();
        assert_eq!(stats.quality_distribution.excellent, 1);
        assert_eq!(stats.quality_distribution.good, 1);
        assert_eq!(stats.quality_distribution.poor, 1);
    }

    #[test]
    fn test_all_failed_pings() {
        let mut diagnostics = NetworkDiagnostics::new();

        for _ in 0..10 {
            diagnostics.record_ping("peer-1", Duration::from_secs(0), false);
        }

        let quality = diagnostics.get_quality("peer-1").unwrap();
        assert_eq!(quality.packet_loss_rate, 1.0);
        assert_eq!(quality.quality, NetworkQuality::VeryPoor);
    }
}
