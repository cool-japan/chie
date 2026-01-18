//! Bandwidth estimation for adaptive network behavior.
//!
//! This module provides bandwidth estimation to help the system adapt
//! to varying network conditions and optimize transfer strategies.

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tracing::debug;

/// Bandwidth sample from a transfer.
#[derive(Debug, Clone)]
struct BandwidthSample {
    /// When this sample was recorded.
    timestamp: Instant,
    /// Bytes transferred.
    bytes: u64,
    /// Duration of transfer.
    duration: Duration,
}

impl BandwidthSample {
    /// Calculate bandwidth in bytes per second.
    fn bandwidth_bps(&self) -> f64 {
        if self.duration.as_secs_f64() == 0.0 {
            0.0
        } else {
            self.bytes as f64 / self.duration.as_secs_f64()
        }
    }

    /// Check if sample is stale.
    fn is_stale(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.timestamp) > max_age
    }
}

/// Bandwidth estimator for a single peer.
#[derive(Debug, Clone)]
struct PeerBandwidthEstimator {
    samples: VecDeque<BandwidthSample>,
    max_samples: usize,
    sample_max_age: Duration,
}

impl PeerBandwidthEstimator {
    fn new(max_samples: usize, sample_max_age: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            max_samples,
            sample_max_age,
        }
    }

    fn add_sample(&mut self, bytes: u64, duration: Duration) {
        // Remove stale samples
        while let Some(sample) = self.samples.front() {
            if sample.is_stale(self.sample_max_age) {
                self.samples.pop_front();
            } else {
                break;
            }
        }

        // Add new sample
        self.samples.push_back(BandwidthSample {
            timestamp: Instant::now(),
            bytes,
            duration,
        });

        // Limit sample count
        if self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    /// Estimate current bandwidth using exponentially weighted moving average.
    fn estimate_ewma(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        let alpha = 0.3; // Weight for recent samples
        let mut ewma = self.samples[0].bandwidth_bps();

        for sample in self.samples.iter().skip(1) {
            let bps = sample.bandwidth_bps();
            ewma = alpha * bps + (1.0 - alpha) * ewma;
        }

        Some(ewma)
    }

    /// Calculate average bandwidth.
    fn average_bandwidth(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        let sum: f64 = self.samples.iter().map(|s| s.bandwidth_bps()).sum();
        Some(sum / self.samples.len() as f64)
    }

    /// Calculate peak bandwidth.
    fn peak_bandwidth(&self) -> Option<f64> {
        self.samples
            .iter()
            .map(|s| s.bandwidth_bps())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Calculate minimum bandwidth.
    fn min_bandwidth(&self) -> Option<f64> {
        self.samples
            .iter()
            .map(|s| s.bandwidth_bps())
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Calculate variance of bandwidth samples.
    fn variance(&self) -> Option<f64> {
        let avg = self.average_bandwidth()?;
        let sum_sq_diff: f64 = self
            .samples
            .iter()
            .map(|s| {
                let diff = s.bandwidth_bps() - avg;
                diff * diff
            })
            .sum();

        Some(sum_sq_diff / self.samples.len() as f64)
    }

    /// Calculate standard deviation.
    fn std_dev(&self) -> Option<f64> {
        self.variance().map(|v| v.sqrt())
    }

    /// Get number of samples.
    fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// Configuration for bandwidth estimation.
#[derive(Debug, Clone)]
pub struct BandwidthEstimatorConfig {
    /// Maximum number of samples to keep per peer.
    pub max_samples: usize,
    /// Maximum age of samples.
    pub sample_max_age: Duration,
}

impl Default for BandwidthEstimatorConfig {
    fn default() -> Self {
        Self {
            max_samples: 20,
            sample_max_age: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Bandwidth estimator manager for all peers.
pub struct BandwidthEstimatorManager {
    config: BandwidthEstimatorConfig,
    estimators: HashMap<PeerId, PeerBandwidthEstimator>,
}

impl Default for BandwidthEstimatorManager {
    fn default() -> Self {
        Self::new(BandwidthEstimatorConfig::default())
    }
}

impl BandwidthEstimatorManager {
    /// Create a new bandwidth estimator manager.
    pub fn new(config: BandwidthEstimatorConfig) -> Self {
        Self {
            config,
            estimators: HashMap::new(),
        }
    }

    /// Record a transfer for bandwidth estimation.
    pub fn record_transfer(&mut self, peer_id: &PeerId, bytes: u64, duration: Duration) {
        let estimator = self.estimators.entry(*peer_id).or_insert_with(|| {
            PeerBandwidthEstimator::new(self.config.max_samples, self.config.sample_max_age)
        });

        estimator.add_sample(bytes, duration);

        debug!(
            "Recorded transfer: peer={:?}, bytes={}, duration={:?}, est_bw={:.2} KB/s",
            peer_id,
            bytes,
            duration,
            estimator.estimate_ewma().unwrap_or(0.0) / 1024.0
        );
    }

    /// Get estimated bandwidth for a peer in bytes per second.
    pub fn estimate_bandwidth(&self, peer_id: &PeerId) -> Option<f64> {
        self.estimators.get(peer_id)?.estimate_ewma()
    }

    /// Get bandwidth estimate in Mbps.
    pub fn estimate_bandwidth_mbps(&self, peer_id: &PeerId) -> Option<f64> {
        self.estimate_bandwidth(peer_id)
            .map(|bps| bps * 8.0 / 1_000_000.0)
    }

    /// Get detailed bandwidth statistics for a peer.
    pub fn get_stats(&self, peer_id: &PeerId) -> Option<BandwidthStats> {
        let estimator = self.estimators.get(peer_id)?;

        Some(BandwidthStats {
            current_estimate_bps: estimator.estimate_ewma(),
            average_bps: estimator.average_bandwidth(),
            peak_bps: estimator.peak_bandwidth(),
            min_bps: estimator.min_bandwidth(),
            std_dev_bps: estimator.std_dev(),
            sample_count: estimator.sample_count(),
        })
    }

    /// Get estimated bandwidth for all peers.
    pub fn get_all_estimates(&self) -> HashMap<PeerId, f64> {
        self.estimators
            .iter()
            .filter_map(|(peer_id, estimator)| estimator.estimate_ewma().map(|bw| (*peer_id, bw)))
            .collect()
    }

    /// Get top N peers by bandwidth.
    pub fn get_top_peers(&self, n: usize) -> Vec<(PeerId, f64)> {
        let mut peers: Vec<_> = self.get_all_estimates().into_iter().collect();
        peers.sort_by(|(_, bw1), (_, bw2)| {
            bw2.partial_cmp(bw1).unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().take(n).collect()
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.estimators.remove(peer_id);
    }

    /// Get total number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.estimators.len()
    }

    /// Clear all estimators.
    pub fn clear(&mut self) {
        self.estimators.clear();
    }

    /// Cleanup stale data for all peers.
    pub fn cleanup(&mut self) {
        for estimator in self.estimators.values_mut() {
            while let Some(sample) = estimator.samples.front() {
                if sample.is_stale(self.config.sample_max_age) {
                    estimator.samples.pop_front();
                } else {
                    break;
                }
            }
        }

        // Remove peers with no samples
        self.estimators
            .retain(|_, estimator| !estimator.samples.is_empty());
    }
}

/// Bandwidth statistics for a peer.
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    /// Current bandwidth estimate (EWMA) in bytes per second.
    pub current_estimate_bps: Option<f64>,
    /// Average bandwidth in bytes per second.
    pub average_bps: Option<f64>,
    /// Peak bandwidth in bytes per second.
    pub peak_bps: Option<f64>,
    /// Minimum bandwidth in bytes per second.
    pub min_bps: Option<f64>,
    /// Standard deviation in bytes per second.
    pub std_dev_bps: Option<f64>,
    /// Number of samples collected.
    pub sample_count: usize,
}

impl BandwidthStats {
    /// Convert to human-readable format.
    pub fn to_human_readable(&self) -> String {
        format!(
            "Current: {:.2} Mbps, Avg: {:.2} Mbps, Peak: {:.2} Mbps, Samples: {}",
            self.current_estimate_bps.unwrap_or(0.0) * 8.0 / 1_000_000.0,
            self.average_bps.unwrap_or(0.0) * 8.0 / 1_000_000.0,
            self.peak_bps.unwrap_or(0.0) * 8.0 / 1_000_000.0,
            self.sample_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_sample() {
        let sample = BandwidthSample {
            timestamp: Instant::now(),
            bytes: 1_000_000, // 1 MB
            duration: Duration::from_secs(1),
        };

        assert_eq!(sample.bandwidth_bps(), 1_000_000.0);
    }

    #[test]
    fn test_add_sample() {
        let config = BandwidthEstimatorConfig::default();
        let mut estimator = PeerBandwidthEstimator::new(config.max_samples, config.sample_max_age);

        estimator.add_sample(1_000_000, Duration::from_secs(1));
        assert_eq!(estimator.sample_count(), 1);
        assert!(estimator.estimate_ewma().is_some());
    }

    #[test]
    fn test_max_samples_limit() {
        let config = BandwidthEstimatorConfig {
            max_samples: 5,
            ..Default::default()
        };
        let mut estimator = PeerBandwidthEstimator::new(config.max_samples, config.sample_max_age);

        for _ in 0..10 {
            estimator.add_sample(1_000_000, Duration::from_secs(1));
        }

        assert_eq!(estimator.sample_count(), 5);
    }

    #[test]
    fn test_bandwidth_estimation() {
        let mut manager = BandwidthEstimatorManager::default();
        let peer = PeerId::random();

        // Record some transfers
        manager.record_transfer(&peer, 1_000_000, Duration::from_secs(1)); // 1 MB/s
        manager.record_transfer(&peer, 2_000_000, Duration::from_secs(1)); // 2 MB/s

        let bw = manager.estimate_bandwidth(&peer).unwrap();
        assert!(bw > 1_000_000.0); // Should be between 1 and 2 MB/s
        assert!(bw < 2_000_000.0);
    }

    #[test]
    fn test_bandwidth_stats() {
        let mut manager = BandwidthEstimatorManager::default();
        let peer = PeerId::random();

        manager.record_transfer(&peer, 1_000_000, Duration::from_secs(1));
        manager.record_transfer(&peer, 2_000_000, Duration::from_secs(1));
        manager.record_transfer(&peer, 3_000_000, Duration::from_secs(1));

        let stats = manager.get_stats(&peer).unwrap();
        assert!(stats.current_estimate_bps.is_some());
        assert!(stats.average_bps.is_some());
        assert!(stats.peak_bps.is_some());
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.peak_bps.unwrap(), 3_000_000.0);
    }

    #[test]
    fn test_mbps_conversion() {
        let mut manager = BandwidthEstimatorManager::default();
        let peer = PeerId::random();

        manager.record_transfer(&peer, 1_000_000, Duration::from_secs(1)); // 1 MB/s = 8 Mbps

        let mbps = manager.estimate_bandwidth_mbps(&peer).unwrap();
        assert!((mbps - 8.0).abs() < 0.1);
    }

    #[test]
    fn test_top_peers() {
        let mut manager = BandwidthEstimatorManager::default();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        manager.record_transfer(&peer1, 1_000_000, Duration::from_secs(1)); // 1 MB/s
        manager.record_transfer(&peer2, 3_000_000, Duration::from_secs(1)); // 3 MB/s
        manager.record_transfer(&peer3, 2_000_000, Duration::from_secs(1)); // 2 MB/s

        let top = manager.get_top_peers(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, peer2); // Highest bandwidth
        assert_eq!(top[1].0, peer3); // Second highest
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = BandwidthEstimatorManager::default();
        let peer = PeerId::random();

        manager.record_transfer(&peer, 1_000_000, Duration::from_secs(1));
        assert_eq!(manager.peer_count(), 1);

        manager.remove_peer(&peer);
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_variance_and_std_dev() {
        let config = BandwidthEstimatorConfig::default();
        let mut estimator = PeerBandwidthEstimator::new(config.max_samples, config.sample_max_age);

        // Add samples with known variance
        estimator.add_sample(1_000_000, Duration::from_secs(1)); // 1 MB/s
        estimator.add_sample(1_000_000, Duration::from_secs(1)); // 1 MB/s
        estimator.add_sample(1_000_000, Duration::from_secs(1)); // 1 MB/s

        let variance = estimator.variance().unwrap();
        assert!(variance < 0.01); // Should be very low for constant values

        let std_dev = estimator.std_dev().unwrap();
        assert!(std_dev < 0.1);
    }

    #[test]
    fn test_cleanup() {
        let config = BandwidthEstimatorConfig {
            max_samples: 10,
            sample_max_age: Duration::from_millis(100),
        };
        let mut manager = BandwidthEstimatorManager::new(config);
        let peer = PeerId::random();

        manager.record_transfer(&peer, 1_000_000, Duration::from_secs(1));
        assert_eq!(manager.peer_count(), 1);

        // Wait for samples to become stale
        std::thread::sleep(Duration::from_millis(150));

        manager.cleanup();
        assert_eq!(manager.peer_count(), 0); // Peer removed due to no valid samples
    }

    #[test]
    fn test_human_readable_stats() {
        let stats = BandwidthStats {
            current_estimate_bps: Some(8_000_000.0), // 64 Mbps
            average_bps: Some(6_000_000.0),          // 48 Mbps
            peak_bps: Some(10_000_000.0),            // 80 Mbps
            min_bps: Some(4_000_000.0),
            std_dev_bps: Some(1_000_000.0),
            sample_count: 10,
        };

        let readable = stats.to_human_readable();
        assert!(readable.contains("64"));
        assert!(readable.contains("48"));
        assert!(readable.contains("80"));
        assert!(readable.contains("10"));
    }
}
