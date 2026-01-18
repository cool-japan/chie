//! Bandwidth estimation and congestion detection for the CHIE protocol.
//!
//! This module provides real-time bandwidth estimation and congestion detection
//! capabilities to optimize content delivery and prevent network overload.
//!
//! # Features
//!
//! - Real-time bandwidth estimation using exponentially weighted moving averages
//! - Congestion detection through packet loss and latency variation
//! - Adaptive rate limiting based on network conditions
//! - Historical bandwidth tracking and statistics
//!
//! # Example
//!
//! ```rust
//! use chie_core::bandwidth_estimation::{BandwidthEstimator, EstimatorConfig};
//!
//! # async fn example() {
//! let config = EstimatorConfig::default();
//! let mut estimator = BandwidthEstimator::new(config);
//!
//! // Record a data transfer
//! estimator.record_transfer(1024 * 1024, 100); // 1 MB in 100ms
//!
//! // Get current estimate
//! let bandwidth_mbps = estimator.estimate_mbps();
//! println!("Estimated bandwidth: {:.2} Mbps", bandwidth_mbps);
//!
//! // Check for congestion
//! if estimator.is_congested() {
//!     println!("Network is congested, reducing rate");
//! }
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Configuration for bandwidth estimator.
#[derive(Debug, Clone)]
pub struct EstimatorConfig {
    /// Smoothing factor for EWMA (0.0 to 1.0).
    pub alpha: f64,
    /// Maximum history size for measurements.
    pub max_history: usize,
    /// Window size for congestion detection (milliseconds).
    pub congestion_window_ms: u64,
    /// Packet loss threshold for congestion (percentage).
    pub loss_threshold_percent: f64,
    /// RTT variation threshold for congestion (percentage).
    pub rtt_var_threshold_percent: f64,
    /// Minimum samples before estimation is considered reliable.
    pub min_samples: usize,
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            alpha: 0.2, // 20% weight to new samples
            max_history: 100,
            congestion_window_ms: 1000,      // 1 second window
            loss_threshold_percent: 5.0,     // 5% loss indicates congestion
            rtt_var_threshold_percent: 50.0, // 50% RTT variation
            min_samples: 5,
        }
    }
}

/// A single bandwidth measurement.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BandwidthSample {
    /// Timestamp of measurement.
    timestamp: Instant,
    /// Bytes transferred.
    bytes: u64,
    /// Duration in milliseconds.
    duration_ms: u64,
    /// Calculated bandwidth in Mbps.
    bandwidth_mbps: f64,
    /// Round-trip time in milliseconds (if available).
    rtt_ms: Option<f64>,
    /// Whether packet loss was detected.
    packet_loss: bool,
}

/// Congestion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CongestionState {
    /// No congestion detected.
    Normal,
    /// Light congestion detected.
    Light,
    /// Moderate congestion detected.
    Moderate,
    /// Heavy congestion detected.
    Heavy,
}

/// Bandwidth estimator with congestion detection.
pub struct BandwidthEstimator {
    /// Configuration.
    config: EstimatorConfig,
    /// Sample history.
    samples: VecDeque<BandwidthSample>,
    /// Current bandwidth estimate (EWMA).
    estimate_mbps: f64,
    /// Current congestion state.
    congestion_state: CongestionState,
    /// Total bytes transferred.
    total_bytes: u64,
    /// Total transfers.
    total_transfers: u64,
    /// Recent RTT measurements.
    rtt_samples: VecDeque<f64>,
    /// Packet loss count in current window.
    loss_count: u64,
    /// Total packet count in current window.
    packet_count: u64,
}

impl BandwidthEstimator {
    /// Create a new bandwidth estimator.
    #[must_use]
    #[inline]
    pub fn new(config: EstimatorConfig) -> Self {
        Self {
            config,
            samples: VecDeque::new(),
            estimate_mbps: 0.0,
            congestion_state: CongestionState::Normal,
            total_bytes: 0,
            total_transfers: 0,
            rtt_samples: VecDeque::new(),
            loss_count: 0,
            packet_count: 0,
        }
    }

    /// Record a data transfer.
    pub fn record_transfer(&mut self, bytes: u64, duration_ms: u64) {
        self.record_transfer_with_rtt(bytes, duration_ms, None, false);
    }

    /// Record a data transfer with RTT information.
    pub fn record_transfer_with_rtt(
        &mut self,
        bytes: u64,
        duration_ms: u64,
        rtt_ms: Option<f64>,
        packet_loss: bool,
    ) {
        if duration_ms == 0 {
            return;
        }

        // Calculate instantaneous bandwidth
        let bandwidth_mbps = (bytes as f64 * 8.0) / (duration_ms as f64 * 1000.0);

        let sample = BandwidthSample {
            timestamp: Instant::now(),
            bytes,
            duration_ms,
            bandwidth_mbps,
            rtt_ms,
            packet_loss,
        };

        // Update EWMA
        if self.estimate_mbps == 0.0 {
            self.estimate_mbps = bandwidth_mbps;
        } else {
            self.estimate_mbps =
                self.config.alpha * bandwidth_mbps + (1.0 - self.config.alpha) * self.estimate_mbps;
        }

        // Add to history
        self.samples.push_back(sample);
        if self.samples.len() > self.config.max_history {
            self.samples.pop_front();
        }

        // Track RTT
        if let Some(rtt) = rtt_ms {
            self.rtt_samples.push_back(rtt);
            if self.rtt_samples.len() > self.config.max_history {
                self.rtt_samples.pop_front();
            }
        }

        // Track packets
        self.packet_count += 1;
        if packet_loss {
            self.loss_count += 1;
        }

        // Update totals
        self.total_bytes += bytes;
        self.total_transfers += 1;

        // Update congestion state
        self.update_congestion_state();
    }

    /// Get current bandwidth estimate in Mbps.
    #[must_use]
    #[inline]
    pub fn estimate_mbps(&self) -> f64 {
        self.estimate_mbps
    }

    /// Get current bandwidth estimate in bytes per second.
    #[must_use]
    #[inline]
    pub fn estimate_bps(&self) -> u64 {
        (self.estimate_mbps * 125_000.0) as u64
    }

    /// Check if bandwidth estimate is reliable.
    #[must_use]
    #[inline]
    pub fn is_reliable(&self) -> bool {
        self.samples.len() >= self.config.min_samples
    }

    /// Get current congestion state.
    #[must_use]
    #[inline]
    pub const fn congestion_state(&self) -> CongestionState {
        self.congestion_state
    }

    /// Check if network is currently congested.
    #[must_use]
    #[inline]
    pub const fn is_congested(&self) -> bool {
        !matches!(self.congestion_state, CongestionState::Normal)
    }

    /// Get packet loss percentage in recent window.
    #[must_use]
    #[inline]
    pub fn packet_loss_percent(&self) -> f64 {
        if self.packet_count == 0 {
            0.0
        } else {
            (self.loss_count as f64 / self.packet_count as f64) * 100.0
        }
    }

    /// Get RTT variation (standard deviation / mean).
    #[must_use]
    #[inline]
    pub fn rtt_variation_percent(&self) -> f64 {
        if self.rtt_samples.len() < 2 {
            return 0.0;
        }

        let mean = self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64;
        let variance = self
            .rtt_samples
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / self.rtt_samples.len() as f64;

        let std_dev = variance.sqrt();
        if mean > 0.0 {
            (std_dev / mean) * 100.0
        } else {
            0.0
        }
    }

    /// Get recommended transfer rate in bytes per second.
    ///
    /// Returns a conservative rate based on current conditions.
    #[must_use]
    #[inline]
    pub fn recommended_rate_bps(&self) -> u64 {
        let base_rate = self.estimate_bps();

        // Apply congestion-based reduction
        let reduction_factor = match self.congestion_state {
            CongestionState::Normal => 1.0,
            CongestionState::Light => 0.8,    // 20% reduction
            CongestionState::Moderate => 0.5, // 50% reduction
            CongestionState::Heavy => 0.25,   // 75% reduction
        };

        (base_rate as f64 * reduction_factor) as u64
    }

    /// Get statistics about bandwidth estimation.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> BandwidthStats {
        let min_bw = self
            .samples
            .iter()
            .map(|s| s.bandwidth_mbps)
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        let max_bw = self
            .samples
            .iter()
            .map(|s| s.bandwidth_mbps)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0);

        let avg_rtt = if self.rtt_samples.is_empty() {
            None
        } else {
            Some(self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64)
        };

        BandwidthStats {
            current_estimate_mbps: self.estimate_mbps,
            min_bandwidth_mbps: min_bw,
            max_bandwidth_mbps: max_bw,
            avg_rtt_ms: avg_rtt,
            rtt_variation_percent: self.rtt_variation_percent(),
            packet_loss_percent: self.packet_loss_percent(),
            congestion_state: self.congestion_state,
            sample_count: self.samples.len(),
            is_reliable: self.is_reliable(),
            total_bytes: self.total_bytes,
            total_transfers: self.total_transfers,
        }
    }

    /// Reset the estimator.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.rtt_samples.clear();
        self.estimate_mbps = 0.0;
        self.congestion_state = CongestionState::Normal;
        self.total_bytes = 0;
        self.total_transfers = 0;
        self.loss_count = 0;
        self.packet_count = 0;
    }

    /// Prune old samples outside the congestion window.
    pub fn prune_old_samples(&mut self) {
        let cutoff = Instant::now() - Duration::from_millis(self.config.congestion_window_ms);

        while let Some(sample) = self.samples.front() {
            if sample.timestamp < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Update congestion state based on recent measurements.
    fn update_congestion_state(&mut self) {
        // Prune old samples first
        self.prune_old_samples();

        let loss_percent = self.packet_loss_percent();
        let rtt_var_percent = self.rtt_variation_percent();

        // Determine congestion state
        let loss_congested = loss_percent > self.config.loss_threshold_percent;
        let rtt_congested = rtt_var_percent > self.config.rtt_var_threshold_percent;

        self.congestion_state = if loss_percent > 15.0 || rtt_var_percent > 100.0 {
            CongestionState::Heavy
        } else if loss_percent > 10.0 || rtt_var_percent > 75.0 {
            CongestionState::Moderate
        } else if loss_congested || rtt_congested {
            CongestionState::Light
        } else {
            CongestionState::Normal
        };
    }
}

/// Bandwidth estimation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStats {
    /// Current bandwidth estimate in Mbps.
    pub current_estimate_mbps: f64,
    /// Minimum observed bandwidth in Mbps.
    pub min_bandwidth_mbps: f64,
    /// Maximum observed bandwidth in Mbps.
    pub max_bandwidth_mbps: f64,
    /// Average RTT in milliseconds.
    pub avg_rtt_ms: Option<f64>,
    /// RTT variation percentage.
    pub rtt_variation_percent: f64,
    /// Packet loss percentage.
    pub packet_loss_percent: f64,
    /// Current congestion state.
    pub congestion_state: CongestionState,
    /// Number of samples collected.
    pub sample_count: usize,
    /// Whether estimate is reliable.
    pub is_reliable: bool,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Total number of transfers.
    pub total_transfers: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_estimator() {
        let config = EstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // Record a 1 MB (decimal) transfer in 100ms
        // Using 1,000,000 bytes for decimal MB (not 1024 * 1024 for binary MiB)
        estimator.record_transfer(1_000_000, 100);

        let estimate = estimator.estimate_mbps();
        // 1 MB / 100ms = 10 MB/s = 80 Mbps
        assert!((estimate - 80.0).abs() < 1.0);
    }

    #[test]
    fn test_ewma_smoothing() {
        let config = EstimatorConfig {
            alpha: 0.5,
            ..Default::default()
        };
        let mut estimator = BandwidthEstimator::new(config);

        // First sample: 100 Mbps (12.5 MB in 1000ms = 12.5 * 8 = 100 Mbps)
        // Using decimal bytes: 100 Mbps = 12,500,000 bytes/sec = 12,500,000 bytes in 1000ms
        estimator.record_transfer(12_500_000, 1000);
        assert!((estimator.estimate_mbps() - 100.0).abs() < 1.0);

        // Second sample: 50 Mbps (6.25 MB in 1000ms)
        estimator.record_transfer(6_250_000, 1000);
        // EWMA: 0.5 * 50 + 0.5 * 100 = 75
        assert!((estimator.estimate_mbps() - 75.0).abs() < 1.0);
    }

    #[test]
    fn test_congestion_detection() {
        let config = EstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // Record transfers without packet loss
        for _ in 0..10 {
            estimator.record_transfer_with_rtt(1024 * 1024, 100, Some(50.0), false);
        }
        assert_eq!(estimator.congestion_state(), CongestionState::Normal);

        // Record transfers with packet loss
        for _ in 0..10 {
            estimator.record_transfer_with_rtt(1024 * 1024, 100, Some(50.0), true);
        }
        assert!(estimator.is_congested());
    }

    #[test]
    fn test_packet_loss_calculation() {
        let config = EstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // 3 successful, 1 failed = 25% loss
        for _ in 0..3 {
            estimator.record_transfer_with_rtt(1024, 10, None, false);
        }
        estimator.record_transfer_with_rtt(1024, 10, None, true);

        assert!((estimator.packet_loss_percent() - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_recommended_rate() {
        let config = EstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // Establish baseline
        estimator.record_transfer(1024 * 1024, 100); // 80 Mbps
        let normal_rate = estimator.recommended_rate_bps();

        // Simulate congestion
        for _ in 0..10 {
            estimator.record_transfer_with_rtt(1024 * 1024, 100, Some(50.0), true);
        }

        let congested_rate = estimator.recommended_rate_bps();
        assert!(congested_rate < normal_rate);
    }

    #[test]
    fn test_reliability() {
        let config = EstimatorConfig {
            min_samples: 3,
            ..Default::default()
        };
        let mut estimator = BandwidthEstimator::new(config);

        assert!(!estimator.is_reliable());

        estimator.record_transfer(1024, 10);
        estimator.record_transfer(1024, 10);
        assert!(!estimator.is_reliable());

        estimator.record_transfer(1024, 10);
        assert!(estimator.is_reliable());
    }

    #[test]
    fn test_reset() {
        let config = EstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        estimator.record_transfer(1024 * 1024, 100);
        assert!(estimator.estimate_mbps() > 0.0);

        estimator.reset();
        assert_eq!(estimator.estimate_mbps(), 0.0);
        assert_eq!(estimator.total_bytes, 0);
        assert_eq!(estimator.congestion_state(), CongestionState::Normal);
    }
}
