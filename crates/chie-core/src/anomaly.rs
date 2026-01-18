//! Anomaly detection module for identifying suspicious behavior and fraud.
//!
//! This module provides statistical anomaly detection to identify unusual patterns
//! in bandwidth proofs, peer behavior, and network activity. It uses multiple
//! detection strategies including z-score analysis, rate-based detection, and
//! pattern matching.
//!
//! # Example
//!
//! ```
//! use chie_core::{AnomalyDetector, DetectionConfig, BehaviorSample};
//!
//! # fn example() {
//! let config = DetectionConfig::default();
//! let mut detector = AnomalyDetector::new(config);
//!
//! // Record normal behavior
//! for i in 0..100 {
//!     detector.record_sample("peer1", BehaviorSample {
//!         value: 100.0 + (i as f64 % 10.0),
//!         timestamp: std::time::SystemTime::now(),
//!         metric_type: "bandwidth".to_string(),
//!     });
//! }
//!
//! // Check for anomaly
//! let sample = BehaviorSample {
//!     value: 500.0, // Unusual spike
//!     timestamp: std::time::SystemTime::now(),
//!     metric_type: "bandwidth".to_string(),
//! };
//!
//! if detector.is_anomalous("peer1", &sample) {
//!     println!("Anomaly detected!");
//! }
//! # }
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

/// Configuration for anomaly detection.
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Z-score threshold for anomaly (default: 3.0)
    pub z_score_threshold: f64,
    /// Minimum samples needed before detection (default: 30)
    pub min_samples: usize,
    /// Maximum samples to keep per peer (default: 1000)
    pub max_samples: usize,
    /// Time window for rate-based detection (seconds)
    pub rate_window_secs: u64,
    /// Maximum rate increase multiplier (default: 5.0)
    pub max_rate_increase: f64,
    /// Sample retention duration (seconds)
    pub retention_secs: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            min_samples: 30,
            max_samples: 1000,
            rate_window_secs: 300, // 5 minutes
            max_rate_increase: 5.0,
            retention_secs: 3600, // 1 hour
        }
    }
}

/// Sample of peer behavior for analysis.
#[derive(Debug, Clone)]
pub struct BehaviorSample {
    /// Sample value (e.g., bandwidth, latency, proof count)
    pub value: f64,
    /// Timestamp when sample was recorded
    pub timestamp: SystemTime,
    /// Type of metric
    pub metric_type: String,
}

/// Anomaly type classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyType {
    /// Statistical outlier (z-score based)
    StatisticalOutlier,
    /// Unusual rate increase
    RateAnomaly,
    /// Suspicious pattern
    PatternAnomaly,
    /// Value out of expected range
    RangeAnomaly,
}

/// Detected anomaly information.
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// Peer ID
    pub peer_id: String,
    /// Type of anomaly
    pub anomaly_type: AnomalyType,
    /// Severity score (0.0 to 1.0)
    pub severity: f64,
    /// Description
    pub description: String,
    /// Sample that triggered detection
    pub sample_value: f64,
    /// Expected value range
    pub expected_range: (f64, f64),
    /// Detection timestamp
    pub detected_at: SystemTime,
}

/// Peer behavior history.
#[derive(Debug)]
struct PeerHistory {
    samples: VecDeque<BehaviorSample>,
    anomaly_count: u64,
    last_anomaly: Option<SystemTime>,
}

impl PeerHistory {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            anomaly_count: 0,
            last_anomaly: None,
        }
    }
}

/// Anomaly detector for identifying suspicious behavior.
pub struct AnomalyDetector {
    config: DetectionConfig,
    peer_history: HashMap<String, PeerHistory>,
    detected_anomalies: Vec<Anomaly>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector.
    #[must_use]
    #[inline]
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            peer_history: HashMap::new(),
            detected_anomalies: Vec::new(),
        }
    }

    /// Record a behavior sample for a peer.
    pub fn record_sample(&mut self, peer_id: &str, sample: BehaviorSample) {
        let history = self
            .peer_history
            .entry(peer_id.to_string())
            .or_insert_with(PeerHistory::new);

        // Add sample
        history.samples.push_back(sample);

        // Enforce max samples limit
        while history.samples.len() > self.config.max_samples {
            history.samples.pop_front();
        }

        // Clean old samples
        self.cleanup_old_samples(peer_id);
    }

    /// Check if a sample is anomalous.
    #[must_use]
    pub fn is_anomalous(&mut self, peer_id: &str, sample: &BehaviorSample) -> bool {
        if let Some(anomaly) = self.detect_anomaly(peer_id, sample) {
            self.record_anomaly(anomaly);
            true
        } else {
            false
        }
    }

    /// Detect anomaly in a sample.
    fn detect_anomaly(&self, peer_id: &str, sample: &BehaviorSample) -> Option<Anomaly> {
        let history = self.peer_history.get(peer_id)?;

        if history.samples.len() < self.config.min_samples {
            return None;
        }

        // Filter samples of the same metric type
        let relevant_samples: Vec<f64> = history
            .samples
            .iter()
            .filter(|s| s.metric_type == sample.metric_type)
            .map(|s| s.value)
            .collect();

        if relevant_samples.len() < self.config.min_samples {
            return None;
        }

        // Calculate statistics
        let mean = relevant_samples.iter().sum::<f64>() / relevant_samples.len() as f64;
        let variance = relevant_samples
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / relevant_samples.len() as f64;
        let std_dev = variance.sqrt();

        // Check z-score
        if std_dev > 0.0 {
            let z_score = (sample.value - mean).abs() / std_dev;

            if z_score > self.config.z_score_threshold {
                let severity = (z_score / (self.config.z_score_threshold * 2.0)).min(1.0);

                return Some(Anomaly {
                    peer_id: peer_id.to_string(),
                    anomaly_type: AnomalyType::StatisticalOutlier,
                    severity,
                    description: format!(
                        "Value {:.2} deviates {:.2} standard deviations from mean {:.2}",
                        sample.value, z_score, mean
                    ),
                    sample_value: sample.value,
                    expected_range: (
                        mean - self.config.z_score_threshold * std_dev,
                        mean + self.config.z_score_threshold * std_dev,
                    ),
                    detected_at: SystemTime::now(),
                });
            }
        }

        // Check for rate anomaly
        if let Some(rate_anomaly) = self.detect_rate_anomaly(peer_id, sample, &relevant_samples) {
            return Some(rate_anomaly);
        }

        None
    }

    /// Detect rate-based anomalies (sudden increases).
    fn detect_rate_anomaly(
        &self,
        peer_id: &str,
        sample: &BehaviorSample,
        historical_samples: &[f64],
    ) -> Option<Anomaly> {
        if historical_samples.len() < 10 {
            return None;
        }

        let recent_avg = historical_samples.iter().rev().take(10).sum::<f64>() / 10.0;

        if recent_avg > 0.0 {
            let increase_ratio = sample.value / recent_avg;

            if increase_ratio > self.config.max_rate_increase {
                let severity = ((increase_ratio / self.config.max_rate_increase) - 1.0).min(1.0);

                return Some(Anomaly {
                    peer_id: peer_id.to_string(),
                    anomaly_type: AnomalyType::RateAnomaly,
                    severity,
                    description: format!(
                        "Value {:.2} is {:.2}x the recent average {:.2}",
                        sample.value, increase_ratio, recent_avg
                    ),
                    sample_value: sample.value,
                    expected_range: (0.0, recent_avg * self.config.max_rate_increase),
                    detected_at: SystemTime::now(),
                });
            }
        }

        None
    }

    /// Record an anomaly.
    fn record_anomaly(&mut self, anomaly: Anomaly) {
        let peer_id = anomaly.peer_id.clone();

        if let Some(history) = self.peer_history.get_mut(&peer_id) {
            history.anomaly_count += 1;
            history.last_anomaly = Some(SystemTime::now());
        }

        self.detected_anomalies.push(anomaly);

        // Keep only recent anomalies
        if self.detected_anomalies.len() > 10000 {
            self.detected_anomalies.drain(0..1000);
        }
    }

    /// Get anomalies for a specific peer.
    #[must_use]
    #[inline]
    pub fn get_peer_anomalies(&self, peer_id: &str) -> Vec<Anomaly> {
        self.detected_anomalies
            .iter()
            .filter(|a| a.peer_id == peer_id)
            .cloned()
            .collect()
    }

    /// Get recent anomalies.
    #[must_use]
    #[inline]
    pub fn get_recent_anomalies(&self, limit: usize) -> Vec<Anomaly> {
        self.detected_anomalies
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get anomalies by type.
    #[must_use]
    #[inline]
    pub fn get_anomalies_by_type(&self, anomaly_type: AnomalyType) -> Vec<Anomaly> {
        self.detected_anomalies
            .iter()
            .filter(|a| a.anomaly_type == anomaly_type)
            .cloned()
            .collect()
    }

    /// Get anomalies with severity above threshold.
    #[must_use]
    #[inline]
    pub fn get_severe_anomalies(&self, min_severity: f64) -> Vec<Anomaly> {
        self.detected_anomalies
            .iter()
            .filter(|a| a.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Get anomaly count for a peer.
    #[must_use]
    #[inline]
    pub fn get_anomaly_count(&self, peer_id: &str) -> u64 {
        self.peer_history
            .get(peer_id)
            .map(|h| h.anomaly_count)
            .unwrap_or(0)
    }

    /// Check if peer has recent anomalies.
    #[must_use]
    #[inline]
    pub fn has_recent_anomalies(&self, peer_id: &str, within: Duration) -> bool {
        if let Some(history) = self.peer_history.get(peer_id) {
            if let Some(last_anomaly) = history.last_anomaly {
                if let Ok(duration) = SystemTime::now().duration_since(last_anomaly) {
                    return duration < within;
                }
            }
        }
        false
    }

    /// Calculate anomaly rate for a peer.
    #[must_use]
    #[inline]
    pub fn get_anomaly_rate(&self, peer_id: &str) -> f64 {
        if let Some(history) = self.peer_history.get(peer_id) {
            if history.samples.is_empty() {
                return 0.0;
            }
            history.anomaly_count as f64 / history.samples.len() as f64
        } else {
            0.0
        }
    }

    /// Get statistics about detected anomalies.
    #[must_use]
    #[inline]
    pub fn get_statistics(&self) -> AnomalyStats {
        let total_anomalies = self.detected_anomalies.len();
        let total_peers = self.peer_history.len();

        let by_type = [
            AnomalyType::StatisticalOutlier,
            AnomalyType::RateAnomaly,
            AnomalyType::PatternAnomaly,
            AnomalyType::RangeAnomaly,
        ]
        .iter()
        .map(|t| {
            let count = self
                .detected_anomalies
                .iter()
                .filter(|a| a.anomaly_type == *t)
                .count();
            (format!("{:?}", t), count)
        })
        .collect();

        let avg_severity = if total_anomalies > 0 {
            self.detected_anomalies
                .iter()
                .map(|a| a.severity)
                .sum::<f64>()
                / total_anomalies as f64
        } else {
            0.0
        };

        AnomalyStats {
            total_anomalies,
            total_peers,
            anomalies_by_type: by_type,
            average_severity: avg_severity,
        }
    }

    /// Clean old samples outside retention window.
    fn cleanup_old_samples(&mut self, peer_id: &str) {
        if let Some(history) = self.peer_history.get_mut(peer_id) {
            let now = SystemTime::now();
            let retention = Duration::from_secs(self.config.retention_secs);

            history.samples.retain(|s| {
                if let Ok(age) = now.duration_since(s.timestamp) {
                    age < retention
                } else {
                    false
                }
            });
        }
    }

    /// Clear all data for a peer.
    #[inline]
    pub fn clear_peer(&mut self, peer_id: &str) {
        self.peer_history.remove(peer_id);
        self.detected_anomalies.retain(|a| a.peer_id != peer_id);
    }

    /// Clear all detected anomalies.
    #[inline]
    pub fn clear_anomalies(&mut self) {
        self.detected_anomalies.clear();
    }

    /// Get number of tracked peers.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peer_history.len()
    }
}

/// Anomaly detection statistics.
#[derive(Debug, Clone)]
pub struct AnomalyStats {
    /// Total detected anomalies
    pub total_anomalies: usize,
    /// Total tracked peers
    pub total_peers: usize,
    /// Anomalies by type
    pub anomalies_by_type: HashMap<String, usize>,
    /// Average severity
    pub average_severity: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sample(value: f64, metric_type: &str) -> BehaviorSample {
        BehaviorSample {
            value,
            timestamp: SystemTime::now(),
            metric_type: metric_type.to_string(),
        }
    }

    #[test]
    fn test_statistical_outlier_detection() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        // Record normal samples
        for i in 0..50 {
            let value = 100.0 + (i as f64 % 5.0);
            detector.record_sample("peer1", create_sample(value, "bandwidth"));
        }

        // Test normal value
        let normal = create_sample(102.0, "bandwidth");
        assert!(!detector.is_anomalous("peer1", &normal));

        // Test outlier
        let outlier = create_sample(500.0, "bandwidth");
        assert!(detector.is_anomalous("peer1", &outlier));
    }

    #[test]
    fn test_rate_anomaly_detection() {
        let config = DetectionConfig {
            max_rate_increase: 3.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        // Record baseline
        for _ in 0..50 {
            detector.record_sample("peer1", create_sample(100.0, "proofs"));
        }

        // Sudden spike
        let spike = create_sample(400.0, "proofs");
        assert!(detector.is_anomalous("peer1", &spike));
    }

    #[test]
    fn test_min_samples_requirement() {
        let config = DetectionConfig {
            min_samples: 30,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        // Record insufficient samples
        for i in 0..20 {
            detector.record_sample("peer1", create_sample(100.0 + i as f64, "bandwidth"));
        }

        // Even outliers shouldn't be detected with insufficient samples
        let outlier = create_sample(1000.0, "bandwidth");
        assert!(!detector.is_anomalous("peer1", &outlier));
    }

    #[test]
    fn test_anomaly_counting() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let sample1 = create_sample(500.0, "bandwidth");
        assert!(detector.is_anomalous("peer1", &sample1));

        let sample2 = create_sample(600.0, "bandwidth");
        assert!(detector.is_anomalous("peer1", &sample2));

        assert_eq!(detector.get_anomaly_count("peer1"), 2);
    }

    #[test]
    fn test_get_peer_anomalies() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
            detector.record_sample("peer2", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));
        let _ = detector.is_anomalous("peer2", &create_sample(600.0, "bandwidth"));

        let peer1_anomalies = detector.get_peer_anomalies("peer1");
        assert_eq!(peer1_anomalies.len(), 1);
        assert_eq!(peer1_anomalies[0].peer_id, "peer1");
    }

    #[test]
    fn test_anomaly_types() {
        let config = DetectionConfig::default();
        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));

        let outliers = detector.get_anomalies_by_type(AnomalyType::StatisticalOutlier);
        assert!(!outliers.is_empty());
    }

    #[test]
    fn test_severe_anomalies() {
        let config = DetectionConfig {
            z_score_threshold: 1.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        for _ in 0..50 {
            detector.record_sample("peer1", create_sample(100.0, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(200.0, "bandwidth"));
        let _ = detector.is_anomalous("peer1", &create_sample(1000.0, "bandwidth"));

        let severe = detector.get_severe_anomalies(0.5);
        assert!(!severe.is_empty());
    }

    #[test]
    fn test_recent_anomalies() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));

        assert!(detector.has_recent_anomalies("peer1", Duration::from_secs(60)));
        assert!(!detector.has_recent_anomalies("peer1", Duration::from_secs(0)));
    }

    #[test]
    fn test_anomaly_rate() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        // 50 normal samples
        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        // 2 anomalies
        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));
        let _ = detector.is_anomalous("peer1", &create_sample(600.0, "bandwidth"));

        let rate = detector.get_anomaly_rate("peer1");
        assert!((rate - 2.0 / 50.0).abs() < 0.001);
    }

    #[test]
    fn test_statistics() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
            detector.record_sample("peer2", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));
        let _ = detector.is_anomalous("peer2", &create_sample(600.0, "bandwidth"));

        let stats = detector.get_statistics();
        assert_eq!(stats.total_anomalies, 2);
        assert_eq!(stats.total_peers, 2);
    }

    #[test]
    fn test_clear_peer() {
        let config = DetectionConfig::default();
        let mut detector = AnomalyDetector::new(config);

        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
        }

        let _ = detector.is_anomalous("peer1", &create_sample(500.0, "bandwidth"));

        assert_eq!(detector.peer_count(), 1);
        assert_eq!(detector.get_anomaly_count("peer1"), 1);

        detector.clear_peer("peer1");

        assert_eq!(detector.peer_count(), 0);
        assert_eq!(detector.get_anomaly_count("peer1"), 0);
    }

    #[test]
    fn test_metric_type_isolation() {
        let config = DetectionConfig {
            z_score_threshold: 2.0,
            min_samples: 10,
            ..Default::default()
        };

        let mut detector = AnomalyDetector::new(config);

        // Record samples for different metrics
        for i in 0..50 {
            detector.record_sample("peer1", create_sample(100.0 + (i % 5) as f64, "bandwidth"));
            detector.record_sample("peer1", create_sample(50.0 + (i % 3) as f64, "latency"));
        }

        // Anomaly in bandwidth shouldn't be affected by latency samples
        let bandwidth_outlier = create_sample(500.0, "bandwidth");
        assert!(detector.is_anomalous("peer1", &bandwidth_outlier));

        // Normal latency value
        let normal_latency = create_sample(51.0, "latency");
        assert!(!detector.is_anomalous("peer1", &normal_latency));
    }
}
