//! Automatic parameter tuning based on network conditions.
//!
//! This module provides adaptive optimization of network parameters based on
//! real-time monitoring of network conditions, latency, bandwidth, and connection quality.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Network condition classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCondition {
    /// Excellent network conditions (low latency, high bandwidth).
    Excellent,
    /// Good network conditions (normal latency, good bandwidth).
    Good,
    /// Fair network conditions (moderate latency, acceptable bandwidth).
    Fair,
    /// Poor network conditions (high latency, limited bandwidth).
    Poor,
    /// Critical network conditions (very high latency, very limited bandwidth).
    Critical,
}

impl NetworkCondition {
    /// Get condition from latency and bandwidth metrics.
    pub fn from_metrics(avg_latency_ms: u64, bandwidth_mbps: f64, packet_loss: f64) -> Self {
        // Classify based on latency
        let latency_score = if avg_latency_ms < 50 {
            5
        } else if avg_latency_ms < 100 {
            4
        } else if avg_latency_ms < 200 {
            3
        } else if avg_latency_ms < 500 {
            2
        } else {
            1
        };

        // Classify based on bandwidth (Mbps)
        let bandwidth_score = if bandwidth_mbps > 100.0 {
            5
        } else if bandwidth_mbps > 50.0 {
            4
        } else if bandwidth_mbps > 10.0 {
            3
        } else if bandwidth_mbps > 1.0 {
            2
        } else {
            1
        };

        // Classify based on packet loss
        let loss_score = if packet_loss < 0.01 {
            5
        } else if packet_loss < 0.05 {
            4
        } else if packet_loss < 0.1 {
            3
        } else if packet_loss < 0.2 {
            2
        } else {
            1
        };

        // Average the scores
        let avg_score = (latency_score + bandwidth_score + loss_score) / 3;

        match avg_score {
            5 => NetworkCondition::Excellent,
            4 => NetworkCondition::Good,
            3 => NetworkCondition::Fair,
            2 => NetworkCondition::Poor,
            _ => NetworkCondition::Critical,
        }
    }

    /// Get recommended connection count for this condition.
    pub fn recommended_connections(&self) -> (usize, usize) {
        match self {
            NetworkCondition::Excellent => (20, 200),
            NetworkCondition::Good => (10, 100),
            NetworkCondition::Fair => (5, 50),
            NetworkCondition::Poor => (3, 30),
            NetworkCondition::Critical => (2, 10),
        }
    }

    /// Get recommended timeout for this condition.
    pub fn recommended_timeout(&self) -> Duration {
        match self {
            NetworkCondition::Excellent => Duration::from_secs(5),
            NetworkCondition::Good => Duration::from_secs(10),
            NetworkCondition::Fair => Duration::from_secs(20),
            NetworkCondition::Poor => Duration::from_secs(30),
            NetworkCondition::Critical => Duration::from_secs(60),
        }
    }

    /// Get recommended bandwidth limit (bytes/sec).
    pub fn recommended_bandwidth_limit(&self, total_available: u64) -> u64 {
        match self {
            NetworkCondition::Excellent => total_available,
            NetworkCondition::Good => (total_available * 9) / 10,
            NetworkCondition::Fair => (total_available * 7) / 10,
            NetworkCondition::Poor => total_available / 2,
            NetworkCondition::Critical => total_available / 4,
        }
    }
}

/// Configuration for auto-tuning.
#[derive(Debug, Clone)]
pub struct AutoTuningConfig {
    /// Enable auto-tuning.
    pub enabled: bool,
    /// Measurement window duration.
    pub measurement_window: Duration,
    /// Minimum time between adjustments.
    pub adjustment_interval: Duration,
    /// Maximum bandwidth limit (bytes/sec).
    pub max_bandwidth: u64,
    /// Enable aggressive tuning (faster adjustments).
    pub aggressive: bool,
}

impl Default for AutoTuningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            measurement_window: Duration::from_secs(60),
            adjustment_interval: Duration::from_secs(30),
            max_bandwidth: 100 * 1024 * 1024, // 100 MB/s
            aggressive: false,
        }
    }
}

/// Network measurements for auto-tuning.
#[derive(Debug, Clone)]
struct NetworkMeasurements {
    latency_samples: Vec<u64>,
    bandwidth_samples: Vec<f64>,
    packet_loss_samples: Vec<f64>,
    #[allow(dead_code)]
    last_measurement: Instant,
}

impl NetworkMeasurements {
    fn new() -> Self {
        Self {
            latency_samples: Vec::with_capacity(100),
            bandwidth_samples: Vec::with_capacity(100),
            packet_loss_samples: Vec::with_capacity(100),
            last_measurement: Instant::now(),
        }
    }

    fn add_latency(&mut self, latency_ms: u64) {
        self.latency_samples.push(latency_ms);
        if self.latency_samples.len() > 100 {
            self.latency_samples.remove(0);
        }
    }

    fn add_bandwidth(&mut self, bandwidth_mbps: f64) {
        self.bandwidth_samples.push(bandwidth_mbps);
        if self.bandwidth_samples.len() > 100 {
            self.bandwidth_samples.remove(0);
        }
    }

    fn add_packet_loss(&mut self, loss_ratio: f64) {
        self.packet_loss_samples.push(loss_ratio);
        if self.packet_loss_samples.len() > 100 {
            self.packet_loss_samples.remove(0);
        }
    }

    fn avg_latency(&self) -> u64 {
        if self.latency_samples.is_empty() {
            return 100; // Default 100ms
        }
        self.latency_samples.iter().sum::<u64>() / self.latency_samples.len() as u64
    }

    fn avg_bandwidth(&self) -> f64 {
        if self.bandwidth_samples.is_empty() {
            return 10.0; // Default 10 Mbps
        }
        self.bandwidth_samples.iter().sum::<f64>() / self.bandwidth_samples.len() as f64
    }

    fn avg_packet_loss(&self) -> f64 {
        if self.packet_loss_samples.is_empty() {
            return 0.0;
        }
        self.packet_loss_samples.iter().sum::<f64>() / self.packet_loss_samples.len() as f64
    }

    #[allow(dead_code)]
    fn should_measure(&self, window: Duration) -> bool {
        self.last_measurement.elapsed() >= window
    }

    #[allow(dead_code)]
    fn mark_measured(&mut self) {
        self.last_measurement = Instant::now();
    }
}

/// Tuning recommendations from the auto-tuner.
#[derive(Debug, Clone)]
pub struct TuningRecommendations {
    /// Current network condition.
    pub condition: NetworkCondition,
    /// Recommended minimum connections.
    pub min_connections: usize,
    /// Recommended maximum connections.
    pub max_connections: usize,
    /// Recommended timeout.
    pub timeout: Duration,
    /// Recommended bandwidth limit (bytes/sec).
    pub bandwidth_limit: u64,
    /// Confidence in recommendations (0.0-1.0).
    pub confidence: f64,
}

/// Auto-tuning statistics.
#[derive(Debug, Clone)]
pub struct AutoTuningStats {
    /// Number of adjustments made.
    pub adjustments_made: u64,
    /// Current network condition.
    pub current_condition: NetworkCondition,
    /// Average latency (ms).
    pub avg_latency_ms: u64,
    /// Average bandwidth (Mbps).
    pub avg_bandwidth_mbps: f64,
    /// Average packet loss ratio.
    pub avg_packet_loss: f64,
    /// Time since last adjustment.
    pub time_since_last_adjustment: Duration,
}

/// Auto-tuning system for adaptive parameter optimization.
pub struct AutoTuner {
    config: AutoTuningConfig,
    measurements: Arc<RwLock<NetworkMeasurements>>,
    last_adjustment: Arc<RwLock<Instant>>,
    adjustments_made: Arc<RwLock<u64>>,
}

impl AutoTuner {
    /// Create a new auto-tuner.
    pub fn new(config: AutoTuningConfig) -> Self {
        Self {
            config,
            measurements: Arc::new(RwLock::new(NetworkMeasurements::new())),
            last_adjustment: Arc::new(RwLock::new(Instant::now())),
            adjustments_made: Arc::new(RwLock::new(0)),
        }
    }

    /// Record a latency measurement (milliseconds).
    pub fn record_latency(&self, latency_ms: u64) {
        if !self.config.enabled {
            return;
        }
        let mut measurements = self.measurements.write().unwrap();
        measurements.add_latency(latency_ms);
    }

    /// Record a bandwidth measurement (Mbps).
    pub fn record_bandwidth(&self, bandwidth_mbps: f64) {
        if !self.config.enabled {
            return;
        }
        let mut measurements = self.measurements.write().unwrap();
        measurements.add_bandwidth(bandwidth_mbps);
    }

    /// Record a packet loss measurement (ratio 0.0-1.0).
    pub fn record_packet_loss(&self, loss_ratio: f64) {
        if !self.config.enabled {
            return;
        }
        let mut measurements = self.measurements.write().unwrap();
        measurements.add_packet_loss(loss_ratio.clamp(0.0, 1.0));
    }

    /// Get current network condition.
    pub fn current_condition(&self) -> NetworkCondition {
        let measurements = self.measurements.read().unwrap();
        let avg_latency = measurements.avg_latency();
        let avg_bandwidth = measurements.avg_bandwidth();
        let avg_loss = measurements.avg_packet_loss();
        NetworkCondition::from_metrics(avg_latency, avg_bandwidth, avg_loss)
    }

    /// Check if tuning recommendations should be generated.
    pub fn should_tune(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let last_adjustment = self.last_adjustment.read().unwrap();
        last_adjustment.elapsed() >= self.config.adjustment_interval
    }

    /// Generate tuning recommendations.
    pub fn get_recommendations(&self) -> TuningRecommendations {
        let measurements = self.measurements.read().unwrap();
        let condition = NetworkCondition::from_metrics(
            measurements.avg_latency(),
            measurements.avg_bandwidth(),
            measurements.avg_packet_loss(),
        );

        let (min_conn, max_conn) = condition.recommended_connections();
        let timeout = condition.recommended_timeout();
        let bandwidth_limit = condition.recommended_bandwidth_limit(self.config.max_bandwidth);

        // Calculate confidence based on sample count
        let sample_count = measurements.latency_samples.len().min(
            measurements
                .bandwidth_samples
                .len()
                .min(measurements.packet_loss_samples.len()),
        );
        let confidence = (sample_count as f64 / 50.0).min(1.0);

        TuningRecommendations {
            condition,
            min_connections: min_conn,
            max_connections: max_conn,
            timeout,
            bandwidth_limit,
            confidence,
        }
    }

    /// Apply tuning (marks that tuning was applied).
    pub fn mark_tuned(&self) {
        *self.last_adjustment.write().unwrap() = Instant::now();
        *self.adjustments_made.write().unwrap() += 1;
    }

    /// Get auto-tuning statistics.
    pub fn stats(&self) -> AutoTuningStats {
        let measurements = self.measurements.read().unwrap();
        let last_adjustment = self.last_adjustment.read().unwrap();
        let adjustments_made = *self.adjustments_made.read().unwrap();

        AutoTuningStats {
            adjustments_made,
            current_condition: self.current_condition(),
            avg_latency_ms: measurements.avg_latency(),
            avg_bandwidth_mbps: measurements.avg_bandwidth(),
            avg_packet_loss: measurements.avg_packet_loss(),
            time_since_last_adjustment: last_adjustment.elapsed(),
        }
    }

    /// Reset auto-tuning state.
    pub fn reset(&self) {
        *self.measurements.write().unwrap() = NetworkMeasurements::new();
        *self.last_adjustment.write().unwrap() = Instant::now();
        *self.adjustments_made.write().unwrap() = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_condition_from_metrics() {
        // Excellent condition
        let condition = NetworkCondition::from_metrics(30, 150.0, 0.001);
        assert_eq!(condition, NetworkCondition::Excellent);

        // Good condition
        let condition = NetworkCondition::from_metrics(80, 60.0, 0.03);
        assert_eq!(condition, NetworkCondition::Good);

        // Poor condition
        let condition = NetworkCondition::from_metrics(400, 2.0, 0.15);
        assert_eq!(condition, NetworkCondition::Poor);

        // Critical condition
        let condition = NetworkCondition::from_metrics(800, 0.5, 0.3);
        assert_eq!(condition, NetworkCondition::Critical);
    }

    #[test]
    fn test_network_condition_recommendations() {
        let excellent = NetworkCondition::Excellent;
        let (min, max) = excellent.recommended_connections();
        assert_eq!(min, 20);
        assert_eq!(max, 200);
        assert_eq!(excellent.recommended_timeout(), Duration::from_secs(5));

        let critical = NetworkCondition::Critical;
        let (min, max) = critical.recommended_connections();
        assert_eq!(min, 2);
        assert_eq!(max, 10);
        assert_eq!(critical.recommended_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_auto_tuner_recording() {
        let config = AutoTuningConfig::default();
        let tuner = AutoTuner::new(config);

        tuner.record_latency(50);
        tuner.record_latency(60);
        tuner.record_latency(55);

        tuner.record_bandwidth(100.0);
        tuner.record_bandwidth(110.0);

        tuner.record_packet_loss(0.01);

        let condition = tuner.current_condition();
        assert!(matches!(
            condition,
            NetworkCondition::Excellent | NetworkCondition::Good
        ));
    }

    #[test]
    fn test_auto_tuner_recommendations() {
        let config = AutoTuningConfig::default();
        let tuner = AutoTuner::new(config);

        // Add some measurements for excellent conditions
        for _ in 0..10 {
            tuner.record_latency(40); // < 50ms for score 5
            tuner.record_bandwidth(150.0); // > 100 Mbps for score 5
            tuner.record_packet_loss(0.005); // < 0.01 for score 5
        }

        let recommendations = tuner.get_recommendations();
        assert_eq!(recommendations.condition, NetworkCondition::Excellent);
        assert!(recommendations.confidence > 0.0);
        assert!(recommendations.min_connections > 0);
        assert!(recommendations.max_connections > recommendations.min_connections);
    }

    #[test]
    fn test_auto_tuner_disabled() {
        let config = AutoTuningConfig {
            enabled: false,
            ..Default::default()
        };
        let tuner = AutoTuner::new(config);

        tuner.record_latency(1000);
        assert!(!tuner.should_tune());
    }

    #[test]
    fn test_auto_tuner_stats() {
        let config = AutoTuningConfig::default();
        let tuner = AutoTuner::new(config);

        tuner.record_latency(50);
        tuner.record_bandwidth(100.0);

        let stats = tuner.stats();
        assert_eq!(stats.adjustments_made, 0);
        assert!(stats.avg_latency_ms > 0);

        tuner.mark_tuned();
        let stats = tuner.stats();
        assert_eq!(stats.adjustments_made, 1);
    }

    #[test]
    fn test_network_measurements_windowing() {
        let mut measurements = NetworkMeasurements::new();

        // Add more than capacity
        for i in 0..150 {
            measurements.add_latency(i);
        }

        // Should keep only last 100
        assert_eq!(measurements.latency_samples.len(), 100);
        assert_eq!(measurements.latency_samples[0], 50);
    }

    #[test]
    fn test_bandwidth_limit_recommendations() {
        let total = 100_000_000; // 100 MB/s

        let excellent = NetworkCondition::Excellent;
        assert_eq!(excellent.recommended_bandwidth_limit(total), total);

        let poor = NetworkCondition::Poor;
        assert_eq!(poor.recommended_bandwidth_limit(total), total / 2);

        let critical = NetworkCondition::Critical;
        assert_eq!(critical.recommended_bandwidth_limit(total), total / 4);
    }

    #[test]
    fn test_tuning_interval() {
        let config = AutoTuningConfig {
            adjustment_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let tuner = AutoTuner::new(config);

        assert!(!tuner.should_tune());
        std::thread::sleep(Duration::from_millis(15));
        assert!(tuner.should_tune());

        tuner.mark_tuned();
        assert!(!tuner.should_tune());
    }

    #[test]
    fn test_confidence_calculation() {
        let config = AutoTuningConfig::default();
        let tuner = AutoTuner::new(config);

        // Low confidence with few samples
        tuner.record_latency(50);
        let rec1 = tuner.get_recommendations();
        assert!(rec1.confidence < 0.5);

        // Higher confidence with more samples
        for _ in 0..50 {
            tuner.record_latency(50);
            tuner.record_bandwidth(100.0);
            tuner.record_packet_loss(0.01);
        }
        let rec2 = tuner.get_recommendations();
        assert!(rec2.confidence >= rec1.confidence);
    }

    #[test]
    fn test_reset() {
        let config = AutoTuningConfig::default();
        let tuner = AutoTuner::new(config);

        tuner.record_latency(50);
        tuner.mark_tuned();

        let stats_before = tuner.stats();
        assert_eq!(stats_before.adjustments_made, 1);

        tuner.reset();

        let stats_after = tuner.stats();
        assert_eq!(stats_after.adjustments_made, 0);
    }
}
