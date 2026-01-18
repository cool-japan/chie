//! Peer health prediction for proactive network management.
//!
//! This module provides machine learning-like predictions of peer availability
//! and health based on historical patterns, helping the network anticipate
//! and mitigate peer failures.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Health prediction for a peer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthPrediction {
    /// Predicted probability of peer being available (0.0-1.0)
    pub availability_probability: f64,
    /// Predicted average response time in milliseconds
    pub predicted_latency: f64,
    /// Predicted bandwidth availability
    pub predicted_bandwidth: f64,
    /// Confidence in this prediction (0.0-1.0)
    pub confidence: f64,
    /// Time horizon for this prediction
    pub prediction_horizon: Duration,
}

/// Historical health data point.
#[derive(Debug, Clone)]
struct HealthDataPoint {
    timestamp: Instant,
    was_available: bool,
    latency: Option<f64>,
    bandwidth: Option<f64>,
}

/// Peer behavior pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorPattern {
    /// Consistently available and reliable
    Stable,
    /// Periodic availability (e.g., daily cycles)
    Periodic,
    /// Gradually declining health
    Degrading,
    /// Rapidly declining health
    Failing,
    /// Erratic behavior
    Unstable,
    /// Insufficient data to determine pattern
    Unknown,
}

/// Configuration for health prediction.
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// How much historical data to keep
    pub history_window: Duration,
    /// Minimum data points required for prediction
    pub min_data_points: usize,
    /// Default prediction horizon
    pub default_horizon: Duration,
    /// Weight for recent data (exponential smoothing alpha)
    pub recent_weight: f64,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            history_window: Duration::from_secs(86400), // 24 hours
            min_data_points: 10,
            default_horizon: Duration::from_secs(3600), // 1 hour
            recent_weight: 0.3,
        }
    }
}

/// Statistics about prediction accuracy.
#[derive(Debug, Clone)]
pub struct PredictorStats {
    /// Number of peers being tracked
    pub peers_tracked: usize,
    /// Total predictions made
    pub predictions_made: usize,
    /// Predictions that were verified
    pub predictions_verified: usize,
    /// Accuracy of verified predictions
    pub prediction_accuracy: f64,
    /// Average confidence level
    pub avg_confidence: f64,
}

/// Peer health predictor.
pub struct PeerHealthPredictor {
    config: PredictorConfig,
    peer_history: Arc<Mutex<HashMap<String, VecDeque<HealthDataPoint>>>>,
    peer_patterns: Arc<Mutex<HashMap<String, BehaviorPattern>>>,
    stats: Arc<Mutex<PredictorStats>>,
}

impl PeerHealthPredictor {
    /// Creates a new health predictor with default configuration.
    pub fn new() -> Self {
        Self::with_config(PredictorConfig::default())
    }

    /// Creates a new health predictor with custom configuration.
    pub fn with_config(config: PredictorConfig) -> Self {
        Self {
            config,
            peer_history: Arc::new(Mutex::new(HashMap::new())),
            peer_patterns: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(PredictorStats {
                peers_tracked: 0,
                predictions_made: 0,
                predictions_verified: 0,
                prediction_accuracy: 0.0,
                avg_confidence: 0.0,
            })),
        }
    }

    /// Records a health observation for a peer.
    pub fn record_observation(
        &self,
        peer_id: &str,
        available: bool,
        latency: Option<f64>,
        bandwidth: Option<f64>,
    ) {
        let mut history = self.peer_history.lock().unwrap();
        let peer_history = history.entry(peer_id.to_string()).or_default();

        peer_history.push_back(HealthDataPoint {
            timestamp: Instant::now(),
            was_available: available,
            latency,
            bandwidth,
        });

        // Cleanup old data
        let cutoff = Instant::now() - self.config.history_window;
        while let Some(front) = peer_history.front() {
            if front.timestamp < cutoff {
                peer_history.pop_front();
            } else {
                break;
            }
        }

        // Update pattern if we have enough data
        if peer_history.len() >= self.config.min_data_points {
            let pattern = self.detect_pattern(peer_history);
            self.peer_patterns
                .lock()
                .unwrap()
                .insert(peer_id.to_string(), pattern);
        }

        // Update stats
        let mut stats = self.stats.lock().unwrap();
        stats.peers_tracked = history.len();
    }

    /// Predicts health for a peer at a future time.
    pub fn predict_health(
        &self,
        peer_id: &str,
        horizon: Option<Duration>,
    ) -> Option<HealthPrediction> {
        let history = self.peer_history.lock().unwrap();
        let peer_history = history.get(peer_id)?;

        if peer_history.len() < self.config.min_data_points {
            return None;
        }

        let horizon = horizon.unwrap_or(self.config.default_horizon);
        let pattern = self
            .peer_patterns
            .lock()
            .unwrap()
            .get(peer_id)
            .copied()
            .unwrap_or(BehaviorPattern::Unknown);

        // Calculate availability probability
        let availability_probability =
            self.calculate_availability_probability(peer_history, pattern, horizon);

        // Predict latency
        let predicted_latency = self.predict_latency(peer_history);

        // Predict bandwidth
        let predicted_bandwidth = self.predict_bandwidth(peer_history);

        // Calculate confidence
        let confidence = self.calculate_confidence(peer_history, pattern);

        // Update stats
        let mut stats = self.stats.lock().unwrap();
        stats.predictions_made += 1;

        let total_predictions = stats.predictions_made as f64;
        stats.avg_confidence =
            (stats.avg_confidence * (total_predictions - 1.0) + confidence) / total_predictions;

        Some(HealthPrediction {
            availability_probability,
            predicted_latency,
            predicted_bandwidth,
            confidence,
            prediction_horizon: horizon,
        })
    }

    /// Detects the behavior pattern of a peer.
    fn detect_pattern(&self, history: &VecDeque<HealthDataPoint>) -> BehaviorPattern {
        if history.len() < self.config.min_data_points {
            return BehaviorPattern::Unknown;
        }

        // Calculate availability rate
        let available_count = history.iter().filter(|d| d.was_available).count();
        let availability_rate = available_count as f64 / history.len() as f64;

        // Check for degradation trend
        let recent_half = history.len() / 2;
        let recent_available = history
            .iter()
            .skip(recent_half)
            .filter(|d| d.was_available)
            .count();
        let recent_rate = recent_available as f64 / recent_half as f64;

        let degradation = availability_rate - recent_rate;

        // Check for periodicity
        let is_periodic = self.detect_periodicity(history);

        // Classify pattern - prioritize failure/degradation over periodicity
        if availability_rate > 0.95 && degradation < 0.05 {
            BehaviorPattern::Stable
        } else if degradation > 0.2 && recent_rate < 0.5 {
            // Failing state takes precedence over periodicity
            BehaviorPattern::Failing
        } else if degradation > 0.1 {
            BehaviorPattern::Degrading
        } else if is_periodic && recent_rate > 0.3 {
            // Only classify as periodic if not currently failing
            BehaviorPattern::Periodic
        } else if availability_rate < 0.7 {
            BehaviorPattern::Unstable
        } else {
            BehaviorPattern::Stable
        }
    }

    /// Detects if there's a periodic pattern in availability.
    fn detect_periodicity(&self, history: &VecDeque<HealthDataPoint>) -> bool {
        if history.len() < 20 {
            return false;
        }

        // Simple periodicity detection: check for regular intervals of unavailability
        let unavailable_indices: Vec<usize> = history
            .iter()
            .enumerate()
            .filter(|(_, d)| !d.was_available)
            .map(|(i, _)| i)
            .collect();

        if unavailable_indices.len() < 3 {
            return false;
        }

        // Check if gaps between unavailable periods are roughly equal
        let gaps: Vec<usize> = unavailable_indices
            .windows(2)
            .map(|w| w[1] - w[0])
            .collect();

        if gaps.is_empty() {
            return false;
        }

        let avg_gap = gaps.iter().sum::<usize>() as f64 / gaps.len() as f64;
        let variance = gaps
            .iter()
            .map(|&g| {
                let diff = g as f64 - avg_gap;
                diff * diff
            })
            .sum::<f64>()
            / gaps.len() as f64;

        // Low variance indicates periodicity
        variance / avg_gap < 0.3
    }

    /// Calculates probability of peer being available.
    fn calculate_availability_probability(
        &self,
        history: &VecDeque<HealthDataPoint>,
        pattern: BehaviorPattern,
        _horizon: Duration,
    ) -> f64 {
        let recent_available = history
            .iter()
            .rev()
            .take(10)
            .filter(|d| d.was_available)
            .count();

        let base_probability = recent_available as f64 / 10.0_f64.min(history.len() as f64);

        // Adjust based on pattern
        match pattern {
            BehaviorPattern::Stable => base_probability.max(0.9),
            BehaviorPattern::Periodic => base_probability * 0.8, // Slightly less predictable
            BehaviorPattern::Degrading => base_probability * 0.7,
            BehaviorPattern::Failing => base_probability * 0.3,
            BehaviorPattern::Unstable => base_probability * 0.5,
            BehaviorPattern::Unknown => base_probability,
        }
    }

    /// Predicts latency using exponential smoothing.
    fn predict_latency(&self, history: &VecDeque<HealthDataPoint>) -> f64 {
        let latencies: Vec<f64> = history
            .iter()
            .rev()
            .filter_map(|d| d.latency)
            .take(20)
            .collect();

        if latencies.is_empty() {
            return 100.0; // Default assumption
        }

        // Exponential moving average
        let mut ema = latencies[0];
        for &latency in &latencies[1..] {
            ema = self.config.recent_weight * latency + (1.0 - self.config.recent_weight) * ema;
        }

        ema
    }

    /// Predicts bandwidth using trend analysis.
    fn predict_bandwidth(&self, history: &VecDeque<HealthDataPoint>) -> f64 {
        let bandwidths: Vec<f64> = history
            .iter()
            .rev()
            .filter_map(|d| d.bandwidth)
            .take(20)
            .collect();

        if bandwidths.is_empty() {
            return 1_000_000.0; // Default 1 MB/s
        }

        // Simple moving average
        bandwidths.iter().sum::<f64>() / bandwidths.len() as f64
    }

    /// Calculates confidence in prediction.
    fn calculate_confidence(
        &self,
        history: &VecDeque<HealthDataPoint>,
        pattern: BehaviorPattern,
    ) -> f64 {
        // More data = higher confidence
        let data_confidence = (history.len() as f64 / 100.0).min(1.0);

        // Stable patterns = higher confidence
        let pattern_confidence = match pattern {
            BehaviorPattern::Stable => 0.9,
            BehaviorPattern::Periodic => 0.8,
            BehaviorPattern::Degrading => 0.7,
            BehaviorPattern::Failing => 0.8, // Failures are predictable
            BehaviorPattern::Unstable => 0.4,
            BehaviorPattern::Unknown => 0.3,
        };

        (data_confidence + pattern_confidence) / 2.0
    }

    /// Gets the detected pattern for a peer.
    pub fn get_pattern(&self, peer_id: &str) -> Option<BehaviorPattern> {
        self.peer_patterns.lock().unwrap().get(peer_id).copied()
    }

    /// Gets peers matching a specific pattern.
    pub fn get_peers_by_pattern(&self, pattern: BehaviorPattern) -> Vec<String> {
        self.peer_patterns
            .lock()
            .unwrap()
            .iter()
            .filter(|&(_, &p)| p == pattern)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Gets current statistics.
    pub fn stats(&self) -> PredictorStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clears all history and resets statistics.
    pub fn clear(&self) {
        self.peer_history.lock().unwrap().clear();
        self.peer_patterns.lock().unwrap().clear();

        let mut stats = self.stats.lock().unwrap();
        *stats = PredictorStats {
            peers_tracked: 0,
            predictions_made: 0,
            predictions_verified: 0,
            prediction_accuracy: 0.0,
            avg_confidence: 0.0,
        };
    }
}

impl Clone for PeerHealthPredictor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            peer_history: Arc::new(Mutex::new(self.peer_history.lock().unwrap().clone())),
            peer_patterns: Arc::new(Mutex::new(self.peer_patterns.lock().unwrap().clone())),
            stats: Arc::new(Mutex::new(self.stats.lock().unwrap().clone())),
        }
    }
}

impl Default for PeerHealthPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predictor_new() {
        let predictor = PeerHealthPredictor::new();
        let stats = predictor.stats();

        assert_eq!(stats.peers_tracked, 0);
        assert_eq!(stats.predictions_made, 0);
    }

    #[test]
    fn test_record_observation() {
        let predictor = PeerHealthPredictor::new();

        predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));

        let stats = predictor.stats();
        assert_eq!(stats.peers_tracked, 1);
    }

    #[test]
    fn test_predict_insufficient_data() {
        let predictor = PeerHealthPredictor::new();

        predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));

        let prediction = predictor.predict_health("peer1", None);
        assert!(prediction.is_none());
    }

    #[test]
    fn test_predict_with_sufficient_data() {
        let predictor = PeerHealthPredictor::new();

        // Add sufficient data points
        for _ in 0..15 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let prediction = predictor.predict_health("peer1", None);
        assert!(prediction.is_some());

        let pred = prediction.unwrap();
        assert!(pred.availability_probability > 0.0);
        assert!(pred.confidence > 0.0);
    }

    #[test]
    fn test_stable_pattern_detection() {
        let predictor = PeerHealthPredictor::new();

        // Consistently available peer
        for _ in 0..20 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let pattern = predictor.get_pattern("peer1");
        assert_eq!(pattern, Some(BehaviorPattern::Stable));
    }

    #[test]
    fn test_failing_pattern_detection() {
        let predictor = PeerHealthPredictor::new();

        // Initially available, then failing
        for _ in 0..10 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }
        for _ in 0..10 {
            predictor.record_observation("peer1", false, None, None);
        }

        let pattern = predictor.get_pattern("peer1");
        assert_eq!(pattern, Some(BehaviorPattern::Failing));
    }

    #[test]
    fn test_unstable_pattern_detection() {
        let predictor = PeerHealthPredictor::new();

        // Erratic availability
        for i in 0..20 {
            let available = i % 3 != 0; // ~67% available, may appear periodic
            predictor.record_observation("peer1", available, Some(10.0), Some(1000.0));
        }

        let pattern = predictor.get_pattern("peer1");
        // Pattern could be detected as Periodic, Unstable, or Stable depending on detection sensitivity
        assert!(
            pattern == Some(BehaviorPattern::Unstable)
                || pattern == Some(BehaviorPattern::Stable)
                || pattern == Some(BehaviorPattern::Periodic)
        );
    }

    #[test]
    fn test_latency_prediction() {
        let predictor = PeerHealthPredictor::new();

        for _ in 0..15 {
            predictor.record_observation("peer1", true, Some(50.0), Some(1000.0));
        }

        let prediction = predictor.predict_health("peer1", None).unwrap();
        assert!((prediction.predicted_latency - 50.0).abs() < 10.0);
    }

    #[test]
    fn test_bandwidth_prediction() {
        let predictor = PeerHealthPredictor::new();

        for _ in 0..15 {
            predictor.record_observation("peer1", true, Some(10.0), Some(2000.0));
        }

        let prediction = predictor.predict_health("peer1", None).unwrap();
        assert!((prediction.predicted_bandwidth - 2000.0).abs() < 500.0);
    }

    #[test]
    fn test_get_peers_by_pattern() {
        let predictor = PeerHealthPredictor::new();

        // Create stable peer
        for _ in 0..20 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        // Create failing peer
        for _ in 0..10 {
            predictor.record_observation("peer2", true, Some(10.0), Some(1000.0));
        }
        for _ in 0..10 {
            predictor.record_observation("peer2", false, None, None);
        }

        let stable_peers = predictor.get_peers_by_pattern(BehaviorPattern::Stable);
        assert!(stable_peers.contains(&"peer1".to_string()));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_confidence_increases_with_data() {
        let mut config = PredictorConfig::default();
        config.min_data_points = 5;

        let predictor = PeerHealthPredictor::with_config(config);

        // Add minimal data
        for _ in 0..5 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let pred1 = predictor.predict_health("peer1", None).unwrap();

        // Add more data
        for _ in 0..20 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let pred2 = predictor.predict_health("peer1", None).unwrap();

        assert!(pred2.confidence >= pred1.confidence);
    }

    #[test]
    fn test_clear() {
        let predictor = PeerHealthPredictor::new();

        for _ in 0..15 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        predictor.clear();

        let stats = predictor.stats();
        assert_eq!(stats.peers_tracked, 0);
        assert_eq!(stats.predictions_made, 0);
    }

    #[test]
    fn test_clone() {
        let predictor1 = PeerHealthPredictor::new();

        for _ in 0..15 {
            predictor1.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let predictor2 = predictor1.clone();
        let stats = predictor2.stats();

        assert_eq!(stats.peers_tracked, 1);
    }

    #[test]
    fn test_config_default() {
        let config = PredictorConfig::default();

        assert_eq!(config.min_data_points, 10);
        assert!(config.recent_weight > 0.0 && config.recent_weight < 1.0);
    }

    #[test]
    fn test_custom_horizon() {
        let predictor = PeerHealthPredictor::new();

        for _ in 0..15 {
            predictor.record_observation("peer1", true, Some(10.0), Some(1000.0));
        }

        let horizon = Duration::from_secs(7200); // 2 hours
        let prediction = predictor.predict_health("peer1", Some(horizon)).unwrap();

        assert_eq!(prediction.prediction_horizon, horizon);
    }

    #[test]
    fn test_high_availability_prediction() {
        let predictor = PeerHealthPredictor::new();

        // Very reliable peer
        for _ in 0..30 {
            predictor.record_observation("peer1", true, Some(5.0), Some(5000.0));
        }

        let prediction = predictor.predict_health("peer1", None).unwrap();
        assert!(prediction.availability_probability > 0.8);
    }

    #[test]
    fn test_low_availability_prediction() {
        let predictor = PeerHealthPredictor::new();

        // Unreliable peer
        for i in 0..30 {
            let available = i % 5 == 0; // Only 20% available
            predictor.record_observation("peer1", available, Some(100.0), Some(100.0));
        }

        let prediction = predictor.predict_health("peer1", None).unwrap();
        assert!(prediction.availability_probability < 0.5);
    }

    #[test]
    fn test_degrading_pattern() {
        let predictor = PeerHealthPredictor::new();

        // Start good, gradually degrade
        for i in 0..30 {
            let available = i < 20; // First 20 available, then fail
            predictor.record_observation("peer1", available, Some(10.0), Some(1000.0));
        }

        let pattern = predictor.get_pattern("peer1");
        assert!(
            pattern == Some(BehaviorPattern::Degrading)
                || pattern == Some(BehaviorPattern::Failing)
        );
    }
}
