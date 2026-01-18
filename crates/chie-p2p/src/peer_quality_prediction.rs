//! Peer quality prediction using ML-inspired models.
//!
//! This module provides predictive analytics for peer quality using various
//! machine learning-inspired techniques including regression, trend analysis,
//! and ensemble methods.

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Quality metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QualityMetric {
    /// Bandwidth (bytes/sec)
    Bandwidth,
    /// Latency (milliseconds)
    Latency,
    /// Success rate (0.0-1.0)
    SuccessRate,
    /// Availability (0.0-1.0)
    Availability,
    /// Reputation score
    Reputation,
}

/// Prediction model type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionModel {
    /// Simple moving average
    SimpleMovingAverage,
    /// Exponential weighted moving average
    ExponentialMovingAverage,
    /// Linear regression
    LinearRegression,
    /// Ensemble (combines multiple models)
    Ensemble,
}

/// Quality data point
#[derive(Debug, Clone)]
struct QualityDataPoint {
    #[allow(dead_code)]
    timestamp: Instant,
    value: f64,
}

/// Peer quality history
#[derive(Debug, Clone)]
struct PeerQualityHistory {
    #[allow(dead_code)]
    metric: QualityMetric,
    data_points: VecDeque<QualityDataPoint>,
    max_history: usize,
}

impl PeerQualityHistory {
    fn new(metric: QualityMetric, max_history: usize) -> Self {
        Self {
            metric,
            data_points: VecDeque::with_capacity(max_history),
            max_history,
        }
    }

    fn add_data_point(&mut self, value: f64) {
        if self.data_points.len() >= self.max_history {
            self.data_points.pop_front();
        }
        self.data_points.push_back(QualityDataPoint {
            timestamp: Instant::now(),
            value,
        });
    }

    fn get_values(&self) -> Vec<f64> {
        self.data_points.iter().map(|dp| dp.value).collect()
    }

    fn get_recent_values(&self, count: usize) -> Vec<f64> {
        self.data_points
            .iter()
            .rev()
            .take(count)
            .map(|dp| dp.value)
            .collect()
    }
}

/// Quality prediction result
#[derive(Debug, Clone)]
pub struct QualityPrediction {
    /// Predicted value
    pub predicted_value: f64,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Trend direction (-1.0 to 1.0, negative = degrading, positive = improving)
    pub trend: f64,
    /// Prediction timestamp
    pub timestamp: Instant,
}

/// Peer quality predictor configuration
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// Maximum history size per metric
    pub max_history: usize,
    /// Prediction model
    pub model: PredictionModel,
    /// EMA smoothing factor (0.0-1.0)
    pub ema_alpha: f64,
    /// Minimum data points required for prediction
    pub min_data_points: usize,
    /// Time window for trend analysis
    pub trend_window: Duration,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            max_history: 100,
            model: PredictionModel::Ensemble,
            ema_alpha: 0.3,
            min_data_points: 5,
            trend_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Peer quality predictor
pub struct PeerQualityPredictor {
    config: PredictorConfig,
    peer_histories: Arc<RwLock<HashMap<PeerId, HashMap<QualityMetric, PeerQualityHistory>>>>,
}

impl PeerQualityPredictor {
    /// Create a new quality predictor
    pub fn new(config: PredictorConfig) -> Self {
        Self {
            config,
            peer_histories: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a quality metric for a peer
    pub fn record_metric(&self, peer_id: PeerId, metric: QualityMetric, value: f64) {
        let mut histories = self.peer_histories.write().unwrap();
        let peer_metrics = histories.entry(peer_id).or_default();
        let history = peer_metrics
            .entry(metric)
            .or_insert_with(|| PeerQualityHistory::new(metric, self.config.max_history));
        history.add_data_point(value);
    }

    /// Predict quality for a peer
    pub fn predict(&self, peer_id: &PeerId, metric: QualityMetric) -> Option<QualityPrediction> {
        let histories = self.peer_histories.read().unwrap();
        let peer_metrics = histories.get(peer_id)?;
        let history = peer_metrics.get(&metric)?;

        if history.data_points.len() < self.config.min_data_points {
            return None;
        }

        match self.config.model {
            PredictionModel::SimpleMovingAverage => self.predict_sma(history),
            PredictionModel::ExponentialMovingAverage => self.predict_ema(history),
            PredictionModel::LinearRegression => self.predict_linear(history),
            PredictionModel::Ensemble => self.predict_ensemble(history),
        }
    }

    /// Simple moving average prediction
    fn predict_sma(&self, history: &PeerQualityHistory) -> Option<QualityPrediction> {
        let values = history.get_values();
        if values.is_empty() {
            return None;
        }

        let predicted_value = values.iter().sum::<f64>() / values.len() as f64;
        let trend = self.calculate_trend(history);
        let confidence = self.calculate_confidence(&values);

        Some(QualityPrediction {
            predicted_value,
            confidence,
            trend,
            timestamp: Instant::now(),
        })
    }

    /// Exponential moving average prediction
    fn predict_ema(&self, history: &PeerQualityHistory) -> Option<QualityPrediction> {
        let values = history.get_values();
        if values.is_empty() {
            return None;
        }

        let mut ema = values[0];
        for &value in values.iter().skip(1) {
            ema = self.config.ema_alpha * value + (1.0 - self.config.ema_alpha) * ema;
        }

        let trend = self.calculate_trend(history);
        let confidence = self.calculate_confidence(&values);

        Some(QualityPrediction {
            predicted_value: ema,
            confidence,
            trend,
            timestamp: Instant::now(),
        })
    }

    /// Linear regression prediction
    fn predict_linear(&self, history: &PeerQualityHistory) -> Option<QualityPrediction> {
        let values = history.get_values();
        if values.len() < 2 {
            return None;
        }

        let n = values.len() as f64;
        let x_values: Vec<f64> = (0..values.len()).map(|i| i as f64).collect();

        // Calculate means
        let x_mean = x_values.iter().sum::<f64>() / n;
        let y_mean = values.iter().sum::<f64>() / n;

        // Calculate slope
        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for i in 0..values.len() {
            numerator += (x_values[i] - x_mean) * (values[i] - y_mean);
            denominator += (x_values[i] - x_mean).powi(2);
        }

        let slope = if denominator != 0.0 {
            numerator / denominator
        } else {
            0.0
        };
        let intercept = y_mean - slope * x_mean;

        // Predict next value
        let predicted_value = slope * n + intercept;
        let trend = slope.signum() * slope.abs().min(1.0);
        let confidence = self.calculate_confidence(&values);

        Some(QualityPrediction {
            predicted_value: predicted_value.max(0.0),
            confidence,
            trend,
            timestamp: Instant::now(),
        })
    }

    /// Ensemble prediction (combines multiple models)
    fn predict_ensemble(&self, history: &PeerQualityHistory) -> Option<QualityPrediction> {
        let sma = self.predict_sma(history)?;
        let ema = self.predict_ema(history)?;
        let linear = self.predict_linear(history)?;

        // Weighted average of predictions
        let predicted_value =
            sma.predicted_value * 0.3 + ema.predicted_value * 0.4 + linear.predicted_value * 0.3;

        // Average confidence
        let confidence = (sma.confidence + ema.confidence + linear.confidence) / 3.0;

        // Use linear trend as it's most indicative
        let trend = linear.trend;

        Some(QualityPrediction {
            predicted_value,
            confidence,
            trend,
            timestamp: Instant::now(),
        })
    }

    /// Calculate trend from history
    fn calculate_trend(&self, history: &PeerQualityHistory) -> f64 {
        let recent = history.get_recent_values(10);
        if recent.len() < 2 {
            return 0.0;
        }

        let first_half = &recent[recent.len() / 2..];
        let second_half = &recent[..recent.len() / 2];

        let avg_first: f64 = first_half.iter().sum::<f64>() / first_half.len() as f64;
        let avg_second: f64 = second_half.iter().sum::<f64>() / second_half.len() as f64;

        if avg_first == 0.0 {
            return 0.0;
        }

        ((avg_second - avg_first) / avg_first).clamp(-1.0, 1.0)
    }

    /// Calculate prediction confidence based on data stability
    fn calculate_confidence(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.5;
        }

        // Calculate variance
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        // Lower variance = higher confidence
        let relative_std_dev = if mean != 0.0 { std_dev / mean } else { 1.0 };
        let confidence = 1.0 / (1.0 + relative_std_dev);

        // Scale confidence based on data points (use square root for gentler scaling)
        let min_points = self.config.min_data_points as f64;
        let data_factor = if values.len() >= self.config.min_data_points {
            let ratio =
                (values.len() as f64 - min_points) / (self.config.max_history as f64 - min_points);
            // Use cube root for even gentler scaling, minimum 0.75 with sufficient data
            ratio.powf(1.0 / 3.0).clamp(0.75, 1.0)
        } else {
            0.3 // Low confidence with insufficient data
        };

        confidence * data_factor
    }

    /// Get all predictions for a peer
    pub fn predict_all(&self, peer_id: &PeerId) -> HashMap<QualityMetric, QualityPrediction> {
        let mut predictions = HashMap::new();
        let metrics = [
            QualityMetric::Bandwidth,
            QualityMetric::Latency,
            QualityMetric::SuccessRate,
            QualityMetric::Availability,
            QualityMetric::Reputation,
        ];

        for metric in metrics {
            if let Some(prediction) = self.predict(peer_id, metric) {
                predictions.insert(metric, prediction);
            }
        }

        predictions
    }

    /// Get composite quality score (0.0-1.0)
    pub fn get_composite_score(&self, peer_id: &PeerId) -> Option<f64> {
        let predictions = self.predict_all(peer_id);
        if predictions.is_empty() {
            return None;
        }

        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        // Weight different metrics
        let weights = [
            (QualityMetric::Bandwidth, 0.25),
            (QualityMetric::Latency, 0.20),
            (QualityMetric::SuccessRate, 0.25),
            (QualityMetric::Availability, 0.15),
            (QualityMetric::Reputation, 0.15),
        ];

        for (metric, weight) in weights {
            if let Some(pred) = predictions.get(&metric) {
                // Normalize different metrics to 0-1 scale
                let normalized = match metric {
                    QualityMetric::Latency => {
                        // Lower latency is better, assume 500ms is max acceptable
                        (1.0 - (pred.predicted_value / 500.0).min(1.0)).max(0.0)
                    }
                    QualityMetric::Bandwidth => {
                        // Higher bandwidth is better, normalize to 0-1 (assume 100MB/s max)
                        (pred.predicted_value / 100_000_000.0).clamp(0.0, 1.0)
                    }
                    _ => pred.predicted_value.clamp(0.0, 1.0),
                };

                total_score += normalized * weight * pred.confidence;
                total_weight += weight * pred.confidence;
            }
        }

        if total_weight > 0.0 {
            Some((total_score / total_weight).clamp(0.0, 1.0))
        } else {
            None
        }
    }

    /// Get peers ranked by predicted quality
    pub fn get_ranked_peers(&self, metric: QualityMetric, ascending: bool) -> Vec<(PeerId, f64)> {
        let histories = self.peer_histories.read().unwrap();
        let mut ranked: Vec<(PeerId, f64)> = histories
            .keys()
            .filter_map(|peer_id| {
                let prediction = self.predict(peer_id, metric)?;
                Some((*peer_id, prediction.predicted_value))
            })
            .collect();

        if ascending {
            ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        } else {
            ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        }

        ranked
    }

    /// Clear history for a peer
    pub fn clear_peer_history(&self, peer_id: &PeerId) {
        self.peer_histories.write().unwrap().remove(peer_id);
    }

    /// Get statistics
    pub fn get_stats(&self) -> PredictorStats {
        let histories = self.peer_histories.read().unwrap();
        let total_peers = histories.len();
        let total_metrics: usize = histories.values().map(|m| m.len()).sum();
        let total_data_points: usize = histories
            .values()
            .flat_map(|m| m.values())
            .map(|h| h.data_points.len())
            .sum();

        PredictorStats {
            total_peers,
            total_metrics,
            total_data_points,
        }
    }
}

/// Predictor statistics
#[derive(Debug, Clone)]
pub struct PredictorStats {
    pub total_peers: usize,
    pub total_metrics: usize,
    pub total_data_points: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_predictor_new() {
        let config = PredictorConfig::default();
        let predictor = PeerQualityPredictor::new(config);
        let stats = predictor.get_stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_record_metric() {
        let config = PredictorConfig::default();
        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
        predictor.record_metric(peer, QualityMetric::Latency, 50.0);

        let stats = predictor.get_stats();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.total_metrics, 2);
    }

    #[test]
    fn test_predict_insufficient_data() {
        let config = PredictorConfig::default();
        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Not enough data points
        predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_none());
    }

    #[test]
    fn test_predict_sma() {
        let config = PredictorConfig {
            model: PredictionModel::SimpleMovingAverage,
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
        predictor.record_metric(peer, QualityMetric::Bandwidth, 1100.0);
        predictor.record_metric(peer, QualityMetric::Bandwidth, 1200.0);

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
        let pred = prediction.unwrap();
        assert!((pred.predicted_value - 1100.0).abs() < 1.0);
    }

    #[test]
    fn test_predict_ema() {
        let config = PredictorConfig {
            model: PredictionModel::ExponentialMovingAverage,
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        for i in 0..5 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0 + i as f64 * 100.0);
        }

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
    }

    #[test]
    fn test_predict_linear() {
        let config = PredictorConfig {
            model: PredictionModel::LinearRegression,
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Linear increase
        for i in 0..10 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0 + i as f64 * 100.0);
        }

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
        let pred = prediction.unwrap();
        // Should predict next value in sequence
        assert!(pred.predicted_value > 1800.0);
        assert!(pred.trend > 0.0); // Positive trend
    }

    #[test]
    fn test_predict_ensemble() {
        let config = PredictorConfig {
            model: PredictionModel::Ensemble,
            min_data_points: 5,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        for i in 0..10 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0 + i as f64 * 50.0);
        }

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
    }

    #[test]
    fn test_trend_calculation() {
        let config = PredictorConfig::default();
        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Increasing trend
        for i in 0..10 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, i as f64 * 100.0);
        }

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
        assert!(prediction.unwrap().trend > 0.0);
    }

    #[test]
    fn test_confidence_calculation() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Stable values should have high confidence
        for _ in 0..10 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
        }

        let prediction = predictor.predict(&peer, QualityMetric::Bandwidth);
        assert!(prediction.is_some());
        assert!(prediction.unwrap().confidence > 0.7);
    }

    #[test]
    fn test_predict_all() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        for _ in 0..5 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
            predictor.record_metric(peer, QualityMetric::Latency, 50.0);
            predictor.record_metric(peer, QualityMetric::SuccessRate, 0.95);
        }

        let predictions = predictor.predict_all(&peer);
        assert!(predictions.len() >= 3);
    }

    #[test]
    fn test_composite_score() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        for _ in 0..5 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, 10_000_000.0); // 10 MB/s
            predictor.record_metric(peer, QualityMetric::Latency, 20.0); // 20ms
            predictor.record_metric(peer, QualityMetric::SuccessRate, 0.95);
            predictor.record_metric(peer, QualityMetric::Availability, 0.99);
            predictor.record_metric(peer, QualityMetric::Reputation, 0.9);
        }

        let score = predictor.get_composite_score(&peer);
        assert!(score.is_some());
        let score_value = score.unwrap();
        assert!(score_value > 0.5 && score_value <= 1.0);
    }

    #[test]
    fn test_ranked_peers() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        for _ in 0..5 {
            predictor.record_metric(peer1, QualityMetric::Bandwidth, 1000.0);
            predictor.record_metric(peer2, QualityMetric::Bandwidth, 2000.0);
            predictor.record_metric(peer3, QualityMetric::Bandwidth, 1500.0);
        }

        let ranked = predictor.get_ranked_peers(QualityMetric::Bandwidth, false);
        assert_eq!(ranked.len(), 3);
        // Should be sorted descending
        assert!(ranked[0].1 >= ranked[1].1);
        assert!(ranked[1].1 >= ranked[2].1);
    }

    #[test]
    fn test_clear_peer_history() {
        let config = PredictorConfig::default();
        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        predictor.record_metric(peer, QualityMetric::Bandwidth, 1000.0);
        assert_eq!(predictor.get_stats().total_peers, 1);

        predictor.clear_peer_history(&peer);
        assert_eq!(predictor.get_stats().total_peers, 0);
    }

    #[test]
    fn test_max_history_limit() {
        let config = PredictorConfig {
            max_history: 10,
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Add more than max_history data points
        for i in 0..20 {
            predictor.record_metric(peer, QualityMetric::Bandwidth, i as f64 * 100.0);
        }

        let stats = predictor.get_stats();
        assert_eq!(stats.total_data_points, 10); // Should be limited to max_history
    }

    #[test]
    fn test_degrading_trend() {
        let config = PredictorConfig {
            min_data_points: 5,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // Decreasing trend
        for i in (0..10).rev() {
            predictor.record_metric(peer, QualityMetric::SuccessRate, i as f64 * 0.1);
        }

        let prediction = predictor.predict(&peer, QualityMetric::SuccessRate);
        assert!(prediction.is_some());
        assert!(prediction.unwrap().trend < 0.0); // Negative trend
    }

    #[test]
    fn test_latency_normalization() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer = create_test_peer();

        // High latency (worse quality)
        for _ in 0..5 {
            predictor.record_metric(peer, QualityMetric::Latency, 400.0); // 400ms
        }

        let score = predictor.get_composite_score(&peer);
        assert!(score.is_some());
        // High latency should result in lower composite score
    }

    #[test]
    fn test_predictor_stats() {
        let config = PredictorConfig {
            min_data_points: 3,
            ..Default::default()
        };

        let predictor = PeerQualityPredictor::new(config);
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        for _ in 0..5 {
            predictor.record_metric(peer1, QualityMetric::Bandwidth, 1000.0);
            predictor.record_metric(peer1, QualityMetric::Latency, 50.0);
            predictor.record_metric(peer2, QualityMetric::Bandwidth, 2000.0);
        }

        let stats = predictor.get_stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_metrics, 3); // 2 for peer1, 1 for peer2
        assert_eq!(stats.total_data_points, 15); // 5+5+5
    }
}
