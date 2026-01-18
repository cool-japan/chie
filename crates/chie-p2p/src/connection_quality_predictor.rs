//! Connection quality prediction for proactive peer selection.
//!
//! This module predicts connection quality before establishing connections,
//! allowing the system to make better peer selection decisions and avoid
//! poor-quality connections.
//!
//! # Features
//!
//! - **Quality Prediction**: Predicts connection quality based on historical data
//! - **Multi-factor Analysis**: Considers latency, bandwidth, stability, and success rate
//! - **Machine Learning Models**: Supports multiple prediction models (SMA, EMA, Weighted)
//! - **Confidence Scoring**: Provides confidence levels for predictions
//! - **Adaptive Learning**: Continuously learns from actual connection outcomes
//! - **Fast Lookups**: Optimized for low-latency predictions
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::connection_quality_predictor::{ConnectionQualityPredictor, PredictorConfig, PredictionModel};
//!
//! let config = PredictorConfig {
//!     model: PredictionModel::ExponentialMovingAverage,
//!     min_samples: 3,
//!     prediction_window: 100,
//!     ema_alpha: 0.3,
//! };
//!
//! let predictor = ConnectionQualityPredictor::new(config);
//!
//! // Record connection outcomes
//! predictor.record_connection("peer1", true, 120.0, 1500.0); // success, 120ms latency, 1500KB/s bandwidth
//! predictor.record_connection("peer1", true, 110.0, 1600.0);
//!
//! // Predict quality before connecting
//! if let Some(prediction) = predictor.predict_quality("peer1") {
//!     println!("Predicted quality: {:.2}, confidence: {:.2}",
//!              prediction.quality_score, prediction.confidence);
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

/// Prediction model algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionModel {
    /// Simple Moving Average
    SimpleMovingAverage,
    /// Exponential Moving Average (more weight to recent)
    ExponentialMovingAverage,
    /// Weighted average with recency bias
    WeightedAverage,
}

/// Configuration for quality predictor
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// Prediction model to use
    pub model: PredictionModel,
    /// Minimum samples required for prediction
    pub min_samples: usize,
    /// Number of recent samples to consider
    pub prediction_window: usize,
    /// Alpha parameter for EMA (0.0-1.0, higher = more weight to recent)
    pub ema_alpha: f64,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            model: PredictionModel::ExponentialMovingAverage,
            min_samples: 3,
            prediction_window: 100,
            ema_alpha: 0.3,
        }
    }
}

/// A recorded connection sample
#[derive(Debug, Clone)]
struct ConnectionSample {
    /// Whether connection was successful
    success: bool,
    /// Latency in milliseconds (if successful)
    latency_ms: f64,
    /// Bandwidth in KB/s (if successful)
    bandwidth_kbps: f64,
    /// Calculated quality score (0.0-1.0)
    quality_score: f64,
}

impl ConnectionSample {
    fn new(success: bool, latency_ms: f64, bandwidth_kbps: f64) -> Self {
        // Calculate quality score from metrics
        let quality_score = if success {
            Self::calculate_quality(latency_ms, bandwidth_kbps)
        } else {
            0.0 // Failed connection
        };

        Self {
            success,
            latency_ms,
            bandwidth_kbps,
            quality_score,
        }
    }

    fn calculate_quality(latency_ms: f64, bandwidth_kbps: f64) -> f64 {
        // Quality is a combination of low latency and high bandwidth
        // Latency component (lower is better, 0ms=1.0, 500ms+=0.0)
        let latency_score = (1.0 - (latency_ms / 500.0).clamp(0.0, 1.0)).max(0.0);

        // Bandwidth component (higher is better, 0KB/s=0.0, 10MB/s+=1.0)
        let bandwidth_score = (bandwidth_kbps / 10240.0).clamp(0.0, 1.0);

        // Weighted combination (latency is more important for P2P)
        0.6 * latency_score + 0.4 * bandwidth_score
    }
}

/// Prediction result
#[derive(Debug, Clone)]
pub struct QualityPrediction {
    /// Predicted quality score (0.0-1.0)
    pub quality_score: f64,
    /// Confidence in prediction (0.0-1.0)
    pub confidence: f64,
    /// Predicted latency (milliseconds)
    pub predicted_latency_ms: f64,
    /// Predicted bandwidth (KB/s)
    pub predicted_bandwidth_kbps: f64,
    /// Success probability (0.0-1.0)
    pub success_probability: f64,
    /// Number of samples used
    pub sample_count: usize,
}

/// Per-peer connection history
#[derive(Debug, Clone)]
struct PeerHistory {
    /// Circular buffer of connection samples
    samples: VecDeque<ConnectionSample>,
    /// Total connections attempted
    total_attempts: u64,
    /// Total successful connections
    total_successes: u64,
}

impl PeerHistory {
    fn new(window_size: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(window_size),
            total_attempts: 0,
            total_successes: 0,
        }
    }

    fn add_sample(&mut self, sample: ConnectionSample, max_samples: usize) {
        if self.samples.len() >= max_samples {
            self.samples.pop_front();
        }
        let success = sample.success;
        self.samples.push_back(sample);
        self.total_attempts += 1;
        if success {
            self.total_successes += 1;
        }
    }

    fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            0.0
        } else {
            self.total_successes as f64 / self.total_attempts as f64
        }
    }
}

/// Statistics for quality predictor
#[derive(Debug, Clone, Default)]
pub struct PredictorStats {
    /// Total predictions made
    pub total_predictions: u64,
    /// Total connections recorded
    pub total_connections: u64,
    /// Number of peers tracked
    pub tracked_peers: usize,
    /// Average prediction confidence
    pub avg_confidence: f64,
    /// Average predicted quality
    pub avg_predicted_quality: f64,
}

/// Connection quality predictor
pub struct ConnectionQualityPredictor {
    config: PredictorConfig,
    history: Arc<RwLock<HashMap<String, PeerHistory>>>,
    stats: Arc<RwLock<PredictorStats>>,
}

impl ConnectionQualityPredictor {
    /// Creates a new connection quality predictor
    pub fn new(config: PredictorConfig) -> Self {
        Self {
            config,
            history: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PredictorStats::default())),
        }
    }

    /// Records a connection attempt and its outcome
    pub fn record_connection(
        &self,
        peer_id: &str,
        success: bool,
        latency_ms: f64,
        bandwidth_kbps: f64,
    ) {
        let sample = ConnectionSample::new(success, latency_ms, bandwidth_kbps);

        let mut history = self.history.write().unwrap();
        let peer = history
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerHistory::new(self.config.prediction_window));

        peer.add_sample(sample, self.config.prediction_window);

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_connections += 1;
        stats.tracked_peers = history.len();
    }

    /// Predicts connection quality for a peer
    pub fn predict_quality(&self, peer_id: &str) -> Option<QualityPrediction> {
        let history = self.history.read().unwrap();

        if let Some(peer) = history.get(peer_id) {
            if peer.samples.len() < self.config.min_samples {
                return None; // Not enough data
            }

            let prediction = match self.config.model {
                PredictionModel::SimpleMovingAverage => self.predict_sma(peer),
                PredictionModel::ExponentialMovingAverage => self.predict_ema(peer),
                PredictionModel::WeightedAverage => self.predict_weighted(peer),
            };

            // Update stats
            let mut stats = self.stats.write().unwrap();
            stats.total_predictions += 1;

            // Update running averages
            let n = stats.total_predictions as f64;
            stats.avg_confidence = (stats.avg_confidence * (n - 1.0) + prediction.confidence) / n;
            stats.avg_predicted_quality =
                (stats.avg_predicted_quality * (n - 1.0) + prediction.quality_score) / n;

            Some(prediction)
        } else {
            None
        }
    }

    fn predict_sma(&self, peer: &PeerHistory) -> QualityPrediction {
        let samples: Vec<_> = peer.samples.iter().collect();
        let count = samples.len();

        let avg_quality: f64 = samples.iter().map(|s| s.quality_score).sum::<f64>() / count as f64;

        let avg_latency: f64 = samples
            .iter()
            .filter(|s| s.success)
            .map(|s| s.latency_ms)
            .sum::<f64>()
            / peer.total_successes.max(1) as f64;

        let avg_bandwidth: f64 = samples
            .iter()
            .filter(|s| s.success)
            .map(|s| s.bandwidth_kbps)
            .sum::<f64>()
            / peer.total_successes.max(1) as f64;

        let confidence = (count as f64 / self.config.prediction_window as f64).min(1.0);

        QualityPrediction {
            quality_score: avg_quality,
            confidence,
            predicted_latency_ms: avg_latency,
            predicted_bandwidth_kbps: avg_bandwidth,
            success_probability: peer.success_rate(),
            sample_count: count,
        }
    }

    fn predict_ema(&self, peer: &PeerHistory) -> QualityPrediction {
        let alpha = self.config.ema_alpha;
        let samples: Vec<_> = peer.samples.iter().collect();
        let count = samples.len();

        // EMA for quality
        let mut ema_quality = samples[0].quality_score;
        for sample in samples.iter().skip(1) {
            ema_quality = alpha * sample.quality_score + (1.0 - alpha) * ema_quality;
        }

        // EMA for latency (successful connections only)
        let mut ema_latency = 0.0;
        let mut latency_count = 0;
        for sample in samples.iter() {
            if sample.success {
                if latency_count == 0 {
                    ema_latency = sample.latency_ms;
                } else {
                    ema_latency = alpha * sample.latency_ms + (1.0 - alpha) * ema_latency;
                }
                latency_count += 1;
            }
        }

        // EMA for bandwidth
        let mut ema_bandwidth = 0.0;
        let mut bandwidth_count = 0;
        for sample in samples.iter() {
            if sample.success {
                if bandwidth_count == 0 {
                    ema_bandwidth = sample.bandwidth_kbps;
                } else {
                    ema_bandwidth = alpha * sample.bandwidth_kbps + (1.0 - alpha) * ema_bandwidth;
                }
                bandwidth_count += 1;
            }
        }

        let confidence = (count as f64 / self.config.prediction_window as f64).min(1.0);

        QualityPrediction {
            quality_score: ema_quality,
            confidence,
            predicted_latency_ms: ema_latency,
            predicted_bandwidth_kbps: ema_bandwidth,
            success_probability: peer.success_rate(),
            sample_count: count,
        }
    }

    fn predict_weighted(&self, peer: &PeerHistory) -> QualityPrediction {
        let samples: Vec<_> = peer.samples.iter().collect();
        let count = samples.len();

        // More recent samples get higher weights
        let mut total_weight = 0.0;
        let mut weighted_quality = 0.0;
        let mut weighted_latency = 0.0;
        let mut weighted_bandwidth = 0.0;
        let mut success_count = 0;

        for (i, sample) in samples.iter().enumerate() {
            let weight = (i + 1) as f64; // Linear weight increase
            total_weight += weight;
            weighted_quality += sample.quality_score * weight;

            if sample.success {
                weighted_latency += sample.latency_ms * weight;
                weighted_bandwidth += sample.bandwidth_kbps * weight;
                success_count += 1;
            }
        }

        let avg_quality = weighted_quality / total_weight;
        let avg_latency = if success_count > 0 {
            weighted_latency / total_weight
        } else {
            0.0
        };
        let avg_bandwidth = if success_count > 0 {
            weighted_bandwidth / total_weight
        } else {
            0.0
        };

        let confidence = (count as f64 / self.config.prediction_window as f64).min(1.0);

        QualityPrediction {
            quality_score: avg_quality,
            confidence,
            predicted_latency_ms: avg_latency,
            predicted_bandwidth_kbps: avg_bandwidth,
            success_probability: peer.success_rate(),
            sample_count: count,
        }
    }

    /// Removes a peer from tracking
    pub fn remove_peer(&self, peer_id: &str) {
        let mut history = self.history.write().unwrap();
        history.remove(peer_id);

        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = history.len();
    }

    /// Clears all peer data
    pub fn clear(&self) {
        let mut history = self.history.write().unwrap();
        history.clear();

        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = 0;
    }

    /// Gets current statistics
    pub fn stats(&self) -> PredictorStats {
        self.stats.read().unwrap().clone()
    }

    /// Gets the configuration
    pub fn config(&self) -> &PredictorConfig {
        &self.config
    }

    /// Gets all tracked peer IDs
    pub fn tracked_peer_ids(&self) -> Vec<String> {
        let history = self.history.read().unwrap();
        history.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = PredictorConfig::default();
        assert_eq!(config.model, PredictionModel::ExponentialMovingAverage);
        assert_eq!(config.min_samples, 3);
        assert_eq!(config.prediction_window, 100);
        assert_eq!(config.ema_alpha, 0.3);
    }

    #[test]
    fn test_new_predictor() {
        let predictor = ConnectionQualityPredictor::new(PredictorConfig::default());
        let stats = predictor.stats();

        assert_eq!(stats.total_predictions, 0);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_record_connection() {
        let predictor = ConnectionQualityPredictor::new(PredictorConfig::default());

        predictor.record_connection("peer1", true, 100.0, 1000.0);

        let stats = predictor.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.tracked_peers, 1);
    }

    #[test]
    fn test_predict_insufficient_samples() {
        let config = PredictorConfig {
            min_samples: 5,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 110.0, 1100.0);

        // Should return None with < 5 samples
        assert!(predictor.predict_quality("peer1").is_none());
    }

    #[test]
    fn test_predict_with_sufficient_samples() {
        let config = PredictorConfig {
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 110.0, 1100.0);
        predictor.record_connection("peer1", true, 105.0, 1050.0);

        let prediction = predictor.predict_quality("peer1");
        assert!(prediction.is_some());

        let pred = prediction.unwrap();
        assert!(pred.quality_score > 0.0 && pred.quality_score <= 1.0);
        assert!(pred.confidence > 0.0);
        assert_eq!(pred.sample_count, 3);
    }

    #[test]
    fn test_predict_sma_model() {
        let config = PredictorConfig {
            model: PredictionModel::SimpleMovingAverage,
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 200.0, 2000.0);
        predictor.record_connection("peer1", true, 150.0, 1500.0);

        let prediction = predictor.predict_quality("peer1").unwrap();

        // Average latency should be 150ms
        assert!((prediction.predicted_latency_ms - 150.0).abs() < 0.1);

        // Average bandwidth should be 1500 KB/s
        assert!((prediction.predicted_bandwidth_kbps - 1500.0).abs() < 0.1);
    }

    #[test]
    fn test_predict_ema_model() {
        let config = PredictorConfig {
            model: PredictionModel::ExponentialMovingAverage,
            min_samples: 3,
            ema_alpha: 0.5,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 200.0, 2000.0);
        predictor.record_connection("peer1", true, 300.0, 3000.0);

        let prediction = predictor.predict_quality("peer1").unwrap();

        // EMA should weight more recent values higher
        assert!(prediction.predicted_latency_ms > 150.0); // Closer to recent 300ms
    }

    #[test]
    fn test_predict_weighted_model() {
        let config = PredictorConfig {
            model: PredictionModel::WeightedAverage,
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 200.0, 2000.0);
        predictor.record_connection("peer1", true, 300.0, 3000.0);

        let prediction = predictor.predict_quality("peer1").unwrap();

        // Weighted average should favor more recent values
        assert!(prediction.predicted_latency_ms > 150.0);
    }

    #[test]
    fn test_failed_connection() {
        let config = PredictorConfig {
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", false, 0.0, 0.0); // Failed
        predictor.record_connection("peer1", true, 110.0, 1100.0);

        let prediction = predictor.predict_quality("peer1").unwrap();

        // Success probability should reflect 2/3 success rate
        assert!((prediction.success_probability - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_quality_score_calculation() {
        let config = PredictorConfig {
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        // Low latency, high bandwidth = high quality
        predictor.record_connection("peer1", true, 10.0, 10000.0);
        predictor.record_connection("peer1", true, 15.0, 9500.0);
        predictor.record_connection("peer1", true, 12.0, 9800.0);

        let pred1 = predictor.predict_quality("peer1").unwrap();

        // High latency, low bandwidth = low quality
        predictor.record_connection("peer2", true, 400.0, 100.0);
        predictor.record_connection("peer2", true, 450.0, 120.0);
        predictor.record_connection("peer2", true, 420.0, 110.0);

        let pred2 = predictor.predict_quality("peer2").unwrap();

        // Peer1 should have significantly higher quality
        assert!(pred1.quality_score > pred2.quality_score);
        assert!(pred1.quality_score > 0.8);
        assert!(pred2.quality_score < 0.3);
    }

    #[test]
    fn test_confidence_increases_with_samples() {
        let config = PredictorConfig {
            min_samples: 3,
            prediction_window: 10,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        // Record 3 samples
        for _ in 0..3 {
            predictor.record_connection("peer1", true, 100.0, 1000.0);
        }
        let pred1 = predictor.predict_quality("peer1").unwrap();

        // Record 7 more samples (total 10)
        for _ in 0..7 {
            predictor.record_connection("peer1", true, 100.0, 1000.0);
        }
        let pred2 = predictor.predict_quality("peer1").unwrap();

        // Confidence should increase with more samples
        assert!(pred2.confidence > pred1.confidence);
        assert_eq!(pred2.confidence, 1.0); // 10/10 = full confidence
    }

    #[test]
    fn test_remove_peer() {
        let predictor = ConnectionQualityPredictor::new(PredictorConfig::default());

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.remove_peer("peer1");

        assert!(predictor.predict_quality("peer1").is_none());

        let stats = predictor.stats();
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_clear() {
        let predictor = ConnectionQualityPredictor::new(PredictorConfig::default());

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer2", true, 200.0, 2000.0);

        predictor.clear();

        let stats = predictor.stats();
        assert_eq!(stats.tracked_peers, 0);

        assert!(predictor.predict_quality("peer1").is_none());
        assert!(predictor.predict_quality("peer2").is_none());
    }

    #[test]
    fn test_tracked_peer_ids() {
        let predictor = ConnectionQualityPredictor::new(PredictorConfig::default());

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer2", true, 200.0, 2000.0);

        let mut peer_ids = predictor.tracked_peer_ids();
        peer_ids.sort();

        assert_eq!(peer_ids, vec!["peer1", "peer2"]);
    }

    #[test]
    fn test_window_size_limit() {
        let config = PredictorConfig {
            prediction_window: 5,
            min_samples: 3,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        // Record more samples than window size
        for i in 0..10 {
            predictor.record_connection("peer1", true, 100.0 + i as f64, 1000.0);
        }

        let prediction = predictor.predict_quality("peer1").unwrap();

        // Should only use last 5 samples
        assert_eq!(prediction.sample_count, 5);
    }

    #[test]
    fn test_concurrent_access() {
        let predictor = Arc::new(ConnectionQualityPredictor::new(PredictorConfig::default()));
        let mut handles = vec![];

        for i in 0..5 {
            let predictor_clone = Arc::clone(&predictor);
            let handle = thread::spawn(move || {
                let peer_id = format!("peer{}", i);
                for j in 0..10 {
                    predictor_clone.record_connection(&peer_id, true, 100.0 + j as f64, 1000.0);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = predictor.stats();
        assert_eq!(stats.total_connections, 50);
        assert_eq!(stats.tracked_peers, 5);
    }

    #[test]
    fn test_stats_tracking() {
        let config = PredictorConfig {
            min_samples: 2,
            ..Default::default()
        };
        let predictor = ConnectionQualityPredictor::new(config);

        predictor.record_connection("peer1", true, 100.0, 1000.0);
        predictor.record_connection("peer1", true, 110.0, 1100.0);

        predictor.predict_quality("peer1");

        let stats = predictor.stats();
        assert_eq!(stats.total_predictions, 1);
        assert_eq!(stats.total_connections, 2);
        assert!(stats.avg_confidence > 0.0);
        assert!(stats.avg_predicted_quality > 0.0);
    }
}
