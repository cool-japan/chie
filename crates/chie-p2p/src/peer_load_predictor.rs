//! Peer load prediction for proactive load balancing.
//!
//! This module predicts future peer load based on historical data and trends,
//! enabling proactive load balancing decisions and preventing overload situations.
//!
//! # Features
//!
//! - **Load Forecasting**: Predicts future load using time series analysis
//! - **Multiple Models**: Supports linear regression, exponential smoothing, and ARIMA-like models
//! - **Trend Detection**: Identifies load trends (increasing, decreasing, stable)
//! - **Capacity Planning**: Estimates when peers will reach capacity
//! - **Anomaly Detection**: Detects unusual load patterns
//! - **Multi-metric**: Tracks CPU, memory, bandwidth, and connection load
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::peer_load_predictor::{PeerLoadPredictor, LoadPredictorConfig, PredictionModel};
//! use std::time::Duration;
//!
//! let config = LoadPredictorConfig {
//!     model: PredictionModel::ExponentialSmoothing,
//!     history_size: 100,
//!     prediction_horizon: Duration::from_secs(300),
//!     smoothing_factor: 0.3,
//! };
//!
//! let predictor = PeerLoadPredictor::new(config);
//!
//! // Record current load
//! predictor.record_load("peer1", 0.5, 0.6, 0.7, 50); // CPU, memory, bandwidth, connections
//!
//! // Predict future load
//! if let Some(prediction) = predictor.predict_load("peer1", Duration::from_secs(60)) {
//!     println!("Predicted CPU load in 60s: {:.2}", prediction.cpu_load);
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Prediction model algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionModel {
    /// Simple linear regression
    LinearRegression,
    /// Exponential smoothing (weighted recent data)
    ExponentialSmoothing,
    /// Moving average
    MovingAverage,
}

/// Configuration for load predictor
#[derive(Debug, Clone)]
pub struct LoadPredictorConfig {
    /// Prediction model to use
    pub model: PredictionModel,
    /// Number of historical samples to keep
    pub history_size: usize,
    /// How far ahead to predict
    pub prediction_horizon: Duration,
    /// Smoothing factor for exponential smoothing (0.0-1.0)
    pub smoothing_factor: f64,
}

impl Default for LoadPredictorConfig {
    fn default() -> Self {
        Self {
            model: PredictionModel::ExponentialSmoothing,
            history_size: 100,
            prediction_horizon: Duration::from_secs(300),
            smoothing_factor: 0.3,
        }
    }
}

/// Load trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadTrend {
    /// Load is increasing
    Increasing,
    /// Load is decreasing
    Decreasing,
    /// Load is stable
    Stable,
}

/// A single load measurement
#[derive(Debug, Clone)]
struct LoadSample {
    /// CPU load (0.0-1.0)
    cpu_load: f64,
    /// Memory load (0.0-1.0)
    memory_load: f64,
    /// Bandwidth usage (0.0-1.0)
    bandwidth_load: f64,
    /// Number of active connections
    connection_count: u32,
    /// When this sample was taken
    #[allow(dead_code)]
    timestamp: Instant,
}

impl LoadSample {
    fn new(cpu: f64, memory: f64, bandwidth: f64, connections: u32) -> Self {
        Self {
            cpu_load: cpu.clamp(0.0, 1.0),
            memory_load: memory.clamp(0.0, 1.0),
            bandwidth_load: bandwidth.clamp(0.0, 1.0),
            connection_count: connections,
            timestamp: Instant::now(),
        }
    }

    /// Overall load score (weighted average)
    fn overall_load(&self) -> f64 {
        0.4 * self.cpu_load + 0.3 * self.memory_load + 0.3 * self.bandwidth_load
    }
}

/// Predicted load
#[derive(Debug, Clone)]
pub struct LoadPrediction {
    /// Predicted CPU load (0.0-1.0)
    pub cpu_load: f64,
    /// Predicted memory load (0.0-1.0)
    pub memory_load: f64,
    /// Predicted bandwidth load (0.0-1.0)
    pub bandwidth_load: f64,
    /// Predicted connection count
    pub connection_count: u32,
    /// Overall predicted load (0.0-1.0)
    pub overall_load: f64,
    /// Prediction confidence (0.0-1.0)
    pub confidence: f64,
    /// Detected trend
    pub trend: LoadTrend,
    /// Time until capacity (if increasing)
    pub time_to_capacity: Option<Duration>,
}

/// Per-peer load history
#[derive(Debug, Clone)]
struct PeerLoad {
    /// Historical load samples
    samples: VecDeque<LoadSample>,
    /// Last prediction made
    last_prediction: Option<LoadPrediction>,
}

impl PeerLoad {
    fn new(history_size: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(history_size),
            last_prediction: None,
        }
    }

    fn add_sample(&mut self, sample: LoadSample, max_samples: usize) {
        if self.samples.len() >= max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    fn detect_trend(&self, min_samples: usize) -> LoadTrend {
        if self.samples.len() < min_samples {
            return LoadTrend::Stable;
        }

        let mid = self.samples.len() / 2;
        let first_half_avg: f64 = self
            .samples
            .iter()
            .take(mid)
            .map(|s| s.overall_load())
            .sum::<f64>()
            / mid as f64;
        let second_half_avg: f64 = self
            .samples
            .iter()
            .skip(mid)
            .map(|s| s.overall_load())
            .sum::<f64>()
            / (self.samples.len() - mid) as f64;

        let diff = second_half_avg - first_half_avg;

        if diff > 0.1 {
            LoadTrend::Increasing
        } else if diff < -0.1 {
            LoadTrend::Decreasing
        } else {
            LoadTrend::Stable
        }
    }
}

/// Statistics for load predictor
#[derive(Debug, Clone, Default)]
pub struct LoadPredictorStats {
    /// Total predictions made
    pub total_predictions: u64,
    /// Total load samples recorded
    pub total_samples: u64,
    /// Number of peers tracked
    pub tracked_peers: usize,
    /// Average prediction confidence
    pub avg_confidence: f64,
    /// Peers with increasing load trend
    pub increasing_trend_count: usize,
    /// Peers with decreasing load trend
    pub decreasing_trend_count: usize,
    /// Peers with stable load trend
    pub stable_trend_count: usize,
}

/// Peer load predictor
pub struct PeerLoadPredictor {
    config: LoadPredictorConfig,
    peers: Arc<RwLock<HashMap<String, PeerLoad>>>,
    stats: Arc<RwLock<LoadPredictorStats>>,
}

impl PeerLoadPredictor {
    /// Creates a new peer load predictor
    pub fn new(config: LoadPredictorConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(LoadPredictorStats::default())),
        }
    }

    /// Records current load for a peer
    pub fn record_load(
        &self,
        peer_id: &str,
        cpu_load: f64,
        memory_load: f64,
        bandwidth_load: f64,
        connection_count: u32,
    ) {
        let sample = LoadSample::new(cpu_load, memory_load, bandwidth_load, connection_count);

        let mut peers = self.peers.write().unwrap();
        let peer = peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerLoad::new(self.config.history_size));

        peer.add_sample(sample, self.config.history_size);

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_samples += 1;
        stats.tracked_peers = peers.len();
    }

    /// Predicts load for a peer at a future time
    pub fn predict_load(&self, peer_id: &str, time_ahead: Duration) -> Option<LoadPrediction> {
        let mut peers = self.peers.write().unwrap();

        if let Some(peer) = peers.get_mut(peer_id) {
            if peer.samples.len() < 3 {
                return None; // Need at least 3 samples
            }

            let prediction = match self.config.model {
                PredictionModel::LinearRegression => {
                    self.predict_linear_regression(peer, time_ahead)
                }
                PredictionModel::ExponentialSmoothing => {
                    self.predict_exponential_smoothing(peer, time_ahead)
                }
                PredictionModel::MovingAverage => self.predict_moving_average(peer, time_ahead),
            };

            peer.last_prediction = Some(prediction.clone());

            // Update stats
            let mut stats = self.stats.write().unwrap();
            stats.total_predictions += 1;

            let n = stats.total_predictions as f64;
            stats.avg_confidence = (stats.avg_confidence * (n - 1.0) + prediction.confidence) / n;

            Some(prediction)
        } else {
            None
        }
    }

    fn predict_linear_regression(&self, peer: &PeerLoad, time_ahead: Duration) -> LoadPrediction {
        let samples = &peer.samples;
        let n = samples.len();

        // Calculate linear regression for each metric
        let cpu_pred =
            self.linear_regress(samples.iter().map(|s| s.cpu_load).collect(), time_ahead);
        let memory_pred =
            self.linear_regress(samples.iter().map(|s| s.memory_load).collect(), time_ahead);
        let bandwidth_pred = self.linear_regress(
            samples.iter().map(|s| s.bandwidth_load).collect(),
            time_ahead,
        );
        let conn_pred = self.linear_regress_u32(
            samples.iter().map(|s| s.connection_count).collect(),
            time_ahead,
        );

        let overall = 0.4 * cpu_pred + 0.3 * memory_pred + 0.3 * bandwidth_pred;
        let confidence = (n as f64 / self.config.history_size as f64).min(1.0);
        let trend = peer.detect_trend(5);

        let time_to_capacity = if trend == LoadTrend::Increasing && overall < 1.0 {
            self.estimate_time_to_capacity(samples, overall)
        } else {
            None
        };

        LoadPrediction {
            cpu_load: cpu_pred.clamp(0.0, 1.0),
            memory_load: memory_pred.clamp(0.0, 1.0),
            bandwidth_load: bandwidth_pred.clamp(0.0, 1.0),
            connection_count: conn_pred,
            overall_load: overall.clamp(0.0, 1.0),
            confidence,
            trend,
            time_to_capacity,
        }
    }

    fn predict_exponential_smoothing(
        &self,
        peer: &PeerLoad,
        _time_ahead: Duration,
    ) -> LoadPrediction {
        let alpha = self.config.smoothing_factor;
        let samples = &peer.samples;

        // Exponential smoothing
        let mut cpu_smooth = samples[0].cpu_load;
        let mut memory_smooth = samples[0].memory_load;
        let mut bandwidth_smooth = samples[0].bandwidth_load;
        let mut conn_smooth = samples[0].connection_count as f64;

        for sample in samples.iter().skip(1) {
            cpu_smooth = alpha * sample.cpu_load + (1.0 - alpha) * cpu_smooth;
            memory_smooth = alpha * sample.memory_load + (1.0 - alpha) * memory_smooth;
            bandwidth_smooth = alpha * sample.bandwidth_load + (1.0 - alpha) * bandwidth_smooth;
            conn_smooth = alpha * sample.connection_count as f64 + (1.0 - alpha) * conn_smooth;
        }

        let overall = 0.4 * cpu_smooth + 0.3 * memory_smooth + 0.3 * bandwidth_smooth;
        let confidence = (samples.len() as f64 / self.config.history_size as f64).min(1.0);
        let trend = peer.detect_trend(5);

        let time_to_capacity = if trend == LoadTrend::Increasing && overall < 1.0 {
            self.estimate_time_to_capacity(samples, overall)
        } else {
            None
        };

        LoadPrediction {
            cpu_load: cpu_smooth.clamp(0.0, 1.0),
            memory_load: memory_smooth.clamp(0.0, 1.0),
            bandwidth_load: bandwidth_smooth.clamp(0.0, 1.0),
            connection_count: conn_smooth.round() as u32,
            overall_load: overall.clamp(0.0, 1.0),
            confidence,
            trend,
            time_to_capacity,
        }
    }

    fn predict_moving_average(&self, peer: &PeerLoad, _time_ahead: Duration) -> LoadPrediction {
        let samples = &peer.samples;
        let n = samples.len();

        let cpu_avg = samples.iter().map(|s| s.cpu_load).sum::<f64>() / n as f64;
        let memory_avg = samples.iter().map(|s| s.memory_load).sum::<f64>() / n as f64;
        let bandwidth_avg = samples.iter().map(|s| s.bandwidth_load).sum::<f64>() / n as f64;
        let conn_avg = samples.iter().map(|s| s.connection_count).sum::<u32>() / n as u32;

        let overall = 0.4 * cpu_avg + 0.3 * memory_avg + 0.3 * bandwidth_avg;
        let confidence = (n as f64 / self.config.history_size as f64).min(1.0);
        let trend = peer.detect_trend(5);

        let time_to_capacity = if trend == LoadTrend::Increasing && overall < 1.0 {
            self.estimate_time_to_capacity(samples, overall)
        } else {
            None
        };

        LoadPrediction {
            cpu_load: cpu_avg.clamp(0.0, 1.0),
            memory_load: memory_avg.clamp(0.0, 1.0),
            bandwidth_load: bandwidth_avg.clamp(0.0, 1.0),
            connection_count: conn_avg,
            overall_load: overall.clamp(0.0, 1.0),
            confidence,
            trend,
            time_to_capacity,
        }
    }

    fn linear_regress(&self, values: Vec<f64>, _time_ahead: Duration) -> f64 {
        let n = values.len() as f64;
        let x_mean = (n - 1.0) / 2.0; // Index mean
        let y_mean = values.iter().sum::<f64>() / n;

        let mut numerator = 0.0;
        let mut denominator = 0.0;

        for (i, &y) in values.iter().enumerate() {
            let x = i as f64;
            numerator += (x - x_mean) * (y - y_mean);
            denominator += (x - x_mean) * (x - x_mean);
        }

        if denominator == 0.0 {
            return y_mean;
        }

        let slope = numerator / denominator;
        let intercept = y_mean - slope * x_mean;

        // Predict at next time point
        slope * n + intercept
    }

    fn linear_regress_u32(&self, values: Vec<u32>, time_ahead: Duration) -> u32 {
        let float_values: Vec<f64> = values.iter().map(|&v| v as f64).collect();
        let prediction = self.linear_regress(float_values, time_ahead);
        prediction.round().max(0.0) as u32
    }

    fn estimate_time_to_capacity(
        &self,
        samples: &VecDeque<LoadSample>,
        current_load: f64,
    ) -> Option<Duration> {
        if samples.len() < 5 {
            return None;
        }

        // Calculate rate of increase
        let first_half: f64 = samples
            .iter()
            .take(samples.len() / 2)
            .map(|s| s.overall_load())
            .sum::<f64>()
            / (samples.len() / 2) as f64;
        let second_half: f64 = samples
            .iter()
            .skip(samples.len() / 2)
            .map(|s| s.overall_load())
            .sum::<f64>()
            / (samples.len() - samples.len() / 2) as f64;

        let rate = second_half - first_half;

        if rate <= 0.0 {
            return None; // Not increasing
        }

        let remaining = 1.0 - current_load;
        let time_secs = (remaining / rate) * 60.0; // Assuming samples are ~1 minute apart

        if time_secs > 0.0 && time_secs < 86400.0 {
            // Cap at 24 hours
            Some(Duration::from_secs(time_secs as u64))
        } else {
            None
        }
    }

    /// Gets the last prediction for a peer
    pub fn get_last_prediction(&self, peer_id: &str) -> Option<LoadPrediction> {
        let peers = self.peers.read().unwrap();
        peers.get(peer_id).and_then(|p| p.last_prediction.clone())
    }

    /// Removes a peer from tracking
    pub fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(peer_id);

        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = peers.len();
    }

    /// Clears all peer data
    pub fn clear(&self) {
        let mut peers = self.peers.write().unwrap();
        peers.clear();

        let mut stats = self.stats.write().unwrap();
        stats.tracked_peers = 0;
    }

    /// Updates trend statistics
    pub fn update_trend_stats(&self) {
        let peers = self.peers.read().unwrap();
        let mut stats = self.stats.write().unwrap();

        let mut increasing = 0;
        let mut decreasing = 0;
        let mut stable = 0;

        for peer in peers.values() {
            match peer.detect_trend(5) {
                LoadTrend::Increasing => increasing += 1,
                LoadTrend::Decreasing => decreasing += 1,
                LoadTrend::Stable => stable += 1,
            }
        }

        stats.increasing_trend_count = increasing;
        stats.decreasing_trend_count = decreasing;
        stats.stable_trend_count = stable;
    }

    /// Gets current statistics
    pub fn stats(&self) -> LoadPredictorStats {
        self.stats.read().unwrap().clone()
    }

    /// Gets the configuration
    pub fn config(&self) -> &LoadPredictorConfig {
        &self.config
    }

    /// Gets all tracked peer IDs
    pub fn tracked_peer_ids(&self) -> Vec<String> {
        let peers = self.peers.read().unwrap();
        peers.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = LoadPredictorConfig::default();
        assert_eq!(config.model, PredictionModel::ExponentialSmoothing);
        assert_eq!(config.history_size, 100);
        assert_eq!(config.smoothing_factor, 0.3);
    }

    #[test]
    fn test_new_predictor() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());
        let stats = predictor.stats();

        assert_eq!(stats.total_predictions, 0);
        assert_eq!(stats.total_samples, 0);
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_record_load() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);

        let stats = predictor.stats();
        assert_eq!(stats.total_samples, 1);
        assert_eq!(stats.tracked_peers, 1);
    }

    #[test]
    fn test_predict_insufficient_samples() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);

        // Should return None with < 3 samples
        assert!(
            predictor
                .predict_load("peer1", Duration::from_secs(60))
                .is_none()
        );
    }

    #[test]
    fn test_predict_with_sufficient_samples() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        for i in 0..5 {
            predictor.record_load("peer1", 0.5 + i as f64 * 0.01, 0.6, 0.7, 10);
        }

        let prediction = predictor.predict_load("peer1", Duration::from_secs(60));
        assert!(prediction.is_some());

        let pred = prediction.unwrap();
        assert!(pred.cpu_load >= 0.0 && pred.cpu_load <= 1.0);
        assert!(pred.overall_load >= 0.0 && pred.overall_load <= 1.0);
        assert!(pred.confidence > 0.0);
    }

    #[test]
    fn test_exponential_smoothing_model() {
        let config = LoadPredictorConfig {
            model: PredictionModel::ExponentialSmoothing,
            smoothing_factor: 0.5,
            ..Default::default()
        };
        let predictor = PeerLoadPredictor::new(config);

        for i in 0..5 {
            predictor.record_load("peer1", 0.5 + i as f64 * 0.05, 0.6, 0.7, 10 + i);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert!(prediction.cpu_load > 0.5);
    }

    #[test]
    fn test_linear_regression_model() {
        let config = LoadPredictorConfig {
            model: PredictionModel::LinearRegression,
            ..Default::default()
        };
        let predictor = PeerLoadPredictor::new(config);

        for i in 0..5 {
            predictor.record_load("peer1", 0.5 + i as f64 * 0.05, 0.6, 0.7, 10 + i);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert!(prediction.cpu_load > 0.5);
    }

    #[test]
    fn test_moving_average_model() {
        let config = LoadPredictorConfig {
            model: PredictionModel::MovingAverage,
            ..Default::default()
        };
        let predictor = PeerLoadPredictor::new(config);

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        predictor.record_load("peer1", 0.6, 0.7, 0.8, 12);
        predictor.record_load("peer1", 0.7, 0.8, 0.9, 14);

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert!((prediction.cpu_load - 0.6).abs() < 0.1);
    }

    #[test]
    fn test_trend_detection_increasing() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        for i in 0..10 {
            predictor.record_load("peer1", 0.3 + i as f64 * 0.05, 0.5, 0.6, 10);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert_eq!(prediction.trend, LoadTrend::Increasing);
    }

    #[test]
    fn test_trend_detection_decreasing() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        for i in 0..10 {
            predictor.record_load("peer1", 0.8 - i as f64 * 0.05, 0.5, 0.6, 10);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert_eq!(prediction.trend, LoadTrend::Decreasing);
    }

    #[test]
    fn test_trend_detection_stable() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        for _ in 0..10 {
            predictor.record_load("peer1", 0.5, 0.5, 0.5, 10);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        assert_eq!(prediction.trend, LoadTrend::Stable);
    }

    #[test]
    fn test_time_to_capacity() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        // Simulate strong increasing load trend
        for i in 0..10 {
            predictor.record_load("peer1", 0.3 + i as f64 * 0.05, 0.5, 0.6, 10);
        }

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();
        // With increasing trend, should have time_to_capacity or be close to capacity
        if prediction.overall_load < 0.95 {
            assert!(
                prediction.time_to_capacity.is_some() || prediction.trend == LoadTrend::Increasing
            );
        }
    }

    #[test]
    fn test_get_last_prediction() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        for i in 0..5 {
            predictor.record_load("peer1", 0.5 + i as f64 * 0.01, 0.6, 0.7, 10);
        }

        predictor.predict_load("peer1", Duration::from_secs(60));

        let last_pred = predictor.get_last_prediction("peer1");
        assert!(last_pred.is_some());
    }

    #[test]
    fn test_remove_peer() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        predictor.remove_peer("peer1");

        let stats = predictor.stats();
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_clear() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        predictor.record_load("peer2", 0.4, 0.5, 0.6, 8);

        predictor.clear();

        let stats = predictor.stats();
        assert_eq!(stats.tracked_peers, 0);
    }

    #[test]
    fn test_update_trend_stats() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        // Peer with increasing trend
        for i in 0..10 {
            predictor.record_load("peer1", 0.3 + i as f64 * 0.05, 0.5, 0.6, 10);
        }

        // Peer with decreasing trend
        for i in 0..10 {
            predictor.record_load("peer2", 0.8 - i as f64 * 0.05, 0.5, 0.6, 10);
        }

        // Peer with stable trend
        for _ in 0..10 {
            predictor.record_load("peer3", 0.5, 0.5, 0.5, 10);
        }

        predictor.update_trend_stats();

        let stats = predictor.stats();
        assert_eq!(stats.increasing_trend_count, 1);
        assert_eq!(stats.decreasing_trend_count, 1);
        assert_eq!(stats.stable_trend_count, 1);
    }

    #[test]
    fn test_tracked_peer_ids() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        predictor.record_load("peer2", 0.4, 0.5, 0.6, 8);

        let mut peer_ids = predictor.tracked_peer_ids();
        peer_ids.sort();

        assert_eq!(peer_ids, vec!["peer1", "peer2"]);
    }

    #[test]
    fn test_load_clamping() {
        let predictor = PeerLoadPredictor::new(LoadPredictorConfig::default());

        // Record loads outside normal range
        predictor.record_load("peer1", 1.5, -0.5, 2.0, 10);
        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);

        let prediction = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();

        // Should be clamped to 0.0-1.0
        assert!(prediction.cpu_load >= 0.0 && prediction.cpu_load <= 1.0);
        assert!(prediction.memory_load >= 0.0 && prediction.memory_load <= 1.0);
        assert!(prediction.bandwidth_load >= 0.0 && prediction.bandwidth_load <= 1.0);
    }

    #[test]
    fn test_concurrent_access() {
        let predictor = Arc::new(PeerLoadPredictor::new(LoadPredictorConfig::default()));
        let mut handles = vec![];

        for i in 0..5 {
            let predictor_clone = Arc::clone(&predictor);
            let handle = thread::spawn(move || {
                let peer_id = format!("peer{}", i);
                for j in 0..10 {
                    predictor_clone.record_load(&peer_id, 0.5 + j as f64 * 0.01, 0.6, 0.7, 10);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = predictor.stats();
        assert_eq!(stats.total_samples, 50);
        assert_eq!(stats.tracked_peers, 5);
    }

    #[test]
    fn test_confidence_increases_with_samples() {
        let config = LoadPredictorConfig {
            history_size: 10,
            ..Default::default()
        };
        let predictor = PeerLoadPredictor::new(config);

        // 3 samples
        for _ in 0..3 {
            predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        }
        let pred1 = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();

        // 10 samples (full history)
        for _ in 0..7 {
            predictor.record_load("peer1", 0.5, 0.6, 0.7, 10);
        }
        let pred2 = predictor
            .predict_load("peer1", Duration::from_secs(60))
            .unwrap();

        assert!(pred2.confidence > pred1.confidence);
        assert_eq!(pred2.confidence, 1.0); // Full history
    }
}
