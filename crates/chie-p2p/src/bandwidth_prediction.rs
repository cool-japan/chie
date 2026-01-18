//! Bandwidth prediction module for forecasting future bandwidth availability.
//!
//! This module provides time series analysis and prediction capabilities for
//! estimating future bandwidth based on historical measurements. It supports
//! multiple prediction strategies and trend detection.
//!
//! # Example
//!
//! ```
//! use chie_p2p::bandwidth_prediction::{BandwidthPredictor, PredictionStrategy};
//! use std::time::{Duration, Instant};
//!
//! let mut predictor = BandwidthPredictor::new(PredictionStrategy::ExponentialSmoothing);
//!
//! // Record some bandwidth measurements
//! predictor.record_measurement(1_000_000, Instant::now()); // 1 MB/s
//! predictor.record_measurement(1_200_000, Instant::now()); // 1.2 MB/s
//!
//! // Predict future bandwidth
//! if let Some(prediction) = predictor.predict() {
//!     println!("Predicted bandwidth: {} bytes/s", prediction.predicted_bps);
//!     println!("Confidence: {:.2}%", prediction.confidence * 100.0);
//! }
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Prediction strategy for bandwidth forecasting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionStrategy {
    /// Simple moving average over recent measurements
    SimpleMovingAverage,
    /// Exponential smoothing with decay factor
    ExponentialSmoothing,
    /// Linear regression for trend-based prediction
    LinearRegression,
    /// Weighted moving average (recent data weighted more)
    WeightedMovingAverage,
}

/// Bandwidth trend classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthTrend {
    /// Bandwidth is improving (>5% increase over time)
    Improving,
    /// Bandwidth is stable (within 5% variance)
    Stable,
    /// Bandwidth is degrading (>5% decrease over time)
    Degrading,
    /// Not enough data to determine trend
    Unknown,
}

/// Bandwidth measurement record
#[derive(Debug, Clone)]
struct BandwidthMeasurement {
    bytes_per_second: u64,
    timestamp: Instant,
}

/// Bandwidth prediction result
#[derive(Debug, Clone)]
pub struct BandwidthPrediction {
    /// Predicted bandwidth in bytes per second
    pub predicted_bps: u64,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Detected trend
    pub trend: BandwidthTrend,
    /// Standard deviation of recent measurements
    pub std_dev: f64,
    /// Number of measurements used for prediction
    pub sample_size: usize,
}

/// Configuration for bandwidth predictor
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// Maximum number of measurements to keep
    pub max_history: usize,
    /// Minimum measurements required for prediction
    pub min_samples: usize,
    /// Time window for considering measurements (older ones are dropped)
    pub time_window: Duration,
    /// Smoothing factor for exponential smoothing (0.0 to 1.0)
    pub smoothing_factor: f64,
    /// Minimum confidence threshold for valid predictions
    pub min_confidence: f64,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            max_history: 100,
            min_samples: 5,
            time_window: Duration::from_secs(300), // 5 minutes
            smoothing_factor: 0.3,
            min_confidence: 0.5,
        }
    }
}

/// Bandwidth predictor for forecasting future bandwidth availability
pub struct BandwidthPredictor {
    strategy: PredictionStrategy,
    config: PredictorConfig,
    measurements: VecDeque<BandwidthMeasurement>,
    last_prediction: Option<BandwidthPrediction>,
}

impl BandwidthPredictor {
    /// Creates a new bandwidth predictor with the specified strategy
    pub fn new(strategy: PredictionStrategy) -> Self {
        Self::with_config(strategy, PredictorConfig::default())
    }

    /// Creates a new bandwidth predictor with custom configuration
    pub fn with_config(strategy: PredictionStrategy, config: PredictorConfig) -> Self {
        Self {
            strategy,
            config,
            measurements: VecDeque::new(),
            last_prediction: None,
        }
    }

    /// Records a new bandwidth measurement
    pub fn record_measurement(&mut self, bytes_per_second: u64, timestamp: Instant) {
        self.measurements.push_back(BandwidthMeasurement {
            bytes_per_second,
            timestamp,
        });

        // Cleanup old measurements
        self.cleanup_old_measurements();

        // Limit history size
        while self.measurements.len() > self.config.max_history {
            self.measurements.pop_front();
        }
    }

    /// Predicts future bandwidth based on historical data
    pub fn predict(&mut self) -> Option<BandwidthPrediction> {
        if self.measurements.len() < self.config.min_samples {
            return None;
        }

        let predicted_bps = match self.strategy {
            PredictionStrategy::SimpleMovingAverage => self.predict_sma(),
            PredictionStrategy::ExponentialSmoothing => self.predict_ema(),
            PredictionStrategy::LinearRegression => self.predict_linear(),
            PredictionStrategy::WeightedMovingAverage => self.predict_wma(),
        };

        let std_dev = self.calculate_std_dev();
        let trend = self.detect_trend();
        let confidence = self.calculate_confidence(std_dev);

        let prediction = BandwidthPrediction {
            predicted_bps,
            confidence,
            trend,
            std_dev,
            sample_size: self.measurements.len(),
        };

        self.last_prediction = Some(prediction.clone());
        Some(prediction)
    }

    /// Gets the last prediction without recalculating
    pub fn last_prediction(&self) -> Option<&BandwidthPrediction> {
        self.last_prediction.as_ref()
    }

    /// Gets the current trend without full prediction
    pub fn current_trend(&self) -> BandwidthTrend {
        if self.measurements.len() < self.config.min_samples {
            return BandwidthTrend::Unknown;
        }
        self.detect_trend()
    }

    /// Gets statistics about recorded measurements
    pub fn stats(&self) -> PredictorStats {
        let values: Vec<u64> = self
            .measurements
            .iter()
            .map(|m| m.bytes_per_second)
            .collect();

        PredictorStats {
            measurement_count: values.len(),
            min_bps: values.iter().copied().min().unwrap_or(0),
            max_bps: values.iter().copied().max().unwrap_or(0),
            avg_bps: if !values.is_empty() {
                values.iter().sum::<u64>() / values.len() as u64
            } else {
                0
            },
            std_dev: self.calculate_std_dev(),
            trend: self.current_trend(),
        }
    }

    /// Clears all recorded measurements
    pub fn clear(&mut self) {
        self.measurements.clear();
        self.last_prediction = None;
    }

    // Private helper methods

    fn cleanup_old_measurements(&mut self) {
        let now = Instant::now();
        let cutoff = now - self.config.time_window;

        while let Some(measurement) = self.measurements.front() {
            if measurement.timestamp < cutoff {
                self.measurements.pop_front();
            } else {
                break;
            }
        }
    }

    fn predict_sma(&self) -> u64 {
        let sum: u64 = self.measurements.iter().map(|m| m.bytes_per_second).sum();
        sum / self.measurements.len() as u64
    }

    fn predict_ema(&self) -> u64 {
        let alpha = self.config.smoothing_factor;
        let mut ema = self.measurements[0].bytes_per_second as f64;

        for measurement in self.measurements.iter().skip(1) {
            ema = alpha * measurement.bytes_per_second as f64 + (1.0 - alpha) * ema;
        }

        ema as u64
    }

    fn predict_wma(&self) -> u64 {
        let n = self.measurements.len();
        let total_weight = (n * (n + 1)) / 2;

        let weighted_sum: u64 = self
            .measurements
            .iter()
            .enumerate()
            .map(|(i, m)| m.bytes_per_second * (i + 1) as u64)
            .sum();

        weighted_sum / total_weight as u64
    }

    fn predict_linear(&self) -> u64 {
        let n = self.measurements.len() as f64;

        // Convert timestamps to seconds since first measurement
        let first_time = self.measurements[0].timestamp;
        let x_values: Vec<f64> = self
            .measurements
            .iter()
            .map(|m| m.timestamp.duration_since(first_time).as_secs_f64())
            .collect();

        let y_values: Vec<f64> = self
            .measurements
            .iter()
            .map(|m| m.bytes_per_second as f64)
            .collect();

        // Calculate means
        let x_mean: f64 = x_values.iter().sum::<f64>() / n;
        let y_mean: f64 = y_values.iter().sum::<f64>() / n;

        // Calculate slope (b) and intercept (a)
        let numerator: f64 = x_values
            .iter()
            .zip(&y_values)
            .map(|(x, y)| (x - x_mean) * (y - y_mean))
            .sum();

        let denominator: f64 = x_values.iter().map(|x| (x - x_mean).powi(2)).sum();

        if denominator == 0.0 {
            return y_mean as u64;
        }

        let slope = numerator / denominator;
        let intercept = y_mean - slope * x_mean;

        // Predict for the next time point (current time)
        let last_x = x_values.last().copied().unwrap_or(0.0);
        let predicted = slope * last_x + intercept;

        predicted.max(0.0) as u64
    }

    fn calculate_std_dev(&self) -> f64 {
        if self.measurements.len() < 2 {
            return 0.0;
        }

        let values: Vec<u64> = self
            .measurements
            .iter()
            .map(|m| m.bytes_per_second)
            .collect();
        let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;

        let variance: f64 = values
            .iter()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / values.len() as f64;

        variance.sqrt()
    }

    fn detect_trend(&self) -> BandwidthTrend {
        if self.measurements.len() < self.config.min_samples {
            return BandwidthTrend::Unknown;
        }

        // Split measurements into two halves and compare averages
        let mid = self.measurements.len() / 2;
        let first_half: Vec<u64> = self
            .measurements
            .iter()
            .take(mid)
            .map(|m| m.bytes_per_second)
            .collect();
        let second_half: Vec<u64> = self
            .measurements
            .iter()
            .skip(mid)
            .map(|m| m.bytes_per_second)
            .collect();

        let first_avg = first_half.iter().sum::<u64>() as f64 / first_half.len() as f64;
        let second_avg = second_half.iter().sum::<u64>() as f64 / second_half.len() as f64;

        let change_ratio = (second_avg - first_avg) / first_avg;

        if change_ratio > 0.05 {
            BandwidthTrend::Improving
        } else if change_ratio < -0.05 {
            BandwidthTrend::Degrading
        } else {
            BandwidthTrend::Stable
        }
    }

    fn calculate_confidence(&self, std_dev: f64) -> f64 {
        // Confidence based on coefficient of variation and sample size
        let values: Vec<u64> = self
            .measurements
            .iter()
            .map(|m| m.bytes_per_second)
            .collect();
        let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;

        if mean == 0.0 {
            return 0.0;
        }

        let cv = std_dev / mean; // Coefficient of variation
        let sample_factor =
            (self.measurements.len() as f64 / self.config.max_history as f64).min(1.0);

        // Lower CV and more samples = higher confidence
        let base_confidence = (1.0 - cv.min(1.0)) * sample_factor;
        base_confidence.clamp(0.0, 1.0)
    }
}

/// Statistics about bandwidth measurements
#[derive(Debug, Clone)]
pub struct PredictorStats {
    pub measurement_count: usize,
    pub min_bps: u64,
    pub max_bps: u64,
    pub avg_bps: u64,
    pub std_dev: f64,
    pub trend: BandwidthTrend,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predictor_new() {
        let predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        assert_eq!(predictor.measurements.len(), 0);
        assert!(predictor.last_prediction.is_none());
    }

    #[test]
    fn test_record_measurement() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        predictor.record_measurement(1_000_000, now);
        assert_eq!(predictor.measurements.len(), 1);

        predictor.record_measurement(1_200_000, now);
        assert_eq!(predictor.measurements.len(), 2);
    }

    #[test]
    fn test_predict_insufficient_samples() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        predictor.record_measurement(1_000_000, now);
        assert!(predictor.predict().is_none());
    }

    #[test]
    fn test_predict_sma() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let prediction = predictor.predict().unwrap();
        assert!(prediction.predicted_bps > 1_000_000);
        assert!(prediction.predicted_bps < 2_000_000);
        assert_eq!(prediction.sample_size, 10);
    }

    #[test]
    fn test_predict_ema() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::ExponentialSmoothing);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let prediction = predictor.predict().unwrap();
        assert!(prediction.predicted_bps > 1_000_000);
        assert!(prediction.confidence > 0.0);
    }

    #[test]
    fn test_predict_wma() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::WeightedMovingAverage);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let prediction = predictor.predict().unwrap();
        assert!(prediction.predicted_bps > 1_000_000);
        // WMA should weight recent measurements more
        assert!(prediction.predicted_bps > predictor.predict_sma());
    }

    #[test]
    fn test_predict_linear() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::LinearRegression);
        let now = Instant::now();

        // Create an upward trend
        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let prediction = predictor.predict().unwrap();
        assert!(prediction.predicted_bps > 1_000_000);
        assert_eq!(prediction.trend, BandwidthTrend::Improving);
    }

    #[test]
    fn test_trend_improving() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        // First half: low bandwidth
        for _ in 0..5 {
            predictor.record_measurement(1_000_000, now);
        }

        // Second half: high bandwidth (>5% increase)
        for _ in 0..5 {
            predictor.record_measurement(1_200_000, now);
        }

        assert_eq!(predictor.current_trend(), BandwidthTrend::Improving);
    }

    #[test]
    fn test_trend_degrading() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        // First half: high bandwidth
        for _ in 0..5 {
            predictor.record_measurement(1_200_000, now);
        }

        // Second half: low bandwidth (>5% decrease)
        for _ in 0..5 {
            predictor.record_measurement(1_000_000, now);
        }

        assert_eq!(predictor.current_trend(), BandwidthTrend::Degrading);
    }

    #[test]
    fn test_trend_stable() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        for _ in 0..10 {
            predictor.record_measurement(1_000_000, now);
        }

        assert_eq!(predictor.current_trend(), BandwidthTrend::Stable);
    }

    #[test]
    fn test_trend_unknown() {
        let predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        assert_eq!(predictor.current_trend(), BandwidthTrend::Unknown);
    }

    #[test]
    fn test_stats() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let stats = predictor.stats();
        assert_eq!(stats.measurement_count, 10);
        assert_eq!(stats.min_bps, 1_000_000);
        assert_eq!(stats.max_bps, 1_900_000);
        assert!(stats.avg_bps > 1_000_000);
        assert!(stats.std_dev > 0.0);
    }

    #[test]
    fn test_cleanup_old_measurements() {
        let config = PredictorConfig {
            time_window: Duration::from_secs(1),
            ..Default::default()
        };
        let mut predictor =
            BandwidthPredictor::with_config(PredictionStrategy::SimpleMovingAverage, config);

        let old_time = Instant::now() - Duration::from_secs(2);
        let new_time = Instant::now();

        predictor.record_measurement(1_000_000, old_time);
        predictor.record_measurement(1_000_000, old_time);
        predictor.record_measurement(1_000_000, new_time);

        // Old measurements should be cleaned up
        assert_eq!(predictor.measurements.len(), 1);
    }

    #[test]
    fn test_max_history_limit() {
        let config = PredictorConfig {
            max_history: 5,
            ..Default::default()
        };
        let mut predictor =
            BandwidthPredictor::with_config(PredictionStrategy::SimpleMovingAverage, config);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        assert_eq!(predictor.measurements.len(), 5);
    }

    #[test]
    fn test_clear() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        predictor.predict();
        assert!(predictor.last_prediction.is_some());

        predictor.clear();
        assert_eq!(predictor.measurements.len(), 0);
        assert!(predictor.last_prediction.is_none());
    }

    #[test]
    fn test_confidence_calculation() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        // Low variance = high confidence
        for _ in 0..10 {
            predictor.record_measurement(1_000_000, now);
        }

        let prediction1 = predictor.predict().unwrap();
        predictor.clear();

        // High variance = lower confidence
        for i in 0..10 {
            predictor.record_measurement(500_000 + i * 200_000, now);
        }

        let prediction2 = predictor.predict().unwrap();
        assert!(prediction1.confidence > prediction2.confidence);
    }

    #[test]
    fn test_last_prediction() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        assert!(predictor.last_prediction().is_none());

        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        predictor.predict();
        assert!(predictor.last_prediction().is_some());

        let last = predictor.last_prediction().unwrap();
        assert!(last.predicted_bps > 0);
    }

    #[test]
    fn test_std_dev_calculation() {
        let mut predictor = BandwidthPredictor::new(PredictionStrategy::SimpleMovingAverage);
        let now = Instant::now();

        // Identical values = zero std dev
        for _ in 0..10 {
            predictor.record_measurement(1_000_000, now);
        }

        let std_dev1 = predictor.calculate_std_dev();
        assert_eq!(std_dev1, 0.0);

        predictor.clear();

        // Varying values = non-zero std dev
        for i in 0..10 {
            predictor.record_measurement(1_000_000 + i * 100_000, now);
        }

        let std_dev2 = predictor.calculate_std_dev();
        assert!(std_dev2 > 0.0);
    }
}
