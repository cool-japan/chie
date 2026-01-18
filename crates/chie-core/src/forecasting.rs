//! Resource usage forecasting with time series analysis.
//!
//! This module provides forecasting capabilities for resource usage prediction
//! using simple linear regression and moving averages.
//!
//! # Features
//!
//! - Linear trend forecasting
//! - Moving average smoothing
//! - Growth rate calculation
//! - Time-to-capacity estimation
//! - Anomaly detection in trends
//!
//! # Example
//!
//! ```
//! use chie_core::forecasting::{Forecaster, ForecastMethod};
//!
//! let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
//!
//! // Add historical data points
//! forecaster.add_sample(100.0);
//! forecaster.add_sample(150.0);
//! forecaster.add_sample(200.0);
//! forecaster.add_sample(250.0);
//!
//! // Predict future value
//! if let Some(forecast) = forecaster.forecast(1) {
//!     println!("Predicted value in 1 period: {:.2}", forecast);
//! }
//!
//! // Estimate time to reach capacity
//! if let Some(periods) = forecaster.time_to_capacity(1000.0) {
//!     println!("Will reach capacity in {} periods", periods);
//! }
//! ```

use std::collections::VecDeque;

/// Forecasting methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForecastMethod {
    /// Simple moving average.
    MovingAverage,
    /// Linear regression (least squares).
    LinearRegression,
    /// Exponential smoothing.
    ExponentialSmoothing,
}

/// A forecaster for time series data.
pub struct Forecaster {
    /// Forecasting method.
    method: ForecastMethod,
    /// Historical samples.
    samples: VecDeque<f64>,
    /// Maximum number of samples to retain.
    max_samples: usize,
    /// Alpha parameter for exponential smoothing (0-1).
    smoothing_alpha: f64,
}

impl Forecaster {
    /// Create a new forecaster with the specified method.
    #[must_use]
    pub fn new(method: ForecastMethod) -> Self {
        Self {
            method,
            samples: VecDeque::new(),
            max_samples: 100,
            smoothing_alpha: 0.3,
        }
    }

    /// Create a forecaster with custom configuration.
    #[must_use]
    pub fn with_config(method: ForecastMethod, max_samples: usize, smoothing_alpha: f64) -> Self {
        Self {
            method,
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            smoothing_alpha: smoothing_alpha.clamp(0.0, 1.0),
        }
    }

    /// Add a sample to the historical data.
    pub fn add_sample(&mut self, value: f64) {
        self.samples.push_back(value);

        // Trim old samples
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    /// Add multiple samples at once.
    pub fn add_samples(&mut self, values: &[f64]) {
        for &value in values {
            self.add_sample(value);
        }
    }

    /// Forecast the value for `periods` ahead.
    #[must_use]
    #[inline]
    pub fn forecast(&self, periods: usize) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        match self.method {
            ForecastMethod::MovingAverage => self.forecast_moving_average(),
            ForecastMethod::LinearRegression => self.forecast_linear_regression(periods),
            ForecastMethod::ExponentialSmoothing => self.forecast_exponential_smoothing(),
        }
    }

    /// Forecast using moving average.
    #[must_use]
    fn forecast_moving_average(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        let sum: f64 = self.samples.iter().sum();
        Some(sum / self.samples.len() as f64)
    }

    /// Forecast using linear regression.
    #[must_use]
    fn forecast_linear_regression(&self, periods: usize) -> Option<f64> {
        if self.samples.len() < 2 {
            return None;
        }

        let (slope, intercept) = self.calculate_linear_trend();
        let next_x = self.samples.len() as f64 + periods as f64 - 1.0;
        Some(slope * next_x + intercept)
    }

    /// Forecast using exponential smoothing.
    #[must_use]
    fn forecast_exponential_smoothing(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }

        let mut smoothed = self.samples[0];
        for &value in self.samples.iter().skip(1) {
            smoothed = self.smoothing_alpha * value + (1.0 - self.smoothing_alpha) * smoothed;
        }

        Some(smoothed)
    }

    /// Calculate linear trend (slope and intercept).
    #[must_use]
    fn calculate_linear_trend(&self) -> (f64, f64) {
        let n = self.samples.len() as f64;

        // Calculate means
        let mean_x = (n - 1.0) / 2.0;
        let mean_y: f64 = self.samples.iter().sum::<f64>() / n;

        // Calculate slope
        let mut numerator = 0.0;
        let mut denominator = 0.0;

        for (i, &y) in self.samples.iter().enumerate() {
            let x = i as f64;
            numerator += (x - mean_x) * (y - mean_y);
            denominator += (x - mean_x) * (x - mean_x);
        }

        let slope = if denominator != 0.0 {
            numerator / denominator
        } else {
            0.0
        };

        let intercept = mean_y - slope * mean_x;

        (slope, intercept)
    }

    /// Get the current growth rate (slope of linear trend).
    #[must_use]
    #[inline]
    pub fn growth_rate(&self) -> Option<f64> {
        if self.samples.len() < 2 {
            return None;
        }

        let (slope, _) = self.calculate_linear_trend();
        Some(slope)
    }

    /// Estimate periods until reaching a capacity threshold.
    #[must_use]
    pub fn time_to_capacity(&self, capacity: f64) -> Option<usize> {
        if self.samples.is_empty() {
            return None;
        }

        let current = self.samples.back()?;

        if *current >= capacity {
            return Some(0);
        }

        let growth = self.growth_rate()?;

        if growth <= 0.0 {
            return None; // Not growing
        }

        let periods = ((capacity - current) / growth).ceil() as usize;
        Some(periods)
    }

    /// Get the confidence level of the forecast (0-1).
    ///
    /// Based on R-squared for linear regression.
    #[must_use]
    pub fn confidence(&self) -> Option<f64> {
        if self.samples.len() < 2 {
            return None;
        }

        match self.method {
            ForecastMethod::LinearRegression => self.calculate_r_squared(),
            ForecastMethod::MovingAverage | ForecastMethod::ExponentialSmoothing => {
                Some(0.5) // Default moderate confidence
            }
        }
    }

    /// Calculate R-squared for linear regression.
    #[must_use]
    fn calculate_r_squared(&self) -> Option<f64> {
        if self.samples.len() < 2 {
            return None;
        }

        let (slope, intercept) = self.calculate_linear_trend();
        let mean_y: f64 = self.samples.iter().sum::<f64>() / self.samples.len() as f64;

        let mut ss_tot = 0.0;
        let mut ss_res = 0.0;

        for (i, &y) in self.samples.iter().enumerate() {
            let x = i as f64;
            let y_pred = slope * x + intercept;

            ss_tot += (y - mean_y) * (y - mean_y);
            ss_res += (y - y_pred) * (y - y_pred);
        }

        if ss_tot == 0.0 {
            return Some(0.0);
        }

        Some(1.0 - (ss_res / ss_tot))
    }

    /// Detect if current trend is anomalous compared to forecast.
    #[must_use]
    #[inline]
    pub fn is_anomalous(&self, threshold: f64) -> bool {
        if self.samples.len() < 3 {
            return false;
        }

        let latest = match self.samples.back() {
            Some(&v) => v,
            None => return false,
        };

        // Forecast based on all but the last sample
        let mut temp_samples = self.samples.clone();
        temp_samples.pop_back();

        let temp_forecaster = Forecaster {
            method: self.method,
            samples: temp_samples,
            max_samples: self.max_samples,
            smoothing_alpha: self.smoothing_alpha,
        };

        let forecast = match temp_forecaster.forecast(1) {
            Some(f) => f,
            None => return false,
        };

        let deviation = (latest - forecast).abs();
        let avg = temp_forecaster.forecast_moving_average().unwrap_or(latest);

        if avg == 0.0 {
            return false;
        }

        let relative_deviation = deviation / avg;
        relative_deviation > threshold
    }

    /// Get the number of samples.
    #[must_use]
    #[inline]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get the latest sample value.
    #[must_use]
    #[inline]
    pub fn latest_value(&self) -> Option<f64> {
        self.samples.back().copied()
    }

    /// Clear all samples.
    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

/// Resource capacity forecast.
#[derive(Debug, Clone)]
pub struct CapacityForecast {
    /// Current usage.
    pub current_usage: f64,
    /// Total capacity.
    pub total_capacity: f64,
    /// Forecasted usage in N periods.
    pub forecasted_usage: f64,
    /// Periods until capacity is reached.
    pub periods_to_capacity: Option<usize>,
    /// Growth rate per period.
    pub growth_rate: f64,
    /// Forecast confidence (0-1).
    pub confidence: f64,
}

impl CapacityForecast {
    /// Check if capacity will be exceeded soon.
    #[must_use]
    #[inline]
    pub fn is_critical(&self, threshold_periods: usize) -> bool {
        match self.periods_to_capacity {
            Some(periods) => periods <= threshold_periods,
            None => false,
        }
    }

    /// Get usage percentage.
    #[must_use]
    #[inline]
    pub fn usage_percent(&self) -> f64 {
        if self.total_capacity == 0.0 {
            return 0.0;
        }
        (self.current_usage / self.total_capacity) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moving_average_forecast() {
        let mut forecaster = Forecaster::new(ForecastMethod::MovingAverage);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let forecast = forecaster.forecast(1);
        assert_eq!(forecast, Some(25.0));
    }

    #[test]
    fn test_linear_regression_forecast() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let forecast = forecaster.forecast(1);
        assert!(forecast.is_some());
        // Should predict ~50.0 for the next period
        let value = forecast.unwrap();
        assert!((value - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_growth_rate() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let growth = forecaster.growth_rate();
        assert!(growth.is_some());
        // Should be ~10.0 per period
        let rate = growth.unwrap();
        assert!((rate - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_time_to_capacity() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let periods = forecaster.time_to_capacity(100.0);
        assert!(periods.is_some());
        // Should take ~6 periods to reach 100
        assert_eq!(periods.unwrap(), 6);
    }

    #[test]
    fn test_time_to_capacity_already_exceeded() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let periods = forecaster.time_to_capacity(30.0);
        assert_eq!(periods, Some(0));
    }

    #[test]
    fn test_exponential_smoothing() {
        let mut forecaster = Forecaster::new(ForecastMethod::ExponentialSmoothing);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let forecast = forecaster.forecast(1);
        assert!(forecast.is_some());
    }

    #[test]
    fn test_confidence() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        let confidence = forecaster.confidence();
        assert!(confidence.is_some());
        // Perfect linear trend should have high confidence
        let conf = confidence.unwrap();
        assert!(conf > 0.9);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut forecaster = Forecaster::new(ForecastMethod::LinearRegression);
        forecaster.add_samples(&[10.0, 20.0, 30.0, 40.0]);

        // Not anomalous
        assert!(!forecaster.is_anomalous(0.5));

        // Add anomalous value
        forecaster.add_sample(100.0);
        assert!(forecaster.is_anomalous(0.5));
    }

    #[test]
    fn test_sample_management() {
        let mut forecaster = Forecaster::new(ForecastMethod::MovingAverage);
        assert_eq!(forecaster.sample_count(), 0);
        assert!(forecaster.latest_value().is_none());

        forecaster.add_sample(42.0);
        assert_eq!(forecaster.sample_count(), 1);
        assert_eq!(forecaster.latest_value(), Some(42.0));

        forecaster.clear();
        assert_eq!(forecaster.sample_count(), 0);
    }

    #[test]
    fn test_capacity_forecast_critical() {
        let forecast = CapacityForecast {
            current_usage: 80.0,
            total_capacity: 100.0,
            forecasted_usage: 95.0,
            periods_to_capacity: Some(3),
            growth_rate: 5.0,
            confidence: 0.9,
        };

        assert!(forecast.is_critical(5));
        assert!(!forecast.is_critical(2));
        assert_eq!(forecast.usage_percent(), 80.0);
    }
}
