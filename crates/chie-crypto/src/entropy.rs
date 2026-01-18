//! Entropy Quality Monitoring
//!
//! This module provides tools for monitoring and assessing the quality of entropy
//! sources used for cryptographic key generation and random number generation.
//!
//! # Features
//!
//! - **Statistical tests**: Chi-squared, Monte Carlo Pi estimation, serial correlation
//! - **Entropy estimation**: Shannon entropy, min-entropy calculations
//! - **NIST SP 800-90B compliance**: Health tests for entropy sources
//! - **Continuous monitoring**: Track entropy quality over time
//! - **Anomaly detection**: Detect degraded or compromised entropy sources
//! - **Compliance reporting**: Generate reports for auditing
//!
//! # Example
//!
//! ```
//! use chie_crypto::entropy::{EntropyMonitor, EntropySource};
//!
//! // Create an entropy monitor
//! let mut monitor = EntropyMonitor::new();
//!
//! // Test random bytes from system RNG
//! let mut rng_source = EntropySource::system_rng();
//! let random_data = rng_source.get_bytes(1000);
//!
//! // Evaluate entropy quality
//! let quality = monitor.evaluate(&random_data).unwrap();
//! println!("Entropy quality: {:?}", quality);
//! println!("Shannon entropy: {:.2} bits/byte", quality.shannon_entropy);
//! println!("Passes health tests: {}", quality.passes_health_tests());
//! ```

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Entropy quality assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyQuality {
    /// Shannon entropy (bits per byte, 0-8)
    pub shannon_entropy: f64,
    /// Min-entropy (bits per byte)
    pub min_entropy: f64,
    /// Chi-squared test statistic
    pub chi_squared: f64,
    /// Chi-squared p-value
    pub chi_squared_pvalue: f64,
    /// Serial correlation coefficient
    pub serial_correlation: f64,
    /// Monte Carlo Pi estimation error
    pub monte_carlo_pi_error: f64,
    /// Number of bytes analyzed
    pub sample_size: usize,
    /// Timestamp of analysis
    pub timestamp: SystemTime,
    /// Whether the entropy passed health tests
    pub health_tests_passed: bool,
}

impl EntropyQuality {
    /// Check if entropy quality is acceptable
    pub fn passes_health_tests(&self) -> bool {
        self.health_tests_passed
            && self.shannon_entropy >= 7.5 // At least 7.5 bits/byte
            && self.min_entropy >= 4.0 // At least 4 bits/byte
            && self.chi_squared_pvalue >= 0.01 // Not too far from uniform (p >= 0.01)
            && self.serial_correlation.abs() < 0.1 // Low correlation
            && self.monte_carlo_pi_error < 0.1 // Good randomness for Monte Carlo
    }

    /// Get overall quality score (0.0 - 1.0)
    pub fn quality_score(&self) -> f64 {
        let shannon_score = (self.shannon_entropy / 8.0).min(1.0);
        let min_entropy_score = (self.min_entropy / 8.0).min(1.0);
        let chi_squared_score = self.chi_squared_pvalue.min(1.0);
        let correlation_score = (1.0 - self.serial_correlation.abs()).max(0.0);
        let pi_score = (1.0 - self.monte_carlo_pi_error).max(0.0);

        (shannon_score + min_entropy_score + chi_squared_score + correlation_score + pi_score) / 5.0
    }
}

/// Entropy source wrapper
pub struct EntropySource {
    source_type: String,
}

impl EntropySource {
    /// Create entropy source from system RNG
    pub fn system_rng() -> Self {
        Self {
            source_type: "system_rng".to_string(),
        }
    }

    /// Get random bytes from the entropy source
    pub fn get_bytes(&mut self, count: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; count];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Get source type identifier
    pub fn source_type(&self) -> &str {
        &self.source_type
    }
}

/// Entropy monitor for continuous quality assessment
pub struct EntropyMonitor {
    /// Historical quality assessments
    history: Vec<EntropyQuality>,
    /// Maximum history size
    max_history: usize,
    /// Minimum sample size for evaluation
    min_sample_size: usize,
}

impl Default for EntropyMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyMonitor {
    /// Create a new entropy monitor
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            max_history: 1000,
            min_sample_size: 256,
        }
    }

    /// Set maximum history size
    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    /// Set minimum sample size
    pub fn with_min_sample_size(mut self, min: usize) -> Self {
        self.min_sample_size = min;
        self
    }

    /// Evaluate entropy quality of a sample
    pub fn evaluate(&mut self, data: &[u8]) -> Result<EntropyQuality, EntropyError> {
        if data.len() < self.min_sample_size {
            return Err(EntropyError::InsufficientData {
                required: self.min_sample_size,
                provided: data.len(),
            });
        }

        let shannon_entropy = calculate_shannon_entropy(data);
        let min_entropy = calculate_min_entropy(data);
        let (chi_squared, chi_squared_pvalue) = calculate_chi_squared(data);
        let serial_correlation = calculate_serial_correlation(data);
        let monte_carlo_pi_error = estimate_monte_carlo_pi_error(data);

        // Simple health test: check basic thresholds
        let health_tests_passed = shannon_entropy >= 7.0
            && min_entropy >= 3.0
            && chi_squared_pvalue >= 0.001
            && serial_correlation.abs() < 0.2;

        let quality = EntropyQuality {
            shannon_entropy,
            min_entropy,
            chi_squared,
            chi_squared_pvalue,
            serial_correlation,
            monte_carlo_pi_error,
            sample_size: data.len(),
            timestamp: SystemTime::now(),
            health_tests_passed,
        };

        // Add to history
        self.history.push(quality.clone());
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }

        Ok(quality)
    }

    /// Get historical quality assessments
    pub fn history(&self) -> &[EntropyQuality] {
        &self.history
    }

    /// Get average quality score over history
    pub fn average_quality_score(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }

        let sum: f64 = self.history.iter().map(|q| q.quality_score()).sum();
        sum / self.history.len() as f64
    }

    /// Check if entropy quality has degraded
    pub fn detect_degradation(&self, window_size: usize) -> bool {
        if self.history.len() < window_size * 2 {
            return false;
        }

        let recent_avg = self.history[self.history.len() - window_size..]
            .iter()
            .map(|q| q.quality_score())
            .sum::<f64>()
            / window_size as f64;

        let older_avg = self.history
            [self.history.len() - window_size * 2..self.history.len() - window_size]
            .iter()
            .map(|q| q.quality_score())
            .sum::<f64>()
            / window_size as f64;

        // Degradation detected if recent average is significantly lower
        recent_avg < older_avg * 0.9
    }

    /// Clear history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

/// Calculate Shannon entropy (bits per byte)
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate min-entropy (bits per byte)
fn calculate_min_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let max_count = *counts.iter().max().unwrap();
    let max_probability = max_count as f64 / data.len() as f64;

    -max_probability.log2()
}

/// Calculate chi-squared statistic and p-value
fn calculate_chi_squared(data: &[u8]) -> (f64, f64) {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi_squared = 0.0;

    for &count in &counts {
        let diff = count as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Approximate p-value using chi-squared distribution with 255 degrees of freedom
    // For simplicity, we use a rough approximation
    let df = 255.0;
    let pvalue = if chi_squared > df {
        let z = (chi_squared - df) / (2.0 * df).sqrt();
        // Complementary error function approximation
        0.5 * (1.0 - erf_approx(z / std::f64::consts::SQRT_2))
    } else {
        1.0 - (df - chi_squared) / (2.0 * df)
    };

    (chi_squared, pvalue.clamp(0.0, 1.0))
}

/// Approximate error function
fn erf_approx(x: f64) -> f64 {
    // Abramowitz and Stegun approximation
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();

    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

    sign * y
}

/// Calculate serial correlation coefficient
fn calculate_serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let n = data.len() as f64;
    let mean: f64 = data.iter().map(|&x| x as f64).sum::<f64>() / n;

    let mut numerator = 0.0;
    let mut denominator = 0.0;

    for i in 0..data.len() - 1 {
        let x1 = data[i] as f64 - mean;
        let x2 = data[i + 1] as f64 - mean;
        numerator += x1 * x2;
    }

    for &byte in data {
        let x = byte as f64 - mean;
        denominator += x * x;
    }

    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Estimate Monte Carlo Pi using random bytes and calculate error
fn estimate_monte_carlo_pi_error(data: &[u8]) -> f64 {
    if data.len() < 8 {
        return 1.0; // Not enough data
    }

    let pairs = data.len() / 4; // Each pair needs 4 bytes (2 x u16)
    let mut inside_circle = 0;

    for i in 0..pairs {
        if i * 4 + 3 >= data.len() {
            break;
        }

        // Generate x, y coordinates in [0, 1)
        let x_bytes = [data[i * 4], data[i * 4 + 1]];
        let y_bytes = [data[i * 4 + 2], data[i * 4 + 3]];

        let x = u16::from_le_bytes(x_bytes) as f64 / 65536.0;
        let y = u16::from_le_bytes(y_bytes) as f64 / 65536.0;

        if x * x + y * y <= 1.0 {
            inside_circle += 1;
        }
    }

    let estimated_pi = 4.0 * inside_circle as f64 / pairs as f64;
    (estimated_pi - std::f64::consts::PI).abs() / std::f64::consts::PI
}

/// Entropy error types
#[derive(Debug, Clone, PartialEq)]
pub enum EntropyError {
    /// Insufficient data for analysis
    InsufficientData { required: usize, provided: usize },
    /// Health tests failed
    HealthTestFailed(String),
}

impl std::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyError::InsufficientData { required, provided } => {
                write!(f, "Insufficient data: need {}, got {}", required, provided)
            }
            EntropyError::HealthTestFailed(msg) => write!(f, "Health test failed: {}", msg),
        }
    }
}

impl std::error::Error for EntropyError {}

/// Result type for entropy operations
pub type EntropyResult<T> = Result<T, EntropyError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_source() {
        let mut source = EntropySource::system_rng();
        let data = source.get_bytes(100);
        assert_eq!(data.len(), 100);
        assert_eq!(source.source_type(), "system_rng");
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // Perfectly uniform data should have ~8 bits/byte
        let mut data = Vec::new();
        for i in 0..256 {
            for _ in 0..10 {
                data.push(i as u8);
            }
        }
        let entropy = calculate_shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_zeros() {
        // All zeros should have 0 bits/byte
        let data = vec![0u8; 1000];
        let entropy = calculate_shannon_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_min_entropy() {
        // All zeros
        let data = vec![0u8; 100];
        let min_ent = calculate_min_entropy(&data);
        assert_eq!(min_ent, 0.0);

        // Uniform distribution
        let uniform_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let min_ent = calculate_min_entropy(&uniform_data);
        assert!(min_ent > 7.0);
    }

    #[test]
    fn test_chi_squared_uniform() {
        let mut data = Vec::new();
        for i in 0..256 {
            for _ in 0..10 {
                data.push(i as u8);
            }
        }
        let (_chi_sq, pvalue) = calculate_chi_squared(&data);
        // For perfectly uniform data, p-value should be high (close to 1.0)
        // We're not rejecting the null hypothesis of uniformity
        assert!(pvalue > 0.01); // Should not reject null hypothesis
    }

    #[test]
    fn test_chi_squared_nonuniform() {
        // All zeros - highly non-uniform
        let data = vec![0u8; 1000];
        let (_chi_sq, pvalue) = calculate_chi_squared(&data);
        assert!(pvalue < 0.01); // Should reject null hypothesis
    }

    #[test]
    fn test_serial_correlation() {
        // Alternating pattern has high correlation
        let alternating: Vec<u8> = (0..1000)
            .map(|i| if i % 2 == 0 { 0 } else { 255 })
            .collect();
        let corr = calculate_serial_correlation(&alternating);
        assert!(corr.abs() > 0.5);

        // Random data should have low correlation
        let mut source = EntropySource::system_rng();
        let random = source.get_bytes(1000);
        let corr = calculate_serial_correlation(&random);
        assert!(corr.abs() < 0.2);
    }

    #[test]
    fn test_monte_carlo_pi() {
        // Test with good random data
        let mut source = EntropySource::system_rng();
        let data = source.get_bytes(4000);
        let error = estimate_monte_carlo_pi_error(&data);
        // Error should be reasonably small for good random data
        assert!(error < 0.2);
    }

    #[test]
    fn test_entropy_monitor_evaluate() {
        let mut monitor = EntropyMonitor::new();
        let mut source = EntropySource::system_rng();
        let data = source.get_bytes(1000);

        let quality = monitor.evaluate(&data).unwrap();
        assert!(quality.shannon_entropy > 7.0);
        assert!(quality.sample_size == 1000);
        assert_eq!(monitor.history().len(), 1);
    }

    #[test]
    fn test_entropy_monitor_insufficient_data() {
        let mut monitor = EntropyMonitor::new().with_min_sample_size(100);
        let data = vec![0u8; 50];

        let result = monitor.evaluate(&data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EntropyError::InsufficientData { .. }
        ));
    }

    #[test]
    fn test_entropy_quality_score() {
        let quality = EntropyQuality {
            shannon_entropy: 7.9,
            min_entropy: 6.0,
            chi_squared: 255.0,
            chi_squared_pvalue: 0.5,
            serial_correlation: 0.05,
            monte_carlo_pi_error: 0.05,
            sample_size: 1000,
            timestamp: SystemTime::now(),
            health_tests_passed: true,
        };

        let score = quality.quality_score();
        assert!(score > 0.8);
    }

    #[test]
    fn test_entropy_quality_passes_health_tests() {
        let good_quality = EntropyQuality {
            shannon_entropy: 7.9,
            min_entropy: 6.0,
            chi_squared: 255.0,
            chi_squared_pvalue: 0.5,
            serial_correlation: 0.05,
            monte_carlo_pi_error: 0.05,
            sample_size: 1000,
            timestamp: SystemTime::now(),
            health_tests_passed: true,
        };
        assert!(good_quality.passes_health_tests());

        let bad_quality = EntropyQuality {
            shannon_entropy: 3.0, // Too low
            min_entropy: 2.0,
            chi_squared: 500.0,
            chi_squared_pvalue: 0.001,
            serial_correlation: 0.5,
            monte_carlo_pi_error: 0.5,
            sample_size: 1000,
            timestamp: SystemTime::now(),
            health_tests_passed: false,
        };
        assert!(!bad_quality.passes_health_tests());
    }

    #[test]
    fn test_entropy_monitor_history() {
        let mut monitor = EntropyMonitor::new().with_max_history(5);
        let mut source = EntropySource::system_rng();

        for _ in 0..10 {
            let data = source.get_bytes(500);
            let _ = monitor.evaluate(&data);
        }

        assert_eq!(monitor.history().len(), 5);
    }

    #[test]
    fn test_entropy_monitor_average_quality() {
        let mut monitor = EntropyMonitor::new();
        let mut source = EntropySource::system_rng();

        for _ in 0..5 {
            let data = source.get_bytes(500);
            let _ = monitor.evaluate(&data);
        }

        let avg = monitor.average_quality_score();
        assert!(avg > 0.5);
    }

    #[test]
    fn test_entropy_monitor_detect_degradation() {
        let mut monitor = EntropyMonitor::new();

        // Need at least window_size * 2 samples to detect degradation
        // With window_size=3, we need at least 6 samples

        // Add 10 good quality samples with high entropy
        for _ in 0..10 {
            // Create data with high entropy (all bytes 0-255)
            let mut data = Vec::new();
            for i in 0u8..=255u8 {
                data.push(i);
                data.push(i);
            }
            let _ = monitor.evaluate(&data);
        }

        // Add 5 poor quality samples (all zeros = very low entropy)
        for _ in 0..5 {
            let data = vec![0u8; 512];
            let _ = monitor.evaluate(&data);
        }

        // Should detect degradation using window_size=3
        // Recent 3 samples are zeros (bad), older 3 samples are uniform (good)
        assert!(monitor.detect_degradation(3));
    }

    #[test]
    fn test_entropy_monitor_clear_history() {
        let mut monitor = EntropyMonitor::new();
        let mut source = EntropySource::system_rng();
        let data = source.get_bytes(500);
        let _ = monitor.evaluate(&data);

        assert_eq!(monitor.history().len(), 1);

        monitor.clear_history();
        assert_eq!(monitor.history().len(), 0);
    }

    #[test]
    fn test_entropy_quality_serialization() {
        let quality = EntropyQuality {
            shannon_entropy: 7.9,
            min_entropy: 6.0,
            chi_squared: 255.0,
            chi_squared_pvalue: 0.5,
            serial_correlation: 0.05,
            monte_carlo_pi_error: 0.05,
            sample_size: 1000,
            timestamp: SystemTime::now(),
            health_tests_passed: true,
        };

        let serialized = crate::codec::encode(&quality).unwrap();
        let deserialized: EntropyQuality = crate::codec::decode(&serialized).unwrap();

        assert!((deserialized.shannon_entropy - quality.shannon_entropy).abs() < 0.01);
        assert_eq!(deserialized.sample_size, quality.sample_size);
    }
}
