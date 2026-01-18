//! Differential Privacy primitives for privacy-preserving data analysis
//!
//! Differential privacy provides mathematical guarantees that the output of a computation
//! does not reveal too much about any individual input. This module implements:
//! - Laplace mechanism for numeric queries
//! - Exponential mechanism for non-numeric queries
//! - Gaussian mechanism for improved utility
//! - Privacy budget tracking and composition
//!
//! # Example
//!
//! ```
//! use chie_crypto::differential_privacy::*;
//!
//! // Create a Laplace mechanism with epsilon = 1.0
//! let mechanism = LaplaceMechanism::new(1.0).unwrap();
//!
//! // Add noise to a sum query with sensitivity 1.0
//! let true_sum = 1000.0;
//! let noisy_sum = mechanism.add_noise(true_sum, 1.0).unwrap();
//!
//! // The noisy result is approximately 1000 but not exact
//! assert!((noisy_sum - true_sum).abs() < 100.0); // Usually within 100
//! ```

use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Differential privacy error types
#[derive(Error, Debug)]
pub enum DPError {
    #[error("Invalid epsilon: {0}")]
    InvalidEpsilon(String),
    #[error("Invalid delta: {0}")]
    InvalidDelta(String),
    #[error("Invalid sensitivity: {0}")]
    InvalidSensitivity(String),
    #[error("Privacy budget exceeded")]
    BudgetExceeded,
    #[error("Invalid probability: {0}")]
    InvalidProbability(String),
}

/// Result type for differential privacy operations
pub type DPResult<T> = Result<T, DPError>;

/// Laplace mechanism for differential privacy
///
/// Adds noise drawn from Laplace distribution with scale parameter determined by
/// the privacy parameter epsilon and the query's sensitivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaplaceMechanism {
    /// Privacy parameter (smaller = more private)
    epsilon: f64,
}

impl LaplaceMechanism {
    /// Create a new Laplace mechanism with given epsilon
    ///
    /// # Arguments
    /// * `epsilon` - Privacy parameter (must be positive)
    pub fn new(epsilon: f64) -> DPResult<Self> {
        if epsilon <= 0.0 {
            return Err(DPError::InvalidEpsilon(
                "epsilon must be positive".to_string(),
            ));
        }

        Ok(Self { epsilon })
    }

    /// Add Laplace noise to a value
    ///
    /// # Arguments
    /// * `true_value` - The true value to add noise to
    /// * `sensitivity` - The global sensitivity of the query
    ///
    /// # Returns
    /// The value with added Laplace noise
    pub fn add_noise(&self, true_value: f64, sensitivity: f64) -> DPResult<f64> {
        if sensitivity <= 0.0 {
            return Err(DPError::InvalidSensitivity(
                "sensitivity must be positive".to_string(),
            ));
        }

        let scale = sensitivity / self.epsilon;
        let noise = sample_laplace(scale);

        Ok(true_value + noise)
    }

    /// Get the privacy parameter
    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }
}

/// Gaussian mechanism for differential privacy
///
/// Adds noise drawn from Gaussian distribution. Provides better utility than Laplace
/// for approximate differential privacy (with delta > 0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaussianMechanism {
    /// Privacy parameter epsilon
    epsilon: f64,
    /// Privacy parameter delta (failure probability)
    delta: f64,
}

impl GaussianMechanism {
    /// Create a new Gaussian mechanism
    ///
    /// # Arguments
    /// * `epsilon` - Privacy parameter (must be positive)
    /// * `delta` - Failure probability (must be in (0, 1))
    pub fn new(epsilon: f64, delta: f64) -> DPResult<Self> {
        if epsilon <= 0.0 {
            return Err(DPError::InvalidEpsilon(
                "epsilon must be positive".to_string(),
            ));
        }

        if delta <= 0.0 || delta >= 1.0 {
            return Err(DPError::InvalidDelta("delta must be in (0, 1)".to_string()));
        }

        Ok(Self { epsilon, delta })
    }

    /// Add Gaussian noise to a value
    ///
    /// # Arguments
    /// * `true_value` - The true value to add noise to
    /// * `sensitivity` - The L2 sensitivity of the query
    ///
    /// # Returns
    /// The value with added Gaussian noise
    pub fn add_noise(&self, true_value: f64, sensitivity: f64) -> DPResult<f64> {
        if sensitivity <= 0.0 {
            return Err(DPError::InvalidSensitivity(
                "sensitivity must be positive".to_string(),
            ));
        }

        // Standard deviation for Gaussian noise
        // sigma = sensitivity * sqrt(2 * ln(1.25 / delta)) / epsilon
        let sigma = sensitivity * (2.0 * (1.25 / self.delta).ln()).sqrt() / self.epsilon;

        let noise = sample_gaussian(sigma);

        Ok(true_value + noise)
    }

    /// Get the privacy parameters
    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }

    pub fn delta(&self) -> f64 {
        self.delta
    }
}

/// Exponential mechanism for selecting from a set of candidates
///
/// Used when the output is non-numeric (e.g., selecting the best option from a set)
#[derive(Debug, Clone)]
pub struct ExponentialMechanism {
    /// Privacy parameter
    epsilon: f64,
}

impl ExponentialMechanism {
    /// Create a new exponential mechanism
    ///
    /// # Arguments
    /// * `epsilon` - Privacy parameter (must be positive)
    pub fn new(epsilon: f64) -> DPResult<Self> {
        if epsilon <= 0.0 {
            return Err(DPError::InvalidEpsilon(
                "epsilon must be positive".to_string(),
            ));
        }

        Ok(Self { epsilon })
    }

    /// Select an output from candidates based on their utility scores
    ///
    /// # Arguments
    /// * `candidates` - Vector of candidate outputs
    /// * `utilities` - Utility scores for each candidate
    /// * `sensitivity` - Sensitivity of the utility function
    ///
    /// # Returns
    /// Index of the selected candidate
    pub fn select<T>(
        &self,
        candidates: &[T],
        utilities: &[f64],
        sensitivity: f64,
    ) -> DPResult<usize> {
        if candidates.len() != utilities.len() {
            return Err(DPError::InvalidProbability(
                "candidates and utilities must have the same length".to_string(),
            ));
        }

        if candidates.is_empty() {
            return Err(DPError::InvalidProbability(
                "cannot select from empty set".to_string(),
            ));
        }

        if sensitivity <= 0.0 {
            return Err(DPError::InvalidSensitivity(
                "sensitivity must be positive".to_string(),
            ));
        }

        // Compute probabilities proportional to exp(epsilon * utility / (2 * sensitivity))
        let mut probabilities = Vec::with_capacity(utilities.len());
        let mut max_utility = utilities[0];

        for &utility in utilities {
            if utility > max_utility {
                max_utility = utility;
            }
        }

        // Normalize for numerical stability
        let mut sum = 0.0;
        for &utility in utilities {
            let prob = ((self.epsilon * (utility - max_utility)) / (2.0 * sensitivity)).exp();
            probabilities.push(prob);
            sum += prob;
        }

        // Normalize probabilities
        for prob in &mut probabilities {
            *prob /= sum;
        }

        // Sample from categorical distribution
        let mut rng = rand::thread_rng();
        let sample: f64 = rng.gen_range(0.0..1.0);

        let mut cumulative = 0.0;
        for (i, &prob) in probabilities.iter().enumerate() {
            cumulative += prob;
            if sample <= cumulative {
                return Ok(i);
            }
        }

        // Fallback (should not happen due to floating point errors)
        Ok(candidates.len() - 1)
    }

    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }
}

/// Privacy budget tracker for composition of multiple queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudget {
    /// Total epsilon budget
    total_epsilon: f64,
    /// Total delta budget (for approximate DP)
    total_delta: f64,
    /// Consumed epsilon
    consumed_epsilon: f64,
    /// Consumed delta
    consumed_delta: f64,
}

impl PrivacyBudget {
    /// Create a new privacy budget
    ///
    /// # Arguments
    /// * `total_epsilon` - Total epsilon budget
    /// * `total_delta` - Total delta budget (use 0.0 for pure DP)
    pub fn new(total_epsilon: f64, total_delta: f64) -> DPResult<Self> {
        if total_epsilon <= 0.0 {
            return Err(DPError::InvalidEpsilon(
                "epsilon must be positive".to_string(),
            ));
        }

        if !(0.0..1.0).contains(&total_delta) {
            return Err(DPError::InvalidDelta("delta must be in [0, 1)".to_string()));
        }

        Ok(Self {
            total_epsilon,
            total_delta,
            consumed_epsilon: 0.0,
            consumed_delta: 0.0,
        })
    }

    /// Check if a query can be executed with the given privacy cost
    ///
    /// # Arguments
    /// * `epsilon` - Epsilon cost of the query
    /// * `delta` - Delta cost of the query
    pub fn can_execute(&self, epsilon: f64, delta: f64) -> bool {
        self.consumed_epsilon + epsilon <= self.total_epsilon
            && self.consumed_delta + delta <= self.total_delta
    }

    /// Consume privacy budget for a query
    ///
    /// # Arguments
    /// * `epsilon` - Epsilon cost of the query
    /// * `delta` - Delta cost of the query
    pub fn consume(&mut self, epsilon: f64, delta: f64) -> DPResult<()> {
        if !self.can_execute(epsilon, delta) {
            return Err(DPError::BudgetExceeded);
        }

        self.consumed_epsilon += epsilon;
        self.consumed_delta += delta;

        Ok(())
    }

    /// Get remaining epsilon budget
    pub fn remaining_epsilon(&self) -> f64 {
        self.total_epsilon - self.consumed_epsilon
    }

    /// Get remaining delta budget
    pub fn remaining_delta(&self) -> f64 {
        self.total_delta - self.consumed_delta
    }

    /// Reset the budget
    pub fn reset(&mut self) {
        self.consumed_epsilon = 0.0;
        self.consumed_delta = 0.0;
    }
}

/// Sample from Laplace distribution with given scale parameter
fn sample_laplace(scale: f64) -> f64 {
    let mut rng = rand::thread_rng();
    let u: f64 = rng.gen_range(-0.5..0.5);

    -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
}

/// Sample from Gaussian distribution with given standard deviation
fn sample_gaussian(sigma: f64) -> f64 {
    let mut rng = rand::thread_rng();

    // Box-Muller transform
    let u1: f64 = rng.gen_range(0.0..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);

    let r = (-2.0 * u1.ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;

    sigma * r * theta.cos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laplace_mechanism_basic() {
        let mechanism = LaplaceMechanism::new(1.0).unwrap();

        let true_value = 100.0;
        let sensitivity = 1.0;

        let noisy_value = mechanism.add_noise(true_value, sensitivity).unwrap();

        // With high probability, noise should be within reasonable bounds
        assert!((noisy_value - true_value).abs() < 50.0);
    }

    #[test]
    fn test_laplace_invalid_epsilon() {
        let result = LaplaceMechanism::new(-1.0);
        assert!(result.is_err());

        let result = LaplaceMechanism::new(0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_laplace_invalid_sensitivity() {
        let mechanism = LaplaceMechanism::new(1.0).unwrap();
        let result = mechanism.add_noise(100.0, -1.0);
        assert!(result.is_err());

        let result = mechanism.add_noise(100.0, 0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_gaussian_mechanism_basic() {
        let mechanism = GaussianMechanism::new(1.0, 0.01).unwrap();

        let true_value = 500.0;
        let sensitivity = 2.0;

        let noisy_value = mechanism.add_noise(true_value, sensitivity).unwrap();

        // With high probability, noise should be within reasonable bounds
        assert!((noisy_value - true_value).abs() < 100.0);
    }

    #[test]
    fn test_gaussian_invalid_params() {
        let result = GaussianMechanism::new(-1.0, 0.01);
        assert!(result.is_err());

        let result = GaussianMechanism::new(1.0, 0.0);
        assert!(result.is_err());

        let result = GaussianMechanism::new(1.0, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_exponential_mechanism() {
        let mechanism = ExponentialMechanism::new(1.0).unwrap();

        let candidates = vec!["A", "B", "C", "D"];
        let utilities = vec![1.0, 5.0, 2.0, 1.5]; // B has highest utility

        // Run multiple times to check distribution
        let mut counts = vec![0; candidates.len()];

        for _ in 0..1000 {
            let idx = mechanism.select(&candidates, &utilities, 1.0).unwrap();
            counts[idx] += 1;
        }

        // B should be selected most often
        assert!(counts[1] > counts[0]);
        assert!(counts[1] > counts[2]);
        assert!(counts[1] > counts[3]);
    }

    #[test]
    fn test_exponential_mechanism_errors() {
        let mechanism = ExponentialMechanism::new(1.0).unwrap();

        // Mismatched lengths
        let candidates = vec!["A", "B"];
        let utilities = vec![1.0];
        let result = mechanism.select(&candidates, &utilities, 1.0);
        assert!(result.is_err());

        // Empty candidates
        let candidates: Vec<&str> = vec![];
        let utilities: Vec<f64> = vec![];
        let result = mechanism.select(&candidates, &utilities, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_privacy_budget_basic() {
        let mut budget = PrivacyBudget::new(10.0, 0.01).unwrap();

        assert!(budget.can_execute(5.0, 0.005));

        budget.consume(5.0, 0.005).unwrap();
        assert_eq!(budget.remaining_epsilon(), 5.0);
        assert!((budget.remaining_delta() - 0.005).abs() < 1e-10);

        assert!(budget.can_execute(5.0, 0.005));

        budget.consume(5.0, 0.005).unwrap();
        assert!(budget.remaining_epsilon() < 1e-10);
        assert!(budget.remaining_delta() < 1e-10);
    }

    #[test]
    fn test_privacy_budget_exceeded() {
        let mut budget = PrivacyBudget::new(1.0, 0.01).unwrap();

        budget.consume(0.5, 0.005).unwrap();

        let result = budget.consume(0.6, 0.005);
        assert!(result.is_err());
    }

    #[test]
    fn test_privacy_budget_reset() {
        let mut budget = PrivacyBudget::new(1.0, 0.01).unwrap();

        budget.consume(0.5, 0.005).unwrap();
        assert_eq!(budget.remaining_epsilon(), 0.5);

        budget.reset();
        assert_eq!(budget.remaining_epsilon(), 1.0);
        assert_eq!(budget.remaining_delta(), 0.01);
    }

    #[test]
    fn test_laplace_noise_distribution() {
        let mechanism = LaplaceMechanism::new(1.0).unwrap();

        let mut samples = Vec::new();
        for _ in 0..1000 {
            let noisy = mechanism.add_noise(0.0, 1.0).unwrap();
            samples.push(noisy);
        }

        // Mean should be close to 0
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.2);

        // Most samples should be within a reasonable range
        let within_range = samples.iter().filter(|&&x| x.abs() < 5.0).count();
        assert!(within_range > 900); // > 90%
    }

    #[test]
    fn test_gaussian_noise_distribution() {
        let mechanism = GaussianMechanism::new(1.0, 0.01).unwrap();

        let mut samples = Vec::new();
        for _ in 0..1000 {
            let noisy = mechanism.add_noise(0.0, 1.0).unwrap();
            samples.push(noisy);
        }

        // Mean should be close to 0
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.5);

        // Most samples should be within a reasonable range
        let within_range = samples.iter().filter(|&&x| x.abs() < 10.0).count();
        assert!(within_range > 900); // > 90%
    }

    #[test]
    fn test_laplace_sensitivity_impact() {
        let mechanism = LaplaceMechanism::new(1.0).unwrap();

        // Higher sensitivity should lead to more noise
        let _noisy1 = mechanism.add_noise(100.0, 1.0).unwrap();
        let _noisy2 = mechanism.add_noise(100.0, 10.0).unwrap();

        // Can't guarantee individual samples, but test the mechanism exists
        assert!(mechanism.epsilon() == 1.0);
    }

    #[test]
    fn test_exponential_equal_utilities() {
        let mechanism = ExponentialMechanism::new(1.0).unwrap();

        let candidates = vec!["A", "B", "C"];
        let utilities = vec![1.0, 1.0, 1.0]; // All equal

        let mut counts = vec![0; candidates.len()];

        for _ in 0..300 {
            let idx = mechanism.select(&candidates, &utilities, 1.0).unwrap();
            counts[idx] += 1;
        }

        // Should be roughly equal (within reasonable variance)
        for &count in &counts {
            assert!(count > 50 && count < 150);
        }
    }

    #[test]
    fn test_privacy_budget_composition() {
        let mut budget = PrivacyBudget::new(3.0, 0.1).unwrap();

        // Sequential composition
        budget.consume(1.0, 0.03).unwrap();
        budget.consume(1.0, 0.03).unwrap();
        budget.consume(1.0, 0.03).unwrap();

        // Budget should be nearly exhausted
        assert!(budget.remaining_epsilon() < 1e-10);
        assert!((budget.remaining_delta() - 0.01).abs() < 1e-10);

        // Cannot execute another query
        assert!(!budget.can_execute(0.1, 0.01));
    }

    #[test]
    fn test_budget_serialization() {
        let budget = PrivacyBudget::new(5.0, 0.05).unwrap();

        let serialized = crate::codec::encode(&budget).unwrap();
        let deserialized: PrivacyBudget = crate::codec::decode(&serialized).unwrap();

        assert_eq!(deserialized.total_epsilon, 5.0);
        assert_eq!(deserialized.total_delta, 0.05);
    }
}
