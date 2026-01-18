//! A/B testing and feature experiment types.
//!
//! This module provides types for managing feature experiments, A/B tests, and gradual rollouts.
//! Useful for controlled feature deployment and data-driven decision making.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Experiment variant identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Variant {
    /// Control group (baseline behavior)
    Control,
    /// Treatment group (new feature/behavior)
    Treatment,
    /// Custom named variant (for multi-variant tests)
    Custom(String),
}

impl Variant {
    /// Check if this is the control variant.
    #[must_use]
    pub fn is_control(&self) -> bool {
        matches!(self, Variant::Control)
    }

    /// Check if this is the treatment variant.
    #[must_use]
    pub fn is_treatment(&self) -> bool {
        matches!(self, Variant::Treatment)
    }

    /// Get the variant name as a string.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Variant::Control => "control",
            Variant::Treatment => "treatment",
            Variant::Custom(name) => name,
        }
    }
}

/// Experiment configuration for A/B testing.
///
/// # Example
/// ```
/// use chie_shared::{Experiment, Variant};
///
/// let exp = Experiment::new("new_ui_redesign", "Test new UI design")
///     .with_rollout_percentage(10); // Start with 10% traffic
///
/// // Check if a user is in the experiment
/// let user_id = "user123";
/// let variant = exp.assign_variant(user_id);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experiment {
    /// Unique experiment identifier
    pub id: String,
    /// Human-readable experiment name
    pub name: String,
    /// Experiment description
    pub description: String,
    /// Rollout percentage (0-100)
    pub rollout_percentage: u8,
    /// Whether the experiment is currently active
    pub enabled: bool,
    /// Optional variant weights (must sum to 100)
    pub variant_weights: Option<HashMap<String, u8>>,
    /// Sticky assignment: same user always gets same variant
    pub sticky: bool,
}

impl Experiment {
    /// Create a new experiment.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            rollout_percentage: 0,
            enabled: false,
            variant_weights: None,
            sticky: true,
        }
    }

    /// Set the experiment description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the rollout percentage (0-100).
    #[must_use]
    pub fn with_rollout_percentage(mut self, percentage: u8) -> Self {
        self.rollout_percentage = percentage.min(100);
        self
    }

    /// Enable the experiment.
    #[must_use]
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set custom variant weights.
    #[must_use]
    pub fn with_variant_weights(mut self, weights: HashMap<String, u8>) -> Self {
        self.variant_weights = Some(weights);
        self
    }

    /// Disable sticky assignment (allow variant to change per request).
    #[must_use]
    pub fn non_sticky(mut self) -> Self {
        self.sticky = false;
        self
    }

    /// Assign a variant to a user based on their ID.
    ///
    /// Uses a hash-based deterministic assignment for consistency.
    #[must_use]
    pub fn assign_variant(&self, user_id: &str) -> Variant {
        if !self.enabled {
            return Variant::Control;
        }

        // Hash user ID for deterministic assignment
        let hash = self.hash_user(user_id);
        let bucket = hash % 100;

        // Check if user is in rollout
        if bucket >= u64::from(self.rollout_percentage) {
            return Variant::Control;
        }

        // Assign to variant based on weights
        if let Some(weights) = &self.variant_weights {
            let mut cumulative = 0u8;
            for (variant_name, weight) in weights {
                cumulative += weight;
                if bucket < u64::from(cumulative) {
                    return Variant::Custom(variant_name.clone());
                }
            }
        }

        // Default: users in rollout get Treatment variant
        Variant::Treatment
    }

    /// Check if a user is enrolled in the experiment.
    #[must_use]
    pub fn is_enrolled(&self, user_id: &str) -> bool {
        self.enabled && !self.assign_variant(user_id).is_control()
    }

    /// Simple hash function for user ID bucketing.
    fn hash_user(&self, user_id: &str) -> u64 {
        // Combine experiment ID and user ID for independent experiments
        let combined = format!("{}{}", self.id, user_id);
        let mut hash = 0u64;
        for byte in combined.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(u64::from(byte));
        }
        hash
    }
}

/// Experiment result tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentResult {
    /// Experiment ID
    pub experiment_id: String,
    /// User ID
    pub user_id: String,
    /// Assigned variant
    pub variant: Variant,
    /// Timestamp when assigned (milliseconds)
    pub assigned_at: u64,
    /// Custom metrics/properties
    pub metrics: HashMap<String, f64>,
}

impl ExperimentResult {
    /// Create a new experiment result.
    #[must_use]
    pub fn new(experiment_id: String, user_id: String, variant: Variant, assigned_at: u64) -> Self {
        Self {
            experiment_id,
            user_id,
            variant,
            assigned_at,
            metrics: HashMap::new(),
        }
    }

    /// Add a metric to the result.
    pub fn add_metric(&mut self, name: impl Into<String>, value: f64) {
        self.metrics.insert(name.into(), value);
    }

    /// Get a metric value.
    #[must_use]
    pub fn get_metric(&self, name: &str) -> Option<f64> {
        self.metrics.get(name).copied()
    }
}

/// Gradual rollout configuration.
///
/// Manages percentage-based feature rollouts with automatic ramping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradualRollout {
    /// Feature identifier
    pub feature_id: String,
    /// Current rollout percentage (0-100)
    pub current_percentage: u8,
    /// Target rollout percentage (0-100)
    pub target_percentage: u8,
    /// Increment step for each ramp
    pub increment_step: u8,
    /// Whether rollout is active
    pub enabled: bool,
}

impl GradualRollout {
    /// Create a new gradual rollout configuration.
    #[must_use]
    pub fn new(feature_id: impl Into<String>) -> Self {
        Self {
            feature_id: feature_id.into(),
            current_percentage: 0,
            target_percentage: 100,
            increment_step: 10,
            enabled: false,
        }
    }

    /// Set the target rollout percentage.
    #[must_use]
    pub fn with_target(mut self, target: u8) -> Self {
        self.target_percentage = target.min(100);
        self
    }

    /// Set the increment step.
    #[must_use]
    pub fn with_step(mut self, step: u8) -> Self {
        self.increment_step = step.max(1);
        self
    }

    /// Enable the rollout.
    #[must_use]
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Ramp up the rollout by one increment.
    pub fn ramp_up(&mut self) {
        if self.enabled && self.current_percentage < self.target_percentage {
            self.current_percentage =
                (self.current_percentage + self.increment_step).min(self.target_percentage);
        }
    }

    /// Ramp down the rollout by one decrement.
    pub fn ramp_down(&mut self) {
        if self.current_percentage > 0 {
            self.current_percentage = self.current_percentage.saturating_sub(self.increment_step);
        }
    }

    /// Check if a user has access to the feature.
    #[must_use]
    pub fn has_access(&self, user_id: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let hash = self.hash_user(user_id);
        let bucket = hash % 100;
        bucket < u64::from(self.current_percentage)
    }

    /// Check if the rollout is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.current_percentage >= self.target_percentage
    }

    fn hash_user(&self, user_id: &str) -> u64 {
        let combined = format!("{}{}", self.feature_id, user_id);
        let mut hash = 0u64;
        for byte in combined.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(u64::from(byte));
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_is_control() {
        assert!(Variant::Control.is_control());
        assert!(!Variant::Treatment.is_control());
        assert!(!Variant::Custom("test".to_string()).is_control());
    }

    #[test]
    fn test_variant_is_treatment() {
        assert!(!Variant::Control.is_treatment());
        assert!(Variant::Treatment.is_treatment());
        assert!(!Variant::Custom("test".to_string()).is_treatment());
    }

    #[test]
    fn test_variant_name() {
        assert_eq!(Variant::Control.name(), "control");
        assert_eq!(Variant::Treatment.name(), "treatment");
        assert_eq!(Variant::Custom("custom".to_string()).name(), "custom");
    }

    #[test]
    fn test_experiment_disabled() {
        let exp = Experiment::new("test", "Test Experiment");
        assert!(!exp.enabled);
        assert_eq!(exp.assign_variant("user123"), Variant::Control);
    }

    #[test]
    fn test_experiment_rollout_percentage() {
        let exp = Experiment::new("test", "Test Experiment")
            .with_rollout_percentage(50)
            .enabled();

        // Test deterministic assignment
        let variant1 = exp.assign_variant("user123");
        let variant2 = exp.assign_variant("user123");
        assert_eq!(variant1, variant2); // Same user gets same variant
    }

    #[test]
    fn test_experiment_rollout_percentage_clamping() {
        let exp = Experiment::new("test", "Test").with_rollout_percentage(150); // Over 100
        assert_eq!(exp.rollout_percentage, 100);
    }

    #[test]
    fn test_experiment_is_enrolled() {
        let exp = Experiment::new("test", "Test")
            .with_rollout_percentage(100)
            .enabled();

        // With 100% rollout, users should be enrolled
        assert!(exp.is_enrolled("user123"));
    }

    #[test]
    fn test_experiment_result() {
        let mut result = ExperimentResult::new(
            "exp1".to_string(),
            "user123".to_string(),
            Variant::Treatment,
            1000,
        );

        result.add_metric("conversion_rate", 0.25);
        result.add_metric("revenue", 100.0);

        assert_eq!(result.get_metric("conversion_rate"), Some(0.25));
        assert_eq!(result.get_metric("revenue"), Some(100.0));
        assert_eq!(result.get_metric("nonexistent"), None);
    }

    #[test]
    fn test_gradual_rollout_new() {
        let rollout = GradualRollout::new("feature1");
        assert_eq!(rollout.current_percentage, 0);
        assert_eq!(rollout.target_percentage, 100);
        assert!(!rollout.enabled);
    }

    #[test]
    fn test_gradual_rollout_ramp_up() {
        let mut rollout = GradualRollout::new("feature1")
            .with_step(10)
            .with_target(50)
            .enabled();

        assert_eq!(rollout.current_percentage, 0);
        rollout.ramp_up();
        assert_eq!(rollout.current_percentage, 10);
        rollout.ramp_up();
        assert_eq!(rollout.current_percentage, 20);

        // Ramp up to target
        rollout.ramp_up();
        rollout.ramp_up();
        rollout.ramp_up();
        assert_eq!(rollout.current_percentage, 50);

        // Should not exceed target
        rollout.ramp_up();
        assert_eq!(rollout.current_percentage, 50);
    }

    #[test]
    fn test_gradual_rollout_ramp_down() {
        let mut rollout = GradualRollout::new("feature1").with_step(10).enabled();

        rollout.current_percentage = 50;
        rollout.ramp_down();
        assert_eq!(rollout.current_percentage, 40);

        // Should not go below 0
        rollout.current_percentage = 5;
        rollout.ramp_down();
        assert_eq!(rollout.current_percentage, 0);
        rollout.ramp_down();
        assert_eq!(rollout.current_percentage, 0);
    }

    #[test]
    fn test_gradual_rollout_has_access() {
        let mut rollout = GradualRollout::new("feature1").enabled();

        // 0% rollout - no access
        assert!(!rollout.has_access("user123"));

        // 100% rollout - full access
        rollout.current_percentage = 100;
        assert!(rollout.has_access("user123"));
    }

    #[test]
    fn test_gradual_rollout_is_complete() {
        let mut rollout = GradualRollout::new("feature1").with_target(50);

        assert!(!rollout.is_complete());
        rollout.current_percentage = 50;
        assert!(rollout.is_complete());
        rollout.current_percentage = 60;
        assert!(rollout.is_complete());
    }

    #[test]
    fn test_experiment_serde() {
        let exp = Experiment::new("test", "Test Experiment")
            .with_description("A test experiment")
            .with_rollout_percentage(50)
            .enabled();

        let json = serde_json::to_string(&exp).unwrap();
        let decoded: Experiment = serde_json::from_str(&json).unwrap();
        assert_eq!(exp.id, decoded.id);
        assert_eq!(exp.rollout_percentage, decoded.rollout_percentage);
        assert_eq!(exp.enabled, decoded.enabled);
    }

    #[test]
    fn test_gradual_rollout_serde() {
        let rollout = GradualRollout::new("feature1")
            .with_target(75)
            .with_step(25)
            .enabled();

        let json = serde_json::to_string(&rollout).unwrap();
        let decoded: GradualRollout = serde_json::from_str(&json).unwrap();
        assert_eq!(rollout.feature_id, decoded.feature_id);
        assert_eq!(rollout.target_percentage, decoded.target_percentage);
        assert_eq!(rollout.increment_step, decoded.increment_step);
    }
}
