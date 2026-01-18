//! Configuration diff utilities

use super::{FeatureFlags, NetworkConfig, RetryConfig};
use serde::{Deserialize, Serialize};

/// Represents a single configuration change with old and new values
///
/// This type is used to track individual field changes when comparing configurations,
/// making it easy to log, audit, or display what changed during a configuration update.
///
/// # Examples
///
/// ```
/// use chie_shared::ConfigChange;
///
/// // Track a simple numeric change
/// let change = ConfigChange::new("max_connections", &100, &200);
/// assert_eq!(change.field, "max_connections");
/// assert_eq!(change.old_value, "100");
/// assert_eq!(change.new_value, "200");
///
/// // Track a boolean change
/// let change = ConfigChange::new("enable_relay", &true, &false);
/// assert_eq!(change.old_value, "true");
/// assert_eq!(change.new_value, "false");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigChange {
    /// Field name that changed
    pub field: String,
    /// Old value (serialized as string)
    pub old_value: String,
    /// New value (serialized as string)
    pub new_value: String,
}

impl ConfigChange {
    /// Create a new configuration change
    #[must_use]
    pub fn new(
        field: impl Into<String>,
        old_value: &impl ToString,
        new_value: &impl ToString,
    ) -> Self {
        Self {
            field: field.into(),
            old_value: old_value.to_string(),
            new_value: new_value.to_string(),
        }
    }
}

/// Configuration diff utilities for detecting differences between configurations
///
/// This utility provides methods to compare configuration instances and detect
/// what fields have changed. Useful for configuration hot-reload, migration,
/// auditing, and change tracking.
///
/// # Examples
///
/// ```
/// use chie_shared::{ConfigDiff, RetryConfig};
///
/// let old_config = RetryConfig::default();
/// let mut new_config = RetryConfig::default();
/// new_config.max_attempts = 10;
///
/// let changes = ConfigDiff::retry_config(&old_config, &new_config);
/// assert_eq!(changes.len(), 1);
/// assert_eq!(changes[0].field, "max_attempts");
/// assert_eq!(changes[0].new_value, "10");
/// ```
pub struct ConfigDiff;

impl ConfigDiff {
    /// Detect differences between two `NetworkConfig` instances
    ///
    /// Returns a list of changes between the old and new configurations.
    /// Compares all fields including `max_connections`, timeouts, relay/DHT settings,
    /// bootstrap peers, and listen addresses.
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{ConfigDiff, NetworkConfig};
    ///
    /// let old = NetworkConfig::default();
    /// let mut new = NetworkConfig::default();
    /// new.max_connections = 200;
    /// new.enable_relay = false;
    ///
    /// let changes = ConfigDiff::network_config(&old, &new);
    /// assert_eq!(changes.len(), 2);
    ///
    /// // Check for specific changes
    /// let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
    /// assert!(fields.contains(&"max_connections"));
    /// assert!(fields.contains(&"enable_relay"));
    /// ```
    #[must_use]
    pub fn network_config(old: &NetworkConfig, new: &NetworkConfig) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        if old.max_connections != new.max_connections {
            changes.push(ConfigChange::new(
                "max_connections",
                &old.max_connections,
                &new.max_connections,
            ));
        }

        if old.connection_timeout_ms != new.connection_timeout_ms {
            changes.push(ConfigChange::new(
                "connection_timeout_ms",
                &old.connection_timeout_ms,
                &new.connection_timeout_ms,
            ));
        }

        if old.request_timeout_ms != new.request_timeout_ms {
            changes.push(ConfigChange::new(
                "request_timeout_ms",
                &old.request_timeout_ms,
                &new.request_timeout_ms,
            ));
        }

        if old.enable_relay != new.enable_relay {
            changes.push(ConfigChange::new(
                "enable_relay",
                &old.enable_relay,
                &new.enable_relay,
            ));
        }

        if old.enable_dht != new.enable_dht {
            changes.push(ConfigChange::new(
                "enable_dht",
                &old.enable_dht,
                &new.enable_dht,
            ));
        }

        if old.bootstrap_peers != new.bootstrap_peers {
            let old_val = format!("{:?}", old.bootstrap_peers);
            let new_val = format!("{:?}", new.bootstrap_peers);
            changes.push(ConfigChange::new("bootstrap_peers", &old_val, &new_val));
        }

        if old.listen_addrs != new.listen_addrs {
            let old_val = format!("{:?}", old.listen_addrs);
            let new_val = format!("{:?}", new.listen_addrs);
            changes.push(ConfigChange::new("listen_addrs", &old_val, &new_val));
        }

        changes
    }

    /// Detect differences between two `RetryConfig` instances
    ///
    /// Returns a list of changes between the old and new configurations.
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{ConfigDiff, RetryConfigBuilder};
    ///
    /// let old = RetryConfigBuilder::new()
    ///     .max_attempts(3)
    ///     .initial_backoff_ms(100)
    ///     .build();
    ///
    /// let new = RetryConfigBuilder::new()
    ///     .max_attempts(5)
    ///     .initial_backoff_ms(200)
    ///     .build();
    ///
    /// let changes = ConfigDiff::retry_config(&old, &new);
    /// assert_eq!(changes.len(), 2);
    ///
    /// // Verify specific changes
    /// let max_attempts_change = changes.iter()
    ///     .find(|c| c.field == "max_attempts")
    ///     .unwrap();
    /// assert_eq!(max_attempts_change.old_value, "3");
    /// assert_eq!(max_attempts_change.new_value, "5");
    /// ```
    #[must_use]
    pub fn retry_config(old: &RetryConfig, new: &RetryConfig) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        if old.max_attempts != new.max_attempts {
            changes.push(ConfigChange::new(
                "max_attempts",
                &old.max_attempts,
                &new.max_attempts,
            ));
        }

        if old.initial_backoff_ms != new.initial_backoff_ms {
            changes.push(ConfigChange::new(
                "initial_backoff_ms",
                &old.initial_backoff_ms,
                &new.initial_backoff_ms,
            ));
        }

        if old.max_backoff_ms != new.max_backoff_ms {
            changes.push(ConfigChange::new(
                "max_backoff_ms",
                &old.max_backoff_ms,
                &new.max_backoff_ms,
            ));
        }

        #[allow(clippy::float_cmp)]
        if old.multiplier != new.multiplier {
            changes.push(ConfigChange::new(
                "multiplier",
                &old.multiplier,
                &new.multiplier,
            ));
        }

        if old.enable_jitter != new.enable_jitter {
            changes.push(ConfigChange::new(
                "enable_jitter",
                &old.enable_jitter,
                &new.enable_jitter,
            ));
        }

        changes
    }

    /// Detect differences between two `FeatureFlags` instances
    ///
    /// Returns a list of changes between the old and new configurations.
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{ConfigDiff, FeatureFlagsBuilder};
    ///
    /// let old = FeatureFlagsBuilder::new()
    ///     .experimental(false)
    ///     .debug_mode(false)
    ///     .build();
    ///
    /// let new = FeatureFlagsBuilder::new()
    ///     .experimental(true)
    ///     .debug_mode(true)
    ///     .performance_profiling(true)
    ///     .build();
    ///
    /// let changes = ConfigDiff::feature_flags(&old, &new);
    /// assert!(changes.len() >= 2);  // At least experimental and debug_mode changed
    ///
    /// // Check for experimental flag change
    /// let exp_change = changes.iter()
    ///     .find(|c| c.field == "experimental")
    ///     .unwrap();
    /// assert_eq!(exp_change.old_value, "false");
    /// assert_eq!(exp_change.new_value, "true");
    /// ```
    #[must_use]
    pub fn feature_flags(old: &FeatureFlags, new: &FeatureFlags) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        if old.experimental != new.experimental {
            changes.push(ConfigChange::new(
                "experimental",
                &old.experimental,
                &new.experimental,
            ));
        }

        if old.beta != new.beta {
            changes.push(ConfigChange::new("beta", &old.beta, &new.beta));
        }

        if old.enhanced_telemetry != new.enhanced_telemetry {
            changes.push(ConfigChange::new(
                "enhanced_telemetry",
                &old.enhanced_telemetry,
                &new.enhanced_telemetry,
            ));
        }

        if old.performance_profiling != new.performance_profiling {
            changes.push(ConfigChange::new(
                "performance_profiling",
                &old.performance_profiling,
                &new.performance_profiling,
            ));
        }

        if old.debug_mode != new.debug_mode {
            changes.push(ConfigChange::new(
                "debug_mode",
                &old.debug_mode,
                &new.debug_mode,
            ));
        }

        if old.compression_optimization != new.compression_optimization {
            changes.push(ConfigChange::new(
                "compression_optimization",
                &old.compression_optimization,
                &new.compression_optimization,
            ));
        }

        if old.adaptive_retry != new.adaptive_retry {
            changes.push(ConfigChange::new(
                "adaptive_retry",
                &old.adaptive_retry,
                &new.adaptive_retry,
            ));
        }

        changes
    }
}
