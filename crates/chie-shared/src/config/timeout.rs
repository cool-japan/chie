//! Timeout configuration

use serde::{Deserialize, Serialize};

/// Timeout configuration for operations
///
/// # Examples
///
/// Using the default configuration:
/// ```
/// use chie_shared::TimeoutConfig;
///
/// let config = TimeoutConfig::default();
/// assert_eq!(config.default_timeout_ms, 30_000);
/// assert_eq!(config.connection_timeout_ms, 10_000);
/// assert!(config.keepalive_enabled());
/// assert!(config.idle_timeout_enabled());
/// assert!(config.validate().is_ok());
/// ```
///
/// Using preset configurations for different scenarios:
/// ```
/// use chie_shared::TimeoutConfig;
///
/// // Fast configuration for low-latency operations
/// let fast_config = TimeoutConfig::fast();
/// assert_eq!(fast_config.default_timeout_ms, 5_000);
/// assert_eq!(fast_config.connection_timeout_ms, 3_000);
///
/// // Slow configuration for batch/background operations
/// let slow_config = TimeoutConfig::slow();
/// assert_eq!(slow_config.default_timeout_ms, 120_000);
/// assert_eq!(slow_config.read_timeout_ms, 300_000);
/// ```
///
/// Building a custom configuration:
/// ```
/// use chie_shared::TimeoutConfigBuilder;
///
/// let config = TimeoutConfigBuilder::new()
///     .default_timeout_ms(45_000)
///     .connection_timeout_ms(15_000)
///     .read_timeout_ms(90_000)
///     .write_timeout_ms(90_000)
///     .idle_timeout_ms(0)  // Disable idle timeout
///     .keepalive_interval_ms(30_000)
///     .build();
///
/// assert_eq!(config.default_timeout_ms, 45_000);
/// assert!(!config.idle_timeout_enabled());
/// assert!(config.keepalive_enabled());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Default operation timeout in milliseconds
    pub default_timeout_ms: u64,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Read timeout in milliseconds
    pub read_timeout_ms: u64,
    /// Write timeout in milliseconds
    pub write_timeout_ms: u64,
    /// Idle timeout in milliseconds (0 = no timeout)
    pub idle_timeout_ms: u64,
    /// Keepalive interval in milliseconds (0 = disabled)
    pub keepalive_interval_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 30_000,    // 30 seconds
            connection_timeout_ms: 10_000, // 10 seconds
            read_timeout_ms: 60_000,       // 60 seconds
            write_timeout_ms: 60_000,      // 60 seconds
            idle_timeout_ms: 300_000,      // 5 minutes
            keepalive_interval_ms: 60_000, // 1 minute
        }
    }
}

impl TimeoutConfig {
    /// Create a new configuration for fast operations
    #[must_use]
    pub const fn fast() -> Self {
        Self {
            default_timeout_ms: 5_000,
            connection_timeout_ms: 3_000,
            read_timeout_ms: 10_000,
            write_timeout_ms: 10_000,
            idle_timeout_ms: 60_000,
            keepalive_interval_ms: 30_000,
        }
    }

    /// Create a new configuration for slow operations
    #[must_use]
    pub const fn slow() -> Self {
        Self {
            default_timeout_ms: 120_000,
            connection_timeout_ms: 30_000,
            read_timeout_ms: 300_000,
            write_timeout_ms: 300_000,
            idle_timeout_ms: 600_000,
            keepalive_interval_ms: 120_000,
        }
    }

    /// Check if keepalive is enabled
    #[must_use]
    pub const fn keepalive_enabled(&self) -> bool {
        self.keepalive_interval_ms > 0
    }

    /// Check if idle timeout is enabled
    #[must_use]
    pub const fn idle_timeout_enabled(&self) -> bool {
        self.idle_timeout_ms > 0
    }

    /// Validate the timeout configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> crate::ChieResult<()> {
        use crate::ChieError;

        if self.default_timeout_ms == 0 {
            return Err(ChieError::validation(
                "default_timeout_ms must be greater than 0",
            ));
        }

        if self.connection_timeout_ms == 0 {
            return Err(ChieError::validation(
                "connection_timeout_ms must be greater than 0",
            ));
        }

        if self.read_timeout_ms == 0 {
            return Err(ChieError::validation(
                "read_timeout_ms must be greater than 0",
            ));
        }

        if self.write_timeout_ms == 0 {
            return Err(ChieError::validation(
                "write_timeout_ms must be greater than 0",
            ));
        }

        Ok(())
    }
}

/// Builder for `TimeoutConfig`
///
/// # Examples
///
/// Building a configuration for API requests:
/// ```
/// use chie_shared::TimeoutConfigBuilder;
///
/// let config = TimeoutConfigBuilder::new()
///     .default_timeout_ms(20_000)
///     .connection_timeout_ms(5_000)
///     .read_timeout_ms(30_000)
///     .write_timeout_ms(30_000)
///     .keepalive_interval_ms(45_000)
///     .build();
///
/// assert_eq!(config.default_timeout_ms, 20_000);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Default)]
pub struct TimeoutConfigBuilder {
    config: TimeoutConfig,
}

impl TimeoutConfigBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set default timeout
    #[must_use]
    pub const fn default_timeout_ms(mut self, ms: u64) -> Self {
        self.config.default_timeout_ms = ms;
        self
    }

    /// Set connection timeout
    #[must_use]
    pub const fn connection_timeout_ms(mut self, ms: u64) -> Self {
        self.config.connection_timeout_ms = ms;
        self
    }

    /// Set read timeout
    #[must_use]
    pub const fn read_timeout_ms(mut self, ms: u64) -> Self {
        self.config.read_timeout_ms = ms;
        self
    }

    /// Set write timeout
    #[must_use]
    pub const fn write_timeout_ms(mut self, ms: u64) -> Self {
        self.config.write_timeout_ms = ms;
        self
    }

    /// Set idle timeout
    #[must_use]
    pub const fn idle_timeout_ms(mut self, ms: u64) -> Self {
        self.config.idle_timeout_ms = ms;
        self
    }

    /// Set keepalive interval
    #[must_use]
    pub const fn keepalive_interval_ms(mut self, ms: u64) -> Self {
        self.config.keepalive_interval_ms = ms;
        self
    }

    /// Build the configuration
    #[must_use]
    pub const fn build(self) -> TimeoutConfig {
        self.config
    }
}
