//! Rate limiting configuration

use serde::{Deserialize, Serialize};

/// Rate limiting configuration
///
/// # Examples
///
/// Using the default configuration:
/// ```
/// use chie_shared::RateLimitConfig;
///
/// let config = RateLimitConfig::default();
/// assert_eq!(config.max_requests, 100);
/// assert_eq!(config.window_secs, 60);
/// assert_eq!(config.burst_size, 20);
/// assert!(config.enabled);
/// assert!(config.validate().is_ok());
/// ```
///
/// Building a strict rate limit configuration:
/// ```
/// use chie_shared::RateLimitConfigBuilder;
///
/// let config = RateLimitConfigBuilder::new()
///     .max_requests(10)
///     .window_secs(1)  // 10 requests per second
///     .burst_size(5)   // Allow small bursts
///     .enabled(true)
///     .build();
///
/// assert_eq!(config.max_requests, 10);
/// assert_eq!(config.window_secs, 1);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per time window
    pub max_requests: u32,
    /// Time window in seconds
    pub window_secs: u64,
    /// Burst allowance (requests above limit temporarily)
    pub burst_size: u32,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 60,
            burst_size: 20,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Validate the rate limit configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> crate::ChieResult<()> {
        use crate::ChieError;

        if self.enabled {
            if self.max_requests == 0 {
                return Err(ChieError::validation(
                    "max_requests must be greater than 0 when rate limiting is enabled",
                ));
            }

            if self.window_secs == 0 {
                return Err(ChieError::validation(
                    "window_secs must be greater than 0 when rate limiting is enabled",
                ));
            }

            if self.burst_size > self.max_requests {
                return Err(ChieError::validation(
                    "burst_size must not exceed max_requests",
                ));
            }
        }

        Ok(())
    }
}

/// Builder for `RateLimitConfig`
///
/// # Examples
///
/// Building a generous rate limit for authenticated users:
/// ```
/// use chie_shared::RateLimitConfigBuilder;
///
/// let config = RateLimitConfigBuilder::new()
///     .max_requests(1000)
///     .window_secs(60)  // 1000 requests per minute
///     .burst_size(200)  // Allow larger bursts
///     .enabled(true)
///     .build();
///
/// assert_eq!(config.max_requests, 1000);
/// assert!(config.validate().is_ok());
/// ```
///
/// Disabling rate limiting for internal services:
/// ```
/// use chie_shared::RateLimitConfigBuilder;
///
/// let config = RateLimitConfigBuilder::new()
///     .enabled(false)
///     .build();
///
/// assert!(!config.enabled);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Default)]
pub struct RateLimitConfigBuilder {
    config: RateLimitConfig,
}

impl RateLimitConfigBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum requests per window
    #[must_use]
    pub const fn max_requests(mut self, max: u32) -> Self {
        self.config.max_requests = max;
        self
    }

    /// Set time window in seconds
    #[must_use]
    pub const fn window_secs(mut self, secs: u64) -> Self {
        self.config.window_secs = secs;
        self
    }

    /// Set burst size
    #[must_use]
    pub const fn burst_size(mut self, size: u32) -> Self {
        self.config.burst_size = size;
        self
    }

    /// Enable or disable rate limiting
    #[must_use]
    pub const fn enabled(mut self, enable: bool) -> Self {
        self.config.enabled = enable;
        self
    }

    /// Build the configuration
    #[must_use]
    pub const fn build(self) -> RateLimitConfig {
        self.config
    }
}
