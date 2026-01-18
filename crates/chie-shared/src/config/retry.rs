//! Retry policy configuration

use serde::{Deserialize, Serialize};

/// Retry policy configuration
///
/// # Examples
///
/// Using the default configuration:
/// ```
/// use chie_shared::RetryConfig;
///
/// let config = RetryConfig::default();
/// assert_eq!(config.max_attempts, 3);
/// assert_eq!(config.initial_backoff_ms, 100);
/// assert_eq!(config.multiplier, 2.0);
/// assert!(config.enable_jitter);
///
/// // Check if retries are exhausted
/// assert!(!config.is_exhausted(0));
/// assert!(!config.is_exhausted(2));
/// assert!(config.is_exhausted(3));
/// ```
///
/// Building a custom aggressive retry policy:
/// ```
/// use chie_shared::RetryConfigBuilder;
///
/// let config = RetryConfigBuilder::new()
///     .max_attempts(5)
///     .initial_backoff_ms(100)
///     .max_backoff_ms(10_000)
///     .multiplier(2.0)
///     .enable_jitter(false)
///     .build();
///
/// assert_eq!(config.max_attempts, 5);
/// assert_eq!(config.initial_backoff_ms, 100);
/// assert!(!config.enable_jitter);
///
/// // Calculate backoff delays (without jitter) - exponential backoff
/// assert_eq!(config.next_backoff_ms(0), 100);   // 100 * 2^0
/// assert_eq!(config.next_backoff_ms(1), 200);   // 100 * 2^1
/// assert_eq!(config.next_backoff_ms(2), 400);   // 100 * 2^2
/// assert_eq!(config.next_backoff_ms(3), 800);   // 100 * 2^3
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial backoff delay in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier (exponential)
    pub multiplier: f64,
    /// Enable jitter to avoid thundering herd
    pub enable_jitter: bool,
}

impl RetryConfig {
    /// Check if retries are exhausted
    #[must_use]
    pub const fn is_exhausted(&self, attempt: u32) -> bool {
        attempt >= self.max_attempts
    }

    /// Calculate next backoff delay with jitter
    #[must_use]
    pub fn next_backoff_ms(&self, attempt: u32) -> u64 {
        use crate::utils::random_jitter;

        // Cap attempt at 10 to prevent overflow and convert to i32
        #[allow(clippy::cast_possible_wrap)]
        let exponent = attempt.min(10) as i32;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let base_delay = self
            .initial_backoff_ms
            .saturating_mul(self.multiplier.powi(exponent) as u64)
            .min(self.max_backoff_ms);

        if self.enable_jitter {
            random_jitter(base_delay, 0.25) // ±25% jitter
        } else {
            base_delay
        }
    }

    /// Validate the retry configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> crate::ChieResult<()> {
        use crate::ChieError;

        if self.max_attempts == 0 {
            return Err(ChieError::validation("max_attempts must be greater than 0"));
        }

        if self.initial_backoff_ms == 0 {
            return Err(ChieError::validation(
                "initial_backoff_ms must be greater than 0",
            ));
        }

        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(ChieError::validation(
                "max_backoff_ms must be greater than or equal to initial_backoff_ms",
            ));
        }

        if self.multiplier <= 0.0 {
            return Err(ChieError::validation("multiplier must be greater than 0"));
        }

        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 30_000,
            multiplier: 2.0,
            enable_jitter: true,
        }
    }
}

/// Builder for `RetryConfig`
///
/// # Examples
///
/// Building a conservative retry policy for critical operations:
/// ```
/// use chie_shared::RetryConfigBuilder;
///
/// let config = RetryConfigBuilder::new()
///     .max_attempts(10)
///     .initial_backoff_ms(1_000)
///     .max_backoff_ms(60_000)
///     .multiplier(2.0)
///     .enable_jitter(true)
///     .build();
///
/// assert_eq!(config.max_attempts, 10);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Default)]
pub struct RetryConfigBuilder {
    config: RetryConfig,
}

impl RetryConfigBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum retry attempts
    #[must_use]
    pub const fn max_attempts(mut self, max: u32) -> Self {
        self.config.max_attempts = max;
        self
    }

    /// Set initial backoff delay
    #[must_use]
    pub const fn initial_backoff_ms(mut self, ms: u64) -> Self {
        self.config.initial_backoff_ms = ms;
        self
    }

    /// Set maximum backoff delay
    #[must_use]
    pub const fn max_backoff_ms(mut self, ms: u64) -> Self {
        self.config.max_backoff_ms = ms;
        self
    }

    /// Set backoff multiplier
    #[must_use]
    pub const fn multiplier(mut self, multiplier: f64) -> Self {
        self.config.multiplier = multiplier;
        self
    }

    /// Enable or disable jitter
    #[must_use]
    pub const fn enable_jitter(mut self, enable: bool) -> Self {
        self.config.enable_jitter = enable;
        self
    }

    /// Build the configuration
    #[must_use]
    pub const fn build(self) -> RetryConfig {
        self.config
    }
}
