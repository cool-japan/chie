//! Configuration merge utilities

use super::{FeatureFlags, RetryConfig};

/// Configuration merge utilities for combining configurations with priority
///
/// This utility provides methods to merge two configuration instances with various
/// merge strategies. Useful for layered configuration systems where settings can come
/// from multiple sources (defaults → file → environment → CLI).
///
/// # Examples
///
/// ```
/// use chie_shared::{ConfigMerge, FeatureFlags};
///
/// // OR merge: feature enabled if enabled in either config
/// let base = FeatureFlags {
///     experimental: true,
///     beta: false,
///     ..FeatureFlags::none()
/// };
/// let override_flags = FeatureFlags {
///     experimental: false,
///     beta: true,
///     ..FeatureFlags::none()
/// };
///
/// let merged = ConfigMerge::feature_flags(&base, &override_flags, false);
/// assert!(merged.experimental); // true from base
/// assert!(merged.beta);         // true from override
/// ```
pub struct ConfigMerge;

impl ConfigMerge {
    /// Merge two `RetryConfig` instances with override semantics
    ///
    /// The `override_config` takes priority over `base_config` for all fields.
    /// This is useful for layered configuration where CLI args override file config, etc.
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{ConfigMerge, RetryConfig};
    ///
    /// let base = RetryConfig {
    ///     max_attempts: 5,
    ///     initial_backoff_ms: 200,
    ///     ..RetryConfig::default()
    /// };
    ///
    /// let override_config = RetryConfig {
    ///     max_attempts: 10,
    ///     ..RetryConfig::default()
    /// };
    ///
    /// let merged = ConfigMerge::retry_config(&base, &override_config);
    /// assert_eq!(merged.max_attempts, 10); // From override
    /// ```
    #[must_use]
    pub fn retry_config(_base: &RetryConfig, override_config: &RetryConfig) -> RetryConfig {
        // Complete override - all fields from override_config
        override_config.clone()
    }

    /// Merge two `FeatureFlags` instances
    ///
    /// If `override_all` is true, the `override_flags` completely replaces `base_flags`.
    /// If `override_all` is false, features are merged with OR logic (a feature is enabled
    /// if it's enabled in either base or override).
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{ConfigMerge, FeatureFlags};
    ///
    /// let base = FeatureFlags::all();
    /// let override_flags = FeatureFlags::none();
    ///
    /// // Complete override - all features disabled
    /// let merged = ConfigMerge::feature_flags(&base, &override_flags, true);
    /// assert!(!merged.experimental);
    /// assert!(!merged.beta);
    ///
    /// // OR merge - features enabled if enabled in either
    /// let merged = ConfigMerge::feature_flags(&base, &override_flags, false);
    /// assert!(merged.experimental); // Enabled in base
    /// assert!(merged.beta);         // Enabled in base
    /// ```
    #[must_use]
    pub fn feature_flags(
        base: &FeatureFlags,
        override_flags: &FeatureFlags,
        override_all: bool,
    ) -> FeatureFlags {
        if override_all {
            // Complete override
            override_flags.clone()
        } else {
            // OR merge - feature is enabled if enabled in either config
            FeatureFlags {
                experimental: base.experimental || override_flags.experimental,
                beta: base.beta || override_flags.beta,
                enhanced_telemetry: base.enhanced_telemetry || override_flags.enhanced_telemetry,
                performance_profiling: base.performance_profiling
                    || override_flags.performance_profiling,
                debug_mode: base.debug_mode || override_flags.debug_mode,
                compression_optimization: base.compression_optimization
                    || override_flags.compression_optimization,
                adaptive_retry: base.adaptive_retry || override_flags.adaptive_retry,
            }
        }
    }
}
