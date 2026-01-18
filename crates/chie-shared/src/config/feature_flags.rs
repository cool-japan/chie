//! Feature flags configuration

use serde::{Deserialize, Serialize};

/// Feature flags for runtime feature toggling
///
/// # Examples
///
/// Using the default configuration (production-ready features enabled):
/// ```
/// use chie_shared::FeatureFlags;
///
/// let flags = FeatureFlags::default();
/// assert!(!flags.experimental);
/// assert!(!flags.beta);
/// assert!(flags.compression_optimization);
/// assert!(flags.adaptive_retry);
/// assert!(!flags.has_unstable_features());
/// ```
///
/// Using preset configurations:
/// ```
/// use chie_shared::FeatureFlags;
///
/// // All features disabled (minimal mode)
/// let minimal = FeatureFlags::none();
/// assert!(!minimal.compression_optimization);
/// assert!(!minimal.has_diagnostic_features());
///
/// // All features enabled (debug/testing mode)
/// let all = FeatureFlags::all();
/// assert!(all.experimental);
/// assert!(all.debug_mode);
/// assert!(all.has_unstable_features());
/// assert!(all.has_diagnostic_features());
/// ```
///
/// Building a custom configuration:
/// ```
/// use chie_shared::FeatureFlagsBuilder;
///
/// let flags = FeatureFlagsBuilder::new()
///     .experimental(true)
///     .performance_profiling(true)
///     .enhanced_telemetry(true)
///     .build();
///
/// assert!(flags.experimental);
/// assert!(flags.performance_profiling);
/// assert!(flags.has_unstable_features());
/// assert!(flags.has_diagnostic_features());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable experimental features
    pub experimental: bool,
    /// Enable beta features
    pub beta: bool,
    /// Enable enhanced telemetry
    pub enhanced_telemetry: bool,
    /// Enable performance profiling
    pub performance_profiling: bool,
    /// Enable debug mode
    pub debug_mode: bool,
    /// Enable compression optimization
    pub compression_optimization: bool,
    /// Enable adaptive retry
    pub adaptive_retry: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            experimental: false,
            beta: false,
            enhanced_telemetry: false,
            performance_profiling: false,
            debug_mode: false,
            compression_optimization: true,
            adaptive_retry: true,
        }
    }
}

impl FeatureFlags {
    /// Create a new feature flags configuration with all features disabled
    #[must_use]
    pub const fn none() -> Self {
        Self {
            experimental: false,
            beta: false,
            enhanced_telemetry: false,
            performance_profiling: false,
            debug_mode: false,
            compression_optimization: false,
            adaptive_retry: false,
        }
    }

    /// Create a new feature flags configuration with all features enabled
    #[must_use]
    pub const fn all() -> Self {
        Self {
            experimental: true,
            beta: true,
            enhanced_telemetry: true,
            performance_profiling: true,
            debug_mode: true,
            compression_optimization: true,
            adaptive_retry: true,
        }
    }

    /// Check if any experimental or beta feature is enabled
    #[must_use]
    pub const fn has_unstable_features(&self) -> bool {
        self.experimental || self.beta
    }

    /// Check if any diagnostic feature is enabled
    #[must_use]
    pub const fn has_diagnostic_features(&self) -> bool {
        self.debug_mode || self.performance_profiling || self.enhanced_telemetry
    }
}

/// Builder for `FeatureFlags`
///
/// # Examples
///
/// Building flags for development environment:
/// ```
/// use chie_shared::FeatureFlagsBuilder;
///
/// let flags = FeatureFlagsBuilder::new()
///     .beta(true)
///     .debug_mode(true)
///     .performance_profiling(true)
///     .enhanced_telemetry(true)
///     .build();
///
/// assert!(flags.beta);
/// assert!(flags.debug_mode);
/// assert!(flags.has_diagnostic_features());
/// ```
///
/// Building flags for staging environment:
/// ```
/// use chie_shared::FeatureFlagsBuilder;
///
/// let flags = FeatureFlagsBuilder::new()
///     .beta(true)
///     .enhanced_telemetry(true)
///     .compression_optimization(true)
///     .adaptive_retry(true)
///     .build();
///
/// assert!(flags.beta);
/// assert!(!flags.experimental);  // Not ready for experimental
/// assert!(flags.enhanced_telemetry);
/// ```
#[derive(Debug, Default)]
pub struct FeatureFlagsBuilder {
    config: FeatureFlags,
}

impl FeatureFlagsBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable experimental features
    #[must_use]
    pub const fn experimental(mut self, enable: bool) -> Self {
        self.config.experimental = enable;
        self
    }

    /// Enable or disable beta features
    #[must_use]
    pub const fn beta(mut self, enable: bool) -> Self {
        self.config.beta = enable;
        self
    }

    /// Enable or disable enhanced telemetry
    #[must_use]
    pub const fn enhanced_telemetry(mut self, enable: bool) -> Self {
        self.config.enhanced_telemetry = enable;
        self
    }

    /// Enable or disable performance profiling
    #[must_use]
    pub const fn performance_profiling(mut self, enable: bool) -> Self {
        self.config.performance_profiling = enable;
        self
    }

    /// Enable or disable debug mode
    #[must_use]
    pub const fn debug_mode(mut self, enable: bool) -> Self {
        self.config.debug_mode = enable;
        self
    }

    /// Enable or disable compression optimization
    #[must_use]
    pub const fn compression_optimization(mut self, enable: bool) -> Self {
        self.config.compression_optimization = enable;
        self
    }

    /// Enable or disable adaptive retry
    #[must_use]
    pub const fn adaptive_retry(mut self, enable: bool) -> Self {
        self.config.adaptive_retry = enable;
        self
    }

    /// Build the feature flags configuration
    #[must_use]
    pub const fn build(self) -> FeatureFlags {
        self.config
    }
}
