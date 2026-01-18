//! Configuration management for CHIE node settings.
//!
//! This module provides centralized configuration with validation, defaults,
//! and builder patterns for easy construction.
//!
//! # Example
//!
//! ```rust
//! use chie_core::config::{NodeSettings, StorageSettings, NetworkSettings};
//!
//! // Use builder pattern
//! let settings = NodeSettings::builder()
//!     .storage(StorageSettings::default())
//!     .network(NetworkSettings::default())
//!     .build()
//!     .expect("Invalid configuration");
//!
//! println!("Max storage: {} GB", settings.storage.max_bytes_gb());
//! ```

use std::path::PathBuf;

/// Storage configuration settings.
#[derive(Debug, Clone)]
pub struct StorageSettings {
    /// Base path for storing content chunks.
    pub base_path: PathBuf,
    /// Maximum storage in bytes.
    pub max_bytes: u64,
    /// Minimum free space to maintain (bytes).
    pub min_free_bytes: u64,
    /// Enable tiered storage (SSD/HDD).
    pub enable_tiering: bool,
    /// SSD tier path (if tiering enabled).
    pub ssd_path: Option<PathBuf>,
    /// HDD tier path (if tiering enabled).
    pub hdd_path: Option<PathBuf>,
}

impl StorageSettings {
    /// Create storage settings with specified path and max bytes.
    #[inline]
    #[must_use]
    pub fn new(base_path: PathBuf, max_bytes: u64) -> Self {
        Self {
            base_path,
            max_bytes,
            min_free_bytes: 1024 * 1024 * 1024, // 1 GB
            enable_tiering: false,
            ssd_path: None,
            hdd_path: None,
        }
    }

    /// Get max storage in gigabytes.
    #[inline]
    #[must_use]
    pub const fn max_bytes_gb(&self) -> f64 {
        self.max_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Validate storage settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_bytes == 0 {
            return Err(ConfigError::InvalidValue(
                "max_bytes must be greater than 0".into(),
            ));
        }

        if self.min_free_bytes >= self.max_bytes {
            return Err(ConfigError::InvalidValue(
                "min_free_bytes must be less than max_bytes".into(),
            ));
        }

        if self.enable_tiering && (self.ssd_path.is_none() || self.hdd_path.is_none()) {
            return Err(ConfigError::InvalidValue(
                "Tiering enabled but SSD/HDD paths not specified".into(),
            ));
        }

        Ok(())
    }
}

impl Default for StorageSettings {
    #[inline]
    fn default() -> Self {
        Self::new(
            PathBuf::from("./chie-data"),
            50 * 1024 * 1024 * 1024, // 50 GB
        )
    }
}

/// Network configuration settings.
#[derive(Debug, Clone)]
pub struct NetworkSettings {
    /// Maximum bandwidth in bytes per second.
    pub max_bandwidth_bps: u64,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u64,
    /// Request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Enable rate limiting.
    pub enable_rate_limiting: bool,
    /// Rate limit (requests per second).
    pub rate_limit_rps: f64,
}

impl NetworkSettings {
    /// Create network settings with specified bandwidth.
    #[inline]
    #[must_use]
    pub fn new(max_bandwidth_bps: u64) -> Self {
        Self {
            max_bandwidth_bps,
            max_connections: 100,
            connection_timeout_secs: 10,
            request_timeout_secs: 30,
            enable_rate_limiting: true,
            rate_limit_rps: 100.0,
        }
    }

    /// Get max bandwidth in Mbps.
    #[inline]
    #[must_use]
    pub const fn max_bandwidth_mbps(&self) -> f64 {
        (self.max_bandwidth_bps * 8) as f64 / (1024.0 * 1024.0)
    }

    /// Validate network settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_bandwidth_bps == 0 {
            return Err(ConfigError::InvalidValue(
                "max_bandwidth_bps must be greater than 0".into(),
            ));
        }

        if self.max_connections == 0 {
            return Err(ConfigError::InvalidValue(
                "max_connections must be greater than 0".into(),
            ));
        }

        if self.rate_limit_rps < 0.0 {
            return Err(ConfigError::InvalidValue(
                "rate_limit_rps must be non-negative".into(),
            ));
        }

        Ok(())
    }
}

impl Default for NetworkSettings {
    #[inline]
    fn default() -> Self {
        Self::new(100 * 1024 * 1024 / 8) // 100 Mbps
    }
}

/// Coordinator configuration settings.
#[derive(Debug, Clone)]
pub struct CoordinatorSettings {
    /// Coordinator base URL.
    pub url: String,
    /// API key for authentication.
    pub api_key: Option<String>,
    /// Proof submission interval in seconds.
    pub proof_submit_interval_secs: u64,
    /// Batch size for proof submissions.
    pub proof_batch_size: usize,
    /// Enable automatic proof submission.
    pub auto_submit: bool,
}

impl CoordinatorSettings {
    /// Create coordinator settings with specified URL.
    #[inline]
    #[must_use]
    pub fn new(url: String) -> Self {
        Self {
            url,
            api_key: None,
            proof_submit_interval_secs: 60,
            proof_batch_size: 10,
            auto_submit: true,
        }
    }

    /// Validate coordinator settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.url.is_empty() {
            return Err(ConfigError::InvalidValue(
                "Coordinator URL cannot be empty".into(),
            ));
        }

        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConfigError::InvalidValue(
                "Coordinator URL must start with http:// or https://".into(),
            ));
        }

        if self.proof_batch_size == 0 {
            return Err(ConfigError::InvalidValue(
                "proof_batch_size must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

impl Default for CoordinatorSettings {
    #[inline]
    fn default() -> Self {
        Self::new("https://coordinator.chie.network".to_string())
    }
}

/// Performance tuning settings.
#[derive(Debug, Clone)]
pub struct PerformanceSettings {
    /// Enable chunk prefetching.
    pub enable_prefetch: bool,
    /// Prefetch cache size (number of chunks).
    pub prefetch_cache_size: usize,
    /// Enable content compression.
    pub enable_compression: bool,
    /// Enable content deduplication.
    pub enable_deduplication: bool,
    /// Garbage collection interval in seconds.
    pub gc_interval_secs: u64,
    /// Enable performance profiling.
    pub enable_profiling: bool,
}

impl PerformanceSettings {
    /// Validate performance settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.prefetch_cache_size == 0 {
            return Err(ConfigError::InvalidValue(
                "prefetch_cache_size must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

impl Default for PerformanceSettings {
    #[inline]
    fn default() -> Self {
        Self {
            enable_prefetch: true,
            prefetch_cache_size: 100,
            enable_compression: true,
            enable_deduplication: true,
            gc_interval_secs: 3600, // 1 hour
            enable_profiling: false,
        }
    }
}

/// Complete node settings.
#[derive(Debug, Clone, Default)]
pub struct NodeSettings {
    /// Storage configuration.
    pub storage: StorageSettings,
    /// Network configuration.
    pub network: NetworkSettings,
    /// Coordinator configuration.
    pub coordinator: CoordinatorSettings,
    /// Performance configuration.
    pub performance: PerformanceSettings,
}

impl NodeSettings {
    /// Create a builder for node settings.
    #[inline]
    #[must_use]
    pub fn builder() -> NodeSettingsBuilder {
        NodeSettingsBuilder::default()
    }

    /// Validate all settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.storage.validate()?;
        self.network.validate()?;
        self.coordinator.validate()?;
        self.performance.validate()?;
        Ok(())
    }

    /// Load settings from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut settings = Self::default();

        // Storage
        if let Ok(path) = std::env::var("CHIE_STORAGE_PATH") {
            settings.storage.base_path = PathBuf::from(path);
        }
        if let Ok(max_bytes) = std::env::var("CHIE_STORAGE_MAX_BYTES") {
            settings.storage.max_bytes = max_bytes
                .parse()
                .map_err(|_| ConfigError::InvalidValue("Invalid CHIE_STORAGE_MAX_BYTES".into()))?;
        }

        // Network
        if let Ok(bandwidth) = std::env::var("CHIE_MAX_BANDWIDTH_BPS") {
            settings.network.max_bandwidth_bps = bandwidth
                .parse()
                .map_err(|_| ConfigError::InvalidValue("Invalid CHIE_MAX_BANDWIDTH_BPS".into()))?;
        }

        // Coordinator
        if let Ok(url) = std::env::var("CHIE_COORDINATOR_URL") {
            settings.coordinator.url = url;
        }
        if let Ok(api_key) = std::env::var("CHIE_API_KEY") {
            settings.coordinator.api_key = Some(api_key);
        }

        settings.validate()?;
        Ok(settings)
    }
}

/// Builder for node settings.
#[derive(Debug, Default)]
pub struct NodeSettingsBuilder {
    storage: Option<StorageSettings>,
    network: Option<NetworkSettings>,
    coordinator: Option<CoordinatorSettings>,
    performance: Option<PerformanceSettings>,
}

impl NodeSettingsBuilder {
    /// Set storage settings.
    #[inline]
    #[must_use]
    pub fn storage(mut self, storage: StorageSettings) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set network settings.
    #[inline]
    #[must_use]
    pub fn network(mut self, network: NetworkSettings) -> Self {
        self.network = Some(network);
        self
    }

    /// Set coordinator settings.
    #[inline]
    #[must_use]
    pub fn coordinator(mut self, coordinator: CoordinatorSettings) -> Self {
        self.coordinator = Some(coordinator);
        self
    }

    /// Set performance settings.
    #[inline]
    #[must_use]
    pub fn performance(mut self, performance: PerformanceSettings) -> Self {
        self.performance = Some(performance);
        self
    }

    /// Build the node settings.
    pub fn build(self) -> Result<NodeSettings, ConfigError> {
        let settings = NodeSettings {
            storage: self.storage.unwrap_or_default(),
            network: self.network.unwrap_or_default(),
            coordinator: self.coordinator.unwrap_or_default(),
            performance: self.performance.unwrap_or_default(),
        };

        settings.validate()?;
        Ok(settings)
    }
}

/// Configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid configuration value.
    InvalidValue(String),
    /// Missing required field.
    MissingField(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValue(msg) => write!(f, "Invalid configuration value: {}", msg),
            Self::MissingField(field) => write!(f, "Missing required field: {}", field),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_settings_default() {
        let settings = StorageSettings::default();
        assert_eq!(settings.max_bytes, 50 * 1024 * 1024 * 1024);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_storage_settings_validation() {
        let settings = StorageSettings {
            max_bytes: 0,
            ..Default::default()
        };
        assert!(settings.validate().is_err());

        let settings = StorageSettings {
            min_free_bytes: 50 * 1024 * 1024 * 1024 + 1,
            ..Default::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_network_settings_default() {
        let settings = NetworkSettings::default();
        assert_eq!(settings.max_connections, 100);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_network_settings_mbps() {
        let settings = NetworkSettings::new(100 * 1024 * 1024 / 8);
        assert_eq!(settings.max_bandwidth_mbps(), 100.0);
    }

    #[test]
    fn test_coordinator_settings_validation() {
        let settings = CoordinatorSettings {
            url: String::new(),
            ..Default::default()
        };
        assert!(settings.validate().is_err());

        let settings = CoordinatorSettings {
            url: "invalid-url".to_string(),
            ..Default::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn test_node_settings_builder() {
        let settings = NodeSettings::builder()
            .storage(StorageSettings::default())
            .network(NetworkSettings::default())
            .build();

        assert!(settings.is_ok());
    }

    #[test]
    fn test_node_settings_default() {
        let settings = NodeSettings::default();
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_performance_settings_default() {
        let settings = PerformanceSettings::default();
        assert!(settings.enable_prefetch);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::InvalidValue("test".to_string());
        assert_eq!(err.to_string(), "Invalid configuration value: test");

        let err = ConfigError::MissingField("field1".to_string());
        assert_eq!(err.to_string(), "Missing required field: field1");
    }

    #[test]
    fn test_storage_tiering_validation() {
        let settings = StorageSettings {
            enable_tiering: true,
            ..Default::default()
        };
        assert!(settings.validate().is_err());

        let mut settings = settings;
        settings.ssd_path = Some(PathBuf::from("/ssd"));
        settings.hdd_path = Some(PathBuf::from("/hdd"));
        assert!(settings.validate().is_ok());
    }
}
