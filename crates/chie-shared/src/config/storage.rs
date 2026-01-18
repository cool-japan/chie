//! Storage configuration

use serde::{Deserialize, Serialize};

/// Storage configuration
///
/// # Examples
///
/// Using the default configuration:
/// ```
/// use chie_shared::StorageConfig;
///
/// let config = StorageConfig::default();
/// assert_eq!(config.data_dir, "./chie_data");
/// assert_eq!(config.max_cache_size_bytes, 10 * 1024 * 1024 * 1024); // 10 GB
/// assert!(config.enable_persistence);
/// assert!(config.enable_compression);
/// assert!(config.validate().is_ok());
/// ```
///
/// Building a custom configuration:
/// ```
/// use chie_shared::StorageConfigBuilder;
///
/// let config = StorageConfigBuilder::new()
///     .data_dir("/var/lib/chie")
///     .max_cache_size_gb(50)
///     .enable_persistence(true)
///     .enable_compression(true)
///     .sync_interval_secs(600)  // 10 minutes
///     .gc_interval_secs(7200)   // 2 hours
///     .build();
///
/// assert_eq!(config.data_dir, "/var/lib/chie");
/// assert_eq!(config.max_cache_size_bytes, 50 * 1024 * 1024 * 1024);
/// assert_eq!(config.sync_interval_secs, 600);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to storage directory
    pub data_dir: String,
    /// Maximum cache size in bytes
    pub max_cache_size_bytes: u64,
    /// Enable disk persistence
    pub enable_persistence: bool,
    /// Sync interval in seconds (0 = no auto-sync)
    pub sync_interval_secs: u64,
    /// Enable compression
    pub enable_compression: bool,
    /// Garbage collection interval in seconds
    pub gc_interval_secs: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: "./chie_data".to_string(),
            max_cache_size_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            enable_persistence: true,
            sync_interval_secs: 300, // 5 minutes
            enable_compression: true,
            gc_interval_secs: 3600, // 1 hour
        }
    }
}

impl StorageConfig {
    /// Validate the storage configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> crate::ChieResult<()> {
        use crate::ChieError;

        if self.data_dir.is_empty() {
            return Err(ChieError::validation("data_dir must not be empty"));
        }

        if self.max_cache_size_bytes == 0 {
            return Err(ChieError::validation(
                "max_cache_size_bytes must be greater than 0",
            ));
        }

        Ok(())
    }
}

/// Builder for `StorageConfig`
///
/// # Examples
///
/// Building a high-capacity storage configuration:
/// ```
/// use chie_shared::StorageConfigBuilder;
///
/// let config = StorageConfigBuilder::new()
///     .data_dir("/mnt/storage/chie")
///     .max_cache_size_gb(100)
///     .enable_persistence(true)
///     .enable_compression(true)
///     .build();
///
/// assert_eq!(config.max_cache_size_bytes, 100 * 1024 * 1024 * 1024);
/// assert!(config.validate().is_ok());
/// ```
///
/// Building a memory-only configuration (no persistence):
/// ```
/// use chie_shared::StorageConfigBuilder;
///
/// let config = StorageConfigBuilder::new()
///     .data_dir("/tmp/chie")
///     .max_cache_size_gb(5)
///     .enable_persistence(false)
///     .sync_interval_secs(0)  // No auto-sync
///     .build();
///
/// assert!(!config.enable_persistence);
/// assert_eq!(config.sync_interval_secs, 0);
/// ```
#[derive(Debug, Default)]
pub struct StorageConfigBuilder {
    config: StorageConfig,
}

impl StorageConfigBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set data directory
    #[must_use]
    pub fn data_dir(mut self, dir: impl Into<String>) -> Self {
        self.config.data_dir = dir.into();
        self
    }

    /// Set maximum cache size in bytes
    #[must_use]
    pub const fn max_cache_size_bytes(mut self, size: u64) -> Self {
        self.config.max_cache_size_bytes = size;
        self
    }

    /// Set maximum cache size in GB
    #[must_use]
    pub const fn max_cache_size_gb(mut self, size: u64) -> Self {
        self.config.max_cache_size_bytes = size * 1024 * 1024 * 1024;
        self
    }

    /// Enable or disable persistence
    #[must_use]
    pub const fn enable_persistence(mut self, enable: bool) -> Self {
        self.config.enable_persistence = enable;
        self
    }

    /// Set sync interval in seconds
    #[must_use]
    pub const fn sync_interval_secs(mut self, interval: u64) -> Self {
        self.config.sync_interval_secs = interval;
        self
    }

    /// Enable or disable compression
    #[must_use]
    pub const fn enable_compression(mut self, enable: bool) -> Self {
        self.config.enable_compression = enable;
        self
    }

    /// Set garbage collection interval in seconds
    #[must_use]
    pub const fn gc_interval_secs(mut self, interval: u64) -> Self {
        self.config.gc_interval_secs = interval;
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> StorageConfig {
        self.config
    }
}
