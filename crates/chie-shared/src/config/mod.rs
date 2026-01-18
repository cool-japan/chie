//! Configuration types with builder patterns
//!
//! This module provides configuration structs for various CHIE protocol components
//! with ergonomic builder patterns for construction.

mod diff;
mod feature_flags;
mod merge;
mod network;
mod rate_limit;
mod retry;
mod storage;
mod timeout;

pub use diff::{ConfigChange, ConfigDiff};
pub use feature_flags::{FeatureFlags, FeatureFlagsBuilder};
pub use merge::ConfigMerge;
pub use network::{NetworkConfig, NetworkConfigBuilder};
pub use rate_limit::{RateLimitConfig, RateLimitConfigBuilder};
pub use retry::{RetryConfig, RetryConfigBuilder};
pub use storage::{StorageConfig, StorageConfigBuilder};
pub use timeout::{TimeoutConfig, TimeoutConfigBuilder};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.connection_timeout_ms, 10_000);
        assert!(config.enable_relay);
        assert!(config.enable_dht);
    }

    #[test]
    fn test_network_config_builder() {
        let config = NetworkConfigBuilder::new()
            .max_connections(50)
            .connection_timeout_ms(5000)
            .enable_relay(false)
            .add_bootstrap_peer("/ip4/127.0.0.1/tcp/4001")
            .build();

        assert_eq!(config.max_connections, 50);
        assert_eq!(config.connection_timeout_ms, 5000);
        assert!(!config.enable_relay);
        assert_eq!(config.bootstrap_peers.len(), 1);
    }

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.data_dir, "./chie_data");
        assert_eq!(config.max_cache_size_bytes, 10 * 1024 * 1024 * 1024);
        assert!(config.enable_persistence);
        assert!(config.enable_compression);
    }

    #[test]
    fn test_storage_config_builder() {
        let config = StorageConfigBuilder::new()
            .data_dir("/var/lib/chie")
            .max_cache_size_gb(20)
            .enable_compression(false)
            .sync_interval_secs(600)
            .build();

        assert_eq!(config.data_dir, "/var/lib/chie");
        assert_eq!(config.max_cache_size_bytes, 20 * 1024 * 1024 * 1024);
        assert!(!config.enable_compression);
        assert_eq!(config.sync_interval_secs, 600);
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.burst_size, 20);
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_config_builder() {
        let config = RateLimitConfigBuilder::new()
            .max_requests(200)
            .window_secs(120)
            .burst_size(50)
            .enabled(false)
            .build();

        assert_eq!(config.max_requests, 200);
        assert_eq!(config.window_secs, 120);
        assert_eq!(config.burst_size, 50);
        assert!(!config.enabled);
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 30_000);
        assert_eq!(config.multiplier, 2.0);
        assert!(config.enable_jitter);
    }

    #[test]
    fn test_retry_config_builder() {
        let config = RetryConfigBuilder::new()
            .max_attempts(5)
            .initial_backoff_ms(200)
            .max_backoff_ms(60_000)
            .multiplier(3.0)
            .enable_jitter(false)
            .build();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_backoff_ms, 200);
        assert_eq!(config.max_backoff_ms, 60_000);
        assert_eq!(config.multiplier, 3.0);
        assert!(!config.enable_jitter);
    }

    #[test]
    fn test_network_config_serde() {
        let config = NetworkConfigBuilder::new().max_connections(75).build();

        let json = serde_json::to_string(&config).unwrap();
        let decoded: NetworkConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.max_connections, 75);
    }

    #[test]
    fn test_storage_config_serde() {
        let config = StorageConfigBuilder::new().data_dir("/custom/path").build();

        let json = serde_json::to_string(&config).unwrap();
        let decoded: StorageConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.data_dir, "/custom/path");
    }

    #[test]
    fn test_builder_chaining() {
        let config = NetworkConfigBuilder::new()
            .max_connections(100)
            .connection_timeout_ms(10_000)
            .request_timeout_ms(30_000)
            .enable_relay(true)
            .enable_dht(true)
            .add_bootstrap_peer("/ip4/1.2.3.4/tcp/4001")
            .add_bootstrap_peer("/ip4/5.6.7.8/tcp/4001")
            .add_listen_addr("/ip4/0.0.0.0/tcp/0")
            .build();

        assert_eq!(config.bootstrap_peers.len(), 2);
        assert_eq!(config.listen_addrs.len(), 2); // 1 default + 1 added
    }

    #[test]
    fn test_retry_config_is_exhausted() {
        let config = RetryConfig::default();
        assert!(!config.is_exhausted(0));
        assert!(!config.is_exhausted(1));
        assert!(!config.is_exhausted(2));
        assert!(config.is_exhausted(3));
        assert!(config.is_exhausted(4));
    }

    #[test]
    fn test_retry_config_next_backoff() {
        let config = RetryConfigBuilder::new()
            .initial_backoff_ms(100)
            .max_backoff_ms(10_000)
            .multiplier(2.0)
            .enable_jitter(false)
            .build();

        assert_eq!(config.next_backoff_ms(0), 100);
        assert_eq!(config.next_backoff_ms(1), 200);
        assert_eq!(config.next_backoff_ms(2), 400);
        assert_eq!(config.next_backoff_ms(3), 800);
        assert_eq!(config.next_backoff_ms(10), 10_000); // Capped at max
    }

    #[test]
    fn test_retry_config_next_backoff_with_jitter() {
        let config = RetryConfig::default();

        // With jitter, values should vary
        let delay1 = config.next_backoff_ms(0);
        let delay2 = config.next_backoff_ms(0);

        // Should be in expected range (100 ± 25%)
        assert!((75..=125).contains(&delay1));
        assert!((75..=125).contains(&delay2));
    }

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.default_timeout_ms, 30_000);
        assert_eq!(config.connection_timeout_ms, 10_000);
        assert_eq!(config.read_timeout_ms, 60_000);
        assert_eq!(config.write_timeout_ms, 60_000);
        assert_eq!(config.idle_timeout_ms, 300_000);
        assert_eq!(config.keepalive_interval_ms, 60_000);
        assert!(config.keepalive_enabled());
        assert!(config.idle_timeout_enabled());
    }

    #[test]
    fn test_timeout_config_fast() {
        let config = TimeoutConfig::fast();
        assert_eq!(config.default_timeout_ms, 5_000);
        assert_eq!(config.connection_timeout_ms, 3_000);
        assert!(config.keepalive_enabled());
    }

    #[test]
    fn test_timeout_config_slow() {
        let config = TimeoutConfig::slow();
        assert_eq!(config.default_timeout_ms, 120_000);
        assert_eq!(config.connection_timeout_ms, 30_000);
        assert!(config.keepalive_enabled());
    }

    #[test]
    fn test_timeout_config_builder() {
        let config = TimeoutConfigBuilder::new()
            .default_timeout_ms(15_000)
            .connection_timeout_ms(5_000)
            .read_timeout_ms(30_000)
            .write_timeout_ms(30_000)
            .idle_timeout_ms(0) // Disabled
            .keepalive_interval_ms(0) // Disabled
            .build();

        assert_eq!(config.default_timeout_ms, 15_000);
        assert_eq!(config.connection_timeout_ms, 5_000);
        assert!(!config.idle_timeout_enabled());
        assert!(!config.keepalive_enabled());
    }

    #[test]
    fn test_timeout_config_serde() {
        let config = TimeoutConfigBuilder::new()
            .default_timeout_ms(20_000)
            .build();

        let json = serde_json::to_string(&config).unwrap();
        let decoded: TimeoutConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.default_timeout_ms, 20_000);
    }

    // Validation tests
    #[test]
    fn test_network_config_validate_success() {
        let config = NetworkConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_network_config_validate_zero_max_connections() {
        let config = NetworkConfig {
            max_connections: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_config_validate_zero_connection_timeout() {
        let config = NetworkConfig {
            connection_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_config_validate_empty_listen_addrs() {
        let mut config = NetworkConfig::default();
        config.listen_addrs.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_storage_config_validate_success() {
        let config = StorageConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_storage_config_validate_empty_data_dir() {
        let config = StorageConfig {
            data_dir: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_storage_config_validate_zero_cache_size() {
        let config = StorageConfig {
            max_cache_size_bytes: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_validate_success() {
        let config = RateLimitConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_config_validate_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            max_requests: 0, // Should be ok when disabled
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_config_validate_zero_max_requests() {
        let config = RateLimitConfig {
            max_requests: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_validate_zero_window() {
        let config = RateLimitConfig {
            window_secs: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_validate_burst_exceeds_max() {
        let config = RateLimitConfig {
            max_requests: 100,
            burst_size: 101,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_config_validate_success() {
        let config = RetryConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_retry_config_validate_zero_max_attempts() {
        let config = RetryConfig {
            max_attempts: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_config_validate_zero_initial_backoff() {
        let config = RetryConfig {
            initial_backoff_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_config_validate_max_less_than_initial() {
        let config = RetryConfig {
            initial_backoff_ms: 1000,
            max_backoff_ms: 500,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_config_validate_zero_multiplier() {
        let config = RetryConfig {
            multiplier: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_retry_config_validate_negative_multiplier() {
        let config = RetryConfig {
            multiplier: -1.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_validate_success() {
        let config = TimeoutConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timeout_config_validate_zero_default_timeout() {
        let config = TimeoutConfig {
            default_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_validate_zero_connection_timeout() {
        let config = TimeoutConfig {
            connection_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_validate_zero_read_timeout() {
        let config = TimeoutConfig {
            read_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_validate_zero_write_timeout() {
        let config = TimeoutConfig {
            write_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timeout_config_validate_zero_idle_ok() {
        let config = TimeoutConfig {
            idle_timeout_ms: 0, // Should be ok (disabled)
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timeout_config_validate_zero_keepalive_ok() {
        let config = TimeoutConfig {
            keepalive_interval_ms: 0, // Should be ok (disabled)
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    // Feature flags tests
    #[test]
    fn test_feature_flags_default() {
        let flags = FeatureFlags::default();
        assert!(!flags.experimental);
        assert!(!flags.beta);
        assert!(!flags.enhanced_telemetry);
        assert!(!flags.performance_profiling);
        assert!(!flags.debug_mode);
        assert!(flags.compression_optimization);
        assert!(flags.adaptive_retry);
    }

    #[test]
    fn test_feature_flags_none() {
        let flags = FeatureFlags::none();
        assert!(!flags.experimental);
        assert!(!flags.beta);
        assert!(!flags.compression_optimization);
        assert!(!flags.adaptive_retry);
    }

    #[test]
    fn test_feature_flags_all() {
        let flags = FeatureFlags::all();
        assert!(flags.experimental);
        assert!(flags.beta);
        assert!(flags.enhanced_telemetry);
        assert!(flags.performance_profiling);
        assert!(flags.debug_mode);
        assert!(flags.compression_optimization);
        assert!(flags.adaptive_retry);
    }

    #[test]
    fn test_feature_flags_has_unstable_features() {
        let mut flags = FeatureFlags::default();
        assert!(!flags.has_unstable_features());

        flags.experimental = true;
        assert!(flags.has_unstable_features());

        flags.experimental = false;
        flags.beta = true;
        assert!(flags.has_unstable_features());
    }

    #[test]
    fn test_feature_flags_has_diagnostic_features() {
        let mut flags = FeatureFlags::default();
        assert!(!flags.has_diagnostic_features());

        flags.debug_mode = true;
        assert!(flags.has_diagnostic_features());

        flags.debug_mode = false;
        flags.performance_profiling = true;
        assert!(flags.has_diagnostic_features());

        flags.performance_profiling = false;
        flags.enhanced_telemetry = true;
        assert!(flags.has_diagnostic_features());
    }

    #[test]
    fn test_feature_flags_builder() {
        let flags = FeatureFlagsBuilder::new()
            .experimental(true)
            .beta(true)
            .debug_mode(true)
            .build();

        assert!(flags.experimental);
        assert!(flags.beta);
        assert!(flags.debug_mode);
        assert!(!flags.performance_profiling);
    }

    #[test]
    fn test_feature_flags_serde() {
        let flags = FeatureFlagsBuilder::new()
            .experimental(true)
            .compression_optimization(false)
            .build();

        let json = serde_json::to_string(&flags).unwrap();
        let decoded: FeatureFlags = serde_json::from_str(&json).unwrap();

        assert!(decoded.experimental);
        assert!(!decoded.compression_optimization);
    }

    // ConfigChange tests
    #[test]
    fn test_config_change_new() {
        let change = ConfigChange::new("max_connections", &100, &200);
        assert_eq!(change.field, "max_connections");
        assert_eq!(change.old_value, "100");
        assert_eq!(change.new_value, "200");
    }

    #[test]
    fn test_config_change_serde() {
        let change = ConfigChange::new("enable_relay", &true, &false);
        let json = serde_json::to_string(&change).unwrap();
        let decoded: ConfigChange = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.field, "enable_relay");
        assert_eq!(decoded.old_value, "true");
        assert_eq!(decoded.new_value, "false");
    }

    // ConfigDiff tests for NetworkConfig
    #[test]
    fn test_config_diff_network_no_changes() {
        let config1 = NetworkConfig::default();
        let config2 = NetworkConfig::default();

        let changes = ConfigDiff::network_config(&config1, &config2);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_config_diff_network_single_change() {
        let config1 = NetworkConfig::default();
        let config2 = NetworkConfig {
            max_connections: 200,
            ..Default::default()
        };

        let changes = ConfigDiff::network_config(&config1, &config2);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "max_connections");
        assert_eq!(changes[0].old_value, "100");
        assert_eq!(changes[0].new_value, "200");
    }

    #[test]
    fn test_config_diff_network_multiple_changes() {
        let config1 = NetworkConfig::default();
        let config2 = NetworkConfig {
            max_connections: 200,
            enable_relay: false,
            connection_timeout_ms: 20_000,
            ..Default::default()
        };

        let changes = ConfigDiff::network_config(&config1, &config2);
        assert_eq!(changes.len(), 3);

        let field_names: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(field_names.contains(&"max_connections"));
        assert!(field_names.contains(&"enable_relay"));
        assert!(field_names.contains(&"connection_timeout_ms"));
    }

    #[test]
    fn test_config_diff_network_vec_changes() {
        let config1 = NetworkConfig {
            bootstrap_peers: vec!["peer1".to_string()],
            ..Default::default()
        };

        let config2 = NetworkConfig {
            bootstrap_peers: vec!["peer1".to_string(), "peer2".to_string()],
            ..Default::default()
        };

        let changes = ConfigDiff::network_config(&config1, &config2);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "bootstrap_peers");
    }

    // ConfigDiff tests for RetryConfig
    #[test]
    fn test_config_diff_retry_no_changes() {
        let config1 = RetryConfig::default();
        let config2 = RetryConfig::default();

        let changes = ConfigDiff::retry_config(&config1, &config2);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_config_diff_retry_single_change() {
        let config1 = RetryConfig::default();
        let config2 = RetryConfig {
            max_attempts: 5,
            ..Default::default()
        };

        let changes = ConfigDiff::retry_config(&config1, &config2);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "max_attempts");
        assert_eq!(changes[0].old_value, "3");
        assert_eq!(changes[0].new_value, "5");
    }

    #[test]
    fn test_config_diff_retry_multiple_changes() {
        let config1 = RetryConfig::default();
        let config2 = RetryConfig {
            max_attempts: 5,
            multiplier: 3.0,
            enable_jitter: false,
            ..Default::default()
        };

        let changes = ConfigDiff::retry_config(&config1, &config2);
        assert_eq!(changes.len(), 3);

        let field_names: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(field_names.contains(&"max_attempts"));
        assert!(field_names.contains(&"multiplier"));
        assert!(field_names.contains(&"enable_jitter"));
    }

    // ConfigDiff tests for FeatureFlags
    #[test]
    fn test_config_diff_feature_flags_no_changes() {
        let flags1 = FeatureFlags::default();
        let flags2 = FeatureFlags::default();

        let changes = ConfigDiff::feature_flags(&flags1, &flags2);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_config_diff_feature_flags_single_change() {
        let flags1 = FeatureFlags::default();
        let flags2 = FeatureFlags {
            experimental: true,
            ..Default::default()
        };

        let changes = ConfigDiff::feature_flags(&flags1, &flags2);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "experimental");
        assert_eq!(changes[0].old_value, "false");
        assert_eq!(changes[0].new_value, "true");
    }

    #[test]
    fn test_config_diff_feature_flags_multiple_changes() {
        let flags1 = FeatureFlags::default();
        let flags2 = FeatureFlags {
            experimental: true,
            beta: true,
            debug_mode: true,
            ..Default::default()
        };

        let changes = ConfigDiff::feature_flags(&flags1, &flags2);
        assert_eq!(changes.len(), 3);

        let field_names: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert!(field_names.contains(&"experimental"));
        assert!(field_names.contains(&"beta"));
        assert!(field_names.contains(&"debug_mode"));
    }

    // ConfigMerge tests for RetryConfig
    #[test]
    fn test_config_merge_retry_complete_override() {
        let base = RetryConfig::default();
        let override_config = RetryConfig {
            max_attempts: 10,
            initial_backoff_ms: 500,
            max_backoff_ms: 60_000,
            multiplier: 3.0,
            enable_jitter: false,
        };

        let merged = ConfigMerge::retry_config(&base, &override_config);

        assert_eq!(merged.max_attempts, 10);
        assert_eq!(merged.initial_backoff_ms, 500);
        assert_eq!(merged.max_backoff_ms, 60_000);
        assert!((merged.multiplier - 3.0).abs() < f64::EPSILON);
        assert!(!merged.enable_jitter);
    }

    #[test]
    fn test_config_merge_retry_partial_override() {
        let base = RetryConfig {
            max_attempts: 5,
            initial_backoff_ms: 200,
            max_backoff_ms: 40_000,
            multiplier: 2.5,
            enable_jitter: true,
        };

        let override_config = RetryConfig {
            max_attempts: 10,
            ..RetryConfig::default()
        };

        let merged = ConfigMerge::retry_config(&base, &override_config);

        // Override takes precedence for all fields
        assert_eq!(merged.max_attempts, 10);
        assert_eq!(
            merged.initial_backoff_ms,
            RetryConfig::default().initial_backoff_ms
        );
    }

    // ConfigMerge tests for FeatureFlags
    #[test]
    fn test_config_merge_feature_flags_override_all() {
        let base = FeatureFlags::all();
        let override_flags = FeatureFlags::none();

        let merged = ConfigMerge::feature_flags(&base, &override_flags, true);

        // Complete override - all should be false
        assert!(!merged.experimental);
        assert!(!merged.beta);
        assert!(!merged.enhanced_telemetry);
        assert!(!merged.compression_optimization);
    }

    #[test]
    fn test_config_merge_feature_flags_or_merge() {
        let base = FeatureFlags {
            experimental: true,
            beta: false,
            enhanced_telemetry: false,
            performance_profiling: false,
            debug_mode: false,
            compression_optimization: true,
            adaptive_retry: false,
        };

        let override_flags = FeatureFlags {
            experimental: false,
            beta: true,
            enhanced_telemetry: false,
            performance_profiling: true,
            debug_mode: false,
            compression_optimization: false,
            adaptive_retry: true,
        };

        let merged = ConfigMerge::feature_flags(&base, &override_flags, false);

        // OR merge - feature enabled if enabled in either
        assert!(merged.experimental); // base=true, override=false -> true
        assert!(merged.beta); // base=false, override=true -> true
        assert!(!merged.enhanced_telemetry); // base=false, override=false -> false
        assert!(merged.performance_profiling); // base=false, override=true -> true
        assert!(!merged.debug_mode); // base=false, override=false -> false
        assert!(merged.compression_optimization); // base=true, override=false -> true
        assert!(merged.adaptive_retry); // base=false, override=true -> true
    }

    #[test]
    fn test_config_merge_feature_flags_both_enabled() {
        let base = FeatureFlags::all();
        let override_flags = FeatureFlags {
            experimental: true,
            beta: true,
            ..FeatureFlags::none()
        };

        let merged = ConfigMerge::feature_flags(&base, &override_flags, false);

        // OR merge - all should be enabled since base has all
        assert!(merged.experimental);
        assert!(merged.beta);
        assert!(merged.enhanced_telemetry);
        assert!(merged.performance_profiling);
        assert!(merged.debug_mode);
        assert!(merged.compression_optimization);
        assert!(merged.adaptive_retry);
    }
}
