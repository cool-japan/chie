//! Configuration management for CHIE Coordinator.
//!
//! Supports loading from:
//! - config.toml file
//! - Environment variables (overrides file config)
//! - Default values

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Complete coordinator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration.
    pub server: ServerConfig,
    /// Database configuration.
    pub database: DatabaseConfig,
    /// Redis configuration.
    pub redis: RedisConfig,
    /// JWT authentication configuration.
    pub jwt: JwtConfig,
    /// Verification service configuration.
    pub verification: VerificationConfig,
    /// Reward engine configuration.
    pub rewards: RewardConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
    /// CORS configuration.
    pub cors: CorsConfig,
    /// Data retention configuration.
    pub retention: RetentionPolicyConfig,
    /// Data archiving configuration.
    pub archiving: ArchivingPolicyConfig,
}

/// Server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host address (default: 0.0.0.0).
    #[serde(default = "default_host")]
    pub host: String,
    /// Server port (default: 3000).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Number of worker threads (default: num_cpus).
    #[serde(default)]
    pub workers: Option<usize>,
    /// Request timeout in seconds (default: 30).
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Enable graceful shutdown (default: true).
    #[serde(default = "default_true")]
    pub graceful_shutdown: bool,
    /// Shutdown timeout in seconds (default: 30).
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

/// Database settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL (postgres://...).
    #[serde(default = "default_database_url")]
    pub url: String,
    /// Maximum number of connections (default: 10).
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,
    /// Minimum number of connections (default: 1).
    #[serde(default = "default_db_min_connections")]
    pub min_connections: u32,
    /// Connection timeout in seconds (default: 30).
    #[serde(default = "default_db_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Idle timeout in seconds (default: 600).
    #[serde(default = "default_db_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Enable query logging (default: false).
    #[serde(default)]
    pub log_queries: bool,
    /// Slow query threshold in milliseconds (default: 1000).
    #[serde(default = "default_slow_query_threshold")]
    pub slow_query_threshold_ms: u64,
}

/// Redis settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis URL (redis://...).
    #[serde(default = "default_redis_url")]
    pub url: String,
    /// Connection pool size (default: 10).
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: u32,
    /// Connection timeout in seconds (default: 5).
    #[serde(default = "default_redis_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Enable Redis (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// JWT authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret key.
    #[serde(default = "default_jwt_secret")]
    pub secret: String,
    /// Token expiration in hours (default: 24).
    #[serde(default = "default_jwt_expiration")]
    pub expiration_hours: u64,
    /// Issuer name (default: chie-coordinator).
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,
    /// Audience (default: chie-users).
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
}

/// Proof verification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Maximum allowed clock drift in seconds (default: 300).
    #[serde(default = "default_max_clock_drift")]
    pub max_clock_drift_secs: u64,
    /// Minimum latency threshold in milliseconds (default: 1).
    #[serde(default = "default_min_latency")]
    pub min_latency_ms: u32,
    /// Maximum latency threshold in milliseconds (default: 10000).
    #[serde(default = "default_max_latency")]
    pub max_latency_ms: u32,
    /// Enable nonce replay protection (default: true).
    #[serde(default = "default_true")]
    pub check_nonce_replay: bool,
    /// Enable signature verification (default: true).
    #[serde(default = "default_true")]
    pub verify_signatures: bool,
}

/// Reward calculation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Base points per GB transferred (default: 10).
    #[serde(default = "default_base_points_per_gb")]
    pub base_points_per_gb: u64,
    /// Maximum reward multiplier (default: 3.0).
    #[serde(default = "default_max_multiplier")]
    pub max_multiplier: f64,
    /// Latency penalty threshold in milliseconds (default: 500).
    #[serde(default = "default_latency_penalty_threshold")]
    pub latency_penalty_threshold_ms: u32,
    /// Latency penalty factor (default: 0.5).
    #[serde(default = "default_latency_penalty_factor")]
    pub latency_penalty_factor: f64,
}

/// Rate limiting settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Requests per minute per IP (default: 60).
    #[serde(default = "default_rate_limit_per_ip")]
    pub requests_per_minute_per_ip: u32,
    /// Requests per minute per user (default: 120).
    #[serde(default = "default_rate_limit_per_user")]
    pub requests_per_minute_per_user: u32,
    /// Requests per minute per node (default: 600).
    #[serde(default = "default_rate_limit_per_node")]
    pub requests_per_minute_per_node: u32,
}

/// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Enable JSON logging (default: false).
    #[serde(default)]
    pub json: bool,
    /// Enable correlation IDs (default: true).
    #[serde(default = "default_true")]
    pub correlation_ids: bool,
    /// Log directory (optional).
    #[serde(default)]
    pub directory: Option<String>,
}

/// CORS settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins (default: ["*"]).
    #[serde(default = "default_cors_origins")]
    pub allowed_origins: Vec<String>,
    /// Enable credentials (default: true).
    #[serde(default = "default_true")]
    pub allow_credentials: bool,
    /// Max age in seconds (default: 3600).
    #[serde(default = "default_cors_max_age")]
    pub max_age_secs: u64,
}

/// Data retention policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicyConfig {
    /// How long to keep transactions in days (default: 90).
    #[serde(default = "default_transaction_retention_days")]
    pub transaction_retention_days: i64,
    /// How long to keep bandwidth proofs in days (default: 30).
    #[serde(default = "default_proof_retention_days")]
    pub proof_retention_days: i64,
    /// How long to keep activity logs in days (default: 180).
    #[serde(default = "default_activity_log_retention_days")]
    pub activity_log_retention_days: i64,
    /// How long to keep metrics in days (default: 365).
    #[serde(default = "default_metrics_retention_days")]
    pub metrics_retention_days: i64,
    /// Cleanup interval in hours (default: 24).
    #[serde(default = "default_cleanup_interval_hours")]
    pub cleanup_interval_hours: u64,
    /// Enable automatic cleanup (default: true).
    #[serde(default = "default_true")]
    pub auto_cleanup_enabled: bool,
    /// Batch size for deletion operations (default: 1000).
    #[serde(default = "default_deletion_batch_size")]
    pub deletion_batch_size: i64,
}

/// Data archiving policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivingPolicyConfig {
    /// Archive data older than this many days (default: 30).
    #[serde(default = "default_archive_age_days")]
    pub archive_age_days: i64,
    /// Archive interval in hours (default: 24).
    #[serde(default = "default_archive_interval_hours")]
    pub archive_interval_hours: u64,
    /// Enable automatic archiving (default: true).
    #[serde(default = "default_true")]
    pub auto_archive_enabled: bool,
    /// Batch size for archiving operations (default: 1000).
    #[serde(default = "default_archive_batch_size")]
    pub archive_batch_size: i64,
    /// Enable compression for archived data (default: true).
    #[serde(default = "default_true")]
    pub compression_enabled: bool,
}

// ============================================================================
// Default value functions
// ============================================================================

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_request_timeout() -> u64 {
    30
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_database_url() -> String {
    "postgres://postgres:postgres@localhost/chie".to_string()
}

fn default_db_max_connections() -> u32 {
    10
}

fn default_db_min_connections() -> u32 {
    1
}

fn default_db_connect_timeout() -> u64 {
    30
}

fn default_db_idle_timeout() -> u64 {
    600
}

fn default_slow_query_threshold() -> u64 {
    1000
}

fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}

fn default_redis_pool_size() -> u32 {
    10
}

fn default_redis_connect_timeout() -> u64 {
    5
}

fn default_jwt_secret() -> String {
    "change-this-secret-in-production".to_string()
}

fn default_jwt_expiration() -> u64 {
    24
}

fn default_jwt_issuer() -> String {
    "chie-coordinator".to_string()
}

fn default_jwt_audience() -> String {
    "chie-users".to_string()
}

fn default_max_clock_drift() -> u64 {
    300
}

fn default_min_latency() -> u32 {
    1
}

fn default_max_latency() -> u32 {
    10000
}

fn default_base_points_per_gb() -> u64 {
    10
}

fn default_max_multiplier() -> f64 {
    3.0
}

fn default_latency_penalty_threshold() -> u32 {
    500
}

fn default_latency_penalty_factor() -> f64 {
    0.5
}

fn default_rate_limit_per_ip() -> u32 {
    60
}

fn default_rate_limit_per_user() -> u32 {
    120
}

fn default_rate_limit_per_node() -> u32 {
    600
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_cors_max_age() -> u64 {
    3600
}

fn default_transaction_retention_days() -> i64 {
    90
}

fn default_proof_retention_days() -> i64 {
    30
}

fn default_activity_log_retention_days() -> i64 {
    180
}

fn default_metrics_retention_days() -> i64 {
    365
}

fn default_cleanup_interval_hours() -> u64 {
    24
}

fn default_deletion_batch_size() -> i64 {
    1000
}

fn default_archive_age_days() -> i64 {
    30
}

fn default_archive_interval_hours() -> u64 {
    24
}

fn default_archive_batch_size() -> i64 {
    1000
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Implementation
// ============================================================================

#[allow(clippy::derivable_impls)]
impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            jwt: JwtConfig::default(),
            verification: VerificationConfig::default(),
            rewards: RewardConfig::default(),
            rate_limit: RateLimitConfig::default(),
            logging: LoggingConfig::default(),
            cors: CorsConfig::default(),
            retention: RetentionPolicyConfig::default(),
            archiving: ArchivingPolicyConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            workers: None,
            request_timeout_secs: default_request_timeout(),
            graceful_shutdown: true,
            shutdown_timeout_secs: default_shutdown_timeout(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: default_db_max_connections(),
            min_connections: default_db_min_connections(),
            connect_timeout_secs: default_db_connect_timeout(),
            idle_timeout_secs: default_db_idle_timeout(),
            log_queries: false,
            slow_query_threshold_ms: default_slow_query_threshold(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
            pool_size: default_redis_pool_size(),
            connect_timeout_secs: default_redis_connect_timeout(),
            enabled: true,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: default_jwt_secret(),
            expiration_hours: default_jwt_expiration(),
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
        }
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            max_clock_drift_secs: default_max_clock_drift(),
            min_latency_ms: default_min_latency(),
            max_latency_ms: default_max_latency(),
            check_nonce_replay: true,
            verify_signatures: true,
        }
    }
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            base_points_per_gb: default_base_points_per_gb(),
            max_multiplier: default_max_multiplier(),
            latency_penalty_threshold_ms: default_latency_penalty_threshold(),
            latency_penalty_factor: default_latency_penalty_factor(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute_per_ip: default_rate_limit_per_ip(),
            requests_per_minute_per_user: default_rate_limit_per_user(),
            requests_per_minute_per_node: default_rate_limit_per_node(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: false,
            correlation_ids: true,
            directory: None,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_cors_origins(),
            allow_credentials: true,
            max_age_secs: default_cors_max_age(),
        }
    }
}

impl Default for RetentionPolicyConfig {
    fn default() -> Self {
        Self {
            transaction_retention_days: default_transaction_retention_days(),
            proof_retention_days: default_proof_retention_days(),
            activity_log_retention_days: default_activity_log_retention_days(),
            metrics_retention_days: default_metrics_retention_days(),
            cleanup_interval_hours: default_cleanup_interval_hours(),
            auto_cleanup_enabled: true,
            deletion_batch_size: default_deletion_batch_size(),
        }
    }
}

impl Default for ArchivingPolicyConfig {
    fn default() -> Self {
        Self {
            archive_age_days: default_archive_age_days(),
            archive_interval_hours: default_archive_interval_hours(),
            auto_archive_enabled: true,
            archive_batch_size: default_archive_batch_size(),
            compression_enabled: true,
        }
    }
}

impl Config {
    /// Load configuration from TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Load configuration from file with environment variable overrides.
    pub fn load() -> anyhow::Result<Self> {
        // Start with defaults
        let mut config = Config::default();

        // Try to load from config.toml if it exists
        if std::path::Path::new("config.toml").exists() {
            config = Config::from_file("config.toml")?;
            tracing::info!("Loaded configuration from config.toml");
        } else {
            tracing::info!("Using default configuration (config.toml not found)");
        }

        // Override with environment variables
        config.apply_env_overrides();

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Apply environment variable overrides.
    fn apply_env_overrides(&mut self) {
        // Server
        if let Ok(host) = std::env::var("HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("PORT") {
            if let Ok(port) = port.parse() {
                self.server.port = port;
            }
        }

        // Database
        if let Ok(url) = std::env::var("DATABASE_URL") {
            self.database.url = url;
        }

        // Redis
        if let Ok(url) = std::env::var("REDIS_URL") {
            self.redis.url = url;
        }

        // JWT
        if let Ok(secret) = std::env::var("JWT_SECRET") {
            self.jwt.secret = secret;
        }

        // Logging
        if let Ok(level) = std::env::var("RUST_LOG") {
            self.logging.level = level;
        }
    }

    /// Validate configuration values.
    fn validate(&self) -> anyhow::Result<()> {
        // Validate port
        if self.server.port == 0 {
            anyhow::bail!("Invalid server port: 0");
        }

        // Validate database connections
        if self.database.max_connections == 0 {
            anyhow::bail!("Database max_connections must be > 0");
        }
        if self.database.min_connections > self.database.max_connections {
            anyhow::bail!(
                "Database min_connections ({}) > max_connections ({})",
                self.database.min_connections,
                self.database.max_connections
            );
        }

        // Validate JWT secret in production
        if self.jwt.secret == "change-this-secret-in-production" {
            tracing::warn!("⚠️  Using default JWT secret - CHANGE THIS IN PRODUCTION!");
        }

        // Validate reward config
        if self.rewards.max_multiplier < 1.0 {
            anyhow::bail!("Reward max_multiplier must be >= 1.0");
        }

        Ok(())
    }

    /// Get server bind address.
    #[allow(dead_code)]
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.max_connections, 10);
        assert!(!config.jwt.secret.is_empty());
    }

    #[test]
    fn test_bind_address() {
        let config = Config::default();
        assert_eq!(config.bind_address(), "0.0.0.0:3000");
    }

    #[test]
    fn test_validation_invalid_port() {
        let mut config = Config::default();
        config.server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_connections() {
        let mut config = Config::default();
        config.database.min_connections = 20;
        config.database.max_connections = 10;
        assert!(config.validate().is_err());
    }
}
