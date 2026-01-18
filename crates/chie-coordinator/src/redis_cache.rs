//! Redis-based distributed caching for coordinator scalability.
//!
//! This module provides a Redis-backed caching layer that can be shared
//! across multiple coordinator instances for horizontal scalability.

use redis::{AsyncCommands, Client, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Errors that can occur during Redis cache operations.
#[derive(Debug, Error)]
pub enum RedisCacheError {
    /// Redis connection error.
    #[error("Redis connection error: {0}")]
    Connection(#[from] redis::RedisError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Cache unavailable (fallback mode).
    #[error("Cache unavailable")]
    Unavailable,
}

/// Configuration for Redis cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCacheConfig {
    /// Redis connection URL (e.g., "redis://localhost:6379").
    pub redis_url: String,

    /// Default TTL for cache entries (in seconds).
    pub default_ttl_secs: u64,

    /// Key prefix for namespacing.
    pub key_prefix: String,

    /// Connection timeout in milliseconds.
    pub connection_timeout_ms: u64,

    /// Enable cache statistics tracking.
    pub enable_stats: bool,

    /// Maximum number of connection retries.
    pub max_retries: u32,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://localhost:6379".to_string(),
            default_ttl_secs: 300, // 5 minutes
            key_prefix: "chie:cache:".to_string(),
            connection_timeout_ms: 5000,
            enable_stats: true,
            max_retries: 3,
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache hits.
    pub hits: u64,

    /// Total cache misses.
    pub misses: u64,

    /// Total cache sets.
    pub sets: u64,

    /// Total cache deletes.
    pub deletes: u64,

    /// Total errors.
    pub errors: u64,
}

impl CacheStats {
    /// Calculate hit rate (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Redis-based distributed cache.
#[derive(Clone)]
pub struct RedisCache {
    /// Redis client.
    client: Client,

    /// Redis connection pool (multiplexed).
    connection: Arc<RwLock<Option<MultiplexedConnection>>>,

    /// Configuration.
    config: RedisCacheConfig,

    /// Cache statistics.
    stats: Arc<RwLock<CacheStats>>,
}

impl RedisCache {
    /// Create a new Redis cache.
    pub fn new(config: RedisCacheConfig) -> Result<Self, RedisCacheError> {
        let client = Client::open(config.redis_url.as_str())?;

        Ok(Self {
            client,
            connection: Arc::new(RwLock::new(None)),
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        })
    }

    /// Connect to Redis server.
    pub async fn connect(&self) -> Result<(), RedisCacheError> {
        let mut retries = 0;
        loop {
            match self.client.get_multiplexed_tokio_connection().await {
                Ok(conn) => {
                    *self.connection.write().await = Some(conn);
                    info!("Redis cache connected successfully");
                    return Ok(());
                }
                Err(e) => {
                    retries += 1;
                    if retries >= self.config.max_retries {
                        error!(
                            "Failed to connect to Redis after {} retries: {}",
                            retries, e
                        );
                        return Err(RedisCacheError::Connection(e));
                    }
                    warn!("Redis connection attempt {} failed, retrying...", retries);
                    tokio::time::sleep(Duration::from_millis(100 * retries as u64)).await;
                }
            }
        }
    }

    /// Check if cache is connected.
    pub async fn is_connected(&self) -> bool {
        self.connection.read().await.is_some()
    }

    /// Build full cache key with prefix.
    fn build_key(&self, key: &str) -> String {
        format!("{}{}", self.config.key_prefix, key)
    }

    /// Get a value from cache.
    pub async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.get::<_, Option<String>>(&full_key).await {
            Ok(Some(data)) => match serde_json::from_str::<T>(&data) {
                Ok(value) => {
                    if self.config.enable_stats {
                        self.stats.write().await.hits += 1;
                    }
                    Ok(Some(value))
                }
                Err(e) => {
                    error!("Failed to deserialize cache value for key {}: {}", key, e);
                    if self.config.enable_stats {
                        self.stats.write().await.errors += 1;
                    }
                    Err(RedisCacheError::Serialization(e))
                }
            },
            Ok(None) => {
                if self.config.enable_stats {
                    self.stats.write().await.misses += 1;
                }
                Ok(None)
            }
            Err(e) => {
                error!("Redis GET error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Set a value in cache with default TTL.
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<(), RedisCacheError> {
        self.set_with_ttl(key, value, self.config.default_ttl_secs)
            .await
    }

    /// Set a value in cache with custom TTL (in seconds).
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_secs: u64,
    ) -> Result<(), RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);
        let serialized = serde_json::to_string(value)?;

        match conn
            .set_ex::<_, _, ()>(&full_key, serialized, ttl_secs)
            .await
        {
            Ok(_) => {
                if self.config.enable_stats {
                    self.stats.write().await.sets += 1;
                }
                Ok(())
            }
            Err(e) => {
                error!("Redis SET error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Delete a value from cache.
    pub async fn delete(&self, key: &str) -> Result<(), RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.del::<_, ()>(&full_key).await {
            Ok(_) => {
                if self.config.enable_stats {
                    self.stats.write().await.deletes += 1;
                }
                Ok(())
            }
            Err(e) => {
                error!("Redis DEL error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Check if a key exists in cache.
    pub async fn exists(&self, key: &str) -> Result<bool, RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.exists::<_, bool>(&full_key).await {
            Ok(exists) => Ok(exists),
            Err(e) => {
                error!("Redis EXISTS error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Set expiration time for a key (in seconds).
    pub async fn expire(&self, key: &str, ttl_secs: u64) -> Result<(), RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.expire::<_, ()>(&full_key, ttl_secs as i64).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Redis EXPIRE error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Get remaining TTL for a key (in seconds).
    pub async fn ttl(&self, key: &str) -> Result<Option<i64>, RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.ttl::<_, i64>(&full_key).await {
            Ok(ttl) if ttl >= 0 => Ok(Some(ttl)),
            Ok(_) => Ok(None), // Key doesn't exist or no expiration
            Err(e) => {
                error!("Redis TTL error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Increment a counter in cache.
    pub async fn increment(&self, key: &str) -> Result<i64, RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.incr::<_, _, i64>(&full_key, 1).await {
            Ok(new_value) => Ok(new_value),
            Err(e) => {
                error!("Redis INCR error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Decrement a counter in cache.
    pub async fn decrement(&self, key: &str) -> Result<i64, RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let full_key = self.build_key(key);

        match conn.decr::<_, _, i64>(&full_key, 1).await {
            Ok(new_value) => Ok(new_value),
            Err(e) => {
                error!("Redis DECR error for key {}: {}", key, e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Clear all keys with the configured prefix.
    pub async fn clear(&self) -> Result<(), RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        let pattern = format!("{}*", self.config.key_prefix);

        match redis::cmd("KEYS")
            .arg(&pattern)
            .query_async::<Vec<String>>(conn)
            .await
        {
            Ok(keys) => {
                if !keys.is_empty() {
                    match conn.del::<_, ()>(keys).await {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            error!("Redis DEL error during clear: {}", e);
                            if self.config.enable_stats {
                                self.stats.write().await.errors += 1;
                            }
                            Err(RedisCacheError::Connection(e))
                        }
                    }
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                error!("Redis KEYS error during clear: {}", e);
                if self.config.enable_stats {
                    self.stats.write().await.errors += 1;
                }
                Err(RedisCacheError::Connection(e))
            }
        }
    }

    /// Get cache statistics.
    pub async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    /// Reset cache statistics.
    pub async fn reset_stats(&self) {
        *self.stats.write().await = CacheStats::default();
    }

    /// Ping Redis server to check connection.
    pub async fn ping(&self) -> Result<(), RedisCacheError> {
        let mut conn_guard = self.connection.write().await;
        let conn = conn_guard.as_mut().ok_or(RedisCacheError::Unavailable)?;

        match redis::cmd("PING").query_async::<String>(conn).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Redis PING error: {}", e);
                Err(RedisCacheError::Connection(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RedisCacheConfig {
        RedisCacheConfig {
            redis_url: "redis://localhost:6379".to_string(),
            default_ttl_secs: 60,
            key_prefix: "test:".to_string(),
            connection_timeout_ms: 1000,
            enable_stats: true,
            max_retries: 3,
        }
    }

    #[tokio::test]
    async fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            sets: 100,
            deletes: 10,
            errors: 0,
        };

        assert_eq!(stats.hit_rate(), 0.8);
    }

    #[tokio::test]
    async fn test_cache_stats_zero_requests() {
        let stats = CacheStats::default();
        assert_eq!(stats.hit_rate(), 0.0);
    }

    #[tokio::test]
    async fn test_build_key() {
        let config = test_config();
        let cache = RedisCache::new(config).unwrap();
        assert_eq!(cache.build_key("mykey"), "test:mykey");
    }

    #[tokio::test]
    async fn test_cache_config_default() {
        let config = RedisCacheConfig::default();
        assert_eq!(config.default_ttl_secs, 300);
        assert_eq!(config.key_prefix, "chie:cache:");
        assert!(config.enable_stats);
    }
}
