//! Redis-based nonce caching for fast replay attack detection.
//!
//! This module provides a high-performance nonce cache using Redis for:
//! - Fast O(1) nonce lookup
//! - Automatic expiration of old nonces
//! - Fallback to database for persistence

use redis::AsyncCommands;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

/// Nonce cache error types.
#[derive(Debug, Error)]
pub enum NonceCacheError {
    #[error("Redis connection error: {0}")]
    ConnectionError(String),

    #[error("Redis operation failed: {0}")]
    OperationFailed(String),

    #[error("Nonce already used")]
    NonceUsed,
}

/// Configuration for the nonce cache.
#[derive(Debug, Clone)]
pub struct NonceCacheConfig {
    /// Redis URL.
    pub redis_url: String,
    /// Nonce TTL (time to live) in seconds.
    pub nonce_ttl_secs: u64,
    /// Key prefix for nonces.
    pub key_prefix: String,
    /// Maximum connection pool size.
    pub max_connections: u32,
}

impl Default for NonceCacheConfig {
    fn default() -> Self {
        Self {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            nonce_ttl_secs: 600, // 10 minutes
            key_prefix: "chie:nonce:".to_string(),
            max_connections: 10,
        }
    }
}

/// Redis-based nonce cache.
pub struct NonceCache {
    client: redis::Client,
    config: NonceCacheConfig,
}

impl NonceCache {
    /// Create a new nonce cache.
    pub fn new(config: NonceCacheConfig) -> Result<Self, NonceCacheError> {
        let client = redis::Client::open(config.redis_url.as_str())
            .map_err(|e| NonceCacheError::ConnectionError(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Get a connection from the pool.
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, NonceCacheError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| NonceCacheError::ConnectionError(e.to_string()))
    }

    /// Check if a nonce has been used and mark it as used if not.
    ///
    /// Returns Ok(true) if the nonce is fresh and was successfully marked as used.
    /// Returns Ok(false) if the nonce was already used.
    /// Returns Err on cache failure.
    pub async fn check_and_use(&self, nonce: &[u8]) -> Result<bool, NonceCacheError> {
        let key = self.nonce_key(nonce);
        let mut conn = self.get_connection().await?;

        // Use SET NX (set if not exists) with expiration
        let result: bool = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(self.config.nonce_ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceCacheError::OperationFailed(e.to_string()))?;

        if result {
            debug!("Nonce {} accepted", hex::encode(nonce));
            Ok(true)
        } else {
            debug!("Nonce {} already used", hex::encode(nonce));
            Ok(false)
        }
    }

    /// Check if a nonce exists without marking it as used.
    pub async fn exists(&self, nonce: &[u8]) -> Result<bool, NonceCacheError> {
        let key = self.nonce_key(nonce);
        let mut conn = self.get_connection().await?;

        conn.exists(&key)
            .await
            .map_err(|e| NonceCacheError::OperationFailed(e.to_string()))
    }

    /// Remove a nonce from the cache.
    pub async fn remove(&self, nonce: &[u8]) -> Result<bool, NonceCacheError> {
        let key = self.nonce_key(nonce);
        let mut conn = self.get_connection().await?;

        let result: i32 = conn
            .del(&key)
            .await
            .map_err(|e| NonceCacheError::OperationFailed(e.to_string()))?;

        Ok(result > 0)
    }

    /// Get statistics about the cache.
    pub async fn stats(&self) -> Result<NonceCacheStats, NonceCacheError> {
        let mut conn = self.get_connection().await?;

        // Count keys with our prefix
        let pattern = format!("{}*", self.config.key_prefix);
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceCacheError::OperationFailed(e.to_string()))?;

        Ok(NonceCacheStats {
            total_nonces: keys.len(),
            ttl_seconds: self.config.nonce_ttl_secs,
        })
    }

    /// Generate the Redis key for a nonce.
    fn nonce_key(&self, nonce: &[u8]) -> String {
        format!("{}{}", self.config.key_prefix, hex::encode(nonce))
    }
}

/// Statistics about the nonce cache.
#[derive(Debug, Clone)]
pub struct NonceCacheStats {
    /// Total number of nonces in cache.
    pub total_nonces: usize,
    /// TTL for nonces in seconds.
    pub ttl_seconds: u64,
}

/// Shared nonce cache that can be used across handlers.
pub type SharedNonceCache = Arc<NonceCache>;

/// Create a shared nonce cache.
pub fn create_nonce_cache(config: NonceCacheConfig) -> Result<SharedNonceCache, NonceCacheError> {
    Ok(Arc::new(NonceCache::new(config)?))
}

/// A hybrid nonce checker that uses Redis for caching and falls back to database.
pub struct HybridNonceChecker {
    cache: SharedNonceCache,
    pool: Arc<crate::db::DbPool>,
}

impl HybridNonceChecker {
    /// Create a new hybrid nonce checker.
    pub fn new(cache: SharedNonceCache, pool: Arc<crate::db::DbPool>) -> Self {
        Self { cache, pool }
    }

    /// Check if a nonce is valid and mark it as used.
    ///
    /// 1. First checks Redis cache (fast path)
    /// 2. If Redis is down, falls back to database
    /// 3. Records the nonce in both cache and database
    pub async fn check_and_use(&self, nonce: &[u8]) -> Result<bool, NonceCacheError> {
        // Try Redis first
        match self.cache.check_and_use(nonce).await {
            Ok(is_valid) => {
                if is_valid {
                    // Also record in database for persistence
                    // This is fire-and-forget; we don't wait for it
                    let pool = self.pool.clone();
                    let nonce_vec = nonce.to_vec();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::db::ProofRepository::check_and_use_nonce(&pool, &nonce_vec).await
                        {
                            warn!("Failed to record nonce in database: {}", e);
                        }
                    });
                }
                Ok(is_valid)
            }
            Err(e) => {
                // Redis is down, fall back to database
                warn!("Redis cache failed, falling back to database: {}", e);
                crate::db::ProofRepository::check_and_use_nonce(&self.pool, nonce)
                    .await
                    .map_err(|e| NonceCacheError::OperationFailed(e.to_string()))
            }
        }
    }
}

/// Shared hybrid checker.
pub type SharedHybridChecker = Arc<HybridNonceChecker>;

/// Create a hybrid nonce checker.
pub fn create_hybrid_checker(
    cache: SharedNonceCache,
    pool: Arc<crate::db::DbPool>,
) -> SharedHybridChecker {
    Arc::new(HybridNonceChecker::new(cache, pool))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Redis instance
    // Run with: cargo test -- --ignored

    #[tokio::test]
    #[ignore]
    async fn test_check_and_use() {
        let config = NonceCacheConfig::default();
        let cache = NonceCache::new(config).unwrap();

        let nonce = [1u8; 32];

        // First use should succeed
        assert!(cache.check_and_use(&nonce).await.unwrap());

        // Second use should fail
        assert!(!cache.check_and_use(&nonce).await.unwrap());

        // Clean up
        cache.remove(&nonce).await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_exists() {
        let config = NonceCacheConfig::default();
        let cache = NonceCache::new(config).unwrap();

        let nonce = [2u8; 32];

        // Should not exist initially
        assert!(!cache.exists(&nonce).await.unwrap());

        // Add it
        cache.check_and_use(&nonce).await.unwrap();

        // Should exist now
        assert!(cache.exists(&nonce).await.unwrap());

        // Clean up
        cache.remove(&nonce).await.unwrap();
    }
}
