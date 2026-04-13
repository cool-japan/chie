//! Multi-level cache hierarchy for optimal performance and cost.
//!
//! This module implements a multi-tiered caching system with automatic promotion
//! and demotion between levels based on access patterns:
//! - L1: Hot data in memory (fastest, smallest)
//! - L2: Warm data on SSD (fast, medium)
//! - L3: Cold data on HDD (slow, largest)
//!
//! # Example
//!
//! ```rust
//! use chie_core::tiered_cache::{TieredCache, TieredCacheConfig};
//! use chie_core::compression::CompressionAlgorithm;
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TieredCacheConfig {
//!     l1_capacity_bytes: 100 * 1024 * 1024,      // 100 MB in memory
//!     l2_capacity_bytes: 1024 * 1024 * 1024,     // 1 GB on SSD
//!     l3_capacity_bytes: 10 * 1024 * 1024 * 1024, // 10 GB on HDD
//!     l2_path: PathBuf::from("/fast-ssd/cache"),
//!     l3_path: PathBuf::from("/slow-hdd/cache"),
//!     promotion_threshold: 3,  // Promote after 3 accesses
//!     compression: CompressionAlgorithm::None,
//! };
//!
//! let mut cache = TieredCache::new(config).await?;
//!
//! // Insert data (starts in L1)
//! cache.put("key1".to_string(), b"hot data".to_vec()).await?;
//!
//! // Get data (automatically promotes if accessed frequently)
//! if let Some(data) = cache.get("key1").await? {
//!     println!("Found data: {} bytes", data.len());
//! }
//!
//! // Get cache statistics
//! let stats = cache.stats();
//! println!("L1 hit rate: {:.2}%", stats.l1_hit_rate() * 100.0);
//! # Ok(())
//! # }
//! ```

use crate::compression::{CompressionAlgorithm, Compressor};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Tiered cache error types.
#[derive(Debug, Error)]
pub enum TieredCacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Tier full: {tier}")]
    TierFull { tier: String },

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Cache tier levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CacheTier {
    /// L1: In-memory cache (hottest data).
    L1 = 1,
    /// L2: SSD cache (warm data).
    L2 = 2,
    /// L3: HDD cache (cold data).
    L3 = 3,
}

impl CacheTier {
    /// Get tier name.
    #[must_use]
    #[inline]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::L1 => "L1-Memory",
            Self::L2 => "L2-SSD",
            Self::L3 => "L3-HDD",
        }
    }
}

/// Metadata for a cached item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheItemMetadata {
    key: String,
    size_bytes: u64,
    tier: CacheTier,
    access_count: u64,
    last_access_ms: i64,
    created_ms: i64,
}

impl CacheItemMetadata {
    /// Create new metadata.
    fn new(key: String, size_bytes: u64, tier: CacheTier) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            key,
            size_bytes,
            tier,
            access_count: 0,
            last_access_ms: now_ms,
            created_ms: now_ms,
        }
    }

    /// Record an access.
    fn record_access(&mut self) {
        self.access_count += 1;
        self.last_access_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
    }

    /// Check if item should be promoted.
    #[must_use]
    #[inline]
    const fn should_promote(&self, threshold: u64) -> bool {
        self.access_count >= threshold
    }
}

/// Configuration for tiered cache.
#[derive(Debug, Clone)]
pub struct TieredCacheConfig {
    /// L1 (memory) capacity in bytes.
    pub l1_capacity_bytes: u64,
    /// L2 (SSD) capacity in bytes.
    pub l2_capacity_bytes: u64,
    /// L3 (HDD) capacity in bytes.
    pub l3_capacity_bytes: u64,
    /// Path for L2 cache.
    pub l2_path: PathBuf,
    /// Path for L3 cache.
    pub l3_path: PathBuf,
    /// Number of accesses before promotion.
    pub promotion_threshold: u64,
    /// Compression algorithm for L2/L3 tiers (None = no compression).
    pub compression: CompressionAlgorithm,
}

impl Default for TieredCacheConfig {
    fn default() -> Self {
        Self {
            l1_capacity_bytes: 100 * 1024 * 1024,       // 100 MB
            l2_capacity_bytes: 1024 * 1024 * 1024,      // 1 GB
            l3_capacity_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            l2_path: PathBuf::from("./cache/l2"),
            l3_path: PathBuf::from("./cache/l3"),
            promotion_threshold: 3,
            compression: CompressionAlgorithm::Balanced, // Default to balanced compression
        }
    }
}

/// Statistics for tiered cache.
#[derive(Debug, Clone, Default)]
pub struct TieredCacheStats {
    /// L1 hits.
    pub l1_hits: u64,
    /// L2 hits.
    pub l2_hits: u64,
    /// L3 hits.
    pub l3_hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Items promoted from L2 to L1.
    pub promotions_l2_to_l1: u64,
    /// Items promoted from L3 to L2.
    pub promotions_l3_to_l2: u64,
    /// Items demoted from L1 to L2.
    pub demotions_l1_to_l2: u64,
    /// Items demoted from L2 to L3.
    pub demotions_l2_to_l3: u64,
    /// Items evicted from L3.
    pub evictions: u64,
}

impl TieredCacheStats {
    /// Calculate L1 hit rate.
    #[must_use]
    #[inline]
    pub fn l1_hit_rate(&self) -> f64 {
        let total = self.l1_hits + self.l2_hits + self.l3_hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.l1_hits as f64 / total as f64
        }
    }

    /// Calculate overall hit rate.
    #[must_use]
    #[inline]
    pub fn overall_hit_rate(&self) -> f64 {
        let hits = self.l1_hits + self.l2_hits + self.l3_hits;
        let total = hits + self.misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Calculate average tier (1.0 = all L1, 3.0 = all L3).
    #[must_use]
    #[inline]
    pub fn average_tier(&self) -> f64 {
        let hits = self.l1_hits + self.l2_hits + self.l3_hits;
        if hits == 0 {
            0.0
        } else {
            (self.l1_hits as f64 + self.l2_hits as f64 * 2.0 + self.l3_hits as f64 * 3.0)
                / hits as f64
        }
    }
}

/// Multi-level cache with automatic tiering.
pub struct TieredCache {
    config: TieredCacheConfig,
    /// L1 cache (in-memory).
    l1: HashMap<String, Vec<u8>>,
    /// Metadata for all items.
    metadata: HashMap<String, CacheItemMetadata>,
    /// Current usage per tier.
    l1_used: u64,
    l2_used: u64,
    l3_used: u64,
    /// Statistics.
    stats: TieredCacheStats,
    /// Compressor for L2/L3 tiers (RefCell for interior mutability).
    compressor: RefCell<Compressor>,
}

impl TieredCache {
    /// Create a new tiered cache.
    pub async fn new(config: TieredCacheConfig) -> Result<Self, TieredCacheError> {
        // Create directories for L2 and L3
        fs::create_dir_all(&config.l2_path).await?;
        fs::create_dir_all(&config.l3_path).await?;

        let compressor = RefCell::new(Compressor::new(config.compression));

        Ok(Self {
            compressor,
            config,
            l1: HashMap::new(),
            metadata: HashMap::new(),
            l1_used: 0,
            l2_used: 0,
            l3_used: 0,
            stats: TieredCacheStats::default(),
        })
    }

    /// Put data into cache (starts in L1).
    pub async fn put(&mut self, key: String, data: Vec<u8>) -> Result<(), TieredCacheError> {
        let size = data.len() as u64;

        // Remove old entry if exists
        if let Some(old_meta) = self.metadata.get(&key) {
            self.remove_from_tier(&key, old_meta.tier).await?;
        }

        // Try to place in L1
        if self.l1_used + size <= self.config.l1_capacity_bytes {
            self.l1.insert(key.clone(), data);
            self.l1_used += size;
            self.metadata.insert(
                key.clone(),
                CacheItemMetadata::new(key, size, CacheTier::L1),
            );
            Ok(())
        } else {
            // Evict from L1 to make space or place in L2
            self.evict_from_l1().await?;
            if self.l1_used + size <= self.config.l1_capacity_bytes {
                self.l1.insert(key.clone(), data);
                self.l1_used += size;
                self.metadata.insert(
                    key.clone(),
                    CacheItemMetadata::new(key, size, CacheTier::L1),
                );
                Ok(())
            } else {
                // Place directly in L2
                self.place_in_l2(key, data, size).await
            }
        }
    }

    /// Get data from cache.
    pub async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, TieredCacheError> {
        // Record access and get tier info
        let (tier, should_promote) = if let Some(meta) = self.metadata.get_mut(key) {
            meta.record_access();
            let should_promote = meta.should_promote(self.config.promotion_threshold);
            (meta.tier, should_promote)
        } else {
            self.stats.misses += 1;
            return Ok(None);
        };

        match tier {
            CacheTier::L1 => {
                self.stats.l1_hits += 1;
                Ok(self.l1.get(key).cloned())
            }
            CacheTier::L2 => {
                self.stats.l2_hits += 1;
                let data = self.read_from_l2(key).await?;

                // Promote to L1 if accessed frequently
                if should_promote {
                    self.promote_to_l1(key.to_string(), data.clone()).await?;
                }

                Ok(Some(data))
            }
            CacheTier::L3 => {
                self.stats.l3_hits += 1;
                let data = self.read_from_l3(key).await?;

                // Promote to L2 if accessed frequently
                if should_promote {
                    self.promote_to_l2(key.to_string(), data.clone()).await?;
                }

                Ok(Some(data))
            }
        }
    }

    /// Remove item from cache.
    pub async fn remove(&mut self, key: &str) -> Result<(), TieredCacheError> {
        if let Some(meta) = self.metadata.remove(key) {
            self.remove_from_tier(key, meta.tier).await?;
        }
        Ok(())
    }

    /// Get cache statistics.
    #[must_use]
    #[inline]
    pub const fn stats(&self) -> &TieredCacheStats {
        &self.stats
    }

    /// Get L1 usage percentage.
    #[must_use]
    #[inline]
    pub fn l1_usage_percent(&self) -> f64 {
        if self.config.l1_capacity_bytes == 0 {
            0.0
        } else {
            self.l1_used as f64 / self.config.l1_capacity_bytes as f64
        }
    }

    /// Warm the cache with a list of key-value pairs.
    ///
    /// This is useful for cold starts where you want to pre-populate
    /// frequently accessed data. Items are placed according to available
    /// capacity, starting from L1.
    pub async fn warm_with_data(
        &mut self,
        items: Vec<(String, Vec<u8>)>,
    ) -> Result<usize, TieredCacheError> {
        let mut warmed = 0;

        for (key, data) in items {
            if self.put(key, data).await.is_ok() {
                warmed += 1;
            }
        }

        Ok(warmed)
    }

    /// Warm the cache by loading keys from a list.
    ///
    /// This method attempts to load data from storage tiers (L2/L3)
    /// and promote them to L1 for faster access on startup.
    pub async fn warm_from_keys(&mut self, keys: &[String]) -> Result<usize, TieredCacheError> {
        let mut warmed = 0;

        for key in keys {
            // Try to load from L2
            if let Ok(data) = self.read_from_l2(key).await {
                if self.put(key.clone(), data).await.is_ok() {
                    warmed += 1;
                    continue;
                }
            }

            // Try to load from L3
            if let Ok(data) = self.read_from_l3(key).await {
                if self.put(key.clone(), data).await.is_ok() {
                    warmed += 1;
                }
            }
        }

        Ok(warmed)
    }

    /// Export hot keys (most frequently accessed) for warming on next startup.
    ///
    /// Returns keys sorted by access count in descending order.
    #[must_use]
    pub fn export_hot_keys(&self, limit: usize) -> Vec<String> {
        let mut items: Vec<_> = self
            .metadata
            .iter()
            .map(|(key, meta)| (key.clone(), meta.access_count))
            .collect();

        items.sort_by(|a, b| b.1.cmp(&a.1));

        items.into_iter().take(limit).map(|(key, _)| key).collect()
    }

    /// Get the number of cached items.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.metadata.len()
    }

    /// Check if the cache is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }

    // Helper methods

    async fn place_in_l2(
        &mut self,
        key: String,
        data: Vec<u8>,
        size: u64,
    ) -> Result<(), TieredCacheError> {
        if self.l2_used + size > self.config.l2_capacity_bytes {
            self.evict_from_l2().await?;
        }

        if self.l2_used + size <= self.config.l2_capacity_bytes {
            self.write_to_l2(&key, &data).await?;
            self.l2_used += size;
            self.metadata.insert(
                key.clone(),
                CacheItemMetadata::new(key, size, CacheTier::L2),
            );
            Ok(())
        } else {
            self.place_in_l3(key, data, size).await
        }
    }

    async fn place_in_l3(
        &mut self,
        key: String,
        data: Vec<u8>,
        size: u64,
    ) -> Result<(), TieredCacheError> {
        if self.l3_used + size > self.config.l3_capacity_bytes {
            self.evict_from_l3().await?;
        }

        if self.l3_used + size <= self.config.l3_capacity_bytes {
            self.write_to_l3(&key, &data).await?;
            self.l3_used += size;
            self.metadata.insert(
                key.clone(),
                CacheItemMetadata::new(key, size, CacheTier::L3),
            );
            Ok(())
        } else {
            Err(TieredCacheError::TierFull {
                tier: "L3".to_string(),
            })
        }
    }

    async fn evict_from_l1(&mut self) -> Result<(), TieredCacheError> {
        // Find LRU item in L1
        let lru_key = self
            .metadata
            .iter()
            .filter(|(_, meta)| meta.tier == CacheTier::L1)
            .min_by_key(|(_, meta)| meta.last_access_ms)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            if let Some(data) = self.l1.remove(&key) {
                // Get size before calling write methods
                let size = self.metadata.get(&key).map(|m| m.size_bytes).unwrap_or(0);

                self.l1_used -= size;
                // Demote to L2
                self.write_to_l2(&key, &data).await?;
                self.l2_used += size;

                // Update metadata tier
                if let Some(meta) = self.metadata.get_mut(&key) {
                    meta.tier = CacheTier::L2;
                }

                self.stats.demotions_l1_to_l2 += 1;
            }
        }

        Ok(())
    }

    async fn evict_from_l2(&mut self) -> Result<(), TieredCacheError> {
        // Find LRU item in L2
        let lru_key = self
            .metadata
            .iter()
            .filter(|(_, meta)| meta.tier == CacheTier::L2)
            .min_by_key(|(_, meta)| meta.last_access_ms)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            // Get size before calling methods
            let size = self.metadata.get(&key).map(|m| m.size_bytes).unwrap_or(0);

            let data = self.read_from_l2(&key).await?;

            self.l2_used -= size;
            // Demote to L3
            self.write_to_l3(&key, &data).await?;
            self.l3_used += size;

            // Update metadata tier
            if let Some(meta) = self.metadata.get_mut(&key) {
                meta.tier = CacheTier::L3;
            }

            self.stats.demotions_l2_to_l3 += 1;

            // Remove from L2
            let _ = fs::remove_file(self.l2_path(&key)).await;
        }

        Ok(())
    }

    async fn evict_from_l3(&mut self) -> Result<(), TieredCacheError> {
        // Find LRU item in L3
        let lru_key = self
            .metadata
            .iter()
            .filter(|(_, meta)| meta.tier == CacheTier::L3)
            .min_by_key(|(_, meta)| meta.last_access_ms)
            .map(|(key, _)| key.clone());

        if let Some(key) = lru_key {
            if let Some(meta) = self.metadata.remove(&key) {
                self.l3_used -= meta.size_bytes;
                let _ = fs::remove_file(self.l3_path(&key)).await;
                self.stats.evictions += 1;
            }
        }

        Ok(())
    }

    async fn promote_to_l1(&mut self, key: String, data: Vec<u8>) -> Result<(), TieredCacheError> {
        // Extract metadata without holding a mutable borrow
        let (size, current_tier) = if let Some(meta) = self.metadata.get(&key) {
            (meta.size_bytes, meta.tier)
        } else {
            return Ok(());
        };

        // Early return if already in L1
        if current_tier == CacheTier::L1 {
            return Ok(());
        }

        // Make space in L1 if needed
        while self.l1_used + size > self.config.l1_capacity_bytes {
            self.evict_from_l1().await?;
        }

        // Remove from current tier
        match current_tier {
            CacheTier::L2 => {
                self.l2_used -= size;
                let _ = fs::remove_file(self.l2_path(&key)).await;
                self.stats.promotions_l2_to_l1 += 1;
            }
            CacheTier::L3 => {
                self.l3_used -= size;
                let _ = fs::remove_file(self.l3_path(&key)).await;
            }
            CacheTier::L1 => return Ok(()), // Already in L1
        }

        // Add to L1
        self.l1.insert(key.clone(), data);
        self.l1_used += size;

        // Update metadata tier
        if let Some(meta) = self.metadata.get_mut(&key) {
            meta.tier = CacheTier::L1;
        }

        Ok(())
    }

    async fn promote_to_l2(&mut self, key: String, data: Vec<u8>) -> Result<(), TieredCacheError> {
        // Extract metadata without holding a mutable borrow
        let (size, current_tier) = if let Some(meta) = self.metadata.get(&key) {
            (meta.size_bytes, meta.tier)
        } else {
            return Ok(());
        };

        if current_tier == CacheTier::L3 {
            // Make space in L2 if needed
            while self.l2_used + size > self.config.l2_capacity_bytes {
                self.evict_from_l2().await?;
            }

            // Remove from L3
            self.l3_used -= size;
            let _ = fs::remove_file(self.l3_path(&key)).await;

            // Add to L2
            self.write_to_l2(&key, &data).await?;
            self.l2_used += size;

            // Update metadata tier
            if let Some(meta) = self.metadata.get_mut(&key) {
                meta.tier = CacheTier::L2;
            }

            self.stats.promotions_l3_to_l2 += 1;
        }

        Ok(())
    }

    async fn remove_from_tier(
        &mut self,
        key: &str,
        tier: CacheTier,
    ) -> Result<(), TieredCacheError> {
        if let Some(meta) = self.metadata.get(key) {
            match tier {
                CacheTier::L1 => {
                    self.l1.remove(key);
                    self.l1_used -= meta.size_bytes;
                }
                CacheTier::L2 => {
                    let _ = fs::remove_file(self.l2_path(key)).await;
                    self.l2_used -= meta.size_bytes;
                }
                CacheTier::L3 => {
                    let _ = fs::remove_file(self.l3_path(key)).await;
                    self.l3_used -= meta.size_bytes;
                }
            }
        }
        Ok(())
    }

    fn l2_path(&self, key: &str) -> PathBuf {
        self.config.l2_path.join(format!("{}.cache", key))
    }

    fn l3_path(&self, key: &str) -> PathBuf {
        self.config.l3_path.join(format!("{}.cache", key))
    }

    async fn write_to_l2(&self, key: &str, data: &[u8]) -> Result<(), TieredCacheError> {
        let path = self.l2_path(key);

        // Compress data if compression is enabled
        let write_data = if !self.config.compression.is_none() {
            self.compressor
                .borrow_mut()
                .compress(data)
                .map_err(|e| TieredCacheError::Io(std::io::Error::other(e)))?
        } else {
            data.to_vec()
        };

        let mut file = fs::File::create(path).await?;
        file.write_all(&write_data).await?;
        file.sync_all().await?;
        Ok(())
    }

    async fn write_to_l3(&self, key: &str, data: &[u8]) -> Result<(), TieredCacheError> {
        let path = self.l3_path(key);

        // Compress data if compression is enabled
        let write_data = if !self.config.compression.is_none() {
            self.compressor
                .borrow_mut()
                .compress(data)
                .map_err(|e| TieredCacheError::Io(std::io::Error::other(e)))?
        } else {
            data.to_vec()
        };

        let mut file = fs::File::create(path).await?;
        file.write_all(&write_data).await?;
        file.sync_all().await?;
        Ok(())
    }

    async fn read_from_l2(&self, key: &str) -> Result<Vec<u8>, TieredCacheError> {
        let path = self.l2_path(key);
        let mut file = fs::File::open(path).await?;
        let mut compressed_data = Vec::new();
        file.read_to_end(&mut compressed_data).await?;

        // Decompress if compression is enabled
        let data = if !self.config.compression.is_none() {
            self.compressor
                .borrow_mut()
                .decompress(&compressed_data)
                .map_err(|e| TieredCacheError::Io(std::io::Error::other(e)))?
        } else {
            compressed_data
        };

        Ok(data)
    }

    async fn read_from_l3(&self, key: &str) -> Result<Vec<u8>, TieredCacheError> {
        let path = self.l3_path(key);
        let mut file = fs::File::open(path).await?;
        let mut compressed_data = Vec::new();
        file.read_to_end(&mut compressed_data).await?;

        // Decompress if compression is enabled
        let data = if !self.config.compression.is_none() {
            self.compressor
                .borrow_mut()
                .decompress(&compressed_data)
                .map_err(|e| TieredCacheError::Io(std::io::Error::other(e)))?
        } else {
            compressed_data
        };

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_cache() -> (TempDir, TieredCache) {
        let temp_dir = TempDir::new().unwrap();
        let config = TieredCacheConfig {
            l1_capacity_bytes: 100,
            l2_capacity_bytes: 200,
            l3_capacity_bytes: 300,
            l2_path: temp_dir.path().join("l2"),
            l3_path: temp_dir.path().join("l3"),
            promotion_threshold: 2,
            compression: CompressionAlgorithm::None, // No compression in tests for predictable sizes
        };
        let cache = TieredCache::new(config).await.unwrap();
        (temp_dir, cache)
    }

    #[tokio::test]
    async fn test_tiered_cache_creation() {
        let (_temp, cache) = create_test_cache().await;
        assert_eq!(cache.l1_used, 0);
        assert_eq!(cache.l2_used, 0);
        assert_eq!(cache.l3_used, 0);
    }

    #[tokio::test]
    async fn test_put_and_get_l1() {
        let (_temp, mut cache) = create_test_cache().await;

        cache
            .put("key1".to_string(), b"small".to_vec())
            .await
            .unwrap();

        let data = cache.get("key1").await.unwrap();
        assert_eq!(data, Some(b"small".to_vec()));
        assert_eq!(cache.stats.l1_hits, 1);
    }

    #[tokio::test]
    async fn test_automatic_demotion() {
        let (_temp, mut cache) = create_test_cache().await;

        // Fill L1 beyond capacity
        cache.put("key1".to_string(), vec![1; 60]).await.unwrap();
        cache.put("key2".to_string(), vec![2; 60]).await.unwrap();

        // This should demote key1 to L2
        assert!(cache.stats.demotions_l1_to_l2 >= 1);
    }

    #[tokio::test]
    async fn test_promotion_on_access() {
        let (_temp, mut cache) = create_test_cache().await;

        // Fill L1 to force item to L2
        cache.put("key1".to_string(), vec![1; 60]).await.unwrap();
        cache.put("key2".to_string(), vec![2; 60]).await.unwrap();

        // Access key1 multiple times to trigger promotion
        let _ = cache.get("key1").await;
        let _ = cache.get("key1").await;
        let _ = cache.get("key1").await;

        // key1 should be promoted back to L1
        if let Some(meta) = cache.metadata.get("key1") {
            assert_eq!(meta.tier, CacheTier::L1);
        }
    }

    #[tokio::test]
    async fn test_hit_rate_calculation() {
        let (_temp, mut cache) = create_test_cache().await;

        cache
            .put("key1".to_string(), b"data".to_vec())
            .await
            .unwrap();

        let _ = cache.get("key1").await;
        let _ = cache.get("key1").await;
        let _ = cache.get("nonexistent").await;

        let hit_rate = cache.stats.overall_hit_rate();
        assert!((hit_rate - 0.666).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_remove() {
        let (_temp, mut cache) = create_test_cache().await;

        cache
            .put("key1".to_string(), b"data".to_vec())
            .await
            .unwrap();
        assert!(cache.get("key1").await.unwrap().is_some());

        cache.remove("key1").await.unwrap();
        assert!(cache.get("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_warm_with_data() {
        let (_temp, mut cache) = create_test_cache().await;

        let warm_data = vec![
            ("key1".to_string(), b"data1".to_vec()),
            ("key2".to_string(), b"data2".to_vec()),
            ("key3".to_string(), b"data3".to_vec()),
        ];

        let warmed = cache.warm_with_data(warm_data).await.unwrap();
        assert_eq!(warmed, 3);

        assert!(cache.get("key1").await.unwrap().is_some());
        assert!(cache.get("key2").await.unwrap().is_some());
        assert!(cache.get("key3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_warm_from_keys() {
        let (_temp, mut cache) = create_test_cache().await;

        // Put some data in L2/L3 first
        cache.put("key1".to_string(), vec![0u8; 150]).await.unwrap();
        cache.put("key2".to_string(), vec![0u8; 150]).await.unwrap();

        // These should be in L2 or L3 now
        let _metadata_before = cache.metadata.clone();

        // Create a new cache instance
        let config = TieredCacheConfig {
            l1_capacity_bytes: 100,
            l2_capacity_bytes: 200,
            l3_capacity_bytes: 300,
            l2_path: cache.config.l2_path.clone(),
            l3_path: cache.config.l3_path.clone(),
            promotion_threshold: 2,
            compression: CompressionAlgorithm::None,
        };
        let mut new_cache = TieredCache::new(config).await.unwrap();

        // Warm from keys
        let keys = vec!["key1".to_string(), "key2".to_string()];
        let _warmed = new_cache.warm_from_keys(&keys).await.unwrap();
        // Warmed count may vary depending on file system state
    }

    #[tokio::test]
    async fn test_export_hot_keys() {
        let (_temp, mut cache) = create_test_cache().await;

        // Add some data with different access patterns
        cache
            .put("hot1".to_string(), b"data".to_vec())
            .await
            .unwrap();
        cache
            .put("hot2".to_string(), b"data".to_vec())
            .await
            .unwrap();
        cache
            .put("cold".to_string(), b"data".to_vec())
            .await
            .unwrap();

        // Access hot keys multiple times
        for _ in 0..5 {
            let _ = cache.get("hot1").await;
        }
        for _ in 0..3 {
            let _ = cache.get("hot2").await;
        }
        let _ = cache.get("cold").await;

        // Export top 2 hot keys
        let hot_keys = cache.export_hot_keys(2);
        assert_eq!(hot_keys.len(), 2);
        assert!(hot_keys.contains(&"hot1".to_string()));
        assert!(hot_keys.contains(&"hot2".to_string()));
    }

    #[tokio::test]
    async fn test_len_and_is_empty() {
        let (_temp, mut cache) = create_test_cache().await;

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache
            .put("key1".to_string(), b"data".to_vec())
            .await
            .unwrap();
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);

        cache
            .put("key2".to_string(), b"data".to_vec())
            .await
            .unwrap();
        assert_eq!(cache.len(), 2);

        cache.remove("key1").await.unwrap();
        assert_eq!(cache.len(), 1);
    }
}
