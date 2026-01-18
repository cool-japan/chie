//! In-memory caching layer for query results and frequently accessed data
//!
//! This module provides:
//! - Thread-safe in-memory cache with TTL support
//! - LRU eviction policy
//! - Cache statistics and monitoring
//! - Integration with database queries

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, RwLock};
use tracing::debug;

/// Cache entry with TTL and access tracking
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    /// Cached value
    value: V,
    /// Expiration timestamp
    expires_at: DateTime<Utc>,
    /// Last access timestamp
    last_accessed: DateTime<Utc>,
    /// Access count
    access_count: u64,
}

impl<V> CacheEntry<V> {
    /// Check if entry is expired
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update access statistics
    fn record_access(&mut self) {
        self.last_accessed = Utc::now();
        self.access_count += 1;
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Current entry count
    pub entry_count: usize,
    /// Maximum capacity
    pub max_capacity: usize,
    /// Total evictions
    pub evictions: u64,
}

/// Configuration for the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_capacity: usize,
    /// Default TTL in seconds
    pub default_ttl_secs: i64,
    /// Enable cache statistics
    pub enable_stats: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 10000,
            default_ttl_secs: 300, // 5 minutes
            enable_stats: true,
        }
    }
}

/// LRU cache with TTL support
pub struct LruCache<K, V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    V: Clone,
{
    config: Arc<CacheConfig>,
    entries: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    access_order: Arc<RwLock<VecDeque<K>>>,
    hits: Arc<RwLock<u64>>,
    misses: Arc<RwLock<u64>>,
    evictions: Arc<RwLock<u64>>,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    V: Clone,
{
    /// Create a new LRU cache
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config: Arc::new(config),
            entries: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(RwLock::new(VecDeque::new())),
            hits: Arc::new(RwLock::new(0)),
            misses: Arc::new(RwLock::new(0)),
            evictions: Arc::new(RwLock::new(0)),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get a value from the cache
    pub fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();

        if let Some(entry) = entries.get_mut(key) {
            // Check expiration
            if entry.is_expired() {
                entries.remove(key);
                self.record_miss();
                return None;
            }

            // Update access statistics
            entry.record_access();
            self.record_hit();

            // Update LRU order
            self.update_access_order(key);

            Some(entry.value.clone())
        } else {
            self.record_miss();
            None
        }
    }

    /// Insert a value with default TTL
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.config.default_ttl_secs);
    }

    /// Insert a value with custom TTL
    pub fn insert_with_ttl(&self, key: K, value: V, ttl_secs: i64) {
        let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs);

        let entry = CacheEntry {
            value,
            expires_at,
            last_accessed: Utc::now(),
            access_count: 0,
        };

        let mut entries = self.entries.write().unwrap();

        // Evict if at capacity
        if entries.len() >= self.config.max_capacity && !entries.contains_key(&key) {
            self.evict_lru(&mut entries);
        }

        entries.insert(key.clone(), entry);
        self.update_access_order(&key);
    }

    /// Remove a value from the cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().unwrap();
        entries.remove(key).map(|entry| {
            self.remove_from_access_order(key);
            entry.value
        })
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();

        let mut access_order = self.access_order.write().unwrap();
        access_order.clear();
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> usize {
        let mut entries = self.entries.write().unwrap();
        let now = Utc::now();

        let expired_keys: Vec<K> = entries
            .iter()
            .filter(|(_, entry)| entry.expires_at < now)
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired_keys.len();

        for key in expired_keys {
            entries.remove(&key);
            self.remove_from_access_order(&key);
        }

        debug!(expired_count = count, "Cache cleanup completed");
        count
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = *self.hits.read().unwrap();
        let misses = *self.misses.read().unwrap();
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            hit_rate,
            entry_count: self.entries.read().unwrap().len(),
            max_capacity: self.config.max_capacity,
            evictions: *self.evictions.read().unwrap(),
        }
    }

    /// Update the LRU access order
    fn update_access_order(&self, key: &K) {
        let mut access_order = self.access_order.write().unwrap();

        // Remove key if it exists
        if let Some(pos) = access_order.iter().position(|k| k == key) {
            access_order.remove(pos);
        }

        // Add to the back (most recently used)
        access_order.push_back(key.clone());
    }

    /// Remove a key from access order
    fn remove_from_access_order(&self, key: &K) {
        let mut access_order = self.access_order.write().unwrap();
        if let Some(pos) = access_order.iter().position(|k| k == key) {
            access_order.remove(pos);
        }
    }

    /// Evict the least recently used entry
    fn evict_lru(&self, entries: &mut HashMap<K, CacheEntry<V>>) {
        let mut access_order = self.access_order.write().unwrap();

        if let Some(lru_key) = access_order.pop_front() {
            entries.remove(&lru_key);
            let mut evictions = self.evictions.write().unwrap();
            *evictions += 1;
            debug!(key = ?lru_key, "Evicted LRU entry");
        }
    }

    /// Record a cache hit
    fn record_hit(&self) {
        if self.config.enable_stats {
            let mut hits = self.hits.write().unwrap();
            *hits += 1;
        }
    }

    /// Record a cache miss
    fn record_miss(&self) {
        if self.config.enable_stats {
            let mut misses = self.misses.write().unwrap();
            *misses += 1;
        }
    }
}

impl<K, V> Clone for LruCache<K, V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            entries: Arc::clone(&self.entries),
            access_order: Arc::clone(&self.access_order),
            hits: Arc::clone(&self.hits),
            misses: Arc::clone(&self.misses),
            evictions: Arc::clone(&self.evictions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache: LruCache<String, String> = LruCache::with_defaults();
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_insert_and_get() {
        let cache = LruCache::with_defaults();

        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_miss() {
        let cache: LruCache<String, String> = LruCache::with_defaults();

        assert_eq!(cache.get(&"nonexistent".to_string()), None);

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let config = CacheConfig {
            max_capacity: 3,
            default_ttl_secs: 300,
            enable_stats: true,
        };
        let cache = LruCache::new(config);

        // Fill cache to capacity
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        cache.insert("key3".to_string(), "value3".to_string());

        // Access key1 to make it most recently used
        let _ = cache.get(&"key1".to_string());

        // Insert new key, should evict key2 (LRU)
        cache.insert("key4".to_string(), "value4".to_string());

        assert!(cache.get(&"key1".to_string()).is_some());
        assert!(cache.get(&"key2".to_string()).is_none()); // Evicted
        assert!(cache.get(&"key3".to_string()).is_some());
        assert!(cache.get(&"key4".to_string()).is_some());

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_ttl_expiration() {
        let cache = LruCache::with_defaults();

        // Insert with short TTL (1 second)
        cache.insert_with_ttl("key1".to_string(), "value1".to_string(), 0);

        // Immediately expired
        assert_eq!(cache.get(&"key1".to_string()), None);
    }

    #[test]
    fn test_remove() {
        let cache = LruCache::with_defaults();

        cache.insert("key1".to_string(), "value1".to_string());
        assert!(cache.get(&"key1".to_string()).is_some());

        let removed = cache.remove(&"key1".to_string());
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(cache.get(&"key1".to_string()), None);
    }

    #[test]
    fn test_clear() {
        let cache = LruCache::with_defaults();

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        assert_eq!(cache.stats().entry_count, 2);

        cache.clear();

        assert_eq!(cache.stats().entry_count, 0);
        assert_eq!(cache.get(&"key1".to_string()), None);
        assert_eq!(cache.get(&"key2".to_string()), None);
    }

    #[test]
    fn test_hit_rate() {
        let cache = LruCache::with_defaults();

        cache.insert("key1".to_string(), "value1".to_string());

        // 2 hits, 1 miss
        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key2".to_string());

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.666).abs() < 0.01); // 2/3 ≈ 0.666
    }
}
