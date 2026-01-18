//! Advanced caching layer with TTL and multiple eviction policies.
//!
//! This module provides flexible caching with support for LRU, LFU, and FIFO
//! eviction policies, time-to-live (TTL), and size-based limits.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Cache eviction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Least Recently Used - evicts items not accessed recently
    LRU,
    /// Least Frequently Used - evicts items accessed least often
    LFU,
    /// First In First Out - evicts oldest items
    FIFO,
    /// Time To Live only - no size-based eviction
    TTLOnly,
}

/// Configuration for cache behavior.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of items in cache
    pub max_items: usize,
    /// Maximum total size in bytes (0 = unlimited)
    pub max_size_bytes: usize,
    /// Default time-to-live for cached items
    pub default_ttl: Option<Duration>,
    /// Eviction policy to use
    pub eviction_policy: EvictionPolicy,
    /// Enable statistics tracking
    pub enable_stats: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_items: 1000,
            max_size_bytes: 100 * 1024 * 1024,            // 100 MB
            default_ttl: Some(Duration::from_secs(3600)), // 1 hour
            eviction_policy: EvictionPolicy::LRU,
            enable_stats: true,
        }
    }
}

/// Entry metadata for cached items.
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    size_bytes: usize,
    #[allow(dead_code)]
    created_at: Instant,
    expires_at: Option<Instant>,
    last_accessed: Instant,
    access_count: u64,
}

impl<V> CacheEntry<V> {
    fn new(value: V, size_bytes: usize, ttl: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            value,
            size_bytes,
            created_at: now,
            expires_at: ttl.map(|duration| now + duration),
            last_accessed: now,
            access_count: 1,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Instant::now() >= exp)
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }
}

/// Statistics for cache performance.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Number of evictions performed
    pub evictions: u64,
    /// Number of expirations (TTL)
    pub expirations: u64,
    /// Number of items currently cached
    pub item_count: usize,
    /// Total size of cached items in bytes
    pub total_size_bytes: usize,
}

impl CacheStats {
    /// Calculates the cache hit rate.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// Advanced cache with configurable eviction policies and TTL.
pub struct Cache<K, V>
where
    K: Hash + Eq + Clone,
{
    config: CacheConfig,
    entries: HashMap<K, CacheEntry<V>>,
    access_order: VecDeque<K>,    // For LRU
    insertion_order: VecDeque<K>, // For FIFO
    current_size_bytes: usize,
    stats: CacheStats,
}

impl<K, V> Cache<K, V>
where
    K: Hash + Eq + Clone,
{
    /// Creates a new cache with default configuration.
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Creates a new cache with custom configuration.
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            insertion_order: VecDeque::new(),
            current_size_bytes: 0,
            stats: CacheStats::default(),
        }
    }

    /// Inserts an item into the cache.
    ///
    /// # Arguments
    /// * `key` - The cache key
    /// * `value` - The value to cache
    /// * `size_bytes` - Size of the value in bytes
    /// * `ttl` - Optional TTL override (uses default if None)
    pub fn insert(&mut self, key: K, value: V, size_bytes: usize, ttl: Option<Duration>) {
        self.cleanup_expired();

        let ttl = ttl.or(self.config.default_ttl);
        let entry = CacheEntry::new(value, size_bytes, ttl);

        // Remove existing entry if present
        if let Some(old_entry) = self.entries.remove(&key) {
            self.current_size_bytes -= old_entry.size_bytes;
            self.remove_from_tracking(&key);
        }

        // Make room if needed
        while self.should_evict(size_bytes) {
            self.evict_one();
        }

        // Insert new entry
        self.current_size_bytes += size_bytes;
        self.entries.insert(key.clone(), entry);
        self.track_insertion(key);

        self.update_stats();
    }

    /// Retrieves an item from the cache.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.cleanup_expired();

        // Check if key exists and is not expired
        let exists_and_valid = self
            .entries
            .get(key)
            .map(|entry| !entry.is_expired())
            .unwrap_or(false);

        if !exists_and_valid {
            if self.config.enable_stats {
                self.stats.misses += 1;
            }
            return None;
        }

        // Track access before getting the entry
        self.track_access(key);

        // Now touch and return
        if let Some(entry) = self.entries.get_mut(key) {
            entry.touch();

            if self.config.enable_stats {
                self.stats.hits += 1;
            }

            Some(&entry.value)
        } else {
            None
        }
    }

    /// Retrieves a mutable reference to an item.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.cleanup_expired();

        // Check if key exists and is not expired
        let exists_and_valid = self
            .entries
            .get(key)
            .map(|entry| !entry.is_expired())
            .unwrap_or(false);

        if !exists_and_valid {
            if self.config.enable_stats {
                self.stats.misses += 1;
            }
            return None;
        }

        // Track access before getting the mutable entry
        self.track_access(key);

        // Now touch and return mutable reference
        if let Some(entry) = self.entries.get_mut(key) {
            entry.touch();

            if self.config.enable_stats {
                self.stats.hits += 1;
            }

            Some(&mut entry.value)
        } else {
            None
        }
    }

    /// Checks if a key exists in the cache without updating access stats.
    pub fn contains_key(&self, key: &K) -> bool {
        if let Some(entry) = self.entries.get(key) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Removes an item from the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size_bytes -= entry.size_bytes;
            self.remove_from_tracking(key);
            self.update_stats();
            Some(entry.value)
        } else {
            None
        }
    }

    /// Clears all items from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.insertion_order.clear();
        self.current_size_bytes = 0;
        self.update_stats();
    }

    /// Returns the number of items in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Checks if eviction is needed.
    fn should_evict(&self, incoming_size: usize) -> bool {
        if self.config.eviction_policy == EvictionPolicy::TTLOnly {
            return false;
        }

        let would_exceed_count = self.entries.len() >= self.config.max_items;
        let would_exceed_size = if self.config.max_size_bytes > 0 {
            self.current_size_bytes + incoming_size > self.config.max_size_bytes
        } else {
            false
        };

        would_exceed_count || would_exceed_size
    }

    /// Evicts one item based on the eviction policy.
    fn evict_one(&mut self) {
        let key_to_evict = match self.config.eviction_policy {
            EvictionPolicy::LRU => self.find_lru_key(),
            EvictionPolicy::LFU => self.find_lfu_key(),
            EvictionPolicy::FIFO => self.find_fifo_key(),
            EvictionPolicy::TTLOnly => return,
        };

        if let Some(key) = key_to_evict {
            self.remove(&key);
            if self.config.enable_stats {
                self.stats.evictions += 1;
            }
        }
    }

    /// Finds the least recently used key.
    fn find_lru_key(&self) -> Option<K> {
        self.access_order.front().cloned()
    }

    /// Finds the least frequently used key.
    fn find_lfu_key(&self) -> Option<K> {
        self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.access_count)
            .map(|(key, _)| key.clone())
    }

    /// Finds the first inserted key (oldest).
    fn find_fifo_key(&self) -> Option<K> {
        self.insertion_order.front().cloned()
    }

    /// Tracks access for LRU policy.
    fn track_access(&mut self, key: &K) {
        if self.config.eviction_policy == EvictionPolicy::LRU {
            // Move to back (most recently used)
            self.access_order.retain(|k| k != key);
            self.access_order.push_back(key.clone());
        }
    }

    /// Tracks insertion for FIFO and LRU policies.
    fn track_insertion(&mut self, key: K) {
        match self.config.eviction_policy {
            EvictionPolicy::FIFO => {
                self.insertion_order.push_back(key);
            }
            EvictionPolicy::LRU => {
                self.access_order.push_back(key);
            }
            _ => {}
        }
    }

    /// Removes key from tracking structures.
    fn remove_from_tracking(&mut self, key: &K) {
        self.access_order.retain(|k| k != key);
        self.insertion_order.retain(|k| k != key);
    }

    /// Removes expired entries.
    fn cleanup_expired(&mut self) {
        let expired_keys: Vec<K> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            self.remove(&key);
            if self.config.enable_stats {
                self.stats.expirations += 1;
            }
        }
    }

    /// Updates cache statistics.
    fn update_stats(&mut self) {
        self.stats.item_count = self.entries.len();
        self.stats.total_size_bytes = self.current_size_bytes;
    }
}

impl<K, V> Default for Cache<K, V>
where
    K: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    #[test]
    fn test_cache_new() {
        let cache: Cache<String, String> = Cache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"key1".to_string()), Some(&"value1".to_string()));
    }

    #[test]
    fn test_cache_miss() {
        let mut cache: Cache<String, String> = Cache::new();
        assert_eq!(cache.get(&"nonexistent".to_string()), None);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn test_cache_hit() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        let _ = cache.get(&"key1".to_string());

        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_hit_rate() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        let _ = cache.get(&"key1".to_string()); // Hit
        let _ = cache.get(&"key2".to_string()); // Miss
        let _ = cache.get(&"key1".to_string()); // Hit

        let hit_rate = cache.stats().hit_rate();
        assert!((hit_rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_ttl_expiration() {
        let mut cache = Cache::new();
        cache.insert(
            "key1".to_string(),
            "value1".to_string(),
            10,
            Some(Duration::from_millis(50)),
        );

        assert!(cache.get(&"key1".to_string()).is_some());

        std::thread::sleep(Duration::from_millis(60));
        assert!(cache.get(&"key1".to_string()).is_none());
        assert_eq!(cache.stats().expirations, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let mut config = CacheConfig::default();
        config.max_items = 3;
        config.eviction_policy = EvictionPolicy::LRU;
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);
        cache.insert("key3".to_string(), "value3".to_string(), 10, None);

        // Access key1 to make it recently used
        let _ = cache.get(&"key1".to_string());

        // Insert key4, should evict key2 (least recently used)
        cache.insert("key4".to_string(), "value4".to_string(), 10, None);

        assert!(cache.contains_key(&"key1".to_string()));
        assert!(!cache.contains_key(&"key2".to_string()));
        assert!(cache.contains_key(&"key3".to_string()));
        assert!(cache.contains_key(&"key4".to_string()));
    }

    #[test]
    fn test_lfu_eviction() {
        let mut config = CacheConfig::default();
        config.max_items = 3;
        config.eviction_policy = EvictionPolicy::LFU;
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);
        cache.insert("key3".to_string(), "value3".to_string(), 10, None);

        // Access key1 multiple times
        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key1".to_string());

        // Insert key4, should evict key2 or key3 (least frequently used)
        cache.insert("key4".to_string(), "value4".to_string(), 10, None);

        assert!(cache.contains_key(&"key1".to_string())); // Most frequently used
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_fifo_eviction() {
        let mut config = CacheConfig::default();
        config.max_items = 3;
        config.eviction_policy = EvictionPolicy::FIFO;
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);
        cache.insert("key3".to_string(), "value3".to_string(), 10, None);

        // Access key1 (shouldn't affect FIFO)
        let _ = cache.get(&"key1".to_string());

        // Insert key4, should evict key1 (first in)
        cache.insert("key4".to_string(), "value4".to_string(), 10, None);

        assert!(!cache.contains_key(&"key1".to_string()));
        assert!(cache.contains_key(&"key2".to_string()));
        assert!(cache.contains_key(&"key3".to_string()));
        assert!(cache.contains_key(&"key4".to_string()));
    }

    #[test]
    fn test_size_based_eviction() {
        let mut config = CacheConfig::default();
        config.max_size_bytes = 50;
        config.eviction_policy = EvictionPolicy::LRU;
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 20, None);
        cache.insert("key2".to_string(), "value2".to_string(), 20, None);

        // This should trigger eviction due to size
        cache.insert("key3".to_string(), "value3".to_string(), 20, None);

        assert_eq!(cache.len(), 2);
        assert!(cache.stats().total_size_bytes <= 50);
    }

    #[test]
    fn test_remove() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        let removed = cache.remove(&"key1".to_string());
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.stats().total_size_bytes, 0);
    }

    #[test]
    fn test_contains_key() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        assert!(cache.contains_key(&"key1".to_string()));
        assert!(!cache.contains_key(&"key2".to_string()));
    }

    #[test]
    fn test_get_mut() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        if let Some(value) = cache.get_mut(&"key1".to_string()) {
            *value = "modified".to_string();
        }

        assert_eq!(
            cache.get(&"key1".to_string()),
            Some(&"modified".to_string())
        );
    }

    #[test]
    fn test_update_existing_key() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key1".to_string(), "value2".to_string(), 15, None);

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"key1".to_string()), Some(&"value2".to_string()));
        assert_eq!(cache.stats().total_size_bytes, 15);
    }

    #[test]
    fn test_stats_tracking() {
        let mut cache = Cache::new();

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        let _ = cache.get(&"key1".to_string()); // Hit
        let _ = cache.get(&"key2".to_string()); // Miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.item_count, 1);
        assert_eq!(stats.total_size_bytes, 10);
    }

    #[test]
    fn test_ttl_only_policy() {
        let mut config = CacheConfig::default();
        config.eviction_policy = EvictionPolicy::TTLOnly;
        config.max_items = 2; // This should be ignored
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);
        cache.insert("key3".to_string(), "value3".to_string(), 10, None);

        // All items should be present (no eviction)
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_access_count() {
        let mut cache = Cache::new();
        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        let _ = cache.get(&"key1".to_string());
        let _ = cache.get(&"key1".to_string());

        if let Some(entry) = cache.entries.get("key1") {
            assert_eq!(entry.access_count, 3); // 1 insert + 2 gets
        }
    }

    #[test]
    fn test_eviction_stats() {
        let mut config = CacheConfig::default();
        config.max_items = 2;
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);
        cache.insert("key2".to_string(), "value2".to_string(), 10, None);
        cache.insert("key3".to_string(), "value3".to_string(), 10, None);

        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_default_ttl() {
        let mut config = CacheConfig::default();
        config.default_ttl = Some(Duration::from_millis(50));
        let mut cache = Cache::with_config(config);

        cache.insert("key1".to_string(), "value1".to_string(), 10, None);

        std::thread::sleep(Duration::from_millis(60));
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_override_default_ttl() {
        let mut config = CacheConfig::default();
        config.default_ttl = Some(Duration::from_millis(50));
        let mut cache = Cache::with_config(config);

        // Override with longer TTL
        cache.insert(
            "key1".to_string(),
            "value1".to_string(),
            10,
            Some(Duration::from_secs(10)),
        );

        std::thread::sleep(Duration::from_millis(60));
        assert!(cache.get(&"key1".to_string()).is_some());
    }
}
