//! Advanced caching utilities with TTL and memory management.
//!
//! This module provides caching structures with time-to-live (TTL) support,
//! automatic eviction, and memory management for efficient data caching.
//!
//! # Examples
//!
//! ```
//! use chie_core::cache::TtlCache;
//! use std::time::Duration;
//!
//! let mut cache = TtlCache::new(100, Duration::from_secs(60));
//!
//! // Insert with TTL
//! cache.insert("key1".to_string(), "value1".to_string());
//!
//! // Retrieve (returns cloned value)
//! assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
//!
//! // Entry expires after TTL
//! std::thread::sleep(Duration::from_millis(100));
//! // Still valid within TTL
//! assert!(cache.get(&"key1".to_string()).is_some());
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Cache entry with expiration time.
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
    last_accessed: Instant,
    access_count: u64,
}

impl<V> CacheEntry<V> {
    #[inline]
    fn new(value: V) -> Self {
        let now = Instant::now();
        Self {
            value,
            inserted_at: now,
            last_accessed: now,
            access_count: 0,
        }
    }

    #[inline]
    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() > ttl
    }

    #[inline]
    fn access(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }
}

/// Time-to-live cache with automatic expiration.
pub struct TtlCache<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
    max_capacity: usize,
    ttl: Duration,
    hits: u64,
    misses: u64,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    /// Create a new TTL cache.
    ///
    /// # Arguments
    /// * `max_capacity` - Maximum number of entries
    /// * `ttl` - Time-to-live for entries
    #[must_use]
    #[inline]
    pub fn new(max_capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_capacity),
            max_capacity,
            ttl,
            hits: 0,
            misses: 0,
        }
    }

    /// Insert a value into the cache.
    #[inline]
    pub fn insert(&mut self, key: K, value: V) {
        // Evict if at capacity
        if self.entries.len() >= self.max_capacity && !self.entries.contains_key(&key) {
            self.evict_one();
        }

        self.entries.insert(key, CacheEntry::new(value));
    }

    /// Get a value from the cache (returns cloned value).
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<V> {
        // Clean expired entries periodically
        if self.entries.len() > 10 && self.hits % 100 == 0 {
            self.cleanup_expired();
        }

        // Check if entry exists and is not expired
        let is_expired = match self.entries.get(key) {
            Some(entry) => entry.is_expired(self.ttl),
            None => {
                self.misses += 1;
                return None;
            }
        };

        if is_expired {
            // Entry expired
            self.entries.remove(key);
            self.misses += 1;
            None
        } else {
            // Update access time and return cloned value
            if let Some(entry) = self.entries.get_mut(key) {
                entry.access();
                self.hits += 1;
                Some(entry.value.clone())
            } else {
                self.misses += 1;
                None
            }
        }
    }

    /// Check if a key exists and is not expired.
    #[must_use]
    #[inline]
    pub fn contains_key(&mut self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Remove a key from the cache.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|e| e.value)
    }

    /// Clear all entries.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Get current cache size.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get cache hit rate.
    #[must_use]
    #[inline]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Get statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.entries.len(),
            capacity: self.max_capacity,
            hits: self.hits,
            misses: self.misses,
            hit_rate: self.hit_rate(),
        }
    }

    /// Remove expired entries.
    fn cleanup_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired(self.ttl));
    }

    /// Evict one entry (least recently used).
    fn evict_one(&mut self) {
        if let Some(lru_key) = self.find_lru_key() {
            self.entries.remove(&lru_key);
        }
    }

    /// Find the least recently used key.
    fn find_lru_key(&self) -> Option<K> {
        self.entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(k, _)| k.clone())
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries.
    pub size: usize,
    /// Maximum capacity.
    pub capacity: usize,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Hit rate (0.0 to 1.0).
    pub hit_rate: f64,
}

/// Two-level cache with L1 (fast, small) and L2 (larger).
pub struct TieredCache<K, V> {
    l1: TtlCache<K, V>,
    l2: TtlCache<K, V>,
}

impl<K: Eq + Hash + Clone, V: Clone> TieredCache<K, V> {
    /// Create a new tiered cache.
    ///
    /// # Arguments
    /// * `l1_capacity` - L1 cache capacity (fast)
    /// * `l2_capacity` - L2 cache capacity (slower but larger)
    /// * `ttl` - Time-to-live for entries
    #[must_use]
    #[inline]
    pub fn new(l1_capacity: usize, l2_capacity: usize, ttl: Duration) -> Self {
        Self {
            l1: TtlCache::new(l1_capacity, ttl),
            l2: TtlCache::new(l2_capacity, ttl),
        }
    }

    /// Insert a value into the cache (goes to L1).
    #[inline]
    pub fn insert(&mut self, key: K, value: V) {
        self.l1.insert(key, value);
    }

    /// Get a value from the cache (checks L1, then L2).
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<V> {
        // Try L1 first
        if let Some(value) = self.l1.get(key) {
            return Some(value.clone());
        }

        // Try L2 and promote to L1 if found
        if let Some(value) = self.l2.get(key) {
            let value_clone = value.clone();
            self.l1.insert(key.clone(), value_clone.clone());
            return Some(value_clone);
        }

        None
    }

    /// Clear both cache levels.
    pub fn clear(&mut self) {
        self.l1.clear();
        self.l2.clear();
    }

    /// Get combined statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> (CacheStats, CacheStats) {
        (self.l1.stats(), self.l2.stats())
    }
}

/// Cache with size-based eviction (for byte-counted values).
pub struct SizedCache<K> {
    entries: HashMap<K, (Vec<u8>, Instant)>,
    current_size: usize,
    max_size: usize,
    ttl: Duration,
}

impl<K: Eq + Hash + Clone> SizedCache<K> {
    /// Create a new size-based cache.
    #[must_use]
    #[inline]
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            current_size: 0,
            max_size,
            ttl,
        }
    }

    /// Insert data into the cache.
    #[inline]
    pub fn insert(&mut self, key: K, data: Vec<u8>) {
        let size = data.len();

        // Evict until we have space
        while self.current_size + size > self.max_size && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // Don't insert if single item is larger than max size
        if size > self.max_size {
            return;
        }

        // Remove old entry if updating
        if let Some((old_data, _)) = self.entries.remove(&key) {
            self.current_size -= old_data.len();
        }

        self.entries.insert(key, (data, Instant::now()));
        self.current_size += size;
    }

    /// Get data from the cache.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<Vec<u8>> {
        self.cleanup_expired();

        // Check if key exists and is not expired
        let is_expired = match self.entries.get(key) {
            Some((_, inserted_at)) => inserted_at.elapsed() >= self.ttl,
            None => return None,
        };

        if is_expired {
            // Remove expired entry
            if let Some((data, _)) = self.entries.remove(key) {
                self.current_size -= data.len();
            }
            None
        } else {
            // Return cloned data
            self.entries.get(key).map(|(data, _)| data.clone())
        }
    }

    /// Get current size in bytes.
    #[must_use]
    #[inline]
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Clear the cache.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_size = 0;
    }

    fn cleanup_expired(&mut self) {
        let ttl = self.ttl;
        let mut removed_size = 0;

        self.entries.retain(|_, (data, inserted_at)| {
            if inserted_at.elapsed() >= ttl {
                removed_size += data.len();
                false
            } else {
                true
            }
        });

        self.current_size -= removed_size;
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.find_oldest_key() {
            if let Some((data, _)) = self.entries.remove(&oldest_key) {
                self.current_size -= data.len();
            }
        }
    }

    fn find_oldest_key(&self) -> Option<K> {
        self.entries
            .iter()
            .min_by_key(|(_, (_, inserted_at))| inserted_at)
            .map(|(k, _)| k.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_ttl_cache_basic() {
        let mut cache = TtlCache::new(10, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_ttl_cache_expiration() {
        let mut cache = TtlCache::new(10, Duration::from_millis(50));

        cache.insert("key1".to_string(), "value1".to_string());
        assert!(cache.get(&"key1".to_string()).is_some());

        thread::sleep(Duration::from_millis(100));
        assert!(cache.get(&"key1".to_string()).is_none());
    }

    #[test]
    fn test_ttl_cache_eviction() {
        let mut cache = TtlCache::new(3, Duration::from_secs(60));

        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");

        // Access key 1 to make it recently used
        cache.get(&1);

        thread::sleep(Duration::from_millis(10));

        // Insert 4th item, should evict LRU (key 2)
        cache.insert(4, "d");

        assert!(cache.get(&1).is_some());
        assert!(cache.get(&2).is_none()); // Evicted
        assert!(cache.get(&3).is_some());
        assert!(cache.get(&4).is_some());
    }

    #[test]
    fn test_ttl_cache_stats() {
        let mut cache = TtlCache::new(10, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());

        cache.get(&"key1".to_string()); // Hit
        cache.get(&"key2".to_string()); // Miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 0.5);
    }

    #[test]
    fn test_tiered_cache() {
        let mut cache = TieredCache::new(2, 5, Duration::from_secs(60));

        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());

        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
    }

    #[test]
    fn test_sized_cache() {
        let mut cache = SizedCache::new(100, Duration::from_secs(60));

        cache.insert("key1", vec![1u8; 40]);
        cache.insert("key2", vec![2u8; 40]);

        assert_eq!(cache.current_size(), 80);

        // This should evict key1
        cache.insert("key3", vec![3u8; 40]);

        assert!(cache.get(&"key1").is_none());
        assert_eq!(cache.get(&"key2"), Some(vec![2u8; 40]));
        assert_eq!(cache.get(&"key3"), Some(vec![3u8; 40]));
    }

    #[test]
    fn test_sized_cache_expiration() {
        let mut cache = SizedCache::new(100, Duration::from_millis(50));

        cache.insert("key1", vec![1u8; 40]);
        assert_eq!(cache.get(&"key1"), Some(vec![1u8; 40]));

        thread::sleep(Duration::from_millis(100));
        assert!(cache.get(&"key1").is_none());
        assert_eq!(cache.current_size(), 0);
    }
}
