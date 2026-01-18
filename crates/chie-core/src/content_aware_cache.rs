//! Content-aware cache sizing with intelligent memory management.
//!
//! This module provides adaptive cache sizing based on content characteristics,
//! access patterns, and system resource availability.
//!
//! # Example
//!
//! ```
//! use chie_core::content_aware_cache::{ContentAwareCache, CacheContentMetrics, ContentType};
//!
//! # fn example() {
//! let mut cache = ContentAwareCache::new(100 * 1024 * 1024); // 100MB
//!
//! // Add content with metrics
//! let metrics = CacheContentMetrics {
//!     content_type: ContentType::VideoChunk,
//!     size_bytes: 256 * 1024,
//!     access_frequency: 10,
//!     priority: 5,
//! };
//!
//! cache.insert("video:chunk1".to_string(), vec![0u8; 256 * 1024], metrics);
//!
//! // Cache automatically adjusts size based on content characteristics
//! println!("Current cache size: {} bytes", cache.current_size());
//! # }
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Maximum number of historical access records to keep.
const MAX_ACCESS_HISTORY: usize = 1000;

/// Content type classification for cache sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// Small metadata entries.
    Metadata,
    /// Image chunks.
    ImageChunk,
    /// Video chunks.
    VideoChunk,
    /// Audio chunks.
    AudioChunk,
    /// Document chunks.
    DocumentChunk,
    /// Generic data.
    Generic,
}

impl ContentType {
    /// Get the base priority weight for this content type.
    #[must_use]
    #[inline]
    pub const fn priority_weight(&self) -> f64 {
        match self {
            Self::Metadata => 2.0, // Metadata is small and important
            Self::ImageChunk => 1.2,
            Self::VideoChunk => 1.0,
            Self::AudioChunk => 1.1,
            Self::DocumentChunk => 1.3,
            Self::Generic => 1.0,
        }
    }

    /// Get the ideal cache retention multiplier for this type.
    #[must_use]
    #[inline]
    pub const fn retention_multiplier(&self) -> f64 {
        match self {
            Self::Metadata => 3.0, // Keep metadata longer
            Self::ImageChunk => 1.5,
            Self::VideoChunk => 1.0,
            Self::AudioChunk => 1.2,
            Self::DocumentChunk => 1.8,
            Self::Generic => 1.0,
        }
    }
}

/// Metrics for content-aware caching decisions.
#[derive(Debug, Clone)]
pub struct CacheContentMetrics {
    /// Type of content.
    pub content_type: ContentType,
    /// Size in bytes.
    pub size_bytes: usize,
    /// Access frequency (accesses per time unit).
    pub access_frequency: u32,
    /// Manual priority (0-10, higher is more important).
    pub priority: u8,
}

/// Cached entry with metadata.
#[derive(Debug)]
struct CacheEntry {
    data: Vec<u8>,
    metrics: CacheContentMetrics,
    access_count: u64,
    last_access: Instant,
    inserted_at: Instant,
    hit_rate: f64,
}

impl CacheEntry {
    fn new(data: Vec<u8>, metrics: CacheContentMetrics) -> Self {
        Self {
            data,
            metrics,
            access_count: 0,
            last_access: Instant::now(),
            inserted_at: Instant::now(),
            hit_rate: 0.0,
        }
    }

    fn access(&mut self) {
        self.access_count += 1;
        self.last_access = Instant::now();

        // Update hit rate (exponential moving average)
        let time_since_insert = self.inserted_at.elapsed().as_secs_f64().max(1.0);
        self.hit_rate = self.access_count as f64 / time_since_insert;
    }

    /// Calculate the value score for this entry (higher = more valuable).
    fn value_score(&self) -> f64 {
        let type_weight = self.metrics.content_type.priority_weight();
        let priority_weight = (self.metrics.priority as f64 / 10.0) * 2.0;
        let recency_weight = {
            let seconds_since_access = self.last_access.elapsed().as_secs_f64();
            1.0 / (1.0 + seconds_since_access / 3600.0) // Decay over hours
        };
        let hit_rate_weight = self.hit_rate.min(10.0) / 10.0;
        let size_penalty = 1.0 / (1.0 + (self.metrics.size_bytes as f64 / 1024.0 / 1024.0));

        (type_weight + priority_weight + recency_weight + hit_rate_weight) * size_penalty
    }
}

/// Access history record for adaptive sizing.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AccessRecord {
    timestamp: u64,
    hit: bool,
    content_type: ContentType,
}

/// Content-aware cache with intelligent sizing.
pub struct ContentAwareCache {
    entries: HashMap<String, CacheEntry>,
    max_size_bytes: usize,
    current_size_bytes: usize,
    access_history: VecDeque<AccessRecord>,
    total_accesses: u64,
    total_hits: u64,
    size_per_type: HashMap<ContentType, usize>,
}

impl ContentAwareCache {
    /// Create a new content-aware cache with a maximum size.
    #[must_use]
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size_bytes,
            current_size_bytes: 0,
            access_history: VecDeque::with_capacity(MAX_ACCESS_HISTORY),
            total_accesses: 0,
            total_hits: 0,
            size_per_type: HashMap::new(),
        }
    }

    /// Insert content into the cache.
    pub fn insert(&mut self, key: String, data: Vec<u8>, metrics: CacheContentMetrics) {
        let size = data.len();

        // Remove old entry if exists
        if let Some(old_entry) = self.entries.remove(&key) {
            self.current_size_bytes -= old_entry.data.len();
            *self
                .size_per_type
                .entry(old_entry.metrics.content_type)
                .or_insert(0) -= old_entry.data.len();
        }

        // Evict entries if necessary
        while self.current_size_bytes + size > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_lowest_value();
        }

        // Insert new entry
        if self.current_size_bytes + size <= self.max_size_bytes {
            self.current_size_bytes += size;
            *self.size_per_type.entry(metrics.content_type).or_insert(0) += size;
            self.entries.insert(key, CacheEntry::new(data, metrics));
        }
    }

    /// Get content from the cache (returns a clone).
    #[must_use]
    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        self.total_accesses += 1;

        let content_type = if let Some(entry) = self.entries.get(key) {
            entry.metrics.content_type
        } else {
            ContentType::Generic
        };

        if let Some(entry) = self.entries.get_mut(key) {
            entry.access();
            self.total_hits += 1;
            let data = entry.data.clone();
            self.record_access(true, content_type);
            Some(data)
        } else {
            self.record_access(false, content_type);
            None
        }
    }

    /// Remove content from the cache.
    #[must_use]
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size_bytes -= entry.data.len();
            *self
                .size_per_type
                .entry(entry.metrics.content_type)
                .or_insert(0) -= entry.data.len();
            Some(entry.data)
        } else {
            None
        }
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_size_bytes = 0;
        self.size_per_type.clear();
    }

    /// Evict the entry with the lowest value score.
    fn evict_lowest_value(&mut self) {
        let mut lowest_key: Option<String> = None;
        let mut lowest_score = f64::MAX;

        for (key, entry) in &self.entries {
            let score = entry.value_score();
            if score < lowest_score {
                lowest_score = score;
                lowest_key = Some(key.clone());
            }
        }

        if let Some(key) = lowest_key {
            let _ = self.remove(&key);
        }
    }

    /// Record an access for adaptive sizing.
    fn record_access(&mut self, hit: bool, content_type: ContentType) {
        if self.access_history.len() >= MAX_ACCESS_HISTORY {
            self.access_history.pop_front();
        }

        self.access_history.push_back(AccessRecord {
            timestamp: current_timestamp(),
            hit,
            content_type,
        });
    }

    /// Get the current cache size in bytes.
    #[must_use]
    #[inline]
    pub const fn current_size(&self) -> usize {
        self.current_size_bytes
    }

    /// Get the maximum cache size in bytes.
    #[must_use]
    #[inline]
    pub const fn max_size(&self) -> usize {
        self.max_size_bytes
    }

    /// Get the cache hit rate.
    #[must_use]
    #[inline]
    pub fn hit_rate(&self) -> f64 {
        if self.total_accesses == 0 {
            0.0
        } else {
            self.total_hits as f64 / self.total_accesses as f64
        }
    }

    /// Get the number of entries in the cache.
    #[must_use]
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get cache usage percentage.
    #[must_use]
    #[inline]
    pub fn usage_percentage(&self) -> f64 {
        (self.current_size_bytes as f64 / self.max_size_bytes as f64) * 100.0
    }

    /// Get size allocated to each content type.
    #[must_use]
    #[inline]
    pub fn size_by_type(&self, content_type: ContentType) -> usize {
        *self.size_per_type.get(&content_type).unwrap_or(&0)
    }

    /// Adjust cache size dynamically based on performance.
    pub fn adjust_size(&mut self, new_max_size: usize) {
        self.max_size_bytes = new_max_size;

        // Evict entries if new size is smaller
        while self.current_size_bytes > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_lowest_value();
        }
    }

    /// Get recommended cache size based on access patterns.
    #[must_use]
    pub fn recommended_size(&self) -> usize {
        if self.access_history.is_empty() {
            return self.max_size_bytes;
        }

        let hit_rate = self.hit_rate();

        // If hit rate is high, current size is good
        // If hit rate is low, recommend increase
        let multiplier = if hit_rate > 0.8 {
            1.0 // Good hit rate
        } else if hit_rate > 0.6 {
            1.2 // Could be better
        } else if hit_rate > 0.4 {
            1.5 // Needs more space
        } else {
            2.0 // Very low hit rate
        };

        let recommended = (self.current_size_bytes as f64 * multiplier) as usize;
        recommended.min(self.max_size_bytes * 2) // Cap at 2x current max
    }

    /// Get cache statistics.
    #[must_use]
    pub fn stats(&self) -> ContentCacheStats {
        ContentCacheStats {
            total_accesses: self.total_accesses,
            total_hits: self.total_hits,
            hit_rate: self.hit_rate(),
            current_size_bytes: self.current_size_bytes,
            max_size_bytes: self.max_size_bytes,
            entry_count: self.entries.len(),
            usage_percentage: self.usage_percentage(),
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct ContentCacheStats {
    /// Total cache accesses.
    pub total_accesses: u64,
    /// Total cache hits.
    pub total_hits: u64,
    /// Current hit rate.
    pub hit_rate: f64,
    /// Current cache size in bytes.
    pub current_size_bytes: usize,
    /// Maximum cache size in bytes.
    pub max_size_bytes: usize,
    /// Number of entries.
    pub entry_count: usize,
    /// Cache usage percentage.
    pub usage_percentage: f64,
}

/// Get current Unix timestamp.
#[inline]
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_insert_and_get() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 8,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics);
        assert_eq!(cache.current_size(), 100);

        let data = cache.get("key1");
        assert!(data.is_some());
        assert_eq!(data.unwrap().len(), 100);
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = ContentAwareCache::new(200);

        let metrics1 = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 10,
            priority: 9,
        };

        let metrics2 = CacheContentMetrics {
            content_type: ContentType::Generic,
            size_bytes: 100,
            access_frequency: 1,
            priority: 1,
        };

        cache.insert("high_value".to_string(), vec![1u8; 100], metrics1);
        cache.insert("low_value".to_string(), vec![2u8; 100], metrics2);

        // Cache is full, insert another entry
        let metrics3 = CacheContentMetrics {
            content_type: ContentType::VideoChunk,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("medium_value".to_string(), vec![3u8; 100], metrics3);

        // Low value entry should be evicted
        assert!(cache.get("low_value").is_none());
        assert!(cache.get("high_value").is_some());
    }

    #[test]
    fn test_hit_rate_calculation() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics);

        // 3 hits, 2 misses
        let _ = cache.get("key1");
        let _ = cache.get("key1");
        let _ = cache.get("key1");
        let _ = cache.get("key2");
        let _ = cache.get("key3");

        assert!((cache.hit_rate() - 0.6).abs() < 0.01);
    }

    #[test]
    fn test_content_type_priority() {
        let weight_metadata = ContentType::Metadata.priority_weight();
        let weight_generic = ContentType::Generic.priority_weight();

        assert!(weight_metadata > weight_generic);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics.clone());
        cache.insert("key2".to_string(), vec![2u8; 100], metrics);

        assert_eq!(cache.entry_count(), 2);

        cache.clear();

        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.current_size(), 0);
    }

    #[test]
    fn test_dynamic_resize() {
        let mut cache = ContentAwareCache::new(300);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics.clone());
        cache.insert("key2".to_string(), vec![2u8; 100], metrics.clone());
        cache.insert("key3".to_string(), vec![3u8; 100], metrics);

        assert_eq!(cache.entry_count(), 3);

        // Shrink cache
        cache.adjust_size(150);

        // Should evict some entries
        assert!(cache.entry_count() < 3);
        assert!(cache.current_size() <= 150);
    }

    #[test]
    fn test_size_by_type() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics_meta = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        let metrics_video = CacheContentMetrics {
            content_type: ContentType::VideoChunk,
            size_bytes: 200,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("meta1".to_string(), vec![1u8; 100], metrics_meta);
        cache.insert("video1".to_string(), vec![2u8; 200], metrics_video);

        assert_eq!(cache.size_by_type(ContentType::Metadata), 100);
        assert_eq!(cache.size_by_type(ContentType::VideoChunk), 200);
    }

    #[test]
    fn test_usage_percentage() {
        let mut cache = ContentAwareCache::new(1000);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 250,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 250], metrics);

        assert!((cache.usage_percentage() - 25.0).abs() < 0.1);
    }

    #[test]
    fn test_remove() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics);
        assert_eq!(cache.current_size(), 100);

        let removed = cache.remove("key1");
        assert!(removed.is_some());
        assert_eq!(cache.current_size(), 0);
    }

    #[test]
    fn test_stats() {
        let mut cache = ContentAwareCache::new(1024);

        let metrics = CacheContentMetrics {
            content_type: ContentType::Metadata,
            size_bytes: 100,
            access_frequency: 5,
            priority: 5,
        };

        cache.insert("key1".to_string(), vec![1u8; 100], metrics);
        let _ = cache.get("key1");
        let _ = cache.get("key2");

        let stats = cache.stats();
        assert_eq!(stats.total_accesses, 2);
        assert_eq!(stats.total_hits, 1);
        assert_eq!(stats.entry_count, 1);
    }
}
