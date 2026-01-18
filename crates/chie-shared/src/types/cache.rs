//! Cache-related types for CHIE Protocol.
//!
//! This module provides shared types for cache statistics and metrics
//! that can be used across different caching implementations.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cache statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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

impl CacheStats {
    /// Create new cache statistics.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::cache::CacheStats;
    ///
    /// let stats = CacheStats::new(750, 1000, 8500, 1500);
    ///
    /// assert_eq!(stats.size, 750);
    /// assert_eq!(stats.capacity, 1000);
    /// assert_eq!(stats.hits, 8500);
    /// assert_eq!(stats.misses, 1500);
    /// assert_eq!(stats.hit_rate, 0.85);
    /// assert_eq!(stats.total_requests(), 10000);
    /// assert!((stats.miss_rate() - 0.15).abs() < 1e-10);
    /// assert_eq!(stats.fill_percentage(), 0.75);
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(size: usize, capacity: usize, hits: u64, misses: u64) -> Self {
        let hit_rate = if hits + misses > 0 {
            hits as f64 / (hits + misses) as f64
        } else {
            0.0
        };

        Self {
            size,
            capacity,
            hits,
            misses,
            hit_rate,
        }
    }

    /// Create empty cache statistics.
    #[must_use]
    pub fn empty(capacity: usize) -> Self {
        Self {
            size: 0,
            capacity,
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
        }
    }

    /// Check if cache is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.size >= self.capacity
    }

    /// Check if cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Get the fill percentage (0.0 to 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fill_percentage(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            self.size as f64 / self.capacity as f64
        }
    }

    /// Get total requests (hits + misses).
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.hits + self.misses
    }

    /// Get miss rate (0.0 to 1.0).
    #[must_use]
    pub fn miss_rate(&self) -> f64 {
        1.0 - self.hit_rate
    }

    /// Calculate efficiency score (0.0 to 100.0).
    ///
    /// Combines hit rate (70% weight) and capacity utilization (30% weight).
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::cache::CacheStats;
    ///
    /// // High efficiency: good hit rate and good utilization
    /// let stats1 = CacheStats::new(900, 1000, 9000, 1000);
    /// assert_eq!(stats1.efficiency_score(), 90.0 * 0.7 + 0.9 * 30.0);
    ///
    /// // Medium efficiency: good hit rate but low utilization
    /// let stats2 = CacheStats::new(300, 1000, 900, 100);
    /// assert_eq!(stats2.efficiency_score(), 0.9 * 70.0 + 0.3 * 30.0);
    ///
    /// // Low efficiency: poor hit rate
    /// let stats3 = CacheStats::new(500, 1000, 300, 700);
    /// assert_eq!(stats3.efficiency_score(), 0.3 * 70.0 + 0.5 * 30.0);
    /// ```
    #[must_use]
    pub fn efficiency_score(&self) -> f64 {
        let hit_score = self.hit_rate * 70.0; // 70% weight on hit rate
        let util_score = self.fill_percentage() * 30.0; // 30% weight on utilization
        hit_score + util_score
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::empty(0)
    }
}

/// Multi-level cache statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct TieredCacheStats {
    /// L1 cache statistics.
    pub l1_stats: CacheStats,
    /// L2 cache statistics.
    pub l2_stats: CacheStats,
    /// L1 to L2 promotion count.
    pub promotions: u64,
}

impl TieredCacheStats {
    /// Create new tiered cache statistics.
    #[must_use]
    pub fn new(l1_stats: CacheStats, l2_stats: CacheStats, promotions: u64) -> Self {
        Self {
            l1_stats,
            l2_stats,
            promotions,
        }
    }

    /// Get combined hit rate across both levels.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn combined_hit_rate(&self) -> f64 {
        let total_hits = self.l1_stats.hits + self.l2_stats.hits;
        let total_misses = self.l1_stats.misses + self.l2_stats.misses;
        let total = total_hits + total_misses;

        if total == 0 {
            0.0
        } else {
            total_hits as f64 / total as f64
        }
    }

    /// Get total size across both levels.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.l1_stats.size + self.l2_stats.size
    }

    /// Get total capacity across both levels.
    #[must_use]
    pub fn total_capacity(&self) -> usize {
        self.l1_stats.capacity + self.l2_stats.capacity
    }
}

/// Size-based cache statistics with byte tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SizedCacheStats {
    /// Number of entries.
    pub entry_count: usize,
    /// Current size in bytes.
    pub current_size_bytes: usize,
    /// Maximum size in bytes.
    pub max_size_bytes: usize,
    /// Total evictions.
    pub evictions: u64,
    /// Total insertions.
    pub insertions: u64,
}

impl SizedCacheStats {
    /// Create new sized cache statistics.
    #[must_use]
    pub fn new(
        entry_count: usize,
        current_size_bytes: usize,
        max_size_bytes: usize,
        evictions: u64,
        insertions: u64,
    ) -> Self {
        Self {
            entry_count,
            current_size_bytes,
            max_size_bytes,
            evictions,
            insertions,
        }
    }

    /// Get size utilization percentage (0.0 to 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self) -> f64 {
        if self.max_size_bytes == 0 {
            0.0
        } else {
            self.current_size_bytes as f64 / self.max_size_bytes as f64
        }
    }

    /// Get average entry size in bytes.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn avg_entry_size(&self) -> f64 {
        if self.entry_count == 0 {
            0.0
        } else {
            self.current_size_bytes as f64 / self.entry_count as f64
        }
    }

    /// Get eviction rate (evictions per insertion).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn eviction_rate(&self) -> f64 {
        if self.insertions == 0 {
            0.0
        } else {
            self.evictions as f64 / self.insertions as f64
        }
    }

    /// Check if cache is nearly full (>90% utilization).
    #[must_use]
    pub fn is_nearly_full(&self) -> bool {
        self.utilization() > 0.9
    }
}

impl Default for SizedCacheStats {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

/// Builder for CacheStats with fluent API.
#[derive(Debug, Default)]
pub struct CacheStatsBuilder {
    size: Option<usize>,
    capacity: Option<usize>,
    hits: Option<u64>,
    misses: Option<u64>,
}

impl CacheStatsBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current size.
    pub fn size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    /// Set the capacity.
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = Some(capacity);
        self
    }

    /// Set the hit count.
    pub fn hits(mut self, hits: u64) -> Self {
        self.hits = Some(hits);
        self
    }

    /// Set the miss count.
    pub fn misses(mut self, misses: u64) -> Self {
        self.misses = Some(misses);
        self
    }

    /// Build the CacheStats.
    pub fn build(self) -> CacheStats {
        CacheStats::new(
            self.size.unwrap_or(0),
            self.capacity.unwrap_or(0),
            self.hits.unwrap_or(0),
            self.misses.unwrap_or(0),
        )
    }
}

/// Builder for SizedCacheStats with fluent API.
#[derive(Debug, Default)]
pub struct SizedCacheStatsBuilder {
    entry_count: Option<usize>,
    current_size_bytes: Option<usize>,
    max_size_bytes: Option<usize>,
    evictions: Option<u64>,
    insertions: Option<u64>,
}

impl SizedCacheStatsBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the entry count.
    pub fn entry_count(mut self, count: usize) -> Self {
        self.entry_count = Some(count);
        self
    }

    /// Set the current size in bytes.
    pub fn current_size_bytes(mut self, size: usize) -> Self {
        self.current_size_bytes = Some(size);
        self
    }

    /// Set the maximum size in bytes.
    pub fn max_size_bytes(mut self, size: usize) -> Self {
        self.max_size_bytes = Some(size);
        self
    }

    /// Set the eviction count.
    pub fn evictions(mut self, evictions: u64) -> Self {
        self.evictions = Some(evictions);
        self
    }

    /// Set the insertion count.
    pub fn insertions(mut self, insertions: u64) -> Self {
        self.insertions = Some(insertions);
        self
    }

    /// Build the SizedCacheStats.
    pub fn build(self) -> SizedCacheStats {
        SizedCacheStats::new(
            self.entry_count.unwrap_or(0),
            self.current_size_bytes.unwrap_or(0),
            self.max_size_bytes.unwrap_or(0),
            self.evictions.unwrap_or(0),
            self.insertions.unwrap_or(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stats_new() {
        let stats = CacheStats::new(50, 100, 80, 20);
        assert_eq!(stats.size, 50);
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.hits, 80);
        assert_eq!(stats.misses, 20);
        assert_eq!(stats.hit_rate, 0.8);
    }

    #[test]
    fn test_cache_stats_empty() {
        let stats = CacheStats::empty(100);
        assert_eq!(stats.size, 0);
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.hit_rate, 0.0);
        assert!(stats.is_empty());
        assert!(!stats.is_full());
    }

    #[test]
    fn test_cache_stats_is_full() {
        let stats = CacheStats::new(100, 100, 0, 0);
        assert!(stats.is_full());

        let stats2 = CacheStats::new(99, 100, 0, 0);
        assert!(!stats2.is_full());
    }

    #[test]
    fn test_cache_stats_fill_percentage() {
        let stats = CacheStats::new(50, 100, 0, 0);
        assert_eq!(stats.fill_percentage(), 0.5);

        let stats2 = CacheStats::new(75, 100, 0, 0);
        assert_eq!(stats2.fill_percentage(), 0.75);
    }

    #[test]
    fn test_cache_stats_total_requests() {
        let stats = CacheStats::new(50, 100, 80, 20);
        assert_eq!(stats.total_requests(), 100);
    }

    #[test]
    fn test_cache_stats_miss_rate() {
        let stats = CacheStats::new(50, 100, 80, 20);
        assert!((stats.miss_rate() - 0.2).abs() < 0.0001);
    }

    #[test]
    fn test_cache_stats_efficiency_score() {
        let stats = CacheStats::new(50, 100, 80, 20);
        // Hit rate 0.8 * 70 + fill 0.5 * 30 = 56 + 15 = 71
        let expected = 0.8 * 70.0 + 0.5 * 30.0;
        assert!((stats.efficiency_score() - expected).abs() < 0.001);
    }

    #[test]
    fn test_tiered_cache_stats() {
        let l1 = CacheStats::new(10, 20, 80, 20);
        let l2 = CacheStats::new(50, 100, 40, 10);
        let tiered = TieredCacheStats::new(l1, l2, 5);

        assert_eq!(tiered.total_size(), 60);
        assert_eq!(tiered.total_capacity(), 120);
        assert_eq!(tiered.promotions, 5);

        // Combined hit rate: (80 + 40) / (80 + 20 + 40 + 10) = 120 / 150 = 0.8
        assert!((tiered.combined_hit_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_sized_cache_stats() {
        let stats = SizedCacheStats::new(100, 50_000, 100_000, 20, 120);

        assert_eq!(stats.entry_count, 100);
        assert_eq!(stats.current_size_bytes, 50_000);
        assert_eq!(stats.max_size_bytes, 100_000);
        assert_eq!(stats.utilization(), 0.5);
        assert_eq!(stats.avg_entry_size(), 500.0);
        assert!((stats.eviction_rate() - (20.0 / 120.0)).abs() < 0.001);
        assert!(!stats.is_nearly_full());
    }

    #[test]
    fn test_sized_cache_stats_nearly_full() {
        let stats = SizedCacheStats::new(100, 95_000, 100_000, 0, 100);
        assert!(stats.is_nearly_full());

        let stats2 = SizedCacheStats::new(100, 89_000, 100_000, 0, 100);
        assert!(!stats2.is_nearly_full());
    }

    #[test]
    fn test_cache_stats_serialization() {
        let stats = CacheStats::new(50, 100, 80, 20);
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: CacheStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_cache_stats_default() {
        let stats = CacheStats::default();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.capacity, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[test]
    fn test_cache_stats_builder() {
        let stats = CacheStatsBuilder::new()
            .size(50)
            .capacity(100)
            .hits(80)
            .misses(20)
            .build();

        assert_eq!(stats.size, 50);
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.hits, 80);
        assert_eq!(stats.misses, 20);
        assert_eq!(stats.hit_rate, 0.8);
    }

    #[test]
    fn test_cache_stats_builder_partial() {
        let stats = CacheStatsBuilder::new().capacity(100).hits(50).build();

        assert_eq!(stats.size, 0);
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.hits, 50);
    }

    #[test]
    fn test_sized_cache_stats_builder() {
        let stats = SizedCacheStatsBuilder::new()
            .entry_count(100)
            .current_size_bytes(50_000)
            .max_size_bytes(100_000)
            .evictions(20)
            .insertions(120)
            .build();

        assert_eq!(stats.entry_count, 100);
        assert_eq!(stats.current_size_bytes, 50_000);
        assert_eq!(stats.max_size_bytes, 100_000);
        assert_eq!(stats.evictions, 20);
        assert_eq!(stats.insertions, 120);
    }
}
