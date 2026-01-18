//! Chunk prefetching for improved performance.
//!
//! This module provides intelligent chunk prefetching that predicts
//! which chunks will be needed next and pre-loads them into memory.
//!
//! # Examples
//!
//! ```rust
//! use chie_core::prefetch::{ChunkPrefetcher, PrefetchConfig};
//!
//! # async fn example() {
//! let config = PrefetchConfig::default();
//! let prefetcher = ChunkPrefetcher::new(config);
//!
//! // Record access pattern (automatically predicts next chunks)
//! let predicted = prefetcher.record_access("QmContent123", 0).await;
//! println!("Predicted chunks after access 0: {:?}", predicted);
//!
//! let predicted = prefetcher.record_access("QmContent123", 1).await;
//! println!("Predicted chunks after access 1: {:?}", predicted);
//!
//! // Cache a chunk for faster retrieval
//! prefetcher.put_cached("QmContent123", 2, vec![1, 2, 3, 4]).await;
//!
//! // Retrieve from cache
//! if let Some(data) = prefetcher.get_cached("QmContent123", 2).await {
//!     println!("Retrieved {} bytes from cache", data.len());
//! }
//! # }
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};

/// Prefetch configuration.
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Maximum chunks to keep in cache.
    pub max_cached_chunks: usize,
    /// Number of chunks to prefetch ahead.
    pub prefetch_ahead: u64,
    /// Maximum memory for cache (bytes).
    pub max_cache_memory: usize,
    /// Cache entry TTL.
    pub cache_ttl: Duration,
    /// Enable sequential access prediction.
    pub enable_sequential_prediction: bool,
    /// Enable popularity-based prefetching.
    pub enable_popularity_prefetch: bool,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            max_cached_chunks: 100,
            prefetch_ahead: 3,
            max_cache_memory: 256 * 1024 * 1024, // 256 MB
            cache_ttl: Duration::from_secs(300), // 5 minutes
            enable_sequential_prediction: true,
            enable_popularity_prefetch: true,
        }
    }
}

/// Cached chunk entry.
#[derive(Debug, Clone)]
pub struct CachedChunk {
    /// Content CID.
    pub cid: String,
    /// Chunk index.
    pub chunk_index: u64,
    /// Chunk data.
    pub data: Vec<u8>,
    /// When this entry was cached.
    pub cached_at: Instant,
    /// Number of times accessed.
    pub access_count: u32,
}

impl CachedChunk {
    /// Check if this cache entry has expired.
    #[inline]
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    /// Get the size in bytes.
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Access pattern for prediction.
#[derive(Debug, Clone)]
struct AccessPattern {
    /// Last accessed chunk indices (ring buffer).
    recent_accesses: VecDeque<u64>,
    /// Detected pattern type.
    pattern_type: PatternType,
    /// Confidence in pattern detection.
    confidence: f64,
    /// Last access time.
    last_access: Instant,
}

impl Default for AccessPattern {
    fn default() -> Self {
        Self {
            recent_accesses: VecDeque::with_capacity(10),
            pattern_type: PatternType::Unknown,
            confidence: 0.0,
            last_access: Instant::now(),
        }
    }
}

/// Detected access pattern type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    /// Sequential access (chunk 0, 1, 2, 3...).
    Sequential,
    /// Reverse sequential (chunk N, N-1, N-2...).
    ReverseSequential,
    /// Strided access (chunk 0, 2, 4, 6...).
    Strided { stride: i64 },
    /// Random access.
    Random,
    /// Unknown pattern (not enough data).
    Unknown,
}

/// Cache key for identifying cached chunks.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    cid: String,
    chunk_index: u64,
}

/// Prefetch hint for external prefetch requests.
#[derive(Debug, Clone)]
pub struct PrefetchHint {
    /// Content CID to prefetch.
    pub cid: String,
    /// Chunk indices to prefetch.
    pub chunk_indices: Vec<u64>,
    /// Priority (higher = more urgent).
    pub priority: u8,
}

/// Chunk prefetcher for intelligent caching and prediction.
pub struct ChunkPrefetcher {
    config: PrefetchConfig,
    /// Cached chunks.
    cache: Arc<RwLock<HashMap<CacheKey, CachedChunk>>>,
    /// Access patterns per content.
    patterns: Arc<RwLock<HashMap<String, AccessPattern>>>,
    /// Current cache memory usage.
    cache_memory: Arc<RwLock<usize>>,
    /// Prefetch request channel.
    prefetch_tx: Option<mpsc::Sender<PrefetchHint>>,
    /// Cache statistics.
    stats: Arc<RwLock<PrefetchStats>>,
}

/// Prefetch statistics.
#[derive(Debug, Clone, Default)]
pub struct PrefetchStats {
    /// Total cache hits.
    pub cache_hits: u64,
    /// Total cache misses.
    pub cache_misses: u64,
    /// Total chunks prefetched.
    pub chunks_prefetched: u64,
    /// Successful predictions.
    pub successful_predictions: u64,
    /// Failed predictions.
    pub failed_predictions: u64,
    /// Current cache size (entries).
    pub cache_entries: usize,
    /// Current cache memory usage.
    pub cache_memory_bytes: usize,
}

impl PrefetchStats {
    /// Get cache hit rate.
    #[inline]
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }

    /// Get prediction accuracy.
    #[inline]
    #[must_use]
    pub fn prediction_accuracy(&self) -> f64 {
        let total = self.successful_predictions + self.failed_predictions;
        if total == 0 {
            0.0
        } else {
            self.successful_predictions as f64 / total as f64
        }
    }
}

impl ChunkPrefetcher {
    /// Create a new chunk prefetcher.
    #[inline]
    pub fn new(config: PrefetchConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            patterns: Arc::new(RwLock::new(HashMap::new())),
            cache_memory: Arc::new(RwLock::new(0)),
            prefetch_tx: None,
            stats: Arc::new(RwLock::new(PrefetchStats::default())),
        }
    }

    /// Set prefetch request channel for async prefetching.
    pub fn set_prefetch_channel(&mut self, tx: mpsc::Sender<PrefetchHint>) {
        self.prefetch_tx = Some(tx);
    }

    /// Try to get a chunk from cache.
    pub async fn get_cached(&self, cid: &str, chunk_index: u64) -> Option<Vec<u8>> {
        let key = CacheKey {
            cid: cid.to_string(),
            chunk_index,
        };

        let mut cache = self.cache.write().await;
        let mut stats = self.stats.write().await;

        if let Some(entry) = cache.get_mut(&key) {
            if entry.is_expired(self.config.cache_ttl) {
                // Entry expired, remove it
                let size = entry.size();
                cache.remove(&key);
                let mut mem = self.cache_memory.write().await;
                *mem = mem.saturating_sub(size);
                stats.cache_misses += 1;
                return None;
            }

            // Cache hit
            entry.access_count += 1;
            stats.cache_hits += 1;
            return Some(entry.data.clone());
        }

        stats.cache_misses += 1;
        None
    }

    /// Put a chunk into cache.
    pub async fn put_cached(&self, cid: &str, chunk_index: u64, data: Vec<u8>) {
        let key = CacheKey {
            cid: cid.to_string(),
            chunk_index,
        };

        let entry = CachedChunk {
            cid: cid.to_string(),
            chunk_index,
            data,
            cached_at: Instant::now(),
            access_count: 1,
        };

        let entry_size = entry.size();

        // Check memory limit
        {
            let mem = self.cache_memory.read().await;
            if *mem + entry_size > self.config.max_cache_memory {
                // Need to evict entries
                self.evict_entries(entry_size).await;
            }
        }

        // Add to cache
        let mut cache = self.cache.write().await;
        if cache.len() >= self.config.max_cached_chunks {
            self.evict_lru(&mut cache).await;
        }

        cache.insert(key, entry);

        let mut mem = self.cache_memory.write().await;
        *mem += entry_size;

        let mut stats = self.stats.write().await;
        stats.cache_entries = cache.len();
        stats.cache_memory_bytes = *mem;
    }

    /// Record an access and predict next chunks.
    pub async fn record_access(&self, cid: &str, chunk_index: u64) -> Vec<u64> {
        let mut patterns = self.patterns.write().await;
        let pattern = patterns
            .entry(cid.to_string())
            .or_insert_with(AccessPattern::default);

        // Add to recent accesses
        pattern.recent_accesses.push_back(chunk_index);
        if pattern.recent_accesses.len() > 10 {
            pattern.recent_accesses.pop_front();
        }
        pattern.last_access = Instant::now();

        // Detect pattern
        if pattern.recent_accesses.len() >= 3 {
            pattern.pattern_type = self.detect_pattern(&pattern.recent_accesses);
            pattern.confidence =
                self.calculate_confidence(&pattern.recent_accesses, pattern.pattern_type);
        }

        // Predict next chunks
        self.predict_next_chunks(chunk_index, pattern)
    }

    /// Request prefetch for predicted chunks.
    pub async fn request_prefetch(&self, cid: &str, chunk_indices: Vec<u64>) {
        if chunk_indices.is_empty() {
            return;
        }

        if let Some(tx) = &self.prefetch_tx {
            let hint = PrefetchHint {
                cid: cid.to_string(),
                chunk_indices,
                priority: 128, // Default priority
            };

            if let Err(e) = tx.try_send(hint) {
                warn!("Failed to send prefetch hint: {}", e);
            }
        }

        let mut stats = self.stats.write().await;
        stats.chunks_prefetched += 1;
    }

    /// Get prefetch statistics.
    pub async fn stats(&self) -> PrefetchStats {
        self.stats.read().await.clone()
    }

    /// Clear the cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();

        let mut mem = self.cache_memory.write().await;
        *mem = 0;

        let mut stats = self.stats.write().await;
        stats.cache_entries = 0;
        stats.cache_memory_bytes = 0;
    }

    /// Clear patterns for a specific content.
    pub async fn clear_pattern(&self, cid: &str) {
        let mut patterns = self.patterns.write().await;
        patterns.remove(cid);
    }

    /// Evict expired entries.
    pub async fn evict_expired(&self) {
        let mut cache = self.cache.write().await;
        let mut mem = self.cache_memory.write().await;

        let expired: Vec<CacheKey> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired(self.config.cache_ttl))
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired {
            if let Some(entry) = cache.remove(&key) {
                *mem = mem.saturating_sub(entry.size());
            }
        }

        let mut stats = self.stats.write().await;
        stats.cache_entries = cache.len();
        stats.cache_memory_bytes = *mem;
    }

    // Internal methods

    fn detect_pattern(&self, accesses: &VecDeque<u64>) -> PatternType {
        if accesses.len() < 3 {
            return PatternType::Unknown;
        }

        let diffs: Vec<i64> = accesses
            .iter()
            .zip(accesses.iter().skip(1))
            .map(|(a, b)| *b as i64 - *a as i64)
            .collect();

        // Check for sequential access
        if diffs.iter().all(|&d| d == 1) {
            return PatternType::Sequential;
        }

        // Check for reverse sequential
        if diffs.iter().all(|&d| d == -1) {
            return PatternType::ReverseSequential;
        }

        // Check for strided access
        if diffs.len() >= 2 {
            let first_diff = diffs[0];
            if first_diff != 0 && diffs.iter().all(|&d| d == first_diff) {
                return PatternType::Strided { stride: first_diff };
            }
        }

        PatternType::Random
    }

    fn calculate_confidence(&self, accesses: &VecDeque<u64>, pattern: PatternType) -> f64 {
        if accesses.len() < 3 {
            return 0.0;
        }

        let base_confidence = match pattern {
            PatternType::Sequential | PatternType::ReverseSequential => 0.9,
            PatternType::Strided { .. } => 0.8,
            PatternType::Random => 0.1,
            PatternType::Unknown => 0.0,
        };

        // Increase confidence with more samples
        let sample_factor = (accesses.len() as f64 / 10.0).min(1.0);
        base_confidence * sample_factor
    }

    fn predict_next_chunks(&self, current: u64, pattern: &AccessPattern) -> Vec<u64> {
        if !self.config.enable_sequential_prediction {
            return vec![];
        }

        if pattern.confidence < 0.5 {
            // Low confidence, just prefetch next few sequential chunks
            return (1..=self.config.prefetch_ahead)
                .map(|i| current + i)
                .collect();
        }

        let prefetch_count = self.config.prefetch_ahead;

        match pattern.pattern_type {
            PatternType::Sequential => (1..=prefetch_count).map(|i| current + i).collect(),
            PatternType::ReverseSequential => (1..=prefetch_count)
                .filter_map(|i| current.checked_sub(i))
                .collect(),
            PatternType::Strided { stride } => (1..=prefetch_count)
                .filter_map(|i| {
                    let next = current as i64 + stride * i as i64;
                    if next >= 0 { Some(next as u64) } else { None }
                })
                .collect(),
            PatternType::Random | PatternType::Unknown => {
                // For random access, just prefetch next sequential
                (1..=prefetch_count).map(|i| current + i).collect()
            }
        }
    }

    async fn evict_entries(&self, needed_bytes: usize) {
        let mut cache = self.cache.write().await;
        let mut mem = self.cache_memory.write().await;

        while *mem + needed_bytes > self.config.max_cache_memory && !cache.is_empty() {
            self.evict_lru(&mut cache).await;
            *mem = cache.values().map(|e| e.size()).sum();
        }
    }

    async fn evict_lru(&self, cache: &mut HashMap<CacheKey, CachedChunk>) {
        // Find least recently used entry (by access count and time)
        let lru_key = cache
            .iter()
            .min_by(|a, b| {
                let score_a =
                    a.1.access_count as f64 / a.1.cached_at.elapsed().as_secs_f64().max(1.0);
                let score_b =
                    b.1.access_count as f64 / b.1.cached_at.elapsed().as_secs_f64().max(1.0);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            if let Some(entry) = cache.remove(&key) {
                debug!(
                    "Evicted chunk from cache: {}:{}",
                    entry.cid, entry.chunk_index
                );
            }
        }
    }
}

/// Builder for ChunkPrefetcher.
#[derive(Debug, Default)]
pub struct PrefetcherBuilder {
    config: PrefetchConfig,
}

impl PrefetcherBuilder {
    /// Create a new builder.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum cached chunks.
    #[inline]
    #[must_use]
    pub fn max_cached_chunks(mut self, count: usize) -> Self {
        self.config.max_cached_chunks = count;
        self
    }

    /// Set prefetch ahead count.
    #[inline]
    #[must_use]
    pub fn prefetch_ahead(mut self, count: u64) -> Self {
        self.config.prefetch_ahead = count;
        self
    }

    /// Set maximum cache memory.
    #[inline]
    #[must_use]
    pub fn max_cache_memory(mut self, bytes: usize) -> Self {
        self.config.max_cache_memory = bytes;
        self
    }

    /// Set cache TTL.
    #[inline]
    #[must_use]
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.cache_ttl = ttl;
        self
    }

    /// Enable/disable sequential prediction.
    #[inline]
    #[must_use]
    pub fn enable_sequential_prediction(mut self, enable: bool) -> Self {
        self.config.enable_sequential_prediction = enable;
        self
    }

    /// Build the prefetcher.
    #[inline]
    #[must_use]
    pub fn build(self) -> ChunkPrefetcher {
        ChunkPrefetcher::new(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_put_get() {
        let prefetcher = ChunkPrefetcher::new(PrefetchConfig::default());

        let data = vec![1, 2, 3, 4, 5];
        prefetcher.put_cached("cid1", 0, data.clone()).await;

        let cached = prefetcher.get_cached("cid1", 0).await;
        assert_eq!(cached, Some(data));

        let not_cached = prefetcher.get_cached("cid1", 1).await;
        assert_eq!(not_cached, None);
    }

    #[tokio::test]
    async fn test_pattern_detection_sequential() {
        let prefetcher = ChunkPrefetcher::new(PrefetchConfig::default());

        // Simulate sequential access
        for i in 0..5 {
            prefetcher.record_access("cid1", i).await;
        }

        // Next prediction should be 5, 6, 7
        let predicted = prefetcher.record_access("cid1", 5).await;
        assert!(predicted.contains(&6));
        assert!(predicted.contains(&7));
    }

    #[tokio::test]
    async fn test_stats() {
        let prefetcher = ChunkPrefetcher::new(PrefetchConfig::default());

        // Cache miss
        prefetcher.get_cached("cid1", 0).await;

        // Cache put and hit
        prefetcher.put_cached("cid1", 0, vec![1, 2, 3]).await;
        prefetcher.get_cached("cid1", 0).await;

        let stats = prefetcher.stats().await;
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_entries, 1);
    }
}
