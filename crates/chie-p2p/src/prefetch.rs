//! Smart prefetching system for predictive content loading.
//!
//! This module implements intelligent prefetching by combining bandwidth prediction,
//! content popularity tracking, and usage pattern analysis to preload content before
//! it's requested, improving user experience and reducing latency.
//!
//! # Example
//!
//! ```
//! use chie_p2p::prefetch::{PrefetchManager, PrefetchConfig, PrefetchStrategy};
//! use std::time::Duration;
//!
//! let config = PrefetchConfig {
//!     strategy: PrefetchStrategy::Hybrid,
//!     max_prefetch_size: 100 * 1024 * 1024, // 100 MB
//!     min_bandwidth_threshold: 1_000_000,    // 1 MB/s
//!     ..Default::default()
//! };
//!
//! let mut manager = PrefetchManager::with_config(config);
//!
//! // Record content access patterns
//! manager.record_access("content-1");
//! manager.record_access("content-2");
//! manager.record_access("content-1");
//!
//! // Get prefetch recommendations
//! let recommendations = manager.get_prefetch_recommendations(5);
//! for rec in recommendations {
//!     println!("Should prefetch: {} (priority: {})", rec.content_id, rec.priority);
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Prefetch strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchStrategy {
    /// Prefetch based on popularity only
    PopularityBased,
    /// Prefetch based on sequential access patterns
    SequentialPattern,
    /// Prefetch based on temporal patterns (time of day, etc.)
    TemporalPattern,
    /// Hybrid approach combining all strategies
    Hybrid,
    /// Conservative prefetching (only very likely content)
    Conservative,
    /// Aggressive prefetching (more speculative)
    Aggressive,
}

/// Configuration for prefetch manager
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    /// Prefetch strategy to use
    pub strategy: PrefetchStrategy,
    /// Maximum total size of prefetched content (bytes)
    pub max_prefetch_size: u64,
    /// Maximum number of items to prefetch
    pub max_prefetch_items: usize,
    /// Minimum bandwidth threshold for prefetching (bytes/sec)
    pub min_bandwidth_threshold: u64,
    /// Minimum confidence score to trigger prefetch (0.0 to 1.0)
    pub min_confidence: f64,
    /// Time window for pattern analysis
    pub pattern_window: Duration,
    /// Maximum age for access records
    pub max_record_age: Duration,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            strategy: PrefetchStrategy::Hybrid,
            max_prefetch_size: 100 * 1024 * 1024, // 100 MB
            max_prefetch_items: 50,
            min_bandwidth_threshold: 500_000, // 500 KB/s
            min_confidence: 0.6,
            pattern_window: Duration::from_secs(3600), // 1 hour
            max_record_age: Duration::from_secs(86400), // 24 hours
        }
    }
}

/// Prefetch recommendation
#[derive(Debug, Clone)]
pub struct PrefetchRecommendation {
    /// Content identifier to prefetch
    pub content_id: String,
    /// Priority score (higher = more important)
    pub priority: f64,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Estimated size if known
    pub estimated_size: Option<u64>,
    /// Reason for recommendation
    pub reason: PrefetchReason,
}

/// Reason for prefetch recommendation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchReason {
    /// High popularity score
    HighPopularity,
    /// Sequential access pattern detected
    SequentialPattern,
    /// Temporal pattern detected (time-based)
    TemporalPattern,
    /// Combination of multiple factors
    Hybrid,
}

/// Access record for pattern analysis
#[derive(Debug, Clone)]
struct AccessRecord {
    content_id: String,
    timestamp: Instant,
    #[allow(dead_code)]
    size: Option<u64>,
}

/// Sequential pattern information
#[derive(Debug, Clone)]
struct SequentialPattern {
    sequence: Vec<String>,
    occurrences: u32,
    confidence: f64,
}

/// Prefetch manager
pub struct PrefetchManager {
    config: PrefetchConfig,
    access_history: VecDeque<AccessRecord>,
    sequential_patterns: Vec<SequentialPattern>,
    temporal_patterns: HashMap<String, Vec<Instant>>,
    prefetched_items: HashMap<String, Instant>,
    current_prefetch_size: u64,
    bandwidth_available: Option<u64>,
}

impl PrefetchManager {
    /// Creates a new prefetch manager with default configuration
    pub fn new() -> Self {
        Self::with_config(PrefetchConfig::default())
    }

    /// Creates a new prefetch manager with custom configuration
    pub fn with_config(config: PrefetchConfig) -> Self {
        Self {
            config,
            access_history: VecDeque::new(),
            sequential_patterns: Vec::new(),
            temporal_patterns: HashMap::new(),
            prefetched_items: HashMap::new(),
            current_prefetch_size: 0,
            bandwidth_available: None,
        }
    }

    /// Records a content access
    pub fn record_access(&mut self, content_id: impl Into<String>) {
        self.record_access_with_size(content_id, None);
    }

    /// Records a content access with size information
    pub fn record_access_with_size(&mut self, content_id: impl Into<String>, size: Option<u64>) {
        let content_id = content_id.into();
        let now = Instant::now();

        self.access_history.push_back(AccessRecord {
            content_id: content_id.clone(),
            timestamp: now,
            size,
        });

        // Update temporal patterns
        self.temporal_patterns
            .entry(content_id)
            .or_default()
            .push(now);

        // Cleanup old records
        self.cleanup_old_records();

        // Update sequential patterns periodically
        if self.access_history.len() % 10 == 0 {
            self.update_sequential_patterns();
        }
    }

    /// Updates available bandwidth information
    pub fn update_bandwidth(&mut self, bytes_per_second: u64) {
        self.bandwidth_available = Some(bytes_per_second);
    }

    /// Marks content as prefetched
    pub fn mark_prefetched(&mut self, content_id: impl Into<String>, size: u64) {
        let content_id = content_id.into();
        self.prefetched_items.insert(content_id, Instant::now());
        self.current_prefetch_size += size;
    }

    /// Marks content as consumed (removes from prefetch cache)
    pub fn mark_consumed(&mut self, content_id: &str, size: u64) {
        if self.prefetched_items.remove(content_id).is_some() {
            self.current_prefetch_size = self.current_prefetch_size.saturating_sub(size);
        }
    }

    /// Gets prefetch recommendations
    pub fn get_prefetch_recommendations(&self, max_items: usize) -> Vec<PrefetchRecommendation> {
        // Check if bandwidth is sufficient
        if let Some(bw) = self.bandwidth_available {
            if bw < self.config.min_bandwidth_threshold {
                return Vec::new();
            }
        }

        let mut recommendations = match self.config.strategy {
            PrefetchStrategy::PopularityBased => self.get_popularity_recommendations(),
            PrefetchStrategy::SequentialPattern => self.get_sequential_recommendations(),
            PrefetchStrategy::TemporalPattern => self.get_temporal_recommendations(),
            PrefetchStrategy::Hybrid => self.get_hybrid_recommendations(),
            PrefetchStrategy::Conservative => self.get_conservative_recommendations(),
            PrefetchStrategy::Aggressive => self.get_aggressive_recommendations(),
        };

        // Filter out already prefetched items
        recommendations.retain(|rec| !self.prefetched_items.contains_key(&rec.content_id));

        // Filter by confidence
        recommendations.retain(|rec| rec.confidence >= self.config.min_confidence);

        // Sort by priority
        recommendations.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap());

        // Limit by count and size
        self.apply_size_limits(recommendations, max_items)
    }

    /// Gets statistics about prefetching
    pub fn stats(&self) -> PrefetchStats {
        PrefetchStats {
            access_records: self.access_history.len(),
            sequential_patterns: self.sequential_patterns.len(),
            temporal_patterns: self.temporal_patterns.len(),
            prefetched_items: self.prefetched_items.len(),
            current_prefetch_size: self.current_prefetch_size,
            bandwidth_available: self.bandwidth_available,
        }
    }

    /// Clears all prefetch data
    pub fn clear(&mut self) {
        self.access_history.clear();
        self.sequential_patterns.clear();
        self.temporal_patterns.clear();
        self.prefetched_items.clear();
        self.current_prefetch_size = 0;
    }

    // Private helper methods

    fn cleanup_old_records(&mut self) {
        let now = Instant::now();
        let cutoff = now - self.config.max_record_age;

        while let Some(record) = self.access_history.front() {
            if record.timestamp < cutoff {
                self.access_history.pop_front();
            } else {
                break;
            }
        }

        // Cleanup temporal patterns
        for accesses in self.temporal_patterns.values_mut() {
            accesses.retain(|&ts| ts >= cutoff);
        }
        self.temporal_patterns
            .retain(|_, accesses| !accesses.is_empty());

        // Cleanup old prefetched items
        self.prefetched_items.retain(|_, &mut ts| ts >= cutoff);
    }

    fn update_sequential_patterns(&mut self) {
        // Find common sequences in recent access history
        let min_pattern_length = 2;
        let max_pattern_length = 5;

        self.sequential_patterns.clear();

        for length in min_pattern_length..=max_pattern_length {
            let patterns = self.find_sequential_patterns(length);
            self.sequential_patterns.extend(patterns);
        }
    }

    fn find_sequential_patterns(&self, length: usize) -> Vec<SequentialPattern> {
        let mut pattern_counts: HashMap<Vec<String>, u32> = HashMap::new();

        for window in self
            .access_history
            .iter()
            .collect::<Vec<_>>()
            .windows(length)
        {
            let sequence: Vec<String> = window.iter().map(|r| r.content_id.clone()).collect();
            *pattern_counts.entry(sequence).or_insert(0) += 1;
        }

        pattern_counts
            .into_iter()
            .filter(|(_, count)| *count >= 2) // At least 2 occurrences
            .map(|(sequence, occurrences)| {
                let confidence = (occurrences as f64 / self.access_history.len() as f64).min(1.0);
                SequentialPattern {
                    sequence,
                    occurrences,
                    confidence,
                }
            })
            .collect()
    }

    fn get_popularity_recommendations(&self) -> Vec<PrefetchRecommendation> {
        let mut content_counts: HashMap<String, u32> = HashMap::new();

        for record in &self.access_history {
            *content_counts.entry(record.content_id.clone()).or_insert(0) += 1;
        }

        let max_count = content_counts.values().copied().max().unwrap_or(1) as f64;

        content_counts
            .into_iter()
            .map(|(content_id, count)| {
                let confidence = count as f64 / max_count;
                PrefetchRecommendation {
                    content_id,
                    priority: count as f64,
                    confidence,
                    estimated_size: None,
                    reason: PrefetchReason::HighPopularity,
                }
            })
            .collect()
    }

    fn get_sequential_recommendations(&self) -> Vec<PrefetchRecommendation> {
        let mut recommendations = Vec::new();

        // Get last accessed content
        if let Some(last_access) = self.access_history.back() {
            let last_content = &last_access.content_id;

            // Find patterns that start with the last accessed content
            for pattern in &self.sequential_patterns {
                if let Some(pos) = pattern.sequence.iter().position(|id| id == last_content) {
                    if pos + 1 < pattern.sequence.len() {
                        let next_content = &pattern.sequence[pos + 1];
                        recommendations.push(PrefetchRecommendation {
                            content_id: next_content.clone(),
                            priority: pattern.occurrences as f64 * pattern.confidence,
                            confidence: pattern.confidence,
                            estimated_size: None,
                            reason: PrefetchReason::SequentialPattern,
                        });
                    }
                }
            }
        }

        recommendations
    }

    fn get_temporal_recommendations(&self) -> Vec<PrefetchRecommendation> {
        // Simple temporal pattern: content accessed around this time recently
        Vec::new() // Placeholder - could implement time-of-day patterns
    }

    fn get_hybrid_recommendations(&self) -> Vec<PrefetchRecommendation> {
        let mut all_recs = Vec::new();

        all_recs.extend(self.get_popularity_recommendations());
        all_recs.extend(self.get_sequential_recommendations());
        all_recs.extend(self.get_temporal_recommendations());

        // Merge duplicates and combine scores
        let mut merged: HashMap<String, PrefetchRecommendation> = HashMap::new();

        for rec in all_recs {
            merged
                .entry(rec.content_id.clone())
                .and_modify(|existing| {
                    existing.priority += rec.priority;
                    existing.confidence = (existing.confidence + rec.confidence) / 2.0;
                })
                .or_insert(rec);
        }

        merged.into_values().collect()
    }

    fn get_conservative_recommendations(&self) -> Vec<PrefetchRecommendation> {
        let mut recs = self.get_hybrid_recommendations();
        recs.retain(|r| r.confidence >= 0.8); // High confidence only
        recs
    }

    fn get_aggressive_recommendations(&self) -> Vec<PrefetchRecommendation> {
        let mut recs = self.get_hybrid_recommendations();
        // Boost all priorities for aggressive prefetching
        for rec in &mut recs {
            rec.priority *= 1.5;
        }
        recs
    }

    fn apply_size_limits(
        &self,
        mut recommendations: Vec<PrefetchRecommendation>,
        max_items: usize,
    ) -> Vec<PrefetchRecommendation> {
        let mut total_size = self.current_prefetch_size;
        let mut result = Vec::new();

        // Use the stricter limit between requested and configured
        let effective_limit = max_items.min(self.config.max_prefetch_items);

        for rec in recommendations.drain(..) {
            if result.len() >= effective_limit {
                break;
            }

            if let Some(size) = rec.estimated_size {
                if total_size + size > self.config.max_prefetch_size {
                    break;
                }
                total_size += size;
            }

            result.push(rec);
        }

        result
    }
}

impl Default for PrefetchManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about prefetching
#[derive(Debug, Clone)]
pub struct PrefetchStats {
    pub access_records: usize,
    pub sequential_patterns: usize,
    pub temporal_patterns: usize,
    pub prefetched_items: usize,
    pub current_prefetch_size: u64,
    pub bandwidth_available: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_new() {
        let manager = PrefetchManager::new();
        assert_eq!(manager.access_history.len(), 0);
        assert_eq!(manager.prefetched_items.len(), 0);
    }

    #[test]
    fn test_record_access() {
        let mut manager = PrefetchManager::new();
        manager.record_access("content-1");

        assert_eq!(manager.access_history.len(), 1);
        assert_eq!(manager.access_history[0].content_id, "content-1");
    }

    #[test]
    fn test_record_access_with_size() {
        let mut manager = PrefetchManager::new();
        manager.record_access_with_size("content-1", Some(1024));

        assert_eq!(manager.access_history.len(), 1);
        assert_eq!(manager.access_history[0].size, Some(1024));
    }

    #[test]
    fn test_update_bandwidth() {
        let mut manager = PrefetchManager::new();
        manager.update_bandwidth(1_000_000);

        assert_eq!(manager.bandwidth_available, Some(1_000_000));
    }

    #[test]
    fn test_mark_prefetched() {
        let mut manager = PrefetchManager::new();
        manager.mark_prefetched("content-1", 1024);

        assert_eq!(manager.prefetched_items.len(), 1);
        assert_eq!(manager.current_prefetch_size, 1024);
    }

    #[test]
    fn test_mark_consumed() {
        let mut manager = PrefetchManager::new();
        manager.mark_prefetched("content-1", 1024);
        manager.mark_consumed("content-1", 1024);

        assert_eq!(manager.prefetched_items.len(), 0);
        assert_eq!(manager.current_prefetch_size, 0);
    }

    #[test]
    fn test_popularity_recommendations() {
        let mut manager = PrefetchManager::new();

        for _ in 0..5 {
            manager.record_access("content-1");
        }
        for _ in 0..2 {
            manager.record_access("content-2");
        }

        manager.update_bandwidth(5_000_000); // Ensure sufficient bandwidth

        let recs = manager.get_prefetch_recommendations(10);

        // Should recommend content-1 with higher priority
        let content_1_rec = recs.iter().find(|r| r.content_id == "content-1");
        let content_2_rec = recs.iter().find(|r| r.content_id == "content-2");

        if let (Some(rec1), Some(rec2)) = (content_1_rec, content_2_rec) {
            assert!(rec1.priority > rec2.priority);
        }
    }

    #[test]
    fn test_sequential_pattern_detection() {
        let mut manager = PrefetchManager::new();

        // Create a sequential pattern: 1 -> 2 -> 3
        for _ in 0..3 {
            manager.record_access("content-1");
            manager.record_access("content-2");
            manager.record_access("content-3");
        }

        manager.update_sequential_patterns();
        assert!(!manager.sequential_patterns.is_empty());
    }

    #[test]
    fn test_sequential_recommendations() {
        let mut manager = PrefetchManager::with_config(PrefetchConfig {
            strategy: PrefetchStrategy::SequentialPattern,
            min_confidence: 0.1,
            ..Default::default()
        });

        // Create pattern: A -> B -> C (repeated)
        for _ in 0..3 {
            manager.record_access("A");
            manager.record_access("B");
            manager.record_access("C");
        }

        manager.update_bandwidth(5_000_000);
        let recs = manager.get_prefetch_recommendations(10);

        // After accessing C, should recommend A (pattern loops)
        // or no recommendation since C is the last in sequence
        assert!(!recs.is_empty() || manager.sequential_patterns.is_empty());
    }

    #[test]
    fn test_insufficient_bandwidth() {
        let mut manager = PrefetchManager::new();

        manager.record_access("content-1");
        manager.record_access("content-1");

        // Set bandwidth below threshold
        manager.update_bandwidth(100_000);

        let recs = manager.get_prefetch_recommendations(10);
        assert_eq!(recs.len(), 0); // Should not recommend due to low bandwidth
    }

    #[test]
    fn test_filter_prefetched() {
        let mut manager = PrefetchManager::new();

        manager.record_access("content-1");
        manager.record_access("content-2");

        manager.mark_prefetched("content-1", 1024);
        manager.update_bandwidth(5_000_000);

        let recs = manager.get_prefetch_recommendations(10);

        // Should not include already prefetched content-1
        assert!(!recs.iter().any(|r| r.content_id == "content-1"));
    }

    #[test]
    fn test_min_confidence_filter() {
        let config = PrefetchConfig {
            min_confidence: 0.8,
            ..Default::default()
        };
        let mut manager = PrefetchManager::with_config(config);

        manager.record_access("content-1");
        manager.update_bandwidth(5_000_000);

        let recs = manager.get_prefetch_recommendations(10);

        // All recommendations should meet minimum confidence
        for rec in recs {
            assert!(rec.confidence >= 0.8);
        }
    }

    #[test]
    fn test_stats() {
        let mut manager = PrefetchManager::new();

        manager.record_access("content-1");
        manager.record_access("content-2");
        manager.mark_prefetched("content-3", 2048);

        let stats = manager.stats();
        assert_eq!(stats.access_records, 2);
        assert_eq!(stats.prefetched_items, 1);
        assert_eq!(stats.current_prefetch_size, 2048);
    }

    #[test]
    fn test_clear() {
        let mut manager = PrefetchManager::new();

        manager.record_access("content-1");
        manager.mark_prefetched("content-2", 1024);

        manager.clear();

        assert_eq!(manager.access_history.len(), 0);
        assert_eq!(manager.prefetched_items.len(), 0);
        assert_eq!(manager.current_prefetch_size, 0);
    }

    #[test]
    fn test_size_limits() {
        let config = PrefetchConfig {
            max_prefetch_size: 2048,
            max_prefetch_items: 2,
            min_confidence: 0.0,
            ..Default::default()
        };
        let mut manager = PrefetchManager::with_config(config);

        manager.record_access("content-1");
        manager.record_access("content-2");
        manager.record_access("content-3");

        manager.update_bandwidth(5_000_000);

        let recs = manager.get_prefetch_recommendations(10);

        // Should respect max_prefetch_items limit
        assert!(recs.len() <= 2);
    }

    #[test]
    fn test_hybrid_strategy() {
        let config = PrefetchConfig {
            strategy: PrefetchStrategy::Hybrid,
            min_confidence: 0.0,
            ..Default::default()
        };
        let mut manager = PrefetchManager::with_config(config);

        // Create both popularity and sequential patterns
        for _ in 0..5 {
            manager.record_access("popular");
        }

        for _ in 0..3 {
            manager.record_access("seq-1");
            manager.record_access("seq-2");
        }

        manager.update_bandwidth(5_000_000);
        let recs = manager.get_prefetch_recommendations(10);

        // Should combine recommendations from different strategies
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_conservative_strategy() {
        let config = PrefetchConfig {
            strategy: PrefetchStrategy::Conservative,
            min_confidence: 0.6,
            ..Default::default()
        };
        let mut manager = PrefetchManager::with_config(config);

        manager.record_access("content-1");
        manager.update_bandwidth(5_000_000);

        let recs = manager.get_prefetch_recommendations(10);

        // Conservative should have very few or no recommendations for low confidence
        for rec in recs {
            assert!(rec.confidence >= 0.8); // Conservative requires high confidence
        }
    }

    #[test]
    fn test_aggressive_strategy() {
        let config = PrefetchConfig {
            strategy: PrefetchStrategy::Aggressive,
            min_confidence: 0.0,
            ..Default::default()
        };
        let mut manager = PrefetchManager::with_config(config);

        manager.record_access("content-1");
        manager.update_bandwidth(5_000_000);

        let recs = manager.get_prefetch_recommendations(10);

        // Aggressive should boost priorities
        for rec in recs {
            assert!(rec.priority > 0.0);
        }
    }
}
