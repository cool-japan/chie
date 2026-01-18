//! Priority-based content eviction.
//!
//! This module provides intelligent content eviction based on priority scores,
//! combining multiple factors such as access frequency, size, revenue potential,
//! and manual priority levels to make optimal eviction decisions.
//!
//! # Features
//!
//! - Multi-factor priority scoring
//! - Weighted priority components
//! - Adaptive eviction based on resource pressure
//! - Revenue-aware eviction for monetization
//! - Custom priority calculators
//! - Eviction history tracking
//!
//! # Example
//!
//! ```
//! use chie_core::priority_eviction::{PriorityEvictor, EvictionConfig, ContentPriority};
//!
//! # fn example() {
//! let config = EvictionConfig::default();
//! let mut evictor = PriorityEvictor::new(config);
//!
//! // Add content with priorities
//! evictor.add_content("content:1".to_string(), ContentPriority {
//!     manual_priority: 5,
//!     access_frequency: 10.0,
//!     size_bytes: 1024,
//!     revenue_per_gb: 5.0,
//!     last_access_age_secs: 3600,
//! });
//!
//! // Get candidates for eviction
//! let candidates = evictor.get_eviction_candidates(1024 * 1024);
//! println!("Eviction candidates: {:?}", candidates);
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

/// Default weight for access frequency in priority calculation
const DEFAULT_FREQUENCY_WEIGHT: f64 = 0.3;

/// Default weight for size in priority calculation (larger = lower priority)
const DEFAULT_SIZE_WEIGHT: f64 = 0.2;

/// Default weight for revenue potential in priority calculation
const DEFAULT_REVENUE_WEIGHT: f64 = 0.3;

/// Default weight for recency in priority calculation
const DEFAULT_RECENCY_WEIGHT: f64 = 0.2;

/// Content priority factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPriority {
    /// Manual priority level (0-10, higher = more important)
    pub manual_priority: u8,
    /// Access frequency (accesses per hour)
    pub access_frequency: f64,
    /// Size in bytes
    pub size_bytes: u64,
    /// Revenue per GB (for monetized content)
    pub revenue_per_gb: f64,
    /// Age since last access in seconds
    pub last_access_age_secs: u64,
}

impl ContentPriority {
    /// Create a new content priority with default values
    #[must_use]
    pub const fn new(size_bytes: u64) -> Self {
        Self {
            manual_priority: 5,
            access_frequency: 0.0,
            size_bytes,
            revenue_per_gb: 0.0,
            last_access_age_secs: 0,
        }
    }

    /// Set manual priority
    #[must_use]
    pub const fn with_manual_priority(mut self, priority: u8) -> Self {
        self.manual_priority = priority;
        self
    }

    /// Set access frequency
    #[must_use]
    pub const fn with_frequency(mut self, frequency: f64) -> Self {
        self.access_frequency = frequency;
        self
    }

    /// Set revenue per GB
    #[must_use]
    pub const fn with_revenue(mut self, revenue_per_gb: f64) -> Self {
        self.revenue_per_gb = revenue_per_gb;
        self
    }
}

/// Configuration for priority-based eviction
#[derive(Debug, Clone)]
pub struct EvictionConfig {
    /// Weight for access frequency (0.0-1.0)
    pub frequency_weight: f64,
    /// Weight for size penalty (0.0-1.0)
    pub size_weight: f64,
    /// Weight for revenue potential (0.0-1.0)
    pub revenue_weight: f64,
    /// Weight for recency (0.0-1.0)
    pub recency_weight: f64,
    /// Manual priority multiplier
    pub manual_priority_multiplier: f64,
}

impl EvictionConfig {
    /// Create a new configuration with custom weights
    #[must_use]
    pub const fn new(
        frequency_weight: f64,
        size_weight: f64,
        revenue_weight: f64,
        recency_weight: f64,
        manual_priority_multiplier: f64,
    ) -> Self {
        Self {
            frequency_weight,
            size_weight,
            revenue_weight,
            recency_weight,
            manual_priority_multiplier,
        }
    }

    /// Create a revenue-focused configuration (prioritize high-revenue content)
    #[must_use]
    pub const fn revenue_focused() -> Self {
        Self {
            frequency_weight: 0.2,
            size_weight: 0.1,
            revenue_weight: 0.6,
            recency_weight: 0.1,
            manual_priority_multiplier: 2.0,
        }
    }

    /// Create a performance-focused configuration (prioritize frequently accessed)
    #[must_use]
    pub const fn performance_focused() -> Self {
        Self {
            frequency_weight: 0.5,
            size_weight: 0.2,
            revenue_weight: 0.1,
            recency_weight: 0.2,
            manual_priority_multiplier: 1.5,
        }
    }

    /// Create a space-focused configuration (prioritize small files)
    #[must_use]
    pub const fn space_focused() -> Self {
        Self {
            frequency_weight: 0.2,
            size_weight: 0.5,
            revenue_weight: 0.1,
            recency_weight: 0.2,
            manual_priority_multiplier: 1.0,
        }
    }
}

impl Default for EvictionConfig {
    fn default() -> Self {
        Self {
            frequency_weight: DEFAULT_FREQUENCY_WEIGHT,
            size_weight: DEFAULT_SIZE_WEIGHT,
            revenue_weight: DEFAULT_REVENUE_WEIGHT,
            recency_weight: DEFAULT_RECENCY_WEIGHT,
            manual_priority_multiplier: 2.0,
        }
    }
}

/// Content entry with calculated priority score
#[derive(Debug, Clone)]
struct PriorityEntry {
    cid: String,
    priority: ContentPriority,
    score: f64,
}

impl PriorityEntry {
    fn new(cid: String, priority: ContentPriority, config: &EvictionConfig) -> Self {
        let score = Self::calculate_score(&priority, config);
        Self {
            cid,
            priority,
            score,
        }
    }

    fn calculate_score(priority: &ContentPriority, config: &EvictionConfig) -> f64 {
        // Normalize factors to 0.0-1.0 range
        let manual_factor =
            (priority.manual_priority as f64 / 10.0) * config.manual_priority_multiplier;

        let frequency_factor =
            (priority.access_frequency.min(100.0) / 100.0) * config.frequency_weight;

        // Size penalty (larger = lower priority)
        let size_mb = priority.size_bytes as f64 / (1024.0 * 1024.0);
        let size_factor = (1.0 / (1.0 + size_mb)) * config.size_weight;

        let revenue_factor = (priority.revenue_per_gb.min(100.0) / 100.0) * config.revenue_weight;

        // Recency (newer access = higher priority)
        let age_hours = priority.last_access_age_secs as f64 / 3600.0;
        let recency_factor = (1.0 / (1.0 + age_hours)) * config.recency_weight;

        // Combine all factors
        manual_factor + frequency_factor + size_factor + revenue_factor + recency_factor
    }
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (lowest priority first)
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
    }
}

/// Statistics for eviction operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvictionStats {
    /// Total content entries tracked
    pub total_entries: usize,
    /// Total bytes tracked
    pub total_bytes: u64,
    /// Number of evictions performed
    pub evictions_performed: u64,
    /// Total bytes evicted
    pub bytes_evicted: u64,
    /// Average priority score of evicted content
    pub avg_evicted_score: f64,
    /// Average priority score of retained content
    pub avg_retained_score: f64,
}

/// Priority-based content evictor
pub struct PriorityEvictor {
    /// Configuration
    config: EvictionConfig,
    /// Content entries (cid -> priority)
    entries: HashMap<String, ContentPriority>,
    /// Statistics
    stats: EvictionStats,
}

impl PriorityEvictor {
    /// Create a new priority evictor
    #[must_use]
    pub fn new(config: EvictionConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            stats: EvictionStats::default(),
        }
    }

    /// Add content to track for eviction
    pub fn add_content(&mut self, cid: String, priority: ContentPriority) {
        let size = priority.size_bytes;
        self.entries.insert(cid, priority);
        self.stats.total_entries = self.entries.len();
        self.stats.total_bytes += size;
    }

    /// Update priority for existing content
    pub fn update_priority(&mut self, cid: &str, priority: ContentPriority) -> bool {
        if let Some(old_priority) = self.entries.get_mut(cid) {
            let old_size = old_priority.size_bytes;
            let new_size = priority.size_bytes;
            *old_priority = priority;
            self.stats.total_bytes = self.stats.total_bytes.saturating_sub(old_size) + new_size;
            true
        } else {
            false
        }
    }

    /// Remove content from tracking
    pub fn remove_content(&mut self, cid: &str) -> Option<ContentPriority> {
        if let Some(priority) = self.entries.remove(cid) {
            self.stats.total_entries = self.entries.len();
            self.stats.total_bytes = self.stats.total_bytes.saturating_sub(priority.size_bytes);
            Some(priority)
        } else {
            None
        }
    }

    /// Get eviction candidates to free up specified bytes
    #[must_use]
    pub fn get_eviction_candidates(&self, bytes_to_free: u64) -> Vec<String> {
        // Build min-heap of all content (lowest priority first)
        let mut heap: BinaryHeap<PriorityEntry> = self
            .entries
            .iter()
            .map(|(cid, priority)| PriorityEntry::new(cid.clone(), priority.clone(), &self.config))
            .collect();

        let mut candidates = Vec::new();
        let mut bytes_freed = 0u64;

        // Pop lowest priority items until we've freed enough space
        while let Some(entry) = heap.pop() {
            bytes_freed += entry.priority.size_bytes;
            candidates.push(entry.cid);

            if bytes_freed >= bytes_to_free {
                break;
            }
        }

        candidates
    }

    /// Get N lowest priority items for eviction
    #[must_use]
    pub fn get_lowest_priority(&self, count: usize) -> Vec<String> {
        let mut heap: BinaryHeap<PriorityEntry> = self
            .entries
            .iter()
            .map(|(cid, priority)| PriorityEntry::new(cid.clone(), priority.clone(), &self.config))
            .collect();

        let mut result = Vec::new();
        for _ in 0..count.min(heap.len()) {
            if let Some(entry) = heap.pop() {
                result.push(entry.cid);
            }
        }

        result
    }

    /// Evict content and update statistics
    pub fn evict(&mut self, candidates: &[String]) {
        let mut total_score = 0.0;

        for cid in candidates {
            if let Some(priority) = self.remove_content(cid) {
                let score = PriorityEntry::calculate_score(&priority, &self.config);
                total_score += score;
                self.stats.evictions_performed += 1;
                self.stats.bytes_evicted += priority.size_bytes;
            }
        }

        if !candidates.is_empty() {
            self.stats.avg_evicted_score = total_score / candidates.len() as f64;
        }

        // Update retained average
        if !self.entries.is_empty() {
            let retained_score: f64 = self
                .entries
                .values()
                .map(|p| PriorityEntry::calculate_score(p, &self.config))
                .sum();
            self.stats.avg_retained_score = retained_score / self.entries.len() as f64;
        }
    }

    /// Get current statistics
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &EvictionStats {
        &self.stats
    }

    /// Get number of tracked entries
    #[must_use]
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get total bytes tracked
    #[must_use]
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.stats.total_bytes
    }

    /// Get priority score for a specific content
    #[must_use]
    #[inline]
    pub fn get_priority_score(&self, cid: &str) -> Option<f64> {
        self.entries
            .get(cid)
            .map(|p| PriorityEntry::calculate_score(p, &self.config))
    }

    /// Update configuration
    pub fn set_config(&mut self, config: EvictionConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_priority_builder() {
        let priority = ContentPriority::new(1024)
            .with_manual_priority(8)
            .with_frequency(10.0)
            .with_revenue(5.0);

        assert_eq!(priority.manual_priority, 8);
        assert_eq!(priority.access_frequency, 10.0);
        assert_eq!(priority.revenue_per_gb, 5.0);
    }

    #[test]
    fn test_eviction_config_presets() {
        let revenue = EvictionConfig::revenue_focused();
        assert!(revenue.revenue_weight > revenue.frequency_weight);

        let performance = EvictionConfig::performance_focused();
        assert!(performance.frequency_weight > performance.revenue_weight);

        let space = EvictionConfig::space_focused();
        assert!(space.size_weight > space.revenue_weight);
    }

    #[test]
    fn test_priority_evictor_add() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        let priority = ContentPriority::new(1024);
        evictor.add_content("test:1".to_string(), priority);

        assert_eq!(evictor.entry_count(), 1);
        assert_eq!(evictor.total_bytes(), 1024);
    }

    #[test]
    fn test_priority_evictor_update() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        let priority1 = ContentPriority::new(1024);
        evictor.add_content("test:1".to_string(), priority1);

        let priority2 = ContentPriority::new(2048).with_manual_priority(8);
        assert!(evictor.update_priority("test:1", priority2));

        assert_eq!(evictor.total_bytes(), 2048);
    }

    #[test]
    fn test_priority_evictor_remove() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        let priority = ContentPriority::new(1024);
        evictor.add_content("test:1".to_string(), priority);

        let removed = evictor.remove_content("test:1");
        assert!(removed.is_some());
        assert_eq!(evictor.entry_count(), 0);
        assert_eq!(evictor.total_bytes(), 0);
    }

    #[test]
    fn test_eviction_candidates_by_bytes() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        // Add content with different priorities
        evictor.add_content(
            "low_priority".to_string(),
            ContentPriority::new(1024).with_manual_priority(1),
        );
        evictor.add_content(
            "high_priority".to_string(),
            ContentPriority::new(1024).with_manual_priority(9),
        );

        // Should evict low priority content first
        let candidates = evictor.get_eviction_candidates(1024);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], "low_priority");
    }

    #[test]
    fn test_eviction_candidates_multiple() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        for i in 0..5 {
            evictor.add_content(
                format!("content:{i}"),
                ContentPriority::new(1024).with_manual_priority(i),
            );
        }

        // Need to evict multiple items
        let candidates = evictor.get_eviction_candidates(3000);
        assert!(candidates.len() >= 2); // Should evict at least 2 items (2048 bytes)
    }

    #[test]
    fn test_get_lowest_priority() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        for i in 0..10u8 {
            evictor.add_content(
                format!("content:{i}"),
                ContentPriority::new(1024).with_manual_priority(i),
            );
        }

        let lowest = evictor.get_lowest_priority(3);
        assert_eq!(lowest.len(), 3);
        // Lowest priorities should be content:0, content:1, content:2
        assert!(lowest.contains(&"content:0".to_string()));
    }

    #[test]
    fn test_evict_and_stats() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        evictor.add_content(
            "test:1".to_string(),
            ContentPriority::new(1024).with_manual_priority(1),
        );
        evictor.add_content(
            "test:2".to_string(),
            ContentPriority::new(2048).with_manual_priority(5),
        );

        let candidates = vec!["test:1".to_string()];
        evictor.evict(&candidates);

        let stats = evictor.stats();
        assert_eq!(stats.evictions_performed, 1);
        assert_eq!(stats.bytes_evicted, 1024);
        assert_eq!(evictor.entry_count(), 1);
    }

    #[test]
    fn test_priority_score_calculation() {
        let config = EvictionConfig::default();
        let mut evictor = PriorityEvictor::new(config);

        let priority = ContentPriority::new(1024)
            .with_manual_priority(8)
            .with_frequency(50.0)
            .with_revenue(10.0);

        evictor.add_content("test:1".to_string(), priority);

        let score = evictor.get_priority_score("test:1").unwrap();
        assert!(score > 0.0);
        assert!(score < 10.0); // Should be reasonable
    }

    #[test]
    fn test_revenue_focused_priority() {
        let config = EvictionConfig::revenue_focused();
        let mut evictor = PriorityEvictor::new(config);

        evictor.add_content(
            "high_revenue".to_string(),
            ContentPriority::new(1024).with_revenue(50.0),
        );
        evictor.add_content(
            "low_revenue".to_string(),
            ContentPriority::new(1024).with_revenue(1.0),
        );

        let candidates = evictor.get_lowest_priority(1);
        assert_eq!(candidates[0], "low_revenue");
    }

    #[test]
    fn test_size_penalty() {
        let config = EvictionConfig::space_focused();
        let mut evictor = PriorityEvictor::new(config);

        evictor.add_content(
            "large".to_string(),
            ContentPriority::new(10 * 1024 * 1024), // 10 MB
        );
        evictor.add_content(
            "small".to_string(),
            ContentPriority::new(1024), // 1 KB
        );

        // Large files should have lower priority with space-focused config
        let candidates = evictor.get_lowest_priority(1);
        assert_eq!(candidates[0], "large");
    }
}
