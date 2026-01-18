//! Content popularity tracking for optimizing cache and replication strategies.
//!
//! This module tracks content request patterns to identify popular content,
//! enabling intelligent caching decisions and optimal content placement.
//!
//! # Example
//!
//! ```
//! use chie_p2p::content_popularity::{PopularityTracker, TrackingConfig};
//! use std::time::Duration;
//!
//! let config = TrackingConfig {
//!     time_window: Duration::from_secs(3600), // 1 hour
//!     decay_rate: 0.95,
//!     ..Default::default()
//! };
//!
//! let mut tracker = PopularityTracker::with_config(config);
//!
//! // Record content requests
//! tracker.record_request("content-123");
//! tracker.record_request("content-123");
//! tracker.record_request("content-456");
//!
//! // Get most popular content
//! let top_content = tracker.top_content(10);
//! println!("Top content: {:?}", top_content);
//!
//! // Check if content should be cached
//! if tracker.should_cache("content-123") {
//!     println!("Content should be cached!");
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Configuration for content popularity tracking
#[derive(Debug, Clone)]
pub struct TrackingConfig {
    /// Maximum number of content items to track
    pub max_tracked_items: usize,
    /// Time window for considering requests (older requests are decayed)
    pub time_window: Duration,
    /// Decay rate for older requests (0.0 to 1.0)
    pub decay_rate: f64,
    /// Minimum requests to be considered "popular"
    pub popularity_threshold: u64,
    /// Threshold for caching decisions (0.0 to 1.0)
    pub cache_threshold: f64,
    /// How often to run decay and cleanup
    pub cleanup_interval: Duration,
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            max_tracked_items: 10_000,
            time_window: Duration::from_secs(3600), // 1 hour
            decay_rate: 0.95,
            popularity_threshold: 10,
            cache_threshold: 0.7,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Content popularity information
#[derive(Debug, Clone)]
pub struct ContentPopularity {
    /// Content identifier
    pub content_id: String,
    /// Total request count
    pub request_count: u64,
    /// Weighted popularity score (with decay applied)
    pub popularity_score: f64,
    /// Requests per time unit (recent rate)
    pub request_rate: f64,
    /// Unique requesters count
    pub unique_requesters: usize,
    /// First request timestamp
    pub first_seen: Instant,
    /// Last request timestamp
    pub last_seen: Instant,
}

/// Request record for tracking
#[derive(Debug, Clone)]
struct RequestRecord {
    timestamp: Instant,
    #[allow(dead_code)]
    requester_id: Option<String>,
}

/// Content metadata for tracking
struct ContentMetadata {
    request_count: u64,
    popularity_score: f64,
    first_seen: Instant,
    last_seen: Instant,
    requests: VecDeque<RequestRecord>,
    unique_requesters: HashMap<String, u64>,
}

/// Content popularity tracker
pub struct PopularityTracker {
    config: TrackingConfig,
    content_map: HashMap<String, ContentMetadata>,
    last_cleanup: Instant,
    total_requests: u64,
}

impl PopularityTracker {
    /// Creates a new popularity tracker with default configuration
    pub fn new() -> Self {
        Self::with_config(TrackingConfig::default())
    }

    /// Creates a new popularity tracker with custom configuration
    pub fn with_config(config: TrackingConfig) -> Self {
        Self {
            config,
            content_map: HashMap::new(),
            last_cleanup: Instant::now(),
            total_requests: 0,
        }
    }

    /// Records a content request
    pub fn record_request(&mut self, content_id: impl Into<String>) {
        self.record_request_with_requester(content_id, None);
    }

    /// Records a content request with requester information
    pub fn record_request_with_requester(
        &mut self,
        content_id: impl Into<String>,
        requester_id: Option<String>,
    ) {
        let content_id = content_id.into();
        let now = Instant::now();

        self.total_requests += 1;

        let metadata = self
            .content_map
            .entry(content_id.clone())
            .or_insert_with(|| ContentMetadata {
                request_count: 0,
                popularity_score: 0.0,
                first_seen: now,
                last_seen: now,
                requests: VecDeque::new(),
                unique_requesters: HashMap::new(),
            });

        metadata.request_count += 1;
        metadata.last_seen = now;
        metadata.requests.push_back(RequestRecord {
            timestamp: now,
            requester_id: requester_id.clone(),
        });

        if let Some(ref requester) = requester_id {
            *metadata
                .unique_requesters
                .entry(requester.clone())
                .or_insert(0) += 1;
        }

        // Update popularity score (simple increment for now, decay applied during cleanup)
        metadata.popularity_score += 1.0;

        // Periodic cleanup
        if now.duration_since(self.last_cleanup) >= self.config.cleanup_interval {
            self.cleanup();
        }

        // Limit tracked items
        if self.content_map.len() > self.config.max_tracked_items {
            self.evict_least_popular();
        }
    }

    /// Gets popularity information for a specific content
    pub fn get_popularity(&self, content_id: &str) -> Option<ContentPopularity> {
        self.content_map.get(content_id).map(|metadata| {
            let request_rate = self.calculate_request_rate(metadata);

            ContentPopularity {
                content_id: content_id.to_string(),
                request_count: metadata.request_count,
                popularity_score: metadata.popularity_score,
                request_rate,
                unique_requesters: metadata.unique_requesters.len(),
                first_seen: metadata.first_seen,
                last_seen: metadata.last_seen,
            }
        })
    }

    /// Returns the top N most popular content items
    pub fn top_content(&self, n: usize) -> Vec<ContentPopularity> {
        let mut items: Vec<_> = self
            .content_map
            .iter()
            .map(|(id, metadata)| {
                let request_rate = self.calculate_request_rate(metadata);
                ContentPopularity {
                    content_id: id.clone(),
                    request_count: metadata.request_count,
                    popularity_score: metadata.popularity_score,
                    request_rate,
                    unique_requesters: metadata.unique_requesters.len(),
                    first_seen: metadata.first_seen,
                    last_seen: metadata.last_seen,
                }
            })
            .collect();

        items.sort_by(|a, b| b.popularity_score.partial_cmp(&a.popularity_score).unwrap());
        items.truncate(n);
        items
    }

    /// Determines if content should be cached based on popularity
    pub fn should_cache(&self, content_id: &str) -> bool {
        if let Some(metadata) = self.content_map.get(content_id) {
            // Normalize popularity score
            let max_score = self.max_popularity_score();
            if max_score == 0.0 {
                return false;
            }

            let normalized_score = metadata.popularity_score / max_score;
            normalized_score >= self.config.cache_threshold
        } else {
            false
        }
    }

    /// Gets the recommended replication factor based on popularity
    pub fn replication_factor(&self, content_id: &str) -> u32 {
        if let Some(popularity) = self.get_popularity(content_id) {
            // Higher popularity = more replicas (1 to 10)
            let max_score = self.max_popularity_score();
            if max_score == 0.0 {
                return 1;
            }

            let normalized = (popularity.popularity_score / max_score).min(1.0);
            let factor = (1.0 + normalized * 9.0) as u32;
            factor.clamp(1, 10)
        } else {
            1
        }
    }

    /// Gets statistics about tracked content
    pub fn stats(&self) -> PopularityStats {
        let popular_count = self
            .content_map
            .values()
            .filter(|m| m.request_count >= self.config.popularity_threshold)
            .count();

        PopularityStats {
            tracked_items: self.content_map.len(),
            total_requests: self.total_requests,
            popular_items: popular_count,
            avg_requests_per_content: if !self.content_map.is_empty() {
                self.total_requests as f64 / self.content_map.len() as f64
            } else {
                0.0
            },
            max_popularity_score: self.max_popularity_score(),
        }
    }

    /// Clears all tracked data
    pub fn clear(&mut self) {
        self.content_map.clear();
        self.total_requests = 0;
        self.last_cleanup = Instant::now();
    }

    // Private helper methods

    fn cleanup(&mut self) {
        let now = Instant::now();
        let cutoff = now - self.config.time_window;

        // Apply decay and remove old requests
        self.content_map.retain(|_, metadata| {
            // Remove old request records
            while let Some(record) = metadata.requests.front() {
                if record.timestamp < cutoff {
                    metadata.requests.pop_front();
                } else {
                    break;
                }
            }

            // Apply decay to popularity score
            metadata.popularity_score *= self.config.decay_rate;

            // Remove content with no recent activity
            !metadata.requests.is_empty() || metadata.popularity_score > 1.0
        });

        self.last_cleanup = now;
    }

    fn evict_least_popular(&mut self) {
        if let Some((least_popular_id, _)) = self
            .content_map
            .iter()
            .min_by(|(_, a), (_, b)| a.popularity_score.partial_cmp(&b.popularity_score).unwrap())
        {
            let id_to_remove = least_popular_id.clone();
            self.content_map.remove(&id_to_remove);
        }
    }

    fn calculate_request_rate(&self, metadata: &ContentMetadata) -> f64 {
        if metadata.requests.is_empty() {
            return 0.0;
        }

        let duration = metadata.last_seen.duration_since(metadata.first_seen);
        if duration.as_secs() == 0 {
            return metadata.request_count as f64;
        }

        metadata.request_count as f64 / duration.as_secs_f64()
    }

    fn max_popularity_score(&self) -> f64 {
        self.content_map
            .values()
            .map(|m| m.popularity_score)
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0)
    }
}

impl Default for PopularityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about content popularity tracking
#[derive(Debug, Clone)]
pub struct PopularityStats {
    pub tracked_items: usize,
    pub total_requests: u64,
    pub popular_items: usize,
    pub avg_requests_per_content: f64,
    pub max_popularity_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_new() {
        let tracker = PopularityTracker::new();
        assert_eq!(tracker.content_map.len(), 0);
        assert_eq!(tracker.total_requests, 0);
    }

    #[test]
    fn test_record_request() {
        let mut tracker = PopularityTracker::new();
        tracker.record_request("content-1");

        assert_eq!(tracker.total_requests, 1);
        assert_eq!(tracker.content_map.len(), 1);

        let popularity = tracker.get_popularity("content-1").unwrap();
        assert_eq!(popularity.request_count, 1);
        assert_eq!(popularity.content_id, "content-1");
    }

    #[test]
    fn test_multiple_requests() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request("content-1");
        tracker.record_request("content-1");
        tracker.record_request("content-2");

        assert_eq!(tracker.total_requests, 3);
        assert_eq!(tracker.content_map.len(), 2);

        let pop1 = tracker.get_popularity("content-1").unwrap();
        assert_eq!(pop1.request_count, 2);

        let pop2 = tracker.get_popularity("content-2").unwrap();
        assert_eq!(pop2.request_count, 1);
    }

    #[test]
    fn test_record_with_requester() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request_with_requester("content-1", Some("peer-1".to_string()));
        tracker.record_request_with_requester("content-1", Some("peer-2".to_string()));
        tracker.record_request_with_requester("content-1", Some("peer-1".to_string()));

        let popularity = tracker.get_popularity("content-1").unwrap();
        assert_eq!(popularity.request_count, 3);
        assert_eq!(popularity.unique_requesters, 2);
    }

    #[test]
    fn test_top_content() {
        let mut tracker = PopularityTracker::new();

        for _ in 0..10 {
            tracker.record_request("content-1");
        }
        for _ in 0..5 {
            tracker.record_request("content-2");
        }
        for _ in 0..2 {
            tracker.record_request("content-3");
        }

        let top = tracker.top_content(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].content_id, "content-1");
        assert_eq!(top[1].content_id, "content-2");
    }

    #[test]
    fn test_should_cache() {
        let config = TrackingConfig {
            cache_threshold: 0.5,
            ..Default::default()
        };
        let mut tracker = PopularityTracker::with_config(config);

        // High popularity
        for _ in 0..100 {
            tracker.record_request("popular-content");
        }

        // Low popularity
        tracker.record_request("unpopular-content");

        assert!(tracker.should_cache("popular-content"));
        assert!(!tracker.should_cache("unpopular-content"));
    }

    #[test]
    fn test_replication_factor() {
        let mut tracker = PopularityTracker::new();

        // Very popular content
        for _ in 0..100 {
            tracker.record_request("content-1");
        }

        // Less popular content
        for _ in 0..10 {
            tracker.record_request("content-2");
        }

        let factor1 = tracker.replication_factor("content-1");
        let factor2 = tracker.replication_factor("content-2");

        assert!(factor1 > factor2);
        assert!((1..=10).contains(&factor1));
        assert!((1..=10).contains(&factor2));
    }

    #[test]
    fn test_replication_factor_unknown() {
        let tracker = PopularityTracker::new();
        let factor = tracker.replication_factor("unknown-content");
        assert_eq!(factor, 1);
    }

    #[test]
    fn test_stats() {
        let mut tracker = PopularityTracker::new();

        for _ in 0..10 {
            tracker.record_request("content-1");
        }
        for _ in 0..5 {
            tracker.record_request("content-2");
        }

        let stats = tracker.stats();
        assert_eq!(stats.tracked_items, 2);
        assert_eq!(stats.total_requests, 15);
        assert!(stats.avg_requests_per_content > 0.0);
    }

    #[test]
    fn test_popularity_score() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request("content-1");
        tracker.record_request("content-1");

        let popularity = tracker.get_popularity("content-1").unwrap();
        assert!(popularity.popularity_score > 0.0);
    }

    #[test]
    fn test_request_rate() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request("content-1");
        std::thread::sleep(Duration::from_millis(100));
        tracker.record_request("content-1");

        let popularity = tracker.get_popularity("content-1").unwrap();
        assert!(popularity.request_rate > 0.0);
    }

    #[test]
    fn test_clear() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request("content-1");
        tracker.record_request("content-2");

        assert_eq!(tracker.content_map.len(), 2);

        tracker.clear();
        assert_eq!(tracker.content_map.len(), 0);
        assert_eq!(tracker.total_requests, 0);
    }

    #[test]
    fn test_max_tracked_items() {
        let config = TrackingConfig {
            max_tracked_items: 5,
            cleanup_interval: Duration::from_secs(1000), // Don't cleanup during test
            ..Default::default()
        };
        let mut tracker = PopularityTracker::with_config(config);

        // Add more items than the limit
        for i in 0..10 {
            tracker.record_request(format!("content-{}", i));
        }

        // Should not exceed max
        assert!(tracker.content_map.len() <= 5);
    }

    #[test]
    fn test_get_popularity_nonexistent() {
        let tracker = PopularityTracker::new();
        assert!(tracker.get_popularity("nonexistent").is_none());
    }

    #[test]
    fn test_timestamps() {
        let mut tracker = PopularityTracker::new();
        let before = Instant::now();

        tracker.record_request("content-1");
        std::thread::sleep(Duration::from_millis(50));
        tracker.record_request("content-1");

        let popularity = tracker.get_popularity("content-1").unwrap();

        assert!(popularity.first_seen >= before);
        assert!(popularity.last_seen >= popularity.first_seen);
    }

    #[test]
    fn test_decay_application() {
        let config = TrackingConfig {
            decay_rate: 0.5,
            cleanup_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let mut tracker = PopularityTracker::with_config(config);

        tracker.record_request("content-1");
        let score_before = tracker
            .get_popularity("content-1")
            .unwrap()
            .popularity_score;

        // Trigger cleanup by waiting and recording another request
        std::thread::sleep(Duration::from_millis(10));
        tracker.record_request("content-2");

        let score_after = tracker
            .get_popularity("content-1")
            .unwrap()
            .popularity_score;

        // Score should have decayed
        assert!(score_after < score_before);
    }

    #[test]
    fn test_unique_requesters_tracking() {
        let mut tracker = PopularityTracker::new();

        tracker.record_request_with_requester("content-1", Some("peer-1".to_string()));
        tracker.record_request_with_requester("content-1", Some("peer-2".to_string()));
        tracker.record_request_with_requester("content-1", Some("peer-3".to_string()));
        tracker.record_request_with_requester("content-1", Some("peer-1".to_string())); // Duplicate

        let popularity = tracker.get_popularity("content-1").unwrap();
        assert_eq!(popularity.unique_requesters, 3);
    }

    #[test]
    fn test_empty_top_content() {
        let tracker = PopularityTracker::new();
        let top = tracker.top_content(10);
        assert_eq!(top.len(), 0);
    }
}
