//! Content popularity tracking for CHIE Protocol.
//!
//! This module tracks content access patterns to help with:
//! - Dynamic pricing based on demand
//! - Smart caching decisions
//! - Investment recommendations

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default time windows for popularity calculation.
pub const WINDOW_1_HOUR: Duration = Duration::from_secs(3600);
pub const WINDOW_24_HOURS: Duration = Duration::from_secs(24 * 3600);
pub const WINDOW_7_DAYS: Duration = Duration::from_secs(7 * 24 * 3600);

/// Configuration for popularity tracking.
#[derive(Debug, Clone)]
pub struct PopularityConfig {
    /// Maximum number of content items to track.
    pub max_tracked_content: usize,
    /// Time window for "hot" content (default: 1 hour).
    pub hot_window: Duration,
    /// Time window for "trending" content (default: 24 hours).
    pub trending_window: Duration,
    /// Minimum requests to be considered popular.
    pub min_requests_for_popular: u64,
    /// How often to prune old data.
    pub prune_interval: Duration,
}

impl Default for PopularityConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_tracked_content: 10000,
            hot_window: WINDOW_1_HOUR,
            trending_window: WINDOW_24_HOURS,
            min_requests_for_popular: 10,
            prune_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Access record for a single content request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AccessRecord {
    timestamp: Instant,
    bytes_transferred: u64,
    peer_count: u32,
}

/// Popularity data for a single content item.
#[derive(Debug, Clone)]
pub struct ContentPopularity {
    /// Content CID.
    pub cid: String,
    /// Total requests (all time).
    pub total_requests: u64,
    /// Total bytes transferred (all time).
    pub total_bytes: u64,
    /// Unique peers that requested this content.
    pub unique_peers: u64,
    /// First access timestamp.
    pub first_seen: Instant,
    /// Last access timestamp.
    pub last_access: Instant,
    /// Access records for time-windowed calculations.
    access_history: Vec<AccessRecord>,
}

impl ContentPopularity {
    #[inline]
    fn new(cid: String) -> Self {
        let now = Instant::now();
        Self {
            cid,
            total_requests: 0,
            total_bytes: 0,
            unique_peers: 0,
            first_seen: now,
            last_access: now,
            access_history: Vec::new(),
        }
    }

    /// Record an access.
    fn record_access(&mut self, bytes: u64, is_new_peer: bool) {
        self.total_requests += 1;
        self.total_bytes += bytes;
        if is_new_peer {
            self.unique_peers += 1;
        }
        self.last_access = Instant::now();

        self.access_history.push(AccessRecord {
            timestamp: Instant::now(),
            bytes_transferred: bytes,
            peer_count: if is_new_peer { 1 } else { 0 },
        });
    }

    /// Get the number of requests within a time window.
    #[inline]
    fn requests_in_window(&self, window: Duration) -> u64 {
        let cutoff = Instant::now() - window;
        self.access_history
            .iter()
            .filter(|r| r.timestamp > cutoff)
            .count() as u64
    }

    /// Get bytes transferred within a time window.
    #[inline]
    fn bytes_in_window(&self, window: Duration) -> u64 {
        let cutoff = Instant::now() - window;
        self.access_history
            .iter()
            .filter(|r| r.timestamp > cutoff)
            .map(|r| r.bytes_transferred)
            .sum()
    }

    /// Prune old access history.
    #[inline]
    fn prune_history(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.access_history.retain(|r| r.timestamp > cutoff);
    }
}

/// Popularity score calculation result.
#[derive(Debug, Clone)]
pub struct PopularityScore {
    /// Content CID.
    pub cid: String,
    /// Overall popularity score (0-100).
    pub score: f64,
    /// Requests in the last hour.
    pub hourly_requests: u64,
    /// Requests in the last 24 hours.
    pub daily_requests: u64,
    /// Bytes transferred in the last 24 hours.
    pub daily_bytes: u64,
    /// Total unique peers.
    pub unique_peers: u64,
    /// Demand level classification.
    pub demand_level: DemandLevel,
    /// Recommended multiplier for pricing.
    pub price_multiplier: f64,
}

/// Demand level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl DemandLevel {
    /// Get the price multiplier for this demand level.
    #[inline]
    #[must_use]
    pub fn price_multiplier(&self) -> f64 {
        match self {
            DemandLevel::Low => 0.5,
            DemandLevel::Medium => 1.0,
            DemandLevel::High => 1.5,
            DemandLevel::VeryHigh => 3.0,
        }
    }
}

/// Content popularity tracker.
pub struct PopularityTracker {
    config: PopularityConfig,
    content: HashMap<String, ContentPopularity>,
    peer_seen: HashMap<String, std::collections::HashSet<String>>,
    last_prune: Instant,
}

impl Default for PopularityTracker {
    #[inline]
    fn default() -> Self {
        Self::new(PopularityConfig::default())
    }
}

impl PopularityTracker {
    /// Create a new popularity tracker.
    #[inline]
    #[must_use]
    pub fn new(config: PopularityConfig) -> Self {
        Self {
            config,
            content: HashMap::new(),
            peer_seen: HashMap::new(),
            last_prune: Instant::now(),
        }
    }

    /// Record a content access.
    pub fn record_access(&mut self, cid: &str, bytes: u64, peer_id: &str) {
        // Check if this is a new peer for this content
        let is_new_peer = self
            .peer_seen
            .entry(cid.to_string())
            .or_default()
            .insert(peer_id.to_string());

        // Get or create popularity data
        let popularity = self
            .content
            .entry(cid.to_string())
            .or_insert_with(|| ContentPopularity::new(cid.to_string()));

        popularity.record_access(bytes, is_new_peer);

        // Periodically prune old data
        self.maybe_prune();
    }

    /// Get popularity data for a content item.
    #[inline]
    #[must_use]
    pub fn get_popularity(&self, cid: &str) -> Option<&ContentPopularity> {
        self.content.get(cid)
    }

    /// Calculate popularity score for a content item.
    #[must_use]
    #[inline]
    pub fn calculate_score(&self, cid: &str) -> Option<PopularityScore> {
        let popularity = self.content.get(cid)?;

        let hourly_requests = popularity.requests_in_window(self.config.hot_window);
        let daily_requests = popularity.requests_in_window(self.config.trending_window);
        let daily_bytes = popularity.bytes_in_window(self.config.trending_window);

        // Calculate score based on multiple factors
        let recency_score = calculate_recency_score(popularity.last_access);
        let volume_score = calculate_volume_score(daily_requests);
        let diversity_score = calculate_diversity_score(popularity.unique_peers, daily_requests);

        // Weighted combination
        let score = (recency_score * 0.3 + volume_score * 0.5 + diversity_score * 0.2) * 100.0;
        let score = score.clamp(0.0, 100.0);

        let demand_level = classify_demand(daily_requests, self.config.min_requests_for_popular);
        let price_multiplier = demand_level.price_multiplier();

        Some(PopularityScore {
            cid: cid.to_string(),
            score,
            hourly_requests,
            daily_requests,
            daily_bytes,
            unique_peers: popularity.unique_peers,
            demand_level,
            price_multiplier,
        })
    }

    /// Get the top N most popular content items.
    #[must_use]
    #[inline]
    pub fn get_top_content(&self, n: usize) -> Vec<PopularityScore> {
        let mut scores: Vec<PopularityScore> = self
            .content
            .keys()
            .filter_map(|cid| self.calculate_score(cid))
            .collect();

        scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        scores.truncate(n);
        scores
    }

    /// Get "hot" content (high activity in the last hour).
    #[must_use]
    #[inline]
    pub fn get_hot_content(&self) -> Vec<PopularityScore> {
        let min_hourly = self.config.min_requests_for_popular / 24;

        self.content
            .keys()
            .filter_map(|cid| self.calculate_score(cid))
            .filter(|s| s.hourly_requests >= min_hourly)
            .collect()
    }

    /// Get "trending" content (growing popularity).
    #[must_use]
    #[inline]
    pub fn get_trending_content(&self) -> Vec<PopularityScore> {
        let mut scores: Vec<PopularityScore> = self
            .content
            .keys()
            .filter_map(|cid| {
                let score = self.calculate_score(cid)?;

                // Check if hourly rate > daily average rate
                let hourly_rate = score.hourly_requests as f64;
                let daily_avg_rate = score.daily_requests as f64 / 24.0;

                if hourly_rate > daily_avg_rate * 1.5 {
                    Some(score)
                } else {
                    None
                }
            })
            .collect();

        scores.sort_by(|a, b| b.hourly_requests.cmp(&a.hourly_requests));
        scores
    }

    /// Get content statistics.
    #[must_use]
    #[inline]
    pub fn get_stats(&self) -> PopularityStats {
        let total_content = self.content.len();
        let total_requests: u64 = self.content.values().map(|p| p.total_requests).sum();
        let total_bytes: u64 = self.content.values().map(|p| p.total_bytes).sum();

        PopularityStats {
            tracked_content: total_content,
            total_requests,
            total_bytes_transferred: total_bytes,
        }
    }

    /// Prune old data if needed.
    fn maybe_prune(&mut self) {
        if Instant::now().duration_since(self.last_prune) < self.config.prune_interval {
            return;
        }

        // Prune old access history
        let max_history = self.config.trending_window * 2;
        for popularity in self.content.values_mut() {
            popularity.prune_history(max_history);
        }

        // If we have too many content items, remove the least popular
        if self.content.len() > self.config.max_tracked_content {
            let mut by_score: Vec<(String, u64)> = self
                .content
                .iter()
                .map(|(cid, p)| {
                    (
                        cid.clone(),
                        p.requests_in_window(self.config.trending_window),
                    )
                })
                .collect();

            by_score.sort_by(|a, b| a.1.cmp(&b.1));

            // Remove bottom 10%
            let to_remove = self.content.len() - self.config.max_tracked_content;
            for (cid, _) in by_score.into_iter().take(to_remove) {
                self.content.remove(&cid);
                self.peer_seen.remove(&cid);
            }
        }

        self.last_prune = Instant::now();
    }
}

/// Statistics about the popularity tracker.
#[derive(Debug, Clone)]
pub struct PopularityStats {
    /// Number of content items being tracked.
    pub tracked_content: usize,
    /// Total requests across all content.
    pub total_requests: u64,
    /// Total bytes transferred across all content.
    pub total_bytes_transferred: u64,
}

// Helper functions

fn calculate_recency_score(last_access: Instant) -> f64 {
    let age = Instant::now().duration_since(last_access);
    let hours = age.as_secs_f64() / 3600.0;

    // Exponential decay: score halves every 24 hours
    0.5_f64.powf(hours / 24.0)
}

fn calculate_volume_score(daily_requests: u64) -> f64 {
    // Logarithmic scale: score increases with requests but with diminishing returns
    if daily_requests == 0 {
        return 0.0;
    }
    let log_requests = (daily_requests as f64).ln();
    (log_requests / 10.0).min(1.0) // Normalize to 0-1
}

fn calculate_diversity_score(unique_peers: u64, total_requests: u64) -> f64 {
    if total_requests == 0 {
        return 0.0;
    }
    let ratio = unique_peers as f64 / total_requests as f64;
    ratio.min(1.0) // Higher ratio = more diverse audience
}

fn classify_demand(daily_requests: u64, min_popular: u64) -> DemandLevel {
    if daily_requests < min_popular / 2 {
        DemandLevel::Low
    } else if daily_requests < min_popular {
        DemandLevel::Medium
    } else if daily_requests < min_popular * 5 {
        DemandLevel::High
    } else {
        DemandLevel::VeryHigh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_access() {
        let mut tracker = PopularityTracker::default();

        tracker.record_access("QmTest123", 1024, "peer1");
        tracker.record_access("QmTest123", 2048, "peer2");
        tracker.record_access("QmTest123", 1024, "peer1"); // Same peer

        let popularity = tracker.get_popularity("QmTest123").unwrap();
        assert_eq!(popularity.total_requests, 3);
        assert_eq!(popularity.total_bytes, 1024 + 2048 + 1024);
        assert_eq!(popularity.unique_peers, 2);
    }

    #[test]
    fn test_calculate_score() {
        let mut tracker = PopularityTracker::default();

        for i in 0..20 {
            tracker.record_access("QmPopular", 1024, &format!("peer{}", i));
        }

        let score = tracker.calculate_score("QmPopular").unwrap();
        assert!(score.score > 0.0);
        assert_eq!(score.daily_requests, 20);
        assert_eq!(score.unique_peers, 20);
    }

    #[test]
    fn test_get_top_content() {
        let mut tracker = PopularityTracker::default();

        // Create content with different popularity
        for i in 0..10 {
            tracker.record_access("QmLow", 1024, &format!("peer{}", i));
        }
        for i in 0..50 {
            tracker.record_access("QmMedium", 1024, &format!("peer{}", i));
        }
        for i in 0..100 {
            tracker.record_access("QmHigh", 1024, &format!("peer{}", i));
        }

        let top = tracker.get_top_content(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].cid, "QmHigh");
    }

    #[test]
    fn test_demand_classification() {
        assert_eq!(classify_demand(0, 10), DemandLevel::Low);
        assert_eq!(classify_demand(3, 10), DemandLevel::Low);
        assert_eq!(classify_demand(7, 10), DemandLevel::Medium);
        assert_eq!(classify_demand(15, 10), DemandLevel::High);
        assert_eq!(classify_demand(100, 10), DemandLevel::VeryHigh);
    }
}
