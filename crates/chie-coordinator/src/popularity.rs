//! Content popularity tracking and trending analysis.
//!
//! This module tracks content access patterns, calculates popularity scores,
//! and identifies trending content for recommendations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Content popularity tracker.
#[derive(Clone)]
pub struct PopularityTracker {
    inner: Arc<RwLock<PopularityTrackerInner>>,
    config: PopularityConfig,
}

struct PopularityTrackerInner {
    /// Content access records (content_id -> access data).
    access_data: HashMap<String, ContentAccessData>,
    /// Trending content cache (updated periodically).
    trending_cache: Vec<TrendingContent>,
    /// Last cache update timestamp.
    last_cache_update: DateTime<Utc>,
}

/// Content access data.
#[derive(Debug, Clone)]
struct ContentAccessData {
    /// Total view count.
    view_count: u64,
    /// Total download count.
    download_count: u64,
    /// Total bandwidth served (bytes).
    bandwidth_served: u64,
    /// Unique viewer count (approximate via IP tracking).
    unique_viewers: u64,
    /// Access timestamps (for time-series analysis).
    recent_accesses: Vec<DateTime<Utc>>,
    /// First seen timestamp.
    first_seen: DateTime<Utc>,
    /// Last access timestamp.
    last_access: DateTime<Utc>,
    /// Average session duration (seconds).
    avg_session_duration: f64,
}

/// Trending content information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendingContent {
    /// Content ID.
    pub content_id: String,
    /// Popularity score (0.0 - 100.0).
    pub popularity_score: f64,
    /// View count in the trending window.
    pub recent_views: u64,
    /// View growth rate (percentage).
    pub growth_rate: f64,
    /// Total views all-time.
    pub total_views: u64,
    /// Rank in trending list.
    pub rank: usize,
}

/// Access event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessEvent {
    /// Content viewed (metadata accessed).
    View,
    /// Content downloaded (chunk requested).
    Download,
    /// Content streaming started.
    Stream,
}

/// Popularity tracker configuration.
#[derive(Debug, Clone)]
pub struct PopularityConfig {
    /// Window for trending calculation (default: 24 hours).
    pub trending_window: Duration,
    /// Maximum recent accesses to track per content (default: 1000).
    pub max_recent_accesses: usize,
    /// Cache update interval (default: 5 minutes).
    pub cache_update_interval: Duration,
    /// Minimum views to be considered trending (default: 10).
    pub min_trending_views: u64,
    /// Decay factor for older views (0.0 - 1.0, default: 0.9).
    pub decay_factor: f64,
}

impl Default for PopularityConfig {
    fn default() -> Self {
        Self {
            trending_window: Duration::hours(24),
            max_recent_accesses: 1000,
            cache_update_interval: Duration::minutes(5),
            min_trending_views: 10,
            decay_factor: 0.9,
        }
    }
}

impl PopularityTracker {
    /// Create a new popularity tracker.
    pub fn new(config: PopularityConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PopularityTrackerInner {
                access_data: HashMap::new(),
                trending_cache: Vec::new(),
                // Initialize to past time to force immediate cache update
                last_cache_update: Utc::now() - Duration::hours(1),
            })),
            config,
        }
    }

    /// Record a content access event.
    pub async fn record_access(
        &self,
        content_id: &str,
        event_type: AccessEvent,
        bandwidth: u64,
        session_duration: Option<f64>,
    ) {
        let mut inner = self.inner.write().await;
        let now = Utc::now();

        let data = inner
            .access_data
            .entry(content_id.to_string())
            .or_insert_with(|| ContentAccessData {
                view_count: 0,
                download_count: 0,
                bandwidth_served: 0,
                unique_viewers: 0,
                recent_accesses: Vec::new(),
                first_seen: now,
                last_access: now,
                avg_session_duration: 0.0,
            });

        // Update counts based on event type
        match event_type {
            AccessEvent::View => {
                data.view_count += 1;
                crate::metrics::record_content_access("view");
            }
            AccessEvent::Download => {
                data.download_count += 1;
                crate::metrics::record_content_access("download");
            }
            AccessEvent::Stream => {
                data.view_count += 1;
                data.download_count += 1;
                crate::metrics::record_content_access("stream");
            }
        }

        data.bandwidth_served += bandwidth;
        data.last_access = now;

        // Update session duration
        if let Some(duration) = session_duration {
            let total_sessions = data.view_count as f64;
            data.avg_session_duration =
                ((data.avg_session_duration * (total_sessions - 1.0)) + duration) / total_sessions;
        }

        // Track recent accesses (maintain sliding window)
        data.recent_accesses.push(now);
        if data.recent_accesses.len() > self.config.max_recent_accesses {
            data.recent_accesses.remove(0);
        }

        // Update trending cache if needed
        if now - inner.last_cache_update > self.config.cache_update_interval {
            self.update_trending_cache_internal(&mut inner);
        }
    }

    /// Get content popularity score (0.0 - 100.0).
    pub async fn get_popularity_score(&self, content_id: &str) -> f64 {
        let inner = self.inner.read().await;
        if let Some(data) = inner.access_data.get(content_id) {
            self.calculate_popularity_score(data)
        } else {
            0.0
        }
    }

    /// Get trending content list.
    pub async fn get_trending(&self, limit: usize) -> Vec<TrendingContent> {
        let mut inner = self.inner.write().await;

        // Update cache if stale
        let now = Utc::now();
        if now - inner.last_cache_update > self.config.cache_update_interval {
            self.update_trending_cache_internal(&mut inner);
        }

        inner.trending_cache.iter().take(limit).cloned().collect()
    }

    /// Force refresh trending cache (primarily for testing).
    pub async fn refresh_trending_cache(&self) {
        let start = std::time::Instant::now();
        let mut inner = self.inner.write().await;
        self.update_trending_cache_internal(&mut inner);
        let duration_ms = start.elapsed().as_millis() as u64;
        crate::metrics::record_popularity_cache_refresh(duration_ms);
        crate::metrics::set_trending_content_count(inner.trending_cache.len());
    }

    /// Get content statistics.
    pub async fn get_content_stats(&self, content_id: &str) -> Option<ContentStats> {
        let inner = self.inner.read().await;
        inner.access_data.get(content_id).map(|data| {
            let now = Utc::now();
            let recent_window_start = now - self.config.trending_window;
            let recent_views = data
                .recent_accesses
                .iter()
                .filter(|ts| **ts >= recent_window_start)
                .count() as u64;

            ContentStats {
                total_views: data.view_count,
                total_downloads: data.download_count,
                total_bandwidth: data.bandwidth_served,
                unique_viewers: data.unique_viewers,
                recent_views,
                avg_session_duration: data.avg_session_duration,
                first_seen: data.first_seen,
                last_access: data.last_access,
                popularity_score: self.calculate_popularity_score(data),
            }
        })
    }

    /// Get global statistics.
    pub async fn get_global_stats(&self) -> GlobalPopularityStats {
        let inner = self.inner.read().await;

        let total_content = inner.access_data.len();
        let total_views: u64 = inner.access_data.values().map(|d| d.view_count).sum();
        let total_downloads: u64 = inner.access_data.values().map(|d| d.download_count).sum();
        let total_bandwidth: u64 = inner.access_data.values().map(|d| d.bandwidth_served).sum();

        let avg_popularity = if total_content > 0 {
            inner
                .access_data
                .values()
                .map(|d| self.calculate_popularity_score(d))
                .sum::<f64>()
                / total_content as f64
        } else {
            0.0
        };

        GlobalPopularityStats {
            total_content,
            total_views,
            total_downloads,
            total_bandwidth,
            avg_popularity,
            trending_count: inner.trending_cache.len(),
        }
    }

    /// Calculate popularity score for content.
    fn calculate_popularity_score(&self, data: &ContentAccessData) -> f64 {
        let now = Utc::now();
        let age_days = (now - data.first_seen).num_days().max(1) as f64;

        // Recent activity (last 24 hours)
        let recent_window_start = now - self.config.trending_window;
        let recent_views = data
            .recent_accesses
            .iter()
            .filter(|ts| **ts >= recent_window_start)
            .count() as f64;

        // Velocity (views per day)
        let velocity = data.view_count as f64 / age_days;

        // Engagement score (downloads / views ratio)
        let engagement = if data.view_count > 0 {
            data.download_count as f64 / data.view_count as f64
        } else {
            0.0
        };

        // Recency boost (decay factor for older content)
        let days_since_access = (now - data.last_access).num_days().max(0) as f64;
        let recency = self.config.decay_factor.powf(days_since_access);

        // Combined score (normalized to 0-100)
        (recent_views * 0.4 + velocity * 0.3 + engagement * 100.0 * 0.2 + recency * 10.0 * 0.1)
            .min(100.0)
    }

    /// Update trending cache (internal, assumes write lock held).
    fn update_trending_cache_internal(&self, inner: &mut PopularityTrackerInner) {
        let now = Utc::now();
        let recent_window_start = now - self.config.trending_window;

        let mut trending: Vec<_> = inner
            .access_data
            .iter()
            .filter_map(|(content_id, data)| {
                let recent_views = data
                    .recent_accesses
                    .iter()
                    .filter(|ts| **ts >= recent_window_start)
                    .count() as u64;

                if recent_views < self.config.min_trending_views {
                    return None;
                }

                // Calculate growth rate (compare to previous window)
                let prev_window_start = recent_window_start - self.config.trending_window;
                let prev_views = data
                    .recent_accesses
                    .iter()
                    .filter(|ts| **ts >= prev_window_start && **ts < recent_window_start)
                    .count() as u64;

                let growth_rate = if prev_views > 0 {
                    ((recent_views as f64 - prev_views as f64) / prev_views as f64) * 100.0
                } else if recent_views > 0 {
                    100.0 // New content
                } else {
                    0.0
                };

                Some((
                    content_id.clone(),
                    self.calculate_popularity_score(data),
                    recent_views,
                    growth_rate,
                    data.view_count,
                ))
            })
            .collect();

        // Sort by popularity score (descending)
        trending.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Build trending content list with ranks
        inner.trending_cache = trending
            .into_iter()
            .enumerate()
            .map(
                |(idx, (content_id, score, recent, growth, total))| TrendingContent {
                    content_id,
                    popularity_score: score,
                    recent_views: recent,
                    growth_rate: growth,
                    total_views: total,
                    rank: idx + 1,
                },
            )
            .collect();

        inner.last_cache_update = now;
    }

    /// Prune old access data (for memory management).
    pub async fn prune_old_data(&self, retention_days: i64) {
        let mut inner = self.inner.write().await;
        let cutoff = Utc::now() - Duration::days(retention_days);

        let before_count = inner.access_data.len();
        inner
            .access_data
            .retain(|_, data| data.last_access >= cutoff);
        let after_count = inner.access_data.len();
        let pruned_count = before_count - after_count;

        crate::metrics::record_popularity_data_pruned(pruned_count);
        crate::metrics::set_tracked_content_count(after_count);

        tracing::info!(
            "Pruned {} old popularity data entries, {} content entries remaining",
            pruned_count,
            after_count
        );
    }
}

/// Content statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentStats {
    pub total_views: u64,
    pub total_downloads: u64,
    pub total_bandwidth: u64,
    pub unique_viewers: u64,
    pub recent_views: u64,
    pub avg_session_duration: f64,
    pub first_seen: DateTime<Utc>,
    pub last_access: DateTime<Utc>,
    pub popularity_score: f64,
}

/// Global popularity statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalPopularityStats {
    pub total_content: usize,
    pub total_views: u64,
    pub total_downloads: u64,
    pub total_bandwidth: u64,
    pub avg_popularity: f64,
    pub trending_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_popularity_tracker_creation() {
        let config = PopularityConfig::default();
        let tracker = PopularityTracker::new(config);

        let stats = tracker.get_global_stats().await;
        assert_eq!(stats.total_content, 0);
        assert_eq!(stats.total_views, 0);
    }

    #[tokio::test]
    async fn test_record_access() {
        let config = PopularityConfig::default();
        let tracker = PopularityTracker::new(config);

        tracker
            .record_access("content1", AccessEvent::View, 1024, Some(60.0))
            .await;

        let score = tracker.get_popularity_score("content1").await;
        assert!(score > 0.0);
    }

    #[tokio::test]
    async fn test_trending_detection() {
        let config = PopularityConfig {
            min_trending_views: 2,
            ..Default::default()
        };
        let tracker = PopularityTracker::new(config);

        // Simulate multiple accesses
        for _ in 0..5 {
            tracker
                .record_access("popular_content", AccessEvent::View, 1024, None)
                .await;
        }

        // Force cache refresh after all accesses are recorded
        tracker.refresh_trending_cache().await;

        let trending = tracker.get_trending(10).await;
        assert!(!trending.is_empty());
        assert_eq!(trending[0].content_id, "popular_content");
    }

    #[tokio::test]
    async fn test_content_stats() {
        let config = PopularityConfig::default();
        let tracker = PopularityTracker::new(config);

        tracker
            .record_access("content1", AccessEvent::View, 1024, Some(30.0))
            .await;
        tracker
            .record_access("content1", AccessEvent::Download, 2048, Some(45.0))
            .await;

        let stats = tracker.get_content_stats("content1").await.unwrap();
        assert_eq!(stats.total_views, 1);
        assert_eq!(stats.total_downloads, 1);
        assert_eq!(stats.total_bandwidth, 3072);
    }

    #[tokio::test]
    async fn test_global_stats() {
        let config = PopularityConfig::default();
        let tracker = PopularityTracker::new(config);

        tracker
            .record_access("content1", AccessEvent::View, 1024, None)
            .await;
        tracker
            .record_access("content2", AccessEvent::View, 2048, None)
            .await;

        let stats = tracker.get_global_stats().await;
        assert_eq!(stats.total_content, 2);
        assert_eq!(stats.total_views, 2);
        assert_eq!(stats.total_bandwidth, 3072);
    }
}
