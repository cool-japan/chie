//! Selective pinning optimizer for CHIE Protocol.
//!
//! This module provides:
//! - Content profitability scoring
//! - Storage allocation optimization
//! - Pin/unpin recommendations

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for the pinning optimizer.
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// Maximum storage to allocate (bytes).
    pub max_storage_bytes: u64,
    /// Minimum expected revenue per GB per day.
    pub min_revenue_per_gb: f64,
    /// Weight for popularity score (0.0-1.0).
    pub popularity_weight: f64,
    /// Weight for revenue score (0.0-1.0).
    pub revenue_weight: f64,
    /// Weight for freshness score (0.0-1.0).
    pub freshness_weight: f64,
    /// How often to recalculate recommendations.
    pub recalc_interval: Duration,
    /// Minimum time to keep content pinned.
    pub min_pin_duration: Duration,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 100 * 1024 * 1024 * 1024, // 100 GB
            min_revenue_per_gb: 0.01,
            popularity_weight: 0.4,
            revenue_weight: 0.4,
            freshness_weight: 0.2,
            recalc_interval: Duration::from_secs(3600), // 1 hour
            min_pin_duration: Duration::from_secs(86400), // 1 day
        }
    }
}

/// Content metrics for scoring.
#[derive(Debug, Clone)]
pub struct ContentMetrics {
    /// Content identifier.
    pub cid: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Total requests served.
    pub total_requests: u64,
    /// Requests in last 24 hours.
    pub daily_requests: u64,
    /// Total revenue earned (points).
    pub total_revenue: u64,
    /// Revenue in last 24 hours.
    pub daily_revenue: u64,
    /// When content was first pinned.
    pub pinned_at: Instant,
    /// Last time content was requested.
    pub last_request: Option<Instant>,
    /// Current demand multiplier.
    pub demand_multiplier: f64,
}

impl ContentMetrics {
    /// Create new metrics for content.
    pub fn new(cid: String, size_bytes: u64) -> Self {
        Self {
            cid,
            size_bytes,
            total_requests: 0,
            daily_requests: 0,
            total_revenue: 0,
            daily_revenue: 0,
            pinned_at: Instant::now(),
            last_request: None,
            demand_multiplier: 1.0,
        }
    }

    /// Record a request.
    pub fn record_request(&mut self, revenue: u64) {
        self.total_requests += 1;
        self.daily_requests += 1;
        self.total_revenue += revenue;
        self.daily_revenue += revenue;
        self.last_request = Some(Instant::now());
    }

    /// Calculate revenue per GB.
    #[must_use]
    #[inline]
    pub fn revenue_per_gb(&self) -> f64 {
        let size_gb = self.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        if size_gb > 0.0 {
            self.total_revenue as f64 / size_gb
        } else {
            0.0
        }
    }

    /// Calculate daily revenue per GB.
    #[must_use]
    #[inline]
    pub fn daily_revenue_per_gb(&self) -> f64 {
        let size_gb = self.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        if size_gb > 0.0 {
            self.daily_revenue as f64 / size_gb
        } else {
            0.0
        }
    }

    /// Get time since last request.
    #[must_use]
    #[inline]
    pub fn time_since_last_request(&self) -> Duration {
        self.last_request
            .map(|t| t.elapsed())
            .unwrap_or(self.pinned_at.elapsed())
    }
}

/// Scored content for optimization.
#[derive(Debug, Clone)]
pub struct ScoredContent {
    /// Content identifier.
    pub cid: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Composite score (0.0-1.0).
    pub score: f64,
    /// Individual score components.
    pub components: ScoreComponents,
    /// Recommendation.
    pub recommendation: PinRecommendation,
}

/// Score components for analysis.
#[derive(Debug, Clone)]
pub struct ScoreComponents {
    /// Popularity score (0.0-1.0).
    pub popularity: f64,
    /// Revenue score (0.0-1.0).
    pub revenue: f64,
    /// Freshness score (0.0-1.0).
    pub freshness: f64,
    /// Demand multiplier impact.
    pub demand: f64,
}

/// Pin recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRecommendation {
    /// Keep pinned (high value).
    Keep,
    /// Consider unpinning (low value).
    Unpin,
    /// New content to pin.
    Pin,
    /// Content is being evaluated.
    Evaluate,
}

/// Selective pinning optimizer.
pub struct PinningOptimizer {
    config: PinningConfig,
    /// Metrics for pinned content.
    content_metrics: HashMap<String, ContentMetrics>,
    /// Current storage usage.
    used_storage: u64,
    /// Last optimization time.
    #[allow(dead_code)]
    last_optimization: Option<Instant>,
}

impl Default for PinningOptimizer {
    fn default() -> Self {
        Self::new(PinningConfig::default())
    }
}

impl PinningOptimizer {
    /// Create a new optimizer.
    pub fn new(config: PinningConfig) -> Self {
        Self {
            config,
            content_metrics: HashMap::new(),
            used_storage: 0,
            last_optimization: None,
        }
    }

    /// Register pinned content.
    pub fn register_content(&mut self, cid: String, size_bytes: u64) {
        let metrics = ContentMetrics::new(cid.clone(), size_bytes);
        self.content_metrics.insert(cid, metrics);
        self.used_storage += size_bytes;
    }

    /// Unregister content.
    pub fn unregister_content(&mut self, cid: &str) -> Option<ContentMetrics> {
        if let Some(metrics) = self.content_metrics.remove(cid) {
            self.used_storage = self.used_storage.saturating_sub(metrics.size_bytes);
            Some(metrics)
        } else {
            None
        }
    }

    /// Record a request for content.
    pub fn record_request(&mut self, cid: &str, revenue: u64) {
        if let Some(metrics) = self.content_metrics.get_mut(cid) {
            metrics.record_request(revenue);
        }
    }

    /// Update demand multiplier for content.
    pub fn update_demand(&mut self, cid: &str, multiplier: f64) {
        if let Some(metrics) = self.content_metrics.get_mut(cid) {
            metrics.demand_multiplier = multiplier;
        }
    }

    /// Calculate score for content.
    fn calculate_score(&self, metrics: &ContentMetrics) -> (f64, ScoreComponents) {
        // Popularity score based on daily requests (normalized)
        let max_daily = self
            .content_metrics
            .values()
            .map(|m| m.daily_requests)
            .max()
            .unwrap_or(1);
        let popularity = if max_daily > 0 {
            metrics.daily_requests as f64 / max_daily as f64
        } else {
            0.0
        };

        // Revenue score based on revenue per GB (normalized)
        let daily_rev_per_gb = metrics.daily_revenue_per_gb();
        let revenue = if daily_rev_per_gb >= self.config.min_revenue_per_gb {
            (daily_rev_per_gb / self.config.min_revenue_per_gb).min(1.0)
        } else {
            daily_rev_per_gb / self.config.min_revenue_per_gb
        };

        // Freshness score (how recently accessed)
        let time_since = metrics.time_since_last_request();
        let freshness = if time_since < Duration::from_secs(3600) {
            1.0
        } else if time_since < Duration::from_secs(86400) {
            0.7
        } else if time_since < Duration::from_secs(604_800) {
            0.4
        } else {
            0.1
        };

        // Demand multiplier boost
        let demand = (metrics.demand_multiplier - 1.0).max(0.0) / 2.0; // 0.0 to 1.0 range

        let components = ScoreComponents {
            popularity,
            revenue,
            freshness,
            demand,
        };

        // Weighted composite score
        let score = (self.config.popularity_weight * popularity)
            + (self.config.revenue_weight * revenue)
            + (self.config.freshness_weight * freshness)
            + (demand * 0.2); // Bonus for high demand

        (score.clamp(0.0, 1.0), components)
    }

    /// Get optimization recommendations.
    #[must_use]
    #[inline]
    pub fn get_recommendations(&self) -> Vec<ScoredContent> {
        let mut scored: Vec<ScoredContent> = self
            .content_metrics
            .values()
            .map(|metrics| {
                let (score, components) = self.calculate_score(metrics);
                let pin_duration = metrics.pinned_at.elapsed();

                let recommendation = if pin_duration < self.config.min_pin_duration {
                    PinRecommendation::Evaluate
                } else if score >= 0.6 {
                    PinRecommendation::Keep
                } else if score < 0.3 {
                    PinRecommendation::Unpin
                } else {
                    PinRecommendation::Evaluate
                };

                ScoredContent {
                    cid: metrics.cid.clone(),
                    size_bytes: metrics.size_bytes,
                    score,
                    components,
                    recommendation,
                }
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        scored
    }

    /// Get content to unpin to free space.
    #[must_use]
    #[inline]
    pub fn get_unpin_candidates(&self, bytes_needed: u64) -> Vec<String> {
        let mut recommendations = self.get_recommendations();

        // Sort by score ascending (lowest first)
        recommendations.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut candidates = Vec::new();
        let mut freed = 0u64;

        for scored in recommendations {
            if freed >= bytes_needed {
                break;
            }

            // Only unpin content past minimum duration
            if let Some(metrics) = self.content_metrics.get(&scored.cid) {
                if metrics.pinned_at.elapsed() >= self.config.min_pin_duration {
                    candidates.push(scored.cid);
                    freed += scored.size_bytes;
                }
            }
        }

        candidates
    }

    /// Check if new content should be pinned.
    #[must_use]
    pub fn should_pin(&self, _cid: &str, size_bytes: u64, expected_demand: f64) -> PinDecision {
        // Check storage capacity
        if self.used_storage + size_bytes > self.config.max_storage_bytes {
            // Need to free space
            let needed = (self.used_storage + size_bytes) - self.config.max_storage_bytes;
            let candidates = self.get_unpin_candidates(needed);

            if candidates.is_empty() {
                return PinDecision::Reject {
                    reason: "Insufficient storage and no low-value content to unpin".to_string(),
                };
            }

            return PinDecision::PinAfterUnpin {
                unpin_cids: candidates,
            };
        }

        // Check expected profitability
        if expected_demand < 0.5 {
            return PinDecision::Evaluate {
                reason: "Low expected demand, consider pinning later".to_string(),
            };
        }

        PinDecision::Accept
    }

    /// Get optimizer statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> OptimizerStats {
        let recommendations = self.get_recommendations();

        let keep_count = recommendations
            .iter()
            .filter(|r| r.recommendation == PinRecommendation::Keep)
            .count();
        let unpin_count = recommendations
            .iter()
            .filter(|r| r.recommendation == PinRecommendation::Unpin)
            .count();

        let avg_score = if recommendations.is_empty() {
            0.0
        } else {
            recommendations.iter().map(|r| r.score).sum::<f64>() / recommendations.len() as f64
        };

        OptimizerStats {
            total_content: self.content_metrics.len(),
            used_storage: self.used_storage,
            max_storage: self.config.max_storage_bytes,
            storage_utilization: self.used_storage as f64 / self.config.max_storage_bytes as f64,
            avg_score,
            keep_count,
            unpin_count,
        }
    }

    /// Reset daily metrics (call once per day).
    pub fn reset_daily_metrics(&mut self) {
        for metrics in self.content_metrics.values_mut() {
            metrics.daily_requests = 0;
            metrics.daily_revenue = 0;
        }
    }
}

/// Decision for pinning new content.
#[derive(Debug, Clone)]
pub enum PinDecision {
    /// Accept and pin immediately.
    Accept,
    /// Pin after unpinning specified content.
    PinAfterUnpin { unpin_cids: Vec<String> },
    /// Evaluate later (borderline).
    Evaluate { reason: String },
    /// Reject pinning.
    Reject { reason: String },
}

/// Optimizer statistics.
#[derive(Debug, Clone)]
pub struct OptimizerStats {
    /// Total pinned content.
    pub total_content: usize,
    /// Used storage in bytes.
    pub used_storage: u64,
    /// Maximum storage in bytes.
    pub max_storage: u64,
    /// Storage utilization (0.0-1.0).
    pub storage_utilization: f64,
    /// Average content score.
    pub avg_score: f64,
    /// Content recommended to keep.
    pub keep_count: usize,
    /// Content recommended to unpin.
    pub unpin_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_metrics() {
        let mut metrics = ContentMetrics::new("QmTest".to_string(), 1024 * 1024 * 100); // 100 MB

        metrics.record_request(100);
        metrics.record_request(200);

        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.total_revenue, 300);
        assert!(metrics.last_request.is_some());
    }

    #[test]
    fn test_optimizer_register() {
        let mut optimizer = PinningOptimizer::default();

        optimizer.register_content("QmTest1".to_string(), 1024 * 1024 * 100);
        optimizer.register_content("QmTest2".to_string(), 1024 * 1024 * 200);

        assert_eq!(optimizer.content_metrics.len(), 2);
        assert_eq!(optimizer.used_storage, 1024 * 1024 * 300);
    }

    #[test]
    fn test_optimizer_recommendations() {
        let mut optimizer = PinningOptimizer::default();

        optimizer.register_content("QmHigh".to_string(), 1024 * 1024 * 100);
        optimizer.register_content("QmLow".to_string(), 1024 * 1024 * 100);

        // Simulate high activity for one content
        for _ in 0..100 {
            optimizer.record_request("QmHigh", 10);
        }

        let recommendations = optimizer.get_recommendations();
        assert_eq!(recommendations.len(), 2);

        // High activity content should have higher score
        let high = recommendations.iter().find(|r| r.cid == "QmHigh").unwrap();
        let low = recommendations.iter().find(|r| r.cid == "QmLow").unwrap();
        assert!(high.score > low.score);
    }

    #[test]
    fn test_pin_decision() {
        let config = PinningConfig {
            max_storage_bytes: 1024 * 1024 * 500,     // 500 MB
            min_pin_duration: Duration::from_secs(0), // Allow immediate unpin for testing
            ..Default::default()
        };
        let mut optimizer = PinningOptimizer::new(config);

        optimizer.register_content("QmExisting".to_string(), 1024 * 1024 * 400);

        // Should accept small content
        let decision = optimizer.should_pin("QmNew1", 1024 * 1024 * 50, 1.0);
        assert!(matches!(decision, PinDecision::Accept));

        // Should require unpin for large content
        let decision = optimizer.should_pin("QmNew2", 1024 * 1024 * 200, 1.0);
        assert!(matches!(decision, PinDecision::PinAfterUnpin { .. }));
    }
}
