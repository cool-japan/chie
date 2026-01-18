//! Adaptive routing optimization module.
//!
//! This module provides intelligent path selection and optimization
//! based on network conditions, historical performance, and learning.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Represents a network path between two peers.
#[derive(Debug, Clone)]
pub struct Path {
    /// Unique identifier for this path
    pub id: String,
    /// Source peer ID
    pub source: String,
    /// Destination peer ID
    pub destination: String,
    /// Intermediate hops (relay peers)
    pub hops: Vec<String>,
    /// Estimated latency for this path
    pub latency: Duration,
    /// Estimated bandwidth (bytes/sec)
    pub bandwidth: u64,
    /// Path reliability score (0.0-1.0)
    pub reliability: f64,
    /// Last time this path was used
    pub last_used: Option<Instant>,
}

impl Path {
    /// Returns the total number of hops (including direct connection).
    pub fn hop_count(&self) -> usize {
        self.hops.len() + 1
    }

    /// Calculates a composite score for this path.
    pub fn score(&self, weights: &PathScoreWeights) -> f64 {
        let latency_score = self.latency_score();
        let bandwidth_score = self.bandwidth_score();
        let reliability_score = self.reliability;
        let hop_score = self.hop_score();

        weights.latency * latency_score
            + weights.bandwidth * bandwidth_score
            + weights.reliability * reliability_score
            + weights.hops * hop_score
    }

    fn latency_score(&self) -> f64 {
        // Lower latency = higher score
        // Using exponential decay: score = e^(-latency/100)
        // 10ms -> ~0.90, 50ms -> ~0.61, 100ms -> ~0.37, 500ms -> ~0.007
        let latency_ms = self.latency.as_millis() as f64;
        (-latency_ms / 100.0).exp()
    }

    fn bandwidth_score(&self) -> f64 {
        // Normalize bandwidth (assuming 1 Gbps as max)
        (self.bandwidth as f64 / 125_000_000.0).min(1.0)
    }

    fn hop_score(&self) -> f64 {
        // Fewer hops = higher score
        1.0 / (self.hop_count() as f64)
    }
}

/// Weights for path scoring.
#[derive(Debug, Clone)]
pub struct PathScoreWeights {
    /// Weight for latency (0.0-1.0)
    pub latency: f64,
    /// Weight for bandwidth (0.0-1.0)
    pub bandwidth: f64,
    /// Weight for reliability (0.0-1.0)
    pub reliability: f64,
    /// Weight for hop count (0.0-1.0)
    pub hops: f64,
}

impl Default for PathScoreWeights {
    fn default() -> Self {
        Self {
            latency: 0.3,
            bandwidth: 0.3,
            reliability: 0.3,
            hops: 0.1,
        }
    }
}

impl PathScoreWeights {
    /// Creates weights optimized for low latency.
    pub fn low_latency() -> Self {
        Self {
            latency: 0.6,
            bandwidth: 0.1,
            reliability: 0.2,
            hops: 0.1,
        }
    }

    /// Creates weights optimized for high bandwidth.
    pub fn high_bandwidth() -> Self {
        Self {
            latency: 0.1,
            bandwidth: 0.6,
            reliability: 0.2,
            hops: 0.1,
        }
    }

    /// Creates weights optimized for reliability.
    pub fn high_reliability() -> Self {
        Self {
            latency: 0.2,
            bandwidth: 0.2,
            reliability: 0.5,
            hops: 0.1,
        }
    }
}

/// Strategy for selecting paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Always use the shortest path (fewest hops)
    ShortestPath,
    /// Use the path with lowest latency
    LowestLatency,
    /// Use the path with highest bandwidth
    HighestBandwidth,
    /// Use the most reliable path
    MostReliable,
    /// Use composite scoring with custom weights
    Composite,
    /// Adaptive selection based on recent performance
    Adaptive,
}

/// Configuration for adaptive routing.
#[derive(Debug, Clone)]
pub struct AdaptiveRoutingConfig {
    /// Routing strategy to use
    pub strategy: RoutingStrategy,
    /// Weights for composite scoring
    pub score_weights: PathScoreWeights,
    /// How long to cache path information
    pub path_cache_duration: Duration,
    /// Minimum number of paths to consider
    pub min_paths: usize,
    /// Maximum number of paths to maintain
    pub max_paths: usize,
    /// Enable learning from path performance
    pub enable_learning: bool,
    /// Learning rate for adaptive updates (0.0-1.0)
    pub learning_rate: f64,
}

impl Default for AdaptiveRoutingConfig {
    fn default() -> Self {
        Self {
            strategy: RoutingStrategy::Composite,
            score_weights: PathScoreWeights::default(),
            path_cache_duration: Duration::from_secs(300),
            min_paths: 2,
            max_paths: 10,
            enable_learning: true,
            learning_rate: 0.1,
        }
    }
}

/// Statistics for a path's performance.
#[derive(Debug, Clone)]
pub struct PathStats {
    /// Number of times used
    pub use_count: u64,
    /// Number of successful transfers
    pub success_count: u64,
    /// Number of failed transfers
    pub failure_count: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Average actual latency observed
    pub avg_latency: Duration,
    /// Last update timestamp
    pub last_updated: Instant,
}

impl PathStats {
    fn new() -> Self {
        Self {
            use_count: 0,
            success_count: 0,
            failure_count: 0,
            bytes_transferred: 0,
            avg_latency: Duration::from_millis(0),
            last_updated: Instant::now(),
        }
    }

    fn success_rate(&self) -> f64 {
        if self.use_count == 0 {
            return 1.0;
        }
        self.success_count as f64 / self.use_count as f64
    }

    fn update_latency(&mut self, new_latency: Duration, learning_rate: f64) {
        let current_ms = self.avg_latency.as_millis() as f64;
        let new_ms = new_latency.as_millis() as f64;
        let updated_ms = current_ms * (1.0 - learning_rate) + new_ms * learning_rate;
        self.avg_latency = Duration::from_millis(updated_ms as u64);
        self.last_updated = Instant::now();
    }
}

/// Adaptive routing optimizer for selecting optimal paths.
pub struct AdaptiveRouter {
    config: AdaptiveRoutingConfig,
    /// Available paths indexed by (source, destination)
    paths: HashMap<(String, String), Vec<Path>>,
    /// Performance statistics for each path
    path_stats: HashMap<String, PathStats>,
}

impl AdaptiveRouter {
    /// Creates a new adaptive router with default configuration.
    pub fn new() -> Self {
        Self::with_config(AdaptiveRoutingConfig::default())
    }

    /// Creates a new adaptive router with custom configuration.
    pub fn with_config(config: AdaptiveRoutingConfig) -> Self {
        Self {
            config,
            paths: HashMap::new(),
            path_stats: HashMap::new(),
        }
    }

    /// Adds a path to the routing table.
    pub fn add_path(&mut self, path: Path) {
        let key = (path.source.clone(), path.destination.clone());

        // Initialize stats if needed
        if !self.path_stats.contains_key(&path.id) {
            self.path_stats.insert(path.id.clone(), PathStats::new());
        }

        let paths = self.paths.entry(key.clone()).or_default();

        // Replace existing path with same ID or add new
        if let Some(pos) = paths.iter().position(|p| p.id == path.id) {
            paths[pos] = path;
        } else {
            paths.push(path);
        }

        // Limit number of paths
        while paths.len() > self.config.max_paths {
            // Find and remove worst performing path
            let worst_idx = Self::find_worst_path_static(paths, &self.path_stats, &self.config);
            if let Some(idx) = worst_idx {
                let removed = paths.remove(idx);
                self.path_stats.remove(&removed.id);
            } else {
                break;
            }
        }
    }

    /// Finds the index of the worst performing path (static version to avoid borrow issues).
    fn find_worst_path_static(
        paths: &[Path],
        path_stats: &HashMap<String, PathStats>,
        config: &AdaptiveRoutingConfig,
    ) -> Option<usize> {
        if paths.is_empty() {
            return None;
        }

        paths
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                let score_a = Self::score_path_static(a, path_stats, config);
                let score_b = Self::score_path_static(b, path_stats, config);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(idx, _)| idx)
    }

    /// Static version of score_path to avoid borrow issues.
    fn score_path_static(
        path: &Path,
        path_stats: &HashMap<String, PathStats>,
        config: &AdaptiveRoutingConfig,
    ) -> f64 {
        let mut base_score = path.score(&config.score_weights);

        // Apply learning adjustments if enabled
        if config.enable_learning {
            if let Some(stats) = path_stats.get(&path.id) {
                base_score *= stats.success_rate();
            }
        }

        base_score
    }

    /// Selects the best path for a given source and destination.
    pub fn select_path(&self, source: &str, destination: &str) -> Option<Path> {
        let key = (source.to_string(), destination.to_string());
        let paths = self.paths.get(&key)?;

        if paths.is_empty() {
            return None;
        }

        match self.config.strategy {
            RoutingStrategy::ShortestPath => paths.iter().min_by_key(|p| p.hop_count()).cloned(),
            RoutingStrategy::LowestLatency => paths.iter().min_by_key(|p| p.latency).cloned(),
            RoutingStrategy::HighestBandwidth => paths.iter().max_by_key(|p| p.bandwidth).cloned(),
            RoutingStrategy::MostReliable => paths
                .iter()
                .max_by(|a, b| {
                    a.reliability
                        .partial_cmp(&b.reliability)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned(),
            RoutingStrategy::Composite | RoutingStrategy::Adaptive => paths
                .iter()
                .max_by(|a, b| {
                    let score_a = self.score_path(a);
                    let score_b = self.score_path(b);
                    score_a
                        .partial_cmp(&score_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .cloned(),
        }
    }

    /// Calculates a score for a path using current strategy.
    fn score_path(&self, path: &Path) -> f64 {
        let mut base_score = path.score(&self.config.score_weights);

        // Apply learning adjustments if enabled
        if self.config.enable_learning {
            if let Some(stats) = self.path_stats.get(&path.id) {
                base_score *= stats.success_rate();
            }
        }

        base_score
    }

    /// Records the outcome of using a path.
    pub fn record_transfer(
        &mut self,
        path_id: &str,
        success: bool,
        bytes: u64,
        actual_latency: Option<Duration>,
    ) {
        if let Some(stats) = self.path_stats.get_mut(path_id) {
            stats.use_count += 1;
            if success {
                stats.success_count += 1;
                stats.bytes_transferred += bytes;
            } else {
                stats.failure_count += 1;
            }

            if let Some(latency) = actual_latency {
                stats.update_latency(latency, self.config.learning_rate);
            }

            // Update path latency based on observed performance
            if self.config.enable_learning {
                if let Some(actual_latency) = actual_latency {
                    self.update_path_latency(path_id, actual_latency);
                }
            }
        }
    }

    /// Updates path latency based on observed performance.
    fn update_path_latency(&mut self, path_id: &str, observed_latency: Duration) {
        for paths in self.paths.values_mut() {
            if let Some(path) = paths.iter_mut().find(|p| p.id == path_id) {
                let current_ms = path.latency.as_millis() as f64;
                let observed_ms = observed_latency.as_millis() as f64;
                let updated_ms = current_ms * (1.0 - self.config.learning_rate)
                    + observed_ms * self.config.learning_rate;
                path.latency = Duration::from_millis(updated_ms as u64);
            }
        }
    }

    /// Returns all known paths between two peers.
    pub fn get_paths(&self, source: &str, destination: &str) -> Option<&Vec<Path>> {
        let key = (source.to_string(), destination.to_string());
        self.paths.get(&key)
    }

    /// Returns statistics for a specific path.
    pub fn get_path_stats(&self, path_id: &str) -> Option<&PathStats> {
        self.path_stats.get(path_id)
    }

    /// Returns routing statistics.
    pub fn stats(&self) -> RoutingStats {
        let total_paths: usize = self.paths.values().map(|v| v.len()).sum();
        let total_transfers: u64 = self.path_stats.values().map(|s| s.use_count).sum();
        let successful_transfers: u64 = self.path_stats.values().map(|s| s.success_count).sum();

        RoutingStats {
            total_paths,
            total_transfers,
            successful_transfers,
            avg_success_rate: if total_transfers > 0 {
                successful_transfers as f64 / total_transfers as f64
            } else {
                0.0
            },
        }
    }

    /// Removes stale paths based on cache duration.
    pub fn cleanup_stale_paths(&mut self) {
        let cutoff = Instant::now() - self.config.path_cache_duration;

        for paths in self.paths.values_mut() {
            paths.retain(|path| {
                if let Some(last_used) = path.last_used {
                    if last_used < cutoff {
                        self.path_stats.remove(&path.id);
                        return false;
                    }
                }
                true
            });
        }

        self.paths.retain(|_, paths| !paths.is_empty());
    }
}

impl Default for AdaptiveRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about routing performance.
#[derive(Debug, Clone)]
pub struct RoutingStats {
    /// Total number of known paths
    pub total_paths: usize,
    /// Total number of transfers attempted
    pub total_transfers: u64,
    /// Number of successful transfers
    pub successful_transfers: u64,
    /// Average success rate across all paths
    pub avg_success_rate: f64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    fn create_test_path(
        id: &str,
        source: &str,
        dest: &str,
        latency_ms: u64,
        bandwidth_mbps: u64,
    ) -> Path {
        Path {
            id: id.to_string(),
            source: source.to_string(),
            destination: dest.to_string(),
            hops: vec![],
            latency: Duration::from_millis(latency_ms),
            bandwidth: bandwidth_mbps * 125_000, // Mbps to bytes/sec
            reliability: 0.95,
            last_used: Some(Instant::now()),
        }
    }

    #[test]
    fn test_adaptive_router_new() {
        let router = AdaptiveRouter::new();
        assert_eq!(router.stats().total_paths, 0);
    }

    #[test]
    fn test_add_path() {
        let mut router = AdaptiveRouter::new();
        let path = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path);

        assert_eq!(router.stats().total_paths, 1);
        assert!(router.get_paths("a", "b").is_some());
    }

    #[test]
    fn test_select_shortest_path() {
        let mut config = AdaptiveRoutingConfig::default();
        config.strategy = RoutingStrategy::ShortestPath;
        let mut router = AdaptiveRouter::with_config(config);

        let mut path1 = create_test_path("p1", "a", "b", 10, 100);
        path1.hops = vec!["relay1".to_string()];

        let path2 = create_test_path("p2", "a", "b", 20, 100);

        router.add_path(path1);
        router.add_path(path2);

        let selected = router.select_path("a", "b").unwrap();
        assert_eq!(selected.id, "p2"); // Direct path (no hops)
    }

    #[test]
    fn test_select_lowest_latency() {
        let mut config = AdaptiveRoutingConfig::default();
        config.strategy = RoutingStrategy::LowestLatency;
        let mut router = AdaptiveRouter::with_config(config);

        router.add_path(create_test_path("p1", "a", "b", 50, 100));
        router.add_path(create_test_path("p2", "a", "b", 10, 100));
        router.add_path(create_test_path("p3", "a", "b", 30, 100));

        let selected = router.select_path("a", "b").unwrap();
        assert_eq!(selected.id, "p2");
    }

    #[test]
    fn test_select_highest_bandwidth() {
        let mut config = AdaptiveRoutingConfig::default();
        config.strategy = RoutingStrategy::HighestBandwidth;
        let mut router = AdaptiveRouter::with_config(config);

        router.add_path(create_test_path("p1", "a", "b", 10, 100));
        router.add_path(create_test_path("p2", "a", "b", 10, 500));
        router.add_path(create_test_path("p3", "a", "b", 10, 200));

        let selected = router.select_path("a", "b").unwrap();
        assert_eq!(selected.id, "p2");
    }

    #[test]
    fn test_path_scoring() {
        let path = create_test_path("p1", "a", "b", 20, 200);
        let weights = PathScoreWeights::default();
        let score = path.score(&weights);
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_score_weights_presets() {
        let low_lat = PathScoreWeights::low_latency();
        assert!(low_lat.latency > 0.5);

        let high_bw = PathScoreWeights::high_bandwidth();
        assert!(high_bw.bandwidth > 0.5);

        let high_rel = PathScoreWeights::high_reliability();
        assert!(high_rel.reliability > 0.4);
    }

    #[test]
    fn test_record_transfer_success() {
        let mut router = AdaptiveRouter::new();
        let path = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path);

        router.record_transfer("p1", true, 1000, Some(Duration::from_millis(15)));

        let stats = router.get_path_stats("p1").unwrap();
        assert_eq!(stats.use_count, 1);
        assert_eq!(stats.success_count, 1);
        assert_eq!(stats.bytes_transferred, 1000);
    }

    #[test]
    fn test_record_transfer_failure() {
        let mut router = AdaptiveRouter::new();
        let path = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path);

        router.record_transfer("p1", false, 0, None);

        let stats = router.get_path_stats("p1").unwrap();
        assert_eq!(stats.use_count, 1);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.bytes_transferred, 0);
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut router = AdaptiveRouter::new();
        let path = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path);

        router.record_transfer("p1", true, 100, None);
        router.record_transfer("p1", true, 100, None);
        router.record_transfer("p1", false, 0, None);

        let stats = router.get_path_stats("p1").unwrap();
        assert!((stats.success_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_learning_latency_update() {
        let mut config = AdaptiveRoutingConfig::default();
        config.learning_rate = 0.5;
        let mut router = AdaptiveRouter::with_config(config);

        let path = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path);

        // Record higher latency
        router.record_transfer("p1", true, 100, Some(Duration::from_millis(30)));

        // Path latency should have increased
        let paths = router.get_paths("a", "b").unwrap();
        let updated_path = &paths[0];
        assert!(updated_path.latency.as_millis() > 10);
    }

    #[test]
    fn test_max_paths_limit() {
        let mut config = AdaptiveRoutingConfig::default();
        config.max_paths = 3;
        let mut router = AdaptiveRouter::with_config(config);

        for i in 0..5 {
            router.add_path(create_test_path(&format!("p{}", i), "a", "b", 10, 100));
        }

        let paths = router.get_paths("a", "b").unwrap();
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn test_path_replacement() {
        let mut router = AdaptiveRouter::new();

        let path1 = create_test_path("p1", "a", "b", 10, 100);
        router.add_path(path1);

        // Add path with same ID but different properties
        let path2 = create_test_path("p1", "a", "b", 20, 200);
        router.add_path(path2);

        let paths = router.get_paths("a", "b").unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].latency.as_millis(), 20);
    }

    #[test]
    fn test_routing_stats() {
        let mut router = AdaptiveRouter::new();
        router.add_path(create_test_path("p1", "a", "b", 10, 100));
        router.add_path(create_test_path("p2", "a", "c", 10, 100));

        router.record_transfer("p1", true, 100, None);
        router.record_transfer("p2", false, 0, None);

        let stats = router.stats();
        assert_eq!(stats.total_paths, 2);
        assert_eq!(stats.total_transfers, 2);
        assert_eq!(stats.successful_transfers, 1);
        assert!((stats.avg_success_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_cleanup_stale_paths() {
        let mut config = AdaptiveRoutingConfig::default();
        config.path_cache_duration = Duration::from_millis(50);
        let mut router = AdaptiveRouter::with_config(config);

        let mut path = create_test_path("p1", "a", "b", 10, 100);
        path.last_used = Some(Instant::now() - Duration::from_millis(100));
        router.add_path(path);

        router.cleanup_stale_paths();

        assert_eq!(router.stats().total_paths, 0);
    }

    #[test]
    fn test_path_hop_count() {
        let mut path = create_test_path("p1", "a", "b", 10, 100);
        assert_eq!(path.hop_count(), 1); // Direct

        path.hops = vec!["relay1".to_string(), "relay2".to_string()];
        assert_eq!(path.hop_count(), 3); // 2 relays + 1
    }

    #[test]
    fn test_composite_strategy() {
        let mut config = AdaptiveRoutingConfig::default();
        config.strategy = RoutingStrategy::Composite;
        config.score_weights = PathScoreWeights::low_latency();
        let mut router = AdaptiveRouter::with_config(config);

        router.add_path(create_test_path("p1", "a", "b", 100, 100)); // High latency
        router.add_path(create_test_path("p2", "a", "b", 10, 50)); // Low latency

        let selected = router.select_path("a", "b").unwrap();
        assert_eq!(selected.id, "p2"); // Should prefer lower latency
    }

    #[test]
    fn test_adaptive_strategy_with_learning() {
        let mut config = AdaptiveRoutingConfig::default();
        config.strategy = RoutingStrategy::Adaptive;
        config.enable_learning = true;
        let mut router = AdaptiveRouter::with_config(config);

        router.add_path(create_test_path("p1", "a", "b", 10, 100));
        router.add_path(create_test_path("p2", "a", "b", 15, 100));

        // Make p1 unreliable
        router.record_transfer("p1", false, 0, None);
        router.record_transfer("p1", false, 0, None);
        router.record_transfer("p2", true, 100, None);

        // Should now prefer p2 due to better success rate
        let selected = router.select_path("a", "b").unwrap();
        assert_eq!(selected.id, "p2");
    }
}
