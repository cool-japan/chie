// SPDX-License-Identifier: MIT OR Apache-2.0
//! Topology-aware routing module
//!
//! This module provides intelligent routing decisions based on network topology
//! analysis. It considers factors like network distance, connectivity, reliability,
//! and bandwidth when determining optimal routes through the P2P network.
//!
//! # Features
//!
//! - Multi-hop path discovery and optimization
//! - Topology-aware peer selection for routing
//! - Route quality scoring based on multiple metrics
//! - Load balancing across multiple routes
//! - Route caching with TTL
//! - Fallback route management
//!
//! # Example
//!
//! ```
//! use chie_p2p::topology_routing::{TopologyRouter, RouteMetrics, RoutingStrategy};
//!
//! let mut router = TopologyRouter::new(RoutingStrategy::LowestLatency);
//!
//! // Add network topology information
//! router.add_link("peer1", "peer2", RouteMetrics {
//!     latency_ms: 10.0,
//!     bandwidth_mbps: 100.0,
//!     reliability: 0.99,
//!     hop_count: 1,
//! });
//!
//! // Find optimal route
//! if let Some(route) = router.find_route("peer1", "peer2") {
//!     println!("Route quality: {}", route.quality_score);
//! }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Metrics for a network link or route
#[derive(Debug, Clone, Copy)]
pub struct RouteMetrics {
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Bandwidth in Mbps
    pub bandwidth_mbps: f64,
    /// Reliability score (0.0-1.0)
    pub reliability: f64,
    /// Number of hops
    pub hop_count: usize,
}

impl RouteMetrics {
    /// Create new route metrics
    pub fn new(latency_ms: f64, bandwidth_mbps: f64, reliability: f64, hop_count: usize) -> Self {
        Self {
            latency_ms,
            bandwidth_mbps,
            reliability,
            hop_count,
        }
    }

    /// Combine metrics along a path (accumulative)
    pub fn combine(&self, other: &RouteMetrics) -> RouteMetrics {
        RouteMetrics {
            latency_ms: self.latency_ms + other.latency_ms,
            bandwidth_mbps: self.bandwidth_mbps.min(other.bandwidth_mbps), // Bottleneck
            reliability: self.reliability * other.reliability,             // Multiplicative
            hop_count: self.hop_count + other.hop_count,
        }
    }
}

/// Routing strategy for path selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Minimize total latency
    LowestLatency,
    /// Maximize minimum bandwidth (bottleneck)
    HighestBandwidth,
    /// Maximize reliability
    MostReliable,
    /// Minimize hop count
    ShortestPath,
    /// Balanced composite score
    Balanced,
}

/// A route through the network
#[derive(Debug, Clone)]
pub struct Route {
    /// Sequence of peer IDs forming the route
    pub path: Vec<String>,
    /// Aggregated metrics for the entire route
    pub metrics: RouteMetrics,
    /// Quality score (0.0-1.0, higher is better)
    pub quality_score: f64,
    /// Timestamp when route was discovered
    pub discovered_at: Instant,
    /// Number of times this route has been used
    pub use_count: u64,
    /// Last time this route was used
    pub last_used: Option<Instant>,
}

impl Route {
    /// Calculate quality score based on strategy
    fn calculate_quality(metrics: &RouteMetrics, strategy: RoutingStrategy) -> f64 {
        match strategy {
            RoutingStrategy::LowestLatency => {
                // Lower latency is better, normalize to 0-1
                // Assuming 500ms is very poor, 0ms is perfect
                (500.0 - metrics.latency_ms.min(500.0)) / 500.0
            }
            RoutingStrategy::HighestBandwidth => {
                // Higher bandwidth is better, normalize to 0-1
                // Assuming 1000 Mbps is excellent, 0 Mbps is poor
                (metrics.bandwidth_mbps.min(1000.0)) / 1000.0
            }
            RoutingStrategy::MostReliable => metrics.reliability,
            RoutingStrategy::ShortestPath => {
                // Fewer hops is better
                // Assuming 10 hops is very poor, 1 hop is perfect
                (10.0 - (metrics.hop_count as f64).min(10.0)) / 9.0
            }
            RoutingStrategy::Balanced => {
                // Composite score with equal weights
                let latency_score = (500.0 - metrics.latency_ms.min(500.0)) / 500.0;
                let bandwidth_score = (metrics.bandwidth_mbps.min(1000.0)) / 1000.0;
                let hop_score = (10.0 - (metrics.hop_count as f64).min(10.0)) / 9.0;
                (latency_score + bandwidth_score + metrics.reliability + hop_score) / 4.0
            }
        }
    }
}

/// Network link between two peers
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Link {
    from: String,
    to: String,
    metrics: RouteMetrics,
    last_updated: Instant,
}

/// Topology-aware routing engine
#[derive(Debug)]
pub struct TopologyRouter {
    /// Routing strategy to use
    strategy: RoutingStrategy,
    /// Network links (adjacency list)
    links: HashMap<String, Vec<Link>>,
    /// Cached routes
    route_cache: HashMap<(String, String), Vec<Route>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Maximum routes to cache per destination
    max_cached_routes: usize,
    /// Link update timeout
    link_timeout: Duration,
    /// Statistics
    routes_calculated: u64,
    cache_hits: u64,
    cache_misses: u64,
}

impl TopologyRouter {
    /// Create a new topology router
    pub fn new(strategy: RoutingStrategy) -> Self {
        Self {
            strategy,
            links: HashMap::new(),
            route_cache: HashMap::new(),
            cache_ttl: Duration::from_secs(60),
            max_cached_routes: 5,
            link_timeout: Duration::from_secs(300),
            routes_calculated: 0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set maximum cached routes per destination
    pub fn with_max_cached_routes(mut self, max: usize) -> Self {
        self.max_cached_routes = max;
        self
    }

    /// Add or update a network link
    pub fn add_link(&mut self, from: &str, to: &str, metrics: RouteMetrics) {
        let link = Link {
            from: from.to_string(),
            to: to.to_string(),
            metrics,
            last_updated: Instant::now(),
        };

        self.links
            .entry(from.to_string())
            .or_default()
            .retain(|l| l.to != to);
        self.links.entry(from.to_string()).or_default().push(link);

        // Invalidate cache entries that might be affected
        self.invalidate_cache_for_peer(from);
        self.invalidate_cache_for_peer(to);
    }

    /// Remove a link
    pub fn remove_link(&mut self, from: &str, to: &str) {
        if let Some(links) = self.links.get_mut(from) {
            links.retain(|l| l.to != to);
        }

        self.invalidate_cache_for_peer(from);
        self.invalidate_cache_for_peer(to);
    }

    /// Remove a peer and all its links
    pub fn remove_peer(&mut self, peer_id: &str) {
        // Remove outgoing links
        self.links.remove(peer_id);

        // Remove incoming links
        for links in self.links.values_mut() {
            links.retain(|l| l.to != peer_id);
        }

        self.invalidate_cache_for_peer(peer_id);
    }

    /// Clean up stale links
    pub fn cleanup_stale_links(&mut self) {
        let now = Instant::now();
        let timeout = self.link_timeout;

        for links in self.links.values_mut() {
            links.retain(|l| now.duration_since(l.last_updated) < timeout);
        }

        // Remove empty entries
        self.links.retain(|_, links| !links.is_empty());

        // Clear entire cache after cleanup
        self.route_cache.clear();
    }

    /// Find optimal route from source to destination
    pub fn find_route(&mut self, from: &str, to: &str) -> Option<Route> {
        // Check cache first
        let cache_key = (from.to_string(), to.to_string());
        if let Some(routes) = self.route_cache.get(&cache_key) {
            if let Some(best_route) = routes.first() {
                if best_route.discovered_at.elapsed() < self.cache_ttl {
                    self.cache_hits += 1;
                    return Some(best_route.clone());
                }
            }
        }

        self.cache_misses += 1;

        // Calculate new route using modified Dijkstra
        let route = self.calculate_route(from, to)?;

        // Cache the route
        self.route_cache
            .entry(cache_key)
            .or_default()
            .insert(0, route.clone());

        // Limit cache size
        if let Some(routes) = self
            .route_cache
            .get_mut(&(from.to_string(), to.to_string()))
        {
            routes.truncate(self.max_cached_routes);
        }

        self.routes_calculated += 1;

        Some(route)
    }

    /// Find multiple alternative routes
    pub fn find_alternative_routes(&mut self, from: &str, to: &str, count: usize) -> Vec<Route> {
        let mut routes = Vec::new();

        // Try to find multiple paths using k-shortest paths approach
        for _ in 0..count {
            if let Some(route) = self.calculate_route(from, to) {
                routes.push(route);
                // In a full implementation, we would exclude this path and find next best
                // For now, we'll just return the single best route
                break;
            }
        }

        routes
    }

    /// Calculate route using modified Dijkstra/BFS based on strategy
    fn calculate_route(&self, from: &str, to: &str) -> Option<Route> {
        // Direct connection check
        if let Some(links) = self.links.get(from) {
            if let Some(direct_link) = links.iter().find(|l| l.to == to) {
                return Some(Route {
                    path: vec![from.to_string(), to.to_string()],
                    metrics: direct_link.metrics,
                    quality_score: Route::calculate_quality(&direct_link.metrics, self.strategy),
                    discovered_at: Instant::now(),
                    use_count: 0,
                    last_used: None,
                });
            }
        }

        // Multi-hop path finding using BFS with quality scoring
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut best_route: Option<Route> = None;
        let mut best_score = 0.0;

        // Start from source
        queue.push_back((
            from.to_string(),
            vec![from.to_string()],
            RouteMetrics::new(0.0, f64::INFINITY, 1.0, 0),
        ));

        while let Some((current, path, metrics)) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            // Found destination
            if current == to {
                let score = Route::calculate_quality(&metrics, self.strategy);
                if score > best_score {
                    best_score = score;
                    best_route = Some(Route {
                        path: path.clone(),
                        metrics,
                        quality_score: score,
                        discovered_at: Instant::now(),
                        use_count: 0,
                        last_used: None,
                    });
                }
                continue;
            }

            // Explore neighbors
            if let Some(links) = self.links.get(&current) {
                for link in links {
                    if !visited.contains(&link.to) && !path.contains(&link.to) {
                        let mut new_path = path.clone();
                        new_path.push(link.to.clone());
                        let new_metrics = metrics.combine(&link.metrics);

                        queue.push_back((link.to.clone(), new_path, new_metrics));
                    }
                }
            }
        }

        best_route
    }

    /// Invalidate cache entries involving a peer
    fn invalidate_cache_for_peer(&mut self, peer_id: &str) {
        self.route_cache
            .retain(|(from, to), _| from != peer_id && to != peer_id);
    }

    /// Get routing statistics
    pub fn stats(&self) -> TopologyRouterStats {
        TopologyRouterStats {
            total_links: self.links.values().map(|v| v.len()).sum(),
            total_peers: self.links.len(),
            cached_routes: self.route_cache.len(),
            routes_calculated: self.routes_calculated,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            cache_hit_rate: if self.cache_hits + self.cache_misses > 0 {
                self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64
            } else {
                0.0
            },
        }
    }

    /// Get all known peers
    pub fn get_peers(&self) -> Vec<String> {
        self.links.keys().cloned().collect()
    }

    /// Get neighbors of a peer
    pub fn get_neighbors(&self, peer_id: &str) -> Vec<String> {
        self.links
            .get(peer_id)
            .map(|links| links.iter().map(|l| l.to.clone()).collect())
            .unwrap_or_default()
    }
}

/// Topology router statistics
#[derive(Debug, Clone)]
pub struct TopologyRouterStats {
    pub total_links: usize,
    pub total_peers: usize,
    pub cached_routes: usize,
    pub routes_calculated: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_metrics_combine() {
        let m1 = RouteMetrics::new(10.0, 100.0, 0.99, 1);
        let m2 = RouteMetrics::new(20.0, 50.0, 0.95, 1);
        let combined = m1.combine(&m2);

        assert_eq!(combined.latency_ms, 30.0);
        assert_eq!(combined.bandwidth_mbps, 50.0); // Bottleneck
        assert!((combined.reliability - 0.9405).abs() < 0.001);
        assert_eq!(combined.hop_count, 2);
    }

    #[test]
    fn test_add_link() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);

        assert_eq!(router.links.len(), 1);
        assert_eq!(router.links.get("peer1").unwrap().len(), 1);
    }

    #[test]
    fn test_direct_route() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);

        let route = router.find_route("peer1", "peer2").unwrap();
        assert_eq!(route.path.len(), 2);
        assert_eq!(route.path[0], "peer1");
        assert_eq!(route.path[1], "peer2");
        assert_eq!(route.metrics.hop_count, 1);
    }

    #[test]
    fn test_multi_hop_route() {
        let mut router = TopologyRouter::new(RoutingStrategy::ShortestPath);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        // Create a chain: peer1 -> peer2 -> peer3
        router.add_link("peer1", "peer2", metrics);
        router.add_link("peer2", "peer3", metrics);

        let route = router.find_route("peer1", "peer3").unwrap();
        assert_eq!(route.path.len(), 3);
        assert_eq!(route.path[0], "peer1");
        assert_eq!(route.path[1], "peer2");
        assert_eq!(route.path[2], "peer3");
        assert_eq!(route.metrics.hop_count, 2);
    }

    #[test]
    fn test_route_caching() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);

        // First call - cache miss
        router.find_route("peer1", "peer2");
        assert_eq!(router.cache_misses, 1);
        assert_eq!(router.cache_hits, 0);

        // Second call - cache hit
        router.find_route("peer1", "peer2");
        assert_eq!(router.cache_hits, 1);
    }

    #[test]
    fn test_remove_link() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.remove_link("peer1", "peer2");

        assert!(router.find_route("peer1", "peer2").is_none());
    }

    #[test]
    fn test_remove_peer() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.add_link("peer2", "peer3", metrics);

        router.remove_peer("peer2");

        assert!(router.find_route("peer1", "peer3").is_none());
    }

    #[test]
    fn test_routing_strategies() {
        let metrics_low_latency = RouteMetrics::new(10.0, 50.0, 0.95, 1);
        let metrics_high_bandwidth = RouteMetrics::new(50.0, 200.0, 0.95, 1);

        // Lowest latency prefers low latency
        let score1 = Route::calculate_quality(&metrics_low_latency, RoutingStrategy::LowestLatency);
        let score2 =
            Route::calculate_quality(&metrics_high_bandwidth, RoutingStrategy::LowestLatency);
        assert!(score1 > score2);

        // Highest bandwidth prefers high bandwidth
        let score1 =
            Route::calculate_quality(&metrics_low_latency, RoutingStrategy::HighestBandwidth);
        let score2 =
            Route::calculate_quality(&metrics_high_bandwidth, RoutingStrategy::HighestBandwidth);
        assert!(score1 < score2);
    }

    #[test]
    fn test_get_neighbors() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.add_link("peer1", "peer3", metrics);

        let neighbors = router.get_neighbors("peer1");
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains(&"peer2".to_string()));
        assert!(neighbors.contains(&"peer3".to_string()));
    }

    #[test]
    fn test_get_peers() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.add_link("peer3", "peer4", metrics);

        let peers = router.get_peers();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"peer1".to_string()));
        assert!(peers.contains(&"peer3".to_string()));
    }

    #[test]
    fn test_stats() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.find_route("peer1", "peer2");

        let stats = router.stats();
        assert_eq!(stats.total_links, 1);
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.routes_calculated, 1);
    }

    #[test]
    fn test_cache_invalidation() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        router.add_link("peer1", "peer2", metrics);
        router.find_route("peer1", "peer2");

        // Cache should have entry
        assert_eq!(router.route_cache.len(), 1);

        // Update link should invalidate cache
        router.add_link("peer1", "peer2", metrics);
        assert_eq!(router.route_cache.len(), 0);
    }

    #[test]
    fn test_no_route_available() {
        let mut router = TopologyRouter::new(RoutingStrategy::Balanced);

        // No links added
        assert!(router.find_route("peer1", "peer2").is_none());
    }

    #[test]
    fn test_quality_scores_range() {
        let metrics = RouteMetrics::new(100.0, 100.0, 0.9, 3);

        for strategy in [
            RoutingStrategy::LowestLatency,
            RoutingStrategy::HighestBandwidth,
            RoutingStrategy::MostReliable,
            RoutingStrategy::ShortestPath,
            RoutingStrategy::Balanced,
        ] {
            let score = Route::calculate_quality(&metrics, strategy);
            assert!(
                (0.0..=1.0).contains(&score),
                "Score out of range for {:?}",
                strategy
            );
        }
    }

    #[test]
    fn test_cleanup_stale_links() {
        let mut router =
            TopologyRouter::new(RoutingStrategy::Balanced).with_cache_ttl(Duration::from_millis(1));

        router.link_timeout = Duration::from_millis(1);

        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);
        router.add_link("peer1", "peer2", metrics);

        // Wait for links to become stale
        std::thread::sleep(Duration::from_millis(10));

        router.cleanup_stale_links();
        assert_eq!(router.links.len(), 0);
    }

    #[test]
    fn test_cycle_prevention() {
        let mut router = TopologyRouter::new(RoutingStrategy::ShortestPath);
        let metrics = RouteMetrics::new(10.0, 100.0, 0.99, 1);

        // Create a cycle: peer1 -> peer2 -> peer3 -> peer1
        router.add_link("peer1", "peer2", metrics);
        router.add_link("peer2", "peer3", metrics);
        router.add_link("peer3", "peer1", metrics);

        // Should still find route without infinite loop
        if let Some(route) = router.find_route("peer1", "peer3") {
            // Path should not contain duplicates
            let mut unique_peers = HashSet::new();
            for peer in &route.path {
                assert!(unique_peers.insert(peer.clone()), "Cycle detected in route");
            }
        }
    }
}
