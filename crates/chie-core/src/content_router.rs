//! Content routing optimizer for efficient content discovery and retrieval.
//!
//! This module provides intelligent routing algorithms to find and retrieve content
//! from the optimal peers in the network. It combines peer selection, network topology,
//! content availability, and caching strategies.
//!
//! # Example
//!
//! ```
//! use chie_core::{ContentRouter, RoutingStrategy, PeerContentLocation};
//!
//! # async fn example() {
//! let mut router = ContentRouter::new();
//!
//! // Register content locations
//! router.register_location("QmContent123", PeerContentLocation {
//!     peer_id: "peer1".to_string(),
//!     cid: "QmContent123".to_string(),
//!     availability_score: 0.95,
//!     last_verified: std::time::SystemTime::now(),
//!     chunk_count: 100,
//!     complete: true,
//! });
//!
//! // Find optimal peers for content
//! let peers = router.find_peers("QmContent123", 3);
//! println!("Found {} peers with content", peers.len());
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Represents a content location (peer hosting content).
#[derive(Debug, Clone)]
pub struct PeerContentLocation {
    /// Peer ID hosting the content
    pub peer_id: String,
    /// Content ID (CID)
    pub cid: String,
    /// Availability score (0.0 to 1.0)
    pub availability_score: f64,
    /// Last time this location was verified
    pub last_verified: SystemTime,
    /// Number of chunks available
    pub chunk_count: u32,
    /// Whether the peer has complete content
    pub complete: bool,
}

/// Routing strategy for content discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Closest peers first (lowest latency)
    Closest,
    /// Most available peers first (highest availability)
    MostAvailable,
    /// Load balanced across peers
    LoadBalanced,
    /// Redundant routing (multiple sources)
    Redundant,
}

/// Content routing statistics.
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Total routing requests
    pub total_requests: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Average peers per content
    pub avg_peers_per_content: f64,
    /// Total unique content tracked
    pub unique_content: usize,
}

/// Content router for intelligent content discovery.
pub struct ContentRouter {
    /// Content ID to locations mapping
    content_locations: HashMap<String, Vec<PeerContentLocation>>,
    /// Routing strategy
    strategy: RoutingStrategy,
    /// Cache for recent lookups
    lookup_cache: HashMap<String, Vec<String>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Statistics
    stats: RoutingStats,
    /// Location verification interval
    verification_interval: Duration,
}

impl ContentRouter {
    /// Create a new content router.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            content_locations: HashMap::new(),
            strategy: RoutingStrategy::LoadBalanced,
            lookup_cache: HashMap::new(),
            cache_ttl: Duration::from_secs(60),
            stats: RoutingStats::default(),
            verification_interval: Duration::from_secs(300),
        }
    }

    /// Create a router with a specific strategy.
    #[must_use]
    #[inline]
    pub fn with_strategy(strategy: RoutingStrategy) -> Self {
        Self {
            strategy,
            ..Self::new()
        }
    }

    /// Set the routing strategy.
    #[inline]
    pub fn set_strategy(&mut self, strategy: RoutingStrategy) {
        self.strategy = strategy;
    }

    /// Set cache TTL.
    #[inline]
    pub fn set_cache_ttl(&mut self, ttl: Duration) {
        self.cache_ttl = ttl;
    }

    /// Register a content location.
    pub fn register_location(&mut self, cid: &str, location: PeerContentLocation) {
        let locations = self.content_locations.entry(cid.to_string()).or_default();

        // Update if exists, otherwise add
        if let Some(existing) = locations.iter_mut().find(|l| l.peer_id == location.peer_id) {
            *existing = location;
        } else {
            locations.push(location);
        }

        // Invalidate cache for this CID
        self.lookup_cache.remove(cid);
    }

    /// Unregister a content location.
    pub fn unregister_location(&mut self, cid: &str, peer_id: &str) {
        if let Some(locations) = self.content_locations.get_mut(cid) {
            locations.retain(|l| l.peer_id != peer_id);
            if locations.is_empty() {
                self.content_locations.remove(cid);
            }
            self.lookup_cache.remove(cid);
        }
    }

    /// Find peers hosting specific content.
    #[must_use]
    pub fn find_peers(&mut self, cid: &str, max_peers: usize) -> Vec<String> {
        self.stats.total_requests += 1;

        // Check cache first
        if let Some(cached) = self.lookup_cache.get(cid) {
            self.stats.cache_hits += 1;
            return cached.iter().take(max_peers).cloned().collect();
        }

        self.stats.cache_misses += 1;

        // Get locations for this content
        let locations = match self.content_locations.get(cid) {
            Some(locs) => locs,
            None => return Vec::new(),
        };

        // Filter out stale locations
        let valid_locations: Vec<_> = locations
            .iter()
            .filter(|l| self.is_location_valid(l))
            .cloned()
            .collect();

        if valid_locations.is_empty() {
            return Vec::new();
        }

        // Apply routing strategy
        let mut selected = match self.strategy {
            RoutingStrategy::Closest => self.route_by_closest(valid_locations),
            RoutingStrategy::MostAvailable => self.route_by_availability(valid_locations),
            RoutingStrategy::LoadBalanced => self.route_load_balanced(valid_locations),
            RoutingStrategy::Redundant => self.route_redundant(valid_locations),
        };

        selected.truncate(max_peers);

        let peer_ids: Vec<String> = selected.iter().map(|l| l.peer_id.clone()).collect();

        // Update cache
        self.lookup_cache.insert(cid.to_string(), peer_ids.clone());

        peer_ids
    }

    /// Check if a location is still valid.
    fn is_location_valid(&self, location: &PeerContentLocation) -> bool {
        if let Ok(duration) = SystemTime::now().duration_since(location.last_verified) {
            duration < self.verification_interval
        } else {
            false
        }
    }

    /// Route by closest peers (would use latency in real implementation).
    fn route_by_closest(
        &self,
        mut locations: Vec<PeerContentLocation>,
    ) -> Vec<PeerContentLocation> {
        // Sort by availability score as proxy for "closeness"
        locations.sort_by(|a, b| {
            b.availability_score
                .partial_cmp(&a.availability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        locations
    }

    /// Route by most available peers.
    fn route_by_availability(
        &self,
        mut locations: Vec<PeerContentLocation>,
    ) -> Vec<PeerContentLocation> {
        locations.sort_by(|a, b| {
            // Complete content first, then by availability score
            match (a.complete, b.complete) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b
                    .availability_score
                    .partial_cmp(&a.availability_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            }
        });
        locations
    }

    /// Route with load balancing.
    fn route_load_balanced(&self, locations: Vec<PeerContentLocation>) -> Vec<PeerContentLocation> {
        // Simple round-robin for now
        // In production, would track actual load per peer
        locations
    }

    /// Route with redundancy (multiple sources).
    fn route_redundant(&self, locations: Vec<PeerContentLocation>) -> Vec<PeerContentLocation> {
        // Return all valid locations for redundancy
        locations
    }

    /// Get all peers hosting a specific content.
    #[must_use]
    #[inline]
    pub fn get_all_peers(&self, cid: &str) -> Vec<String> {
        self.content_locations
            .get(cid)
            .map(|locs| locs.iter().map(|l| l.peer_id.clone()).collect())
            .unwrap_or_default()
    }

    /// Get content availability score.
    #[must_use]
    #[inline]
    pub fn get_availability(&self, cid: &str) -> Option<f64> {
        self.content_locations.get(cid).map(|locs| {
            if locs.is_empty() {
                return 0.0;
            }
            let total: f64 = locs.iter().map(|l| l.availability_score).sum();
            total / locs.len() as f64
        })
    }

    /// Check if content is available.
    #[must_use]
    #[inline]
    pub fn has_content(&self, cid: &str) -> bool {
        self.content_locations.contains_key(cid)
    }

    /// Get number of peers hosting content.
    #[must_use]
    #[inline]
    pub fn peer_count(&self, cid: &str) -> usize {
        self.content_locations
            .get(cid)
            .map(|locs| locs.len())
            .unwrap_or(0)
    }

    /// Find content by popularity (most peers).
    #[must_use]
    pub fn find_popular_content(&self, limit: usize) -> Vec<String> {
        let mut content_peers: Vec<_> = self
            .content_locations
            .iter()
            .map(|(cid, locs)| (cid.clone(), locs.len()))
            .collect();

        content_peers.sort_by(|a, b| b.1.cmp(&a.1));

        content_peers
            .into_iter()
            .take(limit)
            .map(|(cid, _)| cid)
            .collect()
    }

    /// Find rare content (fewest peers).
    #[must_use]
    pub fn find_rare_content(&self, limit: usize) -> Vec<String> {
        let mut content_peers: Vec<_> = self
            .content_locations
            .iter()
            .map(|(cid, locs)| (cid.clone(), locs.len()))
            .collect();

        content_peers.sort_by(|a, b| a.1.cmp(&b.1));

        content_peers
            .into_iter()
            .take(limit)
            .map(|(cid, _)| cid)
            .collect()
    }

    /// Get routing statistics.
    #[must_use]
    #[inline]
    pub fn get_statistics(&self) -> RoutingStats {
        let mut stats = self.stats.clone();
        stats.unique_content = self.content_locations.len();

        if !self.content_locations.is_empty() {
            let total_peers: usize = self.content_locations.values().map(|locs| locs.len()).sum();
            stats.avg_peers_per_content = total_peers as f64 / self.content_locations.len() as f64;
        }

        stats
    }

    /// Clear routing cache.
    #[inline]
    pub fn clear_cache(&mut self) {
        self.lookup_cache.clear();
    }

    /// Remove stale locations.
    #[must_use]
    pub fn cleanup_stale_locations(&mut self) -> usize {
        let mut removed_count = 0;
        let now = SystemTime::now();
        let verification_interval = self.verification_interval;
        let mut cids_to_remove = Vec::new();

        for (cid, locations) in self.content_locations.iter_mut() {
            let initial_len = locations.len();
            locations.retain(|l| {
                if let Ok(duration) = now.duration_since(l.last_verified) {
                    duration < verification_interval
                } else {
                    false
                }
            });
            removed_count += initial_len - locations.len();

            if locations.is_empty() {
                cids_to_remove.push(cid.clone());
            }
        }

        for cid in cids_to_remove {
            self.content_locations.remove(&cid);
            self.lookup_cache.remove(&cid);
        }

        removed_count
    }

    /// Get total number of tracked content.
    #[must_use]
    #[inline]
    pub fn content_count(&self) -> usize {
        self.content_locations.len()
    }

    /// Get total number of locations.
    #[must_use]
    #[inline]
    pub fn location_count(&self) -> usize {
        self.content_locations.values().map(|locs| locs.len()).sum()
    }

    /// Find peers with specific content completeness.
    #[must_use]
    #[inline]
    pub fn find_complete_peers(&self, cid: &str) -> Vec<String> {
        self.content_locations
            .get(cid)
            .map(|locs| {
                locs.iter()
                    .filter(|l| l.complete)
                    .map(|l| l.peer_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get content with minimum peer count.
    #[must_use]
    #[inline]
    pub fn find_well_distributed_content(&self, min_peers: usize) -> Vec<String> {
        self.content_locations
            .iter()
            .filter(|(_, locs)| locs.len() >= min_peers)
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Suggest content for replication (poorly distributed).
    #[must_use]
    #[inline]
    pub fn suggest_replication_targets(&self, max_peers: usize) -> Vec<String> {
        self.content_locations
            .iter()
            .filter(|(_, locs)| locs.len() <= max_peers)
            .map(|(cid, _)| cid.clone())
            .collect()
    }
}

impl Default for ContentRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_location(peer_id: &str, cid: &str, complete: bool) -> PeerContentLocation {
        PeerContentLocation {
            peer_id: peer_id.to_string(),
            cid: cid.to_string(),
            availability_score: 0.9,
            last_verified: SystemTime::now(),
            chunk_count: 100,
            complete,
        }
    }

    #[test]
    fn test_register_and_find_peers() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer2", "QmTest", true));

        let peers = router.find_peers("QmTest", 10);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"peer1".to_string()));
        assert!(peers.contains(&"peer2".to_string()));
    }

    #[test]
    fn test_unregister_location() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer2", "QmTest", true));

        assert_eq!(router.peer_count("QmTest"), 2);

        router.unregister_location("QmTest", "peer1");
        assert_eq!(router.peer_count("QmTest"), 1);

        let peers = router.find_peers("QmTest", 10);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], "peer2");
    }

    #[test]
    fn test_routing_strategies() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer2", "QmTest", false));

        router.set_strategy(RoutingStrategy::MostAvailable);
        let peers = router.find_peers("QmTest", 1);
        assert_eq!(peers.len(), 1);

        router.clear_cache(); // Clear cache before changing strategy
        router.set_strategy(RoutingStrategy::Redundant);
        let peers = router.find_peers("QmTest", 10);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_content_availability() {
        let mut router = ContentRouter::new();

        let mut loc1 = create_test_location("peer1", "QmTest", true);
        loc1.availability_score = 0.8;
        let mut loc2 = create_test_location("peer2", "QmTest", true);
        loc2.availability_score = 1.0;

        router.register_location("QmTest", loc1);
        router.register_location("QmTest", loc2);

        let availability = router.get_availability("QmTest").unwrap();
        assert!((availability - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_find_popular_content() {
        let mut router = ContentRouter::new();

        router.register_location(
            "QmContent1",
            create_test_location("peer1", "QmContent1", true),
        );
        router.register_location(
            "QmContent1",
            create_test_location("peer2", "QmContent1", true),
        );
        router.register_location(
            "QmContent1",
            create_test_location("peer3", "QmContent1", true),
        );

        router.register_location(
            "QmContent2",
            create_test_location("peer1", "QmContent2", true),
        );

        let popular = router.find_popular_content(1);
        assert_eq!(popular.len(), 1);
        assert_eq!(popular[0], "QmContent1");
    }

    #[test]
    fn test_find_rare_content() {
        let mut router = ContentRouter::new();

        router.register_location(
            "QmContent1",
            create_test_location("peer1", "QmContent1", true),
        );
        router.register_location(
            "QmContent1",
            create_test_location("peer2", "QmContent1", true),
        );
        router.register_location(
            "QmContent1",
            create_test_location("peer3", "QmContent1", true),
        );

        router.register_location(
            "QmContent2",
            create_test_location("peer1", "QmContent2", true),
        );

        let rare = router.find_rare_content(1);
        assert_eq!(rare.len(), 1);
        assert_eq!(rare[0], "QmContent2");
    }

    #[test]
    fn test_cache_functionality() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));

        // First call - cache miss
        let _ = router.find_peers("QmTest", 10);
        let stats = router.get_statistics();
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hits, 0);

        // Second call - cache hit
        let _ = router.find_peers("QmTest", 10);
        let stats = router.get_statistics();
        assert_eq!(stats.cache_hits, 1);
    }

    #[test]
    fn test_clear_cache() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        let _ = router.find_peers("QmTest", 10);

        router.clear_cache();
        let _ = router.find_peers("QmTest", 10);

        let stats = router.get_statistics();
        assert_eq!(stats.cache_misses, 2);
    }

    #[test]
    fn test_find_complete_peers() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer2", "QmTest", false));
        router.register_location("QmTest", create_test_location("peer3", "QmTest", true));

        let complete = router.find_complete_peers("QmTest");
        assert_eq!(complete.len(), 2);
        assert!(complete.contains(&"peer1".to_string()));
        assert!(complete.contains(&"peer3".to_string()));
    }

    #[test]
    fn test_replication_suggestions() {
        let mut router = ContentRouter::new();

        router.register_location(
            "QmContent1",
            create_test_location("peer1", "QmContent1", true),
        );

        router.register_location(
            "QmContent2",
            create_test_location("peer1", "QmContent2", true),
        );
        router.register_location(
            "QmContent2",
            create_test_location("peer2", "QmContent2", true),
        );
        router.register_location(
            "QmContent2",
            create_test_location("peer3", "QmContent2", true),
        );

        let targets = router.suggest_replication_targets(2);
        assert!(targets.contains(&"QmContent1".to_string()));
        assert!(!targets.contains(&"QmContent2".to_string()));
    }

    #[test]
    fn test_statistics() {
        let mut router = ContentRouter::new();

        router.register_location(
            "QmContent1",
            create_test_location("peer1", "QmContent1", true),
        );
        router.register_location(
            "QmContent1",
            create_test_location("peer2", "QmContent1", true),
        );
        router.register_location(
            "QmContent2",
            create_test_location("peer1", "QmContent2", true),
        );

        let _ = router.find_peers("QmContent1", 10);

        let stats = router.get_statistics();
        assert_eq!(stats.unique_content, 2);
        assert_eq!(stats.total_requests, 1);
        assert!((stats.avg_peers_per_content - 1.5).abs() < 0.01);
    }

    #[test]
    fn test_max_peers_limit() {
        let mut router = ContentRouter::new();

        router.register_location("QmTest", create_test_location("peer1", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer2", "QmTest", true));
        router.register_location("QmTest", create_test_location("peer3", "QmTest", true));

        let peers = router.find_peers("QmTest", 2);
        assert_eq!(peers.len(), 2);
    }
}
