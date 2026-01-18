// Multi-hop relay optimization for efficient peer routing
//
// Provides intelligent relay selection and path optimization:
// - Relay node discovery and capability tracking
// - Multi-hop path optimization based on performance
// - Incentivized relay selection with reward tracking
// - Relay health monitoring and automatic failover
// - Load balancing across available relays
// - Cost-aware routing with bandwidth budgets

use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Relay node capability information
#[derive(Debug, Clone)]
pub struct RelayCapability {
    /// Relay peer ID
    pub peer_id: PeerId,
    /// Maximum bandwidth the relay can provide (bytes/sec)
    pub max_bandwidth: u64,
    /// Available bandwidth (bytes/sec)
    pub available_bandwidth: u64,
    /// Average latency through this relay (ms)
    pub avg_latency: u64,
    /// Reliability score (0.0-1.0)
    pub reliability: f64,
    /// Cost per GB relayed (in protocol tokens)
    pub cost_per_gb: u64,
    /// Whether the relay accepts new connections
    pub accepting_connections: bool,
    /// When capability was last updated
    pub last_updated: Instant,
}

/// Relay path through the network
#[derive(Debug, Clone)]
pub struct RelayPath {
    /// Source peer
    pub source: PeerId,
    /// Destination peer
    pub destination: PeerId,
    /// Relay hops in order
    pub hops: Vec<PeerId>,
    /// Total estimated latency (ms)
    pub total_latency: u64,
    /// Total cost (tokens)
    pub total_cost: u64,
    /// Minimum bandwidth along the path (bytes/sec)
    pub min_bandwidth: u64,
    /// Path reliability score (0.0-1.0)
    pub reliability: f64,
    /// When path was created
    pub created_at: Instant,
}

impl RelayPath {
    /// Calculate path quality score for comparison
    pub fn quality_score(&self, weights: &PathWeights) -> f64 {
        // Normalize metrics to 0-1 range
        let latency_score = 1.0 / (1.0 + self.total_latency as f64 / 1000.0);
        let cost_score = 1.0 / (1.0 + self.total_cost as f64 / 100.0);
        let bandwidth_score = (self.min_bandwidth as f64 / 1_000_000.0).min(1.0);
        let reliability_score = self.reliability;

        // Weighted sum
        latency_score * weights.latency_weight
            + cost_score * weights.cost_weight
            + bandwidth_score * weights.bandwidth_weight
            + reliability_score * weights.reliability_weight
    }

    /// Number of hops in the path
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Weights for path quality scoring
#[derive(Debug, Clone)]
pub struct PathWeights {
    pub latency_weight: f64,
    pub cost_weight: f64,
    pub bandwidth_weight: f64,
    pub reliability_weight: f64,
}

impl Default for PathWeights {
    fn default() -> Self {
        Self {
            latency_weight: 0.3,
            cost_weight: 0.2,
            bandwidth_weight: 0.3,
            reliability_weight: 0.2,
        }
    }
}

impl PathWeights {
    /// Preset for low-latency routing
    pub fn low_latency() -> Self {
        Self {
            latency_weight: 0.6,
            cost_weight: 0.1,
            bandwidth_weight: 0.2,
            reliability_weight: 0.1,
        }
    }

    /// Preset for low-cost routing
    pub fn low_cost() -> Self {
        Self {
            latency_weight: 0.1,
            cost_weight: 0.6,
            bandwidth_weight: 0.2,
            reliability_weight: 0.1,
        }
    }

    /// Preset for high-bandwidth routing
    pub fn high_bandwidth() -> Self {
        Self {
            latency_weight: 0.2,
            cost_weight: 0.1,
            bandwidth_weight: 0.6,
            reliability_weight: 0.1,
        }
    }

    /// Preset for reliable routing
    pub fn reliable() -> Self {
        Self {
            latency_weight: 0.1,
            cost_weight: 0.1,
            bandwidth_weight: 0.2,
            reliability_weight: 0.6,
        }
    }
}

/// Relay node performance statistics
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    /// Total bytes relayed
    pub bytes_relayed: u64,
    /// Number of successful relays
    pub successful_relays: usize,
    /// Number of failed relays
    pub failed_relays: usize,
    /// Total tokens earned
    pub tokens_earned: u64,
    /// Average response time (ms)
    pub avg_response_time: u64,
}

impl RelayStats {
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_relays + self.failed_relays;
        if total == 0 {
            return 0.0;
        }
        self.successful_relays as f64 / total as f64
    }
}

/// Configuration for relay optimizer
#[derive(Debug, Clone)]
pub struct RelayOptimizerConfig {
    /// Maximum number of hops allowed
    pub max_hops: usize,
    /// Maximum path age before refresh
    pub max_path_age: Duration,
    /// Maximum relay capabilities to cache
    pub max_relay_cache_size: usize,
    /// Minimum reliability score to consider a relay
    pub min_reliability: f64,
    /// Path weights for scoring
    pub path_weights: PathWeights,
    /// Maximum cost per path (tokens)
    pub max_path_cost: u64,
}

impl Default for RelayOptimizerConfig {
    fn default() -> Self {
        Self {
            max_hops: 3,
            max_path_age: Duration::from_secs(300), // 5 minutes
            max_relay_cache_size: 1000,
            min_reliability: 0.7,
            path_weights: PathWeights::default(),
            max_path_cost: 100,
        }
    }
}

/// Multi-hop relay optimizer
pub struct RelayOptimizer {
    config: RelayOptimizerConfig,
    /// Available relay nodes and their capabilities
    relays: HashMap<PeerId, RelayCapability>,
    /// Cached optimal paths
    path_cache: HashMap<(PeerId, PeerId), RelayPath>,
    /// Performance statistics per relay
    relay_stats: HashMap<PeerId, RelayStats>,
    /// Global statistics
    global_stats: RelayOptimizerStats,
}

/// Global relay optimizer statistics
#[derive(Debug, Clone, Default)]
pub struct RelayOptimizerStats {
    /// Total paths computed
    pub paths_computed: usize,
    /// Total paths cached
    pub paths_cached: usize,
    /// Cache hits
    pub cache_hits: usize,
    /// Cache misses
    pub cache_misses: usize,
    /// Total relays discovered
    pub relays_discovered: usize,
    /// Active relay count
    pub active_relays: usize,
}

impl Default for RelayOptimizer {
    fn default() -> Self {
        Self::new(RelayOptimizerConfig::default())
    }
}

impl RelayOptimizer {
    /// Create a new relay optimizer
    pub fn new(config: RelayOptimizerConfig) -> Self {
        Self {
            config,
            relays: HashMap::new(),
            path_cache: HashMap::new(),
            relay_stats: HashMap::new(),
            global_stats: RelayOptimizerStats::default(),
        }
    }

    /// Register a relay node with its capabilities
    pub fn register_relay(&mut self, capability: RelayCapability) {
        let peer_id = capability.peer_id;
        let is_new = !self.relays.contains_key(&peer_id);

        self.relays.insert(peer_id, capability);

        if is_new {
            self.global_stats.relays_discovered += 1;
            self.global_stats.active_relays += 1;
        }

        // Invalidate cached paths using this relay
        self.path_cache
            .retain(|_, path| !path.hops.contains(&peer_id));
    }

    /// Unregister a relay node
    pub fn unregister_relay(&mut self, peer_id: &PeerId) {
        if self.relays.remove(peer_id).is_some() {
            self.global_stats.active_relays = self.global_stats.active_relays.saturating_sub(1);

            // Remove from stats
            self.relay_stats.remove(peer_id);

            // Invalidate paths using this relay
            self.path_cache
                .retain(|_, path| !path.hops.contains(peer_id));
        }
    }

    /// Find optimal relay path between two peers
    pub fn find_path(&mut self, source: PeerId, destination: PeerId) -> Option<RelayPath> {
        // Check cache first
        if let Some(cached_path) = self.path_cache.get(&(source, destination)) {
            // Check if path is still fresh
            if cached_path.created_at.elapsed() < self.config.max_path_age {
                self.global_stats.cache_hits += 1;
                return Some(cached_path.clone());
            }
        }

        self.global_stats.cache_misses += 1;

        // Find all possible paths using BFS with constraints
        let path = self.find_optimal_path_bfs(source, destination)?;

        self.global_stats.paths_computed += 1;

        // Cache the path
        self.path_cache.insert((source, destination), path.clone());
        self.global_stats.paths_cached += 1;

        Some(path)
    }

    /// Find optimal path using breadth-first search
    fn find_optimal_path_bfs(&self, source: PeerId, destination: PeerId) -> Option<RelayPath> {
        let mut best_path: Option<RelayPath> = None;
        let mut best_score = 0.0;

        // State: (current_peer, hops, total_latency, total_cost, min_bandwidth, reliability, visited)
        type PathSearchState = (PeerId, Vec<PeerId>, u64, u64, u64, f64, HashSet<PeerId>);
        let mut queue: Vec<PathSearchState> =
            vec![(source, Vec::new(), 0, 0, u64::MAX, 1.0, HashSet::new())];

        while let Some((current, hops, latency, cost, bandwidth, reliability, visited)) =
            queue.pop()
        {
            // Check if we've reached the destination
            if current == destination {
                let path = RelayPath {
                    source,
                    destination,
                    hops: hops.clone(),
                    total_latency: latency,
                    total_cost: cost,
                    min_bandwidth: bandwidth,
                    reliability,
                    created_at: Instant::now(),
                };

                let score = path.quality_score(&self.config.path_weights);
                if score > best_score {
                    best_score = score;
                    best_path = Some(path);
                }
                continue;
            }

            // Don't exceed max hops
            if hops.len() >= self.config.max_hops {
                continue;
            }

            // Don't exceed max cost
            if cost >= self.config.max_path_cost {
                continue;
            }

            // Explore neighboring relays
            for (relay_id, relay_cap) in &self.relays {
                // Skip if already visited
                if visited.contains(relay_id) {
                    continue;
                }

                // Skip if relay doesn't meet minimum requirements
                if relay_cap.reliability < self.config.min_reliability {
                    continue;
                }

                if !relay_cap.accepting_connections {
                    continue;
                }

                // Calculate new metrics
                let new_latency = latency + relay_cap.avg_latency;
                let new_cost = cost + (relay_cap.cost_per_gb / 1000); // Approximate cost per hop
                let new_bandwidth = bandwidth.min(relay_cap.available_bandwidth);
                let new_reliability = reliability * relay_cap.reliability;

                let mut new_hops = hops.clone();
                new_hops.push(*relay_id);

                let mut new_visited = visited.clone();
                new_visited.insert(*relay_id);

                queue.push((
                    *relay_id,
                    new_hops,
                    new_latency,
                    new_cost,
                    new_bandwidth,
                    new_reliability,
                    new_visited,
                ));
            }
        }

        best_path
    }

    /// Record successful relay operation
    pub fn record_relay_success(
        &mut self,
        relay_id: &PeerId,
        bytes: u64,
        cost: u64,
        response_time: u64,
    ) {
        let stats = self.relay_stats.entry(*relay_id).or_default();
        stats.bytes_relayed += bytes;
        stats.successful_relays += 1;
        stats.tokens_earned += cost;

        // Update average response time
        let total_relays = stats.successful_relays + stats.failed_relays;
        stats.avg_response_time = (stats.avg_response_time * (total_relays - 1) as u64
            + response_time)
            / total_relays as u64;

        // Update relay capability
        if let Some(relay) = self.relays.get_mut(relay_id) {
            relay.reliability = (relay.reliability * 0.9 + 0.1).min(1.0); // Increase reliability
            relay.last_updated = Instant::now();
        }
    }

    /// Record failed relay operation
    pub fn record_relay_failure(&mut self, relay_id: &PeerId) {
        let stats = self.relay_stats.entry(*relay_id).or_default();
        stats.failed_relays += 1;

        // Update relay capability
        if let Some(relay) = self.relays.get_mut(relay_id) {
            relay.reliability = (relay.reliability * 0.9).max(0.0); // Decrease reliability

            // Mark as not accepting connections if reliability drops too low
            if relay.reliability < self.config.min_reliability {
                relay.accepting_connections = false;
            }

            relay.last_updated = Instant::now();
        }

        // Invalidate paths using this relay
        self.path_cache
            .retain(|_, path| !path.hops.contains(relay_id));
    }

    /// Get relay statistics
    pub fn get_relay_stats(&self, peer_id: &PeerId) -> Option<&RelayStats> {
        self.relay_stats.get(peer_id)
    }

    /// Get all available relays
    pub fn get_relays(&self) -> Vec<PeerId> {
        self.relays.keys().copied().collect()
    }

    /// Get relay capability
    pub fn get_relay_capability(&self, peer_id: &PeerId) -> Option<&RelayCapability> {
        self.relays.get(peer_id)
    }

    /// Get top relays by reliability
    pub fn get_top_relays(&self, count: usize) -> Vec<(PeerId, f64)> {
        let mut relays: Vec<_> = self
            .relays
            .iter()
            .map(|(id, cap)| (*id, cap.reliability))
            .collect();

        relays.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        relays.truncate(count);
        relays
    }

    /// Get global statistics
    pub fn stats(&self) -> &RelayOptimizerStats {
        &self.global_stats
    }

    /// Clean up stale paths and relay capabilities
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove stale paths
        self.path_cache
            .retain(|_, path| now.duration_since(path.created_at) <= self.config.max_path_age);

        // Remove stale relay capabilities (not updated in last hour)
        self.relays
            .retain(|_, cap| now.duration_since(cap.last_updated) <= Duration::from_secs(3600));

        self.global_stats.active_relays = self.relays.len();
        self.global_stats.paths_cached = self.path_cache.len();

        // Limit cache size
        if self.path_cache.len() > self.config.max_relay_cache_size {
            // Remove oldest entries
            let mut paths: Vec<_> = self
                .path_cache
                .iter()
                .map(|(k, v)| (*k, v.created_at))
                .collect();
            paths.sort_by_key(|(_, created_at)| *created_at);

            let to_remove = paths.len() - self.config.max_relay_cache_size;
            for (key, _) in paths.into_iter().take(to_remove) {
                self.path_cache.remove(&key);
            }
        }
    }

    /// Update relay bandwidth availability
    pub fn update_relay_bandwidth(&mut self, peer_id: &PeerId, available_bandwidth: u64) {
        if let Some(relay) = self.relays.get_mut(peer_id) {
            relay.available_bandwidth = available_bandwidth;
            relay.last_updated = Instant::now();

            // Invalidate paths using this relay if bandwidth changed significantly
            self.path_cache
                .retain(|_, path| !path.hops.contains(peer_id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_relay(
        peer_id: PeerId,
        bandwidth: u64,
        latency: u64,
        cost: u64,
    ) -> RelayCapability {
        RelayCapability {
            peer_id,
            max_bandwidth: bandwidth,
            available_bandwidth: bandwidth,
            avg_latency: latency,
            reliability: 0.95,
            cost_per_gb: cost,
            accepting_connections: true,
            last_updated: Instant::now(),
        }
    }

    #[test]
    fn test_register_relay() {
        let mut optimizer = RelayOptimizer::default();
        let peer = PeerId::random();
        let relay = create_test_relay(peer, 1_000_000, 50, 10);

        optimizer.register_relay(relay);

        assert_eq!(optimizer.stats().active_relays, 1);
        assert_eq!(optimizer.stats().relays_discovered, 1);
        assert!(optimizer.get_relay_capability(&peer).is_some());
    }

    #[test]
    fn test_unregister_relay() {
        let mut optimizer = RelayOptimizer::default();
        let peer = PeerId::random();
        let relay = create_test_relay(peer, 1_000_000, 50, 10);

        optimizer.register_relay(relay);
        optimizer.unregister_relay(&peer);

        assert_eq!(optimizer.stats().active_relays, 0);
        assert!(optimizer.get_relay_capability(&peer).is_none());
    }

    #[test]
    fn test_find_direct_path() {
        let mut optimizer = RelayOptimizer::default();
        let source = PeerId::random();
        let destination = PeerId::random();

        // Register destination as a relay
        let relay = create_test_relay(destination, 1_000_000, 50, 10);
        optimizer.register_relay(relay);

        let path = optimizer.find_path(source, destination);
        assert!(path.is_some());

        let path = path.unwrap();
        assert_eq!(path.hops.len(), 1);
        assert_eq!(path.hops[0], destination);
    }

    #[test]
    fn test_find_two_hop_path() {
        let mut optimizer = RelayOptimizer::default();
        let source = PeerId::random();
        let relay1 = PeerId::random();
        let destination = PeerId::random();

        // Register relays
        optimizer.register_relay(create_test_relay(relay1, 1_000_000, 50, 10));
        optimizer.register_relay(create_test_relay(destination, 1_000_000, 50, 10));

        let path = optimizer.find_path(source, destination);
        assert!(path.is_some());

        let path = path.unwrap();
        assert!(!path.hops.is_empty());
    }

    #[test]
    fn test_path_caching() {
        let mut optimizer = RelayOptimizer::default();
        let source = PeerId::random();
        let destination = PeerId::random();

        optimizer.register_relay(create_test_relay(destination, 1_000_000, 50, 10));

        // First call - cache miss
        optimizer.find_path(source, destination);
        assert_eq!(optimizer.stats().cache_misses, 1);
        assert_eq!(optimizer.stats().cache_hits, 0);

        // Second call - cache hit
        optimizer.find_path(source, destination);
        assert_eq!(optimizer.stats().cache_hits, 1);
    }

    #[test]
    fn test_record_relay_success() {
        let mut optimizer = RelayOptimizer::default();
        let peer = PeerId::random();
        let relay = create_test_relay(peer, 1_000_000, 50, 10);

        optimizer.register_relay(relay);
        optimizer.record_relay_success(&peer, 1000, 5, 100);

        let stats = optimizer.get_relay_stats(&peer).unwrap();
        assert_eq!(stats.bytes_relayed, 1000);
        assert_eq!(stats.successful_relays, 1);
        assert_eq!(stats.tokens_earned, 5);
    }

    #[test]
    fn test_record_relay_failure() {
        let mut optimizer = RelayOptimizer::default();
        let peer = PeerId::random();
        let relay = create_test_relay(peer, 1_000_000, 50, 10);

        optimizer.register_relay(relay);
        optimizer.record_relay_failure(&peer);

        let stats = optimizer.get_relay_stats(&peer).unwrap();
        assert_eq!(stats.failed_relays, 1);

        // Check reliability decreased
        let capability = optimizer.get_relay_capability(&peer).unwrap();
        assert!(capability.reliability < 0.95);
    }

    #[test]
    fn test_success_rate() {
        let stats = RelayStats {
            successful_relays: 8,
            failed_relays: 2,
            ..Default::default()
        };

        assert!((stats.success_rate() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_path_quality_score() {
        let path = RelayPath {
            source: PeerId::random(),
            destination: PeerId::random(),
            hops: vec![PeerId::random()],
            total_latency: 100,
            total_cost: 10,
            min_bandwidth: 1_000_000,
            reliability: 0.9,
            created_at: Instant::now(),
        };

        let weights = PathWeights::default();
        let score = path.quality_score(&weights);

        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_path_weights_presets() {
        let low_latency = PathWeights::low_latency();
        assert!(low_latency.latency_weight > 0.5);

        let low_cost = PathWeights::low_cost();
        assert!(low_cost.cost_weight > 0.5);

        let high_bandwidth = PathWeights::high_bandwidth();
        assert!(high_bandwidth.bandwidth_weight > 0.5);

        let reliable = PathWeights::reliable();
        assert!(reliable.reliability_weight > 0.5);
    }

    #[test]
    fn test_max_hops_constraint() {
        let config = RelayOptimizerConfig {
            max_hops: 1,
            ..Default::default()
        };
        let mut optimizer = RelayOptimizer::new(config);

        let source = PeerId::random();
        let relay1 = PeerId::random();
        let relay2 = PeerId::random();
        let destination = PeerId::random();

        optimizer.register_relay(create_test_relay(relay1, 1_000_000, 50, 10));
        optimizer.register_relay(create_test_relay(relay2, 1_000_000, 50, 10));
        optimizer.register_relay(create_test_relay(destination, 1_000_000, 50, 10));

        let path = optimizer.find_path(source, destination);
        assert!(path.is_some());
        assert!(path.unwrap().hops.len() <= 1);
    }

    #[test]
    fn test_min_reliability_constraint() {
        let config = RelayOptimizerConfig {
            min_reliability: 0.95,
            ..Default::default()
        };
        let mut optimizer = RelayOptimizer::new(config);

        let source = PeerId::random();
        let destination = PeerId::random();

        // Register unreliable relay
        let mut relay = create_test_relay(destination, 1_000_000, 50, 10);
        relay.reliability = 0.5;
        optimizer.register_relay(relay);

        let path = optimizer.find_path(source, destination);
        assert!(path.is_none()); // Should not find path due to low reliability
    }

    #[test]
    fn test_get_top_relays() {
        let mut optimizer = RelayOptimizer::default();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut relay1 = create_test_relay(peer1, 1_000_000, 50, 10);
        relay1.reliability = 0.99;
        optimizer.register_relay(relay1);

        let mut relay2 = create_test_relay(peer2, 1_000_000, 50, 10);
        relay2.reliability = 0.95;
        optimizer.register_relay(relay2);

        let mut relay3 = create_test_relay(peer3, 1_000_000, 50, 10);
        relay3.reliability = 0.90;
        optimizer.register_relay(relay3);

        let top = optimizer.get_top_relays(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, peer1); // Highest reliability first
    }

    #[test]
    fn test_cleanup_stale_paths() {
        let config = RelayOptimizerConfig {
            max_path_age: Duration::from_millis(100),
            ..Default::default()
        };
        let mut optimizer = RelayOptimizer::new(config);

        let source = PeerId::random();
        let destination = PeerId::random();

        optimizer.register_relay(create_test_relay(destination, 1_000_000, 50, 10));

        optimizer.find_path(source, destination);
        assert_eq!(optimizer.stats().paths_cached, 1);

        // Wait for path to become stale
        std::thread::sleep(Duration::from_millis(150));

        optimizer.cleanup();
        assert_eq!(optimizer.stats().paths_cached, 0);
    }

    #[test]
    fn test_update_relay_bandwidth() {
        let mut optimizer = RelayOptimizer::default();
        let peer = PeerId::random();
        let relay = create_test_relay(peer, 1_000_000, 50, 10);

        optimizer.register_relay(relay);
        optimizer.update_relay_bandwidth(&peer, 500_000);

        let capability = optimizer.get_relay_capability(&peer).unwrap();
        assert_eq!(capability.available_bandwidth, 500_000);
    }

    #[test]
    fn test_hop_count() {
        let path = RelayPath {
            source: PeerId::random(),
            destination: PeerId::random(),
            hops: vec![PeerId::random(), PeerId::random()],
            total_latency: 100,
            total_cost: 20,
            min_bandwidth: 1_000_000,
            reliability: 0.9,
            created_at: Instant::now(),
        };

        assert_eq!(path.hop_count(), 2);
    }

    #[test]
    fn test_get_relays() {
        let mut optimizer = RelayOptimizer::default();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        optimizer.register_relay(create_test_relay(peer1, 1_000_000, 50, 10));
        optimizer.register_relay(create_test_relay(peer2, 1_000_000, 50, 10));

        let relays = optimizer.get_relays();
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&peer1));
        assert!(relays.contains(&peer2));
    }

    #[test]
    fn test_relay_not_accepting_connections() {
        let mut optimizer = RelayOptimizer::default();
        let source = PeerId::random();
        let destination = PeerId::random();

        let mut relay = create_test_relay(destination, 1_000_000, 50, 10);
        relay.accepting_connections = false;
        optimizer.register_relay(relay);

        let path = optimizer.find_path(source, destination);
        assert!(path.is_none());
    }
}
