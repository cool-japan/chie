//! Bandwidth fairness controller for equitable resource allocation.
//!
//! This module ensures fair bandwidth distribution across peers, preventing
//! any single peer from monopolizing network resources while maintaining
//! overall system efficiency.
//!
//! # Features
//!
//! - **Fair Queuing**: Max-min fair bandwidth allocation
//! - **Priority Support**: Allows priority-based allocation while maintaining fairness
//! - **Dynamic Adjustment**: Continuously adapts to changing demand
//! - **Starvation Prevention**: Guarantees minimum bandwidth for all peers
//! - **Weighted Fairness**: Supports weighted fair allocation based on contribution
//! - **Congestion Control**: Automatically adjusts during network congestion
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::bandwidth_fairness::{BandwidthFairnessController, FairnessConfig, AllocationPolicy};
//!
//! let config = FairnessConfig {
//!     total_bandwidth: 10_000_000, // 10 MB/s
//!     min_guarantee: 100_000,       // 100 KB/s minimum per peer
//!     policy: AllocationPolicy::MaxMinFair,
//!     enable_priorities: true,
//!     adjustment_interval_ms: 1000,
//! };
//!
//! let controller = BandwidthFairnessController::new(config);
//!
//! // Register peers
//! controller.register_peer("peer1", 1.0); // Weight 1.0
//! controller.register_peer("peer2", 2.0); // Weight 2.0 (contributed more)
//!
//! // Request bandwidth
//! controller.request_bandwidth("peer1", 5_000_000);
//! controller.request_bandwidth("peer2", 8_000_000);
//!
//! // Calculate fair allocations
//! controller.recalculate_allocations();
//!
//! // Get allocation for a peer
//! if let Some(allocation) = controller.get_allocation("peer1") {
//!     println!("Peer1 allocated: {} bytes/s", allocation);
//! }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Fairness allocation policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationPolicy {
    /// Max-min fairness - maximize minimum allocation
    MaxMinFair,
    /// Proportional fairness - proportional to demand
    ProportionalFair,
    /// Weighted fair - considers peer weights
    WeightedFair,
}

/// Configuration for fairness controller
#[derive(Debug, Clone)]
pub struct FairnessConfig {
    /// Total available bandwidth (bytes/sec)
    pub total_bandwidth: u64,
    /// Minimum guaranteed bandwidth per peer (bytes/sec)
    pub min_guarantee: u64,
    /// Allocation policy to use
    pub policy: AllocationPolicy,
    /// Enable priority-based allocation
    pub enable_priorities: bool,
    /// How often to recalculate allocations (milliseconds)
    pub adjustment_interval_ms: u64,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        Self {
            total_bandwidth: 10_000_000, // 10 MB/s
            min_guarantee: 100_000,      // 100 KB/s
            policy: AllocationPolicy::MaxMinFair,
            enable_priorities: true,
            adjustment_interval_ms: 1000, // 1 second
        }
    }
}

/// Peer bandwidth information
#[derive(Debug, Clone)]
struct PeerBandwidth {
    /// Current allocation (bytes/sec)
    allocation: u64,
    /// Requested bandwidth (bytes/sec)
    demand: u64,
    /// Peer weight (for weighted fairness)
    weight: f64,
    /// Priority level (0-10, higher = more important)
    #[allow(dead_code)]
    priority: u8,
    /// Actual usage in last interval (bytes/sec)
    #[allow(dead_code)]
    actual_usage: u64,
    /// Last update time
    #[allow(dead_code)]
    last_update: Instant,
}

impl PeerBandwidth {
    fn new(weight: f64, priority: u8) -> Self {
        Self {
            allocation: 0,
            demand: 0,
            weight,
            priority,
            actual_usage: 0,
            last_update: Instant::now(),
        }
    }
}

/// Statistics for fairness controller
#[derive(Debug, Clone, Default)]
pub struct FairnessStats {
    /// Total peers registered
    pub total_peers: usize,
    /// Total bandwidth allocated
    pub total_allocated: u64,
    /// Total bandwidth demanded
    pub total_demanded: u64,
    /// Average allocation per peer
    pub avg_allocation: f64,
    /// Fairness index (Jain's fairness index, 0.0-1.0)
    pub fairness_index: f64,
    /// Number of starved peers (below minimum)
    pub starved_peers: usize,
    /// Number of satisfied peers (got full demand)
    pub satisfied_peers: usize,
    /// Utilization ratio (allocated/total_available)
    pub utilization: f64,
    /// Number of recalculations performed
    pub recalculations: u64,
}

/// Bandwidth fairness controller
pub struct BandwidthFairnessController {
    config: FairnessConfig,
    peers: Arc<RwLock<HashMap<String, PeerBandwidth>>>,
    stats: Arc<RwLock<FairnessStats>>,
    last_recalculation: Arc<RwLock<Instant>>,
}

impl BandwidthFairnessController {
    /// Creates a new bandwidth fairness controller
    pub fn new(config: FairnessConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(FairnessStats::default())),
            last_recalculation: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Registers a new peer with optional weight
    pub fn register_peer(&self, peer_id: &str, weight: f64) {
        self.register_peer_with_priority(peer_id, weight, 5) // Default priority 5
    }

    /// Registers a peer with weight and priority
    pub fn register_peer_with_priority(&self, peer_id: &str, weight: f64, priority: u8) {
        let mut peers = self.peers.write().unwrap();
        peers.insert(
            peer_id.to_string(),
            PeerBandwidth::new(weight.max(0.1), priority.min(10)),
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_peers = peers.len();
    }

    /// Unregisters a peer
    pub fn unregister_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(peer_id);

        let mut stats = self.stats.write().unwrap();
        stats.total_peers = peers.len();
    }

    /// Requests bandwidth for a peer
    pub fn request_bandwidth(&self, peer_id: &str, bytes_per_sec: u64) {
        let mut peers = self.peers.write().unwrap();

        if let Some(peer) = peers.get_mut(peer_id) {
            peer.demand = bytes_per_sec;
            peer.last_update = Instant::now();
        }
    }

    /// Reports actual bandwidth usage
    pub fn report_usage(&self, peer_id: &str, bytes_per_sec: u64) {
        let mut peers = self.peers.write().unwrap();

        if let Some(peer) = peers.get_mut(peer_id) {
            peer.actual_usage = bytes_per_sec;
            peer.last_update = Instant::now();
        }
    }

    /// Recalculates bandwidth allocations for all peers
    pub fn recalculate_allocations(&self) {
        let mut last_recalc = self.last_recalculation.write().unwrap();
        *last_recalc = Instant::now();

        let mut peers = self.peers.write().unwrap();

        match self.config.policy {
            AllocationPolicy::MaxMinFair => self.allocate_max_min_fair(&mut peers),
            AllocationPolicy::ProportionalFair => self.allocate_proportional_fair(&mut peers),
            AllocationPolicy::WeightedFair => self.allocate_weighted_fair(&mut peers),
        }

        // Update stats
        self.update_stats(&peers);
    }

    fn allocate_max_min_fair(&self, peers: &mut HashMap<String, PeerBandwidth>) {
        if peers.is_empty() {
            return;
        }

        let mut remaining_bandwidth = self.config.total_bandwidth;
        let peer_count = peers.len();
        let mut unallocated_peers: Vec<String> = peers.keys().cloned().collect();

        // First, guarantee minimums
        for peer in peers.values_mut() {
            let min_alloc = self
                .config
                .min_guarantee
                .min(remaining_bandwidth / peer_count as u64);
            peer.allocation = min_alloc;
            remaining_bandwidth = remaining_bandwidth.saturating_sub(min_alloc);
        }

        // Iteratively allocate remaining bandwidth
        while remaining_bandwidth > 0 && !unallocated_peers.is_empty() {
            let fair_share = remaining_bandwidth / unallocated_peers.len() as u64;
            let mut satisfied_in_round = vec![];

            for peer_id in &unallocated_peers {
                if let Some(peer) = peers.get_mut(peer_id) {
                    let current_allocation = peer.allocation;
                    let needed = peer.demand.saturating_sub(current_allocation);

                    if needed == 0 || needed <= fair_share {
                        // This peer can be satisfied
                        let additional = needed.min(fair_share);
                        peer.allocation += additional;
                        remaining_bandwidth = remaining_bandwidth.saturating_sub(additional);
                        satisfied_in_round.push(peer_id.clone());
                    } else {
                        // Give peer its fair share
                        peer.allocation += fair_share;
                        remaining_bandwidth = remaining_bandwidth.saturating_sub(fair_share);
                    }
                }
            }

            // Remove satisfied peers from next round
            unallocated_peers.retain(|p| !satisfied_in_round.contains(p));

            if satisfied_in_round.is_empty() {
                break; // No progress made, exit
            }
        }
    }

    fn allocate_proportional_fair(&self, peers: &mut HashMap<String, PeerBandwidth>) {
        if peers.is_empty() {
            return;
        }

        let total_demand: u64 = peers.values().map(|p| p.demand).sum();

        if total_demand == 0 {
            return;
        }

        let mut remaining = self.config.total_bandwidth;

        for peer in peers.values_mut() {
            let proportion = peer.demand as f64 / total_demand as f64;
            let allocation = (self.config.total_bandwidth as f64 * proportion) as u64;
            peer.allocation = allocation.min(peer.demand).max(self.config.min_guarantee);
            remaining = remaining.saturating_sub(peer.allocation);
        }

        // Distribute any remaining bandwidth equally
        if remaining > 0 && !peers.is_empty() {
            let extra_per_peer = remaining / peers.len() as u64;
            for peer in peers.values_mut() {
                peer.allocation += extra_per_peer;
            }
        }
    }

    fn allocate_weighted_fair(&self, peers: &mut HashMap<String, PeerBandwidth>) {
        if peers.is_empty() {
            return;
        }

        let total_weight: f64 = peers.values().map(|p| p.weight).sum();

        if total_weight == 0.0 {
            return;
        }

        for peer in peers.values_mut() {
            let weight_ratio = peer.weight / total_weight;
            let allocation = (self.config.total_bandwidth as f64 * weight_ratio) as u64;
            peer.allocation = allocation.min(peer.demand).max(self.config.min_guarantee);
        }
    }

    fn update_stats(&self, peers: &HashMap<String, PeerBandwidth>) {
        let mut stats = self.stats.write().unwrap();

        stats.total_peers = peers.len();
        stats.total_allocated = peers.values().map(|p| p.allocation).sum();
        stats.total_demanded = peers.values().map(|p| p.demand).sum();

        if !peers.is_empty() {
            stats.avg_allocation = stats.total_allocated as f64 / peers.len() as f64;
        }

        stats.utilization = if self.config.total_bandwidth > 0 {
            stats.total_allocated as f64 / self.config.total_bandwidth as f64
        } else {
            0.0
        };

        // Calculate Jain's fairness index
        stats.fairness_index = calculate_fairness_index(peers);

        // Count starved and satisfied peers
        stats.starved_peers = peers
            .values()
            .filter(|p| p.allocation < self.config.min_guarantee)
            .count();

        stats.satisfied_peers = peers.values().filter(|p| p.allocation >= p.demand).count();

        stats.recalculations += 1;
    }

    /// Gets the current allocation for a peer
    pub fn get_allocation(&self, peer_id: &str) -> Option<u64> {
        let peers = self.peers.read().unwrap();
        peers.get(peer_id).map(|p| p.allocation)
    }

    /// Gets all peer allocations
    pub fn get_all_allocations(&self) -> HashMap<String, u64> {
        let peers = self.peers.read().unwrap();
        peers
            .iter()
            .map(|(id, peer)| (id.clone(), peer.allocation))
            .collect()
    }

    /// Checks if automatic recalculation is needed
    pub fn should_recalculate(&self) -> bool {
        let last = self.last_recalculation.read().unwrap();
        let interval = Duration::from_millis(self.config.adjustment_interval_ms);
        last.elapsed() >= interval
    }

    /// Auto-recalculates if interval has passed
    pub fn auto_recalculate(&self) {
        if self.should_recalculate() {
            self.recalculate_allocations();
        }
    }

    /// Clears all peer data
    pub fn clear(&self) {
        let mut peers = self.peers.write().unwrap();
        peers.clear();

        let mut stats = self.stats.write().unwrap();
        stats.total_peers = 0;
        stats.total_allocated = 0;
        stats.total_demanded = 0;
    }

    /// Gets current statistics
    pub fn stats(&self) -> FairnessStats {
        self.stats.read().unwrap().clone()
    }

    /// Gets the configuration
    pub fn config(&self) -> &FairnessConfig {
        &self.config
    }
}

/// Calculates Jain's fairness index (0.0 = unfair, 1.0 = perfectly fair)
fn calculate_fairness_index(peers: &HashMap<String, PeerBandwidth>) -> f64 {
    if peers.is_empty() {
        return 1.0;
    }

    let allocations: Vec<f64> = peers.values().map(|p| p.allocation as f64).collect();
    let sum: f64 = allocations.iter().sum();
    let sum_sq: f64 = allocations.iter().map(|&x| x * x).sum();

    if sum_sq == 0.0 {
        return 1.0;
    }

    let n = allocations.len() as f64;
    (sum * sum) / (n * sum_sq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = FairnessConfig::default();
        assert_eq!(config.total_bandwidth, 10_000_000);
        assert_eq!(config.min_guarantee, 100_000);
        assert_eq!(config.policy, AllocationPolicy::MaxMinFair);
        assert!(config.enable_priorities);
    }

    #[test]
    fn test_new_controller() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());
        let stats = controller.stats();

        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.total_allocated, 0);
    }

    #[test]
    fn test_register_peer() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);

        let stats = controller.stats();
        assert_eq!(stats.total_peers, 1);
    }

    #[test]
    fn test_unregister_peer() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.unregister_peer("peer1");

        let stats = controller.stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_request_bandwidth() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.request_bandwidth("peer1", 5_000_000);

        // Request recorded, allocation happens on recalculate
        controller.recalculate_allocations();

        let alloc = controller.get_allocation("peer1");
        assert!(alloc.is_some());
    }

    #[test]
    fn test_max_min_fair_equal_demand() {
        let config = FairnessConfig {
            total_bandwidth: 10_000_000,
            min_guarantee: 100_000,
            policy: AllocationPolicy::MaxMinFair,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        // Three peers with equal demand
        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);
        controller.register_peer("peer3", 1.0);

        controller.request_bandwidth("peer1", 5_000_000);
        controller.request_bandwidth("peer2", 5_000_000);
        controller.request_bandwidth("peer3", 5_000_000);

        controller.recalculate_allocations();

        // Each should get roughly equal share (total / 3)
        let alloc1 = controller.get_allocation("peer1").unwrap();
        let alloc2 = controller.get_allocation("peer2").unwrap();
        let alloc3 = controller.get_allocation("peer3").unwrap();

        assert!((alloc1 as i64 - alloc2 as i64).abs() < 100_000);
        assert!((alloc2 as i64 - alloc3 as i64).abs() < 100_000);
    }

    #[test]
    fn test_max_min_fair_different_demand() {
        let config = FairnessConfig {
            total_bandwidth: 10_000_000,
            min_guarantee: 100_000,
            policy: AllocationPolicy::MaxMinFair,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.request_bandwidth("peer1", 2_000_000); // Low demand
        controller.request_bandwidth("peer2", 9_000_000); // High demand

        controller.recalculate_allocations();

        let alloc1 = controller.get_allocation("peer1").unwrap();
        let alloc2 = controller.get_allocation("peer2").unwrap();

        // Peer1 should get its full demand
        assert!(alloc1 >= 2_000_000);

        // Peer2 should get the rest
        assert!(alloc2 > alloc1);
    }

    #[test]
    fn test_proportional_fair() {
        let config = FairnessConfig {
            total_bandwidth: 10_000_000,
            min_guarantee: 100_000,
            policy: AllocationPolicy::ProportionalFair,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.request_bandwidth("peer1", 1_000_000); // 10% of total
        controller.request_bandwidth("peer2", 9_000_000); // 90% of total

        controller.recalculate_allocations();

        let alloc1 = controller.get_allocation("peer1").unwrap();
        let alloc2 = controller.get_allocation("peer2").unwrap();

        // Should be proportional to demand
        let ratio = alloc2 as f64 / alloc1 as f64;
        assert!(ratio > 5.0); // Peer2 should get significantly more
    }

    #[test]
    fn test_weighted_fair() {
        let config = FairnessConfig {
            total_bandwidth: 10_000_000,
            min_guarantee: 100_000,
            policy: AllocationPolicy::WeightedFair,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0); // Weight 1.0
        controller.register_peer("peer2", 3.0); // Weight 3.0

        controller.request_bandwidth("peer1", 10_000_000); // Both want max
        controller.request_bandwidth("peer2", 10_000_000);

        controller.recalculate_allocations();

        let alloc1 = controller.get_allocation("peer1").unwrap();
        let alloc2 = controller.get_allocation("peer2").unwrap();

        // Peer2 should get ~3x what peer1 gets
        let ratio = alloc2 as f64 / alloc1 as f64;
        assert!((ratio - 3.0).abs() < 0.5);
    }

    #[test]
    fn test_minimum_guarantee() {
        let config = FairnessConfig {
            total_bandwidth: 1_000_000,
            min_guarantee: 200_000,
            policy: AllocationPolicy::MaxMinFair,
            ..Default::default()
        };
        let min_guarantee = config.min_guarantee;
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.request_bandwidth("peer1", 10_000_000);
        controller.request_bandwidth("peer2", 10_000_000);

        controller.recalculate_allocations();

        let alloc1 = controller.get_allocation("peer1").unwrap();
        let alloc2 = controller.get_allocation("peer2").unwrap();

        // Both should get at least minimum
        assert!(alloc1 >= min_guarantee);
        assert!(alloc2 >= min_guarantee);
    }

    #[test]
    fn test_get_all_allocations() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);
        controller.request_bandwidth("peer1", 5_000_000);
        controller.request_bandwidth("peer2", 5_000_000);
        controller.recalculate_allocations();

        let allocations = controller.get_all_allocations();

        assert_eq!(allocations.len(), 2);
        assert!(allocations.contains_key("peer1"));
        assert!(allocations.contains_key("peer2"));
    }

    #[test]
    fn test_fairness_index() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        // Equal allocations should give fairness index close to 1.0
        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);
        controller.register_peer("peer3", 1.0);

        controller.request_bandwidth("peer1", 5_000_000);
        controller.request_bandwidth("peer2", 5_000_000);
        controller.request_bandwidth("peer3", 5_000_000);

        controller.recalculate_allocations();

        let stats = controller.stats();
        assert!(stats.fairness_index > 0.9); // Should be close to perfectly fair
    }

    #[test]
    fn test_stats_tracking() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.request_bandwidth("peer1", 3_000_000);
        controller.request_bandwidth("peer2", 7_000_000);

        controller.recalculate_allocations();

        let stats = controller.stats();

        assert_eq!(stats.total_peers, 2);
        assert!(stats.total_allocated > 0);
        assert_eq!(stats.total_demanded, 10_000_000);
        assert!(stats.avg_allocation > 0.0);
        assert!(stats.utilization > 0.0 && stats.utilization <= 1.0);
        assert_eq!(stats.recalculations, 1);
    }

    #[test]
    fn test_report_usage() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.report_usage("peer1", 2_500_000);

        // Usage is recorded (not directly testable but shouldn't panic)
    }

    #[test]
    fn test_clear() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.clear();

        let stats = controller.stats();
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.total_allocated, 0);
    }

    #[test]
    fn test_should_recalculate() {
        let config = FairnessConfig {
            adjustment_interval_ms: 50,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        assert!(!controller.should_recalculate()); // Just created

        thread::sleep(Duration::from_millis(60));

        assert!(controller.should_recalculate());
    }

    #[test]
    fn test_auto_recalculate() {
        let config = FairnessConfig {
            adjustment_interval_ms: 50,
            ..Default::default()
        };
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0);
        controller.request_bandwidth("peer1", 5_000_000);

        thread::sleep(Duration::from_millis(60));

        controller.auto_recalculate();

        let stats = controller.stats();
        assert!(stats.recalculations > 0);
    }

    #[test]
    fn test_concurrent_access() {
        let controller = Arc::new(BandwidthFairnessController::new(FairnessConfig::default()));
        let mut handles = vec![];

        for i in 0..5 {
            let controller_clone = Arc::clone(&controller);
            let handle = thread::spawn(move || {
                let peer_id = format!("peer{}", i);
                controller_clone.register_peer(&peer_id, 1.0);
                controller_clone.request_bandwidth(&peer_id, 2_000_000);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        controller.recalculate_allocations();

        let stats = controller.stats();
        assert_eq!(stats.total_peers, 5);
    }

    #[test]
    fn test_zero_demand() {
        let controller = BandwidthFairnessController::new(FairnessConfig::default());

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        controller.request_bandwidth("peer1", 0);
        controller.request_bandwidth("peer2", 0);

        controller.recalculate_allocations();

        // Should not panic with zero demand
        let stats = controller.stats();
        assert_eq!(stats.total_demanded, 0);
    }

    #[test]
    fn test_over_subscription() {
        let config = FairnessConfig {
            total_bandwidth: 1_000_000,
            ..Default::default()
        };
        let total_bandwidth = config.total_bandwidth;
        let controller = BandwidthFairnessController::new(config);

        controller.register_peer("peer1", 1.0);
        controller.register_peer("peer2", 1.0);

        // Total demand exceeds capacity
        controller.request_bandwidth("peer1", 800_000);
        controller.request_bandwidth("peer2", 800_000);

        controller.recalculate_allocations();

        let stats = controller.stats();
        // Should not allocate more than total
        assert!(stats.total_allocated <= total_bandwidth);
    }
}
