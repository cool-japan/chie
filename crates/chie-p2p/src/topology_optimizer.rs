// Network Topology Optimizer
//
// Analyzes and optimizes the P2P network topology for better performance, reliability,
// and efficiency. Provides recommendations for connection changes based on various metrics.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Peer identifier type
pub type PeerId = String;

/// Network topology goals for optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationGoal {
    /// Minimize average network latency
    MinimizeLatency,
    /// Maximize total network bandwidth
    MaximizeBandwidth,
    /// Maximize network reliability and fault tolerance
    MaximizeReliability,
    /// Balance latency, bandwidth, and reliability
    Balanced,
    /// Minimize number of connections (resource conservation)
    MinimizeConnections,
    /// Maximize network connectivity and redundancy
    MaximizeConnectivity,
}

/// Connection recommendation from the optimizer
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionRecommendation {
    /// Add a new connection to improve topology
    Add {
        peer_id: PeerId,
        reason: String,
        priority: u8, // 1 (low) to 10 (high)
    },
    /// Remove an existing connection
    Remove {
        peer_id: PeerId,
        reason: String,
        priority: u8,
    },
    /// Replace one connection with another
    Replace {
        old_peer: PeerId,
        new_peer: PeerId,
        reason: String,
        priority: u8,
    },
}

/// Topology health metrics
#[derive(Debug, Clone)]
pub struct TopologyHealth {
    /// Overall health score (0.0 to 1.0)
    pub overall_score: f64,
    /// Connectivity score (0.0 to 1.0)
    pub connectivity_score: f64,
    /// Latency score (0.0 to 1.0, higher is better/lower latency)
    pub latency_score: f64,
    /// Bandwidth score (0.0 to 1.0)
    pub bandwidth_score: f64,
    /// Reliability score (0.0 to 1.0)
    pub reliability_score: f64,
    /// Number of detected bottlenecks
    pub bottleneck_count: usize,
    /// Number of single points of failure
    pub single_point_failures: usize,
    /// Average path length (hops)
    pub avg_path_length: f64,
    /// Network diameter (max hops between any two nodes)
    pub network_diameter: usize,
}

/// Peer metrics for topology analysis
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    pub peer_id: PeerId,
    pub latency: Duration,
    pub bandwidth: u64,   // bytes per second
    pub reliability: f64, // 0.0 to 1.0
    pub connection_count: usize,
    pub is_bottleneck: bool,
}

/// Network topology optimizer
pub struct TopologyOptimizer {
    optimization_goal: OptimizationGoal,
    peer_metrics: HashMap<PeerId, PeerMetrics>,
    connections: HashMap<PeerId, HashSet<PeerId>>,
    last_optimization: Instant,
    optimization_interval: Duration,
    min_connections: usize,
    max_connections: usize,
    target_connectivity: f64, // desired connectivity ratio (0.0 to 1.0)
}

impl TopologyOptimizer {
    /// Create a new topology optimizer
    pub fn new(goal: OptimizationGoal) -> Self {
        Self {
            optimization_goal: goal,
            peer_metrics: HashMap::new(),
            connections: HashMap::new(),
            last_optimization: Instant::now(),
            optimization_interval: Duration::from_secs(60), // optimize every minute
            min_connections: 3,
            max_connections: 50,
            target_connectivity: 0.7,
        }
    }

    /// Set optimization interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.optimization_interval = interval;
        self
    }

    /// Set connection limits
    pub fn with_connection_limits(mut self, min: usize, max: usize) -> Self {
        self.min_connections = min;
        self.max_connections = max;
        self
    }

    /// Set target connectivity ratio
    pub fn with_target_connectivity(mut self, target: f64) -> Self {
        self.target_connectivity = target.clamp(0.0, 1.0);
        self
    }

    /// Update peer metrics
    pub fn update_peer_metrics(&mut self, metrics: PeerMetrics) {
        self.peer_metrics.insert(metrics.peer_id.clone(), metrics);
    }

    /// Update network connections
    pub fn update_connections(&mut self, peer_id: PeerId, connected_peers: HashSet<PeerId>) {
        self.connections.insert(peer_id, connected_peers);
    }

    /// Remove peer from topology
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peer_metrics.remove(peer_id);
        self.connections.remove(peer_id);
        // Remove from other peers' connections
        for connections in self.connections.values_mut() {
            connections.remove(peer_id);
        }
    }

    /// Check if optimization should run
    pub fn should_optimize(&self) -> bool {
        self.last_optimization.elapsed() >= self.optimization_interval
    }

    /// Analyze topology health
    pub fn analyze_health(&self) -> TopologyHealth {
        let connectivity_score = self.calculate_connectivity_score();
        let latency_score = self.calculate_latency_score();
        let bandwidth_score = self.calculate_bandwidth_score();
        let reliability_score = self.calculate_reliability_score();

        let overall_score = match self.optimization_goal {
            OptimizationGoal::MinimizeLatency => latency_score,
            OptimizationGoal::MaximizeBandwidth => bandwidth_score,
            OptimizationGoal::MaximizeReliability => reliability_score,
            OptimizationGoal::Balanced => {
                (connectivity_score + latency_score + bandwidth_score + reliability_score) / 4.0
            }
            OptimizationGoal::MinimizeConnections => {
                // Score based on how close we are to minimum connections while maintaining health
                let conn_efficiency = 1.0 - self.calculate_connection_overhead();
                (conn_efficiency + reliability_score) / 2.0
            }
            OptimizationGoal::MaximizeConnectivity => connectivity_score,
        };

        let bottleneck_count = self.detect_bottlenecks().len();
        let single_point_failures = self.detect_single_points_of_failure().len();
        let (avg_path_length, network_diameter) = self.calculate_path_metrics();

        TopologyHealth {
            overall_score,
            connectivity_score,
            latency_score,
            bandwidth_score,
            reliability_score,
            bottleneck_count,
            single_point_failures,
            avg_path_length,
            network_diameter,
        }
    }

    /// Generate optimization recommendations
    pub fn generate_recommendations(&mut self) -> Vec<ConnectionRecommendation> {
        if !self.should_optimize() {
            return Vec::new();
        }

        self.last_optimization = Instant::now();

        let mut recommendations = Vec::new();

        // Add goal-specific recommendations
        match self.optimization_goal {
            OptimizationGoal::MinimizeLatency => {
                recommendations.extend(self.recommend_low_latency_connections());
            }
            OptimizationGoal::MaximizeBandwidth => {
                recommendations.extend(self.recommend_high_bandwidth_connections());
            }
            OptimizationGoal::MaximizeReliability => {
                recommendations.extend(self.recommend_reliable_connections());
            }
            OptimizationGoal::Balanced => {
                recommendations.extend(self.recommend_balanced_connections());
            }
            OptimizationGoal::MinimizeConnections => {
                recommendations.extend(self.recommend_minimal_connections());
            }
            OptimizationGoal::MaximizeConnectivity => {
                recommendations.extend(self.recommend_maximal_connectivity());
            }
        }

        // Always check for bottlenecks and single points of failure
        recommendations.extend(self.recommend_bottleneck_fixes());
        recommendations.extend(self.recommend_redundancy_improvements());

        // Sort by priority (highest first)
        recommendations.sort_by(|a, b| {
            let priority_a = match a {
                ConnectionRecommendation::Add { priority, .. } => *priority,
                ConnectionRecommendation::Remove { priority, .. } => *priority,
                ConnectionRecommendation::Replace { priority, .. } => *priority,
            };
            let priority_b = match b {
                ConnectionRecommendation::Add { priority, .. } => *priority,
                ConnectionRecommendation::Remove { priority, .. } => *priority,
                ConnectionRecommendation::Replace { priority, .. } => *priority,
            };
            priority_b.cmp(&priority_a)
        });

        recommendations
    }

    // Private helper methods

    fn calculate_connectivity_score(&self) -> f64 {
        if self.connections.is_empty() {
            return 0.0;
        }

        let total_peers = self.peer_metrics.len();
        if total_peers <= 1 {
            return 1.0; // Single peer is trivially connected
        }

        // Calculate actual connectivity vs. possible connectivity
        let total_connections: usize = self.connections.values().map(|c| c.len()).sum();
        let max_possible = total_peers * (total_peers - 1); // Fully connected graph
        let actual_ratio = total_connections as f64 / max_possible as f64;

        // Score based on how close we are to target connectivity
        let score: f64 = 1.0 - (actual_ratio - self.target_connectivity).abs();
        score.clamp(0.0, 1.0)
    }

    fn calculate_latency_score(&self) -> f64 {
        if self.peer_metrics.is_empty() {
            return 1.0;
        }

        let total_latency: u128 = self
            .peer_metrics
            .values()
            .map(|m| m.latency.as_millis())
            .sum();
        let avg_latency = total_latency as f64 / self.peer_metrics.len() as f64;

        // Score: 1.0 for latency <= 50ms, 0.0 for latency >= 500ms
        1.0 - ((avg_latency - 50.0) / 450.0).clamp(0.0, 1.0)
    }

    fn calculate_bandwidth_score(&self) -> f64 {
        if self.peer_metrics.is_empty() {
            return 0.0;
        }

        let total_bandwidth: u64 = self.peer_metrics.values().map(|m| m.bandwidth).sum();
        let avg_bandwidth = total_bandwidth as f64 / self.peer_metrics.len() as f64;

        // Score: 0.0 for bandwidth <= 1MB/s, 1.0 for bandwidth >= 10MB/s
        let mb_per_sec = avg_bandwidth / 1_000_000.0;
        ((mb_per_sec - 1.0) / 9.0).clamp(0.0, 1.0)
    }

    fn calculate_reliability_score(&self) -> f64 {
        if self.peer_metrics.is_empty() {
            return 0.0;
        }

        let total_reliability: f64 = self.peer_metrics.values().map(|m| m.reliability).sum();
        total_reliability / self.peer_metrics.len() as f64
    }

    fn calculate_connection_overhead(&self) -> f64 {
        let total_connections: usize = self.connections.values().map(|c| c.len()).sum();
        let total_peers = self.peer_metrics.len().max(1);
        let avg_connections = total_connections as f64 / total_peers as f64;
        let min = self.min_connections as f64;

        if avg_connections <= min {
            0.0
        } else {
            (avg_connections - min) / avg_connections
        }
    }

    fn detect_bottlenecks(&self) -> Vec<PeerId> {
        self.peer_metrics
            .values()
            .filter(|m| m.is_bottleneck)
            .map(|m| m.peer_id.clone())
            .collect()
    }

    fn detect_single_points_of_failure(&self) -> Vec<PeerId> {
        let mut critical_peers = Vec::new();

        for peer_id in self.peer_metrics.keys() {
            // A peer is a single point of failure if removing it would partition the network
            if self.is_critical_for_connectivity(peer_id) {
                critical_peers.push(peer_id.clone());
            }
        }

        critical_peers
    }

    fn is_critical_for_connectivity(&self, peer_id: &PeerId) -> bool {
        // Simple heuristic: peer is critical if it has >= 3 connections
        // and removing it would significantly reduce connectivity
        if let Some(connections) = self.connections.get(peer_id) {
            connections.len() >= 3
        } else {
            false
        }
    }

    fn calculate_path_metrics(&self) -> (f64, usize) {
        // Simplified: use connection count as proxy for path length
        if self.connections.is_empty() {
            return (0.0, 0);
        }

        let total_connections: usize = self.connections.values().map(|c| c.len()).sum();
        let avg_connections = total_connections as f64 / self.connections.len() as f64;

        // Estimate average path length (inverse of connectivity)
        let avg_path_length = if avg_connections > 0.0 {
            2.0 / avg_connections.sqrt()
        } else {
            0.0
        };

        // Estimate diameter (max path length)
        let diameter = if avg_connections >= 2.0 {
            3 // Well-connected
        } else if avg_connections >= 1.0 {
            5 // Moderately connected
        } else {
            10 // Poorly connected
        };

        (avg_path_length, diameter)
    }

    fn recommend_low_latency_connections(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Find peers with lowest latency that we're not connected to
        let mut candidates: Vec<_> = self
            .peer_metrics
            .values()
            .filter(|m| m.latency.as_millis() < 100)
            .collect();
        candidates.sort_by_key(|m| m.latency);

        for peer in candidates.iter().take(3) {
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: peer.peer_id.clone(),
                reason: format!("Low latency peer ({}ms)", peer.latency.as_millis()),
                priority: 8,
            });
        }

        recommendations
    }

    fn recommend_high_bandwidth_connections(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Find peers with highest bandwidth
        let mut candidates: Vec<_> = self.peer_metrics.values().collect();
        candidates.sort_by_key(|m| std::cmp::Reverse(m.bandwidth));

        for peer in candidates.iter().take(3) {
            let mbps = peer.bandwidth / 1_000_000;
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: peer.peer_id.clone(),
                reason: format!("High bandwidth peer ({}MB/s)", mbps),
                priority: 7,
            });
        }

        recommendations
    }

    fn recommend_reliable_connections(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Find most reliable peers
        let mut candidates: Vec<_> = self
            .peer_metrics
            .values()
            .filter(|m| m.reliability >= 0.9)
            .collect();
        candidates.sort_by(|a, b| b.reliability.partial_cmp(&a.reliability).unwrap());

        for peer in candidates.iter().take(3) {
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: peer.peer_id.clone(),
                reason: format!("Highly reliable peer ({:.1}%)", peer.reliability * 100.0),
                priority: 9,
            });
        }

        recommendations
    }

    fn recommend_balanced_connections(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Score peers by balanced metrics
        let mut scored_peers: Vec<_> = self
            .peer_metrics
            .values()
            .map(|m| {
                let latency_score = 1.0 - (m.latency.as_millis() as f64 / 500.0).min(1.0);
                let bandwidth_score = (m.bandwidth as f64 / 10_000_000.0).min(1.0);
                let reliability_score = m.reliability;
                let total_score = (latency_score + bandwidth_score + reliability_score) / 3.0;
                (m, total_score)
            })
            .collect();

        scored_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        for (peer, score) in scored_peers.iter().take(3) {
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: peer.peer_id.clone(),
                reason: format!("Balanced quality peer (score: {:.2})", score),
                priority: 7,
            });
        }

        recommendations
    }

    fn recommend_minimal_connections(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Remove redundant low-quality connections
        for (peer_id, metrics) in &self.peer_metrics {
            if metrics.connection_count > self.min_connections && metrics.reliability < 0.5 {
                recommendations.push(ConnectionRecommendation::Remove {
                    peer_id: peer_id.clone(),
                    reason: "Low reliability, reducing connections".to_string(),
                    priority: 5,
                });
            }
        }

        recommendations
    }

    fn recommend_maximal_connectivity(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        // Add more connections to improve redundancy
        let available_peers: Vec<_> = self.peer_metrics.keys().collect();

        for peer_id in available_peers.iter().take(5) {
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: (*peer_id).clone(),
                reason: "Increase network connectivity".to_string(),
                priority: 6,
            });
        }

        recommendations
    }

    fn recommend_bottleneck_fixes(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        for bottleneck in self.detect_bottlenecks() {
            recommendations.push(ConnectionRecommendation::Remove {
                peer_id: bottleneck.clone(),
                reason: "Bottleneck detected, consider alternative route".to_string(),
                priority: 9,
            });
        }

        recommendations
    }

    fn recommend_redundancy_improvements(&self) -> Vec<ConnectionRecommendation> {
        let mut recommendations = Vec::new();

        for critical_peer in self.detect_single_points_of_failure() {
            // For each critical peer, recommend adding backup connections
            recommendations.push(ConnectionRecommendation::Add {
                peer_id: critical_peer.clone(),
                reason: "Add redundancy for critical peer".to_string(),
                priority: 10,
            });
        }

        recommendations
    }

    /// Get statistics about the optimizer
    pub fn stats(&self) -> TopologyOptimizerStats {
        TopologyOptimizerStats {
            peer_count: self.peer_metrics.len(),
            connection_count: self.connections.values().map(|c| c.len()).sum(),
            optimization_goal: self.optimization_goal,
            last_optimization: self.last_optimization.elapsed(),
        }
    }
}

/// Topology optimizer statistics
#[derive(Debug, Clone)]
pub struct TopologyOptimizerStats {
    pub peer_count: usize,
    pub connection_count: usize,
    pub optimization_goal: OptimizationGoal,
    pub last_optimization: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer(
        id: &str,
        latency_ms: u64,
        bandwidth_mbps: u64,
        reliability: f64,
    ) -> PeerMetrics {
        PeerMetrics {
            peer_id: id.to_string(),
            latency: Duration::from_millis(latency_ms),
            bandwidth: bandwidth_mbps * 1_000_000,
            reliability,
            connection_count: 0,
            is_bottleneck: false,
        }
    }

    #[test]
    fn test_new_optimizer() {
        let optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);
        assert_eq!(optimizer.optimization_goal, OptimizationGoal::Balanced);
        assert_eq!(optimizer.min_connections, 3);
        assert_eq!(optimizer.max_connections, 50);
    }

    #[test]
    fn test_with_interval() {
        let optimizer = TopologyOptimizer::new(OptimizationGoal::MinimizeLatency)
            .with_interval(Duration::from_secs(30));
        assert_eq!(optimizer.optimization_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_with_connection_limits() {
        let optimizer = TopologyOptimizer::new(OptimizationGoal::MaximizeBandwidth)
            .with_connection_limits(5, 100);
        assert_eq!(optimizer.min_connections, 5);
        assert_eq!(optimizer.max_connections, 100);
    }

    #[test]
    fn test_with_target_connectivity() {
        let optimizer =
            TopologyOptimizer::new(OptimizationGoal::Balanced).with_target_connectivity(0.8);
        assert_eq!(optimizer.target_connectivity, 0.8);
    }

    #[test]
    fn test_update_peer_metrics() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);
        let peer = create_test_peer("peer1", 50, 10, 0.95);

        optimizer.update_peer_metrics(peer.clone());
        assert_eq!(optimizer.peer_metrics.len(), 1);
        assert!(optimizer.peer_metrics.contains_key(&peer.peer_id));
    }

    #[test]
    fn test_update_connections() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);
        let peer1 = "peer1".to_string();
        let peer2 = "peer2".to_string();
        let mut connections = HashSet::new();
        connections.insert(peer2.clone());

        optimizer.update_connections(peer1.clone(), connections);
        assert_eq!(optimizer.connections.len(), 1);
        assert_eq!(optimizer.connections.get(&peer1).unwrap().len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);
        let peer = create_test_peer("peer1", 50, 10, 0.95);

        optimizer.update_peer_metrics(peer.clone());
        assert_eq!(optimizer.peer_metrics.len(), 1);

        optimizer.remove_peer(&peer.peer_id);
        assert_eq!(optimizer.peer_metrics.len(), 0);
    }

    #[test]
    fn test_should_optimize_initially_true() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced)
            .with_interval(Duration::from_millis(10));

        // Initially should be false (just created)
        assert!(!optimizer.should_optimize());

        // But after the interval, should be true
        std::thread::sleep(Duration::from_millis(15));
        optimizer.last_optimization = Instant::now() - Duration::from_millis(15);
        assert!(optimizer.should_optimize());
    }

    #[test]
    fn test_analyze_health_empty() {
        let optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);
        let health = optimizer.analyze_health();

        assert!(health.overall_score >= 0.0 && health.overall_score <= 1.0);
        assert_eq!(health.bottleneck_count, 0);
        assert_eq!(health.single_point_failures, 0);
    }

    #[test]
    fn test_analyze_health_with_peers() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);

        let peer1 = create_test_peer("peer1", 50, 10, 0.95);
        let peer2 = create_test_peer("peer2", 100, 5, 0.85);

        optimizer.update_peer_metrics(peer1);
        optimizer.update_peer_metrics(peer2);

        let health = optimizer.analyze_health();
        assert!(health.overall_score >= 0.0 && health.overall_score <= 1.0);
        assert!(health.latency_score > 0.0);
        assert!(health.bandwidth_score > 0.0);
        assert!(health.reliability_score > 0.0);
    }

    #[test]
    fn test_generate_recommendations_respects_interval() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced)
            .with_interval(Duration::from_secs(60));

        let recommendations = optimizer.generate_recommendations();
        // Should be empty because we just optimized
        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_generate_recommendations_after_interval() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced)
            .with_interval(Duration::from_millis(1));

        // Set last optimization to past
        optimizer.last_optimization = Instant::now() - Duration::from_millis(10);

        let peer1 = create_test_peer("peer1", 50, 10, 0.95);
        optimizer.update_peer_metrics(peer1);

        std::thread::sleep(Duration::from_millis(5));
        let recommendations = optimizer.generate_recommendations();
        // Should have recommendations now
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_latency_optimization_goal() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::MinimizeLatency)
            .with_interval(Duration::from_millis(1));

        optimizer.last_optimization = Instant::now() - Duration::from_millis(10);

        let peer1 = create_test_peer("peer1", 10, 1, 0.5); // Low latency
        let peer2 = create_test_peer("peer2", 200, 100, 0.99); // High latency

        optimizer.update_peer_metrics(peer1.clone());
        optimizer.update_peer_metrics(peer2);

        let recommendations = optimizer.generate_recommendations();

        // Should prefer low-latency peer
        let has_low_latency_rec = recommendations.iter().any(|r| match r {
            ConnectionRecommendation::Add { peer_id, .. } => peer_id == &peer1.peer_id,
            _ => false,
        });
        assert!(has_low_latency_rec);
    }

    #[test]
    fn test_bandwidth_optimization_goal() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::MaximizeBandwidth)
            .with_interval(Duration::from_millis(1));

        optimizer.last_optimization = Instant::now() - Duration::from_millis(10);

        let peer1 = create_test_peer("peer1", 200, 100, 0.5); // High bandwidth
        let peer2 = create_test_peer("peer2", 10, 1, 0.99); // Low bandwidth

        optimizer.update_peer_metrics(peer1.clone());
        optimizer.update_peer_metrics(peer2);

        let recommendations = optimizer.generate_recommendations();

        // Should prefer high-bandwidth peer
        let has_high_bw_rec = recommendations.iter().any(|r| match r {
            ConnectionRecommendation::Add { peer_id, .. } => peer_id == &peer1.peer_id,
            _ => false,
        });
        assert!(has_high_bw_rec);
    }

    #[test]
    fn test_reliability_optimization_goal() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::MaximizeReliability)
            .with_interval(Duration::from_millis(1));

        optimizer.last_optimization = Instant::now() - Duration::from_millis(10);

        let peer1 = create_test_peer("peer1", 200, 1, 0.99); // High reliability
        let peer2 = create_test_peer("peer2", 10, 100, 0.5); // Low reliability

        optimizer.update_peer_metrics(peer1.clone());
        optimizer.update_peer_metrics(peer2);

        let recommendations = optimizer.generate_recommendations();

        // Should prefer highly reliable peer
        let has_reliable_rec = recommendations.iter().any(|r| match r {
            ConnectionRecommendation::Add { peer_id, .. } => peer_id == &peer1.peer_id,
            _ => false,
        });
        assert!(has_reliable_rec);
    }

    #[test]
    fn test_detect_bottlenecks() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);

        let mut peer1 = create_test_peer("peer1", 50, 10, 0.95);
        peer1.is_bottleneck = true;

        let peer2 = create_test_peer("peer2", 100, 5, 0.85);

        optimizer.update_peer_metrics(peer1.clone());
        optimizer.update_peer_metrics(peer2);

        let bottlenecks = optimizer.detect_bottlenecks();
        assert_eq!(bottlenecks.len(), 1);
        assert_eq!(bottlenecks[0], peer1.peer_id);
    }

    #[test]
    fn test_stats() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced);

        let peer1 = create_test_peer("peer1", 50, 10, 0.95);
        let peer2 = create_test_peer("peer2", 100, 5, 0.85);

        optimizer.update_peer_metrics(peer1.clone());
        optimizer.update_peer_metrics(peer2.clone());

        let mut connections1 = HashSet::new();
        connections1.insert(peer2.peer_id.clone());
        optimizer.update_connections(peer1.peer_id.clone(), connections1);

        let stats = optimizer.stats();
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.connection_count, 1);
        assert_eq!(stats.optimization_goal, OptimizationGoal::Balanced);
    }

    #[test]
    fn test_recommendation_priority_sorting() {
        let mut optimizer = TopologyOptimizer::new(OptimizationGoal::Balanced)
            .with_interval(Duration::from_millis(1));

        optimizer.last_optimization = Instant::now() - Duration::from_millis(10);

        let peer1 = create_test_peer("peer1", 10, 100, 0.99);
        optimizer.update_peer_metrics(peer1);

        let recommendations = optimizer.generate_recommendations();

        // Check that recommendations are sorted by priority (highest first)
        for i in 0..recommendations.len().saturating_sub(1) {
            let priority_i = match &recommendations[i] {
                ConnectionRecommendation::Add { priority, .. } => *priority,
                ConnectionRecommendation::Remove { priority, .. } => *priority,
                ConnectionRecommendation::Replace { priority, .. } => *priority,
            };
            let priority_next = match &recommendations[i + 1] {
                ConnectionRecommendation::Add { priority, .. } => *priority,
                ConnectionRecommendation::Remove { priority, .. } => *priority,
                ConnectionRecommendation::Replace { priority, .. } => *priority,
            };
            assert!(priority_i >= priority_next);
        }
    }
}
