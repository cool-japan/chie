//! Network Coordinator - Holistic P2P Network Management
//!
//! This module provides a central coordinator that integrates all P2P subsystems
//! for holistic network optimization and management. It makes system-wide decisions
//! by considering multiple factors across different subsystems.
//!
//! # Features
//!
//! - **Holistic Optimization**: Coordinates bandwidth, routing, replication, and caching
//! - **System-wide Decision Making**: Makes decisions considering all subsystems
//! - **Event Coordination**: Handles and routes events across subsystems
//! - **Resource Orchestration**: Optimizes resource allocation across the network
//! - **Health Monitoring**: Aggregate health monitoring and alerting
//! - **Performance Tuning**: Automatic performance tuning based on network conditions
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::network_coordinator::{NetworkCoordinator, CoordinatorConfig, OptimizationGoal};
//!
//! let config = CoordinatorConfig {
//!     optimization_goal: OptimizationGoal::Balanced,
//!     enable_auto_tuning: true,
//!     health_check_interval: 60,
//!     ..Default::default()
//! };
//!
//! let mut coordinator = NetworkCoordinator::new(config);
//! coordinator.add_peer("peer1", 100.0, 50); // latency_ms, bandwidth_mbps
//!
//! // Get optimization recommendations
//! let recommendations = coordinator.get_recommendations();
//! println!("System recommendations: {} items", recommendations.len());
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Network coordinator configuration
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Primary optimization goal
    pub optimization_goal: OptimizationGoal,
    /// Enable automatic network tuning
    pub enable_auto_tuning: bool,
    /// Health check interval in seconds
    pub health_check_interval: u64,
    /// Minimum peers for stable operation
    pub min_peers: usize,
    /// Maximum peers to manage
    pub max_peers: usize,
    /// Resource allocation aggressiveness (0.0-1.0)
    pub allocation_aggressiveness: f64,
    /// Enable predictive optimization
    pub enable_prediction: bool,
    /// Rebalancing threshold (0.0-1.0)
    pub rebalance_threshold: f64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            optimization_goal: OptimizationGoal::Balanced,
            enable_auto_tuning: true,
            health_check_interval: 60,
            min_peers: 3,
            max_peers: 1000,
            allocation_aggressiveness: 0.5,
            enable_prediction: true,
            rebalance_threshold: 0.3,
        }
    }
}

/// Primary optimization goals
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationGoal {
    /// Minimize latency
    LowLatency,
    /// Maximize throughput
    HighThroughput,
    /// Maximize reliability
    HighReliability,
    /// Minimize cost
    LowCost,
    /// Balance all factors
    Balanced,
    /// Custom weights
    Custom,
}

/// System health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemHealth {
    /// All systems operating normally
    Healthy,
    /// Some degradation detected
    Degraded,
    /// Critical issues present
    Critical,
    /// System failure
    Failed,
}

/// Optimization recommendation
#[derive(Debug, Clone)]
pub struct Recommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Priority (0.0-1.0, higher is more important)
    pub priority: f64,
    /// Description
    pub description: String,
    /// Expected impact
    pub expected_impact: f64,
    /// Estimated cost
    pub estimated_cost: f64,
}

/// Types of recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationType {
    /// Add more peers
    AddPeers,
    /// Remove underperforming peers
    RemovePeers,
    /// Rebalance content distribution
    RebalanceContent,
    /// Increase replication factor
    IncreaseReplication,
    /// Decrease replication factor
    DecreaseReplication,
    /// Adjust bandwidth allocation
    AdjustBandwidth,
    /// Optimize routing paths
    OptimizeRouting,
    /// Clear cache
    ClearCache,
    /// Warm up cache
    WarmupCache,
    /// Increase connection pool
    IncreaseConnections,
    /// Decrease connection pool
    DecreaseConnections,
}

/// Peer information tracked by coordinator
#[derive(Debug, Clone)]
struct PeerInfo {
    #[allow(dead_code)]
    peer_id: String,
    latency_ms: f64,
    bandwidth_mbps: u64,
    reliability_score: f64,
    last_seen: Instant,
    request_count: u64,
    failure_count: u64,
    avg_response_time_ms: f64,
}

/// Network metrics aggregation
#[derive(Debug, Clone)]
pub struct CoordinatorMetrics {
    /// Total peers in network
    pub total_peers: usize,
    /// Active peers
    pub active_peers: usize,
    /// Average latency across network
    pub avg_latency_ms: f64,
    /// Total available bandwidth
    pub total_bandwidth_mbps: u64,
    /// Average reliability score
    pub avg_reliability: f64,
    /// Network health status
    pub health: SystemHealth,
    /// Total requests served
    pub total_requests: u64,
    /// Total failures
    pub total_failures: u64,
    /// Success rate
    pub success_rate: f64,
}

/// Network coordinator for holistic management
pub struct NetworkCoordinator {
    config: CoordinatorConfig,
    peers: HashMap<String, PeerInfo>,
    #[allow(dead_code)]
    last_health_check: Instant,
    last_optimization: Instant,
    total_requests: u64,
    total_failures: u64,
    recommendations: Vec<Recommendation>,
}

impl NetworkCoordinator {
    /// Create a new network coordinator
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            last_health_check: Instant::now(),
            last_optimization: Instant::now(),
            total_requests: 0,
            total_failures: 0,
            recommendations: Vec::new(),
        }
    }

    /// Add or update a peer in the network
    pub fn add_peer(&mut self, peer_id: &str, latency_ms: f64, bandwidth_mbps: u64) {
        let peer_info = PeerInfo {
            peer_id: peer_id.to_string(),
            latency_ms,
            bandwidth_mbps,
            reliability_score: 1.0,
            last_seen: Instant::now(),
            request_count: 0,
            failure_count: 0,
            avg_response_time_ms: latency_ms,
        };
        self.peers.insert(peer_id.to_string(), peer_info);

        // Check if we need to optimize after adding peer
        if self.should_optimize() {
            self.optimize();
        }
    }

    /// Remove a peer from the network
    pub fn remove_peer(&mut self, peer_id: &str) -> bool {
        self.peers.remove(peer_id).is_some()
    }

    /// Record a successful request
    pub fn record_request(&mut self, peer_id: &str, response_time_ms: f64) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.request_count += 1;
            peer.last_seen = Instant::now();

            // Update average response time with exponential moving average
            peer.avg_response_time_ms = peer.avg_response_time_ms * 0.9 + response_time_ms * 0.1;

            // Update reliability score
            let success_count = peer.request_count.saturating_sub(peer.failure_count);
            let success_rate = success_count as f64 / peer.request_count as f64;
            peer.reliability_score = success_rate;
        }
        self.total_requests += 1;
    }

    /// Record a failed request
    pub fn record_failure(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.request_count += 1;
            peer.failure_count += 1;
            peer.last_seen = Instant::now();

            // Update reliability score
            let success_count = peer.request_count.saturating_sub(peer.failure_count);
            let success_rate = success_count as f64 / peer.request_count.max(1) as f64;
            peer.reliability_score = success_rate;
        }
        self.total_requests += 1;
        self.total_failures += 1;
    }

    /// Get current network metrics
    pub fn get_metrics(&self) -> CoordinatorMetrics {
        let total_peers = self.peers.len();
        let active_peers = self
            .peers
            .values()
            .filter(|p| p.last_seen.elapsed() < Duration::from_secs(300))
            .count();

        let avg_latency = if total_peers > 0 {
            self.peers.values().map(|p| p.latency_ms).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        let total_bandwidth: u64 = self.peers.values().map(|p| p.bandwidth_mbps).sum();

        let avg_reliability = if total_peers > 0 {
            self.peers
                .values()
                .map(|p| p.reliability_score)
                .sum::<f64>()
                / total_peers as f64
        } else {
            0.0
        };

        let success_rate = if self.total_requests > 0 {
            (self.total_requests - self.total_failures) as f64 / self.total_requests as f64
        } else {
            1.0
        };

        let health = self.assess_health(active_peers, avg_reliability, success_rate);

        CoordinatorMetrics {
            total_peers,
            active_peers,
            avg_latency_ms: avg_latency,
            total_bandwidth_mbps: total_bandwidth,
            avg_reliability,
            health,
            total_requests: self.total_requests,
            total_failures: self.total_failures,
            success_rate,
        }
    }

    /// Assess overall system health
    fn assess_health(
        &self,
        active_peers: usize,
        avg_reliability: f64,
        success_rate: f64,
    ) -> SystemHealth {
        if active_peers < self.config.min_peers {
            return SystemHealth::Critical;
        }

        if success_rate < 0.5 || avg_reliability < 0.5 {
            return SystemHealth::Failed;
        }

        if success_rate < 0.8 || avg_reliability < 0.8 {
            return SystemHealth::Degraded;
        }

        SystemHealth::Healthy
    }

    /// Check if optimization should run
    fn should_optimize(&self) -> bool {
        if !self.config.enable_auto_tuning {
            return false;
        }

        let elapsed = self.last_optimization.elapsed();
        elapsed > Duration::from_secs(self.config.health_check_interval)
    }

    /// Run optimization and generate recommendations
    pub fn optimize(&mut self) {
        self.last_optimization = Instant::now();
        self.recommendations.clear();

        let metrics = self.get_metrics();

        // Generate recommendations based on optimization goal
        match self.config.optimization_goal {
            OptimizationGoal::LowLatency => self.optimize_for_latency(&metrics),
            OptimizationGoal::HighThroughput => self.optimize_for_throughput(&metrics),
            OptimizationGoal::HighReliability => self.optimize_for_reliability(&metrics),
            OptimizationGoal::LowCost => self.optimize_for_cost(&metrics),
            OptimizationGoal::Balanced => self.optimize_balanced(&metrics),
            OptimizationGoal::Custom => self.optimize_custom(&metrics),
        }
    }

    /// Optimize for low latency
    fn optimize_for_latency(&mut self, metrics: &CoordinatorMetrics) {
        if metrics.avg_latency_ms > 100.0 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::OptimizeRouting,
                priority: 0.9,
                description: "High average latency detected. Optimize routing paths.".to_string(),
                expected_impact: 0.3,
                estimated_cost: 0.2,
            });
        }

        // Remove high-latency peers
        let high_latency_peers = self.peers.values().filter(|p| p.latency_ms > 200.0).count();

        if high_latency_peers > 0 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::RemovePeers,
                priority: 0.7,
                description: format!(
                    "Found {} high-latency peers. Consider removing.",
                    high_latency_peers
                ),
                expected_impact: 0.25,
                estimated_cost: 0.1,
            });
        }
    }

    /// Optimize for high throughput
    fn optimize_for_throughput(&mut self, metrics: &CoordinatorMetrics) {
        if metrics.total_bandwidth_mbps < 100 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::AddPeers,
                priority: 0.9,
                description: "Low total bandwidth. Add more high-bandwidth peers.".to_string(),
                expected_impact: 0.5,
                estimated_cost: 0.4,
            });
        }

        if metrics.active_peers < self.config.max_peers / 2 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::IncreaseConnections,
                priority: 0.8,
                description: "Connection pool has capacity. Increase connections.".to_string(),
                expected_impact: 0.4,
                estimated_cost: 0.3,
            });
        }
    }

    /// Optimize for high reliability
    fn optimize_for_reliability(&mut self, metrics: &CoordinatorMetrics) {
        if metrics.avg_reliability < 0.9 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::IncreaseReplication,
                priority: 0.95,
                description: "Low reliability. Increase replication factor.".to_string(),
                expected_impact: 0.4,
                estimated_cost: 0.6,
            });
        }

        if metrics.success_rate < 0.95 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::RemovePeers,
                priority: 0.85,
                description: "Low success rate. Remove unreliable peers.".to_string(),
                expected_impact: 0.3,
                estimated_cost: 0.2,
            });
        }
    }

    /// Optimize for low cost
    fn optimize_for_cost(&mut self, _metrics: &CoordinatorMetrics) {
        if self.peers.len() > self.config.min_peers * 2 {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::RemovePeers,
                priority: 0.8,
                description: "More peers than needed. Remove excess peers to reduce cost."
                    .to_string(),
                expected_impact: 0.2,
                estimated_cost: -0.5, // Negative cost means savings
            });
        }

        // Check for over-replication
        self.recommendations.push(Recommendation {
            recommendation_type: RecommendationType::DecreaseReplication,
            priority: 0.7,
            description: "Consider reducing replication factor to save resources.".to_string(),
            expected_impact: 0.1,
            estimated_cost: -0.3,
        });
    }

    /// Balanced optimization
    fn optimize_balanced(&mut self, metrics: &CoordinatorMetrics) {
        // Combine strategies with balanced weights
        if metrics.avg_latency_ms > 150.0 {
            self.optimize_for_latency(metrics);
        }

        if metrics.avg_reliability < 0.85 {
            self.optimize_for_reliability(metrics);
        }

        if metrics.total_bandwidth_mbps < 50 {
            self.optimize_for_throughput(metrics);
        }

        // Rebalance if network is imbalanced
        if self.is_imbalanced(metrics) {
            self.recommendations.push(Recommendation {
                recommendation_type: RecommendationType::RebalanceContent,
                priority: 0.75,
                description: "Network load is imbalanced. Rebalance content distribution."
                    .to_string(),
                expected_impact: 0.35,
                estimated_cost: 0.25,
            });
        }
    }

    /// Custom optimization (placeholder)
    fn optimize_custom(&mut self, metrics: &CoordinatorMetrics) {
        // Custom optimization logic can be implemented here
        self.optimize_balanced(metrics);
    }

    /// Check if network is imbalanced
    fn is_imbalanced(&self, _metrics: &CoordinatorMetrics) -> bool {
        if self.peers.is_empty() {
            return false;
        }

        // Calculate variance in peer request counts
        let avg_requests = self.peers.values().map(|p| p.request_count).sum::<u64>() as f64
            / self.peers.len() as f64;

        let variance = self
            .peers
            .values()
            .map(|p| {
                let diff = p.request_count as f64 - avg_requests;
                diff * diff
            })
            .sum::<f64>()
            / self.peers.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = if avg_requests > 0.0 {
            std_dev / avg_requests
        } else {
            0.0
        };

        // Consider imbalanced if CV > threshold
        coefficient_of_variation > self.config.rebalance_threshold
    }

    /// Get current recommendations
    pub fn get_recommendations(&self) -> Vec<Recommendation> {
        let mut recs = self.recommendations.clone();
        recs.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap());
        recs
    }

    /// Get top N recommendations
    pub fn get_top_recommendations(&self, n: usize) -> Vec<Recommendation> {
        let mut recs = self.get_recommendations();
        recs.truncate(n);
        recs
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.total_requests = 0;
        self.total_failures = 0;
        for peer in self.peers.values_mut() {
            peer.request_count = 0;
            peer.failure_count = 0;
        }
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.get_metrics().health, SystemHealth::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_coordinator() {
        let config = CoordinatorConfig::default();
        let coordinator = NetworkCoordinator::new(config);
        assert_eq!(coordinator.peer_count(), 0);
    }

    #[test]
    fn test_add_peer() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        assert_eq!(coordinator.peer_count(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        assert!(coordinator.remove_peer("peer1"));
        assert_eq!(coordinator.peer_count(), 0);
    }

    #[test]
    fn test_record_request() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.record_request("peer1", 45.0);

        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.total_requests, 1);
    }

    #[test]
    fn test_record_failure() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.record_failure("peer1");

        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.total_failures, 1);
    }

    #[test]
    fn test_metrics() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.add_peer("peer2", 75.0, 200);

        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.total_peers, 2);
        assert_eq!(metrics.total_bandwidth_mbps, 300);
        assert!(metrics.avg_latency_ms > 60.0 && metrics.avg_latency_ms < 65.0);
    }

    #[test]
    fn test_health_assessment() {
        let config = CoordinatorConfig {
            min_peers: 2,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        // Not enough peers
        coordinator.add_peer("peer1", 50.0, 100);
        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.health, SystemHealth::Critical);

        // Enough peers
        coordinator.add_peer("peer2", 60.0, 150);
        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.health, SystemHealth::Healthy);
    }

    #[test]
    fn test_optimization_goals() {
        // Test LowLatency goal
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::LowLatency,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);
        coordinator.add_peer("peer1", 250.0, 10);
        coordinator.optimize();
        assert!(!coordinator.get_recommendations().is_empty());

        // Test HighThroughput goal
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::HighThroughput,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);
        coordinator.add_peer("peer1", 50.0, 10);
        coordinator.optimize();
        assert!(!coordinator.get_recommendations().is_empty());

        // Test HighReliability goal
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::HighReliability,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);
        coordinator.add_peer("peer1", 50.0, 100);
        for _ in 0..10 {
            coordinator.record_failure("peer1");
        }
        coordinator.optimize();
        assert!(!coordinator.get_recommendations().is_empty());

        // Test LowCost goal
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::LowCost,
            enable_auto_tuning: false,
            min_peers: 2,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);
        for i in 0..10 {
            coordinator.add_peer(&format!("peer{}", i), 50.0, 100);
        }
        coordinator.optimize();
        assert!(!coordinator.get_recommendations().is_empty());

        // Test Balanced goal
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::Balanced,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);
        coordinator.add_peer("peer1", 200.0, 10);
        coordinator.optimize();
        // Balanced may or may not have recommendations
        let _ = coordinator.get_recommendations();
    }

    #[test]
    fn test_latency_optimization() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::LowLatency,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        // Add high-latency peer
        coordinator.add_peer("peer1", 250.0, 100);
        coordinator.optimize();

        let recs = coordinator.get_recommendations();
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_throughput_optimization() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::HighThroughput,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        // Add low-bandwidth peer
        coordinator.add_peer("peer1", 50.0, 10);
        coordinator.optimize();

        let recs = coordinator.get_recommendations();
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_reliability_optimization() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::HighReliability,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        coordinator.add_peer("peer1", 50.0, 100);

        // Record failures to decrease reliability
        for _ in 0..10 {
            coordinator.record_failure("peer1");
        }

        coordinator.optimize();
        let recs = coordinator.get_recommendations();
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_cost_optimization() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::LowCost,
            min_peers: 2,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        // Add many peers (more than min_peers * 2)
        for i in 0..10 {
            coordinator.add_peer(&format!("peer{}", i), 50.0, 100);
        }

        coordinator.optimize();
        let recs = coordinator.get_recommendations();
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_top_recommendations() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::LowLatency,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        coordinator.add_peer("peer1", 250.0, 100);
        coordinator.optimize();

        let top_recs = coordinator.get_top_recommendations(1);
        assert_eq!(top_recs.len(), 1);
    }

    #[test]
    fn test_reset_stats() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.record_request("peer1", 45.0);

        coordinator.reset_stats();
        let metrics = coordinator.get_metrics();
        assert_eq!(metrics.total_requests, 0);
    }

    #[test]
    fn test_is_healthy() {
        let config = CoordinatorConfig {
            min_peers: 2,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        assert!(!coordinator.is_healthy());

        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.add_peer("peer2", 60.0, 150);

        assert!(coordinator.is_healthy());
    }

    #[test]
    fn test_imbalance_detection() {
        let config = CoordinatorConfig {
            rebalance_threshold: 0.5,
            optimization_goal: OptimizationGoal::Balanced,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        coordinator.add_peer("peer1", 50.0, 100);
        coordinator.add_peer("peer2", 60.0, 150);
        coordinator.add_peer("peer3", 70.0, 200);

        // Create imbalance
        for _ in 0..100 {
            coordinator.record_request("peer1", 50.0);
        }
        coordinator.record_request("peer2", 60.0);
        coordinator.record_request("peer3", 70.0);

        coordinator.optimize();
        let recs = coordinator.get_recommendations();

        // Should recommend rebalancing
        let has_rebalance = recs
            .iter()
            .any(|r| r.recommendation_type == RecommendationType::RebalanceContent);
        assert!(has_rebalance);
    }

    #[test]
    fn test_success_rate_calculation() {
        let mut coordinator = NetworkCoordinator::new(CoordinatorConfig::default());
        coordinator.add_peer("peer1", 50.0, 100);

        for _ in 0..8 {
            coordinator.record_request("peer1", 50.0);
        }
        for _ in 0..2 {
            coordinator.record_failure("peer1");
        }

        let metrics = coordinator.get_metrics();
        assert!((metrics.success_rate - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_recommendation_sorting() {
        let config = CoordinatorConfig {
            optimization_goal: OptimizationGoal::Balanced,
            enable_auto_tuning: false,
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        coordinator.add_peer("peer1", 250.0, 10);
        coordinator.optimize();

        let recs = coordinator.get_recommendations();
        // Verify recommendations are sorted by priority
        for i in 1..recs.len() {
            assert!(recs[i - 1].priority >= recs[i].priority);
        }
    }

    #[test]
    fn test_auto_tuning() {
        let config = CoordinatorConfig {
            enable_auto_tuning: true,
            health_check_interval: 0, // Immediate
            ..Default::default()
        };
        let mut coordinator = NetworkCoordinator::new(config);

        // Auto-tuning should trigger optimization when adding peer
        coordinator.add_peer("peer1", 50.0, 100);

        // Wait a bit for interval to pass
        std::thread::sleep(std::time::Duration::from_millis(10));

        coordinator.add_peer("peer2", 60.0, 150);
        // Optimization should have run
    }

    #[test]
    fn test_default_config() {
        let config = CoordinatorConfig::default();
        assert_eq!(config.optimization_goal, OptimizationGoal::Balanced);
        assert!(config.enable_auto_tuning);
        assert_eq!(config.min_peers, 3);
        assert_eq!(config.max_peers, 1000);
    }
}
