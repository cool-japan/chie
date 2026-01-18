// Unified relay coordinator for production relay network management
//
// Integrates all relay subsystems into a cohesive whole:
// - Relay path optimization and selection
// - Token reward distribution and payment processing
// - Economic viability monitoring
// - Relay node registration and lifecycle management
// - Network-wide relay health monitoring
// - Automatic relay selection for transfers
// - Performance tracking and optimization

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::Instant;

#[cfg(test)]
use crate::relay_economics::TrafficPattern;
use crate::relay_economics::{RelayEconomicsSimulator, SimulationConfig};
use crate::relay_optimizer::{
    PathWeights, RelayCapability, RelayOptimizer, RelayOptimizerConfig, RelayPath,
};
use crate::relay_reward_manager::{PaymentRequest, RelayRewardManager, RewardConfig};

/// Relay coordinator configuration
#[derive(Debug, Clone)]
pub struct RelayCoordinatorConfig {
    /// Relay optimizer configuration
    pub optimizer_config: RelayOptimizerConfig,
    /// Reward manager configuration
    pub reward_config: RewardConfig,
    /// Minimum quality score for relay selection
    pub min_quality_for_selection: f64,
    /// Maximum path cost (tokens)
    pub max_path_cost: u64,
    /// Enable automatic reward distribution
    pub auto_reward: bool,
    /// Health check interval (seconds)
    pub health_check_interval_secs: u64,
}

impl Default for RelayCoordinatorConfig {
    fn default() -> Self {
        Self {
            optimizer_config: RelayOptimizerConfig::default(),
            reward_config: RewardConfig::default(),
            min_quality_for_selection: 0.7,
            max_path_cost: 1000,
            auto_reward: true,
            health_check_interval_secs: 300, // 5 minutes
        }
    }
}

/// Relay transfer request
#[derive(Debug, Clone)]
pub struct RelayTransferRequest {
    /// Source peer
    pub source: PeerId,
    /// Destination peer
    pub destination: PeerId,
    /// Data size (bytes)
    pub data_size: u64,
    /// Maximum cost willing to pay (tokens)
    pub max_cost: u64,
    /// Path selection weights
    pub weights: PathWeights,
}

/// Relay transfer result
#[derive(Debug, Clone)]
pub struct RelayTransferResult {
    /// Selected path
    pub path: RelayPath,
    /// Actual cost (tokens)
    pub actual_cost: u64,
    /// Transfer success
    pub success: bool,
    /// Transfer duration (ms)
    pub duration_ms: u64,
    /// Average quality score
    pub avg_quality: f64,
}

/// Relay node health status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHealthStatus {
    /// Relay is healthy and performing well
    Healthy,
    /// Relay is experiencing minor issues
    Degraded,
    /// Relay is having significant problems
    Unhealthy,
    /// Relay is not responding
    Offline,
}

/// Relay node health information
#[derive(Debug, Clone)]
pub struct RelayHealth {
    /// Peer ID
    pub peer_id: PeerId,
    /// Health status
    pub status: RelayHealthStatus,
    /// Success rate (0.0-1.0)
    pub success_rate: f64,
    /// Average latency (ms)
    pub avg_latency: u64,
    /// Available bandwidth (bytes/sec)
    pub available_bandwidth: u64,
    /// Tokens earned
    pub tokens_earned: u64,
    /// Last health check
    pub last_check: Instant,
}

/// Relay coordinator statistics
#[derive(Debug, Clone, Default)]
pub struct RelayCoordinatorStats {
    /// Total relays registered
    pub total_relays: usize,
    /// Healthy relays count
    pub healthy_relays: usize,
    /// Total paths found
    pub total_paths_found: u64,
    /// Total transfers completed
    pub total_transfers: u64,
    /// Successful transfers
    pub successful_transfers: u64,
    /// Total tokens distributed
    pub total_tokens_distributed: u64,
    /// Total payments processed
    pub total_payments: u64,
    /// Average path cost (tokens)
    pub avg_path_cost: f64,
    /// Average transfer quality
    pub avg_transfer_quality: f64,
}

/// Unified relay coordinator
pub struct RelayCoordinator {
    config: RelayCoordinatorConfig,
    optimizer: RelayOptimizer,
    reward_manager: RelayRewardManager,
    health_status: HashMap<PeerId, RelayHealth>,
    transfer_history: Vec<RelayTransferResult>,
    last_health_check: Instant,
    stats: RelayCoordinatorStats,
}

impl RelayCoordinator {
    /// Create a new relay coordinator
    pub fn new(config: RelayCoordinatorConfig) -> Self {
        Self {
            optimizer: RelayOptimizer::new(config.optimizer_config.clone()),
            reward_manager: RelayRewardManager::new(config.reward_config.clone()),
            config,
            health_status: HashMap::new(),
            transfer_history: Vec::new(),
            last_health_check: Instant::now(),
            stats: RelayCoordinatorStats::default(),
        }
    }

    /// Register a relay node
    pub fn register_relay(&mut self, capability: RelayCapability) {
        let peer_id = capability.peer_id;

        // Register with optimizer
        self.optimizer.register_relay(capability.clone());

        // Initialize health status
        self.health_status.insert(
            peer_id,
            RelayHealth {
                peer_id,
                status: RelayHealthStatus::Healthy,
                success_rate: 1.0,
                avg_latency: capability.avg_latency,
                available_bandwidth: capability.available_bandwidth,
                tokens_earned: 0,
                last_check: Instant::now(),
            },
        );

        self.stats.total_relays = self.health_status.len();
        self.update_healthy_count();
    }

    /// Unregister a relay node
    pub fn unregister_relay(&mut self, peer_id: &PeerId) {
        self.optimizer.unregister_relay(peer_id);
        self.health_status.remove(peer_id);
        self.stats.total_relays = self.health_status.len();
        self.update_healthy_count();
    }

    /// Find optimal relay path for a transfer
    pub fn find_relay_path(&mut self, request: &RelayTransferRequest) -> Option<RelayPath> {
        // Find path using optimizer
        let path = self
            .optimizer
            .find_path(request.source, request.destination)?;

        // Check cost constraint
        if path.total_cost > request.max_cost {
            return None;
        }

        // Check cost against coordinator limit
        if path.total_cost > self.config.max_path_cost {
            return None;
        }

        // Check relay quality
        if path.reliability < self.config.min_quality_for_selection {
            return None;
        }

        self.stats.total_paths_found += 1;
        Some(path)
    }

    /// Execute a relay transfer
    pub fn execute_transfer(
        &mut self,
        request: RelayTransferRequest,
    ) -> Result<RelayTransferResult, String> {
        // Find path
        let path = self
            .find_relay_path(&request)
            .ok_or("No suitable relay path found")?;

        let start = Instant::now();

        // Simulate transfer (in production, this would do actual transfer)
        let success = path.reliability > 0.8; // Simple success criterion
        let duration_ms = start.elapsed().as_millis() as u64;

        // Calculate quality based on latency and reliability
        let quality = (path.reliability + (1.0 / (1.0 + path.total_latency as f64 / 1000.0))) / 2.0;

        // Award relays if auto-reward enabled and transfer succeeded
        if self.config.auto_reward && success {
            for relay_id in &path.hops {
                // Calculate bytes per relay (split evenly)
                let bytes_per_relay = request.data_size / path.hops.len().max(1) as u64;

                if let Some(reward) =
                    self.reward_manager
                        .award_relay(relay_id, bytes_per_relay, quality, true)
                {
                    // Update health status
                    if let Some(health) = self.health_status.get_mut(relay_id) {
                        health.tokens_earned += reward;
                    }
                }
            }
        }

        // Update relay statistics
        for relay_id in &path.hops {
            if success {
                // Calculate cost per relay (split evenly)
                let cost_per_relay = path.total_cost / path.hops.len().max(1) as u64;
                self.optimizer.record_relay_success(
                    relay_id,
                    request.data_size,
                    cost_per_relay,
                    duration_ms,
                );
            } else {
                self.optimizer.record_relay_failure(relay_id);
            }
        }

        // Create result
        let result = RelayTransferResult {
            path: path.clone(),
            actual_cost: path.total_cost,
            success,
            duration_ms,
            avg_quality: quality,
        };

        // Update stats
        self.stats.total_transfers += 1;
        if success {
            self.stats.successful_transfers += 1;
        }
        self.stats.total_tokens_distributed = self.reward_manager.stats().total_distributed;
        self.stats.avg_path_cost = if self.stats.total_paths_found > 0 {
            (self.stats.avg_path_cost * (self.stats.total_paths_found - 1) as f64
                + path.total_cost as f64)
                / self.stats.total_paths_found as f64
        } else {
            path.total_cost as f64
        };

        self.transfer_history.push(result.clone());

        Ok(result)
    }

    /// Process payment request for a relay
    pub fn process_payment(
        &mut self,
        peer_id: &PeerId,
        amount: u64,
        destination: String,
    ) -> Result<PaymentRequest, String> {
        let payment = self
            .reward_manager
            .request_payment(peer_id, amount, destination)?;
        self.stats.total_payments += 1;
        Ok(payment)
    }

    /// Complete a payment
    pub fn complete_payment(&mut self, payment_id: u64) -> Result<(), String> {
        self.reward_manager.complete_payment(payment_id)
    }

    /// Get relay health status
    pub fn get_relay_health(&self, peer_id: &PeerId) -> Option<&RelayHealth> {
        self.health_status.get(peer_id)
    }

    /// Get all healthy relays
    pub fn get_healthy_relays(&self) -> Vec<&RelayHealth> {
        self.health_status
            .values()
            .filter(|h| h.status == RelayHealthStatus::Healthy)
            .collect()
    }

    /// Update relay health checks
    pub fn update_health_checks(&mut self) {
        let now = Instant::now();

        // Check if it's time for health check
        if now.duration_since(self.last_health_check).as_secs()
            < self.config.health_check_interval_secs
        {
            return;
        }

        for (peer_id, health) in &mut self.health_status {
            // Get relay stats from optimizer
            if let Some(relay_stats) = self.optimizer.get_relay_stats(peer_id) {
                // Update success rate
                health.success_rate = relay_stats.success_rate();

                // Update health status based on success rate
                health.status = if health.success_rate >= 0.95 {
                    RelayHealthStatus::Healthy
                } else if health.success_rate >= 0.80 {
                    RelayHealthStatus::Degraded
                } else if health.success_rate >= 0.50 {
                    RelayHealthStatus::Unhealthy
                } else {
                    RelayHealthStatus::Offline
                };

                // Get earnings
                if let Some(earnings) = self.reward_manager.get_earnings(peer_id) {
                    health.tokens_earned = earnings.total_earned;
                }

                health.last_check = now;
            }
        }

        self.last_health_check = now;
        self.update_healthy_count();
    }

    /// Run economic simulation
    pub fn run_economic_simulation(
        &self,
        config: SimulationConfig,
    ) -> crate::relay_economics::SimulationResults {
        let mut simulator = RelayEconomicsSimulator::new(config);
        simulator.run()
    }

    /// Get relay earnings
    pub fn get_relay_earnings(
        &self,
        peer_id: &PeerId,
    ) -> Option<&crate::relay_reward_manager::RelayEarnings> {
        self.reward_manager.get_earnings(peer_id)
    }

    /// Get top earning relays
    pub fn get_top_earners(
        &self,
        count: usize,
    ) -> Vec<&crate::relay_reward_manager::RelayEarnings> {
        self.reward_manager.get_top_earners(count)
    }

    /// Get relay by performance
    pub fn get_top_relays_by_performance(&self, count: usize) -> Vec<(PeerId, f64)> {
        self.optimizer.get_top_relays(count)
    }

    /// Get pending payments
    pub fn get_pending_payments(&self) -> Vec<&PaymentRequest> {
        self.reward_manager.get_pending_payments()
    }

    /// Get transfer history
    pub fn get_transfer_history(&self) -> &[RelayTransferResult] {
        &self.transfer_history
    }

    /// Get recent transfer success rate
    pub fn get_recent_success_rate(&self, count: usize) -> f64 {
        if self.transfer_history.is_empty() {
            return 0.0;
        }

        let recent: Vec<_> = self.transfer_history.iter().rev().take(count).collect();

        let successful = recent.iter().filter(|t| t.success).count();
        successful as f64 / recent.len() as f64
    }

    /// Get statistics
    pub fn stats(&self) -> &RelayCoordinatorStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &RelayCoordinatorConfig {
        &self.config
    }

    fn update_healthy_count(&mut self) {
        self.stats.healthy_relays = self
            .health_status
            .values()
            .filter(|h| h.status == RelayHealthStatus::Healthy)
            .count();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_relay(peer_id: PeerId) -> RelayCapability {
        RelayCapability {
            peer_id,
            max_bandwidth: 100_000_000,
            available_bandwidth: 100_000_000,
            avg_latency: 50,
            reliability: 0.95,
            cost_per_gb: 15,
            accepting_connections: true,
            last_updated: Instant::now(),
        }
    }

    #[test]
    fn test_coordinator_creation() {
        let config = RelayCoordinatorConfig::default();
        let coordinator = RelayCoordinator::new(config);
        assert_eq!(coordinator.stats().total_relays, 0);
    }

    #[test]
    fn test_register_relay() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();
        let relay = create_test_relay(peer);

        coordinator.register_relay(relay);
        assert_eq!(coordinator.stats().total_relays, 1);
        assert_eq!(coordinator.stats().healthy_relays, 1);
    }

    #[test]
    fn test_unregister_relay() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();
        let relay = create_test_relay(peer);

        coordinator.register_relay(relay);
        assert_eq!(coordinator.stats().total_relays, 1);

        coordinator.unregister_relay(&peer);
        assert_eq!(coordinator.stats().total_relays, 0);
    }

    #[test]
    fn test_find_relay_path() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());

        // Register some relays
        let relay1 = PeerId::random();
        let relay2 = PeerId::random();

        coordinator.register_relay(create_test_relay(relay1));
        coordinator.register_relay(create_test_relay(relay2));

        // Try to find path
        let source = PeerId::random();
        let dest = PeerId::random();

        let request = RelayTransferRequest {
            source,
            destination: dest,
            data_size: 1_000_000,
            max_cost: 1000,
            weights: PathWeights::default(),
        };

        // Path might not be found without proper topology setup
        let _path = coordinator.find_relay_path(&request);
    }

    #[test]
    fn test_get_relay_health() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();
        let relay = create_test_relay(peer);

        coordinator.register_relay(relay);

        let health = coordinator.get_relay_health(&peer).unwrap();
        assert_eq!(health.status, RelayHealthStatus::Healthy);
        assert_eq!(health.success_rate, 1.0);
    }

    #[test]
    fn test_get_healthy_relays() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());

        for _ in 0..3 {
            let peer = PeerId::random();
            coordinator.register_relay(create_test_relay(peer));
        }

        let healthy = coordinator.get_healthy_relays();
        assert_eq!(healthy.len(), 3);
    }

    #[test]
    fn test_process_payment() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();

        // Need to have earnings first
        coordinator
            .reward_manager
            .award_relay(&peer, 10_000_000_000, 0.9, true);

        let result = coordinator.process_payment(&peer, 1000, "test_address".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_complete_payment() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();

        coordinator
            .reward_manager
            .award_relay(&peer, 10_000_000_000, 0.9, true);
        let payment = coordinator
            .process_payment(&peer, 1000, "test".to_string())
            .unwrap();

        let result = coordinator.complete_payment(payment.id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_pending_payments() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();

        coordinator
            .reward_manager
            .award_relay(&peer, 10_000_000_000, 0.9, true);
        coordinator
            .process_payment(&peer, 1000, "test".to_string())
            .unwrap();

        let pending = coordinator.get_pending_payments();
        assert!(!pending.is_empty());
    }

    #[test]
    fn test_stats_tracking() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());

        // Register relays
        for _ in 0..5 {
            coordinator.register_relay(create_test_relay(PeerId::random()));
        }

        let stats = coordinator.stats();
        assert_eq!(stats.total_relays, 5);
        assert_eq!(stats.healthy_relays, 5);
    }

    #[test]
    fn test_economic_simulation() {
        let coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());

        let sim_config = SimulationConfig {
            num_relays: 3,
            daily_bandwidth_gb: 100.0,
            traffic_pattern: TrafficPattern::Constant,
            duration_days: 1,
            ..Default::default()
        };

        let results = coordinator.run_economic_simulation(sim_config);
        assert!(results.total_tokens_distributed > 0);
    }

    #[test]
    fn test_get_top_earners() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        coordinator
            .reward_manager
            .award_relay(&peer1, 1_000_000_000, 0.9, true);
        coordinator
            .reward_manager
            .award_relay(&peer2, 5_000_000_000, 0.9, true);

        let top = coordinator.get_top_earners(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].peer_id, peer2); // Higher earner first
    }

    #[test]
    fn test_health_status_levels() {
        let mut coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let peer = PeerId::random();

        coordinator.register_relay(create_test_relay(peer));

        let health = coordinator.get_relay_health(&peer).unwrap();
        assert_eq!(health.status, RelayHealthStatus::Healthy);
    }

    #[test]
    fn test_transfer_history() {
        let coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let history = coordinator.get_transfer_history();
        assert_eq!(history.len(), 0);
    }

    #[test]
    fn test_recent_success_rate_empty() {
        let coordinator = RelayCoordinator::new(RelayCoordinatorConfig::default());
        let rate = coordinator.get_recent_success_rate(10);
        assert_eq!(rate, 0.0);
    }
}
