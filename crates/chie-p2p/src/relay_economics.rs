// Relay economics simulator for testing incentive mechanisms
//
// Simulates the economic behavior of relay nodes:
// - Network simulation with varying load and relay nodes
// - Economic viability analysis for relay operators
// - Token flow and distribution modeling
// - Incentive mechanism testing and optimization
// - Cost/benefit analysis for relay participation
// - Market equilibrium simulation

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::Instant;

use crate::relay_optimizer::{RelayCapability, RelayOptimizer, RelayOptimizerConfig};
use crate::relay_reward_manager::{RelayRewardManager, RewardConfig};

/// Relay node operating costs
#[derive(Debug, Clone)]
pub struct OperatingCosts {
    /// Fixed costs per day (tokens)
    pub fixed_daily: u64,
    /// Cost per GB bandwidth (tokens)
    pub per_gb: u64,
    /// Maintenance cost per day (tokens)
    pub maintenance: u64,
}

impl Default for OperatingCosts {
    fn default() -> Self {
        Self {
            fixed_daily: 50, // 50 tokens/day fixed
            per_gb: 10,      // 10 tokens/GB
            maintenance: 20, // 20 tokens/day maintenance
        }
    }
}

/// Simulated relay node
#[derive(Debug, Clone)]
pub struct SimulatedRelay {
    /// Peer ID
    pub peer_id: PeerId,
    /// Relay capability
    pub capability: RelayCapability,
    /// Operating costs
    pub costs: OperatingCosts,
    /// Total bytes relayed
    pub total_bytes_relayed: u64,
    /// Total tokens earned
    pub total_earned: u64,
    /// Total costs incurred
    pub total_costs: u64,
    /// Active since
    pub active_since: Instant,
    /// Quality score (0.0-1.0)
    pub quality_score: f64,
}

impl SimulatedRelay {
    fn new(peer_id: PeerId, capability: RelayCapability, costs: OperatingCosts) -> Self {
        Self {
            peer_id,
            capability,
            costs,
            total_bytes_relayed: 0,
            total_earned: 0,
            total_costs: 0,
            active_since: Instant::now(),
            quality_score: 0.8, // Start with good quality
        }
    }

    /// Calculate current profit/loss
    pub fn profit(&self) -> i64 {
        self.total_earned as i64 - self.total_costs as i64
    }

    /// Calculate profit margin
    pub fn profit_margin(&self) -> f64 {
        if self.total_earned == 0 {
            return -100.0;
        }
        (self.profit() as f64 / self.total_earned as f64) * 100.0
    }

    /// Calculate return on investment (ROI) per day
    pub fn roi_per_day(&self) -> f64 {
        let days = self.active_since.elapsed().as_secs() as f64 / 86400.0;
        if days == 0.0 {
            return 0.0;
        }
        (self.profit() as f64 / days) / (self.costs.fixed_daily + self.costs.maintenance) as f64
            * 100.0
    }

    /// Check if relay is profitable
    pub fn is_profitable(&self) -> bool {
        self.profit() > 0
    }
}

/// Network traffic pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPattern {
    /// Constant traffic
    Constant,
    /// Bursty traffic with peaks and valleys
    Bursty,
    /// Gradually increasing traffic
    Increasing,
    /// Gradually decreasing traffic
    Decreasing,
    /// Daily pattern with peak hours
    DailyPattern,
}

/// Simulation configuration
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Number of relay nodes
    pub num_relays: usize,
    /// Total network bandwidth demand (GB/day)
    pub daily_bandwidth_gb: f64,
    /// Traffic pattern
    pub traffic_pattern: TrafficPattern,
    /// Simulation duration (days)
    pub duration_days: u32,
    /// Time step size (seconds)
    pub time_step_secs: u64,
    /// Reward configuration
    pub reward_config: RewardConfig,
    /// Operating costs
    pub operating_costs: OperatingCosts,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            num_relays: 10,
            daily_bandwidth_gb: 1000.0,
            traffic_pattern: TrafficPattern::Constant,
            duration_days: 30,
            time_step_secs: 3600, // 1 hour
            reward_config: RewardConfig::default(),
            operating_costs: OperatingCosts::default(),
        }
    }
}

/// Simulation results
#[derive(Debug, Clone)]
pub struct SimulationResults {
    /// Total tokens distributed
    pub total_tokens_distributed: u64,
    /// Total bytes relayed
    pub total_bytes_relayed: u64,
    /// Number of profitable relays
    pub profitable_relays: usize,
    /// Average profit per relay
    pub avg_profit_per_relay: f64,
    /// Average profit margin
    pub avg_profit_margin: f64,
    /// Average ROI per day
    pub avg_roi_per_day: f64,
    /// Total network costs
    pub total_network_costs: u64,
    /// Highest earning relay
    pub highest_earner: Option<PeerId>,
    /// Highest earning amount
    pub highest_earnings: u64,
    /// Network efficiency (earned/cost ratio)
    pub network_efficiency: f64,
}

/// Relay economics simulator
pub struct RelayEconomicsSimulator {
    config: SimulationConfig,
    relays: HashMap<PeerId, SimulatedRelay>,
    optimizer: RelayOptimizer,
    reward_manager: RelayRewardManager,
    #[allow(dead_code)]
    current_time: Instant,
    total_steps: u64,
}

impl RelayEconomicsSimulator {
    /// Create a new simulator
    pub fn new(config: SimulationConfig) -> Self {
        let optimizer = RelayOptimizer::new(RelayOptimizerConfig::default());
        let reward_manager = RelayRewardManager::new(config.reward_config.clone());

        let mut sim = Self {
            config,
            relays: HashMap::new(),
            optimizer,
            reward_manager,
            current_time: Instant::now(),
            total_steps: 0,
        };

        // Initialize relay nodes
        sim.initialize_relays();

        sim
    }

    fn initialize_relays(&mut self) {
        for _ in 0..self.config.num_relays {
            let peer_id = PeerId::random();
            let capability = RelayCapability {
                peer_id,
                max_bandwidth: 100_000_000, // 100 MB/s
                available_bandwidth: 100_000_000,
                avg_latency: 50, // 50ms
                reliability: 0.95,
                cost_per_gb: 15, // 15 tokens/GB
                accepting_connections: true,
                last_updated: Instant::now(),
            };

            self.optimizer.register_relay(capability.clone());

            let relay =
                SimulatedRelay::new(peer_id, capability, self.config.operating_costs.clone());

            self.relays.insert(peer_id, relay);
        }
    }

    /// Calculate traffic demand for current time step
    fn calculate_traffic_demand(&self, step: u64) -> f64 {
        let total_steps = (self.config.duration_days * 86400) as u64 / self.config.time_step_secs;
        let progress = step as f64 / total_steps as f64;

        match self.config.traffic_pattern {
            TrafficPattern::Constant => self.config.daily_bandwidth_gb / total_steps as f64,
            TrafficPattern::Bursty => {
                // Random bursts
                let phase = (step as f64 * 0.1).sin();
                let base = self.config.daily_bandwidth_gb / total_steps as f64;
                base * (1.0 + phase * 0.5)
            }
            TrafficPattern::Increasing => {
                let base = self.config.daily_bandwidth_gb / total_steps as f64;
                base * (1.0 + progress)
            }
            TrafficPattern::Decreasing => {
                let base = self.config.daily_bandwidth_gb / total_steps as f64;
                base * (2.0 - progress)
            }
            TrafficPattern::DailyPattern => {
                // Peak during "business hours" (assume 8-18h is peak)
                let hour_in_day = (step * self.config.time_step_secs / 3600) % 24;
                let base = self.config.daily_bandwidth_gb / total_steps as f64;
                if (8..18).contains(&hour_in_day) {
                    base * 1.5 // 50% higher during peak
                } else {
                    base * 0.5 // 50% lower during off-peak
                }
            }
        }
    }

    /// Run a simulation step
    fn step(&mut self) {
        // Calculate traffic demand for this step (in GB)
        let traffic_gb = self.calculate_traffic_demand(self.total_steps);
        let traffic_bytes = (traffic_gb * 1_073_741_824.0) as u64;

        // Distribute traffic across relays based on their capacity
        let total_capacity: u64 = self
            .relays
            .values()
            .map(|r| r.capability.available_bandwidth)
            .sum();

        if total_capacity == 0 {
            return; // No capacity available
        }

        for relay in self.relays.values_mut() {
            // Allocate traffic proportional to capacity
            let relay_share = relay.capability.available_bandwidth as f64 / total_capacity as f64;
            let relay_bytes = (traffic_bytes as f64 * relay_share) as u64;

            if relay_bytes == 0 {
                continue;
            }

            // Simulate relay operation
            relay.total_bytes_relayed += relay_bytes;

            // Award tokens
            if let Some(reward) = self.reward_manager.award_relay(
                &relay.peer_id,
                relay_bytes,
                relay.quality_score,
                true,
            ) {
                relay.total_earned += reward;
            }

            // Calculate costs for this relay
            let bandwidth_gb = relay_bytes as f64 / 1_073_741_824.0;
            let bandwidth_cost = (bandwidth_gb * relay.costs.per_gb as f64) as u64;
            relay.total_costs += bandwidth_cost;

            // Add time-based costs (prorated for time step)
            let time_fraction = self.config.time_step_secs as f64 / 86400.0;
            let fixed_cost = (relay.costs.fixed_daily as f64 * time_fraction) as u64;
            let maintenance_cost = (relay.costs.maintenance as f64 * time_fraction) as u64;
            relay.total_costs += fixed_cost + maintenance_cost;

            // Quality varies slightly over time
            relay.quality_score = (relay.quality_score * 0.95 + 0.8 * 0.05).clamp(0.6, 1.0);
        }

        self.total_steps += 1;
    }

    /// Run the complete simulation
    pub fn run(&mut self) -> SimulationResults {
        let total_steps = (self.config.duration_days * 86400) as u64 / self.config.time_step_secs;

        for _ in 0..total_steps {
            self.step();
        }

        self.calculate_results()
    }

    /// Calculate simulation results
    fn calculate_results(&self) -> SimulationResults {
        let total_tokens_distributed = self.reward_manager.stats().total_distributed;
        let total_bytes_relayed: u64 = self.relays.values().map(|r| r.total_bytes_relayed).sum();
        let profitable_relays = self.relays.values().filter(|r| r.is_profitable()).count();

        let total_profit: i64 = self.relays.values().map(|r| r.profit()).sum();
        let avg_profit_per_relay = if !self.relays.is_empty() {
            total_profit as f64 / self.relays.len() as f64
        } else {
            0.0
        };

        let total_margin: f64 = self.relays.values().map(|r| r.profit_margin()).sum();
        let avg_profit_margin = if !self.relays.is_empty() {
            total_margin / self.relays.len() as f64
        } else {
            0.0
        };

        let total_roi: f64 = self.relays.values().map(|r| r.roi_per_day()).sum();
        let avg_roi_per_day = if !self.relays.is_empty() {
            total_roi / self.relays.len() as f64
        } else {
            0.0
        };

        let total_network_costs: u64 = self.relays.values().map(|r| r.total_costs).sum();

        let (highest_earner, highest_earnings) = self
            .relays
            .values()
            .max_by_key(|r| r.total_earned)
            .map(|r| (Some(r.peer_id), r.total_earned))
            .unwrap_or((None, 0));

        let network_efficiency = if total_network_costs > 0 {
            total_tokens_distributed as f64 / total_network_costs as f64
        } else {
            0.0
        };

        SimulationResults {
            total_tokens_distributed,
            total_bytes_relayed,
            profitable_relays,
            avg_profit_per_relay,
            avg_profit_margin,
            avg_roi_per_day,
            total_network_costs,
            highest_earner,
            highest_earnings,
            network_efficiency,
        }
    }

    /// Get relay details
    pub fn get_relay(&self, peer_id: &PeerId) -> Option<&SimulatedRelay> {
        self.relays.get(peer_id)
    }

    /// Get all relays
    pub fn get_relays(&self) -> Vec<&SimulatedRelay> {
        self.relays.values().collect()
    }

    /// Get reward manager stats
    pub fn reward_stats(&self) -> &crate::relay_reward_manager::RewardManagerStats {
        self.reward_manager.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_basic() {
        let config = SimulationConfig {
            num_relays: 5,
            daily_bandwidth_gb: 100.0,
            traffic_pattern: TrafficPattern::Constant,
            duration_days: 1,
            time_step_secs: 3600, // 1 hour
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        let results = sim.run();

        assert!(results.total_tokens_distributed > 0);
        assert!(results.total_bytes_relayed > 0);
        assert_eq!(sim.get_relays().len(), 5);
    }

    #[test]
    fn test_operating_costs_accumulate() {
        let config = SimulationConfig {
            num_relays: 1,
            daily_bandwidth_gb: 10.0,
            duration_days: 2,
            time_step_secs: 86400, // 1 day
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        sim.run();

        let relay = sim.get_relays()[0];
        assert!(relay.total_costs > 0);
    }

    #[test]
    fn test_profit_calculation() {
        let peer_id = PeerId::random();
        let capability = RelayCapability {
            peer_id,
            max_bandwidth: 100_000_000,
            available_bandwidth: 100_000_000,
            avg_latency: 50,
            reliability: 0.95,
            cost_per_gb: 15,
            accepting_connections: true,
            last_updated: Instant::now(),
        };

        let mut relay = SimulatedRelay::new(peer_id, capability, OperatingCosts::default());
        relay.total_earned = 1000;
        relay.total_costs = 800;

        assert_eq!(relay.profit(), 200);
        assert!(relay.is_profitable());
    }

    #[test]
    fn test_profit_margin() {
        let peer_id = PeerId::random();
        let capability = RelayCapability {
            peer_id,
            max_bandwidth: 100_000_000,
            available_bandwidth: 100_000_000,
            avg_latency: 50,
            reliability: 0.95,
            cost_per_gb: 15,
            accepting_connections: true,
            last_updated: Instant::now(),
        };

        let mut relay = SimulatedRelay::new(peer_id, capability, OperatingCosts::default());
        relay.total_earned = 1000;
        relay.total_costs = 800;

        assert!((relay.profit_margin() - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_traffic_patterns() {
        for pattern in [
            TrafficPattern::Constant,
            TrafficPattern::Bursty,
            TrafficPattern::Increasing,
            TrafficPattern::Decreasing,
            TrafficPattern::DailyPattern,
        ] {
            let config = SimulationConfig {
                traffic_pattern: pattern,
                duration_days: 1,
                ..Default::default()
            };

            let mut sim = RelayEconomicsSimulator::new(config);
            let results = sim.run();

            assert!(results.total_bytes_relayed > 0);
        }
    }

    #[test]
    fn test_multiple_relays_share_traffic() {
        let config = SimulationConfig {
            num_relays: 3,
            daily_bandwidth_gb: 300.0,
            duration_days: 1,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        sim.run();

        let relays = sim.get_relays();
        for relay in relays {
            assert!(relay.total_bytes_relayed > 0);
            assert!(relay.total_earned > 0);
        }
    }

    #[test]
    fn test_network_efficiency() {
        let config = SimulationConfig {
            num_relays: 5,
            daily_bandwidth_gb: 100.0,
            duration_days: 7,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        let results = sim.run();

        // Network efficiency should be positive (tokens earned vs costs)
        assert!(results.network_efficiency > 0.0);
    }

    #[test]
    fn test_profitable_relays_count() {
        let config = SimulationConfig {
            num_relays: 5,
            daily_bandwidth_gb: 500.0, // High traffic
            duration_days: 30,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        let results = sim.run();

        // With high traffic, most relays should be profitable
        assert!(results.profitable_relays > 0);
    }

    #[test]
    fn test_highest_earner_tracking() {
        let config = SimulationConfig {
            num_relays: 5,
            daily_bandwidth_gb: 100.0,
            duration_days: 7,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        let results = sim.run();

        assert!(results.highest_earner.is_some());
        assert!(results.highest_earnings > 0);
    }

    #[test]
    fn test_longer_simulation() {
        let config = SimulationConfig {
            num_relays: 3,
            daily_bandwidth_gb: 50.0,
            duration_days: 30, // One month
            time_step_secs: 3600,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        let results = sim.run();

        assert!(results.total_tokens_distributed > 0);
        assert!(results.avg_profit_per_relay != 0.0);
    }

    #[test]
    fn test_reward_stats_integration() {
        let config = SimulationConfig {
            num_relays: 3,
            daily_bandwidth_gb: 100.0,
            duration_days: 1,
            ..Default::default()
        };

        let mut sim = RelayEconomicsSimulator::new(config);
        sim.run();

        let stats = sim.reward_stats();
        assert!(stats.total_distributed > 0);
        assert_eq!(stats.total_relays, 3);
    }
}
