// Adaptive Replication Manager
//
// Intelligently manages content replication across the P2P network based on
// popularity, network conditions, peer churn, and availability requirements.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Peer identifier type
pub type PeerId = String;

/// Content identifier type
pub type ContentId = String;

/// Replication strategy for content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationStrategy {
    /// Minimal replication (1-2 copies)
    Minimal,
    /// Low replication (3-5 copies)
    Low,
    /// Medium replication (6-10 copies)
    Medium,
    /// High replication (11-20 copies)
    High,
    /// Maximum replication (20+ copies)
    Maximum,
    /// Adaptive based on conditions
    Adaptive,
}

impl ReplicationStrategy {
    /// Get the target replica count range for this strategy
    pub fn target_replicas(&self) -> (usize, usize) {
        match self {
            ReplicationStrategy::Minimal => (1, 2),
            ReplicationStrategy::Low => (3, 5),
            ReplicationStrategy::Medium => (6, 10),
            ReplicationStrategy::High => (11, 20),
            ReplicationStrategy::Maximum => (21, 50),
            ReplicationStrategy::Adaptive => (3, 10), // Default adaptive range
        }
    }
}

/// Content replication metadata
#[derive(Debug, Clone)]
pub struct ReplicationMetadata {
    pub content_id: ContentId,
    pub current_replicas: usize,
    pub target_replicas: usize,
    pub strategy: ReplicationStrategy,
    pub last_updated: Instant,
    pub popularity_score: f64,   // 0.0 to 1.0
    pub availability_score: f64, // 0.0 to 1.0 (based on peer stability)
    pub size_bytes: u64,
}

/// Replication action to be taken
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationAction {
    /// Add more replicas
    Increase {
        content_id: ContentId,
        target_count: usize,
        reason: String,
    },
    /// Remove excess replicas
    Decrease {
        content_id: ContentId,
        target_count: usize,
        reason: String,
    },
    /// Redistribute replicas (move to better peers)
    Redistribute {
        content_id: ContentId,
        from_peers: Vec<PeerId>,
        to_peers: Vec<PeerId>,
        reason: String,
    },
    /// No action needed
    Maintain { content_id: ContentId },
}

/// Peer replication capacity
#[derive(Debug, Clone)]
pub struct PeerCapacity {
    pub peer_id: PeerId,
    pub total_storage: u64,   // bytes
    pub used_storage: u64,    // bytes
    pub stability_score: f64, // 0.0 to 1.0
    pub bandwidth: u64,       // bytes per second
    pub reliability: f64,     // 0.0 to 1.0
}

impl PeerCapacity {
    /// Available storage in bytes
    pub fn available_storage(&self) -> u64 {
        self.total_storage.saturating_sub(self.used_storage)
    }

    /// Storage utilization ratio (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        if self.total_storage == 0 {
            return 1.0;
        }
        self.used_storage as f64 / self.total_storage as f64
    }

    /// Overall capacity score for hosting replicas
    pub fn capacity_score(&self) -> f64 {
        let storage_score = 1.0 - self.utilization();
        let bandwidth_score = (self.bandwidth as f64 / 10_000_000.0).min(1.0); // 0-10MB/s
        (storage_score + self.stability_score + bandwidth_score + self.reliability) / 4.0
    }
}

/// Adaptive replication manager configuration
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Minimum replicas for any content
    pub min_replicas: usize,
    /// Maximum replicas for any content
    pub max_replicas: usize,
    /// Popularity threshold for increasing replication (0.0 to 1.0)
    pub popularity_threshold: f64,
    /// Minimum availability score to maintain replication
    pub min_availability: f64,
    /// How often to evaluate replication needs
    pub evaluation_interval: Duration,
    /// Storage utilization threshold before removing replicas
    pub storage_pressure_threshold: f64,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            min_replicas: 3,
            max_replicas: 20,
            popularity_threshold: 0.7,
            min_availability: 0.8,
            evaluation_interval: Duration::from_secs(300), // 5 minutes
            storage_pressure_threshold: 0.9,               // 90% utilization
        }
    }
}

/// Adaptive replication manager
pub struct AdaptiveReplicationManager {
    config: ReplicationConfig,
    content_metadata: HashMap<ContentId, ReplicationMetadata>,
    peer_capacities: HashMap<PeerId, PeerCapacity>,
    content_locations: HashMap<ContentId, Vec<PeerId>>,
    last_evaluation: Instant,
}

impl AdaptiveReplicationManager {
    /// Create a new replication manager
    pub fn new(config: ReplicationConfig) -> Self {
        Self {
            config,
            content_metadata: HashMap::new(),
            peer_capacities: HashMap::new(),
            content_locations: HashMap::new(),
            last_evaluation: Instant::now(),
        }
    }

    /// Register content for replication management
    pub fn register_content(
        &mut self,
        content_id: ContentId,
        size_bytes: u64,
        strategy: ReplicationStrategy,
    ) {
        let (min, _) = strategy.target_replicas();
        let metadata = ReplicationMetadata {
            content_id: content_id.clone(),
            current_replicas: 0,
            target_replicas: min,
            strategy,
            last_updated: Instant::now(),
            popularity_score: 0.0,
            availability_score: 0.0,
            size_bytes,
        };
        self.content_metadata.insert(content_id.clone(), metadata);
        self.content_locations.insert(content_id, Vec::new());
    }

    /// Update content metadata
    pub fn update_content_metadata(
        &mut self,
        content_id: &ContentId,
        popularity_score: f64,
        availability_score: f64,
    ) {
        if let Some(metadata) = self.content_metadata.get_mut(content_id) {
            metadata.popularity_score = popularity_score.clamp(0.0, 1.0);
            metadata.availability_score = availability_score.clamp(0.0, 1.0);
            metadata.last_updated = Instant::now();
        }
    }

    /// Update peer capacity information
    pub fn update_peer_capacity(&mut self, capacity: PeerCapacity) {
        self.peer_capacities
            .insert(capacity.peer_id.clone(), capacity);
    }

    /// Record that content is stored on a peer
    pub fn record_replica(&mut self, content_id: &ContentId, peer_id: PeerId) {
        if let Some(locations) = self.content_locations.get_mut(content_id) {
            if !locations.contains(&peer_id) {
                locations.push(peer_id);
                if let Some(metadata) = self.content_metadata.get_mut(content_id) {
                    metadata.current_replicas = locations.len();
                }
            }
        }
    }

    /// Remove replica from tracking
    pub fn remove_replica(&mut self, content_id: &ContentId, peer_id: &PeerId) {
        if let Some(locations) = self.content_locations.get_mut(content_id) {
            locations.retain(|p| p != peer_id);
            if let Some(metadata) = self.content_metadata.get_mut(content_id) {
                metadata.current_replicas = locations.len();
            }
        }
    }

    /// Check if replication evaluation should run
    pub fn should_evaluate(&self) -> bool {
        self.last_evaluation.elapsed() >= self.config.evaluation_interval
    }

    /// Evaluate replication needs and generate actions
    pub fn evaluate_replication(&mut self) -> Vec<ReplicationAction> {
        if !self.should_evaluate() {
            return Vec::new();
        }

        self.last_evaluation = Instant::now();
        let mut actions = Vec::new();

        // Collect content IDs to avoid borrowing issues
        let content_ids: Vec<_> = self.content_metadata.keys().cloned().collect();

        for content_id in content_ids {
            // Update target replicas based on strategy
            if let Some(metadata) = self.content_metadata.get_mut(&content_id) {
                Self::update_target_replicas_static(&self.config, metadata);
            }

            // Now determine action (requires immutable borrow)
            if let Some(metadata) = self.content_metadata.get(&content_id) {
                let action = self.determine_action(&content_id, metadata);
                if !matches!(action, ReplicationAction::Maintain { .. }) {
                    actions.push(action);
                }
            }
        }

        // Handle storage pressure
        actions.extend(self.handle_storage_pressure());

        actions
    }

    /// Update target replica count based on current conditions (static version)
    fn update_target_replicas_static(
        config: &ReplicationConfig,
        metadata: &mut ReplicationMetadata,
    ) {
        let base_target = match metadata.strategy {
            ReplicationStrategy::Adaptive => Self::calculate_adaptive_target(metadata),
            _ => {
                let (min, max) = metadata.strategy.target_replicas();
                // Adjust within range based on popularity
                let range = max - min;
                let popularity_factor = metadata.popularity_score;
                min + (range as f64 * popularity_factor) as usize
            }
        };

        metadata.target_replicas = base_target
            .max(config.min_replicas)
            .min(config.max_replicas);
    }

    /// Calculate adaptive target replicas
    fn calculate_adaptive_target(metadata: &ReplicationMetadata) -> usize {
        // Base on popularity
        let popularity_factor = metadata.popularity_score;

        // Adjust for availability (low availability = more replicas needed)
        let availability_factor = 1.0 - metadata.availability_score;

        // Combine factors
        let combined_score = (popularity_factor * 0.6 + availability_factor * 0.4).clamp(0.0, 1.0);

        // Map to replica count (3 to 15)
        let base = 3;
        let range = 12;
        base + (range as f64 * combined_score) as usize
    }

    /// Determine what action to take for content
    fn determine_action(
        &self,
        content_id: &ContentId,
        metadata: &ReplicationMetadata,
    ) -> ReplicationAction {
        let current = metadata.current_replicas;
        let target = metadata.target_replicas;

        if current < target {
            // Need more replicas
            ReplicationAction::Increase {
                content_id: content_id.clone(),
                target_count: target - current,
                reason: format!(
                    "Insufficient replicas ({} < {}), popularity: {:.2}, availability: {:.2}",
                    current, target, metadata.popularity_score, metadata.availability_score
                ),
            }
        } else if current > target {
            // Too many replicas
            ReplicationAction::Decrease {
                content_id: content_id.clone(),
                target_count: current - target,
                reason: format!(
                    "Excess replicas ({} > {}), popularity: {:.2}",
                    current, target, metadata.popularity_score
                ),
            }
        } else {
            // Check if redistribution is needed
            if self.needs_redistribution(content_id) {
                self.create_redistribution_action(content_id)
            } else {
                ReplicationAction::Maintain {
                    content_id: content_id.clone(),
                }
            }
        }
    }

    /// Check if content needs redistribution to better peers
    fn needs_redistribution(&self, content_id: &ContentId) -> bool {
        if let Some(locations) = self.content_locations.get(content_id) {
            // Check if any hosting peer has low capacity score
            for peer_id in locations {
                if let Some(capacity) = self.peer_capacities.get(peer_id) {
                    if capacity.capacity_score() < 0.5 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Create a redistribution action
    fn create_redistribution_action(&self, content_id: &ContentId) -> ReplicationAction {
        let mut from_peers = Vec::new();
        let mut to_peers = Vec::new();

        if let Some(locations) = self.content_locations.get(content_id) {
            // Find low-quality hosting peers
            for peer_id in locations {
                if let Some(capacity) = self.peer_capacities.get(peer_id) {
                    if capacity.capacity_score() < 0.5 {
                        from_peers.push(peer_id.clone());
                    }
                }
            }

            // Find high-quality available peers
            for (peer_id, capacity) in &self.peer_capacities {
                if !locations.contains(peer_id) && capacity.capacity_score() > 0.7 {
                    to_peers.push(peer_id.clone());
                    if to_peers.len() >= from_peers.len() {
                        break;
                    }
                }
            }
        }

        ReplicationAction::Redistribute {
            content_id: content_id.clone(),
            from_peers,
            to_peers,
            reason: "Redistributing to higher-quality peers".to_string(),
        }
    }

    /// Handle storage pressure by removing low-priority replicas
    fn handle_storage_pressure(&self) -> Vec<ReplicationAction> {
        let mut actions = Vec::new();

        // Find peers under storage pressure
        for (peer_id, capacity) in &self.peer_capacities {
            if capacity.utilization() >= self.config.storage_pressure_threshold {
                // Find low-priority content on this peer
                for (content_id, locations) in &self.content_locations {
                    if locations.contains(peer_id) {
                        if let Some(metadata) = self.content_metadata.get(content_id) {
                            // Remove if popularity is low and we have excess replicas
                            if metadata.popularity_score < 0.3
                                && metadata.current_replicas > metadata.target_replicas
                            {
                                actions.push(ReplicationAction::Decrease {
                                    content_id: content_id.clone(),
                                    target_count: 1,
                                    reason: format!("Storage pressure on peer {}", peer_id),
                                });
                            }
                        }
                    }
                }
            }
        }

        actions
    }

    /// Get replication statistics
    pub fn stats(&self) -> ReplicationStats {
        let total_content = self.content_metadata.len();
        let total_replicas: usize = self
            .content_metadata
            .values()
            .map(|m| m.current_replicas)
            .sum();
        let avg_replicas = if total_content > 0 {
            total_replicas as f64 / total_content as f64
        } else {
            0.0
        };

        let under_replicated = self
            .content_metadata
            .values()
            .filter(|m| m.current_replicas < m.target_replicas)
            .count();
        let over_replicated = self
            .content_metadata
            .values()
            .filter(|m| m.current_replicas > m.target_replicas)
            .count();

        let total_storage: u64 = self.peer_capacities.values().map(|p| p.total_storage).sum();
        let used_storage: u64 = self.peer_capacities.values().map(|p| p.used_storage).sum();

        ReplicationStats {
            total_content,
            total_replicas,
            avg_replicas,
            under_replicated,
            over_replicated,
            total_storage,
            used_storage,
            peer_count: self.peer_capacities.len(),
        }
    }

    /// Get best peers for hosting new replicas
    pub fn get_best_peers(&self, content_size: u64, count: usize) -> Vec<PeerId> {
        let mut candidates: Vec<_> = self
            .peer_capacities
            .values()
            .filter(|p| p.available_storage() >= content_size)
            .collect();

        // Sort by capacity score (highest first)
        candidates.sort_by(|a, b| b.capacity_score().partial_cmp(&a.capacity_score()).unwrap());

        candidates
            .iter()
            .take(count)
            .map(|p| p.peer_id.clone())
            .collect()
    }

    /// Get worst peers for removing replicas
    pub fn get_worst_peers(&self, content_id: &ContentId, count: usize) -> Vec<PeerId> {
        if let Some(locations) = self.content_locations.get(content_id) {
            let mut peer_scores: Vec<_> = locations
                .iter()
                .filter_map(|peer_id| {
                    self.peer_capacities
                        .get(peer_id)
                        .map(|capacity| (peer_id.clone(), capacity.capacity_score()))
                })
                .collect();

            // Sort by score (lowest first)
            peer_scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            return peer_scores
                .iter()
                .take(count)
                .map(|(peer_id, _)| peer_id.clone())
                .collect();
        }

        Vec::new()
    }
}

/// Replication statistics
#[derive(Debug, Clone)]
pub struct ReplicationStats {
    pub total_content: usize,
    pub total_replicas: usize,
    pub avg_replicas: f64,
    pub under_replicated: usize,
    pub over_replicated: usize,
    pub total_storage: u64,
    pub used_storage: u64,
    pub peer_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_capacity(
        id: &str,
        total: u64,
        used: u64,
        stability: f64,
        reliability: f64,
    ) -> PeerCapacity {
        PeerCapacity {
            peer_id: id.to_string(),
            total_storage: total,
            used_storage: used,
            stability_score: stability,
            bandwidth: 5_000_000, // 5MB/s
            reliability,
        }
    }

    #[test]
    fn test_replication_strategy_target_replicas() {
        assert_eq!(ReplicationStrategy::Minimal.target_replicas(), (1, 2));
        assert_eq!(ReplicationStrategy::Low.target_replicas(), (3, 5));
        assert_eq!(ReplicationStrategy::Medium.target_replicas(), (6, 10));
        assert_eq!(ReplicationStrategy::High.target_replicas(), (11, 20));
        assert_eq!(ReplicationStrategy::Maximum.target_replicas(), (21, 50));
        assert_eq!(ReplicationStrategy::Adaptive.target_replicas(), (3, 10));
    }

    #[test]
    fn test_peer_capacity_available_storage() {
        let capacity = create_test_capacity("peer1", 1000, 400, 0.8, 0.9);
        assert_eq!(capacity.available_storage(), 600);
    }

    #[test]
    fn test_peer_capacity_utilization() {
        let capacity = create_test_capacity("peer1", 1000, 400, 0.8, 0.9);
        assert!((capacity.utilization() - 0.4).abs() < 0.01);
    }

    #[test]
    fn test_peer_capacity_score() {
        let capacity = create_test_capacity("peer1", 1000, 200, 0.8, 0.9);
        let score = capacity.capacity_score();
        assert!((0.0..=1.0).contains(&score));
        assert!(score > 0.7); // Should be high with low utilization and high stability
    }

    #[test]
    fn test_new_manager() {
        let config = ReplicationConfig::default();
        let manager = AdaptiveReplicationManager::new(config);
        assert_eq!(manager.content_metadata.len(), 0);
        assert_eq!(manager.peer_capacities.len(), 0);
    }

    #[test]
    fn test_register_content() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );
        assert_eq!(manager.content_metadata.len(), 1);

        let metadata = manager.content_metadata.get("content1").unwrap();
        assert_eq!(metadata.content_id, "content1");
        assert_eq!(metadata.size_bytes, 1_000_000);
        assert_eq!(metadata.strategy, ReplicationStrategy::Medium);
    }

    #[test]
    fn test_update_content_metadata() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );
        manager.update_content_metadata(&"content1".to_string(), 0.8, 0.9);

        let metadata = manager.content_metadata.get("content1").unwrap();
        assert!((metadata.popularity_score - 0.8).abs() < 0.01);
        assert!((metadata.availability_score - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_update_peer_capacity() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        let capacity = create_test_capacity("peer1", 1000, 400, 0.8, 0.9);
        manager.update_peer_capacity(capacity);

        assert_eq!(manager.peer_capacities.len(), 1);
        assert!(manager.peer_capacities.contains_key("peer1"));
    }

    #[test]
    fn test_record_replica() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );
        manager.record_replica(&"content1".to_string(), "peer1".to_string());
        manager.record_replica(&"content1".to_string(), "peer2".to_string());

        let metadata = manager.content_metadata.get("content1").unwrap();
        assert_eq!(metadata.current_replicas, 2);

        let locations = manager.content_locations.get("content1").unwrap();
        assert_eq!(locations.len(), 2);
        assert!(locations.contains(&"peer1".to_string()));
        assert!(locations.contains(&"peer2".to_string()));
    }

    #[test]
    fn test_remove_replica() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );
        manager.record_replica(&"content1".to_string(), "peer1".to_string());
        manager.record_replica(&"content1".to_string(), "peer2".to_string());
        manager.remove_replica(&"content1".to_string(), &"peer1".to_string());

        let metadata = manager.content_metadata.get("content1").unwrap();
        assert_eq!(metadata.current_replicas, 1);

        let locations = manager.content_locations.get("content1").unwrap();
        assert_eq!(locations.len(), 1);
        assert!(!locations.contains(&"peer1".to_string()));
        assert!(locations.contains(&"peer2".to_string()));
    }

    #[test]
    fn test_should_evaluate() {
        let config = ReplicationConfig {
            evaluation_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let manager = AdaptiveReplicationManager::new(config);

        // Initially should not evaluate (just created)
        assert!(!manager.should_evaluate());
    }

    #[test]
    fn test_evaluate_replication_increase() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content("content1".to_string(), 1_000_000, ReplicationStrategy::High);
        manager.update_content_metadata(&"content1".to_string(), 0.9, 0.9);

        // Force evaluation by setting last_evaluation to past
        manager.last_evaluation = Instant::now() - Duration::from_secs(400);

        let actions = manager.evaluate_replication();
        assert!(!actions.is_empty());

        // Should recommend increasing replicas
        let has_increase = actions
            .iter()
            .any(|a| matches!(a, ReplicationAction::Increase { .. }));
        assert!(has_increase);
    }

    #[test]
    fn test_evaluate_replication_decrease() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Minimal,
        );
        manager.update_content_metadata(&"content1".to_string(), 0.1, 0.9);

        // Add many replicas
        for i in 0..10 {
            manager.record_replica(&"content1".to_string(), format!("peer{}", i));
        }

        // Force evaluation
        manager.last_evaluation = Instant::now() - Duration::from_secs(400);

        let actions = manager.evaluate_replication();

        // Should recommend decreasing replicas
        let has_decrease = actions
            .iter()
            .any(|a| matches!(a, ReplicationAction::Decrease { .. }));
        assert!(has_decrease);
    }

    #[test]
    fn test_get_best_peers() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        // Add peers with different capacities
        manager.update_peer_capacity(create_test_capacity("peer1", 1000, 100, 0.9, 0.9)); // Good
        manager.update_peer_capacity(create_test_capacity("peer2", 1000, 800, 0.5, 0.6)); // Mediocre
        manager.update_peer_capacity(create_test_capacity("peer3", 1000, 200, 0.8, 0.85)); // Good

        let best = manager.get_best_peers(50, 2);
        assert_eq!(best.len(), 2);
        // peer1 should be first (higher capacity score)
        assert!(best.contains(&"peer1".to_string()));
    }

    #[test]
    fn test_get_worst_peers() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );

        // Add peers and record replicas
        manager.update_peer_capacity(create_test_capacity("peer1", 1000, 100, 0.9, 0.9)); // Good
        manager.update_peer_capacity(create_test_capacity("peer2", 1000, 900, 0.3, 0.4)); // Bad
        manager.update_peer_capacity(create_test_capacity("peer3", 1000, 200, 0.8, 0.85)); // Good

        manager.record_replica(&"content1".to_string(), "peer1".to_string());
        manager.record_replica(&"content1".to_string(), "peer2".to_string());
        manager.record_replica(&"content1".to_string(), "peer3".to_string());

        let worst = manager.get_worst_peers(&"content1".to_string(), 1);
        assert_eq!(worst.len(), 1);
        // peer2 should be worst (lowest capacity score)
        assert_eq!(worst[0], "peer2");
    }

    #[test]
    fn test_stats() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Medium,
        );
        manager.register_content("content2".to_string(), 2_000_000, ReplicationStrategy::High);

        manager.record_replica(&"content1".to_string(), "peer1".to_string());
        manager.record_replica(&"content2".to_string(), "peer2".to_string());
        manager.record_replica(&"content2".to_string(), "peer3".to_string());

        manager.update_peer_capacity(create_test_capacity("peer1", 1000, 400, 0.8, 0.9));
        manager.update_peer_capacity(create_test_capacity("peer2", 2000, 800, 0.7, 0.8));

        let stats = manager.stats();
        assert_eq!(stats.total_content, 2);
        assert_eq!(stats.total_replicas, 3);
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.total_storage, 3000);
        assert_eq!(stats.used_storage, 1200);
    }

    #[test]
    fn test_adaptive_strategy() {
        let config = ReplicationConfig::default();
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content(
            "content1".to_string(),
            1_000_000,
            ReplicationStrategy::Adaptive,
        );

        // High popularity, high availability -> moderate replicas
        manager.update_content_metadata(&"content1".to_string(), 0.9, 0.9);
        manager.last_evaluation = Instant::now() - Duration::from_secs(400);

        let _actions = manager.evaluate_replication();

        // Verify target replicas are in adaptive range
        let metadata = manager.content_metadata.get("content1").unwrap();
        assert!(metadata.target_replicas >= 3);
        assert!(metadata.target_replicas <= 15);
    }

    #[test]
    fn test_storage_pressure_handling() {
        let config = ReplicationConfig {
            storage_pressure_threshold: 0.8,
            ..Default::default()
        };
        let mut manager = AdaptiveReplicationManager::new(config);

        manager.register_content("content1".to_string(), 100, ReplicationStrategy::Medium);
        manager.update_content_metadata(&"content1".to_string(), 0.2, 0.9); // Low popularity

        // Add peer with high storage pressure
        manager.update_peer_capacity(create_test_capacity("peer1", 1000, 900, 0.8, 0.9));

        // Over-replicate the content
        for i in 0..15 {
            manager.record_replica(&"content1".to_string(), format!("peer{}", i));
        }

        manager.last_evaluation = Instant::now() - Duration::from_secs(400);
        let actions = manager.evaluate_replication();

        // Should recommend decreasing due to storage pressure
        let has_decrease = actions.iter().any(|a| {
            matches!(a, ReplicationAction::Decrease { reason, .. } if reason.contains("Storage pressure"))
        });
        assert!(has_decrease);
    }
}
