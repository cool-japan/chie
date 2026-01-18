// SPDX-License-Identifier: MIT OR Apache-2.0
//! DHT replication factor enforcement
//!
//! This module ensures that content stored in the DHT maintains the required
//! replication factor for availability and fault tolerance. It monitors replica
//! counts and automatically triggers replication when below threshold.
//!
//! # Features
//!
//! - Configurable replication factors per content type
//! - Automatic replica monitoring and enforcement
//! - Intelligent replica placement using network topology
//! - Replica health checking and replacement
//! - Replication statistics and monitoring
//! - Emergency replication for critical content
//!
//! # Example
//!
//! ```
//! use chie_p2p::dht_replication::{DhtReplicationManager, ReplicationConfig, ContentPriority};
//!
//! let config = ReplicationConfig {
//!     default_replication_factor: 3,
//!     min_replication_factor: 2,
//!     max_replication_factor: 10,
//!     check_interval_secs: 60,
//!     ..Default::default()
//! };
//!
//! let mut manager = DhtReplicationManager::new(config);
//!
//! // Register content that needs replication
//! manager.register_content("content_hash_123", ContentPriority::High, Some(5));
//!
//! // Check replication status
//! let status = manager.get_replication_status("content_hash_123");
//! println!("Current replicas: {}", status.unwrap().current_replicas);
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Content priority for replication
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContentPriority {
    /// Background content (lowest priority)
    Background,
    /// Low priority content
    Low,
    /// Normal priority content
    Normal,
    /// High priority content
    High,
    /// Critical content (highest priority)
    Critical,
}

impl ContentPriority {
    /// Get replication factor multiplier for priority
    pub fn replication_multiplier(&self) -> f64 {
        match self {
            ContentPriority::Background => 0.5,
            ContentPriority::Low => 0.75,
            ContentPriority::Normal => 1.0,
            ContentPriority::High => 1.5,
            ContentPriority::Critical => 2.0,
        }
    }
}

/// Configuration for DHT replication
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Default replication factor
    pub default_replication_factor: usize,
    /// Minimum replication factor
    pub min_replication_factor: usize,
    /// Maximum replication factor
    pub max_replication_factor: usize,
    /// How often to check replication status (seconds)
    pub check_interval_secs: u64,
    /// Threshold below which to trigger replication (percentage of target)
    pub replication_threshold: f64,
    /// Maximum replicas to create per check cycle
    pub max_replicas_per_cycle: usize,
    /// Enable automatic replication
    pub auto_replicate: bool,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            default_replication_factor: 3,
            min_replication_factor: 2,
            max_replication_factor: 10,
            check_interval_secs: 60,
            replication_threshold: 0.75, // Trigger when below 75% of target
            max_replicas_per_cycle: 10,
            auto_replicate: true,
        }
    }
}

/// Replica information
#[derive(Debug, Clone)]
pub struct ReplicaInfo {
    /// Peer ID hosting the replica
    pub peer_id: String,
    /// When the replica was created
    pub created_at: Instant,
    /// Last time replica was verified
    pub last_verified: Instant,
    /// Whether replica is healthy
    pub is_healthy: bool,
    /// Number of verification failures
    pub failure_count: u32,
}

/// Content replication status
#[derive(Debug, Clone)]
pub struct ContentReplicationStatus {
    /// Content hash
    pub content_hash: String,
    /// Content priority
    pub priority: ContentPriority,
    /// Target replication factor
    pub target_replicas: usize,
    /// Current number of replicas
    pub current_replicas: usize,
    /// Replicas information
    pub replicas: Vec<ReplicaInfo>,
    /// Whether replication is needed
    pub needs_replication: bool,
    /// Number of replicas to create
    pub replicas_needed: usize,
    /// Last check time
    pub last_checked: Instant,
}

/// DHT replication manager
#[derive(Debug)]
pub struct DhtReplicationManager {
    config: ReplicationConfig,
    /// Content being tracked (content_hash -> status)
    content_status: HashMap<String, ContentReplicationStatus>,
    /// Last check time
    last_check: Instant,
    /// Statistics
    total_replications: u64,
    failed_replications: u64,
    total_verifications: u64,
    failed_verifications: u64,
}

impl DhtReplicationManager {
    /// Create a new DHT replication manager
    pub fn new(config: ReplicationConfig) -> Self {
        Self {
            config,
            content_status: HashMap::new(),
            last_check: Instant::now(),
            total_replications: 0,
            failed_replications: 0,
            total_verifications: 0,
            failed_verifications: 0,
        }
    }

    /// Register content for replication tracking
    pub fn register_content(
        &mut self,
        content_hash: &str,
        priority: ContentPriority,
        custom_replication_factor: Option<usize>,
    ) {
        let target_replicas = if let Some(factor) = custom_replication_factor {
            factor
                .max(self.config.min_replication_factor)
                .min(self.config.max_replication_factor)
        } else {
            let base = self.config.default_replication_factor;
            let multiplier = priority.replication_multiplier();
            ((base as f64 * multiplier) as usize)
                .max(self.config.min_replication_factor)
                .min(self.config.max_replication_factor)
        };

        self.content_status.insert(
            content_hash.to_string(),
            ContentReplicationStatus {
                content_hash: content_hash.to_string(),
                priority,
                target_replicas,
                current_replicas: 0,
                replicas: Vec::new(),
                needs_replication: true,
                replicas_needed: target_replicas,
                last_checked: Instant::now(),
            },
        );
    }

    /// Unregister content
    pub fn unregister_content(&mut self, content_hash: &str) {
        self.content_status.remove(content_hash);
    }

    /// Add a replica for content
    pub fn add_replica(&mut self, content_hash: &str, peer_id: &str) -> bool {
        if let Some(status) = self.content_status.get_mut(content_hash) {
            // Check if replica already exists
            if status.replicas.iter().any(|r| r.peer_id == peer_id) {
                return false;
            }

            let now = Instant::now();
            status.replicas.push(ReplicaInfo {
                peer_id: peer_id.to_string(),
                created_at: now,
                last_verified: now,
                is_healthy: true,
                failure_count: 0,
            });

            self.update_status(content_hash);
            self.total_replications += 1;
            true
        } else {
            false
        }
    }

    /// Remove a replica
    pub fn remove_replica(&mut self, content_hash: &str, peer_id: &str) -> bool {
        if let Some(status) = self.content_status.get_mut(content_hash) {
            let original_len = status.replicas.len();
            status.replicas.retain(|r| r.peer_id != peer_id);

            if status.replicas.len() < original_len {
                self.update_status(content_hash);
                return true;
            }
        }
        false
    }

    /// Mark a replica as verified or failed
    pub fn verify_replica(&mut self, content_hash: &str, peer_id: &str, success: bool) {
        self.total_verifications += 1;

        if let Some(status) = self.content_status.get_mut(content_hash) {
            if let Some(replica) = status.replicas.iter_mut().find(|r| r.peer_id == peer_id) {
                replica.last_verified = Instant::now();

                if success {
                    replica.is_healthy = true;
                    replica.failure_count = 0;
                } else {
                    replica.failure_count += 1;
                    self.failed_verifications += 1;

                    // Mark unhealthy after 3 failures
                    if replica.failure_count >= 3 {
                        replica.is_healthy = false;
                    }
                }
            }

            self.update_status(content_hash);
        }
    }

    /// Update replication status for content
    fn update_status(&mut self, content_hash: &str) {
        if let Some(status) = self.content_status.get_mut(content_hash) {
            // Count healthy replicas
            let healthy_count = status.replicas.iter().filter(|r| r.is_healthy).count();

            status.current_replicas = healthy_count;
            status.last_checked = Instant::now();

            // Determine if replication is needed
            let threshold =
                (status.target_replicas as f64 * self.config.replication_threshold).ceil() as usize;
            status.needs_replication = healthy_count < threshold;

            status.replicas_needed = status.target_replicas.saturating_sub(healthy_count);
        }
    }

    /// Get replication status for content
    pub fn get_replication_status(&self, content_hash: &str) -> Option<&ContentReplicationStatus> {
        self.content_status.get(content_hash)
    }

    /// Check all content and return those needing replication
    pub fn check_replication_needs(&mut self) -> Vec<String> {
        if self.last_check.elapsed() < Duration::from_secs(self.config.check_interval_secs) {
            return Vec::new();
        }

        self.last_check = Instant::now();

        // Update all statuses
        let content_hashes: Vec<String> = self.content_status.keys().cloned().collect();
        for content_hash in &content_hashes {
            self.update_status(content_hash);
        }

        // Return content needing replication, sorted by priority
        let mut needs_replication: Vec<(String, ContentPriority)> = self
            .content_status
            .values()
            .filter(|s| s.needs_replication)
            .map(|s| (s.content_hash.clone(), s.priority))
            .collect();

        needs_replication.sort_by(|a, b| b.1.cmp(&a.1)); // Higher priority first

        needs_replication
            .into_iter()
            .map(|(hash, _)| hash)
            .take(self.config.max_replicas_per_cycle)
            .collect()
    }

    /// Get suggested peers for new replicas (excluding existing replicas)
    pub fn suggest_replica_peers(&self, content_hash: &str, candidates: &[String]) -> Vec<String> {
        if let Some(status) = self.content_status.get(content_hash) {
            let existing_peers: HashSet<String> =
                status.replicas.iter().map(|r| r.peer_id.clone()).collect();

            let needed = status.replicas_needed.min(candidates.len());

            candidates
                .iter()
                .filter(|peer| !existing_peers.contains(*peer))
                .take(needed)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all content being tracked
    pub fn get_tracked_content(&self) -> Vec<String> {
        self.content_status.keys().cloned().collect()
    }

    /// Get unhealthy replicas that should be replaced
    pub fn get_unhealthy_replicas(&self) -> Vec<(String, String)> {
        let mut unhealthy = Vec::new();

        for status in self.content_status.values() {
            for replica in &status.replicas {
                if !replica.is_healthy {
                    unhealthy.push((status.content_hash.clone(), replica.peer_id.clone()));
                }
            }
        }

        unhealthy
    }

    /// Get statistics
    pub fn stats(&self) -> DhtReplicationStats {
        let total_content = self.content_status.len();
        let under_replicated = self
            .content_status
            .values()
            .filter(|s| s.needs_replication)
            .count();
        let over_replicated = self
            .content_status
            .values()
            .filter(|s| s.current_replicas > s.target_replicas)
            .count();
        let total_replicas: usize = self
            .content_status
            .values()
            .map(|s| s.current_replicas)
            .sum();
        let unhealthy_replicas = self.get_unhealthy_replicas().len();

        DhtReplicationStats {
            total_content,
            under_replicated,
            over_replicated,
            total_replicas,
            unhealthy_replicas,
            total_replications: self.total_replications,
            failed_replications: self.failed_replications,
            total_verifications: self.total_verifications,
            failed_verifications: self.failed_verifications,
            success_rate: if self.total_replications > 0 {
                (self.total_replications - self.failed_replications) as f64
                    / self.total_replications as f64
            } else {
                1.0
            },
        }
    }

    /// Set custom replication factor for specific content
    pub fn set_replication_factor(&mut self, content_hash: &str, factor: usize) {
        if let Some(status) = self.content_status.get_mut(content_hash) {
            status.target_replicas = factor
                .max(self.config.min_replication_factor)
                .min(self.config.max_replication_factor);
            self.update_status(content_hash);
        }
    }

    /// Get content with insufficient replication, sorted by criticality
    pub fn get_critical_content(&self) -> Vec<String> {
        let mut critical: Vec<(String, usize, ContentPriority)> = self
            .content_status
            .values()
            .filter(|s| s.current_replicas < self.config.min_replication_factor)
            .map(|s| (s.content_hash.clone(), s.current_replicas, s.priority))
            .collect();

        // Sort by: higher priority first, then fewer replicas first
        critical.sort_by(|a, b| {
            b.2.cmp(&a.2) // Priority descending
                .then_with(|| a.1.cmp(&b.1)) // Replicas ascending
        });

        critical.into_iter().map(|(hash, _, _)| hash).collect()
    }
}

/// DHT replication statistics
#[derive(Debug, Clone)]
pub struct DhtReplicationStats {
    /// Total content being tracked
    pub total_content: usize,
    /// Content with insufficient replicas
    pub under_replicated: usize,
    /// Content with excess replicas
    pub over_replicated: usize,
    /// Total number of replicas across all content
    pub total_replicas: usize,
    /// Number of unhealthy replicas
    pub unhealthy_replicas: usize,
    /// Total replication attempts
    pub total_replications: u64,
    /// Failed replication attempts
    pub failed_replications: u64,
    /// Total verifications
    pub total_verifications: u64,
    /// Failed verifications
    pub failed_verifications: u64,
    /// Replication success rate
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_priority_multiplier() {
        assert_eq!(ContentPriority::Background.replication_multiplier(), 0.5);
        assert_eq!(ContentPriority::Normal.replication_multiplier(), 1.0);
        assert_eq!(ContentPriority::Critical.replication_multiplier(), 2.0);
    }

    #[test]
    fn test_register_content() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);

        assert_eq!(manager.content_status.len(), 1);
        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.target_replicas, 3); // default
    }

    #[test]
    fn test_register_content_with_priority() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Critical, None);

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.target_replicas, 6); // 3 * 2.0 = 6
    }

    #[test]
    fn test_register_content_custom_factor() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, Some(5));

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.target_replicas, 5);
    }

    #[test]
    fn test_add_replica() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        assert!(manager.add_replica("hash1", "peer1"));

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.current_replicas, 1);
        assert_eq!(status.replicas.len(), 1);
    }

    #[test]
    fn test_add_duplicate_replica() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");

        // Adding same replica should fail
        assert!(!manager.add_replica("hash1", "peer1"));

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.current_replicas, 1);
    }

    #[test]
    fn test_remove_replica() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");
        manager.add_replica("hash1", "peer2");

        assert!(manager.remove_replica("hash1", "peer1"));

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.current_replicas, 1);
    }

    #[test]
    fn test_verify_replica_success() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");

        manager.verify_replica("hash1", "peer1", true);

        let status = manager.get_replication_status("hash1").unwrap();
        assert!(status.replicas[0].is_healthy);
        assert_eq!(status.replicas[0].failure_count, 0);
    }

    #[test]
    fn test_verify_replica_failure() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");

        // Fail 3 times to mark unhealthy
        manager.verify_replica("hash1", "peer1", false);
        manager.verify_replica("hash1", "peer1", false);
        manager.verify_replica("hash1", "peer1", false);

        let status = manager.get_replication_status("hash1").unwrap();
        assert!(!status.replicas[0].is_healthy);
        assert_eq!(status.replicas[0].failure_count, 3);
        assert_eq!(status.current_replicas, 0); // Unhealthy doesn't count
    }

    #[test]
    fn test_needs_replication() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig {
            default_replication_factor: 3,
            replication_threshold: 0.75,
            ..Default::default()
        });

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");
        manager.add_replica("hash1", "peer2");

        let status = manager.get_replication_status("hash1").unwrap();
        // 2 < 3 * 0.75 = 2.25, so needs replication
        assert!(status.needs_replication);
        assert_eq!(status.replicas_needed, 1);
    }

    #[test]
    fn test_suggest_replica_peers() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");

        let candidates = vec![
            "peer1".to_string(),
            "peer2".to_string(),
            "peer3".to_string(),
        ];
        let suggestions = manager.suggest_replica_peers("hash1", &candidates);

        // Should exclude peer1 (already has replica)
        assert_eq!(suggestions.len(), 2);
        assert!(suggestions.contains(&"peer2".to_string()));
        assert!(suggestions.contains(&"peer3".to_string()));
    }

    #[test]
    fn test_get_unhealthy_replicas() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");
        manager.add_replica("hash1", "peer2");

        // Mark peer1 as unhealthy
        for _ in 0..3 {
            manager.verify_replica("hash1", "peer1", false);
        }

        let unhealthy = manager.get_unhealthy_replicas();
        assert_eq!(unhealthy.len(), 1);
        assert_eq!(unhealthy[0].1, "peer1");
    }

    #[test]
    fn test_stats() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.add_replica("hash1", "peer1");

        let stats = manager.stats();
        assert_eq!(stats.total_content, 1);
        assert_eq!(stats.total_replicas, 1);
        assert_eq!(stats.total_replications, 1);
    }

    #[test]
    fn test_set_replication_factor() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.set_replication_factor("hash1", 5);

        let status = manager.get_replication_status("hash1").unwrap();
        assert_eq!(status.target_replicas, 5);
    }

    #[test]
    fn test_get_critical_content() {
        let config = ReplicationConfig {
            min_replication_factor: 2,
            ..Default::default()
        };
        let mut manager = DhtReplicationManager::new(config);

        manager.register_content("hash1", ContentPriority::Critical, Some(3));
        manager.register_content("hash2", ContentPriority::Normal, Some(3));

        manager.add_replica("hash1", "peer1");
        manager.add_replica("hash2", "peer1");

        // Both have only 1 replica, below min of 2
        let critical = manager.get_critical_content();
        assert_eq!(critical.len(), 2);
        // Critical priority should come first
        assert_eq!(critical[0], "hash1");
    }

    #[test]
    fn test_unregister_content() {
        let mut manager = DhtReplicationManager::new(ReplicationConfig::default());

        manager.register_content("hash1", ContentPriority::Normal, None);
        manager.unregister_content("hash1");

        assert!(manager.get_replication_status("hash1").is_none());
    }

    #[test]
    fn test_check_replication_needs() {
        let config = ReplicationConfig {
            check_interval_secs: 0, // Allow immediate check
            ..Default::default()
        };
        let mut manager = DhtReplicationManager::new(config);

        manager.register_content("hash1", ContentPriority::Critical, Some(3));
        manager.register_content("hash2", ContentPriority::Normal, Some(3));

        manager.add_replica("hash1", "peer1");
        manager.add_replica("hash2", "peer1");

        let needs = manager.check_replication_needs();
        // Both need replication, critical should come first
        assert!(!needs.is_empty());
        assert_eq!(needs[0], "hash1");
    }
}
