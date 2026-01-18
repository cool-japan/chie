//! Peer reputation decay system for time-based reputation management.
//!
//! This module provides automatic reputation decay over time, activity-based scoring,
//! and reputation recovery mechanisms to ensure fair and dynamic peer assessment.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::reputation_decay::{ReputationDecayManager, DecayConfig};
//! use libp2p::PeerId;
//!
//! let config = DecayConfig::default();
//! let manager = ReputationDecayManager::new(config);
//!
//! // Set initial reputation
//! manager.set_reputation(PeerId::random(), 100.0);
//!
//! // Reputation decays over time if peer is inactive
//! // manager.update(); // Call periodically
//! ```

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Errors that can occur during reputation management.
#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Invalid reputation value.
    #[error("Invalid reputation value: {0}")]
    InvalidValue(f64),
}

/// Configuration for reputation decay.
#[derive(Debug, Clone)]
pub struct DecayConfig {
    /// Decay rate per hour (fraction of reputation lost).
    pub decay_rate_per_hour: f64,
    /// Minimum reputation (floor).
    pub min_reputation: f64,
    /// Maximum reputation (ceiling).
    pub max_reputation: f64,
    /// Activity bonus multiplier.
    pub activity_bonus: f64,
    /// Inactivity period before decay starts.
    pub inactivity_threshold: Duration,
    /// Update interval for decay calculation.
    pub update_interval: Duration,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            decay_rate_per_hour: 0.1, // 10% per hour
            min_reputation: 0.0,
            max_reputation: 100.0,
            activity_bonus: 1.5,
            inactivity_threshold: Duration::from_secs(3600), // 1 hour
            update_interval: Duration::from_secs(300),       // 5 minutes
        }
    }
}

/// Peer reputation record.
#[derive(Debug, Clone)]
pub struct ReputationRecord {
    /// Current reputation score.
    pub reputation: f64,
    /// Last activity time.
    pub last_active: Instant,
    /// Last decay update time.
    pub last_decay: Instant,
    /// Total activity count.
    pub activity_count: u64,
    /// Successful transfers.
    pub successful_transfers: u64,
    /// Failed transfers.
    pub failed_transfers: u64,
}

impl ReputationRecord {
    /// Create a new reputation record.
    pub fn new(initial_reputation: f64) -> Self {
        let now = Instant::now();
        Self {
            reputation: initial_reputation,
            last_active: now,
            last_decay: now,
            activity_count: 0,
            successful_transfers: 0,
            failed_transfers: 0,
        }
    }

    /// Get success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_transfers + self.failed_transfers;
        if total == 0 {
            return 1.0;
        }
        self.successful_transfers as f64 / total as f64
    }

    /// Check if peer is inactive.
    pub fn is_inactive(&self, threshold: Duration) -> bool {
        self.last_active.elapsed() > threshold
    }

    /// Record activity.
    pub fn record_activity(&mut self, success: bool) {
        self.last_active = Instant::now();
        self.activity_count += 1;
        if success {
            self.successful_transfers += 1;
        } else {
            self.failed_transfers += 1;
        }
    }
}

/// Statistics for reputation decay manager.
#[derive(Debug, Default, Clone)]
pub struct DecayStats {
    /// Total peers tracked.
    pub total_peers: usize,
    /// Active peers (recently active).
    pub active_peers: usize,
    /// Inactive peers.
    pub inactive_peers: usize,
    /// Average reputation.
    pub avg_reputation: f64,
    /// Total decay operations.
    pub total_decays: u64,
}

/// Reputation decay manager.
pub struct ReputationDecayManager {
    config: DecayConfig,
    /// Peer reputation records.
    records: Arc<parking_lot::RwLock<HashMap<PeerId, ReputationRecord>>>,
    /// Last global update time.
    last_update: Arc<parking_lot::RwLock<Instant>>,
    /// Statistics.
    stats: Arc<parking_lot::RwLock<DecayStats>>,
}

impl ReputationDecayManager {
    /// Create a new reputation decay manager with default configuration.
    pub fn new(config: DecayConfig) -> Self {
        Self {
            config,
            records: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            last_update: Arc::new(parking_lot::RwLock::new(Instant::now())),
            stats: Arc::new(parking_lot::RwLock::new(DecayStats::default())),
        }
    }

    /// Set reputation for a peer.
    pub fn set_reputation(&self, peer_id: PeerId, reputation: f64) -> Result<(), ReputationError> {
        if reputation < self.config.min_reputation || reputation > self.config.max_reputation {
            return Err(ReputationError::InvalidValue(reputation));
        }

        let record = ReputationRecord::new(reputation);
        self.records.write().insert(peer_id, record);
        self.update_stats();

        Ok(())
    }

    /// Get reputation for a peer.
    pub fn get_reputation(&self, peer_id: &PeerId) -> Option<f64> {
        self.records.read().get(peer_id).map(|r| r.reputation)
    }

    /// Record activity for a peer.
    pub fn record_activity(&self, peer_id: PeerId, success: bool) -> Result<(), ReputationError> {
        let mut records = self.records.write();

        if let Some(record) = records.get_mut(&peer_id) {
            record.record_activity(success);

            // Apply activity bonus
            if success {
                record.reputation = (record.reputation + self.config.activity_bonus)
                    .min(self.config.max_reputation);
            } else {
                record.reputation = (record.reputation - self.config.activity_bonus)
                    .max(self.config.min_reputation);
            }

            Ok(())
        } else {
            Err(ReputationError::PeerNotFound(peer_id.to_string()))
        }
    }

    /// Update all peer reputations (apply decay).
    pub fn update(&self) {
        let now = Instant::now();
        let mut last_update = self.last_update.write();

        if now.duration_since(*last_update) < self.config.update_interval {
            return; // Too soon
        }

        let elapsed_hours = now.duration_since(*last_update).as_secs_f64() / 3600.0;
        let decay_factor = 1.0 - (self.config.decay_rate_per_hour * elapsed_hours);

        let mut records = self.records.write();
        let mut total_decays = 0u64;

        for record in records.values_mut() {
            if record.is_inactive(self.config.inactivity_threshold) {
                // Apply decay
                let old_rep = record.reputation;
                record.reputation =
                    (record.reputation * decay_factor).max(self.config.min_reputation);

                if old_rep != record.reputation {
                    total_decays += 1;
                }

                record.last_decay = now;
            }
        }

        *last_update = now;

        // Update stats
        let mut stats = self.stats.write();
        stats.total_decays += total_decays;

        drop(records);
        drop(stats);
        self.update_stats();
    }

    /// Update statistics.
    fn update_stats(&self) {
        let records = self.records.read();
        let mut stats = self.stats.write();

        stats.total_peers = records.len();
        stats.active_peers = records
            .values()
            .filter(|r| !r.is_inactive(self.config.inactivity_threshold))
            .count();
        stats.inactive_peers = stats.total_peers - stats.active_peers;

        if !records.is_empty() {
            stats.avg_reputation =
                records.values().map(|r| r.reputation).sum::<f64>() / records.len() as f64;
        } else {
            stats.avg_reputation = 0.0;
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> DecayStats {
        self.stats.read().clone()
    }

    /// Get configuration.
    pub fn config(&self) -> &DecayConfig {
        &self.config
    }

    /// Get all peers with reputation above threshold.
    pub fn get_peers_above(&self, threshold: f64) -> Vec<(PeerId, f64)> {
        self.records
            .read()
            .iter()
            .filter(|(_, r)| r.reputation >= threshold)
            .map(|(p, r)| (*p, r.reputation))
            .collect()
    }

    /// Get top N peers by reputation.
    pub fn get_top_peers(&self, n: usize) -> Vec<(PeerId, f64)> {
        let mut peers: Vec<(PeerId, f64)> = self
            .records
            .read()
            .iter()
            .map(|(p, r)| (*p, r.reputation))
            .collect();

        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        peers.truncate(n);
        peers
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.records.write().remove(peer_id);
        self.update_stats();
    }

    /// Clear all reputation records.
    pub fn clear(&self) {
        self.records.write().clear();
        self.update_stats();
    }
}

impl Clone for ReputationDecayManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            records: Arc::clone(&self.records),
            last_update: Arc::clone(&self.last_update),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_decay_config_default() {
        let config = DecayConfig::default();
        assert_eq!(config.decay_rate_per_hour, 0.1);
        assert_eq!(config.min_reputation, 0.0);
        assert_eq!(config.max_reputation, 100.0);
    }

    #[test]
    fn test_reputation_record_new() {
        let record = ReputationRecord::new(50.0);
        assert_eq!(record.reputation, 50.0);
        assert_eq!(record.activity_count, 0);
    }

    #[test]
    fn test_reputation_record_success_rate() {
        let mut record = ReputationRecord::new(50.0);
        record.successful_transfers = 7;
        record.failed_transfers = 3;
        assert_eq!(record.success_rate(), 0.7);
    }

    #[test]
    fn test_reputation_record_is_inactive() {
        let record = ReputationRecord::new(50.0);
        let threshold = Duration::from_millis(100);

        assert!(!record.is_inactive(threshold));

        thread::sleep(Duration::from_millis(150));
        assert!(record.is_inactive(threshold));
    }

    #[test]
    fn test_manager_new() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let stats = manager.stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_set_get_reputation() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 75.0).unwrap();
        assert_eq!(manager.get_reputation(&peer_id), Some(75.0));
    }

    #[test]
    fn test_set_reputation_invalid() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        // Too high
        assert!(manager.set_reputation(peer_id, 150.0).is_err());

        // Too low
        assert!(manager.set_reputation(peer_id, -10.0).is_err());
    }

    #[test]
    fn test_record_activity_success() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 50.0).unwrap();
        manager.record_activity(peer_id, true).unwrap();

        // Reputation should increase
        let rep = manager.get_reputation(&peer_id).unwrap();
        assert!(rep > 50.0);
    }

    #[test]
    fn test_record_activity_failure() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 50.0).unwrap();
        manager.record_activity(peer_id, false).unwrap();

        // Reputation should decrease
        let rep = manager.get_reputation(&peer_id).unwrap();
        assert!(rep < 50.0);
    }

    #[test]
    fn test_reputation_capped_at_max() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 99.0).unwrap();
        manager.record_activity(peer_id, true).unwrap();

        // Should be capped at max (100.0)
        let rep = manager.get_reputation(&peer_id).unwrap();
        assert_eq!(rep, 100.0);
    }

    #[test]
    fn test_reputation_capped_at_min() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 1.0).unwrap();
        manager.record_activity(peer_id, false).unwrap();

        // Should be capped at min (0.0)
        let rep = manager.get_reputation(&peer_id).unwrap();
        assert_eq!(rep, 0.0);
    }

    #[test]
    fn test_get_peers_above() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        manager.set_reputation(peer1, 80.0).unwrap();
        manager.set_reputation(peer2, 60.0).unwrap();
        manager.set_reputation(peer3, 40.0).unwrap();

        let peers = manager.get_peers_above(50.0);
        assert_eq!(peers.len(), 2); // peer1 and peer2
    }

    #[test]
    fn test_get_top_peers() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        manager.set_reputation(peer1, 80.0).unwrap();
        manager.set_reputation(peer2, 90.0).unwrap();
        manager.set_reputation(peer3, 70.0).unwrap();

        let top = manager.get_top_peers(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].1, 90.0); // peer2
        assert_eq!(top[1].1, 80.0); // peer1
    }

    #[test]
    fn test_remove_peer() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager.set_reputation(peer_id, 50.0).unwrap();
        assert!(manager.get_reputation(&peer_id).is_some());

        manager.remove_peer(&peer_id);
        assert!(manager.get_reputation(&peer_id).is_none());
    }

    #[test]
    fn test_clear() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);

        manager.set_reputation(PeerId::random(), 50.0).unwrap();
        manager.set_reputation(PeerId::random(), 60.0).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_peers, 2);

        manager.clear();
        let stats = manager.stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_stats_update() {
        let config = DecayConfig::default();
        let manager = ReputationDecayManager::new(config);

        manager.set_reputation(PeerId::random(), 50.0).unwrap();
        manager.set_reputation(PeerId::random(), 70.0).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.avg_reputation, 60.0);
    }

    #[test]
    fn test_clone() {
        let config = DecayConfig::default();
        let manager1 = ReputationDecayManager::new(config);
        let peer_id = PeerId::random();

        manager1.set_reputation(peer_id, 50.0).unwrap();

        let manager2 = manager1.clone();
        // Stats should be shared
        assert_eq!(manager1.stats().total_peers, manager2.stats().total_peers);
    }
}
