//! Connection prewarming and predictive management.
//!
//! This module provides advanced connection optimization capabilities including:
//! - Connection warming/pre-connection for anticipated peers
//! - Predictive connection management based on usage patterns
//! - Smart connection migration for better performance
//! - Multi-path support exploration

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Not connected
    Disconnected,
    /// Prewarming in progress
    Prewarming,
    /// Connected and ready
    Connected,
    /// Migrating to better path
    Migrating,
    /// Connection failed
    Failed,
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Peer ID
    pub peer_id: PeerId,
    /// Number of times connected
    pub connection_count: u64,
    /// Number of successful transfers
    pub successful_transfers: u64,
    /// Number of failed transfers
    pub failed_transfers: u64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Average bandwidth in bytes per second
    pub avg_bandwidth_bps: u64,
    /// Last connection time
    pub last_connection: Option<Instant>,
    /// Last successful transfer time
    pub last_transfer: Option<Instant>,
    /// Total bytes transferred
    pub total_bytes: u64,
}

impl ConnectionStats {
    /// Create new connection stats
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            connection_count: 0,
            successful_transfers: 0,
            failed_transfers: 0,
            avg_latency_ms: 0.0,
            avg_bandwidth_bps: 0,
            last_connection: None,
            last_transfer: None,
            total_bytes: 0,
        }
    }

    /// Record a connection
    pub fn record_connection(&mut self) {
        self.connection_count += 1;
        self.last_connection = Some(Instant::now());
    }

    /// Record a transfer
    pub fn record_transfer(
        &mut self,
        success: bool,
        latency_ms: f64,
        bandwidth_bps: u64,
        bytes: u64,
    ) {
        if success {
            self.successful_transfers += 1;
            self.last_transfer = Some(Instant::now());
            self.total_bytes += bytes;

            // Update averages with exponential moving average
            if self.avg_latency_ms == 0.0 {
                self.avg_latency_ms = latency_ms;
            } else {
                self.avg_latency_ms = 0.7 * self.avg_latency_ms + 0.3 * latency_ms;
            }

            if self.avg_bandwidth_bps == 0 {
                self.avg_bandwidth_bps = bandwidth_bps;
            } else {
                self.avg_bandwidth_bps =
                    (0.7 * self.avg_bandwidth_bps as f64 + 0.3 * bandwidth_bps as f64) as u64;
            }
        } else {
            self.failed_transfers += 1;
        }
    }

    /// Calculate connection score (0.0 to 1.0)
    pub fn score(&self) -> f64 {
        let total_transfers = self.successful_transfers + self.failed_transfers;
        if total_transfers == 0 {
            return 0.5;
        }

        let success_rate = self.successful_transfers as f64 / total_transfers as f64;
        let latency_score = if self.avg_latency_ms > 0.0 {
            (1000.0 / (self.avg_latency_ms + 100.0)).min(1.0)
        } else {
            0.5
        };
        let bandwidth_score = (self.avg_bandwidth_bps as f64 / 10_000_000.0).min(1.0);

        0.5 * success_rate + 0.3 * latency_score + 0.2 * bandwidth_score
    }
}

/// Predictive model for connection patterns
#[derive(Debug, Clone)]
pub struct ConnectionPattern {
    /// Peer ID
    pub peer_id: PeerId,
    /// Access times (circular buffer)
    pub access_times: VecDeque<Instant>,
    /// Predicted next access time
    pub predicted_next_access: Option<Instant>,
    /// Access frequency (accesses per hour)
    pub access_frequency: f64,
}

impl ConnectionPattern {
    /// Create new connection pattern
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            access_times: VecDeque::with_capacity(100),
            predicted_next_access: None,
            access_frequency: 0.0,
        }
    }

    /// Record an access
    pub fn record_access(&mut self) {
        let now = Instant::now();
        self.access_times.push_back(now);

        // Keep only last 100 accesses
        if self.access_times.len() > 100 {
            self.access_times.pop_front();
        }

        self.update_prediction();
    }

    /// Update prediction based on access pattern
    fn update_prediction(&mut self) {
        if self.access_times.len() < 2 {
            return;
        }

        // Calculate average interval between accesses
        let mut intervals = Vec::new();
        for i in 1..self.access_times.len() {
            let interval = self.access_times[i].duration_since(self.access_times[i - 1]);
            intervals.push(interval);
        }

        let avg_interval = intervals.iter().sum::<Duration>() / intervals.len() as u32;

        // Calculate access frequency (per hour)
        self.access_frequency = 3600.0 / avg_interval.as_secs_f64();

        // Predict next access
        if let Some(last_access) = self.access_times.back() {
            self.predicted_next_access = Some(*last_access + avg_interval);
        }
    }

    /// Check if prewarming should be triggered
    pub fn should_prewarm(&self) -> bool {
        if let Some(predicted) = self.predicted_next_access {
            let now = Instant::now();
            // Prewarm 30 seconds before predicted access
            if predicted > now {
                let time_until = predicted.duration_since(now);
                time_until < Duration::from_secs(30) && time_until > Duration::from_secs(0)
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Migration strategy for connection optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStrategy {
    /// Migrate to path with lower latency
    LowerLatency,
    /// Migrate to path with higher bandwidth
    HigherBandwidth,
    /// Migrate to more reliable path
    HigherReliability,
    /// Balanced migration considering all factors
    Balanced,
}

/// Path information for multi-path support
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Path identifier
    pub path_id: String,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Bandwidth in bytes per second
    pub bandwidth_bps: u64,
    /// Reliability score (0.0 to 1.0)
    pub reliability: f64,
    /// Last used time
    pub last_used: Option<Instant>,
    /// Number of successful transfers
    pub successful_transfers: u64,
    /// Number of failed transfers
    pub failed_transfers: u64,
}

impl PathInfo {
    /// Create new path info
    pub fn new(path_id: impl Into<String>) -> Self {
        Self {
            path_id: path_id.into(),
            latency_ms: 0.0,
            bandwidth_bps: 0,
            reliability: 1.0,
            last_used: None,
            successful_transfers: 0,
            failed_transfers: 0,
        }
    }

    /// Update path metrics
    pub fn update_metrics(&mut self, success: bool, latency_ms: f64, bandwidth_bps: u64) {
        if success {
            self.successful_transfers += 1;
        } else {
            self.failed_transfers += 1;
        }

        let total = self.successful_transfers + self.failed_transfers;
        self.reliability = self.successful_transfers as f64 / total as f64;

        // Update latency and bandwidth with exponential moving average
        if self.latency_ms == 0.0 {
            self.latency_ms = latency_ms;
        } else {
            self.latency_ms = 0.7 * self.latency_ms + 0.3 * latency_ms;
        }

        if self.bandwidth_bps == 0 {
            self.bandwidth_bps = bandwidth_bps;
        } else {
            self.bandwidth_bps =
                (0.7 * self.bandwidth_bps as f64 + 0.3 * bandwidth_bps as f64) as u64;
        }

        self.last_used = Some(Instant::now());
    }

    /// Calculate path score based on strategy
    pub fn score(&self, strategy: MigrationStrategy) -> f64 {
        match strategy {
            MigrationStrategy::LowerLatency => {
                // Higher score = better (lower latency)
                1000.0 / (self.latency_ms + 1.0)
            }
            MigrationStrategy::HigherBandwidth => {
                // Higher score = better (higher bandwidth)
                self.bandwidth_bps as f64 / 1_000_000.0
            }
            MigrationStrategy::HigherReliability => self.reliability,
            MigrationStrategy::Balanced => {
                let latency_score = (1000.0 / (self.latency_ms + 100.0)).min(1.0);
                let bandwidth_score = (self.bandwidth_bps as f64 / 10_000_000.0).min(1.0);
                0.4 * latency_score + 0.3 * bandwidth_score + 0.3 * self.reliability
            }
        }
    }
}

/// Connection prewarming manager
pub struct PrewarmingManager {
    /// Connection statistics by peer
    stats: Arc<Mutex<HashMap<PeerId, ConnectionStats>>>,
    /// Connection patterns by peer
    patterns: Arc<Mutex<HashMap<PeerId, ConnectionPattern>>>,
    /// Paths by peer (for multi-path support)
    paths: Arc<Mutex<HashMap<PeerId, Vec<PathInfo>>>>,
    /// Migration strategy
    migration_strategy: MigrationStrategy,
    /// Prewarming statistics
    prewarm_stats: Arc<Mutex<PrewarmingStats>>,
}

/// Prewarming statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrewarmingStats {
    /// Total prewarming attempts
    pub total_prewarms: u64,
    /// Successful prewarms
    pub successful_prewarms: u64,
    /// Failed prewarms
    pub failed_prewarms: u64,
    /// Total migrations
    pub total_migrations: u64,
    /// Successful migrations
    pub successful_migrations: u64,
    /// Predictions made
    pub predictions_made: u64,
    /// Prediction accuracy
    pub prediction_accuracy: f64,
}

impl PrewarmingManager {
    /// Create a new prewarming manager
    pub fn new(migration_strategy: MigrationStrategy) -> Self {
        Self {
            stats: Arc::new(Mutex::new(HashMap::new())),
            patterns: Arc::new(Mutex::new(HashMap::new())),
            paths: Arc::new(Mutex::new(HashMap::new())),
            migration_strategy,
            prewarm_stats: Arc::new(Mutex::new(PrewarmingStats::default())),
        }
    }

    /// Record a connection
    pub async fn record_connection(&self, peer_id: PeerId) {
        let mut stats = self.stats.lock().await;
        let entry = stats
            .entry(peer_id)
            .or_insert_with(|| ConnectionStats::new(peer_id));
        entry.record_connection();
    }

    /// Record an access pattern
    pub async fn record_access(&self, peer_id: PeerId) {
        let mut patterns = self.patterns.lock().await;
        let pattern = patterns
            .entry(peer_id)
            .or_insert_with(|| ConnectionPattern::new(peer_id));
        pattern.record_access();
    }

    /// Record a transfer
    pub async fn record_transfer(
        &self,
        peer_id: PeerId,
        success: bool,
        latency_ms: f64,
        bandwidth_bps: u64,
        bytes: u64,
    ) {
        let mut stats = self.stats.lock().await;
        let entry = stats
            .entry(peer_id)
            .or_insert_with(|| ConnectionStats::new(peer_id));
        entry.record_transfer(success, latency_ms, bandwidth_bps, bytes);
    }

    /// Get peers that should be prewarmed
    pub async fn get_prewarm_candidates(&self) -> Vec<PeerId> {
        let patterns = self.patterns.lock().await;
        patterns
            .values()
            .filter(|p| p.should_prewarm())
            .map(|p| p.peer_id)
            .collect()
    }

    /// Record path metrics
    pub async fn record_path_metrics(
        &self,
        peer_id: PeerId,
        path_id: impl Into<String>,
        success: bool,
        latency_ms: f64,
        bandwidth_bps: u64,
    ) {
        let path_id_str = path_id.into();
        let mut paths = self.paths.lock().await;
        let peer_paths = paths.entry(peer_id).or_insert_with(Vec::new);

        if let Some(path) = peer_paths.iter_mut().find(|p| p.path_id == path_id_str) {
            path.update_metrics(success, latency_ms, bandwidth_bps);
        } else {
            let mut new_path = PathInfo::new(&path_id_str);
            new_path.update_metrics(success, latency_ms, bandwidth_bps);
            peer_paths.push(new_path);
        }
    }

    /// Get best path for peer
    pub async fn get_best_path(&self, peer_id: &PeerId) -> Option<String> {
        let paths = self.paths.lock().await;
        if let Some(peer_paths) = paths.get(peer_id) {
            peer_paths
                .iter()
                .max_by(|a, b| {
                    a.score(self.migration_strategy)
                        .partial_cmp(&b.score(self.migration_strategy))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|p| p.path_id.clone())
        } else {
            None
        }
    }

    /// Check if migration is recommended
    pub async fn should_migrate(&self, peer_id: &PeerId, current_path: &str) -> bool {
        let paths = self.paths.lock().await;
        if let Some(peer_paths) = paths.get(peer_id) {
            if let Some(current) = peer_paths.iter().find(|p| p.path_id == current_path) {
                let best = peer_paths.iter().max_by(|a, b| {
                    a.score(self.migration_strategy)
                        .partial_cmp(&b.score(self.migration_strategy))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });

                if let Some(best_path) = best {
                    // Migrate if best path is significantly better (>20% improvement)
                    best_path.score(self.migration_strategy)
                        > current.score(self.migration_strategy) * 1.2
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Record prewarming attempt
    pub async fn record_prewarm(&self, success: bool) {
        let mut stats = self.prewarm_stats.lock().await;
        stats.total_prewarms += 1;
        if success {
            stats.successful_prewarms += 1;
        } else {
            stats.failed_prewarms += 1;
        }
    }

    /// Record migration
    pub async fn record_migration(&self, success: bool) {
        let mut stats = self.prewarm_stats.lock().await;
        stats.total_migrations += 1;
        if success {
            stats.successful_migrations += 1;
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> PrewarmingStats {
        self.prewarm_stats.lock().await.clone()
    }

    /// Get peer statistics
    pub async fn get_peer_stats(&self, peer_id: &PeerId) -> Option<ConnectionStats> {
        let stats = self.stats.lock().await;
        stats.get(peer_id).cloned()
    }

    /// Get all peer stats sorted by score
    pub async fn get_top_peers(&self, limit: usize) -> Vec<ConnectionStats> {
        let stats = self.stats.lock().await;
        let mut peers: Vec<_> = stats.values().cloned().collect();
        peers.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().take(limit).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_stats_new() {
        let peer_id = PeerId::random();
        let stats = ConnectionStats::new(peer_id);
        assert_eq!(stats.connection_count, 0);
        assert_eq!(stats.successful_transfers, 0);
    }

    #[test]
    fn test_connection_stats_record() {
        let peer_id = PeerId::random();
        let mut stats = ConnectionStats::new(peer_id);

        stats.record_connection();
        assert_eq!(stats.connection_count, 1);

        stats.record_transfer(true, 50.0, 1_000_000, 1000);
        assert_eq!(stats.successful_transfers, 1);
        assert_eq!(stats.total_bytes, 1000);
    }

    #[test]
    fn test_connection_stats_score() {
        let peer_id = PeerId::random();
        let mut stats = ConnectionStats::new(peer_id);

        stats.record_transfer(true, 50.0, 5_000_000, 1000);
        stats.record_transfer(true, 60.0, 6_000_000, 2000);

        let score = stats.score();
        assert!(score > 0.5 && score <= 1.0);
    }

    #[test]
    fn test_connection_pattern_new() {
        let peer_id = PeerId::random();
        let pattern = ConnectionPattern::new(peer_id);
        assert_eq!(pattern.access_times.len(), 0);
        assert!(pattern.predicted_next_access.is_none());
    }

    #[test]
    fn test_connection_pattern_record() {
        let peer_id = PeerId::random();
        let mut pattern = ConnectionPattern::new(peer_id);

        pattern.record_access();
        assert_eq!(pattern.access_times.len(), 1);

        pattern.record_access();
        assert_eq!(pattern.access_times.len(), 2);
    }

    #[test]
    fn test_path_info_new() {
        let path = PathInfo::new("path1");
        assert_eq!(path.path_id, "path1");
        assert_eq!(path.reliability, 1.0);
    }

    #[test]
    fn test_path_info_update() {
        let mut path = PathInfo::new("path1");
        path.update_metrics(true, 50.0, 5_000_000);

        assert_eq!(path.successful_transfers, 1);
        assert_eq!(path.latency_ms, 50.0);
        assert_eq!(path.bandwidth_bps, 5_000_000);
    }

    #[test]
    fn test_path_info_score() {
        let mut path = PathInfo::new("path1");
        path.update_metrics(true, 50.0, 5_000_000);

        let score = path.score(MigrationStrategy::Balanced);
        assert!(score > 0.0 && score <= 1.0);
    }

    #[tokio::test]
    async fn test_prewarming_manager_new() {
        let manager = PrewarmingManager::new(MigrationStrategy::Balanced);
        let stats = manager.stats().await;
        assert_eq!(stats.total_prewarms, 0);
    }

    #[tokio::test]
    async fn test_prewarming_manager_record_connection() {
        let manager = PrewarmingManager::new(MigrationStrategy::Balanced);
        let peer_id = PeerId::random();

        manager.record_connection(peer_id).await;

        let peer_stats = manager.get_peer_stats(&peer_id).await;
        assert!(peer_stats.is_some());
        assert_eq!(peer_stats.unwrap().connection_count, 1);
    }

    #[tokio::test]
    async fn test_prewarming_manager_record_transfer() {
        let manager = PrewarmingManager::new(MigrationStrategy::Balanced);
        let peer_id = PeerId::random();

        manager
            .record_transfer(peer_id, true, 50.0, 5_000_000, 1000)
            .await;

        let peer_stats = manager.get_peer_stats(&peer_id).await;
        assert!(peer_stats.is_some());
        assert_eq!(peer_stats.unwrap().successful_transfers, 1);
    }

    #[tokio::test]
    async fn test_prewarming_manager_paths() {
        let manager = PrewarmingManager::new(MigrationStrategy::Balanced);
        let peer_id = PeerId::random();

        manager
            .record_path_metrics(peer_id, "path1", true, 50.0, 5_000_000)
            .await;
        manager
            .record_path_metrics(peer_id, "path2", true, 30.0, 8_000_000)
            .await;

        let best_path = manager.get_best_path(&peer_id).await;
        assert!(best_path.is_some());
    }

    #[tokio::test]
    async fn test_prewarming_manager_migration() {
        let manager = PrewarmingManager::new(MigrationStrategy::LowerLatency);
        let peer_id = PeerId::random();

        manager
            .record_path_metrics(peer_id, "path1", true, 100.0, 5_000_000)
            .await;
        manager
            .record_path_metrics(peer_id, "path2", true, 30.0, 4_000_000)
            .await;

        let should_migrate = manager.should_migrate(&peer_id, "path1").await;
        assert!(should_migrate);

        manager.record_migration(true).await;
        let stats = manager.stats().await;
        assert_eq!(stats.total_migrations, 1);
    }

    #[tokio::test]
    async fn test_prewarming_manager_top_peers() {
        let manager = PrewarmingManager::new(MigrationStrategy::Balanced);

        for _ in 0..5 {
            let peer_id = PeerId::random();
            manager
                .record_transfer(peer_id, true, 50.0, 5_000_000, 1000)
                .await;
        }

        let top_peers = manager.get_top_peers(3).await;
        assert_eq!(top_peers.len(), 3);
    }
}
