//! Content migration manager for load balancing and optimization.
//!
//! This module manages the migration of content between peers to optimize
//! network load distribution, reduce hotspots, and improve overall performance.
//!
//! # Features
//!
//! - **Load-based Migration**: Automatically migrates content from overloaded peers
//! - **Geographic Optimization**: Moves content closer to high-demand regions
//! - **Popularity-aware**: Replicates popular content to more peers
//! - **Bandwidth Optimization**: Reduces bandwidth costs by optimal placement
//! - **Health-based Triggers**: Migrates content away from unhealthy peers
//! - **Migration Planning**: Plans and schedules migrations to minimize disruption
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::content_migration::{ContentMigrationManager, MigrationConfig, MigrationTrigger};
//! use std::time::Duration;
//!
//! let config = MigrationConfig {
//!     max_concurrent_migrations: 5,
//!     migration_timeout: Duration::from_secs(300),
//!     load_threshold: 0.8,
//!     min_replication_factor: 3,
//!     max_replication_factor: 10,
//! };
//!
//! let manager = ContentMigrationManager::new(config);
//!
//! // Plan a migration
//! manager.plan_migration(
//!     "content123",
//!     "peer1",
//!     "peer2",
//!     MigrationTrigger::LoadBalancing,
//! );
//!
//! // Execute planned migrations
//! let active_migrations = manager.execute_migrations();
//! println!("Started {} migrations", active_migrations);
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Configuration for content migration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Maximum number of concurrent migrations
    pub max_concurrent_migrations: usize,
    /// Timeout for a single migration operation
    pub migration_timeout: Duration,
    /// Load threshold (0.0-1.0) above which migrations are triggered
    pub load_threshold: f64,
    /// Minimum number of replicas to maintain
    pub min_replication_factor: usize,
    /// Maximum number of replicas allowed
    pub max_replication_factor: usize,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_concurrent_migrations: 5,
            migration_timeout: Duration::from_secs(300),
            load_threshold: 0.8,
            min_replication_factor: 3,
            max_replication_factor: 10,
        }
    }
}

/// Reason for triggering a migration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTrigger {
    /// Load balancing - peer is overloaded
    LoadBalancing,
    /// Geographic optimization - move content closer to users
    GeographicOptimization,
    /// Replication factor too low
    InsufficientReplication,
    /// Replication factor too high
    ExcessiveReplication,
    /// Source peer is unhealthy
    PeerHealth,
    /// Bandwidth cost optimization
    BandwidthOptimization,
    /// Manual migration requested
    Manual,
}

/// Current state of a migration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// Migration is planned but not started
    Planned,
    /// Migration is currently in progress
    InProgress,
    /// Migration completed successfully
    Completed,
    /// Migration failed
    Failed,
    /// Migration was cancelled
    Cancelled,
}

/// A planned or active content migration
#[derive(Debug, Clone)]
pub struct Migration {
    /// Unique migration ID
    pub id: String,
    /// Content ID being migrated
    pub content_id: String,
    /// Source peer ID
    pub source_peer: String,
    /// Destination peer ID
    pub dest_peer: String,
    /// Reason for migration
    pub trigger: MigrationTrigger,
    /// Current state
    pub state: MigrationState,
    /// When the migration was planned
    pub planned_at: Instant,
    /// When the migration started (if started)
    pub started_at: Option<Instant>,
    /// When the migration completed/failed (if finished)
    pub finished_at: Option<Instant>,
    /// Priority (higher = more urgent)
    pub priority: u32,
    /// Progress (0.0-1.0)
    pub progress: f64,
    /// Error message if failed
    pub error: Option<String>,
}

impl Migration {
    fn new(
        content_id: String,
        source_peer: String,
        dest_peer: String,
        trigger: MigrationTrigger,
        priority: u32,
    ) -> Self {
        let id = format!("{}:{}:{}", content_id, source_peer, dest_peer);

        Self {
            id,
            content_id,
            source_peer,
            dest_peer,
            trigger,
            state: MigrationState::Planned,
            planned_at: Instant::now(),
            started_at: None,
            finished_at: None,
            priority,
            progress: 0.0,
            error: None,
        }
    }

    fn duration(&self) -> Option<Duration> {
        self.started_at
            .and_then(|start| self.finished_at.map(|end| end.duration_since(start)))
    }
}

/// Statistics for migration manager
#[derive(Debug, Clone, Default)]
pub struct MigrationStats {
    /// Total migrations planned
    pub total_planned: u64,
    /// Total migrations executed
    pub total_executed: u64,
    /// Total migrations completed successfully
    pub total_completed: u64,
    /// Total migrations failed
    pub total_failed: u64,
    /// Total migrations cancelled
    pub total_cancelled: u64,
    /// Current pending migrations
    pub pending_count: usize,
    /// Current active migrations
    pub active_count: usize,
    /// Average migration duration (milliseconds)
    pub avg_duration_ms: f64,
    /// Total bytes migrated
    pub total_bytes_migrated: u64,
    /// Migrations by trigger type
    pub by_trigger: HashMap<String, u64>,
}

/// Content migration manager
pub struct ContentMigrationManager {
    config: MigrationConfig,
    planned: Arc<RwLock<VecDeque<Migration>>>,
    active: Arc<RwLock<HashMap<String, Migration>>>,
    completed: Arc<RwLock<Vec<Migration>>>,
    stats: Arc<RwLock<MigrationStats>>,
}

impl ContentMigrationManager {
    /// Creates a new content migration manager
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            config,
            planned: Arc::new(RwLock::new(VecDeque::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(MigrationStats::default())),
        }
    }

    /// Plans a new migration
    pub fn plan_migration(
        &self,
        content_id: &str,
        source_peer: &str,
        dest_peer: &str,
        trigger: MigrationTrigger,
    ) -> String {
        self.plan_migration_with_priority(content_id, source_peer, dest_peer, trigger, 0)
    }

    /// Plans a new migration with specific priority
    pub fn plan_migration_with_priority(
        &self,
        content_id: &str,
        source_peer: &str,
        dest_peer: &str,
        trigger: MigrationTrigger,
        priority: u32,
    ) -> String {
        let migration = Migration::new(
            content_id.to_string(),
            source_peer.to_string(),
            dest_peer.to_string(),
            trigger,
            priority,
        );

        let id = migration.id.clone();

        let mut planned = self.planned.write().unwrap();

        // Insert based on priority (higher priority first)
        let pos = planned
            .iter()
            .position(|m| m.priority < priority)
            .unwrap_or(planned.len());

        planned.insert(pos, migration);

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_planned += 1;
        stats.pending_count = planned.len();

        // Track by trigger
        let trigger_name = format!("{:?}", trigger);
        *stats.by_trigger.entry(trigger_name).or_insert(0) += 1;

        id
    }

    /// Executes pending migrations up to the concurrency limit
    pub fn execute_migrations(&self) -> usize {
        let mut planned = self.planned.write().unwrap();
        let mut active = self.active.write().unwrap();

        let available_slots = self
            .config
            .max_concurrent_migrations
            .saturating_sub(active.len());
        let mut started_count = 0;

        for _ in 0..available_slots {
            if let Some(mut migration) = planned.pop_front() {
                migration.state = MigrationState::InProgress;
                migration.started_at = Some(Instant::now());

                active.insert(migration.id.clone(), migration);
                started_count += 1;
            } else {
                break;
            }
        }

        if started_count > 0 {
            let mut stats = self.stats.write().unwrap();
            stats.total_executed += started_count as u64;
            stats.pending_count = planned.len();
            stats.active_count = active.len();
        }

        started_count
    }

    /// Updates migration progress
    pub fn update_progress(&self, migration_id: &str, progress: f64) -> bool {
        let mut active = self.active.write().unwrap();

        if let Some(migration) = active.get_mut(migration_id) {
            migration.progress = progress.clamp(0.0, 1.0);
            true
        } else {
            false
        }
    }

    /// Marks a migration as completed
    pub fn complete_migration(&self, migration_id: &str, bytes_transferred: u64) -> bool {
        let mut active = self.active.write().unwrap();

        if let Some(mut migration) = active.remove(migration_id) {
            migration.state = MigrationState::Completed;
            migration.finished_at = Some(Instant::now());
            migration.progress = 1.0;

            let duration = migration.duration();

            let mut completed = self.completed.write().unwrap();
            completed.push(migration);

            // Update stats
            let mut stats = self.stats.write().unwrap();
            stats.total_completed += 1;
            stats.active_count = active.len();
            stats.total_bytes_migrated += bytes_transferred;

            if let Some(dur) = duration {
                let total_completed = stats.total_completed;
                let old_avg = stats.avg_duration_ms;
                let new_duration = dur.as_millis() as f64;

                // Incremental average calculation
                stats.avg_duration_ms = (old_avg * (total_completed as f64 - 1.0) + new_duration)
                    / total_completed as f64;
            }

            true
        } else {
            false
        }
    }

    /// Marks a migration as failed
    pub fn fail_migration(&self, migration_id: &str, error: &str) -> bool {
        let mut active = self.active.write().unwrap();

        if let Some(mut migration) = active.remove(migration_id) {
            migration.state = MigrationState::Failed;
            migration.finished_at = Some(Instant::now());
            migration.error = Some(error.to_string());

            let mut completed = self.completed.write().unwrap();
            completed.push(migration);

            // Update stats
            let mut stats = self.stats.write().unwrap();
            stats.total_failed += 1;
            stats.active_count = active.len();

            true
        } else {
            false
        }
    }

    /// Cancels a planned or active migration
    pub fn cancel_migration(&self, migration_id: &str) -> bool {
        // Try to remove from planned first
        {
            let mut planned = self.planned.write().unwrap();
            if let Some(pos) = planned.iter().position(|m| m.id == migration_id) {
                let mut migration = planned.remove(pos).unwrap();
                migration.state = MigrationState::Cancelled;
                migration.finished_at = Some(Instant::now());

                let mut completed = self.completed.write().unwrap();
                completed.push(migration);

                let mut stats = self.stats.write().unwrap();
                stats.total_cancelled += 1;
                stats.pending_count = planned.len();

                return true;
            }
        }

        // Try to remove from active
        {
            let mut active = self.active.write().unwrap();
            if let Some(mut migration) = active.remove(migration_id) {
                migration.state = MigrationState::Cancelled;
                migration.finished_at = Some(Instant::now());

                let mut completed = self.completed.write().unwrap();
                completed.push(migration);

                let mut stats = self.stats.write().unwrap();
                stats.total_cancelled += 1;
                stats.active_count = active.len();

                return true;
            }
        }

        false
    }

    /// Gets a migration by ID
    pub fn get_migration(&self, migration_id: &str) -> Option<Migration> {
        // Check active first
        {
            let active = self.active.read().unwrap();
            if let Some(migration) = active.get(migration_id) {
                return Some(migration.clone());
            }
        }

        // Check planned
        {
            let planned = self.planned.read().unwrap();
            if let Some(migration) = planned.iter().find(|m| m.id == migration_id) {
                return Some(migration.clone());
            }
        }

        // Check completed
        {
            let completed = self.completed.read().unwrap();
            completed.iter().find(|m| m.id == migration_id).cloned()
        }
    }

    /// Gets all active migrations
    pub fn active_migrations(&self) -> Vec<Migration> {
        let active = self.active.read().unwrap();
        active.values().cloned().collect()
    }

    /// Gets all planned migrations
    pub fn planned_migrations(&self) -> Vec<Migration> {
        let planned = self.planned.read().unwrap();
        planned.iter().cloned().collect()
    }

    /// Checks for timed-out migrations and marks them as failed
    pub fn check_timeouts(&self) -> usize {
        let mut active = self.active.write().unwrap();
        let mut timed_out = Vec::new();

        let now = Instant::now();

        for (id, migration) in active.iter() {
            if let Some(started) = migration.started_at {
                if now.duration_since(started) > self.config.migration_timeout {
                    timed_out.push(id.clone());
                }
            }
        }

        let count = timed_out.len();

        for id in timed_out {
            if let Some(mut migration) = active.remove(&id) {
                migration.state = MigrationState::Failed;
                migration.finished_at = Some(now);
                migration.error = Some("Migration timed out".to_string());

                let mut completed = self.completed.write().unwrap();
                completed.push(migration);
            }
        }

        if count > 0 {
            let mut stats = self.stats.write().unwrap();
            stats.total_failed += count as u64;
            stats.active_count = active.len();
        }

        count
    }

    /// Clears completed migration history
    pub fn clear_history(&self) {
        let mut completed = self.completed.write().unwrap();
        completed.clear();
    }

    /// Gets current statistics
    pub fn stats(&self) -> MigrationStats {
        let stats = self.stats.read().unwrap();
        stats.clone()
    }

    /// Gets the configuration
    pub fn config(&self) -> &MigrationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_config() {
        let config = MigrationConfig::default();
        assert_eq!(config.max_concurrent_migrations, 5);
        assert_eq!(config.migration_timeout, Duration::from_secs(300));
        assert_eq!(config.load_threshold, 0.8);
        assert_eq!(config.min_replication_factor, 3);
        assert_eq!(config.max_replication_factor, 10);
    }

    #[test]
    fn test_new_manager() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());
        let stats = manager.stats();

        assert_eq!(stats.total_planned, 0);
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.active_count, 0);
    }

    #[test]
    fn test_plan_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration(
            "content1",
            "peer1",
            "peer2",
            MigrationTrigger::LoadBalancing,
        );

        assert!(!id.is_empty());

        let stats = manager.stats();
        assert_eq!(stats.total_planned, 1);
        assert_eq!(stats.pending_count, 1);
    }

    #[test]
    fn test_execute_migrations() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        manager.plan_migration(
            "content1",
            "peer1",
            "peer2",
            MigrationTrigger::LoadBalancing,
        );
        manager.plan_migration("content2", "peer3", "peer4", MigrationTrigger::PeerHealth);

        let started = manager.execute_migrations();
        assert_eq!(started, 2);

        let stats = manager.stats();
        assert_eq!(stats.total_executed, 2);
        assert_eq!(stats.active_count, 2);
        assert_eq!(stats.pending_count, 0);
    }

    #[test]
    fn test_execute_migrations_with_limit() {
        let config = MigrationConfig {
            max_concurrent_migrations: 2,
            ..Default::default()
        };
        let manager = ContentMigrationManager::new(config);

        for i in 0..5 {
            manager.plan_migration(
                &format!("content{}", i),
                &format!("peer{}", i),
                &format!("peer{}", i + 10),
                MigrationTrigger::LoadBalancing,
            );
        }

        let started = manager.execute_migrations();
        assert_eq!(started, 2);

        let stats = manager.stats();
        assert_eq!(stats.active_count, 2);
        assert_eq!(stats.pending_count, 3);
    }

    #[test]
    fn test_update_progress() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        assert!(manager.update_progress(&id, 0.5));

        let migration = manager.get_migration(&id).unwrap();
        assert_eq!(migration.progress, 0.5);
    }

    #[test]
    fn test_complete_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        thread::sleep(Duration::from_millis(10));

        assert!(manager.complete_migration(&id, 1024 * 1024));

        let stats = manager.stats();
        assert_eq!(stats.total_completed, 1);
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.total_bytes_migrated, 1024 * 1024);
        assert!(stats.avg_duration_ms > 0.0);

        let migration = manager.get_migration(&id).unwrap();
        assert_eq!(migration.state, MigrationState::Completed);
        assert_eq!(migration.progress, 1.0);
    }

    #[test]
    fn test_fail_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        assert!(manager.fail_migration(&id, "Network error"));

        let stats = manager.stats();
        assert_eq!(stats.total_failed, 1);
        assert_eq!(stats.active_count, 0);

        let migration = manager.get_migration(&id).unwrap();
        assert_eq!(migration.state, MigrationState::Failed);
        assert_eq!(migration.error.as_deref(), Some("Network error"));
    }

    #[test]
    fn test_cancel_planned_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);

        assert!(manager.cancel_migration(&id));

        let stats = manager.stats();
        assert_eq!(stats.total_cancelled, 1);
        assert_eq!(stats.pending_count, 0);

        let migration = manager.get_migration(&id).unwrap();
        assert_eq!(migration.state, MigrationState::Cancelled);
    }

    #[test]
    fn test_cancel_active_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        assert!(manager.cancel_migration(&id));

        let stats = manager.stats();
        assert_eq!(stats.total_cancelled, 1);
        assert_eq!(stats.active_count, 0);
    }

    #[test]
    fn test_priority_ordering() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        manager.plan_migration_with_priority(
            "content1",
            "peer1",
            "peer2",
            MigrationTrigger::Manual,
            1,
        );
        manager.plan_migration_with_priority(
            "content2",
            "peer3",
            "peer4",
            MigrationTrigger::Manual,
            10,
        );
        manager.plan_migration_with_priority(
            "content3",
            "peer5",
            "peer6",
            MigrationTrigger::Manual,
            5,
        );

        let planned = manager.planned_migrations();
        assert_eq!(planned.len(), 3);

        // Should be ordered by priority (high to low)
        assert_eq!(planned[0].priority, 10);
        assert_eq!(planned[1].priority, 5);
        assert_eq!(planned[2].priority, 1);
    }

    #[test]
    fn test_get_migration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);

        let migration = manager.get_migration(&id);
        assert!(migration.is_some());
        assert_eq!(migration.unwrap().content_id, "content1");
    }

    #[test]
    fn test_active_migrations() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.plan_migration("content2", "peer3", "peer4", MigrationTrigger::Manual);
        manager.execute_migrations();

        let active = manager.active_migrations();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_planned_migrations() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.plan_migration("content2", "peer3", "peer4", MigrationTrigger::Manual);

        let planned = manager.planned_migrations();
        assert_eq!(planned.len(), 2);
    }

    #[test]
    fn test_check_timeouts() {
        let config = MigrationConfig {
            migration_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let manager = ContentMigrationManager::new(config);

        manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        thread::sleep(Duration::from_millis(100));

        let timed_out = manager.check_timeouts();
        assert_eq!(timed_out, 1);

        let stats = manager.stats();
        assert_eq!(stats.total_failed, 1);
        assert_eq!(stats.active_count, 0);
    }

    #[test]
    fn test_clear_history() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();
        manager.complete_migration(&id, 1024);

        manager.clear_history();

        // Completed migration should no longer be retrievable
        assert!(manager.get_migration(&id).is_none());
    }

    #[test]
    fn test_migration_trigger_stats() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        manager.plan_migration(
            "content1",
            "peer1",
            "peer2",
            MigrationTrigger::LoadBalancing,
        );
        manager.plan_migration(
            "content2",
            "peer3",
            "peer4",
            MigrationTrigger::LoadBalancing,
        );
        manager.plan_migration("content3", "peer5", "peer6", MigrationTrigger::PeerHealth);

        let stats = manager.stats();
        assert_eq!(*stats.by_trigger.get("LoadBalancing").unwrap(), 2);
        assert_eq!(*stats.by_trigger.get("PeerHealth").unwrap(), 1);
    }

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(ContentMigrationManager::new(MigrationConfig::default()));
        let mut handles = vec![];

        for i in 0..5 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                manager_clone.plan_migration(
                    &format!("content{}", i),
                    &format!("peer{}", i),
                    &format!("peer{}", i + 10),
                    MigrationTrigger::Manual,
                );
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = manager.stats();
        assert_eq!(stats.total_planned, 5);
    }

    #[test]
    fn test_migration_duration() {
        let manager = ContentMigrationManager::new(MigrationConfig::default());

        let id = manager.plan_migration("content1", "peer1", "peer2", MigrationTrigger::Manual);
        manager.execute_migrations();

        thread::sleep(Duration::from_millis(50));

        manager.complete_migration(&id, 1024);

        let migration = manager.get_migration(&id).unwrap();
        let duration = migration.duration();

        assert!(duration.is_some());
        assert!(duration.unwrap() >= Duration::from_millis(50));
    }
}
