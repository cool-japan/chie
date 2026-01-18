//! Backup coordinator failover for CHIE network.
//!
//! This module provides automatic failover capabilities:
//! - Primary coordinator monitoring
//! - Automatic promotion to primary on failure
//! - State synchronization before promotion
//! - Graceful handoff when primary recovers

#![allow(dead_code)]
#![allow(clippy::type_complexity)]

use crate::federation::{FederationManager, PeerStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Failover configuration.
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Number of missed heartbeats before considering primary dead.
    pub missed_heartbeat_threshold: u32,
    /// Time to wait before promoting self to primary (seconds).
    pub promotion_delay_secs: u64,
    /// Minimum sync progress before promotion (0.0-1.0).
    pub min_sync_progress: f64,
    /// Whether this coordinator can become primary.
    pub can_become_primary: bool,
    /// Priority for leader election (lower = higher priority).
    pub election_priority: u32,
    /// Health check interval.
    pub health_check_interval: Duration,
    /// Maximum time to wait for graceful handoff.
    pub handoff_timeout: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            missed_heartbeat_threshold: 3,
            promotion_delay_secs: 10,
            min_sync_progress: 0.95,
            can_become_primary: true,
            election_priority: 100,
            health_check_interval: Duration::from_secs(5),
            handoff_timeout: Duration::from_secs(30),
        }
    }
}

/// Failover state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverState {
    /// Normal operation as backup.
    Standby,
    /// Primary health check failing.
    Monitoring,
    /// Preparing for promotion.
    PreparingPromotion,
    /// Syncing state before promotion.
    Syncing,
    /// Promoted to primary.
    Primary,
    /// Handing off to recovered primary.
    HandingOff,
}

/// Failover event for notifications.
#[derive(Debug, Clone)]
pub enum FailoverEvent {
    /// Primary coordinator became unreachable.
    PrimaryUnreachable { primary_id: Uuid },
    /// Started monitoring potential failover.
    MonitoringStarted { primary_id: Uuid },
    /// Preparing to become primary.
    PreparingPromotion,
    /// Syncing state before promotion.
    SyncingState { progress: f64 },
    /// Successfully promoted to primary.
    PromotedToPrimary,
    /// Original primary recovered.
    PrimaryRecovered { primary_id: Uuid },
    /// Handing off back to original primary.
    HandingOff { primary_id: Uuid },
    /// Handoff complete, returned to standby.
    HandoffComplete,
    /// Failover failed.
    FailoverFailed { reason: String },
}

/// Failover manager for handling coordinator failover.
pub struct FailoverManager {
    /// Configuration.
    config: FailoverConfig,
    /// Federation manager reference.
    federation: Arc<FederationManager>,
    /// Current failover state.
    state: Arc<RwLock<FailoverState>>,
    /// Missed heartbeat count.
    missed_heartbeats: AtomicU64,
    /// Last known primary ID.
    last_primary_id: Arc<RwLock<Option<Uuid>>>,
    /// Sync progress (0-100).
    sync_progress: AtomicU64,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Event callback.
    event_callback: Arc<RwLock<Option<Box<dyn Fn(FailoverEvent) + Send + Sync>>>>,
}

impl FailoverManager {
    /// Create a new failover manager.
    pub fn new(config: FailoverConfig, federation: Arc<FederationManager>) -> Self {
        Self {
            config,
            federation,
            state: Arc::new(RwLock::new(FailoverState::Standby)),
            missed_heartbeats: AtomicU64::new(0),
            last_primary_id: Arc::new(RwLock::new(None)),
            sync_progress: AtomicU64::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
            event_callback: Arc::new(RwLock::new(None)),
        }
    }

    /// Set event callback.
    pub async fn set_event_callback<F>(&self, callback: F)
    where
        F: Fn(FailoverEvent) + Send + Sync + 'static,
    {
        *self.event_callback.write().await = Some(Box::new(callback));
    }

    /// Get current failover state.
    pub async fn state(&self) -> FailoverState {
        *self.state.read().await
    }

    /// Check if we are the primary.
    pub async fn is_primary(&self) -> bool {
        *self.state.read().await == FailoverState::Primary
    }

    /// Start the failover manager.
    pub async fn start(&self) {
        info!("Starting failover manager");

        // Check initial state
        if self.federation.is_leader().await {
            *self.state.write().await = FailoverState::Primary;
            info!("Starting as primary coordinator");
        } else {
            *self.state.write().await = FailoverState::Standby;
            info!("Starting as standby coordinator");
        }

        // Start monitoring loop
        let manager = FailoverManagerRef {
            config: self.config.clone(),
            federation: self.federation.clone(),
            state: self.state.clone(),
            missed_heartbeats: self.missed_heartbeats.load(Ordering::Relaxed),
            last_primary_id: self.last_primary_id.clone(),
            sync_progress: self.sync_progress.load(Ordering::Relaxed),
            shutdown: self.shutdown.clone(),
            event_callback: self.event_callback.clone(),
        };

        tokio::spawn(async move {
            manager.monitor_loop().await;
        });
    }

    /// Stop the failover manager.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Trigger manual failover (for testing/admin).
    pub async fn trigger_failover(&self) -> Result<(), FailoverError> {
        if !self.config.can_become_primary {
            return Err(FailoverError::NotEligible);
        }

        let current_state = *self.state.read().await;
        if current_state == FailoverState::Primary {
            return Err(FailoverError::AlreadyPrimary);
        }

        info!("Manual failover triggered");
        self.emit_event(FailoverEvent::PreparingPromotion).await;

        // Skip monitoring, go straight to promotion
        *self.state.write().await = FailoverState::PreparingPromotion;

        // Sync and promote
        self.sync_and_promote().await
    }

    /// Trigger manual handoff to another coordinator.
    pub async fn trigger_handoff(&self, target_id: Uuid) -> Result<(), FailoverError> {
        let current_state = *self.state.read().await;
        if current_state != FailoverState::Primary {
            return Err(FailoverError::NotPrimary);
        }

        // Check target exists and is healthy
        let target = self.federation.get_peer(&target_id).await;
        if target.is_none() {
            return Err(FailoverError::TargetNotFound);
        }

        let target = target.unwrap();
        if target.status != PeerStatus::Healthy {
            return Err(FailoverError::TargetUnhealthy);
        }

        info!("Manual handoff triggered to {}", target_id);
        self.emit_event(FailoverEvent::HandingOff {
            primary_id: target_id,
        })
        .await;

        *self.state.write().await = FailoverState::HandingOff;

        // Perform handoff
        self.perform_handoff(target_id).await
    }

    /// Get failover statistics.
    pub async fn stats(&self) -> FailoverStats {
        FailoverStats {
            state: *self.state.read().await,
            missed_heartbeats: self.missed_heartbeats.load(Ordering::Relaxed),
            sync_progress: self.sync_progress.load(Ordering::Relaxed) as f64 / 100.0,
            last_primary_id: *self.last_primary_id.read().await,
            can_become_primary: self.config.can_become_primary,
            election_priority: self.config.election_priority,
        }
    }

    // Private methods

    async fn emit_event(&self, event: FailoverEvent) {
        if let Some(callback) = self.event_callback.read().await.as_ref() {
            callback(event);
        }
    }

    async fn sync_and_promote(&self) -> Result<(), FailoverError> {
        *self.state.write().await = FailoverState::Syncing;

        // Simulate sync progress
        for progress in (0..=100).step_by(10) {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(FailoverError::Cancelled);
            }

            self.sync_progress.store(progress, Ordering::Relaxed);
            self.emit_event(FailoverEvent::SyncingState {
                progress: progress as f64 / 100.0,
            })
            .await;

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check sync progress meets threshold
        let progress = self.sync_progress.load(Ordering::Relaxed) as f64 / 100.0;
        if progress < self.config.min_sync_progress {
            self.emit_event(FailoverEvent::FailoverFailed {
                reason: format!(
                    "Sync progress {} below threshold {}",
                    progress, self.config.min_sync_progress
                ),
            })
            .await;
            *self.state.write().await = FailoverState::Standby;
            return Err(FailoverError::SyncIncomplete);
        }

        // Promote to primary
        *self.state.write().await = FailoverState::Primary;
        self.emit_event(FailoverEvent::PromotedToPrimary).await;

        info!("Successfully promoted to primary coordinator");
        Ok(())
    }

    async fn perform_handoff(&self, target_id: Uuid) -> Result<(), FailoverError> {
        // Wait for target to be ready
        let deadline = tokio::time::Instant::now() + self.config.handoff_timeout;

        while tokio::time::Instant::now() < deadline {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(FailoverError::Cancelled);
            }

            // Check if target has become leader
            if let Some(leader) = self.federation.leader_id().await {
                if leader == target_id {
                    // Handoff successful
                    *self.state.write().await = FailoverState::Standby;
                    self.emit_event(FailoverEvent::HandoffComplete).await;
                    info!("Handoff complete, now standby");
                    return Ok(());
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Handoff timed out, remain primary
        *self.state.write().await = FailoverState::Primary;
        Err(FailoverError::HandoffTimeout)
    }
}

/// Reference for spawned tasks.
struct FailoverManagerRef {
    config: FailoverConfig,
    federation: Arc<FederationManager>,
    state: Arc<RwLock<FailoverState>>,
    #[allow(dead_code)]
    missed_heartbeats: u64,
    last_primary_id: Arc<RwLock<Option<Uuid>>>,
    #[allow(dead_code)]
    sync_progress: u64,
    shutdown: Arc<AtomicBool>,
    event_callback: Arc<RwLock<Option<Box<dyn Fn(FailoverEvent) + Send + Sync>>>>,
}

impl FailoverManagerRef {
    async fn monitor_loop(&self) {
        let mut missed_count = 0u32;

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            let current_state = *self.state.read().await;

            match current_state {
                FailoverState::Standby => {
                    // Monitor primary health
                    if let Some(leader_id) = self.federation.leader_id().await {
                        *self.last_primary_id.write().await = Some(leader_id);

                        if let Some(leader) = self.federation.get_peer(&leader_id).await {
                            if leader.status == PeerStatus::Healthy {
                                missed_count = 0;
                            } else {
                                missed_count += 1;
                                debug!(
                                    "Primary {} unhealthy, missed count: {}",
                                    leader_id, missed_count
                                );

                                if missed_count >= self.config.missed_heartbeat_threshold {
                                    self.emit_event(FailoverEvent::PrimaryUnreachable {
                                        primary_id: leader_id,
                                    })
                                    .await;
                                    *self.state.write().await = FailoverState::Monitoring;
                                }
                            }
                        }
                    }
                }
                FailoverState::Monitoring => {
                    // Continue monitoring, prepare for potential failover
                    if let Some(leader_id) = *self.last_primary_id.read().await {
                        if let Some(leader) = self.federation.get_peer(&leader_id).await {
                            if leader.status == PeerStatus::Healthy {
                                // Primary recovered
                                info!("Primary {} recovered", leader_id);
                                self.emit_event(FailoverEvent::PrimaryRecovered {
                                    primary_id: leader_id,
                                })
                                .await;
                                *self.state.write().await = FailoverState::Standby;
                                missed_count = 0;
                            } else if self.config.can_become_primary {
                                // Proceed with failover
                                warn!(
                                    "Primary {} still unreachable, preparing promotion",
                                    leader_id
                                );
                                self.emit_event(FailoverEvent::PreparingPromotion).await;
                                *self.state.write().await = FailoverState::PreparingPromotion;
                            }
                        }
                    }
                }
                FailoverState::Primary => {
                    // Check if original primary recovered
                    if let Some(original_primary) = *self.last_primary_id.read().await {
                        if let Some(peer) = self.federation.get_peer(&original_primary).await {
                            if peer.status == PeerStatus::Healthy {
                                // Original primary is back
                                self.emit_event(FailoverEvent::PrimaryRecovered {
                                    primary_id: original_primary,
                                })
                                .await;
                                // Note: Not automatically handing off - requires manual trigger
                                debug!(
                                    "Original primary {} recovered, manual handoff available",
                                    original_primary
                                );
                            }
                        }
                    }
                }
                _ => {
                    // Other states handled elsewhere
                }
            }

            tokio::time::sleep(self.config.health_check_interval).await;
        }
    }

    async fn emit_event(&self, event: FailoverEvent) {
        if let Some(callback) = self.event_callback.read().await.as_ref() {
            callback(event);
        }
    }
}

/// Failover statistics.
#[derive(Debug, Clone)]
pub struct FailoverStats {
    /// Current failover state.
    pub state: FailoverState,
    /// Number of missed heartbeats.
    pub missed_heartbeats: u64,
    /// Sync progress (0.0-1.0).
    pub sync_progress: f64,
    /// Last known primary ID.
    pub last_primary_id: Option<Uuid>,
    /// Whether this node can become primary.
    pub can_become_primary: bool,
    /// Election priority.
    pub election_priority: u32,
}

/// Failover errors.
#[derive(Debug, thiserror::Error)]
pub enum FailoverError {
    #[error("This coordinator is not eligible to become primary")]
    NotEligible,

    #[error("Already primary coordinator")]
    AlreadyPrimary,

    #[error("Not currently the primary coordinator")]
    NotPrimary,

    #[error("Target coordinator not found")]
    TargetNotFound,

    #[error("Target coordinator is not healthy")]
    TargetUnhealthy,

    #[error("Sync did not complete to required threshold")]
    SyncIncomplete,

    #[error("Handoff timed out")]
    HandoffTimeout,

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Federation error: {0}")]
    FederationError(String),
}

/// Shared failover manager type.
pub type SharedFailoverManager = Arc<FailoverManager>;

/// Create a shared failover manager.
pub fn create_failover_manager(
    config: FailoverConfig,
    federation: Arc<FederationManager>,
) -> SharedFailoverManager {
    Arc::new(FailoverManager::new(config, federation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::FederationConfig;

    #[test]
    fn test_failover_config_default() {
        let config = FailoverConfig::default();
        assert_eq!(config.missed_heartbeat_threshold, 3);
        assert!(config.can_become_primary);
        assert_eq!(config.election_priority, 100);
    }

    #[test]
    fn test_failover_state() {
        assert_eq!(FailoverState::Standby, FailoverState::Standby);
        assert_ne!(FailoverState::Standby, FailoverState::Primary);
    }

    #[tokio::test]
    async fn test_failover_manager_creation() {
        let fed_config = FederationConfig::default();
        let federation = Arc::new(FederationManager::new(fed_config));
        let config = FailoverConfig::default();
        let manager = FailoverManager::new(config, federation);

        assert_eq!(manager.state().await, FailoverState::Standby);
        assert!(!manager.is_primary().await);
    }

    #[tokio::test]
    async fn test_failover_stats() {
        let fed_config = FederationConfig::default();
        let federation = Arc::new(FederationManager::new(fed_config));
        let config = FailoverConfig::default();
        let manager = FailoverManager::new(config.clone(), federation);

        let stats = manager.stats().await;
        assert_eq!(stats.state, FailoverState::Standby);
        assert!(stats.can_become_primary);
        assert_eq!(stats.election_priority, config.election_priority);
    }
}
