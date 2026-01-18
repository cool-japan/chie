//! Database connection pool tuning for optimal performance.
//!
//! This module provides adaptive connection pool management that monitors
//! usage patterns and automatically adjusts pool settings to optimize
//! performance and resource utilization.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Connection pool tuning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolTuningConfig {
    /// Minimum number of connections in pool.
    pub min_connections: u32,

    /// Maximum number of connections in pool.
    pub max_connections: u32,

    /// Target connection utilization (0.0 to 1.0).
    pub target_utilization: f64,

    /// Enable adaptive tuning.
    pub enable_adaptive: bool,

    /// Tuning check interval in seconds.
    pub check_interval_secs: u64,

    /// Connection idle timeout in seconds.
    pub idle_timeout_secs: u64,

    /// Connection lifetime in seconds.
    pub max_lifetime_secs: u64,

    /// Connection acquisition timeout in milliseconds.
    pub acquire_timeout_ms: u64,

    /// Scale up threshold (utilization above this triggers increase).
    pub scale_up_threshold: f64,

    /// Scale down threshold (utilization below this triggers decrease).
    pub scale_down_threshold: f64,

    /// Maximum scaling step size.
    pub max_scale_step: u32,
}

impl Default for PoolTuningConfig {
    fn default() -> Self {
        Self {
            min_connections: 5,
            max_connections: 100,
            target_utilization: 0.7,
            enable_adaptive: true,
            check_interval_secs: 60,
            idle_timeout_secs: 600,  // 10 minutes
            max_lifetime_secs: 1800, // 30 minutes
            acquire_timeout_ms: 5000,
            scale_up_threshold: 0.8,
            scale_down_threshold: 0.4,
            max_scale_step: 10,
        }
    }
}

/// Connection pool statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolStats {
    /// Current number of active connections.
    pub active_connections: u32,

    /// Current number of idle connections.
    pub idle_connections: u32,

    /// Total connections in pool.
    pub total_connections: u32,

    /// Number of connection acquisitions.
    pub acquisitions: u64,

    /// Number of acquisition timeouts.
    pub acquisition_timeouts: u64,

    /// Average acquisition time in milliseconds.
    pub avg_acquisition_ms: f64,

    /// Peak connections used.
    pub peak_connections: u32,

    /// Number of connection errors.
    pub connection_errors: u64,

    /// Last tuning time (skipped in serialization).
    #[serde(skip)]
    pub last_tuning_time: Option<Instant>,

    /// Number of scale-up operations.
    pub scale_ups: u64,

    /// Number of scale-down operations.
    pub scale_downs: u64,
}

impl PoolStats {
    /// Calculate current utilization (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            self.active_connections as f64 / self.total_connections as f64
        }
    }

    /// Check if pool is healthy.
    pub fn is_healthy(&self) -> bool {
        self.acquisition_timeouts == 0 && self.connection_errors == 0
    }
}

/// Pool tuning recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TuningRecommendation {
    /// Increase pool size.
    ScaleUp { current: u32, recommended: u32 },

    /// Decrease pool size.
    ScaleDown { current: u32, recommended: u32 },

    /// No change needed.
    NoChange,
}

/// Connection pool tuner.
#[derive(Clone)]
pub struct PoolTuner {
    /// Configuration.
    config: PoolTuningConfig,

    /// Current statistics.
    stats: Arc<RwLock<PoolStats>>,

    /// Acquisition time samples (for averaging).
    acquisition_samples: Arc<RwLock<Vec<Duration>>>,
}

impl PoolTuner {
    /// Create a new pool tuner.
    pub fn new(config: PoolTuningConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(PoolStats::default())),
            acquisition_samples: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a connection acquisition.
    pub async fn record_acquisition(&self, duration: Duration) {
        let mut stats = self.stats.write().await;
        stats.acquisitions += 1;

        // Update average acquisition time
        let mut samples = self.acquisition_samples.write().await;
        samples.push(duration);

        // Keep only last 1000 samples
        if samples.len() > 1000 {
            let excess = samples.len() - 1000;
            samples.drain(0..excess);
        }

        stats.avg_acquisition_ms =
            samples.iter().map(|d| d.as_millis() as f64).sum::<f64>() / samples.len() as f64;

        drop(samples);

        if duration.as_millis() as u64 > self.config.acquire_timeout_ms {
            stats.acquisition_timeouts += 1;
            warn!("Connection acquisition timeout: {:?}", duration);
        }
    }

    /// Record connection pool state.
    pub async fn record_pool_state(&self, active: u32, idle: u32) {
        let mut stats = self.stats.write().await;
        stats.active_connections = active;
        stats.idle_connections = idle;
        stats.total_connections = active + idle;

        if stats.total_connections > stats.peak_connections {
            stats.peak_connections = stats.total_connections;
        }
    }

    /// Record a connection error.
    pub async fn record_error(&self) {
        self.stats.write().await.connection_errors += 1;
    }

    /// Get current statistics.
    pub async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    /// Get tuning recommendation based on current stats.
    pub async fn get_recommendation(&self) -> TuningRecommendation {
        let stats = self.stats.read().await;
        let utilization = stats.utilization();

        if !self.config.enable_adaptive {
            return TuningRecommendation::NoChange;
        }

        let current = stats.total_connections;

        // Scale up if utilization is high
        if utilization > self.config.scale_up_threshold {
            let desired_size = (current as f64 / self.config.target_utilization) as u32;
            let step = (desired_size - current).min(self.config.max_scale_step);
            let recommended = (current + step).min(self.config.max_connections);

            if recommended > current {
                info!(
                    "Pool tuning: Scale up recommended (utilization: {:.2}, {} -> {})",
                    utilization, current, recommended
                );
                return TuningRecommendation::ScaleUp {
                    current,
                    recommended,
                };
            }
        }

        // Scale down if utilization is low
        if utilization < self.config.scale_down_threshold {
            let desired_size = (current as f64 * self.config.target_utilization) as u32;
            let step = (current - desired_size).min(self.config.max_scale_step);
            let recommended = (current.saturating_sub(step)).max(self.config.min_connections);

            if recommended < current {
                info!(
                    "Pool tuning: Scale down recommended (utilization: {:.2}, {} -> {})",
                    utilization, current, recommended
                );
                return TuningRecommendation::ScaleDown {
                    current,
                    recommended,
                };
            }
        }

        debug!(
            "Pool tuning: No change needed (utilization: {:.2})",
            utilization
        );
        TuningRecommendation::NoChange
    }

    /// Apply a tuning recommendation (returns new pool size).
    pub async fn apply_recommendation(&self, recommendation: &TuningRecommendation) -> u32 {
        let mut stats = self.stats.write().await;
        stats.last_tuning_time = Some(Instant::now());

        match recommendation {
            TuningRecommendation::ScaleUp { recommended, .. } => {
                stats.scale_ups += 1;
                *recommended
            }
            TuningRecommendation::ScaleDown { recommended, .. } => {
                stats.scale_downs += 1;
                *recommended
            }
            TuningRecommendation::NoChange => stats.total_connections,
        }
    }

    /// Reset statistics.
    pub async fn reset_stats(&self) {
        *self.stats.write().await = PoolStats::default();
        self.acquisition_samples.write().await.clear();
    }

    /// Get pool configuration.
    pub fn config(&self) -> &PoolTuningConfig {
        &self.config
    }
}

/// Pool health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolHealthCheck {
    /// Health status.
    pub healthy: bool,

    /// Current pool size.
    pub pool_size: u32,

    /// Utilization percentage.
    pub utilization: f64,

    /// Average acquisition time in ms.
    pub avg_acquisition_ms: f64,

    /// Number of acquisition timeouts.
    pub acquisition_timeouts: u64,

    /// Number of connection errors.
    pub connection_errors: u64,

    /// Issues detected.
    pub issues: Vec<String>,
}

impl PoolTuner {
    /// Perform a health check.
    pub async fn health_check(&self) -> PoolHealthCheck {
        let stats = self.stats.read().await;
        let mut issues = Vec::new();

        // Check for acquisition timeouts
        if stats.acquisition_timeouts > 0 {
            issues.push(format!(
                "{} connection acquisition timeouts detected",
                stats.acquisition_timeouts
            ));
        }

        // Check for connection errors
        if stats.connection_errors > 0 {
            issues.push(format!(
                "{} connection errors detected",
                stats.connection_errors
            ));
        }

        // Check if utilization is too high
        let utilization = stats.utilization();
        if utilization > 0.9 {
            issues.push(format!(
                "High connection utilization: {:.1}%",
                utilization * 100.0
            ));
        }

        // Check if acquisition time is slow
        if stats.avg_acquisition_ms > 100.0 {
            issues.push(format!(
                "Slow connection acquisition: {:.1}ms average",
                stats.avg_acquisition_ms
            ));
        }

        PoolHealthCheck {
            healthy: issues.is_empty(),
            pool_size: stats.total_connections,
            utilization,
            avg_acquisition_ms: stats.avg_acquisition_ms,
            acquisition_timeouts: stats.acquisition_timeouts,
            connection_errors: stats.connection_errors,
            issues,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_stats_utilization() {
        let stats = PoolStats {
            active_connections: 7,
            idle_connections: 3,
            total_connections: 10,
            ..Default::default()
        };

        assert_eq!(stats.utilization(), 0.7);
    }

    #[tokio::test]
    async fn test_pool_stats_zero_connections() {
        let stats = PoolStats::default();
        assert_eq!(stats.utilization(), 0.0);
    }

    #[tokio::test]
    async fn test_scale_up_recommendation() {
        let config = PoolTuningConfig {
            min_connections: 5,
            max_connections: 50,
            target_utilization: 0.7,
            scale_up_threshold: 0.8,
            enable_adaptive: true,
            ..Default::default()
        };

        let tuner = PoolTuner::new(config);

        // Simulate high utilization (9 out of 10 connections active)
        tuner.record_pool_state(9, 1).await;

        let recommendation = tuner.get_recommendation().await;
        match recommendation {
            TuningRecommendation::ScaleUp {
                current,
                recommended,
            } => {
                assert_eq!(current, 10);
                assert!(recommended > current);
            }
            _ => panic!("Expected scale up recommendation"),
        }
    }

    #[tokio::test]
    async fn test_scale_down_recommendation() {
        let config = PoolTuningConfig {
            min_connections: 5,
            max_connections: 50,
            target_utilization: 0.7,
            scale_down_threshold: 0.4,
            enable_adaptive: true,
            ..Default::default()
        };

        let tuner = PoolTuner::new(config);

        // Simulate low utilization (2 out of 20 connections active)
        tuner.record_pool_state(2, 18).await;

        let recommendation = tuner.get_recommendation().await;
        match recommendation {
            TuningRecommendation::ScaleDown {
                current,
                recommended,
            } => {
                assert_eq!(current, 20);
                assert!(recommended < current);
                assert!(recommended >= 5); // Should respect min_connections
            }
            _ => panic!("Expected scale down recommendation"),
        }
    }

    #[tokio::test]
    async fn test_no_change_recommendation() {
        let config = PoolTuningConfig::default();
        let tuner = PoolTuner::new(config);

        // Simulate optimal utilization (7 out of 10 connections active = 70%)
        tuner.record_pool_state(7, 3).await;

        let recommendation = tuner.get_recommendation().await;
        match recommendation {
            TuningRecommendation::NoChange => {
                // Expected
            }
            _ => panic!("Expected no change recommendation"),
        }
    }

    #[tokio::test]
    async fn test_record_acquisition() {
        let config = PoolTuningConfig::default();
        let tuner = PoolTuner::new(config);

        tuner.record_acquisition(Duration::from_millis(50)).await;
        tuner.record_acquisition(Duration::from_millis(100)).await;

        let stats = tuner.stats().await;
        assert_eq!(stats.acquisitions, 2);
        assert_eq!(stats.avg_acquisition_ms, 75.0);
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let config = PoolTuningConfig::default();
        let tuner = PoolTuner::new(config);

        tuner.record_pool_state(5, 5).await;
        tuner.record_acquisition(Duration::from_millis(10)).await;

        let health = tuner.health_check().await;
        assert!(health.healthy);
        assert!(health.issues.is_empty());
    }

    #[tokio::test]
    async fn test_health_check_unhealthy() {
        let config = PoolTuningConfig::default();
        let tuner = PoolTuner::new(config);

        tuner.record_pool_state(9, 1).await; // High utilization
        tuner.record_acquisition(Duration::from_millis(150)).await; // Slow
        tuner.record_error().await;

        let health = tuner.health_check().await;
        assert!(!health.healthy);
        assert!(!health.issues.is_empty());
    }

    #[tokio::test]
    async fn test_apply_recommendation() {
        let config = PoolTuningConfig::default();
        let tuner = PoolTuner::new(config);

        let recommendation = TuningRecommendation::ScaleUp {
            current: 10,
            recommended: 15,
        };

        let new_size = tuner.apply_recommendation(&recommendation).await;
        assert_eq!(new_size, 15);

        let stats = tuner.stats().await;
        assert_eq!(stats.scale_ups, 1);
    }
}
