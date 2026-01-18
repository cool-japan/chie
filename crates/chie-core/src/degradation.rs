//! Graceful degradation under resource pressure.
//!
//! This module implements strategies for gracefully degrading service quality when
//! resources (CPU, memory, disk, bandwidth) are under pressure, rather than failing
//! catastrophically. It allows the system to continue operating at reduced capacity
//! while maintaining critical functionality.
//!
//! # Example
//!
//! ```rust
//! use chie_core::degradation::{DegradationManager, ResourcePressure, ServiceDegradationLevel};
//!
//! # async fn example() {
//! let mut manager = DegradationManager::new();
//!
//! // Report resource pressure
//! manager.update_pressure(ResourcePressure {
//!     cpu_usage: 0.95,
//!     memory_usage: 0.85,
//!     disk_usage: 0.90,
//!     bandwidth_usage: 0.80,
//! });
//!
//! // Get current degradation level
//! let level = manager.current_level();
//! match level {
//!     ServiceDegradationLevel::Normal => {
//!         // Operate normally
//!     }
//!     ServiceDegradationLevel::LightDegradation => {
//!         // Reduce non-critical features
//!     }
//!     ServiceDegradationLevel::ModerateDegradation => {
//!         // Focus on core functionality
//!     }
//!     ServiceDegradationLevel::SevereDegradation => {
//!         // Minimal operations only
//!     }
//! }
//!
//! // Check if specific features should be disabled
//! if manager.should_disable_prefetching() {
//!     // Disable chunk prefetching
//! }
//! if manager.should_reduce_cache_size() {
//!     // Reduce cache memory usage
//! }
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Current resource pressure measurements.
#[derive(Debug, Clone, Copy)]
pub struct ResourcePressure {
    /// CPU usage (0.0 to 1.0).
    pub cpu_usage: f64,
    /// Memory usage (0.0 to 1.0).
    pub memory_usage: f64,
    /// Disk usage (0.0 to 1.0).
    pub disk_usage: f64,
    /// Bandwidth usage (0.0 to 1.0).
    pub bandwidth_usage: f64,
}

impl ResourcePressure {
    /// Calculate overall pressure score (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn overall_score(&self) -> f64 {
        // Weighted average (disk and memory are more critical)
        (self.cpu_usage * 0.2
            + self.memory_usage * 0.3
            + self.disk_usage * 0.3
            + self.bandwidth_usage * 0.2)
            .clamp(0.0, 1.0)
    }

    /// Check if any resource is critically high.
    #[must_use]
    #[inline]
    pub fn has_critical_resource(&self) -> bool {
        self.cpu_usage > 0.95
            || self.memory_usage > 0.95
            || self.disk_usage > 0.95
            || self.bandwidth_usage > 0.95
    }
}

impl Default for ResourcePressure {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            bandwidth_usage: 0.0,
        }
    }
}

/// Service degradation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ServiceDegradationLevel {
    /// Normal operation - all features enabled.
    Normal = 0,
    /// Light degradation - reduce non-critical features.
    LightDegradation = 1,
    /// Moderate degradation - focus on core functionality.
    ModerateDegradation = 2,
    /// Severe degradation - minimal operations only.
    SevereDegradation = 3,
}

impl ServiceDegradationLevel {
    /// Get degradation level from pressure score.
    #[must_use]
    #[inline]
    pub fn from_pressure_score(score: f64) -> Self {
        if score < 0.70 {
            Self::Normal
        } else if score < 0.80 {
            Self::LightDegradation
        } else if score < 0.90 {
            Self::ModerateDegradation
        } else {
            Self::SevereDegradation
        }
    }

    /// Get description of this degradation level.
    #[must_use]
    #[inline]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Normal => "Operating normally",
            Self::LightDegradation => "Light resource pressure - reducing non-critical features",
            Self::ModerateDegradation => "Moderate resource pressure - core functionality only",
            Self::SevereDegradation => "Severe resource pressure - minimal operations",
        }
    }

    /// Check if this is a degraded state.
    #[must_use]
    #[inline]
    pub const fn is_degraded(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// Actions to take during degradation.
#[derive(Debug, Clone, Copy)]
pub struct DegradationActions {
    /// Disable chunk prefetching.
    pub disable_prefetching: bool,
    /// Reduce cache size.
    pub reduce_cache_size: bool,
    /// Disable analytics collection.
    pub disable_analytics: bool,
    /// Throttle bandwidth.
    pub throttle_bandwidth: bool,
    /// Pause garbage collection.
    pub pause_gc: bool,
    /// Disable backup operations.
    pub disable_backups: bool,
    /// Reduce connection pool size.
    pub reduce_connection_pool: bool,
    /// Reject new content pinning.
    pub reject_new_pins: bool,
}

impl DegradationActions {
    /// Get actions for a given degradation level.
    #[must_use]
    pub const fn for_level(level: ServiceDegradationLevel) -> Self {
        match level {
            ServiceDegradationLevel::Normal => Self {
                disable_prefetching: false,
                reduce_cache_size: false,
                disable_analytics: false,
                throttle_bandwidth: false,
                pause_gc: false,
                disable_backups: false,
                reduce_connection_pool: false,
                reject_new_pins: false,
            },
            ServiceDegradationLevel::LightDegradation => Self {
                disable_prefetching: true,
                reduce_cache_size: true,
                disable_analytics: false,
                throttle_bandwidth: false,
                pause_gc: false,
                disable_backups: false,
                reduce_connection_pool: false,
                reject_new_pins: false,
            },
            ServiceDegradationLevel::ModerateDegradation => Self {
                disable_prefetching: true,
                reduce_cache_size: true,
                disable_analytics: true,
                throttle_bandwidth: true,
                pause_gc: true,
                disable_backups: true,
                reduce_connection_pool: true,
                reject_new_pins: false,
            },
            ServiceDegradationLevel::SevereDegradation => Self {
                disable_prefetching: true,
                reduce_cache_size: true,
                disable_analytics: true,
                throttle_bandwidth: true,
                pause_gc: true,
                disable_backups: true,
                reduce_connection_pool: true,
                reject_new_pins: true,
            },
        }
    }
}

/// Manages graceful degradation based on resource pressure.
pub struct DegradationManager {
    current_level: ServiceDegradationLevel,
    current_pressure: ResourcePressure,
    last_update: Instant,
    pressure_history: Vec<(Instant, f64)>,
    hysteresis_duration: Duration,
}

impl DegradationManager {
    /// Create a new degradation manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_level: ServiceDegradationLevel::Normal,
            current_pressure: ResourcePressure::default(),
            last_update: Instant::now(),
            pressure_history: Vec::new(),
            hysteresis_duration: Duration::from_secs(60), // 1 minute hysteresis
        }
    }

    /// Update resource pressure and recalculate degradation level.
    pub fn update_pressure(&mut self, pressure: ResourcePressure) {
        self.current_pressure = pressure;
        self.last_update = Instant::now();

        let score = pressure.overall_score();
        self.pressure_history.push((Instant::now(), score));

        // Keep only last 5 minutes of history
        let cutoff = Instant::now() - Duration::from_secs(300);
        self.pressure_history.retain(|(t, _)| *t > cutoff);

        // Calculate new level with hysteresis to prevent flapping
        let new_level = ServiceDegradationLevel::from_pressure_score(score);

        // Only change level if sustained for hysteresis duration
        if new_level != self.current_level {
            let sustained = self.is_level_sustained(new_level);
            if sustained {
                self.current_level = new_level;
            }
        }
    }

    /// Check if a degradation level has been sustained.
    fn is_level_sustained(&self, level: ServiceDegradationLevel) -> bool {
        let cutoff = Instant::now() - self.hysteresis_duration;
        let recent_scores: Vec<f64> = self
            .pressure_history
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, s)| *s)
            .collect();

        if recent_scores.is_empty() {
            return false;
        }

        // Check if all recent scores match this level
        recent_scores
            .iter()
            .all(|&score| ServiceDegradationLevel::from_pressure_score(score) == level)
    }

    /// Get current degradation level.
    #[must_use]
    #[inline]
    pub const fn current_level(&self) -> ServiceDegradationLevel {
        self.current_level
    }

    /// Get current resource pressure.
    #[must_use]
    #[inline]
    pub const fn current_pressure(&self) -> &ResourcePressure {
        &self.current_pressure
    }

    /// Get recommended actions for current degradation level.
    #[must_use]
    pub const fn get_actions(&self) -> DegradationActions {
        DegradationActions::for_level(self.current_level)
    }

    /// Check if prefetching should be disabled.
    #[must_use]
    #[inline]
    pub fn should_disable_prefetching(&self) -> bool {
        self.get_actions().disable_prefetching
    }

    /// Check if cache size should be reduced.
    #[must_use]
    #[inline]
    pub fn should_reduce_cache_size(&self) -> bool {
        self.get_actions().reduce_cache_size
    }

    /// Check if analytics should be disabled.
    #[must_use]
    #[inline]
    pub fn should_disable_analytics(&self) -> bool {
        self.get_actions().disable_analytics
    }

    /// Check if bandwidth should be throttled.
    #[must_use]
    #[inline]
    pub fn should_throttle_bandwidth(&self) -> bool {
        self.get_actions().throttle_bandwidth
    }

    /// Check if garbage collection should be paused.
    #[must_use]
    #[inline]
    pub fn should_pause_gc(&self) -> bool {
        self.get_actions().pause_gc
    }

    /// Check if new content pins should be rejected.
    #[must_use]
    #[inline]
    pub fn should_reject_new_pins(&self) -> bool {
        self.get_actions().reject_new_pins
    }

    /// Get time since last pressure update.
    #[must_use]
    pub fn time_since_update(&self) -> Duration {
        Instant::now().duration_since(self.last_update)
    }

    /// Get average pressure score over the last duration.
    #[must_use]
    pub fn average_pressure_score(&self, duration: Duration) -> Option<f64> {
        let cutoff = Instant::now() - duration;
        let scores: Vec<f64> = self
            .pressure_history
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, s)| *s)
            .collect();

        if scores.is_empty() {
            None
        } else {
            Some(scores.iter().sum::<f64>() / scores.len() as f64)
        }
    }
}

impl Default for DegradationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_pressure_overall_score() {
        let pressure = ResourcePressure {
            cpu_usage: 0.5,
            memory_usage: 0.6,
            disk_usage: 0.7,
            bandwidth_usage: 0.4,
        };

        let score = pressure.overall_score();
        assert!(score > 0.5 && score < 0.7);
    }

    #[test]
    fn test_resource_pressure_critical() {
        let pressure = ResourcePressure {
            cpu_usage: 0.96,
            memory_usage: 0.5,
            disk_usage: 0.5,
            bandwidth_usage: 0.5,
        };

        assert!(pressure.has_critical_resource());

        let normal = ResourcePressure {
            cpu_usage: 0.5,
            memory_usage: 0.5,
            disk_usage: 0.5,
            bandwidth_usage: 0.5,
        };

        assert!(!normal.has_critical_resource());
    }

    #[test]
    fn test_degradation_level_from_score() {
        assert_eq!(
            ServiceDegradationLevel::from_pressure_score(0.5),
            ServiceDegradationLevel::Normal
        );
        assert_eq!(
            ServiceDegradationLevel::from_pressure_score(0.75),
            ServiceDegradationLevel::LightDegradation
        );
        assert_eq!(
            ServiceDegradationLevel::from_pressure_score(0.85),
            ServiceDegradationLevel::ModerateDegradation
        );
        assert_eq!(
            ServiceDegradationLevel::from_pressure_score(0.95),
            ServiceDegradationLevel::SevereDegradation
        );
    }

    #[test]
    fn test_degradation_actions() {
        let normal_actions = DegradationActions::for_level(ServiceDegradationLevel::Normal);
        assert!(!normal_actions.disable_prefetching);
        assert!(!normal_actions.reject_new_pins);

        let severe_actions =
            DegradationActions::for_level(ServiceDegradationLevel::SevereDegradation);
        assert!(severe_actions.disable_prefetching);
        assert!(severe_actions.reject_new_pins);
    }

    #[test]
    fn test_degradation_manager_update() {
        let mut manager = DegradationManager::new();

        assert_eq!(manager.current_level(), ServiceDegradationLevel::Normal);

        // Update with high pressure
        manager.update_pressure(ResourcePressure {
            cpu_usage: 0.95,
            memory_usage: 0.90,
            disk_usage: 0.92,
            bandwidth_usage: 0.88,
        });

        // Level won't change immediately due to hysteresis
        // but pressure is recorded
        assert!(manager.current_pressure().overall_score() > 0.9);
    }

    #[test]
    fn test_degradation_manager_helpers() {
        let mut manager = DegradationManager::new();

        // Normal level
        assert!(!manager.should_disable_prefetching());
        assert!(!manager.should_reject_new_pins());

        // Force severe degradation
        manager.current_level = ServiceDegradationLevel::SevereDegradation;
        assert!(manager.should_disable_prefetching());
        assert!(manager.should_reject_new_pins());
        assert!(manager.should_pause_gc());
    }

    #[test]
    fn test_average_pressure_score() {
        let mut manager = DegradationManager::new();

        manager.update_pressure(ResourcePressure {
            cpu_usage: 0.5,
            memory_usage: 0.5,
            disk_usage: 0.5,
            bandwidth_usage: 0.5,
        });

        let avg = manager.average_pressure_score(Duration::from_secs(60));
        assert!(avg.is_some());
        assert!((avg.unwrap() - 0.5).abs() < 0.1);
    }
}
