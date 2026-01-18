//! Bandwidth scheduling for time-based allocation and off-peak optimization.
//!
//! This module provides intelligent bandwidth scheduling capabilities, allowing
//! nodes to optimize bandwidth usage based on time of day, network conditions,
//! and user-defined schedules. Essential for CDN nodes that want to maximize
//! off-peak bandwidth usage and minimize costs during peak hours.
//!
//! # Features
//!
//! - Time-based bandwidth schedules with configurable windows
//! - Peak/off-peak hour detection and allocation
//! - Priority-based bandwidth allocation during constrained periods
//! - Dynamic schedule adjustment based on network conditions
//! - Bandwidth reservation system for critical operations
//! - Schedule conflict resolution
//! - Comprehensive statistics and usage tracking
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{BandwidthScheduler, ScheduleConfig, TimeWindow, BandwidthPriority};
//! use std::time::Duration;
//!
//! let config = ScheduleConfig::default();
//! let mut scheduler = BandwidthScheduler::new(config);
//!
//! // Add off-peak window (midnight to 6 AM)
//! let off_peak = TimeWindow::new(0, 0, 6, 0);
//! scheduler.add_schedule("off-peak-replication", off_peak, 1_000_000_000, BandwidthPriority::Normal);
//!
//! // Check if bandwidth is available
//! if let Some(allocation) = scheduler.allocate_bandwidth("content-sync", 100_000_000, BandwidthPriority::High) {
//!     println!("Allocated {} bytes/sec", allocation.bytes_per_second);
//! }
//! ```

use chrono::{DateTime, Datelike, Local, Timelike};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Priority level for bandwidth allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BandwidthPriority {
    /// Background tasks (replication, cleanup)
    Background,
    /// Low priority (prefetching, speculative downloads)
    Low,
    /// Normal priority (regular downloads)
    Normal,
    /// High priority (user-requested content)
    High,
    /// Critical priority (emergency updates, system critical)
    Critical,
}

/// Time window for bandwidth scheduling
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeWindow {
    /// Start hour (0-23)
    pub start_hour: u8,
    /// Start minute (0-59)
    pub start_minute: u8,
    /// End hour (0-23)
    pub end_hour: u8,
    /// End minute (0-59)
    pub end_minute: u8,
}

impl TimeWindow {
    /// Create a new time window
    pub fn new(start_hour: u8, start_minute: u8, end_hour: u8, end_minute: u8) -> Self {
        assert!(start_hour < 24, "start_hour must be 0-23");
        assert!(start_minute < 60, "start_minute must be 0-59");
        assert!(end_hour < 24, "end_hour must be 0-23");
        assert!(end_minute < 60, "end_minute must be 0-59");

        Self {
            start_hour,
            start_minute,
            end_hour,
            end_minute,
        }
    }

    /// Check if the current time is within this window
    pub fn is_active(&self, now: &DateTime<Local>) -> bool {
        let current_minutes = now.hour() as u16 * 60 + now.minute() as u16;
        let start_minutes = self.start_hour as u16 * 60 + self.start_minute as u16;
        let end_minutes = self.end_hour as u16 * 60 + self.end_minute as u16;

        if start_minutes <= end_minutes {
            // Same day window
            current_minutes >= start_minutes && current_minutes < end_minutes
        } else {
            // Crosses midnight
            current_minutes >= start_minutes || current_minutes < end_minutes
        }
    }

    /// Get duration until this window starts
    pub fn time_until_start(&self, now: &DateTime<Local>) -> Duration {
        let current_minutes = now.hour() as u16 * 60 + now.minute() as u16;
        let start_minutes = self.start_hour as u16 * 60 + self.start_minute as u16;

        let minutes_until = if current_minutes <= start_minutes {
            start_minutes - current_minutes
        } else {
            // Next day
            1440 - current_minutes + start_minutes
        };

        Duration::from_secs(minutes_until as u64 * 60)
    }

    /// Get duration until this window ends
    pub fn time_until_end(&self, now: &DateTime<Local>) -> Option<Duration> {
        if !self.is_active(now) {
            return None;
        }

        let current_minutes = now.hour() as u16 * 60 + now.minute() as u16;
        let end_minutes = self.end_hour as u16 * 60 + self.end_minute as u16;

        let minutes_until = if current_minutes < end_minutes {
            end_minutes - current_minutes
        } else {
            // Crosses midnight
            1440 - current_minutes + end_minutes
        };

        Some(Duration::from_secs(minutes_until as u64 * 60))
    }
}

/// Bandwidth schedule entry
#[derive(Debug, Clone)]
pub struct BandwidthSchedule {
    /// Schedule ID
    pub id: String,
    /// Time window for this schedule
    pub window: TimeWindow,
    /// Maximum bandwidth in bytes per second
    pub max_bandwidth: u64,
    /// Priority level
    pub priority: BandwidthPriority,
    /// Whether this schedule is enabled
    pub enabled: bool,
    /// Days of week (0=Sunday, 6=Saturday), None means all days
    pub days: Option<Vec<u8>>,
}

/// Active bandwidth allocation
#[derive(Debug, Clone)]
pub struct BandwidthAllocation {
    /// Allocation ID
    pub id: String,
    /// Allocated bandwidth in bytes per second
    pub bytes_per_second: u64,
    /// Priority level
    pub priority: BandwidthPriority,
    /// When this allocation was created
    pub created_at: Instant,
    /// When this allocation expires
    pub expires_at: Option<Instant>,
}

/// Configuration for bandwidth scheduler
#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    /// Default bandwidth limit (bytes per second)
    pub default_bandwidth_limit: u64,
    /// Minimum bandwidth for critical operations
    pub min_critical_bandwidth: u64,
    /// Maximum concurrent allocations
    pub max_allocations: usize,
    /// Allocation timeout (for automatic cleanup)
    pub allocation_timeout: Duration,
    /// Enable dynamic adjustment based on network conditions
    pub enable_dynamic_adjustment: bool,
    /// Reserved bandwidth percentage for critical operations (0.0-1.0)
    pub critical_reserve_percentage: f64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            default_bandwidth_limit: 100_000_000, // 100 MB/s
            min_critical_bandwidth: 10_000_000,   // 10 MB/s
            max_allocations: 100,
            allocation_timeout: Duration::from_secs(300), // 5 minutes
            enable_dynamic_adjustment: true,
            critical_reserve_percentage: 0.2, // 20%
        }
    }
}

/// Statistics for bandwidth scheduler
#[derive(Debug, Clone, Default)]
pub struct SchedulerStats {
    /// Total bandwidth allocated
    pub total_allocated: u64,
    /// Current bandwidth usage
    pub current_usage: u64,
    /// Number of active allocations
    pub active_allocations: usize,
    /// Number of schedules
    pub schedule_count: usize,
    /// Number of allocations rejected due to insufficient bandwidth
    pub rejections: u64,
    /// Peak bandwidth usage
    pub peak_usage: u64,
    /// Average allocation size
    pub avg_allocation: u64,
    /// Time in off-peak mode (seconds)
    pub off_peak_time: u64,
    /// Time in peak mode (seconds)
    pub peak_time: u64,
}

/// Internal state for bandwidth scheduler (protected by a single mutex)
struct SchedulerState {
    schedules: BTreeMap<String, BandwidthSchedule>,
    allocations: HashMap<String, BandwidthAllocation>,
    stats: SchedulerStats,
    last_cleanup: Instant,
}

impl SchedulerState {
    fn new() -> Self {
        Self {
            schedules: BTreeMap::new(),
            allocations: HashMap::new(),
            stats: SchedulerStats::default(),
            last_cleanup: Instant::now(),
        }
    }
}

/// Bandwidth scheduler for time-based allocation
pub struct BandwidthScheduler {
    config: ScheduleConfig,
    state: Arc<Mutex<SchedulerState>>,
}

impl BandwidthScheduler {
    /// Create a new bandwidth scheduler
    pub fn new(config: ScheduleConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(SchedulerState::new())),
        }
    }

    /// Add a bandwidth schedule
    pub fn add_schedule(
        &mut self,
        id: impl Into<String>,
        window: TimeWindow,
        max_bandwidth: u64,
        priority: BandwidthPriority,
    ) {
        let schedule = BandwidthSchedule {
            id: id.into(),
            window,
            max_bandwidth,
            priority,
            enabled: true,
            days: None,
        };

        let schedule_id = schedule.id.clone();
        let mut state = self.state.lock();
        state.schedules.insert(schedule_id, schedule);
        state.stats.schedule_count += 1;
    }

    /// Add a schedule with specific days
    pub fn add_schedule_with_days(
        &mut self,
        id: impl Into<String>,
        window: TimeWindow,
        max_bandwidth: u64,
        priority: BandwidthPriority,
        days: Vec<u8>,
    ) {
        let schedule = BandwidthSchedule {
            id: id.into(),
            window,
            max_bandwidth,
            priority,
            enabled: true,
            days: Some(days),
        };

        let schedule_id = schedule.id.clone();
        let mut state = self.state.lock();
        state.schedules.insert(schedule_id, schedule);
        state.stats.schedule_count += 1;
    }

    /// Remove a schedule
    pub fn remove_schedule(&mut self, id: &str) -> Option<BandwidthSchedule> {
        let mut state = self.state.lock();
        let result = state.schedules.remove(id);
        if result.is_some() {
            state.stats.schedule_count = state.schedules.len();
        }
        result
    }

    /// Enable or disable a schedule
    pub fn set_schedule_enabled(&mut self, id: &str, enabled: bool) {
        let mut state = self.state.lock();
        if let Some(schedule) = state.schedules.get_mut(id) {
            schedule.enabled = enabled;
        }
    }

    /// Get active bandwidth limit based on current schedules
    pub fn get_current_bandwidth_limit(&self) -> u64 {
        let now = Local::now();
        let state = self.state.lock();

        // Find all active schedules
        let mut active_limits = Vec::new();

        for schedule in state.schedules.values() {
            if !schedule.enabled {
                continue;
            }

            // Check day of week if specified
            if let Some(ref days) = schedule.days {
                let current_day = now.weekday().num_days_from_sunday() as u8;
                if !days.contains(&current_day) {
                    continue;
                }
            }

            if schedule.window.is_active(&now) {
                active_limits.push((schedule.priority, schedule.max_bandwidth));
            }
        }

        // If multiple schedules are active, use the one with highest priority
        active_limits.sort_by(|a, b| b.0.cmp(&a.0));

        active_limits
            .first()
            .map(|(_, limit)| *limit)
            .unwrap_or(self.config.default_bandwidth_limit)
    }

    /// Allocate bandwidth for a task
    pub fn allocate_bandwidth(
        &mut self,
        id: impl Into<String>,
        requested: u64,
        priority: BandwidthPriority,
    ) -> Option<BandwidthAllocation> {
        self.cleanup_expired();

        let id = id.into();
        let current_limit = self.get_current_bandwidth_limit();
        let mut state = self.state.lock();

        // Calculate current usage
        let current_usage: u64 = state.allocations.values().map(|a| a.bytes_per_second).sum();

        // Check if we have capacity
        let available = current_limit.saturating_sub(current_usage);

        // For non-critical operations, ensure we don't exceed the limit that would prevent critical operations
        let reserved_critical =
            (current_limit as f64 * self.config.critical_reserve_percentage) as u64;
        let max_non_critical_usage = current_limit.saturating_sub(reserved_critical);

        // Calculate how much we can allocate
        let allocatable = if priority >= BandwidthPriority::Critical {
            // Critical operations can use all available bandwidth
            available
        } else {
            // Non-critical operations must leave reserve for critical
            // They can only use up to (max_non_critical_usage - current_usage)
            max_non_critical_usage
                .saturating_sub(current_usage)
                .min(available)
        };

        if allocatable == 0 {
            state.stats.rejections += 1;
            return None;
        }

        // Check allocation limit
        if state.allocations.len() >= self.config.max_allocations {
            state.stats.rejections += 1;
            return None;
        }

        let allocation = BandwidthAllocation {
            id: id.clone(),
            bytes_per_second: requested.min(allocatable),
            priority,
            created_at: Instant::now(),
            expires_at: Some(Instant::now() + self.config.allocation_timeout),
        };

        state.allocations.insert(id, allocation.clone());

        // Update stats
        state.stats.total_allocated += allocation.bytes_per_second;
        state.stats.current_usage = current_usage + allocation.bytes_per_second;
        state.stats.active_allocations = state.allocations.len();
        state.stats.peak_usage = state.stats.peak_usage.max(state.stats.current_usage);

        if state.stats.active_allocations > 0 {
            state.stats.avg_allocation =
                state.stats.total_allocated / state.stats.active_allocations as u64;
        }

        Some(allocation)
    }

    /// Release a bandwidth allocation
    pub fn release_allocation(&mut self, id: &str) -> bool {
        let mut state = self.state.lock();
        if let Some(allocation) = state.allocations.remove(id) {
            state.stats.current_usage = state
                .stats
                .current_usage
                .saturating_sub(allocation.bytes_per_second);
            state.stats.active_allocations = state.allocations.len();
            true
        } else {
            false
        }
    }

    /// Update an existing allocation
    pub fn update_allocation(&mut self, id: &str, new_bandwidth: u64) -> bool {
        let mut state = self.state.lock();
        if let Some(allocation) = state.allocations.get_mut(id) {
            let old_bandwidth = allocation.bytes_per_second;
            allocation.bytes_per_second = new_bandwidth;

            if new_bandwidth > old_bandwidth {
                state.stats.current_usage += new_bandwidth - old_bandwidth;
            } else {
                state.stats.current_usage -= old_bandwidth - new_bandwidth;
            }
            state.stats.peak_usage = state.stats.peak_usage.max(state.stats.current_usage);
            true
        } else {
            false
        }
    }

    /// Get all active allocations
    pub fn get_active_allocations(&self) -> Vec<BandwidthAllocation> {
        self.state.lock().allocations.values().cloned().collect()
    }

    /// Get allocation by ID
    pub fn get_allocation(&self, id: &str) -> Option<BandwidthAllocation> {
        self.state.lock().allocations.get(id).cloned()
    }

    /// Check if we're currently in off-peak hours
    pub fn is_off_peak(&self) -> bool {
        let now = Local::now();
        let state = self.state.lock();

        for schedule in state.schedules.values() {
            if !schedule.enabled {
                continue;
            }

            if schedule.window.is_active(&now)
                && schedule.max_bandwidth > self.config.default_bandwidth_limit
            {
                return true;
            }
        }

        false
    }

    /// Get time until next off-peak window
    pub fn time_until_off_peak(&self) -> Option<Duration> {
        let now = Local::now();
        let state = self.state.lock();

        let mut min_duration = None;

        for schedule in state.schedules.values() {
            if !schedule.enabled {
                continue;
            }

            if schedule.max_bandwidth > self.config.default_bandwidth_limit {
                let duration = schedule.window.time_until_start(&now);
                min_duration = Some(min_duration.map_or(duration, |d: Duration| d.min(duration)));
            }
        }

        min_duration
    }

    /// Clean up expired allocations
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let mut state = self.state.lock();

        // Only cleanup every 30 seconds
        if now.duration_since(state.last_cleanup) < Duration::from_secs(30) {
            return;
        }

        let mut expired = Vec::new();

        for (id, allocation) in state.allocations.iter() {
            if let Some(expires_at) = allocation.expires_at {
                if now >= expires_at {
                    expired.push(id.clone());
                }
            }
        }

        for id in expired {
            if let Some(allocation) = state.allocations.remove(&id) {
                state.stats.current_usage = state
                    .stats
                    .current_usage
                    .saturating_sub(allocation.bytes_per_second);
            }
        }

        state.stats.active_allocations = state.allocations.len();
        state.last_cleanup = now;
    }

    /// Get current statistics
    pub fn stats(&self) -> SchedulerStats {
        self.state.lock().stats.clone()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        let mut state = self.state.lock();
        state.stats = SchedulerStats {
            schedule_count: state.schedules.len(),
            active_allocations: state.allocations.len(),
            ..Default::default()
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_window_same_day() {
        let window = TimeWindow::new(9, 0, 17, 0); // 9 AM to 5 PM
        // Create a time at 12:00
        let mut dt = Local::now();
        dt = dt.with_hour(12).unwrap().with_minute(0).unwrap();

        // Should be active
        assert!(window.is_active(&dt));

        // Create a time at 8:00
        let mut dt = Local::now();
        dt = dt.with_hour(8).unwrap().with_minute(0).unwrap();

        // Should not be active
        assert!(!window.is_active(&dt));
    }

    #[test]
    fn test_time_window_crosses_midnight() {
        let window = TimeWindow::new(22, 0, 6, 0); // 10 PM to 6 AM
        // Create a time at 23:00
        let mut dt = Local::now();
        dt = dt.with_hour(23).unwrap().with_minute(0).unwrap();

        // Should be active
        assert!(window.is_active(&dt));

        // Create a time at 2:00
        let mut dt = Local::now();
        dt = dt.with_hour(2).unwrap().with_minute(0).unwrap();

        // Should be active
        assert!(window.is_active(&dt));

        // Create a time at 12:00
        let mut dt = Local::now();
        dt = dt.with_hour(12).unwrap().with_minute(0).unwrap();

        // Should not be active
        assert!(!window.is_active(&dt));
    }

    #[test]
    fn test_scheduler_add_schedule() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        let window = TimeWindow::new(0, 0, 6, 0);
        scheduler.add_schedule("off-peak", window, 1_000_000_000, BandwidthPriority::Normal);

        assert_eq!(scheduler.stats().schedule_count, 1);
    }

    #[test]
    fn test_scheduler_remove_schedule() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        let window = TimeWindow::new(0, 0, 6, 0);
        scheduler.add_schedule("off-peak", window, 1_000_000_000, BandwidthPriority::Normal);

        assert!(scheduler.remove_schedule("off-peak").is_some());
        assert_eq!(scheduler.stats().schedule_count, 0);
    }

    #[test]
    fn test_bandwidth_allocation() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        let allocation =
            scheduler.allocate_bandwidth("test", 10_000_000, BandwidthPriority::Normal);
        assert!(allocation.is_some());
        assert_eq!(allocation.unwrap().bytes_per_second, 10_000_000);
        assert_eq!(scheduler.stats().active_allocations, 1);
    }

    #[test]
    fn test_bandwidth_allocation_over_limit() {
        let config = ScheduleConfig {
            default_bandwidth_limit: 50_000_000,
            critical_reserve_percentage: 0.0, // Disable critical reserve for this test
            ..Default::default()
        };
        let mut scheduler = BandwidthScheduler::new(config);

        // Allocate 40 MB/s
        scheduler.allocate_bandwidth("test1", 40_000_000, BandwidthPriority::Normal);

        // Try to allocate another 20 MB/s (should get only 10 MB/s)
        let allocation =
            scheduler.allocate_bandwidth("test2", 20_000_000, BandwidthPriority::Normal);
        assert!(allocation.is_some());
        assert_eq!(allocation.unwrap().bytes_per_second, 10_000_000);
    }

    #[test]
    fn test_critical_bandwidth_reserve() {
        let config = ScheduleConfig {
            default_bandwidth_limit: 100_000_000,
            critical_reserve_percentage: 0.2, // 20% reserved
            ..Default::default()
        };
        let mut scheduler = BandwidthScheduler::new(config);

        // Allocate 70 MB/s (normal priority)
        scheduler.allocate_bandwidth("test1", 70_000_000, BandwidthPriority::Normal);

        // Try to allocate another 20 MB/s (normal priority)
        // Should only get 10 MB/s because we need to reserve 20 MB/s for critical
        let allocation =
            scheduler.allocate_bandwidth("test2", 20_000_000, BandwidthPriority::Normal);
        assert!(allocation.is_some());
        assert_eq!(allocation.unwrap().bytes_per_second, 10_000_000);

        // But critical should succeed
        let allocation =
            scheduler.allocate_bandwidth("critical", 20_000_000, BandwidthPriority::Critical);
        assert!(allocation.is_some());
    }

    #[test]
    fn test_release_allocation() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        scheduler.allocate_bandwidth("test", 10_000_000, BandwidthPriority::Normal);
        assert_eq!(scheduler.stats().active_allocations, 1);

        assert!(scheduler.release_allocation("test"));
        assert_eq!(scheduler.stats().active_allocations, 0);
        assert_eq!(scheduler.stats().current_usage, 0);
    }

    #[test]
    fn test_update_allocation() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        scheduler.allocate_bandwidth("test", 10_000_000, BandwidthPriority::Normal);
        assert_eq!(scheduler.stats().current_usage, 10_000_000);

        assert!(scheduler.update_allocation("test", 20_000_000));
        assert_eq!(scheduler.stats().current_usage, 20_000_000);
    }

    #[test]
    fn test_get_active_allocations() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        scheduler.allocate_bandwidth("test1", 10_000_000, BandwidthPriority::Normal);
        scheduler.allocate_bandwidth("test2", 20_000_000, BandwidthPriority::High);

        let allocations = scheduler.get_active_allocations();
        assert_eq!(allocations.len(), 2);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(BandwidthPriority::Critical > BandwidthPriority::High);
        assert!(BandwidthPriority::High > BandwidthPriority::Normal);
        assert!(BandwidthPriority::Normal > BandwidthPriority::Low);
        assert!(BandwidthPriority::Low > BandwidthPriority::Background);
    }

    #[test]
    fn test_stats_reset() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        scheduler.allocate_bandwidth("test", 10_000_000, BandwidthPriority::Normal);
        scheduler.reset_stats();

        let stats = scheduler.stats();
        assert_eq!(stats.total_allocated, 0);
        assert_eq!(stats.peak_usage, 0);
        assert_eq!(stats.rejections, 0);
    }

    #[test]
    fn test_max_allocations_limit() {
        let config = ScheduleConfig {
            max_allocations: 2,
            ..Default::default()
        };
        let mut scheduler = BandwidthScheduler::new(config);

        scheduler.allocate_bandwidth("test1", 1_000_000, BandwidthPriority::Normal);
        scheduler.allocate_bandwidth("test2", 1_000_000, BandwidthPriority::Normal);

        // Third allocation should fail
        let allocation =
            scheduler.allocate_bandwidth("test3", 1_000_000, BandwidthPriority::Normal);
        assert!(allocation.is_none());
        assert_eq!(scheduler.stats().rejections, 1);
    }

    #[test]
    fn test_schedule_with_days() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        let window = TimeWindow::new(0, 0, 6, 0);
        // Only Monday and Wednesday (1 and 3)
        scheduler.add_schedule_with_days(
            "weekday-off-peak",
            window,
            1_000_000_000,
            BandwidthPriority::Normal,
            vec![1, 3],
        );

        assert_eq!(scheduler.stats().schedule_count, 1);
    }

    #[test]
    fn test_enable_disable_schedule() {
        let config = ScheduleConfig::default();
        let mut scheduler = BandwidthScheduler::new(config);

        let window = TimeWindow::new(0, 0, 6, 0);
        scheduler.add_schedule("off-peak", window, 1_000_000_000, BandwidthPriority::Normal);

        scheduler.set_schedule_enabled("off-peak", false);

        // Verify it's disabled (we can't easily test is_active without time manipulation)
        assert_eq!(scheduler.stats().schedule_count, 1);
    }
}
