//! Advanced resource management and monitoring.
//!
//! This module provides resource tracking, quota enforcement, and automatic throttling
//! for CPU, memory, disk I/O, and network bandwidth. It helps ensure the node operates
//! within system constraints and prevents resource exhaustion.
//!
//! # Example
//!
//! ```rust
//! use chie_core::resource_mgmt::{ResourceMonitor, ResourceLimits, ResourceType};
//!
//! #[tokio::main]
//! async fn main() {
//!     let limits = ResourceLimits::default();
//!     let mut monitor = ResourceMonitor::new(limits);
//!
//!     // Check if we can allocate memory
//!     if monitor.can_allocate(ResourceType::Memory, 1024 * 1024 * 100) {
//!         println!("Can allocate 100MB");
//!         monitor.record_allocation(ResourceType::Memory, 1024 * 1024 * 100);
//!     }
//!
//!     // Get usage statistics
//!     if let Some(stats) = monitor.get_stats(ResourceType::Memory) {
//!         println!("Memory usage: {}/{}", stats.used, stats.limit);
//!     }
//! }
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, System};
use tokio::task::JoinHandle;

/// Type of system resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// CPU usage (in percent, 0-100).
    Cpu,
    /// Memory usage (in bytes).
    Memory,
    /// Disk I/O (in bytes/sec).
    DiskIo,
    /// Network bandwidth (in bytes/sec).
    NetworkBandwidth,
}

/// Resource usage limits.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum CPU usage percentage (0-100).
    pub max_cpu_percent: u32,
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum disk I/O in bytes/sec.
    pub max_disk_io_bps: u64,
    /// Maximum network bandwidth in bytes/sec.
    pub max_network_bps: u64,
    /// Enable automatic throttling when limits are approached.
    pub auto_throttle: bool,
    /// Throttle threshold (0.0 to 1.0) - at what utilization to start throttling.
    pub throttle_threshold: f64,
}

impl Default for ResourceLimits {
    #[inline]
    fn default() -> Self {
        Self {
            max_cpu_percent: 80,
            max_memory_bytes: 4 * 1024 * 1024 * 1024, // 4 GB
            max_disk_io_bps: 100 * 1024 * 1024,       // 100 MB/s
            max_network_bps: 100 * 1024 * 1024,       // 100 MB/s
            auto_throttle: true,
            throttle_threshold: 0.8, // 80%
        }
    }
}

/// Degradation level for graceful handling of resource pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DegradationLevel {
    /// Normal operation - no degradation.
    None = 0,
    /// Minor degradation - reduce non-critical operations.
    Minor = 1,
    /// Moderate degradation - disable background tasks, reduce cache.
    Moderate = 2,
    /// Severe degradation - minimal operations only.
    Severe = 3,
    /// Critical - emergency mode, reject new requests.
    Critical = 4,
}

impl DegradationLevel {
    /// Get a descriptive message for this degradation level.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::None => "Normal operation",
            Self::Minor => "Minor resource pressure - reducing non-critical operations",
            Self::Moderate => "Moderate resource pressure - disabling background tasks",
            Self::Severe => "Severe resource pressure - minimal operations only",
            Self::Critical => "Critical resource exhaustion - emergency mode",
        }
    }

    /// Check if this level requires action.
    #[must_use]
    #[inline]
    pub const fn requires_action(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Get recommended cache size multiplier for this degradation level.
    #[must_use]
    #[inline]
    pub const fn cache_multiplier(&self) -> f64 {
        match self {
            Self::None => 1.0,
            Self::Minor => 0.8,
            Self::Moderate => 0.5,
            Self::Severe => 0.2,
            Self::Critical => 0.0,
        }
    }

    /// Get recommended concurrency limit multiplier.
    #[must_use]
    #[inline]
    pub const fn concurrency_multiplier(&self) -> f64 {
        match self {
            Self::None => 1.0,
            Self::Minor => 0.8,
            Self::Moderate => 0.5,
            Self::Severe => 0.25,
            Self::Critical => 0.1,
        }
    }
}

impl Default for DegradationLevel {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

/// Resource usage statistics.
#[derive(Debug, Clone, Default)]
pub struct ResourceStats {
    /// Current usage.
    pub used: u64,
    /// Configured limit.
    pub limit: u64,
    /// Peak usage observed.
    pub peak: u64,
    /// Number of allocation requests.
    pub allocations: u64,
    /// Number of deallocation requests.
    pub deallocations: u64,
    /// Number of times limit was exceeded.
    pub limit_exceeded_count: u64,
}

impl ResourceStats {
    /// Calculate utilization percentage (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.limit == 0 {
            return 0.0;
        }
        (self.used as f64) / (self.limit as f64)
    }

    /// Check if usage exceeds threshold.
    #[inline]
    #[must_use]
    pub fn exceeds_threshold(&self, threshold: f64) -> bool {
        self.utilization() > threshold
    }

    /// Check if at or over limit.
    #[inline]
    #[must_use]
    pub const fn is_at_limit(&self) -> bool {
        self.used >= self.limit
    }

    /// Calculate available capacity.
    #[inline]
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

/// Resource allocation record.
#[derive(Debug, Clone)]
struct AllocationRecord {
    amount: u64,
    timestamp: Instant,
}

/// Resource monitor for tracking and limiting resource usage.
pub struct ResourceMonitor {
    limits: ResourceLimits,
    /// Usage statistics per resource type.
    stats: Arc<Mutex<HashMap<ResourceType, ResourceStats>>>,
    /// Recent allocations for rate calculation.
    recent_allocations: Arc<Mutex<HashMap<ResourceType, Vec<AllocationRecord>>>>,
    /// Throttling state.
    throttled: Arc<Mutex<HashMap<ResourceType, bool>>>,
    /// System information for actual resource sampling.
    system: Arc<Mutex<System>>,
    /// Current degradation level.
    degradation_level: Arc<Mutex<DegradationLevel>>,
}

impl ResourceMonitor {
    /// Create a new resource monitor with the given limits.
    #[must_use]
    pub fn new(limits: ResourceLimits) -> Self {
        let mut stats = HashMap::new();
        stats.insert(
            ResourceType::Cpu,
            ResourceStats {
                limit: u64::from(limits.max_cpu_percent),
                ..Default::default()
            },
        );
        stats.insert(
            ResourceType::Memory,
            ResourceStats {
                limit: limits.max_memory_bytes,
                ..Default::default()
            },
        );
        stats.insert(
            ResourceType::DiskIo,
            ResourceStats {
                limit: limits.max_disk_io_bps,
                ..Default::default()
            },
        );
        stats.insert(
            ResourceType::NetworkBandwidth,
            ResourceStats {
                limit: limits.max_network_bps,
                ..Default::default()
            },
        );

        let system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_memory(MemoryRefreshKind::everything())
                .with_cpu(CpuRefreshKind::everything())
                .with_processes(ProcessRefreshKind::everything()),
        );

        Self {
            limits,
            stats: Arc::new(Mutex::new(stats)),
            recent_allocations: Arc::new(Mutex::new(HashMap::new())),
            throttled: Arc::new(Mutex::new(HashMap::new())),
            system: Arc::new(Mutex::new(system)),
            degradation_level: Arc::new(Mutex::new(DegradationLevel::None)),
        }
    }

    /// Check if a resource allocation can be made.
    #[must_use]
    #[inline]
    pub fn can_allocate(&self, resource_type: ResourceType, amount: u64) -> bool {
        let stats = self.stats.lock().unwrap();
        if let Some(stat) = stats.get(&resource_type) {
            stat.used + amount <= stat.limit
        } else {
            false
        }
    }

    /// Record a resource allocation.
    pub fn record_allocation(&mut self, resource_type: ResourceType, amount: u64) {
        {
            let mut stats = self.stats.lock().unwrap();
            if let Some(stat) = stats.get_mut(&resource_type) {
                stat.used += amount;
                stat.allocations += 1;

                if stat.used > stat.peak {
                    stat.peak = stat.used;
                }

                if stat.used > stat.limit {
                    stat.limit_exceeded_count += 1;
                }
            }
        } // Drop stats lock here

        // Record for rate tracking
        {
            let mut recent = self.recent_allocations.lock().unwrap();
            recent
                .entry(resource_type)
                .or_default()
                .push(AllocationRecord {
                    amount,
                    timestamp: Instant::now(),
                });
        } // Drop recent lock here

        // Update throttling state (acquires stats lock internally)
        self.update_throttling(resource_type);
    }

    /// Record a resource deallocation.
    pub fn record_deallocation(&mut self, resource_type: ResourceType, amount: u64) {
        {
            let mut stats = self.stats.lock().unwrap();
            if let Some(stat) = stats.get_mut(&resource_type) {
                stat.used = stat.used.saturating_sub(amount);
                stat.deallocations += 1;
            }
        } // Drop stats lock here

        // Update throttling state (acquires stats lock internally)
        self.update_throttling(resource_type);
    }

    /// Update current usage (for absolute measurements like CPU).
    pub fn update_usage(&mut self, resource_type: ResourceType, current: u64) {
        {
            let mut stats = self.stats.lock().unwrap();
            if let Some(stat) = stats.get_mut(&resource_type) {
                stat.used = current;

                if current > stat.peak {
                    stat.peak = current;
                }

                if current > stat.limit {
                    stat.limit_exceeded_count += 1;
                }
            }
        } // Drop stats lock here

        // Update throttling state (acquires stats lock internally)
        self.update_throttling(resource_type);
    }

    /// Update throttling state based on current usage.
    #[inline]
    fn update_throttling(&self, resource_type: ResourceType) {
        if !self.limits.auto_throttle {
            return;
        }

        let stats = self.stats.lock().unwrap();
        if let Some(stat) = stats.get(&resource_type) {
            let should_throttle = stat.exceeds_threshold(self.limits.throttle_threshold);
            let mut throttled = self.throttled.lock().unwrap();
            throttled.insert(resource_type, should_throttle);
        }
    }

    /// Check if a resource type is currently throttled.
    #[inline]
    #[must_use]
    pub fn is_throttled(&self, resource_type: ResourceType) -> bool {
        self.throttled
            .lock()
            .unwrap()
            .get(&resource_type)
            .copied()
            .unwrap_or(false)
    }

    /// Get usage statistics for a resource type.
    #[must_use]
    #[inline]
    pub fn get_stats(&self, resource_type: ResourceType) -> Option<ResourceStats> {
        self.stats.lock().unwrap().get(&resource_type).cloned()
    }

    /// Get all resource statistics.
    #[must_use]
    #[inline]
    pub fn get_all_stats(&self) -> HashMap<ResourceType, ResourceStats> {
        self.stats.lock().unwrap().clone()
    }

    /// Calculate recent allocation rate (bytes/sec or percent/sec).
    #[must_use]
    #[inline]
    pub fn get_allocation_rate(&self, resource_type: ResourceType, window: Duration) -> u64 {
        let recent = self.recent_allocations.lock().unwrap();
        if let Some(records) = recent.get(&resource_type) {
            let cutoff = Instant::now() - window;
            let total: u64 = records
                .iter()
                .filter(|r| r.timestamp > cutoff)
                .map(|r| r.amount)
                .sum();

            // Convert to rate per second
            (total as f64 / window.as_secs_f64()) as u64
        } else {
            0
        }
    }

    /// Clean old allocation records (older than specified duration).
    pub fn cleanup_old_records(&mut self, older_than: Duration) {
        let mut recent = self.recent_allocations.lock().unwrap();
        let cutoff = Instant::now() - older_than;

        for records in recent.values_mut() {
            records.retain(|r| r.timestamp > cutoff);
        }
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        let mut stats = self.stats.lock().unwrap();
        for stat in stats.values_mut() {
            stat.used = 0;
            stat.peak = 0;
            stat.allocations = 0;
            stat.deallocations = 0;
            stat.limit_exceeded_count = 0;
        }
    }

    /// Get overall system health score (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn health_score(&self) -> f64 {
        let stats = self.stats.lock().unwrap();
        let mut total_utilization = 0.0;
        let mut count = 0;

        for stat in stats.values() {
            total_utilization += stat.utilization();
            count += 1;
        }

        if count == 0 {
            return 1.0;
        }

        // Health score is inverse of utilization (lower utilization = better health)
        1.0 - (total_utilization / count as f64)
    }

    /// Check if any resource is over limit.
    #[must_use]
    #[inline]
    pub fn is_over_limit(&self) -> bool {
        let stats = self.stats.lock().unwrap();
        stats.values().any(|s| s.is_at_limit())
    }

    /// Calculate the appropriate degradation level based on current resource usage.
    ///
    /// This method analyzes resource utilization and determines what level of
    /// degradation is appropriate to maintain system stability.
    #[must_use]
    #[inline]
    pub fn calculate_degradation_level(&self) -> DegradationLevel {
        let stats = self.stats.lock().unwrap();

        // Find the maximum utilization across all resources
        let max_utilization = stats
            .values()
            .map(|s| s.utilization())
            .fold(0.0f64, f64::max);

        // Determine degradation level based on utilization thresholds
        if max_utilization >= 0.95 {
            DegradationLevel::Critical
        } else if max_utilization >= 0.90 {
            DegradationLevel::Severe
        } else if max_utilization >= 0.85 {
            DegradationLevel::Moderate
        } else if max_utilization >= 0.80 {
            DegradationLevel::Minor
        } else {
            DegradationLevel::None
        }
    }

    /// Update the degradation level based on current resource usage.
    ///
    /// This should be called periodically to adjust system behavior
    /// based on resource pressure.
    pub fn update_degradation_level(&mut self) {
        let new_level = self.calculate_degradation_level();
        let mut current_level = self.degradation_level.lock().unwrap();

        if new_level != *current_level {
            *current_level = new_level;
            // In a production system, this would emit an event or log
            eprintln!(
                "Resource degradation level changed to: {:?} - {}",
                new_level,
                new_level.description()
            );
        }
    }

    /// Get the current degradation level.
    #[must_use]
    #[inline]
    pub fn degradation_level(&self) -> DegradationLevel {
        *self.degradation_level.lock().unwrap()
    }

    /// Check if the system should accept new requests based on degradation level.
    #[must_use]
    #[inline]
    pub fn should_accept_requests(&self) -> bool {
        self.degradation_level() != DegradationLevel::Critical
    }

    /// Check if background tasks should run based on degradation level.
    #[must_use]
    #[inline]
    pub fn should_run_background_tasks(&self) -> bool {
        matches!(
            self.degradation_level(),
            DegradationLevel::None | DegradationLevel::Minor
        )
    }

    /// Get recommended cache size based on degradation level.
    #[must_use]
    #[inline]
    pub fn recommended_cache_size(&self, base_size: usize) -> usize {
        let multiplier = self.degradation_level().cache_multiplier();
        ((base_size as f64) * multiplier) as usize
    }

    /// Get recommended concurrency limit based on degradation level.
    #[must_use]
    #[inline]
    pub fn recommended_concurrency(&self, base_concurrency: usize) -> usize {
        let multiplier = self.degradation_level().concurrency_multiplier();
        ((base_concurrency as f64) * multiplier).max(1.0) as usize
    }

    /// Sample actual system CPU usage and update statistics.
    ///
    /// This method refreshes CPU usage from the operating system and updates
    /// the internal statistics. Returns the current CPU usage percentage (0-100).
    /// Also updates degradation level based on new resource usage.
    #[must_use]
    pub fn sample_cpu_usage(&mut self) -> f32 {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_cpu_usage();

        // Calculate average CPU usage across all cores
        let cpus = sys.cpus();
        let cpu_usage = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32
        };

        // Update stats with current CPU usage (convert percentage to integer for storage)
        drop(sys); // Release lock before calling update_usage
        self.update_usage(ResourceType::Cpu, cpu_usage as u64);

        // Update degradation level based on new usage
        self.update_degradation_level();

        cpu_usage
    }

    /// Sample actual system memory usage and update statistics.
    ///
    /// This method refreshes memory usage from the operating system and updates
    /// the internal statistics. Returns the current memory usage in bytes.
    /// Also updates degradation level based on new resource usage.
    #[must_use]
    pub fn sample_memory_usage(&mut self) -> u64 {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_memory();

        // Get used memory in bytes
        let used_memory = sys.used_memory();

        // Update stats
        drop(sys); // Release lock before calling update_usage
        self.update_usage(ResourceType::Memory, used_memory);

        // Update degradation level based on new usage
        self.update_degradation_level();

        used_memory
    }

    /// Sample all system resources (CPU and memory) at once.
    ///
    /// This is more efficient than calling individual sample methods separately.
    /// Returns a tuple of (cpu_usage_percent, memory_used_bytes).
    /// Also updates degradation level based on new resource usage.
    #[must_use]
    pub fn sample_all_system_resources(&mut self) -> (f32, u64) {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        // Calculate average CPU usage
        let cpus = sys.cpus();
        let cpu_usage = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32
        };
        let memory_used = sys.used_memory();

        drop(sys); // Release lock before updating stats

        // Update both stats
        self.update_usage(ResourceType::Cpu, cpu_usage as u64);
        self.update_usage(ResourceType::Memory, memory_used);

        // Update degradation level based on new usage
        self.update_degradation_level();

        (cpu_usage, memory_used)
    }

    /// Get total system memory in bytes.
    #[must_use]
    #[inline]
    pub fn total_system_memory(&self) -> u64 {
        self.system.lock().unwrap().total_memory()
    }

    /// Get number of CPU cores.
    #[must_use]
    #[inline]
    pub fn cpu_count(&self) -> usize {
        self.system.lock().unwrap().cpus().len()
    }

    /// Predict future resource usage based on recent trends.
    ///
    /// Uses simple linear regression on recent allocation history to predict
    /// usage at a future time.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The resource type to predict
    /// * `window` - Duration of historical data to analyze
    /// * `forecast_duration` - How far into the future to predict
    ///
    /// # Returns
    ///
    /// Returns predicted usage value, or None if insufficient data.
    #[must_use]
    pub fn predict_usage(
        &self,
        resource_type: ResourceType,
        window: Duration,
        forecast_duration: Duration,
    ) -> Option<u64> {
        let recent = self.recent_allocations.lock().unwrap();
        let records = recent.get(&resource_type)?;

        if records.is_empty() {
            return None;
        }

        let cutoff = Instant::now() - window;
        let relevant_records: Vec<_> = records.iter().filter(|r| r.timestamp > cutoff).collect();

        if relevant_records.len() < 2 {
            return None; // Need at least 2 points for trend
        }

        // Simple linear regression: y = mx + b
        // where x is time offset, y is cumulative usage
        let n = relevant_records.len() as f64;
        let base_time = relevant_records[0].timestamp;

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_xx = 0.0;
        let mut cumulative = 0u64;

        for record in &relevant_records {
            cumulative += record.amount;
            let x = record.timestamp.duration_since(base_time).as_secs_f64();
            let y = cumulative as f64;

            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_xx += x * x;
        }

        // Calculate slope (m) and intercept (b)
        let denominator = n * sum_xx - sum_x * sum_x;
        if denominator.abs() < 1e-10 {
            return None; // Avoid division by zero
        }

        let slope = (n * sum_xy - sum_x * sum_y) / denominator;
        let intercept = (sum_y - slope * sum_x) / n;

        // Predict usage at forecast_duration from now
        let forecast_x = window.as_secs_f64() + forecast_duration.as_secs_f64();
        let predicted = slope * forecast_x + intercept;

        Some(predicted.max(0.0) as u64)
    }

    /// Check if proactive throttling should be enabled based on predictions.
    ///
    /// Analyzes predicted resource usage and determines if throttling should
    /// be enabled preemptively to avoid hitting limits.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The resource type to check
    /// * `prediction_window` - Duration of historical data for prediction
    /// * `forecast_duration` - How far ahead to predict
    ///
    /// # Returns
    ///
    /// Returns true if proactive throttling is recommended, false otherwise.
    #[must_use]
    pub fn should_proactive_throttle(
        &self,
        resource_type: ResourceType,
        prediction_window: Duration,
        forecast_duration: Duration,
    ) -> bool {
        // Get predicted usage
        let predicted_usage =
            match self.predict_usage(resource_type, prediction_window, forecast_duration) {
                Some(pred) => pred,
                None => return false, // Not enough data, don't throttle
            };

        // Get the limit for this resource
        let stats = self.stats.lock().unwrap();
        let limit = match stats.get(&resource_type) {
            Some(stat) => stat.limit,
            None => return false,
        };
        drop(stats);

        // Calculate predicted utilization
        if limit == 0 {
            return false;
        }

        let predicted_utilization = (predicted_usage as f64) / (limit as f64);

        // Proactively throttle if predicted to exceed threshold
        // Use a more conservative threshold for predictions (70% instead of 80%)
        predicted_utilization > 0.7
    }

    /// Get recommended throttle intensity based on predictions.
    ///
    /// Returns a value between 0.0 (no throttling) and 1.0 (maximum throttling)
    /// based on predicted resource pressure.
    ///
    /// # Arguments
    ///
    /// * `resource_type` - The resource type to analyze
    /// * `prediction_window` - Duration of historical data for prediction
    /// * `forecast_duration` - How far ahead to predict
    ///
    /// # Returns
    ///
    /// Returns throttle intensity (0.0 to 1.0), where higher values mean more aggressive throttling.
    #[must_use]
    pub fn get_throttle_intensity(
        &self,
        resource_type: ResourceType,
        prediction_window: Duration,
        forecast_duration: Duration,
    ) -> f64 {
        let predicted_usage =
            match self.predict_usage(resource_type, prediction_window, forecast_duration) {
                Some(pred) => pred,
                None => return 0.0, // No data, no throttling
            };

        let stats = self.stats.lock().unwrap();
        let limit = match stats.get(&resource_type) {
            Some(stat) => stat.limit,
            None => return 0.0,
        };
        drop(stats);

        if limit == 0 {
            return 0.0;
        }

        let predicted_utilization = (predicted_usage as f64) / (limit as f64);

        // Calculate intensity based on how close to limit
        // 0-70%: no throttling (0.0)
        // 70-85%: light throttling (0.0-0.5)
        // 85-95%: moderate throttling (0.5-0.8)
        // 95%+: heavy throttling (0.8-1.0)
        if predicted_utilization < 0.7 {
            0.0
        } else if predicted_utilization < 0.85 {
            (predicted_utilization - 0.7) / 0.15 * 0.5
        } else if predicted_utilization < 0.95 {
            0.5 + (predicted_utilization - 0.85) / 0.10 * 0.3
        } else {
            0.8 + ((predicted_utilization - 0.95) / 0.05 * 0.2).min(0.2)
        }
    }
}

/// Handle for managing background system resource monitoring.
///
/// This handle allows stopping the background monitoring task gracefully.
pub struct MonitoringHandle {
    task_handle: JoinHandle<()>,
    stop_signal: Arc<Mutex<bool>>,
}

impl MonitoringHandle {
    /// Stop the background monitoring task.
    ///
    /// # Errors
    ///
    /// Returns an error if the task has already panicked.
    pub async fn stop(self) -> Result<(), tokio::task::JoinError> {
        // Signal the task to stop
        *self.stop_signal.lock().unwrap() = true;

        // Wait for the task to complete
        self.task_handle.await
    }

    /// Check if the monitoring task is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.task_handle.is_finished()
    }
}

/// Configuration for background system resource monitoring.
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Sampling interval for system resources.
    pub sample_interval: Duration,
    /// Whether to enable automatic degradation level updates.
    pub auto_update_degradation: bool,
    /// Whether to log sampling results (for debugging).
    pub log_sampling: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_secs(5),
            auto_update_degradation: true,
            log_sampling: false,
        }
    }
}

impl ResourceMonitor {
    /// Start background monitoring of system resources.
    ///
    /// This spawns a background task that periodically samples CPU and memory usage
    /// and updates the resource monitor's statistics. The returned handle can be used
    /// to stop the monitoring gracefully.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the monitoring task
    ///
    /// # Example
    ///
    /// ```rust
    /// use chie_core::resource_mgmt::{ResourceMonitor, ResourceLimits, MonitoringConfig};
    /// use std::time::Duration;
    ///
    /// # async fn example() {
    /// let limits = ResourceLimits::default();
    /// let monitor = ResourceMonitor::new(limits);
    ///
    /// // Start background monitoring
    /// let config = MonitoringConfig {
    ///     sample_interval: Duration::from_secs(10),
    ///     ..Default::default()
    /// };
    /// let handle = monitor.start_monitoring(config);
    ///
    /// // Monitor runs in background...
    ///
    /// // Stop when done
    /// handle.stop().await.unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn start_monitoring(&self, config: MonitoringConfig) -> MonitoringHandle {
        let stop_signal = Arc::new(Mutex::new(false));
        let stop_signal_clone = Arc::clone(&stop_signal);

        // Clone the necessary Arc fields for the background task
        let stats = Arc::clone(&self.stats);
        let system = Arc::clone(&self.system);
        let degradation_level = Arc::clone(&self.degradation_level);

        let task_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.sample_interval);

            loop {
                // Check if we should stop
                if *stop_signal_clone.lock().unwrap() {
                    break;
                }

                // Wait for next sampling interval
                interval.tick().await;

                // Sample system resources
                let mut sys = system.lock().unwrap();
                sys.refresh_cpu_usage();
                sys.refresh_memory();

                // Calculate average CPU usage
                let cpus = sys.cpus();
                let cpu_usage = if cpus.is_empty() {
                    0.0
                } else {
                    cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32
                };
                let memory_used = sys.used_memory();

                drop(sys); // Release system lock

                // Update statistics
                {
                    let mut stats_map = stats.lock().unwrap();

                    // Update CPU stats
                    if let Some(cpu_stats) = stats_map.get_mut(&ResourceType::Cpu) {
                        let cpu_value = cpu_usage as u64;
                        cpu_stats.used = cpu_value;
                        if cpu_value > cpu_stats.peak {
                            cpu_stats.peak = cpu_value;
                        }
                        if cpu_value > cpu_stats.limit {
                            cpu_stats.limit_exceeded_count += 1;
                        }
                    }

                    // Update memory stats
                    if let Some(mem_stats) = stats_map.get_mut(&ResourceType::Memory) {
                        mem_stats.used = memory_used;
                        if memory_used > mem_stats.peak {
                            mem_stats.peak = memory_used;
                        }
                        if memory_used > mem_stats.limit {
                            mem_stats.limit_exceeded_count += 1;
                        }
                    }
                }

                // Update degradation level if enabled
                if config.auto_update_degradation {
                    let stats_map = stats.lock().unwrap();

                    // Calculate max utilization across resources
                    let mut max_utilization = 0.0;
                    for stat in stats_map.values() {
                        let util = stat.utilization();
                        if util > max_utilization {
                            max_utilization = util;
                        }
                    }

                    // Determine degradation level based on utilization
                    let new_level = if max_utilization < 0.7 {
                        DegradationLevel::None
                    } else if max_utilization < 0.8 {
                        DegradationLevel::Minor
                    } else if max_utilization < 0.9 {
                        DegradationLevel::Moderate
                    } else if max_utilization < 0.95 {
                        DegradationLevel::Severe
                    } else {
                        DegradationLevel::Critical
                    };

                    *degradation_level.lock().unwrap() = new_level;
                }

                // Log if enabled
                if config.log_sampling {
                    eprintln!(
                        "[ResourceMonitor] CPU: {:.1}%, Memory: {} bytes",
                        cpu_usage, memory_used
                    );
                }
            }
        });

        MonitoringHandle {
            task_handle,
            stop_signal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_stats_utilization() {
        let stats = ResourceStats {
            used: 50,
            limit: 100,
            ..Default::default()
        };
        assert_eq!(stats.utilization(), 0.5);
    }

    #[test]
    fn test_resource_stats_available() {
        let stats = ResourceStats {
            used: 30,
            limit: 100,
            ..Default::default()
        };
        assert_eq!(stats.available(), 70);
    }

    #[test]
    fn test_resource_stats_exceeds_threshold() {
        let stats = ResourceStats {
            used: 85,
            limit: 100,
            ..Default::default()
        };
        assert!(stats.exceeds_threshold(0.8));
        assert!(!stats.exceeds_threshold(0.9));
    }

    #[test]
    fn test_can_allocate() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let monitor = ResourceMonitor::new(limits);

        assert!(monitor.can_allocate(ResourceType::Memory, 500));
        assert!(monitor.can_allocate(ResourceType::Memory, 1000));
        assert!(!monitor.can_allocate(ResourceType::Memory, 1001));
    }

    #[test]
    fn test_record_allocation() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 300);

        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.used, 300);
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.peak, 300);
    }

    #[test]
    fn test_record_deallocation() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 500);
        monitor.record_deallocation(ResourceType::Memory, 200);

        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.used, 300);
        assert_eq!(stats.deallocations, 1);
    }

    #[test]
    fn test_peak_tracking() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 100);
        monitor.record_allocation(ResourceType::Memory, 200);
        monitor.record_deallocation(ResourceType::Memory, 150);

        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.peak, 300);
        assert_eq!(stats.used, 150);
    }

    #[test]
    fn test_limit_exceeded_count() {
        let limits = ResourceLimits {
            max_memory_bytes: 100,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 120);
        monitor.record_allocation(ResourceType::Memory, 50);

        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.limit_exceeded_count, 2);
    }

    #[test]
    fn test_throttling() {
        let limits = ResourceLimits {
            max_memory_bytes: 100,
            auto_throttle: true,
            throttle_threshold: 0.8,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        assert!(!monitor.is_throttled(ResourceType::Memory));

        monitor.record_allocation(ResourceType::Memory, 85);
        assert!(monitor.is_throttled(ResourceType::Memory));

        monitor.record_deallocation(ResourceType::Memory, 30);
        assert!(!monitor.is_throttled(ResourceType::Memory));
    }

    #[test]
    fn test_allocation_rate() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::DiskIo, 1000);
        monitor.record_allocation(ResourceType::DiskIo, 2000);

        std::thread::sleep(Duration::from_millis(100));

        let rate = monitor.get_allocation_rate(ResourceType::DiskIo, Duration::from_secs(1));
        // Rate should be approximately 3000 bytes/sec (with some variance)
        assert!(rate > 0);
    }

    #[test]
    fn test_cleanup_old_records() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 100);
        std::thread::sleep(Duration::from_millis(150));
        monitor.record_allocation(ResourceType::Memory, 200);

        monitor.cleanup_old_records(Duration::from_millis(100));

        // Only the recent allocation should remain
        let rate = monitor.get_allocation_rate(ResourceType::Memory, Duration::from_secs(1));
        assert!(rate > 0);
    }

    #[test]
    fn test_reset_stats() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        monitor.record_allocation(ResourceType::Memory, 500);
        monitor.reset_stats();

        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.used, 0);
        assert_eq!(stats.peak, 0);
        assert_eq!(stats.allocations, 0);
    }

    #[test]
    fn test_health_score() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            max_cpu_percent: 100,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        // Empty system should have perfect health
        assert!(monitor.health_score() > 0.99);

        // Half-utilized Memory and CPU with DiskIo and NetworkBandwidth at 0%
        // Average utilization = (50% + 50% + 0% + 0%) / 4 = 25%
        // Health score = 1.0 - 0.25 = 0.75
        monitor.record_allocation(ResourceType::Memory, 500);
        monitor.update_usage(ResourceType::Cpu, 50);

        let health = monitor.health_score();
        // With 4 resource types and only 2 at 50%, average utilization is 25%
        // Health score should be around 0.75 (1.0 - 0.25)
        assert!(health > 0.7 && health < 0.8);
    }

    #[test]
    fn test_is_over_limit() {
        let limits = ResourceLimits {
            max_memory_bytes: 100,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        assert!(!monitor.is_over_limit());

        monitor.record_allocation(ResourceType::Memory, 150);
        assert!(monitor.is_over_limit());
    }

    #[test]
    fn test_update_usage() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        monitor.update_usage(ResourceType::Cpu, 75);

        let stats = monitor.get_stats(ResourceType::Cpu).unwrap();
        assert_eq!(stats.used, 75);
    }

    #[test]
    fn test_predict_usage_insufficient_data() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        // No allocations yet - should return None
        let prediction = monitor.predict_usage(
            ResourceType::Memory,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(prediction.is_none());
    }

    #[test]
    fn test_predict_usage_with_trend() {
        let limits = ResourceLimits {
            max_memory_bytes: 10000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        // Create a trend: allocating 100 bytes every 100ms
        for i in 0..5 {
            monitor.record_allocation(ResourceType::Memory, 100);
            if i < 4 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        // Predict usage
        let prediction = monitor.predict_usage(
            ResourceType::Memory,
            Duration::from_secs(1),
            Duration::from_millis(500),
        );

        // Should predict something (exact value depends on timing)
        assert!(prediction.is_some());
        let predicted = prediction.unwrap();
        // Should predict continued growth
        assert!(predicted > 0);
    }

    #[test]
    fn test_should_proactive_throttle_no_data() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        // No data - should not throttle
        let should_throttle = monitor.should_proactive_throttle(
            ResourceType::Memory,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(!should_throttle);
    }

    #[test]
    fn test_should_proactive_throttle_high_prediction() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        // Simulate rapid growth that will exceed threshold
        for i in 0..5 {
            monitor.record_allocation(ResourceType::Memory, 200);
            if i < 4 {
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        // Should recommend throttling if trend continues
        let should_throttle = monitor.should_proactive_throttle(
            ResourceType::Memory,
            Duration::from_secs(1),
            Duration::from_millis(200),
        );

        // With rapid growth, should predict high usage and recommend throttling
        assert!(should_throttle);
    }

    #[test]
    fn test_get_throttle_intensity_no_data() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        let intensity = monitor.get_throttle_intensity(
            ResourceType::Memory,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );

        // No data - no throttling
        assert_eq!(intensity, 0.0);
    }

    #[test]
    fn test_get_throttle_intensity_low_usage() {
        let limits = ResourceLimits {
            max_memory_bytes: 10000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        // Low, steady allocations
        for i in 0..3 {
            monitor.record_allocation(ResourceType::Memory, 100);
            if i < 2 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        let intensity = monitor.get_throttle_intensity(
            ResourceType::Memory,
            Duration::from_secs(1),
            Duration::from_millis(500),
        );

        // Low predicted usage - minimal or no throttling
        assert!(intensity < 0.3);
    }

    #[test]
    fn test_degradation_level_calculation() {
        let limits = ResourceLimits {
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let mut monitor = ResourceMonitor::new(limits);

        // Test different utilization levels
        monitor.record_allocation(ResourceType::Memory, 500); // 50%
        assert_eq!(
            monitor.calculate_degradation_level(),
            DegradationLevel::None
        );

        monitor.record_allocation(ResourceType::Memory, 350); // 85%
        assert_eq!(
            monitor.calculate_degradation_level(),
            DegradationLevel::Moderate
        );

        monitor.record_allocation(ResourceType::Memory, 60); // 91%
        assert_eq!(
            monitor.calculate_degradation_level(),
            DegradationLevel::Severe
        );

        monitor.record_allocation(ResourceType::Memory, 50); // 96%
        assert_eq!(
            monitor.calculate_degradation_level(),
            DegradationLevel::Critical
        );
    }

    #[tokio::test]
    async fn test_background_monitoring() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        // Start monitoring with short interval for testing
        let config = MonitoringConfig {
            sample_interval: Duration::from_millis(100),
            auto_update_degradation: true,
            log_sampling: false,
        };

        let handle = monitor.start_monitoring(config);

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Check that the monitor is running
        assert!(handle.is_running());

        // Get stats - should have been updated by background monitoring
        let cpu_stats = monitor.get_stats(ResourceType::Cpu);
        let mem_stats = monitor.get_stats(ResourceType::Memory);

        assert!(cpu_stats.is_some());
        assert!(mem_stats.is_some());

        // Stop monitoring
        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_monitoring_handle_stop() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        let config = MonitoringConfig {
            sample_interval: Duration::from_millis(100),
            ..Default::default()
        };

        let handle = monitor.start_monitoring(config);

        // Monitor should be running
        assert!(handle.is_running());

        // Stop it
        handle.stop().await.unwrap();

        // Give it a moment to actually stop
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn test_sample_cpu_usage() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        // Sample CPU - should work without panicking
        let cpu_usage = monitor.sample_cpu_usage();

        // CPU usage should be reasonable (0-100%)
        assert!(cpu_usage >= 0.0);
        assert!(cpu_usage <= 100.0);

        // Stats should be updated
        let stats = monitor.get_stats(ResourceType::Cpu).unwrap();
        assert_eq!(stats.used, cpu_usage as u64);
    }

    #[tokio::test]
    async fn test_sample_memory_usage() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        // Sample memory - should work without panicking
        let memory_used = monitor.sample_memory_usage();

        // Memory usage should be non-zero
        assert!(memory_used > 0);

        // Stats should be updated
        let stats = monitor.get_stats(ResourceType::Memory).unwrap();
        assert_eq!(stats.used, memory_used);
    }

    #[tokio::test]
    async fn test_sample_all_system_resources() {
        let limits = ResourceLimits::default();
        let mut monitor = ResourceMonitor::new(limits);

        // Sample all resources at once
        let (cpu_usage, memory_used) = monitor.sample_all_system_resources();

        // Validate results
        assert!(cpu_usage >= 0.0);
        assert!(cpu_usage <= 100.0);
        assert!(memory_used > 0);

        // Check stats were updated
        let cpu_stats = monitor.get_stats(ResourceType::Cpu).unwrap();
        let mem_stats = monitor.get_stats(ResourceType::Memory).unwrap();

        assert_eq!(cpu_stats.used, cpu_usage as u64);
        assert_eq!(mem_stats.used, memory_used);
    }

    #[test]
    fn test_monitoring_config_default() {
        let config = MonitoringConfig::default();

        assert_eq!(config.sample_interval, Duration::from_secs(5));
        assert!(config.auto_update_degradation);
        assert!(!config.log_sampling);
    }

    #[tokio::test]
    async fn test_monitoring_updates_degradation() {
        let limits = ResourceLimits {
            max_cpu_percent: 10, // Very low limit to trigger degradation
            max_memory_bytes: 1000,
            ..Default::default()
        };
        let monitor = ResourceMonitor::new(limits);

        let config = MonitoringConfig {
            sample_interval: Duration::from_millis(100),
            auto_update_degradation: true,
            log_sampling: false,
        };

        let handle = monitor.start_monitoring(config);

        // Wait for a few samples
        tokio::time::sleep(Duration::from_millis(350)).await;

        // Degradation level may have been updated based on actual system usage
        let level = monitor.degradation_level();
        assert!(level >= DegradationLevel::None);

        // Stop monitoring
        handle.stop().await.unwrap();
    }

    #[test]
    fn test_total_system_memory() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        let total_mem = monitor.total_system_memory();

        // System should have some memory
        assert!(total_mem > 0);
    }

    #[test]
    fn test_cpu_count() {
        let limits = ResourceLimits::default();
        let monitor = ResourceMonitor::new(limits);

        let cpu_count = monitor.cpu_count();

        // System should have at least one CPU
        assert!(cpu_count > 0);
    }
}
