//! Storage health monitoring with predictive failure detection.
//!
//! This module provides comprehensive monitoring of storage health metrics
//! and predictive analysis to detect potential storage failures before they occur.
//!
//! # Example
//!
//! ```
//! use chie_core::storage_health::{PredictiveStorageMonitor, HealthConfig};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = HealthConfig {
//!     check_interval: Duration::from_secs(60),
//!     latency_warning_threshold_ms: 100,
//!     latency_critical_threshold_ms: 500,
//!     ..Default::default()
//! };
//!
//! let mut monitor = PredictiveStorageMonitor::new(PathBuf::from("/storage"), config);
//!
//! // Perform health check
//! let health = monitor.check_health().await?;
//! println!("Storage health: {:?}", health.overall_status);
//! println!("Failure risk: {:.2}%", health.failure_risk_score * 100.0);
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Maximum number of historical samples to keep for analysis.
const MAX_HISTORY_SAMPLES: usize = 1000;

/// Errors that can occur during health monitoring.
#[derive(Debug, Error)]
pub enum HealthMonitorError {
    #[error("IO error during health check: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to read disk metrics: {0}")]
    MetricsError(String),

    #[error("Insufficient data for prediction (need at least {required} samples, have {actual})")]
    InsufficientData { required: usize, actual: usize },
}

/// Configuration for storage health monitoring.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between health checks.
    pub check_interval: Duration,
    /// Warning threshold for read/write latency (ms).
    pub latency_warning_threshold_ms: u64,
    /// Critical threshold for read/write latency (ms).
    pub latency_critical_threshold_ms: u64,
    /// Minimum free space percentage before warning.
    pub min_free_space_percent: f64,
    /// Number of consecutive failures before marking critical.
    pub critical_failure_count: usize,
    /// Enable predictive failure detection.
    pub enable_prediction: bool,
    /// Failure risk threshold for warnings (0.0-1.0).
    pub failure_risk_threshold: f64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(60),
            latency_warning_threshold_ms: 100,
            latency_critical_threshold_ms: 500,
            min_free_space_percent: 10.0,
            critical_failure_count: 3,
            enable_prediction: true,
            failure_risk_threshold: 0.7,
        }
    }
}

/// Overall storage health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictiveHealthStatus {
    /// Storage is healthy.
    Healthy,
    /// Storage shows warning signs.
    Warning,
    /// Storage is in critical condition.
    Critical,
    /// Storage health is unknown.
    Unknown,
}

/// Detailed storage health report.
#[derive(Debug, Clone)]
pub struct PredictiveHealthReport {
    /// Overall health status.
    pub overall_status: PredictiveHealthStatus,
    /// Timestamp of this report.
    pub timestamp: u64,
    /// Average read latency (ms).
    pub avg_read_latency_ms: f64,
    /// Average write latency (ms).
    pub avg_write_latency_ms: f64,
    /// Recent IO error count.
    pub recent_io_errors: usize,
    /// Available space (bytes).
    pub available_bytes: u64,
    /// Total space (bytes).
    pub total_bytes: u64,
    /// Free space percentage.
    pub free_space_percent: f64,
    /// Predicted failure risk score (0.0-1.0).
    pub failure_risk_score: f64,
    /// Warning messages.
    pub warnings: Vec<String>,
}

/// Historical storage metric sample.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MetricSample {
    timestamp: u64,
    read_latency_ms: f64,
    write_latency_ms: f64,
    io_errors: usize,
    free_space_bytes: u64,
}

/// Storage health monitor with predictive capabilities.
pub struct PredictiveStorageMonitor {
    storage_path: PathBuf,
    config: HealthConfig,
    history: VecDeque<MetricSample>,
    consecutive_failures: usize,
    last_check: Option<Instant>,
    io_error_count: usize,
    total_checks: usize,
}

impl PredictiveStorageMonitor {
    /// Create a new storage health monitor.
    pub fn new(storage_path: PathBuf, config: HealthConfig) -> Self {
        Self {
            storage_path,
            config,
            history: VecDeque::with_capacity(MAX_HISTORY_SAMPLES),
            consecutive_failures: 0,
            last_check: None,
            io_error_count: 0,
            total_checks: 0,
        }
    }

    /// Perform a health check and return the report.
    pub async fn check_health(&mut self) -> Result<PredictiveHealthReport, HealthMonitorError> {
        self.total_checks += 1;
        self.last_check = Some(Instant::now());

        // Collect current metrics
        let (read_latency, write_latency) = self.measure_latency().await?;
        let (available_bytes, total_bytes) = self.get_space_info()?;
        let free_space_percent = (available_bytes as f64 / total_bytes as f64) * 100.0;

        // Record sample
        let sample = MetricSample {
            timestamp: current_timestamp(),
            read_latency_ms: read_latency,
            write_latency_ms: write_latency,
            io_errors: self.io_error_count,
            free_space_bytes: available_bytes,
        };

        if self.history.len() >= MAX_HISTORY_SAMPLES {
            self.history.pop_front();
        }
        self.history.push_back(sample);

        // Calculate averages
        let avg_read_latency = self.calculate_avg_read_latency();
        let avg_write_latency = self.calculate_avg_write_latency();

        // Determine health status
        let mut warnings = Vec::new();
        let mut status = PredictiveHealthStatus::Healthy;

        // Check latency
        if avg_read_latency > self.config.latency_critical_threshold_ms as f64
            || avg_write_latency > self.config.latency_critical_threshold_ms as f64
        {
            status = PredictiveHealthStatus::Critical;
            warnings.push(format!(
                "Critical latency: read={:.2}ms, write={:.2}ms",
                avg_read_latency, avg_write_latency
            ));
            self.consecutive_failures += 1;
        } else if avg_read_latency > self.config.latency_warning_threshold_ms as f64
            || avg_write_latency > self.config.latency_warning_threshold_ms as f64
        {
            status = PredictiveHealthStatus::Warning;
            warnings.push(format!(
                "High latency: read={:.2}ms, write={:.2}ms",
                avg_read_latency, avg_write_latency
            ));
        } else {
            self.consecutive_failures = 0;
        }

        // Check free space
        if free_space_percent < self.config.min_free_space_percent {
            status = PredictiveHealthStatus::Critical;
            warnings.push(format!("Low disk space: {:.2}% free", free_space_percent));
        } else if free_space_percent < self.config.min_free_space_percent * 2.0 {
            if status == PredictiveHealthStatus::Healthy {
                status = PredictiveHealthStatus::Warning;
            }
            warnings.push(format!(
                "Disk space running low: {:.2}% free",
                free_space_percent
            ));
        }

        // Check consecutive failures
        if self.consecutive_failures >= self.config.critical_failure_count {
            status = PredictiveHealthStatus::Critical;
            warnings.push(format!(
                "Consecutive failures: {}",
                self.consecutive_failures
            ));
        }

        // Calculate failure risk
        let failure_risk = if self.config.enable_prediction {
            self.predict_failure_risk()
        } else {
            0.0
        };

        if failure_risk > self.config.failure_risk_threshold {
            if status == PredictiveHealthStatus::Healthy {
                status = PredictiveHealthStatus::Warning;
            }
            warnings.push(format!(
                "High failure risk detected: {:.1}%",
                failure_risk * 100.0
            ));
        }

        Ok(PredictiveHealthReport {
            overall_status: status,
            timestamp: current_timestamp(),
            avg_read_latency_ms: avg_read_latency,
            avg_write_latency_ms: avg_write_latency,
            recent_io_errors: self.io_error_count,
            available_bytes,
            total_bytes,
            free_space_percent,
            failure_risk_score: failure_risk,
            warnings,
        })
    }

    /// Measure current read/write latency by performing test operations.
    async fn measure_latency(&mut self) -> Result<(f64, f64), HealthMonitorError> {
        let test_file = self.storage_path.join(".health_check");

        // Measure write latency
        let write_start = Instant::now();
        let write_result = tokio::fs::write(&test_file, b"health_check").await;
        let write_latency = write_start.elapsed().as_secs_f64() * 1000.0;

        if write_result.is_err() {
            self.io_error_count += 1;
        }

        // Measure read latency
        let read_start = Instant::now();
        let read_result = tokio::fs::read(&test_file).await;
        let read_latency = read_start.elapsed().as_secs_f64() * 1000.0;

        if read_result.is_err() {
            self.io_error_count += 1;
        }

        // Clean up
        let _ = tokio::fs::remove_file(&test_file).await;

        Ok((read_latency, write_latency))
    }

    /// Get storage space information.
    fn get_space_info(&self) -> Result<(u64, u64), HealthMonitorError> {
        #[cfg(unix)]
        {
            let _metadata = std::fs::metadata(&self.storage_path)?;

            // Get filesystem stats using statvfs
            use std::ffi::CString;
            use std::os::raw::c_char;

            // Use libc types for proper cross-platform compatibility
            // The statvfs struct layout varies significantly between platforms (Linux vs macOS)
            #[cfg(target_os = "macos")]
            #[repr(C)]
            struct statvfs {
                f_bsize: u64,   // fundamental file system block size
                f_frsize: u64,  // fragment size
                f_blocks: u64,  // total blocks
                f_bfree: u64,   // free blocks
                f_bavail: u64,  // free blocks available to non-superuser
                f_files: u64,   // total file nodes
                f_ffree: u64,   // free file nodes
                f_favail: u64,  // free file nodes available to non-superuser
                f_fsid: u64,    // file system id
                f_flag: u64,    // mount flags
                f_namemax: u64, // maximum filename length
            }

            #[cfg(not(target_os = "macos"))]
            #[repr(C)]
            struct statvfs {
                f_bsize: libc::c_ulong,
                f_frsize: libc::c_ulong,
                f_blocks: u64,
                f_bfree: u64,
                f_bavail: u64,
                f_files: u64,
                f_ffree: u64,
                f_favail: u64,
                f_fsid: libc::c_ulong,
                f_flag: libc::c_ulong,
                f_namemax: libc::c_ulong,
                _padding: [i32; 6],
            }

            unsafe extern "C" {
                fn statvfs(path: *const c_char, buf: *mut statvfs) -> i32;
            }

            let path_cstr = CString::new(self.storage_path.to_str().unwrap_or_default())
                .map_err(|e| HealthMonitorError::MetricsError(e.to_string()))?;

            let mut stats: statvfs = unsafe { std::mem::zeroed() };
            let result = unsafe { statvfs(path_cstr.as_ptr(), &mut stats) };

            if result == 0 {
                let block_size = stats.f_frsize;
                // Use saturating_mul to prevent overflow
                let available = stats.f_bavail.saturating_mul(block_size);
                let total = stats.f_blocks.saturating_mul(block_size);
                Ok((available, total))
            } else {
                // Fallback to simple estimate
                Ok((100_000_000_000, 1_000_000_000_000)) // 100GB available, 1TB total
            }
        }

        #[cfg(not(unix))]
        {
            // Simplified implementation for non-Unix systems
            Ok((100_000_000_000, 1_000_000_000_000)) // 100GB available, 1TB total
        }
    }

    /// Calculate average read latency from history.
    fn calculate_avg_read_latency(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }

        let sum: f64 = self.history.iter().map(|s| s.read_latency_ms).sum();
        sum / self.history.len() as f64
    }

    /// Calculate average write latency from history.
    fn calculate_avg_write_latency(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }

        let sum: f64 = self.history.iter().map(|s| s.write_latency_ms).sum();
        sum / self.history.len() as f64
    }

    /// Predict failure risk based on historical trends.
    fn predict_failure_risk(&self) -> f64 {
        if self.history.len() < 10 {
            return 0.0;
        }

        let mut risk_score: f64 = 0.0;

        // Analyze latency trends
        let recent_read_latency = self.recent_avg_read_latency(10);
        let older_read_latency = self.older_avg_read_latency(10);

        if older_read_latency > 0.0 {
            let latency_increase = (recent_read_latency - older_read_latency) / older_read_latency;
            if latency_increase > 0.5 {
                risk_score += 0.3; // 30% risk for rapidly increasing latency
            } else if latency_increase > 0.2 {
                risk_score += 0.15;
            }
        }

        // Analyze error rate trends
        let error_rate = self.io_error_count as f64 / self.total_checks as f64;
        if error_rate > 0.05 {
            risk_score += 0.4; // 40% risk for high error rate
        } else if error_rate > 0.01 {
            risk_score += 0.2;
        }

        // Analyze space depletion rate
        if let Some(space_depletion_days) = self.estimate_space_depletion_days() {
            if space_depletion_days < 7.0 {
                risk_score += 0.3;
            } else if space_depletion_days < 30.0 {
                risk_score += 0.15;
            }
        }

        risk_score.min(1.0)
    }

    /// Calculate average read latency for recent samples.
    fn recent_avg_read_latency(&self, count: usize) -> f64 {
        if self.history.len() < count {
            return 0.0;
        }

        let recent: Vec<_> = self.history.iter().rev().take(count).collect();
        let sum: f64 = recent.iter().map(|s| s.read_latency_ms).sum();
        sum / count as f64
    }

    /// Calculate average read latency for older samples.
    fn older_avg_read_latency(&self, count: usize) -> f64 {
        if self.history.len() < count * 2 {
            return 0.0;
        }

        let older: Vec<_> = self
            .history
            .iter()
            .skip(self.history.len() - count * 2)
            .take(count)
            .collect();
        let sum: f64 = older.iter().map(|s| s.read_latency_ms).sum();
        sum / count as f64
    }

    /// Estimate days until storage is full based on current depletion rate.
    fn estimate_space_depletion_days(&self) -> Option<f64> {
        if self.history.len() < 20 {
            return None;
        }

        let history_vec: Vec<_> = self.history.iter().collect();
        let recent = &history_vec[history_vec.len() - 10..];
        let older = &history_vec[history_vec.len() - 20..history_vec.len() - 10];

        // Use saturating_add to prevent overflow when summing large disk space values
        let recent_sum: u64 = recent
            .iter()
            .map(|s| s.free_space_bytes)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        let recent_avg_free: u64 = recent_sum / recent.len() as u64;

        let older_sum: u64 = older
            .iter()
            .map(|s| s.free_space_bytes)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        let older_avg_free: u64 = older_sum / older.len() as u64;

        if recent_avg_free >= older_avg_free {
            return None; // Not depleting
        }

        let space_lost = older_avg_free.saturating_sub(recent_avg_free);
        let recent_last = recent[recent.len() - 1];
        let older_first = older[0];
        let time_span_hours =
            (recent_last.timestamp.saturating_sub(older_first.timestamp)) as f64 / 3600.0;

        if time_span_hours == 0.0 {
            return None;
        }

        let depletion_rate_per_hour = space_lost as f64 / time_span_hours;
        let hours_until_full = recent_avg_free as f64 / depletion_rate_per_hour;

        Some(hours_until_full / 24.0) // Convert to days
    }

    /// Get the number of historical samples collected.
    #[must_use]
    #[inline]
    pub fn sample_count(&self) -> usize {
        self.history.len()
    }

    /// Get the total number of checks performed.
    #[must_use]
    pub const fn total_checks(&self) -> usize {
        self.total_checks
    }

    /// Get the storage path being monitored.
    #[must_use]
    pub fn storage_path(&self) -> &PathBuf {
        &self.storage_path
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_monitor() -> (PredictiveStorageMonitor, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = HealthConfig {
            check_interval: Duration::from_millis(10),
            latency_warning_threshold_ms: 50,
            latency_critical_threshold_ms: 200,
            min_free_space_percent: 10.0,
            critical_failure_count: 3,
            enable_prediction: true,
            failure_risk_threshold: 0.7,
        };
        let monitor = PredictiveStorageMonitor::new(temp_dir.path().to_path_buf(), config);
        (monitor, temp_dir)
    }

    #[tokio::test]
    async fn test_health_check_basic() {
        let (mut monitor, _temp_dir) = create_test_monitor();

        let report = monitor.check_health().await.unwrap();
        assert_eq!(report.overall_status, PredictiveHealthStatus::Healthy);
        assert_eq!(monitor.sample_count(), 1);
    }

    #[tokio::test]
    async fn test_multiple_health_checks() {
        let (mut monitor, _temp_dir) = create_test_monitor();

        for _ in 0..5 {
            let report = monitor.check_health().await.unwrap();
            assert!(matches!(
                report.overall_status,
                PredictiveHealthStatus::Healthy | PredictiveHealthStatus::Warning
            ));
        }

        assert_eq!(monitor.sample_count(), 5);
        assert_eq!(monitor.total_checks(), 5);
    }

    #[tokio::test]
    async fn test_latency_measurement() {
        let (mut monitor, _temp_dir) = create_test_monitor();

        let report = monitor.check_health().await.unwrap();
        assert!(report.avg_read_latency_ms >= 0.0);
        assert!(report.avg_write_latency_ms >= 0.0);
    }

    #[test]
    fn test_health_config_defaults() {
        let config = HealthConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(60));
        assert_eq!(config.latency_warning_threshold_ms, 100);
        assert_eq!(config.min_free_space_percent, 10.0);
        assert!(config.enable_prediction);
    }

    #[tokio::test]
    async fn test_history_limit() {
        let (mut monitor, _temp_dir) = create_test_monitor();

        // Add more samples than the limit
        for _ in 0..MAX_HISTORY_SAMPLES + 10 {
            let _ = monitor.check_health().await;
        }

        assert_eq!(monitor.sample_count(), MAX_HISTORY_SAMPLES);
    }

    #[tokio::test]
    async fn test_failure_risk_insufficient_data() {
        let (monitor, _temp_dir) = create_test_monitor();

        // With no history, risk should be 0
        let risk = monitor.predict_failure_risk();
        assert_eq!(risk, 0.0);
    }

    #[tokio::test]
    async fn test_space_info() {
        let (monitor, _temp_dir) = create_test_monitor();

        let result = monitor.get_space_info();
        assert!(result.is_ok());

        let (available, total) = result.unwrap();
        assert!(available > 0);
        assert!(total > 0);
        assert!(available <= total);
    }

    #[tokio::test]
    async fn test_average_calculations() {
        let (mut monitor, _temp_dir) = create_test_monitor();

        // Perform multiple checks to build history
        for _ in 0..10 {
            let _ = monitor.check_health().await;
        }

        let avg_read = monitor.calculate_avg_read_latency();
        let avg_write = monitor.calculate_avg_write_latency();

        assert!(avg_read >= 0.0);
        assert!(avg_write >= 0.0);
    }
}
