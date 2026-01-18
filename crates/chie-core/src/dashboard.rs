//! Performance dashboard data endpoints.
//!
//! This module provides structured data for performance dashboards and monitoring UIs.
//!
//! # Features
//!
//! - System health status aggregation
//! - Performance metrics summaries
//! - Resource utilization snapshots
//! - Historical trend data
//! - Alert summaries
//!
//! # Example
//!
//! ```
//! use chie_core::dashboard::{DashboardData, SystemStatus, PerformanceSnapshot};
//!
//! let mut dashboard = DashboardData::new();
//!
//! // Update metrics
//! dashboard.update_storage(1024 * 1024, 10 * 1024 * 1024);
//! dashboard.update_bandwidth(500 * 1024, 200 * 1024);
//!
//! // Get snapshot
//! let snapshot = dashboard.snapshot();
//! println!("System Status: {:?}", snapshot.system_status);
//! println!("Storage Usage: {}%", snapshot.storage_usage_percent);
//! ```

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// System health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemStatus {
    /// All systems operating normally.
    Healthy,
    /// Minor issues detected.
    Degraded,
    /// Significant problems detected.
    Unhealthy,
    /// Critical failures.
    Critical,
}

impl SystemStatus {
    /// Get a color code for the status (for UI display).
    #[must_use]
    #[inline]
    pub const fn color_code(&self) -> &'static str {
        match self {
            Self::Healthy => "#22c55e",   // Green
            Self::Degraded => "#f59e0b",  // Amber
            Self::Unhealthy => "#ef4444", // Red
            Self::Critical => "#991b1b",  // Dark red
        }
    }

    /// Get a label for the status.
    #[must_use]
    #[inline]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Unhealthy => "Unhealthy",
            Self::Critical => "Critical",
        }
    }
}

/// Performance snapshot at a point in time.
#[derive(Debug, Clone)]
pub struct PerformanceSnapshot {
    /// Timestamp of the snapshot.
    pub timestamp: SystemTime,
    /// Overall system status.
    pub system_status: SystemStatus,
    /// Storage used in bytes.
    pub storage_used_bytes: u64,
    /// Total storage capacity in bytes.
    pub storage_total_bytes: u64,
    /// Storage usage percentage (0-100).
    pub storage_usage_percent: f64,
    /// Bandwidth upload rate in bytes/sec.
    pub bandwidth_upload_bps: u64,
    /// Bandwidth download rate in bytes/sec.
    pub bandwidth_download_bps: u64,
    /// Average request latency in milliseconds.
    pub avg_latency_ms: u64,
    /// P95 latency in milliseconds.
    pub p95_latency_ms: u64,
    /// Active connections count.
    pub active_connections: u32,
    /// Requests served in the last period.
    pub requests_served: u64,
    /// Error count in the last period.
    pub error_count: u64,
    /// Cache hit rate percentage (0-100).
    pub cache_hit_rate: f64,
    /// Number of active alerts.
    pub active_alerts: u32,
}

impl Default for PerformanceSnapshot {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now(),
            system_status: SystemStatus::Healthy,
            storage_used_bytes: 0,
            storage_total_bytes: 0,
            storage_usage_percent: 0.0,
            bandwidth_upload_bps: 0,
            bandwidth_download_bps: 0,
            avg_latency_ms: 0,
            p95_latency_ms: 0,
            active_connections: 0,
            requests_served: 0,
            error_count: 0,
            cache_hit_rate: 0.0,
            active_alerts: 0,
        }
    }
}

impl PerformanceSnapshot {
    /// Create a new snapshot with current timestamp.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Determine system status based on metrics.
    #[must_use]
    pub fn determine_status(&self) -> SystemStatus {
        // Critical conditions
        if self.storage_usage_percent > 95.0 || self.error_count > 100 || self.active_alerts > 10 {
            return SystemStatus::Critical;
        }

        // Unhealthy conditions
        if self.storage_usage_percent > 90.0 || self.avg_latency_ms > 1000 || self.error_count > 50
        {
            return SystemStatus::Unhealthy;
        }

        // Degraded conditions
        if self.storage_usage_percent > 75.0
            || self.avg_latency_ms > 500
            || self.error_count > 10
            || self.cache_hit_rate < 50.0
        {
            return SystemStatus::Degraded;
        }

        SystemStatus::Healthy
    }
}

/// Historical data point for trend analysis.
#[derive(Debug, Clone)]
pub struct DataPoint {
    /// Timestamp of the data point.
    pub timestamp: SystemTime,
    /// The metric value.
    pub value: f64,
}

impl DataPoint {
    /// Create a new data point.
    #[must_use]
    #[inline]
    pub fn new(value: f64) -> Self {
        Self {
            timestamp: SystemTime::now(),
            value,
        }
    }

    /// Get the age of this data point in seconds.
    #[must_use]
    #[inline]
    pub fn age_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.timestamp)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Time series data for trend analysis.
#[derive(Debug, Clone)]
pub struct TimeSeries {
    /// Data points.
    points: VecDeque<DataPoint>,
    /// Maximum number of points to retain.
    max_points: usize,
    /// Maximum age of points in seconds.
    max_age_secs: u64,
}

impl TimeSeries {
    /// Create a new time series.
    #[must_use]
    pub fn new(max_points: usize, max_age_secs: u64) -> Self {
        Self {
            points: VecDeque::with_capacity(max_points),
            max_points,
            max_age_secs,
        }
    }

    /// Add a data point.
    pub fn add(&mut self, value: f64) {
        self.points.push_back(DataPoint::new(value));

        // Trim old points by age
        let cutoff = SystemTime::now() - Duration::from_secs(self.max_age_secs);
        while let Some(point) = self.points.front() {
            if point.timestamp < cutoff {
                self.points.pop_front();
            } else {
                break;
            }
        }

        // Trim by count
        while self.points.len() > self.max_points {
            self.points.pop_front();
        }
    }

    /// Get all data points.
    #[must_use]
    #[inline]
    pub fn points(&self) -> &VecDeque<DataPoint> {
        &self.points
    }

    /// Get the most recent value.
    #[must_use]
    pub fn latest(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }

    /// Get the average value.
    #[must_use]
    pub fn average(&self) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }

        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        Some(sum / self.points.len() as f64)
    }

    /// Get the minimum value.
    #[must_use]
    pub fn min(&self) -> Option<f64> {
        self.points
            .iter()
            .map(|p| p.value)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the maximum value.
    #[must_use]
    pub fn max(&self) -> Option<f64> {
        self.points
            .iter()
            .map(|p| p.value)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Get the number of points.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// Check if the series is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

/// Dashboard data aggregator.
pub struct DashboardData {
    /// Current snapshot.
    current: PerformanceSnapshot,
    /// Storage usage history.
    storage_history: TimeSeries,
    /// Bandwidth history (upload).
    bandwidth_upload_history: TimeSeries,
    /// Bandwidth history (download).
    bandwidth_download_history: TimeSeries,
    /// Latency history.
    latency_history: TimeSeries,
    /// Error rate history.
    error_history: TimeSeries,
}

impl Default for DashboardData {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardData {
    /// Create a new dashboard data aggregator.
    #[must_use]
    pub fn new() -> Self {
        // Keep 100 points, max 1 hour old
        Self {
            current: PerformanceSnapshot::new(),
            storage_history: TimeSeries::new(100, 3600),
            bandwidth_upload_history: TimeSeries::new(100, 3600),
            bandwidth_download_history: TimeSeries::new(100, 3600),
            latency_history: TimeSeries::new(100, 3600),
            error_history: TimeSeries::new(100, 3600),
        }
    }

    /// Update storage metrics.
    pub fn update_storage(&mut self, used_bytes: u64, total_bytes: u64) {
        self.current.storage_used_bytes = used_bytes;
        self.current.storage_total_bytes = total_bytes;
        self.current.storage_usage_percent = if total_bytes > 0 {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        self.storage_history.add(self.current.storage_usage_percent);
    }

    /// Update bandwidth metrics.
    pub fn update_bandwidth(&mut self, upload_bps: u64, download_bps: u64) {
        self.current.bandwidth_upload_bps = upload_bps;
        self.current.bandwidth_download_bps = download_bps;

        self.bandwidth_upload_history.add(upload_bps as f64);
        self.bandwidth_download_history.add(download_bps as f64);
    }

    /// Update latency metrics.
    pub fn update_latency(&mut self, avg_ms: u64, p95_ms: u64) {
        self.current.avg_latency_ms = avg_ms;
        self.current.p95_latency_ms = p95_ms;

        self.latency_history.add(avg_ms as f64);
    }

    /// Update connection metrics.
    #[inline]
    pub fn update_connections(&mut self, active: u32) {
        self.current.active_connections = active;
    }

    /// Update request metrics.
    #[inline]
    pub fn update_requests(&mut self, served: u64) {
        self.current.requests_served = served;
    }

    /// Update error metrics.
    pub fn update_errors(&mut self, count: u64) {
        self.current.error_count = count;
        self.error_history.add(count as f64);
    }

    /// Update cache metrics.
    #[inline]
    pub fn update_cache(&mut self, hit_rate: f64) {
        self.current.cache_hit_rate = hit_rate;
    }

    /// Update alert count.
    #[inline]
    pub fn update_alerts(&mut self, count: u32) {
        self.current.active_alerts = count;
    }

    /// Get the current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PerformanceSnapshot {
        let mut snapshot = self.current.clone();
        snapshot.system_status = snapshot.determine_status();
        snapshot.timestamp = SystemTime::now();
        snapshot
    }

    /// Get storage usage trend.
    #[must_use]
    #[inline]
    pub fn storage_trend(&self) -> &TimeSeries {
        &self.storage_history
    }

    /// Get bandwidth upload trend.
    #[must_use]
    #[inline]
    pub fn bandwidth_upload_trend(&self) -> &TimeSeries {
        &self.bandwidth_upload_history
    }

    /// Get bandwidth download trend.
    #[must_use]
    #[inline]
    pub fn bandwidth_download_trend(&self) -> &TimeSeries {
        &self.bandwidth_download_history
    }

    /// Get latency trend.
    #[must_use]
    #[inline]
    pub fn latency_trend(&self) -> &TimeSeries {
        &self.latency_history
    }

    /// Get error trend.
    #[must_use]
    #[inline]
    pub fn error_trend(&self) -> &TimeSeries {
        &self.error_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_status_labels() {
        assert_eq!(SystemStatus::Healthy.label(), "Healthy");
        assert_eq!(SystemStatus::Degraded.label(), "Degraded");
        assert_eq!(SystemStatus::Unhealthy.label(), "Unhealthy");
        assert_eq!(SystemStatus::Critical.label(), "Critical");
    }

    #[test]
    fn test_performance_snapshot_status() {
        let mut snapshot = PerformanceSnapshot::new();

        // Set cache_hit_rate to avoid triggering Degraded status (< 50.0 triggers degraded)
        snapshot.cache_hit_rate = 80.0;

        // Healthy
        snapshot.storage_usage_percent = 50.0;
        snapshot.avg_latency_ms = 100;
        assert_eq!(snapshot.determine_status(), SystemStatus::Healthy);

        // Degraded
        snapshot.storage_usage_percent = 80.0;
        assert_eq!(snapshot.determine_status(), SystemStatus::Degraded);

        // Unhealthy
        snapshot.storage_usage_percent = 92.0;
        assert_eq!(snapshot.determine_status(), SystemStatus::Unhealthy);

        // Critical
        snapshot.storage_usage_percent = 96.0;
        assert_eq!(snapshot.determine_status(), SystemStatus::Critical);
    }

    #[test]
    fn test_time_series_basic() {
        let mut ts = TimeSeries::new(10, 3600);
        assert!(ts.is_empty());

        ts.add(10.0);
        ts.add(20.0);
        ts.add(30.0);

        assert_eq!(ts.len(), 3);
        assert_eq!(ts.latest(), Some(30.0));
        assert_eq!(ts.average(), Some(20.0));
        assert_eq!(ts.min(), Some(10.0));
        assert_eq!(ts.max(), Some(30.0));
    }

    #[test]
    fn test_time_series_capacity() {
        let mut ts = TimeSeries::new(5, 3600);

        for i in 0..10 {
            ts.add(i as f64);
        }

        // Should only keep the last 5
        assert_eq!(ts.len(), 5);
        assert_eq!(ts.latest(), Some(9.0));
    }

    #[test]
    fn test_dashboard_data_storage() {
        let mut dashboard = DashboardData::new();
        dashboard.update_storage(5000, 10000);

        let snapshot = dashboard.snapshot();
        assert_eq!(snapshot.storage_used_bytes, 5000);
        assert_eq!(snapshot.storage_total_bytes, 10000);
        assert_eq!(snapshot.storage_usage_percent, 50.0);
    }

    #[test]
    fn test_dashboard_data_bandwidth() {
        let mut dashboard = DashboardData::new();
        dashboard.update_bandwidth(1000, 2000);

        let snapshot = dashboard.snapshot();
        assert_eq!(snapshot.bandwidth_upload_bps, 1000);
        assert_eq!(snapshot.bandwidth_download_bps, 2000);
    }

    #[test]
    fn test_dashboard_data_latency() {
        let mut dashboard = DashboardData::new();
        dashboard.update_latency(100, 250);

        let snapshot = dashboard.snapshot();
        assert_eq!(snapshot.avg_latency_ms, 100);
        assert_eq!(snapshot.p95_latency_ms, 250);
    }

    #[test]
    fn test_dashboard_trends() {
        let mut dashboard = DashboardData::new();

        for i in 1..=5 {
            dashboard.update_storage(i * 1000, 10000);
        }

        let trend = dashboard.storage_trend();
        assert_eq!(trend.len(), 5);
        assert_eq!(trend.latest(), Some(50.0));
    }

    #[test]
    fn test_data_point_age() {
        let point = DataPoint::new(42.0);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(point.age_secs() < 1);
    }
}
