//! Statistics and metrics types for CHIE Protocol.
//!
//! This module contains types for tracking and reporting statistics:
//! - Node statistics and performance metrics
//! - Bandwidth usage statistics
//! - Platform-wide statistics
//! - Network health metrics
//! - Time-series data for monitoring

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::{Bytes, PeerIdString, Points};
use super::enums::NodeStatus;

/// Node statistics.
///
/// # Examples
///
/// ```
/// use chie_shared::{NodeStats, NodeStatus};
///
/// let stats = NodeStats {
///     peer_id: "12D3KooWExample".to_string(),
///     status: NodeStatus::Online,
///     total_bandwidth_bytes: 1024 * 1024 * 1024 * 50, // 50 GB
///     total_earnings: 5000,
///     uptime_seconds: 86400 * 30, // 30 days
///     pinned_content_count: 100,
///     pinned_storage_bytes: 1024 * 1024 * 1024 * 10, // 10 GB
///     last_seen_at: chrono::Utc::now(),
/// };
///
/// // Convert to display-friendly units
/// assert_eq!(stats.bandwidth_gb() as u64, 50);
/// assert_eq!(stats.storage_gb() as u64, 10);
/// assert_eq!(stats.uptime_days() as u64, 30);
///
/// // Check node status
/// assert!(stats.is_online());
/// assert!(stats.is_recently_active());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct NodeStats {
    pub peer_id: PeerIdString,
    pub status: NodeStatus,
    pub total_bandwidth_bytes: Bytes,
    pub total_earnings: Points,
    pub uptime_seconds: u64,
    pub pinned_content_count: u64,
    pub pinned_storage_bytes: Bytes,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
}

impl NodeStats {
    /// Get total bandwidth in gigabytes.
    pub fn bandwidth_gb(&self) -> f64 {
        self.total_bandwidth_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get total bandwidth in terabytes.
    pub fn bandwidth_tb(&self) -> f64 {
        self.total_bandwidth_bytes as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
    }

    /// Get pinned storage in gigabytes.
    pub fn storage_gb(&self) -> f64 {
        self.pinned_storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get uptime in days.
    pub fn uptime_days(&self) -> f64 {
        self.uptime_seconds as f64 / 86400.0
    }

    /// Check if the node is currently online.
    pub fn is_online(&self) -> bool {
        self.status == NodeStatus::Online
    }

    /// Check if the node has been seen recently (within 5 minutes).
    pub fn is_recently_active(&self) -> bool {
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(self.last_seen_at);
        diff.num_seconds() <= 300
    }
}

/// Bandwidth statistics over a time period.
///
/// # Examples
///
/// ```
/// use chie_shared::BandwidthStats;
///
/// let now = chrono::Utc::now();
/// let hour_ago = now - chrono::Duration::hours(1);
///
/// let stats = BandwidthStats {
///     bytes_uploaded: 1024 * 1024 * 100, // 100 MB
///     bytes_downloaded: 1024 * 1024 * 50, // 50 MB
///     chunks_served: 400,
///     chunks_requested: 200,
///     avg_upload_speed_bps: 1024 * 1024, // 1 MB/s
///     avg_download_speed_bps: 512 * 1024, // 512 KB/s
///     peak_upload_speed_bps: 5 * 1024 * 1024, // 5 MB/s
///     peak_download_speed_bps: 2 * 1024 * 1024, // 2 MB/s
///     period_start: hour_ago,
///     period_end: now,
/// };
///
/// // Calculate throughput
/// let total_transfer = stats.bytes_uploaded + stats.bytes_downloaded;
/// assert!(total_transfer > 0);
///
/// // Check chunk efficiency
/// assert!(stats.chunks_served > stats.chunks_requested);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BandwidthStats {
    /// Total bytes uploaded.
    pub bytes_uploaded: Bytes,
    /// Total bytes downloaded.
    pub bytes_downloaded: Bytes,
    /// Number of chunks served.
    pub chunks_served: u64,
    /// Number of chunks requested.
    pub chunks_requested: u64,
    /// Average upload speed (bytes per second).
    pub avg_upload_speed_bps: u64,
    /// Average download speed (bytes per second).
    pub avg_download_speed_bps: u64,
    /// Peak upload speed (bytes per second).
    pub peak_upload_speed_bps: u64,
    /// Peak download speed (bytes per second).
    pub peak_download_speed_bps: u64,
    /// Statistics time range start.
    pub period_start: chrono::DateTime<chrono::Utc>,
    /// Statistics time range end.
    pub period_end: chrono::DateTime<chrono::Utc>,
}

/// Platform-wide statistics.
///
/// # Examples
///
/// ```
/// use chie_shared::PlatformStats;
///
/// let stats = PlatformStats {
///     total_users: 10_000,
///     total_creators: 1_500,
///     active_nodes: 500,
///     total_content: 5_000,
///     total_storage_bytes: 1024 * 1024 * 1024 * 1024 * 5, // 5 TB
///     total_bandwidth_bytes: 1024 * 1024 * 1024 * 1024 * 50, // 50 TB
///     total_points_distributed: 1_000_000,
///     total_transactions: 50_000,
///     timestamp: chrono::Utc::now(),
/// };
///
/// // Calculate ratios
/// let creator_ratio = stats.total_creators as f64 / stats.total_users as f64;
/// assert!(creator_ratio > 0.0 && creator_ratio < 1.0);
///
/// // Average content per creator
/// let avg_content = stats.total_content / stats.total_creators;
/// assert!(avg_content > 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct PlatformStats {
    /// Total number of users.
    pub total_users: u64,
    /// Total number of creators.
    pub total_creators: u64,
    /// Total number of active nodes.
    pub active_nodes: u64,
    /// Total content items.
    pub total_content: u64,
    /// Total storage used (bytes).
    pub total_storage_bytes: Bytes,
    /// Total bandwidth served (bytes).
    pub total_bandwidth_bytes: Bytes,
    /// Total points distributed.
    pub total_points_distributed: Points,
    /// Total transactions.
    pub total_transactions: u64,
    /// Statistics timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Network health metrics.
///
/// # Examples
///
/// ```
/// use chie_shared::NetworkHealth;
///
/// let health = NetworkHealth {
///     online_nodes: 500,
///     avg_uptime_percent: 99.5,
///     avg_latency_ms: 45.0,
///     avg_replication_factor: 4.2,
///     content_availability_percent: 98.5,
///     failed_proofs_24h: 50,
///     successful_proofs_24h: 10_000,
///     timestamp: chrono::Utc::now(),
/// };
///
/// // Assess network health
/// let is_healthy = health.avg_uptime_percent > 95.0
///     && health.avg_latency_ms < 100.0
///     && health.content_availability_percent > 95.0;
/// assert!(is_healthy);
///
/// // Calculate success rate
/// let total_proofs = health.successful_proofs_24h + health.failed_proofs_24h;
/// let success_rate = health.successful_proofs_24h as f64 / total_proofs as f64;
/// assert!(success_rate > 0.99);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct NetworkHealth {
    /// Number of online nodes.
    pub online_nodes: u64,
    /// Average node uptime (percentage).
    pub avg_uptime_percent: f64,
    /// Average latency (milliseconds).
    pub avg_latency_ms: f64,
    /// Network replication factor (average copies per content).
    pub avg_replication_factor: f64,
    /// Percentage of content with at least 3 seeders.
    pub content_availability_percent: f64,
    /// Failed proof submissions (last 24h).
    pub failed_proofs_24h: u64,
    /// Successful proof submissions (last 24h).
    pub successful_proofs_24h: u64,
    /// Health check timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Time-series data point for metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct TimeSeriesPoint {
    /// Timestamp of the data point.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Metric value.
    pub value: f64,
}

/// Time-series metric data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct TimeSeriesMetric {
    /// Metric name.
    pub metric_name: String,
    /// Data points.
    pub data_points: Vec<TimeSeriesPoint>,
    /// Unit of measurement.
    pub unit: String,
}

impl TimeSeriesMetric {
    /// Create a new time-series metric.
    pub fn new(metric_name: impl Into<String>, unit: impl Into<String>) -> Self {
        Self {
            metric_name: metric_name.into(),
            unit: unit.into(),
            data_points: Vec::new(),
        }
    }

    /// Add a data point.
    pub fn add_point(&mut self, timestamp: chrono::DateTime<chrono::Utc>, value: f64) {
        self.data_points.push(TimeSeriesPoint { timestamp, value });
    }

    /// Get the latest value.
    pub fn latest_value(&self) -> Option<f64> {
        self.data_points.last().map(|p| p.value)
    }

    /// Calculate average value.
    pub fn average(&self) -> f64 {
        if self.data_points.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.data_points.iter().map(|p| p.value).sum();
        sum / self.data_points.len() as f64
    }

    /// Calculate maximum value.
    pub fn max(&self) -> Option<f64> {
        self.data_points
            .iter()
            .map(|p| p.value)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Calculate minimum value.
    pub fn min(&self) -> Option<f64> {
        self.data_points
            .iter()
            .map(|p| p.value)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_stats_bandwidth_conversions() {
        let stats = NodeStats {
            peer_id: "12D3KooTest".to_string(),
            status: NodeStatus::Online,
            total_bandwidth_bytes: 5 * 1024 * 1024 * 1024, // 5 GB
            total_earnings: 1000,
            uptime_seconds: 86400, // 1 day
            pinned_content_count: 10,
            pinned_storage_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
            last_seen_at: chrono::Utc::now(),
        };

        assert!((stats.bandwidth_gb() - 5.0).abs() < 0.001);
        assert!((stats.storage_gb() - 2.0).abs() < 0.001);
        assert!((stats.uptime_days() - 1.0).abs() < 0.001);
        assert!(stats.is_online());
        assert!(stats.is_recently_active());
    }

    #[test]
    fn test_time_series_metric_new() {
        let metric = TimeSeriesMetric::new("test_metric", "units");
        assert_eq!(metric.metric_name, "test_metric");
        assert_eq!(metric.unit, "units");
        assert!(metric.data_points.is_empty());
    }

    #[test]
    fn test_time_series_metric_add_point() {
        let mut metric = TimeSeriesMetric::new("test", "units");
        let now = chrono::Utc::now();

        metric.add_point(now, 10.0);
        metric.add_point(now, 20.0);
        metric.add_point(now, 30.0);

        assert_eq!(metric.data_points.len(), 3);
        assert_eq!(metric.latest_value(), Some(30.0));
    }

    #[test]
    fn test_time_series_metric_average() {
        let mut metric = TimeSeriesMetric::new("test", "units");
        let now = chrono::Utc::now();

        metric.add_point(now, 10.0);
        metric.add_point(now, 20.0);
        metric.add_point(now, 30.0);

        assert!((metric.average() - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_time_series_metric_max_min() {
        let mut metric = TimeSeriesMetric::new("test", "units");
        let now = chrono::Utc::now();

        metric.add_point(now, 10.0);
        metric.add_point(now, 30.0);
        metric.add_point(now, 20.0);

        assert_eq!(metric.max(), Some(30.0));
        assert_eq!(metric.min(), Some(10.0));
    }

    #[test]
    fn test_time_series_metric_empty() {
        let metric = TimeSeriesMetric::new("test", "units");

        assert_eq!(metric.latest_value(), None);
        assert_eq!(metric.average(), 0.0);
        assert_eq!(metric.max(), None);
        assert_eq!(metric.min(), None);
    }
}
