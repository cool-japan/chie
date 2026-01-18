//! Profiling and performance metrics types for CHIE Protocol.
//!
//! This module provides shared types for tracking operation performance,
//! timings, and generating performance reports.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::Bytes;

/// Performance statistics for a profiled operation.
///
/// # Examples
///
/// ```
/// use chie_shared::OperationStats;
///
/// // Track 100 database queries
/// let stats = OperationStats::new(100, 5000.0, 10.0, 200.0);
///
/// // Analyze performance
/// assert_eq!(stats.avg_duration_ms, 50.0);
/// assert_eq!(stats.ops_per_second(), 20.0);
///
/// // Check if operations are slow (> 100ms threshold)
/// assert!(!stats.is_slow(100.0));
///
/// // Get percentile estimates
/// assert_eq!(stats.p50_estimate_ms(), 50.0);
/// assert_eq!(stats.p99_estimate_ms(), 200.0);
///
/// // Convert to seconds
/// assert_eq!(stats.total_duration_secs(), 5.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct OperationStats {
    /// Number of times the operation was executed.
    pub count: u64,
    /// Total time spent in milliseconds.
    pub total_duration_ms: f64,
    /// Minimum execution time in milliseconds.
    pub min_duration_ms: f64,
    /// Maximum execution time in milliseconds.
    pub max_duration_ms: f64,
    /// Average execution time in milliseconds.
    pub avg_duration_ms: f64,
}

impl OperationStats {
    /// Create new operation statistics.
    pub fn new(
        count: u64,
        total_duration_ms: f64,
        min_duration_ms: f64,
        max_duration_ms: f64,
    ) -> Self {
        let avg_duration_ms = if count > 0 {
            total_duration_ms / count as f64
        } else {
            0.0
        };

        Self {
            count,
            total_duration_ms,
            min_duration_ms,
            max_duration_ms,
            avg_duration_ms,
        }
    }

    /// Create empty operation statistics.
    pub fn empty() -> Self {
        Self {
            count: 0,
            total_duration_ms: 0.0,
            min_duration_ms: f64::MAX,
            max_duration_ms: 0.0,
            avg_duration_ms: 0.0,
        }
    }

    /// Get operations per second based on total time.
    pub fn ops_per_second(&self) -> f64 {
        if self.total_duration_ms == 0.0 {
            return 0.0;
        }
        (self.count as f64 * 1000.0) / self.total_duration_ms
    }

    /// Get p99 estimate (uses max as approximation).
    pub fn p99_estimate_ms(&self) -> f64 {
        self.max_duration_ms
    }

    /// Get p50 estimate (uses avg as approximation).
    pub fn p50_estimate_ms(&self) -> f64 {
        self.avg_duration_ms
    }

    /// Check if operation is slow (avg > threshold).
    pub fn is_slow(&self, threshold_ms: f64) -> bool {
        self.avg_duration_ms > threshold_ms
    }

    /// Get total time in seconds.
    pub fn total_duration_secs(&self) -> f64 {
        self.total_duration_ms / 1000.0
    }
}

impl Default for OperationStats {
    fn default() -> Self {
        Self::empty()
    }
}

/// Bandwidth performance metrics.
///
/// # Examples
///
/// ```
/// use chie_shared::BandwidthMetrics;
///
/// // Track bandwidth for 10 chunk transfers (1 GB total)
/// let metrics = BandwidthMetrics::new(
///     1024 * 1024 * 1024,  // 1 GB
///     1000.0,              // 1 second
///     10,                  // 10 transfers
///     2_000_000.0,         // 2 MB/s peak
/// );
///
/// // Check average speeds
/// assert!(metrics.avg_mbps() > 1000.0);
/// assert_eq!(metrics.peak_mbps(), 16.0);
///
/// // Calculate efficiency
/// let avg_chunk_size = metrics.avg_bytes_per_transfer();
/// assert!(avg_chunk_size > 0.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BandwidthMetrics {
    /// Total bytes transferred.
    pub bytes_transferred: Bytes,
    /// Total transfer time in milliseconds.
    pub total_time_ms: f64,
    /// Number of transfers.
    pub transfer_count: u64,
    /// Average bytes per second.
    pub avg_bps: f64,
    /// Peak bytes per second.
    pub peak_bps: f64,
}

impl BandwidthMetrics {
    /// Create new bandwidth metrics.
    pub fn new(
        bytes_transferred: Bytes,
        total_time_ms: f64,
        transfer_count: u64,
        peak_bps: f64,
    ) -> Self {
        let avg_bps = if total_time_ms > 0.0 {
            (bytes_transferred as f64 * 1000.0) / total_time_ms
        } else {
            0.0
        };

        Self {
            bytes_transferred,
            total_time_ms,
            transfer_count,
            avg_bps,
            peak_bps,
        }
    }

    /// Get average transfer time in milliseconds.
    pub fn avg_transfer_time_ms(&self) -> f64 {
        if self.transfer_count == 0 {
            0.0
        } else {
            self.total_time_ms / self.transfer_count as f64
        }
    }

    /// Get average bytes per transfer.
    pub fn avg_bytes_per_transfer(&self) -> f64 {
        if self.transfer_count == 0 {
            0.0
        } else {
            self.bytes_transferred as f64 / self.transfer_count as f64
        }
    }

    /// Get bandwidth in Mbps.
    pub fn avg_mbps(&self) -> f64 {
        (self.avg_bps * 8.0) / 1_000_000.0
    }

    /// Get peak bandwidth in Mbps.
    pub fn peak_mbps(&self) -> f64 {
        (self.peak_bps * 8.0) / 1_000_000.0
    }

    /// Get total data in gigabytes.
    pub fn total_gb(&self) -> f64 {
        self.bytes_transferred as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

impl Default for BandwidthMetrics {
    fn default() -> Self {
        Self::new(0, 0.0, 0, 0.0)
    }
}

/// Latency statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LatencyStats {
    /// Number of measurements.
    pub count: u64,
    /// Minimum latency in milliseconds.
    pub min_ms: f64,
    /// Maximum latency in milliseconds.
    pub max_ms: f64,
    /// Average latency in milliseconds.
    pub avg_ms: f64,
    /// P50 latency in milliseconds.
    pub p50_ms: f64,
    /// P95 latency in milliseconds.
    pub p95_ms: f64,
    /// P99 latency in milliseconds.
    pub p99_ms: f64,
}

impl LatencyStats {
    /// Create new latency statistics.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        count: u64,
        min_ms: f64,
        max_ms: f64,
        avg_ms: f64,
        p50_ms: f64,
        p95_ms: f64,
        p99_ms: f64,
    ) -> Self {
        Self {
            count,
            min_ms,
            max_ms,
            avg_ms,
            p50_ms,
            p95_ms,
            p99_ms,
        }
    }

    /// Check if latency is within acceptable range.
    pub fn is_acceptable(&self, threshold_ms: f64) -> bool {
        self.p95_ms <= threshold_ms
    }

    /// Get jitter (max - min).
    pub fn jitter_ms(&self) -> f64 {
        self.max_ms - self.min_ms
    }
}

impl Default for LatencyStats {
    fn default() -> Self {
        Self::new(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    }
}

/// Throughput metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ThroughputMetrics {
    /// Number of operations completed.
    pub operations_completed: u64,
    /// Time period in seconds.
    pub time_period_secs: f64,
    /// Operations per second.
    pub ops_per_second: f64,
    /// Peak ops per second.
    pub peak_ops_per_second: f64,
}

impl ThroughputMetrics {
    /// Create new throughput metrics.
    pub fn new(operations_completed: u64, time_period_secs: f64, peak_ops_per_second: f64) -> Self {
        let ops_per_second = if time_period_secs > 0.0 {
            operations_completed as f64 / time_period_secs
        } else {
            0.0
        };

        Self {
            operations_completed,
            time_period_secs,
            ops_per_second,
            peak_ops_per_second,
        }
    }

    /// Get average time per operation in milliseconds.
    pub fn avg_time_per_op_ms(&self) -> f64 {
        if self.operations_completed == 0 {
            0.0
        } else {
            (self.time_period_secs * 1000.0) / self.operations_completed as f64
        }
    }

    /// Get utilization percentage (current vs peak).
    pub fn utilization_percentage(&self) -> f64 {
        if self.peak_ops_per_second == 0.0 {
            0.0
        } else {
            (self.ops_per_second / self.peak_ops_per_second) * 100.0
        }
    }
}

impl Default for ThroughputMetrics {
    fn default() -> Self {
        Self::new(0, 0.0, 0.0)
    }
}

/// Resource utilization metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ResourceMetrics {
    /// CPU usage percentage (0.0 to 100.0).
    pub cpu_percent: f64,
    /// Memory usage in bytes.
    pub memory_bytes: u64,
    /// Disk usage in bytes.
    pub disk_bytes: u64,
    /// Network bytes sent.
    pub network_bytes_sent: u64,
    /// Network bytes received.
    pub network_bytes_received: u64,
}

impl ResourceMetrics {
    /// Create new resource metrics.
    pub fn new(
        cpu_percent: f64,
        memory_bytes: u64,
        disk_bytes: u64,
        network_bytes_sent: u64,
        network_bytes_received: u64,
    ) -> Self {
        Self {
            cpu_percent,
            memory_bytes,
            disk_bytes,
            network_bytes_sent,
            network_bytes_received,
        }
    }

    /// Get memory usage in megabytes.
    pub fn memory_mb(&self) -> f64 {
        self.memory_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Get disk usage in gigabytes.
    pub fn disk_gb(&self) -> f64 {
        self.disk_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Get total network bytes.
    pub fn total_network_bytes(&self) -> u64 {
        self.network_bytes_sent + self.network_bytes_received
    }
}

impl Default for ResourceMetrics {
    fn default() -> Self {
        Self::new(0.0, 0, 0, 0, 0)
    }
}

/// Builder for OperationStats with fluent API.
#[derive(Debug, Default)]
pub struct OperationStatsBuilder {
    count: Option<u64>,
    total_duration_ms: Option<f64>,
    min_duration_ms: Option<f64>,
    max_duration_ms: Option<f64>,
}

impl OperationStatsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the operation count.
    pub fn count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// Set the total duration in milliseconds.
    pub fn total_duration_ms(mut self, duration: f64) -> Self {
        self.total_duration_ms = Some(duration);
        self
    }

    /// Set the minimum duration in milliseconds.
    pub fn min_duration_ms(mut self, duration: f64) -> Self {
        self.min_duration_ms = Some(duration);
        self
    }

    /// Set the maximum duration in milliseconds.
    pub fn max_duration_ms(mut self, duration: f64) -> Self {
        self.max_duration_ms = Some(duration);
        self
    }

    /// Build the OperationStats.
    pub fn build(self) -> OperationStats {
        OperationStats::new(
            self.count.unwrap_or(0),
            self.total_duration_ms.unwrap_or(0.0),
            self.min_duration_ms.unwrap_or(f64::MAX),
            self.max_duration_ms.unwrap_or(0.0),
        )
    }
}

/// Builder for BandwidthMetrics with fluent API.
#[derive(Debug, Default)]
pub struct BandwidthMetricsBuilder {
    bytes_transferred: Option<Bytes>,
    total_time_ms: Option<f64>,
    transfer_count: Option<u64>,
    peak_bps: Option<f64>,
}

impl BandwidthMetricsBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bytes transferred.
    pub fn bytes_transferred(mut self, bytes: Bytes) -> Self {
        self.bytes_transferred = Some(bytes);
        self
    }

    /// Set the total time in milliseconds.
    pub fn total_time_ms(mut self, time: f64) -> Self {
        self.total_time_ms = Some(time);
        self
    }

    /// Set the transfer count.
    pub fn transfer_count(mut self, count: u64) -> Self {
        self.transfer_count = Some(count);
        self
    }

    /// Set the peak bytes per second.
    pub fn peak_bps(mut self, bps: f64) -> Self {
        self.peak_bps = Some(bps);
        self
    }

    /// Build the BandwidthMetrics.
    pub fn build(self) -> BandwidthMetrics {
        BandwidthMetrics::new(
            self.bytes_transferred.unwrap_or(0),
            self.total_time_ms.unwrap_or(0.0),
            self.transfer_count.unwrap_or(0),
            self.peak_bps.unwrap_or(0.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_stats_new() {
        let stats = OperationStats::new(100, 5000.0, 10.0, 200.0);
        assert_eq!(stats.count, 100);
        assert_eq!(stats.total_duration_ms, 5000.0);
        assert_eq!(stats.min_duration_ms, 10.0);
        assert_eq!(stats.max_duration_ms, 200.0);
        assert_eq!(stats.avg_duration_ms, 50.0);
    }

    #[test]
    fn test_operation_stats_ops_per_second() {
        let stats = OperationStats::new(100, 1000.0, 5.0, 20.0);
        // 100 ops in 1000ms = 100 ops/sec
        assert!((stats.ops_per_second() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_operation_stats_is_slow() {
        let stats = OperationStats::new(10, 1000.0, 50.0, 150.0);
        assert!(stats.is_slow(50.0));
        assert!(!stats.is_slow(200.0));
    }

    #[test]
    fn test_bandwidth_metrics() {
        let metrics = BandwidthMetrics::new(1_000_000, 1000.0, 10, 2_000_000.0);
        assert_eq!(metrics.bytes_transferred, 1_000_000);
        assert_eq!(metrics.transfer_count, 10);
        assert_eq!(metrics.avg_bps, 1_000_000.0);
        assert_eq!(metrics.avg_transfer_time_ms(), 100.0);
        assert_eq!(metrics.avg_bytes_per_transfer(), 100_000.0);
    }

    #[test]
    fn test_bandwidth_metrics_mbps() {
        let metrics = BandwidthMetrics::new(1_000_000, 1000.0, 1, 1_000_000.0);
        // 1 MB/s = 8 Mbps
        assert!((metrics.avg_mbps() - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_latency_stats() {
        let stats = LatencyStats::new(100, 5.0, 100.0, 25.0, 20.0, 80.0, 95.0);
        assert_eq!(stats.count, 100);
        assert!(stats.is_acceptable(90.0));
        assert!(!stats.is_acceptable(75.0));
        assert_eq!(stats.jitter_ms(), 95.0);
    }

    #[test]
    fn test_throughput_metrics() {
        let metrics = ThroughputMetrics::new(1000, 10.0, 200.0);
        assert_eq!(metrics.operations_completed, 1000);
        assert_eq!(metrics.ops_per_second, 100.0);
        assert_eq!(metrics.avg_time_per_op_ms(), 10.0);
        assert_eq!(metrics.utilization_percentage(), 50.0);
    }

    #[test]
    fn test_resource_metrics() {
        let metrics = ResourceMetrics::new(
            75.5,
            512 * 1024 * 1024,      // 512 MB
            5 * 1024 * 1024 * 1024, // 5 GB
            1_000_000,
            2_000_000,
        );

        assert_eq!(metrics.cpu_percent, 75.5);
        assert!((metrics.memory_mb() - 512.0).abs() < 0.1);
        assert!((metrics.disk_gb() - 5.0).abs() < 0.1);
        assert_eq!(metrics.total_network_bytes(), 3_000_000);
    }

    #[test]
    fn test_operation_stats_serialization() {
        let stats = OperationStats::new(100, 5000.0, 10.0, 200.0);
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: OperationStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_operation_stats_empty() {
        let stats = OperationStats::empty();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.total_duration_ms, 0.0);
        assert_eq!(stats.avg_duration_ms, 0.0);
        assert_eq!(stats.ops_per_second(), 0.0);
    }

    #[test]
    fn test_bandwidth_metrics_default() {
        let metrics = BandwidthMetrics::default();
        assert_eq!(metrics.bytes_transferred, 0);
        assert_eq!(metrics.avg_bps, 0.0);
    }

    #[test]
    fn test_operation_stats_builder() {
        let stats = OperationStatsBuilder::new()
            .count(100)
            .total_duration_ms(5000.0)
            .min_duration_ms(10.0)
            .max_duration_ms(200.0)
            .build();

        assert_eq!(stats.count, 100);
        assert_eq!(stats.total_duration_ms, 5000.0);
        assert_eq!(stats.min_duration_ms, 10.0);
        assert_eq!(stats.max_duration_ms, 200.0);
        assert_eq!(stats.avg_duration_ms, 50.0);
    }

    #[test]
    fn test_operation_stats_builder_partial() {
        let stats = OperationStatsBuilder::new()
            .count(10)
            .total_duration_ms(1000.0)
            .build();

        assert_eq!(stats.count, 10);
        assert_eq!(stats.total_duration_ms, 1000.0);
        assert_eq!(stats.avg_duration_ms, 100.0);
    }

    #[test]
    fn test_bandwidth_metrics_builder() {
        let metrics = BandwidthMetricsBuilder::new()
            .bytes_transferred(1_000_000)
            .total_time_ms(1000.0)
            .transfer_count(10)
            .peak_bps(2_000_000.0)
            .build();

        assert_eq!(metrics.bytes_transferred, 1_000_000);
        assert_eq!(metrics.total_time_ms, 1000.0);
        assert_eq!(metrics.transfer_count, 10);
        assert_eq!(metrics.peak_bps, 2_000_000.0);
    }
}
