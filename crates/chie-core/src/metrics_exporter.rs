//! Custom metrics exporters for external monitoring systems.
//!
//! This module provides exporters for various monitoring formats including
//! StatsD and InfluxDB line protocol.
//!
//! # Supported Formats
//!
//! - **StatsD**: Simple UDP-based metrics protocol
//! - **InfluxDB**: Time-series database line protocol
//!
//! # Example
//!
//! ```
//! use chie_core::metrics_exporter::{MetricsExporter, ExportFormat, MetricValue};
//!
//! let exporter = MetricsExporter::new(ExportFormat::StatsD);
//!
//! // Export a counter
//! let output = exporter.export_counter("chie.chunks.stored", 42, &[("node", "node1")]);
//! assert!(output.contains("chie.chunks.stored"));
//!
//! // Export a gauge
//! let output = exporter.export_gauge("chie.storage.used_bytes", 1024000, &[]);
//! assert!(output.contains("1024000"));
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Type alias for metric batch entries.
type MetricBatchEntry = (String, MetricValue, Vec<(String, String)>);

/// Supported metrics export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// StatsD format (metric_name:value|type|@sample_rate|#tags).
    StatsD,
    /// InfluxDB line protocol (measurement,tag=value field=value timestamp).
    InfluxDB,
}

/// Metric value types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MetricValue {
    /// Counter - monotonically increasing value.
    Counter(u64),
    /// Gauge - arbitrary value that can go up or down.
    Gauge(i64),
    /// Timing - duration in milliseconds.
    Timing(u64),
    /// Histogram - value for distribution analysis.
    Histogram(f64),
}

impl MetricValue {
    /// Get the StatsD type suffix.
    #[must_use]
    #[inline]
    const fn statsd_type(&self) -> &'static str {
        match self {
            Self::Counter(_) => "c",
            Self::Gauge(_) => "g",
            Self::Timing(_) => "ms",
            Self::Histogram(_) => "h",
        }
    }

    /// Get the numeric value as a string.
    #[must_use]
    #[inline]
    fn value_string(&self) -> String {
        match self {
            Self::Counter(v) => v.to_string(),
            Self::Gauge(v) => v.to_string(),
            Self::Timing(v) => v.to_string(),
            Self::Histogram(v) => v.to_string(),
        }
    }
}

/// Metrics exporter for external monitoring systems.
pub struct MetricsExporter {
    format: ExportFormat,
    default_tags: HashMap<String, String>,
}

impl MetricsExporter {
    /// Create a new metrics exporter with the specified format.
    #[must_use]
    pub fn new(format: ExportFormat) -> Self {
        Self {
            format,
            default_tags: HashMap::new(),
        }
    }

    /// Create a new exporter with default tags.
    #[must_use]
    pub fn with_tags(format: ExportFormat, tags: &[(&str, &str)]) -> Self {
        let default_tags: HashMap<String, String> = tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();

        Self {
            format,
            default_tags,
        }
    }

    /// Add a default tag to all exported metrics.
    pub fn add_default_tag(&mut self, key: String, value: String) {
        self.default_tags.insert(key, value);
    }

    /// Export a counter metric.
    #[must_use]
    pub fn export_counter(&self, name: &str, value: u64, tags: &[(&str, &str)]) -> String {
        self.export_metric(name, MetricValue::Counter(value), tags)
    }

    /// Export a gauge metric.
    #[must_use]
    pub fn export_gauge(&self, name: &str, value: i64, tags: &[(&str, &str)]) -> String {
        self.export_metric(name, MetricValue::Gauge(value), tags)
    }

    /// Export a timing metric.
    #[must_use]
    pub fn export_timing(&self, name: &str, duration_ms: u64, tags: &[(&str, &str)]) -> String {
        self.export_metric(name, MetricValue::Timing(duration_ms), tags)
    }

    /// Export a histogram metric.
    #[must_use]
    pub fn export_histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]) -> String {
        self.export_metric(name, MetricValue::Histogram(value), tags)
    }

    /// Export a generic metric.
    #[must_use]
    pub fn export_metric(&self, name: &str, value: MetricValue, tags: &[(&str, &str)]) -> String {
        match self.format {
            ExportFormat::StatsD => self.format_statsd(name, value, tags),
            ExportFormat::InfluxDB => self.format_influxdb(name, value, tags),
        }
    }

    /// Format a metric in StatsD format.
    #[must_use]
    fn format_statsd(&self, name: &str, value: MetricValue, tags: &[(&str, &str)]) -> String {
        let mut parts = vec![format!("{}:{}", name, value.value_string())];
        parts.push(value.statsd_type().to_string());

        // Add tags if any
        let all_tags = self.merge_tags(tags);
        if !all_tags.is_empty() {
            let tag_str: Vec<String> = all_tags
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect();
            parts.push(format!("#{}", tag_str.join(",")));
        }

        parts.join("|")
    }

    /// Format a metric in InfluxDB line protocol format.
    #[must_use]
    fn format_influxdb(&self, name: &str, value: MetricValue, tags: &[(&str, &str)]) -> String {
        let all_tags = self.merge_tags(tags);

        // Measurement with tags
        let mut measurement = name.to_string();
        if !all_tags.is_empty() {
            let tag_str: Vec<String> = all_tags
                .iter()
                .map(|(k, v)| format!("{}={}", escape_influx_key(k), escape_influx_value(v)))
                .collect();
            measurement.push(',');
            measurement.push_str(&tag_str.join(","));
        }

        // Field
        let field_name = "value";
        let field_value = value.value_string();

        // Timestamp (nanoseconds)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        format!(
            "{} {}={} {}",
            measurement, field_name, field_value, timestamp
        )
    }

    /// Merge default tags with provided tags.
    #[must_use]
    fn merge_tags(&self, tags: &[(&str, &str)]) -> HashMap<String, String> {
        let mut all_tags = self.default_tags.clone();
        for (k, v) in tags {
            all_tags.insert((*k).to_string(), (*v).to_string());
        }
        all_tags
    }

    /// Export multiple metrics at once.
    #[must_use]
    pub fn export_batch(&self, metrics: &[MetricBatchEntry]) -> Vec<String> {
        metrics
            .iter()
            .map(|(name, value, tags)| {
                let tag_refs: Vec<(&str, &str)> =
                    tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                self.export_metric(name, *value, &tag_refs)
            })
            .collect()
    }
}

/// Escape InfluxDB measurement/tag keys.
#[must_use]
#[inline]
fn escape_influx_key(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape InfluxDB tag values.
#[must_use]
#[inline]
fn escape_influx_value(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// A builder for batch metric exports.
pub struct MetricsBatch {
    metrics: Vec<MetricBatchEntry>,
}

impl Default for MetricsBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsBatch {
    /// Create a new batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    /// Add a counter to the batch.
    pub fn add_counter(mut self, name: String, value: u64, tags: Vec<(String, String)>) -> Self {
        self.metrics.push((name, MetricValue::Counter(value), tags));
        self
    }

    /// Add a gauge to the batch.
    pub fn add_gauge(mut self, name: String, value: i64, tags: Vec<(String, String)>) -> Self {
        self.metrics.push((name, MetricValue::Gauge(value), tags));
        self
    }

    /// Add a timing to the batch.
    pub fn add_timing(
        mut self,
        name: String,
        duration_ms: u64,
        tags: Vec<(String, String)>,
    ) -> Self {
        self.metrics
            .push((name, MetricValue::Timing(duration_ms), tags));
        self
    }

    /// Add a histogram value to the batch.
    pub fn add_histogram(mut self, name: String, value: f64, tags: Vec<(String, String)>) -> Self {
        self.metrics
            .push((name, MetricValue::Histogram(value), tags));
        self
    }

    /// Export the batch using the provided exporter.
    #[must_use]
    pub fn export(&self, exporter: &MetricsExporter) -> Vec<String> {
        exporter.export_batch(&self.metrics)
    }

    /// Get the number of metrics in the batch.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    /// Check if the batch is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
    }
}

/// Common metrics that can be exported.
pub struct CommonMetrics;

impl CommonMetrics {
    /// Export storage metrics.
    #[must_use]
    pub fn storage_metrics(
        exporter: &MetricsExporter,
        used_bytes: u64,
        total_bytes: u64,
        chunk_count: u64,
    ) -> Vec<String> {
        vec![
            exporter.export_gauge("chie.storage.used_bytes", used_bytes as i64, &[]),
            exporter.export_gauge("chie.storage.total_bytes", total_bytes as i64, &[]),
            exporter.export_gauge("chie.storage.chunks_count", chunk_count as i64, &[]),
        ]
    }

    /// Export bandwidth metrics.
    #[must_use]
    pub fn bandwidth_metrics(
        exporter: &MetricsExporter,
        bytes_sent: u64,
        bytes_received: u64,
        requests_served: u64,
    ) -> Vec<String> {
        vec![
            exporter.export_counter("chie.bandwidth.bytes_sent", bytes_sent, &[]),
            exporter.export_counter("chie.bandwidth.bytes_received", bytes_received, &[]),
            exporter.export_counter("chie.bandwidth.requests_served", requests_served, &[]),
        ]
    }

    /// Export performance metrics.
    #[must_use]
    pub fn performance_metrics(
        exporter: &MetricsExporter,
        avg_latency_ms: u64,
        p95_latency_ms: u64,
        p99_latency_ms: u64,
    ) -> Vec<String> {
        vec![
            exporter.export_timing("chie.performance.latency.avg", avg_latency_ms, &[]),
            exporter.export_timing("chie.performance.latency.p95", p95_latency_ms, &[]),
            exporter.export_timing("chie.performance.latency.p99", p99_latency_ms, &[]),
        ]
    }

    /// Export cache metrics.
    #[must_use]
    pub fn cache_metrics(
        exporter: &MetricsExporter,
        hits: u64,
        misses: u64,
        evictions: u64,
    ) -> Vec<String> {
        vec![
            exporter.export_counter("chie.cache.hits", hits, &[]),
            exporter.export_counter("chie.cache.misses", misses, &[]),
            exporter.export_counter("chie.cache.evictions", evictions, &[]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statsd_counter() {
        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let output = exporter.export_counter("test.counter", 42, &[]);
        assert_eq!(output, "test.counter:42|c");
    }

    #[test]
    fn test_statsd_gauge() {
        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let output = exporter.export_gauge("test.gauge", -10, &[]);
        assert_eq!(output, "test.gauge:-10|g");
    }

    #[test]
    fn test_statsd_timing() {
        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let output = exporter.export_timing("test.timing", 250, &[]);
        assert_eq!(output, "test.timing:250|ms");
    }

    #[test]
    fn test_statsd_with_tags() {
        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let output =
            exporter.export_counter("test.counter", 1, &[("host", "server1"), ("env", "prod")]);
        assert!(output.contains("test.counter:1|c|#"));
        assert!(output.contains("host:server1"));
        assert!(output.contains("env:prod"));
    }

    #[test]
    fn test_influxdb_format() {
        let exporter = MetricsExporter::new(ExportFormat::InfluxDB);
        let output = exporter.export_counter("test_counter", 42, &[("host", "server1")]);
        assert!(output.contains("test_counter,host=server1"));
        assert!(output.contains("value=42"));
    }

    #[test]
    fn test_default_tags() {
        let exporter = MetricsExporter::with_tags(
            ExportFormat::StatsD,
            &[("app", "chie"), ("version", "0.1.0")],
        );
        let output = exporter.export_counter("test.counter", 1, &[]);
        assert!(output.contains("app:chie"));
        assert!(output.contains("version:0.1.0"));
    }

    #[test]
    fn test_metrics_batch() {
        let batch = MetricsBatch::new()
            .add_counter("counter".to_string(), 10, vec![])
            .add_gauge("gauge".to_string(), -5, vec![])
            .add_timing("timing".to_string(), 100, vec![]);

        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());

        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let output = batch.export(&exporter);
        assert_eq!(output.len(), 3);
    }

    #[test]
    fn test_common_storage_metrics() {
        let exporter = MetricsExporter::new(ExportFormat::StatsD);
        let metrics = CommonMetrics::storage_metrics(&exporter, 1024, 2048, 10);
        assert_eq!(metrics.len(), 3);
        assert!(metrics[0].contains("chie.storage.used_bytes"));
        assert!(metrics[1].contains("chie.storage.total_bytes"));
        assert!(metrics[2].contains("chie.storage.chunks_count"));
    }

    #[test]
    fn test_influx_escaping() {
        assert_eq!(escape_influx_key("test,key"), "test\\,key");
        assert_eq!(escape_influx_key("test=key"), "test\\=key");
        assert_eq!(escape_influx_key("test key"), "test\\ key");
    }

    #[test]
    fn test_metric_value_types() {
        assert_eq!(MetricValue::Counter(1).statsd_type(), "c");
        assert_eq!(MetricValue::Gauge(1).statsd_type(), "g");
        assert_eq!(MetricValue::Timing(1).statsd_type(), "ms");
        assert_eq!(MetricValue::Histogram(1.0).statsd_type(), "h");
    }
}
