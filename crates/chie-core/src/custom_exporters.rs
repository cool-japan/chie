//! Custom metrics exporters for StatsD and InfluxDB.
//!
//! This module provides exporters that convert metrics to StatsD and InfluxDB formats,
//! enabling integration with popular monitoring systems beyond Prometheus.
//!
//! # Features
//!
//! - StatsD format export (UDP-friendly)
//! - InfluxDB Line Protocol export
//! - Tag/label support for both formats
//! - Batch export optimization
//! - Zero-copy conversions where possible
//!
//! # Example
//!
//! ```
//! use chie_core::custom_exporters::{StatsDExporter, InfluxDBExporter, MetricValue};
//! use std::collections::HashMap;
//!
//! // Export to StatsD format
//! let statsd = StatsDExporter::new("chie".to_string());
//! let mut tags = HashMap::new();
//! tags.insert("node", "node1");
//! let output = statsd.format_metric("requests", MetricValue::Counter(100.0), &tags);
//! // Output: chie.requests:100|c|#node:node1
//!
//! // Export to InfluxDB Line Protocol
//! let influx = InfluxDBExporter::new("chie_metrics".to_string());
//! let output = influx.format_metric("requests", MetricValue::Gauge(42.0), &tags, Some(1609459200));
//! // Output: chie_metrics,node=node1 requests=42.0 1609459200
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metric value types for export.
#[derive(Debug, Clone, Copy)]
pub enum MetricValue {
    /// Counter value (monotonically increasing).
    Counter(f64),
    /// Gauge value (can go up or down).
    Gauge(f64),
    /// Histogram sum and count.
    Histogram { sum: f64, count: u64 },
}

impl MetricValue {
    /// Get the numeric value for simple metrics.
    #[must_use]
    #[inline]
    pub fn value(&self) -> f64 {
        match self {
            Self::Counter(v) | Self::Gauge(v) => *v,
            Self::Histogram { sum, count } => {
                if *count == 0 {
                    0.0
                } else {
                    sum / (*count as f64)
                }
            }
        }
    }

    /// Get the StatsD type suffix.
    #[must_use]
    #[inline]
    pub fn statsd_type(&self) -> &'static str {
        match self {
            Self::Counter(_) => "c",
            Self::Gauge(_) => "g",
            Self::Histogram { .. } => "h",
        }
    }
}

/// StatsD format exporter.
///
/// Exports metrics in StatsD format: `namespace.metric:value|type|#tags`
pub struct StatsDExporter {
    /// Namespace prefix for all metrics.
    namespace: String,
    /// Default sample rate (0.0 to 1.0).
    sample_rate: f64,
}

impl StatsDExporter {
    /// Create a new StatsD exporter with a namespace.
    #[must_use]
    #[inline]
    pub fn new(namespace: String) -> Self {
        Self {
            namespace,
            sample_rate: 1.0,
        }
    }

    /// Create a new StatsD exporter with custom sample rate.
    #[must_use]
    #[inline]
    pub fn with_sample_rate(namespace: String, sample_rate: f64) -> Self {
        Self {
            namespace,
            sample_rate: sample_rate.clamp(0.0, 1.0),
        }
    }

    /// Format a single metric in StatsD format.
    ///
    /// # Format
    /// `namespace.metric_name:value|type|#tag1:val1,tag2:val2`
    ///
    /// # Arguments
    /// * `name` - Metric name
    /// * `value` - Metric value and type
    /// * `tags` - Optional tags (key-value pairs)
    #[must_use]
    pub fn format_metric(
        &self,
        name: &str,
        value: MetricValue,
        tags: &HashMap<&str, &str>,
    ) -> String {
        let mut output = format!(
            "{}.{}:{}|{}",
            self.namespace,
            name.replace('.', "_"),
            value.value(),
            value.statsd_type()
        );

        // Add sample rate if not 1.0
        if (self.sample_rate - 1.0).abs() > f64::EPSILON {
            output.push_str(&format!("|@{:.2}", self.sample_rate));
        }

        // Add tags if present
        if !tags.is_empty() {
            output.push_str("|#");
            let tag_str: Vec<String> = tags.iter().map(|(k, v)| format!("{}:{}", k, v)).collect();
            output.push_str(&tag_str.join(","));
        }

        output
    }

    /// Format histogram metrics with detailed statistics.
    #[must_use]
    pub fn format_histogram(
        &self,
        name: &str,
        sum: f64,
        count: u64,
        tags: &HashMap<&str, &str>,
    ) -> Vec<String> {
        let mut metrics = Vec::new();

        // Sum
        metrics.push(self.format_metric(&format!("{}_sum", name), MetricValue::Counter(sum), tags));

        // Count
        metrics.push(self.format_metric(
            &format!("{}_count", name),
            MetricValue::Counter(count as f64),
            tags,
        ));

        // Average (if count > 0)
        if count > 0 {
            let avg = sum / (count as f64);
            metrics.push(self.format_metric(
                &format!("{}_avg", name),
                MetricValue::Gauge(avg),
                tags,
            ));
        }

        metrics
    }

    /// Batch format multiple metrics.
    #[must_use]
    pub fn format_batch(
        &self,
        metrics: &[(&str, MetricValue, HashMap<&str, &str>)],
    ) -> Vec<String> {
        metrics
            .iter()
            .map(|(name, value, tags)| self.format_metric(name, *value, tags))
            .collect()
    }
}

impl Default for StatsDExporter {
    fn default() -> Self {
        Self::new("chie".to_string())
    }
}

/// InfluxDB Line Protocol exporter.
///
/// Exports metrics in InfluxDB Line Protocol format:
/// `measurement,tag1=value1,tag2=value2 field1=value1,field2=value2 timestamp`
pub struct InfluxDBExporter {
    /// Measurement name (table/series name).
    measurement: String,
    /// Precision for timestamps (nanoseconds, microseconds, milliseconds, seconds).
    time_precision: TimePrecision,
}

/// Time precision for InfluxDB timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimePrecision {
    /// Nanoseconds (ns).
    Nanoseconds,
    /// Microseconds (u, µ).
    Microseconds,
    /// Milliseconds (ms).
    Milliseconds,
    /// Seconds (s).
    Seconds,
}

impl TimePrecision {
    /// Convert SystemTime to timestamp in this precision.
    #[must_use]
    #[inline]
    pub fn from_system_time(&self, time: SystemTime) -> u64 {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();

        match self {
            Self::Nanoseconds => duration.as_nanos() as u64,
            Self::Microseconds => duration.as_micros() as u64,
            Self::Milliseconds => duration.as_millis() as u64,
            Self::Seconds => duration.as_secs(),
        }
    }

    /// Get the precision as a string for InfluxDB API.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nanoseconds => "ns",
            Self::Microseconds => "u",
            Self::Milliseconds => "ms",
            Self::Seconds => "s",
        }
    }
}

impl InfluxDBExporter {
    /// Create a new InfluxDB exporter with a measurement name.
    #[must_use]
    #[inline]
    pub fn new(measurement: String) -> Self {
        Self {
            measurement,
            time_precision: TimePrecision::Nanoseconds,
        }
    }

    /// Create a new InfluxDB exporter with custom time precision.
    #[must_use]
    #[inline]
    pub fn with_precision(measurement: String, precision: TimePrecision) -> Self {
        Self {
            measurement,
            time_precision: precision,
        }
    }

    /// Format a single metric in InfluxDB Line Protocol.
    ///
    /// # Format
    /// `measurement,tag1=value1 field=value timestamp`
    ///
    /// # Arguments
    /// * `field_name` - Field name (metric name)
    /// * `value` - Metric value
    /// * `tags` - Optional tags
    /// * `timestamp` - Optional UNIX timestamp (uses current time if None)
    #[must_use]
    pub fn format_metric(
        &self,
        field_name: &str,
        value: MetricValue,
        tags: &HashMap<&str, &str>,
        timestamp: Option<u64>,
    ) -> String {
        let mut output = self.measurement.clone();

        // Add tags
        if !tags.is_empty() {
            for (key, val) in tags {
                output.push(',');
                output.push_str(&Self::escape_tag_key(key));
                output.push('=');
                output.push_str(&Self::escape_tag_value(val));
            }
        }

        output.push(' ');

        // Add field
        output.push_str(&Self::escape_field_key(field_name));
        output.push('=');

        match value {
            MetricValue::Counter(v) | MetricValue::Gauge(v) => {
                // Use integer format if value is a whole number
                if v.fract().abs() < f64::EPSILON {
                    output.push_str(&format!("{}i", v as i64));
                } else {
                    output.push_str(&v.to_string());
                }
            }
            MetricValue::Histogram { sum, count } => {
                // For histograms, output average
                if count > 0 {
                    output.push_str(&(sum / count as f64).to_string());
                } else {
                    output.push_str("0.0");
                }
            }
        }

        // Add timestamp
        let ts =
            timestamp.unwrap_or_else(|| self.time_precision.from_system_time(SystemTime::now()));
        output.push(' ');
        output.push_str(&ts.to_string());

        output
    }

    /// Format histogram with detailed fields.
    #[must_use]
    pub fn format_histogram(
        &self,
        name: &str,
        sum: f64,
        count: u64,
        tags: &HashMap<&str, &str>,
        timestamp: Option<u64>,
    ) -> String {
        let mut output = self.measurement.clone();

        // Add tags
        if !tags.is_empty() {
            for (key, val) in tags {
                output.push(',');
                output.push_str(&Self::escape_tag_key(key));
                output.push('=');
                output.push_str(&Self::escape_tag_value(val));
            }
        }

        output.push(' ');

        // Add multiple fields
        output.push_str(&format!("{}_sum={},", Self::escape_field_key(name), sum));
        output.push_str(&format!(
            "{}_count={}i",
            Self::escape_field_key(name),
            count
        ));

        if count > 0 {
            let avg = sum / (count as f64);
            output.push_str(&format!(",{}_avg={}", Self::escape_field_key(name), avg));
        }

        // Add timestamp
        let ts =
            timestamp.unwrap_or_else(|| self.time_precision.from_system_time(SystemTime::now()));
        output.push(' ');
        output.push_str(&ts.to_string());

        output
    }

    /// Batch format multiple metrics with the same timestamp.
    #[must_use]
    pub fn format_batch(
        &self,
        metrics: &[(&str, MetricValue, HashMap<&str, &str>)],
        timestamp: Option<u64>,
    ) -> Vec<String> {
        let ts =
            timestamp.unwrap_or_else(|| self.time_precision.from_system_time(SystemTime::now()));

        metrics
            .iter()
            .map(|(name, value, tags)| self.format_metric(name, *value, tags, Some(ts)))
            .collect()
    }

    /// Escape tag keys (special chars: comma, equals, space).
    #[must_use]
    #[inline]
    fn escape_tag_key(key: &str) -> String {
        key.replace(',', "\\,")
            .replace('=', "\\=")
            .replace(' ', "\\ ")
    }

    /// Escape tag values (special chars: comma, equals, space).
    #[must_use]
    #[inline]
    fn escape_tag_value(value: &str) -> String {
        value
            .replace(',', "\\,")
            .replace('=', "\\=")
            .replace(' ', "\\ ")
    }

    /// Escape field keys (special chars: comma, equals, space).
    #[must_use]
    #[inline]
    fn escape_field_key(key: &str) -> String {
        key.replace(',', "\\,")
            .replace('=', "\\=")
            .replace(' ', "\\ ")
    }
}

impl Default for InfluxDBExporter {
    fn default() -> Self {
        Self::new("chie_metrics".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_value_simple() {
        let counter = MetricValue::Counter(42.0);
        assert_eq!(counter.value(), 42.0);
        assert_eq!(counter.statsd_type(), "c");

        let gauge = MetricValue::Gauge(2.5);
        assert_eq!(gauge.value(), 2.5);
        assert_eq!(gauge.statsd_type(), "g");
    }

    #[test]
    fn test_metric_value_histogram() {
        let hist = MetricValue::Histogram {
            sum: 100.0,
            count: 10,
        };
        assert_eq!(hist.value(), 10.0); // average
        assert_eq!(hist.statsd_type(), "h");

        // Zero count
        let empty = MetricValue::Histogram { sum: 0.0, count: 0 };
        assert_eq!(empty.value(), 0.0);
    }

    #[test]
    fn test_statsd_simple_metric() {
        let exporter = StatsDExporter::new("test".to_string());
        let tags = HashMap::new();

        let output = exporter.format_metric("requests", MetricValue::Counter(100.0), &tags);
        assert_eq!(output, "test.requests:100|c");
    }

    #[test]
    fn test_statsd_with_tags() {
        let exporter = StatsDExporter::new("app".to_string());
        let mut tags = HashMap::new();
        tags.insert("host", "server1");
        tags.insert("env", "prod");

        let output = exporter.format_metric("latency", MetricValue::Gauge(42.5), &tags);
        assert!(output.starts_with("app.latency:42.5|g|#"));
        assert!(output.contains("host:server1"));
        assert!(output.contains("env:prod"));
    }

    #[test]
    fn test_statsd_sample_rate() {
        let exporter = StatsDExporter::with_sample_rate("test".to_string(), 0.5);
        let tags = HashMap::new();

        let output = exporter.format_metric("requests", MetricValue::Counter(10.0), &tags);
        assert_eq!(output, "test.requests:10|c|@0.50");
    }

    #[test]
    fn test_statsd_histogram() {
        let exporter = StatsDExporter::new("test".to_string());
        let tags = HashMap::new();

        let outputs = exporter.format_histogram("duration", 250.0, 50, &tags);
        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0], "test.duration_sum:250|c");
        assert_eq!(outputs[1], "test.duration_count:50|c");
        assert_eq!(outputs[2], "test.duration_avg:5|g");
    }

    #[test]
    fn test_statsd_batch() {
        let exporter = StatsDExporter::new("batch".to_string());
        let tags = HashMap::new();

        let metrics = vec![
            ("metric1", MetricValue::Counter(1.0), tags.clone()),
            ("metric2", MetricValue::Gauge(2.0), tags.clone()),
        ];

        let outputs = exporter.format_batch(&metrics);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0], "batch.metric1:1|c");
        assert_eq!(outputs[1], "batch.metric2:2|g");
    }

    #[test]
    fn test_influxdb_simple_metric() {
        let exporter = InfluxDBExporter::new("metrics".to_string());
        let tags = HashMap::new();

        let output = exporter.format_metric(
            "requests",
            MetricValue::Counter(100.0),
            &tags,
            Some(1609459200),
        );
        assert_eq!(output, "metrics requests=100i 1609459200");
    }

    #[test]
    fn test_influxdb_with_tags() {
        let exporter = InfluxDBExporter::new("metrics".to_string());
        let mut tags = HashMap::new();
        tags.insert("host", "server1");
        tags.insert("region", "us-west");

        let output =
            exporter.format_metric("cpu", MetricValue::Gauge(75.5), &tags, Some(1609459200));
        assert!(output.starts_with("metrics,"));
        assert!(output.contains("host=server1"));
        assert!(output.contains("region=us-west"));
        assert!(output.contains(" cpu=75.5 1609459200"));
    }

    #[test]
    fn test_influxdb_histogram() {
        let exporter = InfluxDBExporter::new("metrics".to_string());
        let tags = HashMap::new();

        let output = exporter.format_histogram("latency", 1000.0, 20, &tags, Some(1609459200));
        assert!(output.contains("latency_sum=1000"));
        assert!(output.contains("latency_count=20i"));
        assert!(output.contains("latency_avg=50"));
        assert!(output.ends_with(" 1609459200"));
    }

    #[test]
    fn test_influxdb_escaping() {
        let exporter = InfluxDBExporter::new("metrics".to_string());
        let mut tags = HashMap::new();
        tags.insert("tag with space", "value,with=special");

        let output = exporter.format_metric(
            "field name",
            MetricValue::Counter(1.0),
            &tags,
            Some(1609459200),
        );
        assert!(output.contains("tag\\ with\\ space=value\\,with\\=special"));
        assert!(output.contains("field\\ name=1i"));
    }

    #[test]
    fn test_influxdb_batch() {
        let exporter = InfluxDBExporter::new("metrics".to_string());
        let tags = HashMap::new();

        let metrics = vec![
            ("metric1", MetricValue::Counter(1.0), tags.clone()),
            ("metric2", MetricValue::Gauge(2.5), tags.clone()),
        ];

        let outputs = exporter.format_batch(&metrics, Some(1609459200));
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0], "metrics metric1=1i 1609459200");
        assert_eq!(outputs[1], "metrics metric2=2.5 1609459200");
    }

    #[test]
    fn test_time_precision() {
        let precision = TimePrecision::Milliseconds;
        assert_eq!(precision.as_str(), "ms");

        let precision = TimePrecision::Seconds;
        assert_eq!(precision.as_str(), "s");
    }

    #[test]
    fn test_metric_name_sanitization() {
        let exporter = StatsDExporter::new("test".to_string());
        let tags = HashMap::new();

        // Dots in metric names should be replaced with underscores in StatsD
        let output =
            exporter.format_metric("http.requests.total", MetricValue::Counter(1.0), &tags);
        assert_eq!(output, "test.http_requests_total:1|c");
    }
}
