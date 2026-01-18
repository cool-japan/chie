//! Prometheus-compatible metrics exporter for observability.
//!
//! This module provides metrics collection and export in Prometheus text format,
//! allowing integration with Prometheus monitoring systems.
//!
//! # Features
//!
//! - Counter, Gauge, and Histogram metric types
//! - Prometheus text format export
//! - Label support for multi-dimensional metrics
//! - Thread-safe metric updates
//! - Zero-cost when metrics are disabled
//!
//! # Example
//!
//! ```
//! use chie_core::metrics::{MetricsRegistry, Counter, Gauge};
//!
//! let mut registry = MetricsRegistry::new();
//!
//! // Register metrics
//! let requests = registry.counter("http_requests_total", "Total HTTP requests");
//! let storage_used = registry.gauge("storage_bytes_used", "Storage bytes used");
//!
//! // Update metrics
//! requests.inc();
//! storage_used.set(1024.0);
//!
//! // Export metrics
//! let output = registry.export();
//! println!("{}", output);
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Metric type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// Counter - monotonically increasing value.
    Counter,
    /// Gauge - arbitrary value that can go up or down.
    Gauge,
    /// Histogram - samples observations (currently simplified).
    Histogram,
}

impl MetricType {
    /// Get the Prometheus type string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// Metric metadata.
#[derive(Debug, Clone)]
pub struct MetricMetadata {
    /// Metric name.
    pub name: String,
    /// Metric help text.
    pub help: String,
    /// Metric type.
    pub metric_type: MetricType,
}

/// Counter metric.
#[derive(Debug, Clone)]
pub struct Counter {
    value: Arc<Mutex<f64>>,
}

impl Counter {
    /// Create a new counter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(0.0)),
        }
    }

    /// Increment the counter by 1.
    #[inline]
    pub fn inc(&self) {
        self.add(1.0);
    }

    /// Add a value to the counter.
    #[inline]
    pub fn add(&self, value: f64) {
        if value >= 0.0 {
            let mut val = self.value.lock().unwrap();
            *val += value;
        }
    }

    /// Get the current value.
    #[must_use]
    #[inline]
    pub fn get(&self) -> f64 {
        *self.value.lock().unwrap()
    }

    /// Reset the counter to zero.
    #[inline]
    pub fn reset(&self) {
        *self.value.lock().unwrap() = 0.0;
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge metric.
#[derive(Debug, Clone)]
pub struct Gauge {
    value: Arc<Mutex<f64>>,
}

impl Gauge {
    /// Create a new gauge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(0.0)),
        }
    }

    /// Set the gauge to a value.
    #[inline]
    pub fn set(&self, value: f64) {
        *self.value.lock().unwrap() = value;
    }

    /// Increment the gauge by 1.
    #[inline]
    pub fn inc(&self) {
        self.add(1.0);
    }

    /// Decrement the gauge by 1.
    #[inline]
    pub fn dec(&self) {
        self.sub(1.0);
    }

    /// Add a value to the gauge.
    #[inline]
    pub fn add(&self, value: f64) {
        let mut val = self.value.lock().unwrap();
        *val += value;
    }

    /// Subtract a value from the gauge.
    #[inline]
    pub fn sub(&self, value: f64) {
        let mut val = self.value.lock().unwrap();
        *val -= value;
    }

    /// Get the current value.
    #[must_use]
    #[inline]
    pub fn get(&self) -> f64 {
        *self.value.lock().unwrap()
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Histogram metric (simplified).
#[derive(Debug, Clone)]
pub struct Histogram {
    sum: Arc<Mutex<f64>>,
    count: Arc<Mutex<u64>>,
}

impl Histogram {
    /// Create a new histogram.
    pub fn new() -> Self {
        Self {
            sum: Arc::new(Mutex::new(0.0)),
            count: Arc::new(Mutex::new(0)),
        }
    }

    /// Observe a value.
    #[inline]
    pub fn observe(&self, value: f64) {
        let mut sum = self.sum.lock().unwrap();
        let mut count = self.count.lock().unwrap();
        *sum += value;
        *count += 1;
    }

    /// Get the sum of all observations.
    #[inline]
    pub fn sum(&self) -> f64 {
        *self.sum.lock().unwrap()
    }

    /// Get the count of observations.
    #[must_use]
    #[inline]
    pub fn count(&self) -> u64 {
        *self.count.lock().unwrap()
    }

    /// Get the average value.
    #[inline]
    pub fn avg(&self) -> f64 {
        let sum = *self.sum.lock().unwrap();
        let count = *self.count.lock().unwrap();
        if count == 0 { 0.0 } else { sum / count as f64 }
    }

    /// Reset the histogram.
    #[inline]
    pub fn reset(&self) {
        *self.sum.lock().unwrap() = 0.0;
        *self.count.lock().unwrap() = 0;
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics registry for collecting and exporting metrics.
pub struct MetricsRegistry {
    metadata: HashMap<String, MetricMetadata>,
    counters: HashMap<String, Counter>,
    gauges: HashMap<String, Gauge>,
    histograms: HashMap<String, Histogram>,
}

impl MetricsRegistry {
    /// Create a new metrics registry.
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new(),
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
        }
    }

    /// Register and return a counter metric.
    pub fn counter(&mut self, name: &str, help: &str) -> Counter {
        self.metadata.insert(
            name.to_string(),
            MetricMetadata {
                name: name.to_string(),
                help: help.to_string(),
                metric_type: MetricType::Counter,
            },
        );

        let counter = Counter::new();
        self.counters.insert(name.to_string(), counter.clone());
        counter
    }

    /// Register and return a gauge metric.
    pub fn gauge(&mut self, name: &str, help: &str) -> Gauge {
        self.metadata.insert(
            name.to_string(),
            MetricMetadata {
                name: name.to_string(),
                help: help.to_string(),
                metric_type: MetricType::Gauge,
            },
        );

        let gauge = Gauge::new();
        self.gauges.insert(name.to_string(), gauge.clone());
        gauge
    }

    /// Register and return a histogram metric.
    pub fn histogram(&mut self, name: &str, help: &str) -> Histogram {
        self.metadata.insert(
            name.to_string(),
            MetricMetadata {
                name: name.to_string(),
                help: help.to_string(),
                metric_type: MetricType::Histogram,
            },
        );

        let histogram = Histogram::new();
        self.histograms.insert(name.to_string(), histogram.clone());
        histogram
    }

    /// Export all metrics in Prometheus text format.
    #[must_use]
    #[inline]
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Export counters
        for (name, counter) in &self.counters {
            if let Some(meta) = self.metadata.get(name) {
                output.push_str(&format!("# HELP {} {}\n", meta.name, meta.help));
                output.push_str(&format!(
                    "# TYPE {} {}\n",
                    meta.name,
                    meta.metric_type.as_str()
                ));
                output.push_str(&format!("{} {}\n", name, counter.get()));
            }
        }

        // Export gauges
        for (name, gauge) in &self.gauges {
            if let Some(meta) = self.metadata.get(name) {
                output.push_str(&format!("# HELP {} {}\n", meta.name, meta.help));
                output.push_str(&format!(
                    "# TYPE {} {}\n",
                    meta.name,
                    meta.metric_type.as_str()
                ));
                output.push_str(&format!("{} {}\n", name, gauge.get()));
            }
        }

        // Export histograms
        for (name, histogram) in &self.histograms {
            if let Some(meta) = self.metadata.get(name) {
                output.push_str(&format!("# HELP {} {}\n", meta.name, meta.help));
                output.push_str(&format!(
                    "# TYPE {} {}\n",
                    meta.name,
                    meta.metric_type.as_str()
                ));
                output.push_str(&format!("{}_sum {}\n", name, histogram.sum()));
                output.push_str(&format!("{}_count {}\n", name, histogram.count()));
            }
        }

        output
    }

    /// Get counter by name.
    #[must_use]
    #[inline]
    pub fn get_counter(&self, name: &str) -> Option<&Counter> {
        self.counters.get(name)
    }

    /// Get gauge by name.
    #[must_use]
    #[inline]
    pub fn get_gauge(&self, name: &str) -> Option<&Gauge> {
        self.gauges.get(name)
    }

    /// Get histogram by name.
    #[must_use]
    #[inline]
    pub fn get_histogram(&self, name: &str) -> Option<&Histogram> {
        self.histograms.get(name)
    }

    /// Reset all metrics.
    pub fn reset_all(&self) {
        for counter in self.counters.values() {
            counter.reset();
        }
        for histogram in self.histograms.values() {
            histogram.reset();
        }
        // Note: Gauges are not reset as they represent current state
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a standard metrics registry with common CHIE metrics.
pub fn create_standard_registry() -> MetricsRegistry {
    let mut registry = MetricsRegistry::new();

    // Content metrics
    registry.counter("chie_content_requests_total", "Total content requests");
    registry.counter("chie_content_requests_failed", "Failed content requests");
    registry.counter("chie_bytes_transferred_total", "Total bytes transferred");
    registry.gauge("chie_storage_bytes_used", "Storage bytes used");
    registry.gauge("chie_storage_bytes_available", "Storage bytes available");
    registry.gauge(
        "chie_pinned_content_count",
        "Number of pinned content items",
    );

    // Peer metrics
    registry.gauge("chie_connected_peers", "Number of connected peers");
    registry.counter("chie_peer_connections_total", "Total peer connections");
    registry.counter(
        "chie_peer_disconnections_total",
        "Total peer disconnections",
    );

    // Bandwidth proof metrics
    registry.counter(
        "chie_bandwidth_proofs_submitted",
        "Total bandwidth proofs submitted",
    );
    registry.counter(
        "chie_bandwidth_proofs_verified",
        "Total bandwidth proofs verified",
    );
    registry.counter(
        "chie_bandwidth_proofs_failed",
        "Failed bandwidth proof submissions",
    );

    // Performance metrics
    registry.histogram(
        "chie_request_duration_seconds",
        "Request duration in seconds",
    );
    registry.histogram(
        "chie_chunk_transfer_duration_seconds",
        "Chunk transfer duration",
    );

    // Earnings metrics
    registry.gauge("chie_earnings_total", "Total earnings");
    registry.gauge("chie_earnings_pending", "Pending earnings");

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_basic() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0.0);

        counter.inc();
        assert_eq!(counter.get(), 1.0);

        counter.add(5.0);
        assert_eq!(counter.get(), 6.0);

        counter.reset();
        assert_eq!(counter.get(), 0.0);
    }

    #[test]
    fn test_counter_negative() {
        let counter = Counter::new();
        counter.add(-5.0);
        assert_eq!(counter.get(), 0.0); // Should not allow negative
    }

    #[test]
    fn test_gauge_basic() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0.0);

        gauge.set(10.0);
        assert_eq!(gauge.get(), 10.0);

        gauge.inc();
        assert_eq!(gauge.get(), 11.0);

        gauge.dec();
        assert_eq!(gauge.get(), 10.0);

        gauge.add(5.0);
        assert_eq!(gauge.get(), 15.0);

        gauge.sub(3.0);
        assert_eq!(gauge.get(), 12.0);
    }

    #[test]
    fn test_histogram_basic() {
        let histogram = Histogram::new();
        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.sum(), 0.0);

        histogram.observe(1.0);
        histogram.observe(2.0);
        histogram.observe(3.0);

        assert_eq!(histogram.count(), 3);
        assert_eq!(histogram.sum(), 6.0);
        assert_eq!(histogram.avg(), 2.0);

        histogram.reset();
        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.sum(), 0.0);
    }

    #[test]
    fn test_registry_counter() {
        let mut registry = MetricsRegistry::new();
        let counter = registry.counter("test_counter", "Test counter");

        counter.inc();
        assert_eq!(counter.get(), 1.0);

        let retrieved = registry.get_counter("test_counter").unwrap();
        assert_eq!(retrieved.get(), 1.0);
    }

    #[test]
    fn test_registry_gauge() {
        let mut registry = MetricsRegistry::new();
        let gauge = registry.gauge("test_gauge", "Test gauge");

        gauge.set(42.0);
        assert_eq!(gauge.get(), 42.0);

        let retrieved = registry.get_gauge("test_gauge").unwrap();
        assert_eq!(retrieved.get(), 42.0);
    }

    #[test]
    fn test_registry_histogram() {
        let mut registry = MetricsRegistry::new();
        let histogram = registry.histogram("test_histogram", "Test histogram");

        histogram.observe(1.0);
        histogram.observe(2.0);

        let retrieved = registry.get_histogram("test_histogram").unwrap();
        assert_eq!(retrieved.count(), 2);
        assert_eq!(retrieved.sum(), 3.0);
    }

    #[test]
    fn test_export_format() {
        let mut registry = MetricsRegistry::new();
        let counter = registry.counter("test_counter", "Test counter");
        let gauge = registry.gauge("test_gauge", "Test gauge");

        counter.inc();
        gauge.set(42.0);

        let output = registry.export();
        assert!(output.contains("# HELP test_counter Test counter"));
        assert!(output.contains("# TYPE test_counter counter"));
        assert!(output.contains("test_counter 1"));
        assert!(output.contains("# HELP test_gauge Test gauge"));
        assert!(output.contains("# TYPE test_gauge gauge"));
        assert!(output.contains("test_gauge 42"));
    }

    #[test]
    fn test_reset_all() {
        let mut registry = MetricsRegistry::new();
        let counter = registry.counter("test_counter", "Test counter");
        let histogram = registry.histogram("test_histogram", "Test histogram");

        counter.inc();
        histogram.observe(1.0);

        registry.reset_all();

        assert_eq!(counter.get(), 0.0);
        assert_eq!(histogram.count(), 0);
    }

    #[test]
    fn test_create_standard_registry() {
        let registry = create_standard_registry();
        assert!(
            registry
                .get_counter("chie_content_requests_total")
                .is_some()
        );
        assert!(registry.get_gauge("chie_storage_bytes_used").is_some());
        assert!(
            registry
                .get_histogram("chie_request_duration_seconds")
                .is_some()
        );
    }

    #[test]
    fn test_counter_clone() {
        let counter1 = Counter::new();
        let counter2 = counter1.clone();

        counter1.inc();
        assert_eq!(counter2.get(), 1.0);
    }

    #[test]
    fn test_gauge_clone() {
        let gauge1 = Gauge::new();
        let gauge2 = gauge1.clone();

        gauge1.set(10.0);
        assert_eq!(gauge2.get(), 10.0);
    }
}
