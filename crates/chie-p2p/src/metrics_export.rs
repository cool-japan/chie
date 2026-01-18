//! Advanced metrics export and observability.
//!
//! This module provides comprehensive metrics export capabilities including:
//! - Prometheus-style metrics format
//! - Real-time metrics streaming
//! - Performance profiling hooks
//! - Network visualization data export
//! - Distributed tracing integration points

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Metric type following Prometheus conventions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    /// Counter - monotonically increasing value
    Counter,
    /// Gauge - value that can go up or down
    Gauge,
    /// Histogram - distribution of values
    Histogram,
    /// Summary - similar to histogram with quantiles
    Summary,
}

impl fmt::Display for MetricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricType::Counter => write!(f, "counter"),
            MetricType::Gauge => write!(f, "gauge"),
            MetricType::Histogram => write!(f, "histogram"),
            MetricType::Summary => write!(f, "summary"),
        }
    }
}

/// A metric label (key-value pair)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetricLabel {
    /// Label key
    pub key: String,
    /// Label value
    pub value: String,
}

impl MetricLabel {
    /// Create a new label
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// A single metric value with labels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    /// Metric name
    pub name: String,
    /// Metric type
    pub metric_type: MetricType,
    /// Value
    pub value: f64,
    /// Labels
    pub labels: Vec<MetricLabel>,
    /// Timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Optional help text
    pub help: Option<String>,
}

impl MetricValue {
    /// Create a new metric value
    pub fn new(name: impl Into<String>, metric_type: MetricType, value: f64) -> Self {
        Self {
            name: name.into(),
            metric_type,
            value,
            labels: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            help: None,
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push(MetricLabel::new(key, value));
        self
    }

    /// Add help text
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Format as Prometheus exposition format
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Add help if present
        if let Some(help) = &self.help {
            output.push_str(&format!("# HELP {} {}\n", self.name, help));
        }

        // Add type
        output.push_str(&format!("# TYPE {} {}\n", self.name, self.metric_type));

        // Add metric value with labels
        output.push_str(&self.name);
        if !self.labels.is_empty() {
            output.push('{');
            let labels: Vec<String> = self
                .labels
                .iter()
                .map(|l| format!("{}=\"{}\"", l.key, l.value))
                .collect();
            output.push_str(&labels.join(","));
            output.push('}');
        }
        output.push_str(&format!(" {} {}\n", self.value, self.timestamp));

        output
    }
}

/// Histogram bucket for distribution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Upper bound (le = less than or equal)
    pub le: f64,
    /// Count of observations in this bucket
    pub count: u64,
}

/// Histogram metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    /// Metric name
    pub name: String,
    /// Buckets
    pub buckets: Vec<HistogramBucket>,
    /// Total count
    pub count: u64,
    /// Sum of all observations
    pub sum: f64,
    /// Labels
    pub labels: Vec<MetricLabel>,
}

impl Histogram {
    /// Create a new histogram with default buckets
    pub fn new(name: impl Into<String>) -> Self {
        let default_buckets = [
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        Self {
            name: name.into(),
            buckets: default_buckets
                .iter()
                .map(|&le| HistogramBucket { le, count: 0 })
                .collect(),
            count: 0,
            sum: 0.0,
            labels: Vec::new(),
        }
    }

    /// Observe a value
    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;

        for bucket in &mut self.buckets {
            if value <= bucket.le {
                bucket.count += 1;
            }
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push(MetricLabel::new(key, value));
        self
    }

    /// Format as Prometheus exposition format
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Type declaration
        output.push_str(&format!("# TYPE {} histogram\n", self.name));

        let label_str = if !self.labels.is_empty() {
            let labels: Vec<String> = self
                .labels
                .iter()
                .map(|l| format!("{}=\"{}\"", l.key, l.value))
                .collect();
            format!("{{{}}}", labels.join(","))
        } else {
            String::new()
        };

        // Buckets
        for bucket in &self.buckets {
            output.push_str(&format!(
                "{}_bucket{}{{le=\"{}\"}} {}\n",
                self.name, label_str, bucket.le, bucket.count
            ));
        }

        // +Inf bucket
        output.push_str(&format!(
            "{}_bucket{}{{le=\"+Inf\"}} {}\n",
            self.name, label_str, self.count
        ));

        // Count and sum
        output.push_str(&format!(
            "{}_count{} {}\n",
            self.name, label_str, self.count
        ));
        output.push_str(&format!("{}_sum{} {}\n", self.name, label_str, self.sum));

        output
    }
}

/// Performance profiling span for distributed tracing
#[derive(Debug, Clone)]
pub struct TracingSpan {
    /// Span ID
    pub span_id: String,
    /// Parent span ID
    pub parent_id: Option<String>,
    /// Span name/operation
    pub name: String,
    /// Start time
    pub start_time: Instant,
    /// End time
    pub end_time: Option<Instant>,
    /// Tags/attributes
    pub tags: HashMap<String, String>,
    /// Duration in microseconds
    pub duration_us: Option<u64>,
}

impl TracingSpan {
    /// Create a new tracing span
    pub fn new(span_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            span_id: span_id.into(),
            parent_id: None,
            name: name.into(),
            start_time: Instant::now(),
            end_time: None,
            tags: HashMap::new(),
            duration_us: None,
        }
    }

    /// Set parent span
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Finish the span
    pub fn finish(&mut self) {
        self.end_time = Some(Instant::now());
        self.duration_us = Some(self.start_time.elapsed().as_micros() as u64);
    }

    /// Get duration in microseconds
    pub fn duration(&self) -> Option<u64> {
        self.duration_us
    }
}

/// Network visualization node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationNode {
    /// Node ID
    pub id: String,
    /// Node label
    pub label: String,
    /// X coordinate (for layout)
    pub x: f64,
    /// Y coordinate (for layout)
    pub y: f64,
    /// Node metadata
    pub metadata: HashMap<String, String>,
}

/// Network visualization edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationEdge {
    /// Source node ID
    pub source: String,
    /// Target node ID
    pub target: String,
    /// Edge weight/bandwidth
    pub weight: f64,
    /// Edge metadata
    pub metadata: HashMap<String, String>,
}

/// Network topology visualization data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkVisualization {
    /// Nodes in the network
    pub nodes: Vec<VisualizationNode>,
    /// Edges in the network
    pub edges: Vec<VisualizationEdge>,
    /// Timestamp
    pub timestamp: u64,
}

impl NetworkVisualization {
    /// Create a new network visualization
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add a node
    pub fn add_node(&mut self, node: VisualizationNode) {
        self.nodes.push(node);
    }

    /// Add an edge
    pub fn add_edge(&mut self, edge: VisualizationEdge) {
        self.edges.push(edge);
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for NetworkVisualization {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics exporter
pub struct MetricsExporter {
    /// Collected metrics
    metrics: Arc<Mutex<Vec<MetricValue>>>,
    /// Histograms
    histograms: Arc<Mutex<HashMap<String, Histogram>>>,
    /// Active tracing spans
    spans: Arc<Mutex<HashMap<String, TracingSpan>>>,
    /// Completed spans
    completed_spans: Arc<Mutex<Vec<TracingSpan>>>,
    /// Network visualization
    visualization: Arc<Mutex<NetworkVisualization>>,
    /// Statistics
    stats: Arc<Mutex<ExporterStats>>,
}

/// Exporter statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExporterStats {
    /// Total metrics collected
    pub total_metrics: u64,
    /// Total histograms created
    pub total_histograms: u64,
    /// Total spans created
    pub total_spans: u64,
    /// Total exports
    pub total_exports: u64,
}

impl MetricsExporter {
    /// Create a new metrics exporter
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Vec::new())),
            histograms: Arc::new(Mutex::new(HashMap::new())),
            spans: Arc::new(Mutex::new(HashMap::new())),
            completed_spans: Arc::new(Mutex::new(Vec::new())),
            visualization: Arc::new(Mutex::new(NetworkVisualization::new())),
            stats: Arc::new(Mutex::new(ExporterStats::default())),
        }
    }

    /// Record a metric
    pub async fn record_metric(&self, metric: MetricValue) {
        let mut metrics = self.metrics.lock().await;
        metrics.push(metric);

        let mut stats = self.stats.lock().await;
        stats.total_metrics += 1;
    }

    /// Record a counter increment
    pub async fn record_counter(
        &self,
        name: impl Into<String>,
        value: f64,
        labels: Vec<MetricLabel>,
    ) {
        let mut metric = MetricValue::new(name, MetricType::Counter, value);
        metric.labels = labels;
        self.record_metric(metric).await;
    }

    /// Record a gauge value
    pub async fn record_gauge(
        &self,
        name: impl Into<String>,
        value: f64,
        labels: Vec<MetricLabel>,
    ) {
        let mut metric = MetricValue::new(name, MetricType::Gauge, value);
        metric.labels = labels;
        self.record_metric(metric).await;
    }

    /// Get or create a histogram
    pub async fn histogram(&self, name: impl Into<String>) -> String {
        let name_str = name.into();
        let mut histograms = self.histograms.lock().await;

        if !histograms.contains_key(&name_str) {
            histograms.insert(name_str.clone(), Histogram::new(&name_str));
            let mut stats = self.stats.lock().await;
            stats.total_histograms += 1;
        }

        name_str
    }

    /// Observe a histogram value
    pub async fn observe_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.lock().await;
        if let Some(histogram) = histograms.get_mut(name) {
            histogram.observe(value);
        }
    }

    /// Start a tracing span
    pub async fn start_span(&self, span_id: impl Into<String>, name: impl Into<String>) -> String {
        let span_id_str = span_id.into();
        let span = TracingSpan::new(&span_id_str, name);

        let mut spans = self.spans.lock().await;
        spans.insert(span_id_str.clone(), span);

        let mut stats = self.stats.lock().await;
        stats.total_spans += 1;

        span_id_str
    }

    /// Finish a tracing span
    pub async fn finish_span(&self, span_id: &str) {
        let mut spans = self.spans.lock().await;
        if let Some(mut span) = spans.remove(span_id) {
            span.finish();
            let mut completed = self.completed_spans.lock().await;
            completed.push(span);
        }
    }

    /// Add tag to active span
    pub async fn add_span_tag(
        &self,
        span_id: &str,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let mut spans = self.spans.lock().await;
        if let Some(span) = spans.get_mut(span_id) {
            span.tags.insert(key.into(), value.into());
        }
    }

    /// Update network visualization
    pub async fn update_visualization(&self, viz: NetworkVisualization) {
        let mut visualization = self.visualization.lock().await;
        *visualization = viz;
    }

    /// Export all metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Export simple metrics
        let metrics = self.metrics.lock().await;
        for metric in metrics.iter() {
            output.push_str(&metric.to_prometheus());
        }

        // Export histograms
        let histograms = self.histograms.lock().await;
        for histogram in histograms.values() {
            output.push_str(&histogram.to_prometheus());
        }

        let mut stats = self.stats.lock().await;
        stats.total_exports += 1;

        output
    }

    /// Export completed spans for distributed tracing
    pub async fn export_spans(&self) -> Vec<TracingSpan> {
        let completed = self.completed_spans.lock().await;
        completed.clone()
    }

    /// Export network visualization
    pub async fn export_visualization(&self) -> NetworkVisualization {
        let viz = self.visualization.lock().await;
        viz.clone()
    }

    /// Get statistics
    pub async fn stats(&self) -> ExporterStats {
        self.stats.lock().await.clone()
    }

    /// Clear all metrics
    pub async fn clear(&self) {
        let mut metrics = self.metrics.lock().await;
        metrics.clear();

        let mut histograms = self.histograms.lock().await;
        histograms.clear();

        let mut completed = self.completed_spans.lock().await;
        completed.clear();
    }
}

impl Default for MetricsExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Profiler for performance measurement
pub struct Profiler {
    /// Exporter
    exporter: Arc<MetricsExporter>,
    /// Current span ID
    span_id: String,
}

impl Profiler {
    /// Start profiling an operation
    pub async fn start(exporter: Arc<MetricsExporter>, operation: impl Into<String>) -> Self {
        let operation_name = operation.into();
        let span_id = format!("{}_{}", operation_name, uuid::Uuid::new_v4());
        exporter.start_span(&span_id, &operation_name).await;

        Self { exporter, span_id }
    }

    /// Add a tag to the current span
    pub async fn tag(&self, key: impl Into<String>, value: impl Into<String>) {
        self.exporter.add_span_tag(&self.span_id, key, value).await;
    }

    /// Finish profiling
    pub async fn finish(self) -> Duration {
        let spans = self.exporter.spans.lock().await;
        let start_time = spans.get(&self.span_id).map(|s| s.start_time);
        drop(spans);

        self.exporter.finish_span(&self.span_id).await;

        start_time.map(|st| st.elapsed()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_value_new() {
        let metric = MetricValue::new("test_metric", MetricType::Counter, 42.0);
        assert_eq!(metric.name, "test_metric");
        assert_eq!(metric.metric_type, MetricType::Counter);
        assert_eq!(metric.value, 42.0);
    }

    #[test]
    fn test_metric_value_with_label() {
        let metric = MetricValue::new("test_metric", MetricType::Gauge, 100.0)
            .with_label("instance", "localhost:9090");
        assert_eq!(metric.labels.len(), 1);
        assert_eq!(metric.labels[0].key, "instance");
    }

    #[test]
    fn test_metric_value_to_prometheus() {
        let metric = MetricValue::new("http_requests_total", MetricType::Counter, 1234.0)
            .with_label("method", "GET")
            .with_help("Total HTTP requests");
        let output = metric.to_prometheus();
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("http_requests_total"));
    }

    #[test]
    fn test_histogram_new() {
        let histogram = Histogram::new("request_duration");
        assert_eq!(histogram.name, "request_duration");
        assert!(!histogram.buckets.is_empty());
        assert_eq!(histogram.count, 0);
    }

    #[test]
    fn test_histogram_observe() {
        let mut histogram = Histogram::new("request_duration");
        histogram.observe(0.15);
        histogram.observe(0.5);
        histogram.observe(2.0);

        assert_eq!(histogram.count, 3);
        assert!(histogram.sum > 0.0);
    }

    #[test]
    fn test_histogram_to_prometheus() {
        let mut histogram = Histogram::new("request_duration");
        histogram.observe(0.1);
        histogram.observe(0.5);

        let output = histogram.to_prometheus();
        assert!(output.contains("request_duration_bucket"));
        assert!(output.contains("request_duration_count"));
        assert!(output.contains("request_duration_sum"));
    }

    #[test]
    fn test_tracing_span() {
        let mut span = TracingSpan::new("span-1", "http_request");
        std::thread::sleep(std::time::Duration::from_micros(1));
        span.finish();

        assert!(span.duration().is_some());
        assert!(span.duration().unwrap() > 0);
    }

    #[test]
    fn test_network_visualization() {
        let mut viz = NetworkVisualization::new();

        let node = VisualizationNode {
            id: "node1".to_string(),
            label: "Peer 1".to_string(),
            x: 0.0,
            y: 0.0,
            metadata: HashMap::new(),
        };

        viz.add_node(node);
        assert_eq!(viz.nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_metrics_exporter_new() {
        let exporter = MetricsExporter::new();
        let stats = exporter.stats().await;
        assert_eq!(stats.total_metrics, 0);
    }

    #[tokio::test]
    async fn test_metrics_exporter_record_metric() {
        let exporter = MetricsExporter::new();
        let metric = MetricValue::new("test_metric", MetricType::Counter, 1.0);
        exporter.record_metric(metric).await;

        let stats = exporter.stats().await;
        assert_eq!(stats.total_metrics, 1);
    }

    #[tokio::test]
    async fn test_metrics_exporter_histogram() {
        let exporter = MetricsExporter::new();
        let name = exporter.histogram("request_duration").await;
        exporter.observe_histogram(&name, 0.5).await;

        let stats = exporter.stats().await;
        assert_eq!(stats.total_histograms, 1);
    }

    #[tokio::test]
    async fn test_metrics_exporter_span() {
        let exporter = MetricsExporter::new();
        let span_id = exporter.start_span("test-span", "operation").await;
        exporter.finish_span(&span_id).await;

        let spans = exporter.export_spans().await;
        assert_eq!(spans.len(), 1);
    }

    #[tokio::test]
    async fn test_metrics_exporter_export_prometheus() {
        let exporter = MetricsExporter::new();
        exporter
            .record_counter("requests_total", 100.0, vec![])
            .await;

        let output = exporter.export_prometheus().await;
        assert!(!output.is_empty());
        assert!(output.contains("requests_total"));
    }

    #[tokio::test]
    async fn test_profiler() {
        let exporter = Arc::new(MetricsExporter::new());
        let profiler = Profiler::start(exporter.clone(), "test_operation").await;
        profiler.tag("test_key", "test_value").await;
        let duration = profiler.finish().await;

        assert!(duration.as_micros() > 0);
    }
}
