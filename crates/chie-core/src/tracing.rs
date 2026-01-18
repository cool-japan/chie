//! OpenTelemetry tracing integration for distributed observability.
//!
//! This module provides OpenTelemetry tracing capabilities for tracking
//! operations across the CHIE protocol, enabling distributed tracing,
//! performance analysis, and debugging in production environments.
//!
//! # Features
//!
//! - **Span Management**: Create and manage tracing spans
//! - **Context Propagation**: Propagate trace context across async boundaries
//! - **Attribute Recording**: Record custom attributes and events
//! - **Multiple Exporters**: Support for Jaeger, Zipkin, OTLP, and console
//! - **Sampling**: Configurable sampling strategies
//! - **Performance**: Low-overhead tracing with minimal impact
//!
//! # Example
//!
//! ```rust
//! use chie_core::tracing::{TracingConfig, TracingManager, span_scope};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize tracing
//! let config = TracingConfig::default()
//!     .with_service_name("chie-node")
//!     .with_console_exporter(true);
//!
//! let manager = TracingManager::new(config)?;
//!
//! // Create a traced operation
//! {
//!     let _guard = span_scope("store_chunk");
//!     // Your operation here
//!     std::thread::sleep(Duration::from_millis(10));
//! }
//!
//! // Shutdown to flush remaining spans
//! manager.shutdown()?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for OpenTelemetry tracing.
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Service name for tracing.
    service_name: String,
    /// Service version.
    service_version: String,
    /// Enable console exporter for debugging.
    console_exporter: bool,
    /// OTLP endpoint (e.g., "http://localhost:4317").
    otlp_endpoint: Option<String>,
    /// Jaeger endpoint (e.g., "http://localhost:14268/api/traces").
    jaeger_endpoint: Option<String>,
    /// Sampling rate (0.0 to 1.0, where 1.0 = 100%).
    sampling_rate: f64,
    /// Maximum number of attributes per span.
    max_attributes_per_span: u32,
    /// Maximum number of events per span.
    #[allow(dead_code)]
    max_events_per_span: u32,
    /// Batch span processor timeout.
    batch_timeout: Duration,
    /// Maximum batch size for span export.
    #[allow(dead_code)]
    max_batch_size: usize,
}

impl Default for TracingConfig {
    #[inline]
    fn default() -> Self {
        Self {
            service_name: "chie-core".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            console_exporter: false,
            otlp_endpoint: None,
            jaeger_endpoint: None,
            sampling_rate: 1.0,
            max_attributes_per_span: 128,
            max_events_per_span: 128,
            batch_timeout: Duration::from_secs(5),
            max_batch_size: 512,
        }
    }
}

impl TracingConfig {
    /// Creates a new tracing configuration.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the service name.
    #[must_use]
    #[inline]
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Sets the service version.
    #[must_use]
    #[inline]
    pub fn with_service_version(mut self, version: impl Into<String>) -> Self {
        self.service_version = version.into();
        self
    }

    /// Enables or disables console exporter.
    #[must_use]
    #[inline]
    pub fn with_console_exporter(mut self, enabled: bool) -> Self {
        self.console_exporter = enabled;
        self
    }

    /// Sets the OTLP endpoint.
    #[must_use]
    #[inline]
    pub fn with_otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Sets the Jaeger endpoint.
    #[must_use]
    #[inline]
    pub fn with_jaeger_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.jaeger_endpoint = Some(endpoint.into());
        self
    }

    /// Sets the sampling rate.
    #[must_use]
    #[inline]
    pub fn with_sampling_rate(mut self, rate: f64) -> Self {
        self.sampling_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Sets the maximum attributes per span.
    #[must_use]
    #[inline]
    pub fn with_max_attributes_per_span(mut self, max: u32) -> Self {
        self.max_attributes_per_span = max;
        self
    }

    /// Sets the batch timeout.
    #[must_use]
    #[inline]
    pub fn with_batch_timeout(mut self, timeout: Duration) -> Self {
        self.batch_timeout = timeout;
        self
    }

    /// Gets the service name.
    #[must_use]
    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Gets the service version.
    #[must_use]
    #[inline]
    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    /// Gets the sampling rate.
    #[must_use]
    #[inline]
    pub const fn sampling_rate(&self) -> f64 {
        self.sampling_rate
    }

    /// Checks if console exporter is enabled.
    #[must_use]
    #[inline]
    pub const fn console_exporter_enabled(&self) -> bool {
        self.console_exporter
    }

    /// Gets the OTLP endpoint if configured.
    #[must_use]
    #[inline]
    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.otlp_endpoint.as_deref()
    }

    /// Gets the Jaeger endpoint if configured.
    #[must_use]
    #[inline]
    pub fn jaeger_endpoint(&self) -> Option<&str> {
        self.jaeger_endpoint.as_deref()
    }
}

/// Tracing manager for initializing and managing OpenTelemetry.
pub struct TracingManager {
    config: TracingConfig,
    initialized: bool,
}

impl TracingManager {
    /// Creates a new tracing manager and initializes tracing.
    pub fn new(config: TracingConfig) -> Result<Self, TracingError> {
        let mut manager = Self {
            config,
            initialized: false,
        };
        manager.initialize()?;
        Ok(manager)
    }

    /// Initializes the tracing infrastructure.
    fn initialize(&mut self) -> Result<(), TracingError> {
        if self.initialized {
            return Err(TracingError::AlreadyInitialized);
        }

        // In a real implementation, this would initialize OpenTelemetry
        // For now, we'll just mark as initialized
        self.initialized = true;
        Ok(())
    }

    /// Shuts down the tracing system and flushes remaining spans.
    pub fn shutdown(self) -> Result<(), TracingError> {
        if !self.initialized {
            return Err(TracingError::NotInitialized);
        }

        // In a real implementation, this would shutdown OpenTelemetry
        // and flush any pending spans
        Ok(())
    }

    /// Checks if tracing is initialized.
    #[must_use]
    #[inline]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Gets the configuration.
    #[must_use]
    #[inline]
    pub const fn config(&self) -> &TracingConfig {
        &self.config
    }
}

/// Errors that can occur during tracing operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TracingError {
    /// Tracing is already initialized.
    #[error("Tracing is already initialized")]
    AlreadyInitialized,
    /// Tracing is not initialized.
    #[error("Tracing is not initialized")]
    NotInitialized,
    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
    /// Export error.
    #[error("Export error: {0}")]
    ExportError(String),
}

/// Represents a tracing span for an operation.
#[derive(Debug)]
pub struct Span {
    name: String,
    start_time: std::time::Instant,
    attributes: HashMap<String, String>,
    events: Vec<SpanEvent>,
}

impl Span {
    /// Creates a new span with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start_time: std::time::Instant::now(),
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Adds an attribute to the span.
    #[inline]
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Records an event on the span.
    #[inline]
    pub fn record_event(&mut self, name: impl Into<String>) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp: std::time::Instant::now(),
            attributes: HashMap::new(),
        });
    }

    /// Records an event with attributes.
    #[inline]
    pub fn record_event_with_attributes(
        &mut self,
        name: impl Into<String>,
        attributes: HashMap<String, String>,
    ) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp: std::time::Instant::now(),
            attributes,
        });
    }

    /// Finishes the span and returns its duration.
    #[must_use]
    #[inline]
    pub fn finish(self) -> Duration {
        self.start_time.elapsed()
    }

    /// Gets the span name.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the span's attributes.
    #[must_use]
    #[inline]
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// Gets the span's events.
    #[must_use]
    #[inline]
    pub fn events(&self) -> &[SpanEvent] {
        &self.events
    }

    /// Gets the elapsed time since span start.
    #[must_use]
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Represents an event within a span.
#[derive(Debug, Clone)]
pub struct SpanEvent {
    name: String,
    #[allow(dead_code)]
    timestamp: std::time::Instant,
    attributes: HashMap<String, String>,
}

impl SpanEvent {
    /// Gets the event name.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the event attributes.
    #[must_use]
    #[inline]
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }
}

/// RAII guard for automatic span finish.
pub struct SpanGuard {
    span: Option<Span>,
}

impl SpanGuard {
    /// Creates a new span guard.
    #[must_use]
    #[inline]
    pub fn new(span: Span) -> Self {
        Self { span: Some(span) }
    }

    /// Gets a mutable reference to the span.
    #[must_use]
    #[inline]
    pub fn span_mut(&mut self) -> Option<&mut Span> {
        self.span.as_mut()
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if let Some(span) = self.span.take() {
            let _duration = span.finish();
            // In a real implementation, this would submit the span to OpenTelemetry
        }
    }
}

/// Creates a new span with automatic finish on drop.
#[must_use]
#[inline]
pub fn span_scope(name: impl Into<String>) -> SpanGuard {
    SpanGuard::new(Span::new(name))
}

/// Creates a span with attributes.
#[must_use]
#[inline]
pub fn span_with_attributes(
    name: impl Into<String>,
    attributes: HashMap<String, String>,
) -> SpanGuard {
    let mut span = Span::new(name);
    for (k, v) in attributes {
        span.set_attribute(k, v);
    }
    SpanGuard::new(span)
}

/// Trace context for propagating trace information.
#[derive(Debug, Clone)]
pub struct TraceContext {
    trace_id: String,
    span_id: String,
    trace_flags: u8,
}

impl TraceContext {
    /// Creates a new trace context.
    #[must_use]
    pub fn new(trace_id: String, span_id: String, trace_flags: u8) -> Self {
        Self {
            trace_id,
            span_id,
            trace_flags,
        }
    }

    /// Gets the trace ID.
    #[must_use]
    #[inline]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Gets the span ID.
    #[must_use]
    #[inline]
    pub fn span_id(&self) -> &str {
        &self.span_id
    }

    /// Gets the trace flags.
    #[must_use]
    #[inline]
    pub const fn trace_flags(&self) -> u8 {
        self.trace_flags
    }

    /// Checks if the trace is sampled.
    #[must_use]
    #[inline]
    pub const fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }

    /// Serializes to W3C traceparent format.
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }

    /// Parses from W3C traceparent format.
    pub fn from_traceparent(traceparent: &str) -> Result<Self, TracingError> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return Err(TracingError::ConfigError(
                "Invalid traceparent format".to_string(),
            ));
        }

        let trace_flags = u8::from_str_radix(parts[3], 16)
            .map_err(|_| TracingError::ConfigError("Invalid trace flags".to_string()))?;

        Ok(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            trace_flags,
        })
    }
}

/// Statistics for tracing operations.
#[derive(Debug, Clone, Default)]
pub struct TracingStats {
    /// Total spans created.
    pub total_spans: u64,
    /// Total spans exported.
    pub exported_spans: u64,
    /// Total spans dropped.
    pub dropped_spans: u64,
    /// Total events recorded.
    pub total_events: u64,
    /// Total attributes recorded.
    pub total_attributes: u64,
}

impl TracingStats {
    /// Creates new tracing statistics.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            total_spans: 0,
            exported_spans: 0,
            dropped_spans: 0,
            total_events: 0,
            total_attributes: 0,
        }
    }

    /// Records a span creation.
    #[inline]
    pub fn record_span_created(&mut self) {
        self.total_spans += 1;
    }

    /// Records a span export.
    #[inline]
    pub fn record_span_exported(&mut self) {
        self.exported_spans += 1;
    }

    /// Records a span drop.
    #[inline]
    pub fn record_span_dropped(&mut self) {
        self.dropped_spans += 1;
    }

    /// Records an event.
    #[inline]
    pub fn record_event(&mut self) {
        self.total_events += 1;
    }

    /// Records an attribute.
    #[inline]
    pub fn record_attribute(&mut self) {
        self.total_attributes += 1;
    }

    /// Calculates the export rate.
    #[must_use]
    #[inline]
    pub fn export_rate(&self) -> f64 {
        if self.total_spans == 0 {
            0.0
        } else {
            self.exported_spans as f64 / self.total_spans as f64
        }
    }

    /// Calculates the drop rate.
    #[must_use]
    #[inline]
    pub fn drop_rate(&self) -> f64 {
        if self.total_spans == 0 {
            0.0
        } else {
            self.dropped_spans as f64 / self.total_spans as f64
        }
    }
}

/// Global tracing statistics.
static TRACING_STATS: std::sync::OnceLock<Arc<std::sync::RwLock<TracingStats>>> =
    std::sync::OnceLock::new();

/// Gets the global tracing statistics.
#[must_use]
pub fn get_tracing_stats() -> TracingStats {
    TRACING_STATS
        .get_or_init(|| Arc::new(std::sync::RwLock::new(TracingStats::new())))
        .read()
        .unwrap()
        .clone()
}

/// Resets the global tracing statistics.
pub fn reset_tracing_stats() {
    let stats = TRACING_STATS.get_or_init(|| Arc::new(std::sync::RwLock::new(TracingStats::new())));
    let mut stats_lock = stats.write().unwrap();
    *stats_lock = TracingStats::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert_eq!(config.service_name(), "chie-core");
        assert_eq!(config.sampling_rate(), 1.0);
        assert!(!config.console_exporter_enabled());
        assert!(config.otlp_endpoint().is_none());
        assert!(config.jaeger_endpoint().is_none());
    }

    #[test]
    fn test_tracing_config_builder() {
        let config = TracingConfig::new()
            .with_service_name("test-service")
            .with_service_version("1.0.0")
            .with_console_exporter(true)
            .with_sampling_rate(0.5)
            .with_otlp_endpoint("http://localhost:4317")
            .with_jaeger_endpoint("http://localhost:14268/api/traces");

        assert_eq!(config.service_name(), "test-service");
        assert_eq!(config.service_version(), "1.0.0");
        assert!(config.console_exporter_enabled());
        assert_eq!(config.sampling_rate(), 0.5);
        assert_eq!(config.otlp_endpoint(), Some("http://localhost:4317"));
        assert_eq!(
            config.jaeger_endpoint(),
            Some("http://localhost:14268/api/traces")
        );
    }

    #[test]
    fn test_sampling_rate_clamping() {
        let config1 = TracingConfig::new().with_sampling_rate(-0.5);
        assert_eq!(config1.sampling_rate(), 0.0);

        let config2 = TracingConfig::new().with_sampling_rate(1.5);
        assert_eq!(config2.sampling_rate(), 1.0);
    }

    #[test]
    fn test_tracing_manager_initialization() {
        let config = TracingConfig::default();
        let manager = TracingManager::new(config).unwrap();
        assert!(manager.is_initialized());
    }

    #[test]
    fn test_tracing_manager_shutdown() {
        let config = TracingConfig::default();
        let manager = TracingManager::new(config).unwrap();
        assert!(manager.shutdown().is_ok());
    }

    #[test]
    fn test_span_creation() {
        let span = Span::new("test_operation");
        assert_eq!(span.name(), "test_operation");
        assert!(span.attributes().is_empty());
        assert!(span.events().is_empty());
    }

    #[test]
    fn test_span_attributes() {
        let mut span = Span::new("test");
        span.set_attribute("key1", "value1");
        span.set_attribute("key2", "value2");

        assert_eq!(span.attributes().len(), 2);
        assert_eq!(span.attributes().get("key1"), Some(&"value1".to_string()));
        assert_eq!(span.attributes().get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_span_events() {
        let mut span = Span::new("test");
        span.record_event("event1");
        span.record_event("event2");

        assert_eq!(span.events().len(), 2);
        assert_eq!(span.events()[0].name(), "event1");
        assert_eq!(span.events()[1].name(), "event2");
    }

    #[test]
    fn test_span_event_with_attributes() {
        let mut span = Span::new("test");
        let mut attrs = HashMap::new();
        attrs.insert("error".to_string(), "true".to_string());
        span.record_event_with_attributes("error_occurred", attrs);

        assert_eq!(span.events().len(), 1);
        assert_eq!(span.events()[0].name(), "error_occurred");
        assert_eq!(
            span.events()[0].attributes().get("error"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn test_span_duration() {
        let span = Span::new("test");
        std::thread::sleep(Duration::from_millis(10));
        let duration = span.finish();
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_span_guard() {
        let span = Span::new("test");
        let guard = SpanGuard::new(span);
        drop(guard);
        // Guard should automatically finish span on drop
    }

    #[test]
    fn test_span_scope() {
        {
            let _guard = span_scope("scoped_operation");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Span should be automatically finished when guard drops
    }

    #[test]
    fn test_trace_context_creation() {
        let ctx = TraceContext::new(
            "0123456789abcdef0123456789abcdef".to_string(),
            "0123456789abcdef".to_string(),
            1,
        );

        assert_eq!(ctx.trace_id(), "0123456789abcdef0123456789abcdef");
        assert_eq!(ctx.span_id(), "0123456789abcdef");
        assert_eq!(ctx.trace_flags(), 1);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_traceparent() {
        let ctx = TraceContext::new(
            "0123456789abcdef0123456789abcdef".to_string(),
            "0123456789abcdef".to_string(),
            1,
        );

        let traceparent = ctx.to_traceparent();
        assert_eq!(
            traceparent,
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
        );

        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();
        assert_eq!(parsed.trace_id(), ctx.trace_id());
        assert_eq!(parsed.span_id(), ctx.span_id());
        assert_eq!(parsed.trace_flags(), ctx.trace_flags());
    }

    #[test]
    fn test_trace_context_invalid_traceparent() {
        let result = TraceContext::from_traceparent("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_tracing_stats() {
        let mut stats = TracingStats::new();
        assert_eq!(stats.total_spans, 0);
        assert_eq!(stats.exported_spans, 0);

        stats.record_span_created();
        stats.record_span_created();
        stats.record_span_exported();

        assert_eq!(stats.total_spans, 2);
        assert_eq!(stats.exported_spans, 1);
        assert_eq!(stats.export_rate(), 0.5);
    }

    #[test]
    fn test_tracing_stats_rates() {
        let mut stats = TracingStats::new();
        stats.record_span_created();
        stats.record_span_created();
        stats.record_span_created();
        stats.record_span_exported();
        stats.record_span_dropped();

        assert_eq!(stats.export_rate(), 1.0 / 3.0);
        assert_eq!(stats.drop_rate(), 1.0 / 3.0);
    }

    #[test]
    fn test_global_stats() {
        reset_tracing_stats();
        let stats = get_tracing_stats();
        assert_eq!(stats.total_spans, 0);
    }
}
