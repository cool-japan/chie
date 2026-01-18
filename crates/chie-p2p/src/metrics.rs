//! Connection metrics and monitoring for P2P networking.
//!
//! Provides comprehensive metrics collection for:
//! - Connection statistics (active, total, failed)
//! - Bandwidth usage tracking
//! - Latency measurements
//! - Per-peer and per-protocol metrics

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// Connection metrics configuration.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Enable per-peer metrics tracking.
    pub per_peer_metrics: bool,
    /// Enable per-protocol metrics tracking.
    pub per_protocol_metrics: bool,
    /// Metrics history retention (for rate calculations).
    pub history_duration: Duration,
    /// Sampling interval for rate calculations.
    pub sample_interval: Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            per_peer_metrics: true,
            per_protocol_metrics: true,
            history_duration: Duration::from_secs(3600),
            sample_interval: Duration::from_secs(1),
        }
    }
}

/// Atomic counter for thread-safe incrementing.
#[derive(Debug, Default)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    /// Create a new counter.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Increment the counter.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Add a value to the counter.
    pub fn add(&self, val: u64) {
        self.value.fetch_add(val, Ordering::Relaxed);
    }

    /// Get the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Reset the counter to zero.
    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

/// Bandwidth metrics (bytes transferred).
#[derive(Debug, Default)]
pub struct BandwidthMetrics {
    /// Total bytes received.
    pub bytes_received: AtomicCounter,
    /// Total bytes sent.
    pub bytes_sent: AtomicCounter,
}

impl BandwidthMetrics {
    /// Create new bandwidth metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record received bytes.
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.add(bytes);
    }

    /// Record sent bytes.
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.add(bytes);
    }

    /// Get total received bytes.
    pub fn total_received(&self) -> u64 {
        self.bytes_received.get()
    }

    /// Get total sent bytes.
    pub fn total_sent(&self) -> u64 {
        self.bytes_sent.get()
    }

    /// Get total bytes (in + out).
    pub fn total(&self) -> u64 {
        self.total_received() + self.total_sent()
    }
}

/// Connection state metrics.
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// Total connections established.
    pub total_connections: AtomicCounter,
    /// Currently active connections.
    pub active_connections: AtomicCounter,
    /// Failed connection attempts.
    pub failed_connections: AtomicCounter,
    /// Connections closed normally.
    pub closed_connections: AtomicCounter,
    /// Connections rejected (rate limited, etc.).
    pub rejected_connections: AtomicCounter,
}

impl ConnectionMetrics {
    /// Create new connection metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection.
    pub fn connection_established(&self) {
        self.total_connections.inc();
        self.active_connections.inc();
    }

    /// Record a closed connection.
    pub fn connection_closed(&self) {
        if self.active_connections.get() > 0 {
            self.active_connections
                .value
                .fetch_sub(1, Ordering::Relaxed);
        }
        self.closed_connections.inc();
    }

    /// Record a failed connection attempt.
    pub fn connection_failed(&self) {
        self.failed_connections.inc();
    }

    /// Record a rejected connection.
    pub fn connection_rejected(&self) {
        self.rejected_connections.inc();
    }

    /// Get snapshot of current metrics.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            total: self.total_connections.get(),
            active: self.active_connections.get(),
            failed: self.failed_connections.get(),
            closed: self.closed_connections.get(),
            rejected: self.rejected_connections.get(),
        }
    }
}

/// Snapshot of connection metrics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct ConnectionSnapshot {
    /// Total connections established.
    pub total: u64,
    /// Currently active connections.
    pub active: u64,
    /// Failed connection attempts.
    pub failed: u64,
    /// Connections closed normally.
    pub closed: u64,
    /// Connections rejected.
    pub rejected: u64,
}

/// Latency tracking with percentiles.
#[derive(Debug)]
pub struct LatencyMetrics {
    /// Recent latency samples (for percentile calculations).
    samples: RwLock<Vec<Duration>>,
    /// Maximum samples to keep.
    max_samples: usize,
    /// Total latency observations.
    total_observations: AtomicCounter,
    /// Sum of all latencies (for average).
    total_latency_ms: AtomicCounter,
}

impl Default for LatencyMetrics {
    fn default() -> Self {
        Self::new(1000)
    }
}

impl LatencyMetrics {
    /// Create new latency metrics with specified sample buffer size.
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: RwLock::new(Vec::with_capacity(max_samples)),
            max_samples,
            total_observations: AtomicCounter::new(),
            total_latency_ms: AtomicCounter::new(),
        }
    }

    /// Record a latency observation.
    pub async fn record(&self, latency: Duration) {
        let ms = latency.as_millis() as u64;
        self.total_observations.inc();
        self.total_latency_ms.add(ms);

        let mut samples = self.samples.write().await;
        if samples.len() >= self.max_samples {
            samples.remove(0);
        }
        samples.push(latency);
    }

    /// Get average latency.
    pub fn average(&self) -> Duration {
        let total = self.total_observations.get();
        if total == 0 {
            return Duration::ZERO;
        }
        let avg_ms = self.total_latency_ms.get() / total;
        Duration::from_millis(avg_ms)
    }

    /// Get percentile latency (0-100).
    pub async fn percentile(&self, p: f64) -> Duration {
        let samples = self.samples.read().await;
        if samples.is_empty() {
            return Duration::ZERO;
        }

        let mut sorted: Vec<_> = samples.clone();
        sorted.sort();

        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Get latency statistics.
    pub async fn stats(&self) -> LatencyStats {
        let samples = self.samples.read().await;
        if samples.is_empty() {
            return LatencyStats::default();
        }

        let mut sorted: Vec<_> = samples.clone();
        sorted.sort();

        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let p50 = sorted[(samples.len() as f64 * 0.5) as usize];
        let p95 = sorted[(samples.len() as f64 * 0.95).min(samples.len() as f64 - 1.0) as usize];
        let p99 = sorted[(samples.len() as f64 * 0.99).min(samples.len() as f64 - 1.0) as usize];

        LatencyStats {
            min,
            max,
            average: self.average(),
            p50,
            p95,
            p99,
            sample_count: samples.len(),
        }
    }
}

/// Latency statistics.
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    /// Minimum latency observed.
    pub min: Duration,
    /// Maximum latency observed.
    pub max: Duration,
    /// Average latency.
    pub average: Duration,
    /// 50th percentile (median).
    pub p50: Duration,
    /// 95th percentile.
    pub p95: Duration,
    /// 99th percentile.
    pub p99: Duration,
    /// Number of samples.
    pub sample_count: usize,
}

/// Per-peer metrics.
#[derive(Debug, Default)]
pub struct PeerMetrics {
    /// Bandwidth metrics for this peer.
    pub bandwidth: BandwidthMetrics,
    /// Latency metrics for this peer.
    pub latency: LatencyMetrics,
    /// Connection count to this peer.
    pub connection_count: AtomicCounter,
    /// Last seen timestamp.
    last_seen: RwLock<Option<Instant>>,
    /// Message counts by type.
    message_counts: RwLock<HashMap<String, u64>>,
}

impl PeerMetrics {
    /// Create new peer metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update last seen timestamp.
    pub async fn touch(&self) {
        *self.last_seen.write().await = Some(Instant::now());
    }

    /// Get time since last seen.
    pub async fn time_since_last_seen(&self) -> Option<Duration> {
        self.last_seen.read().await.map(|t| t.elapsed())
    }

    /// Record a message.
    pub async fn record_message(&self, msg_type: &str) {
        let mut counts = self.message_counts.write().await;
        *counts.entry(msg_type.to_string()).or_insert(0) += 1;
    }

    /// Get message counts.
    pub async fn get_message_counts(&self) -> HashMap<String, u64> {
        self.message_counts.read().await.clone()
    }
}

/// Protocol-specific metrics.
#[derive(Debug, Default)]
pub struct ProtocolMetrics {
    /// Request count.
    pub requests: AtomicCounter,
    /// Response count.
    pub responses: AtomicCounter,
    /// Error count.
    pub errors: AtomicCounter,
    /// Bandwidth metrics for this protocol.
    pub bandwidth: BandwidthMetrics,
    /// Latency metrics for this protocol.
    pub latency: LatencyMetrics,
}

impl ProtocolMetrics {
    /// Create new protocol metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request.
    pub fn record_request(&self) {
        self.requests.inc();
    }

    /// Record a response.
    pub fn record_response(&self) {
        self.responses.inc();
    }

    /// Record an error.
    pub fn record_error(&self) {
        self.errors.inc();
    }

    /// Get success rate (0.0-1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.requests.get();
        if total == 0 {
            return 1.0;
        }
        let errors = self.errors.get();
        (total.saturating_sub(errors)) as f64 / total as f64
    }
}

/// Central metrics collector.
#[derive(Debug)]
pub struct MetricsCollector {
    config: MetricsConfig,
    /// Global connection metrics.
    pub connections: ConnectionMetrics,
    /// Global bandwidth metrics.
    pub bandwidth: BandwidthMetrics,
    /// Global latency metrics.
    pub latency: LatencyMetrics,
    /// Per-peer metrics.
    peer_metrics: RwLock<HashMap<String, Arc<PeerMetrics>>>,
    /// Per-protocol metrics.
    protocol_metrics: RwLock<HashMap<String, Arc<ProtocolMetrics>>>,
    /// Start time.
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            connections: ConnectionMetrics::new(),
            bandwidth: BandwidthMetrics::new(),
            latency: LatencyMetrics::new(10000),
            peer_metrics: RwLock::new(HashMap::new()),
            protocol_metrics: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    /// Get uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get or create peer metrics.
    pub async fn peer(&self, peer_id: &str) -> Arc<PeerMetrics> {
        if !self.config.per_peer_metrics {
            return Arc::new(PeerMetrics::new());
        }

        let metrics = self.peer_metrics.read().await;
        if let Some(m) = metrics.get(peer_id) {
            return Arc::clone(m);
        }
        drop(metrics);

        let mut metrics = self.peer_metrics.write().await;
        let m = metrics
            .entry(peer_id.to_string())
            .or_insert_with(|| Arc::new(PeerMetrics::new()));
        Arc::clone(m)
    }

    /// Get or create protocol metrics.
    pub async fn protocol(&self, protocol_name: &str) -> Arc<ProtocolMetrics> {
        if !self.config.per_protocol_metrics {
            return Arc::new(ProtocolMetrics::new());
        }

        let metrics = self.protocol_metrics.read().await;
        if let Some(m) = metrics.get(protocol_name) {
            return Arc::clone(m);
        }
        drop(metrics);

        let mut metrics = self.protocol_metrics.write().await;
        let m = metrics
            .entry(protocol_name.to_string())
            .or_insert_with(|| Arc::new(ProtocolMetrics::new()));
        Arc::clone(m)
    }

    /// Record inbound bytes.
    pub async fn record_bytes_received(&self, peer_id: &str, bytes: u64) {
        self.bandwidth.record_received(bytes);
        if self.config.per_peer_metrics {
            let peer = self.peer(peer_id).await;
            peer.bandwidth.record_received(bytes);
        }
    }

    /// Record outbound bytes.
    pub async fn record_bytes_sent(&self, peer_id: &str, bytes: u64) {
        self.bandwidth.record_sent(bytes);
        if self.config.per_peer_metrics {
            let peer = self.peer(peer_id).await;
            peer.bandwidth.record_sent(bytes);
        }
    }

    /// Record latency.
    pub async fn record_latency(&self, peer_id: &str, latency: Duration) {
        self.latency.record(latency).await;
        if self.config.per_peer_metrics {
            let peer = self.peer(peer_id).await;
            peer.latency.record(latency).await;
        }
        debug!(peer_id = %peer_id, latency_ms = ?latency.as_millis(), "Recorded latency");
    }

    /// Get comprehensive metrics report.
    pub async fn report(&self) -> MetricsReport {
        MetricsReport {
            uptime: self.uptime(),
            connections: self.connections.snapshot(),
            total_bytes_received: self.bandwidth.total_received(),
            total_bytes_sent: self.bandwidth.total_sent(),
            latency: self.latency.stats().await,
            peer_count: self.peer_metrics.read().await.len(),
            protocol_count: self.protocol_metrics.read().await.len(),
        }
    }

    /// Get list of known peers.
    pub async fn known_peers(&self) -> Vec<String> {
        self.peer_metrics.read().await.keys().cloned().collect()
    }

    /// Get list of known protocols.
    pub async fn known_protocols(&self) -> Vec<String> {
        self.protocol_metrics.read().await.keys().cloned().collect()
    }

    /// Clean up stale peer metrics.
    pub async fn cleanup_stale_peers(&self, max_age: Duration) {
        let mut metrics = self.peer_metrics.write().await;
        let mut stale_peers = Vec::new();

        for (peer_id, peer_metrics) in metrics.iter() {
            if let Some(elapsed) = peer_metrics.time_since_last_seen().await {
                if elapsed > max_age {
                    stale_peers.push(peer_id.clone());
                }
            }
        }

        for peer_id in stale_peers {
            metrics.remove(&peer_id);
            debug!(peer_id = %peer_id, "Removed stale peer metrics");
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new(MetricsConfig::default())
    }
}

/// Comprehensive metrics report.
#[derive(Debug, Clone)]
pub struct MetricsReport {
    /// Service uptime.
    pub uptime: Duration,
    /// Connection statistics.
    pub connections: ConnectionSnapshot,
    /// Total bytes received.
    pub total_bytes_received: u64,
    /// Total bytes sent.
    pub total_bytes_sent: u64,
    /// Latency statistics.
    pub latency: LatencyStats,
    /// Number of tracked peers.
    pub peer_count: usize,
    /// Number of tracked protocols.
    pub protocol_count: usize,
}

/// Create a shared metrics collector.
pub fn create_metrics_collector(config: MetricsConfig) -> Arc<MetricsCollector> {
    Arc::new(MetricsCollector::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.add(10);
        assert_eq!(counter.get(), 11);
        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_bandwidth_metrics() {
        let metrics = BandwidthMetrics::new();
        metrics.record_received(100);
        metrics.record_sent(50);
        assert_eq!(metrics.total_received(), 100);
        assert_eq!(metrics.total_sent(), 50);
        assert_eq!(metrics.total(), 150);
    }

    #[test]
    fn test_connection_metrics() {
        let metrics = ConnectionMetrics::new();
        metrics.connection_established();
        metrics.connection_established();
        assert_eq!(metrics.snapshot().active, 2);
        assert_eq!(metrics.snapshot().total, 2);

        metrics.connection_closed();
        assert_eq!(metrics.snapshot().active, 1);
        assert_eq!(metrics.snapshot().closed, 1);

        metrics.connection_failed();
        assert_eq!(metrics.snapshot().failed, 1);
    }

    #[tokio::test]
    async fn test_latency_metrics() {
        let metrics = LatencyMetrics::new(100);
        metrics.record(Duration::from_millis(10)).await;
        metrics.record(Duration::from_millis(20)).await;
        metrics.record(Duration::from_millis(30)).await;

        let stats = metrics.stats().await;
        assert_eq!(stats.min, Duration::from_millis(10));
        assert_eq!(stats.max, Duration::from_millis(30));
        assert_eq!(stats.sample_count, 3);
    }

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::default();

        collector.connections.connection_established();
        collector.record_bytes_received("peer1", 1000).await;
        collector.record_bytes_sent("peer1", 500).await;
        collector
            .record_latency("peer1", Duration::from_millis(50))
            .await;

        let report = collector.report().await;
        assert_eq!(report.connections.active, 1);
        assert_eq!(report.total_bytes_received, 1000);
        assert_eq!(report.total_bytes_sent, 500);
        assert_eq!(report.peer_count, 1);
    }

    #[test]
    fn test_protocol_metrics() {
        let metrics = ProtocolMetrics::new();
        metrics.record_request();
        metrics.record_request();
        metrics.record_response();
        metrics.record_error();

        assert_eq!(metrics.requests.get(), 2);
        assert_eq!(metrics.responses.get(), 1);
        assert_eq!(metrics.errors.get(), 1);
        assert_eq!(metrics.success_rate(), 0.5);
    }
}
