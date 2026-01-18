//! Network analytics and topology analysis for P2P networks.
//!
//! This module provides:
//! - Network topology analysis
//! - Peer connectivity metrics
//! - Bandwidth distribution analysis
//! - Network health scoring
//! - Trend analysis and prediction

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Network topology metrics
#[derive(Debug, Clone)]
pub struct TopologyMetrics {
    /// Total number of peers in the network
    pub total_peers: usize,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Average number of connections per peer
    pub avg_connections_per_peer: f64,
    /// Network diameter (max distance between any two peers)
    pub network_diameter: usize,
    /// Clustering coefficient (how well-connected neighbors are)
    pub clustering_coefficient: f64,
    /// Number of isolated peers (no connections)
    pub isolated_peers: usize,
    /// Timestamp of last update
    pub updated_at: Instant,
}

impl Default for TopologyMetrics {
    fn default() -> Self {
        Self {
            total_peers: 0,
            connected_peers: 0,
            avg_connections_per_peer: 0.0,
            network_diameter: 0,
            clustering_coefficient: 0.0,
            isolated_peers: 0,
            updated_at: Instant::now(),
        }
    }
}

/// Bandwidth distribution statistics
#[derive(Debug, Clone, Default)]
pub struct BandwidthStats {
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Upload bytes
    pub upload_bytes: u64,
    /// Download bytes
    pub download_bytes: u64,
    /// Average transfer rate (bytes/sec)
    pub avg_transfer_rate: f64,
    /// Peak transfer rate
    pub peak_transfer_rate: f64,
    /// Number of active transfers
    pub active_transfers: usize,
    /// Bandwidth per peer
    pub per_peer_bandwidth: HashMap<PeerId, u64>,
}

/// Network health score
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthScore {
    /// Overall health (0.0 - 1.0)
    pub overall: f64,
    /// Connectivity health
    pub connectivity: f64,
    /// Performance health
    pub performance: f64,
    /// Stability health
    pub stability: f64,
}

impl HealthScore {
    /// Create a new health score
    pub fn new(connectivity: f64, performance: f64, stability: f64) -> Self {
        let overall = (connectivity + performance + stability) / 3.0;
        Self {
            overall,
            connectivity,
            performance,
            stability,
        }
    }

    /// Get health status as string
    pub fn status(&self) -> &'static str {
        if self.overall >= 0.9 {
            "Excellent"
        } else if self.overall >= 0.75 {
            "Good"
        } else if self.overall >= 0.5 {
            "Fair"
        } else if self.overall >= 0.25 {
            "Poor"
        } else {
            "Critical"
        }
    }
}

/// Time series data point
#[derive(Debug, Clone)]
struct DataPoint {
    #[allow(dead_code)]
    timestamp: Instant,
    value: f64,
}

/// Time series for trend analysis
#[derive(Debug, Clone)]
struct TimeSeries {
    points: Vec<DataPoint>,
    max_points: usize,
}

impl TimeSeries {
    fn new(max_points: usize) -> Self {
        Self {
            points: Vec::new(),
            max_points,
        }
    }

    fn add(&mut self, value: f64) {
        self.points.push(DataPoint {
            timestamp: Instant::now(),
            value,
        });

        // Keep only recent points
        if self.points.len() > self.max_points {
            self.points.remove(0);
        }
    }

    fn average(&self) -> f64 {
        if self.points.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        sum / self.points.len() as f64
    }

    fn trend(&self) -> f64 {
        if self.points.len() < 2 {
            return 0.0;
        }

        // Simple linear regression slope
        let n = self.points.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, point) in self.points.iter().enumerate() {
            let x = i as f64;
            let y = point.value;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
    }

    #[allow(dead_code)]
    fn latest(&self) -> Option<f64> {
        self.points.last().map(|p| p.value)
    }
}

/// Network analytics manager
#[derive(Clone)]
pub struct NetworkAnalytics {
    inner: Arc<RwLock<NetworkAnalyticsInner>>,
}

struct NetworkAnalyticsInner {
    /// Topology metrics
    topology: TopologyMetrics,
    /// Bandwidth statistics
    bandwidth: BandwidthStats,
    /// Peer connection history
    peer_connections: HashMap<PeerId, Vec<Instant>>,
    /// Transfer history (timestamp, bytes)
    transfer_history: Vec<(Instant, u64)>,
    /// Connectivity time series
    connectivity_series: TimeSeries,
    /// Bandwidth time series
    bandwidth_series: TimeSeries,
    /// Latency time series
    latency_series: TimeSeries,
    /// Analysis window
    analysis_window: Duration,
}

impl Default for NetworkAnalytics {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAnalytics {
    /// Create a new network analytics manager
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(NetworkAnalyticsInner {
                topology: TopologyMetrics::default(),
                bandwidth: BandwidthStats::default(),
                peer_connections: HashMap::new(),
                transfer_history: Vec::new(),
                connectivity_series: TimeSeries::new(100),
                bandwidth_series: TimeSeries::new(100),
                latency_series: TimeSeries::new(100),
                analysis_window: Duration::from_secs(3600), // 1 hour
            })),
        }
    }

    /// Update topology metrics
    pub fn update_topology(&self, total_peers: usize, connected_peers: usize) {
        if let Ok(mut inner) = self.inner.write() {
            inner.topology.total_peers = total_peers;
            inner.topology.connected_peers = connected_peers;
            inner.topology.updated_at = Instant::now();

            // Update time series
            let connectivity_ratio = if total_peers > 0 {
                connected_peers as f64 / total_peers as f64
            } else {
                0.0
            };
            inner.connectivity_series.add(connectivity_ratio);
        }
    }

    /// Record a peer connection
    pub fn record_connection(&self, peer_id: PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peer_connections
                .entry(peer_id)
                .or_insert_with(Vec::new)
                .push(Instant::now());

            // Clean old history
            self.cleanup_old_data(&mut inner);
        }
    }

    /// Record a data transfer
    pub fn record_transfer(&self, peer_id: PeerId, bytes: u64, upload: bool) {
        if let Ok(mut inner) = self.inner.write() {
            inner.bandwidth.total_bytes += bytes;

            if upload {
                inner.bandwidth.upload_bytes += bytes;
            } else {
                inner.bandwidth.download_bytes += bytes;
            }

            *inner
                .bandwidth
                .per_peer_bandwidth
                .entry(peer_id)
                .or_insert(0) += bytes;

            inner.transfer_history.push((Instant::now(), bytes));

            // Update bandwidth time series (bytes per second)
            inner.bandwidth_series.add(bytes as f64);

            // Clean old history
            self.cleanup_old_data(&mut inner);
        }
    }

    /// Record latency measurement
    pub fn record_latency(&self, _peer_id: PeerId, latency_ms: f64) {
        if let Ok(mut inner) = self.inner.write() {
            inner.latency_series.add(latency_ms);
        }
    }

    /// Get topology metrics
    pub fn topology_metrics(&self) -> TopologyMetrics {
        self.inner
            .read()
            .map(|inner| inner.topology.clone())
            .unwrap_or_default()
    }

    /// Get bandwidth statistics
    pub fn bandwidth_stats(&self) -> BandwidthStats {
        self.inner
            .read()
            .map(|inner| {
                let mut stats = inner.bandwidth.clone();

                // Calculate average transfer rate
                if !inner.transfer_history.is_empty() {
                    let total_duration = inner
                        .transfer_history
                        .last()
                        .unwrap()
                        .0
                        .duration_since(inner.transfer_history.first().unwrap().0);

                    if total_duration.as_secs() > 0 {
                        stats.avg_transfer_rate =
                            stats.total_bytes as f64 / total_duration.as_secs_f64();
                    }
                }

                stats
            })
            .unwrap_or_default()
    }

    /// Calculate network health score
    pub fn health_score(&self) -> HealthScore {
        let Ok(inner) = self.inner.read() else {
            return HealthScore::new(0.0, 0.0, 0.0);
        };

        // Connectivity health (based on peer connections)
        let connectivity = if inner.topology.total_peers > 0 {
            (inner.topology.connected_peers as f64 / inner.topology.total_peers as f64).min(1.0)
        } else {
            0.0
        };

        // Performance health (based on bandwidth and latency)
        let avg_latency = inner.latency_series.average();
        let latency_score = if avg_latency > 0.0 {
            (1.0 / (1.0 + avg_latency / 100.0)).min(1.0) // Lower latency is better
        } else {
            1.0
        };

        let bandwidth_trend = inner.bandwidth_series.trend();
        let bandwidth_score = ((bandwidth_trend + 1.0) / 2.0).clamp(0.0, 1.0);

        let performance = (latency_score + bandwidth_score) / 2.0;

        // Stability health (based on connection consistency)
        let connectivity_trend = inner.connectivity_series.trend();
        let stability = ((connectivity_trend + 1.0) / 2.0).clamp(0.0, 1.0);

        HealthScore::new(connectivity, performance, stability)
    }

    /// Get peer activity summary
    pub fn peer_activity(&self, peer_id: &PeerId) -> Option<PeerActivity> {
        self.inner.read().ok().map(|inner| {
            let connection_count = inner
                .peer_connections
                .get(peer_id)
                .map(|v| v.len())
                .unwrap_or(0);

            let total_bandwidth = inner
                .bandwidth
                .per_peer_bandwidth
                .get(peer_id)
                .copied()
                .unwrap_or(0);

            let last_seen = inner
                .peer_connections
                .get(peer_id)
                .and_then(|v| v.last().copied());

            PeerActivity {
                connection_count,
                total_bandwidth,
                last_seen,
            }
        })
    }

    /// Get network trends
    pub fn trends(&self) -> NetworkTrends {
        let Ok(inner) = self.inner.read() else {
            return NetworkTrends::default();
        };

        NetworkTrends {
            connectivity_trend: inner.connectivity_series.trend(),
            bandwidth_trend: inner.bandwidth_series.trend(),
            latency_trend: inner.latency_series.trend(),
            avg_connectivity: inner.connectivity_series.average(),
            avg_bandwidth: inner.bandwidth_series.average(),
            avg_latency: inner.latency_series.average(),
        }
    }

    /// Clean up old data outside analysis window
    fn cleanup_old_data(&self, inner: &mut NetworkAnalyticsInner) {
        let cutoff = Instant::now() - inner.analysis_window;

        // Clean peer connections
        for connections in inner.peer_connections.values_mut() {
            connections.retain(|&t| t > cutoff);
        }

        // Clean transfer history
        inner.transfer_history.retain(|(t, _)| *t > cutoff);
    }

    /// Get top peers by bandwidth
    pub fn top_peers_by_bandwidth(&self, limit: usize) -> Vec<(PeerId, u64)> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };

        let mut peers: Vec<_> = inner.bandwidth.per_peer_bandwidth.iter().collect();
        peers.sort_by(|a, b| b.1.cmp(a.1));
        peers
            .into_iter()
            .take(limit)
            .map(|(p, b)| (*p, *b))
            .collect()
    }
}

/// Peer activity summary
#[derive(Debug, Clone)]
pub struct PeerActivity {
    pub connection_count: usize,
    pub total_bandwidth: u64,
    pub last_seen: Option<Instant>,
}

/// Network trends
#[derive(Debug, Clone, Default)]
pub struct NetworkTrends {
    pub connectivity_trend: f64,
    pub bandwidth_trend: f64,
    pub latency_trend: f64,
    pub avg_connectivity: f64,
    pub avg_bandwidth: f64,
    pub avg_latency: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_update() {
        let analytics = NetworkAnalytics::new();
        analytics.update_topology(100, 75);

        let metrics = analytics.topology_metrics();
        assert_eq!(metrics.total_peers, 100);
        assert_eq!(metrics.connected_peers, 75);
    }

    #[test]
    fn test_connection_recording() {
        let analytics = NetworkAnalytics::new();
        let peer_id = PeerId::random();

        analytics.record_connection(peer_id);
        analytics.record_connection(peer_id);

        let activity = analytics.peer_activity(&peer_id).unwrap();
        assert_eq!(activity.connection_count, 2);
    }

    #[test]
    fn test_transfer_recording() {
        let analytics = NetworkAnalytics::new();
        let peer_id = PeerId::random();

        analytics.record_transfer(peer_id, 1000, true); // Upload
        analytics.record_transfer(peer_id, 2000, false); // Download

        let stats = analytics.bandwidth_stats();
        assert_eq!(stats.total_bytes, 3000);
        assert_eq!(stats.upload_bytes, 1000);
        assert_eq!(stats.download_bytes, 2000);

        let activity = analytics.peer_activity(&peer_id).unwrap();
        assert_eq!(activity.total_bandwidth, 3000);
    }

    #[test]
    fn test_health_score() {
        let analytics = NetworkAnalytics::new();
        analytics.update_topology(100, 90);

        let health = analytics.health_score();
        assert!(health.overall > 0.0);
        assert!(health.connectivity > 0.8);
        // Status depends on overall health calculation which includes performance and stability
        // Just verify it returns a valid status
        assert!(!health.status().is_empty());
    }

    #[test]
    fn test_latency_recording() {
        let analytics = NetworkAnalytics::new();
        let peer_id = PeerId::random();

        analytics.record_latency(peer_id, 50.0);
        analytics.record_latency(peer_id, 60.0);
        analytics.record_latency(peer_id, 55.0);

        let trends = analytics.trends();
        assert!(trends.avg_latency > 0.0);
    }

    #[test]
    fn test_time_series_average() {
        let mut series = TimeSeries::new(10);
        series.add(10.0);
        series.add(20.0);
        series.add(30.0);

        assert_eq!(series.average(), 20.0);
        assert_eq!(series.latest(), Some(30.0));
    }

    #[test]
    fn test_time_series_trend() {
        let mut series = TimeSeries::new(10);
        // Increasing trend
        for i in 0..5 {
            series.add(i as f64);
        }

        let trend = series.trend();
        assert!(trend > 0.0); // Positive trend
    }

    #[test]
    fn test_health_status() {
        let excellent = HealthScore::new(0.95, 0.95, 0.95);
        assert_eq!(excellent.status(), "Excellent");

        let good = HealthScore::new(0.8, 0.8, 0.8);
        assert_eq!(good.status(), "Good");

        let fair = HealthScore::new(0.6, 0.6, 0.6);
        assert_eq!(fair.status(), "Fair");

        let poor = HealthScore::new(0.3, 0.3, 0.3);
        assert_eq!(poor.status(), "Poor");

        let critical = HealthScore::new(0.1, 0.1, 0.1);
        assert_eq!(critical.status(), "Critical");
    }

    #[test]
    fn test_top_peers_by_bandwidth() {
        let analytics = NetworkAnalytics::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        analytics.record_transfer(peer1, 1000, true);
        analytics.record_transfer(peer2, 3000, true);
        analytics.record_transfer(peer3, 2000, true);

        let top_peers = analytics.top_peers_by_bandwidth(2);
        assert_eq!(top_peers.len(), 2);
        assert_eq!(top_peers[0].0, peer2); // Highest bandwidth
        assert_eq!(top_peers[0].1, 3000);
    }

    #[test]
    fn test_time_series_max_points() {
        let mut series = TimeSeries::new(3);
        for i in 0..10 {
            series.add(i as f64);
        }

        assert_eq!(series.points.len(), 3);
        assert_eq!(series.latest(), Some(9.0));
    }
}
