//! Performance analysis and bottleneck detection for P2P networks.
//!
//! This module provides comprehensive performance analysis capabilities to identify
//! bottlenecks, inefficiencies, and optimization opportunities in P2P CDN networks.
//! Essential for maintaining optimal performance at scale.
//!
//! # Features
//!
//! - Real-time performance monitoring and analysis
//! - Bottleneck detection (bandwidth, latency, CPU, memory)
//! - Performance trend analysis and prediction
//! - Automatic recommendations for optimization
//! - Peer performance comparison and ranking
//! - Resource utilization tracking
//! - Performance alerts and notifications
//! - Historical performance data retention
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::performance_analyzer::{PerformanceAnalyzer, AnalyzerConfig, Bottleneck};
//!
//! let config = AnalyzerConfig::default();
//! let mut analyzer = PerformanceAnalyzer::new(config);
//!
//! // Record performance metrics
//! analyzer.record_transfer("peer1", 1024 * 1024, 100); // 1MB in 100ms
//! analyzer.record_cpu_usage(45.5);
//! analyzer.record_memory_usage(512 * 1024 * 1024); // 512MB
//!
//! // Analyze performance
//! if let Some(bottlenecks) = analyzer.detect_bottlenecks() {
//!     for bottleneck in bottlenecks {
//!         println!("Bottleneck detected: {:?}", bottleneck);
//!     }
//! }
//!
//! // Get recommendations
//! let recommendations = analyzer.get_recommendations();
//! for rec in recommendations {
//!     println!("Recommendation: {}", rec);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Performance analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Maximum number of samples to retain
    pub max_samples: usize,
    /// Minimum sample count for analysis
    pub min_samples: usize,
    /// Analysis interval in seconds
    pub analysis_interval: u64,
    /// Bottleneck threshold percentile (0.0-1.0)
    pub bottleneck_threshold: f64,
    /// Enable trend prediction
    pub enable_prediction: bool,
    /// CPU usage threshold (%)
    pub cpu_threshold: f64,
    /// Memory usage threshold (bytes)
    pub memory_threshold: u64,
    /// Bandwidth threshold (bytes/sec)
    pub bandwidth_threshold: u64,
    /// Latency threshold (ms)
    pub latency_threshold: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_samples: 10000,
            min_samples: 100,
            analysis_interval: 60,
            bottleneck_threshold: 0.95,
            enable_prediction: true,
            cpu_threshold: 80.0,
            memory_threshold: 1024 * 1024 * 1024,   // 1GB
            bandwidth_threshold: 100 * 1024 * 1024, // 100 MB/s
            latency_threshold: 200,                 // 200ms
        }
    }
}

/// Type of performance bottleneck
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BottleneckType {
    /// CPU is the limiting factor
    CPU,
    /// Memory is the limiting factor
    Memory,
    /// Bandwidth is the limiting factor
    Bandwidth,
    /// Network latency is the limiting factor
    Latency,
    /// Peer quality is the limiting factor
    PeerQuality,
    /// Disk I/O is the limiting factor
    DiskIO,
}

/// Detected performance bottleneck
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottleneck {
    /// Type of bottleneck
    pub bottleneck_type: BottleneckType,
    /// Severity (0.0-1.0, higher is more severe)
    pub severity: f64,
    /// Current value
    pub current_value: f64,
    /// Threshold value
    pub threshold_value: f64,
    /// Description
    pub description: String,
    /// Timestamp when detected
    #[serde(skip, default = "Instant::now")]
    pub detected_at: Instant,
}

/// Performance sample
#[derive(Debug, Clone)]
struct PerformanceSample {
    #[allow(dead_code)]
    timestamp: Instant,
    cpu_usage: f64,
    memory_usage: u64,
    bandwidth_usage: u64,
    latency: u64,
    #[allow(dead_code)]
    active_transfers: usize,
    #[allow(dead_code)]
    peer_count: usize,
}

/// Transfer record for analysis
#[derive(Debug, Clone)]
struct TransferRecord {
    #[allow(dead_code)]
    peer_id: String,
    bytes: u64,
    duration_ms: u64,
    #[allow(dead_code)]
    timestamp: Instant,
}

/// Performance trend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTrend {
    /// Metric name
    pub metric: String,
    /// Trend direction (positive, negative, stable)
    pub direction: TrendDirection,
    /// Rate of change
    pub rate: f64,
    /// Predicted value for next interval
    pub predicted_value: Option<f64>,
}

/// Trend direction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrendDirection {
    /// Increasing
    Increasing,
    /// Decreasing
    Decreasing,
    /// Stable
    Stable,
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    /// Total samples collected
    pub total_samples: usize,
    /// Total transfers analyzed
    pub total_transfers: usize,
    /// Total bottlenecks detected
    pub bottlenecks_detected: usize,
    /// Average CPU usage
    pub avg_cpu_usage: f64,
    /// Average memory usage
    pub avg_memory_usage: u64,
    /// Average bandwidth usage
    pub avg_bandwidth_usage: u64,
    /// Average latency
    pub avg_latency: u64,
    /// Peak CPU usage
    pub peak_cpu_usage: f64,
    /// Peak memory usage
    pub peak_memory_usage: u64,
    /// Peak bandwidth usage
    pub peak_bandwidth_usage: u64,
    /// Last analysis time
    #[serde(skip)]
    pub last_analysis: Option<Instant>,
}

/// Performance analyzer
pub struct PerformanceAnalyzer {
    config: AnalyzerConfig,
    samples: VecDeque<PerformanceSample>,
    transfers: VecDeque<TransferRecord>,
    peer_performance: HashMap<String, VecDeque<TransferRecord>>,
    bottlenecks: Vec<Bottleneck>,
    last_analysis: Option<Instant>,
    stats: PerformanceStats,
}

impl PerformanceAnalyzer {
    /// Create a new performance analyzer
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            samples: VecDeque::new(),
            transfers: VecDeque::new(),
            peer_performance: HashMap::new(),
            bottlenecks: Vec::new(),
            last_analysis: None,
            stats: PerformanceStats {
                total_samples: 0,
                total_transfers: 0,
                bottlenecks_detected: 0,
                avg_cpu_usage: 0.0,
                avg_memory_usage: 0,
                avg_bandwidth_usage: 0,
                avg_latency: 0,
                peak_cpu_usage: 0.0,
                peak_memory_usage: 0,
                peak_bandwidth_usage: 0,
                last_analysis: None,
            },
        }
    }

    /// Record a performance sample
    pub fn record_sample(
        &mut self,
        cpu_usage: f64,
        memory_usage: u64,
        bandwidth_usage: u64,
        latency: u64,
        active_transfers: usize,
        peer_count: usize,
    ) {
        let sample = PerformanceSample {
            timestamp: Instant::now(),
            cpu_usage,
            memory_usage,
            bandwidth_usage,
            latency,
            active_transfers,
            peer_count,
        };

        self.samples.push_back(sample);
        self.stats.total_samples += 1;

        // Update peaks
        self.stats.peak_cpu_usage = self.stats.peak_cpu_usage.max(cpu_usage);
        self.stats.peak_memory_usage = self.stats.peak_memory_usage.max(memory_usage);
        self.stats.peak_bandwidth_usage = self.stats.peak_bandwidth_usage.max(bandwidth_usage);

        // Maintain max samples limit
        while self.samples.len() > self.config.max_samples {
            self.samples.pop_front();
        }

        // Auto-analyze if interval elapsed
        if self.should_analyze() {
            self.analyze();
        }
    }

    /// Record CPU usage
    pub fn record_cpu_usage(&mut self, cpu_usage: f64) {
        if let Some(sample) = self.samples.back_mut() {
            sample.cpu_usage = cpu_usage;
        } else {
            self.record_sample(cpu_usage, 0, 0, 0, 0, 0);
        }
    }

    /// Record memory usage
    pub fn record_memory_usage(&mut self, memory_usage: u64) {
        if let Some(sample) = self.samples.back_mut() {
            sample.memory_usage = memory_usage;
        } else {
            self.record_sample(0.0, memory_usage, 0, 0, 0, 0);
        }
    }

    /// Record a transfer
    pub fn record_transfer(&mut self, peer_id: &str, bytes: u64, duration_ms: u64) {
        let record = TransferRecord {
            peer_id: peer_id.to_string(),
            bytes,
            duration_ms,
            timestamp: Instant::now(),
        };

        self.transfers.push_back(record.clone());
        self.stats.total_transfers += 1;

        // Record per-peer performance
        self.peer_performance
            .entry(peer_id.to_string())
            .or_default()
            .push_back(record);

        // Maintain max samples limit for transfers
        while self.transfers.len() > self.config.max_samples {
            self.transfers.pop_front();
        }

        // Maintain per-peer limits
        for transfers in self.peer_performance.values_mut() {
            while transfers.len() > 100 {
                transfers.pop_front();
            }
        }
    }

    /// Check if analysis should be performed
    fn should_analyze(&self) -> bool {
        if self.samples.len() < self.config.min_samples {
            return false;
        }

        match self.last_analysis {
            Some(last) => last.elapsed().as_secs() >= self.config.analysis_interval,
            None => true,
        }
    }

    /// Perform performance analysis
    pub fn analyze(&mut self) {
        self.bottlenecks.clear();

        // Calculate averages
        self.calculate_averages();

        // Detect bottlenecks
        self.detect_cpu_bottleneck();
        self.detect_memory_bottleneck();
        self.detect_bandwidth_bottleneck();
        self.detect_latency_bottleneck();
        self.detect_peer_quality_bottleneck();

        self.stats.bottlenecks_detected = self.bottlenecks.len();
        self.last_analysis = Some(Instant::now());
        self.stats.last_analysis = self.last_analysis;
    }

    /// Calculate average metrics
    fn calculate_averages(&mut self) {
        if self.samples.is_empty() {
            return;
        }

        let count = self.samples.len() as f64;
        let sum_cpu: f64 = self.samples.iter().map(|s| s.cpu_usage).sum();
        let sum_memory: u64 = self.samples.iter().map(|s| s.memory_usage).sum();
        let sum_bandwidth: u64 = self.samples.iter().map(|s| s.bandwidth_usage).sum();
        let sum_latency: u64 = self.samples.iter().map(|s| s.latency).sum();

        self.stats.avg_cpu_usage = sum_cpu / count;
        self.stats.avg_memory_usage = (sum_memory as f64 / count) as u64;
        self.stats.avg_bandwidth_usage = (sum_bandwidth as f64 / count) as u64;
        self.stats.avg_latency = (sum_latency as f64 / count) as u64;
    }

    /// Detect CPU bottleneck
    fn detect_cpu_bottleneck(&mut self) {
        if self.stats.avg_cpu_usage > self.config.cpu_threshold {
            let severity = (self.stats.avg_cpu_usage - self.config.cpu_threshold)
                / (100.0 - self.config.cpu_threshold);

            self.bottlenecks.push(Bottleneck {
                bottleneck_type: BottleneckType::CPU,
                severity,
                current_value: self.stats.avg_cpu_usage,
                threshold_value: self.config.cpu_threshold,
                description: format!(
                    "CPU usage at {:.1}% exceeds threshold of {:.1}%",
                    self.stats.avg_cpu_usage, self.config.cpu_threshold
                ),
                detected_at: Instant::now(),
            });
        }
    }

    /// Detect memory bottleneck
    fn detect_memory_bottleneck(&mut self) {
        if self.stats.avg_memory_usage > self.config.memory_threshold {
            let severity = ((self.stats.avg_memory_usage - self.config.memory_threshold) as f64)
                / (self.config.memory_threshold as f64);

            self.bottlenecks.push(Bottleneck {
                bottleneck_type: BottleneckType::Memory,
                severity: severity.min(1.0),
                current_value: self.stats.avg_memory_usage as f64,
                threshold_value: self.config.memory_threshold as f64,
                description: format!(
                    "Memory usage at {} MB exceeds threshold of {} MB",
                    self.stats.avg_memory_usage / (1024 * 1024),
                    self.config.memory_threshold / (1024 * 1024)
                ),
                detected_at: Instant::now(),
            });
        }
    }

    /// Detect bandwidth bottleneck
    fn detect_bandwidth_bottleneck(&mut self) {
        if self.stats.avg_bandwidth_usage > self.config.bandwidth_threshold {
            let severity = ((self.stats.avg_bandwidth_usage - self.config.bandwidth_threshold)
                as f64)
                / (self.config.bandwidth_threshold as f64);

            self.bottlenecks.push(Bottleneck {
                bottleneck_type: BottleneckType::Bandwidth,
                severity: severity.min(1.0),
                current_value: self.stats.avg_bandwidth_usage as f64,
                threshold_value: self.config.bandwidth_threshold as f64,
                description: format!(
                    "Bandwidth usage at {} MB/s exceeds threshold of {} MB/s",
                    self.stats.avg_bandwidth_usage / (1024 * 1024),
                    self.config.bandwidth_threshold / (1024 * 1024)
                ),
                detected_at: Instant::now(),
            });
        }
    }

    /// Detect latency bottleneck
    fn detect_latency_bottleneck(&mut self) {
        if self.stats.avg_latency > self.config.latency_threshold {
            let severity = ((self.stats.avg_latency - self.config.latency_threshold) as f64)
                / (self.config.latency_threshold as f64);

            self.bottlenecks.push(Bottleneck {
                bottleneck_type: BottleneckType::Latency,
                severity: severity.min(1.0),
                current_value: self.stats.avg_latency as f64,
                threshold_value: self.config.latency_threshold as f64,
                description: format!(
                    "Average latency at {} ms exceeds threshold of {} ms",
                    self.stats.avg_latency, self.config.latency_threshold
                ),
                detected_at: Instant::now(),
            });
        }
    }

    /// Detect peer quality bottleneck
    fn detect_peer_quality_bottleneck(&mut self) {
        if self.transfers.is_empty() {
            return;
        }

        // Calculate average throughput
        let total_throughput: f64 = self
            .transfers
            .iter()
            .map(|t| {
                if t.duration_ms > 0 {
                    (t.bytes as f64 / t.duration_ms as f64) * 1000.0
                } else {
                    0.0
                }
            })
            .sum();

        let avg_throughput = total_throughput / self.transfers.len() as f64;

        // If average throughput is very low, it might indicate poor peer quality
        if avg_throughput < 100_000.0 {
            // < 100 KB/s
            let severity = 1.0 - (avg_throughput / 100_000.0).min(1.0);

            self.bottlenecks.push(Bottleneck {
                bottleneck_type: BottleneckType::PeerQuality,
                severity,
                current_value: avg_throughput,
                threshold_value: 100_000.0,
                description: format!(
                    "Average peer throughput at {:.0} KB/s indicates poor peer quality",
                    avg_throughput / 1024.0
                ),
                detected_at: Instant::now(),
            });
        }
    }

    /// Get detected bottlenecks
    pub fn detect_bottlenecks(&self) -> Option<Vec<Bottleneck>> {
        if self.bottlenecks.is_empty() {
            None
        } else {
            Some(self.bottlenecks.clone())
        }
    }

    /// Get optimization recommendations
    pub fn get_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        for bottleneck in &self.bottlenecks {
            match bottleneck.bottleneck_type {
                BottleneckType::CPU => {
                    recommendations.push(
                        "Consider reducing concurrent transfers or optimizing CPU-intensive operations".to_string()
                    );
                }
                BottleneckType::Memory => {
                    recommendations.push(
                        "Consider reducing cache size or implementing more aggressive eviction policies".to_string()
                    );
                }
                BottleneckType::Bandwidth => {
                    recommendations.push(
                        "Consider implementing bandwidth throttling or distributing load across more peers".to_string()
                    );
                }
                BottleneckType::Latency => {
                    recommendations.push(
                        "Consider selecting peers with lower latency or implementing latency-based routing".to_string()
                    );
                }
                BottleneckType::PeerQuality => {
                    recommendations.push(
                        "Consider improving peer selection criteria or implementing peer reputation scoring".to_string()
                    );
                }
                BottleneckType::DiskIO => {
                    recommendations.push(
                        "Consider using faster storage or implementing I/O batching".to_string(),
                    );
                }
            }
        }

        recommendations
    }

    /// Get performance trends
    pub fn get_trends(&self) -> Vec<PerformanceTrend> {
        if !self.config.enable_prediction || self.samples.len() < 10 {
            return Vec::new();
        }

        let trends = vec![
            // CPU trend
            self.calculate_trend("cpu_usage", |s| s.cpu_usage),
            // Memory trend
            self.calculate_trend("memory_usage", |s| s.memory_usage as f64),
            // Bandwidth trend
            self.calculate_trend("bandwidth_usage", |s| s.bandwidth_usage as f64),
            // Latency trend
            self.calculate_trend("latency", |s| s.latency as f64),
        ];

        trends
    }

    /// Calculate trend for a metric
    fn calculate_trend<F>(&self, name: &str, extractor: F) -> PerformanceTrend
    where
        F: Fn(&PerformanceSample) -> f64,
    {
        let values: Vec<f64> = self.samples.iter().map(&extractor).collect();

        if values.len() < 2 {
            return PerformanceTrend {
                metric: name.to_string(),
                direction: TrendDirection::Stable,
                rate: 0.0,
                predicted_value: None,
            };
        }

        // Simple linear regression
        let n = values.len() as f64;
        let x_sum: f64 = (0..values.len()).map(|i| i as f64).sum();
        let y_sum: f64 = values.iter().sum();
        let xy_sum: f64 = values.iter().enumerate().map(|(i, &y)| i as f64 * y).sum();
        let x2_sum: f64 = (0..values.len()).map(|i| (i * i) as f64).sum();

        let slope = (n * xy_sum - x_sum * y_sum) / (n * x2_sum - x_sum * x_sum);
        let intercept = (y_sum - slope * x_sum) / n;

        let direction = if slope > 0.01 {
            TrendDirection::Increasing
        } else if slope < -0.01 {
            TrendDirection::Decreasing
        } else {
            TrendDirection::Stable
        };

        let predicted_value = Some(slope * n + intercept);

        PerformanceTrend {
            metric: name.to_string(),
            direction,
            rate: slope,
            predicted_value,
        }
    }

    /// Get peer performance comparison
    pub fn compare_peers(&self) -> Vec<(String, f64)> {
        let mut peer_scores: Vec<(String, f64)> = self
            .peer_performance
            .iter()
            .map(|(peer_id, transfers)| {
                let avg_throughput = if transfers.is_empty() {
                    0.0
                } else {
                    let total: f64 = transfers
                        .iter()
                        .map(|t| {
                            if t.duration_ms > 0 {
                                (t.bytes as f64 / t.duration_ms as f64) * 1000.0
                            } else {
                                0.0
                            }
                        })
                        .sum();
                    total / transfers.len() as f64
                };

                (peer_id.clone(), avg_throughput)
            })
            .collect();

        peer_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        peer_scores
    }

    /// Get statistics
    pub fn stats(&self) -> &PerformanceStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.samples.clear();
        self.transfers.clear();
        self.peer_performance.clear();
        self.bottlenecks.clear();
        self.last_analysis = None;
        self.stats = PerformanceStats {
            total_samples: 0,
            total_transfers: 0,
            bottlenecks_detected: 0,
            avg_cpu_usage: 0.0,
            avg_memory_usage: 0,
            avg_bandwidth_usage: 0,
            avg_latency: 0,
            peak_cpu_usage: 0.0,
            peak_memory_usage: 0,
            peak_bandwidth_usage: 0,
            last_analysis: None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = PerformanceAnalyzer::new(config);
        assert_eq!(analyzer.stats().total_samples, 0);
    }

    #[test]
    fn test_record_sample() {
        let config = AnalyzerConfig::default();
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(50.0, 1024 * 1024, 1024 * 1024, 100, 5, 10);
        assert_eq!(analyzer.stats().total_samples, 1);
    }

    #[test]
    fn test_record_cpu_usage() {
        let config = AnalyzerConfig::default();
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_cpu_usage(75.5);
        assert_eq!(analyzer.stats().peak_cpu_usage, 75.5);
    }

    #[test]
    fn test_record_transfer() {
        let config = AnalyzerConfig::default();
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_transfer("peer1", 1024 * 1024, 100);
        assert_eq!(analyzer.stats().total_transfers, 1);
    }

    #[test]
    fn test_cpu_bottleneck_detection() {
        let config = AnalyzerConfig {
            cpu_threshold: 50.0,
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(85.0, 0, 0, 0, 0, 0);
        analyzer.analyze();

        let bottlenecks = analyzer.detect_bottlenecks().unwrap();
        assert_eq!(bottlenecks.len(), 1);
        assert_eq!(bottlenecks[0].bottleneck_type, BottleneckType::CPU);
    }

    #[test]
    fn test_memory_bottleneck_detection() {
        let config = AnalyzerConfig {
            memory_threshold: 100 * 1024 * 1024, // 100MB
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(0.0, 200 * 1024 * 1024, 0, 0, 0, 0);
        analyzer.analyze();

        let bottlenecks = analyzer.detect_bottlenecks().unwrap();
        assert!(!bottlenecks.is_empty());
        assert!(
            bottlenecks
                .iter()
                .any(|b| b.bottleneck_type == BottleneckType::Memory)
        );
    }

    #[test]
    fn test_no_bottlenecks() {
        let config = AnalyzerConfig {
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(30.0, 100 * 1024 * 1024, 10 * 1024 * 1024, 50, 5, 10);
        analyzer.analyze();

        assert!(analyzer.detect_bottlenecks().is_none());
    }

    #[test]
    fn test_recommendations() {
        let config = AnalyzerConfig {
            cpu_threshold: 50.0,
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(85.0, 0, 0, 0, 0, 0);
        analyzer.analyze();

        let recommendations = analyzer.get_recommendations();
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_peer_comparison() {
        let config = AnalyzerConfig::default();
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_transfer("peer1", 1024 * 1024, 100); // 10 MB/s
        analyzer.record_transfer("peer2", 512 * 1024, 100); // 5 MB/s
        analyzer.record_transfer("peer3", 2 * 1024 * 1024, 100); // 20 MB/s

        let comparison = analyzer.compare_peers();
        assert_eq!(comparison.len(), 3);
        assert_eq!(comparison[0].0, "peer3"); // Best performer first
    }

    #[test]
    fn test_calculate_averages() {
        let config = AnalyzerConfig {
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(50.0, 1024 * 1024, 512 * 1024, 100, 5, 10);
        analyzer.record_sample(60.0, 2 * 1024 * 1024, 1024 * 1024, 150, 10, 15);
        analyzer.analyze();

        let stats = analyzer.stats();
        assert_eq!(stats.avg_cpu_usage, 55.0);
    }

    #[test]
    fn test_trends() {
        let config = AnalyzerConfig {
            enable_prediction: true,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        for i in 0..20 {
            analyzer.record_sample((i as f64) * 2.0, (i as u64) * 1024 * 1024, 0, 0, 0, 0);
        }

        let trends = analyzer.get_trends();
        assert!(!trends.is_empty());

        let cpu_trend = trends.iter().find(|t| t.metric == "cpu_usage").unwrap();
        assert_eq!(cpu_trend.direction, TrendDirection::Increasing);
    }

    #[test]
    fn test_max_samples_limit() {
        let config = AnalyzerConfig {
            max_samples: 10,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        for _ in 0..20 {
            analyzer.record_sample(50.0, 0, 0, 0, 0, 0);
        }

        assert!(analyzer.samples.len() <= 10);
    }

    #[test]
    fn test_reset_stats() {
        let config = AnalyzerConfig::default();
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(50.0, 0, 0, 0, 0, 0);
        analyzer.record_transfer("peer1", 1024, 100);

        analyzer.reset_stats();

        assert_eq!(analyzer.stats().total_samples, 0);
        assert_eq!(analyzer.stats().total_transfers, 0);
    }

    #[test]
    fn test_latency_bottleneck() {
        let config = AnalyzerConfig {
            latency_threshold: 100,
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(0.0, 0, 0, 500, 0, 0);
        analyzer.analyze();

        let bottlenecks = analyzer.detect_bottlenecks().unwrap();
        assert!(
            bottlenecks
                .iter()
                .any(|b| b.bottleneck_type == BottleneckType::Latency)
        );
    }

    #[test]
    fn test_bandwidth_bottleneck() {
        let config = AnalyzerConfig {
            bandwidth_threshold: 10 * 1024 * 1024, // 10 MB/s
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        analyzer.record_sample(0.0, 0, 50 * 1024 * 1024, 0, 0, 0);
        analyzer.analyze();

        let bottlenecks = analyzer.detect_bottlenecks().unwrap();
        assert!(
            bottlenecks
                .iter()
                .any(|b| b.bottleneck_type == BottleneckType::Bandwidth)
        );
    }

    #[test]
    fn test_peer_quality_bottleneck() {
        let config = AnalyzerConfig {
            min_samples: 1,
            ..Default::default()
        };
        let mut analyzer = PerformanceAnalyzer::new(config);

        // Record very slow transfers
        for _ in 0..10 {
            analyzer.record_transfer("slow_peer", 1024, 1000); // 1 KB/s
        }

        analyzer.record_sample(0.0, 0, 0, 0, 0, 0);
        analyzer.analyze();

        let bottlenecks = analyzer.detect_bottlenecks().unwrap();
        assert!(
            bottlenecks
                .iter()
                .any(|b| b.bottleneck_type == BottleneckType::PeerQuality)
        );
    }
}
