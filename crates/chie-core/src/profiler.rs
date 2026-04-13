//! Performance profiling utilities for CHIE Protocol.
//!
//! This module provides lightweight profiling tools to track operation timings,
//! identify bottlenecks, and generate performance reports.
//!
//! # Examples
//!
//! ```
//! use chie_core::profiler::{Profiler, ProfileScope};
//! use std::time::Duration;
//!
//! let mut profiler = Profiler::new();
//!
//! // Profile a code section
//! {
//!     let _scope = profiler.scope("chunk_encryption");
//!     // ... encryption work ...
//!     std::thread::sleep(Duration::from_millis(10));
//! }
//!
//! // Get statistics
//! let report = profiler.generate_report();
//! println!("{}", report);
//! ```

use rand::RngExt as _;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of histogram buckets for percentile tracking.
const MAX_HISTOGRAM_SAMPLES: usize = 10_000;

/// Latency histogram for accurate percentile calculations.
#[derive(Debug, Clone)]
struct LatencyHistogram {
    /// Sorted samples (maintained up to MAX_HISTOGRAM_SAMPLES).
    samples: Vec<Duration>,
    /// Total number of samples recorded (including those not stored).
    total_count: u64,
}

impl LatencyHistogram {
    /// Create a new histogram.
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(1000),
            total_count: 0,
        }
    }

    /// Record a latency sample.
    fn record(&mut self, duration: Duration) {
        self.total_count += 1;

        // Use reservoir sampling to maintain a representative sample
        if self.samples.len() < MAX_HISTOGRAM_SAMPLES {
            self.samples.push(duration);
        } else if self.total_count > 0 {
            // Reservoir sampling: replace random element with probability
            let idx = (rand::rng().random::<u64>() as usize % (self.total_count as usize))
                .min(MAX_HISTOGRAM_SAMPLES - 1);
            if idx < MAX_HISTOGRAM_SAMPLES {
                self.samples[idx] = duration;
            }
        }
    }

    /// Calculate percentile (p should be between 0.0 and 1.0).
    fn percentile(&self, p: f64) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }

        // Sort samples for percentile calculation
        let mut sorted = self.samples.clone();
        sorted.sort();

        let index = ((sorted.len() as f64) * p).floor() as usize;
        let index = index.min(sorted.len() - 1);
        sorted[index]
    }

    /// Get p50 (median).
    #[inline]
    fn p50(&self) -> Duration {
        self.percentile(0.50)
    }

    /// Get p95.
    #[inline]
    fn p95(&self) -> Duration {
        self.percentile(0.95)
    }

    /// Get p99.
    #[inline]
    fn p99(&self) -> Duration {
        self.percentile(0.99)
    }

    /// Get p999.
    #[inline]
    fn p999(&self) -> Duration {
        self.percentile(0.999)
    }
}

/// Performance statistics for a profiled operation.
#[derive(Debug, Clone)]
pub struct OperationStats {
    /// Number of times the operation was executed.
    pub count: u64,
    /// Total time spent in this operation.
    pub total_duration: Duration,
    /// Minimum execution time.
    pub min_duration: Duration,
    /// Maximum execution time.
    pub max_duration: Duration,
    /// Average execution time.
    pub avg_duration: Duration,
    /// Latency histogram for percentile tracking.
    histogram: LatencyHistogram,
}

impl OperationStats {
    /// Create new operation statistics.
    fn new() -> Self {
        Self {
            count: 0,
            total_duration: Duration::ZERO,
            min_duration: Duration::MAX,
            max_duration: Duration::ZERO,
            avg_duration: Duration::ZERO,
            histogram: LatencyHistogram::new(),
        }
    }

    /// Record a new timing sample.
    fn record(&mut self, duration: Duration) {
        self.count += 1;
        self.total_duration += duration;
        self.min_duration = self.min_duration.min(duration);
        self.max_duration = self.max_duration.max(duration);
        self.avg_duration = self.total_duration / self.count as u32;
        self.histogram.record(duration);
    }

    /// Get operations per second based on total time.
    #[must_use]
    #[inline]
    pub fn ops_per_second(&self) -> f64 {
        if self.total_duration.is_zero() {
            return 0.0;
        }
        self.count as f64 / self.total_duration.as_secs_f64()
    }

    /// Get 50th percentile (median).
    #[must_use]
    #[inline]
    pub fn p50(&self) -> Duration {
        self.histogram.p50()
    }

    /// Get 95th percentile.
    #[must_use]
    #[inline]
    pub fn p95(&self) -> Duration {
        self.histogram.p95()
    }

    /// Get 99th percentile.
    #[must_use]
    #[inline]
    pub fn p99(&self) -> Duration {
        self.histogram.p99()
    }

    /// Get 99.9th percentile.
    #[must_use]
    #[inline]
    pub fn p999(&self) -> Duration {
        self.histogram.p999()
    }

    /// Get 99th percentile estimate (deprecated, use p99() instead).
    #[deprecated(
        since = "0.1.0",
        note = "Use p99() for accurate histogram-based percentile"
    )]
    #[must_use]
    #[inline]
    pub fn p99_estimate(&self) -> Duration {
        self.p99()
    }
}

/// Performance profiler for tracking operation timings.
pub struct Profiler {
    /// Operation statistics by name.
    stats: HashMap<String, OperationStats>,
    /// Whether profiling is enabled.
    enabled: bool,
}

impl Profiler {
    /// Create a new profiler.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            enabled: true,
        }
    }

    /// Create a profiler with profiling disabled.
    #[must_use]
    #[inline]
    pub fn disabled() -> Self {
        Self {
            stats: HashMap::new(),
            enabled: false,
        }
    }

    /// Enable profiling.
    #[inline]
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable profiling.
    #[inline]
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check if profiling is enabled.
    #[must_use]
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Create a profile scope for an operation.
    #[must_use]
    #[inline]
    pub fn scope(&mut self, name: &str) -> ProfileScope<'_> {
        ProfileScope::new(self, name.to_string())
    }

    /// Record a timing manually.
    #[inline]
    pub fn record(&mut self, name: &str, duration: Duration) {
        if !self.enabled {
            return;
        }

        let stats = self
            .stats
            .entry(name.to_string())
            .or_insert_with(OperationStats::new);
        stats.record(duration);
    }

    /// Get statistics for an operation.
    #[must_use]
    #[inline]
    pub fn get_stats(&self, name: &str) -> Option<&OperationStats> {
        self.stats.get(name)
    }

    /// Get all operation names.
    #[must_use]
    #[inline]
    pub fn operation_names(&self) -> Vec<&str> {
        self.stats.keys().map(|s| s.as_str()).collect()
    }

    /// Clear all statistics.
    #[inline]
    pub fn clear(&mut self) {
        self.stats.clear();
    }

    /// Get total number of profiled operations.
    #[must_use]
    #[inline]
    pub fn total_operations(&self) -> usize {
        self.stats.len()
    }

    /// Get total time spent across all operations.
    #[must_use]
    #[inline]
    pub fn total_time(&self) -> Duration {
        self.stats.values().map(|s| s.total_duration).sum()
    }

    /// Generate a performance report.
    #[must_use]
    pub fn generate_report(&self) -> String {
        let mut lines = vec![
            "Performance Profile Report".to_string(),
            "=========================".to_string(),
            String::new(),
        ];

        if self.stats.is_empty() {
            lines.push("No profiling data available.".to_string());
            return lines.join("\n");
        }

        // Sort by total duration (highest first)
        let mut sorted_stats: Vec<_> = self.stats.iter().collect();
        sorted_stats.sort_by(|a, b| b.1.total_duration.cmp(&a.1.total_duration));

        // Header
        lines.push(format!(
            "{:<25} {:>8} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "Operation",
            "Count",
            "Avg(ms)",
            "Min(ms)",
            "p50(ms)",
            "p95(ms)",
            "p99(ms)",
            "p999(ms)",
            "Max(ms)"
        ));
        lines.push("-".repeat(120));

        // Data rows
        for (name, stats) in sorted_stats {
            lines.push(format!(
                "{:<25} {:>8} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
                truncate_str(name, 25),
                stats.count,
                stats.avg_duration.as_secs_f64() * 1000.0,
                stats.min_duration.as_secs_f64() * 1000.0,
                stats.p50().as_secs_f64() * 1000.0,
                stats.p95().as_secs_f64() * 1000.0,
                stats.p99().as_secs_f64() * 1000.0,
                stats.p999().as_secs_f64() * 1000.0,
                stats.max_duration.as_secs_f64() * 1000.0,
            ));
        }

        lines.push(String::new());
        lines.push(format!("Total operations: {}", self.total_operations()));
        lines.push(format!(
            "Total time: {:.2}ms",
            self.total_time().as_secs_f64() * 1000.0
        ));

        lines.join("\n")
    }

    /// Export statistics as JSON (simple format).
    #[must_use]
    pub fn export_json(&self) -> String {
        use serde_json::json;

        let operations: Vec<_> = self
            .stats
            .iter()
            .map(|(name, stats)| {
                json!({
                    "name": name,
                    "count": stats.count,
                    "total_ms": stats.total_duration.as_secs_f64() * 1000.0,
                    "avg_ms": stats.avg_duration.as_secs_f64() * 1000.0,
                    "min_ms": stats.min_duration.as_secs_f64() * 1000.0,
                    "p50_ms": stats.p50().as_secs_f64() * 1000.0,
                    "p95_ms": stats.p95().as_secs_f64() * 1000.0,
                    "p99_ms": stats.p99().as_secs_f64() * 1000.0,
                    "p999_ms": stats.p999().as_secs_f64() * 1000.0,
                    "max_ms": stats.max_duration.as_secs_f64() * 1000.0,
                    "ops_per_sec": stats.ops_per_second(),
                })
            })
            .collect();

        json!({
            "total_operations": self.total_operations(),
            "total_time_ms": self.total_time().as_secs_f64() * 1000.0,
            "operations": operations,
        })
        .to_string()
    }
}

impl Default for Profiler {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for profiling a scope.
pub struct ProfileScope<'a> {
    profiler: &'a mut Profiler,
    name: String,
    start: Instant,
}

impl<'a> ProfileScope<'a> {
    #[inline]
    fn new(profiler: &'a mut Profiler, name: String) -> Self {
        Self {
            profiler,
            name,
            start: Instant::now(),
        }
    }
}

impl Drop for ProfileScope<'_> {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.profiler.record(&self.name, duration);
    }
}

/// Truncate a string to a maximum length.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Global profiler instance for convenience.
static GLOBAL_PROFILER: std::sync::Mutex<Option<Profiler>> = std::sync::Mutex::new(None);

/// Initialize the global profiler.
pub fn init_global_profiler() {
    let mut guard = GLOBAL_PROFILER.lock().unwrap();
    *guard = Some(Profiler::new());
}

/// Get a reference to the global profiler.
pub fn global_profiler<F, R>(f: F) -> R
where
    F: FnOnce(&mut Profiler) -> R,
{
    let mut guard = GLOBAL_PROFILER.lock().unwrap();
    if guard.is_none() {
        *guard = Some(Profiler::new());
    }
    f(guard.as_mut().unwrap())
}

/// Macro for easy profiling of code blocks.
#[macro_export]
macro_rules! profile {
    ($profiler:expr, $name:expr, $block:block) => {{
        let _scope = $profiler.scope($name);
        $block
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_profiler_basic() {
        let mut profiler = Profiler::new();

        {
            let _scope = profiler.scope("test_op");
            thread::sleep(Duration::from_millis(10));
        }

        let stats = profiler.get_stats("test_op").unwrap();
        assert_eq!(stats.count, 1);
        assert!(stats.total_duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_profiler_multiple_operations() {
        let mut profiler = Profiler::new();

        for _ in 0..5 {
            let _scope = profiler.scope("op1");
            thread::sleep(Duration::from_millis(1));
        }

        for _ in 0..3 {
            let _scope = profiler.scope("op2");
            thread::sleep(Duration::from_millis(2));
        }

        let stats1 = profiler.get_stats("op1").unwrap();
        assert_eq!(stats1.count, 5);

        let stats2 = profiler.get_stats("op2").unwrap();
        assert_eq!(stats2.count, 3);

        assert_eq!(profiler.total_operations(), 2);
    }

    #[test]
    fn test_profiler_disabled() {
        let mut profiler = Profiler::disabled();

        {
            let _scope = profiler.scope("test_op");
            thread::sleep(Duration::from_millis(10));
        }

        assert!(profiler.get_stats("test_op").is_none());
        assert_eq!(profiler.total_operations(), 0);
    }

    #[test]
    fn test_profiler_stats() {
        let mut profiler = Profiler::new();

        profiler.record("test", Duration::from_millis(100));
        profiler.record("test", Duration::from_millis(200));
        profiler.record("test", Duration::from_millis(300));

        let stats = profiler.get_stats("test").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.min_duration, Duration::from_millis(100));
        assert_eq!(stats.max_duration, Duration::from_millis(300));
        assert_eq!(stats.avg_duration, Duration::from_millis(200));
    }

    #[test]
    fn test_generate_report() {
        let mut profiler = Profiler::new();

        profiler.record("encryption", Duration::from_millis(100));
        profiler.record("decryption", Duration::from_millis(50));

        let report = profiler.generate_report();
        assert!(report.contains("encryption"));
        assert!(report.contains("decryption"));
        assert!(report.contains("Performance Profile Report"));
    }

    #[test]
    fn test_export_json() {
        let mut profiler = Profiler::new();
        profiler.record("test_op", Duration::from_millis(100));

        let json = profiler.export_json();
        assert!(json.contains("test_op"));
        assert!(json.contains("total_operations"));
    }

    #[test]
    fn test_profiler_clear() {
        let mut profiler = Profiler::new();
        profiler.record("test", Duration::from_millis(100));

        assert_eq!(profiler.total_operations(), 1);

        profiler.clear();
        assert_eq!(profiler.total_operations(), 0);
    }

    #[test]
    fn test_operation_stats_ops_per_second() {
        let mut stats = OperationStats::new();
        stats.record(Duration::from_millis(100));
        stats.record(Duration::from_millis(100));
        stats.record(Duration::from_millis(100));

        // 3 operations in 300ms = 10 ops/sec
        let ops_per_sec = stats.ops_per_second();
        assert!((ops_per_sec - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_percentiles() {
        let mut stats = OperationStats::new();

        // Record samples with known distribution
        for i in 1..=100 {
            stats.record(Duration::from_millis(i));
        }

        // Test percentiles are in expected ranges
        assert_eq!(stats.count, 100);

        let p50 = stats.p50();
        assert!(p50 >= Duration::from_millis(45) && p50 <= Duration::from_millis(55));

        let p95 = stats.p95();
        assert!(p95 >= Duration::from_millis(90) && p95 <= Duration::from_millis(100));

        let p99 = stats.p99();
        assert!(p99 >= Duration::from_millis(95) && p99 <= Duration::from_millis(100));
    }

    #[test]
    fn test_histogram_with_few_samples() {
        let mut stats = OperationStats::new();

        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));

        // With only 3 samples, percentiles should still work
        assert!(stats.p50() > Duration::ZERO);
        assert!(stats.p95() > Duration::ZERO);
        assert!(stats.p99() > Duration::ZERO);
    }

    #[test]
    fn test_percentiles_empty() {
        let stats = OperationStats::new();

        // Empty stats should return zero for percentiles
        assert_eq!(stats.p50(), Duration::ZERO);
        assert_eq!(stats.p95(), Duration::ZERO);
        assert_eq!(stats.p99(), Duration::ZERO);
        assert_eq!(stats.p999(), Duration::ZERO);
    }

    #[test]
    fn test_export_json_with_percentiles() {
        let mut profiler = Profiler::new();

        for i in 1..=50 {
            profiler.record("test_op", Duration::from_millis(i));
        }

        let json = profiler.export_json();

        // Verify JSON contains percentile fields
        assert!(json.contains("p50_ms"));
        assert!(json.contains("p95_ms"));
        assert!(json.contains("p99_ms"));
        assert!(json.contains("p999_ms"));
        assert!(json.contains("ops_per_sec"));
    }

    #[test]
    fn test_generate_report_with_percentiles() {
        let mut profiler = Profiler::new();

        for i in 1..=100 {
            profiler.record("encryption", Duration::from_millis(i));
        }

        let report = profiler.generate_report();

        // Verify report contains percentile columns
        assert!(report.contains("p50(ms)"));
        assert!(report.contains("p95(ms)"));
        assert!(report.contains("p99(ms)"));
        assert!(report.contains("p999(ms)"));
        assert!(report.contains("encryption"));
    }
}
