//! Advanced statistics and analytics utilities.

use std::collections::VecDeque;

/// Streaming statistics calculator using Welford's online algorithm.
/// Computes mean, variance, and standard deviation in a single pass
/// without storing all values in memory.
///
/// # Examples
///
/// ```
/// use chie_shared::StreamingStats;
///
/// let mut stats = StreamingStats::new();
///
/// // Add some latency measurements (in ms)
/// for latency in [100.0, 105.0, 95.0, 110.0, 98.0] {
///     stats.add(latency);
/// }
///
/// assert_eq!(stats.count(), 5);
/// assert!((stats.mean() - 101.6).abs() < 0.1);
/// assert!(stats.std_dev() > 0.0);
///
/// // Merge statistics from another source
/// let mut other_stats = StreamingStats::new();
/// other_stats.add(102.0);
/// other_stats.add(108.0);
///
/// stats.merge(&other_stats);
/// assert_eq!(stats.count(), 7);
/// ```
#[derive(Debug, Clone)]
pub struct StreamingStats {
    n: u64,
    mean: f64,
    m2: f64, // Sum of squared differences from mean
}

impl StreamingStats {
    /// Create a new streaming statistics calculator.
    pub fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Add a new value to the statistics.
    pub fn add(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Get the number of samples.
    pub fn count(&self) -> u64 {
        self.n
    }

    /// Get the mean.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Get the variance.
    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / self.n as f64
        }
    }

    /// Get the sample variance (Bessel's correction).
    pub fn sample_variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n - 1) as f64
        }
    }

    /// Get the standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Get the sample standard deviation.
    pub fn sample_std_dev(&self) -> f64 {
        self.sample_variance().sqrt()
    }

    /// Reset the statistics.
    pub fn reset(&mut self) {
        self.n = 0;
        self.mean = 0.0;
        self.m2 = 0.0;
    }

    /// Merge another StreamingStats into this one.
    pub fn merge(&mut self, other: &StreamingStats) {
        if other.n == 0 {
            return;
        }
        if self.n == 0 {
            *self = other.clone();
            return;
        }

        let total_n = self.n + other.n;
        let delta = other.mean - self.mean;
        let new_mean = (self.n as f64 * self.mean + other.n as f64 * other.mean) / total_n as f64;

        // delta * delta is correct for Welford's parallel variance formula
        #[allow(clippy::suspicious_operation_groupings)]
        {
            self.m2 = self.m2
                + other.m2
                + delta * delta * (self.n as f64 * other.n as f64) / total_n as f64;
        }
        self.mean = new_mean;
        self.n = total_n;
    }
}

impl Default for StreamingStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Exponential backoff calculator for retry logic.
///
/// # Examples
///
/// ```
/// use chie_shared::ExponentialBackoff;
///
/// let mut backoff = ExponentialBackoff::new();
///
/// // Simulate retry attempts
/// let delay1 = backoff.next_delay_ms();
/// assert!(delay1 >= 75 && delay1 <= 125); // ~100ms ± 25% jitter
///
/// let delay2 = backoff.next_delay_ms();
/// assert!(delay2 >= 150 && delay2 <= 250); // ~200ms ± 25% jitter
///
/// assert_eq!(backoff.attempt_count(), 2);
/// assert!(!backoff.is_exhausted());
///
/// // Custom backoff for more aggressive retries
/// let mut fast_backoff = ExponentialBackoff::custom(50, 5_000, 1.5, 5);
/// let first_delay = fast_backoff.next_delay_ms();
/// assert!(first_delay >= 37 && first_delay <= 63); // ~50ms ± 25%
/// ```
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    base_ms: u64,
    max_ms: u64,
    multiplier: f64,
    attempt: u32,
    max_attempts: u32,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff with default settings.
    /// Base: 100ms, Max: 30s, Multiplier: 2.0, Max attempts: 10
    pub fn new() -> Self {
        Self {
            base_ms: 100,
            max_ms: 30_000,
            multiplier: 2.0,
            attempt: 0,
            max_attempts: 10,
        }
    }

    /// Create a custom exponential backoff.
    pub fn custom(base_ms: u64, max_ms: u64, multiplier: f64, max_attempts: u32) -> Self {
        Self {
            base_ms,
            max_ms,
            multiplier,
            attempt: 0,
            max_attempts,
        }
    }

    /// Get the next delay in milliseconds with jitter.
    pub fn next_delay_ms(&mut self) -> u64 {
        if self.attempt >= self.max_attempts {
            return self.max_ms;
        }

        let delay = (self.base_ms as f64 * self.multiplier.powi(self.attempt as i32)) as u64;
        let delay = delay.min(self.max_ms);

        // Add jitter (±25%)
        let jitter_range = delay / 4;
        let jitter = if jitter_range > 0 {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).unwrap_or_default();
            let random_u64 = u64::from_le_bytes(bytes);
            (random_u64 % (jitter_range * 2)).saturating_sub(jitter_range)
        } else {
            0
        };

        self.attempt += 1;
        delay.saturating_add(jitter)
    }

    /// Reset the attempt counter.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Check if max attempts have been reached.
    pub fn is_exhausted(&self) -> bool {
        self.attempt >= self.max_attempts
    }

    /// Get current attempt number.
    pub fn attempt_count(&self) -> u32 {
        self.attempt
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

/// Sliding window for time-series analytics.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    values: VecDeque<f64>,
    capacity: usize,
}

impl SlidingWindow {
    /// Create a new sliding window with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            values: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Add a value to the window.
    pub fn push(&mut self, value: f64) {
        if self.values.len() >= self.capacity {
            self.values.pop_front();
        }
        self.values.push_back(value);
    }

    /// Get the number of values in the window.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Check if the window is full.
    pub fn is_full(&self) -> bool {
        self.values.len() >= self.capacity
    }

    /// Get the mean of values in the window.
    pub fn mean(&self) -> f64 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.values.iter().sum::<f64>() / self.values.len() as f64
    }

    /// Get the minimum value in the window.
    pub fn min(&self) -> Option<f64> {
        self.values
            .iter()
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .copied()
    }

    /// Get the maximum value in the window.
    pub fn max(&self) -> Option<f64> {
        self.values
            .iter()
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .copied()
    }

    /// Get the standard deviation of values in the window.
    pub fn std_dev(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }

        let mean = self.mean();
        let variance = self
            .values
            .iter()
            .map(|v| {
                let diff = v - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.values.len() as f64;

        variance.sqrt()
    }

    /// Clear all values from the window.
    pub fn clear(&mut self) {
        self.values.clear()
    }

    /// Get all values as a slice.
    pub fn values(&self) -> Vec<f64> {
        self.values.iter().copied().collect()
    }
}

/// Histogram for tracking value distributions (e.g., latency).
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<(f64, u64)>, // (upper_bound, count)
    sum: f64,
    count: u64,
    min: f64,
    max: f64,
}

impl Histogram {
    /// Create a new histogram with predefined buckets.
    /// Buckets are defined as upper bounds.
    pub fn new(bucket_bounds: Vec<f64>) -> Self {
        let buckets = bucket_bounds.into_iter().map(|b| (b, 0)).collect();
        Self {
            buckets,
            sum: 0.0,
            count: 0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Create a histogram with exponential buckets for latency (in milliseconds).
    /// Creates buckets: 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000ms
    pub fn for_latency_ms() -> Self {
        Self::new(vec![
            1.0,
            2.0,
            5.0,
            10.0,
            20.0,
            50.0,
            100.0,
            200.0,
            500.0,
            1000.0,
            2000.0,
            5000.0,
            f64::INFINITY,
        ])
    }

    /// Create a histogram with exponential buckets for bandwidth (in Mbps).
    pub fn for_bandwidth_mbps() -> Self {
        Self::new(vec![
            0.1,
            0.5,
            1.0,
            5.0,
            10.0,
            50.0,
            100.0,
            500.0,
            1000.0,
            f64::INFINITY,
        ])
    }

    /// Record a value in the histogram.
    pub fn record(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);

        // Find the appropriate bucket
        for (bound, count) in &mut self.buckets {
            if value <= *bound {
                *count += 1;
                return;
            }
        }
    }

    /// Get the total count of recorded values.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Get the sum of all recorded values.
    pub fn sum(&self) -> f64 {
        self.sum
    }

    /// Get the mean of recorded values.
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    /// Get the minimum recorded value.
    pub fn min(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.min }
    }

    /// Get the maximum recorded value.
    pub fn max(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.max }
    }

    /// Estimate a percentile from the histogram.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }

        let target = (self.count as f64 * p.clamp(0.0, 1.0)) as u64;
        let mut cumulative = 0u64;

        for (bound, count) in &self.buckets {
            cumulative += count;
            if cumulative >= target {
                return *bound;
            }
        }

        self.max
    }

    /// Get P50 (median) latency.
    pub fn p50(&self) -> f64 {
        self.percentile(0.50)
    }

    /// Get P95 latency.
    pub fn p95(&self) -> f64 {
        self.percentile(0.95)
    }

    /// Get P99 latency.
    pub fn p99(&self) -> f64 {
        self.percentile(0.99)
    }

    /// Get P999 (99.9th percentile) latency.
    pub fn p999(&self) -> f64 {
        self.percentile(0.999)
    }

    /// Merge another histogram into this one.
    pub fn merge(&mut self, other: &Histogram) {
        if self.buckets.len() != other.buckets.len() {
            return; // Can only merge histograms with same bucket structure
        }

        for (i, (_, count)) in self.buckets.iter_mut().enumerate() {
            *count += other.buckets[i].1;
        }

        self.sum += other.sum;
        self.count += other.count;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }

    /// Get bucket information as a vector of (upper_bound, count, cumulative_count).
    pub fn buckets_info(&self) -> Vec<(f64, u64, u64)> {
        let mut cumulative = 0u64;
        self.buckets
            .iter()
            .map(|(bound, count)| {
                cumulative += count;
                (*bound, *count, cumulative)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_stats() {
        let mut stats = StreamingStats::new();
        assert_eq!(stats.count(), 0);
        assert_eq!(stats.mean(), 0.0);

        // Add some values
        stats.add(10.0);
        stats.add(20.0);
        stats.add(30.0);

        assert_eq!(stats.count(), 3);
        assert_eq!(stats.mean(), 20.0);
        assert!((stats.std_dev() - 8.164_965_809_277_26).abs() < 0.0001);

        // Test reset
        stats.reset();
        assert_eq!(stats.count(), 0);
        assert_eq!(stats.mean(), 0.0);
    }

    #[test]
    fn test_streaming_stats_merge() {
        let mut stats1 = StreamingStats::new();
        stats1.add(10.0);
        stats1.add(20.0);

        let mut stats2 = StreamingStats::new();
        stats2.add(30.0);
        stats2.add(40.0);

        stats1.merge(&stats2);
        assert_eq!(stats1.count(), 4);
        assert_eq!(stats1.mean(), 25.0);
    }

    #[test]
    fn test_streaming_stats_sample_variance() {
        let mut stats = StreamingStats::new();
        stats.add(2.0);
        stats.add(4.0);
        stats.add(6.0);
        stats.add(8.0);

        let sample_var = stats.sample_variance();
        let expected_var = 6.666_666_666_666_667; // Calculated manually
        assert!((sample_var - expected_var).abs() < 0.0001);
    }

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new();
        assert_eq!(backoff.attempt_count(), 0);
        assert!(!backoff.is_exhausted());

        // Get first delay
        let delay1 = backoff.next_delay_ms();
        assert!((75..=125).contains(&delay1)); // 100ms ± 25%
        assert_eq!(backoff.attempt_count(), 1);

        // Get second delay (should be ~200ms ± 25%)
        let delay2 = backoff.next_delay_ms();
        assert!((150..=250).contains(&delay2));

        // Reset and verify
        backoff.reset();
        assert_eq!(backoff.attempt_count(), 0);
    }

    #[test]
    fn test_exponential_backoff_max() {
        let mut backoff = ExponentialBackoff::custom(100, 1000, 2.0, 5);

        // Exhaust all attempts
        for _ in 0..5 {
            backoff.next_delay_ms();
        }
        assert!(backoff.is_exhausted());

        // Further calls should return max_ms
        let delay = backoff.next_delay_ms();
        assert_eq!(delay, 1000);
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(3);
        assert!(window.is_empty());
        assert!(!window.is_full());

        window.push(10.0);
        window.push(20.0);
        window.push(30.0);

        assert!(window.is_full());
        assert_eq!(window.len(), 3);
        assert_eq!(window.mean(), 20.0);
        assert_eq!(window.min(), Some(10.0));
        assert_eq!(window.max(), Some(30.0));

        // Push another value (should evict first)
        window.push(40.0);
        assert_eq!(window.len(), 3);
        assert_eq!(window.mean(), 30.0);
        assert_eq!(window.min(), Some(20.0));

        // Test clear
        window.clear();
        assert!(window.is_empty());
        assert_eq!(window.len(), 0);
    }

    #[test]
    fn test_sliding_window_std_dev() {
        let mut window = SlidingWindow::new(4);
        window.push(2.0);
        window.push(4.0);
        window.push(6.0);
        window.push(8.0);

        let std_dev = window.std_dev();
        let expected = 2.236_067_977_499_79; // sqrt(5)
        assert!((std_dev - expected).abs() < 0.0001);
    }

    #[test]
    fn test_histogram() {
        let mut hist = Histogram::for_latency_ms();
        assert_eq!(hist.count(), 0);

        // Record some latencies
        hist.record(5.0);
        hist.record(15.0);
        hist.record(25.0);
        hist.record(100.0);
        hist.record(500.0);

        assert_eq!(hist.count(), 5);
        assert_eq!(hist.sum(), 645.0);
        assert_eq!(hist.mean(), 129.0);
        assert_eq!(hist.min(), 5.0);
        assert_eq!(hist.max(), 500.0);

        // Test percentiles
        assert!(hist.p50() > 0.0);
        assert!(hist.p95() > 0.0);
        assert!(hist.p99() > 0.0);
    }

    #[test]
    fn test_histogram_merge() {
        let mut hist1 = Histogram::for_latency_ms();
        hist1.record(10.0);
        hist1.record(20.0);

        let mut hist2 = Histogram::for_latency_ms();
        hist2.record(30.0);
        hist2.record(40.0);

        hist1.merge(&hist2);
        assert_eq!(hist1.count(), 4);
        assert_eq!(hist1.sum(), 100.0);
        assert_eq!(hist1.mean(), 25.0);
        assert_eq!(hist1.min(), 10.0);
        assert_eq!(hist1.max(), 40.0);
    }

    #[test]
    fn test_histogram_percentiles() {
        let mut hist = Histogram::for_latency_ms();
        for i in 1..=100 {
            hist.record(i as f64);
        }

        assert_eq!(hist.count(), 100);
        // P50 should be around 50ms bucket
        let p50 = hist.p50();
        assert!((50.0..=100.0).contains(&p50));

        // P95 should be in a higher bucket
        let p95 = hist.p95();
        assert!(p95 >= 95.0);

        // P99 should be even higher
        let p99 = hist.p99();
        assert!(p99 >= 99.0);
    }

    #[test]
    fn test_histogram_bandwidth() {
        let mut hist = Histogram::for_bandwidth_mbps();
        hist.record(0.5);
        hist.record(5.0);
        hist.record(50.0);

        assert_eq!(hist.count(), 3);
        assert_eq!(hist.mean(), 18.5);
    }

    #[test]
    fn test_histogram_buckets_info() {
        let mut hist = Histogram::new(vec![10.0, 20.0, 30.0]);
        hist.record(5.0);
        hist.record(15.0);
        hist.record(25.0);

        let buckets = hist.buckets_info();
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0], (10.0, 1, 1)); // One value <= 10
        assert_eq!(buckets[1], (20.0, 1, 2)); // One value <= 20
        assert_eq!(buckets[2], (30.0, 1, 3)); // One value <= 30
    }
}
