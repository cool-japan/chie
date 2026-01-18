//! Time window utilities for rate limiting, metrics collection, and sliding window analytics.

use std::collections::VecDeque;

/// Time window for tracking events within a specific time period.
///
/// # Examples
///
/// ```
/// use chie_shared::TimeWindow;
///
/// let mut window = TimeWindow::new(1000, 100); // 1 second window, max 100 events
///
/// // Track events at different timestamps
/// window.add_event(1000);
/// window.add_event(1100);
/// window.add_event(1200);
///
/// // Count events within the window
/// assert_eq!(window.count_events(1500), 3);
///
/// // Events older than window size are cleaned up
/// assert_eq!(window.count_events(2500), 0);
///
/// // Check rate limiting
/// let mut limiter = TimeWindow::new(1000, 5);
/// for i in 0..5 {
///     limiter.add_event(1000 + i * 10);
/// }
/// assert!(limiter.would_exceed_limit(1050, 5));
/// ```
#[derive(Debug, Clone)]
pub struct TimeWindow {
    /// Window size in milliseconds.
    window_size_ms: u64,
    /// Events with their timestamps.
    events: VecDeque<i64>,
    /// Maximum events to track (prevents unbounded memory growth).
    max_events: usize,
}

impl TimeWindow {
    /// Create a new time window.
    ///
    /// # Arguments
    /// * `window_size_ms` - Window size in milliseconds
    /// * `max_events` - Maximum number of events to track
    pub fn new(window_size_ms: u64, max_events: usize) -> Self {
        Self {
            window_size_ms,
            events: VecDeque::with_capacity(max_events.min(1000)),
            max_events,
        }
    }

    /// Add an event at the current time.
    pub fn add_event(&mut self, timestamp_ms: i64) {
        self.cleanup_old_events(timestamp_ms);

        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }

        self.events.push_back(timestamp_ms);
    }

    /// Get the count of events within the window from the given timestamp.
    pub fn count_events(&mut self, now_ms: i64) -> usize {
        self.cleanup_old_events(now_ms);
        self.events.len()
    }

    /// Check if adding a new event would exceed the given limit.
    pub fn would_exceed_limit(&mut self, now_ms: i64, limit: usize) -> bool {
        self.cleanup_old_events(now_ms);
        self.events.len() >= limit
    }

    /// Get events per second rate.
    pub fn events_per_second(&mut self, now_ms: i64) -> f64 {
        let count = self.count_events(now_ms);
        let window_secs = self.window_size_ms as f64 / 1000.0;
        count as f64 / window_secs
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Remove events older than the window.
    fn cleanup_old_events(&mut self, now_ms: i64) {
        let cutoff = now_ms - self.window_size_ms as i64;
        while let Some(&event_time) = self.events.front() {
            if event_time < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the age of the oldest event in milliseconds.
    pub fn oldest_event_age_ms(&self, now_ms: i64) -> Option<u64> {
        self.events.front().map(|&ts| (now_ms - ts) as u64)
    }

    /// Check if the window is full.
    pub fn is_full(&self) -> bool {
        self.events.len() >= self.max_events
    }
}

/// Fixed-size time bucket for aggregating metrics over time periods.
#[derive(Debug, Clone)]
pub struct TimeBucket {
    /// Bucket start time (inclusive).
    pub start_ms: i64,
    /// Bucket end time (exclusive).
    pub end_ms: i64,
    /// Sum of values in this bucket.
    pub sum: f64,
    /// Count of values in this bucket.
    pub count: u64,
    /// Minimum value in this bucket.
    pub min: f64,
    /// Maximum value in this bucket.
    pub max: f64,
}

impl TimeBucket {
    /// Create a new time bucket.
    pub fn new(start_ms: i64, end_ms: i64) -> Self {
        Self {
            start_ms,
            end_ms,
            sum: 0.0,
            count: 0,
            min: f64::MAX,
            max: f64::MIN,
        }
    }

    /// Add a value to the bucket.
    pub fn add_value(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    /// Get the average value.
    pub fn average(&self) -> Option<f64> {
        if self.count > 0 {
            Some(self.sum / self.count as f64)
        } else {
            None
        }
    }

    /// Check if a timestamp falls within this bucket.
    pub fn contains(&self, timestamp_ms: i64) -> bool {
        timestamp_ms >= self.start_ms && timestamp_ms < self.end_ms
    }

    /// Get the bucket duration in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        (self.end_ms - self.start_ms) as u64
    }
}

/// Bucketed time series for aggregating metrics into fixed time intervals.
#[derive(Debug, Clone)]
pub struct BucketedTimeSeries {
    /// Duration of each bucket in milliseconds.
    bucket_size_ms: u64,
    /// Maximum number of buckets to retain.
    max_buckets: usize,
    /// The buckets, ordered from oldest to newest.
    buckets: VecDeque<TimeBucket>,
}

impl BucketedTimeSeries {
    /// Create a new bucketed time series.
    ///
    /// # Arguments
    /// * `bucket_size_ms` - Size of each bucket in milliseconds
    /// * `max_buckets` - Maximum number of buckets to retain
    pub fn new(bucket_size_ms: u64, max_buckets: usize) -> Self {
        Self {
            bucket_size_ms,
            max_buckets,
            buckets: VecDeque::with_capacity(max_buckets.min(1000)),
        }
    }

    /// Add a value at the given timestamp.
    pub fn add_value(&mut self, timestamp_ms: i64, value: f64) {
        let bucket_start = (timestamp_ms / self.bucket_size_ms as i64) * self.bucket_size_ms as i64;
        let bucket_end = bucket_start + self.bucket_size_ms as i64;

        // Find or create the appropriate bucket
        if let Some(bucket) = self.buckets.iter_mut().find(|b| b.start_ms == bucket_start) {
            bucket.add_value(value);
        } else {
            // Create new bucket
            let mut new_bucket = TimeBucket::new(bucket_start, bucket_end);
            new_bucket.add_value(value);

            // Insert in chronological order
            let insert_pos = self
                .buckets
                .iter()
                .position(|b| b.start_ms > bucket_start)
                .unwrap_or(self.buckets.len());
            self.buckets.insert(insert_pos, new_bucket);

            // Remove oldest buckets if we exceed max_buckets
            while self.buckets.len() > self.max_buckets {
                self.buckets.pop_front();
            }
        }
    }

    /// Get all buckets.
    pub fn buckets(&self) -> &VecDeque<TimeBucket> {
        &self.buckets
    }

    /// Get buckets within a time range.
    pub fn buckets_in_range(&self, start_ms: i64, end_ms: i64) -> Vec<&TimeBucket> {
        self.buckets
            .iter()
            .filter(|b| b.end_ms > start_ms && b.start_ms < end_ms)
            .collect()
    }

    /// Calculate aggregate statistics across all buckets.
    pub fn aggregate_stats(&self) -> Option<(f64, f64, f64, u64)> {
        if self.buckets.is_empty() {
            return None;
        }

        let total_sum: f64 = self.buckets.iter().map(|b| b.sum).sum();
        let total_count: u64 = self.buckets.iter().map(|b| b.count).sum();
        let min = self.buckets.iter().map(|b| b.min).fold(f64::MAX, f64::min);
        let max = self.buckets.iter().map(|b| b.max).fold(f64::MIN, f64::max);

        Some((total_sum / total_count as f64, min, max, total_count))
    }

    /// Clear all buckets.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

/// Rate limiter using sliding window algorithm.
///
/// # Examples
///
/// ```
/// use chie_shared::SlidingWindowRateLimiter;
///
/// // Allow 10 requests per second
/// let mut limiter = SlidingWindowRateLimiter::new(1000, 10);
///
/// // First 10 requests should be allowed
/// for i in 0..10 {
///     assert!(limiter.try_acquire(1000 + i));
/// }
///
/// // 11th request should be denied
/// assert!(!limiter.try_acquire(1010));
///
/// // After window passes, new requests allowed
/// assert!(limiter.try_acquire(2100));
///
/// // Check remaining capacity
/// let mut limiter2 = SlidingWindowRateLimiter::new(1000, 5);
/// limiter2.try_acquire(1000);
/// limiter2.try_acquire(1001);
/// assert_eq!(limiter2.remaining_capacity(1002), 3);
/// ```
#[derive(Debug, Clone)]
pub struct SlidingWindowRateLimiter {
    /// Time window for rate limiting.
    window: TimeWindow,
    /// Maximum requests allowed in the window.
    max_requests: usize,
}

impl SlidingWindowRateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Arguments
    /// * `window_ms` - Window size in milliseconds
    /// * `max_requests` - Maximum requests allowed in the window
    pub fn new(window_ms: u64, max_requests: usize) -> Self {
        Self {
            window: TimeWindow::new(window_ms, max_requests * 2), // Extra capacity for safety
            max_requests,
        }
    }

    /// Check if a request is allowed at the given time.
    pub fn is_allowed(&mut self, now_ms: i64) -> bool {
        !self.window.would_exceed_limit(now_ms, self.max_requests)
    }

    /// Try to consume a token (record a request).
    /// Returns true if the request is allowed, false if rate limit is exceeded.
    pub fn try_acquire(&mut self, now_ms: i64) -> bool {
        if self.is_allowed(now_ms) {
            self.window.add_event(now_ms);
            true
        } else {
            false
        }
    }

    /// Get the current request count in the window.
    pub fn current_count(&mut self, now_ms: i64) -> usize {
        self.window.count_events(now_ms)
    }

    /// Get remaining capacity.
    pub fn remaining_capacity(&mut self, now_ms: i64) -> usize {
        let current = self.current_count(now_ms);
        self.max_requests.saturating_sub(current)
    }

    /// Reset the rate limiter.
    pub fn reset(&mut self) {
        self.window.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_window_basic() {
        let mut window = TimeWindow::new(1000, 100); // 1 second window
        let now = 1000;

        window.add_event(now);
        window.add_event(now + 100);
        window.add_event(now + 200);

        // All events within 1000ms window
        assert_eq!(window.count_events(now + 500), 3);

        // Sliding window keeps events from the last 1000ms
        assert_eq!(window.count_events(now + 1000), 3); // All still within window
        assert_eq!(window.count_events(now + 1100), 2); // Event at 1000 expired
        assert_eq!(window.count_events(now + 1200), 1); // Events at 1000, 1100 expired
        assert_eq!(window.count_events(now + 1300), 0); // All events expired (all > 1000ms old)
    }

    #[test]
    fn test_time_window_would_exceed_limit() {
        let mut window = TimeWindow::new(1000, 10);
        let now = 1000;

        for i in 0..5 {
            window.add_event(now + i * 100);
        }

        assert!(!window.would_exceed_limit(now + 500, 10));
        assert!(window.would_exceed_limit(now + 500, 3));
    }

    #[test]
    fn test_time_window_events_per_second() {
        let mut window = TimeWindow::new(1000, 100);
        let now = 1000;

        for i in 0..10 {
            window.add_event(now + i * 50);
        }

        let rate = window.events_per_second(now + 500);
        assert!((9.0..=11.0).contains(&rate)); // ~10 events per second
    }

    #[test]
    fn test_time_window_max_events() {
        let mut window = TimeWindow::new(10000, 5); // Small max_events
        let now = 1000;

        for i in 0..10 {
            window.add_event(now + i);
        }

        // Should only keep 5 most recent events
        assert_eq!(window.count_events(now + 20), 5);
    }

    #[test]
    fn test_time_bucket_basic() {
        let mut bucket = TimeBucket::new(0, 1000);

        bucket.add_value(10.0);
        bucket.add_value(20.0);
        bucket.add_value(30.0);

        assert_eq!(bucket.count, 3);
        assert_eq!(bucket.sum, 60.0);
        assert_eq!(bucket.average(), Some(20.0));
        assert_eq!(bucket.min, 10.0);
        assert_eq!(bucket.max, 30.0);
    }

    #[test]
    fn test_time_bucket_contains() {
        let bucket = TimeBucket::new(1000, 2000);

        assert!(!bucket.contains(999));
        assert!(bucket.contains(1000));
        assert!(bucket.contains(1500));
        assert!(!bucket.contains(2000));
    }

    #[test]
    fn test_bucketed_time_series() {
        let mut series = BucketedTimeSeries::new(1000, 10); // 1 second buckets

        series.add_value(1000, 10.0);
        series.add_value(1500, 20.0);
        series.add_value(2000, 30.0);
        series.add_value(2500, 40.0);

        assert_eq!(series.buckets().len(), 2); // Two buckets: [1000-2000), [2000-3000)

        if let Some((avg, min, max, count)) = series.aggregate_stats() {
            assert_eq!(count, 4);
            assert_eq!(min, 10.0);
            assert_eq!(max, 40.0);
            assert_eq!(avg, 25.0);
        } else {
            panic!("Expected aggregate stats");
        }
    }

    #[test]
    fn test_bucketed_time_series_max_buckets() {
        let mut series = BucketedTimeSeries::new(1000, 3); // Max 3 buckets

        for i in 0..5 {
            series.add_value((i * 1000) as i64, i as f64);
        }

        // Should only keep 3 most recent buckets
        assert_eq!(series.buckets().len(), 3);
    }

    #[test]
    fn test_sliding_window_rate_limiter() {
        let mut limiter = SlidingWindowRateLimiter::new(1000, 5); // 5 requests per second
        let now = 1000;

        // First 5 requests should succeed
        for i in 0..5 {
            assert!(limiter.try_acquire(now + i * 10));
        }

        // 6th request should fail
        assert!(!limiter.try_acquire(now + 50));

        // After window expires, should succeed again
        assert!(limiter.try_acquire(now + 1100));
    }

    #[test]
    fn test_rate_limiter_remaining_capacity() {
        let mut limiter = SlidingWindowRateLimiter::new(1000, 10);
        let now = 1000;

        assert_eq!(limiter.remaining_capacity(now), 10);

        limiter.try_acquire(now);
        limiter.try_acquire(now + 10);
        limiter.try_acquire(now + 20);

        assert_eq!(limiter.remaining_capacity(now + 30), 7);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let mut limiter = SlidingWindowRateLimiter::new(1000, 5);
        let now = 1000;

        for i in 0..5 {
            limiter.try_acquire(now + i);
        }

        assert_eq!(limiter.current_count(now + 10), 5);

        limiter.reset();
        assert_eq!(limiter.current_count(now + 10), 0);
    }
}
