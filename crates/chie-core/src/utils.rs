//! Utility functions for CHIE Protocol operations.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Convert bytes to human-readable format (KB, MB, GB, TB).
#[inline]
pub fn bytes_to_human_readable(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let base = 1024_f64;
    let exponent = (bytes as f64).log(base).floor() as usize;
    let exponent = exponent.min(UNITS.len() - 1);

    let value = bytes as f64 / base.powi(exponent as i32);

    format!("{:.2} {}", value, UNITS[exponent])
}

/// Convert KB to bytes (compile-time constant).
#[inline]
pub const fn kb_to_bytes(kb: u64) -> u64 {
    kb * 1024
}

/// Convert MB to bytes (compile-time constant).
#[inline]
pub const fn mb_to_bytes(mb: u64) -> u64 {
    mb * 1024 * 1024
}

/// Convert GB to bytes (compile-time constant).
#[inline]
pub const fn gb_to_bytes(gb: u64) -> u64 {
    gb * 1024 * 1024 * 1024
}

/// Convert TB to bytes (compile-time constant).
#[inline]
pub const fn tb_to_bytes(tb: u64) -> u64 {
    tb * 1024 * 1024 * 1024 * 1024
}

/// Convert bytes to KB (compile-time constant).
#[inline]
pub const fn bytes_to_kb(bytes: u64) -> u64 {
    bytes / 1024
}

/// Convert bytes to MB (compile-time constant).
#[inline]
pub const fn bytes_to_mb(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

/// Convert bytes to GB (compile-time constant).
#[inline]
pub const fn bytes_to_gb(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024)
}

/// Calculate bandwidth in Mbps from bytes and duration.
#[inline]
pub fn calculate_bandwidth_mbps(bytes: u64, duration: Duration) -> f64 {
    if duration.is_zero() {
        return 0.0;
    }

    let bits = bytes as f64 * 8.0;
    let seconds = duration.as_secs_f64();

    bits / seconds / 1_000_000.0
}

/// Calculate bandwidth in Gbps from bytes and duration.
#[inline]
pub fn calculate_bandwidth_gbps(bytes: u64, duration: Duration) -> f64 {
    calculate_bandwidth_mbps(bytes, duration) / 1000.0
}

/// Convert Mbps to bytes per second.
#[inline]
pub const fn mbps_to_bytes_per_sec(mbps: u64) -> u64 {
    mbps * 1_000_000 / 8
}

/// Convert bytes per second to Mbps (approximate).
#[inline]
pub const fn bytes_per_sec_to_mbps(bps: u64) -> u64 {
    bps * 8 / 1_000_000
}

/// Calculate percentage with two decimal places.
#[inline]
pub fn calculate_percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }

    (part as f64 / total as f64) * 100.0
}

/// Get current Unix timestamp in milliseconds.
#[inline]
pub fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64
}

/// Calculate estimated time remaining based on progress.
pub fn estimate_time_remaining(processed: u64, total: u64, elapsed: Duration) -> Option<Duration> {
    if processed == 0 || total == 0 || processed >= total {
        return None;
    }

    let rate = processed as f64 / elapsed.as_secs_f64();
    let remaining = total - processed;
    let seconds_remaining = remaining as f64 / rate;

    Some(Duration::from_secs_f64(seconds_remaining))
}

/// Format duration as human-readable string (e.g., "2h 15m 30s").
#[inline]
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    let mut parts = Vec::new();

    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 || hours > 0 {
        parts.push(format!("{}m", minutes));
    }
    parts.push(format!("{}s", seconds));

    parts.join(" ")
}

/// Convert seconds to Duration (compile-time constant).
#[inline]
pub const fn secs_to_duration(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

/// Convert milliseconds to Duration (compile-time constant).
#[inline]
pub const fn millis_to_duration(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// Convert minutes to Duration (compile-time constant).
#[inline]
pub const fn minutes_to_duration(minutes: u64) -> Duration {
    Duration::from_secs(minutes * 60)
}

/// Convert hours to Duration (compile-time constant).
#[inline]
pub const fn hours_to_duration(hours: u64) -> Duration {
    Duration::from_secs(hours * 3600)
}

/// Convert days to Duration (compile-time constant).
#[inline]
pub const fn days_to_duration(days: u64) -> Duration {
    Duration::from_secs(days * 86400)
}

/// Validate peer ID format (basic validation).
#[inline]
pub fn is_valid_peer_id(peer_id: &str) -> bool {
    !peer_id.is_empty() && peer_id.len() <= 256 && peer_id.is_ascii()
}

/// Calculate chunk size with padding for encryption overhead.
#[inline]
pub const fn chunk_size_with_overhead(data_size: usize) -> usize {
    // ChaCha20-Poly1305 adds 16 bytes MAC tag
    const ENCRYPTION_OVERHEAD: usize = 16;
    data_size + ENCRYPTION_OVERHEAD
}

/// Ceiling division (divide and round up) - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::div_ceil;
/// assert_eq!(div_ceil(10, 3), 4);
/// assert_eq!(div_ceil(9, 3), 3);
/// ```
#[inline]
pub const fn div_ceil(dividend: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    dividend.div_ceil(divisor)
}

/// Check if a number is a power of 2 - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::is_power_of_two;
/// assert!(is_power_of_two(8));
/// assert!(!is_power_of_two(7));
/// ```
#[inline]
pub const fn is_power_of_two(n: u64) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Align value up to the next multiple of alignment - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::align_up;
/// assert_eq!(align_up(10, 8), 16);
/// assert_eq!(align_up(16, 8), 16);
/// ```
#[inline]
pub const fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
    }
}

/// Align value down to the previous multiple of alignment - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::align_down;
/// assert_eq!(align_down(10, 8), 8);
/// assert_eq!(align_down(16, 8), 16);
/// ```
#[inline]
pub const fn align_down(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value - (value % alignment)
}

/// Return the minimum of two values - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::min_const;
/// assert_eq!(min_const(5, 10), 5);
/// ```
#[inline]
pub const fn min_const(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

/// Return the maximum of two values - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::max_const;
/// assert_eq!(max_const(5, 10), 10);
/// ```
#[inline]
pub const fn max_const(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// Clamp value to a range [min, max] - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::clamp_const;
/// assert_eq!(clamp_const(5, 0, 10), 5);
/// assert_eq!(clamp_const(15, 0, 10), 10);
/// assert_eq!(clamp_const(0, 5, 10), 5);
/// ```
#[inline]
pub const fn clamp_const(value: u64, min: u64, max: u64) -> u64 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Saturating addition (returns u64::MAX on overflow) - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::saturating_add_const;
/// assert_eq!(saturating_add_const(5, 10), 15);
/// assert_eq!(saturating_add_const(u64::MAX, 1), u64::MAX);
/// ```
#[inline]
pub const fn saturating_add_const(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Saturating subtraction (returns 0 on underflow) - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::saturating_sub_const;
/// assert_eq!(saturating_sub_const(10, 5), 5);
/// assert_eq!(saturating_sub_const(5, 10), 0);
/// ```
#[inline]
pub const fn saturating_sub_const(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

/// Saturating multiplication (returns u64::MAX on overflow) - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::saturating_mul_const;
/// assert_eq!(saturating_mul_const(5, 10), 50);
/// assert_eq!(saturating_mul_const(u64::MAX, 2), u64::MAX);
/// ```
#[inline]
pub const fn saturating_mul_const(a: u64, b: u64) -> u64 {
    a.saturating_mul(b)
}

/// Calculate percentage as integer (0-100) - compile-time constant.
///
/// # Examples
/// ```
/// use chie_core::utils::percentage_const;
/// assert_eq!(percentage_const(50, 100), 50);
/// assert_eq!(percentage_const(1, 3), 33);
/// assert_eq!(percentage_const(10, 0), 0);
/// ```
#[inline]
pub const fn percentage_const(part: u64, total: u64) -> u64 {
    if total == 0 { 0 } else { (part * 100) / total }
}

/// Truncate string to maximum length with ellipsis.
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Calculate exponential backoff delay with optional jitter.
///
/// # Arguments
/// * `attempt` - The retry attempt number (0-indexed)
/// * `base_delay_ms` - The base delay in milliseconds
/// * `max_delay_ms` - The maximum delay in milliseconds
/// * `jitter` - Whether to add random jitter (0-100% of calculated delay)
///
/// # Returns
/// The delay duration to wait before the next retry
pub fn exponential_backoff(
    attempt: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: bool,
) -> Duration {
    let exp_delay = base_delay_ms.saturating_mul(2_u64.saturating_pow(attempt));
    let delay = exp_delay.min(max_delay_ms);

    if jitter {
        // Add random jitter between 0-100% of the calculated delay
        use rand::Rng;
        let jitter_range = delay;
        let jitter_amount = rand::thread_rng().gen_range(0..=jitter_range);
        Duration::from_millis(jitter_amount)
    } else {
        Duration::from_millis(delay)
    }
}

/// Configuration for retry logic.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Base delay in milliseconds
    pub base_delay_ms: u64,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
    /// Whether to add jitter to backoff delays
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 100,
            max_delay_ms: 30_000,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    #[must_use]
    pub fn new(max_attempts: u32, base_delay_ms: u64, max_delay_ms: u64, jitter: bool) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms,
            jitter,
        }
    }

    /// Create a builder for retry configuration.
    #[must_use]
    pub fn builder() -> RetryConfigBuilder {
        RetryConfigBuilder::default()
    }

    /// Calculate the delay for a given attempt.
    #[inline]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        exponential_backoff(attempt, self.base_delay_ms, self.max_delay_ms, self.jitter)
    }

    /// Create a configuration for aggressive retries (more attempts, shorter delays).
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 5,
            base_delay_ms: 50,
            max_delay_ms: 5_000,
            jitter: true,
        }
    }

    /// Create a configuration for conservative retries (fewer attempts, longer delays).
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            max_attempts: 2,
            base_delay_ms: 500,
            max_delay_ms: 60_000,
            jitter: true,
        }
    }

    /// Create a configuration with no retries.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_attempts: 0,
            base_delay_ms: 0,
            max_delay_ms: 0,
            jitter: false,
        }
    }
}

/// Builder for RetryConfig.
#[derive(Debug, Clone)]
pub struct RetryConfigBuilder {
    max_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter: bool,
}

impl Default for RetryConfigBuilder {
    fn default() -> Self {
        let default_config = RetryConfig::default();
        Self {
            max_attempts: default_config.max_attempts,
            base_delay_ms: default_config.base_delay_ms,
            max_delay_ms: default_config.max_delay_ms,
            jitter: default_config.jitter,
        }
    }
}

impl RetryConfigBuilder {
    /// Set the maximum number of retry attempts.
    #[must_use]
    pub fn max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Set the base delay in milliseconds.
    #[must_use]
    pub fn base_delay_ms(mut self, base_delay_ms: u64) -> Self {
        self.base_delay_ms = base_delay_ms;
        self
    }

    /// Set the maximum delay in milliseconds.
    #[must_use]
    pub fn max_delay_ms(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Set whether to use jitter.
    #[must_use]
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Build the RetryConfig.
    #[must_use]
    pub fn build(self) -> RetryConfig {
        RetryConfig {
            max_attempts: self.max_attempts,
            base_delay_ms: self.base_delay_ms,
            max_delay_ms: self.max_delay_ms,
            jitter: self.jitter,
        }
    }
}

/// A simple LRU (Least Recently Used) cache.
///
/// This cache stores a fixed number of items and evicts the least recently
/// used item when the capacity is reached.
///
/// # Example
///
/// ```
/// use chie_core::utils::LruCache;
///
/// let mut cache = LruCache::new(2);
/// cache.put("key1", "value1");
/// cache.put("key2", "value2");
///
/// assert_eq!(cache.get(&"key1"), Some(&"value1"));
///
/// // This will evict "key2" since it was least recently used
/// cache.put("key3", "value3");
/// assert_eq!(cache.get(&"key2"), None);
/// ```
#[derive(Debug)]
pub struct LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    capacity: usize,
    map: HashMap<K, V>,
    order: Vec<K>,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Create a new LRU cache with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Get a value from the cache.
    ///
    /// If the key exists, it's marked as recently used.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            // Move to end (most recently used)
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                let k = self.order.remove(pos);
                self.order.push(k);
            }
            self.map.get(key)
        } else {
            None
        }
    }

    /// Put a value into the cache.
    ///
    /// If the cache is at capacity, the least recently used item is evicted.
    pub fn put(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            // Update existing key
            self.map.insert(key.clone(), value);
            // Move to end (most recently used)
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
                self.order.push(key);
            }
        } else {
            // New key
            if self.map.len() >= self.capacity {
                // Evict least recently used
                if let Some(lru_key) = self.order.first().cloned() {
                    self.map.remove(&lru_key);
                    self.order.remove(0);
                }
            }
            self.map.insert(key.clone(), value);
            self.order.push(key);
        }
    }

    /// Remove a value from the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(value) = self.map.remove(key) {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
            Some(value)
        } else {
            None
        }
    }

    /// Get the number of items in the cache.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the cache is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clear all items from the cache.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// Get the capacity of the cache.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Peek at a value without marking it as recently used.
    #[inline]
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Get an iterator over the cache entries.
    ///
    /// Note: This does not update access order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }
}

/// Async utility functions.
pub mod async_utils {
    use super::*;

    /// Timeout wrapper for async operations.
    ///
    /// Returns Ok(result) if the future completes within the timeout,
    /// or Err(()) if it times out.
    pub async fn timeout<F, T>(duration: Duration, future: F) -> Result<T, ()>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(duration, future).await.map_err(|_| ())
    }

    /// Retry an async operation with exponential backoff.
    ///
    /// # Arguments
    /// * `config` - Retry configuration
    /// * `operation` - Async function to retry
    ///
    /// # Returns
    /// The result of the operation, or the last error if all retries failed
    pub async fn retry_async<F, Fut, T, E>(config: &RetryConfig, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut last_error = None;

        for attempt in 0..=config.max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);

                    if attempt < config.max_attempts {
                        let delay = config.delay_for_attempt(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Sleep for a specified duration (async).
    #[inline]
    pub async fn sleep(duration: Duration) {
        tokio::time::sleep(duration).await
    }

    /// Sleep for a specified number of milliseconds (async).
    #[inline]
    pub async fn sleep_ms(millis: u64) {
        tokio::time::sleep(Duration::from_millis(millis)).await
    }

    /// Sleep for a specified number of seconds (async).
    #[inline]
    pub async fn sleep_secs(secs: u64) {
        tokio::time::sleep(Duration::from_secs(secs)).await
    }

    /// Debounce: Delays execution until no calls have been made for the specified duration.
    pub struct Debouncer {
        duration: Duration,
        last_call: std::sync::Arc<tokio::sync::Mutex<Option<tokio::time::Instant>>>,
    }

    impl Debouncer {
        /// Create a new debouncer with the specified duration.
        pub fn new(duration: Duration) -> Self {
            Self {
                duration,
                last_call: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            }
        }

        /// Execute the debounced operation.
        pub async fn execute<F, Fut, T>(&self, operation: F) -> Option<T>
        where
            F: FnOnce() -> Fut,
            Fut: Future<Output = T>,
        {
            {
                let mut last = self.last_call.lock().await;
                *last = Some(tokio::time::Instant::now());
            }

            tokio::time::sleep(self.duration).await;

            let last = self.last_call.lock().await;
            if let Some(last_time) = *last {
                if last_time.elapsed() >= self.duration {
                    drop(last);
                    Some(operation().await)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

// ===== Result Type Aliases (Session 30) =====

/// Shorthand for validation results.
pub type ValidationResult<T = ()> = Result<T, String>;

/// Shorthand for storage operation results.
pub type StorageResult<T> = Result<T, crate::storage::StorageError>;

// ===== Additional Const Fn Helpers (Session 30) =====

/// Calculate kilobytes from megabytes (compile-time constant).
#[inline]
#[must_use]
pub const fn mb_to_kb(mb: u64) -> u64 {
    mb * 1024
}

/// Calculate megabytes from gigabytes (compile-time constant).
#[inline]
#[must_use]
pub const fn gb_to_mb(gb: u64) -> u64 {
    gb * 1024
}

/// Calculate gigabytes from terabytes (compile-time constant).
#[inline]
#[must_use]
pub const fn tb_to_gb(tb: u64) -> u64 {
    tb * 1024
}

/// Round up to nearest multiple (compile-time constant).
///
/// Useful for aligning sizes to chunk boundaries.
#[inline]
#[must_use]
pub const fn round_up_to_multiple(value: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return value;
    }
    let remainder = value % multiple;
    if remainder == 0 {
        value
    } else {
        value + (multiple - remainder)
    }
}

/// Round down to nearest multiple (compile-time constant).
#[inline]
#[must_use]
pub const fn round_down_to_multiple(value: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return value;
    }
    value - (value % multiple)
}

/// Calculate percentage as integer (0-100) with rounding.
#[inline]
#[must_use]
pub const fn calculate_percentage_rounded(part: u64, total: u64) -> u8 {
    if total == 0 {
        return 0;
    }
    let result = (part * 100 + total / 2) / total; // Add half for rounding
    if result > 100 { 100 } else { result as u8 }
}

/// Check if value is within range (inclusive).
#[inline]
#[must_use]
pub const fn is_in_range(value: u64, min: u64, max: u64) -> bool {
    value >= min && value <= max
}

/// Calculate average of two u64 values without overflow.
#[inline]
#[must_use]
pub const fn average_u64(a: u64, b: u64) -> u64 {
    // Avoids overflow by using (a/2 + b/2) + (a%2 + b%2)/2
    (a / 2) + (b / 2) + ((a % 2) + (b % 2)) / 2
}

/// Get the larger of two u64 values (same as max_const but more descriptive name).
#[inline]
#[must_use]
pub const fn larger_of(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// Get the smaller of two u64 values (same as min_const but more descriptive name).
#[inline]
#[must_use]
pub const fn smaller_of(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

// ===== String Utilities (Session 30) =====

/// Check if string is valid ASCII identifier (alphanumeric + underscore + hyphen).
#[inline]
#[must_use]
pub fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Truncate string to max length and add ellipsis if needed.
#[inline]
#[must_use]
pub fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        let mut result: String = s.chars().take(max_len - 3).collect();
        result.push_str("...");
        result
    }
}

/// Safe string slice that doesn't panic on invalid indices.
#[inline]
#[must_use]
pub fn safe_slice(s: &str, start: usize, end: usize) -> &str {
    let len = s.len();
    let start = start.min(len);
    let end = end.min(len).max(start);
    &s[start..end]
}

// ===== Number Formatting Utilities (Session 30) =====

/// Format number with thousands separators.
#[must_use]
pub fn format_number_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);

    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }

    result.chars().rev().collect()
}

/// Format duration as compact string (e.g., "2h15m", "45s").
#[must_use]
pub fn format_duration_compact(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        if minutes > 0 {
            format!("{}h{}m", hours, minutes)
        } else {
            format!("{}h", hours)
        }
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        if seconds > 0 {
            format!("{}m{}s", minutes, seconds)
        } else {
            format!("{}m", minutes)
        }
    } else {
        format!("{}s", total_secs)
    }
}

// ===== Enhanced Utility Functions (Session 29) =====

/// Convert bytes to KB as floating point (compile-time constant).
#[inline]
#[must_use]
pub const fn bytes_to_kb_f64(bytes: u64) -> f64 {
    bytes as f64 / 1024.0
}

/// Convert bytes to MB as floating point (compile-time constant).
#[inline]
#[must_use]
pub const fn bytes_to_mb_f64(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Convert bytes to GB as floating point (compile-time constant).
#[inline]
#[must_use]
pub const fn bytes_to_gb_f64(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

/// Convert bytes to TB as floating point (compile-time constant).
#[inline]
#[must_use]
pub const fn bytes_to_tb_f64(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
}

/// Normalize CID by removing invalid characters.
///
/// This ensures CIDs are safe for filesystem operations and consistent.
#[inline]
#[must_use]
pub fn normalize_cid(cid: &str) -> String {
    cid.trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Convert CID to path-safe format.
///
/// Returns a PathBuf suitable for filesystem usage.
#[inline]
#[must_use]
pub fn cid_to_path_safe(cid: &str) -> std::path::PathBuf {
    use std::path::PathBuf;
    PathBuf::from(normalize_cid(cid))
}

/// Check if CID format is valid (enhanced validation).
///
/// Validates IPFS CID format (both v0 and v1).
#[inline]
#[must_use]
pub fn is_valid_cid_format(cid: &str) -> bool {
    if cid.is_empty() || cid.len() < 10 {
        return false;
    }

    // CIDv0: base58btc encoded, starts with "Qm", 46 characters
    if cid.starts_with("Qm") && cid.len() == 46 {
        return cid.chars().all(|c| c.is_alphanumeric());
    }

    // CIDv1: multibase encoded, starts with b, z, f, etc.
    if cid.len() > 10 && (cid.starts_with('b') || cid.starts_with('z') || cid.starts_with('f')) {
        return cid.chars().all(|c| c.is_alphanumeric());
    }

    false
}

/// Validate peer ID format and return Result.
///
/// Returns Ok(()) if peer ID is valid, Err with description otherwise.
#[inline]
pub fn validate_peer_id(peer_id: &str) -> Result<(), String> {
    if peer_id.is_empty() {
        return Err("Peer ID cannot be empty".to_string());
    }

    if peer_id.len() > 256 {
        return Err(format!("Peer ID too long: {} > 256", peer_id.len()));
    }

    if !peer_id.is_ascii() {
        return Err("Peer ID must be ASCII".to_string());
    }

    Ok(())
}

/// Calculate hash of peer ID for consistent hashing.
///
/// Uses a simple FNV-1a hash for performance.
#[inline]
#[must_use]
pub fn peer_id_hash(peer_id: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in peer_id.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Convert Unix timestamp (milliseconds) to Duration since UNIX_EPOCH.
#[inline]
#[must_use]
pub const fn timestamp_to_duration(timestamp_ms: i64) -> Duration {
    if timestamp_ms < 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(timestamp_ms as u64)
    }
}

/// Calculate age of a timestamp in milliseconds.
///
/// Returns Duration representing how long ago the timestamp was.
#[inline]
#[must_use]
pub fn timestamp_age(timestamp_ms: i64) -> Duration {
    let now_ms = current_timestamp_ms();
    let age_ms = now_ms.saturating_sub(timestamp_ms);

    if age_ms < 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(age_ms as u64)
    }
}

/// Check if timestamp is recent (within max_age_ms).
///
/// Returns true if the timestamp is within the specified age.
#[inline]
#[must_use]
pub fn is_timestamp_recent(timestamp_ms: i64, max_age_ms: u64) -> bool {
    let age = timestamp_age(timestamp_ms);
    age.as_millis() <= max_age_ms as u128
}

/// Convert timestamp to SystemTime.
#[inline]
#[must_use]
pub fn timestamp_to_systemtime(timestamp_ms: i64) -> SystemTime {
    if timestamp_ms < 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_millis(timestamp_ms as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_human_readable() {
        assert_eq!(bytes_to_human_readable(0), "0 B");
        assert_eq!(bytes_to_human_readable(512), "512.00 B");
        assert_eq!(bytes_to_human_readable(1024), "1.00 KB");
        assert_eq!(bytes_to_human_readable(1536), "1.50 KB");
        assert_eq!(bytes_to_human_readable(1024 * 1024), "1.00 MB");
        assert_eq!(bytes_to_human_readable(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(
            bytes_to_human_readable(1024 * 1024 * 1024 * 1024),
            "1.00 TB"
        );
    }

    #[test]
    fn test_calculate_bandwidth_mbps() {
        // 1 MB in 1 second = 8 Mbps
        let bytes = 1024 * 1024;
        let duration = Duration::from_secs(1);
        let bandwidth = calculate_bandwidth_mbps(bytes, duration);
        assert!((bandwidth - 8.388_608).abs() < 0.001);

        // Zero duration
        assert_eq!(calculate_bandwidth_mbps(1024, Duration::ZERO), 0.0);
    }

    #[test]
    fn test_calculate_percentage() {
        assert_eq!(calculate_percentage(50, 100), 50.0);
        assert_eq!(calculate_percentage(25, 100), 25.0);
        assert_eq!(calculate_percentage(100, 100), 100.0);
        assert_eq!(calculate_percentage(0, 100), 0.0);
        assert_eq!(calculate_percentage(50, 0), 0.0);
    }

    #[test]
    fn test_current_timestamp_ms() {
        let ts = current_timestamp_ms();
        assert!(ts > 0);
        assert!(ts > 1_600_000_000_000); // After Sep 2020
    }

    #[test]
    fn test_estimate_time_remaining() {
        let processed = 25;
        let total = 100;
        let elapsed = Duration::from_secs(10);

        let remaining = estimate_time_remaining(processed, total, elapsed);
        assert!(remaining.is_some());

        // 25% done in 10s, 75% remaining should take ~30s
        let remaining_secs = remaining.unwrap().as_secs();
        assert!((29..=31).contains(&remaining_secs));

        // Edge cases
        assert!(estimate_time_remaining(0, 100, elapsed).is_none());
        assert!(estimate_time_remaining(100, 100, elapsed).is_none());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h 0m 0s");
    }

    #[test]
    fn test_is_valid_peer_id() {
        assert!(is_valid_peer_id("peer-123"));
        assert!(is_valid_peer_id("abc123"));
        assert!(!is_valid_peer_id(""));
        assert!(!is_valid_peer_id("🦀")); // Non-ASCII

        // Too long
        let long_id = "a".repeat(257);
        assert!(!is_valid_peer_id(&long_id));
    }

    #[test]
    fn test_chunk_size_with_overhead() {
        assert_eq!(chunk_size_with_overhead(1024), 1040);
        assert_eq!(chunk_size_with_overhead(0), 16);
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("Hello, World!", 20), "Hello, World!");
        assert_eq!(truncate_string("Hello, World!", 10), "Hello, ...");
        assert_eq!(truncate_string("Hello, World!", 5), "He...");
        assert_eq!(truncate_string("Hi", 10), "Hi");
        assert_eq!(truncate_string("Hello", 3), "Hel");
    }

    #[test]
    fn test_exponential_backoff() {
        // Without jitter
        let delay = exponential_backoff(0, 100, 10_000, false);
        assert_eq!(delay, Duration::from_millis(100));

        let delay = exponential_backoff(1, 100, 10_000, false);
        assert_eq!(delay, Duration::from_millis(200));

        let delay = exponential_backoff(2, 100, 10_000, false);
        assert_eq!(delay, Duration::from_millis(400));

        let delay = exponential_backoff(3, 100, 10_000, false);
        assert_eq!(delay, Duration::from_millis(800));

        // Should cap at max_delay
        let delay = exponential_backoff(10, 100, 5_000, false);
        assert_eq!(delay, Duration::from_millis(5_000));

        // With jitter - should be between 0 and calculated delay
        let delay = exponential_backoff(2, 100, 10_000, true);
        assert!(delay <= Duration::from_millis(400));
    }

    #[test]
    fn test_retry_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.base_delay_ms, 100);
        assert_eq!(config.max_delay_ms, 30_000);
        assert!(config.jitter);

        let delay = config.delay_for_attempt(0);
        assert!(delay <= Duration::from_millis(100));

        let custom = RetryConfig::new(5, 200, 60_000, false);
        assert_eq!(custom.max_attempts, 5);
        assert_eq!(custom.delay_for_attempt(1), Duration::from_millis(400));
    }

    #[test]
    fn test_lru_cache_basic() {
        let mut cache = LruCache::new(2);
        cache.put("a", 1);
        cache.put("b", 2);

        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut cache = LruCache::new(2);
        cache.put("a", 1);
        cache.put("b", 2);

        // Access "a" to make it recently used
        assert_eq!(cache.get(&"a"), Some(&1));

        // Add "c" - should evict "b" (least recently used)
        cache.put("c", 3);

        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"c"), Some(&3));
    }

    #[test]
    fn test_lru_cache_update() {
        let mut cache = LruCache::new(2);
        cache.put("a", 1);
        cache.put("a", 2); // Update value

        assert_eq!(cache.get(&"a"), Some(&2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_lru_cache_remove() {
        let mut cache = LruCache::new(2);
        cache.put("a", 1);
        cache.put("b", 2);

        assert_eq!(cache.remove(&"a"), Some(1));
        assert_eq!(cache.get(&"a"), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_lru_cache_clear() {
        let mut cache = LruCache::new(2);
        cache.put("a", 1);
        cache.put("b", 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_lru_cache_capacity() {
        let cache = LruCache::<String, i32>::new(10);
        assert_eq!(cache.capacity(), 10);
    }

    #[test]
    fn test_byte_conversions() {
        // KB conversions
        assert_eq!(kb_to_bytes(1), 1024);
        assert_eq!(kb_to_bytes(10), 10240);
        assert_eq!(bytes_to_kb(1024), 1);
        assert_eq!(bytes_to_kb(2048), 2);

        // MB conversions
        assert_eq!(mb_to_bytes(1), 1024 * 1024);
        assert_eq!(mb_to_bytes(10), 10 * 1024 * 1024);
        assert_eq!(bytes_to_mb(1024 * 1024), 1);
        assert_eq!(bytes_to_mb(2 * 1024 * 1024), 2);

        // GB conversions
        assert_eq!(gb_to_bytes(1), 1024 * 1024 * 1024);
        assert_eq!(gb_to_bytes(10), 10 * 1024 * 1024 * 1024);
        assert_eq!(bytes_to_gb(1024 * 1024 * 1024), 1);

        // TB conversions
        assert_eq!(tb_to_bytes(1), 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_bandwidth_conversions() {
        // Gbps calculation
        let bytes = 1024 * 1024 * 125; // 125 MB
        let duration = Duration::from_secs(1);
        let gbps = calculate_bandwidth_gbps(bytes, duration);
        assert!((gbps - 1.0).abs() < 0.1);

        // Mbps to bytes/sec
        assert_eq!(mbps_to_bytes_per_sec(8), 1_000_000);
        assert_eq!(mbps_to_bytes_per_sec(100), 12_500_000);

        // Bytes/sec to Mbps
        assert_eq!(bytes_per_sec_to_mbps(1_000_000), 8);
        assert_eq!(bytes_per_sec_to_mbps(12_500_000), 100);
    }

    #[test]
    fn test_duration_conversions() {
        assert_eq!(secs_to_duration(60), Duration::from_secs(60));
        assert_eq!(millis_to_duration(1000), Duration::from_millis(1000));
        assert_eq!(minutes_to_duration(1), Duration::from_secs(60));
        assert_eq!(minutes_to_duration(5), Duration::from_secs(300));
        assert_eq!(hours_to_duration(1), Duration::from_secs(3600));
        assert_eq!(hours_to_duration(2), Duration::from_secs(7200));
        assert_eq!(days_to_duration(1), Duration::from_secs(86400));
        assert_eq!(days_to_duration(7), Duration::from_secs(604_800));
    }

    #[test]
    fn test_retry_config_builder() {
        let config = RetryConfig::builder()
            .max_attempts(5)
            .base_delay_ms(200)
            .max_delay_ms(10_000)
            .with_jitter(false)
            .build();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.base_delay_ms, 200);
        assert_eq!(config.max_delay_ms, 10_000);
        assert!(!config.jitter);
    }

    #[test]
    fn test_retry_config_presets() {
        // Aggressive preset
        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_attempts, 5);
        assert_eq!(aggressive.base_delay_ms, 50);
        assert_eq!(aggressive.max_delay_ms, 5_000);

        // Conservative preset
        let conservative = RetryConfig::conservative();
        assert_eq!(conservative.max_attempts, 2);
        assert_eq!(conservative.base_delay_ms, 500);
        assert_eq!(conservative.max_delay_ms, 60_000);

        // None preset
        let none = RetryConfig::none();
        assert_eq!(none.max_attempts, 0);
    }

    #[test]
    fn test_retry_config_builder_default() {
        let config = RetryConfig::builder().build();
        let default_config = RetryConfig::default();

        assert_eq!(config.max_attempts, default_config.max_attempts);
        assert_eq!(config.base_delay_ms, default_config.base_delay_ms);
        assert_eq!(config.max_delay_ms, default_config.max_delay_ms);
        assert_eq!(config.jitter, default_config.jitter);
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(10, 3), 4);
        assert_eq!(div_ceil(9, 3), 3);
        assert_eq!(div_ceil(0, 5), 0);
        assert_eq!(div_ceil(1, 1), 1);
        assert_eq!(div_ceil(100, 10), 10);
        assert_eq!(div_ceil(101, 10), 11);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(8));
        assert!(is_power_of_two(1024));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(100));
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(10, 8), 16);
        assert_eq!(align_up(16, 8), 16);
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(100, 64), 128);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(10, 8), 8);
        assert_eq!(align_down(16, 8), 16);
        assert_eq!(align_down(0, 8), 0);
        assert_eq!(align_down(7, 4), 4);
        assert_eq!(align_down(100, 64), 64);
    }

    #[test]
    fn test_min_max_const() {
        assert_eq!(min_const(5, 10), 5);
        assert_eq!(min_const(10, 5), 5);
        assert_eq!(min_const(0, 0), 0);

        assert_eq!(max_const(5, 10), 10);
        assert_eq!(max_const(10, 5), 10);
        assert_eq!(max_const(0, 0), 0);
    }

    #[test]
    fn test_clamp_const() {
        assert_eq!(clamp_const(5, 0, 10), 5);
        assert_eq!(clamp_const(15, 0, 10), 10);
        assert_eq!(clamp_const(0, 5, 10), 5);
        assert_eq!(clamp_const(0, 0, 10), 0);
        assert_eq!(clamp_const(100, 50, 75), 75);
        assert_eq!(clamp_const(60, 50, 75), 60);
    }

    #[test]
    fn test_saturating_ops_const() {
        // Saturating add
        assert_eq!(saturating_add_const(5, 10), 15);
        assert_eq!(saturating_add_const(u64::MAX, 1), u64::MAX);
        assert_eq!(saturating_add_const(u64::MAX - 10, 20), u64::MAX);

        // Saturating sub
        assert_eq!(saturating_sub_const(10, 5), 5);
        assert_eq!(saturating_sub_const(5, 10), 0);
        assert_eq!(saturating_sub_const(0, 1), 0);

        // Saturating mul
        assert_eq!(saturating_mul_const(5, 10), 50);
        assert_eq!(saturating_mul_const(u64::MAX, 2), u64::MAX);
        assert_eq!(saturating_mul_const(u64::MAX / 2 + 1, 2), u64::MAX);
    }

    #[test]
    fn test_percentage_const() {
        assert_eq!(percentage_const(50, 100), 50);
        assert_eq!(percentage_const(1, 3), 33);
        assert_eq!(percentage_const(2, 3), 66);
        assert_eq!(percentage_const(10, 0), 0);
        assert_eq!(percentage_const(0, 100), 0);
        assert_eq!(percentage_const(100, 100), 100);
        assert_eq!(percentage_const(150, 100), 150); // Over 100%
    }

    // Tests for Session 29 enhancements

    #[test]
    fn test_bytes_to_float_conversions() {
        // KB conversions
        assert!((bytes_to_kb_f64(1024) - 1.0).abs() < 0.001);
        assert!((bytes_to_kb_f64(2048) - 2.0).abs() < 0.001);
        assert!((bytes_to_kb_f64(1536) - 1.5).abs() < 0.001);

        // MB conversions
        assert!((bytes_to_mb_f64(1024 * 1024) - 1.0).abs() < 0.001);
        assert!((bytes_to_mb_f64(1024 * 1024 * 5) - 5.0).abs() < 0.001);

        // GB conversions
        assert!((bytes_to_gb_f64(1024 * 1024 * 1024) - 1.0).abs() < 0.001);
        assert!((bytes_to_gb_f64(1024 * 1024 * 1024 * 2) - 2.0).abs() < 0.001);

        // TB conversions
        assert!((bytes_to_tb_f64(1024u64 * 1024 * 1024 * 1024) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_normalize_cid() {
        assert_eq!(normalize_cid("QmTest123"), "QmTest123");
        assert_eq!(normalize_cid("  QmTest123  "), "QmTest123");
        assert_eq!(normalize_cid("Qm../../../etc/passwd"), "Qmetcpasswd");
        assert_eq!(normalize_cid("Qm Test@123!"), "QmTest123");
        assert_eq!(normalize_cid("valid-cid_123"), "valid-cid_123");
        assert_eq!(normalize_cid(""), "");
    }

    #[test]
    fn test_cid_to_path_safe() {
        let path = cid_to_path_safe("QmTest123");
        assert_eq!(path.to_str().unwrap(), "QmTest123");

        let path = cid_to_path_safe("Qm../../../etc/passwd");
        assert_eq!(path.to_str().unwrap(), "Qmetcpasswd");
    }

    #[test]
    fn test_is_valid_cid_format() {
        // Valid CIDv0 (must be exactly 46 characters)
        assert!(is_valid_cid_format(
            "QmTest1234567890123456789012345678901234567890"
        ));

        // Valid CIDv1
        assert!(is_valid_cid_format(
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf"
        ));
        assert!(is_valid_cid_format(
            "zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA"
        ));

        // Invalid
        assert!(!is_valid_cid_format(""));
        assert!(!is_valid_cid_format("invalid"));
        assert!(!is_valid_cid_format("Qm"));
        assert!(!is_valid_cid_format("QmShort"));
        assert!(!is_valid_cid_format("QmTest12345")); // Too short
    }

    #[test]
    fn test_validate_peer_id() {
        assert!(validate_peer_id("peer-123").is_ok());
        assert!(validate_peer_id("valid_peer_id").is_ok());

        assert!(validate_peer_id("").is_err());
        assert!(validate_peer_id(&"x".repeat(300)).is_err());
    }

    #[test]
    fn test_peer_id_hash() {
        let hash1 = peer_id_hash("peer-123");
        let hash2 = peer_id_hash("peer-456");
        let hash3 = peer_id_hash("peer-123");

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash3); // Same input = same hash
        assert_ne!(hash1, 0);
    }

    #[test]
    fn test_timestamp_to_duration() {
        assert_eq!(timestamp_to_duration(0), Duration::ZERO);
        assert_eq!(timestamp_to_duration(1000), Duration::from_millis(1000));
        assert_eq!(timestamp_to_duration(-100), Duration::ZERO);
    }

    #[test]
    fn test_timestamp_age() {
        let now = current_timestamp_ms();
        let old_timestamp = now - 5000; // 5 seconds ago

        let age = timestamp_age(old_timestamp);
        assert!(age.as_millis() >= 5000);
        assert!(age.as_millis() < 6000); // Allow some tolerance
    }

    #[test]
    fn test_is_timestamp_recent() {
        let now = current_timestamp_ms();
        let recent = now - 1000; // 1 second ago
        let old = now - 10000; // 10 seconds ago

        assert!(is_timestamp_recent(recent, 5000));
        assert!(!is_timestamp_recent(old, 5000));
        assert!(is_timestamp_recent(now, 1000));
    }

    #[test]
    fn test_timestamp_to_systemtime() {
        let timestamp_ms = 1609459200000i64; // 2021-01-01 00:00:00 UTC
        let system_time = timestamp_to_systemtime(timestamp_ms);

        let duration = system_time.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(duration.as_millis(), timestamp_ms as u128);

        let zero_time = timestamp_to_systemtime(0);
        assert_eq!(zero_time, UNIX_EPOCH);

        let negative_time = timestamp_to_systemtime(-1000);
        assert_eq!(negative_time, UNIX_EPOCH);
    }

    // Tests for Session 30 enhancements

    #[test]
    fn test_additional_unit_conversions() {
        assert_eq!(mb_to_kb(1), 1024);
        assert_eq!(mb_to_kb(10), 10240);

        assert_eq!(gb_to_mb(1), 1024);
        assert_eq!(gb_to_mb(5), 5120);

        assert_eq!(tb_to_gb(1), 1024);
        assert_eq!(tb_to_gb(2), 2048);
    }

    #[test]
    fn test_round_to_multiple() {
        // Round up
        assert_eq!(round_up_to_multiple(10, 5), 10);
        assert_eq!(round_up_to_multiple(11, 5), 15);
        assert_eq!(round_up_to_multiple(14, 5), 15);
        assert_eq!(round_up_to_multiple(15, 5), 15);
        assert_eq!(round_up_to_multiple(0, 5), 0);
        assert_eq!(round_up_to_multiple(100, 0), 100); // Edge case

        // Round down
        assert_eq!(round_down_to_multiple(10, 5), 10);
        assert_eq!(round_down_to_multiple(11, 5), 10);
        assert_eq!(round_down_to_multiple(14, 5), 10);
        assert_eq!(round_down_to_multiple(15, 5), 15);
        assert_eq!(round_down_to_multiple(0, 5), 0);
        assert_eq!(round_down_to_multiple(100, 0), 100); // Edge case
    }

    #[test]
    fn test_calculate_percentage_rounded() {
        assert_eq!(calculate_percentage_rounded(50, 100), 50);
        assert_eq!(calculate_percentage_rounded(1, 3), 33);
        assert_eq!(calculate_percentage_rounded(2, 3), 67);
        assert_eq!(calculate_percentage_rounded(0, 100), 0);
        assert_eq!(calculate_percentage_rounded(100, 0), 0); // Division by zero
        assert_eq!(calculate_percentage_rounded(100, 100), 100);
        assert_eq!(calculate_percentage_rounded(150, 100), 100); // Capped at 100
    }

    #[test]
    fn test_is_in_range() {
        assert!(is_in_range(5, 0, 10));
        assert!(is_in_range(0, 0, 10));
        assert!(is_in_range(10, 0, 10));
        assert!(!is_in_range(11, 0, 10));
        assert!(!is_in_range(15, 0, 10));
    }

    #[test]
    fn test_average_u64() {
        assert_eq!(average_u64(10, 20), 15);
        assert_eq!(average_u64(0, 0), 0);
        assert_eq!(average_u64(100, 100), 100);
        assert_eq!(average_u64(1, 2), 1); // Rounds down
        assert_eq!(average_u64(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(average_u64(u64::MAX - 1, u64::MAX), u64::MAX - 1);
    }

    #[test]
    fn test_larger_smaller_of() {
        assert_eq!(larger_of(10, 20), 20);
        assert_eq!(larger_of(20, 10), 20);
        assert_eq!(larger_of(15, 15), 15);

        assert_eq!(smaller_of(10, 20), 10);
        assert_eq!(smaller_of(20, 10), 10);
        assert_eq!(smaller_of(15, 15), 15);
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(is_valid_identifier("valid_id"));
        assert!(is_valid_identifier("valid-id"));
        assert!(is_valid_identifier("ValidId123"));
        assert!(is_valid_identifier("a"));

        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("invalid id")); // Space
        assert!(!is_valid_identifier("invalid@id")); // Special char
        assert!(!is_valid_identifier(&"x".repeat(257))); // Too long
    }

    #[test]
    fn test_truncate_with_ellipsis() {
        assert_eq!(truncate_with_ellipsis("hello", 10), "hello");
        assert_eq!(truncate_with_ellipsis("hello world", 8), "hello...");
        assert_eq!(truncate_with_ellipsis("hello", 5), "hello");
        assert_eq!(truncate_with_ellipsis("hello", 4), "h...");
        assert_eq!(truncate_with_ellipsis("hello", 3), "hel"); // Not enough room for ellipsis
        assert_eq!(truncate_with_ellipsis("hello", 2), "he");
        assert_eq!(truncate_with_ellipsis("hello", 1), "h");
    }

    #[test]
    fn test_safe_slice() {
        let s = "hello world";
        assert_eq!(safe_slice(s, 0, 5), "hello");
        assert_eq!(safe_slice(s, 6, 11), "world");
        assert_eq!(safe_slice(s, 0, 100), "hello world"); // End beyond length
        assert_eq!(safe_slice(s, 100, 200), ""); // Start beyond length
        assert_eq!(safe_slice(s, 5, 3), ""); // Start > end
    }

    #[test]
    fn test_format_number_with_commas() {
        assert_eq!(format_number_with_commas(0), "0");
        assert_eq!(format_number_with_commas(123), "123");
        assert_eq!(format_number_with_commas(1234), "1,234");
        assert_eq!(format_number_with_commas(1234567), "1,234,567");
        assert_eq!(format_number_with_commas(1234567890), "1,234,567,890");
    }

    #[test]
    fn test_format_duration_compact() {
        assert_eq!(format_duration_compact(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration_compact(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration_compact(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_duration_compact(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration_compact(Duration::from_secs(3660)), "1h1m");
        assert_eq!(format_duration_compact(Duration::from_secs(7200)), "2h");
        assert_eq!(format_duration_compact(Duration::from_secs(7380)), "2h3m");
    }
}
