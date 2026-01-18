//! Mathematical calculation utility functions.

use crate::{Bytes, Points};

/// Calculate percentage with proper rounding.
///
/// # Examples
///
/// ```
/// use chie_shared::calculate_percentage;
///
/// // Calculate what percentage 25 is of 100
/// let percentage = calculate_percentage(25, 100);
/// assert_eq!(percentage, 25.0);
///
/// // Calculate what percentage 1 is of 3
/// let percentage = calculate_percentage(1, 3);
/// assert!((percentage - 33.333).abs() < 0.01);
///
/// // Handle division by zero
/// let percentage = calculate_percentage(10, 0);
/// assert_eq!(percentage, 0.0);
/// ```
#[inline]
#[must_use]
pub fn calculate_percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (part as f64 / total as f64) * 100.0
}

/// Calculate bandwidth in Mbps from bytes and duration.
///
/// # Examples
///
/// ```
/// use chie_shared::calculate_bandwidth_mbps;
///
/// // 1 MB transferred in 1 second = 8 Mbps
/// let bandwidth = calculate_bandwidth_mbps(1_000_000, 1000);
/// assert!((bandwidth - 8.0).abs() < 0.01);
///
/// // 10 MB in 2 seconds = 40 Mbps
/// let bandwidth = calculate_bandwidth_mbps(10_000_000, 2000);
/// assert!((bandwidth - 40.0).abs() < 0.01);
///
/// // Handle zero duration
/// let bandwidth = calculate_bandwidth_mbps(1_000_000, 0);
/// assert_eq!(bandwidth, 0.0);
/// ```
#[inline]
#[must_use]
pub fn calculate_bandwidth_mbps(bytes: Bytes, duration_ms: u64) -> f64 {
    if duration_ms == 0 {
        return 0.0;
    }

    let bits = (bytes * 8) as f64;
    let seconds = duration_ms as f64 / 1000.0;
    (bits / seconds) / 1_000_000.0
}

/// Calculate latency from start and end timestamps.
#[inline]
pub fn calculate_latency_ms(start_ms: i64, end_ms: i64) -> u32 {
    (end_ms - start_ms).max(0) as u32
}

/// Calculate estimated transfer time in seconds.
#[inline]
#[must_use]
pub fn estimate_transfer_time(bytes: Bytes, bandwidth_bps: u64) -> u64 {
    if bandwidth_bps == 0 {
        return u64::MAX;
    }

    let bits = bytes * 8;
    bits / bandwidth_bps
}

/// Calculate reward multiplier based on demand/supply ratio.
///
/// Returns a multiplier between 1.0x and 3.0x based on the demand/supply ratio.
/// - Low demand (ratio ≤ 0.5): 1.0x multiplier
/// - High demand (ratio ≥ 2.0): 3.0x multiplier
/// - Medium demand: Linear interpolation between 1.0x and 3.0x
///
/// # Examples
///
/// ```
/// use chie_shared::calculate_demand_multiplier;
///
/// // Low demand: plenty of supply
/// let multiplier = calculate_demand_multiplier(50, 100);
/// assert_eq!(multiplier, 1.0);
///
/// // High demand: scarce supply
/// let multiplier = calculate_demand_multiplier(200, 100);
/// assert_eq!(multiplier, 3.0);
///
/// // Medium demand: 1:1 ratio
/// let multiplier = calculate_demand_multiplier(100, 100);
/// assert!((multiplier - 1.666).abs() < 0.01);
///
/// // No supply: maximum multiplier
/// let multiplier = calculate_demand_multiplier(100, 0);
/// assert_eq!(multiplier, 3.0);
/// ```
#[inline]
#[must_use]
pub fn calculate_demand_multiplier(demand: u64, supply: u64) -> f64 {
    if supply == 0 {
        return 3.0; // Maximum multiplier
    }

    let ratio = demand as f64 / supply as f64;

    // Clamp between 1.0x and 3.0x
    if ratio <= 0.5 {
        1.0
    } else if ratio >= 2.0 {
        3.0
    } else {
        1.0 + (ratio - 0.5) * (2.0 / 1.5)
    }
}

/// Calculate z-score for anomaly detection.
///
/// The z-score indicates how many standard deviations away from the mean a value is.
/// Values with |z-score| > 3 are typically considered anomalies.
///
/// # Examples
///
/// ```
/// use chie_shared::calculate_z_score;
///
/// // Value at the mean has z-score of 0
/// let z = calculate_z_score(100.0, 100.0, 10.0);
/// assert_eq!(z, 0.0);
///
/// // Value 1 std dev above mean has z-score of 1
/// let z = calculate_z_score(110.0, 100.0, 10.0);
/// assert_eq!(z, 1.0);
///
/// // Value 2 std devs below mean has z-score of -2
/// let z = calculate_z_score(80.0, 100.0, 10.0);
/// assert_eq!(z, -2.0);
///
/// // Anomaly: value is 3.5 std devs above mean
/// let z = calculate_z_score(135.0, 100.0, 10.0);
/// assert_eq!(z, 3.5);
/// assert!(z.abs() > 3.0); // Likely an anomaly
///
/// // Handle zero std dev
/// let z = calculate_z_score(100.0, 100.0, 0.0);
/// assert_eq!(z, 0.0);
/// ```
#[inline]
#[must_use]
pub fn calculate_z_score(value: f64, mean: f64, std_dev: f64) -> f64 {
    if std_dev == 0.0 {
        return 0.0;
    }

    (value - mean) / std_dev
}

/// Calculate storage cost per month (points per GB).
#[inline]
#[must_use]
pub fn calculate_storage_cost(size_bytes: Bytes, rate_per_gb_month: Points) -> Points {
    let gb = (size_bytes as f64) / (1024.0 * 1024.0 * 1024.0);
    (gb * rate_per_gb_month as f64).ceil() as Points
}

/// Convert bytes to gigabytes with precision (f64 version for non-const contexts).
#[inline]
pub fn bytes_to_gb_f64(bytes: Bytes) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

/// Convert gigabytes to bytes (f64 version for non-const contexts).
#[inline]
pub fn gb_to_bytes_f64(gb: f64) -> Bytes {
    (gb * 1024.0 * 1024.0 * 1024.0) as Bytes
}

/// Calculate reward with multiplier and penalty based on latency.
#[inline]
#[must_use]
pub fn calculate_reward_with_penalty(
    base_reward: Points,
    multiplier: f64,
    latency_ms: u32,
    latency_threshold_ms: u32,
) -> Points {
    let reward_with_multiplier = (base_reward as f64 * multiplier) as Points;

    if latency_ms > latency_threshold_ms {
        // Apply 50% penalty for high latency
        reward_with_multiplier / 2
    } else {
        reward_with_multiplier
    }
}

/// Calculate exponential moving average.
#[inline]
#[must_use]
pub fn calculate_ema(current: f64, new_value: f64, alpha: f64) -> f64 {
    alpha * new_value + (1.0 - alpha) * current
}

/// Calculate standard deviation from a slice of values.
#[inline]
#[must_use]
pub fn calculate_std_dev(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

/// Calculate mean of values.
#[inline]
#[must_use]
pub fn calculate_mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Calculate median of a slice of values.
pub fn calculate_median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

/// Calculate percentile of a slice of values (p should be between 0.0 and 1.0).
pub fn calculate_percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let p = p.clamp(0.0, 1.0);
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let index = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[index]
}

/// Calculate min, max, and average from a slice of values.
pub fn calculate_stats(values: &[f64]) -> (f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let min = values
        .iter()
        .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .copied()
        .unwrap_or(0.0);

    let max = values
        .iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .copied()
        .unwrap_or(0.0);

    let avg = calculate_mean(values);

    (min, max, avg)
}

/// Check if value is an outlier using IQR method.
pub fn is_outlier_iqr(values: &[f64], value: f64) -> bool {
    if values.len() < 4 {
        return false;
    }

    let q1 = calculate_percentile(values, 0.25);
    let q3 = calculate_percentile(values, 0.75);
    let iqr = q3 - q1;

    let lower_bound = q1 - 1.5 * iqr;
    let upper_bound = q3 + 1.5 * iqr;

    value < lower_bound || value > upper_bound
}

/// Calculate moving average over a window.
pub fn calculate_moving_average(values: &[f64], window_size: usize) -> Vec<f64> {
    if values.is_empty() || window_size == 0 {
        return Vec::new();
    }

    let mut result = Vec::new();
    for i in 0..values.len() {
        let start = if i >= window_size {
            i - window_size + 1
        } else {
            0
        };
        let window = &values[start..=i];
        result.push(calculate_mean(window));
    }

    result
}

/// Round up to the nearest multiple of n.
pub fn round_up_to_multiple(value: u64, n: u64) -> u64 {
    if n == 0 {
        return value;
    }
    value.div_ceil(n) * n
}

/// Round down to the nearest multiple of n.
pub fn round_down_to_multiple(value: u64, n: u64) -> u64 {
    if n == 0 {
        return value;
    }
    (value / n) * n
}

/// Calculate compound growth rate.
pub fn calculate_growth_rate(initial: f64, final_val: f64, periods: u32) -> f64 {
    if initial == 0.0 || periods == 0 {
        return 0.0;
    }
    ((final_val / initial).powf(1.0 / periods as f64) - 1.0) * 100.0
}

/// Calculate reputation score with decay over time.
pub fn calculate_reputation_decay(
    current_reputation: f32,
    days_elapsed: f32,
    decay_rate: f32,
) -> f32 {
    let decayed = current_reputation - (current_reputation * decay_rate * days_elapsed);
    decayed.clamp(crate::MIN_REPUTATION, crate::MAX_REPUTATION)
}

/// Update reputation based on success/failure events.
pub fn update_reputation(current: f32, success: bool, weight: f32) -> f32 {
    let delta = if success { weight } else { -weight * 2.0 }; // Failures have 2x impact
    (current + delta).clamp(crate::MIN_REPUTATION, crate::MAX_REPUTATION)
}

/// Calculate reputation boost for consistent good behavior.
pub fn calculate_reputation_bonus(consecutive_successes: u32) -> f32 {
    // Bonus caps at 20 consecutive successes
    let capped_successes = consecutive_successes.min(20);
    (capped_successes as f32).sqrt() * 0.5 // Up to ~2.2 bonus points
}

/// Calculate tokens available in a token bucket.
pub fn calculate_token_bucket(
    current_tokens: f64,
    capacity: f64,
    refill_rate: f64,
    time_elapsed_secs: f64,
) -> f64 {
    let new_tokens = current_tokens + (refill_rate * time_elapsed_secs);
    new_tokens.min(capacity)
}

/// Check if an action is allowed under rate limiting (token bucket).
pub fn is_rate_limit_allowed(current_tokens: f64, cost: f64) -> bool {
    current_tokens >= cost
}

/// Calculate sliding window rate limit.
pub fn calculate_sliding_window_count(
    timestamps: &[i64],
    window_start_ms: i64,
    window_end_ms: i64,
) -> usize {
    timestamps
        .iter()
        .filter(|&&ts| ts >= window_start_ms && ts <= window_end_ms)
        .count()
}

/// Calculate platform fee from total points.
pub fn calculate_platform_fee(total_points: Points, fee_percentage: f64) -> Points {
    (total_points as f64 * fee_percentage) as Points
}

/// Calculate creator share from total points.
pub fn calculate_creator_share(total_points: Points, share_percentage: f64) -> Points {
    (total_points as f64 * share_percentage) as Points
}

/// Calculate provider earnings after fees and creator share.
pub fn calculate_provider_earnings(
    total_points: Points,
    platform_fee_pct: f64,
    creator_share_pct: f64,
) -> Points {
    let platform_fee = calculate_platform_fee(total_points, platform_fee_pct);
    let creator_share = calculate_creator_share(total_points, creator_share_pct);
    total_points
        .saturating_sub(platform_fee)
        .saturating_sub(creator_share)
}

/// Calculate content pricing based on size and demand.
pub fn calculate_content_price(
    size_bytes: Bytes,
    base_price_per_gb: Points,
    demand_multiplier: f64,
) -> Points {
    let gb = bytes_to_gb_f64(size_bytes);
    ((gb * base_price_per_gb as f64) * demand_multiplier).ceil() as Points
}

/// Clamp a value between a minimum and maximum.
///
/// # Examples
///
/// ```
/// use chie_shared::clamp;
///
/// assert_eq!(clamp(5, 0, 10), 5);
/// assert_eq!(clamp(-5, 0, 10), 0);  // Below min
/// assert_eq!(clamp(15, 0, 10), 10); // Above max
///
/// // Works with floats too
/// assert_eq!(clamp(3.5, 0.0, 5.0), 3.5);
/// assert_eq!(clamp(-1.0, 0.0, 5.0), 0.0);
/// ```
pub fn clamp<T: PartialOrd>(value: T, min: T, max: T) -> T {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Linear interpolation between two values.
///
/// # Examples
///
/// ```
/// use chie_shared::lerp;
///
/// // Interpolate between 0 and 100
/// assert_eq!(lerp(0.0, 100.0, 0.0), 0.0);   // t=0 returns start
/// assert_eq!(lerp(0.0, 100.0, 1.0), 100.0); // t=1 returns end
/// assert_eq!(lerp(0.0, 100.0, 0.5), 50.0);  // t=0.5 returns midpoint
///
/// // Can extrapolate with t > 1 or t < 0
/// assert_eq!(lerp(0.0, 100.0, 2.0), 200.0);
/// assert_eq!(lerp(0.0, 100.0, -0.5), -50.0);
/// ```
#[inline]
pub fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

/// Calculate percentage change between two values.
/// Returns positive for increase, negative for decrease.
/// Returns 0.0 if old_value is 0.
pub fn calculate_percentage_change(old_value: f64, new_value: f64) -> f64 {
    if old_value == 0.0 {
        if new_value == 0.0 {
            0.0
        } else {
            100.0 // or f64::INFINITY, but 100% is more practical
        }
    } else {
        ((new_value - old_value) / old_value) * 100.0
    }
}

/// Calculate rate (events per time unit).
/// Returns events per second.
pub fn calculate_rate(event_count: u64, duration_ms: u64) -> f64 {
    if duration_ms == 0 {
        return 0.0;
    }

    (event_count as f64 / duration_ms as f64) * 1000.0
}

/// Normalize a value to 0.0-1.0 range based on min and max bounds.
/// Values outside bounds are clamped to 0.0 or 1.0.
///
/// # Examples
///
/// ```
/// use chie_shared::normalize;
///
/// // Normalize values in range 0-100
/// assert_eq!(normalize(0.0, 0.0, 100.0), 0.0);
/// assert_eq!(normalize(100.0, 0.0, 100.0), 1.0);
/// assert_eq!(normalize(50.0, 0.0, 100.0), 0.5);
///
/// // Values outside range are clamped
/// assert_eq!(normalize(-10.0, 0.0, 100.0), 0.0);
/// assert_eq!(normalize(150.0, 0.0, 100.0), 1.0);
///
/// // Special case: when min == max, returns 0.5
/// assert_eq!(normalize(5.0, 5.0, 5.0), 0.5);
/// ```
pub fn normalize(value: f64, min: f64, max: f64) -> f64 {
    if max == min {
        return 0.5; // Arbitrary choice when range is zero
    }

    let normalized = (value - min) / (max - min);
    normalized.clamp(0.0, 1.0)
}

/// Calculate the average of two values.
pub fn average(a: f64, b: f64) -> f64 {
    (a + b) / 2.0
}

/// Check if a value is within a tolerance of a target.
pub fn is_within_tolerance(value: f64, target: f64, tolerance: f64) -> bool {
    (value - target).abs() <= tolerance
}

/// Convert bits per second to megabits per second.
pub fn bps_to_mbps(bps: u64) -> f64 {
    bps as f64 / 1_000_000.0
}

/// Convert megabits per second to bits per second.
pub fn mbps_to_bps(mbps: f64) -> u64 {
    (mbps * 1_000_000.0) as u64
}

/// Calculate uptime percentage from total time and downtime.
pub fn calculate_uptime_percentage(total_ms: u64, downtime_ms: u64) -> f64 {
    if total_ms == 0 {
        return 100.0;
    }

    let uptime_ms = total_ms.saturating_sub(downtime_ms);
    (uptime_ms as f64 / total_ms as f64) * 100.0
}

/// Calculate the byte offset for a chunk index.
/// Returns the starting byte position in the content for the given chunk.
#[inline]
#[must_use]
pub const fn chunk_offset(chunk_index: u64, chunk_size: u64) -> u64 {
    chunk_index * chunk_size
}

/// Calculate which chunk contains a given byte offset.
/// Returns the chunk index that contains the specified byte.
#[inline]
#[must_use]
pub const fn byte_to_chunk_index(byte_offset: u64, chunk_size: u64) -> u64 {
    if chunk_size == 0 {
        0
    } else {
        byte_offset / chunk_size
    }
}

/// Get the byte range (start, end) for a specific chunk.
/// Returns (start_byte, end_byte_exclusive) for the chunk.
#[inline]
#[must_use]
pub const fn chunk_byte_range(chunk_index: u64, chunk_size: u64, total_size: u64) -> (u64, u64) {
    let start = chunk_index * chunk_size;
    let end = if start + chunk_size > total_size {
        total_size
    } else {
        start + chunk_size
    };
    (start, end)
}

/// Check if a chunk index is valid for the given content size.
#[inline]
#[must_use]
pub const fn is_valid_chunk_index(chunk_index: u64, total_size: u64, chunk_size: u64) -> bool {
    if chunk_size == 0 {
        return false;
    }
    let max_chunks = total_size.div_ceil(chunk_size);
    chunk_index < max_chunks
}

/// Calculate the actual size of a specific chunk (last chunk may be smaller).
#[inline]
#[must_use]
pub const fn actual_chunk_size(chunk_index: u64, chunk_size: u64, total_size: u64) -> u64 {
    let start = chunk_index * chunk_size;
    if start >= total_size {
        0
    } else {
        let remaining = total_size - start;
        if remaining < chunk_size {
            remaining
        } else {
            chunk_size
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_percentage() {
        assert_eq!(calculate_percentage(50, 100), 50.0);
        assert_eq!(calculate_percentage(0, 100), 0.0);
        assert_eq!(calculate_percentage(100, 100), 100.0);
        assert_eq!(calculate_percentage(25, 0), 0.0);
    }

    #[test]
    fn test_calculate_bandwidth_mbps() {
        // 1 MB in 1 second = 8 Mbps
        assert_eq!(calculate_bandwidth_mbps(1_048_576, 1000), 8.388_608);
        assert_eq!(calculate_bandwidth_mbps(0, 1000), 0.0);
        assert_eq!(calculate_bandwidth_mbps(1000, 0), 0.0);
    }

    #[test]
    fn test_calculate_latency() {
        assert_eq!(calculate_latency_ms(1000, 1500), 500);
        assert_eq!(calculate_latency_ms(1500, 1000), 0);
    }

    #[test]
    fn test_estimate_transfer_time() {
        // 1 MB at 1 Mbps = 8 seconds
        assert_eq!(estimate_transfer_time(1_048_576, 1_000_000), 8);
        assert_eq!(estimate_transfer_time(1000, 0), u64::MAX);
    }

    #[test]
    fn test_calculate_demand_multiplier() {
        // Low demand (ratio <= 0.5): 1.0x multiplier
        assert_eq!(calculate_demand_multiplier(1, 4), 1.0);
        // Medium demand (ratio = 1.0): ~1.67x multiplier
        assert!((calculate_demand_multiplier(2, 2) - 1.666_666_666_666_667).abs() < 0.001);
        // High demand (ratio >= 2.0): 3.0x multiplier
        assert_eq!(calculate_demand_multiplier(4, 2), 3.0);
        // No supply: maximum 3.0x multiplier
        assert_eq!(calculate_demand_multiplier(10, 0), 3.0);
    }

    #[test]
    fn test_calculate_z_score() {
        assert_eq!(calculate_z_score(100.0, 100.0, 10.0), 0.0);
        assert_eq!(calculate_z_score(110.0, 100.0, 10.0), 1.0);
        assert_eq!(calculate_z_score(90.0, 100.0, 10.0), -1.0);
        assert_eq!(calculate_z_score(100.0, 100.0, 0.0), 0.0);
    }

    #[test]
    fn test_calculate_storage_cost() {
        // 1 GB at 10 points/GB/month = 10 points
        assert_eq!(calculate_storage_cost(1_073_741_824, 10), 10);
        // 500 MB at 10 points/GB/month = 5 points (rounded up)
        assert_eq!(calculate_storage_cost(536_870_912, 10), 5);
    }

    #[test]
    fn test_bytes_to_gb_f64() {
        assert_eq!(bytes_to_gb_f64(1_073_741_824), 1.0);
        assert_eq!(bytes_to_gb_f64(536_870_912), 0.5);
    }

    #[test]
    fn test_gb_to_bytes_f64() {
        assert_eq!(gb_to_bytes_f64(1.0), 1_073_741_824);
        assert_eq!(gb_to_bytes_f64(0.5), 536_870_912);
    }

    #[test]
    fn test_calculate_reward_with_penalty() {
        // No penalty if latency is within threshold
        assert_eq!(calculate_reward_with_penalty(100, 2.0, 400, 500), 200);
        // 50% penalty if latency exceeds threshold
        assert_eq!(calculate_reward_with_penalty(100, 2.0, 600, 500), 100);
    }

    #[test]
    fn test_calculate_ema() {
        let current = 100.0;
        let new_value = 120.0;
        let alpha = 0.3;
        let expected = alpha * new_value + (1.0 - alpha) * current;
        assert_eq!(calculate_ema(current, new_value, alpha), expected);
    }

    #[test]
    fn test_calculate_std_dev() {
        let values = vec![10.0, 12.0, 23.0, 23.0, 16.0, 23.0, 21.0, 16.0];
        let std_dev = calculate_std_dev(&values);
        assert!((std_dev - 4.898_979_485_566_356).abs() < 0.001);

        assert_eq!(calculate_std_dev(&[]), 0.0);
    }

    #[test]
    fn test_calculate_mean() {
        assert_eq!(calculate_mean(&[1.0, 2.0, 3.0, 4.0, 5.0]), 3.0);
        assert_eq!(calculate_mean(&[]), 0.0);
    }

    #[test]
    fn test_calculate_median() {
        assert_eq!(calculate_median(&[1.0, 2.0, 3.0, 4.0, 5.0]), 3.0);
        assert_eq!(calculate_median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
        assert_eq!(calculate_median(&[5.0]), 5.0);
        assert_eq!(calculate_median(&[]), 0.0);
    }

    #[test]
    fn test_calculate_percentile() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(calculate_percentile(&values, 0.0), 1.0);
        assert_eq!(calculate_percentile(&values, 0.5), 6.0); // 50th percentile of 10 values is at index 5 (6.0)
        assert_eq!(calculate_percentile(&values, 1.0), 10.0);
    }

    #[test]
    fn test_calculate_stats() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let (min, max, avg) = calculate_stats(&values);
        assert_eq!(min, 1.0);
        assert_eq!(max, 5.0);
        assert_eq!(avg, 3.0);
    }

    #[test]
    fn test_is_outlier_iqr() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert!(!is_outlier_iqr(&values, 5.0));
        assert!(is_outlier_iqr(&values, 100.0));
        assert!(is_outlier_iqr(&values, -100.0));
    }

    #[test]
    fn test_calculate_moving_average() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ma = calculate_moving_average(&values, 3);
        assert_eq!(ma.len(), 5);
        assert_eq!(ma[0], 1.0); // avg of [1.0]
        assert_eq!(ma[1], 1.5); // avg of [1.0, 2.0]
        assert_eq!(ma[2], 2.0); // avg of [1.0, 2.0, 3.0]
        assert_eq!(ma[3], 3.0); // avg of [2.0, 3.0, 4.0]
        assert_eq!(ma[4], 4.0); // avg of [3.0, 4.0, 5.0]
    }

    #[test]
    fn test_round_up_to_multiple() {
        assert_eq!(round_up_to_multiple(10, 5), 10);
        assert_eq!(round_up_to_multiple(11, 5), 15);
        assert_eq!(round_up_to_multiple(14, 5), 15);
        assert_eq!(round_up_to_multiple(15, 5), 15);
    }

    #[test]
    fn test_round_down_to_multiple() {
        assert_eq!(round_down_to_multiple(10, 5), 10);
        assert_eq!(round_down_to_multiple(11, 5), 10);
        assert_eq!(round_down_to_multiple(14, 5), 10);
        assert_eq!(round_down_to_multiple(15, 5), 15);
    }

    #[test]
    fn test_calculate_growth_rate() {
        let rate = calculate_growth_rate(100.0, 121.0, 2);
        assert!((rate - 10.0).abs() < 0.01); // ~10% growth rate
    }

    #[test]
    fn test_calculate_reputation_decay() {
        let reputation = calculate_reputation_decay(100.0, 10.0, 0.01);
        assert_eq!(reputation, 90.0);

        // Should not go below MIN_REPUTATION
        let decayed = calculate_reputation_decay(10.0, 1000.0, 0.01);
        assert_eq!(decayed, crate::MIN_REPUTATION);

        // Should not go above MAX_REPUTATION
        let no_decay = calculate_reputation_decay(100.0, 0.0, 0.01);
        assert_eq!(no_decay, 100.0);
    }

    #[test]
    fn test_update_reputation() {
        // Success increases reputation
        let updated = update_reputation(50.0, true, 1.0);
        assert_eq!(updated, 51.0);

        // Failure decreases reputation (2x impact)
        let updated = update_reputation(50.0, false, 1.0);
        assert_eq!(updated, 48.0);

        // Clamps to MAX_REPUTATION
        let updated = update_reputation(99.0, true, 5.0);
        assert_eq!(updated, crate::MAX_REPUTATION);

        // Clamps to MIN_REPUTATION
        let updated = update_reputation(5.0, false, 10.0);
        assert_eq!(updated, crate::MIN_REPUTATION);
    }

    #[test]
    fn test_calculate_reputation_bonus() {
        assert_eq!(calculate_reputation_bonus(0), 0.0);
        assert_eq!(calculate_reputation_bonus(4), 1.0);
        assert!((calculate_reputation_bonus(16) - 2.0).abs() < 0.01);
        // Caps at 20
        let bonus_20 = calculate_reputation_bonus(20);
        let bonus_30 = calculate_reputation_bonus(30);
        assert_eq!(bonus_20, bonus_30);
    }

    #[test]
    fn test_calculate_token_bucket() {
        let tokens = calculate_token_bucket(5.0, 10.0, 1.0, 3.0);
        assert_eq!(tokens, 8.0);

        // Caps at capacity
        let tokens = calculate_token_bucket(8.0, 10.0, 5.0, 10.0);
        assert_eq!(tokens, 10.0);
    }

    #[test]
    fn test_is_rate_limit_allowed() {
        assert!(is_rate_limit_allowed(10.0, 5.0));
        assert!(is_rate_limit_allowed(5.0, 5.0));
        assert!(!is_rate_limit_allowed(4.0, 5.0));
    }

    #[test]
    fn test_calculate_sliding_window_count() {
        let timestamps = vec![1000, 2000, 3000, 4000, 5000];
        assert_eq!(calculate_sliding_window_count(&timestamps, 2000, 4000), 3);
        assert_eq!(calculate_sliding_window_count(&timestamps, 1000, 5000), 5);
        assert_eq!(calculate_sliding_window_count(&timestamps, 6000, 7000), 0);
    }

    #[test]
    fn test_calculate_platform_fee() {
        assert_eq!(calculate_platform_fee(1000, 0.10), 100);
        assert_eq!(calculate_platform_fee(500, 0.05), 25);
    }

    #[test]
    fn test_calculate_creator_share() {
        assert_eq!(calculate_creator_share(1000, 0.20), 200);
        assert_eq!(calculate_creator_share(500, 0.15), 75);
    }

    #[test]
    fn test_calculate_provider_earnings() {
        // 1000 points - 10% platform - 20% creator = 700 to provider
        assert_eq!(calculate_provider_earnings(1000, 0.10, 0.20), 700);
        // 500 points - 5% platform - 15% creator = 400 to provider
        assert_eq!(calculate_provider_earnings(500, 0.05, 0.15), 400);
    }

    #[test]
    fn test_calculate_content_price() {
        // 1 GB at 10 points/GB with 1.0x multiplier = 10 points
        assert_eq!(calculate_content_price(1_073_741_824, 10, 1.0), 10);
        // 1 GB at 10 points/GB with 2.0x multiplier = 20 points
        assert_eq!(calculate_content_price(1_073_741_824, 10, 2.0), 20);
        // 500 MB at 10 points/GB with 1.0x multiplier = 5 points (rounded up)
        assert_eq!(calculate_content_price(536_870_912, 10, 1.0), 5);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(5, 0, 10), 5);
        assert_eq!(clamp(-5, 0, 10), 0);
        assert_eq!(clamp(15, 0, 10), 10);
        assert_eq!(clamp(5.5, 0.0, 10.0), 5.5);
    }

    #[test]
    fn test_lerp() {
        assert_eq!(lerp(0.0, 10.0, 0.0), 0.0);
        assert_eq!(lerp(0.0, 10.0, 0.5), 5.0);
        assert_eq!(lerp(0.0, 10.0, 1.0), 10.0);
        assert_eq!(lerp(10.0, 20.0, 0.25), 12.5);
    }

    #[test]
    fn test_calculate_percentage_change() {
        assert_eq!(calculate_percentage_change(100.0, 150.0), 50.0);
        assert_eq!(calculate_percentage_change(100.0, 50.0), -50.0);
        assert_eq!(calculate_percentage_change(100.0, 100.0), 0.0);
        assert_eq!(calculate_percentage_change(0.0, 0.0), 0.0);
        assert_eq!(calculate_percentage_change(0.0, 50.0), 100.0);
    }

    #[test]
    fn test_calculate_rate() {
        assert_eq!(calculate_rate(100, 1000), 100.0); // 100 events in 1 second = 100/sec
        assert_eq!(calculate_rate(50, 500), 100.0); // 50 events in 0.5 seconds = 100/sec
        assert_eq!(calculate_rate(0, 1000), 0.0);
        assert_eq!(calculate_rate(100, 0), 0.0); // Division by zero handled
    }

    #[test]
    fn test_normalize() {
        assert_eq!(normalize(50.0, 0.0, 100.0), 0.5);
        assert_eq!(normalize(0.0, 0.0, 100.0), 0.0);
        assert_eq!(normalize(100.0, 0.0, 100.0), 1.0);
        assert_eq!(normalize(150.0, 0.0, 100.0), 1.0); // Clamped
        assert_eq!(normalize(-50.0, 0.0, 100.0), 0.0); // Clamped
        assert_eq!(normalize(50.0, 50.0, 50.0), 0.5); // Same min/max
    }

    #[test]
    fn test_average() {
        assert_eq!(average(10.0, 20.0), 15.0);
        assert_eq!(average(0.0, 100.0), 50.0);
        assert_eq!(average(-10.0, 10.0), 0.0);
    }

    #[test]
    fn test_is_within_tolerance() {
        assert!(is_within_tolerance(10.0, 10.0, 0.0));
        assert!(is_within_tolerance(10.5, 10.0, 1.0));
        assert!(is_within_tolerance(9.5, 10.0, 1.0));
        assert!(!is_within_tolerance(11.5, 10.0, 1.0));
        assert!(!is_within_tolerance(8.5, 10.0, 1.0));
    }

    #[test]
    fn test_bps_to_mbps() {
        assert_eq!(bps_to_mbps(1_000_000), 1.0);
        assert_eq!(bps_to_mbps(10_000_000), 10.0);
        assert_eq!(bps_to_mbps(500_000), 0.5);
    }

    #[test]
    fn test_mbps_to_bps() {
        assert_eq!(mbps_to_bps(1.0), 1_000_000);
        assert_eq!(mbps_to_bps(10.0), 10_000_000);
        assert_eq!(mbps_to_bps(0.5), 500_000);
    }

    #[test]
    fn test_calculate_uptime_percentage() {
        assert_eq!(calculate_uptime_percentage(1000, 0), 100.0);
        assert_eq!(calculate_uptime_percentage(1000, 100), 90.0);
        assert_eq!(calculate_uptime_percentage(1000, 1000), 0.0);
        assert_eq!(calculate_uptime_percentage(0, 0), 100.0);
        assert_eq!(calculate_uptime_percentage(1000, 1500), 0.0); // Downtime > total
    }

    #[test]
    fn test_chunk_offset() {
        assert_eq!(chunk_offset(0, 1024), 0);
        assert_eq!(chunk_offset(1, 1024), 1024);
        assert_eq!(chunk_offset(10, 1024), 10240);
        assert_eq!(chunk_offset(0, 262_144), 0);
        assert_eq!(chunk_offset(5, 262_144), 1_310_720);
    }

    #[test]
    fn test_byte_to_chunk_index() {
        assert_eq!(byte_to_chunk_index(0, 1024), 0);
        assert_eq!(byte_to_chunk_index(1023, 1024), 0);
        assert_eq!(byte_to_chunk_index(1024, 1024), 1);
        assert_eq!(byte_to_chunk_index(2048, 1024), 2);
        assert_eq!(byte_to_chunk_index(1_000_000, 262_144), 3);
        assert_eq!(byte_to_chunk_index(100, 0), 0); // Edge case: zero chunk size
    }

    #[test]
    fn test_chunk_byte_range() {
        assert_eq!(chunk_byte_range(0, 1024, 10240), (0, 1024));
        assert_eq!(chunk_byte_range(1, 1024, 10240), (1024, 2048));
        assert_eq!(chunk_byte_range(9, 1024, 10240), (9216, 10240)); // Last chunk
        assert_eq!(chunk_byte_range(10, 1024, 10240), (10240, 10240)); // Beyond end
    }

    #[test]
    fn test_is_valid_chunk_index() {
        // Content size: 10240 bytes, chunk size: 1024 bytes -> 10 chunks (0-9)
        assert!(is_valid_chunk_index(0, 10240, 1024));
        assert!(is_valid_chunk_index(9, 10240, 1024));
        assert!(!is_valid_chunk_index(10, 10240, 1024));
        assert!(!is_valid_chunk_index(100, 10240, 1024));

        // Edge case: chunk size is 0
        assert!(!is_valid_chunk_index(0, 10240, 0));

        // Exact multiple
        assert!(is_valid_chunk_index(4, 5120, 1024)); // 5 chunks exactly
        assert!(!is_valid_chunk_index(5, 5120, 1024));
    }

    #[test]
    fn test_actual_chunk_size() {
        // Regular chunks
        assert_eq!(actual_chunk_size(0, 1024, 10240), 1024);
        assert_eq!(actual_chunk_size(5, 1024, 10240), 1024);

        // Last chunk (smaller) - chunk 9 starts at 9*1024=9216, remaining is 10000-9216=784
        assert_eq!(actual_chunk_size(9, 1024, 10000), 784);

        // Beyond end
        assert_eq!(actual_chunk_size(100, 1024, 10240), 0);

        // Exact multiple
        assert_eq!(actual_chunk_size(4, 1024, 5120), 1024);
    }
}
