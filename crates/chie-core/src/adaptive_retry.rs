//! Adaptive retry policies based on failure patterns.
//!
//! This module provides intelligent retry logic that adapts based on observed
//! failure patterns, success rates, and error types. Instead of using static
//! retry configurations, it dynamically adjusts retry behavior to optimize
//! for both success rate and resource utilization.
//!
//! # Example
//!
//! ```rust
//! use chie_core::adaptive_retry::{AdaptiveRetryPolicy, FailureType};
//!
//! let mut policy = AdaptiveRetryPolicy::new();
//!
//! // Record failures and successes
//! policy.record_failure("peer1", FailureType::Timeout);
//! policy.record_failure("peer1", FailureType::Timeout);
//! policy.record_success("peer1");
//!
//! // Get recommended retry config for this peer
//! let should_retry = policy.should_retry("peer1", 1);
//! let delay = policy.retry_delay("peer1", 1);
//! ```

use crate::utils::RetryConfig;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Types of failures that can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureType {
    /// Network timeout.
    Timeout,
    /// Connection refused or failed.
    ConnectionFailed,
    /// Rate limit exceeded.
    RateLimited,
    /// Invalid response or data corruption.
    InvalidData,
    /// Temporary server error.
    ServerError,
    /// Unknown or unclassified error.
    Unknown,
}

impl FailureType {
    /// Check if this failure type is retryable.
    #[must_use]
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::ConnectionFailed | Self::ServerError
        )
    }

    /// Get the base retry multiplier for this failure type.
    #[must_use]
    #[inline]
    pub const fn retry_multiplier(&self) -> f64 {
        match self {
            Self::Timeout => 1.5,          // Increase delay for timeouts
            Self::ConnectionFailed => 2.0, // Much longer delay for connection issues
            Self::RateLimited => 3.0,      // Very long delay for rate limits
            Self::ServerError => 1.2,      // Slight increase for server errors
            Self::InvalidData => 0.5,      // Fast retry for data issues
            Self::Unknown => 1.0,          // Default delay
        }
    }
}

/// Failure record for tracking patterns.
#[derive(Debug, Clone)]
struct FailureRecord {
    failure_type: FailureType,
    timestamp: Instant,
}

/// Statistics for a specific target (peer, endpoint, etc.).
#[derive(Debug, Clone, Default)]
struct TargetStats {
    /// Total attempts made.
    total_attempts: u64,
    /// Successful attempts.
    successful_attempts: u64,
    /// Recent failures (limited window).
    recent_failures: Vec<FailureRecord>,
    /// Last success timestamp.
    last_success: Option<Instant>,
    /// Consecutive failures.
    consecutive_failures: u32,
}

impl TargetStats {
    /// Calculate success rate (0.0 to 1.0).
    #[must_use]
    #[inline]
    fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.5; // Assume 50% for unknown targets
        }
        self.successful_attempts as f64 / self.total_attempts as f64
    }

    /// Get the most common recent failure type.
    #[must_use]
    #[inline]
    fn dominant_failure_type(&self) -> Option<FailureType> {
        let mut counts: HashMap<FailureType, usize> = HashMap::new();
        for record in &self.recent_failures {
            *counts.entry(record.failure_type).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(failure_type, _)| failure_type)
    }

    /// Check if the target is currently experiencing issues.
    #[must_use]
    #[inline]
    fn is_having_issues(&self) -> bool {
        self.consecutive_failures > 3 || self.success_rate() < 0.3
    }
}

/// Adaptive retry policy that learns from failure patterns.
pub struct AdaptiveRetryPolicy {
    /// Per-target statistics.
    target_stats: Arc<Mutex<HashMap<String, TargetStats>>>,
    /// Base retry configuration.
    base_config: RetryConfig,
    /// Failure history retention window.
    history_window: Duration,
}

impl AdaptiveRetryPolicy {
    /// Create a new adaptive retry policy.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            target_stats: Arc::new(Mutex::new(HashMap::new())),
            base_config: RetryConfig::default(),
            history_window: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new adaptive retry policy with custom base configuration.
    #[must_use]
    #[inline]
    pub fn with_config(base_config: RetryConfig) -> Self {
        Self {
            target_stats: Arc::new(Mutex::new(HashMap::new())),
            base_config,
            history_window: Duration::from_secs(300),
        }
    }

    /// Record a successful operation.
    pub fn record_success(&mut self, target: &str) {
        let mut stats = self.target_stats.lock().unwrap();
        let entry = stats.entry(target.to_string()).or_default();

        entry.total_attempts += 1;
        entry.successful_attempts += 1;
        entry.consecutive_failures = 0;
        entry.last_success = Some(Instant::now());
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self, target: &str, failure_type: FailureType) {
        let mut stats = self.target_stats.lock().unwrap();
        let entry = stats.entry(target.to_string()).or_default();

        entry.total_attempts += 1;
        entry.consecutive_failures += 1;
        entry.recent_failures.push(FailureRecord {
            failure_type,
            timestamp: Instant::now(),
        });

        // Cleanup old failures
        self.cleanup_old_failures(entry);
    }

    /// Clean up old failure records outside the history window.
    fn cleanup_old_failures(&self, stats: &mut TargetStats) {
        let cutoff = Instant::now() - self.history_window;
        stats.recent_failures.retain(|f| f.timestamp > cutoff);
    }

    /// Determine if a retry should be attempted.
    #[must_use]
    #[inline]
    pub fn should_retry(&self, target: &str, attempt: u32) -> bool {
        let stats = self.target_stats.lock().unwrap();

        // Check attempt limit
        if attempt >= self.base_config.max_attempts {
            return false;
        }

        // Get target stats if available
        if let Some(target_stats) = stats.get(target) {
            // Don't retry if too many consecutive failures (circuit breaker)
            if target_stats.consecutive_failures > 5 {
                return false;
            }

            // Don't retry non-retryable failure types
            if let Some(failure_type) = target_stats.dominant_failure_type() {
                if !failure_type.is_retryable() {
                    return false;
                }
            }
        }

        true
    }

    /// Calculate the recommended retry delay for a target.
    #[must_use]
    #[inline]
    pub fn retry_delay(&self, target: &str, attempt: u32) -> Duration {
        let base_delay = self.base_config.delay_for_attempt(attempt);
        let stats = self.target_stats.lock().unwrap();

        if let Some(target_stats) = stats.get(target) {
            // Adjust delay based on failure patterns
            let mut multiplier = 1.0;

            // Increase delay for targets with low success rate
            let success_rate = target_stats.success_rate();
            if success_rate < 0.5 {
                multiplier *= 1.5;
            } else if success_rate < 0.7 {
                multiplier *= 1.2;
            }

            // Apply failure type specific multiplier
            if let Some(failure_type) = target_stats.dominant_failure_type() {
                multiplier *= failure_type.retry_multiplier();
            }

            // Increase delay for consecutive failures (exponential)
            if target_stats.consecutive_failures > 2 {
                multiplier *= 1.5f64.powi(target_stats.consecutive_failures as i32 - 2);
            }

            Duration::from_millis((base_delay.as_millis() as f64 * multiplier) as u64)
                .min(Duration::from_millis(self.base_config.max_delay_ms))
        } else {
            base_delay
        }
    }

    /// Get the success rate for a target.
    #[must_use]
    #[inline]
    pub fn success_rate(&self, target: &str) -> f64 {
        let stats = self.target_stats.lock().unwrap();
        stats.get(target).map(|s| s.success_rate()).unwrap_or(0.5)
    }

    /// Get the number of consecutive failures for a target.
    #[must_use]
    #[inline]
    pub fn consecutive_failures(&self, target: &str) -> u32 {
        let stats = self.target_stats.lock().unwrap();
        stats
            .get(target)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    /// Check if a target is currently having issues.
    #[must_use]
    #[inline]
    pub fn is_target_having_issues(&self, target: &str) -> bool {
        let stats = self.target_stats.lock().unwrap();
        stats
            .get(target)
            .map(|s| s.is_having_issues())
            .unwrap_or(false)
    }

    /// Get recommended retry config for a specific target.
    #[must_use]
    #[inline]
    pub fn recommended_config(&self, target: &str) -> RetryConfig {
        let stats = self.target_stats.lock().unwrap();

        if let Some(target_stats) = stats.get(target) {
            let success_rate = target_stats.success_rate();

            // Adapt retry strategy based on success rate
            if success_rate > 0.8 {
                // High success rate: use aggressive retries
                RetryConfig::aggressive()
            } else if success_rate > 0.5 {
                // Moderate success rate: use default
                self.base_config.clone()
            } else {
                // Low success rate: use conservative retries
                RetryConfig::conservative()
            }
        } else {
            // Unknown target: use default
            self.base_config.clone()
        }
    }

    /// Reset statistics for a target.
    pub fn reset_target(&mut self, target: &str) {
        let mut stats = self.target_stats.lock().unwrap();
        stats.remove(target);
    }

    /// Clear all statistics.
    pub fn reset_all(&mut self) {
        let mut stats = self.target_stats.lock().unwrap();
        stats.clear();
    }

    /// Get total number of tracked targets.
    #[must_use]
    #[inline]
    pub fn tracked_targets_count(&self) -> usize {
        let stats = self.target_stats.lock().unwrap();
        stats.len()
    }

    /// Detect if there's a burst of failures (many failures in short time).
    #[must_use]
    #[inline]
    pub fn detect_failure_burst(&self, target: &str) -> bool {
        let stats = self.target_stats.lock().unwrap();

        if let Some(target_stats) = stats.get(target) {
            // Check for 5+ failures in the last minute
            let one_minute_ago = Instant::now() - Duration::from_secs(60);
            let recent_count = target_stats
                .recent_failures
                .iter()
                .filter(|f| f.timestamp > one_minute_ago)
                .count();

            return recent_count >= 5;
        }

        false
    }

    /// Get the average time between failures for pattern detection.
    #[must_use]
    #[inline]
    pub fn failure_interval(&self, target: &str) -> Option<Duration> {
        let stats = self.target_stats.lock().unwrap();

        if let Some(target_stats) = stats.get(target) {
            if target_stats.recent_failures.len() < 2 {
                return None;
            }

            let failures = &target_stats.recent_failures;
            let mut intervals = Vec::new();

            for i in 1..failures.len() {
                let interval = failures[i]
                    .timestamp
                    .saturating_duration_since(failures[i - 1].timestamp);
                intervals.push(interval);
            }

            if intervals.is_empty() {
                return None;
            }

            // Calculate average interval
            let total: Duration = intervals.iter().sum();
            Some(total / intervals.len() as u32)
        } else {
            None
        }
    }

    /// Predict when the target might recover based on past recovery patterns.
    #[must_use]
    #[inline]
    pub fn predict_recovery_time(&self, target: &str) -> Option<Duration> {
        let stats = self.target_stats.lock().unwrap();

        if let Some(target_stats) = stats.get(target) {
            if let Some(last_success) = target_stats.last_success {
                let time_since_success = Instant::now().saturating_duration_since(last_success);

                // If we have consecutive failures, estimate recovery time
                if target_stats.consecutive_failures > 0 {
                    // Simple heuristic: double the time since last success
                    // In production, this could use ML or historical patterns
                    let estimated_recovery = time_since_success * 2;
                    return Some(estimated_recovery);
                }
            }

            // If no success history, estimate based on failure rate
            if !target_stats.recent_failures.is_empty() {
                return Some(Duration::from_secs(60)); // Default 1 minute
            }
        }

        None
    }

    /// Get failure pattern statistics for a target.
    #[must_use]
    #[inline]
    pub fn failure_patterns(&self, target: &str) -> Option<FailurePatterns> {
        let stats = self.target_stats.lock().unwrap();

        stats.get(target).map(|target_stats| {
            let mut type_counts: HashMap<FailureType, usize> = HashMap::new();
            for record in &target_stats.recent_failures {
                *type_counts.entry(record.failure_type).or_insert(0) += 1;
            }

            // Calculate is_burst inline to avoid re-acquiring lock
            let one_minute_ago = Instant::now() - Duration::from_secs(60);
            let recent_count = target_stats
                .recent_failures
                .iter()
                .filter(|f| f.timestamp > one_minute_ago)
                .count();
            let is_burst = recent_count >= 5;

            FailurePatterns {
                total_failures: target_stats.recent_failures.len(),
                failure_types: type_counts,
                consecutive_failures: target_stats.consecutive_failures,
                success_rate: target_stats.success_rate(),
                is_burst,
                dominant_type: target_stats.dominant_failure_type(),
            }
        })
    }
}

/// Failure pattern statistics for a specific target.
#[derive(Debug, Clone)]
pub struct FailurePatterns {
    /// Total failures in the history window.
    pub total_failures: usize,
    /// Count of each failure type.
    pub failure_types: HashMap<FailureType, usize>,
    /// Current consecutive failures.
    pub consecutive_failures: u32,
    /// Success rate (0.0 to 1.0).
    pub success_rate: f64,
    /// Whether a failure burst is detected.
    pub is_burst: bool,
    /// Most common failure type.
    pub dominant_type: Option<FailureType>,
}

impl FailurePatterns {
    /// Check if the pattern indicates a systemic issue.
    #[must_use]
    #[inline]
    pub fn is_systemic_issue(&self) -> bool {
        self.consecutive_failures > 5 || self.success_rate < 0.2 || self.is_burst
    }

    /// Get the percentage of a specific failure type.
    #[must_use]
    #[inline]
    pub fn failure_type_percentage(&self, failure_type: FailureType) -> f64 {
        if self.total_failures == 0 {
            return 0.0;
        }
        let count = self.failure_types.get(&failure_type).copied().unwrap_or(0);
        count as f64 / self.total_failures as f64
    }
}

impl Default for AdaptiveRetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_type_retryable() {
        assert!(FailureType::Timeout.is_retryable());
        assert!(FailureType::ConnectionFailed.is_retryable());
        assert!(!FailureType::RateLimited.is_retryable());
    }

    #[test]
    fn test_adaptive_policy_success_rate() {
        let mut policy = AdaptiveRetryPolicy::new();

        policy.record_success("peer1");
        policy.record_success("peer1");
        policy.record_failure("peer1", FailureType::Timeout);

        let rate = policy.success_rate("peer1");
        assert!((rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_should_retry_after_max_attempts() {
        let policy = AdaptiveRetryPolicy::new();
        assert!(!policy.should_retry("peer1", 10));
    }

    #[test]
    fn test_consecutive_failures_tracking() {
        let mut policy = AdaptiveRetryPolicy::new();

        policy.record_failure("peer1", FailureType::Timeout);
        policy.record_failure("peer1", FailureType::Timeout);

        assert_eq!(policy.consecutive_failures("peer1"), 2);

        policy.record_success("peer1");
        assert_eq!(policy.consecutive_failures("peer1"), 0);
    }

    #[test]
    fn test_recommended_config_adapts() {
        let mut policy = AdaptiveRetryPolicy::new();

        // Record high success rate
        for _ in 0..10 {
            policy.record_success("peer1");
        }
        policy.record_failure("peer1", FailureType::Timeout);

        let config = policy.recommended_config("peer1");
        // High success rate should give aggressive retries
        assert!(config.max_attempts >= 5);
    }

    #[test]
    fn test_target_having_issues() {
        let mut policy = AdaptiveRetryPolicy::new();

        // Record many failures
        for _ in 0..5 {
            policy.record_failure("peer1", FailureType::Timeout);
        }

        assert!(policy.is_target_having_issues("peer1"));
    }

    #[test]
    fn test_reset_target() {
        let mut policy = AdaptiveRetryPolicy::new();

        policy.record_failure("peer1", FailureType::Timeout);
        assert_eq!(policy.consecutive_failures("peer1"), 1);

        policy.reset_target("peer1");
        assert_eq!(policy.consecutive_failures("peer1"), 0);
    }

    #[test]
    fn test_failure_burst_detection() {
        let mut policy = AdaptiveRetryPolicy::new();

        // Record 6 failures in quick succession
        for _ in 0..6 {
            policy.record_failure("peer1", FailureType::Timeout);
        }

        assert!(policy.detect_failure_burst("peer1"));

        // Different peer should not show burst
        assert!(!policy.detect_failure_burst("peer2"));
    }

    #[test]
    fn test_failure_patterns() {
        let mut policy = AdaptiveRetryPolicy::new();

        // Record mixed failures
        policy.record_failure("peer1", FailureType::Timeout);
        policy.record_failure("peer1", FailureType::Timeout);
        policy.record_failure("peer1", FailureType::ConnectionFailed);
        policy.record_success("peer1");

        let patterns = policy.failure_patterns("peer1");
        assert!(patterns.is_some());

        let patterns = patterns.unwrap();
        assert_eq!(patterns.total_failures, 3);
        assert_eq!(patterns.dominant_type, Some(FailureType::Timeout));
        assert_eq!(
            patterns.failure_type_percentage(FailureType::Timeout),
            2.0 / 3.0
        );
    }

    #[test]
    fn test_systemic_issue_detection() {
        let mut policy = AdaptiveRetryPolicy::new();

        // Record many consecutive failures
        for _ in 0..7 {
            policy.record_failure("peer1", FailureType::ServerError);
        }

        let patterns = policy.failure_patterns("peer1").unwrap();
        assert!(patterns.is_systemic_issue());
    }

    #[test]
    fn test_predict_recovery_time() {
        let mut policy = AdaptiveRetryPolicy::new();

        policy.record_success("peer1");
        std::thread::sleep(Duration::from_millis(10));
        policy.record_failure("peer1", FailureType::Timeout);

        let recovery = policy.predict_recovery_time("peer1");
        assert!(recovery.is_some());
    }

    #[test]
    fn test_failure_interval() {
        let mut policy = AdaptiveRetryPolicy::new();

        policy.record_failure("peer1", FailureType::Timeout);
        std::thread::sleep(Duration::from_millis(10));
        policy.record_failure("peer1", FailureType::Timeout);

        let interval = policy.failure_interval("peer1");
        assert!(interval.is_some());
    }
}
