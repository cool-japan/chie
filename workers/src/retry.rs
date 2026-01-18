//! Retry logic with exponential backoff for CHIE workers.
//!
//! This module provides:
//! - Configurable retry policies
//! - Exponential backoff with jitter
//! - Retry context for tracking attempts

use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, warn};

/// Retry error types.
#[derive(Debug, Error)]
pub enum RetryError<E> {
    #[error("Operation failed after {attempts} attempts: {source}")]
    MaxRetriesExceeded { attempts: u32, source: E },

    #[error("Operation failed: {0}")]
    OperationFailed(E),
}

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial delay before first retry (milliseconds).
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (milliseconds).
    pub max_delay_ms: u64,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
    /// Add random jitter to delays.
    pub use_jitter: bool,
    /// Maximum jitter ratio (0.0 to 1.0).
    pub jitter_ratio: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 30_000, // 30 seconds
            backoff_multiplier: 2.0,
            use_jitter: true,
            jitter_ratio: 0.25,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum retries.
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Set initial delay.
    pub fn initial_delay(mut self, ms: u64) -> Self {
        self.initial_delay_ms = ms;
        self
    }

    /// Set maximum delay.
    pub fn max_delay(mut self, ms: u64) -> Self {
        self.max_delay_ms = ms;
        self
    }

    /// Set backoff multiplier.
    pub fn multiplier(mut self, m: f64) -> Self {
        self.backoff_multiplier = m;
        self
    }

    /// Enable or disable jitter.
    pub fn jitter(mut self, enabled: bool) -> Self {
        self.use_jitter = enabled;
        self
    }

    /// Calculate delay for a given attempt number.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay =
            self.initial_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32);
        let capped_delay = base_delay.min(self.max_delay_ms as f64);

        let final_delay = if self.use_jitter {
            let jitter_range = capped_delay * self.jitter_ratio;
            let jitter = rand::random::<f64>() * jitter_range * 2.0 - jitter_range;
            (capped_delay + jitter).max(0.0)
        } else {
            capped_delay
        };

        Duration::from_millis(final_delay as u64)
    }
}

/// Context for tracking retry attempts.
#[derive(Debug, Clone)]
pub struct RetryContext {
    /// Current attempt number (0-indexed).
    pub attempt: u32,
    /// Maximum attempts.
    pub max_attempts: u32,
    /// Total time spent in retries.
    pub total_delay: Duration,
    /// Configuration.
    pub config: RetryConfig,
}

impl RetryContext {
    /// Create a new retry context.
    pub fn new(config: RetryConfig) -> Self {
        Self {
            attempt: 0,
            max_attempts: config.max_retries + 1, // +1 for initial attempt
            total_delay: Duration::ZERO,
            config,
        }
    }

    /// Check if we should continue retrying.
    pub fn should_retry(&self) -> bool {
        self.attempt < self.max_attempts
    }

    /// Get the current attempt number (1-indexed for display).
    pub fn current_attempt(&self) -> u32 {
        self.attempt + 1
    }

    /// Get remaining attempts.
    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.attempt)
    }

    /// Record an attempt and return the delay before next retry.
    pub fn record_attempt(&mut self) -> Duration {
        let delay = self.config.delay_for_attempt(self.attempt);
        self.attempt += 1;
        self.total_delay += delay;
        delay
    }
}

/// Execute an async operation with retry.
pub async fn retry<F, Fut, T, E>(config: RetryConfig, mut operation: F) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut ctx = RetryContext::new(config);

    loop {
        match operation().await {
            Ok(value) => {
                if ctx.attempt > 0 {
                    debug!(
                        "Operation succeeded after {} attempts (total delay: {:?})",
                        ctx.current_attempt(),
                        ctx.total_delay
                    );
                }
                return Ok(value);
            }
            Err(e) => {
                let delay = ctx.record_attempt();

                if !ctx.should_retry() {
                    warn!("Operation failed after {} attempts: {}", ctx.attempt, e);
                    return Err(RetryError::MaxRetriesExceeded {
                        attempts: ctx.attempt,
                        source: e,
                    });
                }

                warn!(
                    "Attempt {} failed: {}. Retrying in {:?} ({} attempts remaining)",
                    ctx.attempt,
                    e,
                    delay,
                    ctx.remaining_attempts()
                );

                sleep(delay).await;
            }
        }
    }
}

/// Execute an async operation with retry, passing context to the operation.
pub async fn retry_with_context<F, Fut, T, E>(
    config: RetryConfig,
    mut operation: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut(&RetryContext) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut ctx = RetryContext::new(config);

    loop {
        match operation(&ctx).await {
            Ok(value) => {
                if ctx.attempt > 0 {
                    debug!(
                        "Operation succeeded after {} attempts (total delay: {:?})",
                        ctx.current_attempt(),
                        ctx.total_delay
                    );
                }
                return Ok(value);
            }
            Err(e) => {
                let delay = ctx.record_attempt();

                if !ctx.should_retry() {
                    warn!("Operation failed after {} attempts: {}", ctx.attempt, e);
                    return Err(RetryError::MaxRetriesExceeded {
                        attempts: ctx.attempt,
                        source: e,
                    });
                }

                warn!(
                    "Attempt {} failed: {}. Retrying in {:?} ({} attempts remaining)",
                    ctx.attempt,
                    e,
                    delay,
                    ctx.remaining_attempts()
                );

                sleep(delay).await;
            }
        }
    }
}

/// Retry policy that determines if an error should trigger a retry.
pub trait RetryPolicy<E> {
    /// Check if the error should trigger a retry.
    fn should_retry(&self, error: &E) -> bool;
}

/// Always retry policy - retries on all errors.
pub struct AlwaysRetry;

impl<E> RetryPolicy<E> for AlwaysRetry {
    fn should_retry(&self, _error: &E) -> bool {
        true
    }
}

/// Never retry policy - never retries.
pub struct NeverRetry;

impl<E> RetryPolicy<E> for NeverRetry {
    fn should_retry(&self, _error: &E) -> bool {
        false
    }
}

/// Custom retry policy using a closure.
pub struct CustomRetryPolicy<F> {
    predicate: F,
}

impl<F, E> RetryPolicy<E> for CustomRetryPolicy<F>
where
    F: Fn(&E) -> bool,
{
    fn should_retry(&self, error: &E) -> bool {
        (self.predicate)(error)
    }
}

/// Create a custom retry policy from a closure.
pub fn custom_policy<F, E>(predicate: F) -> CustomRetryPolicy<F>
where
    F: Fn(&E) -> bool,
{
    CustomRetryPolicy { predicate }
}

/// Execute an async operation with retry and a policy.
pub async fn retry_with_policy<F, Fut, T, E, P>(
    config: RetryConfig,
    policy: P,
    mut operation: F,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
    P: RetryPolicy<E>,
{
    let mut ctx = RetryContext::new(config);

    loop {
        match operation().await {
            Ok(value) => {
                if ctx.attempt > 0 {
                    debug!(
                        "Operation succeeded after {} attempts (total delay: {:?})",
                        ctx.current_attempt(),
                        ctx.total_delay
                    );
                }
                return Ok(value);
            }
            Err(e) => {
                if !policy.should_retry(&e) {
                    return Err(RetryError::OperationFailed(e));
                }

                let delay = ctx.record_attempt();

                if !ctx.should_retry() {
                    warn!("Operation failed after {} attempts: {}", ctx.attempt, e);
                    return Err(RetryError::MaxRetriesExceeded {
                        attempts: ctx.attempt,
                        source: e,
                    });
                }

                warn!(
                    "Attempt {} failed: {}. Retrying in {:?} ({} attempts remaining)",
                    ctx.attempt,
                    e,
                    delay,
                    ctx.remaining_attempts()
                );

                sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig::new()
            .initial_delay(100)
            .multiplier(2.0)
            .max_delay(10_000)
            .jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_delay_capping() {
        let config = RetryConfig::new()
            .initial_delay(1000)
            .multiplier(10.0)
            .max_delay(5000)
            .jitter(false);

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(5000)); // Capped
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(5000)); // Capped
    }

    #[tokio::test]
    async fn test_retry_success_first_attempt() {
        let config = RetryConfig::new().max_retries(3);

        let result: Result<i32, RetryError<&str>> = retry(config, || async { Ok(42) }).await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let config = RetryConfig::new()
            .max_retries(3)
            .initial_delay(10)
            .jitter(false);

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: Result<i32, RetryError<&str>> = retry(config, || {
            let c = counter_clone.clone();
            async move {
                let attempt = c.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 { Err("not yet") } else { Ok(42) }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let config = RetryConfig::new()
            .max_retries(2)
            .initial_delay(10)
            .jitter(false);

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: Result<i32, RetryError<&str>> = retry(config, || {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err("always fails")
            }
        })
        .await;

        match result {
            Err(RetryError::MaxRetriesExceeded { attempts, .. }) => {
                assert_eq!(attempts, 3); // Initial + 2 retries
            }
            _ => panic!("Expected MaxRetriesExceeded"),
        }

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_with_policy() {
        let config = RetryConfig::new()
            .max_retries(3)
            .initial_delay(10)
            .jitter(false);

        // Only retry on specific errors
        let policy = custom_policy(|e: &&str| *e == "retryable");

        let result: Result<i32, RetryError<&str>> =
            retry_with_policy(config, policy, || async { Err("not retryable") }).await;

        // Should fail immediately without retrying
        match result {
            Err(RetryError::OperationFailed(e)) => {
                assert_eq!(e, "not retryable");
            }
            _ => panic!("Expected OperationFailed"),
        }
    }
}
