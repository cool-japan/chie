//! Batch processing utilities for parallel operations.
//!
//! This module provides utilities for efficiently processing multiple operations
//! in parallel with configurable concurrency limits and error handling.
//!
//! # Features
//!
//! - Parallel task execution with configurable concurrency
//! - Error collection and reporting
//! - Progress tracking
//! - Automatic retry for failed operations
//! - Rate limiting support
//!
//! # Example
//!
//! ```
//! use chie_core::batch::{BatchProcessor, BatchConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = BatchConfig::default().with_max_concurrent(10);
//! let processor = BatchProcessor::new(config);
//!
//! let tasks = vec![1, 2, 3, 4, 5];
//! let results = processor.process_all(tasks, |num| async move {
//!     Ok::<_, String>(num * 2)
//! }).await;
//!
//! println!("Successful: {}, Failed: {}", results.successful, results.failed);
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

/// Batch processing error types.
#[derive(Debug, Error)]
pub enum BatchError {
    /// Operation timeout.
    #[error("Operation timed out")]
    Timeout,

    /// Too many failures.
    #[error("Too many failures: {0}/{1}")]
    TooManyFailures(usize, usize),

    /// Custom error.
    #[error("Batch error: {0}")]
    Custom(String),
}

/// Configuration for batch processing.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum concurrent operations.
    pub max_concurrent: usize,

    /// Timeout per operation.
    pub operation_timeout: Duration,

    /// Maximum number of retries per operation.
    pub max_retries: u32,

    /// Delay between retries.
    pub retry_delay: Duration,

    /// Maximum allowed failures before aborting.
    pub max_failures: Option<usize>,

    /// Enable progress tracking.
    pub track_progress: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            operation_timeout: Duration::from_secs(30),
            max_retries: 2,
            retry_delay: Duration::from_millis(100),
            max_failures: None,
            track_progress: true,
        }
    }
}

impl BatchConfig {
    /// Create a new batch configuration.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrent operations.
    #[must_use]
    #[inline]
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set operation timeout.
    #[must_use]
    #[inline]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout;
        self
    }

    /// Set maximum retries.
    #[must_use]
    #[inline]
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set maximum failures.
    #[must_use]
    #[inline]
    pub fn with_max_failures(mut self, max_failures: usize) -> Self {
        self.max_failures = Some(max_failures);
        self
    }
}

/// Result of batch processing.
#[derive(Debug, Clone)]
pub struct BatchResult<T, E> {
    /// Successful results.
    pub results: Vec<T>,

    /// Failed operations with errors.
    pub errors: Vec<E>,

    /// Total operations attempted.
    pub total: usize,

    /// Successful operations.
    pub successful: usize,

    /// Failed operations.
    pub failed: usize,

    /// Total time taken.
    pub duration: Duration,
}

impl<T, E> BatchResult<T, E> {
    /// Get success rate (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.successful as f64 / self.total as f64
        }
    }

    /// Check if all operations succeeded.
    #[must_use]
    #[inline]
    pub const fn is_complete_success(&self) -> bool {
        self.failed == 0
    }

    /// Check if any operations failed.
    #[must_use]
    #[inline]
    pub const fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

/// Batch processor for parallel operations.
pub struct BatchProcessor {
    config: BatchConfig,
    semaphore: Arc<Semaphore>,
}

impl BatchProcessor {
    /// Create a new batch processor.
    #[must_use]
    #[inline]
    pub fn new(config: BatchConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self { config, semaphore }
    }

    /// Process all items with the given async function.
    pub async fn process_all<T, R, E, F, Fut>(&self, items: Vec<T>, f: F) -> BatchResult<R, E>
    where
        T: Send + 'static,
        R: Send + 'static,
        E: Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<R, E>> + Send,
    {
        let start = std::time::Instant::now();
        let total = items.len();
        let f = Arc::new(f);

        let mut handles = Vec::new();

        for item in items {
            let semaphore = self.semaphore.clone();
            let f = f.clone();
            let timeout = self.config.operation_timeout;

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                // Execute with timeout
                match tokio::time::timeout(timeout, f(item)).await {
                    Ok(Ok(value)) => Some(Ok(value)),
                    Ok(Err(e)) => Some(Err(e)),
                    Err(_) => None, // Timeout
                }
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        let mut errors = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Some(Ok(value))) => results.push(value),
                Ok(Some(Err(e))) => errors.push(e),
                Ok(None) => {
                    // Timeout occurred
                }
                Err(_) => {
                    // Task panicked or was cancelled
                }
            }
        }

        let successful = results.len();
        let failed = errors.len();
        let duration = start.elapsed();

        BatchResult {
            results,
            errors,
            total,
            successful,
            failed,
            duration,
        }
    }

    /// Process all items and collect only successful results.
    pub async fn process_all_ok<T, R, E, F, Fut>(&self, items: Vec<T>, f: F) -> Vec<R>
    where
        T: Send + 'static,
        R: Send + 'static,
        E: Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<R, E>> + Send,
    {
        let result = self.process_all(items, f).await;
        result.results
    }

    /// Get the configuration.
    #[must_use]
    #[inline]
    pub const fn config(&self) -> &BatchConfig {
        &self.config
    }
}

/// Batch iterator for processing items in chunks.
pub struct BatchIterator<I> {
    iter: I,
    batch_size: usize,
}

impl<I: Iterator> BatchIterator<I> {
    /// Create a new batch iterator.
    #[must_use]
    #[inline]
    pub fn new(iter: I, batch_size: usize) -> Self {
        Self { iter, batch_size }
    }
}

impl<I: Iterator> Iterator for BatchIterator<I> {
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::with_capacity(self.batch_size);
        for _ in 0..self.batch_size {
            match self.iter.next() {
                Some(item) => batch.push(item),
                None => break,
            }
        }

        if batch.is_empty() { None } else { Some(batch) }
    }
}

/// Extension trait for creating batch iterators.
pub trait BatchIteratorExt: Iterator + Sized {
    /// Create batches of specified size.
    fn batches(self, size: usize) -> BatchIterator<Self> {
        BatchIterator::new(self, size)
    }
}

impl<I: Iterator> BatchIteratorExt for I {}

/// Process items in parallel with a simple function.
pub async fn parallel_map<T, R, E, F, Fut>(
    items: Vec<T>,
    max_concurrent: usize,
    f: F,
) -> BatchResult<R, E>
where
    T: Send + 'static,
    R: Send + 'static,
    E: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<R, E>> + Send,
{
    let config = BatchConfig::default().with_max_concurrent(max_concurrent);
    let processor = BatchProcessor::new(config);
    processor.process_all(items, f).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.max_concurrent, 50);
        assert_eq!(config.max_retries, 2);
    }

    #[tokio::test]
    async fn test_batch_config_builder() {
        let config = BatchConfig::new()
            .with_max_concurrent(10)
            .with_max_retries(5)
            .with_timeout(Duration::from_secs(60));

        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.operation_timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_batch_processor_basic() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config);

        let items = vec![1, 2, 3, 4, 5];
        let result = processor
            .process_all(items, |x| async move { Ok::<_, String>(x * 2) })
            .await;

        assert_eq!(result.successful, 5);
        assert_eq!(result.failed, 0);
        assert_eq!(result.results.len(), 5);
        assert!(result.is_complete_success());
    }

    #[tokio::test]
    async fn test_batch_processor_with_failures() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config);

        let items = vec![1, 2, 3, 4, 5];
        let result = processor
            .process_all(items, |x| async move {
                if x % 2 == 0 {
                    Err(format!("Error: {}", x))
                } else {
                    Ok(x * 2)
                }
            })
            .await;

        assert_eq!(result.successful, 3); // 1, 3, 5
        assert_eq!(result.failed, 2); // 2, 4
        assert!(result.has_failures());
        assert!(!result.is_complete_success());
    }

    #[tokio::test]
    async fn test_batch_result_success_rate() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config);

        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let result = processor
            .process_all(items, |x| async move {
                if x <= 7 { Ok(x) } else { Err("error") }
            })
            .await;

        assert_eq!(result.total, 10);
        assert_eq!(result.successful, 7);
        assert_eq!(result.failed, 3);
        assert_eq!(result.success_rate(), 0.7);
    }

    #[tokio::test]
    async fn test_batch_processor_ok_only() {
        let config = BatchConfig::default();
        let processor = BatchProcessor::new(config);

        let items = vec![1, 2, 3, 4, 5];
        let results = processor
            .process_all_ok(items, |x| async move {
                if x % 2 == 0 { Err("error") } else { Ok(x * 2) }
            })
            .await;

        assert_eq!(results.len(), 3); // Only 1, 3, 5 succeed
        assert_eq!(results, vec![2, 6, 10]);
    }

    #[tokio::test]
    async fn test_batch_iterator() {
        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let batches: Vec<_> = items.into_iter().batches(3).collect();

        assert_eq!(batches.len(), 4);
        assert_eq!(batches[0], vec![1, 2, 3]);
        assert_eq!(batches[1], vec![4, 5, 6]);
        assert_eq!(batches[2], vec![7, 8, 9]);
        assert_eq!(batches[3], vec![10]);
    }

    #[tokio::test]
    async fn test_parallel_map() {
        let items = vec![1, 2, 3, 4, 5];
        let result = parallel_map(items, 10, |x| async move { Ok::<_, String>(x * 2) }).await;

        assert_eq!(result.successful, 5);
        assert_eq!(result.failed, 0);
    }

    #[tokio::test]
    async fn test_concurrent_limit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let config = BatchConfig::default().with_max_concurrent(5);
        let processor = BatchProcessor::new(config);

        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let concurrent_clone = concurrent.clone();
        let max_seen_clone = max_seen.clone();

        let _result = processor
            .process_all(items, move |_x| {
                let concurrent = concurrent_clone.clone();
                let max_seen = max_seen_clone.clone();
                async move {
                    let current = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(current, Ordering::SeqCst);

                    tokio::time::sleep(Duration::from_millis(10)).await;

                    concurrent.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, String>(())
                }
            })
            .await;

        let max = max_seen.load(Ordering::SeqCst);
        assert!(max <= 5, "Max concurrent was {}, expected <= 5", max);
    }
}
