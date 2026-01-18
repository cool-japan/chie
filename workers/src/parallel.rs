//! Parallel job processing for CHIE Protocol workers.
//!
//! This module provides:
//! - Worker pools with configurable concurrency
//! - Parallel job processing with backpressure
//! - Graceful shutdown and job draining

use crate::queue::{Job, JobQueue, QueueConfig, QueueError};
use serde::{Serialize, de::DeserializeOwned};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Configuration for the worker pool.
#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    /// Maximum number of concurrent workers.
    pub max_concurrency: usize,
    /// Queue polling interval when idle (milliseconds).
    pub poll_interval_ms: u64,
    /// Graceful shutdown timeout (seconds).
    pub shutdown_timeout_secs: u64,
    /// Whether to enable backpressure.
    pub backpressure_enabled: bool,
    /// Maximum jobs to buffer before applying backpressure.
    pub backpressure_threshold: usize,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            poll_interval_ms: 100,
            shutdown_timeout_secs: 30,
            backpressure_enabled: true,
            backpressure_threshold: 100,
        }
    }
}

/// Statistics for the worker pool.
#[derive(Debug, Clone, Default)]
pub struct WorkerPoolStats {
    /// Total jobs processed.
    pub total_processed: u64,
    /// Jobs currently processing.
    pub active_workers: usize,
    /// Jobs completed successfully.
    pub completed: u64,
    /// Jobs that failed.
    pub failed: u64,
    /// Jobs that were retried.
    pub retried: u64,
}

/// A shared-state worker pool statistics tracker.
#[derive(Debug)]
pub struct SharedStats {
    total_processed: AtomicUsize,
    active_workers: AtomicUsize,
    completed: AtomicUsize,
    failed: AtomicUsize,
    retried: AtomicUsize,
}

impl SharedStats {
    /// Create new shared stats.
    pub fn new() -> Self {
        Self {
            total_processed: AtomicUsize::new(0),
            active_workers: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            retried: AtomicUsize::new(0),
        }
    }

    /// Increment active workers.
    pub fn start_job(&self) {
        self.active_workers.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement active workers and record result.
    pub fn finish_job(&self, success: bool, retry: bool) {
        self.active_workers.fetch_sub(1, Ordering::SeqCst);
        self.total_processed.fetch_add(1, Ordering::SeqCst);
        if success {
            self.completed.fetch_add(1, Ordering::SeqCst);
        } else if retry {
            self.retried.fetch_add(1, Ordering::SeqCst);
        } else {
            self.failed.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Get current stats snapshot.
    pub fn snapshot(&self) -> WorkerPoolStats {
        WorkerPoolStats {
            total_processed: self.total_processed.load(Ordering::SeqCst) as u64,
            active_workers: self.active_workers.load(Ordering::SeqCst),
            completed: self.completed.load(Ordering::SeqCst) as u64,
            failed: self.failed.load(Ordering::SeqCst) as u64,
            retried: self.retried.load(Ordering::SeqCst) as u64,
        }
    }
}

impl Default for SharedStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A parallel worker pool that processes jobs concurrently.
pub struct WorkerPool<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + Clone + 'static,
    F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    config: WorkerPoolConfig,
    redis_url: String,
    queue_name: String,
    handler: F,
    stats: Arc<SharedStats>,
    shutdown: Arc<AtomicBool>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, F, Fut> WorkerPool<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + Clone + 'static,
    F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    /// Create a new worker pool.
    pub fn new(
        redis_url: impl Into<String>,
        queue_name: impl Into<String>,
        handler: F,
        config: WorkerPoolConfig,
    ) -> Self {
        Self {
            config,
            redis_url: redis_url.into(),
            queue_name: queue_name.into(),
            handler,
            stats: Arc::new(SharedStats::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get shared statistics.
    pub fn stats(&self) -> Arc<SharedStats> {
        Arc::clone(&self.stats)
    }

    /// Get a shutdown handle.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown: Arc::clone(&self.shutdown),
        }
    }

    /// Run the worker pool (consumes self).
    pub async fn run(self) -> Result<(), QueueError> {
        info!(
            "Starting worker pool: queue={}, concurrency={}",
            self.queue_name, self.config.max_concurrency
        );

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrency));
        let (job_tx, mut job_rx) = mpsc::channel::<Job<T>>(self.config.backpressure_threshold);

        // Spawn the job fetcher
        let redis_url = self.redis_url.clone();
        let queue_name = self.queue_name.clone();
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);
        let shutdown_clone = Arc::clone(&self.shutdown);

        let fetcher_handle = tokio::spawn(async move {
            let mut queue = match JobQueue::new(&redis_url, QueueConfig::default()).await {
                Ok(q) => q,
                Err(e) => {
                    error!("Failed to connect to Redis: {}", e);
                    return;
                }
            };

            loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    debug!("Fetcher received shutdown signal");
                    break;
                }

                match queue.dequeue::<T>(&queue_name).await {
                    Ok(Some(job)) => {
                        debug!("Fetched job: {}", job.id);
                        if job_tx.send(job).await.is_err() {
                            debug!("Job channel closed, stopping fetcher");
                            break;
                        }
                    }
                    Ok(None) => {
                        // Queue is empty, wait before polling
                        sleep(poll_interval).await;
                    }
                    Err(e) => {
                        error!("Error fetching job: {}", e);
                        sleep(poll_interval).await;
                    }
                }
            }
        });

        // Process jobs as they arrive
        while let Some(job) = job_rx.recv().await {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("Shutdown requested, draining remaining jobs");
                break;
            }

            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let handler = self.handler.clone();
            let stats = Arc::clone(&self.stats);
            let redis_url = self.redis_url.clone();
            let queue_name = self.queue_name.clone();

            tokio::spawn(async move {
                stats.start_job();
                let job_id = job.id;
                let result = handler(job.payload.clone()).await;

                // Update job status in queue
                match JobQueue::new(&redis_url, QueueConfig::default()).await {
                    Ok(mut queue) => {
                        let mut job = job;
                        match result {
                            Ok(()) => {
                                if let Err(e) = queue.complete(&queue_name, &mut job).await {
                                    error!("Failed to mark job {} as complete: {}", job_id, e);
                                }
                                stats.finish_job(true, false);
                                debug!("Job {} completed successfully", job_id);
                            }
                            Err(error) => match queue.fail(&queue_name, &mut job, &error).await {
                                Ok(will_retry) => {
                                    stats.finish_job(false, will_retry);
                                    if will_retry {
                                        warn!("Job {} failed, will retry: {}", job_id, error);
                                    } else {
                                        error!("Job {} failed permanently: {}", job_id, error);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to mark job {} as failed: {}", job_id, e);
                                    stats.finish_job(false, false);
                                }
                            },
                        }
                    }
                    Err(e) => {
                        error!("Failed to connect to Redis: {}", e);
                        stats.finish_job(false, false);
                    }
                }

                drop(permit);
            });
        }

        // Wait for in-flight jobs to complete
        info!("Waiting for in-flight jobs to complete");
        let timeout = Duration::from_secs(self.config.shutdown_timeout_secs);
        let start = std::time::Instant::now();

        while self.stats.snapshot().active_workers > 0 {
            if start.elapsed() > timeout {
                warn!(
                    "Shutdown timeout reached with {} active workers",
                    self.stats.snapshot().active_workers
                );
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }

        // Cancel the fetcher
        fetcher_handle.abort();

        info!("Worker pool shutdown complete");
        Ok(())
    }
}

/// Handle for requesting shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Request graceful shutdown.
    pub fn shutdown(&self) {
        info!("Shutdown requested");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

/// Spawn multiple worker pools for different queues.
pub struct MultiQueueWorkerPool {
    handles: Vec<tokio::task::JoinHandle<Result<(), QueueError>>>,
    shutdown_handles: Vec<ShutdownHandle>,
}

impl MultiQueueWorkerPool {
    /// Create a new multi-queue worker pool.
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            shutdown_handles: Vec::new(),
        }
    }

    /// Add and spawn a worker pool for a queue.
    ///
    /// The worker pool is started immediately and runs in the background.
    pub fn spawn_pool<T, F, Fut>(&mut self, pool: WorkerPool<T, F, Fut>)
    where
        T: DeserializeOwned + Serialize + Send + Sync + Clone + 'static,
        F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let shutdown_handle = pool.shutdown_handle();
        self.shutdown_handles.push(shutdown_handle);

        let handle = tokio::spawn(async move { pool.run().await });
        self.handles.push(handle);
    }

    /// Shutdown all worker pools gracefully.
    pub async fn shutdown_all(&self) {
        info!("Shutting down all worker pools");
        for handle in &self.shutdown_handles {
            handle.shutdown();
        }
    }

    /// Wait for all worker pools to complete.
    pub async fn wait_all(self) -> Vec<Result<Result<(), QueueError>, tokio::task::JoinError>> {
        let mut results = Vec::with_capacity(self.handles.len());
        for handle in self.handles {
            results.push(handle.await);
        }
        results
    }
}

impl Default for MultiQueueWorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating worker pools with common patterns.
pub struct WorkerPoolBuilder<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + Clone + 'static,
    F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    redis_url: String,
    queue_name: String,
    handler: F,
    config: WorkerPoolConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, F, Fut> WorkerPoolBuilder<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + Clone + 'static,
    F: Fn(T) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    /// Create a new builder.
    pub fn new(redis_url: impl Into<String>, queue_name: impl Into<String>, handler: F) -> Self {
        Self {
            redis_url: redis_url.into(),
            queue_name: queue_name.into(),
            handler,
            config: WorkerPoolConfig::default(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set the maximum concurrency.
    pub fn concurrency(mut self, max: usize) -> Self {
        self.config.max_concurrency = max;
        self
    }

    /// Set the poll interval.
    pub fn poll_interval(mut self, ms: u64) -> Self {
        self.config.poll_interval_ms = ms;
        self
    }

    /// Set the shutdown timeout.
    pub fn shutdown_timeout(mut self, secs: u64) -> Self {
        self.config.shutdown_timeout_secs = secs;
        self
    }

    /// Enable or disable backpressure.
    pub fn backpressure(mut self, enabled: bool) -> Self {
        self.config.backpressure_enabled = enabled;
        self
    }

    /// Set the backpressure threshold.
    pub fn backpressure_threshold(mut self, threshold: usize) -> Self {
        self.config.backpressure_threshold = threshold;
        self
    }

    /// Build the worker pool.
    pub fn build(self) -> WorkerPool<T, F, Fut> {
        WorkerPool::new(self.redis_url, self.queue_name, self.handler, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = WorkerPoolConfig::default();
        assert_eq!(config.max_concurrency, 4);
        assert_eq!(config.poll_interval_ms, 100);
        assert!(config.backpressure_enabled);
    }

    #[test]
    fn test_shared_stats() {
        let stats = SharedStats::new();

        stats.start_job();
        assert_eq!(stats.snapshot().active_workers, 1);

        stats.finish_job(true, false);
        assert_eq!(stats.snapshot().active_workers, 0);
        assert_eq!(stats.snapshot().completed, 1);
        assert_eq!(stats.snapshot().total_processed, 1);
    }

    #[test]
    fn test_shutdown_handle() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = ShutdownHandle {
            shutdown: Arc::clone(&shutdown),
        };

        assert!(!handle.is_shutdown());
        handle.shutdown();
        assert!(handle.is_shutdown());
    }
}
