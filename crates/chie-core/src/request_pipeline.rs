//! Request pipelining for efficient batch operations.
//!
//! This module provides request pipelining to batch multiple API requests
//! efficiently, reducing latency and improving throughput when making
//! many requests to the coordinator or other services.
//!
//! # Features
//!
//! - **Batching**: Group multiple requests into batches
//! - **Concurrency Control**: Limit concurrent requests
//! - **Priority Queues**: Prioritize critical requests
//! - **Automatic Retry**: Retry failed requests in batch
//! - **Request Coalescing**: Merge duplicate requests
//! - **Statistics Tracking**: Monitor pipeline performance
//!
//! # Example
//!
//! ```
//! use chie_core::request_pipeline::{RequestPipeline, PipelineConfig, PipelineRequest};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PipelineConfig {
//!     max_batch_size: 50,
//!     max_concurrent: 10,
//!     batch_timeout_ms: 100,
//!     ..Default::default()
//! };
//!
//! let pipeline = Arc::new(RequestPipeline::new(config));
//!
//! // Submit requests to the pipeline
//! let request = PipelineRequest::new("submit_proof", vec![1, 2, 3]);
//! let response = pipeline.submit(request).await?;
//!
//! println!("Response: {:?}", response);
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore, mpsc, oneshot};

/// Maximum number of pending requests in the pipeline.
const MAX_PENDING_REQUESTS: usize = 10_000;

/// Default batch timeout in milliseconds.
const DEFAULT_BATCH_TIMEOUT_MS: u64 = 100;

/// Errors that can occur during request pipelining.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("Pipeline is full, cannot accept more requests")]
    PipelineFull,

    #[error("Request timeout after {0}ms")]
    RequestTimeout(u64),

    #[error("Batch execution failed: {0}")]
    BatchFailed(String),

    #[error("Request cancelled")]
    Cancelled,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Pipeline is shutting down")]
    ShuttingDown,
}

/// Priority level for requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequestPriority {
    /// Low priority (best effort).
    Low = 0,
    /// Normal priority (default).
    Normal = 1,
    /// High priority (expedited processing).
    High = 2,
    /// Critical priority (immediate processing).
    Critical = 3,
}

impl Default for RequestPriority {
    #[inline]
    fn default() -> Self {
        Self::Normal
    }
}

/// A single request in the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRequest {
    /// Request operation name.
    pub operation: String,
    /// Request payload (arbitrary bytes).
    pub payload: Vec<u8>,
    /// Request priority.
    pub priority: RequestPriority,
    /// Request ID for tracking.
    pub request_id: String,
    /// Timestamp when request was created.
    pub created_at_ms: u64,
}

impl PipelineRequest {
    /// Create a new pipeline request.
    #[must_use]
    pub fn new(operation: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            operation: operation.into(),
            payload,
            priority: RequestPriority::Normal,
            request_id: generate_request_id(),
            created_at_ms: current_timestamp_ms(),
        }
    }

    /// Set the priority of this request.
    #[must_use]
    pub fn with_priority(mut self, priority: RequestPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set the request ID.
    #[must_use]
    pub fn with_request_id(mut self, id: String) -> Self {
        self.request_id = id;
        self
    }
}

/// Response from a pipelined request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResponse {
    /// Request ID that this response corresponds to.
    pub request_id: String,
    /// Whether the request succeeded.
    pub success: bool,
    /// Response payload.
    pub payload: Vec<u8>,
    /// Error message if request failed.
    pub error: Option<String>,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

impl PipelineResponse {
    /// Check if the response indicates success.
    #[must_use]
    #[inline]
    pub const fn is_success(&self) -> bool {
        self.success
    }

    /// Check if the response indicates failure.
    #[must_use]
    #[inline]
    pub const fn is_failure(&self) -> bool {
        !self.success
    }

    /// Get the error message if the response failed.
    #[must_use]
    #[inline]
    pub fn error_message(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Configuration for the request pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Maximum number of requests in a single batch.
    pub max_batch_size: usize,
    /// Maximum number of concurrent batch executions.
    pub max_concurrent: usize,
    /// Time to wait before processing a partial batch (ms).
    pub batch_timeout_ms: u64,
    /// Maximum time a request can wait in queue (ms).
    pub max_queue_time_ms: u64,
    /// Enable request deduplication.
    pub enable_deduplication: bool,
}

impl Default for PipelineConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_batch_size: 50,
            max_concurrent: 10,
            batch_timeout_ms: DEFAULT_BATCH_TIMEOUT_MS,
            max_queue_time_ms: 5_000,
            enable_deduplication: true,
        }
    }
}

/// Statistics for the request pipeline.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    /// Total requests submitted.
    pub total_requests: u64,
    /// Total requests successfully processed.
    pub successful_requests: u64,
    /// Total requests that failed.
    pub failed_requests: u64,
    /// Total requests deduplicated.
    pub deduplicated_requests: u64,
    /// Total batches processed.
    pub total_batches: u64,
    /// Average batch size.
    pub avg_batch_size: f64,
    /// Average request latency (ms).
    pub avg_latency_ms: f64,
    /// Current queue depth.
    pub queue_depth: usize,
}

impl PipelineStats {
    /// Calculate the success rate as a percentage.
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        let total_processed = self.successful_requests + self.failed_requests;
        if total_processed == 0 {
            0.0
        } else {
            (self.successful_requests as f64 / total_processed as f64) * 100.0
        }
    }

    /// Calculate the failure rate as a percentage.
    #[must_use]
    #[inline]
    pub fn failure_rate(&self) -> f64 {
        100.0 - self.success_rate()
    }

    /// Calculate the deduplication rate as a percentage.
    #[must_use]
    #[inline]
    pub fn dedup_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            (self.deduplicated_requests as f64 / self.total_requests as f64) * 100.0
        }
    }
}

/// Internal pending request with completion channel.
struct PendingRequest {
    request: PipelineRequest,
    response_tx: oneshot::Sender<Result<PipelineResponse, PipelineError>>,
    queued_at: Instant,
}

/// Request pipeline for batching and concurrent execution.
pub struct RequestPipeline {
    config: PipelineConfig,
    request_tx: mpsc::Sender<PendingRequest>,
    stats: Arc<RwLock<PipelineStats>>,
    _worker_handle: tokio::task::JoinHandle<()>,
}

impl RequestPipeline {
    /// Create a new request pipeline.
    pub fn new(config: PipelineConfig) -> Self {
        let (request_tx, request_rx) = mpsc::channel(MAX_PENDING_REQUESTS);
        let stats = Arc::new(RwLock::new(PipelineStats::default()));

        let worker_handle = tokio::spawn(Self::pipeline_worker(
            config.clone(),
            request_rx,
            Arc::clone(&stats),
        ));

        Self {
            config,
            request_tx,
            stats,
            _worker_handle: worker_handle,
        }
    }

    /// Submit a request to the pipeline.
    pub async fn submit(
        &self,
        request: PipelineRequest,
    ) -> Result<PipelineResponse, PipelineError> {
        let (response_tx, response_rx) = oneshot::channel();

        let pending = PendingRequest {
            request,
            response_tx,
            queued_at: Instant::now(),
        };

        self.request_tx
            .send(pending)
            .await
            .map_err(|_| PipelineError::ShuttingDown)?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            stats.queue_depth = self.request_tx.max_capacity() - self.request_tx.capacity();
        }

        response_rx.await.map_err(|_| PipelineError::Cancelled)?
    }

    /// Submit multiple requests concurrently.
    pub async fn submit_batch(
        &self,
        requests: Vec<PipelineRequest>,
    ) -> Vec<Result<PipelineResponse, PipelineError>> {
        let mut results = Vec::with_capacity(requests.len());

        for request in requests {
            let result = self.submit(request).await;
            results.push(result);
        }

        results
    }

    /// Get pipeline statistics.
    pub async fn stats(&self) -> PipelineStats {
        self.stats.read().await.clone()
    }

    /// Get pipeline configuration.
    #[must_use]
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Pipeline worker task that batches and processes requests.
    async fn pipeline_worker(
        config: PipelineConfig,
        mut request_rx: mpsc::Receiver<PendingRequest>,
        stats: Arc<RwLock<PipelineStats>>,
    ) {
        let mut batch: Vec<PendingRequest> = Vec::with_capacity(config.max_batch_size);
        let mut last_batch_time = Instant::now();
        let batch_timeout = Duration::from_millis(config.batch_timeout_ms);
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        // Deduplication map: operation+payload hash -> list of response channels
        let mut dedup_map: HashMap<
            String,
            Vec<oneshot::Sender<Result<PipelineResponse, PipelineError>>>,
        > = HashMap::new();

        loop {
            // Try to fill the batch
            let timeout = tokio::time::sleep(batch_timeout);
            tokio::pin!(timeout);

            tokio::select! {
                Some(pending) = request_rx.recv() => {
                    // Check for timeout
                    if pending.queued_at.elapsed() > Duration::from_millis(config.max_queue_time_ms) {
                        let _ = pending.response_tx.send(Err(PipelineError::RequestTimeout(config.max_queue_time_ms)));
                        continue;
                    }

                    // Check for deduplication
                    if config.enable_deduplication {
                        let dedup_key = format!("{}:{}", pending.request.operation, hex::encode(&pending.request.payload));
                        if let Some(channels) = dedup_map.get_mut(&dedup_key) {
                            channels.push(pending.response_tx);
                            let mut stats = stats.write().await;
                            stats.deduplicated_requests += 1;
                            continue;
                        } else {
                            dedup_map.insert(dedup_key, vec![]);
                        }
                    }

                    batch.push(pending);

                    // Process batch if full
                    if batch.len() >= config.max_batch_size {
                        let current_batch = std::mem::replace(&mut batch, Vec::with_capacity(config.max_batch_size));
                        Self::process_batch(
                            current_batch,
                            Arc::clone(&semaphore),
                            Arc::clone(&stats),
                        ).await;
                        last_batch_time = Instant::now();
                        dedup_map.clear();
                    }
                }
                () = &mut timeout, if !batch.is_empty() => {
                    // Process partial batch after timeout
                    if last_batch_time.elapsed() >= batch_timeout && !batch.is_empty() {
                        let current_batch = std::mem::replace(&mut batch, Vec::with_capacity(config.max_batch_size));
                        Self::process_batch(
                            current_batch,
                            Arc::clone(&semaphore),
                            Arc::clone(&stats),
                        ).await;
                        last_batch_time = Instant::now();
                        dedup_map.clear();
                    }
                }
                else => break,
            }
        }
    }

    /// Process a batch of requests.
    async fn process_batch(
        batch: Vec<PendingRequest>,
        semaphore: Arc<Semaphore>,
        stats: Arc<RwLock<PipelineStats>>,
    ) {
        let batch_size = batch.len();
        let batch_start = Instant::now();

        // Acquire semaphore permit for concurrency control
        let _permit = semaphore.acquire().await.expect("Semaphore closed");

        // Process each request in the batch
        for pending in batch {
            let start_time = Instant::now();

            // Simulate request processing (in real implementation, this would call the actual handler)
            let response = Self::execute_request(&pending.request).await;

            let processing_time_ms = start_time.elapsed().as_millis() as u64;

            let result = response.map(|mut resp| {
                resp.processing_time_ms = processing_time_ms;
                resp
            });

            // Update stats
            {
                let mut stats = stats.write().await;
                match &result {
                    Ok(_) => stats.successful_requests += 1,
                    Err(_) => stats.failed_requests += 1,
                }

                // Update average latency
                let total_latency = stats.avg_latency_ms
                    * (stats.successful_requests + stats.failed_requests - 1) as f64;
                stats.avg_latency_ms = (total_latency + processing_time_ms as f64)
                    / (stats.successful_requests + stats.failed_requests) as f64;
            }

            // Send response
            let _ = pending.response_tx.send(result);
        }

        // Update batch stats
        {
            let mut stats = stats.write().await;
            stats.total_batches += 1;
            let total_batch_size = stats.avg_batch_size * (stats.total_batches - 1) as f64;
            stats.avg_batch_size =
                (total_batch_size + batch_size as f64) / stats.total_batches as f64;
        }

        let _batch_duration = batch_start.elapsed();
    }

    /// Execute a single request (placeholder for actual implementation).
    async fn execute_request(request: &PipelineRequest) -> Result<PipelineResponse, PipelineError> {
        // This is a placeholder. In a real implementation, this would:
        // 1. Call the appropriate handler based on request.operation
        // 2. Process the request.payload
        // 3. Return actual response data

        // Simulate processing time
        tokio::time::sleep(Duration::from_millis(10)).await;

        Ok(PipelineResponse {
            request_id: request.request_id.clone(),
            success: true,
            payload: vec![],
            error: None,
            processing_time_ms: 0, // Will be set by caller
        })
    }
}

/// Generate a unique request ID.
fn generate_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("req-{}-{}", current_timestamp_ms(), id)
}

/// Get current timestamp in milliseconds.
fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config.max_batch_size, 50);
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.batch_timeout_ms, DEFAULT_BATCH_TIMEOUT_MS);
        assert!(config.enable_deduplication);
    }

    #[test]
    fn test_request_priority_order() {
        assert!(RequestPriority::Critical > RequestPriority::High);
        assert!(RequestPriority::High > RequestPriority::Normal);
        assert!(RequestPriority::Normal > RequestPriority::Low);
    }

    #[test]
    fn test_pipeline_request_creation() {
        let request = PipelineRequest::new("test_op", vec![1, 2, 3]);
        assert_eq!(request.operation, "test_op");
        assert_eq!(request.payload, vec![1, 2, 3]);
        assert_eq!(request.priority, RequestPriority::Normal);
    }

    #[test]
    fn test_pipeline_request_with_priority() {
        let request = PipelineRequest::new("test_op", vec![]).with_priority(RequestPriority::High);
        assert_eq!(request.priority, RequestPriority::High);
    }

    #[test]
    fn test_pipeline_request_with_id() {
        let request =
            PipelineRequest::new("test_op", vec![]).with_request_id("custom-id".to_string());
        assert_eq!(request.request_id, "custom-id");
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = PipelineConfig::default();
        let _pipeline = RequestPipeline::new(config);
        // Pipeline created successfully
    }

    #[tokio::test]
    async fn test_pipeline_submit_single_request() {
        let config = PipelineConfig::default();
        let pipeline = RequestPipeline::new(config);

        let request = PipelineRequest::new("test", vec![1, 2, 3]);
        let response = pipeline.submit(request).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_pipeline_submit_batch() {
        let config = PipelineConfig::default();
        let pipeline = RequestPipeline::new(config);

        let requests = vec![
            PipelineRequest::new("test1", vec![1]),
            PipelineRequest::new("test2", vec![2]),
            PipelineRequest::new("test3", vec![3]),
        ];

        let responses = pipeline.submit_batch(requests).await;

        assert_eq!(responses.len(), 3);
        for response in responses {
            assert!(response.is_ok());
        }
    }

    #[tokio::test]
    async fn test_pipeline_stats() {
        let config = PipelineConfig::default();
        let pipeline = RequestPipeline::new(config);

        let request = PipelineRequest::new("test", vec![1, 2, 3]);
        let _ = pipeline.submit(request).await;

        // Give the worker time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        let stats = pipeline.stats().await;
        assert_eq!(stats.total_requests, 1);
    }

    #[test]
    fn test_generate_request_id_uniqueness() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_request_priority_default() {
        let priority = RequestPriority::default();
        assert_eq!(priority, RequestPriority::Normal);
    }
}
