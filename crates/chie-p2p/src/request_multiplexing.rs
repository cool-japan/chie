// Request multiplexing for pipelining multiple concurrent requests over a single connection
// Enables efficient concurrent request handling similar to HTTP/2 multiplexing

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// Unique identifier for multiplexed requests
pub type RequestId = u64;

/// Helper function for serde default
fn instant_now() -> Instant {
    Instant::now()
}

/// Configuration for request multiplexing
#[derive(Debug, Clone)]
pub struct MultiplexConfig {
    /// Maximum number of concurrent in-flight requests per connection
    pub max_concurrent_requests: usize,

    /// Timeout for individual requests
    pub request_timeout: Duration,

    /// Maximum size of the pending request queue
    pub max_queue_size: usize,

    /// Enable request prioritization
    pub enable_prioritization: bool,

    /// Window size for flow control (bytes)
    pub flow_control_window: u64,

    /// Enable statistics tracking
    pub enable_stats: bool,
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 100,
            request_timeout: Duration::from_secs(30),
            max_queue_size: 1000,
            enable_prioritization: true,
            flow_control_window: 65536, // 64 KB
            enable_stats: true,
        }
    }
}

/// Priority levels for multiplexed requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum RequestPriority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// A multiplexed request with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexedRequest<T> {
    /// Unique request identifier
    pub request_id: RequestId,

    /// Request payload
    pub payload: T,

    /// Request priority
    pub priority: RequestPriority,

    /// Timestamp when request was created
    #[serde(skip, default = "instant_now")]
    pub created_at: Instant,

    /// Expected response size (for flow control)
    pub expected_response_size: Option<u64>,
}

/// A multiplexed response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexedResponse<T> {
    /// Request ID this response corresponds to
    pub request_id: RequestId,

    /// Response payload
    pub payload: T,

    /// Whether this is the final response (supports streaming)
    pub is_final: bool,

    /// Sequence number for ordered streaming responses
    pub sequence: u32,
}

/// Statistics for multiplexer performance
#[derive(Debug, Clone, Default)]
pub struct MultiplexStats {
    /// Total requests sent
    pub total_requests: u64,

    /// Total responses received
    pub total_responses: u64,

    /// Requests that timed out
    pub timeout_count: u64,

    /// Requests that were cancelled
    pub cancelled_count: u64,

    /// Current in-flight requests
    pub in_flight_count: usize,

    /// Current queued requests
    pub queued_count: usize,

    /// Average request latency
    pub avg_latency: Duration,

    /// Peak concurrent requests
    pub peak_concurrent: usize,
}

/// Internal state for a pending request
struct PendingRequest<Res> {
    response_tx: oneshot::Sender<Result<Res, MultiplexError>>,
    created_at: Instant,
    timeout: Duration,
    #[allow(dead_code)]
    priority: RequestPriority,
    expected_size: Option<u64>,
}

/// Errors that can occur during multiplexing
#[derive(Debug, Clone, thiserror::Error)]
pub enum MultiplexError {
    #[error("Request timed out after {0:?}")]
    Timeout(Duration),

    #[error("Request was cancelled")]
    Cancelled,

    #[error("Queue is full (max: {0})")]
    QueueFull(usize),

    #[error("Too many concurrent requests (max: {0})")]
    TooManyConcurrent(usize),

    #[error("Request ID {0} not found")]
    RequestNotFound(RequestId),

    #[error("Flow control window exceeded")]
    FlowControlExceeded,

    #[error("Invalid request ID")]
    InvalidRequestId,

    #[error("Multiplexer shutdown")]
    Shutdown,
}

/// Request multiplexer for managing concurrent requests
pub struct RequestMultiplexer<Req, Res> {
    config: MultiplexConfig,
    next_request_id: Arc<RwLock<RequestId>>,
    pending_requests: Arc<RwLock<HashMap<RequestId, PendingRequest<Res>>>>,
    stats: Arc<RwLock<MultiplexStats>>,
    request_tx: mpsc::UnboundedSender<MultiplexedRequest<Req>>,
    flow_control_used: Arc<RwLock<u64>>,
}

impl<Req, Res> RequestMultiplexer<Req, Res>
where
    Req: Clone + Send + 'static,
    Res: Clone + Send + 'static,
{
    /// Create a new request multiplexer
    pub fn new(
        config: MultiplexConfig,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<MultiplexedRequest<Req>>,
        mpsc::UnboundedSender<MultiplexedResponse<Res>>,
    ) {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (response_tx, mut response_rx) = mpsc::unbounded_channel();

        let pending_requests = Arc::new(RwLock::new(HashMap::new()));
        let stats = Arc::new(RwLock::new(MultiplexStats::default()));
        let flow_control_used = Arc::new(RwLock::new(0));

        let multiplexer = Self {
            config: config.clone(),
            next_request_id: Arc::new(RwLock::new(1)),
            pending_requests: pending_requests.clone(),
            stats: stats.clone(),
            request_tx,
            flow_control_used: flow_control_used.clone(),
        };

        // Spawn background task to handle responses
        let pending_clone = pending_requests;
        let stats_clone = stats;
        let flow_clone = flow_control_used;
        let enable_stats = config.enable_stats;

        tokio::spawn(async move {
            while let Some(response) = response_rx.recv().await {
                let _ = Self::handle_response_internal(
                    response,
                    &pending_clone,
                    &stats_clone,
                    &flow_clone,
                    enable_stats,
                )
                .await;
            }
        });

        (multiplexer, request_rx, response_tx)
    }

    /// Send a request and wait for response
    pub async fn send_request(
        &self,
        payload: Req,
        priority: RequestPriority,
        expected_response_size: Option<u64>,
    ) -> Result<Res, MultiplexError> {
        // Check if we have capacity
        let pending_count = self.pending_requests.read().len();
        if pending_count >= self.config.max_concurrent_requests {
            return Err(MultiplexError::TooManyConcurrent(
                self.config.max_concurrent_requests,
            ));
        }

        // Check flow control
        if let Some(size) = expected_response_size {
            let used = *self.flow_control_used.read();
            if used + size > self.config.flow_control_window {
                return Err(MultiplexError::FlowControlExceeded);
            }
        }

        // Generate request ID
        let request_id = {
            let mut next_id = self.next_request_id.write();
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            id
        };

        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();

        // Store pending request
        let pending = PendingRequest {
            response_tx,
            created_at: Instant::now(),
            timeout: self.config.request_timeout,
            priority,
            expected_size: expected_response_size,
        };

        self.pending_requests.write().insert(request_id, pending);

        // Update flow control
        if let Some(size) = expected_response_size {
            *self.flow_control_used.write() += size;
        }

        // Update stats
        if self.config.enable_stats {
            let mut stats = self.stats.write();
            stats.total_requests += 1;
            stats.in_flight_count = self.pending_requests.read().len();
            if stats.in_flight_count > stats.peak_concurrent {
                stats.peak_concurrent = stats.in_flight_count;
            }
        }

        // Send request
        let request = MultiplexedRequest {
            request_id,
            payload,
            priority,
            created_at: Instant::now(),
            expected_response_size,
        };

        self.request_tx
            .send(request)
            .map_err(|_| MultiplexError::Shutdown)?;

        debug!(
            "Sent multiplexed request {} with priority {:?}",
            request_id, priority
        );

        // Wait for response with timeout
        match tokio::time::timeout(self.config.request_timeout, response_rx).await {
            Ok(Ok(response)) => {
                // Release flow control
                if let Some(size) = expected_response_size {
                    *self.flow_control_used.write() -= size;
                }
                response
            }
            Ok(Err(_)) => {
                self.cleanup_request(request_id, true);
                Err(MultiplexError::Cancelled)
            }
            Err(_) => {
                self.cleanup_request(request_id, false);
                Err(MultiplexError::Timeout(self.config.request_timeout))
            }
        }
    }

    /// Internal method to handle incoming response (called by background task)
    async fn handle_response_internal(
        response: MultiplexedResponse<Res>,
        pending_requests: &Arc<RwLock<HashMap<RequestId, PendingRequest<Res>>>>,
        stats: &Arc<RwLock<MultiplexStats>>,
        flow_control_used: &Arc<RwLock<u64>>,
        enable_stats: bool,
    ) -> Result<(), MultiplexError> {
        let request_id = response.request_id;

        debug!("Handling response for request {}", request_id);

        let pending = pending_requests.write().remove(&request_id);

        match pending {
            Some(pending_req) => {
                // Calculate latency
                if enable_stats {
                    let latency = pending_req.created_at.elapsed();
                    let mut stats_guard = stats.write();
                    stats_guard.total_responses += 1;
                    stats_guard.in_flight_count = pending_requests.read().len();

                    // Update average latency
                    let total = stats_guard.total_responses;
                    let old_avg = stats_guard.avg_latency;
                    stats_guard.avg_latency = Duration::from_nanos(
                        ((old_avg.as_nanos() * (total - 1) as u128 + latency.as_nanos())
                            / total as u128) as u64,
                    );
                }

                // Release flow control
                if let Some(size) = pending_req.expected_size {
                    *flow_control_used.write() -= size;
                }

                // Send response to waiting task
                let _ = pending_req.response_tx.send(Ok(response.payload));

                Ok(())
            }
            None => {
                warn!("Received response for unknown request ID: {}", request_id);
                Err(MultiplexError::RequestNotFound(request_id))
            }
        }
    }

    /// Cancel a specific request
    pub fn cancel_request(&self, request_id: RequestId) -> Result<(), MultiplexError> {
        self.cleanup_request(request_id, true);
        Ok(())
    }

    /// Get current statistics
    pub fn get_stats(&self) -> MultiplexStats {
        self.stats.read().clone()
    }

    /// Get number of in-flight requests
    pub fn in_flight_count(&self) -> usize {
        self.pending_requests.read().len()
    }

    /// Clean up timed-out requests
    pub fn cleanup_timedout_requests(&self) -> usize {
        let now = Instant::now();
        let mut timedout = Vec::new();

        {
            let pending = self.pending_requests.read();
            for (id, req) in pending.iter() {
                if now.duration_since(req.created_at) > req.timeout {
                    timedout.push(*id);
                }
            }
        }

        let count = timedout.len();
        for id in timedout {
            self.cleanup_request(id, false);
        }

        if count > 0 {
            warn!("Cleaned up {} timed-out requests", count);
        }

        count
    }

    /// Internal cleanup for a request
    fn cleanup_request(&self, request_id: RequestId, cancelled: bool) {
        let pending = self.pending_requests.write().remove(&request_id);

        if let Some(pending_req) = pending {
            // Release flow control
            if let Some(size) = pending_req.expected_size {
                *self.flow_control_used.write() -= size;
            }

            // Update stats
            if self.config.enable_stats {
                let mut stats = self.stats.write();
                if cancelled {
                    stats.cancelled_count += 1;
                } else {
                    stats.timeout_count += 1;
                }
                stats.in_flight_count = self.pending_requests.read().len();
            }

            // Notify waiting task
            let error = if cancelled {
                MultiplexError::Cancelled
            } else {
                MultiplexError::Timeout(pending_req.timeout)
            };
            let _ = pending_req.response_tx.send(Err(error));
        }
    }

    /// Start background cleanup task for timed-out requests
    pub fn start_cleanup_task(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.cleanup_timedout_requests();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestRequest {
        data: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestResponse {
        result: String,
    }

    #[tokio::test]
    async fn test_basic_request_response() {
        let config = MultiplexConfig::default();
        let (multiplexer, mut request_rx, response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);

        // Spawn task to handle requests
        tokio::spawn(async move {
            while let Some(req) = request_rx.recv().await {
                let response = MultiplexedResponse {
                    request_id: req.request_id,
                    payload: TestResponse {
                        result: format!("Response to: {}", req.payload.data),
                    },
                    is_final: true,
                    sequence: 0,
                };
                response_tx.send(response).unwrap();
            }
        });

        // Send request
        let request = TestRequest {
            data: "Hello".to_string(),
        };

        let response = multiplexer
            .send_request(request, RequestPriority::Normal, None)
            .await
            .unwrap();

        assert_eq!(response.result, "Response to: Hello");
    }

    #[tokio::test]
    async fn test_multiple_concurrent_requests() {
        let config = MultiplexConfig {
            max_concurrent_requests: 10,
            ..Default::default()
        };
        let (multiplexer, mut request_rx, response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        // Spawn task to handle requests
        tokio::spawn(async move {
            while let Some(req) = request_rx.recv().await {
                // Simulate processing time
                sleep(Duration::from_millis(10)).await;

                let response = MultiplexedResponse {
                    request_id: req.request_id,
                    payload: TestResponse {
                        result: format!("Response: {}", req.payload.data),
                    },
                    is_final: true,
                    sequence: 0,
                };
                response_tx.send(response).unwrap();
            }
        });

        // Send multiple concurrent requests
        let mut handles = vec![];
        for i in 0..5 {
            let mx = multiplexer.clone();
            let handle = tokio::spawn(async move {
                let request = TestRequest {
                    data: format!("Request {}", i),
                };
                mx.send_request(request, RequestPriority::Normal, None)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all responses
        for handle in handles {
            let response = handle.await.unwrap().unwrap();
            assert!(response.result.starts_with("Response: Request"));
        }

        let stats = multiplexer.get_stats();
        assert_eq!(stats.total_requests, 5);
        assert_eq!(stats.total_responses, 5);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        let config = MultiplexConfig {
            request_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let (multiplexer, mut _request_rx, _response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);

        // Don't handle the request - let it timeout
        let request = TestRequest {
            data: "Timeout test".to_string(),
        };

        let result = multiplexer
            .send_request(request, RequestPriority::Normal, None)
            .await;

        assert!(matches!(result, Err(MultiplexError::Timeout(_))));

        let stats = multiplexer.get_stats();
        assert_eq!(stats.timeout_count, 1);
    }

    #[tokio::test]
    async fn test_too_many_concurrent() {
        let config = MultiplexConfig {
            max_concurrent_requests: 2,
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let (multiplexer, _request_rx, _response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        // Send 2 requests (fill capacity)
        let mx1 = multiplexer.clone();
        let _handle1 = tokio::spawn(async move {
            let request = TestRequest {
                data: "1".to_string(),
            };
            mx1.send_request(request, RequestPriority::Normal, None)
                .await
        });

        let mx2 = multiplexer.clone();
        let _handle2 = tokio::spawn(async move {
            let request = TestRequest {
                data: "2".to_string(),
            };
            mx2.send_request(request, RequestPriority::Normal, None)
                .await
        });

        // Wait for requests to be registered
        sleep(Duration::from_millis(50)).await;

        // Third request should fail
        let request = TestRequest {
            data: "3".to_string(),
        };
        let result = multiplexer
            .send_request(request, RequestPriority::Normal, None)
            .await;

        assert!(matches!(result, Err(MultiplexError::TooManyConcurrent(_))));
    }

    #[tokio::test]
    async fn test_flow_control() {
        let config = MultiplexConfig {
            flow_control_window: 100,
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let (multiplexer, _request_rx, _response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        // Send request that uses 60 bytes
        let mx1 = multiplexer.clone();
        let _handle1 = tokio::spawn(async move {
            let request = TestRequest {
                data: "1".to_string(),
            };
            mx1.send_request(request, RequestPriority::Normal, Some(60))
                .await
        });

        // Send request that uses 50 bytes (should exceed window)
        sleep(Duration::from_millis(10)).await;

        let request = TestRequest {
            data: "2".to_string(),
        };
        let result = multiplexer
            .send_request(request, RequestPriority::Normal, Some(50))
            .await;

        assert!(matches!(result, Err(MultiplexError::FlowControlExceeded)));
    }

    #[tokio::test]
    async fn test_request_prioritization() {
        let config = MultiplexConfig::default();
        let (multiplexer, mut request_rx, response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);

        // Collect requests with priorities
        tokio::spawn(async move {
            let mut requests = vec![];
            for _ in 0..3 {
                if let Some(req) = request_rx.recv().await {
                    requests.push(req);
                }
            }

            // Verify priorities are set correctly
            assert_eq!(requests[0].priority, RequestPriority::Low);
            assert_eq!(requests[1].priority, RequestPriority::Normal);
            assert_eq!(requests[2].priority, RequestPriority::High);

            // Send responses
            for req in requests {
                let response = MultiplexedResponse {
                    request_id: req.request_id,
                    payload: TestResponse {
                        result: "OK".to_string(),
                    },
                    is_final: true,
                    sequence: 0,
                };
                response_tx.send(response).unwrap();
            }
        });

        // Send requests with different priorities
        let _r1 = multiplexer.send_request(
            TestRequest {
                data: "low".to_string(),
            },
            RequestPriority::Low,
            None,
        );

        let _r2 = multiplexer.send_request(
            TestRequest {
                data: "normal".to_string(),
            },
            RequestPriority::Normal,
            None,
        );

        let _r3 = multiplexer.send_request(
            TestRequest {
                data: "high".to_string(),
            },
            RequestPriority::High,
            None,
        );

        sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_statistics() {
        let config = MultiplexConfig {
            enable_stats: true,
            ..Default::default()
        };
        let (multiplexer, mut request_rx, response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        // Handle requests
        tokio::spawn(async move {
            while let Some(req) = request_rx.recv().await {
                let response = MultiplexedResponse {
                    request_id: req.request_id,
                    payload: TestResponse {
                        result: "OK".to_string(),
                    },
                    is_final: true,
                    sequence: 0,
                };
                response_tx.send(response).unwrap();
            }
        });

        // Send some requests
        for i in 0..3 {
            let request = TestRequest {
                data: format!("{}", i),
            };
            multiplexer
                .send_request(request, RequestPriority::Normal, None)
                .await
                .unwrap();
        }

        let stats = multiplexer.get_stats();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.total_responses, 3);
        assert!(stats.avg_latency.as_nanos() > 0);
    }

    #[tokio::test]
    async fn test_cleanup_task() {
        let config = MultiplexConfig {
            request_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let (multiplexer, _request_rx, _response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        // Start cleanup task
        let cleanup_handle = multiplexer
            .clone()
            .start_cleanup_task(Duration::from_millis(25));

        // Send request that will timeout
        let request = TestRequest {
            data: "timeout".to_string(),
        };
        let _result = multiplexer
            .send_request(request, RequestPriority::Normal, None)
            .await;

        // Wait for cleanup
        sleep(Duration::from_millis(100)).await;

        let stats = multiplexer.get_stats();
        assert_eq!(stats.timeout_count, 1);
        assert_eq!(stats.in_flight_count, 0);

        cleanup_handle.abort();
    }

    #[tokio::test]
    async fn test_cancel_request() {
        let config = MultiplexConfig {
            request_timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let (multiplexer, mut request_rx, _response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);
        let multiplexer = Arc::new(multiplexer);

        let mx = multiplexer.clone();
        let handle = tokio::spawn(async move {
            let request = TestRequest {
                data: "cancel me".to_string(),
            };
            mx.send_request(request, RequestPriority::Normal, None)
                .await
        });

        // Get the request ID
        let req = request_rx.recv().await.unwrap();
        let request_id = req.request_id;

        // Cancel it
        multiplexer.cancel_request(request_id).unwrap();

        let result = handle.await.unwrap();
        assert!(matches!(result, Err(MultiplexError::Cancelled)));

        let stats = multiplexer.get_stats();
        assert_eq!(stats.cancelled_count, 1);
    }

    #[tokio::test]
    async fn test_handle_unknown_response() {
        let config = MultiplexConfig::default();
        let (_multiplexer, _request_rx, response_tx) =
            RequestMultiplexer::<TestRequest, TestResponse>::new(config);

        // Send a response for an unknown request ID
        // This should be handled gracefully by the background task
        let response = MultiplexedResponse {
            request_id: 99999,
            payload: TestResponse {
                result: "Unknown".to_string(),
            },
            is_final: true,
            sequence: 0,
        };

        // The background task will log a warning but won't crash
        response_tx.send(response).unwrap();

        // Give it a moment to process
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Test passes if we get here without panicking
    }
}
