//! Request queuing system for burst traffic handling.
//!
//! This module provides a request queue that can handle traffic bursts
//! by buffering requests and processing them at a controlled rate,
//! preventing server overload during spikes.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, warn};

/// Request queue configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestQueueConfig {
    /// Maximum number of concurrent requests.
    pub max_concurrent: usize,

    /// Maximum queue size (requests beyond this are rejected).
    pub max_queue_size: usize,

    /// Maximum wait time in queue (in milliseconds).
    pub max_wait_time_ms: u64,

    /// Enable queue monitoring.
    pub enable_monitoring: bool,

    /// Reject requests when queue is full (vs wait).
    pub reject_when_full: bool,

    /// Priority queue enabled.
    pub enable_priority: bool,
}

impl Default for RequestQueueConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 100,
            max_queue_size: 1000,
            max_wait_time_ms: 10000, // 10 seconds
            enable_monitoring: true,
            reject_when_full: true,
            enable_priority: false,
        }
    }
}

/// Queue statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    /// Total requests processed.
    pub total_requests: u64,

    /// Total requests queued.
    pub total_queued: u64,

    /// Total requests rejected.
    pub total_rejected: u64,

    /// Total requests that timed out in queue.
    pub total_timeouts: u64,

    /// Current queue size.
    pub current_queue_size: usize,

    /// Current active requests.
    pub current_active: usize,

    /// Peak queue size.
    pub peak_queue_size: usize,

    /// Average wait time in milliseconds.
    pub avg_wait_time_ms: f64,

    /// Total wait time samples.
    wait_time_samples: Vec<u64>,
}

impl QueueStats {
    /// Record a queued request.
    fn record_queued(&mut self, queue_size: usize) {
        self.total_queued += 1;
        self.current_queue_size = queue_size;
        if queue_size > self.peak_queue_size {
            self.peak_queue_size = queue_size;
        }
    }

    /// Record a rejected request.
    fn record_rejected(&mut self) {
        self.total_rejected += 1;
    }

    /// Record a timeout.
    fn record_timeout(&mut self) {
        self.total_timeouts += 1;
    }

    /// Record request completion with wait time.
    fn record_completion(&mut self, wait_time_ms: u64) {
        self.total_requests += 1;

        // Keep last 1000 samples for average
        self.wait_time_samples.push(wait_time_ms);
        if self.wait_time_samples.len() > 1000 {
            self.wait_time_samples
                .drain(0..self.wait_time_samples.len() - 1000);
        }

        self.avg_wait_time_ms =
            self.wait_time_samples.iter().sum::<u64>() as f64 / self.wait_time_samples.len() as f64;
    }

    /// Get rejection rate (0.0 to 1.0).
    pub fn rejection_rate(&self) -> f64 {
        let total = self.total_requests + self.total_rejected;
        if total == 0 {
            0.0
        } else {
            self.total_rejected as f64 / total as f64
        }
    }

    /// Get timeout rate (0.0 to 1.0).
    pub fn timeout_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.total_timeouts as f64 / self.total_requests as f64
        }
    }
}

/// Request queue for traffic control.
#[derive(Clone)]
pub struct RequestQueue {
    /// Configuration.
    config: RequestQueueConfig,

    /// Semaphore for concurrency control.
    semaphore: Arc<Semaphore>,

    /// Statistics.
    stats: Arc<RwLock<QueueStats>>,
}

impl RequestQueue {
    /// Create a new request queue.
    pub fn new(config: RequestQueueConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        Self {
            config,
            semaphore,
            stats: Arc::new(RwLock::new(QueueStats::default())),
        }
    }

    /// Try to acquire a slot for processing a request.
    async fn try_acquire(&self) -> Result<RequestSlot, QueueError> {
        let queue_start = Instant::now();

        // Check current queue size
        let available = self.semaphore.available_permits();
        let queue_size = self.config.max_concurrent - available;

        if queue_size >= self.config.max_queue_size && self.config.reject_when_full {
            self.stats.write().await.record_rejected();
            warn!("Request queue full ({} requests), rejecting", queue_size);
            return Err(QueueError::QueueFull);
        }

        // Record queuing
        self.stats.write().await.record_queued(queue_size);

        // Try to acquire with timeout
        let max_wait = Duration::from_millis(self.config.max_wait_time_ms);

        match tokio::time::timeout(max_wait, self.semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => {
                let wait_time = queue_start.elapsed();
                let wait_time_ms = wait_time.as_millis() as u64;

                debug!("Request acquired slot after {}ms", wait_time_ms);

                self.stats.write().await.record_completion(wait_time_ms);
                self.stats.write().await.current_active += 1;

                Ok(RequestSlot {
                    _permit: permit,
                    stats: self.stats.clone(),
                })
            }
            Ok(Err(_)) => {
                error!("Semaphore closed unexpectedly");
                Err(QueueError::QueueClosed)
            }
            Err(_) => {
                self.stats.write().await.record_timeout();
                warn!(
                    "Request timed out in queue after {}ms",
                    self.config.max_wait_time_ms
                );
                Err(QueueError::Timeout)
            }
        }
    }

    /// Get current statistics.
    pub async fn stats(&self) -> QueueStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics.
    pub async fn reset_stats(&self) {
        *self.stats.write().await = QueueStats::default();
    }

    /// Get current queue health.
    pub async fn health_check(&self) -> QueueHealthCheck {
        let stats = self.stats.read().await;
        let mut issues = Vec::new();

        // Check rejection rate
        let rejection_rate = stats.rejection_rate();
        if rejection_rate > 0.1 {
            issues.push(format!(
                "High rejection rate: {:.1}%",
                rejection_rate * 100.0
            ));
        }

        // Check timeout rate
        let timeout_rate = stats.timeout_rate();
        if timeout_rate > 0.05 {
            issues.push(format!("High timeout rate: {:.1}%", timeout_rate * 100.0));
        }

        // Check queue utilization
        let utilization = stats.current_queue_size as f64 / self.config.max_queue_size as f64;
        if utilization > 0.8 {
            issues.push(format!(
                "High queue utilization: {:.1}%",
                utilization * 100.0
            ));
        }

        // Check average wait time
        if stats.avg_wait_time_ms > 1000.0 {
            issues.push(format!(
                "High average wait time: {:.0}ms",
                stats.avg_wait_time_ms
            ));
        }

        QueueHealthCheck {
            healthy: issues.is_empty(),
            queue_size: stats.current_queue_size,
            active_requests: stats.current_active,
            rejection_rate,
            timeout_rate,
            avg_wait_time_ms: stats.avg_wait_time_ms,
            issues,
        }
    }
}

/// RAII guard for request slot.
struct RequestSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    stats: Arc<RwLock<QueueStats>>,
}

impl Drop for RequestSlot {
    fn drop(&mut self) {
        // Decrement active count when request completes
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let mut s = stats.write().await;
            s.current_active = s.current_active.saturating_sub(1);
            s.current_queue_size = s.current_queue_size.saturating_sub(1);
        });
    }
}

/// Queue health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueHealthCheck {
    /// Health status.
    pub healthy: bool,

    /// Current queue size.
    pub queue_size: usize,

    /// Current active requests.
    pub active_requests: usize,

    /// Rejection rate (0.0 to 1.0).
    pub rejection_rate: f64,

    /// Timeout rate (0.0 to 1.0).
    pub timeout_rate: f64,

    /// Average wait time in ms.
    pub avg_wait_time_ms: f64,

    /// Issues detected.
    pub issues: Vec<String>,
}

/// Queue errors.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Queue is full.
    #[error("Request queue is full")]
    QueueFull,

    /// Request timed out waiting in queue.
    #[error("Request timed out in queue")]
    Timeout,

    /// Queue is closed.
    #[error("Request queue is closed")]
    QueueClosed,
}

impl IntoResponse for QueueError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            QueueError::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Server is too busy, please try again later",
            ),
            QueueError::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "Request timed out waiting for processing",
            ),
            QueueError::QueueClosed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Request queue is unavailable",
            ),
        };

        (status, message).into_response()
    }
}

/// Middleware for request queuing.
pub async fn request_queue_middleware(
    axum::extract::State(queue): axum::extract::State<RequestQueue>,
    request: Request,
    next: Next,
) -> Result<Response, QueueError> {
    let _slot = queue.try_acquire().await?;

    // Process the request
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_stats_rejection_rate() {
        let stats = QueueStats {
            total_requests: 90,
            total_rejected: 10,
            ..Default::default()
        };

        assert_eq!(stats.rejection_rate(), 0.1);
    }

    #[tokio::test]
    async fn test_queue_stats_timeout_rate() {
        let stats = QueueStats {
            total_requests: 100,
            total_timeouts: 5,
            ..Default::default()
        };

        assert_eq!(stats.timeout_rate(), 0.05);
    }

    #[tokio::test]
    async fn test_queue_basic_flow() {
        let config = RequestQueueConfig {
            max_concurrent: 2,
            max_queue_size: 5,
            max_wait_time_ms: 1000,
            enable_monitoring: true,
            reject_when_full: true,
            enable_priority: false,
        };

        let queue = RequestQueue::new(config);

        // Acquire first slot
        let _slot1 = queue.try_acquire().await.unwrap();
        let stats = queue.stats().await;
        assert_eq!(stats.current_active, 1);

        // Acquire second slot
        let _slot2 = queue.try_acquire().await.unwrap();
        let stats = queue.stats().await;
        assert_eq!(stats.current_active, 2);
    }

    #[tokio::test]
    async fn test_queue_full_rejection() {
        let config = RequestQueueConfig {
            max_concurrent: 1,
            max_queue_size: 1,
            max_wait_time_ms: 100,
            enable_monitoring: true,
            reject_when_full: true,
            enable_priority: false,
        };

        let queue = RequestQueue::new(config);

        // Acquire the only slot
        let _slot = queue.try_acquire().await.unwrap();

        // Try to acquire when full (should be queued then timeout)
        let result = queue.try_acquire().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_queue_slot_release() {
        let config = RequestQueueConfig {
            max_concurrent: 1,
            max_queue_size: 5,
            max_wait_time_ms: 1000,
            enable_monitoring: true,
            reject_when_full: false,
            enable_priority: false,
        };

        let queue = RequestQueue::new(config);

        {
            let _slot = queue.try_acquire().await.unwrap();
            let stats = queue.stats().await;
            assert_eq!(stats.current_active, 1);
        } // slot dropped here

        // Give tokio time to process the drop
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats = queue.stats().await;
        assert_eq!(stats.current_active, 0);
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let config = RequestQueueConfig::default();
        let queue = RequestQueue::new(config);

        let health = queue.health_check().await;
        assert!(health.healthy);
        assert!(health.issues.is_empty());
    }

    #[tokio::test]
    async fn test_record_completion_avg() {
        let mut stats = QueueStats::default();

        stats.record_completion(100);
        stats.record_completion(200);
        stats.record_completion(300);

        assert_eq!(stats.avg_wait_time_ms, 200.0);
        assert_eq!(stats.total_requests, 3);
    }
}
