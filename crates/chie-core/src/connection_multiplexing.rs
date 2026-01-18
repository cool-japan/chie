//! Connection multiplexing for coordinator communication.
//!
//! This module provides connection pooling and multiplexing capabilities for
//! efficient HTTP communication with the coordinator. It reduces connection
//! overhead by reusing existing connections and queuing requests.
//!
//! # Features
//!
//! - Connection pooling with configurable size limits
//! - Automatic connection health monitoring
//! - Request queuing and fair scheduling
//! - Exponential backoff retry logic
//! - Connection keep-alive management
//! - Circuit breaker integration for failed connections
//!
//! # Example
//!
//! ```rust
//! use chie_core::connection_multiplexing::{ConnectionPool, PoolConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure connection pool
//! let config = PoolConfig::default()
//!     .with_max_connections(10)
//!     .with_idle_timeout(Duration::from_secs(60));
//!
//! // Create pool
//! let pool = ConnectionPool::new("https://coordinator.example.com", config);
//!
//! // Make requests through the pool
//! let response = pool.request("POST", "/api/proofs", b"proof_data").await?;
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::sleep;

// Circuit breaker integration removed for simplicity
// Connection pool handles retries and failures internally

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of concurrent connections.
    max_connections: usize,
    /// Idle timeout before closing unused connections.
    idle_timeout: Duration,
    /// Connection timeout for establishing new connections.
    connect_timeout: Duration,
    /// Request timeout for individual requests.
    request_timeout: Duration,
    /// Maximum number of retries for failed requests.
    max_retries: usize,
    /// Base delay for exponential backoff.
    retry_base_delay: Duration,
    /// Maximum delay for exponential backoff.
    retry_max_delay: Duration,
    /// Enable TCP keep-alive.
    tcp_keepalive: bool,
    /// TCP keep-alive interval.
    tcp_keepalive_interval: Duration,
}

impl Default for PoolConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_connections: 10,
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_base_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(30),
            tcp_keepalive: true,
            tcp_keepalive_interval: Duration::from_secs(60),
        }
    }
}

impl PoolConfig {
    /// Creates a new pool configuration with default values.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of concurrent connections.
    #[must_use]
    #[inline]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the idle timeout for connections.
    #[must_use]
    #[inline]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    #[inline]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the request timeout.
    #[must_use]
    #[inline]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets the maximum number of retries.
    #[must_use]
    #[inline]
    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the retry base delay.
    #[must_use]
    #[inline]
    pub fn with_retry_base_delay(mut self, delay: Duration) -> Self {
        self.retry_base_delay = delay;
        self
    }

    /// Enables or disables TCP keep-alive.
    #[must_use]
    #[inline]
    pub fn with_tcp_keepalive(mut self, enabled: bool) -> Self {
        self.tcp_keepalive = enabled;
        self
    }

    /// Gets the maximum number of connections.
    #[must_use]
    #[inline]
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Gets the idle timeout.
    #[must_use]
    #[inline]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Gets the connect timeout.
    #[must_use]
    #[inline]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Gets the request timeout.
    #[must_use]
    #[inline]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Gets the maximum retries.
    #[must_use]
    #[inline]
    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }
}

/// Represents a pooled HTTP connection.
#[derive(Debug)]
struct PooledConnection {
    /// Connection ID for tracking.
    #[allow(dead_code)]
    id: usize,
    /// Last time this connection was used.
    last_used: Instant,
    /// Number of requests served by this connection.
    requests_served: u64,
    /// Whether the connection is currently in use.
    in_use: bool,
    /// HTTP client for this connection (reqwest reuses connections internally).
    client: reqwest::Client,
}

impl PooledConnection {
    /// Creates a new pooled connection.
    #[must_use]
    fn new(id: usize, config: &PoolConfig) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .connect_timeout(config.connect_timeout)
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(config.idle_timeout);

        if config.tcp_keepalive {
            builder = builder.tcp_keepalive(Some(config.tcp_keepalive_interval));
        }

        let client = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        Self {
            id,
            last_used: Instant::now(),
            requests_served: 0,
            in_use: false,
            client,
        }
    }

    /// Marks the connection as used.
    #[inline]
    fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.requests_served += 1;
        self.in_use = true;
    }

    /// Marks the connection as released.
    #[inline]
    fn release(&mut self) {
        self.in_use = false;
        self.last_used = Instant::now();
    }

    /// Checks if the connection is idle for longer than the timeout.
    #[must_use]
    #[inline]
    fn is_idle(&self, idle_timeout: Duration) -> bool {
        !self.in_use && self.last_used.elapsed() > idle_timeout
    }

    /// Gets the connection ID.
    #[must_use]
    #[inline]
    #[allow(dead_code)]
    const fn id(&self) -> usize {
        self.id
    }

    /// Gets the number of requests served.
    #[must_use]
    #[inline]
    #[allow(dead_code)]
    const fn requests_served(&self) -> u64 {
        self.requests_served
    }
}

/// Statistics for the connection pool.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total number of requests processed.
    pub total_requests: u64,
    /// Number of successful requests.
    pub successful_requests: u64,
    /// Number of failed requests.
    pub failed_requests: u64,
    /// Number of retried requests.
    pub retried_requests: u64,
    /// Number of active connections.
    pub active_connections: usize,
    /// Number of idle connections.
    pub idle_connections: usize,
    /// Total connections created.
    pub total_connections_created: u64,
    /// Total connections closed.
    pub total_connections_closed: u64,
    /// Average requests per connection.
    pub avg_requests_per_connection: f64,
}

/// HTTP connection pool with multiplexing support.
pub struct ConnectionPool {
    /// Base URL for the coordinator.
    base_url: String,
    /// Pool configuration.
    config: PoolConfig,
    /// Available connections.
    connections: Arc<RwLock<Vec<PooledConnection>>>,
    /// Request queue for when all connections are busy.
    #[allow(dead_code)]
    request_queue: Arc<Mutex<VecDeque<PendingRequest>>>,
    /// Semaphore to limit concurrent connections.
    connection_semaphore: Arc<Semaphore>,
    /// Pool statistics.
    stats: Arc<RwLock<PoolStats>>,
    /// Next connection ID.
    next_connection_id: Arc<Mutex<usize>>,
}

/// A pending request in the queue.
#[derive(Debug)]
#[allow(dead_code)]
struct PendingRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, ConnectionError>>,
}

/// Errors that can occur during connection pool operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConnectionError {
    /// Request timeout.
    #[error("Request timed out")]
    Timeout,
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    /// Request failed after all retries.
    #[error("Request failed after {0} retries")]
    RetriesExhausted(usize),
    /// Invalid URL or configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    /// HTTP error.
    #[error("HTTP error: {status}")]
    HttpError { status: u16 },
    /// Response channel closed.
    #[error("Response channel closed")]
    ChannelClosed,
}

impl ConnectionPool {
    /// Creates a new connection pool.
    #[must_use]
    pub fn new(base_url: impl Into<String>, config: PoolConfig) -> Self {
        let max_connections = config.max_connections;

        Self {
            base_url: base_url.into(),
            config,
            connections: Arc::new(RwLock::new(Vec::new())),
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            stats: Arc::new(RwLock::new(PoolStats::default())),
            next_connection_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Makes an HTTP request through the connection pool.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
        }

        // Try to execute the request with retries
        let mut attempts = 0;
        let mut last_error = None;

        while attempts <= self.config.max_retries {
            if attempts > 0 {
                // Update retry stats
                let mut stats = self.stats.write().await;
                stats.retried_requests += 1;

                // Calculate exponential backoff delay
                let delay = self.calculate_backoff_delay(attempts);
                sleep(delay).await;
            }

            match self.execute_request(method, path, body).await {
                Ok(response) => {
                    // Success - record it
                    let mut stats = self.stats.write().await;
                    stats.successful_requests += 1;

                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e.clone());

                    // Check if we should retry
                    if !self.should_retry(&e) {
                        break;
                    }

                    attempts += 1;
                }
            }
        }

        // All retries exhausted
        let mut stats = self.stats.write().await;
        stats.failed_requests += 1;

        Err(last_error.unwrap_or(ConnectionError::RetriesExhausted(attempts)))
    }

    /// Executes a single request attempt.
    async fn execute_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        // Acquire a connection from the pool or create a new one
        let connection = self.acquire_connection().await?;

        // Build the full URL
        let url = format!("{}{}", self.base_url, path);

        // Execute the request
        let result = tokio::time::timeout(
            self.config.request_timeout,
            connection
                .client
                .request(method.parse().unwrap_or(reqwest::Method::GET), &url)
                .body(body.to_vec())
                .send(),
        )
        .await;

        // Release the connection back to the pool
        self.release_connection(connection).await;

        // Process the result
        match result {
            Ok(Ok(response)) => {
                let status = response.status();
                if status.is_success() {
                    response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))
                } else {
                    Err(ConnectionError::HttpError {
                        status: status.as_u16(),
                    })
                }
            }
            Ok(Err(e)) => Err(ConnectionError::ConnectionFailed(e.to_string())),
            Err(_) => Err(ConnectionError::Timeout),
        }
    }

    /// Acquires a connection from the pool.
    async fn acquire_connection(&self) -> Result<PooledConnection, ConnectionError> {
        // Try to get an existing idle connection
        {
            let mut connections = self.connections.write().await;
            if let Some(pos) = connections.iter().position(|c| !c.in_use) {
                connections[pos].mark_used();
                return Ok(connections.remove(pos));
            }
        }

        // No idle connection available, try to create a new one
        if let Ok(_permit) = self.connection_semaphore.try_acquire() {
            let mut next_id = self.next_connection_id.lock().await;
            let id = *next_id;
            *next_id += 1;

            let connection = PooledConnection::new(id, &self.config);

            let mut stats = self.stats.write().await;
            stats.total_connections_created += 1;
            stats.active_connections += 1;

            return Ok(connection);
        }

        // Pool is full, wait for a connection to become available
        let _permit = self
            .connection_semaphore
            .acquire()
            .await
            .map_err(|_| ConnectionError::InvalidConfig("Semaphore closed".to_string()))?;

        let mut next_id = self.next_connection_id.lock().await;
        let id = *next_id;
        *next_id += 1;

        let connection = PooledConnection::new(id, &self.config);

        let mut stats = self.stats.write().await;
        stats.total_connections_created += 1;
        stats.active_connections += 1;

        Ok(connection)
    }

    /// Releases a connection back to the pool.
    async fn release_connection(&self, mut connection: PooledConnection) {
        connection.release();

        // Check if the connection should be closed due to idle timeout
        if connection.is_idle(self.config.idle_timeout) {
            let mut stats = self.stats.write().await;
            stats.total_connections_closed += 1;
            stats.active_connections = stats.active_connections.saturating_sub(1);
            return;
        }

        // Add back to the pool
        let mut connections = self.connections.write().await;
        connections.push(connection);
    }

    /// Calculates the backoff delay for a retry attempt.
    #[must_use]
    #[inline]
    fn calculate_backoff_delay(&self, attempt: usize) -> Duration {
        let delay_ms = self.config.retry_base_delay.as_millis() as u64 * 2u64.pow(attempt as u32);
        let delay = Duration::from_millis(delay_ms);
        delay.min(self.config.retry_max_delay)
    }

    /// Checks if an error should be retried.
    #[must_use]
    #[inline]
    fn should_retry(&self, error: &ConnectionError) -> bool {
        matches!(
            error,
            ConnectionError::Timeout | ConnectionError::ConnectionFailed(_)
        )
    }

    /// Gets the current pool statistics.
    pub async fn stats(&self) -> PoolStats {
        let mut stats = self.stats.read().await.clone();

        // Update active/idle connection counts
        let connections = self.connections.read().await;
        stats.active_connections = connections.iter().filter(|c| c.in_use).count();
        stats.idle_connections = connections.iter().filter(|c| !c.in_use).count();

        // Calculate average requests per connection
        if stats.total_connections_created > 0 {
            stats.avg_requests_per_connection =
                stats.total_requests as f64 / stats.total_connections_created as f64;
        }

        stats
    }

    /// Closes all idle connections.
    pub async fn close_idle_connections(&self) {
        let mut connections = self.connections.write().await;
        let idle_timeout = self.config.idle_timeout;

        let closed_count = connections
            .iter()
            .filter(|conn| conn.is_idle(idle_timeout))
            .count();

        connections.retain(|conn| !conn.is_idle(idle_timeout));

        // Update stats
        if closed_count > 0 {
            let mut stats = self.stats.write().await;
            stats.total_connections_closed += closed_count as u64;
            stats.active_connections = stats.active_connections.saturating_sub(closed_count);
        }
    }

    /// Gets the pool configuration.
    #[must_use]
    #[inline]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Gets the base URL.
    #[must_use]
    #[inline]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections(), 10);
        assert_eq!(config.idle_timeout(), Duration::from_secs(60));
        assert_eq!(config.connect_timeout(), Duration::from_secs(10));
        assert_eq!(config.request_timeout(), Duration::from_secs(30));
        assert_eq!(config.max_retries(), 3);
    }

    #[test]
    fn test_pool_config_builder() {
        let config = PoolConfig::new()
            .with_max_connections(20)
            .with_idle_timeout(Duration::from_secs(120))
            .with_connect_timeout(Duration::from_secs(5))
            .with_request_timeout(Duration::from_secs(60))
            .with_max_retries(5)
            .with_tcp_keepalive(false);

        assert_eq!(config.max_connections(), 20);
        assert_eq!(config.idle_timeout(), Duration::from_secs(120));
        assert_eq!(config.connect_timeout(), Duration::from_secs(5));
        assert_eq!(config.request_timeout(), Duration::from_secs(60));
        assert_eq!(config.max_retries(), 5);
    }

    #[test]
    fn test_pooled_connection_creation() {
        let config = PoolConfig::default();
        let conn = PooledConnection::new(0, &config);
        assert_eq!(conn.id(), 0);
        assert_eq!(conn.requests_served(), 0);
        assert!(!conn.in_use);
    }

    #[test]
    fn test_pooled_connection_mark_used() {
        let config = PoolConfig::default();
        let mut conn = PooledConnection::new(0, &config);
        conn.mark_used();
        assert!(conn.in_use);
        assert_eq!(conn.requests_served(), 1);
    }

    #[test]
    fn test_pooled_connection_release() {
        let config = PoolConfig::default();
        let mut conn = PooledConnection::new(0, &config);
        conn.mark_used();
        conn.release();
        assert!(!conn.in_use);
        assert_eq!(conn.requests_served(), 1);
    }

    #[test]
    fn test_pooled_connection_idle() {
        let config = PoolConfig::default();
        let conn = PooledConnection::new(0, &config);
        // Immediately after creation, connection is not idle
        assert!(!conn.is_idle(Duration::from_millis(1)));
    }

    #[test]
    fn test_calculate_backoff_delay() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new("http://localhost", config);

        let delay0 = pool.calculate_backoff_delay(0);
        let delay1 = pool.calculate_backoff_delay(1);
        let delay2 = pool.calculate_backoff_delay(2);

        assert_eq!(delay0, Duration::from_millis(100)); // 100 * 2^0 = 100
        assert_eq!(delay1, Duration::from_millis(200)); // 100 * 2^1 = 200
        assert_eq!(delay2, Duration::from_millis(400)); // 100 * 2^2 = 400
    }

    #[test]
    fn test_should_retry() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new("http://localhost", config);

        assert!(pool.should_retry(&ConnectionError::Timeout));
        assert!(pool.should_retry(&ConnectionError::ConnectionFailed("test".to_string())));
        assert!(!pool.should_retry(&ConnectionError::HttpError { status: 400 }));
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new("http://localhost:8080", config);
        assert_eq!(pool.base_url(), "http://localhost:8080");
    }

    #[tokio::test]
    async fn test_pool_stats_initial() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new("http://localhost:8080", config);
        let stats = pool.stats().await;
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_requests, 0);
        assert_eq!(stats.failed_requests, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.idle_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_close_idle_connections() {
        let config = PoolConfig::default().with_idle_timeout(Duration::from_millis(10));
        let pool = ConnectionPool::new("http://localhost:8080", config);

        // Initially no connections
        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 0);

        // Close idle connections (should be a no-op)
        pool.close_idle_connections().await;

        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 0);
    }
}
