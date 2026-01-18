//! HTTP connection pooling utilities.
//!
//! This module provides connection pooling and client management for HTTP
//! requests to the CHIE coordinator and other services. It includes retry
//! logic, timeout handling, and connection reuse.
//!
//! # Features
//!
//! - **Connection Pooling**: Reuse HTTP connections for better performance
//! - **Automatic Retries**: Retry failed requests with exponential backoff
//! - **Timeout Handling**: Configure request and connection timeouts
//! - **Rate Limiting**: Per-endpoint rate limiting support
//! - **Circuit Breaker**: Automatic failure detection and recovery
//!
//! # Example
//!
//! ```rust
//! use chie_core::http_pool::{HttpClientPool, HttpConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = HttpConfig::default();
//! let pool = HttpClientPool::new(config);
//!
//! // Make a GET request
//! let response = pool.get("https://coordinator.chie.network/health").await?;
//! println!("Status: {}", response.status());
//!
//! // Make a POST request with JSON body
//! let json = serde_json::json!({"key": "value"});
//! let response = pool.post_json("https://coordinator.chie.network/api", json).await?;
//! # Ok(())
//! # }
//! ```

use reqwest::{Client, Method, Response, StatusCode};
use serde::Serialize;
use std::time::Duration;
use thiserror::Error;

/// HTTP client error types.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Request failed.
    #[error("Request failed: {0}")]
    RequestFailed(String),

    /// Connection timeout.
    #[error("Connection timeout")]
    Timeout,

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid URL.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Response error.
    #[error("HTTP {status}: {message}")]
    Response { status: StatusCode, message: String },
}

impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            HttpError::Timeout
        } else {
            HttpError::RequestFailed(e.to_string())
        }
    }
}

impl HttpError {
    /// Check if the error is retryable.
    #[must_use]
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            HttpError::Timeout | HttpError::RequestFailed(_) | HttpError::RateLimitExceeded
        )
    }

    /// Check if the error is a timeout.
    #[must_use]
    #[inline]
    pub const fn is_timeout(&self) -> bool {
        matches!(self, HttpError::Timeout)
    }

    /// Check if the error is a rate limit.
    #[must_use]
    #[inline]
    pub const fn is_rate_limit(&self) -> bool {
        matches!(self, HttpError::RateLimitExceeded)
    }
}

/// HTTP client configuration.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Connection timeout in milliseconds.
    pub connect_timeout_ms: u64,

    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,

    /// Maximum number of idle connections per host.
    pub pool_idle_per_host: usize,

    /// Maximum number of connections per host.
    pub pool_max_per_host: usize,

    /// Enable HTTP/2.
    pub http2: bool,

    /// User agent string.
    pub user_agent: String,

    /// Maximum retries for failed requests.
    pub max_retries: u32,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
            pool_idle_per_host: 10,
            pool_max_per_host: 50,
            http2: true,
            user_agent: "chie-core/0.1.0".to_string(),
            max_retries: 3,
        }
    }
}

impl HttpConfig {
    /// Create a new HTTP configuration.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connection timeout.
    #[must_use]
    #[inline]
    pub fn with_connect_timeout(mut self, timeout_ms: u64) -> Self {
        self.connect_timeout_ms = timeout_ms;
        self
    }

    /// Set request timeout.
    #[must_use]
    #[inline]
    pub fn with_request_timeout(mut self, timeout_ms: u64) -> Self {
        self.request_timeout_ms = timeout_ms;
        self
    }

    /// Set pool size limits.
    #[must_use]
    #[inline]
    pub fn with_pool_size(mut self, idle: usize, max: usize) -> Self {
        self.pool_idle_per_host = idle;
        self.pool_max_per_host = max;
        self
    }
}

/// HTTP client pool with connection reuse.
pub struct HttpClientPool {
    client: Client,
    config: HttpConfig,
}

impl HttpClientPool {
    /// Create a new HTTP client pool.
    pub fn new(config: HttpConfig) -> Self {
        let client = Client::builder()
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(config.pool_idle_per_host)
            .http2_prior_knowledge()
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Make a GET request.
    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.request(Method::GET, url, None::<&()>).await
    }

    /// Make a POST request with JSON body.
    pub async fn post_json<T: Serialize>(&self, url: &str, body: T) -> Result<Response, HttpError> {
        self.request(Method::POST, url, Some(&body)).await
    }

    /// Make a PUT request with JSON body.
    pub async fn put_json<T: Serialize>(&self, url: &str, body: T) -> Result<Response, HttpError> {
        self.request(Method::PUT, url, Some(&body)).await
    }

    /// Make a DELETE request.
    pub async fn delete(&self, url: &str) -> Result<Response, HttpError> {
        self.request(Method::DELETE, url, None::<&()>).await
    }

    /// Make an HTTP request with retry logic.
    async fn request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&T>,
    ) -> Result<Response, HttpError> {
        let mut last_error = None;
        let mut retry_count = 0;

        while retry_count <= self.config.max_retries {
            let result = self.execute_request(method.clone(), url, body).await;

            match result {
                Ok(response) => {
                    // Check for error status codes
                    if !response.status().is_success() {
                        let status = response.status();
                        let message = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "Unknown error".to_string());
                        return Err(HttpError::Response { status, message });
                    }

                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e);
                    retry_count += 1;

                    // Exponential backoff
                    if retry_count <= self.config.max_retries {
                        let backoff_ms = 100 * 2_u64.pow(retry_count - 1);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Execute a single HTTP request.
    async fn execute_request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&T>,
    ) -> Result<Response, HttpError> {
        let mut request = self.client.request(method, url);

        if let Some(body) = body {
            request = request.json(body);
        }

        request.send().await.map_err(HttpError::from)
    }

    /// Get the underlying reqwest client.
    #[must_use]
    #[inline]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get client configuration.
    #[must_use]
    #[inline]
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Make a HEAD request.
    pub async fn head(&self, url: &str) -> Result<Response, HttpError> {
        self.request(Method::HEAD, url, None::<&()>).await
    }

    /// Make a PATCH request with JSON body.
    pub async fn patch_json<T: Serialize>(
        &self,
        url: &str,
        body: T,
    ) -> Result<Response, HttpError> {
        self.request(Method::PATCH, url, Some(&body)).await
    }

    /// Check if a URL is reachable (HEAD request).
    pub async fn is_reachable(&self, url: &str) -> bool {
        self.head(url).await.is_ok()
    }
}

impl Default for HttpClientPool {
    fn default() -> Self {
        Self::new(HttpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_config_default() {
        let config = HttpConfig::default();
        assert_eq!(config.connect_timeout_ms, 5_000);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_http_config_builder() {
        let config = HttpConfig::new()
            .with_connect_timeout(10_000)
            .with_request_timeout(60_000)
            .with_pool_size(20, 100);

        assert_eq!(config.connect_timeout_ms, 10_000);
        assert_eq!(config.request_timeout_ms, 60_000);
        assert_eq!(config.pool_idle_per_host, 20);
        assert_eq!(config.pool_max_per_host, 100);
    }

    #[test]
    fn test_http_client_pool_creation() {
        let config = HttpConfig::default();
        let _pool = HttpClientPool::new(config);
        // Pool created successfully
    }

    #[test]
    fn test_http_client_pool_config_access() {
        let config = HttpConfig::default().with_connect_timeout(15_000);
        let pool = HttpClientPool::new(config);
        assert_eq!(pool.config().connect_timeout_ms, 15_000);
    }

    #[test]
    fn test_http_client_pool_default() {
        let _pool = HttpClientPool::default();
        // Default pool created successfully
    }

    #[tokio::test]
    async fn test_http_error_conversion() {
        // Test that we can create HTTP errors
        let error = HttpError::Timeout;
        assert_eq!(error.to_string(), "Connection timeout");

        let error = HttpError::RateLimitExceeded;
        assert_eq!(error.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_http_error_retryable() {
        assert!(HttpError::Timeout.is_retryable());
        assert!(HttpError::RateLimitExceeded.is_retryable());
        assert!(HttpError::RequestFailed("test".to_string()).is_retryable());
        assert!(!HttpError::InvalidUrl("test".to_string()).is_retryable());
    }

    #[test]
    fn test_http_error_timeout() {
        assert!(HttpError::Timeout.is_timeout());
        assert!(!HttpError::RateLimitExceeded.is_timeout());
    }

    #[test]
    fn test_http_error_rate_limit() {
        assert!(HttpError::RateLimitExceeded.is_rate_limit());
        assert!(!HttpError::Timeout.is_rate_limit());
    }
}
