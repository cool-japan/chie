//! Request Coalescing Middleware
//!
//! This module provides request coalescing functionality to deduplicate concurrent
//! identical requests. When multiple clients make the same request simultaneously,
//! only one request is processed and the response is shared with all waiting clients.
//!
//! # Benefits
//! - Reduces database load for identical queries
//! - Decreases backend processing for expensive operations
//! - Improves response times for duplicate requests
//! - Prevents thundering herd problems
//!
//! # Features
//! - Automatic request key generation (method + path + query)
//! - Configurable header inclusion in request key
//! - TTL for pending requests
//! - Metrics tracking (coalesced requests, cache hits)
//! - Automatic cleanup of expired requests

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, Response, StatusCode},
    middleware::Next,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tracing::{debug, warn};

/// Request coalescing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoalescingConfig {
    /// Enable request coalescing
    pub enabled: bool,

    /// Maximum number of concurrent pending requests to track
    pub max_pending_requests: usize,

    /// Time-to-live for pending requests (seconds)
    pub request_ttl_seconds: u64,

    /// Include query parameters in request key
    pub include_query: bool,

    /// Headers to include in request key (e.g., ["accept", "accept-language"])
    pub include_headers: Vec<String>,

    /// Methods to coalesce (typically only GET/HEAD)
    pub coalesce_methods: Vec<String>,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_pending_requests: 10_000,
            request_ttl_seconds: 30,
            include_query: true,
            include_headers: vec!["accept".to_string()],
            coalesce_methods: vec!["GET".to_string(), "HEAD".to_string()],
        }
    }
}

/// Request key for deduplication
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestKey {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
}

impl RequestKey {
    /// Generate a request key from HTTP request
    fn from_request(req: &Request<Body>, config: &CoalescingConfig) -> Self {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        let query = if config.include_query {
            req.uri().query().map(|q| q.to_string())
        } else {
            None
        };

        let mut headers = Vec::new();
        for header_name in &config.include_headers {
            if let Some(value) = req.headers().get(header_name) {
                if let Ok(value_str) = value.to_str() {
                    headers.push((header_name.clone(), value_str.to_string()));
                }
            }
        }
        headers.sort();

        Self {
            method,
            path,
            query,
            headers,
        }
    }
}

/// Pending request entry
struct PendingRequest {
    /// When this request was first received
    created_at: Instant,

    /// Broadcast channel for sharing response
    tx: broadcast::Sender<SharedResponse>,
}

/// Shared response that can be cloned to multiple waiters
#[derive(Debug, Clone)]
struct SharedResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Request coalescing statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoalescingStats {
    /// Total requests processed
    pub total_requests: u64,

    /// Requests that were coalesced (duplicates)
    pub coalesced_requests: u64,

    /// Requests that were executed (unique)
    pub executed_requests: u64,

    /// Current number of pending requests
    pub pending_requests: usize,

    /// Coalescing hit rate (0.0 - 1.0)
    pub hit_rate: f64,
}

/// Request coalescing manager
#[derive(Clone)]
pub struct CoalescingManager {
    config: Arc<CoalescingConfig>,
    pending: Arc<DashMap<RequestKey, PendingRequest>>,
    stats: Arc<DashMap<String, u64>>,
}

impl CoalescingManager {
    /// Create a new coalescing manager
    pub fn new(config: CoalescingConfig) -> Self {
        let manager = Self {
            config: Arc::new(config),
            pending: Arc::new(DashMap::new()),
            stats: Arc::new(DashMap::new()),
        };

        // Start cleanup task
        let cleanup_manager = manager.clone();
        tokio::spawn(async move {
            cleanup_manager.cleanup_loop().await;
        });

        manager
    }

    /// Get current statistics
    pub fn stats(&self) -> CoalescingStats {
        let total = self.stats.get("total").map(|v| *v).unwrap_or(0);
        let coalesced = self.stats.get("coalesced").map(|v| *v).unwrap_or(0);
        let executed = self.stats.get("executed").map(|v| *v).unwrap_or(0);

        let hit_rate = if total > 0 {
            coalesced as f64 / total as f64
        } else {
            0.0
        };

        CoalescingStats {
            total_requests: total,
            coalesced_requests: coalesced,
            executed_requests: executed,
            pending_requests: self.pending.len(),
            hit_rate,
        }
    }

    /// Check if method should be coalesced
    fn should_coalesce(&self, method: &Method) -> bool {
        self.config.coalesce_methods.contains(&method.to_string())
    }

    /// Cleanup expired pending requests
    async fn cleanup_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let ttl = Duration::from_secs(self.config.request_ttl_seconds);
            let now = Instant::now();

            self.pending
                .retain(|_key, entry| now.duration_since(entry.created_at) < ttl);
        }
    }
}

/// Request coalescing middleware
pub async fn request_coalescing_middleware(
    State(manager): State<Arc<CoalescingManager>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // Check if coalescing is enabled
    if !manager.config.enabled {
        return Ok(next.run(req).await);
    }

    // Check if method should be coalesced
    if !manager.should_coalesce(req.method()) {
        return Ok(next.run(req).await);
    }

    // Generate request key
    let key = RequestKey::from_request(&req, &manager.config);

    // Increment total requests
    manager
        .stats
        .entry("total".to_string())
        .and_modify(|v| *v += 1)
        .or_insert(1);

    // Check if there's a pending request for this key
    if let Some(entry) = manager.pending.get(&key) {
        // This is a duplicate request - wait for the original to complete
        debug!("Coalescing duplicate request: {:?}", key);

        manager
            .stats
            .entry("coalesced".to_string())
            .and_modify(|v| *v += 1)
            .or_insert(1);

        // Record metrics
        crate::metrics::record_request_coalesced();

        let mut rx = entry.tx.subscribe();
        drop(entry); // Release the lock

        // Wait for response
        match rx.recv().await {
            Ok(shared_response) => {
                // Build response from shared data
                let mut response = Response::new(Body::from(shared_response.body));
                *response.status_mut() = shared_response.status;

                for header in &shared_response.headers {
                    let (name, value) = header;
                    if let Ok(header_value) = axum::http::HeaderValue::from_str(value) {
                        if let Ok(header_name) = axum::http::HeaderName::from_bytes(name.as_bytes())
                        {
                            response.headers_mut().insert(header_name, header_value);
                        }
                    }
                }

                return Ok(response);
            }
            Err(e) => {
                warn!("Failed to receive coalesced response: {}", e);
                // Fall through to execute request
            }
        }
    }

    // Check if we've hit the max pending requests limit
    if manager.pending.len() >= manager.config.max_pending_requests {
        warn!("Max pending requests reached, not coalescing");
        return Ok(next.run(req).await);
    }

    // This is a new request - create a broadcast channel and execute
    let (tx, _rx) = broadcast::channel(100);

    let pending_entry = PendingRequest {
        created_at: Instant::now(),
        tx: tx.clone(),
    };

    manager.pending.insert(key.clone(), pending_entry);

    manager
        .stats
        .entry("executed".to_string())
        .and_modify(|v| *v += 1)
        .or_insert(1);

    // Execute the request
    let response = next.run(req).await;

    // Extract response data for sharing
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    // Get the body
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            warn!("Failed to read response body: {}", e);
            manager.pending.remove(&key);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Share the response with waiting requests
    let shared_response = SharedResponse {
        status,
        headers: headers.clone(),
        body: body_bytes.clone(),
    };

    // Broadcast to all waiters (ignore errors if no one is listening)
    let _ = tx.send(shared_response);

    // Remove from pending
    manager.pending.remove(&key);

    // Rebuild the response
    let mut final_response = Response::new(Body::from(body_bytes));
    *final_response.status_mut() = parts.status;
    *final_response.headers_mut() = parts.headers;
    *final_response.version_mut() = parts.version;
    *final_response.extensions_mut() = parts.extensions;

    Ok(final_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CoalescingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_pending_requests, 10_000);
        assert_eq!(config.request_ttl_seconds, 30);
        assert!(config.include_query);
        assert_eq!(config.coalesce_methods, vec!["GET", "HEAD"]);
    }

    #[tokio::test]
    async fn test_should_coalesce() {
        let config = CoalescingConfig::default();
        let manager = CoalescingManager::new(config);

        assert!(manager.should_coalesce(&Method::GET));
        assert!(manager.should_coalesce(&Method::HEAD));
        assert!(!manager.should_coalesce(&Method::POST));
        assert!(!manager.should_coalesce(&Method::PUT));
    }

    #[tokio::test]
    async fn test_stats() {
        let config = CoalescingConfig::default();
        let manager = CoalescingManager::new(config);

        manager.stats.insert("total".to_string(), 100);
        manager.stats.insert("coalesced".to_string(), 30);
        manager.stats.insert("executed".to_string(), 70);

        let stats = manager.stats();
        assert_eq!(stats.total_requests, 100);
        assert_eq!(stats.coalesced_requests, 30);
        assert_eq!(stats.executed_requests, 70);
        assert_eq!(stats.hit_rate, 0.3);
    }

    #[test]
    fn test_request_key_equality() {
        let key1 = RequestKey {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("foo=bar".to_string()),
            headers: vec![("accept".to_string(), "application/json".to_string())],
        };

        let key2 = RequestKey {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("foo=bar".to_string()),
            headers: vec![("accept".to_string(), "application/json".to_string())],
        };

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_request_key_different_query() {
        let key1 = RequestKey {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("foo=bar".to_string()),
            headers: vec![],
        };

        let key2 = RequestKey {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("foo=baz".to_string()),
            headers: vec![],
        };

        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_hit_rate_calculation() {
        let config = CoalescingConfig::default();
        let manager = CoalescingManager::new(config);

        // No requests yet
        let stats = manager.stats();
        assert_eq!(stats.hit_rate, 0.0);

        // 50% hit rate
        manager.stats.insert("total".to_string(), 200);
        manager.stats.insert("coalesced".to_string(), 100);
        let stats = manager.stats();
        assert_eq!(stats.hit_rate, 0.5);
    }
}
