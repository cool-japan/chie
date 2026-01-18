//! IP-based rate limiting middleware.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub max_requests: u32,
    /// Time window duration.
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window: Duration::from_secs(60),
        }
    }
}

/// Rate limit entry for an IP address.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Number of requests in current window.
    count: u32,
    /// Window start time.
    window_start: Instant,
}

/// IP-based rate limiter.
#[derive(Clone)]
pub struct IpRateLimiter {
    /// Configuration.
    config: RateLimitConfig,
    /// IP address rate limit state.
    state: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
}

impl IpRateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        };

        // Spawn cleanup task
        let state = limiter.state.clone();
        let window = limiter.config.window;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(window);
            loop {
                interval.tick().await;
                let mut state = state.write().await;
                state.retain(|_, entry| entry.window_start.elapsed() < window);
            }
        });

        limiter
    }

    /// Check if a request from an IP should be allowed.
    pub async fn check_rate_limit(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let mut state = self.state.write().await;
        let now = Instant::now();

        let entry = state.entry(ip).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if entry.window_start.elapsed() >= self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= self.config.max_requests {
            let retry_after = self
                .config
                .window
                .saturating_sub(entry.window_start.elapsed())
                .as_secs();
            return Err(RateLimitError {
                retry_after_secs: retry_after,
            });
        }

        // Increment counter
        entry.count += 1;

        Ok(())
    }

    /// Get current statistics.
    #[allow(dead_code)]
    pub async fn stats(&self) -> RateLimitStats {
        let state = self.state.read().await;
        RateLimitStats {
            tracked_ips: state.len(),
            total_requests: state.values().map(|e| e.count as u64).sum(),
        }
    }
}

/// Rate limit error.
#[derive(Debug)]
pub struct RateLimitError {
    /// Seconds until the rate limit resets.
    pub retry_after_secs: u64,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded",
            "retry_after_secs": self.retry_after_secs,
        });

        (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                axum::http::header::RETRY_AFTER,
                self.retry_after_secs.to_string(),
            )],
            axum::Json(body),
        )
            .into_response()
    }
}

/// Rate limit statistics.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)]
pub struct RateLimitStats {
    /// Number of tracked IP addresses.
    pub tracked_ips: usize,
    /// Total requests across all IPs.
    pub total_requests: u64,
}

/// Extract IP address from request.
#[allow(dead_code)]
fn extract_ip(request: &Request) -> Option<IpAddr> {
    // Try X-Forwarded-For header first (for proxies)
    if let Some(forwarded) = request.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse() {
                return Some(ip);
            }
        }
    }

    // Fall back to remote address
    request
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
}

/// Middleware function for IP-based rate limiting.
pub async fn ip_rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<Arc<IpRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Extract IP address
    let ip = match extract_ip(&request) {
        Some(ip) => ip,
        None => {
            // If we can't determine IP, allow the request
            tracing::warn!("Could not extract IP address from request");
            return Ok(next.run(request).await);
        }
    };

    // Check rate limit
    match limiter.check_rate_limit(ip).await {
        Ok(()) => {
            // Add rate limit info to response
            let response = next.run(request).await;
            Ok(response)
        }
        Err(err) => {
            tracing::warn!("Rate limit exceeded for IP: {}", ip);
            Err(err.into_response())
        }
    }
}

/// Create rate limiter middleware layer.
#[allow(dead_code)]
pub fn create_ip_rate_limiter(
    config: RateLimitConfig,
) -> impl Fn(
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>>
+ Clone {
    let limiter = Arc::new(IpRateLimiter::new(config));

    move |request: Request, next: Next| {
        let limiter = limiter.clone();
        Box::pin(async move {
            ip_rate_limit_middleware(axum::extract::State(limiter), request, next).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_within_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
        };
        let limiter = IpRateLimiter::new(config);
        let ip = "127.0.0.1".parse().unwrap();

        // First 5 requests should succeed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
        };
        let limiter = IpRateLimiter::new(config);
        let ip = "127.0.0.1".parse().unwrap();

        // First 5 requests should succeed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).await.is_ok());
        }

        // 6th request should fail
        assert!(limiter.check_rate_limit(ip).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_per_ip() {
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
        };
        let limiter = IpRateLimiter::new(config);
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();

        // Each IP should have its own limit
        assert!(limiter.check_rate_limit(ip1).await.is_ok());
        assert!(limiter.check_rate_limit(ip1).await.is_ok());
        assert!(limiter.check_rate_limit(ip2).await.is_ok());
        assert!(limiter.check_rate_limit(ip2).await.is_ok());

        // Both should be blocked on 3rd request
        assert!(limiter.check_rate_limit(ip1).await.is_err());
        assert!(limiter.check_rate_limit(ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_stats() {
        let config = RateLimitConfig {
            max_requests: 10,
            window: Duration::from_secs(60),
        };
        let limiter = IpRateLimiter::new(config);
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();

        limiter.check_rate_limit(ip1).await.unwrap();
        limiter.check_rate_limit(ip1).await.unwrap();
        limiter.check_rate_limit(ip2).await.unwrap();

        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 2);
        assert_eq!(stats.total_requests, 3);
    }
}
