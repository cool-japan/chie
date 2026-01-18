//! Per-endpoint performance metrics tracking.

use axum::{extract::Request, middleware::Next, response::Response};
use metrics::{counter, histogram};
use std::time::Instant;

/// Middleware for tracking per-endpoint performance metrics.
pub async fn endpoint_metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Normalize path to remove IDs (e.g., /api/content/123 -> /api/content/:id)
    let normalized_path = normalize_path(&path);

    // Create labels for metrics
    let endpoint = format!("{}_{}", method, normalized_path);

    // Increment request counter
    counter!("http_requests_total", "endpoint" => endpoint.clone()).increment(1);

    // Process request
    let response = next.run(request).await;

    // Record response time
    let duration = start.elapsed();
    histogram!(
        "http_request_duration_seconds",
        "endpoint" => endpoint.clone()
    )
    .record(duration.as_secs_f64());

    // Record status code
    let status = response.status();
    counter!(
        "http_responses_total",
        "endpoint" => endpoint.clone(),
        "status" => status.as_u16().to_string()
    )
    .increment(1);

    // Track errors (4xx and 5xx)
    if status.is_client_error() || status.is_server_error() {
        counter!(
            "http_errors_total",
            "endpoint" => endpoint.clone(),
            "status" => status.as_u16().to_string()
        )
        .increment(1);
    }

    // Track slow requests (> 1 second)
    if duration.as_secs() >= 1 {
        counter!("http_slow_requests_total", "endpoint" => endpoint).increment(1);
    }

    response
}

/// Normalize path by replacing dynamic segments with placeholders.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let mut normalized = Vec::new();

    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            normalized.push("");
            continue;
        }

        // Check if this looks like a dynamic segment
        // - All digits (e.g., "123")
        // - UUID format
        // - Long hex string (>= 16 chars, all hexdigits)
        // - Mixed alphanumeric that looks like an ID (contains both letters and numbers)
        let is_all_digits = segment.chars().all(|c| c.is_ascii_digit());
        let is_long_hex = segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit());
        let has_letters = segment.chars().any(|c| c.is_ascii_alphabetic());
        let has_digits = segment.chars().any(|c| c.is_ascii_digit());
        let is_alphanumeric = segment.chars().all(|c| c.is_ascii_alphanumeric());
        let looks_like_id = is_alphanumeric && has_letters && has_digits;

        let is_dynamic = is_all_digits || is_uuid(segment) || is_long_hex || looks_like_id;

        if is_dynamic {
            // Try to infer the parameter name from the previous segment
            if i > 0 {
                let prev = segments[i - 1];
                match prev {
                    "content" => normalized.push(":id"),
                    "nodes" => normalized.push(":peer_id"),
                    "users" => normalized.push(":user_id"),
                    _ => normalized.push(":id"),
                }
            } else {
                normalized.push(":id");
            }
        } else {
            normalized.push(segment);
        }
    }

    normalized.join("/")
}

/// Check if a string looks like a UUID.
fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Get metrics for a specific endpoint.
#[allow(dead_code)]
pub struct EndpointMetrics {
    /// Total requests.
    pub total_requests: u64,
    /// Total errors.
    pub total_errors: u64,
    /// Average response time in milliseconds.
    pub avg_response_time_ms: f64,
    /// P95 response time in milliseconds.
    pub p95_response_time_ms: f64,
    /// P99 response time in milliseconds.
    pub p99_response_time_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("/api/health"), "/api/health");
        assert_eq!(normalize_path("/api/users"), "/api/users");
    }

    #[test]
    fn test_normalize_path_with_id() {
        assert_eq!(normalize_path("/api/content/123"), "/api/content/:id");
        assert_eq!(normalize_path("/api/nodes/abc123"), "/api/nodes/:peer_id");
        assert_eq!(normalize_path("/api/users/456"), "/api/users/:user_id");
    }

    #[test]
    fn test_normalize_path_with_uuid() {
        assert_eq!(
            normalize_path("/api/content/550e8400-e29b-41d4-a716-446655440000"),
            "/api/content/:id"
        );
        assert_eq!(
            normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000/stats"),
            "/api/users/:user_id/stats"
        );
    }

    #[test]
    fn test_normalize_path_multiple_params() {
        assert_eq!(
            normalize_path("/api/content/123/chunks/456"),
            "/api/content/:id/chunks/:id"
        );
    }

    #[test]
    fn test_is_uuid_valid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn test_is_uuid_invalid() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400"));
        assert!(!is_uuid(""));
    }

    #[test]
    fn test_normalize_path_preserves_static() {
        assert_eq!(normalize_path("/api/content/search"), "/api/content/search");
        assert_eq!(normalize_path("/metrics"), "/metrics");
        assert_eq!(normalize_path("/health"), "/health");
    }

    #[test]
    fn test_normalize_path_edge_cases() {
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("//"), "//");
    }
}
