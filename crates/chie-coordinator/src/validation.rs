//! Request validation middleware for the coordinator API.
//!
//! This module provides:
//! - Input validation for API requests
//! - Size limit enforcement
//! - Content type validation
//! - Rate limiting helpers

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Validation error response.
#[derive(Debug, Serialize)]
pub struct ValidationError {
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ValidationError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
            field: None,
            details: None,
        }
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

impl IntoResponse for ValidationError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Configuration for request validation.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum request body size (bytes).
    pub max_body_size: usize,
    /// Maximum URL length.
    pub max_url_length: usize,
    /// Maximum number of headers.
    pub max_headers: usize,
    /// Allowed content types for POST/PUT.
    pub allowed_content_types: Vec<String>,
    /// Rate limit: requests per minute per IP.
    pub rate_limit_per_minute: u32,
    /// Rate limit window.
    pub rate_limit_window: Duration,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024, // 10 MB
            max_url_length: 2048,
            max_headers: 100,
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/octet-stream".to_string(),
            ],
            rate_limit_per_minute: 100,
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

/// Rate limiter state.
#[derive(Debug, Default)]
pub struct RateLimiterState {
    requests: HashMap<String, Vec<Instant>>,
}

impl RateLimiterState {
    /// Check if request is allowed and record it.
    pub fn check_and_record(&mut self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let requests = self.requests.entry(key.to_string()).or_default();

        // Remove old requests
        requests.retain(|&t| now.duration_since(t) < window);

        if requests.len() >= limit as usize {
            return false;
        }

        requests.push(now);
        true
    }

    /// Clean up old entries.
    pub fn cleanup(&mut self, window: Duration) {
        let now = Instant::now();
        self.requests.retain(|_, requests| {
            requests.retain(|&t| now.duration_since(t) < window);
            !requests.is_empty()
        });
    }
}

/// Shared rate limiter.
pub type SharedRateLimiter = Arc<RwLock<RateLimiterState>>;

/// Create a shared rate limiter.
pub fn create_rate_limiter() -> SharedRateLimiter {
    Arc::new(RwLock::new(RateLimiterState::default()))
}

/// Middleware for validating content length.
pub async fn validate_content_length(
    request: Request,
    next: Next,
) -> Result<Response, ValidationError> {
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB

    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH) {
        if let Ok(length) = content_length.to_str().unwrap_or("0").parse::<usize>() {
            if length > MAX_BODY_SIZE {
                return Err(ValidationError::new(
                    format!(
                        "Request body too large: {} bytes (max: {} bytes)",
                        length, MAX_BODY_SIZE
                    ),
                    "BODY_TOO_LARGE",
                ));
            }
        }
    }

    Ok(next.run(request).await)
}

/// Middleware for validating content type.
pub async fn validate_content_type(
    request: Request,
    next: Next,
) -> Result<Response, ValidationError> {
    let method = request.method().clone();

    // Only validate for methods that typically have a body
    if method == "POST" || method == "PUT" || method == "PATCH" {
        if let Some(content_type) = request.headers().get(header::CONTENT_TYPE) {
            let ct = content_type.to_str().unwrap_or("");
            if !ct.starts_with("application/json") && !ct.starts_with("application/octet-stream") {
                return Err(ValidationError::new(
                    format!("Unsupported content type: {}", ct),
                    "INVALID_CONTENT_TYPE",
                )
                .with_details("Allowed: application/json, application/octet-stream"));
            }
        }
    }

    Ok(next.run(request).await)
}

/// Middleware for rate limiting by IP.
pub async fn rate_limit_middleware(
    rate_limiter: SharedRateLimiter,
    config: ValidationConfig,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Extract client IP from headers or connection
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Check rate limit
    let allowed = {
        let mut limiter = rate_limiter.write().await;
        limiter.check_and_record(
            &client_ip,
            config.rate_limit_per_minute,
            config.rate_limit_window,
        )
    };

    if !allowed {
        let error = ValidationError::new("Rate limit exceeded", "RATE_LIMIT_EXCEEDED")
            .with_details(format!(
                "Maximum {} requests per minute",
                config.rate_limit_per_minute
            ));
        return Err(error.into_response());
    }

    Ok(next.run(request).await)
}

/// Validation helpers for common fields.
pub mod validators {
    use super::ValidationError;

    /// Validate a UUID string.
    pub fn validate_uuid(value: &str, field: &str) -> Result<uuid::Uuid, ValidationError> {
        uuid::Uuid::parse_str(value).map_err(|_| {
            ValidationError::new(format!("Invalid UUID format for {}", field), "INVALID_UUID")
                .with_field(field)
        })
    }

    /// Validate a non-empty string.
    pub fn validate_non_empty(value: &str, field: &str) -> Result<(), ValidationError> {
        if value.trim().is_empty() {
            return Err(
                ValidationError::new(format!("{} cannot be empty", field), "EMPTY_FIELD")
                    .with_field(field),
            );
        }
        Ok(())
    }

    /// Validate string length.
    pub fn validate_length(
        value: &str,
        field: &str,
        min: usize,
        max: usize,
    ) -> Result<(), ValidationError> {
        let len = value.len();
        if len < min || len > max {
            return Err(ValidationError::new(
                format!("{} must be between {} and {} characters", field, min, max),
                "INVALID_LENGTH",
            )
            .with_field(field));
        }
        Ok(())
    }

    /// Validate a positive integer.
    pub fn validate_positive(value: i64, field: &str) -> Result<i64, ValidationError> {
        if value <= 0 {
            return Err(ValidationError::new(
                format!("{} must be positive", field),
                "INVALID_VALUE",
            )
            .with_field(field));
        }
        Ok(value)
    }

    /// Validate a value is within range.
    pub fn validate_range<T: PartialOrd + std::fmt::Display>(
        value: T,
        field: &str,
        min: T,
        max: T,
    ) -> Result<T, ValidationError> {
        if value < min || value > max {
            return Err(ValidationError::new(
                format!("{} must be between {} and {}", field, min, max),
                "OUT_OF_RANGE",
            )
            .with_field(field));
        }
        Ok(value)
    }

    /// Validate an email address (basic check).
    pub fn validate_email(value: &str, field: &str) -> Result<(), ValidationError> {
        if !value.contains('@') || !value.contains('.') {
            return Err(ValidationError::new(
                format!("Invalid email format for {}", field),
                "INVALID_EMAIL",
            )
            .with_field(field));
        }
        Ok(())
    }

    /// Validate a content CID format.
    pub fn validate_cid(value: &str, field: &str) -> Result<(), ValidationError> {
        // Basic CID validation (starts with Qm or bafy)
        if !value.starts_with("Qm") && !value.starts_with("bafy") {
            return Err(ValidationError::new(
                format!("Invalid CID format for {}", field),
                "INVALID_CID",
            )
            .with_field(field));
        }
        if value.len() < 46 {
            return Err(ValidationError::new(
                format!("CID too short for {}", field),
                "INVALID_CID",
            )
            .with_field(field));
        }
        Ok(())
    }

    /// Validate a public key (32 bytes).
    pub fn validate_public_key(value: &[u8], field: &str) -> Result<(), ValidationError> {
        if value.len() != 32 {
            return Err(ValidationError::new(
                format!("{} must be 32 bytes", field),
                "INVALID_KEY_LENGTH",
            )
            .with_field(field));
        }
        Ok(())
    }

    /// Validate a signature (64 bytes).
    pub fn validate_signature(value: &[u8], field: &str) -> Result<(), ValidationError> {
        if value.len() != 64 {
            return Err(ValidationError::new(
                format!("{} must be 64 bytes", field),
                "INVALID_SIGNATURE_LENGTH",
            )
            .with_field(field));
        }
        Ok(())
    }

    /// Validate timestamp is within acceptable range.
    pub fn validate_timestamp(
        timestamp_ms: i64,
        field: &str,
        tolerance_ms: i64,
    ) -> Result<i64, ValidationError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let diff = (now_ms - timestamp_ms).abs();

        if diff > tolerance_ms {
            return Err(ValidationError::new(
                format!("{} is too far from current time ({} ms drift)", field, diff),
                "TIMESTAMP_OUT_OF_RANGE",
            )
            .with_field(field));
        }
        Ok(timestamp_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::validators::*;
    use super::*;

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000", "id").is_ok());
        assert!(validate_uuid("invalid", "id").is_err());
    }

    #[test]
    fn test_validate_non_empty() {
        assert!(validate_non_empty("hello", "name").is_ok());
        assert!(validate_non_empty("", "name").is_err());
        assert!(validate_non_empty("   ", "name").is_err());
    }

    #[test]
    fn test_validate_length() {
        assert!(validate_length("hello", "name", 1, 10).is_ok());
        assert!(validate_length("", "name", 1, 10).is_err()); // empty is 0 length, NOT in 1..10
        assert!(validate_length("hello world", "name", 1, 5).is_err());
    }

    #[test]
    fn test_validate_cid() {
        assert!(validate_cid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", "cid").is_ok());
        assert!(
            validate_cid(
                "bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq",
                "cid"
            )
            .is_ok()
        );
        assert!(validate_cid("invalid", "cid").is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiterState::default();
        let window = Duration::from_secs(60);

        // First 3 requests should succeed
        assert!(limiter.check_and_record("client1", 3, window));
        assert!(limiter.check_and_record("client1", 3, window));
        assert!(limiter.check_and_record("client1", 3, window));

        // Fourth should fail
        assert!(!limiter.check_and_record("client1", 3, window));

        // Different client should succeed
        assert!(limiter.check_and_record("client2", 3, window));
    }
}
