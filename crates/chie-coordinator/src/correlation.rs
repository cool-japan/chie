//! Request correlation ID middleware for tracing requests across the system.

use axum::{extract::Request, middleware::Next, response::Response};
use uuid::Uuid;

/// Request correlation ID header name.
pub const CORRELATION_ID_HEADER: &str = "X-Correlation-ID";

/// Extension key for storing correlation ID in request extensions.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    /// Create a new correlation ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the correlation ID as a string.
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Middleware to add correlation ID to requests.
pub async fn correlation_middleware(mut request: Request, next: Next) -> Response {
    // Try to extract correlation ID from header, or generate a new one
    let correlation_id = request
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(CorrelationId)
        .unwrap_or_else(CorrelationId::new);

    // Store correlation ID in request extensions
    request.extensions_mut().insert(correlation_id.clone());

    // Add to tracing span
    let span = tracing::info_span!(
        "request",
        correlation_id = %correlation_id,
        method = %request.method(),
        uri = %request.uri(),
    );

    // Process request with correlation context
    let response = {
        let _enter = span.enter();
        next.run(request).await
    };

    // Add correlation ID to response headers
    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        CORRELATION_ID_HEADER,
        correlation_id.as_str().parse().unwrap(),
    );

    Response::from_parts(parts, body)
}

/// Extension trait to extract correlation ID from requests.
#[allow(dead_code)]
pub trait CorrelationIdExt {
    /// Get the correlation ID from the request.
    fn correlation_id(&self) -> Option<&CorrelationId>;
}

impl CorrelationIdExt for Request {
    fn correlation_id(&self) -> Option<&CorrelationId> {
        self.extensions().get::<CorrelationId>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_new() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn test_correlation_id_display() {
        let id = CorrelationId::new();
        let s = format!("{}", id);
        assert!(Uuid::parse_str(&s).is_ok());
    }

    #[test]
    fn test_correlation_id_as_str() {
        let id = CorrelationId::new();
        let s = id.as_str();
        assert!(Uuid::parse_str(&s).is_ok());
        assert_eq!(s, id.0.to_string());
    }
}
