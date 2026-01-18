//! ETag Support for Conditional Requests
//!
//! Provides ETag generation and validation for HTTP caching:
//! - Strong and weak ETag generation
//! - If-None-Match header support
//! - If-Match header support for safe updates
//! - 304 Not Modified responses
//! - Automatic ETag generation from response body

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use blake3::Hasher;
use std::sync::Arc;
use tracing::{debug, trace};

/// ETag type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETag {
    /// Strong ETag (exact match required)
    Strong(String),
    /// Weak ETag (semantic equivalence)
    Weak(String),
}

impl ETag {
    /// Create a strong ETag
    pub fn strong(value: impl Into<String>) -> Self {
        ETag::Strong(value.into())
    }

    /// Create a weak ETag
    pub fn weak(value: impl Into<String>) -> Self {
        ETag::Weak(value.into())
    }

    /// Generate ETag from content using BLAKE3 hash
    pub fn from_content(content: &[u8], weak: bool) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(content);
        let hash = hasher.finalize();
        let etag_value = format!("{}", hash.to_hex());

        if weak {
            ETag::Weak(etag_value)
        } else {
            ETag::Strong(etag_value)
        }
    }

    /// Convert to HTTP header value
    pub fn to_header_value(&self) -> String {
        match self {
            ETag::Strong(value) => format!("\"{}\"", value),
            ETag::Weak(value) => format!("W/\"{}\"", value),
        }
    }

    /// Parse ETag from header value
    pub fn from_header_value(value: &str) -> Option<Self> {
        let value = value.trim();

        if let Some(stripped) = value.strip_prefix("W/\"") {
            if let Some(etag) = stripped.strip_suffix('"') {
                return Some(ETag::Weak(etag.to_string()));
            }
        } else if let Some(stripped) = value.strip_prefix('"') {
            if let Some(etag) = stripped.strip_suffix('"') {
                return Some(ETag::Strong(etag.to_string()));
            }
        }

        None
    }

    /// Check if this ETag matches another (considering weak/strong semantics)
    pub fn matches(&self, other: &ETag, weak_comparison: bool) -> bool {
        match (self, other) {
            (ETag::Strong(a), ETag::Strong(b)) => a == b,
            (ETag::Weak(a), ETag::Weak(b)) if weak_comparison => a == b,
            (ETag::Strong(a), ETag::Weak(b)) if weak_comparison => a == b,
            (ETag::Weak(a), ETag::Strong(b)) if weak_comparison => a == b,
            _ => false,
        }
    }

    /// Get the raw value (without W/ prefix or quotes)
    pub fn value(&self) -> &str {
        match self {
            ETag::Strong(v) | ETag::Weak(v) => v,
        }
    }

    /// Check if this is a weak ETag
    pub fn is_weak(&self) -> bool {
        matches!(self, ETag::Weak(_))
    }
}

/// ETag configuration
#[derive(Debug, Clone)]
pub struct ETagConfig {
    /// Enable ETag generation
    pub enabled: bool,
    /// Use weak ETags by default
    pub use_weak_etags: bool,
    /// Minimum response size to generate ETags (bytes)
    pub min_size: usize,
    /// Maximum response size to generate ETags (bytes)
    pub max_size: usize,
    /// Content types to generate ETags for
    pub etag_content_types: Vec<String>,
}

impl Default for ETagConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_weak_etags: false,
            min_size: 0,
            max_size: 10 * 1024 * 1024, // 10 MB
            etag_content_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "text/javascript".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/xml".to_string(),
                "text/plain".to_string(),
                "image/svg+xml".to_string(),
            ],
        }
    }
}

/// ETag manager
pub struct ETagManager {
    config: ETagConfig,
}

impl ETagManager {
    /// Create new ETag manager
    pub fn new(config: ETagConfig) -> Self {
        Self { config }
    }

    /// Check if content type should have ETag
    pub fn should_generate_etag(&self, content_type: Option<&str>, size: usize) -> bool {
        if !self.config.enabled {
            return false;
        }

        if size < self.config.min_size || size > self.config.max_size {
            return false;
        }

        if let Some(content_type) = content_type {
            let content_type_base = content_type
                .split(';')
                .next()
                .unwrap_or(content_type)
                .trim();
            self.config
                .etag_content_types
                .iter()
                .any(|ct| ct == content_type_base)
        } else {
            false
        }
    }

    /// Parse If-None-Match header
    pub fn parse_if_none_match(&self, headers: &HeaderMap) -> Vec<ETag> {
        headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(|value| {
                if value.trim() == "*" {
                    vec![ETag::Strong("*".to_string())]
                } else {
                    value
                        .split(',')
                        .filter_map(ETag::from_header_value)
                        .collect()
                }
            })
            .unwrap_or_default()
    }

    /// Parse If-Match header
    pub fn parse_if_match(&self, headers: &HeaderMap) -> Vec<ETag> {
        headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(|value| {
                if value.trim() == "*" {
                    vec![ETag::Strong("*".to_string())]
                } else {
                    value
                        .split(',')
                        .filter_map(ETag::from_header_value)
                        .collect()
                }
            })
            .unwrap_or_default()
    }

    /// Check if request matches any of the ETags
    pub fn matches_any(&self, etag: &ETag, etags: &[ETag], weak_comparison: bool) -> bool {
        etags.iter().any(|e| {
            if e.value() == "*" {
                true
            } else {
                etag.matches(e, weak_comparison)
            }
        })
    }
}

/// Middleware to handle ETags and conditional requests
pub async fn etag_middleware(
    State(manager): State<Arc<ETagManager>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get conditional headers
    let if_none_match = manager.parse_if_none_match(request.headers());
    let method = request.method().clone();

    // Process request
    let response = next.run(request).await;

    // Extract response parts
    let (parts, body) = response.into_parts();
    let status = parts.status;
    let headers = parts.headers.clone();

    // Only process successful responses
    if !status.is_success() {
        let mut response = Response::new(Body::from(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap_or_default(),
        ));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }

    // Read response body
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Check if we should generate ETag
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());

    if !manager.should_generate_etag(content_type, body_bytes.len()) {
        trace!("Skipping ETag generation for response");
        let mut response = Response::new(Body::from(body_bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }

    // Generate ETag
    let etag = ETag::from_content(&body_bytes, manager.config.use_weak_etags);

    // Check If-None-Match for GET/HEAD requests
    if (method == axum::http::Method::GET || method == axum::http::Method::HEAD)
        && !if_none_match.is_empty()
        && manager.matches_any(&etag, &if_none_match, true)
    {
        debug!("ETag matched, returning 304 Not Modified");

        // Return 304 Not Modified
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;

        // Copy some headers from original response
        let mut new_headers = HeaderMap::new();
        for header_name in &[
            header::CACHE_CONTROL,
            header::CONTENT_LOCATION,
            header::DATE,
            header::EXPIRES,
            header::VARY,
        ] {
            if let Some(value) = headers.get(header_name) {
                new_headers.insert(header_name, value.clone());
            }
        }

        // Add ETag header
        if let Ok(etag_value) = HeaderValue::from_str(&etag.to_header_value()) {
            new_headers.insert(header::ETAG, etag_value);
        }

        *response.headers_mut() = new_headers;

        // Record metrics
        crate::metrics::record_etag_hit();

        return Ok(response);
    }

    // Build normal response with ETag
    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = status;
    *response.headers_mut() = headers;

    // Add ETag header
    if let Ok(etag_value) = HeaderValue::from_str(&etag.to_header_value()) {
        response.headers_mut().insert(header::ETAG, etag_value);
    }

    // Record metrics
    crate::metrics::record_etag_generated();

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_creation() {
        let strong = ETag::strong("abc123");
        assert!(!strong.is_weak());
        assert_eq!(strong.value(), "abc123");
        assert_eq!(strong.to_header_value(), "\"abc123\"");

        let weak = ETag::weak("abc123");
        assert!(weak.is_weak());
        assert_eq!(weak.value(), "abc123");
        assert_eq!(weak.to_header_value(), "W/\"abc123\"");
    }

    #[test]
    fn test_etag_from_content() {
        let content = b"Hello, World!";
        let etag = ETag::from_content(content, false);
        assert!(!etag.is_weak());

        let weak_etag = ETag::from_content(content, true);
        assert!(weak_etag.is_weak());
        assert_eq!(etag.value(), weak_etag.value());
    }

    #[test]
    fn test_etag_parsing() {
        assert_eq!(
            ETag::from_header_value("\"abc123\""),
            Some(ETag::Strong("abc123".to_string()))
        );
        assert_eq!(
            ETag::from_header_value("W/\"abc123\""),
            Some(ETag::Weak("abc123".to_string()))
        );
        assert_eq!(ETag::from_header_value("invalid"), None);
    }

    #[test]
    fn test_etag_matching() {
        let etag1 = ETag::strong("abc");
        let etag2 = ETag::strong("abc");
        let etag3 = ETag::strong("def");
        let weak1 = ETag::weak("abc");

        assert!(etag1.matches(&etag2, false));
        assert!(!etag1.matches(&etag3, false));
        assert!(!etag1.matches(&weak1, false));
        assert!(etag1.matches(&weak1, true));
    }

    #[test]
    fn test_should_generate_etag() {
        let manager = ETagManager::new(ETagConfig::default());

        assert!(manager.should_generate_etag(Some("application/json"), 1000));
        assert!(manager.should_generate_etag(Some("text/html"), 1000));
        assert!(!manager.should_generate_etag(Some("image/png"), 1000));
        assert!(!manager.should_generate_etag(Some("application/json"), 20 * 1024 * 1024));
    }

    #[test]
    fn test_parse_if_none_match() {
        let manager = ETagManager::new(ETagConfig::default());
        let mut headers = HeaderMap::new();

        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"abc123\""),
        );
        let etags = manager.parse_if_none_match(&headers);
        assert_eq!(etags.len(), 1);
        assert_eq!(etags[0], ETag::Strong("abc123".to_string()));

        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("\"abc\", W/\"def\""),
        );
        let etags = manager.parse_if_none_match(&headers);
        assert_eq!(etags.len(), 2);
    }

    #[test]
    fn test_matches_any() {
        let manager = ETagManager::new(ETagConfig::default());
        let etag = ETag::strong("abc");
        let etags = vec![ETag::strong("def"), ETag::strong("abc")];

        assert!(manager.matches_any(&etag, &etags, false));

        let wildcard = vec![ETag::strong("*")];
        assert!(manager.matches_any(&etag, &wildcard, false));
    }

    #[test]
    fn test_etag_header_value_format() {
        let etag = ETag::strong("test123");
        assert_eq!(etag.to_header_value(), "\"test123\"");

        let weak = ETag::weak("test123");
        assert_eq!(weak.to_header_value(), "W/\"test123\"");
    }
}
