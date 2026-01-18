//! API-related types for CHIE Protocol.
//!
//! This module contains types used for API requests and responses:
//! - Response wrappers (`ApiResponse`, `ApiError`, `PaginatedResponse`)
//! - Proof submission results
//! - Health check responses
//! - User and reward types
//! - Leaderboard entries

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::{PeerIdString, Points};
use super::enums::{ServiceStatus, UserRole};

/// User account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub peer_id: Option<PeerIdString>,
    pub public_key: Option<Vec<u8>>,
    pub points_balance: Points,
    pub referrer_id: Option<uuid::Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Reward distribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RewardDistribution {
    pub proof_id: uuid::Uuid,
    pub provider_reward: Points,
    pub creator_reward: Points,
    pub referrer_rewards: Vec<(uuid::Uuid, Points)>,
    pub platform_fee: Points,
    pub total_distributed: Points,
}

/// Leaderboard entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LeaderboardEntry {
    pub rank: u32,
    pub user_id: uuid::Uuid,
    pub username: String,
    pub total_bandwidth_tb: f64,
    pub total_earnings: Points,
    pub badge: Option<String>,
}

/// Standard API response wrapper for successful operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ApiResponse<T> {
    /// Indicates success.
    pub success: bool,
    /// Response data.
    pub data: T,
    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response.
    #[must_use]
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data,
            message: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a successful response with a message.
    #[must_use]
    pub fn success_with_message(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data,
            message: Some(message.into()),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Standard API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ApiError {
    /// Indicates failure.
    pub success: bool,
    /// Error code.
    pub error_code: String,
    /// Error message.
    pub message: String,
    /// Optional detailed errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
    /// Response timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ApiError {
    /// Create a new error response.
    #[must_use]
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            error_code: error_code.into(),
            message: message.into(),
            details: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create an error response with details.
    #[must_use]
    pub fn with_details(
        error_code: impl Into<String>,
        message: impl Into<String>,
        details: Vec<String>,
    ) -> Self {
        Self {
            success: false,
            error_code: error_code.into(),
            message: message.into(),
            details: Some(details),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Paginated response for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct PaginatedResponse<T> {
    /// Items in the current page.
    pub items: Vec<T>,
    /// Total number of items.
    pub total: u64,
    /// Current page offset.
    pub offset: u64,
    /// Items per page.
    pub limit: u64,
    /// Whether there are more items.
    pub has_more: bool,
}

impl<T> PaginatedResponse<T> {
    /// Create a paginated response.
    #[must_use]
    pub fn new(items: Vec<T>, total: u64, offset: u64, limit: u64) -> Self {
        let has_more = offset + (items.len() as u64) < total;
        Self {
            items,
            total,
            offset,
            limit,
            has_more,
        }
    }

    /// Create an empty paginated response.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            offset: 0,
            limit: 0,
            has_more: false,
        }
    }
}

/// Proof submission result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ProofSubmissionResult {
    /// Unique proof ID.
    pub proof_id: uuid::Uuid,
    /// Whether the proof was accepted.
    pub accepted: bool,
    /// Reason for rejection (if not accepted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    /// Reward amount (if accepted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_points: Option<Points>,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct HealthCheckResponse {
    /// Service status.
    pub status: ServiceStatus,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Service version.
    pub version: String,
    /// Database connection status.
    pub database_ok: bool,
    /// Cache connection status.
    pub cache_ok: bool,
}

/// Cursor for cursor-based pagination (more efficient for large datasets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Cursor {
    /// Opaque cursor value (typically base64-encoded position data).
    pub value: String,
    /// Optional timestamp for time-based cursors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
}

impl Cursor {
    /// Create a new cursor from a value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            timestamp: None,
        }
    }

    /// Create a cursor with a timestamp.
    #[must_use]
    pub fn with_timestamp(value: impl Into<String>, timestamp: i64) -> Self {
        Self {
            value: value.into(),
            timestamp: Some(timestamp),
        }
    }

    /// Create a cursor from an ID (encodes as base64).
    #[must_use]
    pub fn from_id(id: &uuid::Uuid) -> Self {
        use std::fmt::Write;
        let mut buf = String::new();
        write!(&mut buf, "{id}").expect("UUID formatting failed");
        Self::new(buf)
    }

    /// Create a cursor from a timestamp.
    #[must_use]
    pub fn from_timestamp(timestamp: i64) -> Self {
        Self::with_timestamp(timestamp.to_string(), timestamp)
    }
}

/// Cursor-based paginated response (more efficient for large datasets).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CursorPaginatedResponse<T> {
    /// Items in the current page.
    pub items: Vec<T>,
    /// Cursor for the next page (if `has_more` is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    /// Cursor for the previous page (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<Cursor>,
    /// Number of items requested.
    pub limit: u64,
    /// Whether there are more items available.
    pub has_more: bool,
}

impl<T> CursorPaginatedResponse<T> {
    /// Create a new cursor-based paginated response.
    #[must_use]
    pub fn new(
        items: Vec<T>,
        next_cursor: Option<Cursor>,
        prev_cursor: Option<Cursor>,
        limit: u64,
    ) -> Self {
        let has_more = next_cursor.is_some();
        Self {
            items,
            next_cursor,
            prev_cursor,
            limit,
            has_more,
        }
    }

    /// Create an empty cursor-based paginated response.
    #[must_use]
    pub fn empty(limit: u64) -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            prev_cursor: None,
            limit,
            has_more: false,
        }
    }

    /// Create a response without previous cursor.
    #[must_use]
    pub fn forward_only(items: Vec<T>, next_cursor: Option<Cursor>, limit: u64) -> Self {
        Self::new(items, next_cursor, None, limit)
    }
}

/// API version for header-based versioning
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ApiVersion {
    /// API version 1
    V1,
    /// API version 2 (future)
    V2,
}

impl ApiVersion {
    /// Get the version string (e.g., "v1")
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    /// Get the version as an Accept/Content-Type header value
    #[must_use]
    pub fn as_header_value(&self) -> String {
        format!("application/vnd.chie.{}+json", self.as_str())
    }

    /// Get the current/default API version
    #[must_use]
    pub const fn current() -> Self {
        Self::V1
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        Self::current()
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ApiVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            _ => Err(format!("Invalid API version: {s}")),
        }
    }
}

/// HATEOAS link for hypermedia-driven API navigation.
///
/// Links allow clients to discover available actions and navigate the API
/// without hardcoded URLs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Link {
    /// Link relation type (e.g., "self", "next", "prev", "related")
    pub rel: String,
    /// Target URI
    pub href: String,
    /// HTTP method for this link (default: GET)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Human-readable title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl Link {
    /// Create a new link
    #[must_use]
    pub fn new(rel: impl Into<String>, href: impl Into<String>) -> Self {
        Self {
            rel: rel.into(),
            href: href.into(),
            method: None,
            title: None,
        }
    }

    /// Create a link with a specific HTTP method
    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Create a link with a title
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Create a "self" link
    #[must_use]
    pub fn self_link(href: impl Into<String>) -> Self {
        Self::new("self", href)
    }

    /// Create a "next" link for pagination
    #[must_use]
    pub fn next(href: impl Into<String>) -> Self {
        Self::new("next", href).with_title("Next page")
    }

    /// Create a "prev" link for pagination
    #[must_use]
    pub fn prev(href: impl Into<String>) -> Self {
        Self::new("prev", href).with_title("Previous page")
    }

    /// Create a "first" link for pagination
    #[must_use]
    pub fn first(href: impl Into<String>) -> Self {
        Self::new("first", href).with_title("First page")
    }

    /// Create a "last" link for pagination
    #[must_use]
    pub fn last(href: impl Into<String>) -> Self {
        Self::new("last", href).with_title("Last page")
    }
}

/// Collection of HATEOAS links
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Links {
    /// Links associated with this resource
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub links: Vec<Link>,
}

impl Links {
    /// Create an empty links collection
    #[must_use]
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// Add a link object to the collection
    #[must_use]
    pub fn with_link(mut self, link: Link) -> Self {
        self.links.push(link);
        self
    }

    /// Add a link from components
    #[must_use]
    pub fn add_link(mut self, rel: impl Into<String>, href: impl Into<String>) -> Self {
        self.links.push(Link::new(rel, href));
        self
    }

    /// Check if the collection is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Get the number of links
    #[must_use]
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Find a link by relation type
    #[must_use]
    pub fn find(&self, rel: &str) -> Option<&Link> {
        self.links.iter().find(|link| link.rel == rel)
    }
}

impl From<Vec<Link>> for Links {
    fn from(links: Vec<Link>) -> Self {
        Self { links }
    }
}

/// Rate limit response headers following RFC 6585 and draft standards.
///
/// These headers inform clients about their rate limit status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RateLimitHeaders {
    /// Maximum requests allowed in the time window
    pub limit: u32,
    /// Remaining requests in the current window
    pub remaining: u32,
    /// Unix timestamp when the rate limit window resets
    pub reset: i64,
    /// Time until reset in seconds (for convenience)
    pub retry_after: Option<u64>,
}

impl RateLimitHeaders {
    /// Create new rate limit headers
    #[must_use]
    pub fn new(limit: u32, remaining: u32, reset: i64) -> Self {
        Self {
            limit,
            remaining,
            reset,
            retry_after: None,
        }
    }

    /// Create rate limit headers when limit is exceeded
    #[must_use]
    pub fn exceeded(limit: u32, reset: i64) -> Self {
        let now = chrono::Utc::now().timestamp();
        let retry_after = if reset > now {
            Some((reset - now) as u64)
        } else {
            Some(0)
        };

        Self {
            limit,
            remaining: 0,
            reset,
            retry_after,
        }
    }

    /// Check if rate limit is exceeded
    #[must_use]
    pub fn is_exceeded(&self) -> bool {
        self.remaining == 0
    }

    /// Get the utilization as a percentage (0.0 to 1.0)
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self) -> f64 {
        if self.limit == 0 {
            return 0.0;
        }
        let used = self.limit.saturating_sub(self.remaining);
        (used as f64) / (self.limit as f64)
    }

    /// Format as HTTP header pairs (name, value)
    #[must_use]
    pub fn as_http_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("X-RateLimit-Limit", self.limit.to_string()),
            ("X-RateLimit-Remaining", self.remaining.to_string()),
            ("X-RateLimit-Reset", self.reset.to_string()),
        ];

        if let Some(retry_after) = self.retry_after {
            headers.push(("Retry-After", retry_after.to_string()));
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // API Response tests
    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");
        assert!(response.success);
        assert_eq!(response.data, "test data");
        assert!(response.message.is_none());
    }

    #[test]
    fn test_api_response_with_message() {
        let response = ApiResponse::success_with_message("test data", "Success message");
        assert!(response.success);
        assert_eq!(response.data, "test data");
        assert_eq!(response.message, Some("Success message".to_string()));
    }

    #[test]
    fn test_api_error_new() {
        let error = ApiError::new("TEST_ERROR", "Test error message");
        assert!(!error.success);
        assert_eq!(error.error_code, "TEST_ERROR");
        assert_eq!(error.message, "Test error message");
        assert!(error.details.is_none());
    }

    #[test]
    fn test_api_error_with_details() {
        let details = vec!["Detail 1".to_string(), "Detail 2".to_string()];
        let error = ApiError::with_details("TEST_ERROR", "Test error message", details.clone());
        assert!(!error.success);
        assert_eq!(error.details, Some(details));
    }

    // Paginated Response tests
    #[test]
    fn test_paginated_response_new() {
        let items = vec![1, 2, 3];
        let response = PaginatedResponse::new(items.clone(), 10, 0, 3);
        assert_eq!(response.items, items);
        assert_eq!(response.total, 10);
        assert_eq!(response.offset, 0);
        assert_eq!(response.limit, 3);
        assert!(response.has_more);
    }

    #[test]
    fn test_paginated_response_no_more() {
        let items = vec![1, 2, 3];
        let response = PaginatedResponse::new(items.clone(), 3, 0, 3);
        assert!(!response.has_more);
    }

    #[test]
    fn test_paginated_response_empty() {
        let response: PaginatedResponse<i32> = PaginatedResponse::empty();
        assert_eq!(response.items.len(), 0);
        assert_eq!(response.total, 0);
        assert!(!response.has_more);
    }

    // Cursor tests
    #[test]
    fn test_cursor_new() {
        let cursor = Cursor::new("test_cursor_value");
        assert_eq!(cursor.value, "test_cursor_value");
        assert!(cursor.timestamp.is_none());
    }

    #[test]
    fn test_cursor_with_timestamp() {
        let timestamp = 1_234_567_890;
        let cursor = Cursor::with_timestamp("test_value", timestamp);
        assert_eq!(cursor.value, "test_value");
        assert_eq!(cursor.timestamp, Some(timestamp));
    }

    #[test]
    fn test_cursor_from_id() {
        let id = uuid::Uuid::new_v4();
        let cursor = Cursor::from_id(&id);
        assert_eq!(cursor.value, id.to_string());
        assert!(cursor.timestamp.is_none());
    }

    #[test]
    fn test_cursor_from_timestamp() {
        let timestamp = 1_234_567_890;
        let cursor = Cursor::from_timestamp(timestamp);
        assert_eq!(cursor.timestamp, Some(timestamp));
        assert_eq!(cursor.value, timestamp.to_string());
    }

    // CursorPaginatedResponse tests
    #[test]
    fn test_cursor_paginated_response_new() {
        let items = vec![1, 2, 3];
        let next_cursor = Some(Cursor::new("next"));
        let prev_cursor = Some(Cursor::new("prev"));
        let response = CursorPaginatedResponse::new(
            items.clone(),
            next_cursor.clone(),
            prev_cursor.clone(),
            10,
        );

        assert_eq!(response.items, items);
        assert_eq!(response.next_cursor, next_cursor);
        assert_eq!(response.prev_cursor, prev_cursor);
        assert_eq!(response.limit, 10);
        assert!(response.has_more);
    }

    #[test]
    fn test_cursor_paginated_response_no_more() {
        let items = vec![1, 2, 3];
        let response = CursorPaginatedResponse::new(items, None, None, 10);
        assert!(!response.has_more);
        assert!(response.next_cursor.is_none());
    }

    #[test]
    fn test_cursor_paginated_response_empty() {
        let response: CursorPaginatedResponse<i32> = CursorPaginatedResponse::empty(10);
        assert_eq!(response.items.len(), 0);
        assert!(response.next_cursor.is_none());
        assert!(!response.has_more);
    }

    #[test]
    fn test_cursor_paginated_response_forward_only() {
        let items = vec![1, 2, 3];
        let next_cursor = Some(Cursor::new("next"));
        let response =
            CursorPaginatedResponse::forward_only(items.clone(), next_cursor.clone(), 10);

        assert_eq!(response.items, items);
        assert_eq!(response.next_cursor, next_cursor);
        assert!(response.prev_cursor.is_none());
        assert!(response.has_more);
    }

    #[test]
    fn test_api_version() {
        let v1 = ApiVersion::V1;
        assert_eq!(v1.as_str(), "v1");
        assert_eq!(v1.as_header_value(), "application/vnd.chie.v1+json");

        let v2 = ApiVersion::V2;
        assert_eq!(v2.as_str(), "v2");
    }

    #[test]
    fn test_api_version_parse() {
        use std::str::FromStr;

        assert_eq!(ApiVersion::from_str("v1").unwrap(), ApiVersion::V1);
        assert_eq!(ApiVersion::from_str("v2").unwrap(), ApiVersion::V2);
        assert!(ApiVersion::from_str("v3").is_err());
        assert!(ApiVersion::from_str("invalid").is_err());
    }

    #[test]
    fn test_api_version_ordering() {
        assert!(ApiVersion::V1 < ApiVersion::V2);
        assert!(ApiVersion::V2 > ApiVersion::V1);
        assert_eq!(ApiVersion::V1, ApiVersion::V1);
    }

    // RateLimitHeaders tests
    #[test]
    fn test_rate_limit_headers_new() {
        let headers = RateLimitHeaders::new(100, 75, 1_700_000_000);
        assert_eq!(headers.limit, 100);
        assert_eq!(headers.remaining, 75);
        assert_eq!(headers.reset, 1_700_000_000);
        assert!(!headers.is_exceeded());
        assert!(headers.retry_after.is_none());
    }

    #[test]
    fn test_rate_limit_headers_exceeded() {
        let reset = chrono::Utc::now().timestamp() + 60;
        let headers = RateLimitHeaders::exceeded(100, reset);
        assert_eq!(headers.limit, 100);
        assert_eq!(headers.remaining, 0);
        assert!(headers.is_exceeded());
        assert!(headers.retry_after.is_some());
    }

    #[test]
    fn test_rate_limit_headers_utilization() {
        let headers = RateLimitHeaders::new(100, 25, 0);
        assert!((headers.utilization() - 0.75).abs() < 0.01);

        let headers = RateLimitHeaders::new(100, 100, 0);
        assert!((headers.utilization() - 0.0).abs() < 0.01);

        let headers = RateLimitHeaders::new(100, 0, 0);
        assert!((headers.utilization() - 1.0).abs() < 0.01);

        let headers = RateLimitHeaders::new(0, 0, 0);
        assert!((headers.utilization() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_rate_limit_headers_as_http_headers() {
        let headers = RateLimitHeaders::new(100, 75, 1_700_000_000);
        let http_headers = headers.as_http_headers();

        assert_eq!(http_headers.len(), 3);
        assert!(http_headers.contains(&("X-RateLimit-Limit", "100".to_string())));
        assert!(http_headers.contains(&("X-RateLimit-Remaining", "75".to_string())));
        assert!(http_headers.contains(&("X-RateLimit-Reset", "1700000000".to_string())));
    }

    #[test]
    fn test_rate_limit_headers_with_retry_after() {
        let reset = chrono::Utc::now().timestamp() + 60;
        let headers = RateLimitHeaders::exceeded(100, reset);
        let http_headers = headers.as_http_headers();

        assert_eq!(http_headers.len(), 4);
        assert!(http_headers.iter().any(|(name, _)| *name == "Retry-After"));
    }

    #[test]
    fn test_rate_limit_headers_serde() {
        let headers = RateLimitHeaders::new(100, 50, 1_700_000_000);
        let json = serde_json::to_string(&headers).unwrap();
        let decoded: RateLimitHeaders = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, headers);
    }

    // HATEOAS Link tests
    #[test]
    fn test_link_new() {
        let link = Link::new("self", "/api/users/123");
        assert_eq!(link.rel, "self");
        assert_eq!(link.href, "/api/users/123");
        assert!(link.method.is_none());
        assert!(link.title.is_none());
    }

    #[test]
    fn test_link_with_method() {
        let link = Link::new("update", "/api/users/123").with_method("PUT");
        assert_eq!(link.method, Some("PUT".to_string()));
    }

    #[test]
    fn test_link_with_title() {
        let link = Link::new("related", "/api/content/456").with_title("Related Content");
        assert_eq!(link.title, Some("Related Content".to_string()));
    }

    #[test]
    fn test_link_self_link() {
        let link = Link::self_link("/api/users/123");
        assert_eq!(link.rel, "self");
        assert_eq!(link.href, "/api/users/123");
    }

    #[test]
    fn test_link_pagination() {
        let next = Link::next("/api/users?page=2");
        assert_eq!(next.rel, "next");
        assert_eq!(next.title, Some("Next page".to_string()));

        let prev = Link::prev("/api/users?page=1");
        assert_eq!(prev.rel, "prev");

        let first = Link::first("/api/users?page=1");
        assert_eq!(first.rel, "first");

        let last = Link::last("/api/users?page=10");
        assert_eq!(last.rel, "last");
    }

    #[test]
    fn test_links_new() {
        let links = Links::new();
        assert!(links.is_empty());
        assert_eq!(links.len(), 0);
    }

    #[test]
    fn test_links_add() {
        let links = Links::new()
            .with_link(Link::self_link("/api/users/123"))
            .with_link(Link::next("/api/users?page=2"));

        assert!(!links.is_empty());
        assert_eq!(links.len(), 2);
    }

    #[test]
    fn test_links_add_link() {
        let links = Links::new()
            .add_link("self", "/api/users/123")
            .add_link("next", "/api/users?page=2");

        assert_eq!(links.len(), 2);
    }

    #[test]
    fn test_links_find() {
        let links = Links::new()
            .with_link(Link::self_link("/api/users/123"))
            .with_link(Link::next("/api/users?page=2"));

        let self_link = links.find("self");
        assert!(self_link.is_some());
        assert_eq!(self_link.unwrap().href, "/api/users/123");

        let missing_link = links.find("prev");
        assert!(missing_link.is_none());
    }

    #[test]
    fn test_links_from_vec() {
        let vec = vec![
            Link::self_link("/api/users/123"),
            Link::next("/api/users?page=2"),
        ];

        let links = Links::from(vec);
        assert_eq!(links.len(), 2);
    }

    #[test]
    fn test_link_serde() {
        let link = Link::new("self", "/api/users/123")
            .with_method("GET")
            .with_title("User Details");

        let json = serde_json::to_string(&link).unwrap();
        let decoded: Link = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, link);
    }

    #[test]
    fn test_links_serde() {
        let links = Links::new()
            .with_link(Link::self_link("/api/users/123"))
            .with_link(Link::next("/api/users?page=2"));

        let json = serde_json::to_string(&links).unwrap();
        let decoded: Links = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, links);
    }
}
