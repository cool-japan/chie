//! Error tracking and aggregation system for monitoring application errors
//!
//! This module provides comprehensive error tracking functionality including:
//! - Error occurrence tracking with counts and timestamps
//! - Error aggregation by type, endpoint, and correlation ID
//! - Error rate monitoring and alerting
//! - Error statistics and reporting

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use tracing::{error, warn};

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorSeverity {
    /// Debug-level errors (typically shouldn't reach production)
    Debug,
    /// Informational errors (expected failures like validation errors)
    Info,
    /// Warning-level errors (recoverable errors)
    Warning,
    /// Error-level (unexpected failures)
    Error,
    /// Critical errors (system failures requiring immediate attention)
    Critical,
}

impl ErrorSeverity {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorSeverity::Debug => "debug",
            ErrorSeverity::Info => "info",
            ErrorSeverity::Warning => "warning",
            ErrorSeverity::Error => "error",
            ErrorSeverity::Critical => "critical",
        }
    }
}

/// Information about a tracked error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Unique error identifier
    pub id: String,
    /// Error type/category
    pub error_type: String,
    /// Error message
    pub message: String,
    /// Stack trace (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
    /// Severity level
    pub severity: ErrorSeverity,
    /// Timestamp when the error occurred
    pub timestamp: DateTime<Utc>,
    /// Endpoint where error occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Correlation ID for request tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// User ID (if authenticated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// Aggregated error statistics for a specific error type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorAggregate {
    /// Error type
    pub error_type: String,
    /// Total occurrences
    pub count: usize,
    /// First occurrence timestamp
    pub first_seen: DateTime<Utc>,
    /// Last occurrence timestamp
    pub last_seen: DateTime<Utc>,
    /// Affected endpoints
    pub endpoints: Vec<String>,
    /// Affected users (user IDs)
    pub users: Vec<String>,
    /// Severity level
    pub severity: ErrorSeverity,
    /// Sample error message
    pub sample_message: String,
}

/// Error rate statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRateStats {
    /// Total errors in the time window
    pub total_errors: usize,
    /// Errors per minute
    pub errors_per_minute: f64,
    /// Error rate (errors per total requests)
    pub error_rate: f64,
    /// Time window in minutes
    pub window_minutes: i64,
    /// Breakdown by severity
    pub by_severity: HashMap<String, usize>,
    /// Breakdown by endpoint
    pub by_endpoint: HashMap<String, usize>,
}

/// Configuration for error tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTrackingConfig {
    /// Maximum number of errors to keep in history
    pub max_history: usize,
    /// Time window for rate calculations (minutes)
    pub rate_window_minutes: i64,
    /// Error rate threshold for alerting (percentage)
    pub alert_threshold: f64,
    /// Whether to log errors to tracing system
    pub log_to_tracing: bool,
    /// Whether to include stack traces
    pub include_stack_traces: bool,
}

impl Default for ErrorTrackingConfig {
    fn default() -> Self {
        Self {
            max_history: 10000,
            rate_window_minutes: 5,
            alert_threshold: 5.0, // Alert if error rate > 5%
            log_to_tracing: true,
            include_stack_traces: true,
        }
    }
}

/// Error tracker that aggregates and monitors application errors
#[derive(Debug, Clone)]
pub struct ErrorTracker {
    config: Arc<ErrorTrackingConfig>,
    errors: Arc<RwLock<VecDeque<ErrorInfo>>>,
    aggregates: Arc<RwLock<HashMap<String, ErrorAggregate>>>,
    total_requests: Arc<RwLock<usize>>,
}

impl ErrorTracker {
    /// Create a new error tracker with the given configuration
    pub fn new(config: ErrorTrackingConfig) -> Self {
        Self {
            config: Arc::new(config),
            errors: Arc::new(RwLock::new(VecDeque::new())),
            aggregates: Arc::new(RwLock::new(HashMap::new())),
            total_requests: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a new error tracker with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ErrorTrackingConfig::default())
    }

    /// Track an error
    #[allow(clippy::too_many_arguments)]
    pub fn track_error(
        &self,
        error_type: impl Into<String>,
        message: impl Into<String>,
        severity: ErrorSeverity,
        stack_trace: Option<String>,
        endpoint: Option<String>,
        correlation_id: Option<String>,
        user_id: Option<String>,
        metadata: Option<HashMap<String, String>>,
    ) {
        let error_type = error_type.into();
        let message = message.into();

        let error_info = ErrorInfo {
            id: uuid::Uuid::new_v4().to_string(),
            error_type: error_type.clone(),
            message: message.clone(),
            stack_trace: if self.config.include_stack_traces {
                stack_trace
            } else {
                None
            },
            severity,
            timestamp: Utc::now(),
            endpoint: endpoint.clone(),
            correlation_id: correlation_id.clone(),
            user_id: user_id.clone(),
            metadata,
        };

        // Log to tracing if enabled
        if self.config.log_to_tracing {
            match severity {
                ErrorSeverity::Critical => {
                    error!(
                        error_type = %error_type,
                        message = %message,
                        correlation_id = ?correlation_id,
                        endpoint = ?endpoint,
                        "Critical error tracked"
                    );
                }
                ErrorSeverity::Error => {
                    error!(
                        error_type = %error_type,
                        message = %message,
                        correlation_id = ?correlation_id,
                        endpoint = ?endpoint,
                        "Error tracked"
                    );
                }
                ErrorSeverity::Warning => {
                    warn!(
                        error_type = %error_type,
                        message = %message,
                        correlation_id = ?correlation_id,
                        endpoint = ?endpoint,
                        "Warning tracked"
                    );
                }
                _ => {}
            }
        }

        // Store in history
        {
            let mut errors = self.errors.write().unwrap();
            if errors.len() >= self.config.max_history {
                errors.pop_front();
            }
            errors.push_back(error_info.clone());
        }

        // Update aggregates
        {
            let mut aggregates = self.aggregates.write().unwrap();
            aggregates
                .entry(error_type.clone())
                .and_modify(|agg| {
                    agg.count += 1;
                    agg.last_seen = error_info.timestamp;
                    if let Some(ref ep) = endpoint {
                        if !agg.endpoints.contains(ep) {
                            agg.endpoints.push(ep.clone());
                        }
                    }
                    if let Some(ref uid) = user_id {
                        if !agg.users.contains(uid) {
                            agg.users.push(uid.clone());
                        }
                    }
                })
                .or_insert_with(|| ErrorAggregate {
                    error_type: error_type.clone(),
                    count: 1,
                    first_seen: error_info.timestamp,
                    last_seen: error_info.timestamp,
                    endpoints: endpoint.into_iter().collect(),
                    users: user_id.into_iter().collect(),
                    severity,
                    sample_message: message,
                });
        }

        // Record metrics
        crate::metrics::record_error_tracked(&error_type, severity.as_str());

        // Check error rate and alert if necessary
        self.check_error_rate();
    }

    /// Increment total requests counter
    pub fn record_request(&self) {
        let mut total = self.total_requests.write().unwrap();
        *total += 1;
    }

    /// Get recent errors
    pub fn get_recent_errors(&self, limit: usize) -> Vec<ErrorInfo> {
        let errors = self.errors.read().unwrap();
        errors.iter().rev().take(limit).cloned().collect()
    }

    /// Get error aggregates
    pub fn get_aggregates(&self) -> Vec<ErrorAggregate> {
        let aggregates = self.aggregates.read().unwrap();
        let mut result: Vec<_> = aggregates.values().cloned().collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result
    }

    /// Get error rate statistics
    pub fn get_error_rate_stats(&self) -> ErrorRateStats {
        let errors = self.errors.read().unwrap();
        let total_requests = *self.total_requests.read().unwrap();

        let cutoff = Utc::now() - ChronoDuration::minutes(self.config.rate_window_minutes);
        let recent_errors: Vec<_> = errors.iter().filter(|e| e.timestamp > cutoff).collect();

        let total_errors = recent_errors.len();
        let errors_per_minute = total_errors as f64 / self.config.rate_window_minutes as f64;
        let error_rate = if total_requests > 0 {
            (total_errors as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        // Group by severity
        let mut by_severity = HashMap::new();
        for error in &recent_errors {
            *by_severity
                .entry(error.severity.as_str().to_string())
                .or_insert(0) += 1;
        }

        // Group by endpoint
        let mut by_endpoint = HashMap::new();
        for error in &recent_errors {
            if let Some(ref ep) = error.endpoint {
                *by_endpoint.entry(ep.clone()).or_insert(0) += 1;
            }
        }

        ErrorRateStats {
            total_errors,
            errors_per_minute,
            error_rate,
            window_minutes: self.config.rate_window_minutes,
            by_severity,
            by_endpoint,
        }
    }

    /// Clear error history
    pub fn clear_history(&self) {
        let mut errors = self.errors.write().unwrap();
        errors.clear();
        let mut aggregates = self.aggregates.write().unwrap();
        aggregates.clear();
    }

    /// Check error rate and trigger alert if necessary
    fn check_error_rate(&self) {
        let stats = self.get_error_rate_stats();
        if stats.error_rate > self.config.alert_threshold {
            warn!(
                error_rate = stats.error_rate,
                threshold = self.config.alert_threshold,
                errors_per_minute = stats.errors_per_minute,
                "High error rate detected!"
            );
            crate::metrics::record_error_rate_alert(stats.error_rate);
        }
    }

    /// Get configuration
    pub fn config(&self) -> &ErrorTrackingConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_tracker_creation() {
        let tracker = ErrorTracker::with_defaults();
        assert_eq!(tracker.config().max_history, 10000);
        assert_eq!(tracker.config().rate_window_minutes, 5);
    }

    #[test]
    fn test_track_error() {
        let config = ErrorTrackingConfig {
            max_history: 100,
            rate_window_minutes: 5,
            alert_threshold: 10.0,
            log_to_tracing: false,
            include_stack_traces: true,
        };
        let tracker = ErrorTracker::new(config);

        tracker.track_error(
            "DatabaseError",
            "Connection timeout",
            ErrorSeverity::Error,
            Some("stack trace here".to_string()),
            Some("/api/users".to_string()),
            Some("corr-123".to_string()),
            Some("user-456".to_string()),
            None,
        );

        let errors = tracker.get_recent_errors(10);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error_type, "DatabaseError");
        assert_eq!(errors[0].message, "Connection timeout");
        assert_eq!(errors[0].severity, ErrorSeverity::Error);
    }

    #[test]
    fn test_error_aggregates() {
        let tracker = ErrorTracker::with_defaults();

        // Track multiple errors of the same type
        for i in 0..5 {
            tracker.track_error(
                "ValidationError",
                format!("Validation failed {}", i),
                ErrorSeverity::Warning,
                None,
                Some("/api/register".to_string()),
                None,
                None,
                None,
            );
        }

        // Track errors of a different type
        for i in 0..3 {
            tracker.track_error(
                "AuthenticationError",
                format!("Auth failed {}", i),
                ErrorSeverity::Error,
                None,
                Some("/api/login".to_string()),
                None,
                None,
                None,
            );
        }

        let aggregates = tracker.get_aggregates();
        assert_eq!(aggregates.len(), 2);

        // Check that ValidationError has count 5
        let validation_agg = aggregates
            .iter()
            .find(|a| a.error_type == "ValidationError")
            .unwrap();
        assert_eq!(validation_agg.count, 5);
        assert!(
            validation_agg
                .endpoints
                .contains(&"/api/register".to_string())
        );

        // Check that AuthenticationError has count 3
        let auth_agg = aggregates
            .iter()
            .find(|a| a.error_type == "AuthenticationError")
            .unwrap();
        assert_eq!(auth_agg.count, 3);
    }

    #[test]
    fn test_error_rate_stats() {
        let config = ErrorTrackingConfig {
            max_history: 100,
            rate_window_minutes: 5,
            alert_threshold: 10.0,
            log_to_tracing: false,
            include_stack_traces: false,
        };
        let tracker = ErrorTracker::new(config);

        // Record some requests
        for _ in 0..100 {
            tracker.record_request();
        }

        // Track some errors
        for _ in 0..10 {
            tracker.track_error(
                "SomeError",
                "Error message",
                ErrorSeverity::Error,
                None,
                Some("/api/test".to_string()),
                None,
                None,
                None,
            );
        }

        let stats = tracker.get_error_rate_stats();
        assert_eq!(stats.total_errors, 10);
        assert_eq!(stats.error_rate, 10.0); // 10/100 * 100 = 10%
        assert!(stats.errors_per_minute > 0.0);
    }

    #[test]
    fn test_error_history_limit() {
        let config = ErrorTrackingConfig {
            max_history: 5,
            rate_window_minutes: 5,
            alert_threshold: 10.0,
            log_to_tracing: false,
            include_stack_traces: false,
        };
        let tracker = ErrorTracker::new(config);

        // Track more errors than the limit
        for i in 0..10 {
            tracker.track_error(
                "TestError",
                format!("Error {}", i),
                ErrorSeverity::Error,
                None,
                None,
                None,
                None,
                None,
            );
        }

        let errors = tracker.get_recent_errors(100);
        assert_eq!(errors.len(), 5); // Should only keep the last 5

        // Verify we have the latest errors
        assert_eq!(errors[0].message, "Error 9");
        assert_eq!(errors[4].message, "Error 5");
    }

    #[test]
    fn test_clear_history() {
        let tracker = ErrorTracker::with_defaults();

        tracker.track_error(
            "Error1",
            "Message 1",
            ErrorSeverity::Error,
            None,
            None,
            None,
            None,
            None,
        );
        tracker.track_error(
            "Error2",
            "Message 2",
            ErrorSeverity::Warning,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(tracker.get_recent_errors(10).len(), 2);
        assert_eq!(tracker.get_aggregates().len(), 2);

        tracker.clear_history();

        assert_eq!(tracker.get_recent_errors(10).len(), 0);
        assert_eq!(tracker.get_aggregates().len(), 0);
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(ErrorSeverity::Debug.as_str(), "debug");
        assert_eq!(ErrorSeverity::Info.as_str(), "info");
        assert_eq!(ErrorSeverity::Warning.as_str(), "warning");
        assert_eq!(ErrorSeverity::Error.as_str(), "error");
        assert_eq!(ErrorSeverity::Critical.as_str(), "critical");
    }
}
