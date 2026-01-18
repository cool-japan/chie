//! Slow query logging middleware for database performance monitoring
//!
//! This module provides middleware to log slow database queries, helping identify
//! performance bottlenecks in the application. It tracks query execution time and
//! logs queries that exceed configured thresholds.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, warn};

/// Configuration for slow query logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowQueryConfig {
    /// Threshold in milliseconds above which queries are considered slow
    pub threshold_ms: u64,
    /// Maximum number of slow queries to keep in memory
    pub max_history: usize,
    /// Whether to log slow queries to the tracing system
    pub log_to_tracing: bool,
    /// Whether to include query parameters in logs (be careful with sensitive data)
    pub log_parameters: bool,
}

impl Default for SlowQueryConfig {
    fn default() -> Self {
        Self {
            threshold_ms: 100, // 100ms default threshold
            max_history: 1000,
            log_to_tracing: true,
            log_parameters: false, // Default to false for security
        }
    }
}

/// Information about a slow query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowQueryInfo {
    /// Timestamp when the query was executed
    pub timestamp: DateTime<Utc>,
    /// Query SQL text
    pub query: String,
    /// Query execution time in milliseconds
    pub duration_ms: u64,
    /// Query parameters (optional, for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
    /// Correlation ID for request tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Endpoint that triggered the query
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Statistics about slow queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowQueryStats {
    /// Total number of slow queries recorded
    pub total_count: usize,
    /// Number of slow queries in current history
    pub current_history_size: usize,
    /// Average duration of slow queries in milliseconds
    pub avg_duration_ms: f64,
    /// Maximum duration observed in milliseconds
    pub max_duration_ms: u64,
    /// Minimum duration observed in milliseconds (above threshold)
    pub min_duration_ms: u64,
}

/// Slow query logger that tracks and stores slow query information
#[derive(Debug, Clone)]
pub struct SlowQueryLogger {
    config: Arc<SlowQueryConfig>,
    history: Arc<RwLock<VecDeque<SlowQueryInfo>>>,
    total_count: Arc<RwLock<usize>>,
}

impl SlowQueryLogger {
    /// Create a new slow query logger with the given configuration
    pub fn new(config: SlowQueryConfig) -> Self {
        Self {
            config: Arc::new(config),
            history: Arc::new(RwLock::new(VecDeque::new())),
            total_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a new slow query logger with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SlowQueryConfig::default())
    }

    /// Log a query with its execution time
    ///
    /// If the duration exceeds the threshold, the query is logged as slow
    pub fn log_query(
        &self,
        query: impl Into<String>,
        duration: Duration,
        parameters: Option<String>,
        correlation_id: Option<String>,
        endpoint: Option<String>,
    ) {
        let duration_ms = duration.as_millis() as u64;

        if duration_ms >= self.config.threshold_ms {
            let query_str = query.into();
            let info = SlowQueryInfo {
                timestamp: Utc::now(),
                query: query_str.clone(),
                duration_ms,
                parameters: if self.config.log_parameters {
                    parameters
                } else {
                    None
                },
                correlation_id: correlation_id.clone(),
                endpoint: endpoint.clone(),
            };

            // Log to tracing if enabled
            if self.config.log_to_tracing {
                warn!(
                    query = %query_str,
                    duration_ms = duration_ms,
                    correlation_id = ?correlation_id,
                    endpoint = ?endpoint,
                    "Slow query detected"
                );
            }

            // Store in history
            {
                let mut history = self.history.write().unwrap();
                if history.len() >= self.config.max_history {
                    history.pop_front();
                }
                history.push_back(info);
            }

            // Increment total count
            {
                let mut count = self.total_count.write().unwrap();
                *count += 1;
            }

            // Record metrics
            crate::metrics::record_slow_query(duration_ms);
        } else {
            debug!(
                query = %query.into(),
                duration_ms = duration_ms,
                "Query executed"
            );
        }
    }

    /// Get the current slow query history
    pub fn get_history(&self) -> Vec<SlowQueryInfo> {
        self.history.read().unwrap().iter().cloned().collect()
    }

    /// Get slow query statistics
    pub fn get_stats(&self) -> SlowQueryStats {
        let history = self.history.read().unwrap();
        let total_count = *self.total_count.read().unwrap();

        if history.is_empty() {
            return SlowQueryStats {
                total_count,
                current_history_size: 0,
                avg_duration_ms: 0.0,
                max_duration_ms: 0,
                min_duration_ms: 0,
            };
        }

        let durations: Vec<u64> = history.iter().map(|q| q.duration_ms).collect();
        let sum: u64 = durations.iter().sum();
        let avg = sum as f64 / durations.len() as f64;
        let max = *durations.iter().max().unwrap();
        let min = *durations.iter().min().unwrap();

        SlowQueryStats {
            total_count,
            current_history_size: history.len(),
            avg_duration_ms: avg,
            max_duration_ms: max,
            min_duration_ms: min,
        }
    }

    /// Clear the slow query history
    pub fn clear_history(&self) {
        let mut history = self.history.write().unwrap();
        history.clear();
    }

    /// Get the current configuration
    pub fn config(&self) -> &SlowQueryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slow_query_logger_creation() {
        let logger = SlowQueryLogger::with_defaults();
        assert_eq!(logger.config().threshold_ms, 100);
        assert_eq!(logger.config().max_history, 1000);
    }

    #[test]
    fn test_slow_query_logging() {
        let config = SlowQueryConfig {
            threshold_ms: 50,
            max_history: 10,
            log_to_tracing: false,
            log_parameters: true,
        };
        let logger = SlowQueryLogger::new(config);

        // Log a fast query (should not be recorded)
        logger.log_query(
            "SELECT * FROM users WHERE id = 1",
            Duration::from_millis(30),
            None,
            None,
            None,
        );
        assert_eq!(logger.get_history().len(), 0);

        // Log a slow query (should be recorded)
        logger.log_query(
            "SELECT * FROM users WHERE name LIKE '%test%'",
            Duration::from_millis(150),
            Some("name='test'".to_string()),
            Some("corr-123".to_string()),
            Some("/api/users".to_string()),
        );
        assert_eq!(logger.get_history().len(), 1);

        let history = logger.get_history();
        assert_eq!(
            history[0].query,
            "SELECT * FROM users WHERE name LIKE '%test%'"
        );
        assert_eq!(history[0].duration_ms, 150);
        assert_eq!(history[0].parameters, Some("name='test'".to_string()));
    }

    #[test]
    fn test_slow_query_stats() {
        let config = SlowQueryConfig {
            threshold_ms: 50,
            max_history: 10,
            log_to_tracing: false,
            log_parameters: false,
        };
        let logger = SlowQueryLogger::new(config);

        // Log multiple slow queries
        logger.log_query("SELECT 1", Duration::from_millis(100), None, None, None);
        logger.log_query("SELECT 2", Duration::from_millis(200), None, None, None);
        logger.log_query("SELECT 3", Duration::from_millis(150), None, None, None);

        let stats = logger.get_stats();
        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.current_history_size, 3);
        assert_eq!(stats.max_duration_ms, 200);
        assert_eq!(stats.min_duration_ms, 100);
        assert!((stats.avg_duration_ms - 150.0).abs() < 0.01);
    }

    #[test]
    fn test_slow_query_history_limit() {
        let config = SlowQueryConfig {
            threshold_ms: 50,
            max_history: 3,
            log_to_tracing: false,
            log_parameters: false,
        };
        let logger = SlowQueryLogger::new(config);

        // Log more queries than the history limit
        for i in 1..=5 {
            logger.log_query(
                format!("SELECT {}", i),
                Duration::from_millis(100),
                None,
                None,
                None,
            );
        }

        let history = logger.get_history();
        assert_eq!(history.len(), 3); // Should keep only the last 3

        // Check that the oldest queries were removed
        assert_eq!(history[0].query, "SELECT 3");
        assert_eq!(history[1].query, "SELECT 4");
        assert_eq!(history[2].query, "SELECT 5");

        let stats = logger.get_stats();
        assert_eq!(stats.total_count, 5); // Total count should still be 5
        assert_eq!(stats.current_history_size, 3);
    }

    #[test]
    fn test_clear_history() {
        let logger = SlowQueryLogger::with_defaults();

        logger.log_query("SELECT 1", Duration::from_millis(200), None, None, None);
        logger.log_query("SELECT 2", Duration::from_millis(300), None, None, None);

        assert_eq!(logger.get_history().len(), 2);

        logger.clear_history();
        assert_eq!(logger.get_history().len(), 0);

        // Total count should remain the same
        let stats = logger.get_stats();
        assert_eq!(stats.total_count, 2);
    }

    #[test]
    fn test_parameters_logging_disabled() {
        let config = SlowQueryConfig {
            threshold_ms: 50,
            max_history: 10,
            log_to_tracing: false,
            log_parameters: false, // Disabled
        };
        let logger = SlowQueryLogger::new(config);

        logger.log_query(
            "SELECT * FROM users",
            Duration::from_millis(100),
            Some("sensitive_data".to_string()),
            None,
            None,
        );

        let history = logger.get_history();
        assert_eq!(history[0].parameters, None); // Should be None even though provided
    }
}
