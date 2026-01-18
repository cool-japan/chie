//! Alerting system with configurable thresholds.
//!
//! This module provides a comprehensive alerting system for monitoring various metrics
//! and triggering alerts when thresholds are exceeded.
//!
//! # Features
//!
//! - Multiple severity levels (Info, Warning, Error, Critical)
//! - Configurable thresholds for various metrics
//! - Alert suppression to prevent alert fatigue
//! - Alert history tracking
//! - Customizable alert handlers
//!
//! # Example
//!
//! ```
//! use chie_core::alerting::{AlertManager, AlertSeverity, ThresholdConfig, AlertMetric};
//!
//! let mut manager = AlertManager::new();
//!
//! // Configure a threshold for high storage usage
//! let threshold = ThresholdConfig {
//!     metric: AlertMetric::StorageUsagePercent,
//!     warning_threshold: 75.0,
//!     error_threshold: 90.0,
//!     critical_threshold: 95.0,
//!     check_interval_secs: 60,
//! };
//! manager.add_threshold(threshold);
//!
//! // Check a metric value
//! manager.check_metric(AlertMetric::StorageUsagePercent, 92.0);
//!
//! // Get active alerts
//! let alerts = manager.get_active_alerts();
//! for alert in alerts {
//!     println!("Alert: {:?} - {}", alert.severity, alert.message);
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Informational alerts.
    Info,
    /// Warning alerts that require attention.
    Warning,
    /// Error alerts that indicate problems.
    Error,
    /// Critical alerts that require immediate action.
    Critical,
}

/// Alert metric types that can be monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertMetric {
    /// Storage usage percentage (0-100).
    StorageUsagePercent,
    /// Bandwidth usage in bytes per second.
    BandwidthUsageBps,
    /// CPU usage percentage (0-100).
    CpuUsagePercent,
    /// Memory usage percentage (0-100).
    MemoryUsagePercent,
    /// Error rate (errors per second).
    ErrorRate,
    /// Request latency in milliseconds.
    LatencyMs,
    /// Failed chunk verification count.
    FailedVerifications,
    /// Peer reputation score (0-100).
    PeerReputation,
    /// Cache hit rate percentage (0-100).
    CacheHitRate,
    /// Queue depth (number of pending requests).
    QueueDepth,
}

impl AlertMetric {
    /// Get a human-readable name for the metric.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            Self::StorageUsagePercent => "Storage Usage",
            Self::BandwidthUsageBps => "Bandwidth Usage",
            Self::CpuUsagePercent => "CPU Usage",
            Self::MemoryUsagePercent => "Memory Usage",
            Self::ErrorRate => "Error Rate",
            Self::LatencyMs => "Latency",
            Self::FailedVerifications => "Failed Verifications",
            Self::PeerReputation => "Peer Reputation",
            Self::CacheHitRate => "Cache Hit Rate",
            Self::QueueDepth => "Queue Depth",
        }
    }

    /// Get the unit for the metric.
    #[must_use]
    #[inline]
    pub fn unit(&self) -> &'static str {
        match self {
            Self::StorageUsagePercent
            | Self::CpuUsagePercent
            | Self::MemoryUsagePercent
            | Self::CacheHitRate => "%",
            Self::BandwidthUsageBps => "bps",
            Self::ErrorRate => "errors/sec",
            Self::LatencyMs => "ms",
            Self::FailedVerifications | Self::QueueDepth => "count",
            Self::PeerReputation => "score",
        }
    }
}

/// Configuration for threshold-based alerting.
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// The metric type to monitor.
    pub metric: AlertMetric,
    /// Warning threshold value.
    pub warning_threshold: f64,
    /// Error threshold value.
    pub error_threshold: f64,
    /// Critical threshold value.
    pub critical_threshold: f64,
    /// Minimum interval between checks in seconds.
    pub check_interval_secs: u64,
}

impl ThresholdConfig {
    /// Determine the severity level for a given metric value.
    #[must_use]
    #[inline]
    pub fn evaluate(&self, value: f64) -> Option<AlertSeverity> {
        if value >= self.critical_threshold {
            Some(AlertSeverity::Critical)
        } else if value >= self.error_threshold {
            Some(AlertSeverity::Error)
        } else if value >= self.warning_threshold {
            Some(AlertSeverity::Warning)
        } else {
            None
        }
    }
}

/// An alert triggered by a threshold violation.
#[derive(Debug, Clone)]
pub struct Alert {
    /// Unique alert ID.
    pub id: String,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// The metric that triggered the alert.
    pub metric: AlertMetric,
    /// The measured value.
    pub value: f64,
    /// The threshold that was exceeded.
    pub threshold: f64,
    /// Alert message.
    pub message: String,
    /// Timestamp when the alert was created.
    pub timestamp: SystemTime,
    /// Whether the alert is still active.
    pub active: bool,
}

impl Alert {
    /// Create a new alert.
    #[must_use]
    pub fn new(severity: AlertSeverity, metric: AlertMetric, value: f64, threshold: f64) -> Self {
        let id = format!(
            "{:?}_{:?}_{}",
            metric,
            severity,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        let message = format!(
            "{} {} is {:.2}{} (threshold: {:.2}{})",
            severity_emoji(severity),
            metric.name(),
            value,
            metric.unit(),
            threshold,
            metric.unit()
        );

        Self {
            id,
            severity,
            metric,
            value,
            threshold,
            message,
            timestamp: SystemTime::now(),
            active: true,
        }
    }

    /// Resolve the alert.
    #[inline]
    pub fn resolve(&mut self) {
        self.active = false;
    }

    /// Get the age of the alert in seconds.
    #[must_use]
    #[inline]
    pub fn age_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.timestamp)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Alert manager for threshold-based monitoring.
pub struct AlertManager {
    /// Configured thresholds.
    thresholds: HashMap<AlertMetric, ThresholdConfig>,
    /// Active alerts.
    active_alerts: Vec<Alert>,
    /// Alert history (resolved alerts).
    alert_history: Vec<Alert>,
    /// Maximum number of alerts to keep in history.
    max_history_size: usize,
    /// Last check time for each metric.
    last_check: HashMap<AlertMetric, SystemTime>,
    /// Suppression window in seconds.
    suppression_window_secs: u64,
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertManager {
    /// Create a new alert manager.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            thresholds: HashMap::new(),
            active_alerts: Vec::new(),
            alert_history: Vec::new(),
            max_history_size: 1000,
            last_check: HashMap::new(),
            suppression_window_secs: 300, // 5 minutes default
        }
    }

    /// Create a new alert manager with custom configuration.
    #[must_use]
    #[inline]
    pub fn with_config(max_history_size: usize, suppression_window_secs: u64) -> Self {
        Self {
            thresholds: HashMap::new(),
            active_alerts: Vec::new(),
            alert_history: Vec::new(),
            max_history_size,
            last_check: HashMap::new(),
            suppression_window_secs,
        }
    }

    /// Add a threshold configuration.
    pub fn add_threshold(&mut self, config: ThresholdConfig) {
        self.thresholds.insert(config.metric, config);
    }

    /// Remove a threshold configuration.
    pub fn remove_threshold(&mut self, metric: AlertMetric) {
        self.thresholds.remove(&metric);
    }

    /// Check a metric value against configured thresholds.
    pub fn check_metric(&mut self, metric: AlertMetric, value: f64) {
        let Some(config) = self.thresholds.get(&metric) else {
            return;
        };

        // Check if we should skip this check due to interval
        if let Some(last_check_time) = self.last_check.get(&metric) {
            let elapsed = SystemTime::now()
                .duration_since(*last_check_time)
                .unwrap_or_default();
            if elapsed < Duration::from_secs(config.check_interval_secs) {
                return;
            }
        }

        self.last_check.insert(metric, SystemTime::now());

        // Evaluate the metric
        if let Some(severity) = config.evaluate(value) {
            let threshold = match severity {
                AlertSeverity::Critical => config.critical_threshold,
                AlertSeverity::Error => config.error_threshold,
                AlertSeverity::Warning => config.warning_threshold,
                AlertSeverity::Info => 0.0,
            };

            // Check if we should suppress this alert
            if !self.should_suppress_alert(metric, severity) {
                let alert = Alert::new(severity, metric, value, threshold);
                self.active_alerts.push(alert);
            }
        } else {
            // Resolve any active alerts for this metric
            self.resolve_alerts_for_metric(metric);
        }
    }

    /// Check if an alert should be suppressed.
    #[must_use]
    fn should_suppress_alert(&self, metric: AlertMetric, severity: AlertSeverity) -> bool {
        let suppression_duration = Duration::from_secs(self.suppression_window_secs);

        self.active_alerts.iter().any(|alert| {
            alert.metric == metric
                && alert.severity == severity
                && alert.active
                && SystemTime::now()
                    .duration_since(alert.timestamp)
                    .unwrap_or_default()
                    < suppression_duration
        })
    }

    /// Resolve all active alerts for a metric.
    fn resolve_alerts_for_metric(&mut self, metric: AlertMetric) {
        for alert in &mut self.active_alerts {
            if alert.metric == metric && alert.active {
                alert.resolve();
            }
        }

        // Move resolved alerts to history
        let mut remaining = Vec::new();
        let mut resolved = Vec::new();

        for alert in self.active_alerts.drain(..) {
            if alert.active {
                remaining.push(alert);
            } else {
                resolved.push(alert);
            }
        }

        self.active_alerts = remaining;
        self.alert_history.extend(resolved);

        // Trim history if needed
        if self.alert_history.len() > self.max_history_size {
            let excess = self.alert_history.len() - self.max_history_size;
            self.alert_history.drain(0..excess);
        }
    }

    /// Get all active alerts.
    #[must_use]
    #[inline]
    pub fn get_active_alerts(&self) -> &[Alert] {
        &self.active_alerts
    }

    /// Get active alerts for a specific metric.
    #[must_use]
    #[inline]
    pub fn get_alerts_for_metric(&self, metric: AlertMetric) -> Vec<&Alert> {
        self.active_alerts
            .iter()
            .filter(|a| a.metric == metric && a.active)
            .collect()
    }

    /// Get active alerts by severity.
    #[must_use]
    #[inline]
    pub fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<&Alert> {
        self.active_alerts
            .iter()
            .filter(|a| a.severity == severity && a.active)
            .collect()
    }

    /// Get the alert history.
    #[must_use]
    #[inline]
    pub fn get_alert_history(&self) -> &[Alert] {
        &self.alert_history
    }

    /// Clear all resolved alerts from history.
    pub fn clear_history(&mut self) {
        self.alert_history.clear();
    }

    /// Get the count of active alerts.
    #[must_use]
    #[inline]
    pub fn active_alert_count(&self) -> usize {
        self.active_alerts.len()
    }

    /// Get the count of critical alerts.
    #[must_use]
    #[inline]
    pub fn critical_alert_count(&self) -> usize {
        self.active_alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical && a.active)
            .count()
    }

    /// Check if there are any critical alerts.
    #[must_use]
    #[inline]
    pub fn has_critical_alerts(&self) -> bool {
        self.critical_alert_count() > 0
    }
}

/// Get an emoji for an alert severity.
#[must_use]
#[inline]
fn severity_emoji(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Info => "ℹ️",
        AlertSeverity::Warning => "⚠️",
        AlertSeverity::Error => "❌",
        AlertSeverity::Critical => "🚨",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_evaluation() {
        let config = ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 60,
        };

        assert_eq!(config.evaluate(50.0), None);
        assert_eq!(config.evaluate(75.0), Some(AlertSeverity::Warning));
        assert_eq!(config.evaluate(90.0), Some(AlertSeverity::Error));
        assert_eq!(config.evaluate(95.0), Some(AlertSeverity::Critical));
    }

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(
            AlertSeverity::Warning,
            AlertMetric::StorageUsagePercent,
            85.0,
            75.0,
        );

        assert_eq!(alert.severity, AlertSeverity::Warning);
        assert_eq!(alert.metric, AlertMetric::StorageUsagePercent);
        assert_eq!(alert.value, 85.0);
        assert_eq!(alert.threshold, 75.0);
        assert!(alert.active);
    }

    #[test]
    fn test_alert_manager_basic() {
        let mut manager = AlertManager::new();

        let config = ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        };
        manager.add_threshold(config);

        // Check below threshold
        manager.check_metric(AlertMetric::StorageUsagePercent, 50.0);
        assert_eq!(manager.active_alert_count(), 0);

        // Check above warning threshold
        manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
        assert_eq!(manager.active_alert_count(), 1);

        // Resolve by checking below threshold
        manager.check_metric(AlertMetric::StorageUsagePercent, 50.0);
        assert_eq!(manager.active_alert_count(), 0);
    }

    #[test]
    fn test_alert_severity_filtering() {
        let mut manager = AlertManager::new();

        let config = ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        };
        manager.add_threshold(config);

        manager.check_metric(AlertMetric::StorageUsagePercent, 96.0);

        let critical_alerts = manager.get_alerts_by_severity(AlertSeverity::Critical);
        assert_eq!(critical_alerts.len(), 1);
        assert!(manager.has_critical_alerts());
    }

    #[test]
    fn test_multiple_metrics() {
        let mut manager = AlertManager::new();

        let storage_config = ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        };
        manager.add_threshold(storage_config);

        let cpu_config = ThresholdConfig {
            metric: AlertMetric::CpuUsagePercent,
            warning_threshold: 70.0,
            error_threshold: 85.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        };
        manager.add_threshold(cpu_config);

        manager.check_metric(AlertMetric::StorageUsagePercent, 92.0);
        manager.check_metric(AlertMetric::CpuUsagePercent, 88.0);

        assert_eq!(manager.active_alert_count(), 2);
    }

    #[test]
    fn test_alert_history() {
        let mut manager = AlertManager::with_config(100, 0);

        let config = ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        };
        manager.add_threshold(config);

        // Trigger and resolve an alert
        manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
        assert_eq!(manager.active_alert_count(), 1);

        manager.check_metric(AlertMetric::StorageUsagePercent, 50.0);
        assert_eq!(manager.active_alert_count(), 0);
        assert_eq!(manager.get_alert_history().len(), 1);

        manager.clear_history();
        assert_eq!(manager.get_alert_history().len(), 0);
    }

    #[test]
    fn test_metric_type_info() {
        assert_eq!(AlertMetric::StorageUsagePercent.name(), "Storage Usage");
        assert_eq!(AlertMetric::StorageUsagePercent.unit(), "%");
        assert_eq!(AlertMetric::BandwidthUsageBps.unit(), "bps");
        assert_eq!(AlertMetric::LatencyMs.unit(), "ms");
    }
}
