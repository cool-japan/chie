//! Comprehensive alerting system for CHIE Coordinator.
//!
//! Provides multi-channel alert notifications with configurable rules,
//! severity levels, escalation policies, and alert deduplication.
//!
//! **TODO**: This file is currently 2772 lines, exceeding the 2000-line limit specified in CLAUDE.md.
//! It should be refactored into smaller modules:
//! - alerting/mod.rs - Main alerting manager and types
//! - alerting/channels.rs - Notification channels (Email, Slack, Webhook)
//! - alerting/email.rs - Email delivery, retry, templates, and bounces
//! - alerting/config.rs - Configuration structures
//! - alerting/rules.rs - Alert rule evaluation
//! - alerting/tests.rs - Test suite

use crate::webhooks::{WebhookEvent, WebhookManager};
use lettre::message::{Mailbox, Message, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational alert.
    Info,
    /// Warning level alert.
    Warning,
    /// Critical alert requiring immediate attention.
    Critical,
}

/// Email priority levels for retry queue ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum EmailPriority {
    /// Low priority - retry last.
    Low = 1,
    /// Normal priority - default.
    #[default]
    Normal = 2,
    /// High priority - retry before normal.
    High = 3,
    /// Urgent priority - retry first.
    Urgent = 4,
}

impl EmailPriority {
    /// Convert priority to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Urgent => "urgent",
        }
    }

    /// Get priority from alert severity.
    pub fn from_severity(severity: AlertSeverity) -> Self {
        match severity {
            AlertSeverity::Info => Self::Low,
            AlertSeverity::Warning => Self::Normal,
            AlertSeverity::Critical => Self::Urgent,
        }
    }
}

impl AlertSeverity {
    /// Convert severity to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Alert notification channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertChannel {
    /// Email notification.
    Email { recipients: Vec<String> },
    /// Slack webhook.
    Slack {
        webhook_url: String,
        channel: String,
    },
    /// Custom webhook.
    Webhook {
        url: String,
        headers: HashMap<String, String>,
    },
    /// Console/log output.
    Console,
}

/// Alert rule condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    /// Metric name to monitor.
    pub metric_name: String,
    /// Comparison operator.
    pub operator: ComparisonOperator,
    /// Threshold value.
    pub threshold: f64,
    /// Duration the condition must be true.
    pub duration_seconds: u64,
}

/// Comparison operators for alert conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Greater than.
    GreaterThan,
    /// Greater than or equal.
    GreaterThanOrEqual,
    /// Less than.
    LessThan,
    /// Less than or equal.
    LessThanOrEqual,
    /// Equal.
    Equal,
    /// Not equal.
    NotEqual,
}

impl ComparisonOperator {
    /// Evaluate the comparison.
    pub fn evaluate(&self, value: f64, threshold: f64) -> bool {
        match self {
            Self::GreaterThan => value > threshold,
            Self::GreaterThanOrEqual => value >= threshold,
            Self::LessThan => value < threshold,
            Self::LessThanOrEqual => value <= threshold,
            Self::Equal => (value - threshold).abs() < f64::EPSILON,
            Self::NotEqual => (value - threshold).abs() >= f64::EPSILON,
        }
    }
}

/// Alert rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule ID.
    pub id: Uuid,
    /// Rule name.
    pub name: String,
    /// Rule description.
    pub description: String,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Condition to trigger alert.
    pub condition: AlertCondition,
    /// Notification channels.
    pub channels: Vec<AlertChannel>,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// Cooldown period between alerts (seconds).
    pub cooldown_seconds: u64,
}

/// Alert instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID.
    pub id: Uuid,
    /// Rule that triggered this alert.
    pub rule_id: Uuid,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Alert title.
    pub title: String,
    /// Alert message.
    pub message: String,
    /// Metric value that triggered the alert.
    pub metric_value: f64,
    /// Timestamp when alert was created.
    pub created_at: u64,
    /// Timestamp when alert was acknowledged (if any).
    pub acknowledged_at: Option<u64>,
    /// Who acknowledged the alert.
    pub acknowledged_by: Option<String>,
    /// Alert status.
    pub status: AlertStatus,
}

/// Alert status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    /// Alert is active and not acknowledged.
    Active,
    /// Alert has been acknowledged.
    Acknowledged,
    /// Alert has been resolved.
    Resolved,
    /// Alert has been snoozed.
    Snoozed,
}

impl AlertStatus {
    /// Convert status to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::Snoozed => "snoozed",
        }
    }
}

/// Alert statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertStats {
    /// Total alerts triggered.
    pub total_alerts: usize,
    /// Active alerts count.
    pub active_alerts: usize,
    /// Acknowledged alerts count.
    pub acknowledged_alerts: usize,
    /// Resolved alerts count.
    pub resolved_alerts: usize,
    /// Alerts by severity.
    pub by_severity: HashMap<String, usize>,
    /// Alerts by rule.
    pub by_rule: HashMap<Uuid, usize>,
    /// Average time to acknowledge (seconds).
    pub avg_time_to_ack: f64,
}

/// SMTP configuration for email notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port (typically 587 for TLS, 465 for SSL).
    pub port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password for authentication.
    pub password: String,
    /// Sender email address.
    pub from_email: String,
    /// Sender display name.
    pub from_name: String,
    /// Use STARTTLS (true) or implicit TLS (false).
    pub use_starttls: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 587,
            username: String::new(),
            password: String::new(),
            from_email: "alerts@chie.example.com".to_string(),
            from_name: "CHIE Alerts".to_string(),
            use_starttls: true,
        }
    }
}

/// Email retry configuration for handling delivery failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRetryConfig {
    /// Maximum number of retry attempts for failed emails.
    pub max_retry_attempts: u32,
    /// Initial retry delay in seconds (will be doubled for each retry).
    pub initial_retry_delay_seconds: u64,
    /// Maximum retry delay in seconds (cap for exponential backoff).
    pub max_retry_delay_seconds: u64,
    /// Maximum age of failed emails to retry (seconds).
    pub max_retry_age_seconds: u64,
}

impl Default for EmailRetryConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: 5,
            initial_retry_delay_seconds: 60,  // 1 minute
            max_retry_delay_seconds: 3600,    // 1 hour
            max_retry_age_seconds: 24 * 3600, // 24 hours
        }
    }
}

/// Failed email delivery attempt for retry queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedEmail {
    /// Unique ID for this failed email.
    pub id: Uuid,
    /// Alert that triggered this email.
    pub alert: Alert,
    /// Email recipients.
    pub recipients: Vec<String>,
    /// Number of retry attempts made.
    pub retry_attempts: u32,
    /// Last retry attempt timestamp.
    pub last_retry_at: u64,
    /// First failure timestamp.
    pub failed_at: u64,
    /// Last error message.
    pub last_error: String,
    /// Email priority level (higher priority emails are retried first).
    #[serde(default)]
    pub priority: EmailPriority,
}

/// Email bounce tracking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBounceConfig {
    /// Maximum number of failures before marking email as bounced.
    pub max_failures_before_bounce: u32,
    /// Time window in seconds to track failures (failures outside this window are ignored).
    pub failure_tracking_window_seconds: u64,
    /// Whether to automatically skip bounced emails.
    pub auto_skip_bounced: bool,
}

impl Default for EmailBounceConfig {
    fn default() -> Self {
        Self {
            max_failures_before_bounce: 5,
            failure_tracking_window_seconds: 7 * 24 * 3600, // 7 days
            auto_skip_bounced: true,
        }
    }
}

/// Email bounce tracking entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailBounce {
    /// Email address that bounced.
    pub email: String,
    /// Number of consecutive failures.
    pub failure_count: u32,
    /// First failure timestamp.
    pub first_failed_at: u64,
    /// Last failure timestamp.
    pub last_failed_at: u64,
    /// Last bounce reason/error.
    pub last_error: String,
    /// Whether this email is marked as permanently bounced.
    pub is_bounced: bool,
}

/// Email unsubscribe configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailUnsubscribeConfig {
    /// Whether to automatically skip unsubscribed emails.
    pub auto_skip_unsubscribed: bool,
    /// Unsubscribe link base URL (e.g., "https://chie.example.com/unsubscribe").
    pub unsubscribe_base_url: Option<String>,
}

impl Default for EmailUnsubscribeConfig {
    fn default() -> Self {
        Self {
            auto_skip_unsubscribed: true,
            unsubscribe_base_url: None,
        }
    }
}

/// Email unsubscribe entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailUnsubscribe {
    /// Email address that unsubscribed.
    pub email: String,
    /// When the email was unsubscribed.
    pub unsubscribed_at: u64,
    /// Reason for unsubscription (optional).
    pub reason: Option<String>,
    /// Source of unsubscription (user, admin, automated).
    pub source: UnsubscribeSource,
}

/// Source of an unsubscribe action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsubscribeSource {
    /// User clicked unsubscribe link.
    User,
    /// Admin manually unsubscribed.
    Admin,
    /// Automated system (e.g., bounce threshold).
    Automated,
}

impl UnsubscribeSource {
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::Automated => "automated",
        }
    }
}

/// Email delivery SLA configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSlaConfig {
    /// Target delivery time in milliseconds (default: 5000ms = 5s).
    pub target_delivery_ms: u64,
    /// Whether to track SLA metrics.
    pub enabled: bool,
}

impl Default for EmailSlaConfig {
    fn default() -> Self {
        Self {
            target_delivery_ms: 5000, // 5 seconds
            enabled: true,
        }
    }
}

/// Email delivery SLA metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSlaMetrics {
    /// Total emails sent.
    pub total_sent: u64,
    /// Total emails within SLA.
    pub within_sla: u64,
    /// Total emails breaching SLA.
    pub breached_sla: u64,
    /// Average delivery time in milliseconds.
    pub avg_delivery_ms: f64,
    /// Minimum delivery time in milliseconds.
    pub min_delivery_ms: u64,
    /// Maximum delivery time in milliseconds.
    pub max_delivery_ms: u64,
    /// SLA compliance rate (0.0 - 1.0).
    pub sla_rate: f64,
}

impl Default for EmailSlaMetrics {
    fn default() -> Self {
        Self {
            total_sent: 0,
            within_sla: 0,
            breached_sla: 0,
            avg_delivery_ms: 0.0,
            min_delivery_ms: 0,
            max_delivery_ms: 0,
            sla_rate: 1.0,
        }
    }
}

/// Alerting manager configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    /// Maximum number of active alerts to keep in memory.
    pub max_active_alerts: usize,
    /// Default cooldown period (seconds).
    pub default_cooldown_seconds: u64,
    /// Alert history retention (seconds).
    pub history_retention_seconds: u64,
    /// SMTP configuration for email notifications (optional).
    pub smtp: Option<SmtpConfig>,
    /// Email retry configuration.
    pub email_retry: EmailRetryConfig,
    /// Email bounce tracking configuration.
    pub email_bounce: EmailBounceConfig,
    /// Email unsubscribe configuration.
    pub email_unsubscribe: EmailUnsubscribeConfig,
    /// Email delivery SLA configuration.
    pub email_sla: EmailSlaConfig,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            max_active_alerts: 1000,
            default_cooldown_seconds: 300,            // 5 minutes
            history_retention_seconds: 7 * 24 * 3600, // 7 days
            smtp: None,                               // No SMTP configured by default
            email_retry: EmailRetryConfig::default(),
            email_bounce: EmailBounceConfig::default(),
            email_unsubscribe: EmailUnsubscribeConfig::default(),
            email_sla: EmailSlaConfig::default(),
        }
    }
}

/// Internal state for alert rule.
struct AlertRuleState {
    /// Rule configuration.
    rule: AlertRule,
    /// Last alert time.
    last_alert_time: Option<u64>,
    /// Condition met since timestamp.
    condition_met_since: Option<u64>,
}

/// Alerting manager.
pub struct AlertingManager {
    /// Database connection pool.
    db: PgPool,
    /// Configuration.
    config: Arc<RwLock<AlertingConfig>>,
    /// Alert rules.
    rules: Arc<RwLock<HashMap<Uuid, AlertRuleState>>>,
    /// Active alerts.
    alerts: Arc<RwLock<HashMap<Uuid, Alert>>>,
    /// Alert history.
    history: Arc<RwLock<Vec<Alert>>>,
    /// Failed email retry queue.
    failed_emails: Arc<RwLock<Vec<FailedEmail>>>,
    /// Email bounce tracking map (email -> bounce info).
    email_bounces: Arc<RwLock<HashMap<String, EmailBounce>>>,
    /// Email unsubscribe list (email -> unsubscribe info).
    email_unsubscribes: Arc<RwLock<HashMap<String, EmailUnsubscribe>>>,
    /// Email delivery SLA metrics.
    email_sla_metrics: Arc<RwLock<EmailSlaMetrics>>,
    /// HTTP client for webhooks.
    http_client: reqwest::Client,
    /// Webhook manager for sending event notifications (optional).
    webhook_manager: Option<Arc<WebhookManager>>,
}

/// Email delivery result.
#[derive(Debug, Clone)]
struct EmailDeliveryResult {
    /// Recipients that succeeded.
    succeeded: Vec<String>,
    /// Recipients that failed.
    failed: Vec<String>,
    /// Last error message (if any).
    last_error: Option<String>,
}

impl AlertingManager {
    /// Create a new alerting manager.
    pub fn new(db: PgPool, config: AlertingConfig) -> Self {
        Self::new_with_webhook(db, config, None)
    }

    /// Create a new alerting manager with optional webhook manager.
    pub fn new_with_webhook(
        db: PgPool,
        config: AlertingConfig,
        webhook_manager: Option<Arc<WebhookManager>>,
    ) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
            rules: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            failed_emails: Arc::new(RwLock::new(Vec::new())),
            email_bounces: Arc::new(RwLock::new(HashMap::new())),
            email_unsubscribes: Arc::new(RwLock::new(HashMap::new())),
            email_sla_metrics: Arc::new(RwLock::new(EmailSlaMetrics::default())),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            webhook_manager,
        }
    }

    /// Add an alert rule.
    pub async fn add_rule(&self, rule: AlertRule) {
        let mut rules = self.rules.write().await;
        let rule_id = rule.id;
        rules.insert(
            rule_id,
            AlertRuleState {
                rule,
                last_alert_time: None,
                condition_met_since: None,
            },
        );
        info!(rule_id = %rule_id, "Alert rule added");
    }

    /// Remove an alert rule.
    pub async fn remove_rule(&self, rule_id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        let removed = rules.remove(&rule_id).is_some();
        if removed {
            info!(rule_id = %rule_id, "Alert rule removed");
        }
        removed
    }

    /// Update an alert rule.
    pub async fn update_rule(&self, rule: AlertRule) -> bool {
        let mut rules = self.rules.write().await;
        let rule_id = rule.id;
        if let Some(state) = rules.get_mut(&rule_id) {
            state.rule = rule;
            info!(rule_id = %rule_id, "Alert rule updated");
            true
        } else {
            false
        }
    }

    /// Get all alert rules.
    pub async fn get_rules(&self) -> Vec<AlertRule> {
        let rules = self.rules.read().await;
        rules.values().map(|state| state.rule.clone()).collect()
    }

    /// Get a specific alert rule.
    pub async fn get_rule(&self, rule_id: Uuid) -> Option<AlertRule> {
        let rules = self.rules.read().await;
        rules.get(&rule_id).map(|state| state.rule.clone())
    }

    /// Enable or disable a rule.
    pub async fn set_rule_enabled(&self, rule_id: Uuid, enabled: bool) -> bool {
        let mut rules = self.rules.write().await;
        if let Some(state) = rules.get_mut(&rule_id) {
            state.rule.enabled = enabled;
            info!(rule_id = %rule_id, enabled = enabled, "Alert rule enabled status changed");
            true
        } else {
            false
        }
    }

    /// Check metric value against all enabled rules.
    pub async fn check_metric(&self, metric_name: &str, value: f64) {
        let now = current_timestamp();
        let mut rules = self.rules.write().await;

        for (rule_id, state) in rules.iter_mut() {
            if !state.rule.enabled {
                continue;
            }

            if state.rule.condition.metric_name != metric_name {
                continue;
            }

            let condition_met = state
                .rule
                .condition
                .operator
                .evaluate(value, state.rule.condition.threshold);

            if condition_met {
                // Condition is met
                if state.condition_met_since.is_none() {
                    state.condition_met_since = Some(now);
                }

                // Check if duration threshold is met
                let duration_met = if let Some(since) = state.condition_met_since {
                    now >= since + state.rule.condition.duration_seconds
                } else {
                    false
                };

                if duration_met {
                    // Check cooldown
                    let can_alert = if let Some(last_alert) = state.last_alert_time {
                        now >= last_alert + state.rule.cooldown_seconds
                    } else {
                        true
                    };

                    if can_alert {
                        // Trigger alert
                        let alert = self.create_alert(*rule_id, &state.rule, value).await;
                        state.last_alert_time = Some(now);
                        state.condition_met_since = None; // Reset

                        // Send notifications (without holding the lock)
                        let channels = state.rule.channels.clone();
                        drop(rules); // Release lock before async operations
                        self.send_notifications(&alert, &channels).await;
                        return;
                    }
                }
            } else {
                // Condition no longer met
                state.condition_met_since = None;
            }
        }
    }

    /// Create an alert.
    async fn create_alert(&self, rule_id: Uuid, rule: &AlertRule, metric_value: f64) -> Alert {
        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id,
            severity: rule.severity,
            title: rule.name.clone(),
            message: format!(
                "{}: {} {} {} (current: {})",
                rule.description,
                rule.condition.metric_name,
                match rule.condition.operator {
                    ComparisonOperator::GreaterThan => ">",
                    ComparisonOperator::GreaterThanOrEqual => ">=",
                    ComparisonOperator::LessThan => "<",
                    ComparisonOperator::LessThanOrEqual => "<=",
                    ComparisonOperator::Equal => "==",
                    ComparisonOperator::NotEqual => "!=",
                },
                rule.condition.threshold,
                metric_value
            ),
            metric_value,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        let mut alerts = self.alerts.write().await;
        alerts.insert(alert.id, alert.clone());

        // Limit active alerts
        let max_active_alerts = self.config.read().await.max_active_alerts;
        if alerts.len() > max_active_alerts {
            // Remove oldest resolved/acknowledged alert
            let oldest_resolved = alerts
                .values()
                .filter(|a| a.status != AlertStatus::Active)
                .min_by_key(|a| a.created_at)
                .map(|a| a.id);

            if let Some(id) = oldest_resolved {
                alerts.remove(&id);
            }
        }

        info!(
            alert_id = %alert.id,
            rule_id = %rule_id,
            severity = rule.severity.as_str(),
            "Alert triggered"
        );

        // Record metric
        crate::metrics::record_alert_triggered(rule.severity.as_str(), &rule.name);

        alert
    }

    /// Send notifications for an alert.
    async fn send_notifications(&self, alert: &Alert, channels: &[AlertChannel]) {
        for channel in channels {
            match channel {
                AlertChannel::Console => {
                    self.send_console_notification(alert);
                }
                AlertChannel::Email { recipients } => {
                    let _result = self.send_email_notification(alert, recipients).await;
                    // Email failures are already tracked and queued for retry in send_email_notification
                }
                AlertChannel::Slack {
                    webhook_url,
                    channel: slack_channel,
                } => {
                    self.send_slack_notification(alert, webhook_url, slack_channel)
                        .await;
                }
                AlertChannel::Webhook { url, headers } => {
                    self.send_webhook_notification(alert, url, headers).await;
                }
            }
        }
    }

    /// Send console notification.
    fn send_console_notification(&self, alert: &Alert) {
        match alert.severity {
            AlertSeverity::Info => {
                info!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
            AlertSeverity::Warning => {
                warn!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
            AlertSeverity::Critical => {
                error!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
        }
    }

    /// Send email notification via SMTP.
    async fn send_email_notification(
        &self,
        alert: &Alert,
        recipients: &[String],
    ) -> EmailDeliveryResult {
        let config = self.config.read().await;

        // Check if SMTP is configured
        let smtp_config = match &config.smtp {
            Some(smtp) => smtp,
            None => {
                debug!(
                    alert_id = %alert.id,
                    "SMTP not configured, skipping email notification"
                );
                return EmailDeliveryResult {
                    succeeded: Vec::new(),
                    failed: recipients.to_vec(),
                    last_error: Some("SMTP not configured".to_string()),
                };
            }
        };

        // Validate recipients
        if recipients.is_empty() {
            warn!(alert_id = %alert.id, "No recipients specified for email alert");
            return EmailDeliveryResult {
                succeeded: Vec::new(),
                failed: Vec::new(),
                last_error: Some("No recipients specified".to_string()),
            };
        }

        // Build email subject
        let subject = format!(
            "[CHIE Alert - {}] {}",
            alert.severity.as_str().to_uppercase(),
            alert.title
        );

        // Build email body (HTML)
        let severity_color = match alert.severity {
            AlertSeverity::Info => "#36a64f",     // Green
            AlertSeverity::Warning => "#ff9900",  // Orange
            AlertSeverity::Critical => "#ff0000", // Red
        };

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f4f4f4; padding: 20px; border-radius: 0 0 5px 5px; }}
        .field {{ margin: 10px 0; }}
        .field-label {{ font-weight: bold; }}
        .footer {{ margin-top: 20px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
        </div>
        <div class="content">
            <div class="field">
                <span class="field-label">Severity:</span> {severity}
            </div>
            <div class="field">
                <span class="field-label">Message:</span> {message}
            </div>
            <div class="field">
                <span class="field-label">Metric Value:</span> {metric_value}
            </div>
            <div class="field">
                <span class="field-label">Alert ID:</span> {alert_id}
            </div>
            <div class="field">
                <span class="field-label">Created At:</span> {created_at}
            </div>
        </div>
        <div class="footer">
            This is an automated alert from CHIE Coordinator.
        </div>
    </div>
</body>
</html>"#,
            color = severity_color,
            title = alert.title,
            severity = alert.severity.as_str().to_uppercase(),
            message = alert.message,
            metric_value = alert.metric_value,
            alert_id = alert.id,
            created_at = chrono::DateTime::from_timestamp(alert.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
        );

        // Build plain text body as fallback
        let text_body = format!(
            "{title}\n\nSeverity: {severity}\nMessage: {message}\nMetric Value: {metric_value}\nAlert ID: {alert_id}\nCreated At: {created_at}\n\n---\nThis is an automated alert from CHIE Coordinator.",
            title = alert.title,
            severity = alert.severity.as_str().to_uppercase(),
            message = alert.message,
            metric_value = alert.metric_value,
            alert_id = alert.id,
            created_at = chrono::DateTime::from_timestamp(alert.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
        );

        // Parse from email
        let from_mailbox = match format!("{} <{}>", smtp_config.from_name, smtp_config.from_email)
            .parse::<Mailbox>()
        {
            Ok(mailbox) => mailbox,
            Err(e) => {
                error!(alert_id = %alert.id, error = %e, "Invalid from email address");
                return EmailDeliveryResult {
                    succeeded: Vec::new(),
                    failed: recipients.to_vec(),
                    last_error: Some(format!("Invalid from email address: {}", e)),
                };
            }
        };

        // Track succeeded and failed recipients for retry
        let mut succeeded_recipients = Vec::new();
        let mut failed_recipients = Vec::new();
        let mut last_error = String::new();

        // Send to each recipient
        for recipient in recipients {
            // Check if email is bounced
            if config.email_bounce.auto_skip_bounced && self.is_email_bounced(recipient).await {
                warn!(
                    alert_id = %alert.id,
                    recipient = %recipient,
                    "Skipping bounced email address"
                );
                failed_recipients.push(recipient.clone());
                last_error = "Email address is bounced".to_string();
                continue;
            }

            // Check if email is unsubscribed
            if config.email_unsubscribe.auto_skip_unsubscribed
                && self.is_email_unsubscribed(recipient).await
            {
                warn!(
                    alert_id = %alert.id,
                    recipient = %recipient,
                    "Skipping unsubscribed email address"
                );
                failed_recipients.push(recipient.clone());
                last_error = "Email address is unsubscribed".to_string();
                continue;
            }

            // Parse recipient email
            let to_mailbox = match recipient.parse::<Mailbox>() {
                Ok(mailbox) => mailbox,
                Err(e) => {
                    error!(alert_id = %alert.id, recipient = %recipient, error = %e, "Invalid recipient email address");
                    failed_recipients.push(recipient.clone());
                    last_error = format!("Invalid email address: {}", e);
                    // Track as bounce (invalid email)
                    self.track_email_failure(recipient, &format!("Invalid email: {}", e))
                        .await;
                    continue;
                }
            };

            // Build email message
            let email = match Message::builder()
                .from(from_mailbox.clone())
                .to(to_mailbox)
                .subject(&subject)
                .header(header::ContentType::TEXT_HTML)
                .multipart(
                    lettre::message::MultiPart::alternative()
                        .singlepart(
                            lettre::message::SinglePart::builder()
                                .header(header::ContentType::TEXT_PLAIN)
                                .body(text_body.clone()),
                        )
                        .singlepart(
                            lettre::message::SinglePart::builder()
                                .header(header::ContentType::TEXT_HTML)
                                .body(html_body.clone()),
                        ),
                ) {
                Ok(email) => email,
                Err(e) => {
                    error!(alert_id = %alert.id, recipient = %recipient, error = %e, "Failed to build email message");
                    failed_recipients.push(recipient.clone());
                    last_error = format!("Failed to build message: {}", e);
                    // Track email failure for bounce management
                    self.track_email_failure(recipient, &last_error).await;
                    continue;
                }
            };

            // Build SMTP transport
            let smtp_transport = if smtp_config.use_starttls {
                SmtpTransport::starttls_relay(&smtp_config.host)
            } else {
                SmtpTransport::relay(&smtp_config.host)
            };

            let smtp_transport = match smtp_transport {
                Ok(transport) => transport
                    .port(smtp_config.port)
                    .credentials(Credentials::new(
                        smtp_config.username.clone(),
                        smtp_config.password.clone(),
                    ))
                    .build(),
                Err(e) => {
                    error!(alert_id = %alert.id, error = %e, "Failed to create SMTP transport");
                    failed_recipients.push(recipient.clone());
                    last_error = format!("Failed to create SMTP transport: {}", e);
                    continue;
                }
            };

            // Send email (with SLA tracking)
            let start_time = std::time::Instant::now();
            match smtp_transport.send(&email) {
                Ok(_) => {
                    let delivery_time_ms = start_time.elapsed().as_millis() as u64;

                    info!(
                        alert_id = %alert.id,
                        recipient = %recipient,
                        delivery_time_ms = delivery_time_ms,
                        "Email alert sent successfully"
                    );
                    succeeded_recipients.push(recipient.clone());
                    crate::metrics::record_email_sent_successfully();

                    // Track SLA
                    self.track_email_delivery_time(delivery_time_ms).await;

                    // Record success to history
                    let priority = EmailPriority::from_severity(alert.severity);
                    if let Err(e) = self
                        .record_delivery_success(alert, recipient, priority, 0)
                        .await
                    {
                        warn!(error = %e, "Failed to record email delivery success to history");
                    }
                }
                Err(e) => {
                    error!(
                        alert_id = %alert.id,
                        recipient = %recipient,
                        error = %e,
                        "Failed to send email alert"
                    );
                    failed_recipients.push(recipient.clone());
                    last_error = format!("SMTP send failed: {}", e);

                    // Track email failure for bounce management
                    self.track_email_failure(recipient, &last_error).await;

                    // Record failure to history
                    let priority = EmailPriority::from_severity(alert.severity);
                    if let Err(err) = self
                        .record_delivery_failure(alert, recipient, priority, 0, &last_error)
                        .await
                    {
                        warn!(error = %err, "Failed to record email delivery failure to history");
                    }
                }
            }
        }

        // Queue failed emails for retry
        if !failed_recipients.is_empty() {
            self.queue_failed_email(alert, failed_recipients.clone(), last_error.clone())
                .await;
        }

        // Trigger success webhook if configured and all recipients succeeded
        if !succeeded_recipients.is_empty() && failed_recipients.is_empty() {
            if let Some(webhook_mgr) = &self.webhook_manager {
                let payload = serde_json::json!({
                    "alert_id": alert.id,
                    "alert_severity": alert.severity.as_str(),
                    "alert_title": alert.title,
                    "recipients": succeeded_recipients,
                    "delivered_at": current_timestamp(),
                });

                webhook_mgr
                    .trigger_event(WebhookEvent::EmailDeliverySucceeded, payload)
                    .await;

                debug!(
                    alert_id = %alert.id,
                    recipient_count = succeeded_recipients.len(),
                    "Email delivery success webhook triggered"
                );
            }
        }

        EmailDeliveryResult {
            succeeded: succeeded_recipients,
            failed: failed_recipients,
            last_error: if last_error.is_empty() {
                None
            } else {
                Some(last_error)
            },
        }
    }

    /// Send Slack notification.
    async fn send_slack_notification(&self, alert: &Alert, webhook_url: &str, channel: &str) {
        let color = match alert.severity {
            AlertSeverity::Info => "#36a64f",     // Green
            AlertSeverity::Warning => "#ff9900",  // Orange
            AlertSeverity::Critical => "#ff0000", // Red
        };

        let payload = serde_json::json!({
            "channel": channel,
            "username": "CHIE Alerting",
            "icon_emoji": ":warning:",
            "attachments": [{
                "color": color,
                "title": alert.title,
                "text": alert.message,
                "fields": [
                    {
                        "title": "Severity",
                        "value": alert.severity.as_str(),
                        "short": true
                    },
                    {
                        "title": "Metric Value",
                        "value": format!("{:.2}", alert.metric_value),
                        "short": true
                    },
                    {
                        "title": "Alert ID",
                        "value": alert.id.to_string(),
                        "short": false
                    }
                ],
                "footer": "CHIE Coordinator",
                "ts": alert.created_at
            }]
        });

        match self
            .http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                debug!(alert_id = %alert.id, "Slack notification sent");
            }
            Ok(response) => {
                error!(
                    alert_id = %alert.id,
                    status = %response.status(),
                    "Failed to send Slack notification"
                );
            }
            Err(e) => {
                error!(alert_id = %alert.id, error = %e, "Error sending Slack notification");
            }
        }
    }

    /// Send custom webhook notification.
    async fn send_webhook_notification(
        &self,
        alert: &Alert,
        url: &str,
        headers: &HashMap<String, String>,
    ) {
        let mut request = self.http_client.post(url).json(alert);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => {
                debug!(alert_id = %alert.id, "Webhook notification sent");
            }
            Ok(response) => {
                error!(
                    alert_id = %alert.id,
                    status = %response.status(),
                    "Failed to send webhook notification"
                );
            }
            Err(e) => {
                error!(alert_id = %alert.id, error = %e, "Error sending webhook notification");
            }
        }
    }

    /// Queue a failed email for retry.
    async fn queue_failed_email(&self, alert: &Alert, recipients: Vec<String>, error: String) {
        let failed_email = FailedEmail {
            id: Uuid::new_v4(),
            alert: alert.clone(),
            recipients,
            retry_attempts: 0,
            last_retry_at: current_timestamp(),
            failed_at: current_timestamp(),
            last_error: error,
            priority: EmailPriority::from_severity(alert.severity),
        };

        let mut failed_emails = self.failed_emails.write().await;
        failed_emails.push(failed_email.clone());
        drop(failed_emails); // Release lock before DB operation

        debug!(
            failed_email_id = %failed_email.id,
            alert_id = %alert.id,
            "Email queued for retry"
        );

        // Save to database for persistence
        if let Err(e) = self.save_failed_email_to_db(&failed_email).await {
            warn!(
                failed_email_id = %failed_email.id,
                error = %e,
                "Failed to save failed email to database"
            );
        }

        // Record metric
        crate::metrics::record_email_retry_queued();
    }

    /// Calculate retry delay based on exponential backoff.
    fn calculate_retry_delay(&self, retry_attempts: u32, config: &EmailRetryConfig) -> u64 {
        let base_delay = config.initial_retry_delay_seconds;
        let exponential_delay = base_delay * 2_u64.pow(retry_attempts);
        exponential_delay.min(config.max_retry_delay_seconds)
    }

    /// Check if email should be retried.
    fn should_retry_email(&self, failed_email: &FailedEmail, config: &EmailRetryConfig) -> bool {
        let current_time = current_timestamp();
        let age = current_time.saturating_sub(failed_email.failed_at);

        // Check if email is too old
        if age > config.max_retry_age_seconds {
            return false;
        }

        // Check if max retries exceeded
        if failed_email.retry_attempts >= config.max_retry_attempts {
            return false;
        }

        // Check if enough time has passed since last retry
        let retry_delay = self.calculate_retry_delay(failed_email.retry_attempts, config);
        let time_since_last_retry = current_time.saturating_sub(failed_email.last_retry_at);

        time_since_last_retry >= retry_delay
    }

    /// Process email retry queue.
    pub async fn process_email_retries(&self) {
        let config = self.config.read().await;
        let retry_config = config.email_retry.clone();
        drop(config);

        let mut failed_emails = self.failed_emails.write().await;
        let mut emails_to_retry = Vec::new();
        let mut emails_to_remove = Vec::new();

        // Identify emails to retry or remove
        for (index, failed_email) in failed_emails.iter().enumerate() {
            if self.should_retry_email(failed_email, &retry_config) {
                emails_to_retry.push((index, failed_email.clone()));
            } else {
                let age = current_timestamp().saturating_sub(failed_email.failed_at);
                if age > retry_config.max_retry_age_seconds
                    || failed_email.retry_attempts >= retry_config.max_retry_attempts
                {
                    emails_to_remove.push(index);
                }
            }
        }

        // Remove expired/exceeded emails (reverse order to maintain indices)
        let mut removed_emails = Vec::new();
        for &index in emails_to_remove.iter().rev() {
            let removed = failed_emails.remove(index);
            warn!(
                failed_email_id = %removed.id,
                retry_attempts = removed.retry_attempts,
                priority = %removed.priority.as_str(),
                alert_severity = %removed.alert.severity.as_str(),
                "Giving up on failed email after max retries or age limit"
            );
            crate::metrics::record_email_retry_abandoned();
            removed_emails.push(removed);
        }

        drop(failed_emails);

        // Trigger webhook notifications and record history for abandoned emails
        if let Some(webhook_mgr) = &self.webhook_manager {
            for email in &removed_emails {
                // Record abandoned delivery to history for each recipient
                for recipient in &email.recipients {
                    if let Err(e) = self
                        .record_delivery_abandoned(
                            &email.alert,
                            recipient,
                            email.priority,
                            email.retry_attempts,
                            &email.last_error,
                        )
                        .await
                    {
                        warn!(error = %e, "Failed to record abandoned delivery to history");
                    }
                }

                let payload = serde_json::json!({
                    "email_id": email.id,
                    "alert": {
                        "id": email.alert.id,
                        "severity": email.alert.severity.as_str(),
                        "title": email.alert.title,
                        "message": email.alert.message,
                    },
                    "recipients": email.recipients,
                    "retry_attempts": email.retry_attempts,
                    "priority": email.priority.as_str(),
                    "last_error": email.last_error,
                    "failed_at": email.failed_at,
                    "reason": "max_retries_or_age_limit_exceeded",
                });

                webhook_mgr
                    .trigger_event(WebhookEvent::EmailDeliveryFailed, payload)
                    .await;

                // Record webhook metric
                crate::metrics::record_email_delivery_webhook(
                    email.priority.as_str(),
                    "max_retries_or_age_limit_exceeded",
                );

                debug!(
                    failed_email_id = %email.id,
                    priority = %email.priority.as_str(),
                    "Email delivery failure webhook triggered"
                );
            }
        } else {
            // No webhook manager, but still record abandoned emails to history
            for email in &removed_emails {
                for recipient in &email.recipients {
                    if let Err(e) = self
                        .record_delivery_abandoned(
                            &email.alert,
                            recipient,
                            email.priority,
                            email.retry_attempts,
                            &email.last_error,
                        )
                        .await
                    {
                        warn!(error = %e, "Failed to record abandoned delivery to history");
                    }
                }
            }
        }

        // Delete from database
        for email in removed_emails {
            if let Err(e) = self.delete_failed_email_from_db(email.id).await {
                warn!(failed_email_id = %email.id, error = %e, "Failed to delete abandoned email from database");
            }
        }

        // Sort emails by priority (highest priority first)
        emails_to_retry.sort_by(|a, b| b.1.priority.cmp(&a.1.priority));

        // Retry emails
        for (_index, mut failed_email) in emails_to_retry {
            info!(
                failed_email_id = %failed_email.id,
                attempt = failed_email.retry_attempts + 1,
                priority = %failed_email.priority.as_str(),
                "Retrying failed email delivery"
            );

            // Record metrics
            crate::metrics::record_email_retry_by_priority(failed_email.priority.as_str());

            // Attempt to send email
            let delivery_result = self
                .send_email_notification(&failed_email.alert, &failed_email.recipients)
                .await;

            // Check if delivery was fully successful (all recipients succeeded)
            let fully_succeeded =
                delivery_result.failed.is_empty() && !delivery_result.succeeded.is_empty();

            if fully_succeeded {
                // Remove from retry queue on success
                info!(
                    failed_email_id = %failed_email.id,
                    succeeded_count = delivery_result.succeeded.len(),
                    "Email delivered successfully on retry, removing from queue"
                );

                // Record successful retry delivery to history for each recipient
                for recipient in &delivery_result.succeeded {
                    if let Err(e) = self
                        .record_delivery_success(
                            &failed_email.alert,
                            recipient,
                            failed_email.priority,
                            failed_email.retry_attempts + 1,
                        )
                        .await
                    {
                        warn!(error = %e, "Failed to record retry delivery success to history");
                    }
                }

                let mut failed_emails = self.failed_emails.write().await;
                if let Some(pos) = failed_emails.iter().position(|e| e.id == failed_email.id) {
                    failed_emails.remove(pos);
                }
                drop(failed_emails);

                // Remove from database
                if let Err(e) = self.delete_failed_email_from_db(failed_email.id).await {
                    warn!(
                        failed_email_id = %failed_email.id,
                        error = %e,
                        "Failed to delete successfully delivered email from database"
                    );
                }

                // Record metric
                crate::metrics::record_email_retry_queue_removed();
            } else if !delivery_result.failed.is_empty() {
                // Still failing - update retry info
                failed_email.retry_attempts += 1;
                failed_email.last_retry_at = current_timestamp();
                failed_email.recipients = delivery_result.failed.clone();
                if let Some(err) = delivery_result.last_error {
                    failed_email.last_error = err;
                }

                let mut failed_emails = self.failed_emails.write().await;
                if let Some(email) = failed_emails.iter_mut().find(|e| e.id == failed_email.id) {
                    email.retry_attempts = failed_email.retry_attempts;
                    email.last_retry_at = failed_email.last_retry_at;
                    email.recipients = failed_email.recipients.clone();
                    email.last_error = failed_email.last_error.clone();
                }
                drop(failed_emails);

                // Update database with new retry count
                if let Err(e) = self.save_failed_email_to_db(&failed_email).await {
                    warn!(
                        failed_email_id = %failed_email.id,
                        error = %e,
                        "Failed to update failed email in database after retry"
                    );
                }

                crate::metrics::record_email_retry_attempt(failed_email.retry_attempts);
            }
        }
    }

    /// Get failed emails from retry queue.
    pub async fn get_failed_emails(&self) -> Vec<FailedEmail> {
        self.failed_emails.read().await.clone()
    }

    /// Remove a failed email from retry queue (after successful delivery or manual intervention).
    pub async fn remove_failed_email(&self, email_id: Uuid) -> bool {
        let mut failed_emails = self.failed_emails.write().await;
        if let Some(pos) = failed_emails.iter().position(|e| e.id == email_id) {
            failed_emails.remove(pos);
            info!(failed_email_id = %email_id, "Failed email removed from retry queue");

            // Remove from database as well
            if let Err(e) = self.delete_failed_email_from_db(email_id).await {
                warn!(failed_email_id = %email_id, error = %e, "Failed to delete failed email from database");
            }

            return true;
        }
        false
    }

    /// Save a failed email to database for persistence.
    async fn save_failed_email_to_db(&self, failed_email: &FailedEmail) -> Result<(), sqlx::Error> {
        let alert_severity = match failed_email.alert.severity {
            AlertSeverity::Info => "Info",
            AlertSeverity::Warning => "Warning",
            AlertSeverity::Critical => "Critical",
        };

        let retry_config = self.config.read().await.email_retry.clone();
        let max_age_seconds = retry_config.max_retry_age_seconds;
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(max_age_seconds as i64);

        // Calculate next retry time
        let next_retry_at = if Self::should_retry_email_static(failed_email, &retry_config) {
            let delay =
                Self::calculate_retry_delay_static(failed_email.retry_attempts, &retry_config);
            Some(chrono::Utc::now() + chrono::Duration::seconds(delay as i64))
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT INTO email_retry_queue
                (id, alert_id, alert_severity, alert_message, recipients, failed_recipients,
                 last_error, retry_count, max_retries, next_retry_at, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO UPDATE SET
                retry_count = EXCLUDED.retry_count,
                last_error = EXCLUDED.last_error,
                next_retry_at = EXCLUDED.next_retry_at,
                updated_at = NOW()
            "#,
        )
        .bind(failed_email.id)
        .bind(failed_email.alert.id)
        .bind(alert_severity)
        .bind(&failed_email.alert.message)
        .bind(&failed_email.recipients)
        .bind(&failed_email.recipients)
        .bind(&failed_email.last_error)
        .bind(failed_email.retry_attempts as i32)
        .bind(retry_config.max_retry_attempts as i32)
        .bind(next_retry_at)
        .bind(chrono::DateTime::from_timestamp(
            failed_email.failed_at as i64,
            0,
        ))
        .bind(expires_at)
        .execute(&self.db)
        .await?;

        debug!(failed_email_id = %failed_email.id, "Failed email saved to database");
        crate::metrics::record_email_retry_db_save();
        Ok(())
    }

    /// Load failed emails from database on startup.
    pub async fn load_failed_emails_from_db(&self) -> Result<(), sqlx::Error> {
        use sqlx::Row;

        let rows = sqlx::query(
            r#"
            SELECT id, alert_id, alert_severity, alert_message, recipients, failed_recipients,
                   last_error, retry_count, created_at
            FROM email_retry_queue
            WHERE expires_at > NOW()
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.db)
        .await?;

        let mut failed_emails = self.failed_emails.write().await;
        failed_emails.clear();

        for row in rows {
            let alert_severity: String = row.try_get("alert_severity")?;
            let severity = match alert_severity.as_str() {
                "Info" => AlertSeverity::Info,
                "Warning" => AlertSeverity::Warning,
                "Critical" => AlertSeverity::Critical,
                _ => AlertSeverity::Warning,
            };

            let alert_id: Uuid = row.try_get("alert_id")?;
            let alert_message: String = row.try_get("alert_message")?;
            let created_at: chrono::NaiveDateTime = row.try_get("created_at")?;

            let alert = Alert {
                id: alert_id,
                rule_id: Uuid::nil(), // Unknown rule ID when loading from DB
                severity,
                title: "Email Retry Alert".to_string(),
                message: alert_message,
                metric_value: 0.0,
                created_at: created_at.and_utc().timestamp() as u64,
                acknowledged_at: None,
                acknowledged_by: None,
                status: AlertStatus::Active,
            };

            let email_id: Uuid = row.try_get("id")?;
            let failed_recipients: Vec<String> = row.try_get("failed_recipients")?;
            let retry_count: i32 = row.try_get("retry_count")?;
            let last_error: Option<String> = row.try_get("last_error")?;

            let failed_email = FailedEmail {
                id: email_id,
                alert: alert.clone(),
                recipients: failed_recipients,
                retry_attempts: retry_count as u32,
                last_retry_at: chrono::Utc::now().timestamp() as u64,
                failed_at: created_at.and_utc().timestamp() as u64,
                last_error: last_error.unwrap_or_default(),
                priority: EmailPriority::from_severity(alert.severity),
            };

            failed_emails.push(failed_email);
        }

        let count = failed_emails.len();
        info!(count = count, "Loaded failed emails from database");
        crate::metrics::record_email_retry_db_load(count);
        Ok(())
    }

    /// Delete a failed email from database.
    async fn delete_failed_email_from_db(&self, email_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM email_retry_queue WHERE id = $1")
            .bind(email_id)
            .execute(&self.db)
            .await?;

        debug!(failed_email_id = %email_id, "Failed email deleted from database");
        Ok(())
    }

    /// Cleanup expired failed emails from database.
    pub async fn cleanup_expired_failed_emails_db(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM email_retry_queue WHERE expires_at <= NOW()")
            .execute(&self.db)
            .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!(
                deleted = deleted,
                "Cleaned up expired failed emails from database"
            );
            crate::metrics::record_email_retry_db_cleanup(deleted);
        }
        Ok(deleted)
    }

    /// Record successful email delivery to history.
    async fn record_delivery_success(
        &self,
        alert: &Alert,
        recipient: &str,
        priority: EmailPriority,
        retry_attempt: u32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO email_delivery_history
                (alert_id, alert_severity, alert_title, alert_message, recipient,
                 status, priority, retry_attempt, delivered_at)
            VALUES ($1, $2, $3, $4, $5, 'sent', $6, $7, NOW())
            "#,
        )
        .bind(alert.id)
        .bind(alert.severity.as_str())
        .bind(&alert.title)
        .bind(&alert.message)
        .bind(recipient)
        .bind(priority.as_str())
        .bind(retry_attempt as i32)
        .execute(&self.db)
        .await?;

        debug!(alert_id = %alert.id, recipient = %recipient, "Email delivery success recorded to history");
        Ok(())
    }

    /// Record failed email delivery to history.
    async fn record_delivery_failure(
        &self,
        alert: &Alert,
        recipient: &str,
        priority: EmailPriority,
        retry_attempt: u32,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO email_delivery_history
                (alert_id, alert_severity, alert_title, alert_message, recipient,
                 status, priority, retry_attempt, error_message, failed_at)
            VALUES ($1, $2, $3, $4, $5, 'failed', $6, $7, $8, NOW())
            "#,
        )
        .bind(alert.id)
        .bind(alert.severity.as_str())
        .bind(&alert.title)
        .bind(&alert.message)
        .bind(recipient)
        .bind(priority.as_str())
        .bind(retry_attempt as i32)
        .bind(error)
        .execute(&self.db)
        .await?;

        debug!(alert_id = %alert.id, recipient = %recipient, "Email delivery failure recorded to history");
        Ok(())
    }

    /// Record abandoned email (max retries exceeded) to history.
    async fn record_delivery_abandoned(
        &self,
        alert: &Alert,
        recipient: &str,
        priority: EmailPriority,
        retry_attempt: u32,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO email_delivery_history
                (alert_id, alert_severity, alert_title, alert_message, recipient,
                 status, priority, retry_attempt, error_message, failed_at)
            VALUES ($1, $2, $3, $4, $5, 'abandoned', $6, $7, $8, NOW())
            "#,
        )
        .bind(alert.id)
        .bind(alert.severity.as_str())
        .bind(&alert.title)
        .bind(&alert.message)
        .bind(recipient)
        .bind(priority.as_str())
        .bind(retry_attempt as i32)
        .bind(error)
        .execute(&self.db)
        .await?;

        debug!(alert_id = %alert.id, recipient = %recipient, "Email delivery abandonment recorded to history");
        Ok(())
    }

    /// Helper: Calculate retry delay (static version for DB operations).
    fn calculate_retry_delay_static(retry_attempts: u32, config: &EmailRetryConfig) -> u64 {
        let delay = config.initial_retry_delay_seconds * 2u64.pow(retry_attempts);
        delay.min(config.max_retry_delay_seconds)
    }

    /// Helper: Check if email should be retried (static version for DB operations).
    fn should_retry_email_static(failed_email: &FailedEmail, config: &EmailRetryConfig) -> bool {
        // Check max retries
        if failed_email.retry_attempts >= config.max_retry_attempts {
            return false;
        }

        // Check max age
        let age = chrono::Utc::now().timestamp() as u64 - failed_email.failed_at;
        if age > config.max_retry_age_seconds {
            return false;
        }

        true
    }

    /// Acknowledge an alert.
    pub async fn acknowledge_alert(&self, alert_id: Uuid, acknowledged_by: String) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(&alert_id) {
            if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Acknowledged;
                alert.acknowledged_at = Some(current_timestamp());
                alert.acknowledged_by = Some(acknowledged_by.clone());

                info!(
                    alert_id = %alert_id,
                    acknowledged_by = %acknowledged_by,
                    "Alert acknowledged"
                );

                return true;
            }
        }
        false
    }

    /// Resolve an alert.
    pub async fn resolve_alert(&self, alert_id: Uuid) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(&alert_id) {
            alert.status = AlertStatus::Resolved;
            info!(alert_id = %alert_id, "Alert resolved");

            // Move to history
            let mut history = self.history.write().await;
            history.push(alert.clone());

            // Clean old history
            let history_retention_seconds = self.config.read().await.history_retention_seconds;
            let cutoff = current_timestamp().saturating_sub(history_retention_seconds);
            history.retain(|a| a.created_at >= cutoff);

            return true;
        }
        false
    }

    /// Get all active alerts.
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .values()
            .filter(|a| a.status == AlertStatus::Active)
            .cloned()
            .collect()
    }

    /// Get all alerts (active and historical).
    pub async fn get_all_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        let mut all: Vec<_> = alerts.values().cloned().collect();

        let history = self.history.read().await;
        all.extend(history.iter().cloned());

        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        all
    }

    /// Get alert by ID.
    pub async fn get_alert(&self, alert_id: Uuid) -> Option<Alert> {
        let alerts = self.alerts.read().await;
        if let Some(alert) = alerts.get(&alert_id) {
            return Some(alert.clone());
        }

        let history = self.history.read().await;
        history.iter().find(|a| a.id == alert_id).cloned()
    }

    /// Get alerting statistics.
    pub async fn get_stats(&self) -> AlertStats {
        let alerts = self.alerts.read().await;
        let history = self.history.read().await;

        let mut all_alerts: Vec<_> = alerts.values().collect();
        all_alerts.extend(history.iter());

        let total_alerts = all_alerts.len();
        let mut active_alerts = 0usize;
        let mut acknowledged_alerts = 0usize;
        let mut resolved_alerts = 0usize;
        let mut by_severity = HashMap::new();
        let mut by_rule = HashMap::new();

        let mut total_ack_time = 0u64;
        let mut ack_count = 0usize;

        for alert in &all_alerts {
            match alert.status {
                AlertStatus::Active => active_alerts += 1,
                AlertStatus::Acknowledged => acknowledged_alerts += 1,
                AlertStatus::Resolved => resolved_alerts += 1,
                AlertStatus::Snoozed => {}
            }

            *by_severity
                .entry(alert.severity.as_str().to_string())
                .or_insert(0) += 1;
            *by_rule.entry(alert.rule_id).or_insert(0) += 1;

            if let Some(ack_time) = alert.acknowledged_at {
                total_ack_time += ack_time.saturating_sub(alert.created_at);
                ack_count += 1;
            }
        }

        let avg_time_to_ack = if ack_count > 0 {
            (total_ack_time as f64) / (ack_count as f64)
        } else {
            0.0
        };

        AlertStats {
            total_alerts,
            active_alerts,
            acknowledged_alerts,
            resolved_alerts,
            by_severity,
            by_rule,
            avg_time_to_ack,
        }
    }

    /// Track an email delivery failure for bounce management.
    pub async fn track_email_failure(&self, email: &str, error: &str) {
        let now = current_timestamp();
        let config = self.config.read().await;
        let bounce_config = &config.email_bounce;

        let mut bounces = self.email_bounces.write().await;

        if let Some(bounce) = bounces.get_mut(email) {
            // Update existing bounce record
            bounce.failure_count += 1;
            bounce.last_failed_at = now;
            bounce.last_error = error.to_string();

            // Check if we should mark as bounced
            if bounce.failure_count >= bounce_config.max_failures_before_bounce {
                bounce.is_bounced = true;
                warn!(
                    email = %email,
                    failure_count = bounce.failure_count,
                    "Email marked as bounced due to repeated failures"
                );

                // Record metric
                crate::metrics::record_email_bounce_marked(email);
            }
        } else {
            // Create new bounce record
            bounces.insert(
                email.to_string(),
                EmailBounce {
                    email: email.to_string(),
                    failure_count: 1,
                    first_failed_at: now,
                    last_failed_at: now,
                    last_error: error.to_string(),
                    is_bounced: false,
                },
            );
        }
    }

    /// Check if an email address is marked as bounced.
    pub async fn is_email_bounced(&self, email: &str) -> bool {
        let bounces = self.email_bounces.read().await;
        bounces.get(email).map(|b| b.is_bounced).unwrap_or(false)
    }

    /// Get all bounced email addresses.
    pub async fn get_bounced_emails(&self) -> Vec<EmailBounce> {
        let bounces = self.email_bounces.read().await;
        bounces.values().filter(|b| b.is_bounced).cloned().collect()
    }

    /// Get all email bounce records (bounced and not bounced).
    pub async fn get_all_bounces(&self) -> Vec<EmailBounce> {
        let bounces = self.email_bounces.read().await;
        bounces.values().cloned().collect()
    }

    /// Remove bounce status from an email address.
    pub async fn remove_bounce(&self, email: &str) -> bool {
        let mut bounces = self.email_bounces.write().await;
        let removed = bounces.remove(email).is_some();
        if removed {
            info!(email = %email, "Bounce status removed from email");
            crate::metrics::record_email_bounce_removed(email);
        }
        removed
    }

    /// Clear old bounce records outside the tracking window.
    pub async fn cleanup_old_bounces(&self) {
        let config = self.config.read().await;
        let bounce_config = &config.email_bounce;
        let now = current_timestamp();
        let cutoff = now.saturating_sub(bounce_config.failure_tracking_window_seconds);

        let mut bounces = self.email_bounces.write().await;
        let before_count = bounces.len();

        bounces.retain(|_, bounce| {
            // Keep if still within tracking window
            bounce.last_failed_at >= cutoff
        });

        let removed_count = before_count - bounces.len();
        if removed_count > 0 {
            info!(removed_count, "Cleaned up old bounce records");
            crate::metrics::record_email_bounce_cleanup(removed_count);
        }
    }

    /// Add an email to the unsubscribe list.
    pub async fn unsubscribe_email(
        &self,
        email: &str,
        reason: Option<String>,
        source: UnsubscribeSource,
    ) {
        let now = current_timestamp();
        let mut unsubscribes = self.email_unsubscribes.write().await;

        unsubscribes.insert(
            email.to_string(),
            EmailUnsubscribe {
                email: email.to_string(),
                unsubscribed_at: now,
                reason,
                source,
            },
        );

        info!(
            email = %email,
            source = %source.as_str(),
            "Email unsubscribed"
        );

        crate::metrics::record_email_unsubscribed(source.as_str());
    }

    /// Check if an email address is unsubscribed.
    pub async fn is_email_unsubscribed(&self, email: &str) -> bool {
        let unsubscribes = self.email_unsubscribes.read().await;
        unsubscribes.contains_key(email)
    }

    /// Get all unsubscribed email addresses.
    pub async fn get_unsubscribed_emails(&self) -> Vec<EmailUnsubscribe> {
        let unsubscribes = self.email_unsubscribes.read().await;
        unsubscribes.values().cloned().collect()
    }

    /// Resubscribe an email (remove from unsubscribe list).
    pub async fn resubscribe_email(&self, email: &str) -> bool {
        let mut unsubscribes = self.email_unsubscribes.write().await;
        let removed = unsubscribes.remove(email).is_some();

        if removed {
            info!(email = %email, "Email resubscribed");
            crate::metrics::record_email_resubscribed();
        }

        removed
    }

    /// Generate unsubscribe link for an email address.
    pub async fn generate_unsubscribe_link(&self, email: &str) -> Option<String> {
        let config = self.config.read().await;
        if let Some(base_url) = &config.email_unsubscribe.unsubscribe_base_url {
            // Simple token-based unsubscribe link (in production, use signed tokens)
            let token = blake3::hash(format!("{}:{}", email, current_timestamp()).as_bytes())
                .to_hex()
                .to_string();
            Some(format!(
                "{}?email={}&token={}",
                base_url,
                urlencoding::encode(email),
                token
            ))
        } else {
            None
        }
    }

    /// Track email delivery time for SLA monitoring.
    pub async fn track_email_delivery_time(&self, delivery_time_ms: u64) {
        let config = self.config.read().await;
        if !config.email_sla.enabled {
            return;
        }

        let target_ms = config.email_sla.target_delivery_ms;
        drop(config); // Release config lock

        let mut metrics = self.email_sla_metrics.write().await;

        // Update counts
        metrics.total_sent += 1;
        if delivery_time_ms <= target_ms {
            metrics.within_sla += 1;
        } else {
            metrics.breached_sla += 1;
        }

        // Update min/max
        if metrics.total_sent == 1 {
            metrics.min_delivery_ms = delivery_time_ms;
            metrics.max_delivery_ms = delivery_time_ms;
            metrics.avg_delivery_ms = delivery_time_ms as f64;
        } else {
            if delivery_time_ms < metrics.min_delivery_ms {
                metrics.min_delivery_ms = delivery_time_ms;
            }
            if delivery_time_ms > metrics.max_delivery_ms {
                metrics.max_delivery_ms = delivery_time_ms;
            }

            // Update running average
            let total = metrics.total_sent as f64;
            metrics.avg_delivery_ms =
                (metrics.avg_delivery_ms * (total - 1.0) + delivery_time_ms as f64) / total;
        }

        // Update SLA rate
        metrics.sla_rate = metrics.within_sla as f64 / metrics.total_sent as f64;

        // Record metrics
        crate::metrics::record_email_delivery_time(delivery_time_ms);
        if delivery_time_ms > target_ms {
            crate::metrics::record_email_sla_breach(delivery_time_ms, target_ms);
        }
    }

    /// Get current email delivery SLA metrics.
    pub async fn get_sla_metrics(&self) -> EmailSlaMetrics {
        let metrics = self.email_sla_metrics.read().await;
        metrics.clone()
    }

    /// Reset SLA metrics (useful for testing or periodic resets).
    pub async fn reset_sla_metrics(&self) {
        let mut metrics = self.email_sla_metrics.write().await;
        *metrics = EmailSlaMetrics::default();
        info!("Email SLA metrics reset");
    }
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    /// Helper function to create a test database pool.
    fn test_db_pool() -> PgPool {
        // Create a lazy pool with very short acquire timeout (fails fast if DB unavailable)
        // This prevents tests from hanging for 60+ seconds when DB is not available
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/test_db")
            .expect("Failed to create test pool")
    }

    #[test]
    fn test_comparison_operator_evaluate() {
        assert!(ComparisonOperator::GreaterThan.evaluate(10.0, 5.0));
        assert!(!ComparisonOperator::GreaterThan.evaluate(5.0, 10.0));

        assert!(ComparisonOperator::LessThan.evaluate(5.0, 10.0));
        assert!(!ComparisonOperator::LessThan.evaluate(10.0, 5.0));

        assert!(ComparisonOperator::Equal.evaluate(5.0, 5.0));
        assert!(!ComparisonOperator::Equal.evaluate(5.0, 6.0));
    }

    #[test]
    fn test_alert_severity_as_str() {
        assert_eq!(AlertSeverity::Info.as_str(), "info");
        assert_eq!(AlertSeverity::Warning.as_str(), "warning");
        assert_eq!(AlertSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_alert_status_as_str() {
        assert_eq!(AlertStatus::Active.as_str(), "active");
        assert_eq!(AlertStatus::Acknowledged.as_str(), "acknowledged");
        assert_eq!(AlertStatus::Resolved.as_str(), "resolved");
        assert_eq!(AlertStatus::Snoozed.as_str(), "snoozed");
    }

    #[test]
    fn test_alerting_config_default() {
        let config = AlertingConfig::default();
        assert_eq!(config.max_active_alerts, 1000);
        assert_eq!(config.default_cooldown_seconds, 300);
        assert_eq!(config.history_retention_seconds, 7 * 24 * 3600);
    }

    #[tokio::test]
    async fn test_alerting_manager_creation() {
        let config = AlertingConfig::default();
        let manager = AlertingManager::new(test_db_pool(), config);
        assert_eq!(manager.get_rules().await.len(), 0);
    }

    #[tokio::test]
    async fn test_add_and_remove_rule() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let rule = AlertRule {
            id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            description: "Test description".to_string(),
            severity: AlertSeverity::Warning,
            condition: AlertCondition {
                metric_name: "test_metric".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 100.0,
                duration_seconds: 60,
            },
            channels: vec![AlertChannel::Console],
            enabled: true,
            cooldown_seconds: 300,
        };

        let rule_id = rule.id;

        manager.add_rule(rule).await;
        assert_eq!(manager.get_rules().await.len(), 1);

        assert!(manager.remove_rule(rule_id).await);
        assert_eq!(manager.get_rules().await.len(), 0);
    }

    #[tokio::test]
    async fn test_update_rule() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let mut rule = AlertRule {
            id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            description: "Original description".to_string(),
            severity: AlertSeverity::Warning,
            condition: AlertCondition {
                metric_name: "test_metric".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 100.0,
                duration_seconds: 60,
            },
            channels: vec![AlertChannel::Console],
            enabled: true,
            cooldown_seconds: 300,
        };

        manager.add_rule(rule.clone()).await;

        rule.description = "Updated description".to_string();
        assert!(manager.update_rule(rule.clone()).await);

        let retrieved = manager.get_rule(rule.id).await.unwrap();
        assert_eq!(retrieved.description, "Updated description");
    }

    #[tokio::test]
    async fn test_enable_disable_rule() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let rule = AlertRule {
            id: Uuid::new_v4(),
            name: "Test Rule".to_string(),
            description: "Test".to_string(),
            severity: AlertSeverity::Info,
            condition: AlertCondition {
                metric_name: "test_metric".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 50.0,
                duration_seconds: 0,
            },
            channels: vec![AlertChannel::Console],
            enabled: true,
            cooldown_seconds: 0,
        };

        let rule_id = rule.id;
        manager.add_rule(rule).await;

        assert!(manager.set_rule_enabled(rule_id, false).await);
        let retrieved = manager.get_rule(rule_id).await.unwrap();
        assert!(!retrieved.enabled);
    }

    #[tokio::test]
    async fn test_acknowledge_and_resolve_alert() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let rule = AlertRule {
            id: Uuid::new_v4(),
            name: "Test Alert".to_string(),
            description: "Test".to_string(),
            severity: AlertSeverity::Critical,
            condition: AlertCondition {
                metric_name: "error_rate".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 10.0,
                duration_seconds: 0,
            },
            channels: vec![AlertChannel::Console],
            enabled: true,
            cooldown_seconds: 0,
        };

        manager.add_rule(rule).await;

        // Trigger alert
        manager.check_metric("error_rate", 15.0).await;

        let active = manager.get_active_alerts().await;
        assert_eq!(active.len(), 1);

        let alert_id = active[0].id;

        // Acknowledge
        assert!(
            manager
                .acknowledge_alert(alert_id, "admin".to_string())
                .await
        );
        let alert = manager.get_alert(alert_id).await.unwrap();
        assert_eq!(alert.status, AlertStatus::Acknowledged);

        // Resolve
        assert!(manager.resolve_alert(alert_id).await);
        let alert = manager.get_alert(alert_id).await.unwrap();
        assert_eq!(alert.status, AlertStatus::Resolved);
    }

    #[tokio::test]
    async fn test_alert_stats() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let rule = AlertRule {
            id: Uuid::new_v4(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            severity: AlertSeverity::Warning,
            condition: AlertCondition {
                metric_name: "test".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: 5.0,
                duration_seconds: 0,
            },
            channels: vec![AlertChannel::Console],
            enabled: true,
            cooldown_seconds: 0,
        };

        manager.add_rule(rule).await;
        manager.check_metric("test", 10.0).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_alerts, 1);
        assert_eq!(stats.active_alerts, 1);
    }

    #[test]
    fn test_smtp_config_default() {
        let smtp_config = SmtpConfig::default();
        assert_eq!(smtp_config.host, "localhost");
        assert_eq!(smtp_config.port, 587);
        assert_eq!(smtp_config.from_email, "alerts@chie.example.com");
        assert_eq!(smtp_config.from_name, "CHIE Alerts");
        assert!(smtp_config.use_starttls);
    }

    #[test]
    fn test_alerting_config_with_smtp() {
        let smtp_config = SmtpConfig {
            host: "smtp.gmail.com".to_string(),
            port: 587,
            username: "user@example.com".to_string(),
            password: "password".to_string(),
            from_email: "alerts@example.com".to_string(),
            from_name: "Test Alerts".to_string(),
            use_starttls: true,
        };

        let config = AlertingConfig {
            max_active_alerts: 1000,
            default_cooldown_seconds: 300,
            history_retention_seconds: 7 * 24 * 3600,
            smtp: Some(smtp_config.clone()),
            email_retry: EmailRetryConfig::default(),
            email_bounce: EmailBounceConfig::default(),
            email_unsubscribe: EmailUnsubscribeConfig::default(),
            email_sla: EmailSlaConfig::default(),
        };

        assert!(config.smtp.is_some());
        let smtp = config.smtp.unwrap();
        assert_eq!(smtp.host, "smtp.gmail.com");
        assert_eq!(smtp.username, "user@example.com");
    }

    #[tokio::test]
    async fn test_email_notification_without_smtp() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Warning,
            title: "Test Alert".to_string(),
            message: "This is a test alert".to_string(),
            metric_value: 42.0,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        // This should not panic, just log that SMTP is not configured
        manager
            .send_email_notification(&alert, &["test@example.com".to_string()])
            .await;
    }

    #[tokio::test]
    async fn test_email_notification_with_empty_recipients() {
        let smtp_config = SmtpConfig::default();
        let config = AlertingConfig {
            max_active_alerts: 1000,
            default_cooldown_seconds: 300,
            history_retention_seconds: 7 * 24 * 3600,
            smtp: Some(smtp_config),
            email_retry: EmailRetryConfig::default(),
            email_bounce: EmailBounceConfig::default(),
            email_unsubscribe: EmailUnsubscribeConfig::default(),
            email_sla: EmailSlaConfig::default(),
        };
        let manager = AlertingManager::new(test_db_pool(), config);

        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Critical,
            title: "Test Alert".to_string(),
            message: "This is a test alert".to_string(),
            metric_value: 100.0,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        // This should not panic, just log that no recipients specified
        manager.send_email_notification(&alert, &[]).await;
    }

    #[test]
    fn test_alert_channel_email_variant() {
        let email_channel = AlertChannel::Email {
            recipients: vec![
                "admin@example.com".to_string(),
                "ops@example.com".to_string(),
            ],
        };

        match email_channel {
            AlertChannel::Email { recipients } => {
                assert_eq!(recipients.len(), 2);
                assert_eq!(recipients[0], "admin@example.com");
                assert_eq!(recipients[1], "ops@example.com");
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn test_email_retry_config_default() {
        let retry_config = EmailRetryConfig::default();
        assert_eq!(retry_config.max_retry_attempts, 5);
        assert_eq!(retry_config.initial_retry_delay_seconds, 60);
        assert_eq!(retry_config.max_retry_delay_seconds, 3600);
        assert_eq!(retry_config.max_retry_age_seconds, 24 * 3600);
    }

    #[test]
    fn test_alerting_config_with_email_retry() {
        let config = AlertingConfig::default();
        assert_eq!(config.email_retry.max_retry_attempts, 5);
        assert_eq!(config.email_retry.initial_retry_delay_seconds, 60);
    }

    #[tokio::test]
    async fn test_calculate_retry_delay() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());
        let config = EmailRetryConfig::default();

        // Test exponential backoff: base * 2^attempts
        assert_eq!(manager.calculate_retry_delay(0, &config), 60); // 60 * 2^0 = 60
        assert_eq!(manager.calculate_retry_delay(1, &config), 120); // 60 * 2^1 = 120
        assert_eq!(manager.calculate_retry_delay(2, &config), 240); // 60 * 2^2 = 240
        assert_eq!(manager.calculate_retry_delay(3, &config), 480); // 60 * 2^3 = 480

        // Test max delay cap
        assert_eq!(manager.calculate_retry_delay(10, &config), 3600); // Capped at max_retry_delay_seconds
    }

    #[tokio::test]
    async fn test_should_retry_email() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());
        let config = EmailRetryConfig::default();

        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Critical,
            title: "Test".to_string(),
            message: "Test".to_string(),
            metric_value: 100.0,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        // Fresh failure - should not retry yet (need to wait for delay)
        let failed_email = FailedEmail {
            id: Uuid::new_v4(),
            alert: alert.clone(),
            recipients: vec!["test@example.com".to_string()],
            retry_attempts: 0,
            last_retry_at: current_timestamp(),
            failed_at: current_timestamp(),
            last_error: "Test error".to_string(),
            priority: EmailPriority::Urgent,
        };
        assert!(!manager.should_retry_email(&failed_email, &config));

        // Old failure - should retry
        let old_failed_email = FailedEmail {
            id: Uuid::new_v4(),
            alert: alert.clone(),
            recipients: vec!["test@example.com".to_string()],
            retry_attempts: 0,
            last_retry_at: current_timestamp() - 120, // 2 minutes ago
            failed_at: current_timestamp() - 120,
            last_error: "Test error".to_string(),
            priority: EmailPriority::Urgent,
        };
        assert!(manager.should_retry_email(&old_failed_email, &config));

        // Too many retries
        let max_retries_email = FailedEmail {
            id: Uuid::new_v4(),
            alert: alert.clone(),
            recipients: vec!["test@example.com".to_string()],
            retry_attempts: 5, // Max retries reached
            last_retry_at: current_timestamp() - 120,
            failed_at: current_timestamp() - 120,
            last_error: "Test error".to_string(),
            priority: EmailPriority::Urgent,
        };
        assert!(!manager.should_retry_email(&max_retries_email, &config));

        // Too old
        let too_old_email = FailedEmail {
            id: Uuid::new_v4(),
            alert,
            recipients: vec!["test@example.com".to_string()],
            retry_attempts: 1,
            last_retry_at: current_timestamp() - 25 * 3600, // 25 hours ago
            failed_at: current_timestamp() - 25 * 3600,
            last_error: "Test error".to_string(),
            priority: EmailPriority::Urgent,
        };
        assert!(!manager.should_retry_email(&too_old_email, &config));
    }

    #[tokio::test]
    async fn test_failed_email_queue_operations() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Warning,
            title: "Test Alert".to_string(),
            message: "Test message".to_string(),
            metric_value: 50.0,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        // Queue a failed email
        manager
            .queue_failed_email(
                &alert,
                vec!["failed@example.com".to_string()],
                "SMTP connection failed".to_string(),
            )
            .await;

        // Check it's in the queue
        let failed_emails = manager.get_failed_emails().await;
        assert_eq!(failed_emails.len(), 1);
        assert_eq!(failed_emails[0].recipients[0], "failed@example.com");
        assert_eq!(failed_emails[0].last_error, "SMTP connection failed");

        // Remove from queue
        let email_id = failed_emails[0].id;
        assert!(manager.remove_failed_email(email_id).await);

        // Verify it's removed
        let failed_emails = manager.get_failed_emails().await;
        assert_eq!(failed_emails.len(), 0);
    }

    #[test]
    fn test_failed_email_structure() {
        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Info,
            title: "Test".to_string(),
            message: "Test message".to_string(),
            metric_value: 10.0,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        let failed_email = FailedEmail {
            id: Uuid::new_v4(),
            alert,
            recipients: vec![
                "user1@example.com".to_string(),
                "user2@example.com".to_string(),
            ],
            retry_attempts: 2,
            last_retry_at: current_timestamp(),
            failed_at: current_timestamp() - 300,
            last_error: "Connection timeout".to_string(),
            priority: EmailPriority::Normal,
        };

        assert_eq!(failed_email.recipients.len(), 2);
        assert_eq!(failed_email.retry_attempts, 2);
        assert_eq!(failed_email.last_error, "Connection timeout");
        assert_eq!(failed_email.priority, EmailPriority::Normal);
    }

    #[test]
    fn test_email_priority_default() {
        let priority = EmailPriority::default();
        assert_eq!(priority, EmailPriority::Normal);
    }

    #[test]
    fn test_email_priority_from_severity() {
        assert_eq!(
            EmailPriority::from_severity(AlertSeverity::Info),
            EmailPriority::Low
        );
        assert_eq!(
            EmailPriority::from_severity(AlertSeverity::Warning),
            EmailPriority::Normal
        );
        assert_eq!(
            EmailPriority::from_severity(AlertSeverity::Critical),
            EmailPriority::Urgent
        );
    }

    #[test]
    fn test_email_priority_ordering() {
        assert!(EmailPriority::Urgent > EmailPriority::High);
        assert!(EmailPriority::High > EmailPriority::Normal);
        assert!(EmailPriority::Normal > EmailPriority::Low);
    }

    #[test]
    fn test_email_priority_as_str() {
        assert_eq!(EmailPriority::Low.as_str(), "low");
        assert_eq!(EmailPriority::Normal.as_str(), "normal");
        assert_eq!(EmailPriority::High.as_str(), "high");
        assert_eq!(EmailPriority::Urgent.as_str(), "urgent");
    }

    #[tokio::test]
    async fn test_failed_email_priority_assignment() {
        let manager = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        // Create alerts with different severities
        let critical_alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Critical,
            title: "Critical Alert".to_string(),
            message: "System failure".to_string(),
            metric_value: 100.0,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        let warning_alert = Alert {
            id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            severity: AlertSeverity::Warning,
            title: "Warning Alert".to_string(),
            message: "High load".to_string(),
            metric_value: 80.0,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        // Queue emails and check priority
        manager
            .queue_failed_email(
                &critical_alert,
                vec!["critical@example.com".to_string()],
                "SMTP error".to_string(),
            )
            .await;

        manager
            .queue_failed_email(
                &warning_alert,
                vec!["warning@example.com".to_string()],
                "SMTP error".to_string(),
            )
            .await;

        let failed_emails = manager.get_failed_emails().await;
        assert_eq!(failed_emails.len(), 2);

        // Find the critical and warning emails
        let critical_email = failed_emails
            .iter()
            .find(|e| e.alert.severity == AlertSeverity::Critical)
            .unwrap();
        let warning_email = failed_emails
            .iter()
            .find(|e| e.alert.severity == AlertSeverity::Warning)
            .unwrap();

        // Verify priority assignment
        assert_eq!(critical_email.priority, EmailPriority::Urgent);
        assert_eq!(warning_email.priority, EmailPriority::Normal);
    }

    #[test]
    fn test_webhook_event_email_delivery_failed() {
        use crate::webhooks::WebhookEvent;

        // Verify that EmailDeliveryFailed variant exists and has correct string representation
        let event = WebhookEvent::EmailDeliveryFailed;
        assert_eq!(event.as_str(), "email_delivery_failed");
    }

    #[tokio::test]
    async fn test_alerting_manager_with_webhook_manager() {
        use crate::webhooks::{WebhookConfig, WebhookManager};

        // Create webhook manager
        let webhook_manager = Arc::new(WebhookManager::new(WebhookConfig::default()));

        // Create alerting manager with webhook manager
        let manager = AlertingManager::new_with_webhook(
            test_db_pool(),
            AlertingConfig::default(),
            Some(webhook_manager.clone()),
        );

        // Verify webhook manager is set
        assert!(manager.webhook_manager.is_some());

        // Create alerting manager without webhook manager
        let manager_no_webhook = AlertingManager::new(test_db_pool(), AlertingConfig::default());

        // Verify webhook manager is not set
        assert!(manager_no_webhook.webhook_manager.is_none());
    }

    #[tokio::test]
    async fn test_email_delivery_result_structure() {
        // Test EmailDeliveryResult with full success
        let success_result = EmailDeliveryResult {
            succeeded: vec![
                "user1@example.com".to_string(),
                "user2@example.com".to_string(),
            ],
            failed: vec![],
            last_error: None,
        };
        assert_eq!(success_result.succeeded.len(), 2);
        assert!(success_result.failed.is_empty());
        assert!(success_result.last_error.is_none());

        // Test EmailDeliveryResult with partial failure
        let partial_result = EmailDeliveryResult {
            succeeded: vec!["user1@example.com".to_string()],
            failed: vec!["user2@example.com".to_string()],
            last_error: Some("SMTP error".to_string()),
        };
        assert_eq!(partial_result.succeeded.len(), 1);
        assert_eq!(partial_result.failed.len(), 1);
        assert!(partial_result.last_error.is_some());

        // Test EmailDeliveryResult with complete failure
        let failure_result = EmailDeliveryResult {
            succeeded: vec![],
            failed: vec![
                "user1@example.com".to_string(),
                "user2@example.com".to_string(),
            ],
            last_error: Some("Connection timeout".to_string()),
        };
        assert!(failure_result.succeeded.is_empty());
        assert_eq!(failure_result.failed.len(), 2);
        assert_eq!(
            failure_result.last_error,
            Some("Connection timeout".to_string())
        );
    }

    #[test]
    fn test_webhook_event_email_delivery_succeeded() {
        let event = WebhookEvent::EmailDeliverySucceeded;
        assert_eq!(event.as_str(), "email_delivery_succeeded");
    }
}
