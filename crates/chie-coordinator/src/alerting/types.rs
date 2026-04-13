//! Type definitions for the alerting system.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::webhooks::WebhookManager;

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
    /// Unsubscribe link base URL (e.g., "<https://chie.example.com/unsubscribe>").
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
pub(super) struct AlertRuleState {
    /// Rule configuration.
    pub(super) rule: AlertRule,
    /// Last alert time.
    pub(super) last_alert_time: Option<u64>,
    /// Condition met since timestamp.
    pub(super) condition_met_since: Option<u64>,
}

/// Email delivery result (internal).
#[derive(Debug, Clone)]
pub(super) struct EmailDeliveryResult {
    /// Recipients that succeeded.
    pub(super) succeeded: Vec<String>,
    /// Recipients that failed.
    pub(super) failed: Vec<String>,
    /// Last error message (if any).
    pub(super) last_error: Option<String>,
}

/// Alerting manager — owns all runtime state.
pub struct AlertingManager {
    /// Database connection pool.
    pub(super) db: PgPool,
    /// Configuration.
    pub(super) config: Arc<RwLock<AlertingConfig>>,
    /// Alert rules.
    pub(super) rules: Arc<RwLock<HashMap<Uuid, AlertRuleState>>>,
    /// Active alerts.
    pub(super) alerts: Arc<RwLock<HashMap<Uuid, Alert>>>,
    /// Alert history.
    pub(super) history: Arc<RwLock<Vec<Alert>>>,
    /// Failed email retry queue.
    pub(super) failed_emails: Arc<RwLock<Vec<FailedEmail>>>,
    /// Email bounce tracking map (email -> bounce info).
    pub(super) email_bounces: Arc<RwLock<HashMap<String, EmailBounce>>>,
    /// Email unsubscribe list (email -> unsubscribe info).
    pub(super) email_unsubscribes: Arc<RwLock<HashMap<String, EmailUnsubscribe>>>,
    /// Email delivery SLA metrics.
    pub(super) email_sla_metrics: Arc<RwLock<EmailSlaMetrics>>,
    /// HTTP client for webhooks.
    pub(super) http_client: reqwest::Client,
    /// Webhook manager for sending event notifications (optional).
    pub(super) webhook_manager: Option<Arc<WebhookManager>>,
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
}
