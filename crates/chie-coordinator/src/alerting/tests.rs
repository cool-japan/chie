//! Tests for the alerting system.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::PgPool;
use uuid::Uuid;

use crate::alerting::types::EmailDeliveryResult as InternalEmailDeliveryResult;
use crate::alerting::utils::current_timestamp;
use crate::alerting::{
    Alert, AlertChannel, AlertCondition, AlertRule, AlertSeverity, AlertStatus, AlertingConfig,
    AlertingManager, ComparisonOperator, EmailBounceConfig, EmailPriority, EmailRetryConfig,
    EmailSlaConfig, EmailUnsubscribeConfig, FailedEmail, SmtpConfig,
};

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
            .unwrap_or_default()
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
            .unwrap_or_default()
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
    let success_result = InternalEmailDeliveryResult {
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
    let partial_result = InternalEmailDeliveryResult {
        succeeded: vec!["user1@example.com".to_string()],
        failed: vec!["user2@example.com".to_string()],
        last_error: Some("SMTP error".to_string()),
    };
    assert_eq!(partial_result.succeeded.len(), 1);
    assert_eq!(partial_result.failed.len(), 1);
    assert!(partial_result.last_error.is_some());

    // Test EmailDeliveryResult with complete failure
    let failure_result = InternalEmailDeliveryResult {
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
    use crate::webhooks::WebhookEvent;
    let event = WebhookEvent::EmailDeliverySucceeded;
    assert_eq!(event.as_str(), "email_delivery_succeeded");
}
