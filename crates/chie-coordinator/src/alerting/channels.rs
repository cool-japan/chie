//! Notification channel implementations: console, email, Slack, webhook.

use lettre::message::{Mailbox, Message, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use super::types::{
    Alert, AlertChannel, AlertSeverity, AlertingManager, EmailDeliveryResult, EmailPriority,
};
use super::utils::current_timestamp;
use crate::webhooks::WebhookEvent;

impl AlertingManager {
    /// Send notifications for an alert to all configured channels.
    pub(super) async fn send_notifications(&self, alert: &Alert, channels: &[AlertChannel]) {
        for channel in channels {
            match channel {
                AlertChannel::Console => {
                    self.send_console_notification(alert);
                }
                AlertChannel::Email { recipients } => {
                    let _result = self.send_email_notification(alert, recipients).await;
                    // Email failures are already tracked and queued for retry
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

    /// Send console (log) notification.
    pub(super) fn send_console_notification(&self, alert: &Alert) {
        match alert.severity {
            AlertSeverity::Info => {
                tracing::info!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
            AlertSeverity::Warning => {
                tracing::warn!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
            AlertSeverity::Critical => {
                tracing::error!(alert_id = %alert.id, "{}: {}", alert.title, alert.message)
            }
        }
    }

    /// Send email notification via SMTP.
    pub(super) async fn send_email_notification(
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

        // Clone SMTP config fields before dropping the config guard
        let smtp_host = smtp_config.host.clone();
        let smtp_port = smtp_config.port;
        let smtp_username = smtp_config.username.clone();
        let smtp_password = smtp_config.password.clone();
        let smtp_use_starttls = smtp_config.use_starttls;
        let bounce_auto_skip = config.email_bounce.auto_skip_bounced;
        let unsubscribe_auto_skip = config.email_unsubscribe.auto_skip_unsubscribed;
        drop(config);

        // Track succeeded and failed recipients for retry
        let mut succeeded_recipients = Vec::new();
        let mut failed_recipients = Vec::new();
        let mut last_error = String::new();

        // Send to each recipient
        for recipient in recipients {
            // Check if email is bounced
            if bounce_auto_skip && self.is_email_bounced(recipient).await {
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
            if unsubscribe_auto_skip && self.is_email_unsubscribed(recipient).await {
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
                    self.track_email_failure(recipient, &last_error).await;
                    continue;
                }
            };

            // Build SMTP transport
            let smtp_transport = if smtp_use_starttls {
                SmtpTransport::starttls_relay(&smtp_host)
            } else {
                SmtpTransport::relay(&smtp_host)
            };

            let smtp_transport = match smtp_transport {
                Ok(transport) => transport
                    .port(smtp_port)
                    .credentials(Credentials::new(
                        smtp_username.clone(),
                        smtp_password.clone(),
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
    pub(super) async fn send_slack_notification(
        &self,
        alert: &Alert,
        webhook_url: &str,
        channel: &str,
    ) {
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
    pub(super) async fn send_webhook_notification(
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
}
