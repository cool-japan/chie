//! Email retry queue, bounce tracking, unsubscribe management, and SLA monitoring.

use tracing::{debug, info, warn};
use uuid::Uuid;

use super::types::{
    Alert, AlertingManager, EmailBounce, EmailPriority, EmailRetryConfig, EmailSlaMetrics,
    EmailUnsubscribe, FailedEmail, UnsubscribeSource,
};
use super::utils::current_timestamp;
use crate::webhooks::WebhookEvent;

// ============================================================================
// Email Retry Queue
// ============================================================================

impl AlertingManager {
    /// Queue a failed email for retry.
    pub(super) async fn queue_failed_email(
        &self,
        alert: &Alert,
        recipients: Vec<String>,
        error: String,
    ) {
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
    pub(super) fn calculate_retry_delay(
        &self,
        retry_attempts: u32,
        config: &EmailRetryConfig,
    ) -> u64 {
        let base_delay = config.initial_retry_delay_seconds;
        let exponential_delay = base_delay * 2_u64.pow(retry_attempts);
        exponential_delay.min(config.max_retry_delay_seconds)
    }

    /// Check if email should be retried.
    pub(super) fn should_retry_email(
        &self,
        failed_email: &FailedEmail,
        config: &EmailRetryConfig,
    ) -> bool {
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

    /// Remove a failed email from retry queue.
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
}

// ============================================================================
// Database persistence for email retry queue
// ============================================================================

impl AlertingManager {
    /// Save a failed email to database for persistence.
    pub(super) async fn save_failed_email_to_db(
        &self,
        failed_email: &FailedEmail,
    ) -> Result<(), sqlx::Error> {
        let alert_severity = match failed_email.alert.severity {
            super::types::AlertSeverity::Info => "Info",
            super::types::AlertSeverity::Warning => "Warning",
            super::types::AlertSeverity::Critical => "Critical",
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
                "Info" => super::types::AlertSeverity::Info,
                "Warning" => super::types::AlertSeverity::Warning,
                "Critical" => super::types::AlertSeverity::Critical,
                _ => super::types::AlertSeverity::Warning,
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
                status: super::types::AlertStatus::Active,
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
    pub(super) async fn delete_failed_email_from_db(
        &self,
        email_id: Uuid,
    ) -> Result<(), sqlx::Error> {
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
    pub(super) async fn record_delivery_success(
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
    pub(super) async fn record_delivery_failure(
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
    pub(super) async fn record_delivery_abandoned(
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
    pub(super) fn calculate_retry_delay_static(
        retry_attempts: u32,
        config: &EmailRetryConfig,
    ) -> u64 {
        let delay = config.initial_retry_delay_seconds * 2u64.pow(retry_attempts);
        delay.min(config.max_retry_delay_seconds)
    }

    /// Helper: Check if email should be retried (static version for DB operations).
    pub(super) fn should_retry_email_static(
        failed_email: &FailedEmail,
        config: &EmailRetryConfig,
    ) -> bool {
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
}

// ============================================================================
// Bounce tracking
// ============================================================================

impl AlertingManager {
    /// Track an email delivery failure for bounce management.
    pub async fn track_email_failure(&self, email: &str, error: &str) {
        let now = current_timestamp();
        let config = self.config.read().await;
        let bounce_config = config.email_bounce.clone();
        drop(config);

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
        let bounce_window = config.email_bounce.failure_tracking_window_seconds;
        drop(config);

        let now = current_timestamp();
        let cutoff = now.saturating_sub(bounce_window);

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
}

// ============================================================================
// Unsubscribe management
// ============================================================================

impl AlertingManager {
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
}

// ============================================================================
// SLA monitoring
// ============================================================================

impl AlertingManager {
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
