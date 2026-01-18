//! Webhook notification system for real-time event delivery to external services.
//!
//! This module provides a robust webhook system for notifying external services about
//! important events in the coordinator:
//! - Fraud detection alerts
//! - High error rates
//! - Node failures and suspensions
//! - System health degradation
//! - Critical audit events
//! - Proof verification failures
//! - Email delivery failures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Webhook event types that can trigger notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    /// Fraud alert detected.
    FraudDetected,
    /// High error rate detected.
    HighErrorRate,
    /// Node suspended due to suspicious activity.
    NodeSuspended,
    /// Node failure detected.
    NodeFailed,
    /// System health degraded.
    HealthDegraded,
    /// Critical audit event.
    CriticalAudit,
    /// Proof verification failed.
    ProofVerificationFailed,
    /// User banned.
    UserBanned,
    /// Content flagged.
    ContentFlagged,
    /// System started.
    SystemStarted,
    /// System stopping.
    SystemStopping,
    /// Email delivery failed (after retry attempts).
    EmailDeliveryFailed,
    /// Email delivery succeeded.
    EmailDeliverySucceeded,
}

impl WebhookEvent {
    /// Convert event to string for database storage and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FraudDetected => "fraud_detected",
            Self::HighErrorRate => "high_error_rate",
            Self::NodeSuspended => "node_suspended",
            Self::NodeFailed => "node_failed",
            Self::HealthDegraded => "health_degraded",
            Self::CriticalAudit => "critical_audit",
            Self::ProofVerificationFailed => "proof_verification_failed",
            Self::UserBanned => "user_banned",
            Self::ContentFlagged => "content_flagged",
            Self::SystemStarted => "system_started",
            Self::SystemStopping => "system_stopping",
            Self::EmailDeliveryFailed => "email_delivery_failed",
            Self::EmailDeliverySucceeded => "email_delivery_succeeded",
        }
    }
}

/// Webhook configuration for a single endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Unique identifier for this webhook.
    pub id: Uuid,
    /// Webhook URL to send POST requests to.
    pub url: String,
    /// Optional secret for HMAC signature verification.
    pub secret: Option<String>,
    /// Events this webhook subscribes to.
    pub events: Vec<WebhookEvent>,
    /// Whether this webhook is active.
    pub active: bool,
    /// Custom headers to include in requests.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Timeout for webhook requests (milliseconds).
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Maximum retry attempts on failure.
    #[serde(default = "default_retries")]
    pub max_retries: u32,
    /// When this webhook was created.
    #[serde(default)]
    pub created_at: DateTime<Utc>,
}

fn default_timeout() -> u64 {
    5000
}

fn default_retries() -> u32 {
    3
}

/// Webhook payload sent to endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event ID for idempotency.
    pub id: Uuid,
    /// Event type.
    pub event: WebhookEvent,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Event data (JSON).
    pub data: serde_json::Value,
    /// Optional correlation ID for tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Backoff strategy for webhook retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    /// Linear backoff: wait = base_ms * attempt.
    Linear,
    /// Exponential backoff: wait = base_ms * 2^attempt.
    #[default]
    Exponential,
    /// Fixed delay: wait = base_ms.
    Fixed,
}

/// Webhook delivery result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Delivery ID.
    pub id: Uuid,
    /// Webhook endpoint ID.
    pub webhook_id: Uuid,
    /// Payload that was sent.
    pub payload: WebhookPayload,
    /// HTTP status code received (if any).
    pub status_code: Option<u16>,
    /// Response body (truncated to 1KB).
    pub response_body: Option<String>,
    /// Error message if delivery failed.
    pub error: Option<String>,
    /// Number of retry attempts made.
    pub retry_count: u32,
    /// Whether delivery was successful.
    pub success: bool,
    /// When delivery was attempted.
    pub attempted_at: DateTime<Utc>,
    /// Duration of the request (milliseconds).
    pub duration_ms: u64,
}

/// Configuration for the webhook system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Maximum concurrent webhook deliveries.
    pub max_concurrent: usize,
    /// Default timeout for webhook requests.
    pub default_timeout_ms: u64,
    /// Default retry attempts.
    pub default_max_retries: u32,
    /// Whether to log webhook deliveries.
    pub log_deliveries: bool,
    /// Maximum payload size (bytes).
    pub max_payload_size: usize,
    /// Backoff strategy for retries.
    pub backoff_strategy: BackoffStrategy,
    /// Base delay for backoff calculations (milliseconds).
    pub backoff_base_ms: u64,
    /// Maximum number of delivery history entries to keep per webhook.
    pub max_delivery_history: usize,
    /// How long to keep delivery history (hours).
    pub delivery_history_retention_hours: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            default_timeout_ms: 5000,
            default_max_retries: 3,
            log_deliveries: true,
            max_payload_size: 1024 * 1024, // 1 MB
            backoff_strategy: BackoffStrategy::Exponential,
            backoff_base_ms: 1000,
            max_delivery_history: 1000,
            delivery_history_retention_hours: 72, // 3 days
        }
    }
}

/// Webhook manager for managing endpoints and delivering events.
pub struct WebhookManager {
    /// Configuration.
    config: Arc<RwLock<WebhookConfig>>,
    /// Registered webhook endpoints.
    endpoints: Arc<RwLock<HashMap<Uuid, WebhookEndpoint>>>,
    /// HTTP client for sending requests.
    client: reqwest::Client,
    /// Delivery statistics.
    stats: Arc<RwLock<WebhookStats>>,
    /// Delivery history (webhook_id -> deliveries).
    delivery_history: Arc<RwLock<HashMap<Uuid, Vec<WebhookDelivery>>>>,
}

/// Webhook delivery statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookStats {
    /// Total events triggered.
    pub total_events: u64,
    /// Total deliveries attempted.
    pub total_deliveries: u64,
    /// Total successful deliveries.
    pub total_successes: u64,
    /// Total failed deliveries.
    pub total_failures: u64,
    /// Total retries made.
    pub total_retries: u64,
    /// Average delivery time (milliseconds).
    pub avg_delivery_ms: f64,
    /// Deliveries by event type.
    pub by_event: HashMap<String, u64>,
}

impl WebhookManager {
    /// Create a new webhook manager.
    pub fn new(config: WebhookConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.default_timeout_ms))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config: Arc::new(RwLock::new(config)),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            client,
            stats: Arc::new(RwLock::new(WebhookStats::default())),
            delivery_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new webhook endpoint.
    pub async fn register_webhook(&self, mut webhook: WebhookEndpoint) -> Result<Uuid, String> {
        // Validate URL
        if webhook.url.is_empty() {
            return Err("Webhook URL cannot be empty".to_string());
        }

        if !webhook.url.starts_with("http://") && !webhook.url.starts_with("https://") {
            return Err("Webhook URL must start with http:// or https://".to_string());
        }

        // Validate events
        if webhook.events.is_empty() {
            return Err("Webhook must subscribe to at least one event".to_string());
        }

        // Generate ID if not set
        if webhook.id == Uuid::nil() {
            webhook.id = Uuid::new_v4();
        }

        // Set creation time
        if webhook.created_at == DateTime::<Utc>::MIN_UTC {
            webhook.created_at = Utc::now();
        }

        let id = webhook.id;
        let mut endpoints = self.endpoints.write().await;
        endpoints.insert(id, webhook);

        debug!("Registered webhook endpoint: {}", id);
        Ok(id)
    }

    /// Unregister a webhook endpoint.
    pub async fn unregister_webhook(&self, id: Uuid) -> Result<(), String> {
        let mut endpoints = self.endpoints.write().await;
        endpoints
            .remove(&id)
            .ok_or_else(|| "Webhook not found".to_string())?;

        debug!("Unregistered webhook endpoint: {}", id);
        Ok(())
    }

    /// Update webhook endpoint.
    pub async fn update_webhook(&self, id: Uuid, webhook: WebhookEndpoint) -> Result<(), String> {
        let mut endpoints = self.endpoints.write().await;
        endpoints
            .get_mut(&id)
            .ok_or_else(|| "Webhook not found".to_string())?;

        endpoints.insert(id, webhook);
        debug!("Updated webhook endpoint: {}", id);
        Ok(())
    }

    /// Get webhook endpoint by ID.
    pub async fn get_webhook(&self, id: Uuid) -> Option<WebhookEndpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.get(&id).cloned()
    }

    /// List all webhook endpoints.
    pub async fn list_webhooks(&self) -> Vec<WebhookEndpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.values().cloned().collect()
    }

    /// Trigger a webhook event.
    pub async fn trigger_event(&self, event: WebhookEvent, data: serde_json::Value) {
        self.trigger_event_with_correlation(event, data, None).await;
    }

    /// Trigger a webhook event with correlation ID.
    pub async fn trigger_event_with_correlation(
        &self,
        event: WebhookEvent,
        data: serde_json::Value,
        correlation_id: Option<String>,
    ) {
        let payload = WebhookPayload {
            id: Uuid::new_v4(),
            event: event.clone(),
            timestamp: Utc::now(),
            data,
            correlation_id,
        };

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_events += 1;
            *stats
                .by_event
                .entry(event.as_str().to_string())
                .or_insert(0) += 1;
        }

        // Find matching endpoints
        let endpoints = self.endpoints.read().await;
        let matching: Vec<_> = endpoints
            .values()
            .filter(|w| w.active && w.events.contains(&event))
            .cloned()
            .collect();
        drop(endpoints);

        if matching.is_empty() {
            debug!("No active webhooks for event: {}", event.as_str());
            return;
        }

        debug!(
            "Triggering {} webhooks for event: {}",
            matching.len(),
            event.as_str()
        );

        // Deliver to all matching endpoints concurrently
        let deliveries: Vec<_> = matching
            .into_iter()
            .map(|endpoint| {
                let manager = self.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    manager.deliver_to_endpoint(&endpoint, payload).await;
                })
            })
            .collect();

        // Wait for all deliveries to complete
        for delivery in deliveries {
            let _ = delivery.await;
        }
    }

    /// Deliver payload to a specific endpoint.
    async fn deliver_to_endpoint(&self, endpoint: &WebhookEndpoint, payload: WebhookPayload) {
        let delivery_id = Uuid::new_v4();
        let start = std::time::Instant::now();

        for attempt in 0..=endpoint.max_retries {
            let result = self.send_webhook_request(endpoint, &payload).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let success = result.is_ok();
            let (status_code, response_body, error) = match result {
                Ok((status, body)) => (Some(status), Some(body), None),
                Err(e) => (None, None, Some(e)),
            };

            let delivery = WebhookDelivery {
                id: delivery_id,
                webhook_id: endpoint.id,
                payload: payload.clone(),
                status_code,
                response_body,
                error,
                retry_count: attempt,
                success,
                attempted_at: Utc::now(),
                duration_ms,
            };

            // Store delivery in history
            self.store_delivery(delivery.clone()).await;

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.total_deliveries += 1;
                if success {
                    stats.total_successes += 1;
                } else {
                    stats.total_failures += 1;
                    if attempt > 0 {
                        stats.total_retries += 1;
                    }
                }

                // Update average delivery time
                let total_time = stats.avg_delivery_ms * (stats.total_deliveries - 1) as f64;
                stats.avg_delivery_ms =
                    (total_time + duration_ms as f64) / stats.total_deliveries as f64;
            }

            let config = self.config.read().await;
            if config.log_deliveries {
                if success {
                    debug!(
                        "Webhook delivered successfully: {} (attempt {}/{})",
                        delivery_id,
                        attempt + 1,
                        endpoint.max_retries + 1
                    );
                } else {
                    warn!(
                        "Webhook delivery failed: {} (attempt {}/{}) - {:?}",
                        delivery_id,
                        attempt + 1,
                        endpoint.max_retries + 1,
                        delivery.error
                    );
                }
            }

            // If successful, stop retrying
            if success {
                return;
            }

            // Wait before retry using configured backoff strategy
            if attempt < endpoint.max_retries {
                let wait_ms = self.calculate_backoff_delay(attempt).await;
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            }
        }

        error!(
            "Webhook delivery failed after {} attempts: {}",
            endpoint.max_retries + 1,
            delivery_id
        );
    }

    /// Send HTTP POST request to webhook endpoint.
    async fn send_webhook_request(
        &self,
        endpoint: &WebhookEndpoint,
        payload: &WebhookPayload,
    ) -> Result<(u16, String), String> {
        let body = serde_json::to_string(payload).map_err(|e| e.to_string())?;

        // Check payload size
        let config = self.config.read().await;
        if body.len() > config.max_payload_size {
            return Err(format!(
                "Payload too large: {} bytes (max: {})",
                body.len(),
                config.max_payload_size
            ));
        }
        drop(config);

        let mut request = self
            .client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "CHIE-Coordinator/0.1.0")
            .header("X-Webhook-ID", endpoint.id.to_string())
            .header("X-Event-ID", payload.id.to_string())
            .header("X-Event-Type", payload.event.as_str())
            .timeout(Duration::from_millis(endpoint.timeout_ms))
            .body(body.clone());

        // Add custom headers
        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }

        // Add HMAC signature if secret is configured
        if let Some(secret) = &endpoint.secret {
            let signature = self.generate_signature(&body, secret);
            request = request.header("X-Webhook-Signature", signature);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| String::from("(failed to read response)"));

                // Truncate response body to 1KB
                let truncated_body = if body.len() > 1024 {
                    format!("{}... (truncated)", &body[..1024])
                } else {
                    body
                };

                if (200..300).contains(&status) {
                    Ok((status, truncated_body))
                } else {
                    Err(format!("HTTP {}: {}", status, truncated_body))
                }
            }
            Err(e) => Err(format!("Request failed: {}", e)),
        }
    }

    /// Generate HMAC-SHA256 signature for webhook payload.
    fn generate_signature(&self, payload: &str, secret: &str) -> String {
        use chie_crypto::hash;
        let data = format!("{}{}", secret, payload);
        hex::encode(hash(data.as_bytes()))
    }

    /// Get webhook delivery statistics.
    pub async fn get_stats(&self) -> WebhookStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics.
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = WebhookStats::default();
    }

    /// Calculate backoff delay for retry attempts.
    async fn calculate_backoff_delay(&self, attempt: u32) -> u64 {
        let config = self.config.read().await;
        match config.backoff_strategy {
            BackoffStrategy::Linear => config.backoff_base_ms * (attempt as u64 + 1),
            BackoffStrategy::Exponential => config.backoff_base_ms * 2_u64.pow(attempt),
            BackoffStrategy::Fixed => config.backoff_base_ms,
        }
    }

    /// Store a delivery in history.
    async fn store_delivery(&self, delivery: WebhookDelivery) {
        let mut history = self.delivery_history.write().await;
        let webhook_history = history.entry(delivery.webhook_id).or_default();

        // Add delivery
        webhook_history.push(delivery);

        // Enforce max history size
        let config = self.config.read().await;
        if webhook_history.len() > config.max_delivery_history {
            webhook_history.remove(0);
        }
    }

    /// Get delivery history for a specific webhook.
    pub async fn get_delivery_history(
        &self,
        webhook_id: Uuid,
        limit: Option<usize>,
    ) -> Vec<WebhookDelivery> {
        let history = self.delivery_history.read().await;
        match history.get(&webhook_id) {
            Some(deliveries) => {
                let mut result = deliveries.clone();
                // Sort by attempted_at descending (most recent first)
                result.sort_by(|a, b| b.attempted_at.cmp(&a.attempted_at));

                if let Some(limit) = limit {
                    result.truncate(limit);
                }
                result
            }
            None => Vec::new(),
        }
    }

    /// Get all delivery history across all webhooks.
    pub async fn get_all_delivery_history(&self, limit: Option<usize>) -> Vec<WebhookDelivery> {
        let history = self.delivery_history.read().await;
        let mut all_deliveries: Vec<WebhookDelivery> =
            history.values().flat_map(|v| v.iter()).cloned().collect();

        // Sort by attempted_at descending (most recent first)
        all_deliveries.sort_by(|a, b| b.attempted_at.cmp(&a.attempted_at));

        if let Some(limit) = limit {
            all_deliveries.truncate(limit);
        }
        all_deliveries
    }

    /// Get failed deliveries for retry.
    pub async fn get_failed_deliveries(
        &self,
        webhook_id: Option<Uuid>,
        limit: Option<usize>,
    ) -> Vec<WebhookDelivery> {
        let history = self.delivery_history.read().await;

        let mut failed: Vec<WebhookDelivery> = if let Some(wid) = webhook_id {
            history
                .get(&wid)
                .map(|v| v.iter().filter(|d| !d.success).cloned().collect())
                .unwrap_or_default()
        } else {
            history
                .values()
                .flat_map(|v| v.iter().filter(|d| !d.success))
                .cloned()
                .collect()
        };

        // Sort by attempted_at descending
        failed.sort_by(|a, b| b.attempted_at.cmp(&a.attempted_at));

        if let Some(limit) = limit {
            failed.truncate(limit);
        }
        failed
    }

    /// Manually retry a failed delivery.
    pub async fn manual_retry(&self, delivery_id: Uuid) -> Result<(), String> {
        // Find the original delivery
        let history = self.delivery_history.read().await;
        let mut delivery = None;

        for deliveries in history.values() {
            if let Some(d) = deliveries.iter().find(|d| d.id == delivery_id) {
                delivery = Some(d.clone());
                break;
            }
        }
        drop(history);

        let delivery = delivery.ok_or_else(|| {
            crate::metrics::record_webhook_manual_retry(false);
            "Delivery not found".to_string()
        })?;

        if delivery.success {
            crate::metrics::record_webhook_manual_retry(false);
            return Err("Delivery already succeeded".to_string());
        }

        // Get the webhook endpoint
        let endpoint = self.get_webhook(delivery.webhook_id).await.ok_or_else(|| {
            crate::metrics::record_webhook_manual_retry(false);
            "Webhook not found".to_string()
        })?;

        // Retry the delivery
        debug!("Manually retrying delivery: {}", delivery_id);
        self.deliver_to_endpoint(&endpoint, delivery.payload).await;

        crate::metrics::record_webhook_manual_retry(true);
        Ok(())
    }

    /// Cleanup old delivery history based on retention policy.
    pub async fn cleanup_old_deliveries(&self) -> usize {
        let config = self.config.read().await;
        let retention_hours = config.delivery_history_retention_hours;
        drop(config);

        let cutoff = Utc::now() - chrono::Duration::hours(retention_hours as i64);
        let mut history = self.delivery_history.write().await;
        let mut removed = 0;

        for deliveries in history.values_mut() {
            let before_len = deliveries.len();
            deliveries.retain(|d| d.attempted_at > cutoff);
            removed += before_len - deliveries.len();
        }

        debug!("Cleaned up {} old delivery records", removed);

        if removed > 0 {
            crate::metrics::record_delivery_history_cleanup(removed);
        }

        removed
    }

    /// Update webhook configuration.
    pub async fn update_config(&self, new_config: WebhookConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        debug!("Updated webhook configuration");
    }

    /// Get current configuration.
    pub async fn get_config(&self) -> WebhookConfig {
        self.config.read().await.clone()
    }
}

impl Clone for WebhookManager {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            endpoints: Arc::clone(&self.endpoints),
            client: self.client.clone(),
            stats: Arc::clone(&self.stats),
            delivery_history: Arc::clone(&self.delivery_history),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_event_as_str() {
        assert_eq!(WebhookEvent::FraudDetected.as_str(), "fraud_detected");
        assert_eq!(WebhookEvent::HighErrorRate.as_str(), "high_error_rate");
        assert_eq!(WebhookEvent::NodeSuspended.as_str(), "node_suspended");
        assert_eq!(WebhookEvent::NodeFailed.as_str(), "node_failed");
        assert_eq!(WebhookEvent::HealthDegraded.as_str(), "health_degraded");
        assert_eq!(WebhookEvent::CriticalAudit.as_str(), "critical_audit");
        assert_eq!(
            WebhookEvent::ProofVerificationFailed.as_str(),
            "proof_verification_failed"
        );
        assert_eq!(WebhookEvent::UserBanned.as_str(), "user_banned");
        assert_eq!(WebhookEvent::ContentFlagged.as_str(), "content_flagged");
        assert_eq!(WebhookEvent::SystemStarted.as_str(), "system_started");
        assert_eq!(WebhookEvent::SystemStopping.as_str(), "system_stopping");
    }

    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.max_concurrent, 50);
        assert_eq!(config.default_timeout_ms, 5000);
        assert_eq!(config.default_max_retries, 3);
        assert!(config.log_deliveries);
        assert_eq!(config.max_payload_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_webhook_manager_creation() {
        let manager = WebhookManager::new(WebhookConfig::default());
        let webhooks = manager.list_webhooks().await;
        assert_eq!(webhooks.len(), 0);
    }

    #[tokio::test]
    async fn test_register_webhook() {
        let manager = WebhookManager::new(WebhookConfig::default());

        let webhook = WebhookEndpoint {
            id: Uuid::nil(),
            url: "https://example.com/webhook".to_string(),
            secret: None,
            events: vec![WebhookEvent::FraudDetected],
            active: true,
            headers: HashMap::new(),
            timeout_ms: 5000,
            max_retries: 3,
            created_at: DateTime::<Utc>::MIN_UTC,
        };

        let id = manager.register_webhook(webhook).await.unwrap();
        assert_ne!(id, Uuid::nil());

        let registered = manager.get_webhook(id).await.unwrap();
        assert_eq!(registered.url, "https://example.com/webhook");
    }

    #[tokio::test]
    async fn test_register_webhook_validation() {
        let manager = WebhookManager::new(WebhookConfig::default());

        // Empty URL
        let webhook = WebhookEndpoint {
            id: Uuid::nil(),
            url: String::new(),
            secret: None,
            events: vec![WebhookEvent::FraudDetected],
            active: true,
            headers: HashMap::new(),
            timeout_ms: 5000,
            max_retries: 3,
            created_at: DateTime::<Utc>::MIN_UTC,
        };
        assert!(manager.register_webhook(webhook).await.is_err());

        // Invalid URL scheme
        let webhook = WebhookEndpoint {
            id: Uuid::nil(),
            url: "ftp://example.com/webhook".to_string(),
            secret: None,
            events: vec![WebhookEvent::FraudDetected],
            active: true,
            headers: HashMap::new(),
            timeout_ms: 5000,
            max_retries: 3,
            created_at: DateTime::<Utc>::MIN_UTC,
        };
        assert!(manager.register_webhook(webhook).await.is_err());

        // No events
        let webhook = WebhookEndpoint {
            id: Uuid::nil(),
            url: "https://example.com/webhook".to_string(),
            secret: None,
            events: vec![],
            active: true,
            headers: HashMap::new(),
            timeout_ms: 5000,
            max_retries: 3,
            created_at: DateTime::<Utc>::MIN_UTC,
        };
        assert!(manager.register_webhook(webhook).await.is_err());
    }

    #[tokio::test]
    async fn test_unregister_webhook() {
        let manager = WebhookManager::new(WebhookConfig::default());

        let webhook = WebhookEndpoint {
            id: Uuid::nil(),
            url: "https://example.com/webhook".to_string(),
            secret: None,
            events: vec![WebhookEvent::FraudDetected],
            active: true,
            headers: HashMap::new(),
            timeout_ms: 5000,
            max_retries: 3,
            created_at: DateTime::<Utc>::MIN_UTC,
        };

        let id = manager.register_webhook(webhook).await.unwrap();
        assert!(manager.unregister_webhook(id).await.is_ok());
        assert!(manager.get_webhook(id).await.is_none());
    }

    #[tokio::test]
    async fn test_webhook_stats() {
        let manager = WebhookManager::new(WebhookConfig::default());
        let stats = manager.get_stats().await;

        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.total_deliveries, 0);
        assert_eq!(stats.total_successes, 0);
        assert_eq!(stats.total_failures, 0);
    }
}
