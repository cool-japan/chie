//! Webhook management and email delivery statistics endpoints.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Request to register a new webhook.
#[derive(Debug, Deserialize)]
pub(super) struct RegisterWebhookRequest {
    url: String,
    secret: Option<String>,
    events: Vec<crate::webhooks::WebhookEvent>,
    headers: Option<std::collections::HashMap<String, String>>,
    timeout_ms: Option<u64>,
    max_retries: Option<u32>,
}

/// Response for webhook registration.
#[derive(Debug, Serialize)]
pub(super) struct WebhookResponse {
    id: uuid::Uuid,
    webhook: crate::webhooks::WebhookEndpoint,
}

/// Query parameters for delivery history.
#[derive(Debug, Deserialize)]
pub(super) struct DeliveryHistoryQuery {
    limit: Option<usize>,
    failed_only: Option<bool>,
}

/// Email delivery statistics response.
#[derive(Debug, Serialize)]
pub(super) struct EmailStatsResponse {
    total_sent: u64,
    total_failed: u64,
    total_bounced: u64,
    total_unsubscribed: u64,
    retry_queue_size: usize,
    success_rate: f64,
}

/// Register a new webhook endpoint.
pub(super) async fn register_webhook_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<Json<WebhookResponse>, (StatusCode, String)> {
    // Validate URL
    if req.url.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "URL cannot be empty".to_string()));
    }

    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Err((
            StatusCode::BAD_REQUEST,
            "URL must start with http:// or https://".to_string(),
        ));
    }

    if req.events.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "At least one event must be subscribed".to_string(),
        ));
    }

    let webhook = crate::webhooks::WebhookEndpoint {
        id: uuid::Uuid::new_v4(),
        url: req.url,
        secret: req.secret,
        events: req.events,
        active: true,
        headers: req.headers.unwrap_or_default(),
        timeout_ms: req.timeout_ms.unwrap_or(5000),
        max_retries: req.max_retries.unwrap_or(3),
        created_at: chrono::Utc::now(),
    };

    match state
        .webhook_manager
        .register_webhook(webhook.clone())
        .await
    {
        Ok(id) => Ok(Json(WebhookResponse { id, webhook })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

/// List all registered webhooks.
pub(super) async fn list_webhooks_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::webhooks::WebhookEndpoint>> {
    let webhooks = state.webhook_manager.list_webhooks().await;
    Json(webhooks)
}

/// Get a specific webhook by ID.
pub(super) async fn get_webhook_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::webhooks::WebhookEndpoint>, StatusCode> {
    match state.webhook_manager.get_webhook(id).await {
        Some(webhook) => Ok(Json(webhook)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Update an existing webhook.
pub(super) async fn update_webhook_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Json(webhook): Json<crate::webhooks::WebhookEndpoint>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.webhook_manager.update_webhook(id, webhook).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((StatusCode::NOT_FOUND, e)),
    }
}

/// Delete a webhook.
pub(super) async fn delete_webhook_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.webhook_manager.unregister_webhook(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((StatusCode::NOT_FOUND, e)),
    }
}

/// Get delivery history for a specific webhook.
pub(super) async fn get_webhook_deliveries_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Query(query): Query<DeliveryHistoryQuery>,
) -> Json<Vec<crate::webhooks::WebhookDelivery>> {
    if query.failed_only.unwrap_or(false) {
        let deliveries = state
            .webhook_manager
            .get_failed_deliveries(Some(id), query.limit)
            .await;
        Json(deliveries)
    } else {
        let deliveries = state
            .webhook_manager
            .get_delivery_history(id, query.limit)
            .await;
        Json(deliveries)
    }
}

/// Manually retry a failed webhook delivery.
pub(super) async fn retry_webhook_delivery_handler(
    State(state): State<AppState>,
    Path((id, delivery_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify webhook exists
    if state.webhook_manager.get_webhook(id).await.is_none() {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    match state.webhook_manager.manual_retry(delivery_id).await {
        Ok(()) => Ok(StatusCode::ACCEPTED),
        Err(e) => Err((StatusCode::NOT_FOUND, e)),
    }
}

/// Get webhook system statistics.
pub(super) async fn get_webhook_stats_handler(
    State(state): State<AppState>,
) -> Json<crate::webhooks::WebhookStats> {
    let stats = state.webhook_manager.get_stats().await;
    Json(stats)
}

/// Get webhook system configuration.
pub(super) async fn get_webhook_config_handler(
    State(state): State<AppState>,
) -> Json<crate::webhooks::WebhookConfig> {
    let config = state.webhook_manager.get_config().await;
    Json(config)
}

/// Update webhook system configuration.
pub(super) async fn update_webhook_config_handler(
    State(state): State<AppState>,
    Json(config): Json<crate::webhooks::WebhookConfig>,
) -> StatusCode {
    state.webhook_manager.update_config(config).await;
    StatusCode::NO_CONTENT
}

// ==================== Email Delivery Statistics Endpoints ====================

/// Get email delivery statistics.
pub(super) async fn get_email_stats_handler(
    State(state): State<AppState>,
) -> Json<EmailStatsResponse> {
    let alerting_manager = &state.alerting_manager;

    // Get email statistics from alert system
    let failed_emails = alerting_manager.get_failed_emails().await;
    let bounced_emails = alerting_manager.get_all_bounces().await;
    let unsubscribed_emails = alerting_manager.get_unsubscribed_emails().await;
    let sla_metrics = alerting_manager.get_sla_metrics().await;

    let total_sent = sla_metrics.total_sent;
    let total_failed = failed_emails.len() as u64;
    let total_bounced = bounced_emails.len() as u64;
    let total_unsubscribed = unsubscribed_emails.len() as u64;
    let retry_queue_size = failed_emails.len();

    let success_rate = if total_sent > 0 {
        ((total_sent - total_failed) as f64 / total_sent as f64) * 100.0
    } else {
        100.0
    };

    Json(EmailStatsResponse {
        total_sent,
        total_failed,
        total_bounced,
        total_unsubscribed,
        retry_queue_size,
        success_rate,
    })
}

/// Get failed emails in retry queue.
pub(super) async fn get_failed_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::FailedEmail>> {
    let failed_emails = state.alerting_manager.get_failed_emails().await;
    Json(failed_emails)
}

/// Get bounced email addresses.
pub(super) async fn get_bounced_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::EmailBounce>> {
    let bounced = state.alerting_manager.get_all_bounces().await;
    Json(bounced)
}

/// Get unsubscribed email addresses.
pub(super) async fn get_unsubscribed_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::EmailUnsubscribe>> {
    let unsubscribed = state.alerting_manager.get_unsubscribed_emails().await;
    Json(unsubscribed)
}

/// Get email SLA metrics.
pub(super) async fn get_email_sla_handler(
    State(state): State<AppState>,
) -> Json<crate::alerting::EmailSlaMetrics> {
    let sla_metrics = state.alerting_manager.get_sla_metrics().await;
    Json(sla_metrics)
}

/// Remove a failed email from retry queue.
pub(super) async fn remove_failed_email_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, StatusCode> {
    if state.alerting_manager.remove_failed_email(id).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Remove an email from bounce list.
pub(super) async fn remove_bounce_handler(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if state.alerting_manager.remove_bounce(&email).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Resubscribe an email address.
pub(super) async fn resubscribe_handler(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if state.alerting_manager.resubscribe_email(&email).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
