//! Email delivery monitoring, template management, rate limiting, unsubscribes, and SLA admin handlers.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;

/// Assemble email-related routes.
pub fn email_routes() -> Router<AppState> {
    Router::new()
        // Email Delivery Monitoring
        .route("/email/stats", get(get_email_stats))
        .route("/email/queue", get(get_email_retry_queue))
        .route("/email/queue/:id", get(get_email_queue_item))
        .route("/email/queue/:id/remove", post(remove_email_from_queue))
        .route("/email/queue/:id/retry", post(retry_email_now))
        .route("/email/history", get(get_email_history))
        .route("/email/analytics", get(get_email_analytics))
        .route("/email/analytics/success-rate", get(get_email_success_rate))
        // Email Template Management
        .route("/email/templates", get(list_email_templates))
        .route("/email/templates", post(create_email_template))
        .route("/email/templates/:id", get(get_email_template))
        .route("/email/templates/:id", put(update_email_template))
        .route("/email/templates/:id", delete(delete_email_template))
        .route("/email/templates/:id/preview", post(preview_email_template))
        // Email Rate Limiting
        .route("/email/rate-limits", get(list_rate_limits))
        .route("/email/rate-limits", post(create_rate_limit))
        .route("/email/rate-limits/:id", put(update_rate_limit))
        .route("/email/rate-limits/:id", delete(delete_rate_limit))
        // Email Unsubscribe Management
        .route("/email/unsubscribes", get(list_unsubscribes))
        .route("/email/unsubscribes", post(unsubscribe_email))
        .route("/email/unsubscribes/:email", delete(resubscribe_email))
        // Email SLA Monitoring
        .route("/email/sla", get(get_email_sla_metrics))
        .route("/email/sla/reset", post(reset_email_sla_metrics))
}

// ============================================================================
// Email Delivery Monitoring
// ============================================================================

/// Email delivery statistics response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EmailStats {
    /// Total emails in retry queue.
    pub queue_size: usize,
    /// Emails by priority level.
    pub queue_by_priority: std::collections::HashMap<String, usize>,
    /// Average retry attempts in queue.
    pub avg_retry_attempts: f64,
    /// Oldest email in queue (age in seconds).
    pub oldest_email_age_secs: Option<u64>,
    /// Emails expiring soon (within 1 hour).
    pub emails_expiring_soon: usize,
}

/// Failed email queue item response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EmailQueueItem {
    /// Email ID.
    pub id: String,
    /// Alert ID.
    pub alert_id: String,
    /// Alert severity.
    pub alert_severity: String,
    /// Alert title.
    pub alert_title: String,
    /// Recipients.
    pub recipients: Vec<String>,
    /// Retry attempts made.
    pub retry_attempts: u32,
    /// Last error message.
    pub last_error: String,
    /// Email priority.
    pub priority: String,
    /// Failed at timestamp.
    pub failed_at: u64,
    /// Last retry at timestamp.
    pub last_retry_at: u64,
}

/// Get email delivery statistics.
async fn get_email_stats(State(state): State<AppState>) -> impl IntoResponse {
    let failed_emails = state.alerting_manager.get_failed_emails().await;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut queue_by_priority = std::collections::HashMap::new();
    let mut total_retry_attempts = 0u64;
    let mut oldest_age: Option<u64> = None;
    let mut emails_expiring_soon = 0;

    for email in &failed_emails {
        *queue_by_priority
            .entry(email.priority.as_str().to_string())
            .or_insert(0) += 1;

        total_retry_attempts += email.retry_attempts as u64;

        let age = current_time.saturating_sub(email.failed_at);
        oldest_age = Some(oldest_age.map_or(age, |old| old.max(age)));

        // Check if email will expire within 1 hour (3600 seconds)
        let time_until_expiry = (email.failed_at + 24 * 3600).saturating_sub(current_time);
        if time_until_expiry < 3600 {
            emails_expiring_soon += 1;
        }
    }

    let avg_retry_attempts = if !failed_emails.is_empty() {
        total_retry_attempts as f64 / failed_emails.len() as f64
    } else {
        0.0
    };

    let stats = EmailStats {
        queue_size: failed_emails.len(),
        queue_by_priority,
        avg_retry_attempts,
        oldest_email_age_secs: oldest_age,
        emails_expiring_soon,
    };

    Json(stats)
}

/// Get email retry queue.
async fn get_email_retry_queue(State(state): State<AppState>) -> impl IntoResponse {
    let failed_emails = state.alerting_manager.get_failed_emails().await;

    let queue_items: Vec<EmailQueueItem> = failed_emails
        .iter()
        .map(|email| EmailQueueItem {
            id: email.id.to_string(),
            alert_id: email.alert.id.to_string(),
            alert_severity: email.alert.severity.as_str().to_string(),
            alert_title: email.alert.title.clone(),
            recipients: email.recipients.clone(),
            retry_attempts: email.retry_attempts,
            last_error: email.last_error.clone(),
            priority: email.priority.as_str().to_string(),
            failed_at: email.failed_at,
            last_retry_at: email.last_retry_at,
        })
        .collect();

    Json(queue_items)
}

/// Get specific email queue item.
async fn get_email_queue_item(
    State(state): State<AppState>,
    Path(email_id): Path<String>,
) -> impl IntoResponse {
    let email_uuid = match Uuid::parse_str(&email_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid email ID format"
                })),
            )
                .into_response();
        }
    };

    let failed_emails = state.alerting_manager.get_failed_emails().await;

    if let Some(email) = failed_emails.iter().find(|e| e.id == email_uuid) {
        let item = EmailQueueItem {
            id: email.id.to_string(),
            alert_id: email.alert.id.to_string(),
            alert_severity: email.alert.severity.as_str().to_string(),
            alert_title: email.alert.title.clone(),
            recipients: email.recipients.clone(),
            retry_attempts: email.retry_attempts,
            last_error: email.last_error.clone(),
            priority: email.priority.as_str().to_string(),
            failed_at: email.failed_at,
            last_retry_at: email.last_retry_at,
        };
        Json(item).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Email not found in retry queue"
            })),
        )
            .into_response()
    }
}

/// Remove email from retry queue (manual intervention).
async fn remove_email_from_queue(
    State(state): State<AppState>,
    Path(email_id): Path<String>,
) -> impl IntoResponse {
    let email_uuid = match Uuid::parse_str(&email_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid email ID format"
                })),
            )
                .into_response();
        }
    };

    let removed = state.alerting_manager.remove_failed_email(email_uuid).await;

    if removed {
        Json(serde_json::json!({
            "success": true,
            "message": "Email removed from retry queue"
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Email not found in retry queue"
            })),
        )
            .into_response()
    }
}

/// Retry email immediately (bypass retry delay).
async fn retry_email_now(
    State(state): State<AppState>,
    Path(email_id): Path<String>,
) -> impl IntoResponse {
    let email_uuid = match Uuid::parse_str(&email_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid email ID format"
                })),
            )
                .into_response();
        }
    };

    let failed_emails = state.alerting_manager.get_failed_emails().await;

    if let Some(_email) = failed_emails.iter().find(|e| e.id == email_uuid) {
        // Trigger immediate retry by processing retries
        // The retry logic will pick up this email if it meets retry criteria
        state.alerting_manager.process_email_retries().await;

        Json(serde_json::json!({
            "success": true,
            "message": "Email retry initiated"
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Email not found in retry queue"
            })),
        )
            .into_response()
    }
}

/// Email delivery history query parameters.
#[derive(Debug, Deserialize)]
struct EmailHistoryQuery {
    /// Limit number of results.
    limit: Option<i64>,
    /// Offset for pagination.
    offset: Option<i64>,
    /// Filter by status (sent, failed, queued, abandoned).
    status: Option<String>,
    /// Filter by recipient email.
    recipient: Option<String>,
    /// Filter by alert severity.
    severity: Option<String>,
    /// Filter by priority.
    priority: Option<String>,
}

/// Email delivery history item.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailHistoryItem {
    id: String,
    alert_id: String,
    alert_severity: String,
    alert_title: String,
    recipient: String,
    status: String,
    priority: String,
    retry_attempt: i32,
    error_message: Option<String>,
    delivered_at: Option<String>,
    failed_at: Option<String>,
    created_at: String,
}

/// Get email delivery history with filtering and pagination.
async fn get_email_history(
    State(state): State<AppState>,
    Query(params): Query<EmailHistoryQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    // Build query with optional filters
    let mut query = String::from(
        "SELECT id, alert_id, alert_severity, alert_title, recipient, status, priority,
         retry_attempt, error_message, delivered_at, failed_at, created_at
         FROM email_delivery_history WHERE 1=1",
    );

    if params.status.is_some() {
        query.push_str(" AND status = $1");
    }
    if params.recipient.is_some() {
        let status_param = if params.status.is_some() { 2 } else { 1 };
        query.push_str(&format!(" AND recipient = ${}", status_param));
    }
    if params.severity.is_some() {
        let mut param_num = 1;
        if params.status.is_some() {
            param_num += 1;
        }
        if params.recipient.is_some() {
            param_num += 1;
        }
        query.push_str(&format!(" AND alert_severity = ${}", param_num));
    }
    if params.priority.is_some() {
        let mut param_num = 1;
        if params.status.is_some() {
            param_num += 1;
        }
        if params.recipient.is_some() {
            param_num += 1;
        }
        if params.severity.is_some() {
            param_num += 1;
        }
        query.push_str(&format!(" AND priority = ${}", param_num));
    }

    query.push_str(" ORDER BY created_at DESC");

    let mut param_num = 1;
    if params.status.is_some() {
        param_num += 1;
    }
    if params.recipient.is_some() {
        param_num += 1;
    }
    if params.severity.is_some() {
        param_num += 1;
    }
    if params.priority.is_some() {
        param_num += 1;
    }

    query.push_str(&format!(" LIMIT ${} OFFSET ${}", param_num, param_num + 1));

    // Execute query with bound parameters
    let mut sql_query = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            String,
            String,
            String,
            String,
            String,
            i32,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(&query);

    if let Some(status) = &params.status {
        sql_query = sql_query.bind(status);
    }
    if let Some(recipient) = &params.recipient {
        sql_query = sql_query.bind(recipient);
    }
    if let Some(severity) = &params.severity {
        sql_query = sql_query.bind(severity);
    }
    if let Some(priority) = &params.priority {
        sql_query = sql_query.bind(priority);
    }

    sql_query = sql_query.bind(limit).bind(offset);

    match sql_query.fetch_all(&state.db).await {
        Ok(rows) => {
            let history: Vec<EmailHistoryItem> = rows
                .iter()
                .map(|row| EmailHistoryItem {
                    id: row.0.to_string(),
                    alert_id: row.1.to_string(),
                    alert_severity: row.2.clone(),
                    alert_title: row.3.clone(),
                    recipient: row.4.clone(),
                    status: row.5.clone(),
                    priority: row.6.clone(),
                    retry_attempt: row.7,
                    error_message: row.8.clone(),
                    delivered_at: row.9.map(|dt| dt.to_rfc3339()),
                    failed_at: row.10.map(|dt| dt.to_rfc3339()),
                    created_at: row.11.to_rfc3339(),
                })
                .collect();

            Json(serde_json::json!({
                "history": history,
                "count": history.len(),
                "limit": limit,
                "offset": offset
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to fetch email history: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Email analytics response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailAnalytics {
    total_emails: i64,
    successful_deliveries: i64,
    failed_deliveries: i64,
    abandoned_deliveries: i64,
    by_priority: std::collections::HashMap<String, i64>,
    by_severity: std::collections::HashMap<String, i64>,
    avg_retry_attempts: f64,
    top_recipients: Vec<(String, i64)>,
}

/// Get comprehensive email delivery analytics.
async fn get_email_analytics(State(state): State<AppState>) -> impl IntoResponse {
    // Query for total counts by status
    let counts_result = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*) FROM email_delivery_history GROUP BY status",
    )
    .fetch_all(&state.db)
    .await;

    let counts_map: std::collections::HashMap<String, i64> = match counts_result {
        Ok(rows) => rows.into_iter().collect(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to fetch email counts: {}", e)
                })),
            )
                .into_response();
        }
    };

    let successful = counts_map.get("sent").copied().unwrap_or(0);
    let failed = counts_map.get("failed").copied().unwrap_or(0);
    let abandoned = counts_map.get("abandoned").copied().unwrap_or(0);
    let total = successful + failed + abandoned;

    // Query for counts by priority
    let priority_result = sqlx::query_as::<_, (String, i64)>(
        "SELECT priority, COUNT(*) FROM email_delivery_history GROUP BY priority",
    )
    .fetch_all(&state.db)
    .await;

    let by_priority: std::collections::HashMap<String, i64> = match priority_result {
        Ok(rows) => rows.into_iter().collect(),
        Err(_) => std::collections::HashMap::new(),
    };

    // Query for counts by severity
    let severity_result = sqlx::query_as::<_, (String, i64)>(
        "SELECT alert_severity, COUNT(*) FROM email_delivery_history GROUP BY alert_severity",
    )
    .fetch_all(&state.db)
    .await;

    let by_severity: std::collections::HashMap<String, i64> = match severity_result {
        Ok(rows) => rows.into_iter().collect(),
        Err(_) => std::collections::HashMap::new(),
    };

    // Query for average retry attempts
    let avg_retries_result = sqlx::query_as::<_, (Option<f64>,)>(
        "SELECT AVG(retry_attempt) FROM email_delivery_history",
    )
    .fetch_one(&state.db)
    .await;

    let avg_retry_attempts = match avg_retries_result {
        Ok((Some(avg),)) => avg,
        _ => 0.0,
    };

    // Query for top recipients
    let top_recipients_result = sqlx::query_as::<_, (String, i64)>(
        "SELECT recipient, COUNT(*) as cnt
         FROM email_delivery_history
         GROUP BY recipient
         ORDER BY cnt DESC
         LIMIT 10",
    )
    .fetch_all(&state.db)
    .await;

    let top_recipients = top_recipients_result.unwrap_or_default();

    let analytics = EmailAnalytics {
        total_emails: total,
        successful_deliveries: successful,
        failed_deliveries: failed,
        abandoned_deliveries: abandoned,
        by_priority,
        by_severity,
        avg_retry_attempts,
        top_recipients,
    };

    Json(analytics).into_response()
}

/// Email success rate query parameters.
#[derive(Debug, Deserialize)]
struct SuccessRateQuery {
    /// Time period in hours (default 24).
    hours: Option<i64>,
}

/// Email success rate response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailSuccessRate {
    period_hours: i64,
    total_attempts: i64,
    successful: i64,
    failed: i64,
    abandoned: i64,
    success_rate_percent: f64,
    failure_rate_percent: f64,
}

/// Get email delivery success rate for a time period.
async fn get_email_success_rate(
    State(state): State<AppState>,
    Query(params): Query<SuccessRateQuery>,
) -> impl IntoResponse {
    let hours = params.hours.unwrap_or(24);

    let result = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*)
         FROM email_delivery_history
         WHERE created_at >= NOW() - INTERVAL '1 hour' * $1
         GROUP BY status",
    )
    .bind(hours)
    .fetch_all(&state.db)
    .await;

    let counts_map: std::collections::HashMap<String, i64> = match result {
        Ok(rows) => rows.into_iter().collect(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to fetch success rate: {}", e)
                })),
            )
                .into_response();
        }
    };

    let successful = counts_map.get("sent").copied().unwrap_or(0);
    let failed = counts_map.get("failed").copied().unwrap_or(0);
    let abandoned = counts_map.get("abandoned").copied().unwrap_or(0);
    let total = successful + failed + abandoned;

    let success_rate = if total > 0 {
        (successful as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let failure_rate = if total > 0 {
        ((failed + abandoned) as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let success_rate_response = EmailSuccessRate {
        period_hours: hours,
        total_attempts: total,
        successful,
        failed,
        abandoned,
        success_rate_percent: success_rate,
        failure_rate_percent: failure_rate,
    };

    Json(success_rate_response).into_response()
}

// ============================================================================
// Email Template Management
// ============================================================================

/// Email template response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailTemplate {
    id: String,
    name: String,
    description: Option<String>,
    severity: Option<String>,
    subject_template: String,
    html_template: String,
    text_template: String,
    is_active: bool,
    created_at: String,
    updated_at: String,
}

/// Email template create/update request.
#[derive(Debug, Deserialize)]
struct EmailTemplateRequest {
    name: String,
    description: Option<String>,
    severity: Option<String>,
    subject_template: String,
    html_template: String,
    text_template: String,
    is_active: Option<bool>,
}

/// List all email templates.
async fn list_email_templates(State(state): State<AppState>) -> impl IntoResponse {
    let result = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, name, description, severity, subject_template, html_template,
         text_template, is_active, created_at, updated_at
         FROM email_templates
         ORDER BY name",
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            let templates: Vec<EmailTemplate> = rows
                .iter()
                .map(|row| EmailTemplate {
                    id: row.0.to_string(),
                    name: row.1.clone(),
                    description: row.2.clone(),
                    severity: row.3.clone(),
                    subject_template: row.4.clone(),
                    html_template: row.5.clone(),
                    text_template: row.6.clone(),
                    is_active: row.7,
                    created_at: row.8.to_rfc3339(),
                    updated_at: row.9.to_rfc3339(),
                })
                .collect();

            Json(templates).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to fetch templates: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Get specific email template.
async fn get_email_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let template_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid template ID format"
                })),
            )
                .into_response();
        }
    };

    let result = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, name, description, severity, subject_template, html_template,
         text_template, is_active, created_at, updated_at
         FROM email_templates WHERE id = $1",
    )
    .bind(template_id)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(row) => {
            let template = EmailTemplate {
                id: row.0.to_string(),
                name: row.1,
                description: row.2,
                severity: row.3,
                subject_template: row.4,
                html_template: row.5,
                text_template: row.6,
                is_active: row.7,
                created_at: row.8.to_rfc3339(),
                updated_at: row.9.to_rfc3339(),
            };
            Json(template).into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Template not found"
            })),
        )
            .into_response(),
    }
}

/// Create new email template.
async fn create_email_template(
    State(state): State<AppState>,
    Json(req): Json<EmailTemplateRequest>,
) -> impl IntoResponse {
    let template_id = Uuid::new_v4();
    let is_active = req.is_active.unwrap_or(true);

    let result = sqlx::query(
        "INSERT INTO email_templates
         (id, name, description, severity, subject_template, html_template, text_template, is_active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(template_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.severity)
    .bind(&req.subject_template)
    .bind(&req.html_template)
    .bind(&req.text_template)
    .bind(is_active)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Json(serde_json::json!({
            "id": template_id.to_string(),
            "message": "Template created successfully"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create template: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Update email template.
async fn update_email_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EmailTemplateRequest>,
) -> impl IntoResponse {
    let template_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid template ID format"
                })),
            )
                .into_response();
        }
    };

    let is_active = req.is_active.unwrap_or(true);

    let result = sqlx::query(
        "UPDATE email_templates
         SET name = $1, description = $2, severity = $3, subject_template = $4,
             html_template = $5, text_template = $6, is_active = $7
         WHERE id = $8",
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.severity)
    .bind(&req.subject_template)
    .bind(&req.html_template)
    .bind(&req.text_template)
    .bind(is_active)
    .bind(template_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Json(serde_json::json!({
            "message": "Template updated successfully"
        }))
        .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Template not found"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to update template: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Delete email template.
async fn delete_email_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let template_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid template ID format"
                })),
            )
                .into_response();
        }
    };

    let result = sqlx::query("DELETE FROM email_templates WHERE id = $1")
        .bind(template_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Json(serde_json::json!({
            "message": "Template deleted successfully"
        }))
        .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Template not found"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to delete template: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Email template preview request.
#[derive(Debug, Deserialize, ToSchema)]
struct EmailTemplatePreviewRequest {
    variables: HashMap<String, String>,
}

/// Email template preview response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailTemplatePreview {
    subject: String,
    html_body: String,
    text_body: String,
}

/// Helper function to render template variables.
fn render_template(template: &str, variables: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in variables {
        let placeholder = format!("{{{{{}}}}}", key);
        result = result.replace(&placeholder, value);
    }
    result
}

/// Preview email template with sample data.
#[utoipa::path(
    post,
    path = "/admin/email/templates/{id}/preview",
    tag = "admin",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    request_body = EmailTemplatePreviewRequest,
    responses(
        (status = 200, description = "Template preview generated successfully", body = EmailTemplatePreview),
        (status = 400, description = "Invalid template ID"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Server error")
    )
)]
async fn preview_email_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EmailTemplatePreviewRequest>,
) -> impl IntoResponse {
    let template_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid template ID format"
                })),
            )
                .into_response();
        }
    };

    let result = sqlx::query_as::<_, (String, String, String)>(
        "SELECT subject_template, html_template, text_template
         FROM email_templates
         WHERE id = $1 AND is_active = TRUE",
    )
    .bind(template_id)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let subject_template = &row.0;
            let html_template = &row.1;
            let text_template = &row.2;

            let preview = EmailTemplatePreview {
                subject: render_template(subject_template, &req.variables),
                html_body: render_template(html_template, &req.variables),
                text_body: render_template(text_template, &req.variables),
            };

            (StatusCode::OK, Json(preview)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Template not found or inactive"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to fetch template: {}", e)
            })),
        )
            .into_response(),
    }
}

// ============================================================================
// Email Rate Limiting
// ============================================================================

/// Email rate limit response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailRateLimit {
    id: String,
    recipient_pattern: String,
    max_emails_per_hour: i32,
    max_emails_per_day: i32,
    is_active: bool,
    created_at: String,
    updated_at: String,
}

/// Email rate limit request.
#[derive(Debug, Deserialize)]
struct EmailRateLimitRequest {
    recipient_pattern: String,
    max_emails_per_hour: i32,
    max_emails_per_day: i32,
    is_active: Option<bool>,
}

/// List all rate limits.
async fn list_rate_limits(State(state): State<AppState>) -> impl IntoResponse {
    let result = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            i32,
            i32,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, recipient_pattern, max_emails_per_hour, max_emails_per_day,
         is_active, created_at, updated_at
         FROM email_rate_limits
         ORDER BY recipient_pattern",
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            let limits: Vec<EmailRateLimit> = rows
                .iter()
                .map(|row| EmailRateLimit {
                    id: row.0.to_string(),
                    recipient_pattern: row.1.clone(),
                    max_emails_per_hour: row.2,
                    max_emails_per_day: row.3,
                    is_active: row.4,
                    created_at: row.5.to_rfc3339(),
                    updated_at: row.6.to_rfc3339(),
                })
                .collect();

            Json(limits).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to fetch rate limits: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Create new rate limit.
async fn create_rate_limit(
    State(state): State<AppState>,
    Json(req): Json<EmailRateLimitRequest>,
) -> impl IntoResponse {
    let limit_id = Uuid::new_v4();
    let is_active = req.is_active.unwrap_or(true);

    let result = sqlx::query(
        "INSERT INTO email_rate_limits
         (id, recipient_pattern, max_emails_per_hour, max_emails_per_day, is_active)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(limit_id)
    .bind(&req.recipient_pattern)
    .bind(req.max_emails_per_hour)
    .bind(req.max_emails_per_day)
    .bind(is_active)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Json(serde_json::json!({
            "id": limit_id.to_string(),
            "message": "Rate limit created successfully"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create rate limit: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Update rate limit.
async fn update_rate_limit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EmailRateLimitRequest>,
) -> impl IntoResponse {
    let limit_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid rate limit ID format"
                })),
            )
                .into_response();
        }
    };

    let is_active = req.is_active.unwrap_or(true);

    let result = sqlx::query(
        "UPDATE email_rate_limits
         SET recipient_pattern = $1, max_emails_per_hour = $2,
             max_emails_per_day = $3, is_active = $4
         WHERE id = $5",
    )
    .bind(&req.recipient_pattern)
    .bind(req.max_emails_per_hour)
    .bind(req.max_emails_per_day)
    .bind(is_active)
    .bind(limit_id)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Json(serde_json::json!({
            "message": "Rate limit updated successfully"
        }))
        .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Rate limit not found"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to update rate limit: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Delete rate limit.
async fn delete_rate_limit(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let limit_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid rate limit ID format"
                })),
            )
                .into_response();
        }
    };

    let result = sqlx::query("DELETE FROM email_rate_limits WHERE id = $1")
        .bind(limit_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Json(serde_json::json!({
            "message": "Rate limit deleted successfully"
        }))
        .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Rate limit not found"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to delete rate limit: {}", e)
            })),
        )
            .into_response(),
    }
}

// ============================================================================
// Email Unsubscribe Management
// ============================================================================

/// Email unsubscribe response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct EmailUnsubscribeResponse {
    email: String,
    unsubscribed_at: String,
    reason: Option<String>,
    source: String,
}

/// Email unsubscribe request.
#[derive(Debug, Deserialize, ToSchema)]
struct EmailUnsubscribeRequest {
    email: String,
    reason: Option<String>,
}

/// List all unsubscribed emails.
#[utoipa::path(
    get,
    path = "/admin/email/unsubscribes",
    tag = "admin",
    responses(
        (status = 200, description = "List of unsubscribed emails", body = Vec<EmailUnsubscribeResponse>),
        (status = 500, description = "Server error")
    )
)]
async fn list_unsubscribes(State(state): State<AppState>) -> impl IntoResponse {
    let unsubscribes = state.alerting_manager.get_unsubscribed_emails().await;

    let response: Vec<EmailUnsubscribeResponse> = unsubscribes
        .iter()
        .map(|unsub| EmailUnsubscribeResponse {
            email: unsub.email.clone(),
            unsubscribed_at: chrono::DateTime::from_timestamp(unsub.unsubscribed_at as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "Unknown".to_string()),
            reason: unsub.reason.clone(),
            source: unsub.source.as_str().to_string(),
        })
        .collect();

    (StatusCode::OK, Json(response)).into_response()
}

/// Unsubscribe an email address.
#[utoipa::path(
    post,
    path = "/admin/email/unsubscribes",
    tag = "admin",
    request_body = EmailUnsubscribeRequest,
    responses(
        (status = 200, description = "Email unsubscribed successfully"),
        (status = 500, description = "Server error")
    )
)]
async fn unsubscribe_email(
    State(state): State<AppState>,
    Json(req): Json<EmailUnsubscribeRequest>,
) -> impl IntoResponse {
    state
        .alerting_manager
        .unsubscribe_email(
            &req.email,
            req.reason,
            crate::alerting::UnsubscribeSource::Admin,
        )
        .await;

    Json(serde_json::json!({
        "message": "Email unsubscribed successfully",
        "email": req.email
    }))
    .into_response()
}

/// Resubscribe an email address (remove from unsubscribe list).
#[utoipa::path(
    delete,
    path = "/admin/email/unsubscribes/{email}",
    tag = "admin",
    params(
        ("email" = String, Path, description = "Email address to resubscribe")
    ),
    responses(
        (status = 200, description = "Email resubscribed successfully"),
        (status = 404, description = "Email not in unsubscribe list"),
        (status = 500, description = "Server error")
    )
)]
async fn resubscribe_email(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    let removed = state.alerting_manager.resubscribe_email(&email).await;

    if removed {
        Json(serde_json::json!({
            "message": "Email resubscribed successfully",
            "email": email
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Email not in unsubscribe list"
            })),
        )
            .into_response()
    }
}

// ============================================================================
// Email SLA Monitoring
// ============================================================================

/// Get email delivery SLA metrics.
async fn get_email_sla_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.alerting_manager.get_sla_metrics().await;
    (StatusCode::OK, Json(metrics)).into_response()
}

/// Reset email delivery SLA metrics.
async fn reset_email_sla_metrics(State(state): State<AppState>) -> impl IntoResponse {
    state.alerting_manager.reset_sla_metrics().await;
    Json(serde_json::json!({
        "message": "SLA metrics reset successfully"
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use crate::admin::system::{HealthStatus, SystemStats};

    #[test]
    fn test_system_stats_serialization() {
        let stats = SystemStats {
            total_users: 100,
            active_users_24h: 50,
            total_nodes: 200,
            active_nodes: 150,
            total_content: 1000,
            total_storage_bytes: 1024 * 1024 * 1024,
            proofs_today: 5000,
            rewards_today: 50000,
            fraud_alerts_today: 5,
        };

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("total_users"));
    }

    #[test]
    fn test_health_status_serialization() {
        let health = HealthStatus {
            status: "healthy".to_string(),
            uptime_secs: 3600,
            version: "0.1.0".to_string(),
            components: vec![],
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("healthy"));
    }
}
