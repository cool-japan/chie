//! Content moderation, node reputation, alerting management, and feature flags admin handlers.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;

/// Assemble moderation-related routes.
pub fn moderation_routes() -> Router<AppState> {
    Router::new()
        // Content Moderation
        .route("/moderation/queue", get(get_moderation_queue))
        .route("/moderation/flags/:flag_id", get(get_flag_details))
        .route(
            "/moderation/flags/:flag_id/action",
            post(take_moderation_action),
        )
        .route(
            "/moderation/content/:content_id/flag",
            post(flag_content_manual),
        )
        .route(
            "/moderation/content/:content_id/flags",
            get(get_content_flags),
        )
        .route("/moderation/stats", get(get_moderation_stats))
        .route("/moderation/rules", get(get_moderation_rules))
        .route(
            "/moderation/rules/:rule_id/toggle",
            post(toggle_moderation_rule),
        )
        // Node Reputation
        .route("/reputation/node/:peer_id", get(get_node_reputation))
        .route("/reputation/top", get(get_top_nodes))
        .route("/reputation/stats", get(get_reputation_stats))
        .route("/reputation/decay", post(apply_reputation_decay))
        // Alerting
        .route("/alerts/rules", get(list_alert_rules))
        .route("/alerts/rules", post(create_alert_rule))
        .route("/alerts/rules/:id", get(get_alert_rule))
        .route("/alerts/rules/:id", put(update_alert_rule))
        .route("/alerts/rules/:id", delete(delete_alert_rule))
        .route("/alerts/rules/:id/toggle", post(toggle_alert_rule))
        .route("/alerts", get(list_alerts))
        .route("/alerts/active", get(list_active_alerts))
        .route("/alerts/:id", get(get_alert))
        .route("/alerts/:id/acknowledge", post(acknowledge_alert))
        .route("/alerts/:id/resolve", post(resolve_alert))
        .route("/alerts/stats", get(get_alert_stats))
        .route("/alerts/email-retries", get(get_email_retries))
        .route("/alerts/email-retries/process", post(process_email_retries))
        .route("/alerts/email-retries/:id", delete(remove_email_retry))
        // Feature Flags
        .route("/flags", get(list_feature_flags))
        .route("/flags", post(create_feature_flag))
        .route("/flags/:id", get(get_feature_flag))
        .route("/flags/:id", put(update_feature_flag))
        .route("/flags/:id", delete(delete_feature_flag))
        .route("/flags/:id/enable", post(enable_feature_flag))
        .route("/flags/:id/disable", post(disable_feature_flag))
        .route("/flags/evaluate", post(evaluate_feature_flag))
        .route("/flags/stats", get(get_feature_flags_stats))
}

// ============================================================================
// Content Moderation
// ============================================================================

/// Query parameters for moderation queue.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ModerationQueueQuery {
    /// Maximum number of flags to return.
    #[serde(default = "default_queue_limit")]
    pub limit: i64,
}

fn default_queue_limit() -> i64 {
    50
}

/// Request to take moderation action.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ModerationActionRequest {
    /// Action to take.
    pub action: String,
    /// Moderator notes.
    pub notes: Option<String>,
}

/// Request to toggle rule.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ToggleRuleRequest {
    /// Enable or disable rule.
    pub enabled: bool,
}

/// Get moderation queue (pending flags).
async fn get_moderation_queue(
    State(state): State<AppState>,
    Query(query): Query<ModerationQueueQuery>,
) -> impl IntoResponse {
    match state
        .moderation_manager
        .get_pending_flags(query.limit)
        .await
    {
        Ok(flags) => (StatusCode::OK, Json(flags)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get moderation queue: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get moderation queue",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get flag details by ID.
async fn get_flag_details(
    State(state): State<AppState>,
    Path(flag_id): Path<Uuid>,
) -> impl IntoResponse {
    #[derive(sqlx::FromRow, serde::Serialize)]
    struct FlagRow {
        id: Uuid,
        content_id: String,
        reason: String,
        description: Option<String>,
        reporter_id: Option<Uuid>,
        status: String,
        action: Option<String>,
        moderator_id: Option<Uuid>,
        severity: i32,
        created_at: chrono::NaiveDateTime,
        resolved_at: Option<chrono::NaiveDateTime>,
        metadata: Option<serde_json::Value>,
    }

    // Query database for the specific flag
    match sqlx::query_as::<_, FlagRow>(
        r#"
        SELECT id, content_id, reason, description, reporter_id,
               status, action, moderator_id, severity,
               created_at, resolved_at, metadata
        FROM content_flags
        WHERE id = $1
        "#,
    )
    .bind(flag_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(flag)) => (StatusCode::OK, Json(flag)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Flag not found",
                "flag_id": flag_id
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to get flag details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get flag details",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Take moderation action on a flag.
async fn take_moderation_action(
    State(state): State<AppState>,
    Path(flag_id): Path<Uuid>,
    Json(req): Json<ModerationActionRequest>,
) -> impl IntoResponse {
    use crate::ModerationAction;

    let action =
        match req.action.as_str() {
            "approved" => ModerationAction::Approved,
            "rejected" => ModerationAction::Rejected,
            "quarantined" => ModerationAction::Quarantined,
            "banned" => ModerationAction::Banned,
            "dismissed" => ModerationAction::Dismissed,
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid action",
                    "valid_actions": ["approved", "rejected", "quarantined", "banned", "dismissed"]
                })),
            )
                .into_response(),
        };

    match state
        .moderation_manager
        .take_action(flag_id, action.clone(), None, req.notes.clone())
        .await
    {
        Ok(()) => {
            // Log audit event
            state
                .audit_logger
                .log_event(
                    crate::AuditSeverity::Info,
                    crate::AuditCategory::Admin,
                    "moderation_action_taken",
                )
                .await
                .details(
                    serde_json::to_string(&serde_json::json!({
                        "flag_id": flag_id,
                        "action": req.action,
                        "notes": req.notes
                    }))
                    .unwrap_or_default(),
                )
                .submit()
                .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": "Moderation action taken successfully"
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to take moderation action: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to take moderation action",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Manually flag content.
async fn flag_content_manual(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
    Json(req): Json<crate::admin::system::FlagContentRequest>,
) -> impl IntoResponse {
    use crate::FlagReason;

    let reason = match req.reason.as_str() {
        "policy_violation" => FlagReason::PolicyViolation,
        "suspicious_hash" => FlagReason::SuspiciousHash,
        "excessive_size" => FlagReason::ExcessiveSize,
        "user_reported" => FlagReason::UserReported,
        "malware_detected" => FlagReason::MalwareDetected,
        "dmca_takedown" => FlagReason::DmcaTakedown,
        "spam" => FlagReason::Spam,
        "manual_flag" => FlagReason::ManualFlag,
        "automated_rule" => FlagReason::AutomatedRule,
        "other" => FlagReason::Other,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid reason",
                    "valid_reasons": [
                        "policy_violation", "suspicious_hash", "excessive_size",
                        "user_reported", "malware_detected", "dmca_takedown",
                        "spam", "manual_flag", "automated_rule", "other"
                    ]
                })),
            )
                .into_response();
        }
    };

    match state
        .moderation_manager
        .flag_content(content_id.clone(), reason, req.details, None, req.severity)
        .await
    {
        Ok(flag_id) => {
            // Log audit event
            state
                .audit_logger
                .log_event(
                    crate::AuditSeverity::Warning,
                    crate::AuditCategory::Content,
                    "content_flagged",
                )
                .await
                .details(
                    serde_json::to_string(&serde_json::json!({
                        "content_id": content_id,
                        "flag_id": flag_id,
                        "reason": req.reason,
                        "severity": req.severity
                    }))
                    .unwrap_or_default(),
                )
                .submit()
                .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "flag_id": flag_id,
                    "message": "Content flagged successfully"
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to flag content: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to flag content",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get all flags for specific content.
async fn get_content_flags(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
) -> impl IntoResponse {
    match state
        .moderation_manager
        .get_flags_by_content(&content_id)
        .await
    {
        Ok(flags) => (StatusCode::OK, Json(flags)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get content flags: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get content flags",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get moderation statistics.
async fn get_moderation_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.moderation_manager.get_stats().await;
    (StatusCode::OK, Json(stats)).into_response()
}

/// Get moderation rules.
async fn get_moderation_rules(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.moderation_manager.get_rules().await;
    (StatusCode::OK, Json(rules)).into_response()
}

/// Toggle moderation rule enabled status.
async fn toggle_moderation_rule(
    State(state): State<AppState>,
    Path(rule_id): Path<String>,
    Json(req): Json<ToggleRuleRequest>,
) -> impl IntoResponse {
    match state
        .moderation_manager
        .set_rule_enabled(&rule_id, req.enabled)
        .await
    {
        Ok(()) => {
            // Log audit event
            state
                .audit_logger
                .log_event(
                    crate::AuditSeverity::Info,
                    crate::AuditCategory::Config,
                    "moderation_rule_toggled",
                )
                .await
                .details(
                    serde_json::to_string(&serde_json::json!({
                        "rule_id": rule_id,
                        "enabled": req.enabled
                    }))
                    .unwrap_or_default(),
                )
                .submit()
                .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "message": format!("Rule {} successfully", if req.enabled { "enabled" } else { "disabled" })
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to toggle rule: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to toggle rule",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Node Reputation
// ============================================================================

/// Query parameters for top nodes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TopNodesQuery {
    /// Maximum number of nodes to return.
    #[serde(default = "default_top_limit")]
    pub limit: usize,
    /// Minimum trust level.
    #[serde(default)]
    pub min_trust: Option<String>,
}

fn default_top_limit() -> usize {
    20
}

/// Get reputation for a specific node.
async fn get_node_reputation(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    match state.reputation_manager.get_reputation(&peer_id).await {
        Ok(Some(reputation)) => (StatusCode::OK, Json(reputation)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Node not found",
                "peer_id": peer_id
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to get node reputation: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get node reputation",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get top nodes by reputation.
async fn get_top_nodes(
    State(state): State<AppState>,
    Query(query): Query<TopNodesQuery>,
) -> impl IntoResponse {
    let min_trust = if let Some(trust_str) = query.min_trust {
        match trust_str.as_str() {
            "untrusted" => crate::TrustLevel::Untrusted,
            "low" => crate::TrustLevel::Low,
            "medium" => crate::TrustLevel::Medium,
            "high" => crate::TrustLevel::High,
            "excellent" => crate::TrustLevel::Excellent,
            _ => crate::TrustLevel::Medium, // Default
        }
    } else {
        crate::TrustLevel::Medium
    };

    match state
        .reputation_manager
        .get_top_nodes(query.limit, min_trust)
        .await
    {
        Ok(nodes) => (StatusCode::OK, Json(nodes)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get top nodes: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get top nodes",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get reputation statistics.
async fn get_reputation_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.reputation_manager.get_stats().await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get reputation stats: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get reputation stats",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Manually apply reputation decay.
async fn apply_reputation_decay(State(state): State<AppState>) -> impl IntoResponse {
    match state.reputation_manager.apply_decay().await {
        Ok(affected) => {
            // Log audit event
            state
                .audit_logger
                .log_event(
                    crate::AuditSeverity::Info,
                    crate::AuditCategory::Admin,
                    "reputation_decay_applied",
                )
                .await
                .details(
                    serde_json::to_string(&serde_json::json!({
                        "affected_nodes": affected
                    }))
                    .unwrap_or_default(),
                )
                .submit()
                .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "affected_nodes": affected,
                    "message": format!("Applied reputation decay to {} nodes", affected)
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to apply reputation decay: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to apply reputation decay",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Alerting Management
// ============================================================================

/// GET /admin/alerts/rules - List all alert rules.
async fn list_alert_rules(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.alerting_manager.get_rules().await;
    (StatusCode::OK, Json(rules)).into_response()
}

/// POST /admin/alerts/rules - Create a new alert rule.
async fn create_alert_rule(
    State(state): State<AppState>,
    Json(rule): Json<crate::AlertRule>,
) -> impl IntoResponse {
    state.alerting_manager.add_rule(rule.clone()).await;
    (StatusCode::CREATED, Json(rule)).into_response()
}

/// GET /admin/alerts/rules/:id - Get alert rule by ID.
async fn get_alert_rule(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.alerting_manager.get_rule(id).await {
        Some(rule) => (StatusCode::OK, Json(rule)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert rule not found" })),
        )
            .into_response(),
    }
}

/// PUT /admin/alerts/rules/:id - Update alert rule.
async fn update_alert_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut rule): Json<crate::AlertRule>,
) -> impl IntoResponse {
    rule.id = id; // Ensure ID matches path
    if state.alerting_manager.update_rule(rule.clone()).await {
        (StatusCode::OK, Json(rule)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert rule not found" })),
        )
            .into_response()
    }
}

/// DELETE /admin/alerts/rules/:id - Delete alert rule.
async fn delete_alert_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if state.alerting_manager.remove_rule(id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert rule not found" })),
        )
            .into_response()
    }
}

/// POST /admin/alerts/rules/:id/toggle - Enable/disable alert rule.
async fn toggle_alert_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<ToggleRuleRequest>,
) -> impl IntoResponse {
    if state
        .alerting_manager
        .set_rule_enabled(id, req.enabled)
        .await
    {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "enabled": req.enabled })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert rule not found" })),
        )
            .into_response()
    }
}

/// GET /admin/alerts - List all alerts (active + historical).
async fn list_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let alerts = state.alerting_manager.get_all_alerts().await;
    (StatusCode::OK, Json(alerts)).into_response()
}

/// GET /admin/alerts/active - List active alerts only.
async fn list_active_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let alerts = state.alerting_manager.get_active_alerts().await;
    (StatusCode::OK, Json(alerts)).into_response()
}

/// GET /admin/alerts/:id - Get alert by ID.
async fn get_alert(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.alerting_manager.get_alert(id).await {
        Some(alert) => (StatusCode::OK, Json(alert)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert not found" })),
        )
            .into_response(),
    }
}

/// POST /admin/alerts/:id/acknowledge - Acknowledge an alert.
#[derive(Debug, Deserialize)]
struct AcknowledgeRequest {
    acknowledged_by: String,
}

async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<AcknowledgeRequest>,
) -> impl IntoResponse {
    if state
        .alerting_manager
        .acknowledge_alert(id, req.acknowledged_by)
        .await
    {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "acknowledged": true })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert not found or already acknowledged" })),
        )
            .into_response()
    }
}

/// POST /admin/alerts/:id/resolve - Resolve an alert.
async fn resolve_alert(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    if state.alerting_manager.resolve_alert(id).await {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "resolved": true })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Alert not found" })),
        )
            .into_response()
    }
}

/// GET /admin/alerts/stats - Get alerting statistics.
async fn get_alert_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.alerting_manager.get_stats().await;
    (StatusCode::OK, Json(stats)).into_response()
}

/// GET /admin/alerts/email-retries - Get all failed emails in retry queue.
async fn get_email_retries(State(state): State<AppState>) -> impl IntoResponse {
    let failed_emails = state.alerting_manager.get_failed_emails().await;
    (StatusCode::OK, Json(failed_emails)).into_response()
}

/// POST /admin/alerts/email-retries/process - Manually trigger email retry processing.
async fn process_email_retries(State(state): State<AppState>) -> impl IntoResponse {
    state.alerting_manager.process_email_retries().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "Email retry processing completed"})),
    )
        .into_response()
}

/// DELETE /admin/alerts/email-retries/:id - Remove a failed email from retry queue.
async fn remove_email_retry(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.alerting_manager.remove_failed_email(id).await {
        true => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "Failed email removed from retry queue"})),
        )
            .into_response(),
        false => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Failed email not found in retry queue"})),
        )
            .into_response(),
    }
}

// ============================================================================
// Feature Flags Management
// ============================================================================

/// GET /admin/flags - List all feature flags.
async fn list_feature_flags(State(state): State<AppState>) -> impl IntoResponse {
    let flags = state.feature_flags_manager.list_flags().await;
    (StatusCode::OK, Json(flags)).into_response()
}

/// POST /admin/flags - Create a new feature flag.
async fn create_feature_flag(
    State(state): State<AppState>,
    Json(flag): Json<crate::FeatureFlag>,
) -> impl IntoResponse {
    match state.feature_flags_manager.create_flag(flag).await {
        Ok(created) => {
            crate::metrics::record_flag_created(created.flag_type.as_str());
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// GET /admin/flags/:id - Get feature flag by ID.
async fn get_feature_flag(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.feature_flags_manager.get_flag(id).await {
        Some(flag) => (StatusCode::OK, Json(flag)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Feature flag not found" })),
        )
            .into_response(),
    }
}

/// PUT /admin/flags/:id - Update feature flag.
async fn update_feature_flag(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut flag): Json<crate::FeatureFlag>,
) -> impl IntoResponse {
    flag.id = id; // Ensure ID matches path
    match state.feature_flags_manager.update_flag(flag.clone()).await {
        Ok(updated) => {
            crate::metrics::record_flag_updated(&updated.key);
            (StatusCode::OK, Json(updated)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// DELETE /admin/flags/:id - Delete feature flag.
async fn delete_feature_flag(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Get flag key before deletion for metrics
    let flag_key = if let Some(flag) = state.feature_flags_manager.get_flag(id).await {
        Some(flag.key)
    } else {
        None
    };

    if state.feature_flags_manager.delete_flag(id).await {
        if let Some(key) = flag_key {
            crate::metrics::record_flag_deleted(&key);
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Feature flag not found" })),
        )
            .into_response()
    }
}

/// POST /admin/flags/:id/enable - Enable feature flag.
async fn enable_feature_flag(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if state.feature_flags_manager.enable_flag(id).await {
        (StatusCode::OK, Json(serde_json::json!({ "enabled": true }))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Feature flag not found" })),
        )
            .into_response()
    }
}

/// POST /admin/flags/:id/disable - Disable feature flag.
async fn disable_feature_flag(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if state.feature_flags_manager.disable_flag(id).await {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "enabled": false })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Feature flag not found" })),
        )
            .into_response()
    }
}

/// Request for evaluating a feature flag.
#[derive(Debug, Deserialize)]
struct EvaluateRequest {
    key: String,
    context: crate::EvaluationContext,
}

/// POST /admin/flags/evaluate - Evaluate feature flag for a context.
async fn evaluate_feature_flag(
    State(state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> impl IntoResponse {
    let result = state
        .feature_flags_manager
        .evaluate(&req.key, &req.context)
        .await;
    crate::metrics::record_flag_evaluation(&req.key, result.enabled);
    (StatusCode::OK, Json(result)).into_response()
}

/// GET /admin/flags/stats - Get feature flags statistics.
async fn get_feature_flags_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.feature_flags_manager.get_stats().await;
    crate::metrics::set_feature_flags_count(stats.total_flags, stats.enabled_flags);
    (StatusCode::OK, Json(stats)).into_response()
}
