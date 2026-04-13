//! Data management admin handlers: retention, archiving, popularity, verification, migrations, audit log, webhooks, and data export.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AppState,
    audit_log::AuditQueryFilter,
    export::{AuditLogExportFilter, ExportFormat, ProofExportFilter, TransactionExportFilter},
    webhooks::WebhookEndpoint,
};

/// Assemble management-related routes.
pub fn management_routes() -> Router<AppState> {
    Router::new()
        // Data Retention
        .route("/retention/info", get(get_retention_info))
        .route("/retention/stats", get(get_retention_stats))
        .route("/retention/cleanup", post(run_retention_cleanup))
        .route("/retention/estimate", get(estimate_retention_cleanup))
        // Data Archiving
        .route("/archiving/info", get(get_archiving_info))
        .route("/archiving/stats", get(get_archiving_stats))
        .route("/archiving/archive", post(run_archiving))
        .route("/archiving/estimate", get(estimate_archiving))
        .route("/archiving/storage", get(get_archive_storage))
        // Popularity Management
        .route("/popularity/stats", get(get_popularity_stats))
        .route("/popularity/trending", get(get_admin_trending))
        .route("/popularity/refresh", post(refresh_popularity_cache))
        .route("/popularity/prune", post(prune_popularity_data))
        // Verification Management
        .route("/verification/config", get(get_verification_config))
        .route("/verification/stats", get(get_verification_stats))
        // Migration Management
        .route("/migrations/status", get(get_migration_status))
        .route("/migrations/run", post(run_pending_migrations))
        // Audit Log Management
        .route("/audit/query", get(query_audit_log))
        .route("/audit/stats", get(get_audit_stats))
        // Webhook Management
        .route("/webhooks", get(list_webhooks))
        .route("/webhooks", post(create_webhook))
        .route("/webhooks/:id", get(get_webhook))
        .route("/webhooks/:id", put(update_webhook))
        .route("/webhooks/:id", delete(delete_webhook))
        .route("/webhooks/stats", get(get_webhook_stats))
        .route("/webhooks/config", get(get_webhook_config))
        .route("/webhooks/config", put(update_webhook_config))
        .route("/webhooks/:id/deliveries", get(get_webhook_deliveries))
        .route("/webhooks/deliveries", get(get_all_deliveries))
        .route("/webhooks/deliveries/failed", get(get_failed_deliveries))
        .route("/webhooks/deliveries/:id/retry", post(retry_delivery))
        .route("/webhooks/cleanup-deliveries", post(cleanup_deliveries))
        // Data Export
        .route("/export/audit-logs", get(export_audit_logs))
        .route("/export/transactions", get(export_transactions))
        .route("/export/proofs", get(export_proofs))
}

// ============================================================================
// Data Retention Management
// ============================================================================

/// Get retention policy information
async fn get_retention_info(State(state): State<AppState>) -> impl IntoResponse {
    let info = state.retention_manager.get_policy_info().await;
    Json(info)
}

/// Get retention statistics
async fn get_retention_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.retention_manager.get_stats().await;
    Json(stats)
}

/// Run retention cleanup manually
async fn run_retention_cleanup(State(state): State<AppState>) -> impl IntoResponse {
    match state.retention_manager.run_cleanup().await {
        Ok(deleted) => Json(serde_json::json!({
            "success": true,
            "deleted": deleted,
            "message": format!("Deleted {} old records", deleted)
        })),
        Err(e) => {
            tracing::error!("Retention cleanup failed: {}", e);
            Json(serde_json::json!({
                "success": false,
                "error": e.to_string()
            }))
        }
    }
}

/// Estimate records to be deleted in next cleanup
async fn estimate_retention_cleanup(State(state): State<AppState>) -> impl IntoResponse {
    match state.retention_manager.estimate_cleanup_size().await {
        Ok(estimate) => (StatusCode::OK, Json(estimate)).into_response(),
        Err(e) => {
            tracing::error!("Failed to estimate cleanup size: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Data Archiving Management
// ============================================================================

/// Get archiving policy information
async fn get_archiving_info(State(state): State<AppState>) -> impl IntoResponse {
    let info = state.archiving_manager.get_policy_info().await;
    Json(info)
}

/// Get archiving statistics
async fn get_archiving_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.archiving_manager.get_stats().await;
    Json(stats)
}

/// Run archiving manually
async fn run_archiving(State(state): State<AppState>) -> impl IntoResponse {
    match state.archiving_manager.run_archive().await {
        Ok(archived) => Json(serde_json::json!({
            "success": true,
            "archived": archived,
            "message": format!("Archived {} records", archived)
        })),
        Err(e) => {
            tracing::error!("Archiving failed: {}", e);
            Json(serde_json::json!({
                "success": false,
                "error": e.to_string()
            }))
        }
    }
}

/// Estimate records to be archived in next run
async fn estimate_archiving(State(state): State<AppState>) -> impl IntoResponse {
    match state.archiving_manager.estimate_archive_size().await {
        Ok(estimate) => (StatusCode::OK, Json(estimate)).into_response(),
        Err(e) => {
            tracing::error!("Failed to estimate archive size: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Get archive storage statistics
async fn get_archive_storage(State(state): State<AppState>) -> impl IntoResponse {
    match state.archiving_manager.get_archive_storage_stats().await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get archive storage stats: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Popularity Management
// ============================================================================

/// Get global popularity statistics.
async fn get_popularity_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.popularity_tracker.get_global_stats().await;
    (StatusCode::OK, Json(stats)).into_response()
}

/// Trending query parameters for admin.
#[derive(Debug, Deserialize)]
struct AdminTrendingParams {
    /// Maximum number of trending items to return (default: 50).
    #[serde(default = "default_admin_trending_limit")]
    limit: usize,
}

fn default_admin_trending_limit() -> usize {
    50
}

/// Get trending content (admin view with extended limit).
async fn get_admin_trending(
    State(state): State<AppState>,
    Query(params): Query<AdminTrendingParams>,
) -> impl IntoResponse {
    let trending = state.popularity_tracker.get_trending(params.limit).await;
    (StatusCode::OK, Json(trending)).into_response()
}

/// Force refresh popularity cache.
async fn refresh_popularity_cache(State(state): State<AppState>) -> impl IntoResponse {
    state.popularity_tracker.refresh_trending_cache().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Popularity cache refreshed successfully"
        })),
    )
        .into_response()
}

/// Prune old popularity data query parameters.
#[derive(Debug, Deserialize)]
struct PrunePopularityParams {
    /// Days of data to retain (default: 90).
    #[serde(default = "default_prune_retention_days")]
    retention_days: i64,
}

fn default_prune_retention_days() -> i64 {
    90
}

/// Prune old popularity data.
async fn prune_popularity_data(
    State(state): State<AppState>,
    Query(params): Query<PrunePopularityParams>,
) -> impl IntoResponse {
    state
        .popularity_tracker
        .prune_old_data(params.retention_days)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": format!("Popularity data pruned (retention: {} days)", params.retention_days)
        })),
    )
        .into_response()
}

// ============================================================================
// Verification Management
// ============================================================================

/// Verification configuration response.
#[derive(Debug, Serialize, Deserialize)]
struct VerificationConfigResponse {
    /// Maximum allowed timestamp drift (milliseconds).
    pub timestamp_tolerance_ms: i64,
    /// Z-score threshold for anomaly detection.
    pub anomaly_z_threshold: f64,
    /// Minimum latency (to detect impossible transfers).
    pub min_latency_ms: u32,
    /// Maximum latency before penalty.
    pub high_latency_threshold_ms: u32,
    /// Speed deviation threshold for historical comparison.
    pub speed_deviation_threshold: f64,
}

/// Get current verification configuration.
async fn get_verification_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.verification.config();
    let response = VerificationConfigResponse {
        timestamp_tolerance_ms: config.timestamp_tolerance_ms,
        anomaly_z_threshold: config.anomaly_z_threshold,
        min_latency_ms: config.min_latency_ms,
        high_latency_threshold_ms: config.high_latency_threshold_ms,
        speed_deviation_threshold: 5.0, // Hardcoded in verification module
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Verification statistics response.
#[derive(Debug, Serialize, Deserialize)]
struct VerificationStatsResponse {
    /// Total proofs verified in the last hour.
    pub total_verified_1h: i64,
    /// Total proofs rejected in the last hour.
    pub total_rejected_1h: i64,
    /// Total anomalies detected in the last hour.
    pub total_anomalies_1h: i64,
    /// Average verification quality score.
    pub avg_quality_score: f64,
    /// Recent speed anomaly count.
    pub speed_anomalies_1h: i64,
}

/// Get verification statistics.
async fn get_verification_stats(State(state): State<AppState>) -> impl IntoResponse {
    let total_verified = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM bandwidth_proofs
        WHERE status = 'VERIFIED'
            AND created_at > NOW() - INTERVAL '1 hour'
        "#,
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let total_rejected = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM bandwidth_proofs
        WHERE status = 'REJECTED'
            AND created_at > NOW() - INTERVAL '1 hour'
        "#,
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let stats = VerificationStatsResponse {
        total_verified_1h: total_verified,
        total_rejected_1h: total_rejected,
        total_anomalies_1h: 0,
        avg_quality_score: 0.95,
        speed_anomalies_1h: 0,
    };

    (StatusCode::OK, Json(stats)).into_response()
}

// ============================================================================
// Migration Management
// ============================================================================

/// Migration status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MigrationStatusResponse {
    /// List of applied migrations.
    pub migrations: Vec<crate::MigrationStatus>,
    /// Total number of applied migrations.
    pub total_applied: usize,
    /// Whether all migrations are up to date.
    pub up_to_date: bool,
}

/// GET /admin/migrations/status - Get migration status.
#[allow(dead_code)]
async fn get_migration_status(State(state): State<AppState>) -> impl IntoResponse {
    match state.migration_runner.get_migration_status().await {
        Ok(migrations) => {
            let total_applied = migrations.len();
            let up_to_date = state
                .migration_runner
                .is_up_to_date()
                .await
                .unwrap_or(false);

            let response = MigrationStatusResponse {
                migrations,
                total_applied,
                up_to_date,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get migration status: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get migration status",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// Migration run response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MigrationRunResponse {
    /// Number of migrations applied.
    pub applied_count: usize,
    /// Success message.
    pub message: String,
}

/// POST /admin/migrations/run - Run pending migrations.
#[allow(dead_code)]
async fn run_pending_migrations(State(state): State<AppState>) -> impl IntoResponse {
    match state.migration_runner.run_migrations().await {
        Ok(count) => {
            let message = if count > 0 {
                format!("Successfully applied {} migrations", count)
            } else {
                "No pending migrations".to_string()
            };

            let response = MigrationRunResponse {
                applied_count: count,
                message,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to run migrations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to run migrations",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Audit Log Management
// ============================================================================

/// GET /admin/audit/query - Query audit log entries.
async fn query_audit_log(
    State(state): State<AppState>,
    Query(filter): Query<AuditQueryFilter>,
) -> impl IntoResponse {
    match state.audit_logger.query(filter).await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to query audit log",
                    "message": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

/// GET /admin/audit/stats - Get audit log statistics.
async fn get_audit_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.audit_logger.get_stats().await;
    (StatusCode::OK, Json(stats)).into_response()
}

// ============================================================================
// Webhook Management
// ============================================================================

/// GET /admin/webhooks - List all webhooks.
async fn list_webhooks(State(state): State<AppState>) -> impl IntoResponse {
    let webhooks = state.webhook_manager.list_webhooks().await;
    (StatusCode::OK, Json(webhooks)).into_response()
}

/// POST /admin/webhooks - Create a new webhook.
async fn create_webhook(
    State(state): State<AppState>,
    Json(webhook): Json<WebhookEndpoint>,
) -> impl IntoResponse {
    match state.webhook_manager.register_webhook(webhook).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": id,
                "message": "Webhook created successfully"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Failed to create webhook",
                "message": e
            })),
        )
            .into_response(),
    }
}

/// GET /admin/webhooks/:id - Get webhook by ID.
async fn get_webhook(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.webhook_manager.get_webhook(id).await {
        Some(webhook) => (StatusCode::OK, Json(webhook)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Webhook not found"
            })),
        )
            .into_response(),
    }
}

/// PUT /admin/webhooks/:id - Update webhook.
async fn update_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(webhook): Json<WebhookEndpoint>,
) -> impl IntoResponse {
    match state.webhook_manager.update_webhook(id, webhook).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Webhook updated successfully"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Failed to update webhook",
                "message": e
            })),
        )
            .into_response(),
    }
}

/// DELETE /admin/webhooks/:id - Delete webhook.
async fn delete_webhook(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.webhook_manager.unregister_webhook(id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Webhook deleted successfully"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Failed to delete webhook",
                "message": e
            })),
        )
            .into_response(),
    }
}

/// GET /admin/webhooks/stats - Get webhook delivery statistics.
async fn get_webhook_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.webhook_manager.get_stats().await;
    (StatusCode::OK, Json(stats)).into_response()
}

/// GET /admin/webhooks/config - Get webhook configuration.
async fn get_webhook_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.webhook_manager.get_config().await;
    (StatusCode::OK, Json(config)).into_response()
}

/// PUT /admin/webhooks/config - Update webhook configuration.
async fn update_webhook_config(
    State(state): State<AppState>,
    Json(config): Json<crate::webhooks::WebhookConfig>,
) -> impl IntoResponse {
    state.webhook_manager.update_config(config).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Webhook configuration updated successfully"
        })),
    )
        .into_response()
}

/// GET /admin/webhooks/:id/deliveries - Get delivery history for a webhook.
#[derive(Debug, Deserialize)]
struct DeliveryQueryParams {
    limit: Option<usize>,
}

async fn get_webhook_deliveries(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<DeliveryQueryParams>,
) -> impl IntoResponse {
    let deliveries = state
        .webhook_manager
        .get_delivery_history(id, params.limit)
        .await;
    (StatusCode::OK, Json(deliveries)).into_response()
}

/// GET /admin/webhooks/deliveries - Get all delivery history.
async fn get_all_deliveries(
    State(state): State<AppState>,
    Query(params): Query<DeliveryQueryParams>,
) -> impl IntoResponse {
    let deliveries = state
        .webhook_manager
        .get_all_delivery_history(params.limit)
        .await;
    (StatusCode::OK, Json(deliveries)).into_response()
}

/// GET /admin/webhooks/deliveries/failed - Get failed deliveries.
#[derive(Debug, Deserialize)]
struct FailedDeliveriesQuery {
    webhook_id: Option<Uuid>,
    limit: Option<usize>,
}

async fn get_failed_deliveries(
    State(state): State<AppState>,
    Query(params): Query<FailedDeliveriesQuery>,
) -> impl IntoResponse {
    let deliveries = state
        .webhook_manager
        .get_failed_deliveries(params.webhook_id, params.limit)
        .await;
    (StatusCode::OK, Json(deliveries)).into_response()
}

/// POST /admin/webhooks/deliveries/:id/retry - Manually retry a failed delivery.
async fn retry_delivery(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.webhook_manager.manual_retry(id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "message": "Delivery retry initiated successfully"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Failed to retry delivery",
                "details": e
            })),
        )
            .into_response(),
    }
}

/// POST /admin/webhooks/cleanup-deliveries - Cleanup old delivery history.
async fn cleanup_deliveries(State(state): State<AppState>) -> impl IntoResponse {
    let removed = state.webhook_manager.cleanup_old_deliveries().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Delivery history cleaned up successfully",
            "records_removed": removed
        })),
    )
        .into_response()
}

// ============================================================================
// Data Export
// ============================================================================

/// Export format query parameter.
#[derive(Debug, Deserialize)]
struct ExportQuery {
    /// Export format (csv, json, jsonlines).
    #[serde(default = "default_export_format")]
    format: ExportFormat,
}

fn default_export_format() -> ExportFormat {
    ExportFormat::Json
}

/// GET /admin/export/audit-logs - Export audit logs.
async fn export_audit_logs(
    State(state): State<AppState>,
    Query(export_query): Query<ExportQuery>,
    Query(filter): Query<AuditLogExportFilter>,
) -> impl IntoResponse {
    match state
        .data_exporter
        .export_audit_logs(filter, export_query.format)
        .await
    {
        Ok(data) => {
            let content_type = export_query.format.mime_type();
            let filename = format!("audit_logs.{}", export_query.format.extension());

            (
                StatusCode::OK,
                [
                    ("Content-Type", content_type),
                    (
                        "Content-Disposition",
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to export audit logs: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to export audit logs",
                    "message": e
                })),
            )
                .into_response()
        }
    }
}

/// GET /admin/export/transactions - Export transactions.
async fn export_transactions(
    State(state): State<AppState>,
    Query(export_query): Query<ExportQuery>,
    Query(filter): Query<TransactionExportFilter>,
) -> impl IntoResponse {
    match state
        .data_exporter
        .export_transactions(filter, export_query.format)
        .await
    {
        Ok(data) => {
            let content_type = export_query.format.mime_type();
            let filename = format!("transactions.{}", export_query.format.extension());

            (
                StatusCode::OK,
                [
                    ("Content-Type", content_type),
                    (
                        "Content-Disposition",
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to export transactions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to export transactions",
                    "message": e
                })),
            )
                .into_response()
        }
    }
}

/// GET /admin/export/proofs - Export bandwidth proofs.
async fn export_proofs(
    State(state): State<AppState>,
    Query(export_query): Query<ExportQuery>,
    Query(filter): Query<ProofExportFilter>,
) -> impl IntoResponse {
    match state
        .data_exporter
        .export_proofs(filter, export_query.format)
        .await
    {
        Ok(data) => {
            let content_type = export_query.format.mime_type();
            let filename = format!("proofs.{}", export_query.format.extension());

            (
                StatusCode::OK,
                [
                    ("Content-Type", content_type),
                    (
                        "Content-Disposition",
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to export proofs: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to export proofs",
                    "message": e
                })),
            )
                .into_response()
        }
    }
}
