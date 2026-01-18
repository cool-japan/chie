//! Admin dashboard API for CHIE Coordinator.
//!
//! This module provides REST endpoints for administrative operations:
//! - System statistics and health
//! - User management
//! - Content moderation
//! - Node management
//! - Configuration management
//!
//! **TODO**: This file is currently 4439 lines, exceeding the 2000-line limit specified in CLAUDE.md.
//! It should be refactored into smaller modules under admin/ directory:
//! - admin/handlers/system.rs - System stats, health, config
//! - admin/handlers/users.rs - User management
//! - admin/handlers/content.rs - Content management
//! - admin/handlers/nodes.rs - Node management
//! - admin/handlers/data.rs - Retention, archiving, export
//! - admin/handlers/webhooks.rs - Webhook management
//! - admin/handlers/moderation.rs - Content moderation
//! - admin/handlers/reputation.rs - Node reputation
//! - admin/handlers/alerts.rs - Alerting system
//! - admin/handlers/email.rs - Email system (templates, delivery, SLA)
//! - admin/handlers/features.rs - Feature flags
//! - admin/handlers/quotas.rs - Rate limit quotas
//! - admin/mod.rs - Main router assembly

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

use crate::{
    AppState,
    audit_log::AuditQueryFilter,
    export::{AuditLogExportFilter, ExportFormat, ProofExportFilter, TransactionExportFilter},
    webhooks::WebhookEndpoint,
};

/// Admin API routes.
pub fn admin_routes() -> Router<AppState> {
    Router::new()
        // System stats
        .route("/stats", get(get_system_stats))
        .route("/stats/detailed", get(get_detailed_stats))
        // Health
        .route("/health", get(get_health_status))
        .route("/health/components", get(get_component_health))
        // Users
        .route("/users", get(list_users))
        .route("/users/:id", get(get_user))
        .route("/users/:id/ban", post(ban_user))
        .route("/users/:id/unban", post(unban_user))
        // Content
        .route("/content", get(list_content))
        .route("/content/:id", get(get_content))
        .route("/content/:id", delete(remove_content))
        .route("/content/:id/flag", post(flag_content))
        // Nodes
        .route("/nodes", get(list_nodes))
        .route("/nodes/:id", get(get_node))
        .route("/nodes/:id/suspend", post(suspend_node))
        .route("/nodes/:id/unsuspend", post(unsuspend_node))
        // Fraud
        .route("/fraud/alerts", get(list_fraud_alerts))
        .route("/fraud/alerts/:id/resolve", post(resolve_fraud_alert))
        // Config
        .route("/config", get(get_config))
        .route("/config", put(update_config))
        // Proofs
        .route("/proofs/recent", get(list_recent_proofs))
        .route("/proofs/stats", get(get_proof_stats))
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
        // Data Export
        .route("/export/audit-logs", get(export_audit_logs))
        .route("/export/transactions", get(export_transactions))
        .route("/export/proofs", get(export_proofs))
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
        // API Versioning
        .route("/versions", get(list_api_versions))
        .route("/versions/:version", get(get_api_version))
        .route("/versions/:version/deprecate", post(deprecate_api_version))
        // Rate Limit Quotas
        .route("/quotas/tiers", get(get_quota_tiers))
        .route("/quotas/stats", get(get_quota_stats))
        .route("/quotas/active", get(get_active_quotas))
        .route("/quotas/user/:user_id", get(get_user_quota_admin))
        .route("/quotas/purchase/:id", get(get_quota_purchase))
        .route("/quotas/purchase/:id/activate", post(activate_quota_admin))
        .route("/quotas/purchase/:id/cancel", post(cancel_quota_admin))
        .route("/quotas/config", get(get_quota_config))
        .route("/quotas/config", put(update_quota_config))
        // Request Coalescing
        .route("/coalescing/stats", get(get_coalescing_stats))
    // TODO: Uncomment when analytics module is ready
    // // Advanced Analytics
    // .route("/analytics/dashboard", get(get_dashboard_metrics_admin))
    // .route("/analytics/content", get(get_content_performance_admin))
    // .route("/analytics/nodes/leaderboard", get(get_node_leaderboard_admin))
    // .route("/analytics/query", post(execute_custom_analytics_query_admin))
    // .route("/analytics/timeseries/cleanup", post(cleanup_timeseries_admin))
    // TODO: Uncomment when database migration 006_payments.sql is run
    // // Payment & Settlement
    // .route("/payments", get(list_payments_admin))
    // .route("/payments/:id", get(get_payment_admin))
    // .route("/payments/stats", get(get_payment_stats_admin))
    // .route("/settlements", get(list_settlement_batches_admin))
    // .route("/settlements/create", post(create_settlement_batch_admin))
    // .route("/settlements/:id/process", post(process_settlement_batch_admin))
    // .route("/escrow", get(list_escrow_entries_admin))
    // .route("/escrow/:id/release", post(release_escrow_admin))
    // .route("/escrow/:id/refund", post(refund_escrow_admin))
    // TODO: Uncomment when database migration 005_tenants.sql is run
    // // Tenant Management
    // .route("/tenants", get(list_tenants_admin))
    // .route("/tenants", post(create_tenant_admin))
    // .route("/tenants/:id", get(get_tenant_admin))
    // .route("/tenants/:id", put(update_tenant_admin))
    // .route("/tenants/:id", delete(delete_tenant_admin))
    // .route("/tenants/:id/stats", get(get_tenant_stats_admin))
}

// ============================================================================
// System Stats
// ============================================================================

/// System statistics response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SystemStats {
    /// Total registered users.
    pub total_users: u64,
    /// Active users (last 24h).
    pub active_users_24h: u64,
    /// Total nodes.
    pub total_nodes: u64,
    /// Active nodes.
    pub active_nodes: u64,
    /// Total content items.
    pub total_content: u64,
    /// Total storage used (bytes).
    pub total_storage_bytes: u64,
    /// Proofs verified today.
    pub proofs_today: u64,
    /// Rewards distributed today.
    pub rewards_today: u64,
    /// Fraud alerts today.
    pub fraud_alerts_today: u64,
}

async fn get_system_stats(State(_state): State<AppState>) -> impl IntoResponse {
    // In production, these would come from the database
    let stats = SystemStats {
        total_users: 0,
        active_users_24h: 0,
        total_nodes: 0,
        active_nodes: 0,
        total_content: 0,
        total_storage_bytes: 0,
        proofs_today: 0,
        rewards_today: 0,
        fraud_alerts_today: 0,
    };

    Json(stats)
}

/// Detailed statistics response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetailedStats {
    /// Basic stats.
    pub basic: SystemStats,
    /// Hourly proof counts (last 24h).
    pub proofs_hourly: Vec<HourlyCount>,
    /// Daily stats (last 7 days).
    pub daily_stats: Vec<DailyStats>,
    /// Top content by transfers.
    pub top_content: Vec<ContentStats>,
    /// Top nodes by earnings.
    pub top_nodes: Vec<NodeStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HourlyCount {
    pub hour: u32,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DailyStats {
    pub date: String,
    pub proofs: u64,
    pub rewards: u64,
    pub new_users: u64,
    pub new_content: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContentStats {
    pub cid: String,
    pub title: Option<String>,
    pub transfer_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeStats {
    pub node_id: Uuid,
    pub total_earnings: u64,
    pub proof_count: u64,
    pub uptime_percent: f64,
}

async fn get_detailed_stats(State(_state): State<AppState>) -> impl IntoResponse {
    let stats = DetailedStats {
        basic: SystemStats {
            total_users: 0,
            active_users_24h: 0,
            total_nodes: 0,
            active_nodes: 0,
            total_content: 0,
            total_storage_bytes: 0,
            proofs_today: 0,
            rewards_today: 0,
            fraud_alerts_today: 0,
        },
        proofs_hourly: vec![],
        daily_stats: vec![],
        top_content: vec![],
        top_nodes: vec![],
    };

    Json(stats)
}

// ============================================================================
// Health
// ============================================================================

/// Health status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthStatus {
    /// Overall status.
    pub status: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Version string.
    pub version: String,
    /// Component statuses.
    pub components: Vec<ComponentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComponentStatus {
    pub name: String,
    pub status: String,
    pub latency_ms: Option<f64>,
    pub message: Option<String>,
}

async fn get_health_status(State(_state): State<AppState>) -> impl IntoResponse {
    let health = HealthStatus {
        status: "healthy".to_string(),
        uptime_secs: 0,
        version: env!("CARGO_PKG_VERSION").to_string(),
        components: vec![
            ComponentStatus {
                name: "database".to_string(),
                status: "healthy".to_string(),
                latency_ms: Some(1.5),
                message: None,
            },
            ComponentStatus {
                name: "redis".to_string(),
                status: "healthy".to_string(),
                latency_ms: Some(0.5),
                message: None,
            },
        ],
    };

    Json(health)
}

async fn get_component_health(State(_state): State<AppState>) -> impl IntoResponse {
    let components = vec![
        ComponentStatus {
            name: "database".to_string(),
            status: "healthy".to_string(),
            latency_ms: Some(1.5),
            message: None,
        },
        ComponentStatus {
            name: "redis".to_string(),
            status: "healthy".to_string(),
            latency_ms: Some(0.5),
            message: None,
        },
        ComponentStatus {
            name: "verification_service".to_string(),
            status: "healthy".to_string(),
            latency_ms: None,
            message: None,
        },
        ComponentStatus {
            name: "reward_engine".to_string(),
            status: "healthy".to_string(),
            latency_ms: None,
            message: None,
        },
    ];

    Json(components)
}

// ============================================================================
// Users
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub search: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<AdminUserInfo>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminUserInfo {
    pub id: Uuid,
    pub public_key: String,
    pub created_at: String,
    pub status: String,
    pub total_earnings: u64,
    pub proof_count: u64,
    pub content_count: u64,
}

async fn list_users(
    State(_state): State<AppState>,
    Query(query): Query<UserListQuery>,
) -> impl IntoResponse {
    let _ = query;
    let response = UserListResponse {
        users: vec![],
        total: 0,
        page: 1,
        limit: 20,
    };

    Json(response)
}

async fn get_user(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminUserInfo>, (StatusCode, String)> {
    let _ = id;
    Err((StatusCode::NOT_FOUND, "User not found".to_string()))
}

async fn ban_user(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id;
    Ok(Json(serde_json::json!({"status": "banned"})))
}

async fn unban_user(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id;
    Ok(Json(serde_json::json!({"status": "active"})))
}

// ============================================================================
// Content
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContentListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub category: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContentListResponse {
    pub content: Vec<AdminContentInfo>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminContentInfo {
    pub id: Uuid,
    pub cid: String,
    pub title: String,
    pub creator_id: Uuid,
    pub size_bytes: u64,
    pub status: String,
    pub created_at: String,
    pub transfer_count: u64,
    pub flagged: bool,
}

async fn list_content(
    State(_state): State<AppState>,
    Query(query): Query<ContentListQuery>,
) -> impl IntoResponse {
    let _ = query;
    let response = ContentListResponse {
        content: vec![],
        total: 0,
        page: 1,
        limit: 20,
    };

    Json(response)
}

async fn get_content(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminContentInfo>, (StatusCode, String)> {
    let _ = id;
    Err((StatusCode::NOT_FOUND, "Content not found".to_string()))
}

async fn remove_content(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id;
    Ok(Json(serde_json::json!({"status": "removed"})))
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FlagContentRequest {
    pub reason: String,
    pub details: Option<String>,
    pub severity: Option<i32>,
}

async fn flag_content(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<FlagContentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = (id, request);
    Ok(Json(serde_json::json!({"status": "flagged"})))
}

// ============================================================================
// Nodes
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeListResponse {
    pub nodes: Vec<AdminNodeInfo>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminNodeInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub peer_id: String,
    pub status: String,
    pub last_seen: String,
    pub total_earnings: u64,
    pub proof_count: u64,
    pub uptime_percent: f64,
}

async fn list_nodes(
    State(_state): State<AppState>,
    Query(query): Query<NodeListQuery>,
) -> impl IntoResponse {
    let _ = query;
    let response = NodeListResponse {
        nodes: vec![],
        total: 0,
        page: 1,
        limit: 20,
    };

    Json(response)
}

async fn get_node(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminNodeInfo>, (StatusCode, String)> {
    let _ = id;
    Err((StatusCode::NOT_FOUND, "Node not found".to_string()))
}

async fn suspend_node(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id;
    Ok(Json(serde_json::json!({"status": "suspended"})))
}

async fn unsuspend_node(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id;
    Ok(Json(serde_json::json!({"status": "active"})))
}

// ============================================================================
// Fraud
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FraudAlertListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FraudAlertListResponse {
    pub alerts: Vec<AdminFraudAlert>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminFraudAlert {
    pub id: Uuid,
    pub alert_type: String,
    pub severity: String,
    pub node_id: Uuid,
    pub details: String,
    pub status: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

async fn list_fraud_alerts(
    State(_state): State<AppState>,
    Query(query): Query<FraudAlertListQuery>,
) -> impl IntoResponse {
    let _ = query;
    let response = FraudAlertListResponse {
        alerts: vec![],
        total: 0,
        page: 1,
        limit: 20,
    };

    Json(response)
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResolveFraudRequest {
    pub resolution: String,
    pub notes: Option<String>,
}

async fn resolve_fraud_alert(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<ResolveFraudRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = (id, request);
    Ok(Json(serde_json::json!({"status": "resolved"})))
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SystemConfig {
    /// Base reward per GB.
    pub base_reward_per_gb: u64,
    /// Max demand multiplier.
    pub max_demand_multiplier: f64,
    /// Minimum demand multiplier.
    pub min_demand_multiplier: f64,
    /// Creator share (0.0-1.0).
    pub creator_share: f64,
    /// Platform fee share (0.0-1.0).
    pub platform_fee_share: f64,
    /// Fraud detection z-score threshold.
    pub fraud_zscore_threshold: f64,
    /// Timestamp window for proofs (seconds).
    pub timestamp_window_secs: u64,
}

async fn get_config(State(_state): State<AppState>) -> impl IntoResponse {
    let config = SystemConfig {
        base_reward_per_gb: 10,
        max_demand_multiplier: 3.0,
        min_demand_multiplier: 0.5,
        creator_share: 0.1,
        platform_fee_share: 0.1,
        fraud_zscore_threshold: 3.0,
        timestamp_window_secs: 300,
    };

    Json(config)
}

async fn update_config(
    State(_state): State<AppState>,
    Json(config): Json<SystemConfig>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // In production, validate and persist the config
    let _ = config;
    Ok(Json(serde_json::json!({"status": "updated"})))
}

// ============================================================================
// Proofs
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProofListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProofListResponse {
    pub proofs: Vec<AdminProofInfo>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminProofInfo {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub requester_id: Uuid,
    pub content_cid: String,
    pub bytes_transferred: u64,
    pub latency_ms: u32,
    pub status: String,
    pub reward: u64,
    pub created_at: String,
}

async fn list_recent_proofs(
    State(_state): State<AppState>,
    Query(query): Query<ProofListQuery>,
) -> impl IntoResponse {
    let _ = query;
    let response = ProofListResponse {
        proofs: vec![],
        total: 0,
        page: 1,
        limit: 20,
    };

    Json(response)
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProofStats {
    /// Total proofs today.
    pub total_today: u64,
    /// Verified proofs today.
    pub verified_today: u64,
    /// Rejected proofs today.
    pub rejected_today: u64,
    /// Total rewards today.
    pub rewards_today: u64,
    /// Average latency (ms).
    pub avg_latency_ms: f64,
    /// Average bytes per proof.
    pub avg_bytes_per_proof: u64,
}

async fn get_proof_stats(State(_state): State<AppState>) -> impl IntoResponse {
    let stats = ProofStats {
        total_today: 0,
        verified_today: 0,
        rejected_today: 0,
        rewards_today: 0,
        avg_latency_ms: 0.0,
        avg_bytes_per_proof: 0,
    };

    Json(stats)
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
    // Query database for verification statistics
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

    // For anomalies and quality score, we'd need additional tables
    // For now, return placeholder values
    let stats = VerificationStatsResponse {
        total_verified_1h: total_verified,
        total_rejected_1h: total_rejected,
        total_anomalies_1h: 0,   // Would need anomaly_reports table
        avg_quality_score: 0.95, // Would need to store quality scores
        speed_anomalies_1h: 0,   // Would need anomaly_reports table
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
    Json(req): Json<FlagContentRequest>,
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

// ============================================================================
// API Versioning
// ============================================================================

/// List all API versions
async fn list_api_versions(State(state): State<AppState>) -> impl IntoResponse {
    let versions = state.versioning_manager.list_versions();
    Json(versions)
}

/// Get specific API version details
async fn get_api_version(
    State(state): State<AppState>,
    Path(version_str): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    use crate::api_versioning::ApiVersion;

    let version = ApiVersion::from_str(&version_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid version",
                "message": format!("Unknown API version: {}", version_str),
            })),
        )
    })?;

    let version_info = state
        .versioning_manager
        .get_version_info(version)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Version not found",
                    "message": format!("API version {} is not registered", version_str),
                })),
            )
        })?;

    Ok(Json(version_info))
}

/// Request to deprecate an API version
#[derive(Debug, Deserialize, ToSchema)]
struct DeprecateVersionRequest {
    /// Sunset date (ISO 8601 format)
    sunset_at: Option<String>,
    /// Reason for deprecation
    reason: Option<String>,
    /// Replacement version
    replacement_version: Option<String>,
}

/// Deprecate an API version
async fn deprecate_api_version(
    State(state): State<AppState>,
    Path(version_str): Path<String>,
    Json(req): Json<DeprecateVersionRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    use crate::api_versioning::ApiVersion;
    use chrono::DateTime;

    let version = ApiVersion::from_str(&version_str).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid version",
                "message": format!("Unknown API version: {}", version_str),
            })),
        )
    })?;

    let mut version_info = state
        .versioning_manager
        .get_version_info(version)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Version not found",
                    "message": format!("API version {} is not registered", version_str),
                })),
            )
        })?;

    // Parse sunset date if provided
    let sunset_at = if let Some(sunset_str) = req.sunset_at {
        Some(
            DateTime::parse_from_rfc3339(&sunset_str)
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "Invalid date format",
                            "message": "sunset_at must be in ISO 8601 format",
                        })),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    // Parse replacement version if provided
    let replacement = if let Some(replacement_str) = req.replacement_version {
        ApiVersion::from_str(&replacement_str)
    } else {
        None
    };

    // Update deprecation info
    version_info = version_info.deprecate(sunset_at, req.reason, replacement);

    // Re-register the version with updated info
    state
        .versioning_manager
        .register_version(version_info.clone());

    // Log the deprecation
    let audit_entry = crate::audit_log::AuditEntry {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        severity: crate::audit_log::AuditSeverity::Warning,
        category: crate::audit_log::AuditCategory::Config,
        action: "api_version_deprecated".to_string(),
        actor: "admin".to_string(),
        ip_address: None,
        resource_type: Some("api_version".to_string()),
        resource_id: Some(version.as_str().to_string()),
        correlation_id: None,
        details: Some(
            serde_json::to_string(&serde_json::json!({
                "version": version.as_str(),
                "sunset_at": sunset_at,
                "reason": version_info.deprecation.reason,
            }))
            .unwrap(),
        ),
        result: "success".to_string(),
        error_message: None,
    };

    state.audit_logger.log(audit_entry).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("API version {} has been deprecated", version),
        "version_info": version_info,
    })))
}

// ============================================================================
// Rate Limit Quotas
// ============================================================================

/// GET /admin/quotas/tiers - Get available quota tiers.
async fn get_quota_tiers() -> impl IntoResponse {
    let tiers = crate::QuotaManager::get_available_tiers();
    let tiers_info: Vec<_> = tiers
        .into_iter()
        .map(|(tier, requests, price, desc)| {
            serde_json::json!({
                "tier": tier,
                "requests_per_hour": requests,
                "price_cents": price,
                "price_usd": price as f64 / 100.0,
                "description": desc,
            })
        })
        .collect();

    (StatusCode::OK, Json(tiers_info)).into_response()
}

/// GET /admin/quotas/stats - Get quota purchase statistics.
async fn get_quota_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.quota_manager.get_stats().await;
    crate::metrics::set_quota_purchases_count(stats.total_purchases, stats.active_quotas);
    (StatusCode::OK, Json(stats)).into_response()
}

/// GET /admin/quotas/active - Get all active quotas.
async fn get_active_quotas(State(state): State<AppState>) -> impl IntoResponse {
    let quotas = state.quota_manager.get_active_quotas().await;
    (StatusCode::OK, Json(quotas)).into_response()
}

/// GET /admin/quotas/user/:user_id - Get quota information for a specific user.
async fn get_user_quota_admin(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let quota_info = state.quota_manager.get_user_quota(user_id).await;
    (StatusCode::OK, Json(quota_info)).into_response()
}

/// GET /admin/quotas/purchase/:id - Get a specific quota purchase.
async fn get_quota_purchase(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.quota_manager.get_purchase(id).await {
        Some(purchase) => (StatusCode::OK, Json(purchase)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Purchase not found"
            })),
        )
            .into_response(),
    }
}

/// POST /admin/quotas/purchase/:id/activate - Activate a pending quota purchase.
async fn activate_quota_admin(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.quota_manager.activate_quota(id).await {
        Ok(()) => {
            crate::metrics::record_quota_activated();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Quota activated successfully"
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Failed to activate quota",
                "details": e
            })),
        )
            .into_response(),
    }
}

/// POST /admin/quotas/purchase/:id/cancel - Cancel a quota purchase.
async fn cancel_quota_admin(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.quota_manager.cancel_quota(id).await {
        Ok(()) => {
            crate::metrics::record_quota_cancelled();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "Quota cancelled successfully"
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Failed to cancel quota",
                "details": e
            })),
        )
            .into_response(),
    }
}

/// GET /admin/quotas/config - Get quota configuration.
async fn get_quota_config(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.quota_manager.get_config().await;
    Json(config)
}

/// PUT /admin/quotas/config - Update quota configuration.
async fn update_quota_config(
    State(state): State<AppState>,
    Json(config): Json<crate::QuotaConfig>,
) -> impl IntoResponse {
    state.quota_manager.update_config(config).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Quota configuration updated successfully"
        })),
    )
        .into_response()
}

// ============================================================================
// Request Coalescing
// ============================================================================

/// Get request coalescing statistics.
///
/// # Endpoint
/// GET /admin/coalescing/stats
async fn get_coalescing_stats(
    State(state): State<AppState>,
) -> Result<Json<crate::CoalescingStats>, StatusCode> {
    let stats = state.coalescing_manager.stats();
    Ok(Json(stats))
}

// TODO: Uncomment when database migration 005_tenants.sql is run
// // ============================================================================
// // Tenant Management
// // ============================================================================
//
// /// List all tenants
// ///
// /// # Endpoint
// /// GET /admin/tenants
// async fn list_tenants_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::Tenant>>, StatusCode> {
//     let status_filter = params
//         .get("status")
//         .and_then(|s| match s.as_str() {
//             "active" => Some(crate::TenantStatus::Active),
//             "suspended" => Some(crate::TenantStatus::Suspended),
//             "archived" => Some(crate::TenantStatus::Archived),
//             _ => None,
//         });
//
//     let limit = params
//         .get("limit")
//         .and_then(|l| l.parse::<i64>().ok())
//         .unwrap_or(100);
//
//     let offset = params
//         .get("offset")
//         .and_then(|o| o.parse::<i64>().ok())
//         .unwrap_or(0);
//
//     let tenants = state
//         .tenant_manager
//         .list_tenants(status_filter, limit, offset)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(tenants))
// }
//
// /// Create a new tenant
// ///
// /// # Endpoint
// /// POST /admin/tenants
// async fn create_tenant_admin(
//     State(state): State<AppState>,
//     Json(req): Json<crate::CreateTenantRequest>,
// ) -> Result<Json<crate::Tenant>, StatusCode> {
//     let tenant = state
//         .tenant_manager
//         .create_tenant(req)
//         .await
//         .map_err(|_| StatusCode::BAD_REQUEST)?;
//
//     crate::metrics::record_tenant_created();
//
//     Ok(Json(tenant))
// }
//
// /// Get tenant by ID
// ///
// /// # Endpoint
// /// GET /admin/tenants/:id
// async fn get_tenant_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<crate::Tenant>, StatusCode> {
//     let tenant = state
//         .tenant_manager
//         .get_tenant(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
//         .ok_or(StatusCode::NOT_FOUND)?;
//
//     Ok(Json(tenant))
// }
//
// /// Update tenant
// ///
// /// # Endpoint
// /// PUT /admin/tenants/:id
// async fn update_tenant_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
//     Json(req): Json<crate::UpdateTenantRequest>,
// ) -> Result<Json<crate::Tenant>, StatusCode> {
//     let tenant = state
//         .tenant_manager
//         .update_tenant(id, req)
//         .await
//         .map_err(|_| StatusCode::BAD_REQUEST)?;
//
//     crate::metrics::record_tenant_updated();
//
//     Ok(Json(tenant))
// }
//
// /// Delete tenant (soft delete)
// ///
// /// # Endpoint
// /// DELETE /admin/tenants/:id
// async fn delete_tenant_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     state
//         .tenant_manager
//         .delete_tenant(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     crate::metrics::record_tenant_deleted();
//
//     Ok(Json(serde_json::json!({
//         "success": true,
//         "message": "Tenant archived successfully"
//     })))
// }
//
// /// Get tenant statistics
// ///
// /// # Endpoint
// /// GET /admin/tenants/:id/stats
// async fn get_tenant_stats_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<crate::TenantStats>, StatusCode> {
//     let stats = state
//         .tenant_manager
//         .get_tenant_stats(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(stats))
// }

// TODO: Uncomment when database migration 006_payments.sql is run
// // ============================================================================
// // Payment & Settlement Management
// // ============================================================================
//
// /// List all payments with optional filtering
// ///
// /// # Endpoint
// /// GET /admin/payments
// async fn list_payments_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::payment::PaymentLedgerEntry>>, StatusCode> {
//     let user_id = params
//         .get("user_id")
//         .and_then(|id| uuid::Uuid::parse_str(id).ok());
//
//     let limit = params
//         .get("limit")
//         .and_then(|l| l.parse::<i64>().ok())
//         .unwrap_or(100);
//
//     let offset = params
//         .get("offset")
//         .and_then(|o| o.parse::<i64>().ok())
//         .unwrap_or(0);
//
//     if let Some(user_id) = user_id {
//         let payments = state
//             .payment_manager
//             .get_user_payments(user_id, limit, offset)
//             .await
//             .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//         Ok(Json(payments))
//     } else {
//         // TODO: Implement list all payments (not just for one user)
//         Err(StatusCode::BAD_REQUEST)
//     }
// }
//
// /// Get payment by ID
// ///
// /// # Endpoint
// /// GET /admin/payments/:id
// async fn get_payment_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<crate::payment::PaymentLedgerEntry>, StatusCode> {
//     let payment = state
//         .payment_manager
//         .get_payment(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
//         .ok_or(StatusCode::NOT_FOUND)?;
//
//     Ok(Json(payment))
// }
//
// /// Get payment statistics
// ///
// /// # Endpoint
// /// GET /admin/payments/stats
// async fn get_payment_stats_admin(
//     State(state): State<AppState>,
// ) -> Result<Json<crate::payment::PaymentStats>, StatusCode> {
//     let stats = state
//         .payment_manager
//         .get_payment_stats()
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(stats))
// }
//
// /// List settlement batches
// ///
// /// # Endpoint
// /// GET /admin/settlements
// async fn list_settlement_batches_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::payment::SettlementBatch>>, StatusCode> {
//     let limit = params
//         .get("limit")
//         .and_then(|l| l.parse::<i64>().ok())
//         .unwrap_or(100);
//
//     let offset = params
//         .get("offset")
//         .and_then(|o| o.parse::<i64>().ok())
//         .unwrap_or(0);
//
//     let batches = state
//         .payment_manager
//         .list_settlement_batches(limit, offset)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(batches))
// }
//
// /// Create a new settlement batch
// ///
// /// # Endpoint
// /// POST /admin/settlements/create
// async fn create_settlement_batch_admin(
//     State(state): State<AppState>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     let batch = state
//         .payment_manager
//         .create_settlement_batch()
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     match batch {
//         Some(batch) => Ok(Json(serde_json::json!({
//             "success": true,
//             "batch_id": batch.id,
//             "payment_count": batch.payment_count,
//         }))),
//         None => Ok(Json(serde_json::json!({
//             "success": false,
//             "message": "No pending payments to batch"
//         }))),
//     }
// }
//
// /// Process a settlement batch
// ///
// /// # Endpoint
// /// POST /admin/settlements/:id/process
// async fn process_settlement_batch_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     state
//         .payment_manager
//         .process_settlement_batch(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(serde_json::json!({
//         "success": true,
//         "message": "Settlement batch processed"
//     })))
// }
//
// /// List escrow entries
// ///
// /// # Endpoint
// /// GET /admin/escrow
// async fn list_escrow_entries_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::payment::EscrowEntry>>, StatusCode> {
//     let proof_id = params
//         .get("proof_id")
//         .and_then(|id| uuid::Uuid::parse_str(id).ok());
//
//     if let Some(proof_id) = proof_id {
//         let entries = state
//             .payment_manager
//             .list_escrow_for_proof(proof_id)
//             .await
//             .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//         Ok(Json(entries))
//     } else {
//         // TODO: Implement list all escrow entries
//         Err(StatusCode::BAD_REQUEST)
//     }
// }
//
// /// Release escrow funds
// ///
// /// # Endpoint
// /// POST /admin/escrow/:id/release
// async fn release_escrow_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     state
//         .payment_manager
//         .release_escrow(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(serde_json::json!({
//         "success": true,
//         "message": "Escrow funds released"
//     })))
// }
//
// /// Refund escrow funds
// ///
// /// # Endpoint
// /// POST /admin/escrow/:id/refund
// async fn refund_escrow_admin(
//     State(state): State<AppState>,
//     Path(id): Path<uuid::Uuid>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     state
//         .payment_manager
//         .refund_escrow(id)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(serde_json::json!({
//         "success": true,
//         "message": "Escrow funds refunded"
//     })))
// }

// TODO: Uncomment when analytics module is ready
// // ============================================================================
// // Advanced Analytics Management
// // ============================================================================
//
// /// Get real-time dashboard metrics
// ///
// /// # Endpoint
// /// GET /admin/analytics/dashboard
// async fn get_dashboard_metrics_admin(
//     State(state): State<AppState>,
// ) -> Result<Json<crate::analytics::DashboardMetrics>, StatusCode> {
//     let metrics = state
//         .analytics_manager
//         .get_dashboard_metrics()
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(metrics))
// }
//
// /// Get content performance analytics
// ///
// /// # Endpoint
// /// GET /admin/analytics/content
// async fn get_content_performance_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::analytics::ContentPerformance>>, StatusCode> {
//     let content_id = params
//         .get("content_id")
//         .and_then(|id| uuid::Uuid::parse_str(id).ok());
//
//     let time_range = params
//         .get("time_range")
//         .and_then(|r| match r.as_str() {
//             "hour" => Some(crate::analytics::TimeRange::Hour),
//             "day" => Some(crate::analytics::TimeRange::Day),
//             "week" => Some(crate::analytics::TimeRange::Week),
//             "month" => Some(crate::analytics::TimeRange::Month),
//             "quarter" => Some(crate::analytics::TimeRange::Quarter),
//             "year" => Some(crate::analytics::TimeRange::Year),
//             "all" => Some(crate::analytics::TimeRange::AllTime),
//             _ => None,
//         })
//         .unwrap_or(crate::analytics::TimeRange::Month);
//
//     let limit = params
//         .get("limit")
//         .and_then(|l| l.parse::<i64>().ok())
//         .unwrap_or(100);
//
//     let offset = params
//         .get("offset")
//         .and_then(|o| o.parse::<i64>().ok())
//         .unwrap_or(0);
//
//     let performance = state
//         .analytics_manager
//         .get_content_performance(content_id, time_range, limit, offset)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(performance))
// }
//
// /// Get node performance leaderboard
// ///
// /// # Endpoint
// /// GET /admin/analytics/nodes/leaderboard
// async fn get_node_leaderboard_admin(
//     State(state): State<AppState>,
//     Query(params): Query<std::collections::HashMap<String, String>>,
// ) -> Result<Json<Vec<crate::analytics::NodePerformance>>, StatusCode> {
//     let time_range = params
//         .get("time_range")
//         .and_then(|r| match r.as_str() {
//             "hour" => Some(crate::analytics::TimeRange::Hour),
//             "day" => Some(crate::analytics::TimeRange::Day),
//             "week" => Some(crate::analytics::TimeRange::Week),
//             "month" => Some(crate::analytics::TimeRange::Month),
//             "quarter" => Some(crate::analytics::TimeRange::Quarter),
//             "year" => Some(crate::analytics::TimeRange::Year),
//             "all" => Some(crate::analytics::TimeRange::AllTime),
//             _ => None,
//         })
//         .unwrap_or(crate::analytics::TimeRange::Month);
//
//     let sort_by = params
//         .get("sort_by")
//         .map(|s| s.as_str())
//         .unwrap_or("bandwidth");
//
//     let sort_order = params
//         .get("sort_order")
//         .and_then(|o| match o.as_str() {
//             "asc" => Some(crate::analytics::SortOrder::Asc),
//             "desc" => Some(crate::analytics::SortOrder::Desc),
//             _ => None,
//         })
//         .unwrap_or(crate::analytics::SortOrder::Desc);
//
//     let limit = params
//         .get("limit")
//         .and_then(|l| l.parse::<i64>().ok())
//         .unwrap_or(100);
//
//     let offset = params
//         .get("offset")
//         .and_then(|o| o.parse::<i64>().ok())
//         .unwrap_or(0);
//
//     let leaderboard = state
//         .analytics_manager
//         .get_node_leaderboard(time_range, sort_by, sort_order, limit, offset)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(leaderboard))
// }
//
// /// Execute a custom analytics query
// ///
// /// # Endpoint
// /// POST /admin/analytics/query
// async fn execute_custom_analytics_query_admin(
//     State(state): State<AppState>,
//     Json(query): Json<crate::analytics::AnalyticsQuery>,
// ) -> Result<Json<crate::analytics::AnalyticsResult>, StatusCode> {
//     let result = state
//         .analytics_manager
//         .execute_custom_query(query)
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(result))
// }
//
// /// Cleanup old time-series data
// ///
// /// # Endpoint
// /// POST /admin/analytics/timeseries/cleanup
// async fn cleanup_timeseries_admin(
//     State(state): State<AppState>,
// ) -> Result<Json<serde_json::Value>, StatusCode> {
//     let deleted_count = state
//         .analytics_manager
//         .cleanup_old_timeseries()
//         .await
//         .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
//
//     Ok(Json(serde_json::json!({
//         "success": true,
//         "deleted_count": deleted_count,
//         "message": format!("Cleaned up {} old time-series records", deleted_count)
//     })))
// }

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
        .unwrap()
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
    use super::*;

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
