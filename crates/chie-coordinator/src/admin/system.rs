//! System statistics, health, users, content, nodes, fraud, config, and proofs admin handlers.

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

use crate::AppState;

/// Assemble system-related routes.
pub fn system_routes() -> Router<AppState> {
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
