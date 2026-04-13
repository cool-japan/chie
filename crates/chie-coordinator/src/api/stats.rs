//! Statistics, SDK generation, and rate limit quota endpoints.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::AuthenticatedUser;
use crate::db::{ContentRepository, NodeRepository, UserRepository};

/// Platform statistics response.
#[derive(Debug, Serialize)]
pub struct PlatformStats {
    pub total_users: i64,
    pub total_nodes: i64,
    pub total_content: i64,
    pub total_transactions: i64,
    pub total_bandwidth_bytes: i64,
    pub total_points_distributed: i64,
    pub active_nodes_24h: i64,
}

/// Content statistics response.
#[derive(Debug, Serialize)]
pub struct ContentStats {
    pub content_id: uuid::Uuid,
    pub downloads: i64,
    pub total_bytes_transferred: i64,
    pub total_revenue: i64,
    pub active_seeders: i64,
    pub avg_latency_ms: Option<i32>,
}

/// Node statistics response.
#[derive(Debug, Serialize)]
pub struct NodeStats {
    pub node_id: uuid::Uuid,
    pub peer_id: String,
    pub total_bandwidth_bytes: i64,
    pub successful_transfers: i64,
    pub failed_transfers: i64,
    pub success_rate: f64,
    pub total_earnings: i64,
    pub reputation_score: f32,
    pub uptime_hours: f64,
}

/// User statistics response.
#[derive(Debug, Serialize)]
pub struct UserStats {
    pub user_id: uuid::Uuid,
    pub points_balance: i64,
    pub total_earned: i64,
    pub total_spent: i64,
    pub referral_count: i64,
    pub content_created: i64,
    pub nodes_registered: i64,
}

/// SDK generation response.
#[derive(Debug, Serialize)]
pub(super) struct SdkResponse {
    language: String,
    code: String,
    filename: String,
}

/// SDK language information.
#[derive(Debug, Serialize)]
pub(super) struct SdkLanguageInfo {
    language: String,
    display_name: String,
    extension: String,
    package_manager: String,
}

/// Quota tier information for API response.
#[derive(Debug, Serialize)]
pub(super) struct QuotaTierInfo {
    tier: String,
    requests_per_hour: u64,
    price_cents: u64,
    price_usd: String,
    duration_days: i64,
    description: String,
}

/// Purchase quota request.
#[derive(Debug, Deserialize)]
pub(super) struct PurchaseQuotaRequest {
    tier: String,
}

/// Purchase quota response.
#[derive(Debug, Serialize)]
pub(super) struct PurchaseQuotaResponse {
    success: bool,
    purchase_id: Option<uuid::Uuid>,
    message: String,
    status: Option<String>,
}

/// Trending query parameters.
#[derive(Debug, Deserialize)]
pub(super) struct TrendingParams {
    limit: Option<usize>,
}

/// Get platform-wide statistics.
pub(super) async fn get_platform_stats(
    State(state): State<AppState>,
) -> Result<Json<PlatformStats>, (StatusCode, String)> {
    let total_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_nodes: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nodes")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_content: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM content WHERE status = 'ACTIVE'")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_transactions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM point_transactions")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_bandwidth: (Option<i64>,) =
        sqlx::query_as("SELECT SUM(total_bandwidth_bytes) FROM nodes")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_points: (Option<i64>,) =
        sqlx::query_as("SELECT SUM(amount) FROM point_transactions WHERE amount > 0")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let active_nodes: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM nodes WHERE last_seen_at > NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PlatformStats {
        total_users: total_users.0,
        total_nodes: total_nodes.0,
        total_content: total_content.0,
        total_transactions: total_transactions.0,
        total_bandwidth_bytes: total_bandwidth.0.unwrap_or(0),
        total_points_distributed: total_points.0.unwrap_or(0),
        active_nodes_24h: active_nodes.0,
    }))
}

/// Get content statistics.
pub(super) async fn get_content_stats(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ContentStats>, (StatusCode, String)> {
    // Check if content exists
    let content = ContentRepository::find_by_id(&state.db, id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Content not found".to_string()))?;

    let downloads: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT session_id) FROM bandwidth_proofs WHERE content_id = $1 AND status IN ('VERIFIED', 'REWARDED')",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let bytes_transferred: (Option<i64>,) = sqlx::query_as(
        "SELECT SUM(bytes_transferred) FROM bandwidth_proofs WHERE content_id = $1 AND status IN ('VERIFIED', 'REWARDED')",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let active_seeders: (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT n.id) FROM nodes n JOIN content_pins cp ON cp.node_id = n.id WHERE cp.content_id = $1 AND n.status = 'ONLINE'",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let avg_latency: (Option<f64>,) = sqlx::query_as(
        "SELECT AVG(latency_ms) FROM bandwidth_proofs WHERE content_id = $1 AND status IN ('VERIFIED', 'REWARDED')",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ContentStats {
        content_id: id,
        downloads: downloads.0,
        total_bytes_transferred: bytes_transferred.0.unwrap_or(0),
        total_revenue: content.total_revenue,
        active_seeders: active_seeders.0,
        avg_latency_ms: avg_latency.0.map(|v| v as i32),
    }))
}

/// Get node statistics.
pub(super) async fn get_node_stats(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<Json<NodeStats>, (StatusCode, String)> {
    let node = NodeRepository::find_by_peer_id(&state.db, &peer_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Node not found".to_string()))?;

    let total_transfers = node.successful_transfers + node.failed_transfers;
    let success_rate = if total_transfers > 0 {
        (node.successful_transfers as f64) / (total_transfers as f64) * 100.0
    } else {
        0.0
    };

    let uptime_hours = (node.uptime_seconds as f64) / 3600.0;

    Ok(Json(NodeStats {
        node_id: node.id,
        peer_id: node.peer_id,
        total_bandwidth_bytes: node.total_bandwidth_bytes,
        successful_transfers: node.successful_transfers,
        failed_transfers: node.failed_transfers,
        success_rate,
        total_earnings: node.total_earnings,
        reputation_score: node.reputation_score,
        uptime_hours,
    }))
}

/// Get authenticated user statistics.
pub(super) async fn get_user_stats(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<UserStats>, (StatusCode, String)> {
    let user_data = UserRepository::find_by_id(&state.db, user.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    let total_earned: (Option<i64>,) = sqlx::query_as(
        "SELECT SUM(amount) FROM point_transactions WHERE user_id = $1 AND amount > 0",
    )
    .bind(user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total_spent: (Option<i64>,) = sqlx::query_as(
        "SELECT SUM(ABS(amount)) FROM point_transactions WHERE user_id = $1 AND amount < 0",
    )
    .bind(user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let referral_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE referrer_id = $1")
            .bind(user.user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let content_created: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM content WHERE creator_id = $1")
            .bind(user.user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let nodes_registered: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nodes WHERE user_id = $1")
        .bind(user.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UserStats {
        user_id: user.user_id,
        points_balance: user_data.points_balance,
        total_earned: total_earned.0.unwrap_or(0),
        total_spent: total_spent.0.unwrap_or(0),
        referral_count: referral_count.0,
        content_created: content_created.0,
        nodes_registered: nodes_registered.0,
    }))
}

/// Get trending content.
pub(super) async fn get_trending_content(
    State(state): State<AppState>,
    Query(params): Query<TrendingParams>,
) -> Result<Json<Vec<crate::popularity::TrendingContent>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    let trending = state.popularity_tracker.get_trending(limit).await;
    Ok(Json(trending))
}

/// Get content popularity details.
pub(super) async fn get_content_popularity(
    State(state): State<AppState>,
    Path(content_id): Path<String>,
) -> Result<Json<crate::popularity::ContentStats>, (StatusCode, String)> {
    match state
        .popularity_tracker
        .get_content_stats(&content_id)
        .await
    {
        Some(stats) => Ok(Json(stats)),
        None => Err((
            StatusCode::NOT_FOUND,
            "Content not found or no popularity data available".to_string(),
        )),
    }
}

/// List available SDK languages.
pub(super) async fn list_sdk_languages() -> Json<Vec<SdkLanguageInfo>> {
    Json(vec![
        SdkLanguageInfo {
            language: "python".to_string(),
            display_name: "Python".to_string(),
            extension: "py".to_string(),
            package_manager: "pip".to_string(),
        },
        SdkLanguageInfo {
            language: "javascript".to_string(),
            display_name: "JavaScript".to_string(),
            extension: "js".to_string(),
            package_manager: "npm".to_string(),
        },
        SdkLanguageInfo {
            language: "typescript".to_string(),
            display_name: "TypeScript".to_string(),
            extension: "ts".to_string(),
            package_manager: "npm".to_string(),
        },
        SdkLanguageInfo {
            language: "rust".to_string(),
            display_name: "Rust".to_string(),
            extension: "rs".to_string(),
            package_manager: "cargo".to_string(),
        },
        SdkLanguageInfo {
            language: "go".to_string(),
            display_name: "Go".to_string(),
            extension: "go".to_string(),
            package_manager: "go".to_string(),
        },
    ])
}

/// Generate SDK for a specific language.
pub(super) async fn generate_sdk(
    Path(language): Path<String>,
) -> Result<Json<SdkResponse>, (StatusCode, String)> {
    use crate::sdk_generator::{SdkConfig, SdkGenerator, SdkLanguage};

    // Parse language parameter
    let sdk_language = match language.to_lowercase().as_str() {
        "python" => SdkLanguage::Python,
        "javascript" | "js" => SdkLanguage::JavaScript,
        "typescript" | "ts" => SdkLanguage::TypeScript,
        "rust" => SdkLanguage::Rust,
        "go" => SdkLanguage::Go,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Unsupported language: {}. Supported: python, javascript, typescript, rust, go",
                    language
                ),
            ));
        }
    };

    // Generate SDK
    let config = SdkConfig::default();
    let generator = SdkGenerator::new(config.clone());
    let code = generator.generate(sdk_language);

    let filename = format!("{}.{}", config.package_name, sdk_language.extension());

    Ok(Json(SdkResponse {
        language: language.to_lowercase(),
        code,
        filename,
    }))
}

/// Get available quota tiers.
pub(super) async fn get_quota_tiers_api() -> Json<Vec<QuotaTierInfo>> {
    use crate::rate_limit_quotas::QuotaTier;

    let tiers = vec![
        QuotaTier::Basic,
        QuotaTier::Standard,
        QuotaTier::Premium,
        QuotaTier::Enterprise,
    ];

    Json(
        tiers
            .into_iter()
            .map(|tier| QuotaTierInfo {
                tier: format!("{:?}", tier).to_lowercase(),
                requests_per_hour: tier.requests_per_hour(),
                price_cents: tier.price_cents(),
                price_usd: format!("${:.2}", tier.price_cents() as f64 / 100.0),
                duration_days: tier.duration_days(),
                description: tier.description().to_string(),
            })
            .collect(),
    )
}

/// Purchase a rate limit quota.
pub(super) async fn purchase_quota_api(
    axum::Extension(auth): axum::Extension<crate::AuthenticatedUser>,
    State(state): State<AppState>,
    Json(request): Json<PurchaseQuotaRequest>,
) -> Result<Json<PurchaseQuotaResponse>, (StatusCode, String)> {
    use crate::rate_limit_quotas::QuotaTier;

    // Parse tier
    let tier = match request.tier.to_lowercase().as_str() {
        "basic" => QuotaTier::Basic,
        "standard" => QuotaTier::Standard,
        "premium" => QuotaTier::Premium,
        "enterprise" => QuotaTier::Enterprise,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Invalid tier: {}. Valid options: basic, standard, premium, enterprise",
                    request.tier
                ),
            ));
        }
    };

    let price_cents = tier.price_cents();

    // Purchase quota (with auto-renew disabled by default, no payment_id for now)
    match state
        .quota_manager
        .purchase_quota(auth.user_id, tier, false, None)
        .await
    {
        Ok(purchase) => {
            crate::metrics::record_quota_purchased(&request.tier, price_cents);
            Ok(Json(PurchaseQuotaResponse {
                success: true,
                purchase_id: Some(purchase.id),
                message: format!("Quota purchased successfully: {}", tier.description()),
                status: Some(format!("{:?}", purchase.status).to_lowercase()),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to purchase quota: {}", e),
        )),
    }
}

/// Get user's current quota information.
pub(super) async fn get_my_quotas(
    axum::Extension(auth): axum::Extension<crate::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<crate::rate_limit_quotas::UserQuotaInfo> {
    let quota_info = state.quota_manager.get_user_quota(auth.user_id).await;
    Json(quota_info)
}

/// Get user's quota purchase history.
pub(super) async fn get_my_quota_history(
    axum::Extension(auth): axum::Extension<crate::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<Vec<crate::rate_limit_quotas::QuotaPurchase>> {
    let history = state.quota_manager.get_user_purchases(auth.user_id).await;
    Json(history)
}
