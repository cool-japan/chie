//! API versioning, rate limit quotas, and request coalescing admin handlers.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::AppState;

/// Assemble operations-related routes.
pub fn operations_routes() -> Router<AppState> {
    Router::new()
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
}

// ============================================================================
// API Versioning
// ============================================================================

/// Request to deprecate an API version
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeprecateVersionRequest {
    /// Sunset date (ISO 8601 format)
    pub sunset_at: Option<String>,
    /// Reason for deprecation
    pub reason: Option<String>,
    /// Replacement version
    pub replacement_version: Option<String>,
}

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
            .unwrap_or_default(),
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
