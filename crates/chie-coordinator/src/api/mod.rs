//! REST API endpoints for the coordinator.
//!
//! This module is split into focused sub-modules:
//! - `proofs`    — Bandwidth proof submission
//! - `core`      — User/node/content registration and CRUD
//! - `stats`     — Statistics, SDK generation, rate limit quotas
//! - `webhooks`  — Webhook management and email delivery stats
//! - `developer` — Postman collection, analytics, API version/changelog

pub mod core;
pub mod developer;
pub mod proofs;
pub mod stats;
pub mod webhooks;

// Re-export public types so callers can use `crate::api::ProofResponse` etc.
#[allow(unused_imports)]
pub use core::{
    ContentListQuery, ContentResponse, RecommendationQuery, RegisterContentRequest,
    RegisterNodeRequest, RegisterNodeResponse, RegisterUserRequest, RegisterUserResponse,
    TokenRequest, TokenResponse, TransactionQuery, UserInfo,
};
#[allow(unused_imports)]
pub use proofs::ProofResponse;
#[allow(unused_imports)]
pub use stats::{ContentStats, NodeStats, PlatformStats, UserStats};

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};

/// Validation error type.
pub(super) type ValidationResult<T> = Result<T, String>;

/// Validate email format.
pub(super) fn validate_email(email: &str) -> ValidationResult<()> {
    if email.is_empty() {
        return Err("Email cannot be empty".to_string());
    }
    if !email.contains('@') || !email.contains('.') {
        return Err("Invalid email format".to_string());
    }
    if email.len() > 255 {
        return Err("Email too long (max 255 characters)".to_string());
    }
    Ok(())
}

/// Validate username.
pub(super) fn validate_username(username: &str) -> ValidationResult<()> {
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }
    if username.len() < 3 {
        return Err("Username must be at least 3 characters".to_string());
    }
    if username.len() > 50 {
        return Err("Username too long (max 50 characters)".to_string());
    }
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Username can only contain alphanumeric characters, underscores, and hyphens"
                .to_string(),
        );
    }
    Ok(())
}

/// Validate password strength.
pub(super) fn validate_password(password: &str) -> ValidationResult<()> {
    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    if password.len() > 128 {
        return Err("Password too long (max 128 characters)".to_string());
    }
    Ok(())
}

/// Validate peer ID format.
pub(super) fn validate_peer_id(peer_id: &str) -> ValidationResult<()> {
    if peer_id.is_empty() {
        return Err("Peer ID cannot be empty".to_string());
    }
    if peer_id.len() < 10 || peer_id.len() > 100 {
        return Err("Invalid peer ID length".to_string());
    }
    Ok(())
}

/// Validate public key hex string.
pub(super) fn validate_public_key_hex(hex_str: &str) -> ValidationResult<()> {
    if hex_str.is_empty() {
        return Err("Public key cannot be empty".to_string());
    }
    if hex_str.len() != 64 {
        return Err("Public key must be 32 bytes (64 hex characters)".to_string());
    }
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Public key must be valid hexadecimal".to_string());
    }
    Ok(())
}

/// Build the API router.
pub fn router() -> Router<AppState> {
    Router::new()
        // Public endpoints
        .route("/proofs", post(proofs::submit_proof))
        .route("/users", post(core::register_user))
        .route("/nodes", post(core::register_node))
        .route("/auth/token", post(core::generate_token))
        .route("/content", get(core::list_content))
        .route("/content/:id", get(core::get_content))
        .route("/content/:id/seeders", get(core::get_content_seeders))
        .route("/content/:id/stats", get(stats::get_content_stats))
        .route("/nodes/:peer_id", get(core::get_node_info))
        .route("/nodes/:peer_id/stats", get(stats::get_node_stats))
        .route("/stats/platform", get(stats::get_platform_stats))
        .route("/trending", get(stats::get_trending_content))
        .route(
            "/content/:id/popularity",
            get(stats::get_content_popularity),
        )
        // SDK generation endpoints
        .route("/sdk/generate/:language", get(stats::generate_sdk))
        .route("/sdk/list", get(stats::list_sdk_languages))
        // Rate limit quota endpoints
        .route("/quotas/tiers", get(stats::get_quota_tiers_api))
        .route("/quotas/purchase", post(stats::purchase_quota_api))
        .route("/quotas/my", get(stats::get_my_quotas))
        .route("/quotas/my/history", get(stats::get_my_quota_history))
        // Authenticated endpoints
        .route("/content/register", post(core::register_content))
        .route("/me", get(core::get_current_user))
        .route("/me/stats", get(stats::get_user_stats))
        .route("/transactions", get(core::get_transactions))
        .route("/recommendations", get(core::get_content_recommendations))
        // Webhook management endpoints
        .route("/webhooks", post(webhooks::register_webhook_handler))
        .route("/webhooks", get(webhooks::list_webhooks_handler))
        .route("/webhooks/:id", get(webhooks::get_webhook_handler))
        .route(
            "/webhooks/:id",
            axum::routing::put(webhooks::update_webhook_handler),
        )
        .route(
            "/webhooks/:id",
            axum::routing::delete(webhooks::delete_webhook_handler),
        )
        .route(
            "/webhooks/:id/deliveries",
            get(webhooks::get_webhook_deliveries_handler),
        )
        .route(
            "/webhooks/:id/retry/:delivery_id",
            post(webhooks::retry_webhook_delivery_handler),
        )
        .route("/webhooks/stats", get(webhooks::get_webhook_stats_handler))
        .route(
            "/webhooks/config",
            get(webhooks::get_webhook_config_handler),
        )
        .route(
            "/webhooks/config",
            axum::routing::put(webhooks::update_webhook_config_handler),
        )
        // Email delivery statistics endpoints
        .route("/emails/stats", get(webhooks::get_email_stats_handler))
        .route("/emails/failed", get(webhooks::get_failed_emails_handler))
        .route("/emails/bounced", get(webhooks::get_bounced_emails_handler))
        .route(
            "/emails/unsubscribed",
            get(webhooks::get_unsubscribed_emails_handler),
        )
        .route("/emails/sla", get(webhooks::get_email_sla_handler))
        .route(
            "/emails/failed/:id",
            axum::routing::delete(webhooks::remove_failed_email_handler),
        )
        .route(
            "/emails/bounced/:email",
            axum::routing::delete(webhooks::remove_bounce_handler),
        )
        .route(
            "/emails/unsubscribed/:email",
            axum::routing::delete(webhooks::resubscribe_handler),
        )
        // Developer tools
        .route(
            "/postman/collection",
            get(developer::get_postman_collection_handler),
        )
        // Analytics dashboard endpoints
        .route(
            "/analytics/dashboard",
            get(developer::get_analytics_dashboard_handler),
        )
        .route(
            "/analytics/content/performance",
            get(developer::get_content_performance_handler),
        )
        .route(
            "/analytics/nodes/leaderboard",
            get(developer::get_node_leaderboard_handler),
        )
        .route(
            "/analytics/query",
            post(developer::execute_custom_analytics_query_handler),
        )
        .route(
            "/analytics/config",
            get(developer::get_analytics_config_handler),
        )
        .route(
            "/analytics/config",
            axum::routing::put(developer::update_analytics_config_handler),
        )
        // API version and changelog endpoints
        .route("/version", get(developer::get_api_version_handler))
        .route("/version/all", get(developer::get_all_versions_handler))
        .route("/changelog", get(developer::get_changelog_handler))
        .route(
            "/changelog/version/:version",
            get(developer::get_version_changelog_handler),
        )
        .route(
            "/changelog/category/:category",
            get(developer::get_category_changelog_handler),
        )
        // Gamification endpoints
        .nest("/v1/gamification", crate::gamification::router())
        // Referral endpoints
        .merge(crate::referral::router())
}
