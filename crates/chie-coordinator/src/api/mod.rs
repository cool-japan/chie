//! REST API endpoints for the coordinator.

use crate::db::{
    ContentRepository, CreateContent, CreateNode, CreateUser, NodeRepository, UserRepository,
};
use crate::rewards::InvestmentEngine;
use crate::{AppState, AuthenticatedUser};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chie_shared::BandwidthProof;
use serde::{Deserialize, Serialize};

/// Validation error type.
type ValidationResult<T> = Result<T, String>;

/// Validate email format.
fn validate_email(email: &str) -> ValidationResult<()> {
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
fn validate_username(username: &str) -> ValidationResult<()> {
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
fn validate_password(password: &str) -> ValidationResult<()> {
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
fn validate_peer_id(peer_id: &str) -> ValidationResult<()> {
    if peer_id.is_empty() {
        return Err("Peer ID cannot be empty".to_string());
    }
    if peer_id.len() < 10 || peer_id.len() > 100 {
        return Err("Invalid peer ID length".to_string());
    }
    Ok(())
}

/// Validate public key hex string.
fn validate_public_key_hex(hex_str: &str) -> ValidationResult<()> {
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
        .route("/proofs", post(submit_proof))
        .route("/users", post(register_user))
        .route("/nodes", post(register_node))
        .route("/auth/token", post(generate_token))
        .route("/content", get(list_content))
        .route("/content/:id", get(get_content))
        .route("/content/:id/seeders", get(get_content_seeders))
        .route("/content/:id/stats", get(get_content_stats))
        .route("/nodes/:peer_id", get(get_node_info))
        .route("/nodes/:peer_id/stats", get(get_node_stats))
        .route("/stats/platform", get(get_platform_stats))
        .route("/trending", get(get_trending_content))
        .route("/content/:id/popularity", get(get_content_popularity))
        // SDK generation endpoints
        .route("/sdk/generate/:language", get(generate_sdk))
        .route("/sdk/list", get(list_sdk_languages))
        // Rate limit quota endpoints
        .route("/quotas/tiers", get(get_quota_tiers_api))
        .route("/quotas/purchase", post(purchase_quota_api))
        .route("/quotas/my", get(get_my_quotas))
        .route("/quotas/my/history", get(get_my_quota_history))
        // Authenticated endpoints
        .route("/content/register", post(register_content))
        .route("/me", get(get_current_user))
        .route("/me/stats", get(get_user_stats))
        .route("/transactions", get(get_transactions))
        .route("/recommendations", get(get_content_recommendations))
        // Webhook management endpoints
        .route("/webhooks", post(register_webhook_handler))
        .route("/webhooks", get(list_webhooks_handler))
        .route("/webhooks/:id", get(get_webhook_handler))
        .route("/webhooks/:id", axum::routing::put(update_webhook_handler))
        .route(
            "/webhooks/:id",
            axum::routing::delete(delete_webhook_handler),
        )
        .route(
            "/webhooks/:id/deliveries",
            get(get_webhook_deliveries_handler),
        )
        .route(
            "/webhooks/:id/retry/:delivery_id",
            post(retry_webhook_delivery_handler),
        )
        .route("/webhooks/stats", get(get_webhook_stats_handler))
        .route("/webhooks/config", get(get_webhook_config_handler))
        .route(
            "/webhooks/config",
            axum::routing::put(update_webhook_config_handler),
        )
        // Email delivery statistics endpoints
        .route("/emails/stats", get(get_email_stats_handler))
        .route("/emails/failed", get(get_failed_emails_handler))
        .route("/emails/bounced", get(get_bounced_emails_handler))
        .route("/emails/unsubscribed", get(get_unsubscribed_emails_handler))
        .route("/emails/sla", get(get_email_sla_handler))
        .route(
            "/emails/failed/:id",
            axum::routing::delete(remove_failed_email_handler),
        )
        .route(
            "/emails/bounced/:email",
            axum::routing::delete(remove_bounce_handler),
        )
        .route(
            "/emails/unsubscribed/:email",
            axum::routing::delete(resubscribe_handler),
        )
        // Developer tools
        .route("/postman/collection", get(get_postman_collection_handler))
        // Analytics dashboard endpoints
        .route("/analytics/dashboard", get(get_analytics_dashboard_handler))
        .route(
            "/analytics/content/performance",
            get(get_content_performance_handler),
        )
        .route(
            "/analytics/nodes/leaderboard",
            get(get_node_leaderboard_handler),
        )
        .route(
            "/analytics/query",
            post(execute_custom_analytics_query_handler),
        )
        .route("/analytics/config", get(get_analytics_config_handler))
        .route(
            "/analytics/config",
            axum::routing::put(update_analytics_config_handler),
        )
        // API version and changelog endpoints
        .route("/version", get(get_api_version_handler))
        .route("/version/all", get(get_all_versions_handler))
        .route("/changelog", get(get_changelog_handler))
        .route(
            "/changelog/version/:version",
            get(get_version_changelog_handler),
        )
        .route(
            "/changelog/category/:category",
            get(get_category_changelog_handler),
        )
}

/// Response for proof submission.
#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub accepted: bool,
    pub reward: Option<u64>,
    pub message: String,
    pub quality_score: Option<f64>,
}

/// Submit a bandwidth proof for verification.
async fn submit_proof(
    State(state): State<AppState>,
    Json(proof): Json<BandwidthProof>,
) -> Result<Json<ProofResponse>, (StatusCode, String)> {
    tracing::info!(
        "Received proof: session={}, bytes={}",
        proof.session_id,
        proof.bytes_transferred
    );

    // Validate proof structure
    if let Err(errors) = proof.validate() {
        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: format!("Validation failed: {:?}", errors),
            quality_score: None,
        }));
    }

    // Validate timestamp against current time
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Err(e) = proof.validate_timestamp(now_ms) {
        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: format!("Timestamp validation failed: {}", e),
            quality_score: None,
        }));
    }

    // Run full verification pipeline
    let verification_result = match state.verification.verify_and_store(&proof).await {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Verification error: {}", e);
            return Ok(Json(ProofResponse {
                accepted: false,
                reward: None,
                message: format!("Verification error: {}", e),
                quality_score: None,
            }));
        }
    };

    // Check for critical anomalies (potential fraud)
    let has_critical_anomaly = verification_result
        .anomalies
        .iter()
        .any(|a| matches!(a.severity, crate::verification::Severity::Critical));

    if has_critical_anomaly {
        // Apply severe fraud penalty
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::FraudDetected,
                Some(serde_json::json!({
                    "anomalies": verification_result.anomalies.iter()
                        .map(|a| a.description.clone())
                        .collect::<Vec<_>>(),
                    "session_id": proof.session_id,
                })),
            )
            .await
        {
            tracing::error!("Failed to record fraud detection in reputation: {}", e);
        } else {
            // Record fraud-reputation integration metrics
            crate::metrics::record_fraud_reputation_integration("critical_anomaly", -50);

            tracing::warn!(
                "Fraud detected: peer_id={}, anomalies={:?}",
                proof.provider_peer_id,
                verification_result.anomalies
            );
        }
    }

    if !verification_result.is_valid {
        // Update reputation: proof verification failed
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::ProofFailed,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for failed proof: {}", e);
        } else {
            // Record metrics for failed proof
            crate::metrics::record_reputation_event("proof_failed", -10);
        }

        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: verification_result
                .rejection_reason
                .unwrap_or_else(|| "Proof rejected".to_string()),
            quality_score: Some(verification_result.quality_score),
        }));
    }

    // Get node reputation before update (for change detection)
    let old_reputation = state
        .reputation_manager
        .get_reputation(&proof.provider_peer_id)
        .await
        .ok()
        .flatten();

    // Update reputation: proof verification succeeded
    if let Err(e) = state
        .reputation_manager
        .record_event(
            proof.provider_peer_id.clone(),
            crate::node_reputation::ReputationEvent::ProofVerified,
            None,
        )
        .await
    {
        tracing::warn!("Failed to update reputation for verified proof: {}", e);
    } else {
        // Record metrics for successful reputation update
        crate::metrics::record_reputation_event("proof_verified", 5);
    }

    // Check for reputation changes and trigger webhooks if needed
    if let Ok(Some(new_reputation)) = state
        .reputation_manager
        .get_reputation(&proof.provider_peer_id)
        .await
    {
        // Trigger webhook if trust level degraded significantly
        if let Some(old_rep) = old_reputation {
            if new_reputation.trust_level < old_rep.trust_level {
                tracing::warn!(
                    "Node reputation degraded: peer_id={}, old={:?}, new={:?}",
                    proof.provider_peer_id,
                    old_rep.trust_level,
                    new_reputation.trust_level
                );

                // Record trust level change metric
                crate::metrics::record_trust_level_change(
                    old_rep.trust_level.as_str(),
                    new_reputation.trust_level.as_str(),
                );

                // Trigger webhook for health degradation
                let payload = serde_json::json!({
                    "peer_id": proof.provider_peer_id,
                    "old_trust_level": old_rep.trust_level.as_str(),
                    "new_trust_level": new_reputation.trust_level.as_str(),
                    "old_score": old_rep.score,
                    "new_score": new_reputation.score,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                state
                    .webhook_manager
                    .trigger_event(crate::WebhookEvent::HealthDegraded, payload)
                    .await;
            }

            // Trigger webhook if node became untrusted
            if new_reputation.trust_level == crate::node_reputation::TrustLevel::Untrusted
                && old_rep.trust_level != crate::node_reputation::TrustLevel::Untrusted
            {
                let payload = serde_json::json!({
                    "peer_id": proof.provider_peer_id,
                    "trust_level": new_reputation.trust_level.as_str(),
                    "score": new_reputation.score,
                    "reason": "reputation_too_low",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                state
                    .webhook_manager
                    .trigger_event(crate::WebhookEvent::NodeSuspended, payload)
                    .await;
            }
        }

        // Record reputation score distribution
        crate::metrics::record_reputation_score(new_reputation.score);
    }

    // Additional reputation updates based on quality and transfer speed
    let duration_secs = proof.latency_ms as f64 / 1000.0;
    let speed_mbps = if duration_secs > 0.0 {
        (proof.bytes_transferred as f64) / duration_secs / (1024.0 * 1024.0)
    } else {
        0.0
    };

    // High quality bandwidth (quality > 0.95 and speed > 50 MB/s)
    if verification_result.quality_score > 0.95 && speed_mbps > 50.0 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::HighQualityBandwidth,
                None,
            )
            .await
        {
            tracing::warn!(
                "Failed to update reputation for high quality bandwidth: {}",
                e
            );
        }
    }
    // Low quality bandwidth (quality < 0.5 or very slow speed)
    else if verification_result.quality_score < 0.5
        || (speed_mbps < 1.0 && proof.bytes_transferred > 1_000_000)
    {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::LowQualityBandwidth,
                None,
            )
            .await
        {
            tracing::warn!(
                "Failed to update reputation for low quality bandwidth: {}",
                e
            );
        }
    }

    // Fast transfer (latency < 100ms and reasonable size)
    if proof.latency_ms < 100 && proof.bytes_transferred > 100_000 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::FastTransfer,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for fast transfer: {}", e);
        }
    }
    // Slow transfer (latency > 1000ms for small file)
    else if proof.latency_ms > 1000 && proof.bytes_transferred < 10_000_000 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::SlowTransfer,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for slow transfer: {}", e);
        }
    }

    // Lookup provider and content info for reward calculation
    let provider_user =
        match UserRepository::find_by_peer_id(&state.db, &proof.provider_peer_id).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                tracing::warn!("Provider not found for peer_id: {}", proof.provider_peer_id);
                return Ok(Json(ProofResponse {
                    accepted: true,
                    reward: None,
                    message: "Proof verified but provider not registered".to_string(),
                    quality_score: Some(verification_result.quality_score),
                }));
            }
            Err(e) => {
                tracing::error!("Database error looking up provider: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                ));
            }
        };

    let content = match ContentRepository::find_by_cid(&state.db, &proof.content_cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!("Content not found for cid: {}", proof.content_cid);
            return Ok(Json(ProofResponse {
                accepted: true,
                reward: None,
                message: "Proof verified but content not registered".to_string(),
                quality_score: Some(verification_result.quality_score),
            }));
        }
        Err(e) => {
            tracing::error!("Database error looking up content: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ));
        }
    };

    // Calculate and distribute rewards
    let distribution = match state
        .rewards
        .calculate_and_distribute(
            &proof,
            proof.session_id,
            verification_result.quality_score,
            provider_user.id,
            content.creator_id,
        )
        .await
    {
        Ok(dist) => dist,
        Err(e) => {
            tracing::error!("Reward calculation error: {}", e);
            return Ok(Json(ProofResponse {
                accepted: true,
                reward: None,
                message: format!("Proof verified but reward calculation failed: {}", e),
                quality_score: Some(verification_result.quality_score),
            }));
        }
    };

    // Update node transfer stats
    if let Ok(Some(node)) =
        NodeRepository::find_by_peer_id(&state.db, &proof.provider_peer_id).await
    {
        if let Err(e) = NodeRepository::record_transfer(
            &state.db,
            node.id,
            proof.bytes_transferred as i64,
            true,
        )
        .await
        {
            tracing::warn!("Failed to record node transfer stats: {}", e);
        }
    }

    Ok(Json(ProofResponse {
        accepted: true,
        reward: Some(distribution.provider_reward),
        message: format!(
            "Proof verified and rewarded. Total: {} points (provider: {}, creator: {})",
            distribution.total_distributed,
            distribution.provider_reward,
            distribution.creator_reward
        ),
        quality_score: Some(verification_result.quality_score),
    }))
}

/// Request to register new content.
#[derive(Debug, Deserialize)]
pub struct RegisterContentRequest {
    pub cid: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub size_bytes: u64,
    pub price: u64,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Response for content registration.
#[derive(Debug, Serialize)]
pub struct ContentResponse {
    pub success: bool,
    pub content_id: Option<uuid::Uuid>,
    pub message: String,
}

/// Register new content (requires authentication).
async fn register_content(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(request): Json<RegisterContentRequest>,
) -> Result<Json<ContentResponse>, (StatusCode, String)> {
    use crate::db::ContentCategory;

    tracing::info!(
        "User {} registering content: cid={}, title={}",
        user.user_id,
        request.cid,
        request.title
    );

    // Parse category
    let category = match request.category.as_deref() {
        Some("3D_MODELS") | Some("THREE_D_MODELS") => ContentCategory::ThreeDModels,
        Some("TEXTURES") => ContentCategory::Textures,
        Some("AUDIO") => ContentCategory::Audio,
        Some("SCRIPTS") => ContentCategory::Scripts,
        Some("ANIMATIONS") => ContentCategory::Animations,
        Some("ASSET_PACKS") => ContentCategory::AssetPacks,
        Some("AI_MODELS") => ContentCategory::AiModels,
        _ => ContentCategory::Other,
    };

    // Calculate chunk count
    let chunk_size = chie_shared::CHUNK_SIZE as u64;
    let chunk_count = request.size_bytes.div_ceil(chunk_size) as i32;

    // Check content moderation rules (will auto-flag if rules are violated)
    // Note: We check this before content creation, but actual flagging happens after
    // content is created (since we need the content_id)

    // Create content record
    let create_content = CreateContent {
        creator_id: user.user_id,
        title: request.title.clone(),
        description: if request.description.is_empty() {
            None
        } else {
            Some(request.description.clone())
        },
        category,
        tags: request.tags.clone(),
        cid: request.cid.clone(),
        size_bytes: request.size_bytes as i64,
        chunk_count,
        encryption_key: None, // Will be set by encryption worker
        price: request.price as i64,
    };

    match ContentRepository::create(&state.db, create_content).await {
        Ok(content) => {
            tracing::info!("Content created: id={}, cid={}", content.id, content.cid);

            // Check if creator has low reputation and auto-flag if needed
            if let Some(peer_id) = &user.peer_id {
                if let Ok(Some(reputation)) = state.reputation_manager.get_reputation(peer_id).await
                {
                    // Auto-flag content from untrusted or low trust nodes
                    if reputation.trust_level == crate::node_reputation::TrustLevel::Untrusted
                        || reputation.trust_level == crate::node_reputation::TrustLevel::Low
                    {
                        tracing::warn!(
                            "Auto-flagging content from low-trust node: peer_id={}, trust_level={:?}, content_id={}",
                            peer_id,
                            reputation.trust_level,
                            content.id
                        );

                        // Create a flag for low reputation
                        if let Err(e) = state
                            .moderation_manager
                            .flag_content(
                                content.id.to_string(),
                                crate::content_moderation::FlagReason::AutomatedRule,
                                Some(format!(
                                    "Content from low-trust node (trust_level: {:?}, score: {})",
                                    reputation.trust_level, reputation.score
                                )),
                                None,     // reporter_id (system flag)
                                Some(70), // severity (high enough to trigger review)
                            )
                            .await
                        {
                            tracing::warn!("Failed to flag content from low-trust node: {}", e);
                        } else {
                            // Record metrics for low reputation auto-flag
                            crate::metrics::record_auto_flag_low_reputation(
                                reputation.trust_level.as_str(),
                            );
                            crate::metrics::record_content_flag("automated_rule", 70);
                            crate::metrics::record_reputation_moderation_integration(
                                "auto_flag_low_trust",
                            );

                            // Log audit event
                            state
                                .audit_logger
                                .log_event(
                                    crate::AuditSeverity::Warning,
                                    crate::AuditCategory::Security,
                                    "content_flagged_low_reputation",
                                )
                                .await
                                .actor("system".to_string())
                                .resource("content", content.id.to_string())
                                .details(
                                    serde_json::json!({
                                        "peer_id": peer_id,
                                        "trust_level": reputation.trust_level.as_str(),
                                        "score": reputation.score,
                                        "cid": content.cid,
                                    })
                                    .to_string(),
                                )
                                .submit()
                                .await;

                            // Trigger webhook
                            state
                                .webhook_manager
                                .trigger_event(
                                    crate::WebhookEvent::ContentFlagged,
                                    serde_json::json!({
                                        "content_id": content.id.to_string(),
                                        "cid": content.cid,
                                        "creator_id": user.user_id.to_string(),
                                        "peer_id": peer_id,
                                        "trust_level": reputation.trust_level.as_str(),
                                        "score": reputation.score,
                                        "reason": "low_reputation_node",
                                        "timestamp": chrono::Utc::now().to_rfc3339(),
                                    }),
                                )
                                .await;
                        }
                    }
                }
            }

            // Check content moderation rules and auto-flag if needed
            match state
                .moderation_manager
                .check_content(
                    content.id.to_string(),
                    Some(request.size_bytes),
                    None, // content_type not available in this API
                    Some(user.user_id),
                )
                .await
            {
                Ok(flags) if !flags.is_empty() => {
                    tracing::warn!(
                        "Content auto-flagged by moderation: content_id={}, flags={:?}",
                        content.id,
                        flags
                    );

                    // Log audit event for auto-flagging
                    state
                        .audit_logger
                        .log_event(
                            crate::AuditSeverity::Warning,
                            crate::AuditCategory::Content,
                            "content_auto_flagged",
                        )
                        .await
                        .actor(user.user_id.to_string())
                        .resource("content", content.id.to_string())
                        .details(
                            serde_json::json!({
                                "cid": content.cid,
                                "size_bytes": request.size_bytes,
                                "flag_count": flags.len(),
                            })
                            .to_string(),
                        )
                        .submit()
                        .await;

                    // Trigger webhook for content flagged
                    let webhook_payload = serde_json::json!({
                        "content_id": content.id.to_string(),
                        "cid": content.cid,
                        "creator_id": user.user_id.to_string(),
                        "size_bytes": request.size_bytes,
                        "flag_count": flags.len(),
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    });

                    state
                        .webhook_manager
                        .trigger_event(crate::WebhookEvent::ContentFlagged, webhook_payload)
                        .await;
                }
                Ok(_) => {
                    // No flags created, content is clean
                }
                Err(e) => {
                    tracing::warn!("Failed to check content moderation: {}", e);
                }
            }

            Ok(Json(ContentResponse {
                success: true,
                content_id: Some(content.id),
                message: "Content registered successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to create content: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create content: {}", e),
            ))
        }
    }
}

/// Get current user info (requires authentication).
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub user_id: uuid::Uuid,
    pub peer_id: Option<String>,
    pub role: String,
}

async fn get_current_user(user: AuthenticatedUser) -> Json<UserInfo> {
    Json(UserInfo {
        user_id: user.user_id,
        peer_id: user.peer_id,
        role: user.role,
    })
}

/// Token generation request.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub user_id: uuid::Uuid,
    pub peer_id: Option<String>,
    pub role: String,
}

/// Token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: i64,
}

/// Generate a JWT token (for development/testing).
async fn generate_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, crate::auth::AuthError> {
    let token = state
        .jwt
        .generate_token(request.user_id, request.peer_id, &request.role)?;

    Ok(Json(TokenResponse {
        token,
        expires_in: 24 * 3600, // 24 hours in seconds
    }))
}

/// User registration request.
#[derive(Debug, Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub referral_code: Option<String>,
}

/// User registration response.
#[derive(Debug, Serialize)]
pub struct RegisterUserResponse {
    pub success: bool,
    pub user_id: Option<uuid::Uuid>,
    pub message: String,
}

/// Register a new user.
async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, (StatusCode, String)> {
    use crate::db::UserRole;

    // Validate inputs
    validate_username(&request.username).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_email(&request.email).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_password(&request.password).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Hash password (in production, use bcrypt or argon2)
    let password_hash = format!("hashed_{}", request.password);

    // Lookup referrer if referral code provided
    let referrer_id = if let Some(ref_code) = request.referral_code {
        match sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE referral_code = $1")
            .bind(&ref_code)
            .fetch_optional(&state.db)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("Failed to lookup referral code: {}", e);
                None
            }
        }
    } else {
        None
    };

    let create_user = CreateUser {
        username: request.username,
        email: request.email,
        password_hash,
        role: UserRole::User,
        referrer_id,
    };

    match UserRepository::create(&state.db, create_user).await {
        Ok(user) => {
            tracing::info!(
                "User registered: id={}, username={}",
                user.id,
                user.username
            );
            Ok(Json(RegisterUserResponse {
                success: true,
                user_id: Some(user.id),
                message: "User registered successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create user: {}", e),
            ))
        }
    }
}

/// Node registration request.
#[derive(Debug, Deserialize)]
pub struct RegisterNodeRequest {
    pub user_id: uuid::Uuid,
    pub peer_id: String,
    pub public_key: String,
    pub max_storage_gb: u64,
    pub max_bandwidth_mbps: u64,
}

/// Node registration response.
#[derive(Debug, Serialize)]
pub struct RegisterNodeResponse {
    pub success: bool,
    pub node_id: Option<uuid::Uuid>,
    pub message: String,
}

/// Register a new node.
async fn register_node(
    State(state): State<AppState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<RegisterNodeResponse>, (StatusCode, String)> {
    // Validate inputs
    validate_peer_id(&request.peer_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_public_key_hex(&request.public_key).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if request.max_storage_gb == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Storage capacity must be greater than 0".to_string(),
        ));
    }
    if request.max_bandwidth_mbps == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Bandwidth capacity must be greater than 0".to_string(),
        ));
    }

    // Decode public key from hex
    let public_key = hex::decode(&request.public_key).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key hex: {}", e),
        )
    })?;

    let create_node = CreateNode {
        user_id: request.user_id,
        peer_id: request.peer_id.clone(),
        public_key,
        max_storage_bytes: (request.max_storage_gb * 1024 * 1024 * 1024) as i64,
        max_bandwidth_bps: (request.max_bandwidth_mbps * 1_000_000) as i64,
    };

    match NodeRepository::create(&state.db, create_node).await {
        Ok(node) => {
            tracing::info!(
                "Node registered: id={}, peer_id={}",
                node.id,
                request.peer_id
            );
            Ok(Json(RegisterNodeResponse {
                success: true,
                node_id: Some(node.id),
                message: "Node registered successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to register node: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to register node: {}", e),
            ))
        }
    }
}

/// Content list query parameters.
#[derive(Debug, Deserialize)]
pub struct ContentListQuery {
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List content with optional filters.
async fn list_content(
    State(state): State<AppState>,
    Query(query): Query<ContentListQuery>,
) -> Result<Json<Vec<crate::db::Content>>, (StatusCode, String)> {
    use crate::db::ContentCategory;

    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0);

    let sql = if let Some(cat) = query.category {
        let category = match cat.as_str() {
            "3D_MODELS" | "THREE_D_MODELS" => ContentCategory::ThreeDModels,
            "TEXTURES" => ContentCategory::Textures,
            "AUDIO" => ContentCategory::Audio,
            "SCRIPTS" => ContentCategory::Scripts,
            "ANIMATIONS" => ContentCategory::Animations,
            "ASSET_PACKS" => ContentCategory::AssetPacks,
            "AI_MODELS" => ContentCategory::AiModels,
            _ => ContentCategory::Other,
        };

        sqlx::query_as(
            "SELECT * FROM content WHERE status = 'ACTIVE' AND category = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(category)
        .bind(limit)
        .bind(offset)
    } else {
        sqlx::query_as(
            "SELECT * FROM content WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
    };

    match sql.fetch_all(&state.db).await {
        Ok(content) => Ok(Json(content)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )),
    }
}

/// Get content by ID.
async fn get_content(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::db::Content>, (StatusCode, String)> {
    match ContentRepository::find_by_id(&state.db, id).await {
        Ok(Some(content)) => {
            // Track content view for popularity
            state
                .popularity_tracker
                .record_access(
                    &content.id.to_string(),
                    crate::popularity::AccessEvent::View,
                    0, // No bandwidth tracked for metadata view
                    None,
                )
                .await;

            Ok(Json(content))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "Content not found".to_string())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )),
    }
}

/// Get seeders for content.
async fn get_content_seeders(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Vec<crate::db::Node>>, (StatusCode, String)> {
    match NodeRepository::get_seeders_for_content(&state.db, id).await {
        Ok(nodes) => Ok(Json(nodes)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )),
    }
}

/// Get node info by peer ID.
async fn get_node_info(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Result<Json<crate::db::Node>, (StatusCode, String)> {
    match NodeRepository::find_by_peer_id(&state.db, &peer_id).await {
        Ok(Some(node)) => Ok(Json(node)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Node not found".to_string())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )),
    }
}

/// Transaction history query parameters.
#[derive(Debug, Deserialize)]
pub struct TransactionQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Get transaction history for authenticated user.
async fn get_transactions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<TransactionQuery>,
) -> Result<Json<Vec<crate::db::PointTransaction>>, (StatusCode, String)> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    match sqlx::query_as(
        "SELECT * FROM point_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(user.user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    {
        Ok(transactions) => Ok(Json(transactions)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )),
    }
}

/// Content recommendation query.
#[derive(Debug, Deserialize)]
pub struct RecommendationQuery {
    #[serde(default = "default_storage_gb")]
    pub storage_gb: f64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_storage_gb() -> f64 {
    100.0
}

fn default_limit() -> usize {
    10
}

/// Get content pinning recommendations.
async fn get_content_recommendations(
    Query(query): Query<RecommendationQuery>,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::rewards::ContentRecommendation>>, (StatusCode, String)> {
    use std::sync::Arc;

    let engine = InvestmentEngine::new(Arc::new(state.db.clone()));

    match engine
        .get_recommendations(query.storage_gb, query.limit)
        .await
    {
        Ok(recommendations) => Ok(Json(recommendations)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get recommendations: {}", e),
        )),
    }
}

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

/// Get platform-wide statistics.
async fn get_platform_stats(
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

/// Get content statistics.
async fn get_content_stats(
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

/// Get node statistics.
async fn get_node_stats(
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

/// Get authenticated user statistics.
async fn get_user_stats(
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
async fn get_trending_content(
    State(state): State<AppState>,
    Query(params): Query<TrendingParams>,
) -> Result<Json<Vec<crate::popularity::TrendingContent>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    let trending = state.popularity_tracker.get_trending(limit).await;
    Ok(Json(trending))
}

/// Trending query parameters.
#[derive(Debug, Deserialize)]
struct TrendingParams {
    limit: Option<usize>,
}

/// Get content popularity details.
async fn get_content_popularity(
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

/// SDK generation response.
#[derive(Debug, Serialize)]
struct SdkResponse {
    language: String,
    code: String,
    filename: String,
}

/// List available SDK languages.
async fn list_sdk_languages() -> Json<Vec<SdkLanguageInfo>> {
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

/// SDK language information.
#[derive(Debug, Serialize)]
struct SdkLanguageInfo {
    language: String,
    display_name: String,
    extension: String,
    package_manager: String,
}

/// Generate SDK for a specific language.
async fn generate_sdk(
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

/// Quota tier information for API response.
#[derive(Debug, Serialize)]
struct QuotaTierInfo {
    tier: String,
    requests_per_hour: u64,
    price_cents: u64,
    price_usd: String,
    duration_days: i64,
    description: String,
}

/// Get available quota tiers.
async fn get_quota_tiers_api() -> Json<Vec<QuotaTierInfo>> {
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

/// Purchase quota request.
#[derive(Debug, Deserialize)]
struct PurchaseQuotaRequest {
    tier: String,
}

/// Purchase quota response.
#[derive(Debug, Serialize)]
struct PurchaseQuotaResponse {
    success: bool,
    purchase_id: Option<uuid::Uuid>,
    message: String,
    status: Option<String>,
}

/// Purchase a rate limit quota.
async fn purchase_quota_api(
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
async fn get_my_quotas(
    axum::Extension(auth): axum::Extension<crate::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<crate::rate_limit_quotas::UserQuotaInfo> {
    let quota_info = state.quota_manager.get_user_quota(auth.user_id).await;
    Json(quota_info)
}

/// Get user's quota purchase history.
async fn get_my_quota_history(
    axum::Extension(auth): axum::Extension<crate::AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<Vec<crate::rate_limit_quotas::QuotaPurchase>> {
    let history = state.quota_manager.get_user_purchases(auth.user_id).await;
    Json(history)
}

// ==================== Webhook Management Endpoints ====================

/// Request to register a new webhook.
#[derive(Debug, Deserialize)]
struct RegisterWebhookRequest {
    url: String,
    secret: Option<String>,
    events: Vec<crate::webhooks::WebhookEvent>,
    headers: Option<std::collections::HashMap<String, String>>,
    timeout_ms: Option<u64>,
    max_retries: Option<u32>,
}

/// Response for webhook registration.
#[derive(Debug, Serialize)]
struct WebhookResponse {
    id: uuid::Uuid,
    webhook: crate::webhooks::WebhookEndpoint,
}

/// Register a new webhook endpoint.
async fn register_webhook_handler(
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
async fn list_webhooks_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::webhooks::WebhookEndpoint>> {
    let webhooks = state.webhook_manager.list_webhooks().await;
    Json(webhooks)
}

/// Get a specific webhook by ID.
async fn get_webhook_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::webhooks::WebhookEndpoint>, StatusCode> {
    match state.webhook_manager.get_webhook(id).await {
        Some(webhook) => Ok(Json(webhook)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Update an existing webhook.
async fn update_webhook_handler(
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
async fn delete_webhook_handler(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.webhook_manager.unregister_webhook(id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((StatusCode::NOT_FOUND, e)),
    }
}

/// Query parameters for delivery history.
#[derive(Debug, Deserialize)]
struct DeliveryHistoryQuery {
    limit: Option<usize>,
    failed_only: Option<bool>,
}

/// Get delivery history for a specific webhook.
async fn get_webhook_deliveries_handler(
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
async fn retry_webhook_delivery_handler(
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
async fn get_webhook_stats_handler(
    State(state): State<AppState>,
) -> Json<crate::webhooks::WebhookStats> {
    let stats = state.webhook_manager.get_stats().await;
    Json(stats)
}

/// Get webhook system configuration.
async fn get_webhook_config_handler(
    State(state): State<AppState>,
) -> Json<crate::webhooks::WebhookConfig> {
    let config = state.webhook_manager.get_config().await;
    Json(config)
}

/// Update webhook system configuration.
async fn update_webhook_config_handler(
    State(state): State<AppState>,
    Json(config): Json<crate::webhooks::WebhookConfig>,
) -> StatusCode {
    state.webhook_manager.update_config(config).await;
    StatusCode::NO_CONTENT
}

// ==================== Email Delivery Statistics Endpoints ====================

/// Email delivery statistics response.
#[derive(Debug, Serialize)]
struct EmailStatsResponse {
    total_sent: u64,
    total_failed: u64,
    total_bounced: u64,
    total_unsubscribed: u64,
    retry_queue_size: usize,
    success_rate: f64,
}

/// Get email delivery statistics.
async fn get_email_stats_handler(State(state): State<AppState>) -> Json<EmailStatsResponse> {
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
async fn get_failed_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::FailedEmail>> {
    let failed_emails = state.alerting_manager.get_failed_emails().await;
    Json(failed_emails)
}

/// Get bounced email addresses.
async fn get_bounced_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::EmailBounce>> {
    let bounced = state.alerting_manager.get_all_bounces().await;
    Json(bounced)
}

/// Get unsubscribed email addresses.
async fn get_unsubscribed_emails_handler(
    State(state): State<AppState>,
) -> Json<Vec<crate::alerting::EmailUnsubscribe>> {
    let unsubscribed = state.alerting_manager.get_unsubscribed_emails().await;
    Json(unsubscribed)
}

/// Get email SLA metrics.
async fn get_email_sla_handler(
    State(state): State<AppState>,
) -> Json<crate::alerting::EmailSlaMetrics> {
    let sla_metrics = state.alerting_manager.get_sla_metrics().await;
    Json(sla_metrics)
}

/// Remove a failed email from retry queue.
async fn remove_failed_email_handler(
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
async fn remove_bounce_handler(
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
async fn resubscribe_handler(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if state.alerting_manager.resubscribe_email(&email).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// ==================== Developer Tools ====================

/// Generate Postman Collection v2.1 JSON.
async fn get_postman_collection_handler() -> Json<serde_json::Value> {
    let collection = serde_json::json!({
        "info": {
            "name": "CHIE Coordinator API",
            "description": "CHIE Protocol Coordinator API - Bandwidth proof verification and reward distribution",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "version": "0.1.0"
        },
        "variable": [
            {
                "key": "base_url",
                "value": "http://localhost:8080/api",
                "type": "string"
            },
            {
                "key": "auth_token",
                "value": "",
                "type": "string"
            }
        ],
        "auth": {
            "type": "bearer",
            "bearer": [
                {
                    "key": "token",
                    "value": "{{auth_token}}",
                    "type": "string"
                }
            ]
        },
        "item": [
            {
                "name": "Authentication",
                "item": [
                    {
                        "name": "Generate Token",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/auth/token",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"email\": \"user@example.com\", \"password\": \"password123\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Users",
                "item": [
                    {
                        "name": "Register User",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/users",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"email\": \"user@example.com\", \"username\": \"testuser\", \"password\": \"SecurePass123!\"}"
                            }
                        }
                    },
                    {
                        "name": "Get Current User",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/me"
                        }
                    },
                    {
                        "name": "Get User Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/me/stats"
                        }
                    }
                ]
            },
            {
                "name": "Nodes",
                "item": [
                    {
                        "name": "Register Node",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/nodes",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"peer_id\": \"12D3KooWABC123\", \"public_key\": \"abcdef1234567890\", \"bandwidth_capacity\": 1000000000}"
                            }
                        }
                    },
                    {
                        "name": "Get Node Info",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/nodes/:peer_id"
                        }
                    },
                    {
                        "name": "Get Node Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/nodes/:peer_id/stats"
                        }
                    }
                ]
            },
            {
                "name": "Content",
                "item": [
                    {
                        "name": "List Content",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": {
                                "raw": "{{base_url}}/content?category=video&page=1&limit=20",
                                "host": ["{{base_url}}"],
                                "path": ["content"],
                                "query": [
                                    {"key": "category", "value": "video"},
                                    {"key": "page", "value": "1"},
                                    {"key": "limit", "value": "20"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Get Content Details",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id"
                        }
                    },
                    {
                        "name": "Register Content",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/content/register",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"title\": \"My Video\", \"content_id\": \"QmABC123\", \"size\": 1000000, \"category\": \"video\"}"
                            }
                        }
                    },
                    {
                        "name": "Get Content Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/stats"
                        }
                    },
                    {
                        "name": "Get Content Seeders",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/seeders"
                        }
                    },
                    {
                        "name": "Get Trending Content",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/trending"
                        }
                    },
                    {
                        "name": "Get Content Popularity",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/popularity"
                        }
                    }
                ]
            },
            {
                "name": "Bandwidth Proofs",
                "item": [
                    {
                        "name": "Submit Proof",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/proofs",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"requester_id\": \"12D3KooWREQ\", \"provider_id\": \"12D3KooWPROV\", \"content_id\": \"QmABC123\", \"bytes_transferred\": 1048576, \"timestamp\": 1234567890, \"nonce\": \"abc123\", \"requester_signature\": \"sig1\", \"provider_signature\": \"sig2\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Statistics",
                "item": [
                    {
                        "name": "Platform Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/stats/platform"
                        }
                    }
                ]
            },
            {
                "name": "Transactions",
                "item": [
                    {
                        "name": "Get User Transactions",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/transactions"
                        }
                    }
                ]
            },
            {
                "name": "Recommendations",
                "item": [
                    {
                        "name": "Get Content Recommendations",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/recommendations"
                        }
                    }
                ]
            },
            {
                "name": "Rate Limit Quotas",
                "item": [
                    {
                        "name": "Get Quota Tiers",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/tiers"
                        }
                    },
                    {
                        "name": "Purchase Quota",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/quotas/purchase",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"tier_id\": \"premium\", \"duration_days\": 30}"
                            }
                        }
                    },
                    {
                        "name": "Get My Quotas",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/my"
                        }
                    },
                    {
                        "name": "Get My Quota History",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/my/history"
                        }
                    }
                ]
            },
            {
                "name": "Webhooks",
                "item": [
                    {
                        "name": "Register Webhook",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"url\": \"https://example.com/webhook\", \"events\": [\"fraud_detected\", \"node_suspended\"], \"secret\": \"webhook_secret\", \"max_retries\": 3}"
                            }
                        }
                    },
                    {
                        "name": "List Webhooks",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks"
                        }
                    },
                    {
                        "name": "Get Webhook",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id"
                        }
                    },
                    {
                        "name": "Update Webhook",
                        "request": {
                            "method": "PUT",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks/:id",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"url\": \"https://example.com/webhook\", \"events\": [\"fraud_detected\"], \"active\": true}"
                            }
                        }
                    },
                    {
                        "name": "Delete Webhook",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id"
                        }
                    },
                    {
                        "name": "Get Webhook Deliveries",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": {
                                "raw": "{{base_url}}/webhooks/:id/deliveries?limit=50&failed_only=false",
                                "host": ["{{base_url}}"],
                                "path": ["webhooks", ":id", "deliveries"],
                                "query": [
                                    {"key": "limit", "value": "50"},
                                    {"key": "failed_only", "value": "false"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Retry Webhook Delivery",
                        "request": {
                            "method": "POST",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id/retry/:delivery_id"
                        }
                    },
                    {
                        "name": "Get Webhook Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/stats"
                        }
                    },
                    {
                        "name": "Get Webhook Config",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/config"
                        }
                    },
                    {
                        "name": "Update Webhook Config",
                        "request": {
                            "method": "PUT",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks/config",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"max_concurrent\": 100, \"default_timeout_ms\": 5000, \"default_max_retries\": 3}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Email Delivery",
                "item": [
                    {
                        "name": "Get Email Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/stats"
                        }
                    },
                    {
                        "name": "Get Failed Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/failed"
                        }
                    },
                    {
                        "name": "Get Bounced Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/bounced"
                        }
                    },
                    {
                        "name": "Get Unsubscribed Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/unsubscribed"
                        }
                    },
                    {
                        "name": "Get Email SLA Metrics",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/sla"
                        }
                    },
                    {
                        "name": "Remove Failed Email",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/failed/:id"
                        }
                    },
                    {
                        "name": "Remove Bounce",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/bounced/:email"
                        }
                    },
                    {
                        "name": "Resubscribe Email",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/unsubscribed/:email"
                        }
                    }
                ]
            },
            {
                "name": "SDK",
                "item": [
                    {
                        "name": "Generate SDK",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/sdk/generate/:language"
                        }
                    },
                    {
                        "name": "List SDK Languages",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/sdk/list"
                        }
                    }
                ]
            }
        ]
    });

    Json(collection)
}

// ==================== Analytics Dashboard Endpoints ====================

/// Get dashboard metrics summary.
async fn get_analytics_dashboard_handler(
    State(state): State<AppState>,
) -> Result<Json<crate::analytics::DashboardMetrics>, (StatusCode, String)> {
    match state.analytics_manager.get_dashboard_metrics().await {
        Ok(metrics) => Ok(Json(metrics)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get dashboard metrics: {}", e),
        )),
    }
}

/// Query parameters for content performance.
#[derive(Debug, Deserialize)]
struct ContentPerformanceQuery {
    content_id: Option<uuid::Uuid>,
    time_range: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Get content performance analytics.
async fn get_content_performance_handler(
    State(state): State<AppState>,
    Query(query): Query<ContentPerformanceQuery>,
) -> Result<Json<Vec<crate::analytics::ContentPerformance>>, (StatusCode, String)> {
    // Parse time range
    let time_range = query
        .time_range
        .and_then(|tr| match tr.as_str() {
            "hour" => Some(crate::analytics::TimeRange::Hour),
            "day" => Some(crate::analytics::TimeRange::Day),
            "week" => Some(crate::analytics::TimeRange::Week),
            "month" => Some(crate::analytics::TimeRange::Month),
            "year" => Some(crate::analytics::TimeRange::Year),
            _ => None,
        })
        .unwrap_or(crate::analytics::TimeRange::Day);

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match state
        .analytics_manager
        .get_content_performance(query.content_id, time_range, limit, offset)
        .await
    {
        Ok(performance) => Ok(Json(performance)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get content performance: {}", e),
        )),
    }
}

/// Query parameters for node leaderboard.
#[derive(Debug, Deserialize)]
struct NodeLeaderboardQuery {
    time_range: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Get node performance leaderboard.
async fn get_node_leaderboard_handler(
    State(state): State<AppState>,
    Query(query): Query<NodeLeaderboardQuery>,
) -> Result<Json<Vec<crate::analytics::NodePerformance>>, (StatusCode, String)> {
    // Parse time range
    let time_range = query
        .time_range
        .and_then(|tr| match tr.as_str() {
            "hour" => Some(crate::analytics::TimeRange::Hour),
            "day" => Some(crate::analytics::TimeRange::Day),
            "week" => Some(crate::analytics::TimeRange::Week),
            "month" => Some(crate::analytics::TimeRange::Month),
            "year" => Some(crate::analytics::TimeRange::Year),
            _ => None,
        })
        .unwrap_or(crate::analytics::TimeRange::Day);

    // Parse sort order
    let sort_order = query
        .sort_order
        .and_then(|so| match so.as_str() {
            "asc" => Some(crate::analytics::SortOrder::Asc),
            "desc" => Some(crate::analytics::SortOrder::Desc),
            _ => None,
        })
        .unwrap_or(crate::analytics::SortOrder::Desc);

    let sort_by = query.sort_by.as_deref().unwrap_or("points_earned");
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match state
        .analytics_manager
        .get_node_leaderboard(time_range, sort_by, sort_order, limit, offset)
        .await
    {
        Ok(leaderboard) => Ok(Json(leaderboard)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get node leaderboard: {}", e),
        )),
    }
}

/// Execute a custom analytics query.
async fn execute_custom_analytics_query_handler(
    State(state): State<AppState>,
    Json(query): Json<crate::analytics::AnalyticsQuery>,
) -> Result<Json<crate::analytics::AnalyticsResult>, (StatusCode, String)> {
    match state.analytics_manager.execute_custom_query(query).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to execute custom query: {}", e),
        )),
    }
}

/// Get analytics configuration.
async fn get_analytics_config_handler(
    State(state): State<AppState>,
) -> Json<crate::analytics::AnalyticsConfig> {
    let config = state.analytics_manager.config().await;
    Json(config)
}

/// Update analytics configuration.
async fn update_analytics_config_handler(
    State(state): State<AppState>,
    Json(config): Json<crate::analytics::AnalyticsConfig>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.analytics_manager.update_config(config).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update analytics config: {}", e),
        )),
    }
}

// ==================== API Version & Changelog Endpoints ====================

/// Get current API version information.
async fn get_api_version_handler() -> Json<crate::api_changelog::ApiVersion> {
    let version = crate::api_changelog::get_current_version();
    Json(version)
}

/// Get all API versions.
async fn get_all_versions_handler() -> Json<Vec<crate::api_changelog::ApiVersion>> {
    let versions = crate::api_changelog::get_all_versions();
    Json(versions)
}

/// Get complete API changelog.
async fn get_changelog_handler() -> Json<crate::api_changelog::ApiChangelog> {
    let changelog = crate::api_changelog::get_changelog();
    Json(changelog)
}

/// Get changelog for a specific version.
async fn get_version_changelog_handler(
    Path(version): Path<String>,
) -> Json<Vec<crate::api_changelog::ChangelogEntry>> {
    let entries = crate::api_changelog::get_version_changelog(&version);
    Json(entries)
}

/// Get changelog by category.
async fn get_category_changelog_handler(
    Path(category): Path<String>,
) -> Json<Vec<crate::api_changelog::ChangelogEntry>> {
    let entries = crate::api_changelog::get_changelog_by_category(&category);
    Json(entries)
}
