//! Core API endpoints: authentication, user/node/content registration and CRUD.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::AuthenticatedUser;
use crate::db::{
    ContentRepository, CreateContent, CreateNode, CreateUser, NodeRepository, UserRepository,
};
use crate::rewards::InvestmentEngine;

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

/// Get current user info (requires authentication).
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub user_id: uuid::Uuid,
    pub peer_id: Option<String>,
    pub role: String,
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

/// Content list query parameters.
#[derive(Debug, Deserialize)]
pub struct ContentListQuery {
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Transaction history query parameters.
#[derive(Debug, Deserialize)]
pub struct TransactionQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
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

/// Register new content (requires authentication).
pub(super) async fn register_content(
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
pub(super) async fn get_current_user(user: AuthenticatedUser) -> Json<UserInfo> {
    Json(UserInfo {
        user_id: user.user_id,
        peer_id: user.peer_id,
        role: user.role,
    })
}

/// Generate a JWT token (for development/testing).
pub(super) async fn generate_token(
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

/// Register a new user.
pub(super) async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, (StatusCode, String)> {
    use crate::db::UserRole;

    // Validate inputs
    super::validate_username(&request.username).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    super::validate_email(&request.email).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    super::validate_password(&request.password).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

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

/// Register a new node.
pub(super) async fn register_node(
    State(state): State<AppState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<RegisterNodeResponse>, (StatusCode, String)> {
    // Validate inputs
    super::validate_peer_id(&request.peer_id).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    super::validate_public_key_hex(&request.public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

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

/// List content with optional filters.
pub(super) async fn list_content(
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
pub(super) async fn get_content(
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
pub(super) async fn get_content_seeders(
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
pub(super) async fn get_node_info(
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

/// Get transaction history for authenticated user.
pub(super) async fn get_transactions(
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

/// Get content pinning recommendations.
pub(super) async fn get_content_recommendations(
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
