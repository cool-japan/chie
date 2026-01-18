//! OpenAPI/Swagger documentation for CHIE Coordinator API.
//!
//! This module provides:
//! - OpenAPI specification generation
//! - Swagger UI endpoint
//! - API schema definitions

#![allow(dead_code)]

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::admin::SystemStats as AdminSystemStats;
use crate::admin::{
    AdminContentInfo, AdminFraudAlert, AdminNodeInfo, AdminProofInfo, AdminUserInfo,
    ComponentStatus, ContentListResponse, ContentStats, DailyStats, FlagContentRequest,
    FraudAlertListResponse, HealthStatus, HourlyCount, NodeListResponse, NodeStats, ProofStats,
    ResolveFraudRequest, SystemConfig, UserListResponse,
};

/// Main OpenAPI documentation.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "CHIE Protocol Coordinator API",
        version = "0.1.0",
        description = "Central coordinator server for the CHIE Protocol decentralized content distribution network.",
        contact(
            name = "CHIE Protocol Team",
            url = "https://github.com/cooljapan/chie-protocol"
        ),
        license(
            name = "Proprietary",
            url = "https://chie.network/license"
        )
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server"),
        (url = "https://api.chie.network", description = "Production server")
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "proofs", description = "Bandwidth proof verification and submission"),
        (name = "content", description = "Content registration and management"),
        (name = "auth", description = "Authentication and authorization"),
        (name = "rewards", description = "Reward calculation and distribution"),
        (name = "admin", description = "Administrative operations"),
        (name = "websocket", description = "Real-time WebSocket connections"),
        (name = "federation", description = "Coordinator federation management")
    ),
    paths(
        // Health endpoints
        health_check,
        health_check_db,
        // API endpoints
        submit_proof,
        register_content,
        get_current_user,
        generate_token,
        // Admin endpoints (from admin.rs)
        get_system_stats,
        get_detailed_stats,
        get_health_status,
        get_component_health,
        list_users,
        get_user,
        ban_user,
        unban_user,
        list_content,
        get_content,
        remove_content,
        flag_content,
        list_nodes,
        get_node,
        suspend_node,
        unsuspend_node,
        list_fraud_alerts,
        resolve_fraud_alert,
        get_config,
        update_config,
        list_recent_proofs,
        get_proof_stats,
    ),
    components(
        schemas(
            // Admin schemas
            AdminSystemStats,
            HealthStatus,
            ComponentStatus,
            UserListResponse,
            AdminUserInfo,
            ContentListResponse,
            AdminContentInfo,
            FlagContentRequest,
            NodeListResponse,
            AdminNodeInfo,
            FraudAlertListResponse,
            AdminFraudAlert,
            ResolveFraudRequest,
            SystemConfig,
            ProofStats,
            AdminProofInfo,
            HourlyCount,
            DailyStats,
            ContentStats,
            NodeStats,
            // API schemas
            ProofSubmissionRequest,
            ProofSubmissionResponse,
            RegisterContentRequest,
            ContentResponse,
            UserInfo,
            TokenRequest,
            TokenResponse,
            RewardInfo,
            ErrorResponse,
            PaginationParams,
        )
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

/// Security addon for JWT authentication.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT token for authentication"))
                        .build(),
                ),
            );
        }
    }
}

// Health endpoint schemas

/// Health check response.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    )
)]
pub async fn health_check() -> &'static str {
    "OK"
}

/// Database health check response.
#[utoipa::path(
    get,
    path = "/health/db",
    tag = "health",
    responses(
        (status = 200, description = "Database is healthy", body = String),
        (status = 503, description = "Database is unavailable")
    )
)]
pub async fn health_check_db() -> &'static str {
    "DB OK"
}

// Admin endpoint docs (reference to actual handlers in admin.rs)

#[utoipa::path(
    get,
    path = "/admin/stats",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "System statistics", body = AdminSystemStats),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_system_stats() {}

#[utoipa::path(
    get,
    path = "/admin/stats/detailed",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Detailed system statistics"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_detailed_stats() {}

#[utoipa::path(
    get,
    path = "/admin/health",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Health status", body = HealthStatus),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_health_status() {}

#[utoipa::path(
    get,
    path = "/admin/health/components",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Component health statuses", body = Vec<ComponentStatus>),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_component_health() {}

#[utoipa::path(
    get,
    path = "/admin/users",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("limit" = Option<u32>, Query, description = "Items per page"),
        ("search" = Option<String>, Query, description = "Search term"),
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "List of users", body = UserListResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_users() {}

#[utoipa::path(
    get,
    path = "/admin/users/{id}",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User details", body = AdminUserInfo),
        (status = 404, description = "User not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_user() {}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/ban",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User banned"),
        (status = 404, description = "User not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn ban_user() {}

#[utoipa::path(
    post,
    path = "/admin/users/{id}/unban",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User unbanned"),
        (status = 404, description = "User not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn unban_user() {}

#[utoipa::path(
    get,
    path = "/admin/content",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("limit" = Option<u32>, Query, description = "Items per page"),
        ("category" = Option<String>, Query, description = "Filter by category"),
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "List of content", body = ContentListResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_content() {}

#[utoipa::path(
    get,
    path = "/admin/content/{id}",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Content ID")
    ),
    responses(
        (status = 200, description = "Content details", body = AdminContentInfo),
        (status = 404, description = "Content not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_content() {}

#[utoipa::path(
    delete,
    path = "/admin/content/{id}",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Content ID")
    ),
    responses(
        (status = 200, description = "Content removed"),
        (status = 404, description = "Content not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn remove_content() {}

#[utoipa::path(
    post,
    path = "/admin/content/{id}/flag",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Content ID")
    ),
    request_body = FlagContentRequest,
    responses(
        (status = 200, description = "Content flagged"),
        (status = 404, description = "Content not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn flag_content() {}

#[utoipa::path(
    get,
    path = "/admin/nodes",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("limit" = Option<u32>, Query, description = "Items per page"),
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "List of nodes", body = NodeListResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_nodes() {}

#[utoipa::path(
    get,
    path = "/admin/nodes/{id}",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Node ID")
    ),
    responses(
        (status = 200, description = "Node details", body = AdminNodeInfo),
        (status = 404, description = "Node not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_node() {}

#[utoipa::path(
    post,
    path = "/admin/nodes/{id}/suspend",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Node ID")
    ),
    responses(
        (status = 200, description = "Node suspended"),
        (status = 404, description = "Node not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn suspend_node() {}

#[utoipa::path(
    post,
    path = "/admin/nodes/{id}/unsuspend",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Node ID")
    ),
    responses(
        (status = 200, description = "Node unsuspended"),
        (status = 404, description = "Node not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn unsuspend_node() {}

#[utoipa::path(
    get,
    path = "/admin/fraud/alerts",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("limit" = Option<u32>, Query, description = "Items per page"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("severity" = Option<String>, Query, description = "Filter by severity")
    ),
    responses(
        (status = 200, description = "List of fraud alerts", body = FraudAlertListResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_fraud_alerts() {}

#[utoipa::path(
    post,
    path = "/admin/fraud/alerts/{id}/resolve",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Alert ID")
    ),
    request_body = ResolveFraudRequest,
    responses(
        (status = 200, description = "Alert resolved"),
        (status = 404, description = "Alert not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn resolve_fraud_alert() {}

#[utoipa::path(
    get,
    path = "/admin/config",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "System configuration", body = SystemConfig),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_config() {}

#[utoipa::path(
    put,
    path = "/admin/config",
    tag = "admin",
    security(("bearer_auth" = [])),
    request_body = SystemConfig,
    responses(
        (status = 200, description = "Configuration updated"),
        (status = 400, description = "Invalid configuration"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn update_config() {}

#[utoipa::path(
    get,
    path = "/admin/proofs/recent",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number"),
        ("limit" = Option<u32>, Query, description = "Items per page"),
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "Recent proofs"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_recent_proofs() {}

#[utoipa::path(
    get,
    path = "/admin/proofs/stats",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Proof statistics", body = ProofStats),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_proof_stats() {}

// API endpoints (public and authenticated)

#[utoipa::path(
    post,
    path = "/api/proofs",
    tag = "proofs",
    request_body = ProofSubmissionRequest,
    responses(
        (status = 200, description = "Proof processed", body = ProofSubmissionResponse),
        (status = 400, description = "Invalid proof format"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn submit_proof() {}

#[utoipa::path(
    post,
    path = "/api/content",
    tag = "content",
    security(("bearer_auth" = [])),
    request_body = RegisterContentRequest,
    responses(
        (status = 200, description = "Content registered", body = ContentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn register_content() {}

#[utoipa::path(
    get,
    path = "/api/me",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user info", body = UserInfo),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_current_user() {}

#[utoipa::path(
    post,
    path = "/api/auth/token",
    tag = "auth",
    request_body = TokenRequest,
    responses(
        (status = 200, description = "Token generated", body = TokenResponse),
        (status = 400, description = "Invalid request")
    )
)]
pub async fn generate_token() {}

// Common API schemas

/// Proof submission request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ProofSubmissionRequest {
    /// Provider's public key (hex encoded).
    pub provider_key: String,
    /// Requester's public key (hex encoded).
    pub requester_key: String,
    /// Content CID.
    pub content_cid: String,
    /// Chunk index transferred.
    pub chunk_index: u64,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Transfer latency in milliseconds.
    pub latency_ms: u32,
    /// Challenge nonce (hex encoded).
    pub challenge_nonce: String,
    /// Provider's signature (hex encoded).
    pub provider_signature: String,
    /// Requester's signature (hex encoded).
    pub requester_signature: String,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
}

/// Proof submission response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ProofSubmissionResponse {
    /// Whether the proof was accepted.
    pub accepted: bool,
    /// Proof ID if accepted.
    pub proof_id: Option<uuid::Uuid>,
    /// Calculated reward points.
    pub reward_points: Option<u64>,
    /// Error message if rejected.
    pub error: Option<String>,
}

/// Reward information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RewardInfo {
    /// User ID.
    pub user_id: uuid::Uuid,
    /// Total earned points.
    pub total_points: u64,
    /// Points earned today.
    pub points_today: u64,
    /// Points earned this week.
    pub points_this_week: u64,
    /// Pending payout amount.
    pub pending_payout: u64,
}

/// Error response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Additional details.
    pub details: Option<String>,
}

/// Pagination parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PaginationParams {
    /// Page number (1-indexed).
    pub page: u32,
    /// Items per page.
    pub limit: u32,
    /// Total items available.
    pub total: u64,
    /// Total pages.
    pub total_pages: u32,
}

/// Content registration request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RegisterContentRequest {
    /// Content CID (IPFS Content Identifier).
    pub cid: String,
    /// Content title.
    pub title: String,
    /// Content description.
    #[serde(default)]
    pub description: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Price in points.
    pub price: u64,
    /// Content category (e.g., "3D_MODELS", "TEXTURES", "AI_MODELS").
    #[serde(default)]
    pub category: Option<String>,
    /// Tags for discovery.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Content registration response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ContentResponse {
    /// Whether registration succeeded.
    pub success: bool,
    /// Content ID if successful.
    pub content_id: Option<uuid::Uuid>,
    /// Status message.
    pub message: String,
}

/// Current user information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UserInfo {
    /// User's unique identifier.
    pub user_id: uuid::Uuid,
    /// User's peer ID (if registered as node).
    pub peer_id: Option<String>,
    /// User's role (user, creator, admin).
    pub role: String,
}

/// Token generation request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    /// User ID to generate token for.
    pub user_id: uuid::Uuid,
    /// Associated peer ID (optional).
    pub peer_id: Option<String>,
    /// Role for the token.
    pub role: String,
}

/// Token response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct TokenResponse {
    /// JWT token.
    pub token: String,
    /// Token expiry time in seconds.
    pub expires_in: i64,
}

/// Create the Swagger UI router.
pub fn swagger_routes() -> SwaggerUi {
    SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi())
}

use crate::sdk_generator::{SdkGenerator, SdkLanguage};
use axum::{
    Router,
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::get,
};

/// Create enhanced API documentation routes with multiple UI options.
pub fn enhanced_docs_routes() -> Router {
    Router::new()
        .route("/api-docs", get(docs_landing_page))
        .route("/api-docs/rapidoc", get(rapidoc_ui))
        .route("/api-docs/redoc", get(redoc_ui))
        .route("/api-docs/playground", get(api_playground))
        .route("/api-docs/sdk", get(sdk_download_page))
        .route("/api-docs/sdk/python", get(download_python_sdk))
        .route("/api-docs/sdk/javascript", get(download_javascript_sdk))
        .route("/api-docs/sdk/typescript", get(download_typescript_sdk))
        .route("/api-docs/sdk/rust", get(download_rust_sdk))
        .route("/api-docs/sdk/go", get(download_go_sdk))
        .route("/api-docs/sdk/all", get(download_all_sdks))
}

/// Landing page for API documentation.
async fn docs_landing_page() -> Html<String> {
    Html(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHIE Protocol API Documentation</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .card {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            text-decoration: none;
            color: inherit;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            border-color: #667eea;
        }
        .card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        .card p {
            color: #666;
            line-height: 1.6;
        }
        .badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75em;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>CHIE Protocol API</h1>
        <p class="subtitle">Choose your preferred documentation interface</p>

        <div class="grid">
            <a href="/swagger-ui" class="card">
                <h3>Swagger UI</h3>
                <p>Classic OpenAPI documentation with interactive testing capabilities.</p>
                <span class="badge">Interactive</span>
            </a>

            <a href="/api-docs/rapidoc" class="card">
                <h3>RapiDoc</h3>
                <p>Modern, fast, and feature-rich API documentation with dark mode support.</p>
                <span class="badge">Recommended</span>
            </a>

            <a href="/api-docs/redoc" class="card">
                <h3>Redoc</h3>
                <p>Beautiful three-panel design optimized for reading and understanding APIs.</p>
                <span class="badge">Clean</span>
            </a>

            <a href="/api-docs/playground" class="card">
                <h3>API Playground</h3>
                <p>Interactive testing environment with request history and code generation.</p>
                <span class="badge">Developer</span>
            </a>

            <a href="/graphql" class="card">
                <h3>GraphQL Playground</h3>
                <p>Explore the GraphQL API with subscriptions support for real-time updates.</p>
                <span class="badge">GraphQL</span>
            </a>

            <a href="/api-docs/openapi.json" class="card">
                <h3>OpenAPI Spec</h3>
                <p>Download the raw OpenAPI 3.0 specification in JSON format.</p>
                <span class="badge">Download</span>
            </a>

            <a href="/api-docs/sdk" class="card">
                <h3>SDK Downloads</h3>
                <p>Client libraries for Python, JavaScript, TypeScript, Rust, and Go.</p>
                <span class="badge">SDKs</span>
            </a>
        </div>
    </div>
</body>
</html>"##
            .to_string(),
    )
}

/// RapiDoc UI endpoint.
async fn rapidoc_ui() -> Html<String> {
    Html(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CHIE Protocol API - RapiDoc</title>
    <script type="module" src="https://unpkg.com/rapidoc/dist/rapidoc-min.js"></script>
</head>
<body>
    <rapi-doc
        spec-url="/api-docs/openapi.json"
        theme="dark"
        render-style="read"
        layout="row"
        schema-style="tree"
        show-header="true"
        show-info="true"
        allow-authentication="true"
        allow-server-selection="true"
        allow-api-list-style-selection="true"
        allow-try="true"
        allow-spec-url-load="false"
        allow-spec-file-load="false"
        allow-search="true"
        heading-text="CHIE Protocol Coordinator API"
        primary-color="#667eea"
        nav-bg-color="#2d3748"
        nav-text-color="#fff"
        nav-hover-bg-color="#4a5568"
        nav-hover-text-color="#fff"
        nav-accent-color="#667eea"
        bg-color="#1a202c"
        text-color="#e2e8f0"
        header-color="#667eea"
        regular-font="Open Sans, sans-serif"
        mono-font="Roboto Mono, monospace"
        font-size="default"
        sort-tags="true"
        sort-endpoints-by="path">
    </rapi-doc>
</body>
</html>"##
            .to_string(),
    )
}

/// Redoc UI endpoint.
async fn redoc_ui() -> Html<String> {
    Html(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CHIE Protocol API - Redoc</title>
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url="/api-docs/openapi.json"
           hide-download-button="false"
           hide-hostname="false"
           expand-responses="200,201"
           json-sample-expand-level="2"
           theme='{
             "colors": {
               "primary": {
                 "main": "#667eea"
               }
             },
             "typography": {
               "fontFamily": "Open Sans, sans-serif",
               "fontSize": "14px",
               "headings": {
                 "fontFamily": "Montserrat, sans-serif"
               }
             },
             "sidebar": {
               "backgroundColor": "#2d3748",
               "textColor": "#fff"
             }
           }'>
    </redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>"##
            .to_string(),
    )
}

/// Interactive API Playground.
async fn api_playground() -> Html<String> {
    Html(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHIE Protocol API Playground</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #1a202c;
            color: #e2e8f0;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #2d3748;
            padding: 15px 20px;
            border-bottom: 2px solid #667eea;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 {
            font-size: 1.5em;
            color: #667eea;
        }
        .header nav a {
            color: #a0aec0;
            text-decoration: none;
            margin-left: 20px;
            transition: color 0.2s;
        }
        .header nav a:hover { color: #667eea; }
        .container {
            flex: 1;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
            overflow: hidden;
        }
        .panel {
            background: #2d3748;
            border-radius: 8px;
            padding: 20px;
            overflow-y: auto;
        }
        .panel h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #a0aec0;
            font-size: 0.9em;
        }
        .form-group select,
        .form-group input,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            background: #1a202c;
            border: 1px solid #4a5568;
            border-radius: 4px;
            color: #e2e8f0;
            font-family: monospace;
        }
        .form-group textarea {
            min-height: 150px;
            font-size: 0.9em;
        }
        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.2s;
        }
        button:hover { background: #5a67d8; }
        button:active { transform: scale(0.98); }
        .response-box {
            background: #1a202c;
            border: 1px solid #4a5568;
            border-radius: 4px;
            padding: 15px;
            margin-top: 15px;
            font-family: monospace;
            font-size: 0.85em;
            overflow-x: auto;
        }
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            margin-bottom: 10px;
        }
        .status.success { background: #48bb78; color: white; }
        .status.error { background: #f56565; color: white; }
        .history {
            max-height: 200px;
            overflow-y: auto;
        }
        .history-item {
            background: #1a202c;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .history-item:hover { background: #2d3748; }
        .history-item .method {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            margin-right: 8px;
            font-weight: bold;
        }
        .method.GET { background: #48bb78; color: white; }
        .method.POST { background: #4299e1; color: white; }
        .method.PUT { background: #ed8936; color: white; }
        .method.DELETE { background: #f56565; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>API Playground</h1>
        <nav>
            <a href="/api-docs">← Back to Docs</a>
            <a href="/swagger-ui">Swagger UI</a>
            <a href="/graphql">GraphQL</a>
        </nav>
    </div>

    <div class="container">
        <div class="panel">
            <h2>Request</h2>

            <div class="form-group">
                <label>Method</label>
                <select id="method">
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                </select>
            </div>

            <div class="form-group">
                <label>Endpoint</label>
                <input type="text" id="endpoint" placeholder="/api/content" value="/api/stats/platform">
            </div>

            <div class="form-group">
                <label>Headers (JSON)</label>
                <textarea id="headers" placeholder='{"Authorization": "Bearer token"}'>{}</textarea>
            </div>

            <div class="form-group">
                <label>Body (JSON)</label>
                <textarea id="body" placeholder='{"key": "value"}'></textarea>
            </div>

            <button onclick="sendRequest()">Send Request</button>
            <button onclick="clearHistory()" style="background: #4a5568; margin-left: 10px;">Clear History</button>

            <h2 style="margin-top: 30px;">Request History</h2>
            <div class="history" id="history"></div>
        </div>

        <div class="panel">
            <h2>Response</h2>
            <div id="response-status"></div>
            <div class="response-box" id="response">
                <div style="color: #a0aec0; text-align: center; padding: 40px;">
                    Send a request to see the response
                </div>
            </div>

            <h2 style="margin-top: 30px;">Code Generation</h2>
            <div class="form-group">
                <label>Language</label>
                <select id="codeLang" onchange="generateCode()">
                    <option value="curl">cURL</option>
                    <option value="javascript">JavaScript (fetch)</option>
                    <option value="python">Python (requests)</option>
                    <option value="rust">Rust (reqwest)</option>
                </select>
            </div>
            <div class="response-box" id="codeGen"></div>
        </div>
    </div>

    <script>
        let history = JSON.parse(localStorage.getItem('apiHistory') || '[]');
        renderHistory();

        async function sendRequest() {
            const method = document.getElementById('method').value;
            const endpoint = document.getElementById('endpoint').value;
            const headersText = document.getElementById('headers').value;
            const bodyText = document.getElementById('body').value;

            let headers = {};
            try {
                headers = JSON.parse(headersText || '{}');
            } catch (e) {
                alert('Invalid headers JSON');
                return;
            }

            const options = {
                method: method,
                headers: headers
            };

            if (method !== 'GET' && bodyText) {
                options.body = bodyText;
                headers['Content-Type'] = 'application/json';
            }

            try {
                const startTime = Date.now();
                const response = await fetch(endpoint, options);
                const duration = Date.now() - startTime;
                const responseText = await response.text();

                let responseJson;
                try {
                    responseJson = JSON.parse(responseText);
                } catch {
                    responseJson = responseText;
                }

                const statusClass = response.ok ? 'success' : 'error';
                document.getElementById('response-status').innerHTML =
                    `<span class="status ${statusClass}">${response.status} ${response.statusText}</span> <span style="color: #a0aec0; font-size: 0.85em;">(${duration}ms)</span>`;

                document.getElementById('response').innerHTML =
                    '<pre>' + JSON.stringify(responseJson, null, 2) + '</pre>';

                // Add to history
                history.unshift({
                    method, endpoint, headers, body: bodyText,
                    status: response.status,
                    timestamp: new Date().toISOString()
                });
                history = history.slice(0, 20); // Keep last 20
                localStorage.setItem('apiHistory', JSON.stringify(history));
                renderHistory();
                generateCode();
            } catch (error) {
                document.getElementById('response-status').innerHTML =
                    '<span class="status error">Error</span>';
                document.getElementById('response').innerHTML =
                    '<pre style="color: #f56565;">' + error.message + '</pre>';
            }
        }

        function renderHistory() {
            const historyDiv = document.getElementById('history');
            if (history.length === 0) {
                historyDiv.innerHTML = '<div style="color: #a0aec0; text-align: center; padding: 20px;">No requests yet</div>';
                return;
            }

            historyDiv.innerHTML = history.map((item, index) => `
                <div class="history-item" onclick="loadFromHistory(${index})">
                    <span class="method ${item.method}">${item.method}</span>
                    <span>${item.endpoint}</span>
                    <span style="color: #a0aec0; font-size: 0.75em; float: right;">${new Date(item.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('');
        }

        function loadFromHistory(index) {
            const item = history[index];
            document.getElementById('method').value = item.method;
            document.getElementById('endpoint').value = item.endpoint;
            document.getElementById('headers').value = JSON.stringify(item.headers, null, 2);
            document.getElementById('body').value = item.body || '';
            generateCode();
        }

        function clearHistory() {
            if (confirm('Clear all request history?')) {
                history = [];
                localStorage.removeItem('apiHistory');
                renderHistory();
            }
        }

        function generateCode() {
            const method = document.getElementById('method').value;
            const endpoint = document.getElementById('endpoint').value;
            const headersText = document.getElementById('headers').value;
            const bodyText = document.getElementById('body').value;
            const lang = document.getElementById('codeLang').value;

            let code = '';
            const fullUrl = window.location.origin + endpoint;

            if (lang === 'curl') {
                code = `curl -X ${method} '${fullUrl}'`;
                try {
                    const headers = JSON.parse(headersText || '{}');
                    Object.entries(headers).forEach(([key, value]) => {
                        code += `\n  -H '${key}: ${value}'`;
                    });
                } catch {}
                if (bodyText) code += `\n  -d '${bodyText}'`;

            } else if (lang === 'javascript') {
                code = `fetch('${fullUrl}', {\n  method: '${method}'`;
                if (headersText !== '{}') code += `,\n  headers: ${headersText}`;
                if (bodyText) code += `,\n  body: ${bodyText}`;
                code += `\n})\n  .then(res => res.json())\n  .then(data => console.log(data));`;

            } else if (lang === 'python') {
                code = `import requests\n\nresponse = requests.${method.toLowerCase()}('${fullUrl}'`;
                if (headersText !== '{}') code += `,\n  headers=${headersText.replace(/"/g, "'")}`;
                if (bodyText) code += `,\n  json=${bodyText.replace(/"/g, "'")}`;
                code += `)\nprint(response.json())`;

            } else if (lang === 'rust') {
                code = `let client = reqwest::Client::new();\nlet response = client.${method.toLowerCase()}("${fullUrl}")`;
                if (bodyText) code += `\n  .json(&serde_json::json!(${bodyText}))`;
                code += `\n  .send()\n  .await?;`;
            }

            document.getElementById('codeGen').innerHTML = '<pre>' + code + '</pre>';
        }

        generateCode();
    </script>
</body>
</html>"##.to_string())
}

/// SDK download landing page.
async fn sdk_download_page() -> Html<String> {
    Html(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHIE Protocol SDK Downloads</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        .sdk-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .sdk-card {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        .sdk-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            border-color: #667eea;
        }
        .sdk-icon {
            font-size: 3em;
            margin-bottom: 15px;
        }
        .sdk-name {
            color: #333;
            font-size: 1.2em;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .download-btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            text-decoration: none;
            transition: background 0.2s;
            margin-top: 10px;
        }
        .download-btn:hover {
            background: #5a67d8;
        }
        .all-sdks {
            background: #667eea;
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .all-sdks a {
            color: white;
            text-decoration: none;
            font-size: 1.2em;
            font-weight: 600;
        }
        .features {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
        }
        .features h2 {
            color: #667eea;
            margin-bottom: 15px;
        }
        .features ul {
            list-style-position: inside;
            color: #666;
            line-height: 1.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SDK Downloads</h1>
        <p class="subtitle">Client libraries for the CHIE Protocol API</p>

        <div class="sdk-grid">
            <div class="sdk-card">
                <div class="sdk-icon">🐍</div>
                <div class="sdk-name">Python</div>
                <a href="/api-docs/sdk/python" class="download-btn" download>Download</a>
            </div>

            <div class="sdk-card">
                <div class="sdk-icon">📜</div>
                <div class="sdk-name">JavaScript</div>
                <a href="/api-docs/sdk/javascript" class="download-btn" download>Download</a>
            </div>

            <div class="sdk-card">
                <div class="sdk-icon">🔷</div>
                <div class="sdk-name">TypeScript</div>
                <a href="/api-docs/sdk/typescript" class="download-btn" download>Download</a>
            </div>

            <div class="sdk-card">
                <div class="sdk-icon">🦀</div>
                <div class="sdk-name">Rust</div>
                <a href="/api-docs/sdk/rust" class="download-btn" download>Download</a>
            </div>

            <div class="sdk-card">
                <div class="sdk-icon">🔵</div>
                <div class="sdk-name">Go</div>
                <a href="/api-docs/sdk/go" class="download-btn" download>Download</a>
            </div>
        </div>

        <div class="all-sdks">
            <a href="/api-docs/sdk/all" download>📦 Download All SDKs (ZIP)</a>
        </div>

        <div class="features">
            <h2>SDK Features</h2>
            <ul>
                <li>✅ Complete API coverage</li>
                <li>✅ Type-safe interfaces</li>
                <li>✅ Authentication support</li>
                <li>✅ Comprehensive error handling</li>
                <li>✅ Configurable timeouts</li>
                <li>✅ Production-ready</li>
                <li>✅ Well-documented with examples</li>
            </ul>
        </div>

        <p style="margin-top: 30px; text-align: center; color: #666;">
            <a href="/api-docs" style="color: #667eea; text-decoration: none;">← Back to API Docs</a>
        </p>
    </div>
</body>
</html>"##.to_string())
}

/// Download Python SDK.
async fn download_python_sdk() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let code = generator.generate(SdkLanguage::Python);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-python")],
        code,
    )
}

/// Download JavaScript SDK.
async fn download_javascript_sdk() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let code = generator.generate(SdkLanguage::JavaScript);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/javascript")],
        code,
    )
}

/// Download TypeScript SDK.
async fn download_typescript_sdk() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let code = generator.generate(SdkLanguage::TypeScript);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/typescript")],
        code,
    )
}

/// Download Rust SDK.
async fn download_rust_sdk() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let code = generator.generate(SdkLanguage::Rust);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-rust")],
        code,
    )
}

/// Download Go SDK.
async fn download_go_sdk() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let code = generator.generate(SdkLanguage::Go);

    (StatusCode::OK, [(header::CONTENT_TYPE, "text/x-go")], code)
}

/// Download all SDKs as a ZIP file.
async fn download_all_sdks() -> impl IntoResponse {
    let generator = SdkGenerator::default();
    let files = generator.generate_all();

    // Create a simple concatenated text file for now
    // In production, this would create an actual ZIP file
    let mut combined = String::from("# CHIE Protocol SDK Bundle\n\n");

    for (filename, content) in files {
        combined.push_str(&format!("=== {} ===\n\n", filename));
        combined.push_str(&content);
        combined.push_str("\n\n");
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        combined,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_generation() {
        let doc = ApiDoc::openapi();
        assert_eq!(doc.info.title, "CHIE Protocol Coordinator API");
        assert_eq!(doc.info.version, "0.1.0");
    }

    #[test]
    fn test_swagger_routes() {
        let _swagger_ui = swagger_routes();
    }

    #[test]
    fn test_enhanced_docs_routes() {
        let _router = enhanced_docs_routes();
    }
}
