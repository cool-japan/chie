//! CHIE Protocol Central Coordinator Server.

use axum::{Router, routing::get};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;

mod admin;
mod alerting;
mod analytics;
mod api;
mod api_changelog;
mod api_keys;
mod api_validation;
mod api_versioning;
mod archiving;
mod audit_log;
mod auth;
mod batch;
mod brute_force;
mod cache;
mod compression;
mod config;
mod content_moderation;
mod correlation;
mod db;
mod deployment;
mod endpoint_metrics;
mod error_tracking;
mod etag;
mod export;
mod failover;
mod feature_flags;
mod federation;
mod fraud;
mod gdpr;
mod graphql;
mod health;
mod ip_rate_limit;
mod jurisdiction;
mod metrics;
mod migrations;
mod node_reputation;
mod nonce_cache;
mod openapi;
mod payment;
mod pool_tuning;
mod popularity;
mod rate_limit_quotas;
mod read_replicas;
mod redis_cache;
mod request_coalescing;
mod request_queue;
mod request_signature;
mod retention;
mod rewards;
mod sdk_generator;
mod security_headers;
mod shutdown;
mod slow_query;
mod tenants;
mod tos_tracking;
mod validation;
mod verification;
mod webhooks;
mod websocket;

pub use alerting::{
    AlertRule, AlertSeverity, AlertStatus, AlertingConfig, AlertingManager, EmailPriority,
    EmailSlaMetrics,
};
pub use analytics::{
    AggregationType, AnalyticsConfig, AnalyticsManager, AnalyticsQuery, AnalyticsResult,
    ContentPerformance, DashboardMetrics, NodePerformance, SortOrder, TimeRange, TimeSeriesPoint,
};
pub use api_keys::{ApiKeyConfig, ApiKeyManager};
pub use api_versioning::{ApiVersion, VersionInfo, VersioningConfig, VersioningManager};
pub use archiving::{ArchivingConfig, ArchivingManager};
pub use audit_log::{AuditCategory, AuditLogConfig, AuditLogger, AuditSeverity};
pub use auth::{AuthenticatedUser, JwtAuth, JwtConfig, SharedJwtAuth};
pub use batch::*;
pub use brute_force::{BruteForceConfig, BruteForceProtection};
pub use cache::{CacheConfig, LruCache};
pub use compression::{CompressionConfig, CompressionManager};
pub use content_moderation::{
    ContentFlag, FlagReason, ModerationAction, ModerationConfig, ModerationManager, ModerationRule,
    ModerationStats, ModerationStatus,
};
pub use db::DbPool;
pub use error_tracking::{ErrorTracker, ErrorTrackingConfig};
pub use etag::{ETag, ETagConfig, ETagManager};
pub use export::{DataExporter, ExportConfig, ExportFormat};
pub use feature_flags::{
    EvaluationContext, EvaluationResult, FeatureFlag, FeatureFlagsConfig, FeatureFlagsManager,
    FlagType,
};
pub use fraud::*;
pub use gdpr::{
    AuditLogData, ContentData, DataExportRequest, ExportMetadata, ExportStatus, GdprConfig,
    GdprError, GdprManager, NodeData, ProofData, RtbfRequest, RtbfStatus, TransactionData,
    UserData, UserPersonalData,
};
pub use jurisdiction::{
    ContentRestriction, JurisdictionCode, JurisdictionConfig, JurisdictionError,
    JurisdictionFilterResult, JurisdictionManager, JurisdictionStats, RestrictionReason,
};
pub use metrics::*;
pub use migrations::{MigrationRunner, MigrationStatus};
pub use node_reputation::{
    NodeReputation, ReputationConfig, ReputationEvent, ReputationManager, ReputationStats,
    TrustLevel,
};
pub use nonce_cache::*;
pub use payment::{
    EscrowEntry, EscrowStatus, PaymentConfig, PaymentLedgerEntry, PaymentManager, PaymentProvider,
    PaymentStats, PaymentStatus, RevenueSplit, RevenueSplitConfig, SettlementBatch,
    SettlementStatus,
};
pub use pool_tuning::{PoolTuner, PoolTuningConfig};
pub use popularity::{PopularityConfig, PopularityTracker};
pub use rate_limit_quotas::{
    QuotaConfig, QuotaManager, QuotaPurchase, QuotaStats, QuotaStatus, QuotaTier, UserQuotaInfo,
};
pub use redis_cache::{RedisCache, RedisCacheConfig};
pub use request_coalescing::{CoalescingConfig, CoalescingManager, CoalescingStats};
pub use request_queue::{RequestQueue, RequestQueueConfig};
pub use request_signature::{SignatureConfig, SignatureVerifier};
pub use retention::{RetentionConfig, RetentionManager};
pub use rewards::{ContentRecommendation, InvestmentEngine, RewardConfig, RewardEngine};
pub use shutdown::{ShutdownCoordinator, ShutdownTracker};
pub use slow_query::{SlowQueryConfig, SlowQueryLogger};
pub use tenants::{
    CreateTenantRequest, MultiTenancyConfig, Tenant, TenantContext, TenantManager, TenantStats,
    TenantStatus, UpdateTenantRequest,
};
pub use tos_tracking::{
    TosAcceptance, TosAcceptanceStatus, TosConfig, TosError, TosManager, TosStats, TosVersion,
};
pub use validation::*;
pub use verification::{VerificationConfig, VerificationService};
pub use webhooks::{WebhookConfig, WebhookEvent, WebhookManager};
pub use websocket::{
    EventBroadcaster, EventType, SharedWsHub, SystemStats, WsEvent, WsHub, create_ws_hub,
};

/// Shared verification service.
pub type SharedVerificationService = Arc<VerificationService>;

/// Shared reward engine.
pub type SharedRewardEngine = Arc<RewardEngine>;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: DbPool,
    /// JWT authentication.
    pub jwt: SharedJwtAuth,
    /// Proof verification service.
    pub verification: SharedVerificationService,
    /// Reward calculation engine.
    pub rewards: SharedRewardEngine,
    /// WebSocket hub for real-time updates.
    pub ws_hub: SharedWsHub,
    /// Event broadcaster.
    pub broadcaster: EventBroadcaster,
    /// Slow query logger.
    pub slow_query_logger: SlowQueryLogger,
    /// Error tracker.
    pub error_tracker: ErrorTracker,
    /// Signature verifier.
    pub signature_verifier: Arc<SignatureVerifier>,
    /// API key manager.
    pub api_key_manager: Arc<ApiKeyManager>,
    /// Brute force protection.
    pub brute_force: BruteForceProtection,
    /// Redis cache (optional).
    pub redis_cache: Option<Arc<RedisCache>>,
    /// Connection pool tuner.
    pub pool_tuner: Arc<PoolTuner>,
    /// Request queue.
    pub request_queue: RequestQueue,
    /// Request coalescing manager.
    pub coalescing_manager: Arc<CoalescingManager>,
    /// Data retention manager.
    pub retention_manager: Arc<RetentionManager>,
    /// Data archiving manager.
    pub archiving_manager: Arc<ArchivingManager>,
    /// Content popularity tracker.
    pub popularity_tracker: PopularityTracker,
    /// Rate limit quota manager.
    pub quota_manager: Arc<QuotaManager>,
    /// Database migration runner.
    pub migration_runner: Arc<MigrationRunner>,
    /// Audit logger.
    pub audit_logger: AuditLogger,
    /// Webhook manager.
    pub webhook_manager: WebhookManager,
    /// Data exporter.
    pub data_exporter: DataExporter,
    /// Content moderation manager.
    pub moderation_manager: ModerationManager,
    /// Node reputation manager.
    pub reputation_manager: Arc<ReputationManager>,
    /// Alerting manager.
    pub alerting_manager: Arc<AlertingManager>,
    /// Feature flags manager.
    pub feature_flags_manager: Arc<FeatureFlagsManager>,
    /// API versioning manager.
    pub versioning_manager: Arc<VersioningManager>,
    /// Compression manager.
    pub compression_manager: Arc<CompressionManager>,
    /// ETag manager.
    pub etag_manager: Arc<ETagManager>,
    /// Analytics manager.
    pub analytics_manager: Arc<AnalyticsManager>,
    /// Tenant manager.
    pub tenant_manager: Arc<TenantManager>,
    /// Payment manager.
    pub payment_manager: Arc<PaymentManager>,
    /// GDPR compliance manager.
    pub gdpr_manager: Arc<GdprManager>,
    /// Terms of Service tracking manager.
    pub tos_manager: Arc<TosManager>,
    /// Jurisdiction filtering manager.
    pub jurisdiction_manager: Arc<JurisdictionManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting CHIE Coordinator...");

    // Load configuration from file and environment
    let config = Config::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config: {}. Using defaults.", e);
        Config::default()
    });
    tracing::info!("Configuration loaded successfully");

    // Initialize metrics
    let _metrics_handle = metrics::init_metrics();
    tracing::info!("Prometheus metrics initialized");

    // Initialize database pool
    let db_pool = match db::init_pool(&config.database.url).await {
        Ok(pool) => {
            tracing::info!("Database connected successfully");
            pool
        }
        Err(e) => {
            tracing::warn!("Database connection failed: {}. Running without DB.", e);
            // For development, continue without DB
            // In production, you'd want to fail here
            return Err(e);
        }
    };

    // Initialize and run database migrations
    let migration_runner = Arc::new(MigrationRunner::new(db_pool.clone(), "migrations"));
    match migration_runner.run_migrations().await {
        Ok(count) => {
            if count > 0 {
                tracing::info!("Applied {} database migrations", count);
            } else {
                tracing::info!("Database schema is up to date");
            }
        }
        Err(e) => {
            tracing::error!("Migration failed: {}", e);
            return Err(e);
        }
    }

    // Initialize JWT auth
    // Use JWT secret from config if provided
    let jwt_config = if !config.jwt.secret.is_empty() {
        JwtConfig {
            secret: config.jwt.secret.clone(),
            ..Default::default()
        }
    } else {
        JwtConfig::default()
    };
    let jwt_auth = Arc::new(JwtAuth::new(jwt_config));
    tracing::info!("JWT authentication initialized");

    // Initialize verification service (using module-specific config)
    let verification_service = Arc::new(VerificationService::new(
        Arc::new(db_pool.clone()),
        VerificationConfig::default(),
    ));
    tracing::info!("Verification service initialized");

    // Initialize reward engine (using module-specific config)
    let reward_engine = Arc::new(RewardEngine::new(
        Arc::new(db_pool.clone()),
        RewardConfig::default(),
    ));
    tracing::info!("Reward engine initialized");

    // Initialize WebSocket hub
    let ws_hub = create_ws_hub();
    let broadcaster = EventBroadcaster::new(ws_hub.clone());
    tracing::info!("WebSocket hub initialized");

    // Initialize slow query logger
    let slow_query_logger = SlowQueryLogger::new(SlowQueryConfig {
        threshold_ms: config.database.slow_query_threshold_ms,
        ..Default::default()
    });
    tracing::info!("Slow query logger initialized");

    // Initialize error tracker
    let error_tracker = ErrorTracker::new(ErrorTrackingConfig::default());
    tracing::info!("Error tracker initialized");

    // Initialize signature verifier
    let signature_verifier = Arc::new(SignatureVerifier::new(SignatureConfig::default()));
    tracing::info!("Signature verifier initialized");

    // Initialize API key manager
    let api_key_manager = Arc::new(ApiKeyManager::new(ApiKeyConfig::default()));
    tracing::info!("API key manager initialized");

    // Initialize brute force protection
    let brute_force = BruteForceProtection::new(BruteForceConfig::default());
    tracing::info!("Brute force protection initialized");

    // Initialize IP rate limiter
    let ip_rate_limit_config = ip_rate_limit::RateLimitConfig {
        max_requests: config.rate_limit.requests_per_minute_per_ip,
        window: std::time::Duration::from_secs(60),
    };
    let ip_rate_limiter = Arc::new(ip_rate_limit::IpRateLimiter::new(ip_rate_limit_config));
    tracing::info!("IP rate limiter initialized");

    // Initialize Redis cache (optional, if enabled in config)
    let redis_cache = if config.redis.enabled {
        let redis_config = RedisCacheConfig {
            redis_url: config.redis.url.clone(),
            key_prefix: "chie:".to_string(),
            default_ttl_secs: 300,
            max_retries: 3,
            connection_timeout_ms: 5000,
            enable_stats: true,
        };
        match RedisCache::new(redis_config) {
            Ok(cache) => {
                if cache.connect().await.is_ok() {
                    tracing::info!("Redis cache connected successfully");
                    Some(Arc::new(cache))
                } else {
                    tracing::warn!("Redis cache connection failed, running without Redis");
                    None
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize Redis cache: {}, running without Redis",
                    e
                );
                None
            }
        }
    } else {
        tracing::info!("Redis cache disabled in configuration");
        None
    };

    // Initialize connection pool tuner
    let pool_tuning_config = PoolTuningConfig::default();
    let pool_tuner = Arc::new(PoolTuner::new(pool_tuning_config));
    tracing::info!("Connection pool tuner initialized");

    // Initialize request queue
    let request_queue_config = RequestQueueConfig::default();
    let max_concurrent = request_queue_config.max_concurrent;
    let request_queue = RequestQueue::new(request_queue_config);
    tracing::info!(
        "Request queue initialized (max concurrent: {})",
        max_concurrent
    );

    // Initialize retention manager
    let retention_config = RetentionConfig {
        transaction_retention_days: config.retention.transaction_retention_days,
        proof_retention_days: config.retention.proof_retention_days,
        activity_log_retention_days: config.retention.activity_log_retention_days,
        metrics_retention_days: config.retention.metrics_retention_days,
        cleanup_interval_hours: config.retention.cleanup_interval_hours,
        auto_cleanup_enabled: config.retention.auto_cleanup_enabled,
        deletion_batch_size: config.retention.deletion_batch_size,
    };
    let retention_manager = Arc::new(RetentionManager::new(retention_config, db_pool.clone()));
    tracing::info!("Data retention manager initialized");

    // Start auto cleanup task
    let _retention_cleanup_task = retention_manager.clone().start_auto_cleanup();
    tracing::info!("Auto retention cleanup task started");

    // Initialize archiving manager
    let archiving_config = ArchivingConfig {
        archive_age_days: config.archiving.archive_age_days,
        archive_interval_hours: config.archiving.archive_interval_hours,
        auto_archive_enabled: config.archiving.auto_archive_enabled,
        archive_batch_size: config.archiving.archive_batch_size,
        compression_enabled: config.archiving.compression_enabled,
    };
    let archiving_manager = Arc::new(ArchivingManager::new(archiving_config, db_pool.clone()));
    tracing::info!("Data archiving manager initialized");

    // Start auto archive task
    let _archiving_task = archiving_manager.clone().start_auto_archive();
    tracing::info!("Auto archiving task started");

    // Initialize popularity tracker
    let popularity_tracker = PopularityTracker::new(PopularityConfig::default());
    tracing::info!("Content popularity tracker initialized");

    // Initialize rate limit quota manager
    let quota_manager = Arc::new(QuotaManager::new(QuotaConfig::default()));
    tracing::info!("Rate limit quota manager initialized");

    // Start quota expiration task (hourly)
    let quota_manager_clone = quota_manager.clone();
    let _quota_expiration_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
            quota_manager_clone.expire_quotas().await;
        }
    });

    // Start popularity data pruning task (daily at 3 AM)
    let popularity_tracker_clone = popularity_tracker.clone();
    let _popularity_pruning_task = tokio::spawn(async move {
        loop {
            // Wait 24 hours
            tokio::time::sleep(tokio::time::Duration::from_secs(24 * 3600)).await;

            // Prune data older than 180 days
            popularity_tracker_clone.prune_old_data(180).await;
            tracing::info!("Popularity data pruned (retention: 180 days)");
        }
    });
    tracing::info!("Auto popularity pruning task started");

    // Initialize audit logger
    let audit_logger = AuditLogger::new(db_pool.clone(), AuditLogConfig::default());
    tracing::info!("Audit logger initialized");

    // Start auto cleanup task for audit logs
    let _audit_cleanup_task = Arc::new(audit_logger.clone()).start_auto_cleanup();
    tracing::info!("Auto audit log cleanup task started");

    // Initialize webhook manager
    let webhook_manager = WebhookManager::new(WebhookConfig::default());
    tracing::info!("Webhook manager initialized");

    // Initialize data exporter
    let data_exporter = DataExporter::new(db_pool.clone(), ExportConfig::default());
    tracing::info!("Data exporter initialized");

    // Initialize content moderation manager
    let moderation_manager = ModerationManager::new(db_pool.clone(), ModerationConfig::default());
    moderation_manager.init_default_rules().await;
    tracing::info!("Content moderation manager initialized");

    // Initialize node reputation manager
    let reputation_manager = Arc::new(ReputationManager::new(
        db_pool.clone(),
        ReputationConfig::default(),
    ));
    tracing::info!("Node reputation manager initialized");

    // Start automatic reputation decay task
    let _reputation_decay_task = reputation_manager.clone().start_auto_decay();
    tracing::info!("Auto reputation decay task started");

    // Initialize alerting manager with webhook manager integration
    let alerting_manager = Arc::new(AlertingManager::new_with_webhook(
        db_pool.clone(),
        AlertingConfig::default(),
        Some(Arc::new(webhook_manager.clone())),
    ));
    tracing::info!("Alerting manager initialized with webhook integration");

    // Load failed emails from database
    if let Err(e) = alerting_manager.load_failed_emails_from_db().await {
        tracing::error!(error = %e, "Failed to load failed emails from database");
    }

    // Start email retry processing task (every 5 minutes)
    let alerting_manager_clone = alerting_manager.clone();
    let _email_retry_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            alerting_manager_clone.process_email_retries().await;
            tracing::debug!("Email retry processing completed");
        }
    });
    tracing::info!("Email retry processing task started (5-minute interval)");

    // Start email retry database cleanup task (hourly)
    let alerting_manager_clone = alerting_manager.clone();
    let _email_cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
            if let Err(e) = alerting_manager_clone
                .cleanup_expired_failed_emails_db()
                .await
            {
                tracing::error!(error = %e, "Failed to cleanup expired failed emails from database");
            }
        }
    });
    tracing::info!("Email retry database cleanup task started (hourly)");

    // Initialize feature flags manager
    let feature_flags_manager = Arc::new(FeatureFlagsManager::new(FeatureFlagsConfig::default()));
    tracing::info!("Feature flags manager initialized");

    // Initialize API versioning manager
    let versioning_manager = Arc::new(VersioningManager::new(VersioningConfig::default()));
    tracing::info!("API versioning manager initialized");

    // Initialize compression manager
    let compression_manager = Arc::new(CompressionManager::new(CompressionConfig::default()));
    tracing::info!("Compression manager initialized");

    // Initialize ETag manager
    let etag_manager = Arc::new(ETagManager::new(ETagConfig::default()));
    tracing::info!("ETag manager initialized");

    // Initialize analytics manager
    let analytics_manager = Arc::new(AnalyticsManager::new(
        db_pool.clone(),
        AnalyticsConfig::default(),
    ));
    tracing::info!("Analytics manager initialized");

    // Initialize request coalescing manager
    let coalescing_manager = Arc::new(CoalescingManager::new(CoalescingConfig::default()));
    tracing::info!("Request coalescing manager initialized");

    // Initialize tenant manager
    let tenant_manager = Arc::new(TenantManager::new(
        db_pool.clone(),
        MultiTenancyConfig::default(),
    ));
    tracing::info!("Tenant manager initialized");

    // Initialize payment manager
    let payment_manager = Arc::new(PaymentManager::new(
        db_pool.clone(),
        PaymentConfig::default(),
    ));
    tracing::info!("Payment manager initialized");

    // Initialize GDPR compliance manager
    let gdpr_manager = Arc::new(GdprManager::new(db_pool.clone(), GdprConfig::default()));
    tracing::info!("GDPR compliance manager initialized");

    // Initialize Terms of Service tracking manager
    let tos_manager = Arc::new(TosManager::new(db_pool.clone(), TosConfig::default()));
    tracing::info!("Terms of Service tracking manager initialized");

    // Initialize jurisdiction filtering manager
    let jurisdiction_manager = Arc::new(JurisdictionManager::new(
        db_pool.clone(),
        JurisdictionConfig::default(),
    ));
    tracing::info!("Jurisdiction filtering manager initialized");

    // Create application state
    let state = AppState {
        db: db_pool,
        jwt: jwt_auth.clone(),
        verification: verification_service,
        rewards: reward_engine,
        ws_hub: ws_hub.clone(),
        broadcaster,
        slow_query_logger,
        error_tracker,
        signature_verifier: signature_verifier.clone(),
        api_key_manager: api_key_manager.clone(),
        brute_force,
        redis_cache,
        pool_tuner,
        request_queue: request_queue.clone(),
        coalescing_manager: coalescing_manager.clone(),
        retention_manager,
        archiving_manager,
        popularity_tracker,
        quota_manager,
        migration_runner,
        audit_logger,
        webhook_manager,
        data_exporter,
        moderation_manager,
        reputation_manager,
        alerting_manager,
        feature_flags_manager,
        versioning_manager: versioning_manager.clone(),
        compression_manager: compression_manager.clone(),
        etag_manager: etag_manager.clone(),
        analytics_manager: analytics_manager.clone(),
        tenant_manager: tenant_manager.clone(),
        payment_manager: payment_manager.clone(),
        gdpr_manager: gdpr_manager.clone(),
        tos_manager: tos_manager.clone(),
        jurisdiction_manager: jurisdiction_manager.clone(),
    };

    // Create GraphQL schema
    let graphql_schema = graphql::create_schema(state.clone());
    tracing::info!("GraphQL schema initialized");

    // Build the router with state
    let stateful_routes = Router::new()
        .route("/health", get(health::health_check_simple))
        .route("/health/detailed", get(health::health_check_detailed))
        .route("/health/db", get(health::health_check_db))
        .nest("/api", api::router())
        .nest("/admin", admin::admin_routes())
        .merge(metrics::metrics_router())
        .merge(websocket::ws_routes(ws_hub))
        .with_state(state);

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Configure request tracing
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    // Configure security headers
    let security_config = if std::env::var("ENV").as_deref() == Ok("production") {
        security_headers::SecurityHeadersConfig::production()
    } else {
        security_headers::SecurityHeadersConfig::development()
    };

    // Merge with stateless routes (Swagger UI, Enhanced Docs, GraphQL)
    let app = stateful_routes
        .merge(openapi::swagger_routes())
        .merge(openapi::enhanced_docs_routes())
        .merge(graphql::graphql_routes(graphql_schema))
        .layer(axum::Extension(jwt_auth))
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(
            etag_manager.clone(),
            etag::etag_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            compression_manager.clone(),
            compression::compression_middleware,
        ))
        .layer(axum::middleware::from_fn(move |req, next| {
            security_headers::security_headers_middleware(security_config.clone(), req, next)
        }))
        .layer(axum::middleware::from_fn(
            endpoint_metrics::endpoint_metrics_middleware,
        ))
        .layer(axum::middleware::from_fn(
            correlation::correlation_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            versioning_manager.clone(),
            api_versioning::versioning_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            coalescing_manager.clone(),
            request_coalescing::request_coalescing_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            ip_rate_limiter.clone(),
            ip_rate_limit::ip_rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            request_queue.clone(),
            request_queue::request_queue_middleware,
        ))
        .layer(trace_layer);

    // Initialize shutdown coordinator
    let shutdown_coordinator = ShutdownCoordinator::with_default_timeout();
    let shutdown_rx = shutdown_coordinator.subscribe();
    tracing::info!("Graceful shutdown handler initialized (30s timeout)");

    // Start the server
    let bind_addr = config.bind_address();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Server listening on {}", listener.local_addr()?);
    tracing::info!("Metrics available at http://{}/metrics", bind_addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui", bind_addr);
    tracing::info!(
        "GraphQL Playground available at http://{}/graphql",
        bind_addr
    );

    // Spawn shutdown signal handler
    let shutdown_coord_clone = shutdown_coordinator.clone();
    tokio::spawn(async move {
        shutdown_coord_clone.wait_for_signal().await;
    });

    // Serve with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.resubscribe().recv().await;
            tracing::info!("Shutdown signal received, draining connections...");
        })
        .await?;

    tracing::info!("Server shut down successfully");
    Ok(())
}
