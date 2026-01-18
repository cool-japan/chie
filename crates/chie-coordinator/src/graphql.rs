//! GraphQL API for CHIE Coordinator.
//!
//! This module provides a GraphQL interface for:
//! - Querying system statistics
//! - User and node information
//! - Content management
//! - Proof history
//! - Real-time subscriptions

use async_graphql::{
    Context, Enum, InputObject, Object, Result, Schema, SimpleObject, Subscription,
};
use chrono::{DateTime, Utc};
use futures::stream::{self, Stream};
use std::time::Duration;
use uuid::Uuid;

use crate::AppState;

/// GraphQL schema type alias.
pub type CoordinatorSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Create the GraphQL schema.
pub fn create_schema(state: AppState) -> CoordinatorSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(state)
        .finish()
}

// ============================================================================
// Query Types
// ============================================================================

/// Root query object.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get system statistics.
    async fn system_stats(&self, ctx: &Context<'_>) -> Result<SystemStats> {
        let _state = ctx.data::<AppState>()?;

        // In production, these would come from the database
        Ok(SystemStats {
            total_users: 0,
            active_users_24h: 0,
            total_nodes: 0,
            active_nodes: 0,
            total_content: 0,
            total_storage_bytes: 0,
            proofs_today: 0,
            rewards_today: 0,
        })
    }

    /// Get a user by ID.
    async fn user(&self, ctx: &Context<'_>, id: Uuid) -> Result<Option<User>> {
        let _state = ctx.data::<AppState>()?;
        let _ = id;

        // In production, query the database
        Ok(None)
    }

    /// List users with pagination.
    async fn users(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: i32,
        #[graphql(default = 20)] limit: i32,
        filter: Option<UserFilter>,
    ) -> Result<UserConnection> {
        let _state = ctx.data::<AppState>()?;
        let _ = (offset, limit, filter);

        Ok(UserConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                total_count: 0,
            },
        })
    }

    /// Get a node by ID.
    async fn node(&self, ctx: &Context<'_>, id: Uuid) -> Result<Option<Node>> {
        let _state = ctx.data::<AppState>()?;
        let _ = id;

        Ok(None)
    }

    /// List nodes with pagination.
    async fn nodes(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: i32,
        #[graphql(default = 20)] limit: i32,
        filter: Option<NodeFilter>,
    ) -> Result<NodeConnection> {
        let _state = ctx.data::<AppState>()?;
        let _ = (offset, limit, filter);

        Ok(NodeConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                total_count: 0,
            },
        })
    }

    /// Get content by CID.
    async fn content(&self, ctx: &Context<'_>, cid: String) -> Result<Option<Content>> {
        let _state = ctx.data::<AppState>()?;
        let _ = cid;

        Ok(None)
    }

    /// List content with pagination.
    async fn contents(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: i32,
        #[graphql(default = 20)] limit: i32,
        filter: Option<ContentFilter>,
    ) -> Result<ContentConnection> {
        let _state = ctx.data::<AppState>()?;
        let _ = (offset, limit, filter);

        Ok(ContentConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                total_count: 0,
            },
        })
    }

    /// Get proof by ID.
    async fn proof(&self, ctx: &Context<'_>, id: Uuid) -> Result<Option<Proof>> {
        let _state = ctx.data::<AppState>()?;
        let _ = id;

        Ok(None)
    }

    /// List recent proofs.
    async fn proofs(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: i32,
        #[graphql(default = 20)] limit: i32,
        filter: Option<ProofFilter>,
    ) -> Result<ProofConnection> {
        let _state = ctx.data::<AppState>()?;
        let _ = (offset, limit, filter);

        Ok(ProofConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                total_count: 0,
            },
        })
    }

    /// Get fraud alerts.
    async fn fraud_alerts(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: i32,
        #[graphql(default = 20)] limit: i32,
        status: Option<FraudAlertStatus>,
    ) -> Result<FraudAlertConnection> {
        let _state = ctx.data::<AppState>()?;
        let _ = (offset, limit, status);

        Ok(FraudAlertConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                total_count: 0,
            },
        })
    }

    /// Get rewards for a user.
    async fn user_rewards(&self, ctx: &Context<'_>, user_id: Uuid) -> Result<UserRewards> {
        let _state = ctx.data::<AppState>()?;
        let _ = user_id;

        Ok(UserRewards {
            user_id,
            total_earned: 0,
            earned_today: 0,
            earned_this_week: 0,
            earned_this_month: 0,
            pending_payout: 0,
        })
    }

    /// Get coordinator health status.
    async fn health(&self, _ctx: &Context<'_>) -> Result<HealthStatus> {
        Ok(HealthStatus {
            status: ServiceStatus::Healthy,
            uptime_secs: 0,
            version: env!("CARGO_PKG_VERSION").to_string(),
            database_status: ServiceStatus::Healthy,
            redis_status: ServiceStatus::Healthy,
        })
    }
}

// ============================================================================
// Mutation Types
// ============================================================================

/// Root mutation object.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Ban a user.
    async fn ban_user(&self, ctx: &Context<'_>, id: Uuid, reason: String) -> Result<User> {
        let _state = ctx.data::<AppState>()?;

        Ok(User {
            id,
            public_key: String::new(),
            status: UserStatus::Banned,
            created_at: Utc::now(),
            total_earnings: 0,
            proof_count: 0,
            ban_reason: Some(reason),
        })
    }

    /// Unban a user.
    async fn unban_user(&self, ctx: &Context<'_>, id: Uuid) -> Result<User> {
        let _state = ctx.data::<AppState>()?;

        Ok(User {
            id,
            public_key: String::new(),
            status: UserStatus::Active,
            created_at: Utc::now(),
            total_earnings: 0,
            proof_count: 0,
            ban_reason: None,
        })
    }

    /// Suspend a node.
    async fn suspend_node(&self, ctx: &Context<'_>, id: Uuid, reason: String) -> Result<Node> {
        let _state = ctx.data::<AppState>()?;

        Ok(Node {
            id,
            user_id: Uuid::nil(),
            peer_id: String::new(),
            status: NodeStatus::Suspended,
            last_seen: Utc::now(),
            total_earnings: 0,
            proof_count: 0,
            uptime_percent: 0.0,
            suspension_reason: Some(reason),
        })
    }

    /// Unsuspend a node.
    async fn unsuspend_node(&self, ctx: &Context<'_>, id: Uuid) -> Result<Node> {
        let _state = ctx.data::<AppState>()?;

        Ok(Node {
            id,
            user_id: Uuid::nil(),
            peer_id: String::new(),
            status: NodeStatus::Active,
            last_seen: Utc::now(),
            total_earnings: 0,
            proof_count: 0,
            uptime_percent: 0.0,
            suspension_reason: None,
        })
    }

    /// Flag content for review.
    async fn flag_content(
        &self,
        ctx: &Context<'_>,
        cid: String,
        reason: String,
    ) -> Result<Content> {
        let _state = ctx.data::<AppState>()?;

        Ok(Content {
            id: Uuid::new_v4(),
            cid,
            title: None,
            creator_id: Uuid::nil(),
            size_bytes: 0,
            status: ContentStatus::Flagged,
            created_at: Utc::now(),
            transfer_count: 0,
            flag_reason: Some(reason),
        })
    }

    /// Remove flagged content.
    async fn remove_content(&self, ctx: &Context<'_>, cid: String) -> Result<bool> {
        let _state = ctx.data::<AppState>()?;
        let _ = cid;

        Ok(true)
    }

    /// Resolve a fraud alert.
    async fn resolve_fraud_alert(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        resolution: String,
        notes: Option<String>,
    ) -> Result<FraudAlert> {
        let _state = ctx.data::<AppState>()?;

        Ok(FraudAlert {
            id,
            alert_type: FraudAlertType::AnomalousActivity,
            severity: FraudSeverity::Medium,
            node_id: Uuid::nil(),
            details: String::new(),
            status: FraudAlertStatus::Resolved,
            created_at: Utc::now(),
            resolved_at: Some(Utc::now()),
            resolution: Some(resolution),
            notes,
        })
    }

    /// Update system configuration.
    async fn update_config(&self, ctx: &Context<'_>, input: ConfigInput) -> Result<SystemConfig> {
        let _state = ctx.data::<AppState>()?;

        Ok(SystemConfig {
            base_reward_per_gb: input.base_reward_per_gb.unwrap_or(10),
            max_demand_multiplier: input.max_demand_multiplier.unwrap_or(3.0),
            min_demand_multiplier: input.min_demand_multiplier.unwrap_or(0.5),
            creator_share: input.creator_share.unwrap_or(0.1),
            platform_fee_share: input.platform_fee_share.unwrap_or(0.1),
            fraud_zscore_threshold: input.fraud_zscore_threshold.unwrap_or(3.0),
            timestamp_window_secs: input.timestamp_window_secs.unwrap_or(300),
        })
    }
}

// ============================================================================
// Subscription Types
// ============================================================================

/// Root subscription object.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Subscribe to system statistics updates.
    /// Emits updated statistics every 5 seconds.
    async fn system_stats(&self, ctx: &Context<'_>) -> impl Stream<Item = SystemStats> {
        let _state = ctx.data::<AppState>().ok();

        stream::unfold((), |_| async move {
            tokio::time::sleep(Duration::from_secs(5)).await;

            // In production, query real stats from database
            Some((
                SystemStats {
                    total_users: 0,
                    active_users_24h: 0,
                    total_nodes: 0,
                    active_nodes: 0,
                    total_content: 0,
                    total_storage_bytes: 0,
                    proofs_today: 0,
                    rewards_today: 0,
                },
                (),
            ))
        })
    }

    /// Subscribe to new proof submissions.
    /// Emits a proof event whenever a new proof is verified.
    async fn proof_submitted(&self, ctx: &Context<'_>) -> impl Stream<Item = ProofEvent> {
        let _state = ctx.data::<AppState>().ok();

        stream::unfold((), |_| async move {
            tokio::time::sleep(Duration::from_secs(2)).await;

            // In production, use a broadcast channel to emit real proof events
            Some((
                ProofEvent {
                    proof_id: Uuid::new_v4(),
                    provider_id: Uuid::nil(),
                    requester_id: Uuid::nil(),
                    content_cid: String::new(),
                    bytes_transferred: 0,
                    reward_points: 0,
                    timestamp: Utc::now(),
                },
                (),
            ))
        })
    }

    /// Subscribe to fraud alerts.
    /// Emits an alert whenever fraud is detected.
    async fn fraud_alert(
        &self,
        ctx: &Context<'_>,
        severity: Option<FraudSeverity>,
    ) -> impl Stream<Item = FraudAlert> {
        let _state = ctx.data::<AppState>().ok();
        let filter_severity = severity;

        stream::unfold((), move |_| {
            let severity_filter = filter_severity;
            async move {
                tokio::time::sleep(Duration::from_secs(10)).await;

                // In production, use a broadcast channel for real alerts
                let alert = FraudAlert {
                    id: Uuid::new_v4(),
                    alert_type: FraudAlertType::AnomalousActivity,
                    severity: FraudSeverity::Medium,
                    node_id: Uuid::nil(),
                    details: String::new(),
                    status: FraudAlertStatus::Open,
                    created_at: Utc::now(),
                    resolved_at: None,
                    resolution: None,
                    notes: None,
                };

                // Filter by severity if specified
                if let Some(sev) = severity_filter {
                    if alert.severity != sev {
                        return Some((alert, ()));
                    }
                }

                Some((alert, ()))
            }
        })
    }

    /// Subscribe to node status changes.
    /// Emits an event when a node comes online, goes offline, or is suspended.
    async fn node_status_changed(&self, ctx: &Context<'_>) -> impl Stream<Item = NodeStatusEvent> {
        let _state = ctx.data::<AppState>().ok();

        stream::unfold((), |_| async move {
            tokio::time::sleep(Duration::from_secs(15)).await;

            // In production, use a broadcast channel for real node events
            Some((
                NodeStatusEvent {
                    node_id: Uuid::nil(),
                    peer_id: String::new(),
                    old_status: NodeStatus::Active,
                    new_status: NodeStatus::Offline,
                    timestamp: Utc::now(),
                },
                (),
            ))
        })
    }

    /// Subscribe to content moderation events.
    /// Emits an event when content is flagged or moderated.
    async fn content_moderation(
        &self,
        ctx: &Context<'_>,
    ) -> impl Stream<Item = ContentModerationEvent> {
        let _state = ctx.data::<AppState>().ok();

        stream::unfold((), |_| async move {
            tokio::time::sleep(Duration::from_secs(20)).await;

            // In production, use a broadcast channel for real moderation events
            Some((
                ContentModerationEvent {
                    content_id: Uuid::new_v4(),
                    cid: String::new(),
                    action: ModerationEventAction::Flagged,
                    reason: Some("Policy violation".to_string()),
                    moderator_id: None,
                    timestamp: Utc::now(),
                },
                (),
            ))
        })
    }

    /// Subscribe to health status changes.
    /// Emits updates when system or component health changes.
    async fn health_status(&self, ctx: &Context<'_>) -> impl Stream<Item = HealthStatus> {
        let _state = ctx.data::<AppState>().ok();

        stream::unfold((), |_| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;

            // In production, query real health status
            Some((
                HealthStatus {
                    status: ServiceStatus::Healthy,
                    uptime_secs: 0,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    database_status: ServiceStatus::Healthy,
                    redis_status: ServiceStatus::Healthy,
                },
                (),
            ))
        })
    }
}

// ============================================================================
// Subscription Event Types
// ============================================================================

/// Proof submission event.
#[derive(SimpleObject, Clone)]
pub struct ProofEvent {
    /// Proof ID.
    pub proof_id: Uuid,
    /// Provider node ID.
    pub provider_id: Uuid,
    /// Requester node ID.
    pub requester_id: Uuid,
    /// Content CID.
    pub content_cid: String,
    /// Bytes transferred.
    pub bytes_transferred: i64,
    /// Reward points earned.
    pub reward_points: i64,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Node status change event.
#[derive(SimpleObject, Clone)]
pub struct NodeStatusEvent {
    /// Node ID.
    pub node_id: Uuid,
    /// libp2p peer ID.
    pub peer_id: String,
    /// Previous status.
    pub old_status: NodeStatus,
    /// New status.
    pub new_status: NodeStatus,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Content moderation event.
#[derive(SimpleObject, Clone)]
pub struct ContentModerationEvent {
    /// Content ID.
    pub content_id: Uuid,
    /// Content CID.
    pub cid: String,
    /// Moderation action taken.
    pub action: ModerationEventAction,
    /// Reason for action.
    pub reason: Option<String>,
    /// Moderator ID if manually moderated.
    pub moderator_id: Option<Uuid>,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Moderation event action.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ModerationEventAction {
    /// Content was flagged for review.
    Flagged,
    /// Content was approved.
    Approved,
    /// Content was removed.
    Removed,
    /// Content was quarantined.
    Quarantined,
}

// ============================================================================
// Object Types
// ============================================================================

/// System statistics.
#[derive(SimpleObject)]
pub struct SystemStats {
    /// Total registered users.
    pub total_users: i64,
    /// Active users in last 24 hours.
    pub active_users_24h: i64,
    /// Total nodes.
    pub total_nodes: i64,
    /// Active nodes.
    pub active_nodes: i64,
    /// Total content items.
    pub total_content: i64,
    /// Total storage used in bytes.
    pub total_storage_bytes: i64,
    /// Proofs verified today.
    pub proofs_today: i64,
    /// Rewards distributed today.
    pub rewards_today: i64,
}

/// User object.
#[derive(SimpleObject)]
pub struct User {
    /// Unique user ID.
    pub id: Uuid,
    /// Public key (hex encoded).
    pub public_key: String,
    /// User status.
    pub status: UserStatus,
    /// When the user registered.
    pub created_at: DateTime<Utc>,
    /// Total earnings in points.
    pub total_earnings: i64,
    /// Total proof count.
    pub proof_count: i64,
    /// Ban reason if banned.
    pub ban_reason: Option<String>,
}

/// User status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum UserStatus {
    /// User is active.
    Active,
    /// User is banned.
    Banned,
    /// User is suspended.
    Suspended,
}

/// Node object.
#[derive(SimpleObject)]
pub struct Node {
    /// Unique node ID.
    pub id: Uuid,
    /// Owner user ID.
    pub user_id: Uuid,
    /// libp2p peer ID.
    pub peer_id: String,
    /// Node status.
    pub status: NodeStatus,
    /// Last seen timestamp.
    pub last_seen: DateTime<Utc>,
    /// Total earnings.
    pub total_earnings: i64,
    /// Total proof count.
    pub proof_count: i64,
    /// Uptime percentage.
    pub uptime_percent: f64,
    /// Suspension reason if suspended.
    pub suspension_reason: Option<String>,
}

/// Node status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum NodeStatus {
    /// Node is active and responding.
    Active,
    /// Node is offline.
    Offline,
    /// Node is suspended.
    Suspended,
}

/// Content object.
#[derive(SimpleObject)]
pub struct Content {
    /// Internal content ID.
    pub id: Uuid,
    /// Content CID.
    pub cid: String,
    /// Content title.
    pub title: Option<String>,
    /// Creator user ID.
    pub creator_id: Uuid,
    /// Size in bytes.
    pub size_bytes: i64,
    /// Content status.
    pub status: ContentStatus,
    /// When content was registered.
    pub created_at: DateTime<Utc>,
    /// Number of transfers.
    pub transfer_count: i64,
    /// Flag reason if flagged.
    pub flag_reason: Option<String>,
}

/// Content status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ContentStatus {
    /// Content is active.
    Active,
    /// Content is flagged for review.
    Flagged,
    /// Content has been removed.
    Removed,
}

/// Proof object.
#[derive(SimpleObject)]
pub struct Proof {
    /// Unique proof ID.
    pub id: Uuid,
    /// Provider node ID.
    pub provider_id: Uuid,
    /// Requester node ID.
    pub requester_id: Uuid,
    /// Content CID.
    pub content_cid: String,
    /// Bytes transferred.
    pub bytes_transferred: i64,
    /// Latency in milliseconds.
    pub latency_ms: i32,
    /// Proof status.
    pub status: ProofStatus,
    /// Reward points earned.
    pub reward: i64,
    /// When proof was submitted.
    pub created_at: DateTime<Utc>,
}

/// Proof status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProofStatus {
    /// Proof is pending verification.
    Pending,
    /// Proof has been verified.
    Verified,
    /// Proof was rejected.
    Rejected,
}

/// Fraud alert object.
#[derive(SimpleObject)]
pub struct FraudAlert {
    /// Alert ID.
    pub id: Uuid,
    /// Type of fraud detected.
    pub alert_type: FraudAlertType,
    /// Severity level.
    pub severity: FraudSeverity,
    /// Associated node ID.
    pub node_id: Uuid,
    /// Alert details.
    pub details: String,
    /// Alert status.
    pub status: FraudAlertStatus,
    /// When alert was created.
    pub created_at: DateTime<Utc>,
    /// When alert was resolved.
    pub resolved_at: Option<DateTime<Utc>>,
    /// Resolution action taken.
    pub resolution: Option<String>,
    /// Additional notes.
    pub notes: Option<String>,
}

/// Fraud alert type.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum FraudAlertType {
    /// Anomalous activity detected.
    AnomalousActivity,
    /// Signature verification failed.
    InvalidSignature,
    /// Timestamp out of valid range.
    TimestampAnomaly,
    /// Replay attack detected.
    ReplayAttack,
    /// Collusion detected.
    Collusion,
}

/// Fraud severity level.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum FraudSeverity {
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

/// Fraud alert status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum FraudAlertStatus {
    /// Alert is open.
    Open,
    /// Alert is under investigation.
    Investigating,
    /// Alert has been resolved.
    Resolved,
    /// Alert was dismissed.
    Dismissed,
}

/// User rewards information.
#[derive(SimpleObject)]
pub struct UserRewards {
    /// User ID.
    pub user_id: Uuid,
    /// Total earned points.
    pub total_earned: i64,
    /// Points earned today.
    pub earned_today: i64,
    /// Points earned this week.
    pub earned_this_week: i64,
    /// Points earned this month.
    pub earned_this_month: i64,
    /// Pending payout amount.
    pub pending_payout: i64,
}

/// Health status.
#[derive(SimpleObject)]
pub struct HealthStatus {
    /// Overall service status.
    pub status: ServiceStatus,
    /// Uptime in seconds.
    pub uptime_secs: i64,
    /// Version string.
    pub version: String,
    /// Database status.
    pub database_status: ServiceStatus,
    /// Redis status.
    pub redis_status: ServiceStatus,
}

/// Service status.
#[derive(Enum, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceStatus {
    /// Service is healthy.
    Healthy,
    /// Service is degraded.
    Degraded,
    /// Service is unhealthy.
    Unhealthy,
}

/// System configuration.
#[derive(SimpleObject)]
pub struct SystemConfig {
    /// Base reward per GB.
    pub base_reward_per_gb: i64,
    /// Maximum demand multiplier.
    pub max_demand_multiplier: f64,
    /// Minimum demand multiplier.
    pub min_demand_multiplier: f64,
    /// Creator share (0.0-1.0).
    pub creator_share: f64,
    /// Platform fee share (0.0-1.0).
    pub platform_fee_share: f64,
    /// Fraud detection z-score threshold.
    pub fraud_zscore_threshold: f64,
    /// Timestamp window in seconds.
    pub timestamp_window_secs: i64,
}

// ============================================================================
// Input Types
// ============================================================================

/// User filter input.
#[derive(InputObject)]
pub struct UserFilter {
    /// Filter by status.
    pub status: Option<UserStatus>,
    /// Search by public key prefix.
    pub public_key_prefix: Option<String>,
}

/// Node filter input.
#[derive(InputObject)]
pub struct NodeFilter {
    /// Filter by status.
    pub status: Option<NodeStatus>,
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
}

/// Content filter input.
#[derive(InputObject)]
pub struct ContentFilter {
    /// Filter by status.
    pub status: Option<ContentStatus>,
    /// Filter by creator ID.
    pub creator_id: Option<Uuid>,
}

/// Proof filter input.
#[derive(InputObject)]
pub struct ProofFilter {
    /// Filter by status.
    pub status: Option<ProofStatus>,
    /// Filter by provider ID.
    pub provider_id: Option<Uuid>,
    /// Filter by requester ID.
    pub requester_id: Option<Uuid>,
    /// Filter by content CID.
    pub content_cid: Option<String>,
}

/// Configuration update input.
#[derive(InputObject)]
pub struct ConfigInput {
    /// Base reward per GB.
    pub base_reward_per_gb: Option<i64>,
    /// Maximum demand multiplier.
    pub max_demand_multiplier: Option<f64>,
    /// Minimum demand multiplier.
    pub min_demand_multiplier: Option<f64>,
    /// Creator share.
    pub creator_share: Option<f64>,
    /// Platform fee share.
    pub platform_fee_share: Option<f64>,
    /// Fraud z-score threshold.
    pub fraud_zscore_threshold: Option<f64>,
    /// Timestamp window.
    pub timestamp_window_secs: Option<i64>,
}

// ============================================================================
// Connection Types (Pagination)
// ============================================================================

/// Page information for pagination.
#[derive(SimpleObject)]
pub struct PageInfo {
    /// Whether there's a next page.
    pub has_next_page: bool,
    /// Whether there's a previous page.
    pub has_previous_page: bool,
    /// Total count of items.
    pub total_count: i64,
}

/// User connection for pagination.
#[derive(SimpleObject)]
pub struct UserConnection {
    /// List of users.
    pub edges: Vec<User>,
    /// Pagination info.
    pub page_info: PageInfo,
}

/// Node connection for pagination.
#[derive(SimpleObject)]
pub struct NodeConnection {
    /// List of nodes.
    pub edges: Vec<Node>,
    /// Pagination info.
    pub page_info: PageInfo,
}

/// Content connection for pagination.
#[derive(SimpleObject)]
pub struct ContentConnection {
    /// List of content.
    pub edges: Vec<Content>,
    /// Pagination info.
    pub page_info: PageInfo,
}

/// Proof connection for pagination.
#[derive(SimpleObject)]
pub struct ProofConnection {
    /// List of proofs.
    pub edges: Vec<Proof>,
    /// Pagination info.
    pub page_info: PageInfo,
}

/// Fraud alert connection for pagination.
#[derive(SimpleObject)]
pub struct FraudAlertConnection {
    /// List of fraud alerts.
    pub edges: Vec<FraudAlert>,
    /// Pagination info.
    pub page_info: PageInfo,
}

// ============================================================================
// Axum Integration
// ============================================================================

use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};

/// GraphQL handler.
async fn graphql_handler(
    State(schema): State<CoordinatorSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// GraphQL Playground HTML.
async fn graphql_playground() -> impl IntoResponse {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}

/// Create GraphQL routes.
pub fn graphql_routes(schema: CoordinatorSchema) -> Router {
    Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .with_state(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_status_enum() {
        assert_eq!(UserStatus::Active, UserStatus::Active);
        assert_ne!(UserStatus::Active, UserStatus::Banned);
    }

    #[test]
    fn test_node_status_enum() {
        assert_eq!(NodeStatus::Active, NodeStatus::Active);
        assert_ne!(NodeStatus::Active, NodeStatus::Offline);
    }

    #[test]
    fn test_fraud_severity_enum() {
        assert_eq!(FraudSeverity::High, FraudSeverity::High);
        assert_ne!(FraudSeverity::Low, FraudSeverity::Critical);
    }

    #[test]
    fn test_moderation_event_action_enum() {
        assert_eq!(
            ModerationEventAction::Flagged,
            ModerationEventAction::Flagged
        );
        assert_ne!(
            ModerationEventAction::Flagged,
            ModerationEventAction::Approved
        );
    }

    #[test]
    fn test_proof_event_creation() {
        let event = ProofEvent {
            proof_id: Uuid::new_v4(),
            provider_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            content_cid: "QmTest123".to_string(),
            bytes_transferred: 1024,
            reward_points: 100,
            timestamp: Utc::now(),
        };

        assert_eq!(event.content_cid, "QmTest123");
        assert_eq!(event.bytes_transferred, 1024);
        assert_eq!(event.reward_points, 100);
    }

    #[test]
    fn test_node_status_event_creation() {
        let event = NodeStatusEvent {
            node_id: Uuid::new_v4(),
            peer_id: "12D3KooTest".to_string(),
            old_status: NodeStatus::Active,
            new_status: NodeStatus::Offline,
            timestamp: Utc::now(),
        };

        assert_eq!(event.old_status, NodeStatus::Active);
        assert_eq!(event.new_status, NodeStatus::Offline);
    }

    #[test]
    fn test_content_moderation_event_creation() {
        let event = ContentModerationEvent {
            content_id: Uuid::new_v4(),
            cid: "QmContent123".to_string(),
            action: ModerationEventAction::Flagged,
            reason: Some("Inappropriate content".to_string()),
            moderator_id: Some(Uuid::new_v4()),
            timestamp: Utc::now(),
        };

        assert_eq!(event.action, ModerationEventAction::Flagged);
        assert_eq!(event.reason, Some("Inappropriate content".to_string()));
    }
}
