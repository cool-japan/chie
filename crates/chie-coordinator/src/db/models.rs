//! Database models for CHIE Protocol.
//!
//! NOTE: Some models are not yet used but are prepared for future features.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// Enums (matching PostgreSQL enum types)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "user_role", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserRole {
    User,
    Creator,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "kyc_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KycStatus {
    None,
    Pending,
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "content_category", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentCategory {
    ThreeDModels,
    Textures,
    Audio,
    Scripts,
    Animations,
    AssetPacks,
    AiModels,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "content_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentStatus {
    Processing,
    Active,
    PendingReview,
    Rejected,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "node_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeStatus {
    Online,
    Offline,
    Syncing,
    Banned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "proof_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatus {
    Pending,
    Verified,
    Rejected,
    Rewarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "transaction_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionType {
    BandwidthReward,
    CreatorPayout,
    ReferralReward,
    Purchase,
    Withdrawal,
    Bonus,
    PlatformFee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "purchase_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PurchaseStatus {
    Pending,
    Completed,
    Refunded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "fraud_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FraudStatus {
    Suspected,
    Confirmed,
    Cleared,
}

// ============================================================================
// Models
// ============================================================================

/// User account.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: UserRole,
    pub peer_id: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub points_balance: i64,
    pub referrer_id: Option<Uuid>,
    pub referral_code: Option<String>,
    pub kyc_status: KycStatus,
    pub stripe_account_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Content item.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Content {
    pub id: Uuid,
    pub creator_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub category: ContentCategory,
    pub tags: Vec<String>,
    pub cid: String,
    pub size_bytes: i64,
    pub chunk_count: i32,
    pub encryption_key: Option<Vec<u8>>,
    pub price: i64,
    pub status: ContentStatus,
    pub preview_images: Vec<String>,
    pub download_count: i64,
    pub total_revenue: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Node instance.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Node {
    pub id: Uuid,
    pub user_id: Uuid,
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub status: NodeStatus,
    pub max_storage_bytes: i64,
    pub used_storage_bytes: i64,
    pub max_bandwidth_bps: i64,
    pub total_bandwidth_bytes: i64,
    pub total_earnings: i64,
    pub uptime_seconds: i64,
    pub reputation_score: f32,
    pub successful_transfers: i64,
    pub failed_transfers: i64,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub ip_address: Option<String>,
    pub region: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Content pin (node hosting content).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ContentPin {
    pub id: Uuid,
    pub node_id: Uuid,
    pub content_id: Uuid,
    pub pinned_at: DateTime<Utc>,
    pub bytes_provided: i64,
    pub earnings_from_content: i64,
    pub last_served_at: Option<DateTime<Utc>>,
}

/// Bandwidth proof record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BandwidthProofRecord {
    pub id: Uuid,
    pub session_id: Uuid,
    pub content_id: Uuid,
    pub chunk_index: i32,
    pub bytes_transferred: i64,
    pub provider_node_id: Uuid,
    pub requester_node_id: Uuid,
    pub provider_public_key: Vec<u8>,
    pub requester_public_key: Vec<u8>,
    pub provider_signature: Vec<u8>,
    pub requester_signature: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub chunk_hash: Vec<u8>,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub latency_ms: i32,
    pub status: ProofStatus,
    pub verified_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
    pub reward_amount: Option<i64>,
    pub rewarded_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Point transaction.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PointTransaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub amount: i64,
    #[sqlx(rename = "type")]
    pub transaction_type: TransactionType,
    pub proof_id: Option<Uuid>,
    pub content_id: Option<Uuid>,
    pub related_user_id: Option<Uuid>,
    pub balance_before: i64,
    pub balance_after: i64,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Purchase record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Purchase {
    pub id: Uuid,
    pub buyer_id: Uuid,
    pub content_id: Uuid,
    pub price: i64,
    pub creator_payout: i64,
    pub platform_fee: i64,
    pub referral_rewards: i64,
    pub status: PurchaseStatus,
    pub encryption_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Content demand metrics.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ContentDemandHourly {
    pub id: Uuid,
    pub content_id: Uuid,
    pub hour: DateTime<Utc>,
    pub download_requests: i64,
    pub bytes_transferred: i64,
    pub active_seeders: i32,
    pub average_latency_ms: Option<i32>,
}

/// Fraud report.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FraudReport {
    pub id: Uuid,
    pub node_id: Uuid,
    pub detection_method: String,
    pub confidence_score: f32,
    pub status: FraudStatus,
    pub evidence: serde_json::Value,
    pub related_proofs: Vec<Uuid>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Input types for creating records
// ============================================================================

/// Input for creating a new user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: UserRole,
    pub referrer_id: Option<Uuid>,
}

/// Input for creating new content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContent {
    pub creator_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub category: ContentCategory,
    pub tags: Vec<String>,
    pub cid: String,
    pub size_bytes: i64,
    pub chunk_count: i32,
    pub encryption_key: Option<Vec<u8>>,
    pub price: i64,
}

/// Input for registering a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNode {
    pub user_id: Uuid,
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub max_storage_bytes: i64,
    pub max_bandwidth_bps: i64,
}

/// Input for submitting a bandwidth proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBandwidthProof {
    pub session_id: Uuid,
    pub content_id: Uuid,
    pub chunk_index: i32,
    pub bytes_transferred: i64,
    pub provider_node_id: Uuid,
    pub requester_node_id: Uuid,
    pub provider_public_key: Vec<u8>,
    pub requester_public_key: Vec<u8>,
    pub provider_signature: Vec<u8>,
    pub requester_signature: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub chunk_hash: Vec<u8>,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub latency_ms: i32,
}
