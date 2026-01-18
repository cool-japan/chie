//! Conversion traits between shared types and database models.
//!
//! This module provides traits for converting between the shared protocol
//! types and database-specific models. The implementations live in chie-coordinator
//! to avoid circular dependencies.

use crate::{
    BandwidthProof, ContentCategory, ContentMetadata, ContentStatus, DemandLevel, NodeStats,
    NodeStatus, UserRole,
};

/// Trait for converting from a database model to a shared type.
pub trait FromDbModel<T> {
    /// Convert from the database model.
    fn from_db_model(model: T) -> Self;
}

/// Trait for converting to a database model from a shared type.
pub trait ToDbModel<T> {
    /// Convert to the database model.
    fn to_db_model(&self) -> T;
}

/// Trait for types that can be converted bidirectionally with database models.
pub trait DbModelConvert<T>: FromDbModel<T> + ToDbModel<T> {}

// Blanket implementation
impl<S, T> DbModelConvert<T> for S where S: FromDbModel<T> + ToDbModel<T> {}

/// Input type for creating content from shared type.
#[derive(Debug, Clone)]
pub struct CreateContentInput {
    pub creator_id: uuid::Uuid,
    pub title: String,
    pub description: Option<String>,
    pub category: ContentCategory,
    pub tags: Vec<String>,
    pub cid: String,
    pub size_bytes: u64,
    pub chunk_count: u64,
    pub encryption_key: Option<Vec<u8>>,
    pub price: u64,
}

impl From<&ContentMetadata> for CreateContentInput {
    fn from(metadata: &ContentMetadata) -> Self {
        Self {
            creator_id: metadata.creator_id,
            title: metadata.title.clone(),
            description: Some(metadata.description.clone()),
            category: metadata.category,
            tags: metadata.tags.clone(),
            cid: metadata.cid.clone(),
            size_bytes: metadata.size_bytes,
            chunk_count: metadata.chunk_count,
            encryption_key: None, // Encryption key is stored separately
            price: metadata.price,
        }
    }
}

/// Input type for creating a bandwidth proof record.
#[derive(Debug, Clone)]
pub struct CreateProofInput {
    pub session_id: uuid::Uuid,
    pub content_cid: String,
    pub chunk_index: u64,
    pub bytes_transferred: u64,
    pub provider_peer_id: String,
    pub requester_peer_id: String,
    pub provider_public_key: Vec<u8>,
    pub requester_public_key: Vec<u8>,
    pub provider_signature: Vec<u8>,
    pub requester_signature: Vec<u8>,
    pub challenge_nonce: Vec<u8>,
    pub chunk_hash: Vec<u8>,
    pub start_timestamp_ms: i64,
    pub end_timestamp_ms: i64,
    pub latency_ms: u32,
}

impl From<&BandwidthProof> for CreateProofInput {
    fn from(proof: &BandwidthProof) -> Self {
        Self {
            session_id: proof.session_id,
            content_cid: proof.content_cid.clone(),
            chunk_index: proof.chunk_index,
            bytes_transferred: proof.bytes_transferred,
            provider_peer_id: proof.provider_peer_id.clone(),
            requester_peer_id: proof.requester_peer_id.clone(),
            provider_public_key: proof.provider_public_key.clone(),
            requester_public_key: proof.requester_public_key.clone(),
            provider_signature: proof.provider_signature.clone(),
            requester_signature: proof.requester_signature.clone(),
            challenge_nonce: proof.challenge_nonce.clone(),
            chunk_hash: proof.chunk_hash.clone(),
            start_timestamp_ms: proof.start_timestamp_ms,
            end_timestamp_ms: proof.end_timestamp_ms,
            latency_ms: proof.latency_ms,
        }
    }
}

/// Input type for creating a user.
#[derive(Debug, Clone)]
pub struct CreateUserInput {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: UserRole,
    pub referrer_id: Option<uuid::Uuid>,
}

impl CreateUserInput {
    /// Create a new user input for registration.
    #[must_use]
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        Self {
            username,
            email,
            password_hash,
            role: UserRole::User,
            referrer_id: None,
        }
    }

    /// Set the user role.
    #[must_use]
    pub const fn with_role(mut self, role: UserRole) -> Self {
        self.role = role;
        self
    }

    /// Set the referrer.
    #[must_use]
    pub fn with_referrer(mut self, referrer_id: uuid::Uuid) -> Self {
        self.referrer_id = Some(referrer_id);
        self
    }
}

/// Input type for creating a node.
#[derive(Debug, Clone)]
pub struct CreateNodeInput {
    pub user_id: uuid::Uuid,
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub max_storage_bytes: u64,
    pub max_bandwidth_bps: u64,
}

impl CreateNodeInput {
    /// Create a new node input.
    #[must_use]
    pub fn new(
        user_id: uuid::Uuid,
        peer_id: String,
        public_key: Vec<u8>,
        max_storage_bytes: u64,
        max_bandwidth_bps: u64,
    ) -> Self {
        Self {
            user_id,
            peer_id,
            public_key,
            max_storage_bytes,
            max_bandwidth_bps,
        }
    }
}

impl From<&NodeStats> for CreateNodeInput {
    fn from(stats: &NodeStats) -> Self {
        Self {
            user_id: uuid::Uuid::nil(), // Must be set separately
            peer_id: stats.peer_id.clone(),
            public_key: Vec::new(), // Must be set separately
            max_storage_bytes: stats.pinned_storage_bytes,
            max_bandwidth_bps: 0, // Default
        }
    }
}

/// Result of a database query for content list.
#[derive(Debug, Clone)]
pub struct ContentListResult {
    pub items: Vec<ContentMetadata>,
    pub total_count: u64,
    pub offset: u64,
    pub limit: u64,
}

impl ContentListResult {
    /// Create an empty result.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total_count: 0,
            offset: 0,
            limit: 0,
        }
    }

    /// Check if there are more results.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.offset + (self.items.len() as u64) < self.total_count
    }

    /// Get the next offset.
    #[must_use]
    pub fn next_offset(&self) -> u64 {
        self.offset + self.items.len() as u64
    }
}

/// Filter for content queries.
#[derive(Debug, Clone, Default)]
pub struct ContentFilter {
    /// Filter by creator ID.
    pub creator_id: Option<uuid::Uuid>,
    /// Filter by category.
    pub category: Option<ContentCategory>,
    /// Filter by status.
    pub status: Option<ContentStatus>,
    /// Filter by minimum price.
    pub min_price: Option<u64>,
    /// Filter by maximum price.
    pub max_price: Option<u64>,
    /// Search in title/description.
    pub search: Option<String>,
    /// Filter by tags (any match).
    pub tags: Option<Vec<String>>,
    /// Order by field.
    pub order_by: Option<ContentOrderBy>,
    /// Order direction.
    pub order_desc: bool,
}

impl ContentFilter {
    /// Create a new empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by creator.
    #[must_use]
    pub fn creator(mut self, creator_id: uuid::Uuid) -> Self {
        self.creator_id = Some(creator_id);
        self
    }

    /// Filter by category.
    #[must_use]
    pub fn category(mut self, category: ContentCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Filter by status.
    #[must_use]
    pub fn status(mut self, status: ContentStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by price range.
    #[must_use]
    pub fn price_range(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.min_price = min;
        self.max_price = max;
        self
    }

    /// Search in title and description.
    #[must_use]
    pub fn search(mut self, query: impl Into<String>) -> Self {
        self.search = Some(query.into());
        self
    }

    /// Filter by tags.
    #[must_use]
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Order by field.
    #[must_use]
    pub fn order_by(mut self, field: ContentOrderBy, desc: bool) -> Self {
        self.order_by = Some(field);
        self.order_desc = desc;
        self
    }
}

/// Content ordering options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentOrderBy {
    /// Order by creation date.
    CreatedAt,
    /// Order by update date.
    UpdatedAt,
    /// Order by price.
    Price,
    /// Order by download count.
    DownloadCount,
    /// Order by title.
    Title,
    /// Order by size.
    Size,
}

/// Filter for node queries.
#[derive(Debug, Clone, Default)]
pub struct NodeFilter {
    /// Filter by user ID.
    pub user_id: Option<uuid::Uuid>,
    /// Filter by status.
    pub status: Option<NodeStatus>,
    /// Filter by minimum reputation.
    pub min_reputation: Option<f32>,
    /// Filter by region.
    pub region: Option<String>,
}

impl NodeFilter {
    /// Create a new empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by user.
    #[must_use]
    pub fn user(mut self, user_id: uuid::Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Filter by status.
    #[must_use]
    pub fn status(mut self, status: NodeStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by minimum reputation.
    #[must_use]
    pub fn min_reputation(mut self, score: f32) -> Self {
        self.min_reputation = Some(score);
        self
    }

    /// Filter by region.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }
}

/// Trait for types that can be converted to SQL enum string.
pub trait ToSqlEnum {
    /// Get the SQL enum value as a string.
    fn to_sql_enum(&self) -> &'static str;
}

impl ToSqlEnum for ContentCategory {
    fn to_sql_enum(&self) -> &'static str {
        match self {
            Self::ThreeDModels => "THREE_D_MODELS",
            Self::Textures => "TEXTURES",
            Self::Audio => "AUDIO",
            Self::Scripts => "SCRIPTS",
            Self::Animations => "ANIMATIONS",
            Self::AssetPacks => "ASSET_PACKS",
            Self::AiModels => "AI_MODELS",
            Self::Other => "OTHER",
        }
    }
}

impl ToSqlEnum for ContentStatus {
    fn to_sql_enum(&self) -> &'static str {
        match self {
            Self::Processing => "PROCESSING",
            Self::Active => "ACTIVE",
            Self::PendingReview => "PENDING_REVIEW",
            Self::Rejected => "REJECTED",
            Self::Removed => "REMOVED",
        }
    }
}

impl ToSqlEnum for NodeStatus {
    fn to_sql_enum(&self) -> &'static str {
        match self {
            Self::Online => "ONLINE",
            Self::Offline => "OFFLINE",
            Self::Syncing => "SYNCING",
            Self::Banned => "BANNED",
        }
    }
}

impl ToSqlEnum for UserRole {
    fn to_sql_enum(&self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Creator => "CREATOR",
            Self::Admin => "ADMIN",
        }
    }
}

impl ToSqlEnum for DemandLevel {
    fn to_sql_enum(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::VeryHigh => "VERY_HIGH",
        }
    }
}

/// Trait for parsing from SQL enum string.
pub trait FromSqlEnum: Sized {
    /// Parse from SQL enum value.
    fn from_sql_enum(s: &str) -> Option<Self>;
}

impl FromSqlEnum for ContentCategory {
    fn from_sql_enum(s: &str) -> Option<Self> {
        match s {
            "THREE_D_MODELS" => Some(Self::ThreeDModels),
            "TEXTURES" => Some(Self::Textures),
            "AUDIO" => Some(Self::Audio),
            "SCRIPTS" => Some(Self::Scripts),
            "ANIMATIONS" => Some(Self::Animations),
            "ASSET_PACKS" => Some(Self::AssetPacks),
            "AI_MODELS" => Some(Self::AiModels),
            "OTHER" => Some(Self::Other),
            _ => None,
        }
    }
}

impl FromSqlEnum for ContentStatus {
    fn from_sql_enum(s: &str) -> Option<Self> {
        match s {
            "PROCESSING" => Some(Self::Processing),
            "ACTIVE" => Some(Self::Active),
            "PENDING_REVIEW" => Some(Self::PendingReview),
            "REJECTED" => Some(Self::Rejected),
            "REMOVED" => Some(Self::Removed),
            _ => None,
        }
    }
}

impl FromSqlEnum for NodeStatus {
    fn from_sql_enum(s: &str) -> Option<Self> {
        match s {
            "ONLINE" => Some(Self::Online),
            "OFFLINE" => Some(Self::Offline),
            "SYNCING" => Some(Self::Syncing),
            "BANNED" => Some(Self::Banned),
            _ => None,
        }
    }
}

impl FromSqlEnum for UserRole {
    fn from_sql_enum(s: &str) -> Option<Self> {
        match s {
            "USER" => Some(Self::User),
            "CREATOR" => Some(Self::Creator),
            "ADMIN" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl FromSqlEnum for DemandLevel {
    fn from_sql_enum(s: &str) -> Option<Self> {
        match s {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "VERY_HIGH" => Some(Self::VeryHigh),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_category_sql_enum() {
        assert_eq!(
            ContentCategory::ThreeDModels.to_sql_enum(),
            "THREE_D_MODELS"
        );
        assert_eq!(
            ContentCategory::from_sql_enum("THREE_D_MODELS"),
            Some(ContentCategory::ThreeDModels)
        );
        assert_eq!(ContentCategory::from_sql_enum("INVALID"), None);
    }

    #[test]
    fn test_content_filter_builder() {
        let filter = ContentFilter::new()
            .category(ContentCategory::Audio)
            .status(ContentStatus::Active)
            .price_range(Some(100), Some(1000))
            .order_by(ContentOrderBy::Price, true);

        assert_eq!(filter.category, Some(ContentCategory::Audio));
        assert_eq!(filter.status, Some(ContentStatus::Active));
        assert_eq!(filter.min_price, Some(100));
        assert_eq!(filter.max_price, Some(1000));
        assert_eq!(filter.order_by, Some(ContentOrderBy::Price));
        assert!(filter.order_desc);
    }

    #[test]
    fn test_content_list_result() {
        let result = ContentListResult {
            items: vec![],
            total_count: 100,
            offset: 0,
            limit: 10,
        };

        assert!(result.has_more());
        assert_eq!(result.next_offset(), 0);

        let empty = ContentListResult::empty();
        assert!(!empty.has_more());
    }
}
