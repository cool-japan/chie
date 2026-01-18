//! Enum types for CHIE Protocol.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Content category for marketplace.
///
/// # Examples
///
/// ```
/// use chie_shared::ContentCategory;
///
/// // Using specific categories for content classification
/// let model_category = ContentCategory::ThreeDModels;
/// let audio_category = ContentCategory::Audio;
///
/// // Display formatting for UI
/// assert_eq!(model_category.to_string(), "3D Models");
/// assert_eq!(audio_category.to_string(), "Audio");
///
/// // Default category
/// let default = ContentCategory::default();
/// assert_eq!(default, ContentCategory::Other);
///
/// // Serialization example
/// let json = serde_json::to_string(&model_category).unwrap();
/// assert_eq!(json, "\"THREE_D_MODELS\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentCategory {
    /// 3D models (.fbx, .obj, .blend)
    ThreeDModels,
    /// Textures and materials
    Textures,
    /// Audio files (music, SFX)
    Audio,
    /// Scripts and code
    Scripts,
    /// Animations
    Animations,
    /// Complete asset packs
    AssetPacks,
    /// AI/ML models
    AiModels,
    /// Other content types
    #[default]
    Other,
}

impl fmt::Display for ContentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreeDModels => write!(f, "3D Models"),
            Self::Textures => write!(f, "Textures"),
            Self::Audio => write!(f, "Audio"),
            Self::Scripts => write!(f, "Scripts"),
            Self::Animations => write!(f, "Animations"),
            Self::AssetPacks => write!(f, "Asset Packs"),
            Self::AiModels => write!(f, "AI Models"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Content status in the system.
///
/// # Examples
///
/// ```
/// use chie_shared::ContentStatus;
///
/// // Track content through its lifecycle
/// let mut status = ContentStatus::default();
/// assert_eq!(status, ContentStatus::Processing);
///
/// // After processing completes
/// status = ContentStatus::Active;
/// assert_eq!(status.to_string(), "Active");
///
/// // Check if content is available
/// let is_available = matches!(status, ContentStatus::Active);
/// assert!(is_available);
///
/// // Serialization for API responses
/// let json = serde_json::to_string(&status).unwrap();
/// assert_eq!(json, "\"ACTIVE\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentStatus {
    /// Content is being processed (encrypted, pinned)
    #[default]
    Processing,
    /// Content is active and available
    Active,
    /// Content is pending review
    PendingReview,
    /// Content was rejected
    Rejected,
    /// Content was removed
    Removed,
}

impl fmt::Display for ContentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing => write!(f, "Processing"),
            Self::Active => write!(f, "Active"),
            Self::PendingReview => write!(f, "Pending Review"),
            Self::Rejected => write!(f, "Rejected"),
            Self::Removed => write!(f, "Removed"),
        }
    }
}

/// Node status.
///
/// # Examples
///
/// ```
/// use chie_shared::NodeStatus;
///
/// // Check node availability
/// let status = NodeStatus::Online;
/// assert_eq!(status.to_string(), "Online");
///
/// // Filter operational nodes
/// let nodes = vec![
///     NodeStatus::Online,
///     NodeStatus::Offline,
///     NodeStatus::Syncing,
///     NodeStatus::Banned,
/// ];
/// let operational: Vec<_> = nodes
///     .iter()
///     .filter(|s| matches!(s, NodeStatus::Online | NodeStatus::Syncing))
///     .collect();
/// assert_eq!(operational.len(), 2);
///
/// // Serialization
/// let json = serde_json::to_string(&status).unwrap();
/// assert_eq!(json, "\"ONLINE\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeStatus {
    Online,
    Offline,
    Syncing,
    Banned,
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Online => write!(f, "Online"),
            Self::Offline => write!(f, "Offline"),
            Self::Syncing => write!(f, "Syncing"),
            Self::Banned => write!(f, "Banned"),
        }
    }
}

/// User role in the system.
///
/// # Examples
///
/// ```
/// use chie_shared::UserRole;
///
/// // Role-based access control
/// let user_role = UserRole::Creator;
/// assert_eq!(user_role.to_string(), "Creator");
///
/// // Permission checking
/// let can_upload = matches!(user_role, UserRole::Creator | UserRole::Admin);
/// assert!(can_upload);
///
/// // Admin privileges
/// let admin_role = UserRole::Admin;
/// let is_admin = admin_role == UserRole::Admin;
/// assert!(is_admin);
///
/// // Serialization for JWT claims
/// let json = serde_json::to_string(&user_role).unwrap();
/// assert_eq!(json, "\"CREATOR\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserRole {
    /// Regular user (buyer/node operator)
    User,
    /// Content creator
    Creator,
    /// Platform administrator
    Admin,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Creator => write!(f, "Creator"),
            Self::Admin => write!(f, "Admin"),
        }
    }
}

/// Demand level for content.
///
/// # Examples
///
/// ```
/// use chie_shared::DemandLevel;
///
/// // Classify content demand for reward multipliers
/// let demand = DemandLevel::High;
/// assert_eq!(demand.to_string(), "High");
///
/// // Determine reward multiplier based on demand
/// let multiplier = match demand {
///     DemandLevel::Low => 1.0,
///     DemandLevel::Medium => 1.5,
///     DemandLevel::High => 2.0,
///     DemandLevel::VeryHigh => 3.0,
/// };
/// assert_eq!(multiplier, 2.0);
///
/// // Serialization for analytics
/// let json = serde_json::to_string(&demand).unwrap();
/// assert_eq!(json, "\"HIGH\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DemandLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl fmt::Display for DemandLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// Service status.
///
/// # Examples
///
/// ```
/// use chie_shared::ServiceStatus;
///
/// // Health check monitoring
/// let status = ServiceStatus::Healthy;
/// assert_eq!(status.to_string(), "Healthy");
///
/// // Determine if service can handle requests
/// let can_serve = !matches!(status, ServiceStatus::Down);
/// assert!(can_serve);
///
/// // Alert on degradation
/// let degraded_status = ServiceStatus::Degraded;
/// let should_alert = matches!(degraded_status, ServiceStatus::Degraded | ServiceStatus::Down);
/// assert!(should_alert);
///
/// // Serialization for status endpoint
/// let json = serde_json::to_string(&status).unwrap();
/// assert_eq!(json, "\"HEALTHY\"");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceStatus {
    /// Service is healthy.
    Healthy,
    /// Service is degraded.
    Degraded,
    /// Service is down.
    Down,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Down => write!(f, "Down"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_category_display() {
        assert_eq!(ContentCategory::ThreeDModels.to_string(), "3D Models");
        assert_eq!(ContentCategory::AiModels.to_string(), "AI Models");
    }

    #[test]
    fn test_content_status_display() {
        assert_eq!(ContentStatus::Processing.to_string(), "Processing");
        assert_eq!(ContentStatus::PendingReview.to_string(), "Pending Review");
    }

    #[test]
    fn test_node_status_display() {
        assert_eq!(NodeStatus::Online.to_string(), "Online");
        assert_eq!(NodeStatus::Offline.to_string(), "Offline");
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(UserRole::User.to_string(), "User");
        assert_eq!(UserRole::Creator.to_string(), "Creator");
        assert_eq!(UserRole::Admin.to_string(), "Admin");
    }

    #[test]
    fn test_demand_level_display() {
        assert_eq!(DemandLevel::Low.to_string(), "Low");
        assert_eq!(DemandLevel::VeryHigh.to_string(), "Very High");
    }

    #[test]
    fn test_service_status_display() {
        assert_eq!(ServiceStatus::Healthy.to_string(), "Healthy");
        assert_eq!(ServiceStatus::Degraded.to_string(), "Degraded");
        assert_eq!(ServiceStatus::Down.to_string(), "Down");
    }
}
