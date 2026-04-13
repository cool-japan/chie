//! Admin dashboard API for CHIE Coordinator.
//!
//! This module provides REST endpoints for administrative operations:
//! - System statistics and health
//! - User management
//! - Content moderation
//! - Node management
//! - Configuration management

pub mod email;
pub mod management;
pub mod moderation;
pub mod operations;
pub mod system;

// Re-export all public types for backward compatibility with openapi.rs and other modules
pub use system::{
    AdminContentInfo, AdminFraudAlert, AdminNodeInfo, AdminProofInfo, AdminUserInfo,
    ComponentStatus, ContentListResponse, ContentStats, DailyStats, FlagContentRequest,
    FraudAlertListResponse, HealthStatus, HourlyCount, NodeListResponse, NodeStats, ProofStats,
    ResolveFraudRequest, SystemConfig, SystemStats, UserListResponse,
};

use crate::AppState;
use axum::Router;

/// Admin API routes.
pub fn admin_routes() -> Router<AppState> {
    Router::new()
        .merge(system::system_routes())
        .merge(management::management_routes())
        .merge(moderation::moderation_routes())
        .merge(operations::operations_routes())
        .merge(email::email_routes())
}
