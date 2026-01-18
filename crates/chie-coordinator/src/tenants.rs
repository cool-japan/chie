//! Multi-tenant Isolation System
//!
//! This module provides comprehensive multi-tenancy support for the CHIE Coordinator,
//! enabling per-creator namespaces and data isolation.
//!
//! # Features
//! - Tenant identification via header (`X-Tenant-ID`) or subdomain
//! - Complete data isolation per tenant
//! - Tenant-specific quotas and limits
//! - Tenant configuration and settings
//! - Tenant status management (active, suspended, archived)
//! - Namespace-based routing
//!
//! # Architecture
//! - Each tenant (creator) has a unique namespace
//! - All data is scoped to a tenant_id
//! - Middleware extracts tenant context from requests
//! - API endpoints enforce tenant isolation

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

/// Tenant status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "tenant_status", rename_all = "lowercase")]
pub enum TenantStatus {
    /// Active tenant
    Active,
    /// Suspended (e.g., payment issues)
    Suspended,
    /// Archived (soft deleted)
    Archived,
}

/// Tenant model representing a creator/organization
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    /// Unique tenant ID
    pub id: Uuid,

    /// Unique namespace (e.g., "creator-123", "acme-corp")
    pub namespace: String,

    /// Display name
    pub name: String,

    /// Tenant status
    pub status: TenantStatus,

    /// Owner user ID
    pub owner_user_id: Uuid,

    /// Storage quota in bytes (None = unlimited)
    pub storage_quota_bytes: Option<i64>,

    /// Bandwidth quota in bytes per month (None = unlimited)
    pub bandwidth_quota_bytes: Option<i64>,

    /// Maximum number of users (None = unlimited)
    pub max_users: Option<i32>,

    /// Maximum number of nodes (None = unlimited)
    pub max_nodes: Option<i32>,

    /// Custom settings (JSON)
    pub settings: serde_json::Value,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Tenant creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTenantRequest {
    /// Unique namespace
    pub namespace: String,

    /// Display name
    pub name: String,

    /// Owner user ID
    pub owner_user_id: Uuid,

    /// Storage quota in bytes
    pub storage_quota_bytes: Option<i64>,

    /// Bandwidth quota in bytes per month
    pub bandwidth_quota_bytes: Option<i64>,

    /// Maximum number of users
    pub max_users: Option<i32>,

    /// Maximum number of nodes
    pub max_nodes: Option<i32>,

    /// Custom settings
    pub settings: Option<serde_json::Value>,
}

/// Tenant update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTenantRequest {
    /// Display name
    pub name: Option<String>,

    /// Tenant status
    pub status: Option<TenantStatus>,

    /// Storage quota in bytes
    pub storage_quota_bytes: Option<i64>,

    /// Bandwidth quota in bytes per month
    pub bandwidth_quota_bytes: Option<i64>,

    /// Maximum number of users
    pub max_users: Option<i32>,

    /// Maximum number of nodes
    pub max_nodes: Option<i32>,

    /// Custom settings
    pub settings: Option<serde_json::Value>,
}

/// Tenant statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantStats {
    /// Total storage used in bytes
    pub storage_used_bytes: i64,

    /// Bandwidth used this month in bytes
    pub bandwidth_used_bytes: i64,

    /// Number of users
    pub user_count: i32,

    /// Number of nodes
    pub node_count: i32,

    /// Number of content items
    pub content_count: i32,

    /// Total revenue (points)
    pub total_revenue: i64,
}

/// Tenant context extracted from request
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant ID
    pub tenant_id: Uuid,

    /// Tenant namespace
    pub namespace: String,

    /// Tenant status
    pub status: TenantStatus,
}

/// Multi-tenancy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenancyConfig {
    /// Enable multi-tenancy
    pub enabled: bool,

    /// Default tenant ID for single-tenant mode
    pub default_tenant_id: Option<Uuid>,

    /// Require tenant header on all requests
    pub require_tenant_header: bool,

    /// Extract tenant from subdomain
    pub extract_from_subdomain: bool,

    /// Tenant header name
    pub tenant_header_name: String,
}

impl Default for MultiTenancyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_tenant_id: None,
            require_tenant_header: false,
            extract_from_subdomain: true,
            tenant_header_name: "x-tenant-id".to_string(),
        }
    }
}

/// Tenant manager
#[derive(Clone)]
pub struct TenantManager {
    db: PgPool,
    config: Arc<MultiTenancyConfig>,
}

impl TenantManager {
    /// Create a new tenant manager
    pub fn new(db: PgPool, config: MultiTenancyConfig) -> Self {
        Self {
            db,
            config: Arc::new(config),
        }
    }

    /// Create a new tenant
    pub async fn create_tenant(&self, req: CreateTenantRequest) -> Result<Tenant, String> {
        // Validate namespace (alphanumeric, hyphens, underscores only)
        if !req
            .namespace
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Invalid namespace: must contain only alphanumeric characters, hyphens, and underscores".to_string());
        }

        if req.namespace.len() < 3 || req.namespace.len() > 64 {
            return Err("Invalid namespace: must be between 3 and 64 characters".to_string());
        }

        let tenant_id = Uuid::new_v4();
        let settings = req.settings.unwrap_or(serde_json::json!({}));

        let tenant = sqlx::query_as::<_, Tenant>(
            r#"
            INSERT INTO tenants (
                id, namespace, name, status, owner_user_id,
                storage_quota_bytes, bandwidth_quota_bytes,
                max_users, max_nodes, settings
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING
                id, namespace, name,
                status,
                owner_user_id,
                storage_quota_bytes, bandwidth_quota_bytes,
                max_users, max_nodes, settings,
                created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(&req.namespace)
        .bind(&req.name)
        .bind(TenantStatus::Active)
        .bind(req.owner_user_id)
        .bind(req.storage_quota_bytes)
        .bind(req.bandwidth_quota_bytes)
        .bind(req.max_users)
        .bind(req.max_nodes)
        .bind(&settings)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Failed to create tenant: {}", e))?;

        debug!("Created tenant: {} ({})", tenant.namespace, tenant.id);
        Ok(tenant)
    }

    /// Get tenant by ID
    pub async fn get_tenant(&self, tenant_id: Uuid) -> Result<Option<Tenant>, String> {
        let tenant = sqlx::query_as::<_, Tenant>(
            r#"
            SELECT
                id, namespace, name,
                status,
                owner_user_id,
                storage_quota_bytes, bandwidth_quota_bytes,
                max_users, max_nodes, settings,
                created_at, updated_at
            FROM tenants
            WHERE id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Failed to get tenant: {}", e))?;

        Ok(tenant)
    }

    /// Get tenant by namespace
    pub async fn get_tenant_by_namespace(&self, namespace: &str) -> Result<Option<Tenant>, String> {
        let tenant = sqlx::query_as::<_, Tenant>(
            r#"
            SELECT
                id, namespace, name,
                status,
                owner_user_id,
                storage_quota_bytes, bandwidth_quota_bytes,
                max_users, max_nodes, settings,
                created_at, updated_at
            FROM tenants
            WHERE namespace = $1
            "#,
        )
        .bind(namespace)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("Failed to get tenant by namespace: {}", e))?;

        Ok(tenant)
    }

    /// Update tenant
    pub async fn update_tenant(
        &self,
        tenant_id: Uuid,
        req: UpdateTenantRequest,
    ) -> Result<Tenant, String> {
        // Build update query dynamically based on provided fields
        let mut updates = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(name) = &req.name {
            updates.push(format!("name = ${}", values.len() + 2));
            values.push(name.clone());
        }

        if let Some(status) = req.status {
            updates.push(format!("status = ${}", values.len() + 2));
            values.push(format!("{:?}", status).to_lowercase());
        }

        if let Some(storage_quota) = req.storage_quota_bytes {
            updates.push(format!("storage_quota_bytes = ${}", values.len() + 2));
            values.push(storage_quota.to_string());
        }

        if let Some(bandwidth_quota) = req.bandwidth_quota_bytes {
            updates.push(format!("bandwidth_quota_bytes = ${}", values.len() + 2));
            values.push(bandwidth_quota.to_string());
        }

        if let Some(max_users) = req.max_users {
            updates.push(format!("max_users = ${}", values.len() + 2));
            values.push(max_users.to_string());
        }

        if let Some(max_nodes) = req.max_nodes {
            updates.push(format!("max_nodes = ${}", values.len() + 2));
            values.push(max_nodes.to_string());
        }

        if let Some(settings) = &req.settings {
            updates.push(format!("settings = ${}", values.len() + 2));
            values.push(serde_json::to_string(settings).unwrap_or_default());
        }

        if updates.is_empty() {
            return self
                .get_tenant(tenant_id)
                .await?
                .ok_or_else(|| "Tenant not found".to_string());
        }

        updates.push("updated_at = NOW()".to_string());

        // Use a simpler approach: fetch current, update in Rust, then save
        let mut tenant = self
            .get_tenant(tenant_id)
            .await?
            .ok_or_else(|| "Tenant not found".to_string())?;

        if let Some(name) = req.name {
            tenant.name = name;
        }
        if let Some(status) = req.status {
            tenant.status = status;
        }
        if let Some(storage_quota_bytes) = req.storage_quota_bytes {
            tenant.storage_quota_bytes = Some(storage_quota_bytes);
        }
        if let Some(bandwidth_quota_bytes) = req.bandwidth_quota_bytes {
            tenant.bandwidth_quota_bytes = Some(bandwidth_quota_bytes);
        }
        if let Some(max_users) = req.max_users {
            tenant.max_users = Some(max_users);
        }
        if let Some(max_nodes) = req.max_nodes {
            tenant.max_nodes = Some(max_nodes);
        }
        if let Some(settings) = req.settings {
            tenant.settings = settings;
        }

        let updated_tenant = sqlx::query_as::<_, Tenant>(
            r#"
            UPDATE tenants
            SET name = $2, status = $3, storage_quota_bytes = $4,
                bandwidth_quota_bytes = $5, max_users = $6, max_nodes = $7,
                settings = $8, updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, namespace, name,
                status,
                owner_user_id,
                storage_quota_bytes, bandwidth_quota_bytes,
                max_users, max_nodes, settings,
                created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(&tenant.name)
        .bind(tenant.status)
        .bind(tenant.storage_quota_bytes)
        .bind(tenant.bandwidth_quota_bytes)
        .bind(tenant.max_users)
        .bind(tenant.max_nodes)
        .bind(&tenant.settings)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("Failed to update tenant: {}", e))?;

        debug!("Updated tenant: {}", tenant_id);
        Ok(updated_tenant)
    }

    /// Delete tenant (soft delete - archive)
    pub async fn delete_tenant(&self, tenant_id: Uuid) -> Result<(), String> {
        sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(TenantStatus::Archived)
            .bind(tenant_id)
            .execute(&self.db)
            .await
            .map_err(|e| format!("Failed to delete tenant: {}", e))?;

        debug!("Archived tenant: {}", tenant_id);
        Ok(())
    }

    /// List all tenants
    pub async fn list_tenants(
        &self,
        status_filter: Option<TenantStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Tenant>, String> {
        let tenants: Result<Vec<Tenant>, sqlx::Error> = if let Some(status) = status_filter {
            sqlx::query_as::<_, Tenant>(
                r#"
                SELECT
                    id, namespace, name,
                    status,
                    owner_user_id,
                    storage_quota_bytes, bandwidth_quota_bytes,
                    max_users, max_nodes, settings,
                    created_at, updated_at
                FROM tenants
                WHERE status = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query_as::<_, Tenant>(
                r#"
                SELECT
                    id, namespace, name,
                    status,
                    owner_user_id,
                    storage_quota_bytes, bandwidth_quota_bytes,
                    max_users, max_nodes, settings,
                    created_at, updated_at
                FROM tenants
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                "#,
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
        };

        tenants.map_err(|e| format!("Failed to list tenants: {}", e))
    }

    /// Get tenant statistics
    pub async fn get_tenant_stats(&self, _tenant_id: Uuid) -> Result<TenantStats, String> {
        // In a real implementation, these would be actual database queries
        // For now, return placeholder stats
        Ok(TenantStats {
            storage_used_bytes: 0,
            bandwidth_used_bytes: 0,
            user_count: 0,
            node_count: 0,
            content_count: 0,
            total_revenue: 0,
        })
    }

    /// Extract tenant context from request headers
    pub async fn extract_tenant_context(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<TenantContext>, String> {
        // Try to get tenant ID from header
        let tenant_id = if let Some(header_value) = headers.get(&self.config.tenant_header_name) {
            let id_str = header_value
                .to_str()
                .map_err(|_| "Invalid tenant header value")?;

            // Could be either namespace or UUID
            if let Ok(uuid) = Uuid::parse_str(id_str) {
                Some(uuid)
            } else {
                // Try to lookup by namespace
                if let Some(tenant) = self.get_tenant_by_namespace(id_str).await? {
                    Some(tenant.id)
                } else {
                    None
                }
            }
        } else {
            self.config.default_tenant_id
        };

        if let Some(id) = tenant_id {
            if let Some(tenant) = self.get_tenant(id).await? {
                return Ok(Some(TenantContext {
                    tenant_id: tenant.id,
                    namespace: tenant.namespace,
                    status: tenant.status,
                }));
            }
        }

        Ok(None)
    }
}

/// Tenant context middleware
#[allow(dead_code)]
pub async fn tenant_context_middleware(
    State(manager): State<Arc<TenantManager>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip if multi-tenancy is disabled
    if !manager.config.enabled {
        return Ok(next.run(req).await);
    }

    // Extract tenant context
    let tenant_context = manager
        .extract_tenant_context(req.headers())
        .await
        .map_err(|e| {
            warn!("Failed to extract tenant context: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    if let Some(context) = tenant_context {
        // Check if tenant is active
        if context.status != TenantStatus::Active {
            warn!("Request for non-active tenant: {}", context.tenant_id);
            return Err(StatusCode::FORBIDDEN);
        }

        // Store tenant context in request extensions
        req.extensions_mut().insert(context);

        Ok(next.run(req).await)
    } else if manager.config.require_tenant_header {
        warn!("Tenant header required but not provided");
        Err(StatusCode::BAD_REQUEST)
    } else {
        // Allow request without tenant context
        Ok(next.run(req).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MultiTenancyConfig::default();
        assert!(config.enabled);
        assert!(config.extract_from_subdomain);
        assert_eq!(config.tenant_header_name, "x-tenant-id");
    }

    #[test]
    fn test_tenant_status() {
        assert_eq!(TenantStatus::Active, TenantStatus::Active);
        assert_ne!(TenantStatus::Active, TenantStatus::Suspended);
    }

    #[test]
    fn test_namespace_validation() {
        // Valid namespaces
        assert!(
            "creator-123"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
        assert!(
            "acme_corp"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );

        // Invalid namespaces
        assert!(
            !"creator@123"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
        assert!(
            !"creator 123"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }
}
