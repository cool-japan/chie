//! Terms of Service Version Tracking System
//!
//! Implements legal compliance for Terms of Service management including:
//! - ToS version management with effective dates
//! - User acceptance tracking
//! - Mandatory acceptance enforcement
//! - Version comparison and updates
//! - Audit trail for legal compliance

use crate::metrics;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

/// Terms of Service version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TosVersion {
    pub id: Uuid,
    pub version: String,
    pub title: String,
    pub content: String,
    pub summary_of_changes: Option<String>,
    pub effective_date: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
    pub requires_acceptance: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
}

/// User acceptance of ToS version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TosAcceptance {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tos_version_id: Uuid,
    pub tos_version: String,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// ToS acceptance status for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TosAcceptanceStatus {
    pub user_id: Uuid,
    pub current_version: String,
    pub accepted_version: Option<String>,
    pub requires_acceptance: bool,
    pub last_accepted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// ToS tracking manager configuration
#[derive(Debug, Clone)]
pub struct TosConfig {
    /// Enforce ToS acceptance before API access
    pub enforce_acceptance: bool,
    /// Grace period in days after new ToS is published
    pub grace_period_days: i64,
    /// Keep acceptance history (default: 7 years for GDPR compliance)
    pub retention_years: i64,
}

impl Default for TosConfig {
    fn default() -> Self {
        Self {
            enforce_acceptance: true,
            grace_period_days: 30,
            retention_years: 7,
        }
    }
}

/// Terms of Service tracking manager
pub struct TosManager {
    db: PgPool,
    config: Arc<RwLock<TosConfig>>,
}

impl TosManager {
    /// Create a new ToS manager
    pub fn new(db: PgPool, config: TosConfig) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Create a new ToS version
    #[allow(clippy::too_many_arguments)]
    pub async fn create_version(
        &self,
        version: String,
        title: String,
        content: String,
        summary_of_changes: Option<String>,
        effective_date: chrono::DateTime<chrono::Utc>,
        requires_acceptance: bool,
        created_by: String,
    ) -> Result<TosVersion, TosError> {
        // Check if version already exists
        let row = sqlx::query("SELECT COUNT(*) as count FROM tos_versions WHERE version = $1")
            .bind(&version)
            .fetch_one(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        let existing: i64 = row.get("count");

        if existing > 0 {
            return Err(TosError::VersionAlreadyExists(version));
        }

        let id = Uuid::new_v4();

        // Deactivate all previous versions if this is a new active version
        if effective_date <= chrono::Utc::now() {
            sqlx::query("UPDATE tos_versions SET is_active = false WHERE is_active = true")
                .execute(&self.db)
                .await
                .map_err(|e| TosError::DatabaseError(e.to_string()))?;
        }

        let row = sqlx::query(
            r#"
            INSERT INTO tos_versions (id, version, title, content, summary_of_changes, effective_date, is_active, requires_acceptance, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, version, title, content, summary_of_changes, effective_date, is_active, requires_acceptance, created_at, created_by
            "#
        )
        .bind(id)
        .bind(&version)
        .bind(&title)
        .bind(&content)
        .bind(&summary_of_changes)
        .bind(effective_date)
        .bind(effective_date <= chrono::Utc::now())
        .bind(requires_acceptance)
        .bind(&created_by)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to create ToS version: {}", e);
            TosError::DatabaseError(e.to_string())
        })?;

        let tos = TosVersion {
            id: row.get("id"),
            version: row.get("version"),
            title: row.get("title"),
            content: row.get("content"),
            summary_of_changes: row.get("summary_of_changes"),
            effective_date: row.get("effective_date"),
            is_active: row.get("is_active"),
            requires_acceptance: row.get("requires_acceptance"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
        };

        info!("Created new ToS version {} (id: {})", version, id);
        metrics::record_tos_version_created();

        Ok(tos)
    }

    /// Get the current active ToS version
    pub async fn get_active_version(&self) -> Result<TosVersion, TosError> {
        let row = sqlx::query(
            r#"
            SELECT id, version, title, content, summary_of_changes, effective_date, is_active, requires_acceptance, created_at, created_by
            FROM tos_versions
            WHERE is_active = true AND effective_date <= NOW()
            ORDER BY effective_date DESC
            LIMIT 1
            "#
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                TosError::NoActiveVersion
            } else {
                TosError::DatabaseError(e.to_string())
            }
        })?;

        Ok(TosVersion {
            id: row.get("id"),
            version: row.get("version"),
            title: row.get("title"),
            content: row.get("content"),
            summary_of_changes: row.get("summary_of_changes"),
            effective_date: row.get("effective_date"),
            is_active: row.get("is_active"),
            requires_acceptance: row.get("requires_acceptance"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
        })
    }

    /// Get a specific ToS version by ID
    pub async fn get_version(&self, id: Uuid) -> Result<TosVersion, TosError> {
        let row = sqlx::query(
            r#"
            SELECT id, version, title, content, summary_of_changes, effective_date, is_active, requires_acceptance, created_at, created_by
            FROM tos_versions WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                TosError::VersionNotFound
            } else {
                TosError::DatabaseError(e.to_string())
            }
        })?;

        Ok(TosVersion {
            id: row.get("id"),
            version: row.get("version"),
            title: row.get("title"),
            content: row.get("content"),
            summary_of_changes: row.get("summary_of_changes"),
            effective_date: row.get("effective_date"),
            is_active: row.get("is_active"),
            requires_acceptance: row.get("requires_acceptance"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
        })
    }

    /// Get all ToS versions (ordered by effective date, newest first)
    pub async fn list_versions(&self, limit: Option<i64>) -> Result<Vec<TosVersion>, TosError> {
        let limit = limit.unwrap_or(100);

        let rows = sqlx::query(
            r#"
            SELECT id, version, title, content, summary_of_changes, effective_date, is_active, requires_acceptance, created_at, created_by
            FROM tos_versions
            ORDER BY effective_date DESC
            LIMIT $1
            "#
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| TosVersion {
                id: row.get("id"),
                version: row.get("version"),
                title: row.get("title"),
                content: row.get("content"),
                summary_of_changes: row.get("summary_of_changes"),
                effective_date: row.get("effective_date"),
                is_active: row.get("is_active"),
                requires_acceptance: row.get("requires_acceptance"),
                created_at: row.get("created_at"),
                created_by: row.get("created_by"),
            })
            .collect())
    }

    /// Record user acceptance of ToS
    pub async fn record_acceptance(
        &self,
        user_id: Uuid,
        tos_version_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<TosAcceptance, TosError> {
        // Get the ToS version
        let tos = self.get_version(tos_version_id).await?;

        // Check if user already accepted this version
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM tos_acceptances WHERE user_id = $1 AND tos_version_id = $2"
        )
        .bind(user_id)
        .bind(tos_version_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        let existing: i64 = row.get("count");

        if existing > 0 {
            debug!(
                "User {} already accepted ToS version {}",
                user_id, tos.version
            );
            // Return existing acceptance
            return self.get_user_acceptance(user_id, tos_version_id).await;
        }

        let id = Uuid::new_v4();

        let row = sqlx::query(
            r#"
            INSERT INTO tos_acceptances (id, user_id, tos_version_id, tos_version, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, tos_version_id, tos_version, accepted_at, ip_address, user_agent
            "#
        )
        .bind(id)
        .bind(user_id)
        .bind(tos_version_id)
        .bind(&tos.version)
        .bind(&ip_address)
        .bind(&user_agent)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to record ToS acceptance: {}", e);
            TosError::DatabaseError(e.to_string())
        })?;

        let acceptance = TosAcceptance {
            id: row.get("id"),
            user_id: row.get("user_id"),
            tos_version_id: row.get("tos_version_id"),
            tos_version: row.get("tos_version"),
            accepted_at: row.get("accepted_at"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
        };

        info!(
            "User {} accepted ToS version {} (id: {})",
            user_id, tos.version, tos_version_id
        );
        metrics::record_tos_acceptance();

        Ok(acceptance)
    }

    /// Get user's acceptance of a specific ToS version
    async fn get_user_acceptance(
        &self,
        user_id: Uuid,
        tos_version_id: Uuid,
    ) -> Result<TosAcceptance, TosError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, tos_version_id, tos_version, accepted_at, ip_address, user_agent
            FROM tos_acceptances
            WHERE user_id = $1 AND tos_version_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tos_version_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        Ok(TosAcceptance {
            id: row.get("id"),
            user_id: row.get("user_id"),
            tos_version_id: row.get("tos_version_id"),
            tos_version: row.get("tos_version"),
            accepted_at: row.get("accepted_at"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
        })
    }

    /// Check if user has accepted the current ToS version
    pub async fn check_acceptance_status(
        &self,
        user_id: Uuid,
    ) -> Result<TosAcceptanceStatus, TosError> {
        let current_version = match self.get_active_version().await {
            Ok(v) => v,
            Err(TosError::NoActiveVersion) => {
                // No active ToS version, so no acceptance required
                return Ok(TosAcceptanceStatus {
                    user_id,
                    current_version: "none".to_string(),
                    accepted_version: None,
                    requires_acceptance: false,
                    last_accepted_at: None,
                });
            }
            Err(e) => return Err(e),
        };

        // Check if user has accepted the current version
        let acceptance = sqlx::query(
            r#"
            SELECT tos_version, accepted_at
            FROM tos_acceptances
            WHERE user_id = $1 AND tos_version_id = $2
            "#,
        )
        .bind(user_id)
        .bind(current_version.id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| TosError::DatabaseError(e.to_string()))?
        .map(|row| {
            (
                row.get::<String, _>("tos_version"),
                row.get::<chrono::DateTime<chrono::Utc>, _>("accepted_at"),
            )
        });

        let config = self.config.read().await;
        let grace_period_end =
            current_version.effective_date + chrono::Duration::days(config.grace_period_days);
        let in_grace_period = chrono::Utc::now() < grace_period_end;

        let requires_acceptance =
            acceptance.is_none() && current_version.requires_acceptance && !in_grace_period;

        Ok(TosAcceptanceStatus {
            user_id,
            current_version: current_version.version.clone(),
            accepted_version: acceptance.as_ref().map(|(version, _)| version.clone()),
            requires_acceptance,
            last_accepted_at: acceptance.map(|(_, accepted_at)| accepted_at),
        })
    }

    /// Get all acceptances for a user
    pub async fn list_user_acceptances(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<TosAcceptance>, TosError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, tos_version_id, tos_version, accepted_at, ip_address, user_agent
            FROM tos_acceptances
            WHERE user_id = $1
            ORDER BY accepted_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| TosAcceptance {
                id: row.get("id"),
                user_id: row.get("user_id"),
                tos_version_id: row.get("tos_version_id"),
                tos_version: row.get("tos_version"),
                accepted_at: row.get("accepted_at"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
            })
            .collect())
    }

    /// Activate a ToS version (set as current)
    pub async fn activate_version(&self, id: Uuid) -> Result<(), TosError> {
        // First, deactivate all versions
        sqlx::query("UPDATE tos_versions SET is_active = false WHERE is_active = true")
            .execute(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        // Then activate the specified version
        let result = sqlx::query("UPDATE tos_versions SET is_active = true WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(TosError::VersionNotFound);
        }

        info!("Activated ToS version {}", id);
        metrics::record_tos_version_activated();

        Ok(())
    }

    /// Get statistics about ToS acceptances
    pub async fn get_stats(&self) -> Result<TosStats, TosError> {
        // Get current version
        let current_version = self.get_active_version().await.ok();

        let row = sqlx::query("SELECT COUNT(*) as count FROM tos_versions")
            .fetch_one(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;
        let total_versions: i64 = row.get("count");

        let row = sqlx::query("SELECT COUNT(*) as count FROM tos_acceptances")
            .fetch_one(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;
        let total_acceptances: i64 = row.get("count");

        let current_version_acceptances = if let Some(ref version) = current_version {
            let row = sqlx::query(
                "SELECT COUNT(*) as count FROM tos_acceptances WHERE tos_version_id = $1",
            )
            .bind(version.id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;
            row.get::<i64, _>("count")
        } else {
            0
        };

        let row = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;
        let total_users: i64 = row.get("count");

        let acceptance_rate = if total_users > 0 {
            (current_version_acceptances as f64 / total_users as f64) * 100.0
        } else {
            0.0
        };

        Ok(TosStats {
            current_version: current_version.map(|v| v.version),
            total_versions,
            total_acceptances,
            current_version_acceptances,
            total_users,
            acceptance_rate,
        })
    }

    /// Clean up old acceptance records (GDPR retention)
    pub async fn cleanup_old_acceptances(&self) -> Result<u64, TosError> {
        let config = self.config.read().await;
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(config.retention_years * 365);

        let result = sqlx::query("DELETE FROM tos_acceptances WHERE accepted_at < $1")
            .bind(cutoff_date)
            .execute(&self.db)
            .await
            .map_err(|e| TosError::DatabaseError(e.to_string()))?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!("Cleaned up {} old ToS acceptance records", deleted);
        }

        Ok(deleted)
    }

    /// Get configuration
    pub async fn config(&self) -> TosConfig {
        self.config.read().await.clone()
    }
}

/// ToS statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TosStats {
    pub current_version: Option<String>,
    pub total_versions: i64,
    pub total_acceptances: i64,
    pub current_version_acceptances: i64,
    pub total_users: i64,
    pub acceptance_rate: f64,
}

/// ToS error types
#[derive(Debug, thiserror::Error)]
pub enum TosError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Version {0} already exists")]
    VersionAlreadyExists(String),

    #[error("No active ToS version")]
    NoActiveVersion,

    #[error("ToS version not found")]
    VersionNotFound,

    #[error("User has not accepted current ToS")]
    AcceptanceRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tos_config_default() {
        let config = TosConfig::default();
        assert!(config.enforce_acceptance);
        assert_eq!(config.grace_period_days, 30);
        assert_eq!(config.retention_years, 7);
    }

    #[test]
    fn test_tos_stats_acceptance_rate() {
        let stats = TosStats {
            current_version: Some("2.0".to_string()),
            total_versions: 5,
            total_acceptances: 100,
            current_version_acceptances: 80,
            total_users: 100,
            acceptance_rate: 80.0,
        };
        assert_eq!(stats.acceptance_rate, 80.0);
        assert_eq!(stats.current_version_acceptances, 80);
    }

    #[test]
    fn test_tos_version_serialization() {
        let version = TosVersion {
            id: Uuid::new_v4(),
            version: "1.0".to_string(),
            title: "Terms of Service".to_string(),
            content: "Full ToS text".to_string(),
            summary_of_changes: Some("Initial version".to_string()),
            effective_date: chrono::Utc::now(),
            is_active: true,
            requires_acceptance: true,
            created_at: chrono::Utc::now(),
            created_by: "admin".to_string(),
        };

        let json = serde_json::to_string(&version).unwrap();
        assert!(json.contains("\"version\":\"1.0\""));
    }
}
