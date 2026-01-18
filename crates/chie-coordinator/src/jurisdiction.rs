//! Jurisdiction-Aware Content Filtering System
//!
//! Implements geographic and legal jurisdiction-based content filtering including:
//! - Country-based content blocking
//! - DMCA and legal takedown notices
//! - EU/GDPR compliance filtering
//! - Regional content restrictions
//! - Legal compliance reporting

use crate::metrics;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Jurisdiction code (ISO 3166-1 alpha-2 country codes)
pub type JurisdictionCode = String;

/// Content restriction reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "restriction_reason", rename_all = "snake_case")]
pub enum RestrictionReason {
    /// DMCA takedown notice (US)
    DmcaTakedown,
    /// EU Copyright Directive (Article 17)
    EuCopyrightDirective,
    /// GDPR right to be forgotten
    GdprRightToErasure,
    /// Court order
    CourtOrder,
    /// Government request
    GovernmentRequest,
    /// Terms of service violation
    TosViolation,
    /// Regional licensing restrictions
    RegionalLicensing,
    /// Age restriction compliance
    AgeRestriction,
    /// Other legal reason
    Other,
}

/// Content restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentRestriction {
    pub id: Uuid,
    pub content_id: Uuid,
    pub jurisdiction_codes: Vec<String>, // Countries where content is blocked
    pub reason: RestrictionReason,
    pub legal_reference: Option<String>, // Case number, DMCA reference, etc.
    pub description: String,
    pub is_global: bool,   // If true, blocked globally
    pub placed_by: String, // Admin who placed the restriction
    pub placed_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub appeal_url: Option<String>,
}

/// Jurisdiction filter result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionFilterResult {
    pub content_id: Uuid,
    pub is_allowed: bool,
    pub restriction: Option<ContentRestriction>,
    pub checked_jurisdiction: Option<String>,
}

/// Jurisdiction manager configuration
#[derive(Debug, Clone)]
pub struct JurisdictionConfig {
    /// Enable jurisdiction filtering (can be disabled for testing)
    pub enabled: bool,
    /// Default jurisdiction if none provided
    pub default_jurisdiction: Option<String>,
    /// Whitelist jurisdictions (content always allowed)
    pub whitelist_jurisdictions: HashSet<String>,
    /// Automatically block in high-risk jurisdictions
    pub auto_block_jurisdictions: HashSet<String>,
}

impl Default for JurisdictionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_jurisdiction: None,
            whitelist_jurisdictions: HashSet::new(),
            auto_block_jurisdictions: HashSet::new(),
        }
    }
}

/// Jurisdiction manager
pub struct JurisdictionManager {
    db: PgPool,
    config: Arc<RwLock<JurisdictionConfig>>,
}

impl JurisdictionManager {
    /// Create a new jurisdiction manager
    pub fn new(db: PgPool, config: JurisdictionConfig) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Create a content restriction
    #[allow(clippy::too_many_arguments)]
    pub async fn create_restriction(
        &self,
        content_id: Uuid,
        jurisdiction_codes: Vec<String>,
        reason: RestrictionReason,
        legal_reference: Option<String>,
        description: String,
        is_global: bool,
        placed_by: String,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        appeal_url: Option<String>,
    ) -> Result<ContentRestriction, JurisdictionError> {
        let id = Uuid::new_v4();

        // Validate jurisdiction codes (should be ISO 3166-1 alpha-2)
        for code in &jurisdiction_codes {
            if code.len() != 2 {
                warn!(
                    "Invalid jurisdiction code: {} (should be 2 characters)",
                    code
                );
            }
        }

        let row = sqlx::query(
            r#"
            INSERT INTO content_restrictions
                (id, content_id, jurisdiction_codes, reason, legal_reference, description,
                 is_global, placed_by, expires_at, appeal_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, content_id, jurisdiction_codes,
                      reason,
                      legal_reference, description, is_global, placed_by, placed_at,
                      expires_at, appeal_url
            "#,
        )
        .bind(id)
        .bind(content_id)
        .bind(&jurisdiction_codes)
        .bind(reason)
        .bind(legal_reference)
        .bind(description)
        .bind(is_global)
        .bind(placed_by)
        .bind(expires_at)
        .bind(appeal_url)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to create content restriction: {}", e);
            JurisdictionError::DatabaseError(e.to_string())
        })?;

        let restriction = ContentRestriction {
            id: row.get("id"),
            content_id: row.get("content_id"),
            jurisdiction_codes: row.get("jurisdiction_codes"),
            reason: row.get("reason"),
            legal_reference: row.get("legal_reference"),
            description: row.get("description"),
            is_global: row.get("is_global"),
            placed_by: row.get("placed_by"),
            placed_at: row.get("placed_at"),
            expires_at: row.get("expires_at"),
            appeal_url: row.get("appeal_url"),
        };

        info!(
            "Created content restriction {} for content {} in {:?}",
            id, content_id, jurisdiction_codes
        );
        metrics::record_jurisdiction_restriction_created(format!("{:?}", reason).to_lowercase());

        Ok(restriction)
    }

    /// Check if content is allowed in a jurisdiction
    pub async fn check_content(
        &self,
        content_id: Uuid,
        jurisdiction: Option<String>,
    ) -> Result<JurisdictionFilterResult, JurisdictionError> {
        let config = self.config.read().await;

        // If filtering is disabled, allow everything
        if !config.enabled {
            return Ok(JurisdictionFilterResult {
                content_id,
                is_allowed: true,
                restriction: None,
                checked_jurisdiction: jurisdiction,
            });
        }

        // Determine jurisdiction to check
        let check_jurisdiction = jurisdiction
            .or_else(|| config.default_jurisdiction.clone())
            .map(|j| j.to_uppercase());

        // Check if jurisdiction is whitelisted
        if let Some(ref jur) = check_jurisdiction {
            if config.whitelist_jurisdictions.contains(jur) {
                return Ok(JurisdictionFilterResult {
                    content_id,
                    is_allowed: true,
                    restriction: None,
                    checked_jurisdiction: Some(jur.clone()),
                });
            }
        }

        // Check for active restrictions
        let restriction = self
            .get_active_restriction(content_id, check_jurisdiction.clone())
            .await?;

        let is_allowed = restriction.is_none();

        if !is_allowed {
            metrics::record_jurisdiction_content_blocked(
                check_jurisdiction.as_deref().unwrap_or("unknown"),
            );
        }

        Ok(JurisdictionFilterResult {
            content_id,
            is_allowed,
            restriction,
            checked_jurisdiction: check_jurisdiction,
        })
    }

    /// Get active restriction for content in a jurisdiction
    async fn get_active_restriction(
        &self,
        content_id: Uuid,
        jurisdiction: Option<String>,
    ) -> Result<Option<ContentRestriction>, JurisdictionError> {
        // Check for global restrictions first
        let global_restriction = sqlx::query(
            r#"
            SELECT id, content_id, jurisdiction_codes,
                   reason,
                   legal_reference, description, is_global, placed_by, placed_at,
                   expires_at, appeal_url
            FROM content_restrictions
            WHERE content_id = $1
              AND is_global = true
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY placed_at DESC
            LIMIT 1
            "#,
        )
        .bind(content_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?
        .map(|row| ContentRestriction {
            id: row.get("id"),
            content_id: row.get("content_id"),
            jurisdiction_codes: row.get("jurisdiction_codes"),
            reason: row.get("reason"),
            legal_reference: row.get("legal_reference"),
            description: row.get("description"),
            is_global: row.get("is_global"),
            placed_by: row.get("placed_by"),
            placed_at: row.get("placed_at"),
            expires_at: row.get("expires_at"),
            appeal_url: row.get("appeal_url"),
        });

        if global_restriction.is_some() {
            return Ok(global_restriction);
        }

        // Check for jurisdiction-specific restrictions
        if let Some(ref jur) = jurisdiction {
            let restriction = sqlx::query(
                r#"
                SELECT id, content_id, jurisdiction_codes,
                       reason,
                       legal_reference, description, is_global, placed_by, placed_at,
                       expires_at, appeal_url
                FROM content_restrictions
                WHERE content_id = $1
                  AND is_global = false
                  AND $2 = ANY(jurisdiction_codes)
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY placed_at DESC
                LIMIT 1
                "#,
            )
            .bind(content_id)
            .bind(jur)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?
            .map(|row| ContentRestriction {
                id: row.get("id"),
                content_id: row.get("content_id"),
                jurisdiction_codes: row.get("jurisdiction_codes"),
                reason: row.get("reason"),
                legal_reference: row.get("legal_reference"),
                description: row.get("description"),
                is_global: row.get("is_global"),
                placed_by: row.get("placed_by"),
                placed_at: row.get("placed_at"),
                expires_at: row.get("expires_at"),
                appeal_url: row.get("appeal_url"),
            });

            return Ok(restriction);
        }

        Ok(None)
    }

    /// Get all restrictions for content
    pub async fn get_content_restrictions(
        &self,
        content_id: Uuid,
    ) -> Result<Vec<ContentRestriction>, JurisdictionError> {
        let rows = sqlx::query(
            r#"
            SELECT id, content_id, jurisdiction_codes,
                   reason,
                   legal_reference, description, is_global, placed_by, placed_at,
                   expires_at, appeal_url
            FROM content_restrictions
            WHERE content_id = $1
            ORDER BY placed_at DESC
            "#,
        )
        .bind(content_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| ContentRestriction {
                id: row.get("id"),
                content_id: row.get("content_id"),
                jurisdiction_codes: row.get("jurisdiction_codes"),
                reason: row.get("reason"),
                legal_reference: row.get("legal_reference"),
                description: row.get("description"),
                is_global: row.get("is_global"),
                placed_by: row.get("placed_by"),
                placed_at: row.get("placed_at"),
                expires_at: row.get("expires_at"),
                appeal_url: row.get("appeal_url"),
            })
            .collect())
    }

    /// Remove a restriction
    pub async fn remove_restriction(&self, restriction_id: Uuid) -> Result<(), JurisdictionError> {
        let result = sqlx::query("DELETE FROM content_restrictions WHERE id = $1")
            .bind(restriction_id)
            .execute(&self.db)
            .await
            .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(JurisdictionError::RestrictionNotFound);
        }

        info!("Removed content restriction {}", restriction_id);
        metrics::record_jurisdiction_restriction_removed();

        Ok(())
    }

    /// Get restriction by ID
    pub async fn get_restriction(
        &self,
        restriction_id: Uuid,
    ) -> Result<ContentRestriction, JurisdictionError> {
        let row = sqlx::query(
            r#"
            SELECT id, content_id, jurisdiction_codes,
                   reason,
                   legal_reference, description, is_global, placed_by, placed_at,
                   expires_at, appeal_url
            FROM content_restrictions WHERE id = $1
            "#,
        )
        .bind(restriction_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if matches!(e, sqlx::Error::RowNotFound) {
                JurisdictionError::RestrictionNotFound
            } else {
                JurisdictionError::DatabaseError(e.to_string())
            }
        })?;

        Ok(ContentRestriction {
            id: row.get("id"),
            content_id: row.get("content_id"),
            jurisdiction_codes: row.get("jurisdiction_codes"),
            reason: row.get("reason"),
            legal_reference: row.get("legal_reference"),
            description: row.get("description"),
            is_global: row.get("is_global"),
            placed_by: row.get("placed_by"),
            placed_at: row.get("placed_at"),
            expires_at: row.get("expires_at"),
            appeal_url: row.get("appeal_url"),
        })
    }

    /// List all restrictions with optional filters
    pub async fn list_restrictions(
        &self,
        jurisdiction: Option<String>,
        reason: Option<RestrictionReason>,
        limit: Option<i64>,
    ) -> Result<Vec<ContentRestriction>, JurisdictionError> {
        let limit = limit.unwrap_or(100);

        // Build query dynamically based on filters
        let rows = if let Some(jur) = jurisdiction {
            if let Some(rsn) = reason {
                sqlx::query(
                    r#"
                    SELECT id, content_id, jurisdiction_codes,
                           reason,
                           legal_reference, description, is_global, placed_by, placed_at,
                           expires_at, appeal_url
                    FROM content_restrictions
                    WHERE $1 = ANY(jurisdiction_codes) AND reason = $2
                    ORDER BY placed_at DESC
                    LIMIT $3
                    "#,
                )
                .bind(jur)
                .bind(rsn)
                .bind(limit)
                .fetch_all(&self.db)
                .await
            } else {
                sqlx::query(
                    r#"
                    SELECT id, content_id, jurisdiction_codes,
                           reason,
                           legal_reference, description, is_global, placed_by, placed_at,
                           expires_at, appeal_url
                    FROM content_restrictions
                    WHERE $1 = ANY(jurisdiction_codes)
                    ORDER BY placed_at DESC
                    LIMIT $2
                    "#,
                )
                .bind(jur)
                .bind(limit)
                .fetch_all(&self.db)
                .await
            }
        } else if let Some(rsn) = reason {
            sqlx::query(
                r#"
                SELECT id, content_id, jurisdiction_codes,
                       reason,
                       legal_reference, description, is_global, placed_by, placed_at,
                       expires_at, appeal_url
                FROM content_restrictions
                WHERE reason = $1
                ORDER BY placed_at DESC
                LIMIT $2
                "#,
            )
            .bind(rsn)
            .bind(limit)
            .fetch_all(&self.db)
            .await
        } else {
            sqlx::query(
                r#"
                SELECT id, content_id, jurisdiction_codes,
                       reason,
                       legal_reference, description, is_global, placed_by, placed_at,
                       expires_at, appeal_url
                FROM content_restrictions
                ORDER BY placed_at DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(&self.db)
            .await
        }
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| ContentRestriction {
                id: row.get("id"),
                content_id: row.get("content_id"),
                jurisdiction_codes: row.get("jurisdiction_codes"),
                reason: row.get("reason"),
                legal_reference: row.get("legal_reference"),
                description: row.get("description"),
                is_global: row.get("is_global"),
                placed_by: row.get("placed_by"),
                placed_at: row.get("placed_at"),
                expires_at: row.get("expires_at"),
                appeal_url: row.get("appeal_url"),
            })
            .collect())
    }

    /// Clean up expired restrictions
    pub async fn cleanup_expired_restrictions(&self) -> Result<u64, JurisdictionError> {
        let result = sqlx::query(
            "DELETE FROM content_restrictions WHERE expires_at IS NOT NULL AND expires_at < NOW()",
        )
        .execute(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!("Cleaned up {} expired content restrictions", deleted);
            metrics::record_jurisdiction_restrictions_expired(deleted);
        }

        Ok(deleted)
    }

    /// Get statistics about restrictions
    pub async fn get_stats(&self) -> Result<JurisdictionStats, JurisdictionError> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM content_restrictions")
            .fetch_one(&self.db)
            .await
            .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;
        let total_restrictions: i64 = row.get("count");

        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM content_restrictions WHERE (expires_at IS NULL OR expires_at > NOW())"
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;
        let active_restrictions: i64 = row.get("count");

        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM content_restrictions WHERE is_global = true AND (expires_at IS NULL OR expires_at > NOW())"
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;
        let global_restrictions: i64 = row.get("count");

        let rows = sqlx::query(
            r#"
            SELECT reason, COUNT(*) as count
            FROM content_restrictions
            WHERE (expires_at IS NULL OR expires_at > NOW())
            GROUP BY reason
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| JurisdictionError::DatabaseError(e.to_string()))?;

        let restrictions_by_reason = rows
            .into_iter()
            .map(|row| {
                let reason: RestrictionReason = row.get("reason");
                let count: i64 = row.get("count");
                (format!("{:?}", reason), count)
            })
            .collect();

        Ok(JurisdictionStats {
            total_restrictions,
            active_restrictions,
            global_restrictions,
            restrictions_by_reason,
        })
    }

    /// Get configuration
    pub async fn config(&self) -> JurisdictionConfig {
        self.config.read().await.clone()
    }
}

/// Jurisdiction statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionStats {
    pub total_restrictions: i64,
    pub active_restrictions: i64,
    pub global_restrictions: i64,
    pub restrictions_by_reason: Vec<(String, i64)>,
}

/// Jurisdiction error types
#[derive(Debug, thiserror::Error)]
pub enum JurisdictionError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Restriction not found")]
    RestrictionNotFound,

    #[error("Invalid jurisdiction code: {0}")]
    InvalidJurisdiction(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jurisdiction_config_default() {
        let config = JurisdictionConfig::default();
        assert!(config.enabled);
        assert!(config.whitelist_jurisdictions.is_empty());
        assert!(config.auto_block_jurisdictions.is_empty());
    }

    #[test]
    fn test_restriction_reason_serialization() {
        let reason = RestrictionReason::DmcaTakedown;
        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("DmcaTakedown"));
    }

    #[test]
    fn test_jurisdiction_filter_result() {
        let result = JurisdictionFilterResult {
            content_id: Uuid::new_v4(),
            is_allowed: false,
            restriction: None,
            checked_jurisdiction: Some("US".to_string()),
        };
        assert!(!result.is_allowed);
        assert_eq!(result.checked_jurisdiction.unwrap(), "US");
    }
}
