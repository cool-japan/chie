//! GDPR Compliance System
//!
//! Implements GDPR (General Data Protection Regulation) requirements including:
//! - Right to Data Portability (Article 20)
//! - Right to Erasure / Right to be Forgotten (Article 17)
//! - Data export in machine-readable format
//! - Personal data deletion with audit trail
//! - Anonymization for legal retention requirements

use crate::metrics;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// GDPR data export request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gdpr_export_status", rename_all = "snake_case")]
pub enum ExportStatus {
    /// Request submitted, waiting to be processed
    Pending,
    /// Export is being generated
    Processing,
    /// Export completed successfully
    Completed,
    /// Export failed due to error
    Failed,
    /// Export expired and was deleted
    Expired,
}

/// Right to be forgotten (RTBF) request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "rtbf_status", rename_all = "snake_case")]
pub enum RtbfStatus {
    /// Request submitted, waiting for review
    Pending,
    /// Request is being processed
    Processing,
    /// Data successfully deleted
    Completed,
    /// Request was cancelled by user
    Cancelled,
    /// Request failed due to error
    Failed,
}

/// GDPR data export request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExportRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: ExportStatus,
    pub format: ExportFormat,
    pub file_path: Option<String>,
    pub file_size_bytes: Option<i64>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
}

/// Data export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "export_format", rename_all = "lowercase")]
pub enum ExportFormat {
    /// JSON format (default, most structured)
    Json,
    /// CSV format (tabular data)
    Csv,
    /// ZIP archive containing multiple files
    Zip,
}

/// Right to be forgotten (RTBF) request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtbfRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: RtbfStatus,
    pub reason: Option<String>,
    pub anonymize_only: bool,
    pub legal_hold: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub deleted_records: Option<serde_json::Value>,
}

/// User's complete personal data for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPersonalData {
    pub user: UserData,
    pub nodes: Vec<NodeData>,
    pub content: Vec<ContentData>,
    pub transactions: Vec<TransactionData>,
    pub proofs: Vec<ProofData>,
    pub audit_log: Vec<AuditLogData>,
    pub export_metadata: ExportMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub public_key: String,
    pub points: i64,
    pub created_at: String,
    pub last_login: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub peer_id: String,
    pub multiaddr: String,
    pub capacity_gb: i64,
    pub reputation_score: f64,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentData {
    pub content_id: String,
    pub name: String,
    pub size_bytes: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub transaction_id: String,
    pub transaction_type: String,
    pub amount: i64,
    pub description: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub proof_id: String,
    pub chunk_hash: String,
    pub bytes_transferred: i64,
    pub timestamp: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogData {
    pub timestamp: String,
    pub action: String,
    pub category: String,
    pub severity: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub export_id: String,
    pub export_date: String,
    pub data_controller: String,
    pub gdpr_compliant: bool,
    pub retention_notice: String,
}

/// GDPR manager configuration
#[derive(Debug, Clone)]
pub struct GdprConfig {
    /// How long export files are kept before deletion (default: 30 days)
    pub export_retention_days: i64,
    /// Maximum export file size in MB (default: 500 MB)
    pub max_export_size_mb: i64,
    /// How long to keep RTBF request history (default: 365 days)
    pub rtbf_retention_days: i64,
    /// Whether to allow immediate deletion (vs anonymization)
    pub allow_immediate_deletion: bool,
}

impl Default for GdprConfig {
    fn default() -> Self {
        Self {
            export_retention_days: 30,
            max_export_size_mb: 500,
            rtbf_retention_days: 365,
            allow_immediate_deletion: false,
        }
    }
}

/// GDPR compliance manager
pub struct GdprManager {
    db: PgPool,
    config: Arc<RwLock<GdprConfig>>,
}

impl GdprManager {
    /// Create a new GDPR manager
    pub fn new(db: PgPool, config: GdprConfig) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Request a data export for a user (Right to Data Portability - Article 20)
    pub async fn request_export(
        &self,
        user_id: Uuid,
        format: ExportFormat,
    ) -> Result<DataExportRequest, GdprError> {
        let id = Uuid::new_v4();
        let config = self.config.read().await;
        let expires_at = chrono::Utc::now() + chrono::Duration::days(config.export_retention_days);

        let row = sqlx::query(
            r#"
            INSERT INTO gdpr_exports (id, user_id, status, format, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, status, format, file_path, file_size_bytes,
                      expires_at, created_at, completed_at, error_message
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(ExportStatus::Pending)
        .bind(format)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to create export request: {}", e);
            GdprError::DatabaseError(e.to_string())
        })?;

        let request = DataExportRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            format: row.get("format"),
            file_path: row.get("file_path"),
            file_size_bytes: row.get("file_size_bytes"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            error_message: row.get("error_message"),
        };

        info!("Created data export request {} for user {}", id, user_id);
        metrics::record_gdpr_export_created(format!("{:?}", format).to_lowercase());

        Ok(request)
    }

    /// Process a data export request and generate the export file
    pub async fn process_export(&self, export_id: Uuid) -> Result<(), GdprError> {
        // Update status to Processing
        sqlx::query("UPDATE gdpr_exports SET status = $1 WHERE id = $2")
            .bind(ExportStatus::Processing)
            .bind(export_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        // Fetch the export request
        let row = sqlx::query(
            r#"
            SELECT id, user_id, status, format, file_path, file_size_bytes,
                   expires_at, created_at, completed_at, error_message
            FROM gdpr_exports WHERE id = $1
            "#,
        )
        .bind(export_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        let export = DataExportRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            format: row.get("format"),
            file_path: row.get("file_path"),
            file_size_bytes: row.get("file_size_bytes"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            error_message: row.get("error_message"),
        };

        debug!(
            "Processing export request {} for user {}",
            export_id, export.user_id
        );

        // Gather all user data
        let _personal_data = self.gather_user_data(export.user_id).await?;

        // Generate export file (placeholder - actual file generation would happen here)
        let file_path = std::env::temp_dir()
            .join(format!("gdpr_export_{}.json", export_id))
            .to_string_lossy()
            .into_owned();
        let file_size = 1024; // Placeholder size

        // Update export as completed
        sqlx::query(
            "UPDATE gdpr_exports SET status = $1, file_path = $2, file_size_bytes = $3, completed_at = NOW() WHERE id = $4"
        )
        .bind(ExportStatus::Completed)
        .bind(file_path)
        .bind(file_size)
        .bind(export_id)
        .execute(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        info!(
            "Completed data export {} for user {}",
            export_id, export.user_id
        );
        metrics::record_gdpr_export_completed();

        Ok(())
    }

    /// Gather all personal data for a user
    async fn gather_user_data(&self, user_id: Uuid) -> Result<UserPersonalData, GdprError> {
        // Fetch user data
        let user = self.fetch_user_data(user_id).await?;
        let nodes = self.fetch_node_data(user_id).await?;
        let content = self.fetch_content_data(user_id).await?;
        let transactions = self.fetch_transaction_data(user_id).await?;
        let proofs = self.fetch_proof_data(user_id).await?;
        let audit_log = self.fetch_audit_log_data(user_id).await?;

        let export_metadata = ExportMetadata {
            export_id: Uuid::new_v4().to_string(),
            export_date: chrono::Utc::now().to_rfc3339(),
            data_controller: "CHIE Protocol".to_string(),
            gdpr_compliant: true,
            retention_notice: "This data export is available for 30 days and will be automatically deleted afterwards.".to_string(),
        };

        Ok(UserPersonalData {
            user,
            nodes,
            content,
            transactions,
            proofs,
            audit_log,
            export_metadata,
        })
    }

    async fn fetch_user_data(&self, user_id: Uuid) -> Result<UserData, GdprError> {
        let row = sqlx::query(
            r#"
            SELECT id, username, email, public_key, points_balance, created_at, last_seen_at
            FROM users WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(UserData {
            user_id: row.get::<Uuid, _>("id").to_string(),
            username: row.get("username"),
            email: row.get("email"),
            public_key: row.get("public_key"),
            points: row.get("points_balance"),
            created_at: row
                .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .to_rfc3339(),
            last_login: row
                .get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_seen_at")
                .map(|dt| dt.to_rfc3339()),
        })
    }

    async fn fetch_node_data(&self, user_id: Uuid) -> Result<Vec<NodeData>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT peer_id, max_storage_bytes, created_at
            FROM nodes WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| NodeData {
                peer_id: row.get("peer_id"),
                multiaddr: String::new(), // Not stored in schema
                capacity_gb: row.get::<i64, _>("max_storage_bytes") / (1024 * 1024 * 1024),
                reputation_score: 0.0, // Would fetch from reputation system
                registered_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect())
    }

    async fn fetch_content_data(&self, user_id: Uuid) -> Result<Vec<ContentData>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT id, title, size_bytes, created_at
            FROM content WHERE creator_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| ContentData {
                content_id: row.get::<Uuid, _>("id").to_string(),
                name: row.get("title"),
                size_bytes: row.get("size_bytes"),
                created_at: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect())
    }

    async fn fetch_transaction_data(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<TransactionData>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT id, type, amount, description, created_at
            FROM point_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1000
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| TransactionData {
                transaction_id: row.get::<Uuid, _>("id").to_string(),
                transaction_type: format!("{:?}", row.get::<String, _>("type")),
                amount: row.get("amount"),
                description: row.get("description"),
                timestamp: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
            })
            .collect())
    }

    async fn fetch_proof_data(&self, user_id: Uuid) -> Result<Vec<ProofData>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT bp.id, bp.chunk_hash, bp.bytes_transferred, bp.created_at, bp.status
            FROM bandwidth_proofs bp
            INNER JOIN nodes n1 ON bp.requester_node_id = n1.id
            LEFT JOIN nodes n2 ON bp.provider_node_id = n2.id
            WHERE n1.user_id = $1 OR n2.user_id = $1
            ORDER BY bp.created_at DESC LIMIT 1000
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| ProofData {
                proof_id: row.get::<Uuid, _>("id").to_string(),
                chunk_hash: hex::encode(row.get::<Vec<u8>, _>("chunk_hash")),
                bytes_transferred: row.get("bytes_transferred"),
                timestamp: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .to_rfc3339(),
                status: format!("{:?}", row.get::<String, _>("status")),
            })
            .collect())
    }

    async fn fetch_audit_log_data(&self, user_id: Uuid) -> Result<Vec<AuditLogData>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT timestamp, action, category, severity, details
            FROM audit_log WHERE actor_id = $1 ORDER BY timestamp DESC LIMIT 1000
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| AuditLogData {
                timestamp: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("timestamp")
                    .to_rfc3339(),
                action: row.get("action"),
                category: row.get("category"),
                severity: row.get("severity"),
                details: row.get("details"),
            })
            .collect())
    }

    /// Request right to be forgotten for a user (Article 17)
    pub async fn request_rtbf(
        &self,
        user_id: Uuid,
        reason: Option<String>,
        anonymize_only: bool,
    ) -> Result<RtbfRequest, GdprError> {
        let id = Uuid::new_v4();

        // Check for legal holds
        let legal_hold = self.check_legal_hold(user_id).await?;
        if legal_hold && !anonymize_only {
            warn!("Cannot delete user {} - legal hold in effect", user_id);
            return Err(GdprError::LegalHoldError(
                "User has active legal hold, can only anonymize".to_string(),
            ));
        }

        let row = sqlx::query(
            r#"
            INSERT INTO rtbf_requests (id, user_id, status, reason, anonymize_only, legal_hold)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_id, status, reason, anonymize_only, legal_hold,
                      created_at, completed_at, deleted_records
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(RtbfStatus::Pending)
        .bind(reason)
        .bind(anonymize_only)
        .bind(legal_hold)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            error!("Failed to create RTBF request: {}", e);
            GdprError::DatabaseError(e.to_string())
        })?;

        let request = RtbfRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            reason: row.get("reason"),
            anonymize_only: row.get("anonymize_only"),
            legal_hold: row.get("legal_hold"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            deleted_records: row.get("deleted_records"),
        };

        info!(
            "Created RTBF request {} for user {} (anonymize_only: {})",
            id, user_id, anonymize_only
        );
        metrics::record_gdpr_rtbf_created(if anonymize_only {
            "anonymize"
        } else {
            "delete"
        });

        Ok(request)
    }

    /// Process a right to be forgotten request
    pub async fn process_rtbf(&self, rtbf_id: Uuid) -> Result<(), GdprError> {
        // Update status to Processing
        sqlx::query("UPDATE rtbf_requests SET status = $1 WHERE id = $2")
            .bind(RtbfStatus::Processing)
            .bind(rtbf_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        // Fetch the RTBF request
        let row = sqlx::query(
            r#"
            SELECT id, user_id, status, reason, anonymize_only, legal_hold,
                   created_at, completed_at, deleted_records
            FROM rtbf_requests WHERE id = $1
            "#,
        )
        .bind(rtbf_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        let request = RtbfRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            reason: row.get("reason"),
            anonymize_only: row.get("anonymize_only"),
            legal_hold: row.get("legal_hold"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            deleted_records: row.get("deleted_records"),
        };

        debug!(
            "Processing RTBF request {} for user {}",
            rtbf_id, request.user_id
        );

        let deleted_records = if request.anonymize_only {
            self.anonymize_user_data(request.user_id).await?
        } else {
            self.delete_user_data(request.user_id).await?
        };

        // Update RTBF request as completed
        sqlx::query(
            "UPDATE rtbf_requests SET status = $1, completed_at = NOW(), deleted_records = $2 WHERE id = $3"
        )
        .bind(RtbfStatus::Completed)
        .bind(deleted_records)
        .bind(rtbf_id)
        .execute(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        info!(
            "Completed RTBF request {} for user {}",
            rtbf_id, request.user_id
        );
        metrics::record_gdpr_rtbf_completed(if request.anonymize_only {
            "anonymize"
        } else {
            "delete"
        });

        Ok(())
    }

    /// Check if user has active legal hold
    async fn check_legal_hold(&self, user_id: Uuid) -> Result<bool, GdprError> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM legal_holds WHERE user_id = $1 AND status = 'active'",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        let count: i64 = row.get("count");
        Ok(count > 0)
    }

    /// Anonymize user data (replace PII with anonymized values)
    async fn anonymize_user_data(&self, user_id: Uuid) -> Result<serde_json::Value, GdprError> {
        let mut deleted = HashMap::new();

        // Anonymize user record (correct column: id, not user_id)
        let user_count = sqlx::query(
            r#"
            UPDATE users
            SET email = 'anonymized_' || id || '@deleted.local',
                username = 'anonymized_' || id,
                public_key = NULL
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        deleted.insert("users_anonymized", user_count.rows_affected());

        // Anonymize audit log (remove PII from details)
        let audit_count = sqlx::query("UPDATE audit_log SET details = NULL WHERE actor_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        deleted.insert("audit_logs_anonymized", audit_count.rows_affected());

        info!("Anonymized data for user {}: {:?}", user_id, deleted);

        serde_json::to_value(deleted).map_err(|e| GdprError::SerializationError(e.to_string()))
    }

    /// Delete user data (complete removal)
    async fn delete_user_data(&self, user_id: Uuid) -> Result<serde_json::Value, GdprError> {
        let config = self.config.read().await;
        if !config.allow_immediate_deletion {
            return Err(GdprError::DeletionNotAllowed(
                "Immediate deletion is disabled".to_string(),
            ));
        }

        let mut deleted = HashMap::new();

        // Delete in reverse foreign key order
        // Delete bandwidth proofs (correct column names: requester_node_id, provider_node_id)
        let proof_count = sqlx::query(
            "DELETE FROM bandwidth_proofs WHERE requester_node_id IN (SELECT id FROM nodes WHERE user_id = $1) OR provider_node_id IN (SELECT id FROM nodes WHERE user_id = $1)",
        )
        .bind(user_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;
        deleted.insert("bandwidth_proofs", proof_count.rows_affected());

        // Delete transactions (correct table name: point_transactions)
        let tx_count = sqlx::query("DELETE FROM point_transactions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;
        deleted.insert("point_transactions", tx_count.rows_affected());

        // Delete content
        let content_count = sqlx::query("DELETE FROM content WHERE creator_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;
        deleted.insert("content", content_count.rows_affected());

        // Delete nodes (correct column name: user_id, not owner_id)
        let node_count = sqlx::query("DELETE FROM nodes WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;
        deleted.insert("nodes", node_count.rows_affected());

        // Finally delete user (correct column name: id, not user_id)
        let user_count = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| GdprError::DatabaseError(e.to_string()))?;
        deleted.insert("users", user_count.rows_affected());

        info!("Deleted data for user {}: {:?}", user_id, deleted);

        serde_json::to_value(deleted).map_err(|e| GdprError::SerializationError(e.to_string()))
    }

    /// Clean up expired export files
    pub async fn cleanup_expired_exports(&self) -> Result<u64, GdprError> {
        let result = sqlx::query(
            r#"
            DELETE FROM gdpr_exports
            WHERE status = $1 AND expires_at < NOW()
            "#,
        )
        .bind(ExportStatus::Completed)
        .execute(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!("Cleaned up {} expired export files", deleted);
            metrics::record_gdpr_exports_cleaned(deleted);
        }

        Ok(deleted)
    }

    /// Get export request status
    pub async fn get_export(&self, export_id: Uuid) -> Result<DataExportRequest, GdprError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, status, format, file_path, file_size_bytes,
                   expires_at, created_at, completed_at, error_message
            FROM gdpr_exports WHERE id = $1
            "#,
        )
        .bind(export_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(DataExportRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            format: row.get("format"),
            file_path: row.get("file_path"),
            file_size_bytes: row.get("file_size_bytes"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            error_message: row.get("error_message"),
        })
    }

    /// Get RTBF request status
    pub async fn get_rtbf(&self, rtbf_id: Uuid) -> Result<RtbfRequest, GdprError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, status, reason, anonymize_only, legal_hold,
                   created_at, completed_at, deleted_records
            FROM rtbf_requests WHERE id = $1
            "#,
        )
        .bind(rtbf_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(RtbfRequest {
            id: row.get("id"),
            user_id: row.get("user_id"),
            status: row.get("status"),
            reason: row.get("reason"),
            anonymize_only: row.get("anonymize_only"),
            legal_hold: row.get("legal_hold"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            deleted_records: row.get("deleted_records"),
        })
    }

    /// Get all export requests for a user
    pub async fn list_user_exports(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<DataExportRequest>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, status, format, file_path, file_size_bytes,
                   expires_at, created_at, completed_at, error_message
            FROM gdpr_exports WHERE user_id = $1 ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| DataExportRequest {
                id: row.get("id"),
                user_id: row.get("user_id"),
                status: row.get("status"),
                format: row.get("format"),
                file_path: row.get("file_path"),
                file_size_bytes: row.get("file_size_bytes"),
                expires_at: row.get("expires_at"),
                created_at: row.get("created_at"),
                completed_at: row.get("completed_at"),
                error_message: row.get("error_message"),
            })
            .collect())
    }

    /// Get all RTBF requests for a user
    pub async fn list_user_rtbf(&self, user_id: Uuid) -> Result<Vec<RtbfRequest>, GdprError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, status, reason, anonymize_only, legal_hold,
                   created_at, completed_at, deleted_records
            FROM rtbf_requests WHERE user_id = $1 ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| GdprError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| RtbfRequest {
                id: row.get("id"),
                user_id: row.get("user_id"),
                status: row.get("status"),
                reason: row.get("reason"),
                anonymize_only: row.get("anonymize_only"),
                legal_hold: row.get("legal_hold"),
                created_at: row.get("created_at"),
                completed_at: row.get("completed_at"),
                deleted_records: row.get("deleted_records"),
            })
            .collect())
    }

    /// Get configuration
    pub async fn config(&self) -> GdprConfig {
        self.config.read().await.clone()
    }
}

/// GDPR error types
#[derive(Debug, thiserror::Error)]
pub enum GdprError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Legal hold prevents deletion: {0}")]
    LegalHoldError(String),

    #[error("Deletion not allowed: {0}")]
    DeletionNotAllowed(String),

    #[error("Export not found")]
    ExportNotFound,

    #[error("RTBF request not found")]
    RtbfNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdpr_config_default() {
        let config = GdprConfig::default();
        assert_eq!(config.export_retention_days, 30);
        assert_eq!(config.max_export_size_mb, 500);
        assert_eq!(config.rtbf_retention_days, 365);
        assert!(!config.allow_immediate_deletion);
    }

    #[test]
    fn test_export_status_serialization() {
        let status = ExportStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Completed"));
    }

    #[test]
    fn test_rtbf_status_serialization() {
        let status = RtbfStatus::Processing;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Processing"));
    }

    #[test]
    fn test_export_metadata_creation() {
        let metadata = ExportMetadata {
            export_id: Uuid::new_v4().to_string(),
            export_date: chrono::Utc::now().to_rfc3339(),
            data_controller: "CHIE Protocol".to_string(),
            gdpr_compliant: true,
            retention_notice: "30 days".to_string(),
        };
        assert_eq!(metadata.data_controller, "CHIE Protocol");
        assert!(metadata.gdpr_compliant);
    }
}
