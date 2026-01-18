//! Comprehensive audit logging system for tracking all critical operations.
//!
//! This module provides a robust audit trail for compliance, security, and debugging.
//! It tracks:
//! - User operations (registration, authentication, modifications)
//! - Node operations (registration, updates, deactivation)
//! - Content operations (uploads, modifications, deletions)
//! - Admin operations (configuration changes, manual interventions)
//! - Proof submissions and verification results
//! - Security events (failed logins, suspicious activities)

use crate::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Audit event severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational events (normal operations).
    Info,
    /// Warning events (unusual but not critical).
    Warning,
    /// Critical events (security-relevant or high-impact).
    Critical,
}

impl AuditSeverity {
    /// Convert severity to string for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Parse severity from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => Self::Info,
        }
    }
}

/// Audit event categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// User-related operations.
    User,
    /// Node-related operations.
    Node,
    /// Content-related operations.
    Content,
    /// Bandwidth proof operations.
    Proof,
    /// Administrative operations.
    Admin,
    /// Security-related events.
    Security,
    /// System configuration changes.
    Config,
    /// Data retention/archiving operations.
    DataManagement,
}

impl AuditCategory {
    /// Convert category to string for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Node => "node",
            Self::Content => "content",
            Self::Proof => "proof",
            Self::Admin => "admin",
            Self::Security => "security",
            Self::Config => "config",
            Self::DataManagement => "data_management",
        }
    }

    /// Parse category from string.
    pub fn parse(s: &str) -> Self {
        match s {
            "user" => Self::User,
            "node" => Self::Node,
            "content" => Self::Content,
            "proof" => Self::Proof,
            "admin" => Self::Admin,
            "security" => Self::Security,
            "config" => Self::Config,
            "data_management" => Self::DataManagement,
            _ => Self::Admin,
        }
    }
}

/// Audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry.
    pub id: Uuid,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Event severity.
    pub severity: AuditSeverity,
    /// Event category.
    pub category: AuditCategory,
    /// Action performed (e.g., "user_created", "proof_verified").
    pub action: String,
    /// Actor who performed the action (user ID, "system", or "anonymous").
    pub actor: String,
    /// Actor's IP address (if available).
    pub ip_address: Option<String>,
    /// Resource affected (e.g., user ID, content ID).
    pub resource_type: Option<String>,
    /// Resource ID affected.
    pub resource_id: Option<String>,
    /// Request correlation ID for tracing.
    pub correlation_id: Option<String>,
    /// Additional details (JSON).
    pub details: Option<String>,
    /// Result of the operation (success, failure, partial).
    pub result: String,
    /// Error message if result is failure.
    pub error_message: Option<String>,
}

/// Configuration for audit logging.
#[derive(Debug, Clone)]
pub struct AuditLogConfig {
    /// Retention period for audit logs in days.
    pub retention_days: i32,
    /// Whether to log to database.
    pub log_to_database: bool,
    /// Whether to log to file/stdout.
    pub log_to_tracing: bool,
    /// Minimum severity to log.
    pub min_severity: AuditSeverity,
    /// Maximum batch size for bulk inserts.
    pub batch_size: usize,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            retention_days: 365, // 1 year default
            log_to_database: true,
            log_to_tracing: true,
            min_severity: AuditSeverity::Info,
            batch_size: 100,
        }
    }
}

/// Audit logger for tracking critical operations.
pub struct AuditLogger {
    /// Database connection pool.
    db: DbPool,
    /// Configuration.
    config: AuditLogConfig,
    /// In-memory buffer for batching.
    buffer: Arc<RwLock<Vec<AuditEntry>>>,
    /// Statistics.
    stats: Arc<RwLock<AuditStats>>,
}

/// Audit logging statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events logged.
    pub total_logged: u64,
    /// Events logged by severity.
    pub by_severity: SeverityStats,
    /// Events logged by category.
    pub by_category: CategoryStats,
    /// Total events flushed to database.
    pub total_flushed: u64,
    /// Total flush errors.
    pub flush_errors: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityStats {
    pub info: u64,
    pub warning: u64,
    pub critical: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryStats {
    pub user: u64,
    pub node: u64,
    pub content: u64,
    pub proof: u64,
    pub admin: u64,
    pub security: u64,
    pub config: u64,
    pub data_management: u64,
}

impl AuditLogger {
    /// Create a new audit logger.
    pub fn new(db: DbPool, config: AuditLogConfig) -> Self {
        Self {
            db,
            config,
            buffer: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(AuditStats::default())),
        }
    }

    /// Log an audit event.
    pub async fn log(&self, mut entry: AuditEntry) {
        // Check minimum severity
        if !self.should_log(entry.severity) {
            return;
        }

        // Ensure ID and timestamp are set
        if entry.id == Uuid::nil() {
            entry.id = Uuid::new_v4();
        }
        if entry.timestamp == DateTime::<Utc>::MIN_UTC {
            entry.timestamp = Utc::now();
        }

        // Log to tracing if enabled
        if self.config.log_to_tracing {
            self.log_to_tracing(&entry);
        }

        // Update statistics
        self.update_stats(&entry).await;

        // Add to buffer for database logging
        if self.config.log_to_database {
            let mut buffer = self.buffer.write().await;
            buffer.push(entry);

            // Flush if buffer is full
            if buffer.len() >= self.config.batch_size {
                let entries = buffer.drain(..).collect();
                drop(buffer); // Release lock before async operation
                self.flush_entries(entries).await;
            }
        }
    }

    /// Log an audit event with builder pattern.
    pub async fn log_event(
        &self,
        severity: AuditSeverity,
        category: AuditCategory,
        action: impl Into<String>,
    ) -> AuditEntryBuilder {
        AuditEntryBuilder::new(self.clone(), severity, category, action)
    }

    /// Check if event should be logged based on severity.
    fn should_log(&self, severity: AuditSeverity) -> bool {
        match (self.config.min_severity, severity) {
            (AuditSeverity::Critical, AuditSeverity::Critical) => true,
            (AuditSeverity::Critical, _) => false,
            (AuditSeverity::Warning, AuditSeverity::Info) => false,
            _ => true,
        }
    }

    /// Log to tracing system.
    fn log_to_tracing(&self, entry: &AuditEntry) {
        let msg = format!(
            "[AUDIT] {} - {} - {} by {} (result: {})",
            entry.category.as_str(),
            entry.action,
            entry.severity.as_str(),
            entry.actor,
            entry.result
        );

        match entry.severity {
            AuditSeverity::Info => debug!("{}", msg),
            AuditSeverity::Warning => warn!("{}", msg),
            AuditSeverity::Critical => error!("{}", msg),
        }
    }

    /// Update statistics.
    async fn update_stats(&self, entry: &AuditEntry) {
        let mut stats = self.stats.write().await;
        stats.total_logged += 1;

        // Update severity stats
        match entry.severity {
            AuditSeverity::Info => stats.by_severity.info += 1,
            AuditSeverity::Warning => stats.by_severity.warning += 1,
            AuditSeverity::Critical => stats.by_severity.critical += 1,
        }

        // Update category stats
        match entry.category {
            AuditCategory::User => stats.by_category.user += 1,
            AuditCategory::Node => stats.by_category.node += 1,
            AuditCategory::Content => stats.by_category.content += 1,
            AuditCategory::Proof => stats.by_category.proof += 1,
            AuditCategory::Admin => stats.by_category.admin += 1,
            AuditCategory::Security => stats.by_category.security += 1,
            AuditCategory::Config => stats.by_category.config += 1,
            AuditCategory::DataManagement => stats.by_category.data_management += 1,
        }
    }

    /// Flush entries to database.
    async fn flush_entries(&self, entries: Vec<AuditEntry>) {
        if entries.is_empty() {
            return;
        }

        let count = entries.len();
        match self.insert_batch(&entries).await {
            Ok(()) => {
                let mut stats = self.stats.write().await;
                stats.total_flushed += count as u64;
                debug!("Flushed {} audit entries to database", count);
            }
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.flush_errors += 1;
                error!("Failed to flush audit entries: {}", e);
            }
        }
    }

    /// Insert batch of entries into database.
    async fn insert_batch(&self, entries: &[AuditEntry]) -> Result<(), sqlx::Error> {
        let mut tx = self.db.begin().await?;

        for entry in entries {
            sqlx::query(
                r#"
                INSERT INTO audit_log (
                    id, timestamp, severity, category, action, actor, ip_address,
                    resource_type, resource_id, correlation_id, details, result, error_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(entry.id)
            .bind(entry.timestamp)
            .bind(entry.severity.as_str())
            .bind(entry.category.as_str())
            .bind(&entry.action)
            .bind(&entry.actor)
            .bind(&entry.ip_address)
            .bind(&entry.resource_type)
            .bind(&entry.resource_id)
            .bind(&entry.correlation_id)
            .bind(&entry.details)
            .bind(&entry.result)
            .bind(&entry.error_message)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Flush all pending entries to database.
    pub async fn flush(&self) -> Result<(), sqlx::Error> {
        let entries: Vec<AuditEntry> = {
            let mut buffer = self.buffer.write().await;
            buffer.drain(..).collect()
        };

        if !entries.is_empty() {
            self.flush_entries(entries).await;
        }

        Ok(())
    }

    /// Get audit statistics.
    pub async fn get_stats(&self) -> AuditStats {
        self.stats.read().await.clone()
    }

    /// Query audit log entries.
    pub async fn query(&self, filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, sqlx::Error> {
        // Flush pending entries first
        let _ = self.flush().await;

        let mut query = String::from(
            "SELECT id, timestamp, severity, category, action, actor, ip_address, \
             resource_type, resource_id, correlation_id, details, result, error_message \
             FROM audit_log WHERE 1=1",
        );

        let mut params: Vec<String> = Vec::new();

        if let Some(start) = filter.start_time {
            params.push(format!("timestamp >= '{}'", start.to_rfc3339()));
            query.push_str(&format!(" AND timestamp >= ${}", params.len()));
        }

        if let Some(end) = filter.end_time {
            params.push(format!("timestamp <= '{}'", end.to_rfc3339()));
            query.push_str(&format!(" AND timestamp <= ${}", params.len()));
        }

        if let Some(category) = filter.category {
            params.push(category.as_str().to_string());
            query.push_str(&format!(" AND category = ${}", params.len()));
        }

        if let Some(severity) = filter.severity {
            params.push(severity.as_str().to_string());
            query.push_str(&format!(" AND severity = ${}", params.len()));
        }

        if let Some(actor) = filter.actor {
            params.push(actor);
            query.push_str(&format!(" AND actor = ${}", params.len()));
        }

        if let Some(action) = filter.action {
            params.push(action);
            query.push_str(&format!(" AND action = ${}", params.len()));
        }

        query.push_str(&format!(" ORDER BY timestamp DESC LIMIT {}", filter.limit));

        let rows = sqlx::query(&query).fetch_all(&self.db).await?;

        let entries = rows
            .iter()
            .map(|row| AuditEntry {
                id: row.get("id"),
                timestamp: row.get("timestamp"),
                severity: AuditSeverity::parse(row.get("severity")),
                category: AuditCategory::parse(row.get("category")),
                action: row.get("action"),
                actor: row.get("actor"),
                ip_address: row.get("ip_address"),
                resource_type: row.get("resource_type"),
                resource_id: row.get("resource_id"),
                correlation_id: row.get("correlation_id"),
                details: row.get("details"),
                result: row.get("result"),
                error_message: row.get("error_message"),
            })
            .collect();

        Ok(entries)
    }

    /// Clean up old audit log entries based on retention policy.
    pub async fn cleanup_old_entries(&self) -> Result<u64, sqlx::Error> {
        let retention_date = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);

        let result = sqlx::query("DELETE FROM audit_log WHERE timestamp < $1")
            .bind(retention_date)
            .execute(&self.db)
            .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            debug!("Cleaned up {} old audit log entries", deleted);
        }

        Ok(deleted)
    }

    /// Start automatic cleanup task.
    pub fn start_auto_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                // Wait 24 hours
                tokio::time::sleep(tokio::time::Duration::from_secs(24 * 3600)).await;

                match self.cleanup_old_entries().await {
                    Ok(count) => {
                        if count > 0 {
                            debug!("Auto-cleanup removed {} old audit entries", count);
                        }
                    }
                    Err(e) => {
                        error!("Auto-cleanup failed: {}", e);
                    }
                }
            }
        })
    }
}

impl Clone for AuditLogger {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            config: self.config.clone(),
            buffer: Arc::clone(&self.buffer),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Query filter for audit log entries.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditQueryFilter {
    /// Start time filter.
    pub start_time: Option<DateTime<Utc>>,
    /// End time filter.
    pub end_time: Option<DateTime<Utc>>,
    /// Category filter.
    pub category: Option<AuditCategory>,
    /// Severity filter.
    pub severity: Option<AuditSeverity>,
    /// Actor filter.
    pub actor: Option<String>,
    /// Action filter.
    pub action: Option<String>,
    /// Maximum number of results.
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    100
}

/// Builder for audit log entries.
pub struct AuditEntryBuilder {
    logger: AuditLogger,
    entry: AuditEntry,
}

impl AuditEntryBuilder {
    /// Create a new audit entry builder.
    pub fn new(
        logger: AuditLogger,
        severity: AuditSeverity,
        category: AuditCategory,
        action: impl Into<String>,
    ) -> Self {
        Self {
            logger,
            entry: AuditEntry {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                severity,
                category,
                action: action.into(),
                actor: "system".to_string(),
                ip_address: None,
                resource_type: None,
                resource_id: None,
                correlation_id: None,
                details: None,
                result: "success".to_string(),
                error_message: None,
            },
        }
    }

    /// Set the actor.
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.entry.actor = actor.into();
        self
    }

    /// Set the IP address.
    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.entry.ip_address = Some(ip.into());
        self
    }

    /// Set the resource.
    pub fn resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.entry.resource_type = Some(resource_type.into());
        self.entry.resource_id = Some(resource_id.into());
        self
    }

    /// Set the correlation ID.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.entry.correlation_id = Some(id.into());
        self
    }

    /// Set additional details (JSON).
    pub fn details(mut self, details: impl Into<String>) -> Self {
        self.entry.details = Some(details.into());
        self
    }

    /// Set the result.
    pub fn result(mut self, result: impl Into<String>) -> Self {
        self.entry.result = result.into();
        self
    }

    /// Set error message (for failures).
    pub fn error(mut self, error: impl Into<String>) -> Self {
        self.entry.error_message = Some(error.into());
        self.entry.result = "failure".to_string();
        self
    }

    /// Submit the audit entry.
    pub async fn submit(self) {
        self.logger.log(self.entry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_severity_as_str() {
        assert_eq!(AuditSeverity::Info.as_str(), "info");
        assert_eq!(AuditSeverity::Warning.as_str(), "warning");
        assert_eq!(AuditSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_audit_severity_parse() {
        assert_eq!(AuditSeverity::parse("info"), AuditSeverity::Info);
        assert_eq!(AuditSeverity::parse("warning"), AuditSeverity::Warning);
        assert_eq!(AuditSeverity::parse("critical"), AuditSeverity::Critical);
        assert_eq!(AuditSeverity::parse("unknown"), AuditSeverity::Info);
    }

    #[test]
    fn test_audit_category_as_str() {
        assert_eq!(AuditCategory::User.as_str(), "user");
        assert_eq!(AuditCategory::Node.as_str(), "node");
        assert_eq!(AuditCategory::Content.as_str(), "content");
        assert_eq!(AuditCategory::Proof.as_str(), "proof");
        assert_eq!(AuditCategory::Admin.as_str(), "admin");
        assert_eq!(AuditCategory::Security.as_str(), "security");
        assert_eq!(AuditCategory::Config.as_str(), "config");
        assert_eq!(AuditCategory::DataManagement.as_str(), "data_management");
    }

    #[test]
    fn test_audit_category_parse() {
        assert_eq!(AuditCategory::parse("user"), AuditCategory::User);
        assert_eq!(AuditCategory::parse("node"), AuditCategory::Node);
        assert_eq!(AuditCategory::parse("content"), AuditCategory::Content);
        assert_eq!(AuditCategory::parse("proof"), AuditCategory::Proof);
        assert_eq!(AuditCategory::parse("admin"), AuditCategory::Admin);
        assert_eq!(AuditCategory::parse("security"), AuditCategory::Security);
        assert_eq!(AuditCategory::parse("config"), AuditCategory::Config);
        assert_eq!(
            AuditCategory::parse("data_management"),
            AuditCategory::DataManagement
        );
    }

    #[test]
    fn test_audit_log_config_default() {
        let config = AuditLogConfig::default();
        assert_eq!(config.retention_days, 365);
        assert!(config.log_to_database);
        assert!(config.log_to_tracing);
        assert_eq!(config.min_severity, AuditSeverity::Info);
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 100);
    }
}
