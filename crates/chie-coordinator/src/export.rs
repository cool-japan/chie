//! Data export system for analytics and reporting.
//!
//! This module provides comprehensive data export capabilities for:
//! - Audit logs
//! - Transaction history
//! - Proof verification data
//! - Node performance metrics
//! - Content statistics
//! - User activity data
//!
//! Supports multiple export formats:
//! - CSV (Comma-Separated Values)
//! - JSON (JavaScript Object Notation)
//! - JSON Lines (newline-delimited JSON)

use crate::DbPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::io::Write;
use tracing::debug;

/// Export format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// CSV format (comma-separated values).
    Csv,
    /// JSON format (array of objects).
    Json,
    /// JSON Lines format (newline-delimited JSON).
    JsonLines,
}

impl ExportFormat {
    /// Get file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::JsonLines => "jsonl",
        }
    }

    /// Get MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Csv => "text/csv",
            Self::Json => "application/json",
            Self::JsonLines => "application/x-ndjson",
        }
    }
}

/// Data export configuration.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// Maximum number of records to export in a single request.
    pub max_records: usize,
    /// Buffer size for streaming exports.
    pub buffer_size: usize,
    /// Whether to include headers in CSV exports.
    pub include_headers: bool,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            buffer_size: 8192,
            include_headers: true,
        }
    }
}

/// Audit log export filter.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogExportFilter {
    /// Start date for export.
    pub start_date: Option<DateTime<Utc>>,
    /// End date for export.
    pub end_date: Option<DateTime<Utc>>,
    /// Severity filter.
    pub severity: Option<String>,
    /// Category filter.
    pub category: Option<String>,
    /// Actor filter.
    pub actor: Option<String>,
}

/// Transaction export filter.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionExportFilter {
    /// Start date for export.
    pub start_date: Option<DateTime<Utc>>,
    /// End date for export.
    pub end_date: Option<DateTime<Utc>>,
    /// User ID filter.
    pub user_id: Option<i32>,
    /// Transaction type filter.
    pub transaction_type: Option<String>,
}

/// Proof export filter.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofExportFilter {
    /// Start date for export.
    pub start_date: Option<DateTime<Utc>>,
    /// End date for export.
    pub end_date: Option<DateTime<Utc>>,
    /// Status filter.
    pub status: Option<String>,
    /// Provider peer ID filter.
    pub provider_peer_id: Option<String>,
}

/// Node metrics export filter.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct NodeMetricsExportFilter {
    /// Start date for export.
    pub start_date: Option<DateTime<Utc>>,
    /// End date for export.
    pub end_date: Option<DateTime<Utc>>,
    /// Peer ID filter.
    pub peer_id: Option<String>,
}

/// Data exporter for generating export files.
#[derive(Clone)]
pub struct DataExporter {
    /// Database connection pool.
    db: DbPool,
    /// Export configuration.
    config: ExportConfig,
}

impl DataExporter {
    /// Create a new data exporter.
    pub fn new(db: DbPool, config: ExportConfig) -> Self {
        Self { db, config }
    }

    /// Export audit logs.
    pub async fn export_audit_logs(
        &self,
        filter: AuditLogExportFilter,
        format: ExportFormat,
    ) -> Result<Vec<u8>, String> {
        let mut query = String::from(
            "SELECT id, timestamp, severity, category, action, actor, ip_address, \
             resource_type, resource_id, correlation_id, result, error_message \
             FROM audit_log WHERE 1=1",
        );

        if let Some(start) = filter.start_date {
            query.push_str(&format!(" AND timestamp >= '{}'", start.to_rfc3339()));
        }

        if let Some(end) = filter.end_date {
            query.push_str(&format!(" AND timestamp <= '{}'", end.to_rfc3339()));
        }

        if let Some(severity) = filter.severity {
            query.push_str(&format!(" AND severity = '{}'", severity));
        }

        if let Some(category) = filter.category {
            query.push_str(&format!(" AND category = '{}'", category));
        }

        if let Some(actor) = filter.actor {
            query.push_str(&format!(" AND actor = '{}'", actor));
        }

        query.push_str(&format!(
            " ORDER BY timestamp DESC LIMIT {}",
            self.config.max_records
        ));

        let rows = sqlx::query(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("Database query failed: {}", e))?;

        debug!("Exporting {} audit log entries", rows.len());

        match format {
            ExportFormat::Csv => self.export_audit_logs_csv(&rows),
            ExportFormat::Json => self.export_audit_logs_json(&rows),
            ExportFormat::JsonLines => self.export_audit_logs_jsonlines(&rows),
        }
    }

    /// Export audit logs as CSV.
    fn export_audit_logs_csv(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        // Write headers
        if self.config.include_headers {
            writeln!(
                &mut output,
                "id,timestamp,severity,category,action,actor,ip_address,resource_type,resource_id,correlation_id,result,error_message"
            )
            .map_err(|e| e.to_string())?;
        }

        // Write data rows
        for row in rows {
            let id: uuid::Uuid = row.get("id");
            let timestamp: DateTime<Utc> = row.get("timestamp");
            let severity: String = row.get("severity");
            let category: String = row.get("category");
            let action: String = row.get("action");
            let actor: String = row.get("actor");
            let ip_address: Option<String> = row.get("ip_address");
            let resource_type: Option<String> = row.get("resource_type");
            let resource_id: Option<String> = row.get("resource_id");
            let correlation_id: Option<String> = row.get("correlation_id");
            let result: String = row.get("result");
            let error_message: Option<String> = row.get("error_message");

            writeln!(
                &mut output,
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                id,
                timestamp.to_rfc3339(),
                severity,
                category,
                Self::escape_csv(&action),
                Self::escape_csv(&actor),
                ip_address.unwrap_or_default(),
                resource_type.unwrap_or_default(),
                resource_id.unwrap_or_default(),
                correlation_id.unwrap_or_default(),
                result,
                error_message
                    .as_ref()
                    .map(|s| Self::escape_csv(s))
                    .unwrap_or_default()
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Export audit logs as JSON.
    fn export_audit_logs_json(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let mut records = Vec::new();

        for row in rows {
            let record = serde_json::json!({
                "id": row.get::<uuid::Uuid, _>("id").to_string(),
                "timestamp": row.get::<DateTime<Utc>, _>("timestamp").to_rfc3339(),
                "severity": row.get::<String, _>("severity"),
                "category": row.get::<String, _>("category"),
                "action": row.get::<String, _>("action"),
                "actor": row.get::<String, _>("actor"),
                "ip_address": row.get::<Option<String>, _>("ip_address"),
                "resource_type": row.get::<Option<String>, _>("resource_type"),
                "resource_id": row.get::<Option<String>, _>("resource_id"),
                "correlation_id": row.get::<Option<String>, _>("correlation_id"),
                "result": row.get::<String, _>("result"),
                "error_message": row.get::<Option<String>, _>("error_message"),
            });
            records.push(record);
        }

        serde_json::to_vec_pretty(&records).map_err(|e| e.to_string())
    }

    /// Export audit logs as JSON Lines.
    fn export_audit_logs_jsonlines(
        &self,
        rows: &[sqlx::postgres::PgRow],
    ) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        for row in rows {
            let record = serde_json::json!({
                "id": row.get::<uuid::Uuid, _>("id").to_string(),
                "timestamp": row.get::<DateTime<Utc>, _>("timestamp").to_rfc3339(),
                "severity": row.get::<String, _>("severity"),
                "category": row.get::<String, _>("category"),
                "action": row.get::<String, _>("action"),
                "actor": row.get::<String, _>("actor"),
                "ip_address": row.get::<Option<String>, _>("ip_address"),
                "resource_type": row.get::<Option<String>, _>("resource_type"),
                "resource_id": row.get::<Option<String>, _>("resource_id"),
                "correlation_id": row.get::<Option<String>, _>("correlation_id"),
                "result": row.get::<String, _>("result"),
                "error_message": row.get::<Option<String>, _>("error_message"),
            });

            writeln!(
                &mut output,
                "{}",
                serde_json::to_string(&record).map_err(|e| e.to_string())?
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Export transactions.
    pub async fn export_transactions(
        &self,
        filter: TransactionExportFilter,
        format: ExportFormat,
    ) -> Result<Vec<u8>, String> {
        let mut query = String::from(
            "SELECT id, user_id, amount, transaction_type, status, created_at, description \
             FROM transactions WHERE 1=1",
        );

        if let Some(start) = filter.start_date {
            query.push_str(&format!(" AND created_at >= '{}'", start.to_rfc3339()));
        }

        if let Some(end) = filter.end_date {
            query.push_str(&format!(" AND created_at <= '{}'", end.to_rfc3339()));
        }

        if let Some(user_id) = filter.user_id {
            query.push_str(&format!(" AND user_id = {}", user_id));
        }

        if let Some(tx_type) = filter.transaction_type {
            query.push_str(&format!(" AND transaction_type = '{}'", tx_type));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT {}",
            self.config.max_records
        ));

        let rows = sqlx::query(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("Database query failed: {}", e))?;

        debug!("Exporting {} transactions", rows.len());

        match format {
            ExportFormat::Csv => self.export_transactions_csv(&rows),
            ExportFormat::Json => self.export_transactions_json(&rows),
            ExportFormat::JsonLines => self.export_transactions_jsonlines(&rows),
        }
    }

    /// Export transactions as CSV.
    fn export_transactions_csv(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        if self.config.include_headers {
            writeln!(
                &mut output,
                "id,user_id,amount,transaction_type,status,created_at,description"
            )
            .map_err(|e| e.to_string())?;
        }

        for row in rows {
            writeln!(
                &mut output,
                "{},{},{},{},{},{},{}",
                row.get::<i32, _>("id"),
                row.get::<i32, _>("user_id"),
                row.get::<i64, _>("amount"),
                row.get::<String, _>("transaction_type"),
                row.get::<String, _>("status"),
                row.get::<DateTime<Utc>, _>("created_at").to_rfc3339(),
                Self::escape_csv(
                    &row.get::<Option<String>, _>("description")
                        .unwrap_or_default()
                )
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Export transactions as JSON.
    fn export_transactions_json(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let records: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.get::<i32, _>("id"),
                    "user_id": row.get::<i32, _>("user_id"),
                    "amount": row.get::<i64, _>("amount"),
                    "transaction_type": row.get::<String, _>("transaction_type"),
                    "status": row.get::<String, _>("status"),
                    "created_at": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339(),
                    "description": row.get::<Option<String>, _>("description"),
                })
            })
            .collect();

        serde_json::to_vec_pretty(&records).map_err(|e| e.to_string())
    }

    /// Export transactions as JSON Lines.
    fn export_transactions_jsonlines(
        &self,
        rows: &[sqlx::postgres::PgRow],
    ) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        for row in rows {
            let record = serde_json::json!({
                "id": row.get::<i32, _>("id"),
                "user_id": row.get::<i32, _>("user_id"),
                "amount": row.get::<i64, _>("amount"),
                "transaction_type": row.get::<String, _>("transaction_type"),
                "status": row.get::<String, _>("status"),
                "created_at": row.get::<DateTime<Utc>, _>("created_at").to_rfc3339(),
                "description": row.get::<Option<String>, _>("description"),
            });

            writeln!(
                &mut output,
                "{}",
                serde_json::to_string(&record).map_err(|e| e.to_string())?
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Export bandwidth proofs.
    pub async fn export_proofs(
        &self,
        filter: ProofExportFilter,
        format: ExportFormat,
    ) -> Result<Vec<u8>, String> {
        let mut query = String::from(
            "SELECT id, requester_peer_id, provider_peer_id, content_id, chunk_index, \
             bytes_transferred, transfer_duration_ms, status, verified_at \
             FROM bandwidth_proofs WHERE 1=1",
        );

        if let Some(start) = filter.start_date {
            query.push_str(&format!(" AND verified_at >= '{}'", start.to_rfc3339()));
        }

        if let Some(end) = filter.end_date {
            query.push_str(&format!(" AND verified_at <= '{}'", end.to_rfc3339()));
        }

        if let Some(status) = filter.status {
            query.push_str(&format!(" AND status = '{}'", status));
        }

        if let Some(provider) = filter.provider_peer_id {
            query.push_str(&format!(" AND provider_peer_id = '{}'", provider));
        }

        query.push_str(&format!(
            " ORDER BY verified_at DESC LIMIT {}",
            self.config.max_records
        ));

        let rows = sqlx::query(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| format!("Database query failed: {}", e))?;

        debug!("Exporting {} bandwidth proofs", rows.len());

        match format {
            ExportFormat::Csv => self.export_proofs_csv(&rows),
            ExportFormat::Json => self.export_proofs_json(&rows),
            ExportFormat::JsonLines => self.export_proofs_jsonlines(&rows),
        }
    }

    /// Export proofs as CSV.
    fn export_proofs_csv(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        if self.config.include_headers {
            writeln!(
                &mut output,
                "id,requester_peer_id,provider_peer_id,content_id,chunk_index,bytes_transferred,transfer_duration_ms,status,verified_at"
            )
            .map_err(|e| e.to_string())?;
        }

        for row in rows {
            writeln!(
                &mut output,
                "{},{},{},{},{},{},{},{},{}",
                row.get::<uuid::Uuid, _>("id"),
                row.get::<String, _>("requester_peer_id"),
                row.get::<String, _>("provider_peer_id"),
                row.get::<String, _>("content_id"),
                row.get::<i32, _>("chunk_index"),
                row.get::<i64, _>("bytes_transferred"),
                row.get::<i32, _>("transfer_duration_ms"),
                row.get::<String, _>("status"),
                row.get::<DateTime<Utc>, _>("verified_at").to_rfc3339()
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Export proofs as JSON.
    fn export_proofs_json(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let records: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.get::<uuid::Uuid, _>("id").to_string(),
                    "requester_peer_id": row.get::<String, _>("requester_peer_id"),
                    "provider_peer_id": row.get::<String, _>("provider_peer_id"),
                    "content_id": row.get::<String, _>("content_id"),
                    "chunk_index": row.get::<i32, _>("chunk_index"),
                    "bytes_transferred": row.get::<i64, _>("bytes_transferred"),
                    "transfer_duration_ms": row.get::<i32, _>("transfer_duration_ms"),
                    "status": row.get::<String, _>("status"),
                    "verified_at": row.get::<DateTime<Utc>, _>("verified_at").to_rfc3339(),
                })
            })
            .collect();

        serde_json::to_vec_pretty(&records).map_err(|e| e.to_string())
    }

    /// Export proofs as JSON Lines.
    fn export_proofs_jsonlines(&self, rows: &[sqlx::postgres::PgRow]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();

        for row in rows {
            let record = serde_json::json!({
                "id": row.get::<uuid::Uuid, _>("id").to_string(),
                "requester_peer_id": row.get::<String, _>("requester_peer_id"),
                "provider_peer_id": row.get::<String, _>("provider_peer_id"),
                "content_id": row.get::<String, _>("content_id"),
                "chunk_index": row.get::<i32, _>("chunk_index"),
                "bytes_transferred": row.get::<i64, _>("bytes_transferred"),
                "transfer_duration_ms": row.get::<i32, _>("transfer_duration_ms"),
                "status": row.get::<String, _>("status"),
                "verified_at": row.get::<DateTime<Utc>, _>("verified_at").to_rfc3339(),
            });

            writeln!(
                &mut output,
                "{}",
                serde_json::to_string(&record).map_err(|e| e.to_string())?
            )
            .map_err(|e| e.to_string())?;
        }

        Ok(output)
    }

    /// Escape CSV field (wrap in quotes if contains comma, newline, or quote).
    fn escape_csv(s: &str) -> String {
        if s.contains(',') || s.contains('\n') || s.contains('"') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Csv.extension(), "csv");
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::JsonLines.extension(), "jsonl");
    }

    #[test]
    fn test_export_format_mime_type() {
        assert_eq!(ExportFormat::Csv.mime_type(), "text/csv");
        assert_eq!(ExportFormat::Json.mime_type(), "application/json");
        assert_eq!(ExportFormat::JsonLines.mime_type(), "application/x-ndjson");
    }

    #[test]
    fn test_export_config_default() {
        let config = ExportConfig::default();
        assert_eq!(config.max_records, 100_000);
        assert_eq!(config.buffer_size, 8192);
        assert!(config.include_headers);
    }

    #[test]
    fn test_escape_csv_simple() {
        assert_eq!(DataExporter::escape_csv("hello"), "hello");
    }

    #[test]
    fn test_escape_csv_with_comma() {
        assert_eq!(DataExporter::escape_csv("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn test_escape_csv_with_quotes() {
        assert_eq!(
            DataExporter::escape_csv("hello\"world"),
            "\"hello\"\"world\""
        );
    }

    #[test]
    fn test_escape_csv_with_newline() {
        assert_eq!(DataExporter::escape_csv("hello\nworld"), "\"hello\nworld\"");
    }
}
