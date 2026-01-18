//! Content moderation and safety system for CHIE protocol.
//!
//! This module provides:
//! - Automated content flagging based on configurable rules
//! - Manual content flagging and review workflow
//! - Moderation actions (approve, reject, ban, quarantine)
//! - Integration with audit logging and webhooks
//! - Moderation statistics and reporting
//! - Content reputation scoring

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Content moderation flag reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlagReason {
    /// Violates content policy.
    PolicyViolation,
    /// Suspicious hash pattern.
    SuspiciousHash,
    /// Excessive file size.
    ExcessiveSize,
    /// Reported by users.
    UserReported,
    /// Detected malware.
    MalwareDetected,
    /// DMCA takedown request.
    DmcaTakedown,
    /// Spam or low quality.
    Spam,
    /// Manual flag by moderator.
    ManualFlag,
    /// Automated rule trigger.
    AutomatedRule,
    /// Other reason.
    Other,
}

impl FlagReason {
    /// Convert to database string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyViolation => "policy_violation",
            Self::SuspiciousHash => "suspicious_hash",
            Self::ExcessiveSize => "excessive_size",
            Self::UserReported => "user_reported",
            Self::MalwareDetected => "malware_detected",
            Self::DmcaTakedown => "dmca_takedown",
            Self::Spam => "spam",
            Self::ManualFlag => "manual_flag",
            Self::AutomatedRule => "automated_rule",
            Self::Other => "other",
        }
    }
}

/// Moderation action taken on content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    /// Content approved after review.
    Approved,
    /// Content rejected and removed.
    Rejected,
    /// Content quarantined for further review.
    Quarantined,
    /// Content banned (permanent removal).
    Banned,
    /// Flag dismissed as false positive.
    Dismissed,
}

impl ModerationAction {
    /// Convert to database string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Banned => "banned",
            Self::Dismissed => "dismissed",
        }
    }
}

/// Content moderation status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModerationStatus {
    /// Pending review.
    Pending,
    /// Under review by moderator.
    UnderReview,
    /// Review completed.
    Resolved,
}

impl ModerationStatus {
    /// Convert to database string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::UnderReview => "under_review",
            Self::Resolved => "resolved",
        }
    }
}

/// Content flag entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFlag {
    /// Flag ID.
    pub id: Uuid,
    /// Content ID being flagged.
    pub content_id: String,
    /// Reason for flagging.
    pub reason: FlagReason,
    /// Detailed description.
    pub description: Option<String>,
    /// Reporter user ID (if manual report).
    pub reporter_id: Option<Uuid>,
    /// Moderation status.
    pub status: ModerationStatus,
    /// Action taken (if resolved).
    pub action: Option<ModerationAction>,
    /// Moderator who took action.
    pub moderator_id: Option<Uuid>,
    /// Severity score (0-100).
    pub severity: i32,
    /// Flag creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Resolution timestamp.
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Moderation rule for automatic flagging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationRule {
    /// Rule ID.
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Rule description.
    pub description: String,
    /// Is rule enabled.
    pub enabled: bool,
    /// Flag reason when triggered.
    pub flag_reason: FlagReason,
    /// Severity score (0-100).
    pub severity: i32,
    /// Rule configuration.
    pub config: RuleConfig,
}

/// Rule configuration for different rule types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleConfig {
    /// File size threshold.
    FileSizeLimit {
        /// Maximum size in bytes.
        max_size_bytes: u64,
    },
    /// Blocked hash patterns.
    HashBlocklist {
        /// List of blocked hashes.
        blocked_hashes: Vec<String>,
    },
    /// Content type restrictions.
    ContentTypeFilter {
        /// Allowed MIME types.
        allowed_types: Vec<String>,
    },
    /// Upload rate limit per user.
    UploadRateLimit {
        /// Max uploads per time window.
        max_uploads: u32,
        /// Time window in seconds.
        window_secs: u64,
    },
    /// Custom rule with configurable thresholds.
    Custom {
        /// Custom configuration.
        config: serde_json::Value,
    },
}

/// Moderation statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModerationStats {
    /// Total flags created.
    pub total_flags: u64,
    /// Flags pending review.
    pub pending_flags: u64,
    /// Flags under review.
    pub under_review_flags: u64,
    /// Flags resolved.
    pub resolved_flags: u64,
    /// Content approved.
    pub content_approved: u64,
    /// Content rejected.
    pub content_rejected: u64,
    /// Content banned.
    pub content_banned: u64,
    /// Content quarantined.
    pub content_quarantined: u64,
    /// Flags dismissed.
    pub flags_dismissed: u64,
    /// Average resolution time in seconds.
    pub avg_resolution_time_secs: f64,
    /// Flags by reason.
    pub flags_by_reason: HashMap<String, u64>,
}

/// Content moderation system configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationConfig {
    /// Enable automatic flagging.
    pub auto_flag_enabled: bool,
    /// Default severity for auto-flagged content.
    pub default_severity: i32,
    /// Auto-quarantine threshold (severity score).
    pub auto_quarantine_threshold: i32,
    /// Auto-ban threshold (severity score).
    pub auto_ban_threshold: i32,
    /// Maximum flags per content.
    pub max_flags_per_content: u32,
    /// Enable webhook notifications.
    pub webhook_notifications: bool,
}

impl Default for ModerationConfig {
    fn default() -> Self {
        Self {
            auto_flag_enabled: true,
            default_severity: 50,
            auto_quarantine_threshold: 70,
            auto_ban_threshold: 90,
            max_flags_per_content: 10,
            webhook_notifications: true,
        }
    }
}

/// Content moderation manager.
#[derive(Clone)]
pub struct ModerationManager {
    db: PgPool,
    config: ModerationConfig,
    rules: Arc<RwLock<Vec<ModerationRule>>>,
    stats: Arc<RwLock<ModerationStats>>,
}

impl ModerationManager {
    /// Create a new moderation manager.
    pub fn new(db: PgPool, config: ModerationConfig) -> Self {
        Self {
            db,
            config,
            rules: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(ModerationStats::default())),
        }
    }

    /// Initialize with default moderation rules.
    pub async fn init_default_rules(&self) {
        let mut rules = self.rules.write().await;

        // Rule 1: File size limit (10GB)
        rules.push(ModerationRule {
            id: "file_size_limit".to_string(),
            name: "File Size Limit".to_string(),
            description: "Flag files exceeding 10GB".to_string(),
            enabled: true,
            flag_reason: FlagReason::ExcessiveSize,
            severity: 40,
            config: RuleConfig::FileSizeLimit {
                max_size_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            },
        });

        // Rule 2: Upload rate limit
        rules.push(ModerationRule {
            id: "upload_rate_limit".to_string(),
            name: "Upload Rate Limit".to_string(),
            description: "Flag users uploading more than 100 files per hour".to_string(),
            enabled: true,
            flag_reason: FlagReason::Spam,
            severity: 60,
            config: RuleConfig::UploadRateLimit {
                max_uploads: 100,
                window_secs: 3600,
            },
        });

        info!("Initialized {} default moderation rules", rules.len());
    }

    /// Flag content for moderation.
    pub async fn flag_content(
        &self,
        content_id: String,
        reason: FlagReason,
        description: Option<String>,
        reporter_id: Option<Uuid>,
        severity: Option<i32>,
    ) -> Result<Uuid, anyhow::Error> {
        let flag_id = Uuid::new_v4();
        let severity = severity.unwrap_or(self.config.default_severity);
        let status = ModerationStatus::Pending;

        // Insert flag into database
        sqlx::query(
            r#"
            INSERT INTO content_flags
                (id, content_id, reason, description, reporter_id, status, severity, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            "#,
        )
        .bind(flag_id)
        .bind(&content_id)
        .bind(reason.as_str())
        .bind(&description)
        .bind(reporter_id)
        .bind(status.as_str())
        .bind(severity)
        .execute(&self.db)
        .await?;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_flags += 1;
        stats.pending_flags += 1;
        *stats
            .flags_by_reason
            .entry(reason.as_str().to_string())
            .or_insert(0) += 1;

        info!(
            "Content flagged: content_id={}, reason={:?}, severity={}",
            content_id, reason, severity
        );

        // Auto-quarantine or ban based on severity
        if severity >= self.config.auto_ban_threshold {
            warn!(
                "Auto-banning content due to high severity: {} (threshold: {})",
                severity, self.config.auto_ban_threshold
            );
            self.take_action_internal(
                flag_id,
                ModerationAction::Banned,
                None,
                Some("Auto-banned due to high severity".to_string()),
            )
            .await?;
        } else if severity >= self.config.auto_quarantine_threshold {
            warn!(
                "Auto-quarantining content due to severity: {} (threshold: {})",
                severity, self.config.auto_quarantine_threshold
            );
            self.take_action_internal(
                flag_id,
                ModerationAction::Quarantined,
                None,
                Some("Auto-quarantined for review".to_string()),
            )
            .await?;
        }

        Ok(flag_id)
    }

    /// Check content against moderation rules.
    pub async fn check_content(
        &self,
        content_id: String,
        file_size: Option<u64>,
        content_type: Option<String>,
        uploader_id: Option<Uuid>,
    ) -> Result<Vec<Uuid>, anyhow::Error> {
        if !self.config.auto_flag_enabled {
            return Ok(Vec::new());
        }

        let mut flags = Vec::new();
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            let should_flag = match &rule.config {
                RuleConfig::FileSizeLimit { max_size_bytes } => {
                    if let Some(size) = file_size {
                        size > *max_size_bytes
                    } else {
                        false
                    }
                }
                RuleConfig::ContentTypeFilter { allowed_types } => {
                    if let Some(ref ct) = content_type {
                        !allowed_types.iter().any(|allowed| ct.contains(allowed))
                    } else {
                        false
                    }
                }
                RuleConfig::UploadRateLimit {
                    max_uploads,
                    window_secs,
                } => {
                    if let Some(user_id) = uploader_id {
                        self.check_upload_rate(user_id, *max_uploads, *window_secs)
                            .await
                            .unwrap_or(false)
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if should_flag {
                debug!("Rule '{}' triggered for content: {}", rule.name, content_id);

                let flag_id = self
                    .flag_content(
                        content_id.clone(),
                        rule.flag_reason.clone(),
                        Some(format!("Triggered by rule: {}", rule.name)),
                        None,
                        Some(rule.severity),
                    )
                    .await?;

                flags.push(flag_id);
            }
        }

        Ok(flags)
    }

    /// Check upload rate for a user.
    async fn check_upload_rate(
        &self,
        user_id: Uuid,
        max_uploads: u32,
        window_secs: u64,
    ) -> Result<bool, anyhow::Error> {
        let window_start = chrono::Utc::now() - chrono::Duration::seconds(window_secs as i64);

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM content
            WHERE uploader_id = $1 AND created_at > $2
            "#,
        )
        .bind(user_id)
        .bind(window_start)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        Ok(count as u32 > max_uploads)
    }

    /// Take moderation action on flagged content.
    pub async fn take_action(
        &self,
        flag_id: Uuid,
        action: ModerationAction,
        moderator_id: Option<Uuid>,
        notes: Option<String>,
    ) -> Result<(), anyhow::Error> {
        self.take_action_internal(flag_id, action, moderator_id, notes)
            .await
    }

    /// Internal method to take action (used by both manual and auto actions).
    async fn take_action_internal(
        &self,
        flag_id: Uuid,
        action: ModerationAction,
        moderator_id: Option<Uuid>,
        notes: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let metadata = notes.map(|n| serde_json::json!({ "notes": n }));

        sqlx::query(
            r#"
            UPDATE content_flags
            SET status = $1,
                action = $2,
                moderator_id = $3,
                resolved_at = NOW(),
                metadata = COALESCE($4, metadata)
            WHERE id = $5
            "#,
        )
        .bind(ModerationStatus::Resolved.as_str())
        .bind(action.as_str())
        .bind(moderator_id)
        .bind(metadata)
        .bind(flag_id)
        .execute(&self.db)
        .await?;

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.pending_flags = stats.pending_flags.saturating_sub(1);
        stats.resolved_flags += 1;

        match action {
            ModerationAction::Approved => stats.content_approved += 1,
            ModerationAction::Rejected => stats.content_rejected += 1,
            ModerationAction::Banned => stats.content_banned += 1,
            ModerationAction::Quarantined => stats.content_quarantined += 1,
            ModerationAction::Dismissed => stats.flags_dismissed += 1,
        }

        info!(
            "Moderation action taken: flag_id={}, action={:?}, moderator={:?}",
            flag_id, action, moderator_id
        );

        Ok(())
    }

    /// Get pending moderation queue.
    pub async fn get_pending_flags(&self, limit: i64) -> Result<Vec<ContentFlag>, anyhow::Error> {
        #[allow(dead_code)]
        #[derive(sqlx::FromRow)]
        struct FlagRow {
            id: Uuid,
            content_id: String,
            reason: String,
            description: Option<String>,
            reporter_id: Option<Uuid>,
            status: String,
            action: Option<String>,
            moderator_id: Option<Uuid>,
            severity: i32,
            created_at: chrono::NaiveDateTime,
            resolved_at: Option<chrono::NaiveDateTime>,
            metadata: Option<serde_json::Value>,
        }

        let rows: Vec<FlagRow> = sqlx::query_as(
            r#"
            SELECT id, content_id, reason, description, reporter_id,
                   status, action, moderator_id, severity,
                   created_at, resolved_at, metadata
            FROM content_flags
            WHERE status IN ('pending', 'under_review')
            ORDER BY severity DESC, created_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        let flags = rows
            .into_iter()
            .map(|row| {
                let reason = match row.reason.as_str() {
                    "policy_violation" => FlagReason::PolicyViolation,
                    "suspicious_hash" => FlagReason::SuspiciousHash,
                    "excessive_size" => FlagReason::ExcessiveSize,
                    "user_reported" => FlagReason::UserReported,
                    "malware_detected" => FlagReason::MalwareDetected,
                    "dmca_takedown" => FlagReason::DmcaTakedown,
                    "spam" => FlagReason::Spam,
                    "manual_flag" => FlagReason::ManualFlag,
                    "automated_rule" => FlagReason::AutomatedRule,
                    _ => FlagReason::Other,
                };

                let status = match row.status.as_str() {
                    "pending" => ModerationStatus::Pending,
                    "under_review" => ModerationStatus::UnderReview,
                    _ => ModerationStatus::Resolved,
                };

                let action = row.action.as_ref().and_then(|a| match a.as_str() {
                    "approved" => Some(ModerationAction::Approved),
                    "rejected" => Some(ModerationAction::Rejected),
                    "quarantined" => Some(ModerationAction::Quarantined),
                    "banned" => Some(ModerationAction::Banned),
                    "dismissed" => Some(ModerationAction::Dismissed),
                    _ => None,
                });

                ContentFlag {
                    id: row.id,
                    content_id: row.content_id,
                    reason,
                    description: row.description,
                    reporter_id: row.reporter_id,
                    status,
                    action,
                    moderator_id: row.moderator_id,
                    severity: row.severity,
                    created_at: row.created_at.and_utc(),
                    resolved_at: row.resolved_at.map(|dt| dt.and_utc()),
                    metadata: row.metadata,
                }
            })
            .collect();

        Ok(flags)
    }

    /// Get content flags by content ID.
    pub async fn get_flags_by_content(
        &self,
        content_id: &str,
    ) -> Result<Vec<ContentFlag>, anyhow::Error> {
        #[allow(dead_code)]
        #[derive(sqlx::FromRow)]
        struct FlagRow {
            id: Uuid,
            content_id: String,
            reason: String,
            description: Option<String>,
            reporter_id: Option<Uuid>,
            status: String,
            action: Option<String>,
            moderator_id: Option<Uuid>,
            severity: i32,
            created_at: chrono::NaiveDateTime,
            resolved_at: Option<chrono::NaiveDateTime>,
            metadata: Option<serde_json::Value>,
        }

        let rows: Vec<FlagRow> = sqlx::query_as(
            r#"
            SELECT id, content_id, reason, description, reporter_id,
                   status, action, moderator_id, severity,
                   created_at, resolved_at, metadata
            FROM content_flags
            WHERE content_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(content_id)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        let flags = rows
            .into_iter()
            .map(|row| {
                let reason = match row.reason.as_str() {
                    "policy_violation" => FlagReason::PolicyViolation,
                    "suspicious_hash" => FlagReason::SuspiciousHash,
                    "excessive_size" => FlagReason::ExcessiveSize,
                    "user_reported" => FlagReason::UserReported,
                    "malware_detected" => FlagReason::MalwareDetected,
                    "dmca_takedown" => FlagReason::DmcaTakedown,
                    "spam" => FlagReason::Spam,
                    "manual_flag" => FlagReason::ManualFlag,
                    "automated_rule" => FlagReason::AutomatedRule,
                    _ => FlagReason::Other,
                };

                let status = match row.status.as_str() {
                    "pending" => ModerationStatus::Pending,
                    "under_review" => ModerationStatus::UnderReview,
                    _ => ModerationStatus::Resolved,
                };

                let action = row.action.as_ref().and_then(|a| match a.as_str() {
                    "approved" => Some(ModerationAction::Approved),
                    "rejected" => Some(ModerationAction::Rejected),
                    "quarantined" => Some(ModerationAction::Quarantined),
                    "banned" => Some(ModerationAction::Banned),
                    "dismissed" => Some(ModerationAction::Dismissed),
                    _ => None,
                });

                ContentFlag {
                    id: row.id,
                    content_id: row.content_id,
                    reason,
                    description: row.description,
                    reporter_id: row.reporter_id,
                    status,
                    action,
                    moderator_id: row.moderator_id,
                    severity: row.severity,
                    created_at: row.created_at.and_utc(),
                    resolved_at: row.resolved_at.map(|dt| dt.and_utc()),
                    metadata: row.metadata,
                }
            })
            .collect();

        Ok(flags)
    }

    /// Get moderation statistics.
    pub async fn get_stats(&self) -> ModerationStats {
        // Update stats from database
        if let Ok(counts) = self.get_stats_from_db().await {
            let mut stats = self.stats.write().await;
            *stats = counts;
        }

        self.stats.read().await.clone()
    }

    /// Get statistics from database.
    async fn get_stats_from_db(&self) -> Result<ModerationStats, anyhow::Error> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_flags")
            .fetch_one(&self.db)
            .await
            .unwrap_or(0);

        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE status = 'pending'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let under_review: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE status = 'under_review'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let resolved: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE status = 'resolved'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let approved: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE action = 'approved'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let rejected: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE action = 'rejected'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let banned: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE action = 'banned'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let quarantined: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE action = 'quarantined'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let dismissed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_flags WHERE action = 'dismissed'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        // Calculate average resolution time
        let avg_time: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)))
            FROM content_flags
            WHERE resolved_at IS NOT NULL
            "#,
        )
        .fetch_one(&self.db)
        .await
        .ok();

        // Get flags by reason
        struct ReasonCount {
            reason: String,
            count: i64,
        }

        let reason_rows: Vec<ReasonCount> = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT reason, COUNT(*) as count
            FROM content_flags
            GROUP BY reason
            "#,
        )
        .fetch_all(&self.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(reason, count)| ReasonCount { reason, count })
        .collect();

        let mut flags_by_reason = HashMap::new();
        for row in reason_rows {
            flags_by_reason.insert(row.reason, row.count as u64);
        }

        Ok(ModerationStats {
            total_flags: total as u64,
            pending_flags: pending as u64,
            under_review_flags: under_review as u64,
            resolved_flags: resolved as u64,
            content_approved: approved as u64,
            content_rejected: rejected as u64,
            content_banned: banned as u64,
            content_quarantined: quarantined as u64,
            flags_dismissed: dismissed as u64,
            avg_resolution_time_secs: avg_time.unwrap_or(0.0),
            flags_by_reason,
        })
    }

    /// Add a moderation rule.
    pub async fn add_rule(&self, rule: ModerationRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    /// Get all moderation rules.
    pub async fn get_rules(&self) -> Vec<ModerationRule> {
        self.rules.read().await.clone()
    }

    /// Update rule enabled status.
    pub async fn set_rule_enabled(
        &self,
        rule_id: &str,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let mut rules = self.rules.write().await;
        if let Some(rule) = rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            info!(
                "Rule '{}' {}",
                rule_id,
                if enabled { "enabled" } else { "disabled" }
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("Rule not found: {}", rule_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_reason_as_str() {
        assert_eq!(FlagReason::PolicyViolation.as_str(), "policy_violation");
        assert_eq!(FlagReason::Spam.as_str(), "spam");
        assert_eq!(FlagReason::MalwareDetected.as_str(), "malware_detected");
    }

    #[test]
    fn test_moderation_action_as_str() {
        assert_eq!(ModerationAction::Approved.as_str(), "approved");
        assert_eq!(ModerationAction::Banned.as_str(), "banned");
        assert_eq!(ModerationAction::Quarantined.as_str(), "quarantined");
    }

    #[test]
    fn test_moderation_status_as_str() {
        assert_eq!(ModerationStatus::Pending.as_str(), "pending");
        assert_eq!(ModerationStatus::UnderReview.as_str(), "under_review");
        assert_eq!(ModerationStatus::Resolved.as_str(), "resolved");
    }

    #[test]
    fn test_moderation_config_defaults() {
        let config = ModerationConfig::default();
        assert!(config.auto_flag_enabled);
        assert_eq!(config.default_severity, 50);
        assert_eq!(config.auto_quarantine_threshold, 70);
        assert_eq!(config.auto_ban_threshold, 90);
    }

    #[test]
    fn test_moderation_stats_default() {
        let stats = ModerationStats::default();
        assert_eq!(stats.total_flags, 0);
        assert_eq!(stats.pending_flags, 0);
        assert_eq!(stats.content_approved, 0);
    }
}
