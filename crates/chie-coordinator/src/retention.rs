use chrono::{DateTime, Duration, Utc};
use metrics::{counter, gauge, histogram};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Configuration for data retention policies
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// How long to keep completed transactions (days)
    pub transaction_retention_days: i64,
    /// How long to keep bandwidth proofs (days)
    pub proof_retention_days: i64,
    /// How long to keep user activity logs (days)
    pub activity_log_retention_days: i64,
    /// How long to keep metrics/stats data (days)
    pub metrics_retention_days: i64,
    /// How often to run retention cleanup (hours)
    pub cleanup_interval_hours: u64,
    /// Enable automatic cleanup on schedule
    pub auto_cleanup_enabled: bool,
    /// Batch size for deletion operations
    pub deletion_batch_size: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            transaction_retention_days: 90,   // 3 months
            proof_retention_days: 30,         // 1 month
            activity_log_retention_days: 180, // 6 months
            metrics_retention_days: 365,      // 1 year
            cleanup_interval_hours: 24,       // Daily
            auto_cleanup_enabled: true,
            deletion_batch_size: 1000,
        }
    }
}

/// Statistics about retention cleanup operations
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RetentionStats {
    /// Total number of cleanup runs
    pub total_cleanups: u64,
    /// Total records deleted
    pub total_deleted: u64,
    /// Last cleanup timestamp
    pub last_cleanup: Option<DateTime<Utc>>,
    /// Last cleanup duration (seconds)
    pub last_cleanup_duration: Option<f64>,
    /// Number of errors encountered
    pub errors: u64,
}

/// Data retention policy manager
pub struct RetentionManager {
    config: RetentionConfig,
    pool: PgPool,
    stats: Arc<RwLock<RetentionStats>>,
}

impl RetentionManager {
    /// Create a new retention manager
    pub fn new(config: RetentionConfig, pool: PgPool) -> Self {
        Self {
            config,
            pool,
            stats: Arc::new(RwLock::new(RetentionStats::default())),
        }
    }

    /// Start automatic cleanup task
    pub fn start_auto_cleanup(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_hours = self.config.cleanup_interval_hours;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_hours * 3600));

            loop {
                interval.tick().await;

                if self.config.auto_cleanup_enabled {
                    info!("Starting scheduled retention cleanup");
                    if let Err(e) = self.run_cleanup().await {
                        error!("Retention cleanup failed: {}", e);
                        let mut stats = self.stats.write().await;
                        stats.errors += 1;
                        counter!("retention_cleanup_errors_total").increment(1);
                    }
                } else {
                    warn!("Auto cleanup is disabled, skipping");
                }
            }
        })
    }

    /// Run retention cleanup manually
    pub async fn run_cleanup(&self) -> Result<u64, sqlx::Error> {
        let start = std::time::Instant::now();
        let mut total_deleted = 0u64;

        info!("Starting retention cleanup");

        // Clean up old transactions
        let deleted = self.cleanup_old_transactions().await?;
        total_deleted += deleted;
        info!("Deleted {} old transactions", deleted);

        // Clean up old bandwidth proofs
        let deleted = self.cleanup_old_proofs().await?;
        total_deleted += deleted;
        info!("Deleted {} old bandwidth proofs", deleted);

        // Clean up old activity logs
        let deleted = self.cleanup_old_activity_logs().await?;
        total_deleted += deleted;
        info!("Deleted {} old activity logs", deleted);

        // Clean up old metrics
        let deleted = self.cleanup_old_metrics().await?;
        total_deleted += deleted;
        info!("Deleted {} old metrics", deleted);

        let duration = start.elapsed().as_secs_f64();

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_cleanups += 1;
        stats.total_deleted += total_deleted;
        stats.last_cleanup = Some(Utc::now());
        stats.last_cleanup_duration = Some(duration);

        // Record metrics
        counter!("retention_cleanup_total").increment(1);
        counter!("retention_records_deleted_total").increment(total_deleted);
        histogram!("retention_cleanup_duration_seconds").record(duration);
        gauge!("retention_last_cleanup_timestamp").set(Utc::now().timestamp() as f64);

        info!(
            "Retention cleanup completed: {} records deleted in {:.2}s",
            total_deleted, duration
        );

        Ok(total_deleted)
    }

    /// Clean up old transactions
    async fn cleanup_old_transactions(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.transaction_retention_days);
        let batch_size = self.config.deletion_batch_size;

        let result = sqlx::query(
            r#"
            WITH deleted AS (
                DELETE FROM transactions
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM transactions
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(cutoff)
        .bind(batch_size)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = result.try_get("count").unwrap_or(0);
        let count = count as u64;
        counter!("retention_transactions_deleted_total").increment(count);
        Ok(count)
    }

    /// Clean up old bandwidth proofs
    async fn cleanup_old_proofs(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.proof_retention_days);
        let batch_size = self.config.deletion_batch_size;

        let result = sqlx::query(
            r#"
            WITH deleted AS (
                DELETE FROM bandwidth_proofs
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM bandwidth_proofs
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(cutoff)
        .bind(batch_size)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = result.try_get("count").unwrap_or(0);
        let count = count as u64;
        counter!("retention_proofs_deleted_total").increment(count);
        Ok(count)
    }

    /// Clean up old activity logs
    async fn cleanup_old_activity_logs(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.activity_log_retention_days);
        let batch_size = self.config.deletion_batch_size;

        // This assumes an activity_logs table exists
        // If it doesn't exist yet, this will just return 0
        let result = sqlx::query(
            r#"
            WITH deleted AS (
                DELETE FROM activity_logs
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM activity_logs
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(cutoff)
        .bind(batch_size)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => {
                let count: i64 = row.try_get("count").unwrap_or(0);
                let count = count as u64;
                counter!("retention_activity_logs_deleted_total").increment(count);
                Ok(count)
            }
            Ok(None) => Ok(0),
            Err(_) => Ok(0), // Table doesn't exist yet
        }
    }

    /// Clean up old metrics
    async fn cleanup_old_metrics(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.metrics_retention_days);
        let batch_size = self.config.deletion_batch_size;

        // This assumes a metrics table exists
        // If it doesn't exist yet, this will just return 0
        let result = sqlx::query(
            r#"
            WITH deleted AS (
                DELETE FROM metrics
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM metrics
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(cutoff)
        .bind(batch_size)
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => {
                let count: i64 = row.try_get("count").unwrap_or(0);
                let count = count as u64;
                counter!("retention_metrics_deleted_total").increment(count);
                Ok(count)
            }
            Ok(None) => Ok(0),
            Err(_) => Ok(0), // Table doesn't exist yet
        }
    }

    /// Get current retention statistics
    pub async fn get_stats(&self) -> RetentionStats {
        self.stats.read().await.clone()
    }

    /// Get retention policy information
    pub async fn get_policy_info(&self) -> RetentionPolicyInfo {
        let stats = self.stats.read().await;

        RetentionPolicyInfo {
            transaction_retention_days: self.config.transaction_retention_days,
            proof_retention_days: self.config.proof_retention_days,
            activity_log_retention_days: self.config.activity_log_retention_days,
            metrics_retention_days: self.config.metrics_retention_days,
            cleanup_interval_hours: self.config.cleanup_interval_hours,
            auto_cleanup_enabled: self.config.auto_cleanup_enabled,
            total_cleanups: stats.total_cleanups,
            total_deleted: stats.total_deleted,
            last_cleanup: stats.last_cleanup,
            last_cleanup_duration: stats.last_cleanup_duration,
        }
    }

    /// Update retention configuration
    pub async fn update_config(&mut self, new_config: RetentionConfig) {
        info!("Updating retention configuration");
        self.config = new_config;
    }

    /// Get estimated records to be deleted in next cleanup
    pub async fn estimate_cleanup_size(&self) -> Result<EstimatedCleanup, sqlx::Error> {
        let tx_cutoff = Utc::now() - Duration::days(self.config.transaction_retention_days);
        let proof_cutoff = Utc::now() - Duration::days(self.config.proof_retention_days);
        let activity_cutoff = Utc::now() - Duration::days(self.config.activity_log_retention_days);
        let metrics_cutoff = Utc::now() - Duration::days(self.config.metrics_retention_days);

        let transactions =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE created_at < $1")
                .bind(tx_cutoff)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0) as u64;

        let proofs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bandwidth_proofs WHERE created_at < $1",
        )
        .bind(proof_cutoff)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0) as u64;

        let activity_logs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM activity_logs WHERE created_at < $1",
        )
        .bind(activity_cutoff)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0) as u64;

        let metrics =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM metrics WHERE created_at < $1")
                .bind(metrics_cutoff)
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None)
                .unwrap_or(0) as u64;

        Ok(EstimatedCleanup {
            transactions,
            proofs,
            activity_logs,
            metrics,
            total: transactions + proofs + activity_logs + metrics,
        })
    }
}

/// Information about retention policies
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionPolicyInfo {
    pub transaction_retention_days: i64,
    pub proof_retention_days: i64,
    pub activity_log_retention_days: i64,
    pub metrics_retention_days: i64,
    pub cleanup_interval_hours: u64,
    pub auto_cleanup_enabled: bool,
    pub total_cleanups: u64,
    pub total_deleted: u64,
    pub last_cleanup: Option<DateTime<Utc>>,
    pub last_cleanup_duration: Option<f64>,
}

/// Estimated cleanup size
#[derive(Debug, Clone, serde::Serialize)]
pub struct EstimatedCleanup {
    pub transactions: u64,
    pub proofs: u64,
    pub activity_logs: u64,
    pub metrics: u64,
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_config_defaults() {
        let config = RetentionConfig::default();
        assert_eq!(config.transaction_retention_days, 90);
        assert_eq!(config.proof_retention_days, 30);
        assert_eq!(config.activity_log_retention_days, 180);
        assert_eq!(config.metrics_retention_days, 365);
        assert_eq!(config.cleanup_interval_hours, 24);
        assert!(config.auto_cleanup_enabled);
        assert_eq!(config.deletion_batch_size, 1000);
    }

    #[test]
    fn test_retention_stats_default() {
        let stats = RetentionStats::default();
        assert_eq!(stats.total_cleanups, 0);
        assert_eq!(stats.total_deleted, 0);
        assert_eq!(stats.errors, 0);
        assert!(stats.last_cleanup.is_none());
        assert!(stats.last_cleanup_duration.is_none());
    }
}
