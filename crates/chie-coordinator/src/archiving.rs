use chrono::{DateTime, Duration, Utc};
use metrics::{counter, histogram};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Configuration for data archiving
#[derive(Debug, Clone)]
pub struct ArchivingConfig {
    /// Archive transactions older than this many days
    pub archive_age_days: i64,
    /// How often to run archiving (hours)
    pub archive_interval_hours: u64,
    /// Enable automatic archiving on schedule
    pub auto_archive_enabled: bool,
    /// Batch size for archiving operations
    pub archive_batch_size: i64,
    /// Compress archived data
    pub compression_enabled: bool,
}

impl Default for ArchivingConfig {
    fn default() -> Self {
        Self {
            archive_age_days: 30,       // Archive after 30 days
            archive_interval_hours: 24, // Daily
            auto_archive_enabled: true,
            archive_batch_size: 1000,
            compression_enabled: true,
        }
    }
}

/// Statistics about archiving operations
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ArchivingStats {
    /// Total number of archiving runs
    pub total_archives: u64,
    /// Total records archived
    pub total_archived: u64,
    /// Last archive timestamp
    pub last_archive: Option<DateTime<Utc>>,
    /// Last archive duration (seconds)
    pub last_archive_duration: Option<f64>,
    /// Number of errors encountered
    pub errors: u64,
}

/// Data archiving manager
pub struct ArchivingManager {
    config: ArchivingConfig,
    pool: PgPool,
    stats: Arc<RwLock<ArchivingStats>>,
}

impl ArchivingManager {
    /// Create a new archiving manager
    pub fn new(config: ArchivingConfig, pool: PgPool) -> Self {
        Self {
            config,
            pool,
            stats: Arc::new(RwLock::new(ArchivingStats::default())),
        }
    }

    /// Start automatic archiving task
    pub fn start_auto_archive(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval_hours = self.config.archive_interval_hours;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_hours * 3600));

            loop {
                interval.tick().await;

                if self.config.auto_archive_enabled {
                    info!("Starting scheduled archiving");
                    if let Err(e) = self.run_archive().await {
                        error!("Archiving failed: {}", e);
                        let mut stats = self.stats.write().await;
                        stats.errors += 1;
                        counter!("archiving_errors_total").increment(1);
                    }
                } else {
                    warn!("Auto archiving is disabled, skipping");
                }
            }
        })
    }

    /// Run archiving manually
    pub async fn run_archive(&self) -> Result<u64, sqlx::Error> {
        let start = std::time::Instant::now();
        let mut total_archived = 0u64;

        info!("Starting data archiving");

        // Archive old transactions
        let archived = self.archive_old_transactions().await?;
        total_archived += archived;
        info!("Archived {} old transactions", archived);

        // Archive old bandwidth proofs
        let archived = self.archive_old_proofs().await?;
        total_archived += archived;
        info!("Archived {} old bandwidth proofs", archived);

        let duration = start.elapsed().as_secs_f64();

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_archives += 1;
        stats.total_archived += total_archived;
        stats.last_archive = Some(Utc::now());
        stats.last_archive_duration = Some(duration);

        // Record metrics
        counter!("archiving_total").increment(1);
        counter!("archiving_records_archived_total").increment(total_archived);
        histogram!("archiving_duration_seconds").record(duration);

        info!(
            "Archiving completed: {} records archived in {:.2}s",
            total_archived, duration
        );

        Ok(total_archived)
    }

    /// Archive old transactions
    async fn archive_old_transactions(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.archive_age_days);
        let batch_size = self.config.archive_batch_size;

        // Create archive table if it doesn't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS transactions_archive (
                LIKE transactions INCLUDING ALL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Move old transactions to archive
        let result = sqlx::query(
            r#"
            WITH moved AS (
                INSERT INTO transactions_archive
                SELECT * FROM transactions
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM transactions
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            ),
            deleted AS (
                DELETE FROM transactions
                WHERE id IN (SELECT id FROM moved)
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
        counter!("archiving_transactions_archived_total").increment(count);
        Ok(count)
    }

    /// Archive old bandwidth proofs
    async fn archive_old_proofs(&self) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.archive_age_days);
        let batch_size = self.config.archive_batch_size;

        // Create archive table if it doesn't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS bandwidth_proofs_archive (
                LIKE bandwidth_proofs INCLUDING ALL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Move old proofs to archive
        let result = sqlx::query(
            r#"
            WITH moved AS (
                INSERT INTO bandwidth_proofs_archive
                SELECT * FROM bandwidth_proofs
                WHERE created_at < $1
                AND id IN (
                    SELECT id FROM bandwidth_proofs
                    WHERE created_at < $1
                    LIMIT $2
                )
                RETURNING id
            ),
            deleted AS (
                DELETE FROM bandwidth_proofs
                WHERE id IN (SELECT id FROM moved)
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
        counter!("archiving_proofs_archived_total").increment(count);
        Ok(count)
    }

    /// Get current archiving statistics
    pub async fn get_stats(&self) -> ArchivingStats {
        self.stats.read().await.clone()
    }

    /// Get archiving policy information
    pub async fn get_policy_info(&self) -> ArchivingPolicyInfo {
        let stats = self.stats.read().await;

        ArchivingPolicyInfo {
            archive_age_days: self.config.archive_age_days,
            archive_interval_hours: self.config.archive_interval_hours,
            auto_archive_enabled: self.config.auto_archive_enabled,
            compression_enabled: self.config.compression_enabled,
            total_archives: stats.total_archives,
            total_archived: stats.total_archived,
            last_archive: stats.last_archive,
            last_archive_duration: stats.last_archive_duration,
        }
    }

    /// Update archiving configuration
    pub async fn update_config(&mut self, new_config: ArchivingConfig) {
        info!("Updating archiving configuration");
        self.config = new_config;
    }

    /// Get estimated records to be archived in next run
    pub async fn estimate_archive_size(&self) -> Result<EstimatedArchive, sqlx::Error> {
        let cutoff = Utc::now() - Duration::days(self.config.archive_age_days);

        let transactions =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions WHERE created_at < $1")
                .bind(cutoff)
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0) as u64;

        let proofs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bandwidth_proofs WHERE created_at < $1",
        )
        .bind(cutoff)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0) as u64;

        Ok(EstimatedArchive {
            transactions,
            proofs,
            total: transactions + proofs,
        })
    }

    /// Restore archived data for a specific time range
    pub async fn restore_from_archive(
        &self,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let mut total_restored = 0u64;

        // Restore transactions
        let result = sqlx::query(
            r#"
            WITH moved AS (
                INSERT INTO transactions
                SELECT * FROM transactions_archive
                WHERE created_at >= $1 AND created_at <= $2
                ON CONFLICT (id) DO NOTHING
                RETURNING id
            ),
            deleted AS (
                DELETE FROM transactions_archive
                WHERE id IN (SELECT id FROM moved)
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = result.try_get("count").unwrap_or(0);
        let count = count as u64;
        total_restored += count;
        info!("Restored {} transactions from archive", count);

        // Restore proofs
        let result = sqlx::query(
            r#"
            WITH moved AS (
                INSERT INTO bandwidth_proofs
                SELECT * FROM bandwidth_proofs_archive
                WHERE created_at >= $1 AND created_at <= $2
                ON CONFLICT (id) DO NOTHING
                RETURNING id
            ),
            deleted AS (
                DELETE FROM bandwidth_proofs_archive
                WHERE id IN (SELECT id FROM moved)
                RETURNING id
            )
            SELECT COUNT(*) as count FROM deleted
            "#,
        )
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = result.try_get("count").unwrap_or(0);
        let count = count as u64;
        total_restored += count;
        info!("Restored {} proofs from archive", count);

        counter!("archiving_records_restored_total").increment(total_restored);
        Ok(total_restored)
    }

    /// Get archive storage statistics
    pub async fn get_archive_storage_stats(&self) -> Result<ArchiveStorageStats, sqlx::Error> {
        let tx_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM transactions_archive")
            .fetch_optional(&self.pool)
            .await
            .unwrap_or(None)
            .unwrap_or(0) as u64;

        let proof_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bandwidth_proofs_archive")
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None)
                .unwrap_or(0) as u64;

        Ok(ArchiveStorageStats {
            archived_transactions: tx_count,
            archived_proofs: proof_count,
            total_archived: tx_count + proof_count,
        })
    }
}

/// Information about archiving policies
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchivingPolicyInfo {
    pub archive_age_days: i64,
    pub archive_interval_hours: u64,
    pub auto_archive_enabled: bool,
    pub compression_enabled: bool,
    pub total_archives: u64,
    pub total_archived: u64,
    pub last_archive: Option<DateTime<Utc>>,
    pub last_archive_duration: Option<f64>,
}

/// Estimated archive size
#[derive(Debug, Clone, serde::Serialize)]
pub struct EstimatedArchive {
    pub transactions: u64,
    pub proofs: u64,
    pub total: u64,
}

/// Archive storage statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchiveStorageStats {
    pub archived_transactions: u64,
    pub archived_proofs: u64,
    pub total_archived: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archiving_config_defaults() {
        let config = ArchivingConfig::default();
        assert_eq!(config.archive_age_days, 30);
        assert_eq!(config.archive_interval_hours, 24);
        assert!(config.auto_archive_enabled);
        assert_eq!(config.archive_batch_size, 1000);
        assert!(config.compression_enabled);
    }

    #[test]
    fn test_archiving_stats_default() {
        let stats = ArchivingStats::default();
        assert_eq!(stats.total_archives, 0);
        assert_eq!(stats.total_archived, 0);
        assert_eq!(stats.errors, 0);
        assert!(stats.last_archive.is_none());
        assert!(stats.last_archive_duration.is_none());
    }
}
