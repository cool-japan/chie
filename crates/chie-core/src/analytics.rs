//! Local analytics for CHIE node dashboard.
//!
//! This module provides comprehensive analytics data for the desktop client:
//! - Storage metrics (used/free space, chunk counts)
//! - Transfer statistics (bandwidth, history)
//! - Earning analytics (rewards, content performance)
//! - Content metrics (popularity, access patterns)
//! - Performance data (latency, uptime)
//!
//! # Examples
//!
//! ```no_run
//! use chie_core::analytics::{AnalyticsCollector, AnalyticsConfig};
//! use chie_core::ChunkStorage;
//! use std::sync::{Arc, RwLock};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = Arc::new(RwLock::new(
//!     ChunkStorage::new(PathBuf::from("/tmp/test"), 1024 * 1024).await?
//! ));
//! let config = AnalyticsConfig::default();
//! let collector = AnalyticsCollector::new(storage, config);
//!
//! // Record upload
//! collector.record_upload(1024 * 1024, true);
//!
//! // Record earnings (amount in u64)
//! collector.record_earning(100, Some("QmContent123"));
//!
//! // Get analytics snapshots
//! let transfer_analytics = collector.transfer_analytics();
//! let earning_analytics = collector.earning_analytics();
//!
//! println!("Total uploaded: {} bytes", transfer_analytics.total_uploaded);
//! println!("Total earned: {} points", earning_analytics.total_earned);
//! # Ok(())
//! # }
//! ```

use crate::storage::ChunkStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Storage analytics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageAnalytics {
    /// Total storage capacity (bytes).
    pub total_capacity: u64,
    /// Used storage (bytes).
    pub used_storage: u64,
    /// Free storage (bytes).
    pub free_storage: u64,
    /// Storage utilization percentage.
    pub utilization_percent: f64,
    /// Number of stored chunks.
    pub chunk_count: u64,
    /// Number of unique content items.
    pub content_count: u64,
    /// Average chunk size (bytes).
    pub avg_chunk_size: u64,
    /// Largest content item (bytes).
    pub largest_content: u64,
}

/// Transfer analytics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransferAnalytics {
    /// Total bytes uploaded (all time).
    pub total_uploaded: u64,
    /// Total bytes downloaded (all time).
    pub total_downloaded: u64,
    /// Bytes uploaded today.
    pub uploaded_today: u64,
    /// Bytes downloaded today.
    pub downloaded_today: u64,
    /// Bytes uploaded this week.
    pub uploaded_week: u64,
    /// Bytes downloaded this week.
    pub downloaded_week: u64,
    /// Bytes uploaded this month.
    pub uploaded_month: u64,
    /// Bytes downloaded this month.
    pub downloaded_month: u64,
    /// Current upload rate (bytes/sec).
    pub upload_rate: f64,
    /// Current download rate (bytes/sec).
    pub download_rate: f64,
    /// Peak upload rate (bytes/sec).
    pub peak_upload_rate: f64,
    /// Peak download rate (bytes/sec).
    pub peak_download_rate: f64,
    /// Number of successful transfers today.
    pub transfers_today: u64,
    /// Number of failed transfers today.
    pub failed_transfers_today: u64,
}

/// Earning analytics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EarningAnalytics {
    /// Total points earned (all time).
    pub total_earned: u64,
    /// Points earned today.
    pub earned_today: u64,
    /// Points earned this week.
    pub earned_week: u64,
    /// Points earned this month.
    pub earned_month: u64,
    /// Estimated daily earning rate.
    pub daily_rate: f64,
    /// Number of proofs submitted today.
    pub proofs_today: u64,
    /// Number of successful proofs today.
    pub successful_proofs_today: u64,
    /// Average reward per proof.
    pub avg_reward_per_proof: f64,
    /// Best performing content (CID -> earnings).
    pub top_earners: Vec<ContentEarning>,
}

/// Content earning information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentEarning {
    /// Content CID.
    pub cid: String,
    /// Content title (if known).
    pub title: Option<String>,
    /// Total earnings from this content.
    pub total_earned: u64,
    /// Number of transfers.
    pub transfer_count: u64,
}

/// Content analytics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentAnalytics {
    /// Number of pinned content items.
    pub pinned_count: u64,
    /// Number of cached content items.
    pub cached_count: u64,
    /// Most accessed content.
    pub most_accessed: Vec<ContentAccess>,
    /// Recently accessed content.
    pub recent_access: Vec<ContentAccess>,
    /// Content by category.
    pub by_category: HashMap<String, u64>,
}

/// Content access information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAccess {
    /// Content CID.
    pub cid: String,
    /// Content title (if known).
    pub title: Option<String>,
    /// Access count.
    pub access_count: u64,
    /// Last accessed timestamp.
    pub last_accessed: u64,
}

/// Performance analytics data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceAnalytics {
    /// Node uptime (seconds).
    pub uptime_secs: u64,
    /// Uptime percentage (last 7 days).
    pub uptime_percent_7d: f64,
    /// Average latency (ms).
    pub avg_latency_ms: f64,
    /// P50 latency (ms).
    pub p50_latency_ms: f64,
    /// P95 latency (ms).
    pub p95_latency_ms: f64,
    /// P99 latency (ms).
    pub p99_latency_ms: f64,
    /// Connected peers count.
    pub connected_peers: u64,
    /// Active transfers.
    pub active_transfers: u64,
    /// CPU usage percentage.
    pub cpu_usage_percent: f64,
    /// Memory usage (bytes).
    pub memory_usage: u64,
    /// Disk I/O rate (bytes/sec).
    pub disk_io_rate: u64,
}

/// Combined dashboard analytics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardAnalytics {
    /// Storage metrics.
    pub storage: StorageAnalytics,
    /// Transfer metrics.
    pub transfer: TransferAnalytics,
    /// Earning metrics.
    pub earning: EarningAnalytics,
    /// Content metrics.
    pub content: ContentAnalytics,
    /// Performance metrics.
    pub performance: PerformanceAnalytics,
    /// Last updated timestamp.
    pub last_updated: u64,
}

/// Time-series data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Timestamp (Unix millis).
    pub timestamp: u64,
    /// Value.
    pub value: f64,
}

/// Historical data for charts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HistoricalData {
    /// Upload bandwidth (hourly, last 24h).
    pub upload_hourly: Vec<TimeSeriesPoint>,
    /// Download bandwidth (hourly, last 24h).
    pub download_hourly: Vec<TimeSeriesPoint>,
    /// Earnings (daily, last 30 days).
    pub earnings_daily: Vec<TimeSeriesPoint>,
    /// Storage usage (daily, last 30 days).
    pub storage_daily: Vec<TimeSeriesPoint>,
    /// Transfer count (daily, last 30 days).
    pub transfers_daily: Vec<TimeSeriesPoint>,
}

/// Analytics collector for the local node.
pub struct AnalyticsCollector {
    /// Storage reference.
    storage: Arc<RwLock<ChunkStorage>>,
    /// Node start time.
    start_time: Instant,
    /// Transfer records.
    transfers: RwLock<TransferRecords>,
    /// Earning records.
    earnings: RwLock<EarningRecords>,
    /// Latency samples.
    latency_samples: RwLock<Vec<f64>>,
    /// Configuration.
    config: AnalyticsConfig,
}

/// Transfer records for analytics.
#[derive(Debug, Default)]
struct TransferRecords {
    /// Total uploaded bytes.
    total_uploaded: u64,
    /// Total downloaded bytes.
    total_downloaded: u64,
    /// Recent uploads (timestamp -> bytes).
    recent_uploads: Vec<(Instant, u64)>,
    /// Recent downloads (timestamp -> bytes).
    recent_downloads: Vec<(Instant, u64)>,
    /// Transfer history (for charts).
    history: Vec<TransferRecord>,
}

/// Single transfer record.
#[derive(Debug, Clone)]
struct TransferRecord {
    timestamp: u64,
    uploaded: u64,
    downloaded: u64,
    success: bool,
}

/// Earning records for analytics.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct EarningRecords {
    /// Total earned points.
    total_earned: u64,
    /// Proof submissions (timestamp -> reward).
    proofs: Vec<(u64, u64)>,
    /// Earnings by content (CID -> total).
    by_content: HashMap<String, u64>,
    /// Daily earnings history.
    daily_history: Vec<(u64, u64)>,
}

/// Analytics configuration.
#[derive(Debug, Clone)]
pub struct AnalyticsConfig {
    /// Maximum latency samples to keep.
    pub max_latency_samples: usize,
    /// Maximum transfer records to keep.
    pub max_transfer_records: usize,
    /// History retention (days).
    pub history_retention_days: u64,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            max_latency_samples: 1000,
            max_transfer_records: 10000,
            history_retention_days: 30,
        }
    }
}

impl AnalyticsCollector {
    /// Create a new analytics collector.
    #[inline]
    #[must_use]
    pub fn new(storage: Arc<RwLock<ChunkStorage>>, config: AnalyticsConfig) -> Self {
        Self {
            storage,
            start_time: Instant::now(),
            transfers: RwLock::new(TransferRecords::default()),
            earnings: RwLock::new(EarningRecords::default()),
            latency_samples: RwLock::new(Vec::new()),
            config,
        }
    }

    /// Record an upload.
    #[inline]
    pub fn record_upload(&self, bytes: u64, success: bool) {
        let mut transfers = self.transfers.write().unwrap();
        if success {
            transfers.total_uploaded += bytes;
        }
        transfers.recent_uploads.push((Instant::now(), bytes));

        // Cleanup old records
        let cutoff = Instant::now() - Duration::from_secs(86400);
        transfers.recent_uploads.retain(|(t, _)| *t > cutoff);

        // Add to history
        transfers.history.push(TransferRecord {
            timestamp: current_timestamp(),
            uploaded: bytes,
            downloaded: 0,
            success,
        });

        // Limit history size
        if transfers.history.len() > self.config.max_transfer_records {
            transfers.history.remove(0);
        }
    }

    /// Record a download.
    #[inline]
    pub fn record_download(&self, bytes: u64, success: bool) {
        let mut transfers = self.transfers.write().unwrap();
        if success {
            transfers.total_downloaded += bytes;
        }
        transfers.recent_downloads.push((Instant::now(), bytes));

        // Cleanup old records
        let cutoff = Instant::now() - Duration::from_secs(86400);
        transfers.recent_downloads.retain(|(t, _)| *t > cutoff);

        // Add to history
        transfers.history.push(TransferRecord {
            timestamp: current_timestamp(),
            uploaded: 0,
            downloaded: bytes,
            success,
        });

        // Limit history size
        if transfers.history.len() > self.config.max_transfer_records {
            transfers.history.remove(0);
        }
    }

    /// Record earnings from a proof.
    #[inline]
    pub fn record_earning(&self, amount: u64, content_cid: Option<&str>) {
        let mut earnings = self.earnings.write().unwrap();
        earnings.total_earned += amount;
        earnings.proofs.push((current_timestamp(), amount));

        if let Some(cid) = content_cid {
            *earnings.by_content.entry(cid.to_string()).or_insert(0) += amount;
        }
    }

    /// Record latency sample.
    #[inline]
    pub fn record_latency(&self, latency_ms: f64) {
        let mut samples = self.latency_samples.write().unwrap();
        samples.push(latency_ms);

        // Limit samples
        if samples.len() > self.config.max_latency_samples {
            samples.remove(0);
        }
    }

    /// Get storage analytics.
    #[must_use]
    pub fn storage_analytics(&self) -> StorageAnalytics {
        let storage = self.storage.read().unwrap();
        let stats = storage.stats();

        let used = stats.used_bytes;
        let total = stats.max_bytes;
        let free = stats.available_bytes;

        StorageAnalytics {
            total_capacity: total,
            used_storage: used,
            free_storage: free,
            utilization_percent: stats.usage_percent,
            chunk_count: 0, // Would need chunk tracking
            content_count: stats.pinned_content_count as u64,
            avg_chunk_size: 0,
            largest_content: 0,
        }
    }

    /// Get transfer analytics.
    #[must_use]
    pub fn transfer_analytics(&self) -> TransferAnalytics {
        let transfers = self.transfers.read().unwrap();
        let now = Instant::now();
        let day_ago = now - Duration::from_secs(86400);
        let week_ago = now - Duration::from_secs(7 * 86400);
        let month_ago = now - Duration::from_secs(30 * 86400);

        let uploaded_today: u64 = transfers
            .recent_uploads
            .iter()
            .filter(|(t, _)| *t > day_ago)
            .map(|(_, b)| b)
            .sum();

        let downloaded_today: u64 = transfers
            .recent_downloads
            .iter()
            .filter(|(t, _)| *t > day_ago)
            .map(|(_, b)| b)
            .sum();

        // Calculate rates (bytes in last minute)
        let minute_ago = now - Duration::from_secs(60);
        let upload_rate: f64 = transfers
            .recent_uploads
            .iter()
            .filter(|(t, _)| *t > minute_ago)
            .map(|(_, b)| *b as f64)
            .sum::<f64>()
            / 60.0;

        let download_rate: f64 = transfers
            .recent_downloads
            .iter()
            .filter(|(t, _)| *t > minute_ago)
            .map(|(_, b)| *b as f64)
            .sum::<f64>()
            / 60.0;

        TransferAnalytics {
            total_uploaded: transfers.total_uploaded,
            total_downloaded: transfers.total_downloaded,
            uploaded_today,
            downloaded_today,
            uploaded_week: calculate_period_sum(&transfers.recent_uploads, week_ago),
            downloaded_week: calculate_period_sum(&transfers.recent_downloads, week_ago),
            uploaded_month: calculate_period_sum(&transfers.recent_uploads, month_ago),
            downloaded_month: calculate_period_sum(&transfers.recent_downloads, month_ago),
            upload_rate,
            download_rate,
            peak_upload_rate: 0.0, // Would need tracking
            peak_download_rate: 0.0,
            transfers_today: transfers
                .history
                .iter()
                .filter(|r| r.success && is_today(r.timestamp))
                .count() as u64,
            failed_transfers_today: transfers
                .history
                .iter()
                .filter(|r| !r.success && is_today(r.timestamp))
                .count() as u64,
        }
    }

    /// Get earning analytics.
    #[must_use]
    pub fn earning_analytics(&self) -> EarningAnalytics {
        let earnings = self.earnings.read().unwrap();
        let now = current_timestamp();
        let day_start = now - (now % 86400);
        let week_start = now - 7 * 86400;
        let month_start = now - 30 * 86400;

        let earned_today: u64 = earnings
            .proofs
            .iter()
            .filter(|(t, _)| *t >= day_start)
            .map(|(_, a)| a)
            .sum();

        let earned_week: u64 = earnings
            .proofs
            .iter()
            .filter(|(t, _)| *t >= week_start)
            .map(|(_, a)| a)
            .sum();

        let earned_month: u64 = earnings
            .proofs
            .iter()
            .filter(|(t, _)| *t >= month_start)
            .map(|(_, a)| a)
            .sum();

        let proofs_today = earnings
            .proofs
            .iter()
            .filter(|(t, _)| *t >= day_start)
            .count() as u64;

        let avg_reward = if proofs_today > 0 {
            earned_today as f64 / proofs_today as f64
        } else {
            0.0
        };

        // Get top earners
        let mut top_earners: Vec<_> = earnings
            .by_content
            .iter()
            .map(|(cid, total)| ContentEarning {
                cid: cid.clone(),
                title: None,
                total_earned: *total,
                transfer_count: 0,
            })
            .collect();
        top_earners.sort_by(|a, b| b.total_earned.cmp(&a.total_earned));
        top_earners.truncate(10);

        EarningAnalytics {
            total_earned: earnings.total_earned,
            earned_today,
            earned_week,
            earned_month,
            daily_rate: if self.start_time.elapsed().as_secs() > 0 {
                earned_month as f64 / 30.0
            } else {
                0.0
            },
            proofs_today,
            successful_proofs_today: proofs_today,
            avg_reward_per_proof: avg_reward,
            top_earners,
        }
    }

    /// Get performance analytics.
    #[must_use]
    pub fn performance_analytics(&self) -> PerformanceAnalytics {
        let samples = self.latency_samples.read().unwrap();

        let (avg, p50, p95, p99) = if !samples.is_empty() {
            let mut sorted: Vec<f64> = samples.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let avg = sorted.iter().sum::<f64>() / sorted.len() as f64;
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[(sorted.len() * 95) / 100];
            let p99 = sorted[(sorted.len() * 99) / 100];

            (avg, p50, p95, p99)
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };

        PerformanceAnalytics {
            uptime_secs: self.start_time.elapsed().as_secs(),
            uptime_percent_7d: 100.0, // Would need persistent tracking
            avg_latency_ms: avg,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            connected_peers: 0, // Would need P2P integration
            active_transfers: 0,
            cpu_usage_percent: 0.0,
            memory_usage: 0,
            disk_io_rate: 0,
        }
    }

    /// Get full dashboard analytics.
    #[must_use]
    pub fn dashboard_analytics(&self) -> DashboardAnalytics {
        DashboardAnalytics {
            storage: self.storage_analytics(),
            transfer: self.transfer_analytics(),
            earning: self.earning_analytics(),
            content: ContentAnalytics::default(), // Would need content tracking
            performance: self.performance_analytics(),
            last_updated: current_timestamp(),
        }
    }

    /// Get historical data for charts.
    #[must_use]
    pub fn historical_data(&self) -> HistoricalData {
        let transfers = self.transfers.read().unwrap();
        let earnings = self.earnings.read().unwrap();

        // Generate hourly upload/download data
        let now = current_timestamp();
        let mut upload_hourly = Vec::new();
        let mut download_hourly = Vec::new();

        for h in 0..24 {
            let hour_start = now - (now % 3600) - (h * 3600);
            let hour_end = hour_start + 3600;

            let upload: u64 = transfers
                .history
                .iter()
                .filter(|r| r.timestamp >= hour_start && r.timestamp < hour_end)
                .map(|r| r.uploaded)
                .sum();

            let download: u64 = transfers
                .history
                .iter()
                .filter(|r| r.timestamp >= hour_start && r.timestamp < hour_end)
                .map(|r| r.downloaded)
                .sum();

            upload_hourly.push(TimeSeriesPoint {
                timestamp: hour_start * 1000,
                value: upload as f64,
            });
            download_hourly.push(TimeSeriesPoint {
                timestamp: hour_start * 1000,
                value: download as f64,
            });
        }

        // Generate daily earnings data
        let mut earnings_daily = Vec::new();
        for d in 0..30 {
            let day_start = now - (now % 86400) - (d * 86400);
            let day_end = day_start + 86400;

            let earned: u64 = earnings
                .proofs
                .iter()
                .filter(|(t, _)| *t >= day_start && *t < day_end)
                .map(|(_, a)| a)
                .sum();

            earnings_daily.push(TimeSeriesPoint {
                timestamp: day_start * 1000,
                value: earned as f64,
            });
        }

        HistoricalData {
            upload_hourly,
            download_hourly,
            earnings_daily,
            storage_daily: Vec::new(), // Would need persistent storage
            transfers_daily: Vec::new(),
        }
    }
}

/// Calculate sum for a time period.
#[inline]
fn calculate_period_sum(records: &[(Instant, u64)], since: Instant) -> u64 {
    records
        .iter()
        .filter(|(t, _)| *t > since)
        .map(|(_, b)| b)
        .sum()
}

/// Check if timestamp is today.
#[inline]
fn is_today(timestamp: u64) -> bool {
    let now = current_timestamp();
    let day_start = now - (now % 86400);
    timestamp >= day_start
}

/// Get current Unix timestamp.
#[inline]
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_storage_analytics() {
        let tmp = tempdir().unwrap();
        let storage = ChunkStorage::new(tmp.path().to_path_buf(), 1024 * 1024 * 100)
            .await
            .unwrap();
        let collector =
            AnalyticsCollector::new(Arc::new(RwLock::new(storage)), AnalyticsConfig::default());

        let analytics = collector.storage_analytics();
        assert!(analytics.total_capacity > 0);
    }

    #[tokio::test]
    async fn test_transfer_recording() {
        let tmp = tempdir().unwrap();
        let storage = ChunkStorage::new(tmp.path().to_path_buf(), 1024 * 1024 * 100)
            .await
            .unwrap();
        let collector =
            AnalyticsCollector::new(Arc::new(RwLock::new(storage)), AnalyticsConfig::default());

        collector.record_upload(1024, true);
        collector.record_download(2048, true);

        let analytics = collector.transfer_analytics();
        assert_eq!(analytics.total_uploaded, 1024);
        assert_eq!(analytics.total_downloaded, 2048);
    }

    #[tokio::test]
    async fn test_earning_recording() {
        let tmp = tempdir().unwrap();
        let storage = ChunkStorage::new(tmp.path().to_path_buf(), 1024 * 1024 * 100)
            .await
            .unwrap();
        let collector =
            AnalyticsCollector::new(Arc::new(RwLock::new(storage)), AnalyticsConfig::default());

        collector.record_earning(100, Some("QmTest1"));
        collector.record_earning(200, Some("QmTest1"));
        collector.record_earning(50, Some("QmTest2"));

        let analytics = collector.earning_analytics();
        assert_eq!(analytics.total_earned, 350);
    }

    #[tokio::test]
    async fn test_latency_percentiles() {
        let tmp = tempdir().unwrap();
        let storage = ChunkStorage::new(tmp.path().to_path_buf(), 1024 * 1024 * 100)
            .await
            .unwrap();
        let collector =
            AnalyticsCollector::new(Arc::new(RwLock::new(storage)), AnalyticsConfig::default());

        for i in 1..=100 {
            collector.record_latency(i as f64);
        }

        let analytics = collector.performance_analytics();
        assert!(analytics.avg_latency_ms > 0.0);
        assert!(analytics.p50_latency_ms > 0.0);
        assert!(analytics.p95_latency_ms > analytics.p50_latency_ms);
    }
}
