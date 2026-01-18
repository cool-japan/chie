//! Advanced Analytics System
//!
//! Provides real-time dashboard metrics, content performance analytics,
//! node leaderboards, time-series data, and custom query capabilities.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

// ============================================================================
// Types and Enums
// ============================================================================

/// Time range for analytics queries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeRange {
    /// Last hour
    Hour,
    /// Last 24 hours
    Day,
    /// Last 7 days
    Week,
    /// Last 30 days
    Month,
    /// Last 90 days
    Quarter,
    /// Last 365 days
    Year,
    /// All time
    AllTime,
}

impl TimeRange {
    /// Get the duration in seconds for this time range
    pub fn duration_secs(&self) -> Option<i64> {
        match self {
            Self::Hour => Some(3600),
            Self::Day => Some(86400),
            Self::Week => Some(604800),
            Self::Month => Some(2592000),
            Self::Quarter => Some(7776000),
            Self::Year => Some(31536000),
            Self::AllTime => None,
        }
    }
}

/// Metric aggregation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregationType {
    /// Sum of values
    Sum,
    /// Average of values
    Average,
    /// Minimum value
    Min,
    /// Maximum value
    Max,
    /// Count of records
    Count,
}

/// Sort order for leaderboards
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    /// Ascending order
    Asc,
    /// Descending order
    Desc,
}

// ============================================================================
// Data Models
// ============================================================================

/// Real-time dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    /// Total number of users
    pub total_users: i64,
    /// Active users in the last 24 hours
    pub active_users_24h: i64,
    /// Total number of nodes
    pub total_nodes: i64,
    /// Active nodes currently online
    pub active_nodes: i64,
    /// Total content items
    pub total_content: i64,
    /// Total bandwidth served (bytes)
    pub total_bandwidth_bytes: i64,
    /// Bandwidth in the last 24 hours (bytes)
    pub bandwidth_24h_bytes: i64,
    /// Total points distributed
    pub total_points_distributed: i64,
    /// Points distributed in the last 24 hours
    pub points_24h: i64,
    /// Total revenue (cents)
    pub total_revenue_cents: i64,
    /// Revenue in the last 24 hours (cents)
    pub revenue_24h_cents: i64,
    /// Average response time (milliseconds)
    pub avg_response_time_ms: f64,
    /// Success rate percentage (0-100)
    pub success_rate_percent: f64,
}

/// Content performance analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPerformance {
    /// Content ID
    pub content_id: Uuid,
    /// Content hash
    pub content_hash: String,
    /// Total views
    pub total_views: i64,
    /// Total downloads
    pub total_downloads: i64,
    /// Total streams
    pub total_streams: i64,
    /// Total bandwidth served (bytes)
    pub total_bandwidth_bytes: i64,
    /// Total points earned
    pub total_points_earned: i64,
    /// Total revenue generated (cents)
    pub total_revenue_cents: i64,
    /// Average quality score (0-1)
    pub avg_quality_score: f64,
    /// Number of unique providers
    pub unique_providers: i64,
    /// Last accessed timestamp
    pub last_accessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Node performance metrics for leaderboards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePerformance {
    /// Node peer ID
    pub peer_id: String,
    /// Total bandwidth served (bytes)
    pub total_bandwidth_bytes: i64,
    /// Total successful transfers
    pub total_successful_transfers: i64,
    /// Total failed transfers
    pub total_failed_transfers: i64,
    /// Success rate percentage (0-100)
    pub success_rate_percent: f64,
    /// Total points earned
    pub total_points_earned: i64,
    /// Average transfer speed (bytes/sec)
    pub avg_transfer_speed_bps: f64,
    /// Average latency (milliseconds)
    pub avg_latency_ms: f64,
    /// Reputation score (0-1000)
    pub reputation_score: i32,
    /// Uptime percentage (0-100)
    pub uptime_percent: f64,
    /// Rank position
    pub rank: i64,
}

/// Time-series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Metric name
    pub metric_name: String,
    /// Metric value
    pub value: f64,
    /// Optional labels/tags
    pub labels: HashMap<String, String>,
}

/// Analytics query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsQuery {
    /// Metric name to query
    pub metric: String,
    /// Time range
    pub time_range: TimeRange,
    /// Aggregation type
    pub aggregation: AggregationType,
    /// Optional filters
    pub filters: HashMap<String, String>,
    /// Group by fields
    pub group_by: Vec<String>,
}

/// Analytics query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsResult {
    /// Query that was executed
    pub query: AnalyticsQuery,
    /// Result data points
    pub data: Vec<HashMap<String, serde_json::Value>>,
    /// Total number of data points
    pub total_count: usize,
    /// Query execution time (milliseconds)
    pub execution_time_ms: u64,
}

// ============================================================================
// Configuration
// ============================================================================

/// Analytics system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    /// Time-series data retention period in days
    pub timeseries_retention_days: i64,
    /// Maximum results per query
    pub max_query_results: i64,
    /// Enable real-time aggregation
    pub enable_realtime_aggregation: bool,
    /// Cache TTL for dashboard metrics (seconds)
    pub dashboard_cache_ttl_secs: u64,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            timeseries_retention_days: 90, // 90 days retention
            max_query_results: 10000,
            enable_realtime_aggregation: true,
            dashboard_cache_ttl_secs: 60, // 1 minute cache
        }
    }
}

// ============================================================================
// Analytics Manager
// ============================================================================

/// Analytics manager handles all analytics operations
pub struct AnalyticsManager {
    db: PgPool,
    config: Arc<RwLock<AnalyticsConfig>>,
    #[allow(clippy::type_complexity)]
    dashboard_cache: Arc<RwLock<Option<(DashboardMetrics, chrono::DateTime<chrono::Utc>)>>>,
}

impl AnalyticsManager {
    /// Create a new analytics manager
    pub fn new(db: PgPool, config: AnalyticsConfig) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
            dashboard_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Get current configuration
    pub async fn config(&self) -> AnalyticsConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, config: AnalyticsConfig) -> Result<()> {
        *self.config.write().await = config;
        info!("Analytics configuration updated");
        Ok(())
    }

    // ========================================================================
    // Dashboard Metrics
    // ========================================================================

    /// Get real-time dashboard metrics with caching
    pub async fn get_dashboard_metrics(&self) -> Result<DashboardMetrics> {
        let config = self.config.read().await;
        let cache_ttl_secs = config.dashboard_cache_ttl_secs;
        drop(config);

        // Check cache
        {
            let cache = self.dashboard_cache.read().await;
            if let Some((metrics, cached_at)) = cache.as_ref() {
                let age_secs = (chrono::Utc::now() - *cached_at).num_seconds();
                if age_secs < cache_ttl_secs as i64 {
                    debug!("Returning cached dashboard metrics (age: {}s)", age_secs);
                    return Ok(metrics.clone());
                }
            }
        }

        // Fetch fresh metrics
        let metrics = self.fetch_dashboard_metrics().await?;

        // Update cache
        {
            let mut cache = self.dashboard_cache.write().await;
            *cache = Some((metrics.clone(), chrono::Utc::now()));
        }

        info!("Dashboard metrics refreshed");
        crate::metrics::record_analytics_query_executed("dashboard");

        Ok(metrics)
    }

    /// Fetch dashboard metrics from database
    async fn fetch_dashboard_metrics(&self) -> Result<DashboardMetrics> {
        // Total users
        let total_users_result = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.db)
            .await?;
        let total_users: i64 = total_users_result.get("count");

        // Active users in last 24 hours (based on bandwidth_proofs activity via nodes)
        let active_users_result = sqlx::query(
            "SELECT COUNT(DISTINCT n.user_id) as count FROM bandwidth_proofs bp
             JOIN nodes n ON bp.provider_node_id = n.id OR bp.requester_node_id = n.id
             WHERE bp.created_at > NOW() - INTERVAL '24 hours'",
        )
        .fetch_one(&self.db)
        .await?;
        let active_users_24h: i64 = active_users_result.get("count");

        // Total and active nodes
        let total_nodes_result = sqlx::query("SELECT COUNT(*) as count FROM nodes")
            .fetch_one(&self.db)
            .await?;
        let total_nodes: i64 = total_nodes_result.get("count");

        let active_nodes_result = sqlx::query(
            "SELECT COUNT(*) as count FROM nodes WHERE last_seen_at > NOW() - INTERVAL '5 minutes'",
        )
        .fetch_one(&self.db)
        .await?;
        let active_nodes: i64 = active_nodes_result.get("count");

        // Total content
        let total_content_result = sqlx::query("SELECT COUNT(*) as count FROM content")
            .fetch_one(&self.db)
            .await?;
        let total_content: i64 = total_content_result.get("count");

        // Total bandwidth
        let total_bandwidth_result = sqlx::query(
            "SELECT COALESCE(SUM(bytes_transferred), 0)::BIGINT as total FROM bandwidth_proofs WHERE status = 'VERIFIED'"
        )
        .fetch_one(&self.db)
        .await?;
        let total_bandwidth_bytes: i64 = total_bandwidth_result.get("total");

        // Bandwidth in last 24 hours
        let bandwidth_24h_result = sqlx::query(
            "SELECT COALESCE(SUM(bytes_transferred), 0)::BIGINT as total FROM bandwidth_proofs
             WHERE status = 'VERIFIED' AND created_at > NOW() - INTERVAL '24 hours'",
        )
        .fetch_one(&self.db)
        .await?;
        let bandwidth_24h_bytes: i64 = bandwidth_24h_result.get("total");

        // Total points distributed
        let total_points_result = sqlx::query(
            "SELECT COALESCE(SUM(reward_amount), 0)::BIGINT as total FROM bandwidth_proofs WHERE status = 'REWARDED'"
        )
        .fetch_one(&self.db)
        .await?;
        let total_points_distributed: i64 = total_points_result.get("total");

        // Points in last 24 hours
        let points_24h_result = sqlx::query(
            "SELECT COALESCE(SUM(reward_amount), 0)::BIGINT as total FROM bandwidth_proofs
             WHERE status = 'REWARDED' AND created_at > NOW() - INTERVAL '24 hours'",
        )
        .fetch_one(&self.db)
        .await?;
        let points_24h: i64 = points_24h_result.get("total");

        // Calculate average response time and success rate
        let perf_result = sqlx::query(
            r#"
            SELECT
                AVG(latency_ms) as avg_latency,
                COUNT(*) FILTER (WHERE status = 'VERIFIED') as successful,
                COUNT(*) as total
            FROM bandwidth_proofs
            WHERE created_at > NOW() - INTERVAL '24 hours'
            "#,
        )
        .fetch_one(&self.db)
        .await?;

        let avg_response_time_ms: f64 = perf_result
            .get::<Option<f64>, _>("avg_latency")
            .unwrap_or(0.0);
        let successful: i64 = perf_result.get("successful");
        let total: i64 = perf_result.get("total");
        let success_rate_percent = if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        // Revenue metrics (placeholder - would integrate with payment system)
        let total_revenue_cents = 0;
        let revenue_24h_cents = 0;

        Ok(DashboardMetrics {
            total_users,
            active_users_24h,
            total_nodes,
            active_nodes,
            total_content,
            total_bandwidth_bytes,
            bandwidth_24h_bytes,
            total_points_distributed,
            points_24h,
            total_revenue_cents,
            revenue_24h_cents,
            avg_response_time_ms,
            success_rate_percent,
        })
    }

    // ========================================================================
    // Content Performance Analytics
    // ========================================================================

    /// Get content performance analytics
    pub async fn get_content_performance(
        &self,
        content_id: Option<Uuid>,
        time_range: TimeRange,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ContentPerformance>> {
        let time_filter = if let Some(duration_secs) = time_range.duration_secs() {
            format!(
                "AND bp.created_at > NOW() - INTERVAL '{} seconds'",
                duration_secs
            )
        } else {
            String::new()
        };

        let content_filter = if let Some(id) = content_id {
            format!("AND c.id = '{}'", id)
        } else {
            String::new()
        };

        let query = format!(
            r#"
            SELECT
                c.id as content_id,
                c.content_hash,
                COUNT(*) FILTER (WHERE pa.event_type = 'view') as total_views,
                COUNT(*) FILTER (WHERE pa.event_type = 'download') as total_downloads,
                COUNT(*) FILTER (WHERE pa.event_type = 'stream') as total_streams,
                COALESCE(SUM(bp.chunk_size), 0) as total_bandwidth_bytes,
                COALESCE(SUM(bp.points_earned), 0) as total_points_earned,
                0 as total_revenue_cents,
                AVG(bp.quality_score) as avg_quality_score,
                COUNT(DISTINCT bp.provider_peer_id) as unique_providers,
                MAX(bp.created_at) as last_accessed_at
            FROM content c
            LEFT JOIN bandwidth_proofs bp ON c.content_hash = bp.content_hash {}
            LEFT JOIN popularity_accesses pa ON c.id = pa.content_id
            WHERE 1=1 {}
            GROUP BY c.id, c.content_hash
            ORDER BY total_bandwidth_bytes DESC
            LIMIT {} OFFSET {}
            "#,
            time_filter, content_filter, limit, offset
        );

        let results = sqlx::query_as::<_, ContentPerformanceRow>(&query)
            .fetch_all(&self.db)
            .await
            .context("Failed to fetch content performance")?;

        let performances: Vec<ContentPerformance> = results
            .into_iter()
            .map(|row| ContentPerformance {
                content_id: row.content_id,
                content_hash: row.content_hash,
                total_views: row.total_views.unwrap_or(0),
                total_downloads: row.total_downloads.unwrap_or(0),
                total_streams: row.total_streams.unwrap_or(0),
                total_bandwidth_bytes: row.total_bandwidth_bytes.unwrap_or(0),
                total_points_earned: row.total_points_earned.unwrap_or(0),
                total_revenue_cents: row.total_revenue_cents.unwrap_or(0),
                avg_quality_score: row.avg_quality_score.unwrap_or(0.0),
                unique_providers: row.unique_providers.unwrap_or(0),
                last_accessed_at: row.last_accessed_at,
            })
            .collect();

        crate::metrics::record_analytics_query_executed("content_performance");

        Ok(performances)
    }

    // ========================================================================
    // Node Performance Leaderboards
    // ========================================================================

    /// Get node performance leaderboard
    pub async fn get_node_leaderboard(
        &self,
        time_range: TimeRange,
        sort_by: &str,
        sort_order: SortOrder,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NodePerformance>> {
        let time_filter = if let Some(duration_secs) = time_range.duration_secs() {
            format!(
                "AND bp.created_at > NOW() - INTERVAL '{} seconds'",
                duration_secs
            )
        } else {
            String::new()
        };

        let order_direction = match sort_order {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        };

        let sort_column = match sort_by {
            "bandwidth" => "total_bandwidth_bytes",
            "transfers" => "total_successful_transfers",
            "success_rate" => "success_rate_percent",
            "points" => "total_points_earned",
            "speed" => "avg_transfer_speed_bps",
            "latency" => "avg_latency_ms",
            "reputation" => "reputation_score",
            "uptime" => "uptime_percent",
            _ => "total_bandwidth_bytes",
        };

        let query = format!(
            r#"
            WITH node_stats AS (
                SELECT
                    n.peer_id,
                    COALESCE(SUM(bp.chunk_size), 0) as total_bandwidth_bytes,
                    COUNT(*) FILTER (WHERE bp.verified = true) as total_successful_transfers,
                    COUNT(*) FILTER (WHERE bp.verified = false) as total_failed_transfers,
                    CASE
                        WHEN COUNT(*) > 0 THEN (COUNT(*) FILTER (WHERE bp.verified = true)::float / COUNT(*)::float * 100.0)
                        ELSE 0.0
                    END as success_rate_percent,
                    COALESCE(SUM(bp.points_earned), 0) as total_points_earned,
                    AVG(bp.chunk_size::float / NULLIF(bp.latency_ms, 0) * 1000.0) as avg_transfer_speed_bps,
                    AVG(bp.latency_ms) as avg_latency_ms,
                    COALESCE(nr.reputation_score, 500) as reputation_score,
                    100.0 as uptime_percent
                FROM nodes n
                LEFT JOIN bandwidth_proofs bp ON n.peer_id = bp.provider_peer_id {}
                LEFT JOIN node_reputation nr ON n.peer_id = nr.peer_id
                GROUP BY n.peer_id, nr.reputation_score
            )
            SELECT
                peer_id,
                total_bandwidth_bytes,
                total_successful_transfers,
                total_failed_transfers,
                success_rate_percent,
                total_points_earned,
                avg_transfer_speed_bps,
                avg_latency_ms,
                reputation_score,
                uptime_percent,
                ROW_NUMBER() OVER (ORDER BY {} {}) as rank
            FROM node_stats
            ORDER BY {} {}
            LIMIT {} OFFSET {}
            "#,
            time_filter, sort_column, order_direction, sort_column, order_direction, limit, offset
        );

        let results = sqlx::query_as::<_, NodePerformanceRow>(&query)
            .fetch_all(&self.db)
            .await
            .context("Failed to fetch node leaderboard")?;

        let performances: Vec<NodePerformance> = results
            .into_iter()
            .map(|row| NodePerformance {
                peer_id: row.peer_id,
                total_bandwidth_bytes: row.total_bandwidth_bytes.unwrap_or(0),
                total_successful_transfers: row.total_successful_transfers.unwrap_or(0),
                total_failed_transfers: row.total_failed_transfers.unwrap_or(0),
                success_rate_percent: row.success_rate_percent.unwrap_or(0.0),
                total_points_earned: row.total_points_earned.unwrap_or(0),
                avg_transfer_speed_bps: row.avg_transfer_speed_bps.unwrap_or(0.0),
                avg_latency_ms: row.avg_latency_ms.unwrap_or(0.0),
                reputation_score: row.reputation_score.unwrap_or(500),
                uptime_percent: row.uptime_percent.unwrap_or(0.0),
                rank: row.rank.unwrap_or(0),
            })
            .collect();

        crate::metrics::record_analytics_query_executed("node_leaderboard");

        Ok(performances)
    }

    // ========================================================================
    // Time-Series Data Management
    // ========================================================================

    /// Cleanup old time-series data based on retention policy
    pub async fn cleanup_old_timeseries(&self) -> Result<u64> {
        let config = self.config.read().await;
        let retention_days = config.timeseries_retention_days;
        drop(config);

        // This would delete old entries from a time_series_data table
        // For now, we'll use a placeholder query
        let result = sqlx::query(
            "DELETE FROM bandwidth_proofs WHERE created_at < NOW() - INTERVAL '1 day' * $1
             AND status != 'VERIFIED'",
        )
        .bind(retention_days)
        .execute(&self.db)
        .await
        .context("Failed to cleanup old time-series data")?;

        let deleted_count = result.rows_affected();
        info!("Cleaned up {} old time-series records", deleted_count);

        crate::metrics::record_timeseries_cleaned(deleted_count);

        Ok(deleted_count)
    }

    // ========================================================================
    // Custom Query Builder
    // ========================================================================

    /// Execute a custom analytics query
    pub async fn execute_custom_query(&self, query: AnalyticsQuery) -> Result<AnalyticsResult> {
        let start_time = std::time::Instant::now();

        // Validate and build the query
        // This is a simplified implementation - a real query builder would be more sophisticated
        let data = match query.metric.as_str() {
            "bandwidth" => self.query_bandwidth_metric(&query).await?,
            "points" => self.query_points_metric(&query).await?,
            "content_views" => self.query_content_views_metric(&query).await?,
            _ => {
                anyhow::bail!("Unsupported metric: {}", query.metric);
            }
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        crate::metrics::record_analytics_query_executed(&query.metric);
        crate::metrics::record_analytics_query_duration(execution_time_ms);

        Ok(AnalyticsResult {
            query: query.clone(),
            total_count: data.len(),
            data,
            execution_time_ms,
        })
    }

    /// Query bandwidth metric
    async fn query_bandwidth_metric(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>> {
        let time_filter = if let Some(duration_secs) = query.time_range.duration_secs() {
            format!(
                "WHERE created_at > NOW() - INTERVAL '{} seconds'",
                duration_secs
            )
        } else {
            String::new()
        };

        let agg_func = match query.aggregation {
            AggregationType::Sum => "SUM",
            AggregationType::Average => "AVG",
            AggregationType::Min => "MIN",
            AggregationType::Max => "MAX",
            AggregationType::Count => "COUNT",
        };

        let sql = format!(
            "SELECT {}(chunk_size) as value FROM bandwidth_proofs {} AND verified = true",
            agg_func, time_filter
        );

        let result = sqlx::query(&sql)
            .fetch_one(&self.db)
            .await
            .context("Failed to execute bandwidth query")?;

        let value: Option<i64> = result.try_get("value").ok();

        let mut row = HashMap::new();
        row.insert("value".to_string(), serde_json::json!(value.unwrap_or(0)));

        Ok(vec![row])
    }

    /// Query points metric
    async fn query_points_metric(
        &self,
        query: &AnalyticsQuery,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>> {
        let time_filter = if let Some(duration_secs) = query.time_range.duration_secs() {
            format!(
                "WHERE created_at > NOW() - INTERVAL '{} seconds'",
                duration_secs
            )
        } else {
            String::new()
        };

        let agg_func = match query.aggregation {
            AggregationType::Sum => "SUM",
            AggregationType::Average => "AVG",
            AggregationType::Min => "MIN",
            AggregationType::Max => "MAX",
            AggregationType::Count => "COUNT",
        };

        let sql = format!(
            "SELECT {}(points_earned) as value FROM bandwidth_proofs {} AND verified = true",
            agg_func, time_filter
        );

        let result = sqlx::query(&sql)
            .fetch_one(&self.db)
            .await
            .context("Failed to execute points query")?;

        let value: Option<i64> = result.try_get("value").ok();

        let mut row = HashMap::new();
        row.insert("value".to_string(), serde_json::json!(value.unwrap_or(0)));

        Ok(vec![row])
    }

    /// Query content views metric
    async fn query_content_views_metric(
        &self,
        _query: &AnalyticsQuery,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>> {
        // Placeholder implementation
        let mut row = HashMap::new();
        row.insert("value".to_string(), serde_json::json!(0));
        Ok(vec![row])
    }
}

// ============================================================================
// Helper Structures for SQLx
// ============================================================================

#[derive(sqlx::FromRow)]
struct ContentPerformanceRow {
    content_id: Uuid,
    content_hash: String,
    total_views: Option<i64>,
    total_downloads: Option<i64>,
    total_streams: Option<i64>,
    total_bandwidth_bytes: Option<i64>,
    total_points_earned: Option<i64>,
    total_revenue_cents: Option<i64>,
    avg_quality_score: Option<f64>,
    unique_providers: Option<i64>,
    last_accessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(sqlx::FromRow)]
struct NodePerformanceRow {
    peer_id: String,
    total_bandwidth_bytes: Option<i64>,
    total_successful_transfers: Option<i64>,
    total_failed_transfers: Option<i64>,
    success_rate_percent: Option<f64>,
    total_points_earned: Option<i64>,
    avg_transfer_speed_bps: Option<f64>,
    avg_latency_ms: Option<f64>,
    reputation_score: Option<i32>,
    uptime_percent: Option<f64>,
    rank: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range_duration() {
        assert_eq!(TimeRange::Hour.duration_secs(), Some(3600));
        assert_eq!(TimeRange::Day.duration_secs(), Some(86400));
        assert_eq!(TimeRange::Week.duration_secs(), Some(604800));
        assert_eq!(TimeRange::AllTime.duration_secs(), None);
    }

    #[test]
    fn test_analytics_config_default() {
        let config = AnalyticsConfig::default();
        assert_eq!(config.timeseries_retention_days, 90);
        assert_eq!(config.max_query_results, 10000);
        assert!(config.enable_realtime_aggregation);
        assert_eq!(config.dashboard_cache_ttl_secs, 60);
    }

    #[test]
    fn test_aggregation_type() {
        let agg = AggregationType::Sum;
        assert_eq!(agg, AggregationType::Sum);
    }

    #[test]
    fn test_sort_order() {
        let order = SortOrder::Desc;
        assert_eq!(order, SortOrder::Desc);
    }
}
