//! Node reputation and trust scoring system for CHIE protocol.
//!
//! This module provides:
//! - Node reliability scoring based on historical performance
//! - Trust metrics (uptime, success rate, bandwidth quality)
//! - Reputation decay over time (encourages consistent performance)
//! - Integration with fraud detection and proof verification
//! - Trust-based peer recommendations
//! - Reputation-based incentives

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Reputation event type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationEvent {
    /// Successful proof verification.
    ProofVerified,
    /// Failed proof verification.
    ProofFailed,
    /// Fast transfer (better than average).
    FastTransfer,
    /// Slow transfer (worse than average).
    SlowTransfer,
    /// High quality bandwidth.
    HighQualityBandwidth,
    /// Low quality bandwidth.
    LowQualityBandwidth,
    /// Fraud detected.
    FraudDetected,
    /// Node went offline.
    NodeOffline,
    /// Node came online.
    NodeOnline,
    /// Consistent uptime milestone.
    UptimeMilestone,
}

impl ReputationEvent {
    /// Get the reputation impact of this event (-100 to +100).
    pub fn impact(&self) -> i32 {
        match self {
            Self::ProofVerified => 5,
            Self::ProofFailed => -10,
            Self::FastTransfer => 3,
            Self::SlowTransfer => -2,
            Self::HighQualityBandwidth => 10,
            Self::LowQualityBandwidth => -5,
            Self::FraudDetected => -50,
            Self::NodeOffline => -15,
            Self::NodeOnline => 2,
            Self::UptimeMilestone => 20,
        }
    }

    /// Convert to database string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProofVerified => "proof_verified",
            Self::ProofFailed => "proof_failed",
            Self::FastTransfer => "fast_transfer",
            Self::SlowTransfer => "slow_transfer",
            Self::HighQualityBandwidth => "high_quality_bandwidth",
            Self::LowQualityBandwidth => "low_quality_bandwidth",
            Self::FraudDetected => "fraud_detected",
            Self::NodeOffline => "node_offline",
            Self::NodeOnline => "node_online",
            Self::UptimeMilestone => "uptime_milestone",
        }
    }
}

/// Node reputation score and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReputation {
    /// Node peer ID.
    pub peer_id: String,
    /// Overall reputation score (0-1000).
    pub score: i32,
    /// Trust level based on score.
    pub trust_level: TrustLevel,
    /// Total successful proofs.
    pub successful_proofs: u64,
    /// Total failed proofs.
    pub failed_proofs: u64,
    /// Success rate (0.0-1.0).
    pub success_rate: f64,
    /// Average transfer speed (bytes/sec).
    pub avg_transfer_speed: f64,
    /// Uptime percentage (0.0-1.0).
    pub uptime_percentage: f64,
    /// Total fraud incidents.
    pub fraud_incidents: u32,
    /// Last seen timestamp.
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Reputation calculation timestamp.
    pub calculated_at: chrono::DateTime<chrono::Utc>,
}

/// Trust level based on reputation score.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Untrusted (score < 200).
    Untrusted,
    /// Low trust (score 200-400).
    Low,
    /// Medium trust (score 400-600).
    Medium,
    /// High trust (score 600-800).
    High,
    /// Excellent trust (score >= 800).
    Excellent,
}

impl TrustLevel {
    /// Get trust level from reputation score.
    pub fn from_score(score: i32) -> Self {
        match score {
            s if s < 200 => Self::Untrusted,
            s if s < 400 => Self::Low,
            s if s < 600 => Self::Medium,
            s if s < 800 => Self::High,
            _ => Self::Excellent,
        }
    }

    /// Get minimum score threshold for this trust level.
    pub fn min_score(&self) -> i32 {
        match self {
            Self::Untrusted => 0,
            Self::Low => 200,
            Self::Medium => 400,
            Self::High => 600,
            Self::Excellent => 800,
        }
    }

    /// Convert to database string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Excellent => "excellent",
        }
    }
}

/// Reputation system configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Initial reputation score for new nodes.
    pub initial_score: i32,
    /// Minimum reputation score.
    pub min_score: i32,
    /// Maximum reputation score.
    pub max_score: i32,
    /// Decay rate per day (score reduction for inactivity).
    pub decay_rate_per_day: i32,
    /// Minimum trust level for recommendations.
    pub min_trust_for_recommendations: TrustLevel,
    /// Enable automatic reputation updates.
    pub auto_update_enabled: bool,
    /// Update interval in hours.
    pub update_interval_hours: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_score: 500, // Start at medium trust
            min_score: 0,
            max_score: 1000,
            decay_rate_per_day: 2, // Lose 2 points per day of inactivity
            min_trust_for_recommendations: TrustLevel::Medium,
            auto_update_enabled: true,
            update_interval_hours: 6, // Update every 6 hours
        }
    }
}

/// Reputation statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationStats {
    /// Total nodes tracked.
    pub total_nodes: u64,
    /// Excellent trust nodes.
    pub excellent_nodes: u64,
    /// High trust nodes.
    pub high_nodes: u64,
    /// Medium trust nodes.
    pub medium_nodes: u64,
    /// Low trust nodes.
    pub low_nodes: u64,
    /// Untrusted nodes.
    pub untrusted_nodes: u64,
    /// Average reputation score.
    pub avg_score: f64,
    /// Total reputation events processed.
    pub total_events: u64,
}

/// Node reputation manager.
#[derive(Clone)]
pub struct ReputationManager {
    db: PgPool,
    config: ReputationConfig,
    cache: Arc<RwLock<HashMap<String, NodeReputation>>>,
    stats: Arc<RwLock<ReputationStats>>,
}

impl ReputationManager {
    /// Create a new reputation manager.
    pub fn new(db: PgPool, config: ReputationConfig) -> Self {
        Self {
            db,
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ReputationStats::default())),
        }
    }

    /// Record a reputation event for a node.
    pub async fn record_event(
        &self,
        peer_id: String,
        event: ReputationEvent,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), anyhow::Error> {
        let impact = event.impact();

        // Insert event into database
        sqlx::query(
            r#"
            INSERT INTO reputation_events
                (id, peer_id, event_type, impact, metadata, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&peer_id)
        .bind(event.as_str())
        .bind(impact)
        .bind(metadata)
        .execute(&self.db)
        .await?;

        // Update node reputation score
        self.update_node_score(&peer_id, impact).await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_events += 1;

        debug!(
            "Recorded reputation event: peer_id={}, event={:?}, impact={}",
            peer_id, event, impact
        );

        Ok(())
    }

    /// Update a node's reputation score.
    async fn update_node_score(&self, peer_id: &str, impact: i32) -> Result<(), anyhow::Error> {
        // Get current score or initialize new node
        let current: Option<i32> =
            sqlx::query_scalar("SELECT score FROM node_reputation WHERE peer_id = $1")
                .bind(peer_id)
                .fetch_optional(&self.db)
                .await?;

        let new_score = if let Some(score) = current {
            (score + impact).clamp(self.config.min_score, self.config.max_score)
        } else {
            // New node: initialize with default score + impact
            (self.config.initial_score + impact).clamp(self.config.min_score, self.config.max_score)
        };

        let trust_level = TrustLevel::from_score(new_score);

        // Upsert node reputation
        sqlx::query(
            r#"
            INSERT INTO node_reputation (peer_id, score, trust_level, last_updated)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (peer_id)
            DO UPDATE SET
                score = $2,
                trust_level = $3,
                last_updated = NOW()
            "#,
        )
        .bind(peer_id)
        .bind(new_score)
        .bind(trust_level.as_str())
        .execute(&self.db)
        .await?;

        // Invalidate cache
        let mut cache = self.cache.write().await;
        cache.remove(peer_id);

        Ok(())
    }

    /// Get reputation for a node.
    pub async fn get_reputation(
        &self,
        peer_id: &str,
    ) -> Result<Option<NodeReputation>, anyhow::Error> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(rep) = cache.get(peer_id) {
                return Ok(Some(rep.clone()));
            }
        }

        // Query database
        #[derive(sqlx::FromRow)]
        struct ReputationRow {
            peer_id: String,
            score: i32,
            #[allow(dead_code)]
            trust_level: String,
            last_updated: chrono::NaiveDateTime,
        }

        let row: Option<ReputationRow> = sqlx::query_as(
            r#"
            SELECT peer_id, score, trust_level, last_updated
            FROM node_reputation
            WHERE peer_id = $1
            "#,
        )
        .bind(peer_id)
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = row {
            // Get additional metrics from proofs and events
            let metrics = self.calculate_metrics(peer_id).await?;

            let reputation = NodeReputation {
                peer_id: row.peer_id.clone(),
                score: row.score,
                trust_level: TrustLevel::from_score(row.score),
                successful_proofs: metrics.successful_proofs,
                failed_proofs: metrics.failed_proofs,
                success_rate: metrics.success_rate,
                avg_transfer_speed: metrics.avg_transfer_speed,
                uptime_percentage: metrics.uptime_percentage,
                fraud_incidents: metrics.fraud_incidents,
                last_seen: row.last_updated.and_utc(),
                calculated_at: chrono::Utc::now(),
            };

            // Update cache
            let mut cache = self.cache.write().await;
            cache.insert(row.peer_id, reputation.clone());

            Ok(Some(reputation))
        } else {
            Ok(None)
        }
    }

    /// Calculate detailed metrics for a node.
    async fn calculate_metrics(&self, peer_id: &str) -> Result<NodeMetrics, anyhow::Error> {
        // Count successful and failed proofs
        let proof_stats: (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE verified = true) as successful,
                COUNT(*) FILTER (WHERE verified = false) as failed
            FROM bandwidth_proofs
            WHERE provider_peer_id = $1
            "#,
        )
        .bind(peer_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or((0, 0));

        let successful_proofs = proof_stats.0 as u64;
        let failed_proofs = proof_stats.1 as u64;
        let total_proofs = successful_proofs + failed_proofs;
        let success_rate = if total_proofs > 0 {
            successful_proofs as f64 / total_proofs as f64
        } else {
            0.0
        };

        // Calculate average transfer speed
        let avg_speed: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(bytes_transferred::float / GREATEST(EXTRACT(EPOCH FROM (verified_at - created_at)), 1))
            FROM bandwidth_proofs
            WHERE provider_peer_id = $1 AND verified = true
            "#
        )
        .bind(peer_id)
        .fetch_one(&self.db)
        .await
        .ok();

        // Count fraud incidents
        let fraud_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reputation_events WHERE peer_id = $1 AND event_type = 'fraud_detected'"
        )
        .bind(peer_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        // Calculate uptime (simplified: based on online/offline events)
        let uptime_percentage = self.calculate_uptime(peer_id).await.unwrap_or(1.0);

        Ok(NodeMetrics {
            successful_proofs,
            failed_proofs,
            success_rate,
            avg_transfer_speed: avg_speed.unwrap_or(0.0),
            uptime_percentage,
            fraud_incidents: fraud_count as u32,
        })
    }

    /// Calculate uptime percentage for a node.
    async fn calculate_uptime(&self, peer_id: &str) -> Result<f64, anyhow::Error> {
        let online_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reputation_events WHERE peer_id = $1 AND event_type = 'node_online'"
        )
        .bind(peer_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let offline_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reputation_events WHERE peer_id = $1 AND event_type = 'node_offline'"
        )
        .bind(peer_id)
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let total_events = online_events + offline_events;
        if total_events > 0 {
            Ok(online_events as f64 / total_events as f64)
        } else {
            Ok(1.0) // Assume 100% uptime if no events
        }
    }

    /// Get top nodes by reputation.
    pub async fn get_top_nodes(
        &self,
        limit: usize,
        min_trust: TrustLevel,
    ) -> Result<Vec<NodeReputation>, anyhow::Error> {
        #[derive(sqlx::FromRow)]
        struct ReputationRow {
            peer_id: String,
            score: i32,
            #[allow(dead_code)]
            trust_level: String,
            last_updated: chrono::NaiveDateTime,
        }

        let rows: Vec<ReputationRow> = sqlx::query_as(
            r#"
            SELECT peer_id, score, trust_level, last_updated
            FROM node_reputation
            WHERE score >= $1
            ORDER BY score DESC
            LIMIT $2
            "#,
        )
        .bind(min_trust.min_score())
        .bind(limit as i64)
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        let mut reputations = Vec::new();
        for row in rows {
            let trust = TrustLevel::from_score(row.score);
            if trust >= min_trust {
                let metrics = self.calculate_metrics(&row.peer_id).await?;
                reputations.push(NodeReputation {
                    peer_id: row.peer_id,
                    score: row.score,
                    trust_level: trust,
                    successful_proofs: metrics.successful_proofs,
                    failed_proofs: metrics.failed_proofs,
                    success_rate: metrics.success_rate,
                    avg_transfer_speed: metrics.avg_transfer_speed,
                    uptime_percentage: metrics.uptime_percentage,
                    fraud_incidents: metrics.fraud_incidents,
                    last_seen: row.last_updated.and_utc(),
                    calculated_at: chrono::Utc::now(),
                });
            }
        }

        Ok(reputations)
    }

    /// Apply reputation decay for inactive nodes.
    pub async fn apply_decay(&self) -> Result<u64, anyhow::Error> {
        let decay_threshold = chrono::Utc::now() - chrono::Duration::days(1);

        let affected = sqlx::query(
            r#"
            UPDATE node_reputation
            SET score = GREATEST(score - $1, $2),
                trust_level = CASE
                    WHEN GREATEST(score - $1, $2) < 200 THEN 'untrusted'
                    WHEN GREATEST(score - $1, $2) < 400 THEN 'low'
                    WHEN GREATEST(score - $1, $2) < 600 THEN 'medium'
                    WHEN GREATEST(score - $1, $2) < 800 THEN 'high'
                    ELSE 'excellent'
                END
            WHERE last_updated < $3
            "#,
        )
        .bind(self.config.decay_rate_per_day)
        .bind(self.config.min_score)
        .bind(decay_threshold.naive_utc())
        .execute(&self.db)
        .await?;

        info!(
            "Applied reputation decay to {} nodes",
            affected.rows_affected()
        );

        // Clear cache after decay
        let mut cache = self.cache.write().await;
        cache.clear();

        Ok(affected.rows_affected())
    }

    /// Get reputation statistics.
    pub async fn get_stats(&self) -> Result<ReputationStats, anyhow::Error> {
        let total_nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM node_reputation")
            .fetch_one(&self.db)
            .await
            .unwrap_or(0);

        let excellent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_reputation WHERE trust_level = 'excellent'",
        )
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let high: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM node_reputation WHERE trust_level = 'high'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let medium: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM node_reputation WHERE trust_level = 'medium'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let low: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM node_reputation WHERE trust_level = 'low'")
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);

        let untrusted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM node_reputation WHERE trust_level = 'untrusted'",
        )
        .fetch_one(&self.db)
        .await
        .unwrap_or(0);

        let avg_score: Option<f64> = sqlx::query_scalar("SELECT AVG(score) FROM node_reputation")
            .fetch_one(&self.db)
            .await
            .ok();

        let total_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reputation_events")
            .fetch_one(&self.db)
            .await
            .unwrap_or(0);

        Ok(ReputationStats {
            total_nodes: total_nodes as u64,
            excellent_nodes: excellent as u64,
            high_nodes: high as u64,
            medium_nodes: medium as u64,
            low_nodes: low as u64,
            untrusted_nodes: untrusted as u64,
            avg_score: avg_score.unwrap_or(0.0),
            total_events: total_events as u64,
        })
    }

    /// Start automatic decay task.
    pub fn start_auto_decay(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(24 * 3600), // Daily
            );

            loop {
                interval.tick().await;

                if let Err(e) = self.apply_decay().await {
                    warn!("Failed to apply reputation decay: {}", e);
                } else {
                    info!("Successfully applied reputation decay");
                }
            }
        })
    }
}

/// Node performance metrics.
#[derive(Debug, Clone)]
struct NodeMetrics {
    successful_proofs: u64,
    failed_proofs: u64,
    success_rate: f64,
    avg_transfer_speed: f64,
    uptime_percentage: f64,
    fraud_incidents: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_event_impact() {
        assert_eq!(ReputationEvent::ProofVerified.impact(), 5);
        assert_eq!(ReputationEvent::ProofFailed.impact(), -10);
        assert_eq!(ReputationEvent::FraudDetected.impact(), -50);
        assert_eq!(ReputationEvent::UptimeMilestone.impact(), 20);
    }

    #[test]
    fn test_trust_level_from_score() {
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(300), TrustLevel::Low);
        assert_eq!(TrustLevel::from_score(500), TrustLevel::Medium);
        assert_eq!(TrustLevel::from_score(700), TrustLevel::High);
        assert_eq!(TrustLevel::from_score(900), TrustLevel::Excellent);
    }

    #[test]
    fn test_reputation_config_defaults() {
        let config = ReputationConfig::default();
        assert_eq!(config.initial_score, 500);
        assert_eq!(config.min_score, 0);
        assert_eq!(config.max_score, 1000);
        assert_eq!(config.decay_rate_per_day, 2);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Excellent > TrustLevel::High);
        assert!(TrustLevel::High > TrustLevel::Medium);
        assert!(TrustLevel::Medium > TrustLevel::Low);
        assert!(TrustLevel::Low > TrustLevel::Untrusted);
    }
}
