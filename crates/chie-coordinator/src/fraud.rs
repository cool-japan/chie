//! Fraud detection and alerting for CHIE Protocol.
//!
//! This module provides:
//! - Statistical anomaly detection
//! - Pattern-based fraud detection
//! - Alert generation and notification
//! - Node reputation impact

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Fraud detection configuration.
#[derive(Debug, Clone)]
pub struct FraudConfig {
    /// Z-score threshold for statistical anomaly.
    pub zscore_threshold: f64,
    /// Maximum bandwidth speed (bytes/second) - 10 Gbps.
    pub max_bandwidth_speed: u64,
    /// Minimum latency threshold (ms) - below is suspicious.
    pub min_latency_ms: u32,
    /// Maximum proofs per minute from single node.
    pub max_proofs_per_minute: u32,
    /// Time window for rate limiting (seconds).
    pub rate_limit_window_secs: u64,
    /// Enable alert notifications.
    pub enable_alerts: bool,
    /// Cooldown between alerts for same node (seconds).
    pub alert_cooldown_secs: u64,
}

impl Default for FraudConfig {
    fn default() -> Self {
        Self {
            zscore_threshold: 3.0,
            max_bandwidth_speed: 10 * 1024 * 1024 * 1024, // 10 Gbps
            min_latency_ms: 1,
            max_proofs_per_minute: 100,
            rate_limit_window_secs: 60,
            enable_alerts: true,
            alert_cooldown_secs: 300, // 5 minutes
        }
    }
}

/// Type of fraud detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FraudType {
    /// Statistical anomaly in transfer patterns.
    StatisticalAnomaly,
    /// Impossibly fast transfer speed.
    ImpossibleSpeed,
    /// Suspiciously low latency.
    SuspiciousLatency,
    /// Self-transfer attempt.
    SelfTransfer,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Timestamp manipulation.
    TimestampManipulation,
    /// Duplicate nonce reuse.
    NonceReuse,
    /// Signature verification failed.
    InvalidSignature,
    /// Collusion between nodes.
    PotentialCollusion,
    /// Unusual geographic pattern.
    GeographicAnomaly,
}

impl std::fmt::Display for FraudType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatisticalAnomaly => write!(f, "Statistical Anomaly"),
            Self::ImpossibleSpeed => write!(f, "Impossible Speed"),
            Self::SuspiciousLatency => write!(f, "Suspicious Latency"),
            Self::SelfTransfer => write!(f, "Self Transfer"),
            Self::RateLimitExceeded => write!(f, "Rate Limit Exceeded"),
            Self::TimestampManipulation => write!(f, "Timestamp Manipulation"),
            Self::NonceReuse => write!(f, "Nonce Reuse"),
            Self::InvalidSignature => write!(f, "Invalid Signature"),
            Self::PotentialCollusion => write!(f, "Potential Collusion"),
            Self::GeographicAnomaly => write!(f, "Geographic Anomaly"),
        }
    }
}

/// Severity level of fraud alert.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum AlertSeverity {
    /// Low severity - might be false positive.
    Low,
    /// Medium severity - suspicious activity.
    Medium,
    /// High severity - likely fraud.
    High,
    /// Critical - definite fraud, immediate action needed.
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Fraud alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FraudAlert {
    /// Unique alert ID.
    pub id: uuid::Uuid,
    /// Type of fraud detected.
    pub fraud_type: FraudType,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Node ID (peer ID) involved.
    pub node_id: String,
    /// Secondary node ID (if applicable).
    pub secondary_node_id: Option<String>,
    /// Proof ID that triggered the alert.
    pub proof_id: Option<uuid::Uuid>,
    /// Alert message.
    pub message: String,
    /// Additional details.
    pub details: HashMap<String, String>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Suggested action.
    pub suggested_action: SuggestedAction,
    /// When the alert was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the alert has been acknowledged.
    pub acknowledged: bool,
    /// Who acknowledged the alert.
    pub acknowledged_by: Option<String>,
    /// When the alert was acknowledged.
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl FraudAlert {
    /// Create a new fraud alert.
    pub fn new(
        fraud_type: FraudType,
        severity: AlertSeverity,
        node_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            fraud_type,
            severity,
            node_id: node_id.into(),
            secondary_node_id: None,
            proof_id: None,
            message: message.into(),
            details: HashMap::new(),
            confidence: 0.8,
            suggested_action: SuggestedAction::Review,
            created_at: chrono::Utc::now(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        }
    }

    /// Set secondary node ID.
    pub fn with_secondary_node(mut self, node_id: impl Into<String>) -> Self {
        self.secondary_node_id = Some(node_id.into());
        self
    }

    /// Set proof ID.
    pub fn with_proof_id(mut self, proof_id: uuid::Uuid) -> Self {
        self.proof_id = Some(proof_id);
        self
    }

    /// Add a detail.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Set confidence.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set suggested action.
    pub fn with_action(mut self, action: SuggestedAction) -> Self {
        self.suggested_action = action;
        self
    }
}

/// Suggested action for fraud alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SuggestedAction {
    /// No action needed, just monitoring.
    Monitor,
    /// Manual review required.
    Review,
    /// Temporarily suspend node.
    Suspend,
    /// Ban node immediately.
    Ban,
    /// Reverse fraudulent rewards.
    ReverseRewards,
}

impl std::fmt::Display for SuggestedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "Monitor"),
            Self::Review => write!(f, "Review"),
            Self::Suspend => write!(f, "Suspend"),
            Self::Ban => write!(f, "Ban"),
            Self::ReverseRewards => write!(f, "Reverse Rewards"),
        }
    }
}

/// Node statistics for fraud detection.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct NodeStats {
    /// Recent proof timestamps.
    proof_times: Vec<Instant>,
    /// Total bytes transferred.
    total_bytes: u64,
    /// Average latency (ms).
    avg_latency_ms: f64,
    /// Standard deviation of latency.
    latency_stddev: f64,
    /// Number of proofs submitted.
    proof_count: u64,
    /// Number of failed verifications.
    failed_verifications: u64,
    /// Partners (nodes this node has transferred with).
    partners: HashMap<String, u64>,
    /// Last alert time per fraud type.
    last_alerts: HashMap<FraudType, Instant>,
}

/// Fraud detector service.
pub struct FraudDetector {
    config: FraudConfig,
    /// Per-node statistics.
    node_stats: Arc<RwLock<HashMap<String, NodeStats>>>,
    /// Active alerts.
    alerts: Arc<RwLock<Vec<FraudAlert>>>,
    /// Alert handlers.
    handlers: Arc<RwLock<Vec<Box<dyn AlertHandler + Send + Sync>>>>,
    /// Detection statistics.
    stats: Arc<RwLock<DetectionStats>>,
}

/// Alert handler trait.
pub trait AlertHandler: Send + Sync {
    /// Handle a fraud alert.
    fn handle(&self, alert: &FraudAlert);
}

/// Detection statistics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DetectionStats {
    /// Total proofs analyzed.
    pub proofs_analyzed: u64,
    /// Total alerts generated.
    pub alerts_generated: u64,
    /// Alerts by type.
    pub alerts_by_type: HashMap<String, u64>,
    /// Alerts by severity.
    pub alerts_by_severity: HashMap<String, u64>,
    /// False positives (acknowledged as not fraud).
    pub false_positives: u64,
    /// Confirmed fraud cases.
    pub confirmed_fraud: u64,
}

impl FraudDetector {
    /// Create a new fraud detector.
    pub fn new(config: FraudConfig) -> Self {
        Self {
            config,
            node_stats: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            handlers: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(DetectionStats::default())),
        }
    }

    /// Register an alert handler.
    pub async fn register_handler(&self, handler: Box<dyn AlertHandler + Send + Sync>) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    /// Analyze a bandwidth proof for fraud.
    pub async fn analyze_proof(&self, proof: &ProofData) -> Vec<FraudAlert> {
        let mut alerts = Vec::new();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.proofs_analyzed += 1;
        }

        // Check for self-transfer
        if proof.provider_id == proof.requester_id {
            let alert = FraudAlert::new(
                FraudType::SelfTransfer,
                AlertSeverity::Critical,
                &proof.provider_id,
                "Node attempted self-transfer",
            )
            .with_proof_id(proof.id)
            .with_confidence(1.0)
            .with_action(SuggestedAction::Ban);

            alerts.push(alert);
        }

        // Check for impossible speed
        if proof.latency_ms > 0 {
            let speed = (proof.bytes_transferred as f64 / proof.latency_ms as f64) * 1000.0;
            if speed > self.config.max_bandwidth_speed as f64 {
                let alert = FraudAlert::new(
                    FraudType::ImpossibleSpeed,
                    AlertSeverity::High,
                    &proof.provider_id,
                    format!(
                        "Transfer speed {} bytes/s exceeds maximum possible",
                        speed as u64
                    ),
                )
                .with_proof_id(proof.id)
                .with_detail("speed_bps", format!("{}", speed as u64))
                .with_confidence(0.95)
                .with_action(SuggestedAction::Review);

                alerts.push(alert);
            }
        }

        // Check for suspicious latency
        if proof.latency_ms < self.config.min_latency_ms {
            let alert = FraudAlert::new(
                FraudType::SuspiciousLatency,
                AlertSeverity::Medium,
                &proof.provider_id,
                format!(
                    "Latency {}ms below minimum threshold {}ms",
                    proof.latency_ms, self.config.min_latency_ms
                ),
            )
            .with_proof_id(proof.id)
            .with_detail("latency_ms", proof.latency_ms.to_string())
            .with_confidence(0.7)
            .with_action(SuggestedAction::Monitor);

            alerts.push(alert);
        }

        // Check rate limiting
        if self.check_rate_limit(&proof.provider_id).await {
            let alert = FraudAlert::new(
                FraudType::RateLimitExceeded,
                AlertSeverity::Medium,
                &proof.provider_id,
                format!(
                    "Node exceeded {} proofs per minute",
                    self.config.max_proofs_per_minute
                ),
            )
            .with_proof_id(proof.id)
            .with_confidence(0.9)
            .with_action(SuggestedAction::Suspend);

            alerts.push(alert);
        }

        // Update node stats
        self.update_node_stats(proof).await;

        // Check for statistical anomalies
        if let Some(alert) = self.check_statistical_anomaly(&proof.provider_id).await {
            alerts.push(alert);
        }

        // Check for collusion
        if let Some(alert) = self
            .check_collusion(&proof.provider_id, &proof.requester_id)
            .await
        {
            alerts.push(alert);
        }

        // Process alerts
        for alert in &alerts {
            self.process_alert(alert).await;
        }

        alerts
    }

    /// Get all active alerts.
    pub async fn get_alerts(&self) -> Vec<FraudAlert> {
        self.alerts.read().await.clone()
    }

    /// Get alerts for a specific node.
    pub async fn get_node_alerts(&self, node_id: &str) -> Vec<FraudAlert> {
        self.alerts
            .read()
            .await
            .iter()
            .filter(|a| a.node_id == node_id)
            .cloned()
            .collect()
    }

    /// Acknowledge an alert.
    pub async fn acknowledge_alert(&self, alert_id: uuid::Uuid, by: &str, is_fraud: bool) -> bool {
        let mut alerts = self.alerts.write().await;
        let mut stats = self.stats.write().await;

        for alert in alerts.iter_mut() {
            if alert.id == alert_id {
                alert.acknowledged = true;
                alert.acknowledged_by = Some(by.to_string());
                alert.acknowledged_at = Some(chrono::Utc::now());

                if is_fraud {
                    stats.confirmed_fraud += 1;
                } else {
                    stats.false_positives += 1;
                }

                return true;
            }
        }

        false
    }

    /// Get detection statistics.
    pub async fn stats(&self) -> DetectionStats {
        self.stats.read().await.clone()
    }

    /// Clear old alerts.
    pub async fn clear_old_alerts(&self, max_age: Duration) {
        let mut alerts = self.alerts.write().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();
        alerts.retain(|a| a.created_at > cutoff || !a.acknowledged);
    }

    // Internal methods

    async fn check_rate_limit(&self, node_id: &str) -> bool {
        let mut node_stats = self.node_stats.write().await;
        let stats = node_stats.entry(node_id.to_string()).or_default();

        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit_window_secs);

        // Remove old entries
        stats
            .proof_times
            .retain(|t| now.duration_since(*t) < window);

        // Check rate
        if stats.proof_times.len() >= self.config.max_proofs_per_minute as usize {
            return true;
        }

        stats.proof_times.push(now);
        false
    }

    async fn update_node_stats(&self, proof: &ProofData) {
        let mut node_stats = self.node_stats.write().await;
        let stats = node_stats.entry(proof.provider_id.clone()).or_default();

        stats.total_bytes += proof.bytes_transferred;
        stats.proof_count += 1;

        // Update average latency
        let n = stats.proof_count as f64;
        let old_avg = stats.avg_latency_ms;
        stats.avg_latency_ms = old_avg + (proof.latency_ms as f64 - old_avg) / n;

        // Update latency stddev (Welford's algorithm)
        let delta = proof.latency_ms as f64 - old_avg;
        let delta2 = proof.latency_ms as f64 - stats.avg_latency_ms;
        stats.latency_stddev =
            ((stats.latency_stddev.powi(2) * (n - 1.0) + delta * delta2) / n).sqrt();

        // Update partners
        *stats
            .partners
            .entry(proof.requester_id.clone())
            .or_insert(0) += 1;
    }

    async fn check_statistical_anomaly(&self, node_id: &str) -> Option<FraudAlert> {
        let node_stats = self.node_stats.read().await;
        let stats = node_stats.get(node_id)?;

        if stats.proof_count < 10 {
            // Not enough data
            return None;
        }

        // Check if stddev is suspiciously low (too consistent)
        if stats.latency_stddev < 0.1 && stats.avg_latency_ms < 10.0 {
            return Some(
                FraudAlert::new(
                    FraudType::StatisticalAnomaly,
                    AlertSeverity::Medium,
                    node_id,
                    "Suspiciously consistent latency pattern",
                )
                .with_detail("avg_latency_ms", format!("{:.2}", stats.avg_latency_ms))
                .with_detail("latency_stddev", format!("{:.2}", stats.latency_stddev))
                .with_confidence(0.6)
                .with_action(SuggestedAction::Monitor),
            );
        }

        None
    }

    async fn check_collusion(&self, provider_id: &str, requester_id: &str) -> Option<FraudAlert> {
        let node_stats = self.node_stats.read().await;

        if let Some(provider_stats) = node_stats.get(provider_id) {
            if let Some(&count) = provider_stats.partners.get(requester_id) {
                // Check if majority of transfers are with same partner
                let total = provider_stats.partners.values().sum::<u64>();
                if total > 20 && count as f64 / total as f64 > 0.8 {
                    return Some(
                        FraudAlert::new(
                            FraudType::PotentialCollusion,
                            AlertSeverity::High,
                            provider_id,
                            format!(
                                "{}% of transfers with same partner",
                                (count as f64 / total as f64 * 100.0) as u32
                            ),
                        )
                        .with_secondary_node(requester_id)
                        .with_detail("partner_transfer_count", count.to_string())
                        .with_detail("total_transfers", total.to_string())
                        .with_confidence(0.75)
                        .with_action(SuggestedAction::Review),
                    );
                }
            }
        }

        None
    }

    async fn process_alert(&self, alert: &FraudAlert) {
        // Check cooldown
        {
            let mut node_stats = self.node_stats.write().await;
            let stats = node_stats.entry(alert.node_id.clone()).or_default();

            if let Some(last_alert) = stats.last_alerts.get(&alert.fraud_type) {
                if last_alert.elapsed() < Duration::from_secs(self.config.alert_cooldown_secs) {
                    return; // Still in cooldown
                }
            }

            stats.last_alerts.insert(alert.fraud_type, Instant::now());
        }

        // Log alert
        match alert.severity {
            AlertSeverity::Critical => {
                error!(
                    "FRAUD ALERT [CRITICAL]: {} - Node: {} - {}",
                    alert.fraud_type, alert.node_id, alert.message
                );
            }
            AlertSeverity::High => {
                warn!(
                    "FRAUD ALERT [HIGH]: {} - Node: {} - {}",
                    alert.fraud_type, alert.node_id, alert.message
                );
            }
            AlertSeverity::Medium => {
                warn!(
                    "FRAUD ALERT [MEDIUM]: {} - Node: {} - {}",
                    alert.fraud_type, alert.node_id, alert.message
                );
            }
            AlertSeverity::Low => {
                info!(
                    "FRAUD ALERT [LOW]: {} - Node: {} - {}",
                    alert.fraud_type, alert.node_id, alert.message
                );
            }
        }

        // Store alert
        {
            let mut alerts = self.alerts.write().await;
            alerts.push(alert.clone());
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.alerts_generated += 1;
            *stats
                .alerts_by_type
                .entry(alert.fraud_type.to_string())
                .or_insert(0) += 1;
            *stats
                .alerts_by_severity
                .entry(alert.severity.to_string())
                .or_insert(0) += 1;
        }

        // Notify handlers
        if self.config.enable_alerts {
            let handlers = self.handlers.read().await;
            for handler in handlers.iter() {
                handler.handle(alert);
            }
        }
    }
}

/// Proof data for fraud analysis.
#[derive(Debug, Clone)]
pub struct ProofData {
    /// Proof ID.
    pub id: uuid::Uuid,
    /// Provider node ID.
    pub provider_id: String,
    /// Requester node ID.
    pub requester_id: String,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Transfer latency (ms).
    pub latency_ms: u32,
    /// Proof timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Logging alert handler.
pub struct LoggingAlertHandler;

impl AlertHandler for LoggingAlertHandler {
    fn handle(&self, alert: &FraudAlert) {
        tracing::event!(
            target: "fraud_alerts",
            tracing::Level::WARN,
            alert_id = %alert.id,
            fraud_type = %alert.fraud_type,
            severity = %alert.severity,
            node_id = %alert.node_id,
            message = %alert.message,
            "Fraud alert generated"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_self_transfer_detection() {
        let detector = FraudDetector::new(FraudConfig::default());

        let proof = ProofData {
            id: uuid::Uuid::new_v4(),
            provider_id: "node1".to_string(),
            requester_id: "node1".to_string(), // Same as provider
            bytes_transferred: 1000,
            latency_ms: 10,
            timestamp: chrono::Utc::now(),
        };

        let alerts = detector.analyze_proof(&proof).await;
        assert!(
            alerts
                .iter()
                .any(|a| a.fraud_type == FraudType::SelfTransfer)
        );
    }

    #[tokio::test]
    async fn test_rate_limit_detection() {
        let config = FraudConfig {
            max_proofs_per_minute: 5,
            ..Default::default()
        };
        let detector = FraudDetector::new(config);

        // Submit many proofs quickly
        for i in 0..10 {
            let proof = ProofData {
                id: uuid::Uuid::new_v4(),
                provider_id: "node1".to_string(),
                requester_id: format!("node{}", i + 2),
                bytes_transferred: 1000,
                latency_ms: 100,
                timestamp: chrono::Utc::now(),
            };
            detector.analyze_proof(&proof).await;
        }

        let alerts = detector.get_node_alerts("node1").await;
        assert!(
            alerts
                .iter()
                .any(|a| a.fraud_type == FraudType::RateLimitExceeded)
        );
    }
}
