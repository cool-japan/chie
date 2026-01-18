//! Proof verification engine.
//!
//! Implements the complete verification pipeline for bandwidth proofs:
//! 1. Nonce replay attack prevention
//! 2. Timestamp validation
//! 3. Signature verification (provider and requester)
//! 4. Statistical anomaly detection
//! 5. Fraud scoring

mod inner {
    use crate::db::{DbPool, ProofRepository, ProofStatus};
    use chie_crypto::verify as verify_signature;
    use chie_shared::{BandwidthProof, VerificationError};
    use std::sync::Arc;
    use tracing::{debug, warn};

    /// Configuration for proof verification.
    #[derive(Debug, Clone)]
    pub struct VerificationConfig {
        /// Maximum allowed timestamp drift (milliseconds).
        pub timestamp_tolerance_ms: i64,
        /// Z-score threshold for anomaly detection.
        pub anomaly_z_threshold: f64,
        /// Minimum latency (to detect impossible transfers).
        pub min_latency_ms: u32,
        /// Maximum latency before penalty.
        pub high_latency_threshold_ms: u32,
    }

    impl Default for VerificationConfig {
        fn default() -> Self {
            Self {
                timestamp_tolerance_ms: 300_000, // 5 minutes
                anomaly_z_threshold: 3.0,
                min_latency_ms: 1,
                high_latency_threshold_ms: 500,
            }
        }
    }

    /// Result of proof verification.
    #[derive(Debug)]
    pub struct VerificationResult {
        /// Whether the proof is valid.
        pub is_valid: bool,
        /// Proof status to set.
        pub status: ProofStatus,
        /// Rejection reason if invalid.
        pub rejection_reason: Option<String>,
        /// Detected anomalies.
        pub anomalies: Vec<AnomalyReport>,
        /// Quality score (0.0 to 1.0).
        pub quality_score: f64,
    }

    /// Detected anomaly in a proof.
    #[derive(Debug)]
    pub struct AnomalyReport {
        pub anomaly_type: AnomalyType,
        pub severity: Severity,
        pub description: String,
    }

    #[derive(Debug, Clone, Copy)]
    #[allow(clippy::enum_variant_names)]
    pub enum AnomalyType {
        SpeedAnomaly,
        TimingAnomaly,
        PatternAnomaly,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }

    /// Proof verification engine.
    pub struct ProofVerifier {
        pool: Arc<DbPool>,
        config: VerificationConfig,
    }

    impl ProofVerifier {
        /// Create a new verifier.
        pub fn new(pool: Arc<DbPool>, config: VerificationConfig) -> Self {
            Self { pool, config }
        }

        /// Verify a bandwidth proof.
        pub async fn verify(
            &self,
            proof: &BandwidthProof,
        ) -> Result<VerificationResult, VerificationError> {
            let mut anomalies = Vec::new();
            let mut quality_score = 1.0;

            // Step 1: Check for nonce replay
            debug!("Checking nonce replay for session {}", proof.session_id);
            let nonce_valid =
                ProofRepository::check_and_use_nonce(&self.pool, &proof.challenge_nonce)
                    .await
                    .map_err(|e| VerificationError::AnomalyDetected(format!("DB error: {}", e)))?;

            if !nonce_valid {
                return Ok(VerificationResult {
                    is_valid: false,
                    status: ProofStatus::Rejected,
                    rejection_reason: Some(
                        "Nonce already used (replay attack detected)".to_string(),
                    ),
                    anomalies,
                    quality_score: 0.0,
                });
            }

            // Step 2: Validate timestamp
            let now_ms = chrono::Utc::now().timestamp_millis();
            let time_diff = (now_ms - proof.end_timestamp_ms).abs();
            if time_diff > self.config.timestamp_tolerance_ms {
                return Ok(VerificationResult {
                    is_valid: false,
                    status: ProofStatus::Rejected,
                    rejection_reason: Some(format!(
                        "Timestamp out of range: {}ms drift (max: {}ms)",
                        time_diff, self.config.timestamp_tolerance_ms
                    )),
                    anomalies,
                    quality_score: 0.0,
                });
            }

            // Step 3: Validate latency
            if proof.latency_ms < self.config.min_latency_ms {
                anomalies.push(AnomalyReport {
                    anomaly_type: AnomalyType::SpeedAnomaly,
                    severity: Severity::Critical,
                    description: format!(
                        "Impossibly low latency: {}ms (min: {}ms)",
                        proof.latency_ms, self.config.min_latency_ms
                    ),
                });
                return Ok(VerificationResult {
                    is_valid: false,
                    status: ProofStatus::Rejected,
                    rejection_reason: Some(
                        "Latency too low - impossible transfer speed".to_string(),
                    ),
                    anomalies,
                    quality_score: 0.0,
                });
            }

            // Latency penalty
            if proof.latency_ms > self.config.high_latency_threshold_ms {
                quality_score *= 0.8; // 20% penalty for high latency
            }

            // Step 4: Verify provider signature
            let provider_pubkey: [u8; 32] = proof
                .provider_public_key
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::InvalidProviderSignature)?;

            let provider_sig: [u8; 64] = proof
                .provider_signature
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::InvalidProviderSignature)?;

            let provider_message = proof.provider_sign_message();
            if verify_signature(&provider_pubkey, &provider_message, &provider_sig).is_err() {
                return Ok(VerificationResult {
                    is_valid: false,
                    status: ProofStatus::Rejected,
                    rejection_reason: Some("Invalid provider signature".to_string()),
                    anomalies,
                    quality_score: 0.0,
                });
            }

            // Step 5: Verify requester signature
            let requester_pubkey: [u8; 32] = proof
                .requester_public_key
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::InvalidRequesterSignature)?;

            let requester_sig: [u8; 64] = proof
                .requester_signature
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::InvalidRequesterSignature)?;

            let requester_message = proof.requester_sign_message();
            if verify_signature(&requester_pubkey, &requester_message, &requester_sig).is_err() {
                return Ok(VerificationResult {
                    is_valid: false,
                    status: ProofStatus::Rejected,
                    rejection_reason: Some("Invalid requester signature".to_string()),
                    anomalies,
                    quality_score: 0.0,
                });
            }

            // Step 6: Statistical anomaly detection
            if let Some(anomaly) = self.check_statistical_anomaly(proof).await {
                anomalies.push(anomaly);
                quality_score *= 0.5; // 50% penalty for anomaly
            }

            Ok(VerificationResult {
                is_valid: true,
                status: ProofStatus::Verified,
                rejection_reason: None,
                anomalies,
                quality_score,
            })
        }

        /// Check for statistical anomalies in transfer speed.
        async fn check_statistical_anomaly(&self, proof: &BandwidthProof) -> Option<AnomalyReport> {
            // Calculate transfer speed
            let duration_secs = proof.latency_ms as f64 / 1000.0;
            if duration_secs == 0.0 {
                return Some(AnomalyReport {
                    anomaly_type: AnomalyType::TimingAnomaly,
                    severity: Severity::Critical,
                    description: "Zero duration transfer".to_string(),
                });
            }

            let speed_bps = (proof.bytes_transferred as f64) / duration_secs;
            let speed_gbps = speed_bps / (1024.0 * 1024.0 * 1024.0);

            // Flag if speed exceeds theoretical maximum (e.g., 100 Gbps)
            const MAX_REASONABLE_GBPS: f64 = 100.0;
            if speed_gbps > MAX_REASONABLE_GBPS {
                return Some(AnomalyReport {
                    anomaly_type: AnomalyType::SpeedAnomaly,
                    severity: Severity::High,
                    description: format!(
                        "Transfer speed {:.2} Gbps exceeds maximum reasonable speed",
                        speed_gbps
                    ),
                });
            }

            // Historical average speed check
            // Look up node by peer_id to get node_id
            match crate::db::NodeRepository::find_by_peer_id(&self.pool, &proof.provider_peer_id)
                .await
            {
                Ok(Some(node)) => {
                    // Get historical average speed for this node
                    if let Ok(Some(avg_speed_bps)) =
                        crate::db::ProofRepository::get_average_speed(&self.pool, node.id).await
                    {
                        let current_speed_bps = speed_bps;

                        // Flag if current speed deviates significantly from historical average
                        // Consider 5x faster or 5x slower as anomalous
                        const SPEED_DEVIATION_THRESHOLD: f64 = 5.0;

                        if current_speed_bps > avg_speed_bps * SPEED_DEVIATION_THRESHOLD {
                            crate::metrics::record_anomaly_detected(
                                "speed_deviation_high",
                                "medium",
                            );
                            return Some(AnomalyReport {
                                anomaly_type: AnomalyType::SpeedAnomaly,
                                severity: Severity::Medium,
                                description: format!(
                                    "Transfer speed {:.2} Mbps is {:.1}x higher than historical average {:.2} Mbps",
                                    current_speed_bps / (1024.0 * 1024.0),
                                    current_speed_bps / avg_speed_bps,
                                    avg_speed_bps / (1024.0 * 1024.0)
                                ),
                            });
                        } else if current_speed_bps < avg_speed_bps / SPEED_DEVIATION_THRESHOLD {
                            crate::metrics::record_anomaly_detected("speed_deviation_low", "low");
                            return Some(AnomalyReport {
                                anomaly_type: AnomalyType::SpeedAnomaly,
                                severity: Severity::Low,
                                description: format!(
                                    "Transfer speed {:.2} Mbps is {:.1}x lower than historical average {:.2} Mbps",
                                    current_speed_bps / (1024.0 * 1024.0),
                                    avg_speed_bps / current_speed_bps,
                                    avg_speed_bps / (1024.0 * 1024.0)
                                ),
                            });
                        }
                    }
                }
                Ok(None) => {
                    // Node not found in database - this might be a first-time provider
                    // We'll allow it but could log this for monitoring
                    tracing::debug!("Node not found for peer_id: {}", proof.provider_peer_id);
                }
                Err(e) => {
                    // Database error - log but don't fail verification
                    tracing::warn!("Failed to lookup node for speed check: {}", e);
                }
            }

            None
        }
    }

    /// Service that combines verification with database operations.
    pub struct VerificationService {
        verifier: ProofVerifier,
        pool: Arc<DbPool>,
    }

    impl VerificationService {
        pub fn new(pool: Arc<DbPool>, config: VerificationConfig) -> Self {
            Self {
                verifier: ProofVerifier::new(pool.clone(), config),
                pool,
            }
        }

        /// Get the verification configuration.
        pub fn config(&self) -> &VerificationConfig {
            &self.verifier.config
        }

        /// Verify a proof and store the result.
        pub async fn verify_and_store(
            &self,
            proof: &BandwidthProof,
        ) -> Result<VerificationResult, VerificationError> {
            let result = self.verifier.verify(proof).await?;

            // Update proof status in database
            if let Err(e) = ProofRepository::update_status(
                &self.pool,
                proof.session_id,
                result.status,
                result.rejection_reason.as_deref(),
            )
            .await
            {
                warn!("Failed to update proof status: {}", e);
            }

            Ok(result)
        }
    }
}

// Re-export types for external use
pub use inner::*;
