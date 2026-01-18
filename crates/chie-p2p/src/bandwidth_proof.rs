//! Bandwidth proof verification for the CHIE protocol.
//!
//! This module provides verification of bandwidth proofs submitted by peers,
//! ensuring they are valid, non-replayed, and statistically sound.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::bandwidth_proof::BandwidthProofVerifier;
//! use chie_p2p::NonceManager;
//!
//! let verifier = BandwidthProofVerifier::new();
//! let nonce_manager = NonceManager::new();
//!
//! // Verification happens in the coordinator
//! // let result = verifier.verify_proof(&proof, &nonce_manager);
//! ```

use crate::nonce_manager::NonceManager;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// Proof signature is invalid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Nonce has been reused (replay attack).
    #[error("Nonce reused (replay attack): {0}")]
    NonceReused(String),

    /// Timestamp is outside acceptable window.
    #[error("Timestamp out of bounds: {0}")]
    TimestampOutOfBounds(String),

    /// Statistical anomaly detected.
    #[error("Statistical anomaly detected: {0}")]
    StatisticalAnomaly(String),

    /// Proof data is invalid or corrupted.
    #[error("Invalid proof data: {0}")]
    InvalidProofData(String),

    /// Peer is not authorized.
    #[error("Peer not authorized: {0}")]
    Unauthorized(String),
}

/// Configuration for proof verification.
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Maximum timestamp age in seconds (5 minutes default).
    pub max_timestamp_age: Duration,
    /// Maximum timestamp future tolerance (1 minute default).
    pub max_timestamp_future: Duration,
    /// Z-score threshold for anomaly detection (3.0 default).
    pub anomaly_z_threshold: f64,
    /// Minimum chunk size in bytes.
    pub min_chunk_size: usize,
    /// Maximum chunk size in bytes.
    pub max_chunk_size: usize,
    /// Enable statistical anomaly detection.
    pub enable_anomaly_detection: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            max_timestamp_age: Duration::from_secs(300), // 5 minutes
            max_timestamp_future: Duration::from_secs(60), // 1 minute
            anomaly_z_threshold: 3.0,
            min_chunk_size: 256,              // 256 bytes
            max_chunk_size: 10 * 1024 * 1024, // 10 MB
            enable_anomaly_detection: true,
        }
    }
}

/// Statistics for proof verification.
#[derive(Debug, Default, Clone)]
pub struct VerificationStats {
    /// Total proofs verified.
    pub total_verified: u64,
    /// Successful verifications.
    pub successful: u64,
    /// Failed verifications.
    pub failed: u64,
    /// Replay attacks detected.
    pub replay_attacks: u64,
    /// Invalid signatures detected.
    pub invalid_signatures: u64,
    /// Timestamp violations.
    pub timestamp_violations: u64,
    /// Statistical anomalies detected.
    pub anomalies_detected: u64,
    /// Total bandwidth verified (bytes).
    pub total_bandwidth_bytes: u64,
}

impl VerificationStats {
    /// Get the success rate.
    pub fn success_rate(&self) -> f64 {
        if self.total_verified == 0 {
            return 0.0;
        }
        self.successful as f64 / self.total_verified as f64
    }

    /// Get the anomaly rate.
    pub fn anomaly_rate(&self) -> f64 {
        if self.total_verified == 0 {
            return 0.0;
        }
        self.anomalies_detected as f64 / self.total_verified as f64
    }
}

/// Proof record for tracking peer bandwidth usage.
#[derive(Debug, Clone)]
pub struct ProofRecord {
    /// Peer ID.
    pub peer_id: PeerId,
    /// Chunk size in bytes.
    pub chunk_size: usize,
    /// Timestamp when proof was created.
    pub timestamp: Instant,
    /// Latency in milliseconds.
    pub latency_ms: u64,
}

/// Bandwidth proof verifier.
pub struct BandwidthProofVerifier {
    config: VerificationConfig,
    /// Peer proof history for anomaly detection.
    proof_history: Arc<parking_lot::RwLock<HashMap<PeerId, Vec<ProofRecord>>>>,
    /// Statistics.
    stats: Arc<parking_lot::RwLock<VerificationStats>>,
}

impl BandwidthProofVerifier {
    /// Create a new bandwidth proof verifier with default configuration.
    pub fn new() -> Self {
        Self::with_config(VerificationConfig::default())
    }

    /// Create a new bandwidth proof verifier with custom configuration.
    pub fn with_config(config: VerificationConfig) -> Self {
        Self {
            config,
            proof_history: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            stats: Arc::new(parking_lot::RwLock::new(VerificationStats::default())),
        }
    }

    /// Verify a bandwidth proof (simplified version for testing).
    ///
    /// In production, this would verify Ed25519 signatures from both requester and provider.
    pub fn verify_proof(
        &self,
        peer_id: PeerId,
        chunk_size: usize,
        latency_ms: u64,
        timestamp_secs_ago: u64,
        nonce: &str,
        nonce_manager: &NonceManager,
    ) -> Result<(), VerificationError> {
        let mut stats = self.stats.write();
        stats.total_verified += 1;

        // Validate chunk size
        if chunk_size < self.config.min_chunk_size || chunk_size > self.config.max_chunk_size {
            stats.failed += 1;
            return Err(VerificationError::InvalidProofData(format!(
                "Chunk size {} out of bounds",
                chunk_size
            )));
        }

        // Verify nonce (prevents replay attacks)
        if let Err(e) = nonce_manager.validate_nonce(nonce) {
            stats.failed += 1;
            stats.replay_attacks += 1;
            return Err(VerificationError::NonceReused(e.to_string()));
        }

        // Verify timestamp
        if timestamp_secs_ago > self.config.max_timestamp_age.as_secs() {
            stats.failed += 1;
            stats.timestamp_violations += 1;
            return Err(VerificationError::TimestampOutOfBounds(format!(
                "Timestamp too old: {} seconds",
                timestamp_secs_ago
            )));
        }

        // Statistical anomaly detection
        if self.config.enable_anomaly_detection {
            if let Err(e) = self.check_anomaly(peer_id, chunk_size, latency_ms) {
                stats.failed += 1;
                stats.anomalies_detected += 1;
                return Err(e);
            }
        }

        // Record proof
        let record = ProofRecord {
            peer_id,
            chunk_size,
            timestamp: Instant::now(),
            latency_ms,
        };

        let mut history = self.proof_history.write();
        history.entry(peer_id).or_default().push(record);

        // Limit history size
        if let Some(records) = history.get_mut(&peer_id) {
            if records.len() > 1000 {
                records.drain(0..500); // Keep last 500
            }
        }

        stats.successful += 1;
        stats.total_bandwidth_bytes += chunk_size as u64;

        Ok(())
    }

    /// Check for statistical anomalies.
    fn check_anomaly(
        &self,
        peer_id: PeerId,
        chunk_size: usize,
        latency_ms: u64,
    ) -> Result<(), VerificationError> {
        let history = self.proof_history.read();

        if let Some(records) = history.get(&peer_id) {
            if records.len() < 10 {
                return Ok(()); // Not enough data
            }

            // Calculate mean and std dev for chunk size
            let sizes: Vec<f64> = records.iter().map(|r| r.chunk_size as f64).collect();
            let mean_size = sizes.iter().sum::<f64>() / sizes.len() as f64;
            let variance =
                sizes.iter().map(|&s| (s - mean_size).powi(2)).sum::<f64>() / sizes.len() as f64;
            let std_dev = variance.sqrt();

            if std_dev > 0.0 {
                let z_score = ((chunk_size as f64) - mean_size).abs() / std_dev;
                if z_score > self.config.anomaly_z_threshold {
                    return Err(VerificationError::StatisticalAnomaly(format!(
                        "Chunk size z-score {} exceeds threshold {}",
                        z_score, self.config.anomaly_z_threshold
                    )));
                }
            }

            // Calculate mean and std dev for latency
            let latencies: Vec<f64> = records.iter().map(|r| r.latency_ms as f64).collect();
            let mean_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
            let variance = latencies
                .iter()
                .map(|&l| (l - mean_latency).powi(2))
                .sum::<f64>()
                / latencies.len() as f64;
            let std_dev = variance.sqrt();

            if std_dev > 0.0 {
                let z_score = ((latency_ms as f64) - mean_latency).abs() / std_dev;
                if z_score > self.config.anomaly_z_threshold {
                    return Err(VerificationError::StatisticalAnomaly(format!(
                        "Latency z-score {} exceeds threshold {}",
                        z_score, self.config.anomaly_z_threshold
                    )));
                }
            }
        }

        Ok(())
    }

    /// Get verification statistics.
    pub fn stats(&self) -> VerificationStats {
        self.stats.read().clone()
    }

    /// Get configuration.
    pub fn config(&self) -> &VerificationConfig {
        &self.config
    }

    /// Get proof count for a peer.
    pub fn get_peer_proof_count(&self, peer_id: &PeerId) -> usize {
        self.proof_history
            .read()
            .get(peer_id)
            .map(|r| r.len())
            .unwrap_or(0)
    }

    /// Clear proof history for a peer.
    pub fn clear_peer_history(&self, peer_id: &PeerId) {
        self.proof_history.write().remove(peer_id);
    }

    /// Clear all proof history.
    pub fn clear_all_history(&self) {
        self.proof_history.write().clear();
    }
}

impl Default for BandwidthProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BandwidthProofVerifier {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            proof_history: Arc::clone(&self.proof_history),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_config_default() {
        let config = VerificationConfig::default();
        assert_eq!(config.max_timestamp_age, Duration::from_secs(300));
        assert_eq!(config.anomaly_z_threshold, 3.0);
        assert!(config.enable_anomaly_detection);
    }

    #[test]
    fn test_verifier_new() {
        let verifier = BandwidthProofVerifier::new();
        let stats = verifier.stats();
        assert_eq!(stats.total_verified, 0);
    }

    #[test]
    fn test_verify_proof_success() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let nonce = nonce_manager.generate_nonce();
        let peer_id = PeerId::random();

        let result = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        assert!(result.is_ok());

        let stats = verifier.stats();
        assert_eq!(stats.total_verified, 1);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn test_verify_proof_invalid_chunk_size() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let nonce = nonce_manager.generate_nonce();
        let peer_id = PeerId::random();

        // Too small
        let result = verifier.verify_proof(peer_id, 100, 100, 10, &nonce, &nonce_manager);
        assert!(result.is_err());

        let stats = verifier.stats();
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_verify_proof_nonce_reuse() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let nonce = nonce_manager.generate_nonce();
        let peer_id = PeerId::random();

        // First verification succeeds
        let result = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        assert!(result.is_ok());

        // Second verification with same nonce fails
        let result = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        assert!(result.is_err());

        let stats = verifier.stats();
        assert_eq!(stats.replay_attacks, 1);
    }

    #[test]
    fn test_verify_proof_timestamp_too_old() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let nonce = nonce_manager.generate_nonce();
        let peer_id = PeerId::random();

        // Timestamp 400 seconds ago (exceeds 300 second limit)
        let result = verifier.verify_proof(peer_id, 1024, 100, 400, &nonce, &nonce_manager);
        assert!(result.is_err());

        let stats = verifier.stats();
        assert_eq!(stats.timestamp_violations, 1);
    }

    #[test]
    fn test_anomaly_detection_disabled() {
        let config = VerificationConfig {
            enable_anomaly_detection: false,
            ..Default::default()
        };
        let verifier = BandwidthProofVerifier::with_config(config);
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        // Submit many proofs with varying sizes
        for i in 0..20 {
            let nonce = nonce_manager.generate_nonce();
            let chunk_size = 1024 * (i % 5 + 1);
            let _ = verifier.verify_proof(peer_id, chunk_size, 100, 10, &nonce, &nonce_manager);
        }

        let stats = verifier.stats();
        // No anomalies detected because detection is disabled
        assert_eq!(stats.anomalies_detected, 0);
    }

    #[test]
    fn test_success_rate() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        // 3 successful
        for _ in 0..3 {
            let nonce = nonce_manager.generate_nonce();
            let _ = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        }

        // 1 failed (too small chunk)
        let nonce = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer_id, 100, 100, 10, &nonce, &nonce_manager);

        let stats = verifier.stats();
        assert_eq!(stats.success_rate(), 0.75); // 3/4
    }

    #[test]
    fn test_get_peer_proof_count() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        assert_eq!(verifier.get_peer_proof_count(&peer_id), 0);

        for _ in 0..5 {
            let nonce = nonce_manager.generate_nonce();
            let _ = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        }

        assert_eq!(verifier.get_peer_proof_count(&peer_id), 5);
    }

    #[test]
    fn test_clear_peer_history() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        let nonce = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);
        assert_eq!(verifier.get_peer_proof_count(&peer_id), 1);

        verifier.clear_peer_history(&peer_id);
        assert_eq!(verifier.get_peer_proof_count(&peer_id), 0);
    }

    #[test]
    fn test_clear_all_history() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let nonce1 = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer1, 1024, 100, 10, &nonce1, &nonce_manager);

        let nonce2 = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer2, 1024, 100, 10, &nonce2, &nonce_manager);

        assert_eq!(verifier.get_peer_proof_count(&peer1), 1);
        assert_eq!(verifier.get_peer_proof_count(&peer2), 1);

        verifier.clear_all_history();
        assert_eq!(verifier.get_peer_proof_count(&peer1), 0);
        assert_eq!(verifier.get_peer_proof_count(&peer2), 0);
    }

    #[test]
    fn test_clone() {
        let verifier1 = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        let nonce = nonce_manager.generate_nonce();
        let _ = verifier1.verify_proof(peer_id, 1024, 100, 10, &nonce, &nonce_manager);

        let verifier2 = verifier1.clone();
        // Stats should be shared
        assert_eq!(
            verifier1.stats().total_verified,
            verifier2.stats().total_verified
        );
    }

    #[test]
    fn test_bandwidth_accounting() {
        let verifier = BandwidthProofVerifier::new();
        let nonce_manager = NonceManager::new();
        let peer_id = PeerId::random();

        let nonce1 = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer_id, 1024, 100, 10, &nonce1, &nonce_manager);

        let nonce2 = nonce_manager.generate_nonce();
        let _ = verifier.verify_proof(peer_id, 2048, 100, 10, &nonce2, &nonce_manager);

        let stats = verifier.stats();
        assert_eq!(stats.total_bandwidth_bytes, 1024 + 2048);
    }
}
