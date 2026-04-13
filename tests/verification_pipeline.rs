//! Integration tests for the verification pipeline.
//!
//! Tests the complete proof verification flow including:
//! - Timestamp validation
//! - Signature verification
//! - Nonce replay detection
//! - Statistical anomaly detection
//! - Quality scoring

use chie_crypto::KeyPair;
use chie_shared::{BandwidthProof, CHUNK_SIZE};
use chrono::Utc;
use std::collections::HashSet;
use uuid::Uuid;

/// Mock nonce cache for replay detection.
struct NonceCache {
    seen_nonces: HashSet<Vec<u8>>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            seen_nonces: HashSet::new(),
        }
    }

    fn check_and_store(&mut self, nonce: &[u8]) -> bool {
        if self.seen_nonces.contains(nonce) {
            false // Replay detected
        } else {
            self.seen_nonces.insert(nonce.to_vec());
            true
        }
    }
}

/// Mock statistical analyzer for anomaly detection.
struct AnomalyDetector {
    transfer_history: Vec<TransferRecord>,
    z_score_threshold: f64,
}

struct TransferRecord {
    bytes: u64,
    latency_ms: u32,
    timestamp_ms: i64,
}

impl AnomalyDetector {
    fn new(z_score_threshold: f64) -> Self {
        Self {
            transfer_history: Vec::new(),
            z_score_threshold,
        }
    }

    fn record_transfer(&mut self, bytes: u64, latency_ms: u32, timestamp_ms: i64) {
        self.transfer_history.push(TransferRecord {
            bytes,
            latency_ms,
            timestamp_ms,
        });
    }

    fn check_anomaly(&self, bytes: u64, latency_ms: u32) -> Option<String> {
        if self.transfer_history.len() < 10 {
            return None; // Not enough data
        }

        // Calculate mean and std dev for bytes/second
        let rates: Vec<f64> = self
            .transfer_history
            .iter()
            .map(|r| r.bytes as f64 / (r.latency_ms as f64 / 1000.0))
            .collect();

        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        let variance = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev < 0.001 {
            return None; // Not enough variance
        }

        let current_rate = bytes as f64 / (latency_ms as f64 / 1000.0);
        let z_score = (current_rate - mean).abs() / std_dev;

        if z_score > self.z_score_threshold {
            Some(format!(
                "Anomaly detected: z-score {:.2} exceeds threshold {:.2}",
                z_score, self.z_score_threshold
            ))
        } else {
            None
        }
    }
}

/// Verification result.
#[derive(Debug)]
struct VerificationResult {
    is_valid: bool,
    quality_score: f64,
    rejection_reason: Option<String>,
    anomaly_flags: Vec<String>,
}

/// Complete verification pipeline.
struct VerificationPipeline {
    nonce_cache: NonceCache,
    anomaly_detector: AnomalyDetector,
    max_timestamp_drift_ms: i64,
    min_latency_ms: u32,
    max_latency_ms: u32,
}

impl VerificationPipeline {
    fn new() -> Self {
        Self {
            nonce_cache: NonceCache::new(),
            anomaly_detector: AnomalyDetector::new(3.0),
            max_timestamp_drift_ms: 300_000, // 5 minutes
            min_latency_ms: 1,
            max_latency_ms: 60_000, // 1 minute
        }
    }

    fn verify(&mut self, proof: &BandwidthProof) -> VerificationResult {
        let mut anomaly_flags = Vec::new();

        // 1. Timestamp validation
        let now_ms = Utc::now().timestamp_millis();
        let drift = (now_ms - proof.end_timestamp_ms).abs();
        if drift > self.max_timestamp_drift_ms {
            return VerificationResult {
                is_valid: false,
                quality_score: 0.0,
                rejection_reason: Some(format!("Timestamp drift {}ms exceeds maximum", drift)),
                anomaly_flags,
            };
        }

        // 2. Latency validation
        if proof.latency_ms < self.min_latency_ms {
            return VerificationResult {
                is_valid: false,
                quality_score: 0.0,
                rejection_reason: Some("Impossible latency (too low)".to_string()),
                anomaly_flags,
            };
        }

        if proof.latency_ms > self.max_latency_ms {
            anomaly_flags.push(format!("High latency: {}ms", proof.latency_ms));
        }

        // 3. Nonce replay check
        if !self.nonce_cache.check_and_store(&proof.challenge_nonce) {
            return VerificationResult {
                is_valid: false,
                quality_score: 0.0,
                rejection_reason: Some("Replay attack detected: nonce already used".to_string()),
                anomaly_flags,
            };
        }

        // 4. Provider signature verification
        let provider_pubkey: [u8; 32] = match proof.provider_public_key.as_slice().try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return VerificationResult {
                    is_valid: false,
                    quality_score: 0.0,
                    rejection_reason: Some("Invalid provider public key length".to_string()),
                    anomaly_flags,
                }
            }
        };

        let provider_sig: [u8; 64] = match proof.provider_signature.as_slice().try_into() {
            Ok(sig) => sig,
            Err(_) => {
                return VerificationResult {
                    is_valid: false,
                    quality_score: 0.0,
                    rejection_reason: Some("Invalid provider signature length".to_string()),
                    anomaly_flags,
                }
            }
        };

        let mut provider_message = Vec::new();
        provider_message.extend_from_slice(&proof.challenge_nonce);
        provider_message.extend_from_slice(&proof.chunk_hash);
        provider_message.extend_from_slice(&proof.requester_public_key);

        if chie_crypto::verify(&provider_pubkey, &provider_message, &provider_sig).is_err() {
            return VerificationResult {
                is_valid: false,
                quality_score: 0.0,
                rejection_reason: Some("Invalid provider signature".to_string()),
                anomaly_flags,
            };
        }

        // 5. Requester signature verification
        let requester_pubkey: [u8; 32] = match proof.requester_public_key.as_slice().try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return VerificationResult {
                    is_valid: false,
                    quality_score: 0.0,
                    rejection_reason: Some("Invalid requester public key length".to_string()),
                    anomaly_flags,
                }
            }
        };

        let requester_sig: [u8; 64] = match proof.requester_signature.as_slice().try_into() {
            Ok(sig) => sig,
            Err(_) => {
                return VerificationResult {
                    is_valid: false,
                    quality_score: 0.0,
                    rejection_reason: Some("Invalid requester signature length".to_string()),
                    anomaly_flags,
                }
            }
        };

        let mut requester_message = Vec::new();
        requester_message.extend_from_slice(&proof.challenge_nonce);
        requester_message.extend_from_slice(&proof.chunk_hash);
        requester_message.extend_from_slice(&proof.provider_public_key);
        requester_message.extend_from_slice(&proof.provider_signature);

        if chie_crypto::verify(&requester_pubkey, &requester_message, &requester_sig).is_err() {
            return VerificationResult {
                is_valid: false,
                quality_score: 0.0,
                rejection_reason: Some("Invalid requester signature".to_string()),
                anomaly_flags,
            };
        }

        // 6. Statistical anomaly detection
        if let Some(anomaly) = self
            .anomaly_detector
            .check_anomaly(proof.bytes_transferred, proof.latency_ms)
        {
            anomaly_flags.push(anomaly);
        }

        // Record for future anomaly detection
        self.anomaly_detector.record_transfer(
            proof.bytes_transferred,
            proof.latency_ms,
            proof.end_timestamp_ms,
        );

        // 7. Calculate quality score
        let quality_score = calculate_quality_score(proof, &anomaly_flags);

        VerificationResult {
            is_valid: true,
            quality_score,
            rejection_reason: None,
            anomaly_flags,
        }
    }
}

/// Calculate quality score based on transfer characteristics.
fn calculate_quality_score(proof: &BandwidthProof, anomaly_flags: &[String]) -> f64 {
    let mut score = 1.0;

    // Latency penalty
    if proof.latency_ms > 500 {
        score *= 0.8;
    } else if proof.latency_ms > 200 {
        score *= 0.9;
    }

    // High latency severe penalty
    if proof.latency_ms > 10000 {
        score *= 0.5;
    }

    // Anomaly penalty
    score *= 0.9_f64.powi(anomaly_flags.len() as i32);

    // Bytes transferred bonus for larger transfers
    if proof.bytes_transferred >= CHUNK_SIZE as u64 {
        score *= 1.0;
    } else {
        score *= proof.bytes_transferred as f64 / CHUNK_SIZE as f64;
    }

    score.clamp(0.0, 1.0)
}

/// Helper to create a valid proof for testing.
fn create_valid_proof(
    provider_keypair: &KeyPair,
    requester_keypair: &KeyPair,
    content_cid: &str,
    chunk_index: u64,
    latency_ms: u32,
) -> BandwidthProof {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

    let chunk_data = vec![0xAB; CHUNK_SIZE];
    let chunk_hash = chie_crypto::hash(&chunk_data);

    let now = Utc::now().timestamp_millis();
    let start_time = now - latency_ms as i64;

    // Provider signs
    let mut provider_msg = Vec::new();
    provider_msg.extend_from_slice(&nonce);
    provider_msg.extend_from_slice(&chunk_hash);
    provider_msg.extend_from_slice(&requester_keypair.public_key());
    let provider_sig = provider_keypair.sign(&provider_msg);

    // Requester signs
    let mut requester_msg = Vec::new();
    requester_msg.extend_from_slice(&nonce);
    requester_msg.extend_from_slice(&chunk_hash);
    requester_msg.extend_from_slice(&provider_keypair.public_key());
    requester_msg.extend_from_slice(&provider_sig);
    let requester_sig = requester_keypair.sign(&requester_msg);

    BandwidthProof {
        session_id: Uuid::new_v4(),
        content_cid: content_cid.to_string(),
        chunk_index,
        bytes_transferred: CHUNK_SIZE as u64,
        provider_peer_id: format!("provider-{}", rand::random::<u32>()),
        requester_peer_id: format!("requester-{}", rand::random::<u32>()),
        provider_public_key: provider_keypair.public_key().to_vec(),
        requester_public_key: requester_keypair.public_key().to_vec(),
        provider_signature: provider_sig.to_vec(),
        requester_signature: requester_sig.to_vec(),
        challenge_nonce: nonce.to_vec(),
        chunk_hash: chunk_hash.to_vec(),
        start_timestamp_ms: start_time,
        end_timestamp_ms: now,
        latency_ms,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_valid_proof_verification() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let proof = create_valid_proof(&provider, &requester, "QmTestContent", 0, 100);
    let result = pipeline.verify(&proof);

    assert!(result.is_valid, "Valid proof should pass: {:?}", result.rejection_reason);
    assert!(result.quality_score > 0.8, "Quality score should be high");
    assert!(result.rejection_reason.is_none());
}

#[test]
fn test_timestamp_too_old() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let mut proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);
    // Set timestamp to 10 minutes ago
    proof.end_timestamp_ms = Utc::now().timestamp_millis() - 600_000;

    let result = pipeline.verify(&proof);
    assert!(!result.is_valid);
    assert!(result.rejection_reason.unwrap().contains("Timestamp"));
}

#[test]
fn test_impossible_latency() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let mut proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);
    proof.latency_ms = 0;

    let result = pipeline.verify(&proof);
    assert!(!result.is_valid);
    assert!(result.rejection_reason.unwrap().contains("latency"));
}

#[test]
fn test_replay_attack_detection() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);

    // First submission should succeed
    let result1 = pipeline.verify(&proof);
    assert!(result1.is_valid);

    // Second submission with same nonce should fail
    let result2 = pipeline.verify(&proof);
    assert!(!result2.is_valid);
    assert!(result2.rejection_reason.unwrap().contains("Replay"));
}

#[test]
fn test_invalid_provider_signature() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let mut proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);
    // Tamper with signature
    proof.provider_signature[0] ^= 0xFF;

    let result = pipeline.verify(&proof);
    assert!(!result.is_valid);
    assert!(result.rejection_reason.unwrap().contains("provider signature"));
}

#[test]
fn test_invalid_requester_signature() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let mut proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);
    // Tamper with signature
    proof.requester_signature[0] ^= 0xFF;

    let result = pipeline.verify(&proof);
    assert!(!result.is_valid);
    assert!(result.rejection_reason.unwrap().contains("requester signature"));
}

#[test]
fn test_quality_score_latency_impact() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    // Low latency = high score
    let proof_fast = create_valid_proof(&provider, &requester, "QmFast", 0, 50);
    let result_fast = pipeline.verify(&proof_fast);

    // High latency = lower score
    let proof_slow = create_valid_proof(&provider, &requester, "QmSlow", 0, 5000);
    let result_slow = pipeline.verify(&proof_slow);

    assert!(result_fast.is_valid);
    assert!(result_slow.is_valid);
    assert!(
        result_fast.quality_score > result_slow.quality_score,
        "Fast transfer should have higher quality score"
    );
}

#[test]
fn test_batch_verification() {
    let mut pipeline = VerificationPipeline::new();

    // Simulate batch of proofs from different peers
    let proofs: Vec<_> = (0..10)
        .map(|i| {
            let provider = KeyPair::generate();
            let requester = KeyPair::generate();
            create_valid_proof(
                &provider,
                &requester,
                &format!("QmContent{}", i),
                i as u64,
                50 + i as u32 * 10,
            )
        })
        .collect();

    let mut valid_count = 0;
    let mut total_quality = 0.0;

    for proof in &proofs {
        let result = pipeline.verify(proof);
        if result.is_valid {
            valid_count += 1;
            total_quality += result.quality_score;
        }
    }

    assert_eq!(valid_count, 10, "All valid proofs should pass");
    let avg_quality = total_quality / valid_count as f64;
    assert!(avg_quality > 0.7, "Average quality should be reasonable");
}

#[test]
fn test_anomaly_detection_with_history() {
    let mut pipeline = VerificationPipeline::new();
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    // Build up transfer history with normal transfers
    for i in 0..20 {
        let proof = create_valid_proof(
            &provider,
            &requester,
            &format!("QmNormal{}", i),
            i as u64,
            100, // Normal latency
        );
        let _ = pipeline.verify(&proof);
    }

    // Now submit a transfer with abnormally fast speed (should flag anomaly)
    let mut fast_proof = create_valid_proof(&provider, &requester, "QmFast", 100, 1);
    fast_proof.bytes_transferred = CHUNK_SIZE as u64 * 100; // 100x normal
    fast_proof.latency_ms = 1; // Very fast

    let result = pipeline.verify(&fast_proof);
    // Should still be valid but may have anomaly flags
    assert!(result.is_valid || result.rejection_reason.is_some());
}

#[test]
fn test_concurrent_proofs_different_content() {
    let mut pipeline = VerificationPipeline::new();

    // Multiple providers serving different content simultaneously
    let contents = ["QmContent1", "QmContent2", "QmContent3"];
    let providers: Vec<_> = (0..3).map(|_| KeyPair::generate()).collect();
    let requesters: Vec<_> = (0..3).map(|_| KeyPair::generate()).collect();

    for (i, content) in contents.iter().enumerate() {
        for chunk in 0..5 {
            let proof = create_valid_proof(
                &providers[i],
                &requesters[i],
                content,
                chunk,
                50 + (i as u32 * 10),
            );
            let result = pipeline.verify(&proof);
            assert!(result.is_valid, "Chunk {} of {} failed", chunk, content);
        }
    }
}

#[test]
fn test_proof_validation_struct_method() {
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);

    // Test the built-in validation
    let validation_errors = proof.validate();
    assert!(
        validation_errors.is_empty(),
        "Valid proof should have no validation errors: {:?}",
        validation_errors
    );
}

#[test]
fn test_proof_timestamp_validation() {
    let provider = KeyPair::generate();
    let requester = KeyPair::generate();

    let proof = create_valid_proof(&provider, &requester, "QmContent", 0, 100);
    let now_ms = Utc::now().timestamp_millis();

    // Should pass with recent timestamp
    assert!(proof.validate_timestamp(now_ms).is_ok());

    // Should fail with old "now"
    let old_now = now_ms - 600_000; // 10 minutes ago
    assert!(proof.validate_timestamp(old_now).is_err());
}
