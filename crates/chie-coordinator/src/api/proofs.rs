//! Bandwidth proof submission endpoint.

use axum::{Json, extract::State, http::StatusCode};
use chie_shared::BandwidthProof;
use serde::Serialize;

use crate::AppState;

/// Response for proof submission.
#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub accepted: bool,
    pub reward: Option<u64>,
    pub message: String,
    pub quality_score: Option<f64>,
}

/// Submit a bandwidth proof for verification.
pub(super) async fn submit_proof(
    State(state): State<AppState>,
    Json(proof): Json<BandwidthProof>,
) -> Result<Json<ProofResponse>, (StatusCode, String)> {
    tracing::info!(
        "Received proof: session={}, bytes={}",
        proof.session_id,
        proof.bytes_transferred
    );

    // Validate proof structure
    if let Err(errors) = proof.validate() {
        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: format!("Validation failed: {:?}", errors),
            quality_score: None,
        }));
    }

    // Validate timestamp against current time
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Err(e) = proof.validate_timestamp(now_ms) {
        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: format!("Timestamp validation failed: {}", e),
            quality_score: None,
        }));
    }

    // Run full verification pipeline
    let verification_result = match state.verification.verify_and_store(&proof).await {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Verification error: {}", e);
            return Ok(Json(ProofResponse {
                accepted: false,
                reward: None,
                message: format!("Verification error: {}", e),
                quality_score: None,
            }));
        }
    };

    // Check for critical anomalies (potential fraud)
    let has_critical_anomaly = verification_result
        .anomalies
        .iter()
        .any(|a| matches!(a.severity, crate::verification::Severity::Critical));

    if has_critical_anomaly {
        // Apply severe fraud penalty
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::FraudDetected,
                Some(serde_json::json!({
                    "anomalies": verification_result.anomalies.iter()
                        .map(|a| a.description.clone())
                        .collect::<Vec<_>>(),
                    "session_id": proof.session_id,
                })),
            )
            .await
        {
            tracing::error!("Failed to record fraud detection in reputation: {}", e);
        } else {
            // Record fraud-reputation integration metrics
            crate::metrics::record_fraud_reputation_integration("critical_anomaly", -50);

            tracing::warn!(
                "Fraud detected: peer_id={}, anomalies={:?}",
                proof.provider_peer_id,
                verification_result.anomalies
            );
        }
    }

    if !verification_result.is_valid {
        // Update reputation: proof verification failed
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::ProofFailed,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for failed proof: {}", e);
        } else {
            // Record metrics for failed proof
            crate::metrics::record_reputation_event("proof_failed", -10);
        }

        return Ok(Json(ProofResponse {
            accepted: false,
            reward: None,
            message: verification_result
                .rejection_reason
                .unwrap_or_else(|| "Proof rejected".to_string()),
            quality_score: Some(verification_result.quality_score),
        }));
    }

    // Get node reputation before update (for change detection)
    let old_reputation = state
        .reputation_manager
        .get_reputation(&proof.provider_peer_id)
        .await
        .ok()
        .flatten();

    // Update reputation: proof verification succeeded
    if let Err(e) = state
        .reputation_manager
        .record_event(
            proof.provider_peer_id.clone(),
            crate::node_reputation::ReputationEvent::ProofVerified,
            None,
        )
        .await
    {
        tracing::warn!("Failed to update reputation for verified proof: {}", e);
    } else {
        // Record metrics for successful reputation update
        crate::metrics::record_reputation_event("proof_verified", 5);
    }

    // Check for reputation changes and trigger webhooks if needed
    if let Ok(Some(new_reputation)) = state
        .reputation_manager
        .get_reputation(&proof.provider_peer_id)
        .await
    {
        // Trigger webhook if trust level degraded significantly
        if let Some(old_rep) = old_reputation {
            if new_reputation.trust_level < old_rep.trust_level {
                tracing::warn!(
                    "Node reputation degraded: peer_id={}, old={:?}, new={:?}",
                    proof.provider_peer_id,
                    old_rep.trust_level,
                    new_reputation.trust_level
                );

                // Record trust level change metric
                crate::metrics::record_trust_level_change(
                    old_rep.trust_level.as_str(),
                    new_reputation.trust_level.as_str(),
                );

                // Trigger webhook for health degradation
                let payload = serde_json::json!({
                    "peer_id": proof.provider_peer_id,
                    "old_trust_level": old_rep.trust_level.as_str(),
                    "new_trust_level": new_reputation.trust_level.as_str(),
                    "old_score": old_rep.score,
                    "new_score": new_reputation.score,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                state
                    .webhook_manager
                    .trigger_event(crate::WebhookEvent::HealthDegraded, payload)
                    .await;
            }

            // Trigger webhook if node became untrusted
            if new_reputation.trust_level == crate::node_reputation::TrustLevel::Untrusted
                && old_rep.trust_level != crate::node_reputation::TrustLevel::Untrusted
            {
                let payload = serde_json::json!({
                    "peer_id": proof.provider_peer_id,
                    "trust_level": new_reputation.trust_level.as_str(),
                    "score": new_reputation.score,
                    "reason": "reputation_too_low",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                state
                    .webhook_manager
                    .trigger_event(crate::WebhookEvent::NodeSuspended, payload)
                    .await;
            }
        }

        // Record reputation score distribution
        crate::metrics::record_reputation_score(new_reputation.score);
    }

    // Additional reputation updates based on quality and transfer speed
    let duration_secs = proof.latency_ms as f64 / 1000.0;
    let speed_mbps = if duration_secs > 0.0 {
        (proof.bytes_transferred as f64) / duration_secs / (1024.0 * 1024.0)
    } else {
        0.0
    };

    // High quality bandwidth (quality > 0.95 and speed > 50 MB/s)
    if verification_result.quality_score > 0.95 && speed_mbps > 50.0 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::HighQualityBandwidth,
                None,
            )
            .await
        {
            tracing::warn!(
                "Failed to update reputation for high quality bandwidth: {}",
                e
            );
        }
    }
    // Low quality bandwidth (quality < 0.5 or very slow speed)
    else if verification_result.quality_score < 0.5
        || (speed_mbps < 1.0 && proof.bytes_transferred > 1_000_000)
    {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::LowQualityBandwidth,
                None,
            )
            .await
        {
            tracing::warn!(
                "Failed to update reputation for low quality bandwidth: {}",
                e
            );
        }
    }

    // Fast transfer (latency < 100ms and reasonable size)
    if proof.latency_ms < 100 && proof.bytes_transferred > 100_000 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::FastTransfer,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for fast transfer: {}", e);
        }
    }
    // Slow transfer (latency > 1000ms for small file)
    else if proof.latency_ms > 1000 && proof.bytes_transferred < 10_000_000 {
        if let Err(e) = state
            .reputation_manager
            .record_event(
                proof.provider_peer_id.clone(),
                crate::node_reputation::ReputationEvent::SlowTransfer,
                None,
            )
            .await
        {
            tracing::warn!("Failed to update reputation for slow transfer: {}", e);
        }
    }

    // Lookup provider and content info for reward calculation
    use crate::db::{ContentRepository, UserRepository};
    let provider_user =
        match UserRepository::find_by_peer_id(&state.db, &proof.provider_peer_id).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                tracing::warn!("Provider not found for peer_id: {}", proof.provider_peer_id);
                return Ok(Json(ProofResponse {
                    accepted: true,
                    reward: None,
                    message: "Proof verified but provider not registered".to_string(),
                    quality_score: Some(verification_result.quality_score),
                }));
            }
            Err(e) => {
                tracing::error!("Database error looking up provider: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                ));
            }
        };

    let content = match ContentRepository::find_by_cid(&state.db, &proof.content_cid).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!("Content not found for cid: {}", proof.content_cid);
            return Ok(Json(ProofResponse {
                accepted: true,
                reward: None,
                message: "Proof verified but content not registered".to_string(),
                quality_score: Some(verification_result.quality_score),
            }));
        }
        Err(e) => {
            tracing::error!("Database error looking up content: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ));
        }
    };

    // Calculate and distribute rewards
    let distribution = match state
        .rewards
        .calculate_and_distribute(
            &proof,
            proof.session_id,
            verification_result.quality_score,
            provider_user.id,
            content.creator_id,
        )
        .await
    {
        Ok(dist) => dist,
        Err(e) => {
            tracing::error!("Reward calculation error: {}", e);
            return Ok(Json(ProofResponse {
                accepted: true,
                reward: None,
                message: format!("Proof verified but reward calculation failed: {}", e),
                quality_score: Some(verification_result.quality_score),
            }));
        }
    };

    // Update node transfer stats
    use crate::db::NodeRepository;
    if let Ok(Some(node)) =
        NodeRepository::find_by_peer_id(&state.db, &proof.provider_peer_id).await
    {
        if let Err(e) = NodeRepository::record_transfer(
            &state.db,
            node.id,
            proof.bytes_transferred as i64,
            true,
        )
        .await
        {
            tracing::warn!("Failed to record node transfer stats: {}", e);
        }
    }

    Ok(Json(ProofResponse {
        accepted: true,
        reward: Some(distribution.provider_reward),
        message: format!(
            "Proof verified and rewarded. Total: {} points (provider: {}, creator: {})",
            distribution.total_distributed,
            distribution.provider_reward,
            distribution.creator_reward
        ),
        quality_score: Some(verification_result.quality_score),
    }))
}
