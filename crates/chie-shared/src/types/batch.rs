//! Batch operation types for efficient processing in CHIE Protocol.
//!
//! This module provides types for batching operations like proof submissions,
//! content announcements, and statistics updates.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{BandwidthProof, ContentCid, PeerIdString, Points};

/// Batch submission of bandwidth proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BatchProofSubmission {
    /// List of proofs to submit.
    pub proofs: Vec<BandwidthProof>,
    /// Batch ID for tracking.
    pub batch_id: uuid::Uuid,
    /// Submitter peer ID.
    pub peer_id: PeerIdString,
    /// Submission timestamp (Unix milliseconds).
    pub timestamp_ms: i64,
}

impl BatchProofSubmission {
    /// Create a new batch proof submission.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::batch::BatchProofSubmission;
    /// use chie_shared::types::bandwidth::BandwidthProofBuilder;
    ///
    /// // Create multiple bandwidth proofs
    /// let proof1 = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .bytes_transferred(262_144)
    ///     .timestamps(1000, 1100)
    ///     .build()
    ///     .unwrap();
    ///
    /// let proof2 = BandwidthProofBuilder::new()
    ///     .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
    ///     .chunk_index(1)
    ///     .provider_peer_id("12D3KooWProvider")
    ///     .requester_peer_id("12D3KooWRequester")
    ///     .provider_public_key(vec![1u8; 32])
    ///     .requester_public_key(vec![2u8; 32])
    ///     .provider_signature(vec![3u8; 64])
    ///     .requester_signature(vec![4u8; 64])
    ///     .challenge_nonce(vec![5u8; 32])
    ///     .chunk_hash(vec![6u8; 32])
    ///     .bytes_transferred(262_144)
    ///     .timestamps(1100, 1200)
    ///     .build()
    ///     .unwrap();
    ///
    /// // Submit proofs as a batch
    /// let batch = BatchProofSubmission::new(
    ///     vec![proof1, proof2],
    ///     "12D3KooWProvider"
    /// );
    ///
    /// assert_eq!(batch.proof_count(), 2);
    /// assert_eq!(batch.total_bytes_transferred(), 524_288);
    /// assert!(!batch.is_empty());
    /// ```
    #[must_use]
    pub fn new(proofs: Vec<BandwidthProof>, peer_id: impl Into<String>) -> Self {
        Self {
            proofs,
            batch_id: uuid::Uuid::new_v4(),
            peer_id: peer_id.into(),
            timestamp_ms: crate::now_ms(),
        }
    }

    /// Get the number of proofs in the batch.
    #[must_use]
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Check if batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Calculate total bytes transferred across all proofs.
    #[must_use]
    pub fn total_bytes_transferred(&self) -> u64 {
        self.proofs.iter().map(|p| p.bytes_transferred).sum()
    }
}

/// Response to batch proof submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BatchProofResponse {
    /// Batch ID that was processed.
    pub batch_id: uuid::Uuid,
    /// Number of proofs accepted.
    pub accepted_count: usize,
    /// Number of proofs rejected.
    pub rejected_count: usize,
    /// Total reward points for accepted proofs.
    pub total_reward_points: Points,
    /// Individual results per proof.
    pub results: Vec<ProofResult>,
}

impl BatchProofResponse {
    /// Create a new batch response.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::batch::{BatchProofResponse, ProofResult};
    /// use uuid::Uuid;
    ///
    /// let batch_id = Uuid::new_v4();
    /// let mut response = BatchProofResponse::new(batch_id);
    ///
    /// // Add results
    /// response.results.push(ProofResult::accepted(0, Uuid::new_v4(), 1000));
    /// response.results.push(ProofResult::accepted(1, Uuid::new_v4(), 1500));
    /// response.results.push(ProofResult::rejected(2, "Invalid signature"));
    ///
    /// response.accepted_count = 2;
    /// response.rejected_count = 1;
    /// response.total_reward_points = 2500;
    ///
    /// assert_eq!(response.total_count(), 3);
    /// assert_eq!(response.acceptance_rate(), 2.0 / 3.0);
    /// assert!(!response.all_accepted());
    /// assert!(!response.all_rejected());
    /// ```
    #[must_use]
    pub fn new(batch_id: uuid::Uuid) -> Self {
        Self {
            batch_id,
            accepted_count: 0,
            rejected_count: 0,
            total_reward_points: 0,
            results: Vec::new(),
        }
    }

    /// Get total number of proofs processed.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.accepted_count + self.rejected_count
    }

    /// Get acceptance rate (0.0 to 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn acceptance_rate(&self) -> f64 {
        let total = self.total_count();
        if total == 0 {
            0.0
        } else {
            self.accepted_count as f64 / total as f64
        }
    }

    /// Check if all proofs were accepted.
    #[must_use]
    pub fn all_accepted(&self) -> bool {
        self.rejected_count == 0 && self.accepted_count > 0
    }

    /// Check if all proofs were rejected.
    #[must_use]
    pub fn all_rejected(&self) -> bool {
        self.accepted_count == 0 && self.rejected_count > 0
    }
}

/// Result for an individual proof in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ProofResult {
    /// Index in the original batch.
    pub index: usize,
    /// Whether the proof was accepted.
    pub accepted: bool,
    /// Proof ID if accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<uuid::Uuid>,
    /// Reward points if accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_points: Option<Points>,
    /// Rejection reason if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

impl ProofResult {
    /// Create a result for an accepted proof.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::batch::ProofResult;
    /// use uuid::Uuid;
    ///
    /// let proof_id = Uuid::new_v4();
    /// let result = ProofResult::accepted(0, proof_id, 1000);
    ///
    /// assert!(result.accepted);
    /// assert_eq!(result.index, 0);
    /// assert_eq!(result.proof_id, Some(proof_id));
    /// assert_eq!(result.reward_points, Some(1000));
    /// assert_eq!(result.rejection_reason, None);
    /// ```
    #[must_use]
    pub fn accepted(index: usize, proof_id: uuid::Uuid, reward_points: Points) -> Self {
        Self {
            index,
            accepted: true,
            proof_id: Some(proof_id),
            reward_points: Some(reward_points),
            rejection_reason: None,
        }
    }

    /// Create a result for a rejected proof.
    ///
    /// # Example
    ///
    /// ```
    /// use chie_shared::types::batch::ProofResult;
    ///
    /// let result = ProofResult::rejected(2, "Invalid signature length");
    ///
    /// assert!(!result.accepted);
    /// assert_eq!(result.index, 2);
    /// assert_eq!(result.proof_id, None);
    /// assert_eq!(result.reward_points, None);
    /// assert_eq!(result.rejection_reason, Some("Invalid signature length".to_string()));
    /// ```
    #[must_use]
    pub fn rejected(index: usize, reason: impl Into<String>) -> Self {
        Self {
            index,
            accepted: false,
            proof_id: None,
            reward_points: None,
            rejection_reason: Some(reason.into()),
        }
    }
}

/// Batch content announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BatchContentAnnouncement {
    /// List of content CIDs being announced.
    pub content_cids: Vec<ContentCid>,
    /// Peer ID of the announcing node.
    pub peer_id: PeerIdString,
    /// Batch ID for tracking.
    pub batch_id: uuid::Uuid,
    /// Announcement timestamp (Unix milliseconds).
    pub timestamp_ms: i64,
}

impl BatchContentAnnouncement {
    /// Create a new batch content announcement.
    #[must_use]
    pub fn new(content_cids: Vec<ContentCid>, peer_id: impl Into<String>) -> Self {
        Self {
            content_cids,
            peer_id: peer_id.into(),
            batch_id: uuid::Uuid::new_v4(),
            timestamp_ms: crate::now_ms(),
        }
    }

    /// Get the number of content items announced.
    #[must_use]
    pub fn content_count(&self) -> usize {
        self.content_cids.len()
    }

    /// Check if batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_cids.is_empty()
    }
}

/// Batch statistics update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BatchStatsUpdate {
    /// List of stat updates.
    pub updates: Vec<StatUpdate>,
    /// Batch ID for tracking.
    pub batch_id: uuid::Uuid,
    /// Update timestamp (Unix milliseconds).
    pub timestamp_ms: i64,
}

impl BatchStatsUpdate {
    /// Create a new batch stats update.
    #[must_use]
    pub fn new(updates: Vec<StatUpdate>) -> Self {
        Self {
            updates,
            batch_id: uuid::Uuid::new_v4(),
            timestamp_ms: crate::now_ms(),
        }
    }

    /// Get the number of updates in the batch.
    #[must_use]
    pub fn update_count(&self) -> usize {
        self.updates.len()
    }

    /// Check if batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }
}

/// Individual statistics update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StatUpdate {
    /// Metric name.
    pub metric: String,
    /// Metric value.
    pub value: f64,
    /// Associated entity (e.g., peer ID, content CID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
}

impl StatUpdate {
    /// Create a new stat update.
    #[must_use]
    pub fn new(metric: impl Into<String>, value: f64) -> Self {
        Self {
            metric: metric.into(),
            value,
            entity: None,
        }
    }

    /// Create a stat update with entity.
    #[must_use]
    pub fn with_entity(metric: impl Into<String>, value: f64, entity: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value,
            entity: Some(entity.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_proof_submission() {
        let proof1 = crate::test_helpers::create_test_proof();
        let proof2 = crate::test_helpers::create_test_proof();

        let batch = BatchProofSubmission::new(vec![proof1, proof2], "12D3KooTest");

        assert_eq!(batch.proof_count(), 2);
        assert!(!batch.is_empty());
        assert!(batch.total_bytes_transferred() > 0);
    }

    #[test]
    fn test_batch_proof_response() {
        let batch_id = uuid::Uuid::new_v4();
        let mut response = BatchProofResponse::new(batch_id);

        response.accepted_count = 8;
        response.rejected_count = 2;
        response.total_reward_points = 1000;

        assert_eq!(response.total_count(), 10);
        assert_eq!(response.acceptance_rate(), 0.8);
        assert!(!response.all_accepted());
        assert!(!response.all_rejected());
    }

    #[test]
    fn test_batch_proof_response_all_accepted() {
        let batch_id = uuid::Uuid::new_v4();
        let mut response = BatchProofResponse::new(batch_id);

        response.accepted_count = 10;
        response.rejected_count = 0;

        assert!(response.all_accepted());
        assert_eq!(response.acceptance_rate(), 1.0);
    }

    #[test]
    fn test_batch_proof_response_all_rejected() {
        let batch_id = uuid::Uuid::new_v4();
        let mut response = BatchProofResponse::new(batch_id);

        response.accepted_count = 0;
        response.rejected_count = 10;

        assert!(response.all_rejected());
        assert_eq!(response.acceptance_rate(), 0.0);
    }

    #[test]
    fn test_proof_result_accepted() {
        let proof_id = uuid::Uuid::new_v4();
        let result = ProofResult::accepted(0, proof_id, 100);

        assert!(result.accepted);
        assert_eq!(result.proof_id, Some(proof_id));
        assert_eq!(result.reward_points, Some(100));
        assert!(result.rejection_reason.is_none());
    }

    #[test]
    fn test_proof_result_rejected() {
        let result = ProofResult::rejected(1, "Invalid signature");

        assert!(!result.accepted);
        assert!(result.proof_id.is_none());
        assert!(result.reward_points.is_none());
        assert_eq!(
            result.rejection_reason,
            Some("Invalid signature".to_string())
        );
    }

    #[test]
    fn test_batch_content_announcement() {
        let cids = vec![
            "QmTest1".to_string(),
            "QmTest2".to_string(),
            "QmTest3".to_string(),
        ];
        let batch = BatchContentAnnouncement::new(cids, "12D3KooTest");

        assert_eq!(batch.content_count(), 3);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_stats_update() {
        let updates = vec![
            StatUpdate::new("bandwidth_total", 1_000_000.0),
            StatUpdate::with_entity("chunks_served", 50.0, "12D3KooTest"),
        ];

        let batch = BatchStatsUpdate::new(updates);

        assert_eq!(batch.update_count(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_stat_update() {
        let update1 = StatUpdate::new("test_metric", 42.0);
        assert_eq!(update1.metric, "test_metric");
        assert_eq!(update1.value, 42.0);
        assert!(update1.entity.is_none());

        let update2 = StatUpdate::with_entity("peer_metric", 100.0, "12D3Koo");
        assert_eq!(update2.metric, "peer_metric");
        assert_eq!(update2.value, 100.0);
        assert_eq!(update2.entity, Some("12D3Koo".to_string()));
    }

    #[test]
    fn test_batch_proof_submission_serialization() {
        let proof = crate::test_helpers::create_test_proof();
        let batch = BatchProofSubmission::new(vec![proof], "12D3KooTest");

        let json = serde_json::to_string(&batch).unwrap();
        let deserialized: BatchProofSubmission = serde_json::from_str(&json).unwrap();

        assert_eq!(batch.batch_id, deserialized.batch_id);
        assert_eq!(batch.proof_count(), deserialized.proof_count());
    }
}
