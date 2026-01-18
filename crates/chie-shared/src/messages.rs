//! Message types for inter-component communication.

use crate::{BandwidthProof, Bytes, ContentCid, PeerIdString, Points};
use serde::{Deserialize, Serialize};

/// Request to submit a bandwidth proof to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofRequest {
    /// The bandwidth proof to submit.
    pub proof: BandwidthProof,
    /// Optional metadata about the submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProofMetadata>,
}

/// Additional metadata for proof submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Client version that generated the proof.
    pub client_version: String,
    /// Node region/location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Connection type (e.g., "direct", "relay").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
}

/// Response from proof submission.
///
/// # Examples
///
/// ```
/// use chie_shared::SubmitProofResponse;
/// use uuid::Uuid;
///
/// // Accepted proof with rewards
/// let accepted = SubmitProofResponse {
///     accepted: true,
///     proof_id: Some(Uuid::new_v4()),
///     reward_points: Some(100),
///     rejection_reason: None,
/// };
/// assert!(accepted.accepted);
/// assert!(accepted.reward_points.is_some());
///
/// // Rejected proof with reason
/// let rejected = SubmitProofResponse {
///     accepted: false,
///     proof_id: None,
///     reward_points: None,
///     rejection_reason: Some("Invalid signature".to_string()),
/// };
/// assert!(!rejected.accepted);
/// assert!(rejected.rejection_reason.is_some());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofResponse {
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

/// Request to announce new content to the network.
///
/// # Examples
///
/// ```
/// use chie_shared::AnnounceContentRequest;
///
/// // Announce a 25MB content with 100 chunks
/// let request = AnnounceContentRequest {
///     content_cid: "QmExampleContent123".to_string(),
///     peer_id: "12D3KooWProvider".to_string(),
///     chunk_count: 100,
///     size_bytes: 25 * 1024 * 1024, // 25 MB
///     ttl_seconds: 7200, // 2 hours
/// };
///
/// assert_eq!(request.chunk_count, 100);
/// assert_eq!(request.size_bytes, 26_214_400);
/// assert_eq!(request.ttl_seconds, 7200);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceContentRequest {
    /// Content CID being announced.
    pub content_cid: ContentCid,
    /// Peer ID of the announcing node.
    pub peer_id: PeerIdString,
    /// Number of chunks available.
    pub chunk_count: u64,
    /// Total size in bytes.
    pub size_bytes: Bytes,
    /// TTL for the announcement (seconds).
    #[serde(default = "default_announcement_ttl")]
    pub ttl_seconds: u32,
}

fn default_announcement_ttl() -> u32 {
    3600 // 1 hour
}

/// Request to query content availability.
///
/// # Examples
///
/// ```
/// use chie_shared::QueryContentRequest;
///
/// // Query for content with default max providers (20)
/// let request = QueryContentRequest {
///     content_cid: "QmExampleContent".to_string(),
///     max_providers: 20,
/// };
///
/// assert_eq!(request.content_cid, "QmExampleContent");
/// assert_eq!(request.max_providers, 20);
///
/// // Query with custom limit
/// let limited = QueryContentRequest {
///     content_cid: "QmAnotherContent".to_string(),
///     max_providers: 5,
/// };
/// assert_eq!(limited.max_providers, 5);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryContentRequest {
    /// Content CID to query.
    pub content_cid: ContentCid,
    /// Maximum number of providers to return.
    #[serde(default = "default_max_providers")]
    pub max_providers: usize,
}

fn default_max_providers() -> usize {
    20
}

/// Response to content query.
///
/// # Examples
///
/// ```
/// use chie_shared::{QueryContentResponse, ContentProvider};
///
/// // Response with multiple providers
/// let response = QueryContentResponse {
///     content_cid: "QmExample".to_string(),
///     providers: vec![
///         ContentProvider {
///             peer_id: "12D3Koo1".to_string(),
///             addresses: vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
///             available_chunks: Some(vec![0, 1, 2, 3]),
///             reputation: Some(98.5),
///             last_seen: None,
///         },
///         ContentProvider {
///             peer_id: "12D3Koo2".to_string(),
///             addresses: vec!["/ip4/5.6.7.8/tcp/4001".to_string()],
///             available_chunks: None,
///             reputation: Some(87.0),
///             last_seen: None,
///         },
///     ],
///     total_providers: 5,
/// };
///
/// assert_eq!(response.providers.len(), 2);
/// assert_eq!(response.total_providers, 5);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryContentResponse {
    /// Content CID that was queried.
    pub content_cid: ContentCid,
    /// List of providers.
    pub providers: Vec<ContentProvider>,
    /// Total number of providers available.
    pub total_providers: usize,
}

/// Information about a content provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProvider {
    /// Provider's peer ID.
    pub peer_id: PeerIdString,
    /// Provider's multiaddresses.
    pub addresses: Vec<String>,
    /// Chunks available from this provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_chunks: Option<Vec<u64>>,
    /// Provider reputation score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<f32>,
    /// Last seen timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to update node statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNodeStatsRequest {
    /// Node's peer ID.
    pub peer_id: PeerIdString,
    /// Bandwidth uploaded (bytes).
    pub bandwidth_uploaded: Bytes,
    /// Bandwidth downloaded (bytes).
    pub bandwidth_downloaded: Bytes,
    /// Number of chunks served.
    pub chunks_served: u64,
    /// Storage used (bytes).
    pub storage_used: Bytes,
    /// Uptime (seconds).
    pub uptime_seconds: u64,
}

/// Heartbeat message from node to coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    /// Node's peer ID.
    pub peer_id: PeerIdString,
    /// Current node status.
    pub status: crate::NodeStatus,
    /// Available storage (bytes).
    pub available_storage: Bytes,
    /// Available bandwidth (bps).
    pub available_bandwidth: u64,
    /// Number of active connections.
    pub active_connections: u32,
    /// Timestamp of the heartbeat.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl NodeHeartbeat {
    /// Create a new heartbeat with current timestamp.
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{NodeHeartbeat, NodeStatus};
    ///
    /// // Create online heartbeat
    /// let heartbeat = NodeHeartbeat::new("12D3KooWNode", NodeStatus::Online);
    /// assert_eq!(heartbeat.peer_id, "12D3KooWNode");
    /// assert_eq!(heartbeat.status, NodeStatus::Online);
    /// assert_eq!(heartbeat.available_storage, 0);
    ///
    /// // Create custom heartbeat with resources
    /// let mut custom = NodeHeartbeat::new("12D3KooWOther", NodeStatus::Online);
    /// custom.available_storage = 100 * 1024 * 1024 * 1024; // 100 GB
    /// custom.available_bandwidth = 10_000_000; // 10 Mbps
    /// custom.active_connections = 42;
    /// assert_eq!(custom.active_connections, 42);
    /// ```
    pub fn new(peer_id: impl Into<String>, status: crate::NodeStatus) -> Self {
        Self {
            peer_id: peer_id.into(),
            status,
            available_storage: 0,
            available_bandwidth: 0,
            active_connections: 0,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Request to get earnings information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEarningsRequest {
    /// Peer ID to get earnings for.
    pub peer_id: PeerIdString,
    /// Start of time range (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// End of time range (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response with earnings information.
///
/// # Examples
///
/// ```
/// use chie_shared::{GetEarningsResponse, ContentEarnings};
///
/// // Earnings summary with breakdown
/// let earnings = GetEarningsResponse {
///     total_points: 50_000,
///     total_bandwidth: 100 * 1024 * 1024 * 1024, // 100 GB
///     proof_count: 500,
///     avg_per_proof: 100,
///     by_content: Some(vec![
///         ContentEarnings {
///             content_cid: "QmPopular".to_string(),
///             points_earned: 30_000,
///             bandwidth_served: 60 * 1024 * 1024 * 1024,
///             chunks_served: 300,
///         },
///         ContentEarnings {
///             content_cid: "QmRare".to_string(),
///             points_earned: 20_000,
///             bandwidth_served: 40 * 1024 * 1024 * 1024,
///             chunks_served: 200,
///         },
///     ]),
/// };
///
/// assert_eq!(earnings.total_points, 50_000);
/// assert_eq!(earnings.proof_count, 500);
/// assert_eq!(earnings.avg_per_proof, 100);
/// assert!(earnings.by_content.is_some());
/// assert_eq!(earnings.by_content.as_ref().unwrap().len(), 2);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEarningsResponse {
    /// Total points earned.
    pub total_points: Points,
    /// Total bandwidth served (bytes).
    pub total_bandwidth: Bytes,
    /// Number of successful proofs.
    pub proof_count: u64,
    /// Average earnings per proof.
    pub avg_per_proof: Points,
    /// Earnings breakdown by content (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by_content: Option<Vec<ContentEarnings>>,
}

/// Earnings for a specific content item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentEarnings {
    /// Content CID.
    pub content_cid: ContentCid,
    /// Points earned from this content.
    pub points_earned: Points,
    /// Bandwidth served for this content (bytes).
    pub bandwidth_served: Bytes,
    /// Number of chunks served.
    pub chunks_served: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_proof_request_serialization() {
        let proof = crate::test_helpers::create_test_proof();
        let request = SubmitProofRequest {
            proof,
            metadata: Some(ProofMetadata {
                client_version: "1.0.0".to_string(),
                region: Some("us-west".to_string()),
                connection_type: Some("direct".to_string()),
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SubmitProofRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.proof.content_cid, deserialized.proof.content_cid);
    }

    #[test]
    fn test_announce_content_request() {
        let request = AnnounceContentRequest {
            content_cid: "QmTest123".to_string(),
            peer_id: "12D3KooTest".to_string(),
            chunk_count: 100,
            size_bytes: 26_214_400,
            ttl_seconds: 7200,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AnnounceContentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.content_cid, deserialized.content_cid);
        assert_eq!(request.chunk_count, deserialized.chunk_count);
    }

    #[test]
    fn test_node_heartbeat() {
        let heartbeat = NodeHeartbeat::new("12D3KooTest", crate::NodeStatus::Online);
        assert_eq!(heartbeat.peer_id, "12D3KooTest");
        assert_eq!(heartbeat.status, crate::NodeStatus::Online);

        let json = serde_json::to_string(&heartbeat).unwrap();
        let deserialized: NodeHeartbeat = serde_json::from_str(&json).unwrap();
        assert_eq!(heartbeat.peer_id, deserialized.peer_id);
    }

    #[test]
    fn test_query_content_response() {
        let response = QueryContentResponse {
            content_cid: "QmTest".to_string(),
            providers: vec![ContentProvider {
                peer_id: "12D3Koo1".to_string(),
                addresses: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
                available_chunks: Some(vec![0, 1, 2]),
                reputation: Some(95.5),
                last_seen: Some(chrono::Utc::now()),
            }],
            total_providers: 5,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: QueryContentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.providers.len(), deserialized.providers.len());
    }
}
