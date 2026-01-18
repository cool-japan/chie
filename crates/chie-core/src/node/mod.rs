//! Node management for CHIE Protocol.

use crate::storage::{ChunkStorage, StorageError};
use chie_crypto::KeyPair;
use chie_shared::{BandwidthProof, ChunkRequest, ChunkResponse, ContentCid, Points};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for a CHIE node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Maximum storage to allocate (bytes).
    pub max_storage_bytes: u64,

    /// Maximum bandwidth to provide (bytes/second).
    pub max_bandwidth_bps: u64,

    /// Coordinator API endpoint.
    pub coordinator_url: String,

    /// Storage path for chunk data.
    pub storage_path: PathBuf,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
            max_bandwidth_bps: 100 * 1024 * 1024 / 8,   // 100 Mbps
            coordinator_url: "https://coordinator.chie.network".to_string(),
            storage_path: PathBuf::from("./chie-storage"),
        }
    }
}

/// Pinned content metadata.
#[derive(Debug, Clone)]
pub struct PinnedContent {
    /// Content CID.
    pub cid: ContentCid,

    /// Size in bytes.
    pub size_bytes: u64,

    /// Encryption key for this content.
    pub encryption_key: [u8; 32],

    /// Expected revenue per GB.
    pub predicted_revenue_per_gb: f64,
}

/// Error type for ContentNode operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Content not found: {0}")]
    ContentNotFound(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Proof submission failed: {0}")]
    ProofSubmission(String),
}

/// CHIE node instance.
///
/// # Examples
///
/// ```
/// use chie_core::{ContentNode, NodeConfig, PinnedContent};
/// use std::path::PathBuf;
///
/// let config = NodeConfig {
///     storage_path: PathBuf::from("/tmp/chie-test"),
///     max_storage_bytes: 10 * 1024 * 1024,
///     max_bandwidth_bps: 100 * 1024 * 1024 / 8,
///     coordinator_url: "https://coordinator.chie.network".to_string(),
/// };
///
/// let mut node = ContentNode::new(config);
///
/// // Pin some content
/// let content = PinnedContent {
///     cid: "QmTest123".to_string(),
///     size_bytes: 1024,
///     encryption_key: [0u8; 32],
///     predicted_revenue_per_gb: 10.0,
/// };
/// node.pin_content(content);
///
/// assert_eq!(node.pinned_count(), 1);
/// assert!(node.has_content(&"QmTest123".to_string()));
/// ```
pub struct ContentNode {
    /// Node configuration.
    config: NodeConfig,

    /// Cryptographic key pair (wrapped in Arc for concurrent access).
    keypair: Arc<KeyPair>,

    /// Pinned content (in-memory metadata).
    pinned_contents: HashMap<ContentCid, PinnedContent>,

    /// Total earnings accumulated.
    earnings: Points,

    /// Chunk storage backend.
    storage: Option<Arc<RwLock<ChunkStorage>>>,

    /// HTTP client with connection pooling for proof submission.
    http_client: reqwest::Client,
}

impl ContentNode {
    /// Create a new content node.
    pub fn new(config: NodeConfig) -> Self {
        // Create HTTP client with connection pooling
        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            config,
            keypair: Arc::new(KeyPair::generate()),
            pinned_contents: HashMap::new(),
            earnings: 0,
            storage: None,
            http_client,
        }
    }

    /// Create a new content node with storage backend.
    pub async fn with_storage(config: NodeConfig) -> Result<Self, NodeError> {
        let storage =
            ChunkStorage::new(config.storage_path.clone(), config.max_storage_bytes).await?;

        // Create HTTP client with connection pooling
        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| NodeError::Network(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self {
            config,
            keypair: Arc::new(KeyPair::generate()),
            pinned_contents: HashMap::new(),
            earnings: 0,
            storage: Some(Arc::new(RwLock::new(storage))),
            http_client,
        })
    }

    /// Set the storage backend.
    #[inline]
    pub fn set_storage(&mut self, storage: Arc<RwLock<ChunkStorage>>) {
        self.storage = Some(storage);
    }

    /// Get a reference to the storage backend.
    #[inline]
    pub fn storage(&self) -> Option<&Arc<RwLock<ChunkStorage>>> {
        self.storage.as_ref()
    }

    /// Get the node's public key.
    #[inline]
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }

    /// Get total earnings.
    #[inline]
    pub fn earnings(&self) -> Points {
        self.earnings
    }

    /// Get the node configuration.
    #[inline]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Pin content for distribution.
    #[inline]
    pub fn pin_content(&mut self, content: PinnedContent) {
        self.pinned_contents.insert(content.cid.clone(), content);
    }

    /// Unpin content.
    #[inline]
    pub fn unpin_content(&mut self, cid: &ContentCid) -> Option<PinnedContent> {
        self.pinned_contents.remove(cid)
    }

    /// Check if content is pinned.
    #[inline]
    pub fn has_content(&self, cid: &ContentCid) -> bool {
        self.pinned_contents.contains_key(cid)
    }

    /// Get pinned content count.
    #[inline]
    pub fn pinned_count(&self) -> usize {
        self.pinned_contents.len()
    }

    /// Handle a chunk request and generate a response.
    ///
    /// This method reads the requested chunk from storage, signs it, and returns
    /// a ChunkResponse. If storage is not configured, returns a placeholder response.
    pub async fn handle_chunk_request(
        &self,
        request: ChunkRequest,
    ) -> Result<ChunkResponse, NodeError> {
        // Verify content is pinned
        if !self.pinned_contents.contains_key(&request.content_cid) {
            return Err(NodeError::ContentNotFound(request.content_cid.clone()));
        }

        // Read chunk from storage
        let chunk_data = if let Some(storage) = &self.storage {
            let storage_guard = storage.read().await;
            storage_guard
                .get_chunk(&request.content_cid, request.chunk_index)
                .await?
        } else {
            // Fallback for nodes without storage (testing purposes)
            vec![0u8; 1024]
        };

        let chunk_hash = chie_crypto::hash(&chunk_data);

        // Sign the transfer (nonce || hash || requester_pubkey)
        let message = [
            &request.challenge_nonce[..],
            &chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let signature = self.keypair.sign(&message);

        Ok(ChunkResponse {
            encrypted_chunk: chunk_data,
            chunk_hash,
            provider_signature: signature.to_vec(),
            provider_public_key: self.keypair.public_key(),
            challenge_echo: request.challenge_nonce,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        })
    }

    /// Handle a chunk request with verification.
    ///
    /// Same as handle_chunk_request but also verifies the chunk hash matches storage metadata.
    pub async fn handle_chunk_request_verified(
        &self,
        request: ChunkRequest,
    ) -> Result<ChunkResponse, NodeError> {
        // Verify content is pinned
        if !self.pinned_contents.contains_key(&request.content_cid) {
            return Err(NodeError::ContentNotFound(request.content_cid.clone()));
        }

        // Read and verify chunk from storage
        let (chunk_data, chunk_hash) = if let Some(storage) = &self.storage {
            let storage_guard = storage.read().await;
            storage_guard
                .get_chunk_verified(&request.content_cid, request.chunk_index)
                .await?
        } else {
            let data = vec![0u8; 1024];
            let hash = chie_crypto::hash(&data);
            (data, hash)
        };

        // Sign the transfer
        let message = [
            &request.challenge_nonce[..],
            &chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let signature = self.keypair.sign(&message);

        Ok(ChunkResponse {
            encrypted_chunk: chunk_data,
            chunk_hash,
            provider_signature: signature.to_vec(),
            provider_public_key: self.keypair.public_key(),
            challenge_echo: request.challenge_nonce,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        })
    }

    /// Submit a proof to the coordinator using pooled connection.
    pub async fn submit_proof(&self, proof: BandwidthProof) -> Result<(), NodeError> {
        let response = self
            .http_client
            .post(format!("{}/api/proofs", self.config.coordinator_url))
            .json(&proof)
            .send()
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(NodeError::ProofSubmission(format!(
                "Server returned status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Submit multiple proofs in batch for improved efficiency.
    pub async fn submit_proofs_batch(&self, proofs: Vec<BandwidthProof>) -> Result<(), NodeError> {
        let response = self
            .http_client
            .post(format!("{}/api/proofs/batch", self.config.coordinator_url))
            .json(&proofs)
            .send()
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(NodeError::ProofSubmission(format!(
                "Batch submission failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Add earnings (called when proof is verified).
    pub fn add_earnings(&mut self, amount: Points) {
        self.earnings += amount;
    }

    /// Get storage statistics if storage is configured.
    pub async fn storage_stats(&self) -> Option<crate::storage::StorageStats> {
        if let Some(storage) = &self.storage {
            let storage_guard = storage.read().await;
            Some(storage_guard.stats())
        } else {
            None
        }
    }

    /// Handle multiple chunk requests concurrently for improved throughput.
    pub async fn handle_chunk_requests_batch(
        &self,
        requests: Vec<ChunkRequest>,
    ) -> Result<Vec<ChunkResponse>, NodeError> {
        // Verify all requests upfront
        for request in &requests {
            if !self.pinned_contents.contains_key(&request.content_cid) {
                return Err(NodeError::ContentNotFound(request.content_cid.clone()));
            }
        }

        // Process requests sequentially (signing requires non-cloneable KeyPair)
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            let response = self.handle_chunk_request(request).await?;
            responses.push(response);
        }

        Ok(responses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{create_bandwidth_proof, create_chunk_request};
    use chie_crypto::{KeyPair, generate_key, generate_nonce, hash, verify};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let node = ContentNode::new(config);

        assert_eq!(node.earnings(), 0);
        assert_eq!(node.pinned_count(), 0);
    }

    #[tokio::test]
    async fn test_node_with_storage() {
        let temp_dir = TempDir::new().unwrap();
        let config = NodeConfig {
            storage_path: temp_dir.path().to_path_buf(),
            max_storage_bytes: 10 * 1024 * 1024, // 10 MB
            ..Default::default()
        };

        let node = ContentNode::with_storage(config).await.unwrap();
        assert!(node.storage().is_some());

        let stats = node.storage_stats().await.unwrap();
        assert_eq!(stats.used_bytes, 0);
        assert_eq!(stats.max_bytes, 10 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_pin_unpin_content() {
        let config = NodeConfig::default();
        let mut node = ContentNode::new(config);

        let cid = "QmTest123".to_string();
        let content = PinnedContent {
            cid: cid.clone(),
            size_bytes: 1024,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };

        node.pin_content(content);
        assert!(node.has_content(&cid));
        assert_eq!(node.pinned_count(), 1);

        let unpinned = node.unpin_content(&cid);
        assert!(unpinned.is_some());
        assert!(!node.has_content(&cid));
        assert_eq!(node.pinned_count(), 0);
    }

    #[tokio::test]
    async fn test_add_earnings() {
        let config = NodeConfig::default();
        let mut node = ContentNode::new(config);

        assert_eq!(node.earnings(), 0);
        node.add_earnings(100);
        assert_eq!(node.earnings(), 100);
        node.add_earnings(50);
        assert_eq!(node.earnings(), 150);
    }

    #[tokio::test]
    async fn test_handle_chunk_request_without_storage() {
        let config = NodeConfig::default();
        let mut node = ContentNode::new(config);

        let cid = "QmTest123".to_string();
        let content = PinnedContent {
            cid: cid.clone(),
            size_bytes: 1024,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };
        node.pin_content(content);

        let requester_keypair = KeyPair::generate();
        let request = create_chunk_request(
            cid.clone(),
            0,
            "peer-123".to_string(),
            requester_keypair.public_key(),
        );

        let response = node.handle_chunk_request(request.clone()).await.unwrap();

        // Verify response structure
        assert_eq!(response.provider_public_key, node.public_key());
        assert_eq!(response.challenge_echo, request.challenge_nonce);
        assert_eq!(response.encrypted_chunk.len(), 1024); // Fallback data

        // Verify signature
        let message = [
            &request.challenge_nonce[..],
            &response.chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let sig: [u8; 64] = response.provider_signature.as_slice().try_into().unwrap();
        assert!(verify(&node.public_key(), &message, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_handle_chunk_request_content_not_found() {
        let config = NodeConfig::default();
        let node = ContentNode::new(config);

        let requester_keypair = KeyPair::generate();
        let request = create_chunk_request(
            "QmNonExistent".to_string(),
            0,
            "peer-123".to_string(),
            requester_keypair.public_key(),
        );

        let result = node.handle_chunk_request(request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NodeError::ContentNotFound(_)));
    }

    #[tokio::test]
    async fn test_handle_chunk_request_with_storage() {
        let temp_dir = TempDir::new().unwrap();
        let config = NodeConfig {
            storage_path: temp_dir.path().to_path_buf(),
            max_storage_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };

        let mut node = ContentNode::with_storage(config).await.unwrap();

        // Prepare test data
        let cid = "QmTest123".to_string();
        let test_data = b"Hello, CHIE Protocol!".to_vec();
        let chunks = vec![test_data.clone()];

        // Pin content to storage
        if let Some(storage_arc) = node.storage() {
            let mut storage = storage_arc.write().await;
            let key = generate_key();
            let nonce = generate_nonce();

            storage
                .pin_content(&cid, &chunks, &key, &nonce)
                .await
                .unwrap();
        }

        // Pin content metadata in node
        let content = PinnedContent {
            cid: cid.clone(),
            size_bytes: test_data.len() as u64,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };
        node.pin_content(content);

        // Create and handle chunk request
        let requester_keypair = KeyPair::generate();
        let request = create_chunk_request(
            cid.clone(),
            0,
            "peer-123".to_string(),
            requester_keypair.public_key(),
        );

        let response = node.handle_chunk_request(request.clone()).await.unwrap();

        // Verify response
        assert_eq!(response.provider_public_key, node.public_key());
        assert_eq!(response.challenge_echo, request.challenge_nonce);
        assert!(!response.encrypted_chunk.is_empty());

        // Verify signature
        let message = [
            &request.challenge_nonce[..],
            &response.chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let sig: [u8; 64] = response.provider_signature.as_slice().try_into().unwrap();
        assert!(verify(&node.public_key(), &message, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_handle_chunk_request_verified() {
        let temp_dir = TempDir::new().unwrap();
        let config = NodeConfig {
            storage_path: temp_dir.path().to_path_buf(),
            max_storage_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };

        let mut node = ContentNode::with_storage(config).await.unwrap();

        // Prepare test data
        let cid = "QmTest456".to_string();
        let test_data = b"Verified chunk test".to_vec();
        let chunks = vec![test_data.clone()];
        let expected_hash = hash(&test_data);

        // Pin content to storage
        if let Some(storage_arc) = node.storage() {
            let mut storage = storage_arc.write().await;
            let key = generate_key();
            let nonce = generate_nonce();

            storage
                .pin_content(&cid, &chunks, &key, &nonce)
                .await
                .unwrap();
        }

        // Pin content metadata in node
        let content = PinnedContent {
            cid: cid.clone(),
            size_bytes: test_data.len() as u64,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };
        node.pin_content(content);

        // Create and handle verified chunk request
        let requester_keypair = KeyPair::generate();
        let request = create_chunk_request(
            cid.clone(),
            0,
            "peer-456".to_string(),
            requester_keypair.public_key(),
        );

        let response = node
            .handle_chunk_request_verified(request.clone())
            .await
            .unwrap();

        // Verify hash matches expected
        assert_eq!(response.chunk_hash, expected_hash);

        // Verify signature
        let message = [
            &request.challenge_nonce[..],
            &response.chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let sig: [u8; 64] = response.provider_signature.as_slice().try_into().unwrap();
        assert!(verify(&node.public_key(), &message, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_full_bandwidth_proof_flow() {
        let temp_dir = TempDir::new().unwrap();
        let config = NodeConfig {
            storage_path: temp_dir.path().to_path_buf(),
            max_storage_bytes: 10 * 1024 * 1024,
            ..Default::default()
        };

        let mut provider_node = ContentNode::with_storage(config).await.unwrap();
        let requester_keypair = KeyPair::generate();

        // Setup: Pin content
        let cid = "QmFullFlow".to_string();
        let test_data = b"Full bandwidth proof flow test data".to_vec();
        let chunks = vec![test_data.clone()];

        if let Some(storage_arc) = provider_node.storage() {
            let mut storage = storage_arc.write().await;
            let key = generate_key();
            let nonce = generate_nonce();
            storage
                .pin_content(&cid, &chunks, &key, &nonce)
                .await
                .unwrap();
        }

        let content = PinnedContent {
            cid: cid.clone(),
            size_bytes: test_data.len() as u64,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };
        provider_node.pin_content(content);

        // Step 1: Create chunk request
        let start_time = chrono::Utc::now().timestamp_millis();
        let request = create_chunk_request(
            cid.clone(),
            0,
            "requester-peer".to_string(),
            requester_keypair.public_key(),
        );

        // Step 2: Provider handles request
        let response = provider_node
            .handle_chunk_request_verified(request.clone())
            .await
            .unwrap();
        let end_time = chrono::Utc::now().timestamp_millis();

        // Step 3: Requester signs the response
        let requester_message = [
            &request.challenge_nonce[..],
            &response.chunk_hash[..],
            &response.provider_public_key[..],
        ]
        .concat();
        let requester_signature = requester_keypair.sign(&requester_message);

        // Step 4: Create bandwidth proof
        let proof = create_bandwidth_proof(
            &request,
            "provider-peer".to_string(),
            response.provider_public_key.to_vec(),
            response.encrypted_chunk.len() as u64,
            response.provider_signature.clone(),
            requester_signature.to_vec(),
            response.chunk_hash.to_vec(),
            start_time,
            end_time,
            (end_time - start_time) as u32,
        );

        // Verify proof structure
        assert_eq!(proof.content_cid, cid);
        assert_eq!(proof.chunk_index, 0);
        assert_eq!(
            proof.bytes_transferred,
            response.encrypted_chunk.len() as u64
        );
        assert_eq!(
            proof.provider_public_key,
            response.provider_public_key.to_vec()
        );
        assert_eq!(
            proof.requester_public_key,
            requester_keypair.public_key().to_vec()
        );

        // Verify both signatures
        let provider_msg = [
            &request.challenge_nonce[..],
            &response.chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let prov_sig: [u8; 64] = proof.provider_signature.as_slice().try_into().unwrap();
        assert!(verify(&provider_node.public_key(), &provider_msg, &prov_sig).is_ok());
        let req_sig: [u8; 64] = proof.requester_signature.as_slice().try_into().unwrap();
        assert!(
            verify(
                &requester_keypair.public_key(),
                &requester_message,
                &req_sig
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.max_storage_bytes, 50 * 1024 * 1024 * 1024);
        assert_eq!(config.max_bandwidth_bps, 100 * 1024 * 1024 / 8);
        assert_eq!(config.coordinator_url, "https://coordinator.chie.network");
    }
}
