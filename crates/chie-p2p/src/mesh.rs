//! Mesh simulation for testing P2P network behavior.
//!
//! This module provides utilities for creating and managing multiple virtual
//! P2P nodes within a single process for testing and simulation purposes.

use crate::NodeEvent;
use chie_crypto::KeyPair;
use chie_shared::{BandwidthProof, BandwidthProofBuilder, ChunkRequest, ChunkResponse};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Configuration for mesh simulation.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Number of nodes in the mesh.
    pub node_count: usize,
    /// Base TCP port for nodes.
    pub base_tcp_port: u16,
    /// Base QUIC port for nodes.
    pub base_quic_port: u16,
    /// Enable QUIC transport.
    pub enable_quic: bool,
    /// Enable mDNS for local discovery.
    pub enable_mdns: bool,
    /// Connection timeout.
    pub connection_timeout: Duration,
    /// Simulation step duration.
    pub step_duration: Duration,
    /// Maximum simulation time.
    pub max_simulation_time: Duration,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            node_count: 5,
            base_tcp_port: 10000,
            base_quic_port: 20000,
            enable_quic: false, // Disable for faster tests
            enable_mdns: true,
            connection_timeout: Duration::from_secs(30),
            step_duration: Duration::from_millis(100),
            max_simulation_time: Duration::from_secs(60),
        }
    }
}

/// Statistics collected during mesh simulation.
#[derive(Debug, Clone, Default)]
pub struct MeshStats {
    /// Total number of chunk transfers.
    pub chunk_transfers: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Total proofs generated.
    pub proofs_generated: u64,
    /// Average latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Number of successful transfers.
    pub successful_transfers: u64,
    /// Number of failed transfers.
    pub failed_transfers: u64,
    /// Simulation duration.
    pub simulation_duration: Duration,
    /// Per-node statistics.
    pub node_stats: HashMap<PeerId, NodeStats>,
}

/// Statistics for a single node.
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Chunks served.
    pub chunks_served: u64,
    /// Chunks received.
    pub chunks_received: u64,
    /// Bytes uploaded.
    pub bytes_uploaded: u64,
    /// Bytes downloaded.
    pub bytes_downloaded: u64,
    /// Connected peer count.
    pub connected_peers: usize,
}

/// A virtual node in the mesh simulation.
pub struct VirtualNode {
    /// Node identifier.
    pub peer_id: PeerId,
    /// Node keypair.
    pub keypair: KeyPair,
    /// Listen addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Event receiver.
    pub event_rx: mpsc::Receiver<NodeEvent>,
    /// Event sender (for internal use).
    event_tx: mpsc::Sender<NodeEvent>,
    /// Content CIDs this node is seeding.
    pub seeding: HashSet<String>,
    /// Statistics.
    pub stats: NodeStats,
}

impl VirtualNode {
    /// Create a new virtual node.
    pub fn new(peer_id: PeerId, keypair: KeyPair) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        Self {
            peer_id,
            keypair,
            listen_addrs: Vec::new(),
            event_rx,
            event_tx,
            seeding: HashSet::new(),
            stats: NodeStats::default(),
        }
    }

    /// Get the event sender for this node.
    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.event_tx.clone()
    }

    /// Add content to seed.
    pub fn seed_content(&mut self, cid: &str) {
        self.seeding.insert(cid.to_string());
    }

    /// Check if this node is seeding content.
    pub fn is_seeding(&self, cid: &str) -> bool {
        self.seeding.contains(cid)
    }
}

/// Mesh simulation controller.
pub struct MeshSimulation {
    /// Configuration.
    config: MeshConfig,
    /// Virtual nodes.
    nodes: HashMap<PeerId, VirtualNode>,
    /// Node order for deterministic iteration.
    node_order: Vec<PeerId>,
    /// Collected statistics.
    stats: MeshStats,
    /// Simulation start time.
    start_time: Option<Instant>,
    /// Generated proofs.
    proofs: Vec<BandwidthProof>,
}

impl MeshSimulation {
    /// Create a new mesh simulation.
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            node_order: Vec::new(),
            stats: MeshStats::default(),
            start_time: None,
            proofs: Vec::new(),
        }
    }

    /// Create a default 5-node mesh.
    pub fn five_node() -> Self {
        Self::new(MeshConfig {
            node_count: 5,
            ..Default::default()
        })
    }

    /// Create a 2-node mesh for simple transfer tests.
    pub fn two_node() -> Self {
        Self::new(MeshConfig {
            node_count: 2,
            ..Default::default()
        })
    }

    /// Initialize the mesh with virtual nodes.
    pub fn initialize(&mut self) -> &[PeerId] {
        info!(
            "Initializing mesh simulation with {} nodes",
            self.config.node_count
        );

        for i in 0..self.config.node_count {
            let keypair = KeyPair::generate();
            let libp2p_keypair = libp2p::identity::Keypair::generate_ed25519();
            let peer_id = PeerId::from(libp2p_keypair.public());

            let mut node = VirtualNode::new(peer_id, keypair);

            // Set up listen addresses
            let tcp_port = self.config.base_tcp_port + i as u16;
            let quic_port = self.config.base_quic_port + i as u16;

            node.listen_addrs
                .push(format!("/ip4/127.0.0.1/tcp/{}", tcp_port).parse().unwrap());
            if self.config.enable_quic {
                node.listen_addrs.push(
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", quic_port)
                        .parse()
                        .unwrap(),
                );
            }

            info!("Created virtual node {} with peer ID {}", i, peer_id);
            self.node_order.push(peer_id);
            self.nodes.insert(peer_id, node);
        }

        &self.node_order
    }

    /// Get the number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get a reference to a node.
    pub fn get_node(&self, peer_id: &PeerId) -> Option<&VirtualNode> {
        self.nodes.get(peer_id)
    }

    /// Get a mutable reference to a node.
    pub fn get_node_mut(&mut self, peer_id: &PeerId) -> Option<&mut VirtualNode> {
        self.nodes.get_mut(peer_id)
    }

    /// Get all peer IDs.
    pub fn peer_ids(&self) -> &[PeerId] {
        &self.node_order
    }

    /// Have a node start seeding content.
    pub fn add_seeder(&mut self, peer_id: &PeerId, cid: &str) {
        if let Some(node) = self.nodes.get_mut(peer_id) {
            node.seed_content(cid);
            info!("Node {} is now seeding content {}", peer_id, cid);
        }
    }

    /// Find seeders for a given content.
    pub fn find_seeders(&self, cid: &str) -> Vec<PeerId> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.is_seeding(cid))
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Simulate a chunk transfer between two nodes.
    pub fn simulate_transfer(
        &mut self,
        requester_id: &PeerId,
        provider_id: &PeerId,
        content_cid: &str,
        chunk_index: u64,
        chunk_data: &[u8],
    ) -> Result<SimulatedTransfer, MeshError> {
        // Validate nodes exist
        let requester = self
            .nodes
            .get(requester_id)
            .ok_or(MeshError::NodeNotFound(*requester_id))?;
        let provider = self
            .nodes
            .get(provider_id)
            .ok_or(MeshError::NodeNotFound(*provider_id))?;

        // Validate provider is seeding
        if !provider.is_seeding(content_cid) {
            return Err(MeshError::ContentNotSeeded {
                peer_id: *provider_id,
                cid: content_cid.to_string(),
            });
        }

        let transfer_start = Instant::now();

        // Create chunk request
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let request = ChunkRequest {
            content_cid: content_cid.to_string(),
            chunk_index,
            challenge_nonce: nonce,
            requester_peer_id: requester_id.to_string(),
            requester_public_key: requester.keypair.public_key(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };

        // Simulate provider response
        let chunk_hash = chie_crypto::hash(chunk_data);

        // Sign the transfer
        let message = [
            &request.challenge_nonce[..],
            &chunk_hash[..],
            &request.requester_public_key[..],
        ]
        .concat();
        let provider_signature = provider.keypair.sign(&message);

        let response = ChunkResponse {
            encrypted_chunk: chunk_data.to_vec(),
            chunk_hash,
            provider_signature: provider_signature.to_vec(),
            provider_public_key: provider.keypair.public_key(),
            challenge_echo: request.challenge_nonce,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
        };

        let transfer_duration = transfer_start.elapsed();
        let latency_ms = transfer_duration.as_millis() as u32;

        // Create requester signature before releasing the borrow
        let requester_sign_message = [
            &response.challenge_echo[..],
            &response.chunk_hash[..],
            &response.provider_public_key[..],
        ]
        .concat();
        let requester_signature = requester.keypair.sign(&requester_sign_message);

        // Generate bandwidth proof
        let proof = self.create_proof(
            &request,
            &response,
            requester_signature.to_vec(),
            provider_id,
            requester_id,
            chunk_data.len() as u64,
            latency_ms,
        )?;

        // Update statistics
        let bytes = chunk_data.len() as u64;

        if let Some(provider_node) = self.nodes.get_mut(provider_id) {
            provider_node.stats.chunks_served += 1;
            provider_node.stats.bytes_uploaded += bytes;
        }

        if let Some(requester_node) = self.nodes.get_mut(requester_id) {
            requester_node.stats.chunks_received += 1;
            requester_node.stats.bytes_downloaded += bytes;
        }

        self.stats.chunk_transfers += 1;
        self.stats.bytes_transferred += bytes;
        self.stats.successful_transfers += 1;
        self.stats.proofs_generated += 1;

        // Update average latency
        let total_latency = self.stats.avg_latency_ms * (self.stats.chunk_transfers - 1) as f64;
        self.stats.avg_latency_ms =
            (total_latency + latency_ms as f64) / self.stats.chunk_transfers as f64;

        // Store proof
        self.proofs.push(proof.clone());

        Ok(SimulatedTransfer {
            request,
            response,
            proof,
            latency_ms,
            bytes_transferred: bytes,
        })
    }

    /// Create a bandwidth proof for a simulated transfer.
    #[allow(clippy::too_many_arguments)]
    fn create_proof(
        &self,
        request: &ChunkRequest,
        response: &ChunkResponse,
        requester_signature: Vec<u8>,
        provider_id: &PeerId,
        requester_id: &PeerId,
        bytes_transferred: u64,
        latency_ms: u32,
    ) -> Result<BandwidthProof, MeshError> {
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Build the proof with BandwidthProofBuilder
        let proof = BandwidthProofBuilder::new()
            .content_cid(&request.content_cid)
            .chunk_index(request.chunk_index)
            .bytes_transferred(bytes_transferred)
            .provider_peer_id(provider_id.to_string())
            .requester_peer_id(requester_id.to_string())
            .provider_public_key(response.provider_public_key.to_vec())
            .requester_public_key(request.requester_public_key.to_vec())
            .provider_signature(response.provider_signature.clone())
            .requester_signature(requester_signature)
            .challenge_nonce(request.challenge_nonce.to_vec())
            .chunk_hash(response.chunk_hash.to_vec())
            .timestamps(now_ms - latency_ms as i64, now_ms)
            .latency_ms(latency_ms)
            .build()
            .map_err(|e| MeshError::ProofGenerationFailed(e.to_string()))?;

        Ok(proof)
    }

    /// Run a full simulation scenario.
    pub async fn run_scenario(&mut self, scenario: MeshScenario) -> Result<MeshStats, MeshError> {
        self.start_time = Some(Instant::now());

        match scenario {
            MeshScenario::SingleTransfer { chunk_size } => {
                self.run_single_transfer(chunk_size).await?;
            }
            MeshScenario::RoundRobin { rounds, chunk_size } => {
                self.run_round_robin(rounds, chunk_size).await?;
            }
            MeshScenario::ContentPopularity {
                content_count,
                requests_per_content,
            } => {
                self.run_content_popularity(content_count, requests_per_content)
                    .await?;
            }
            MeshScenario::Custom(func) => {
                func(self).await?;
            }
        }

        // Finalize statistics
        if let Some(start) = self.start_time {
            self.stats.simulation_duration = start.elapsed();
        }

        // Collect per-node stats
        for (peer_id, node) in &self.nodes {
            self.stats.node_stats.insert(*peer_id, node.stats.clone());
        }

        Ok(self.stats.clone())
    }

    /// Run a single transfer scenario.
    async fn run_single_transfer(&mut self, chunk_size: usize) -> Result<(), MeshError> {
        if self.nodes.len() < 2 {
            return Err(MeshError::InsufficientNodes {
                required: 2,
                available: self.nodes.len(),
            });
        }

        let provider_id = self.node_order[0];
        let requester_id = self.node_order[1];
        let content_cid = "test-content-single";

        // Set up provider
        self.add_seeder(&provider_id, content_cid);

        // Create test chunk
        let chunk_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

        // Execute transfer
        self.simulate_transfer(&requester_id, &provider_id, content_cid, 0, &chunk_data)?;

        info!("Single transfer completed successfully");
        Ok(())
    }

    /// Run a round-robin scenario where all nodes transfer to each other.
    async fn run_round_robin(&mut self, rounds: u32, chunk_size: usize) -> Result<(), MeshError> {
        if self.nodes.len() < 2 {
            return Err(MeshError::InsufficientNodes {
                required: 2,
                available: self.nodes.len(),
            });
        }

        // All nodes seed content
        for peer_id in self.node_order.clone() {
            let content_cid = format!("content-{}", peer_id);
            self.add_seeder(&peer_id, &content_cid);
        }

        // Create test chunk
        let chunk_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

        for round in 0..rounds {
            info!("Running round {} of {}", round + 1, rounds);

            for (i, provider_id) in self.node_order.clone().into_iter().enumerate() {
                let content_cid = format!("content-{}", provider_id);

                // Transfer to all other nodes
                for (j, requester_id) in self.node_order.clone().into_iter().enumerate() {
                    if i != j {
                        match self.simulate_transfer(
                            &requester_id,
                            &provider_id,
                            &content_cid,
                            round as u64,
                            &chunk_data,
                        ) {
                            Ok(_) => {
                                debug!("Transfer {} -> {} completed", provider_id, requester_id)
                            }
                            Err(e) => {
                                warn!("Transfer {} -> {} failed: {}", provider_id, requester_id, e);
                                self.stats.failed_transfers += 1;
                            }
                        }
                    }
                }
            }
        }

        info!("Round-robin scenario completed: {} rounds", rounds);
        Ok(())
    }

    /// Run a content popularity simulation.
    async fn run_content_popularity(
        &mut self,
        content_count: u32,
        requests_per_content: u32,
    ) -> Result<(), MeshError> {
        if self.nodes.is_empty() {
            return Err(MeshError::InsufficientNodes {
                required: 1,
                available: 0,
            });
        }

        let chunk_size = 1024 * 64; // 64KB chunks

        // Distribute content across nodes
        for i in 0..content_count {
            let node_idx = i as usize % self.node_order.len();
            let peer_id = self.node_order[node_idx];
            let content_cid = format!("popular-content-{}", i);
            self.add_seeder(&peer_id, &content_cid);
        }

        // Create test chunk
        let chunk_data: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();

        // Simulate requests with popularity distribution (zipf-like)
        for content_idx in 0..content_count {
            let content_cid = format!("popular-content-{}", content_idx);
            let seeders = self.find_seeders(&content_cid);

            if seeders.is_empty() {
                continue;
            }

            // Popular content gets more requests
            let request_count = requests_per_content / (content_idx + 1);

            for req_num in 0..request_count {
                // Round-robin through seeders
                let provider_id = seeders[req_num as usize % seeders.len()];

                // Pick a random requester (not the provider)
                let requester_idx = (req_num as usize + 1) % self.node_order.len();
                let requester_id = self.node_order[requester_idx];

                if requester_id != provider_id {
                    let _ = self.simulate_transfer(
                        &requester_id,
                        &provider_id,
                        &content_cid,
                        req_num as u64,
                        &chunk_data,
                    );
                }
            }
        }

        info!(
            "Content popularity scenario completed: {} contents",
            content_count
        );
        Ok(())
    }

    /// Get all generated proofs.
    pub fn proofs(&self) -> &[BandwidthProof] {
        &self.proofs
    }

    /// Get simulation statistics.
    pub fn stats(&self) -> &MeshStats {
        &self.stats
    }
}

/// Simulated transfer result.
#[derive(Debug, Clone)]
pub struct SimulatedTransfer {
    /// The chunk request.
    pub request: ChunkRequest,
    /// The chunk response.
    pub response: ChunkResponse,
    /// The generated bandwidth proof.
    pub proof: BandwidthProof,
    /// Transfer latency in milliseconds.
    pub latency_ms: u32,
    /// Bytes transferred.
    pub bytes_transferred: u64,
}

/// Type alias for custom scenario functions.
pub type CustomScenarioFn = Box<
    dyn for<'a> FnOnce(
            &'a mut MeshSimulation,
        ) -> futures::future::BoxFuture<'a, Result<(), MeshError>>
        + Send,
>;

/// Predefined simulation scenarios.
#[allow(clippy::type_complexity)]
pub enum MeshScenario {
    /// Single transfer between two nodes.
    SingleTransfer { chunk_size: usize },
    /// Round-robin transfers between all nodes.
    RoundRobin { rounds: u32, chunk_size: usize },
    /// Content popularity simulation (zipf distribution).
    ContentPopularity {
        content_count: u32,
        requests_per_content: u32,
    },
    /// Custom scenario with user-provided function.
    Custom(CustomScenarioFn),
}

/// Mesh simulation errors.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("Node not found: {0}")]
    NodeNotFound(PeerId),

    #[error("Content not seeded by peer {peer_id}: {cid}")]
    ContentNotSeeded { peer_id: PeerId, cid: String },

    #[error("Insufficient nodes: required {required}, available {available}")]
    InsufficientNodes { required: usize, available: usize },

    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Simulation timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_initialization() {
        let mut mesh = MeshSimulation::five_node();
        let peer_ids = mesh.initialize();

        assert_eq!(peer_ids.len(), 5);
        assert_eq!(mesh.node_count(), 5);
    }

    #[test]
    fn test_two_node_mesh() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize();

        assert_eq!(peer_ids.len(), 2);
    }

    #[test]
    fn test_seeder_management() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize().to_vec();

        let cid = "test-content";
        mesh.add_seeder(&peer_ids[0], cid);

        assert!(mesh.get_node(&peer_ids[0]).unwrap().is_seeding(cid));
        assert!(!mesh.get_node(&peer_ids[1]).unwrap().is_seeding(cid));

        let seeders = mesh.find_seeders(cid);
        assert_eq!(seeders.len(), 1);
        assert_eq!(seeders[0], peer_ids[0]);
    }

    #[test]
    fn test_simulated_transfer() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize().to_vec();

        let provider_id = peer_ids[0];
        let requester_id = peer_ids[1];
        let cid = "test-content";

        mesh.add_seeder(&provider_id, cid);

        let chunk_data = vec![1u8; 1024];
        let result = mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data);

        assert!(result.is_ok());
        let transfer = result.unwrap();

        assert_eq!(transfer.bytes_transferred, 1024);
        assert!(!transfer.proof.provider_signature.is_empty());
        assert!(!transfer.proof.requester_signature.is_empty());
    }

    #[test]
    fn test_transfer_stats() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize().to_vec();

        let provider_id = peer_ids[0];
        let requester_id = peer_ids[1];
        let cid = "test-content";

        mesh.add_seeder(&provider_id, cid);

        let chunk_data = vec![1u8; 1024];
        mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data)
            .unwrap();

        let stats = mesh.stats();
        assert_eq!(stats.chunk_transfers, 1);
        assert_eq!(stats.bytes_transferred, 1024);
        assert_eq!(stats.successful_transfers, 1);
    }

    #[tokio::test]
    async fn test_single_transfer_scenario() {
        let mut mesh = MeshSimulation::two_node();
        mesh.initialize();

        let stats = mesh
            .run_scenario(MeshScenario::SingleTransfer { chunk_size: 4096 })
            .await
            .unwrap();

        assert_eq!(stats.chunk_transfers, 1);
        assert_eq!(stats.bytes_transferred, 4096);
    }

    #[tokio::test]
    async fn test_round_robin_scenario() {
        let mut mesh = MeshSimulation::new(MeshConfig {
            node_count: 3,
            ..Default::default()
        });
        mesh.initialize();

        let stats = mesh
            .run_scenario(MeshScenario::RoundRobin {
                rounds: 2,
                chunk_size: 1024,
            })
            .await
            .unwrap();

        // 3 nodes, 2 rounds, each node sends to 2 other nodes
        // Expected: 3 * 2 * 2 = 12 transfers
        assert_eq!(stats.chunk_transfers, 12);
    }

    #[tokio::test]
    async fn test_five_node_mesh_scenario() {
        let mut mesh = MeshSimulation::five_node();
        mesh.initialize();

        let stats = mesh
            .run_scenario(MeshScenario::RoundRobin {
                rounds: 1,
                chunk_size: 2048,
            })
            .await
            .unwrap();

        // 5 nodes, 1 round, each node sends to 4 other nodes
        // Expected: 5 * 4 = 20 transfers
        assert_eq!(stats.chunk_transfers, 20);
    }

    #[test]
    fn test_content_not_seeded_error() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize().to_vec();

        let provider_id = peer_ids[0];
        let requester_id = peer_ids[1];
        let cid = "not-seeded";

        // Don't add seeder, should fail
        let chunk_data = vec![1u8; 1024];
        let result = mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data);

        assert!(matches!(result, Err(MeshError::ContentNotSeeded { .. })));
    }

    #[test]
    fn test_proof_generation() {
        let mut mesh = MeshSimulation::two_node();
        let peer_ids = mesh.initialize().to_vec();

        let provider_id = peer_ids[0];
        let requester_id = peer_ids[1];
        let cid = "test-content";

        mesh.add_seeder(&provider_id, cid);

        let chunk_data = vec![1u8; 1024];
        mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data)
            .unwrap();

        let proofs = mesh.proofs();
        assert_eq!(proofs.len(), 1);

        let proof = &proofs[0];
        assert_eq!(proof.content_cid, cid);
        assert_eq!(proof.bytes_transferred, 1024);
    }
}
