//! 5-node mesh simulation test.
//!
//! This test simulates a mesh network of 5 nodes where:
//! - Each node can act as both provider and requester
//! - Content is distributed across multiple nodes
//! - Nodes discover and transfer chunks between each other
//! - All transfers generate valid bandwidth proofs

use chie_crypto::{hash, KeyPair};
use chie_shared::{BandwidthProof, CHUNK_SIZE};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Represents a node in the mesh network.
struct MeshNode {
    id: usize,
    keypair: KeyPair,
    peer_id: String,
    /// Content this node has (CID -> chunk indices).
    available_content: HashMap<String, HashSet<u64>>,
    /// Transfer statistics.
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    proofs_generated: Vec<BandwidthProof>,
}

impl MeshNode {
    fn new(id: usize) -> Self {
        Self {
            id,
            keypair: KeyPair::generate(),
            peer_id: format!("12D3KooWNode{}", id),
            available_content: HashMap::new(),
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            proofs_generated: Vec::new(),
        }
    }

    /// Pin content (mark as available).
    fn pin_content(&mut self, cid: &str, chunks: &[u64]) {
        let entry = self.available_content.entry(cid.to_string()).or_default();
        entry.extend(chunks);
    }

    /// Check if this node has a specific chunk.
    fn has_chunk(&self, cid: &str, chunk_index: u64) -> bool {
        self.available_content
            .get(cid)
            .is_some_and(|chunks| chunks.contains(&chunk_index))
    }

    /// Get all chunks available for a CID.
    fn get_available_chunks(&self, cid: &str) -> Vec<u64> {
        self.available_content
            .get(cid)
            .map(|c| c.iter().copied().collect())
            .unwrap_or_default()
    }

    fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }
}

/// Simulates the mesh network.
struct MeshNetwork {
    nodes: Vec<MeshNode>,
    /// All proofs generated during simulation.
    all_proofs: Vec<BandwidthProof>,
    /// Track unique content.
    content_registry: HashMap<String, ContentInfo>,
}

struct ContentInfo {
    total_chunks: u64,
    chunk_size: u64,
}

impl MeshNetwork {
    fn new(node_count: usize) -> Self {
        Self {
            nodes: (0..node_count).map(MeshNode::new).collect(),
            all_proofs: Vec::new(),
            content_registry: HashMap::new(),
        }
    }

    /// Register content in the network.
    fn register_content(&mut self, cid: &str, total_chunks: u64) {
        self.content_registry.insert(
            cid.to_string(),
            ContentInfo {
                total_chunks,
                chunk_size: CHUNK_SIZE as u64,
            },
        );
    }

    /// Find nodes that have a specific chunk.
    fn find_providers(&self, cid: &str, chunk_index: u64) -> Vec<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.has_chunk(cid, chunk_index))
            .map(|(i, _)| i)
            .collect()
    }

    /// Simulate a transfer between two nodes.
    fn simulate_transfer(
        &mut self,
        provider_idx: usize,
        requester_idx: usize,
        cid: &str,
        chunk_index: u64,
    ) -> Result<BandwidthProof, String> {
        if provider_idx == requester_idx {
            return Err("Cannot transfer to self".to_string());
        }

        if !self.nodes[provider_idx].has_chunk(cid, chunk_index) {
            return Err(format!(
                "Provider {} doesn't have chunk {} of {}",
                provider_idx, chunk_index, cid
            ));
        }

        // Simulate transfer time (random 10-200ms)
        let latency_ms = 10 + (rand::random::<u32>() % 190);

        // Generate mock chunk data
        let chunk_data = vec![0xAB; CHUNK_SIZE];
        let chunk_hash = hash(&chunk_data);

        // Generate nonce
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let now = Utc::now().timestamp_millis();
        let start_time = now - latency_ms as i64;

        let provider = &self.nodes[provider_idx];
        let requester = &self.nodes[requester_idx];

        // Provider signs
        let mut provider_msg = Vec::new();
        provider_msg.extend_from_slice(&nonce);
        provider_msg.extend_from_slice(&chunk_hash);
        provider_msg.extend_from_slice(&requester.public_key());
        let provider_sig = provider.keypair.sign(&provider_msg);

        // Requester signs
        let mut requester_msg = Vec::new();
        requester_msg.extend_from_slice(&nonce);
        requester_msg.extend_from_slice(&chunk_hash);
        requester_msg.extend_from_slice(&provider.public_key());
        requester_msg.extend_from_slice(&provider_sig);
        let requester_sig = requester.keypair.sign(&requester_msg);

        let proof = BandwidthProof {
            session_id: Uuid::new_v4(),
            content_cid: cid.to_string(),
            chunk_index,
            bytes_transferred: CHUNK_SIZE as u64,
            provider_peer_id: provider.peer_id.clone(),
            requester_peer_id: requester.peer_id.clone(),
            provider_public_key: provider.public_key().to_vec(),
            requester_public_key: requester.public_key().to_vec(),
            provider_signature: provider_sig.to_vec(),
            requester_signature: requester_sig.to_vec(),
            challenge_nonce: nonce.to_vec(),
            chunk_hash: chunk_hash.to_vec(),
            start_timestamp_ms: start_time,
            end_timestamp_ms: now,
            latency_ms,
        };

        // Update statistics
        self.nodes[provider_idx].bytes_uploaded += CHUNK_SIZE as u64;
        self.nodes[requester_idx].bytes_downloaded += CHUNK_SIZE as u64;
        self.nodes[provider_idx].proofs_generated.push(proof.clone());

        // Requester now has the chunk too
        self.nodes[requester_idx].pin_content(cid, &[chunk_index]);

        self.all_proofs.push(proof.clone());

        Ok(proof)
    }

    /// Get network statistics.
    fn get_stats(&self) -> NetworkStats {
        let total_uploaded: u64 = self.nodes.iter().map(|n| n.bytes_uploaded).sum();
        let total_downloaded: u64 = self.nodes.iter().map(|n| n.bytes_downloaded).sum();

        NetworkStats {
            node_count: self.nodes.len(),
            total_proofs: self.all_proofs.len(),
            total_bytes_transferred: total_uploaded,
            avg_bytes_per_node: total_uploaded / self.nodes.len() as u64,
            content_count: self.content_registry.len(),
            upload_by_node: self.nodes.iter().map(|n| n.bytes_uploaded).collect(),
            download_by_node: self.nodes.iter().map(|n| n.bytes_downloaded).collect(),
        }
    }
}

struct NetworkStats {
    node_count: usize,
    total_proofs: usize,
    total_bytes_transferred: u64,
    avg_bytes_per_node: u64,
    content_count: usize,
    upload_by_node: Vec<u64>,
    download_by_node: Vec<u64>,
}

/// Verify a proof is valid.
fn verify_proof(proof: &BandwidthProof) -> bool {
    // Verify provider signature
    let provider_pubkey: [u8; 32] = match proof.provider_public_key.as_slice().try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let provider_sig: [u8; 64] = match proof.provider_signature.as_slice().try_into() {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let mut provider_msg = Vec::new();
    provider_msg.extend_from_slice(&proof.challenge_nonce);
    provider_msg.extend_from_slice(&proof.chunk_hash);
    provider_msg.extend_from_slice(&proof.requester_public_key);

    if chie_crypto::verify(&provider_pubkey, &provider_msg, &provider_sig).is_err() {
        return false;
    }

    // Verify requester signature
    let requester_pubkey: [u8; 32] = match proof.requester_public_key.as_slice().try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let requester_sig: [u8; 64] = match proof.requester_signature.as_slice().try_into() {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let mut requester_msg = Vec::new();
    requester_msg.extend_from_slice(&proof.challenge_nonce);
    requester_msg.extend_from_slice(&proof.chunk_hash);
    requester_msg.extend_from_slice(&proof.provider_public_key);
    requester_msg.extend_from_slice(&proof.provider_signature);

    chie_crypto::verify(&requester_pubkey, &requester_msg, &requester_sig).is_ok()
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_5_node_mesh_basic() {
    let mut network = MeshNetwork::new(5);

    // Register content
    let cid = "QmTestContent5Nodes";
    let total_chunks = 10;
    network.register_content(cid, total_chunks);

    // Node 0 is the original seeder with all chunks
    network.nodes[0].pin_content(cid, &(0..total_chunks).collect::<Vec<_>>());

    // Each other node requests chunks from available providers
    for requester_idx in 1..5 {
        for chunk_idx in 0..total_chunks {
            let providers = network.find_providers(cid, chunk_idx);
            assert!(!providers.is_empty(), "No provider for chunk {}", chunk_idx);

            // Pick a provider (not self)
            let provider_idx = providers
                .iter()
                .find(|&&p| p != requester_idx)
                .copied()
                .unwrap();

            let proof = network
                .simulate_transfer(provider_idx, requester_idx, cid, chunk_idx)
                .expect("Transfer should succeed");

            // Verify the proof
            assert!(verify_proof(&proof), "Proof verification failed");
        }
    }

    let stats = network.get_stats();
    println!("Network Stats:");
    println!("  Nodes: {}", stats.node_count);
    println!("  Total Proofs: {}", stats.total_proofs);
    println!(
        "  Total Bytes: {} MB",
        stats.total_bytes_transferred / (1024 * 1024)
    );

    // Each of 4 nodes downloaded 10 chunks = 40 transfers
    assert_eq!(stats.total_proofs, 40);

    // All proofs should be valid
    for proof in &network.all_proofs {
        assert!(verify_proof(proof));
    }
}

#[test]
fn test_mesh_content_propagation() {
    let mut network = MeshNetwork::new(5);

    let cid = "QmPropagationTest";
    network.register_content(cid, 5);

    // Node 0 starts with chunk 0
    network.nodes[0].pin_content(cid, &[0]);

    // Propagate: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 4
    let transfers = [
        (0, 1, 0),
        (0, 2, 0),
        (1, 3, 0),
        (2, 4, 0),
    ];

    for (provider, requester, chunk) in transfers {
        let proof = network
            .simulate_transfer(provider, requester, cid, chunk)
            .expect("Transfer should succeed");
        assert!(verify_proof(&proof));
    }

    // Now all nodes should have chunk 0
    for (i, node) in network.nodes.iter().enumerate() {
        assert!(node.has_chunk(cid, 0), "Node {} should have chunk 0", i);
    }
}

#[test]
fn test_mesh_multi_content() {
    let mut network = MeshNetwork::new(5);

    // Multiple pieces of content
    let contents = [
        ("QmContent1", 3, 0),  // 3 chunks, seeded by node 0
        ("QmContent2", 5, 1),  // 5 chunks, seeded by node 1
        ("QmContent3", 2, 2),  // 2 chunks, seeded by node 2
    ];

    for (cid, chunks, seeder) in contents.iter() {
        network.register_content(cid, *chunks);
        network.nodes[*seeder].pin_content(cid, &(0..*chunks).collect::<Vec<_>>());
    }

    // Each node requests all content from all seeders
    for (cid, chunks, seeder) in contents.iter() {
        for requester in 0..5 {
            if requester == *seeder {
                continue;
            }
            for chunk in 0..*chunks {
                let proof = network
                    .simulate_transfer(*seeder, requester, cid, chunk)
                    .expect("Transfer should succeed");
                assert!(verify_proof(&proof));
            }
        }
    }

    let stats = network.get_stats();

    // 3 contents, (3 + 5 + 2) * 4 requesters = 40 transfers
    assert_eq!(stats.total_proofs, 40);
}

#[test]
fn test_mesh_parallel_transfers() {
    let mut network = MeshNetwork::new(5);

    let cid = "QmParallelContent";
    network.register_content(cid, 20);

    // Node 0 has all chunks
    network.nodes[0].pin_content(cid, &(0..20).collect::<Vec<_>>());

    // Simulate parallel requests from all nodes
    // Each node requests different chunks to avoid overlap
    for requester in 1..5 {
        let start_chunk = ((requester - 1) * 5) as u64;
        let end_chunk = start_chunk + 5;

        for chunk in start_chunk..end_chunk {
            let proof = network
                .simulate_transfer(0, requester, cid, chunk)
                .expect("Transfer should succeed");
            assert!(verify_proof(&proof));
        }
    }

    let stats = network.get_stats();

    // 4 requesters * 5 chunks each = 20 transfers
    assert_eq!(stats.total_proofs, 20);

    // All proofs should be unique (different session_ids)
    let session_ids: HashSet<_> = network.all_proofs.iter().map(|p| p.session_id).collect();
    assert_eq!(session_ids.len(), 20);
}

#[test]
fn test_mesh_swarm_distribution() {
    let mut network = MeshNetwork::new(5);

    let cid = "QmSwarmContent";
    let total_chunks = 10u64;
    network.register_content(cid, total_chunks);

    // Node 0 has all chunks initially
    network.nodes[0].pin_content(cid, &(0..total_chunks).collect::<Vec<_>>());

    // Round 1: Nodes 1,2 get from node 0
    for chunk in 0..5 {
        network.simulate_transfer(0, 1, cid, chunk).unwrap();
    }
    for chunk in 5..10 {
        network.simulate_transfer(0, 2, cid, chunk).unwrap();
    }

    // Round 2: Nodes 3,4 get from nodes 1,2 (swarm behavior)
    for chunk in 0..5 {
        // Node 1 now has chunks 0-4
        network.simulate_transfer(1, 3, cid, chunk).unwrap();
        network.simulate_transfer(1, 4, cid, chunk).unwrap();
    }
    for chunk in 5..10 {
        // Node 2 has chunks 5-9
        network.simulate_transfer(2, 3, cid, chunk).unwrap();
        network.simulate_transfer(2, 4, cid, chunk).unwrap();
    }

    let stats = network.get_stats();

    // 10 + 20 = 30 transfers
    assert_eq!(stats.total_proofs, 30);

    // Node 0 uploaded least (only initial seeding)
    // Nodes 1,2 uploaded more (they re-seeded)
    assert!(stats.upload_by_node[1] > stats.upload_by_node[0] / 2);
    assert!(stats.upload_by_node[2] > stats.upload_by_node[0] / 2);
}

#[test]
fn test_mesh_all_proofs_tamper_resistant() {
    let mut network = MeshNetwork::new(5);

    let cid = "QmTamperTest";
    network.register_content(cid, 5);
    network.nodes[0].pin_content(cid, &[0, 1, 2, 3, 4]);

    // Generate some proofs
    for requester in 1..5 {
        for chunk in 0..5u64 {
            network.simulate_transfer(0, requester, cid, chunk).unwrap();
        }
    }

    // Try to tamper with each proof and verify detection
    for proof in &network.all_proofs {
        // Original should verify
        assert!(verify_proof(proof));

        // Tampered provider signature should fail
        let mut tampered = proof.clone();
        tampered.provider_signature[0] ^= 0xFF;
        assert!(!verify_proof(&tampered));

        // Tampered requester signature should fail
        let mut tampered = proof.clone();
        tampered.requester_signature[0] ^= 0xFF;
        assert!(!verify_proof(&tampered));

        // Tampered nonce should fail (signature won't match)
        let mut tampered = proof.clone();
        tampered.challenge_nonce[0] ^= 0xFF;
        assert!(!verify_proof(&tampered));

        // Tampered chunk hash should fail
        let mut tampered = proof.clone();
        tampered.chunk_hash[0] ^= 0xFF;
        assert!(!verify_proof(&tampered));
    }
}

#[test]
fn test_mesh_node_availability_changes() {
    let mut network = MeshNetwork::new(5);

    let cid = "QmAvailabilityTest";
    network.register_content(cid, 10);

    // Initially only node 0 has content
    network.nodes[0].pin_content(cid, &(0..10).collect::<Vec<_>>());

    // Node 1 downloads first half
    for chunk in 0..5 {
        network.simulate_transfer(0, 1, cid, chunk).unwrap();
    }

    // Node 2 can now get from either node 0 or node 1 for first half
    for chunk in 0..5 {
        let providers = network.find_providers(cid, chunk);
        assert!(providers.len() >= 2, "Should have multiple providers");

        // Get from node 1 (not the original seeder)
        network.simulate_transfer(1, 2, cid, chunk).unwrap();
    }

    // For second half, only node 0 has it
    for chunk in 5..10 {
        let providers = network.find_providers(cid, chunk);
        assert_eq!(providers, vec![0], "Only node 0 should have chunk {}", chunk);
        network.simulate_transfer(0, 2, cid, chunk).unwrap();
    }

    // Verify node 2 now has all chunks
    for chunk in 0..10 {
        assert!(network.nodes[2].has_chunk(cid, chunk));
    }
}
