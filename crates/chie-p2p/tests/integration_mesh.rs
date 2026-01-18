//! Integration tests for mesh simulation.

use chie_p2p::{MeshConfig, MeshSimulation};
use std::time::Duration;

#[test]
fn test_two_node_mesh_basic() {
    let mut mesh = MeshSimulation::two_node();
    let peer_ids = mesh.initialize();

    assert_eq!(peer_ids.len(), 2, "Should create 2 nodes");
    assert_eq!(mesh.node_count(), 2, "Node count should be 2");
}

#[test]
fn test_five_node_mesh_basic() {
    let mut mesh = MeshSimulation::five_node();
    let peer_ids = mesh.initialize();

    assert_eq!(peer_ids.len(), 5, "Should create 5 nodes");
    assert_eq!(mesh.node_count(), 5, "Node count should be 5");
}

#[test]
fn test_seeder_management() {
    let mut mesh = MeshSimulation::two_node();
    let peer_ids = mesh.initialize().to_vec();

    let cid = "bafytest123";
    mesh.add_seeder(&peer_ids[0], cid);

    assert!(
        mesh.get_node(&peer_ids[0]).unwrap().is_seeding(cid),
        "Node 0 should be seeding"
    );
    assert!(
        !mesh.get_node(&peer_ids[1]).unwrap().is_seeding(cid),
        "Node 1 should not be seeding"
    );

    let seeders = mesh.find_seeders(cid);
    assert_eq!(seeders.len(), 1, "Should find 1 seeder");
    assert_eq!(seeders[0], peer_ids[0], "Seeder should be node 0");
}

#[test]
fn test_simulated_transfer() {
    let mut mesh = MeshSimulation::two_node();
    let peer_ids = mesh.initialize().to_vec();

    let provider_id = peer_ids[0];
    let requester_id = peer_ids[1];
    let cid = "bafytest123";

    mesh.add_seeder(&provider_id, cid);

    let chunk_data = vec![0xAB; 1024];
    let result = mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data);

    assert!(result.is_ok(), "Transfer should succeed");
}

#[test]
fn test_multiple_seeders() {
    let mut mesh = MeshSimulation::five_node();
    let peer_ids = mesh.initialize().to_vec();

    let cid = "bafytest123";
    mesh.add_seeder(&peer_ids[0], cid);
    mesh.add_seeder(&peer_ids[1], cid);
    mesh.add_seeder(&peer_ids[2], cid);

    let seeders = mesh.find_seeders(cid);
    assert_eq!(seeders.len(), 3, "Should find 3 seeders");

    for (i, peer_id) in peer_ids.iter().enumerate().take(3) {
        assert!(
            mesh.get_node(peer_id).unwrap().is_seeding(cid),
            "Node {} should be seeding",
            i
        );
    }
}

#[test]
fn test_transfer_without_seeder() {
    let mut mesh = MeshSimulation::two_node();
    let peer_ids = mesh.initialize().to_vec();

    let provider_id = peer_ids[0];
    let requester_id = peer_ids[1];
    let cid = "bafytest123";

    // Don't add seeder
    let chunk_data = vec![0xAB; 1024];
    let result = mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data);

    assert!(result.is_err(), "Transfer should fail without seeder");
}

#[test]
fn test_custom_node_count() {
    let config = MeshConfig {
        node_count: 3,
        enable_quic: false,
        ..Default::default()
    };

    let mut mesh = MeshSimulation::new(config);
    let peer_ids = mesh.initialize();

    assert_eq!(peer_ids.len(), 3, "Should create 3 nodes");
    assert_eq!(mesh.node_count(), 3, "Node count should be 3");
}

#[test]
fn test_mesh_stats_initialization() {
    let mut mesh = MeshSimulation::five_node();
    mesh.initialize();

    let stats = mesh.stats();

    assert_eq!(stats.chunk_transfers, 0, "No transfers yet");
    assert_eq!(stats.bytes_transferred, 0, "No bytes transferred yet");
    assert_eq!(stats.proofs_generated, 0, "No proofs generated yet");
    assert_eq!(stats.successful_transfers, 0, "No successful transfers yet");
    assert_eq!(stats.failed_transfers, 0, "No failed transfers yet");
}

#[test]
fn test_multiple_content_items() {
    let mut mesh = MeshSimulation::five_node();
    let peer_ids = mesh.initialize().to_vec();

    let cids = ["content1", "content2", "content3"];

    for (i, cid) in cids.iter().enumerate() {
        mesh.add_seeder(&peer_ids[i], cid);
    }

    for (i, cid) in cids.iter().enumerate() {
        let seeders = mesh.find_seeders(cid);
        assert_eq!(seeders.len(), 1, "Should find 1 seeder for content {}", i);
        assert_eq!(seeders[0], peer_ids[i]);
    }
}

#[test]
fn test_different_chunk_sizes() {
    let mut mesh = MeshSimulation::two_node();
    let peer_ids = mesh.initialize().to_vec();

    let provider_id = peer_ids[0];
    let requester_id = peer_ids[1];
    let cid = "bafytest123";

    mesh.add_seeder(&provider_id, cid);

    let sizes = vec![512, 1024, 4096, 16384, 65536];

    for size in sizes {
        let chunk_data = vec![0xAB; size];
        let result = mesh.simulate_transfer(&requester_id, &provider_id, cid, 0, &chunk_data);

        assert!(
            result.is_ok(),
            "Transfer should succeed for chunk size {}",
            size
        );
    }
}

#[test]
fn test_mesh_with_custom_timeout() {
    let config = MeshConfig {
        node_count: 2,
        max_simulation_time: Duration::from_secs(5),
        ..Default::default()
    };

    let mut mesh = MeshSimulation::new(config);
    let peer_ids = mesh.initialize();

    assert_eq!(peer_ids.len(), 2, "Should create 2 nodes");
}

#[test]
fn test_peer_id_uniqueness() {
    let mut mesh = MeshSimulation::five_node();
    let peer_ids = mesh.initialize();

    let mut seen = std::collections::HashSet::new();

    for peer_id in peer_ids {
        assert!(seen.insert(peer_id), "All peer IDs should be unique");
    }
}

#[test]
fn test_find_seeders_empty() {
    let mut mesh = MeshSimulation::five_node();
    mesh.initialize();

    let seeders = mesh.find_seeders("nonexistent-content");

    assert_eq!(
        seeders.len(),
        0,
        "Should find no seeders for nonexistent content"
    );
}
