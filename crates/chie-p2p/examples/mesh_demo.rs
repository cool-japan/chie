//! Mesh simulation demonstration.
//!
//! This example shows basic P2P mesh network functionality.

use chie_p2p::MeshSimulation;

fn main() {
    println!("=== CHIE P2P Mesh Simulation Demo ===\n");

    // Create a 5-node mesh
    println!("Creating 5-node mesh...");
    let mut mesh = MeshSimulation::five_node();
    let peer_ids = mesh.initialize().to_vec();

    println!("✓ Created {} nodes\n", peer_ids.len());

    // Add content seeders
    let cid = "bafyexample123";
    mesh.add_seeder(&peer_ids[0], cid);
    mesh.add_seeder(&peer_ids[1], cid);

    let seeders = mesh.find_seeders(cid);
    println!("Content '{}' is seeded by {} nodes\n", cid, seeders.len());

    // Simulate a transfer
    println!("Simulating chunk transfer...");
    let chunk_data = vec![0xAB; 65536]; // 64KB

    match mesh.simulate_transfer(&peer_ids[2], &peer_ids[0], cid, 0, &chunk_data) {
        Ok(transfer) => {
            println!("✓ Transfer completed successfully");
            println!("  Bytes: {}", transfer.bytes_transferred);
            println!("  Latency: {}ms\n", transfer.latency_ms);
        }
        Err(e) => {
            eprintln!("✗ Transfer failed: {}\n", e);
        }
    }

    // Show statistics
    let stats = mesh.stats();
    println!("Network Statistics:");
    println!("  Successful transfers: {}", stats.successful_transfers);
    println!("  Total bytes: {}", stats.bytes_transferred);
    println!("  Proofs generated: {}", stats.proofs_generated);
}
