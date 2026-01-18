//! Protocol version negotiation demonstration.

use chie_p2p::{
    CURRENT_VERSION, NodeCapabilities, ProtocolVersion, VersionNegotiator, VersionRequest,
};

fn main() {
    println!("=== CHIE P2P Protocol Demo ===\n");

    println!("Current protocol version: {}\n", CURRENT_VERSION);

    // Create a version negotiator
    let negotiator = VersionNegotiator::new();

    // Simulate a client request
    let request = VersionRequest {
        supported_versions: vec![ProtocolVersion::new(1, 0, 0)],
        current_version: CURRENT_VERSION,
        capabilities: NodeCapabilities::full(),
    };

    // Handle the negotiation
    let response = negotiator.handle_request(&request);

    if response.success {
        println!("✓ Negotiation successful");
        if let Some(version) = response.selected_version {
            println!("  Agreed version: {}", version);
        }
    } else {
        println!("✗ Negotiation failed: {:?}", response.error);
    }

    // Show capability compatibility
    println!("\nCapability features:");
    let caps = NodeCapabilities::full();
    println!("  Streaming: {}", caps.streaming);
    println!("  Compression: {}", caps.compression);
    println!("  Encryption: {}", caps.encryption);
    println!("  Max chunk size: {} bytes", caps.max_chunk_size);
}
