//! Bootstrap Node Management Example
//!
//! This example demonstrates how to use the bootstrap node management system
//! in the CHIE P2P network, including:
//! - Loading bootstrap nodes from different sources
//! - Health monitoring
//! - Statistics tracking
//! - Fallback mechanisms

use chie_p2p::{BootstrapManager, BootstrapSource, DiscoveryConfig};
use std::time::Duration;

fn main() {
    // Initialize tracing for better visibility
    tracing_subscriber::fmt::init();

    println!("=== CHIE P2P Bootstrap Node Management Demo ===\n");

    // Example 1: Static Bootstrap Nodes
    demo_static_bootstrap();

    // Example 2: Custom Bootstrap Nodes
    demo_custom_bootstrap();

    // Example 3: Environment Variable Bootstrap
    demo_environment_bootstrap();

    // Example 4: Bootstrap Health Monitoring
    demo_health_monitoring();

    // Example 5: Bootstrap Statistics
    demo_statistics();

    println!("\n=== Demo Complete ===");
}

/// Demonstrate using static (hardcoded) bootstrap nodes.
fn demo_static_bootstrap() {
    println!("--- Example 1: Static Bootstrap Nodes ---");

    let config = DiscoveryConfig::default();
    let manager = BootstrapManager::new(config);

    println!("Created bootstrap manager with static configuration");
    println!("Bootstrap nodes: {:?}", manager.get_nodes().len());

    let stats = manager.get_stats();
    println!("Initial stats: {} total nodes\n", stats.total_nodes);
}

/// Demonstrate using custom bootstrap nodes.
fn demo_custom_bootstrap() {
    println!("--- Example 2: Custom Bootstrap Nodes ---");

    // Define custom bootstrap nodes
    let custom_nodes = vec![
        // TCP bootstrap nodes
        "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWBootstrap1Example".to_string(),
        "/ip4/203.0.113.20/tcp/4001/p2p/12D3KooWBootstrap2Example".to_string(),
        // QUIC bootstrap nodes
        "/ip4/203.0.113.30/udp/4001/quic-v1/p2p/12D3KooWBootstrap3Example".to_string(),
        // DNS-based bootstrap nodes
        "/dns4/bootstrap1.chie.network/tcp/4001/p2p/12D3KooWBootstrap4Example".to_string(),
        "/dns6/bootstrap2.chie.network/tcp/4001/p2p/12D3KooWBootstrap5Example".to_string(),
    ];

    let config = DiscoveryConfig::default()
        .with_bootstrap_source(BootstrapSource::Custom(custom_nodes.clone()))
        .with_bootstrap_fallback(true)
        .with_health_check_interval(Duration::from_secs(300)); // 5 minutes

    let mut manager = BootstrapManager::new(config);

    println!("Loading {} custom bootstrap nodes...", custom_nodes.len());
    match manager.load_bootstrap_nodes() {
        Ok(addrs) => {
            println!("Successfully loaded {} bootstrap nodes:", addrs.len());
            for (i, addr) in addrs.iter().enumerate() {
                println!("  {}. {}", i + 1, addr);
            }
        }
        Err(e) => {
            println!("Failed to load bootstrap nodes: {}", e);
        }
    }

    let stats = manager.get_stats();
    println!(
        "Stats: {} total, {} unknown health\n",
        stats.total_nodes, stats.unknown_nodes
    );
}

/// Demonstrate loading bootstrap nodes from environment variables.
fn demo_environment_bootstrap() {
    println!("--- Example 3: Environment Variable Bootstrap ---");

    // In practice, you would set this environment variable before running:
    // export CHIE_BOOTSTRAP_NODES="/ip4/1.2.3.4/tcp/4001/p2p/12D3...,/dns4/node.example.com/tcp/4001/p2p/12D3..."

    println!("To use environment variable bootstrap, set:");
    println!("  export CHIE_BOOTSTRAP_NODES=\"addr1,addr2,addr3\"");
    println!("  export CHIE_BOOTSTRAP_DNS=\"bootstrap.chie.network\"");

    let config = DiscoveryConfig::default()
        .with_bootstrap_source(BootstrapSource::Environment)
        .with_bootstrap_fallback(true); // Fall back to static if env var not set

    let mut manager = BootstrapManager::new(config);

    println!("\nAttempting to load from environment...");
    match manager.load_bootstrap_nodes() {
        Ok(addrs) => {
            if addrs.is_empty() {
                println!("No bootstrap nodes loaded (likely using fallback)");
            } else {
                println!("Loaded {} nodes from environment", addrs.len());
            }
        }
        Err(e) => {
            println!("Error loading from environment: {}", e);
            println!("Fallback to static nodes would be used if enabled");
        }
    }
    println!();
}

/// Demonstrate bootstrap node health monitoring.
fn demo_health_monitoring() {
    println!("--- Example 4: Bootstrap Health Monitoring ---");

    let custom_nodes = vec![
        "/ip4/127.0.0.1/tcp/4001".to_string(),
        "/ip4/127.0.0.1/tcp/4002".to_string(),
        "/ip4/127.0.0.1/tcp/4003".to_string(),
    ];

    let config = DiscoveryConfig::default()
        .with_bootstrap_source(BootstrapSource::Custom(custom_nodes))
        .with_health_check_interval(Duration::from_secs(60));

    let mut manager = BootstrapManager::new(config);
    manager.load_bootstrap_nodes().unwrap();

    println!("Loaded {} bootstrap nodes", manager.get_nodes().len());

    // Simulate health checks
    println!("\nSimulating health checks...");

    // Collect nodes first to avoid borrow checker issues
    let nodes: Vec<_> = manager.get_nodes().iter().map(|n| n.addr.clone()).collect();

    for addr in nodes {
        let is_healthy = addr.to_string().contains("4001") || addr.to_string().contains("4002");

        manager.update_node_health(&addr, is_healthy);

        let status = if is_healthy { "HEALTHY" } else { "UNHEALTHY" };
        println!("  {} - {}", addr, status);
    }

    // Check which nodes need health checks
    println!("\nNodes needing health check:");
    let needs_check = manager.get_nodes_needing_check();
    if needs_check.is_empty() {
        println!("  None (all recently checked)");
    } else {
        for node in needs_check {
            println!("  {}", node.addr);
        }
    }

    // Get only healthy nodes
    println!("\nHealthy nodes:");
    let healthy = manager.get_healthy_nodes();
    for node in healthy {
        println!(
            "  {} (success rate: {:.1}%)",
            node.addr,
            node.success_rate() * 100.0
        );
    }
    println!();
}

/// Demonstrate bootstrap statistics and monitoring.
fn demo_statistics() {
    println!("--- Example 5: Bootstrap Statistics ---");

    let custom_nodes = vec![
        "/ip4/127.0.0.1/tcp/4001".to_string(),
        "/ip4/127.0.0.1/tcp/4002".to_string(),
        "/ip4/127.0.0.1/tcp/4003".to_string(),
        "/ip4/127.0.0.1/tcp/4004".to_string(),
        "/ip4/127.0.0.1/tcp/4005".to_string(),
    ];

    let config =
        DiscoveryConfig::default().with_bootstrap_source(BootstrapSource::Custom(custom_nodes));

    let mut manager = BootstrapManager::new(config);
    manager.load_bootstrap_nodes().unwrap();

    // Simulate various health states
    let nodes: Vec<_> = manager.get_nodes().iter().map(|n| n.addr.clone()).collect();

    // Mark some as healthy
    manager.update_node_health(&nodes[0], true);
    manager.update_node_health(&nodes[1], true);
    manager.update_node_health(&nodes[2], true);

    // Mark some as unhealthy
    manager.update_node_health(&nodes[3], false);

    // Leave nodes[4] as unknown

    let stats = manager.get_stats();

    println!("Bootstrap Network Statistics:");
    println!("  Total nodes:     {}", stats.total_nodes);
    println!(
        "  Healthy nodes:   {} ({:.1}%)",
        stats.healthy_nodes,
        (stats.healthy_nodes as f64 / stats.total_nodes as f64) * 100.0
    );
    println!(
        "  Unhealthy nodes: {} ({:.1}%)",
        stats.unhealthy_nodes,
        (stats.unhealthy_nodes as f64 / stats.total_nodes as f64) * 100.0
    );
    println!(
        "  Unknown nodes:   {} ({:.1}%)",
        stats.unknown_nodes,
        (stats.unknown_nodes as f64 / stats.total_nodes as f64) * 100.0
    );

    // Detailed node information
    println!("\nDetailed Node Information:");
    for node in manager.get_nodes() {
        println!(
            "  {} - Status: {:?}, Success: {}, Failures: {}, Rate: {:.1}%",
            node.addr,
            node.health,
            node.success_count,
            node.failure_count,
            node.success_rate() * 100.0
        );
    }
}

// Example usage in production code:
#[allow(dead_code)]
fn production_example() {
    // Production configuration with all best practices
    let config = DiscoveryConfig::default()
        // Try environment variable first
        .with_bootstrap_source(BootstrapSource::Environment)
        // Fall back to static nodes if environment variable not set
        .with_bootstrap_fallback(true)
        // Check health every 5 minutes
        .with_health_check_interval(Duration::from_secs(300));

    let mut manager = BootstrapManager::new(config);

    // Load bootstrap nodes
    match manager.load_bootstrap_nodes() {
        Ok(addrs) => {
            tracing::info!("Loaded {} bootstrap nodes", addrs.len());

            // In a real application, you would:
            // 1. Attempt connections to bootstrap nodes
            // 2. Update their health status based on connection success
            // 3. Periodically re-check health
            // 4. Use healthy nodes for peer discovery

            // Example health check (in practice, this would be async)
            // Collect addresses first to avoid borrow checker issues
            let addrs: Vec<_> = manager.get_nodes().iter().map(|n| n.addr.clone()).collect();

            for addr in addrs {
                // Simulate connection attempt
                let is_healthy = true; // Would be result of actual connection attempt

                manager.update_node_health(&addr, is_healthy);
            }

            // Get healthy nodes for connections
            let healthy_nodes = manager.get_healthy_nodes();
            tracing::info!("Found {} healthy bootstrap nodes", healthy_nodes.len());

            // Monitor statistics
            let stats = manager.get_stats();
            tracing::info!(
                "Bootstrap stats: {}/{} healthy",
                stats.healthy_nodes,
                stats.total_nodes
            );
        }
        Err(e) => {
            tracing::error!("Failed to load bootstrap nodes: {}", e);
        }
    }
}
