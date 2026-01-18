//! Performance benchmarks for chie-p2p crate.

use chie_p2p::*;
use chie_shared::{ChunkRequest, ChunkResponse};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use libp2p::{Multiaddr, PeerId};
use std::hint::black_box;
use std::time::Duration;

/// Benchmark codec serialization and deserialization.
fn bench_codec_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec");

    // Create test data
    let request = ChunkRequest {
        content_cid: "QmTest123456789".to_string(),
        chunk_index: 42,
        challenge_nonce: [1u8; 32],
        requester_peer_id: "12D3KooWTest".to_string(),
        requester_public_key: [2u8; 32],
        timestamp_ms: 1234567890000,
    };

    let response = ChunkResponse {
        encrypted_chunk: vec![0u8; 256 * 1024], // 256 KB chunk
        chunk_hash: [5u8; 32],
        provider_signature: vec![3u8; 64],
        provider_public_key: [4u8; 32],
        challenge_echo: [1u8; 32],
        timestamp_ms: 1234567890001,
    };

    group.bench_function("serialize_request", |b| {
        b.iter(|| {
            let data =
                oxicode::serde::encode_to_vec(black_box(&request), oxicode::config::standard())
                    .unwrap();
            black_box(data);
        });
    });

    group.bench_function("deserialize_request", |b| {
        let data = oxicode::serde::encode_to_vec(&request, oxicode::config::standard()).unwrap();
        b.iter(|| {
            let (req, _): (ChunkRequest, _) =
                oxicode::serde::decode_from_slice(black_box(&data), oxicode::config::standard())
                    .unwrap();
            black_box(req);
        });
    });

    group.bench_function("serialize_response", |b| {
        b.iter(|| {
            let data =
                oxicode::serde::encode_to_vec(black_box(&response), oxicode::config::standard())
                    .unwrap();
            black_box(data);
        });
    });

    group.bench_function("deserialize_response", |b| {
        let data = oxicode::serde::encode_to_vec(&response, oxicode::config::standard()).unwrap();
        b.iter(|| {
            let (resp, _): (ChunkResponse, _) =
                oxicode::serde::decode_from_slice(black_box(&data), oxicode::config::standard())
                    .unwrap();
            black_box(resp);
        });
    });

    group.finish();
}

/// Benchmark throttling operations.
fn bench_throttle_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("throttle");

    let config = ThrottleConfig::default();
    let mut throttle = BandwidthThrottle::new(config);

    let peer_id_str = "12D3KooWTest".to_string();

    group.bench_function("try_upload", |b| {
        b.iter(|| {
            let result = throttle.try_upload(black_box(&peer_id_str), black_box(1024));
            black_box(result);
        });
    });

    group.bench_function("try_download", |b| {
        b.iter(|| {
            let result = throttle.try_download(black_box(&peer_id_str), black_box(1024));
            black_box(result);
        });
    });

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            let stats = throttle.stats();
            black_box(stats);
        });
    });

    group.finish();
}

/// Benchmark reputation system operations.
fn bench_reputation_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("reputation");

    let mut manager = ReputationManager::new(ReputationConfig::default());
    let peer_id = PeerId::random();

    group.bench_function("record_transfer_success", |b| {
        b.iter(|| {
            manager.record_transfer(black_box(&peer_id), true, 50);
        });
    });

    group.bench_function("record_transfer_failure", |b| {
        b.iter(|| {
            manager.record_transfer(black_box(&peer_id), false, 500);
        });
    });

    group.bench_function("get_score", |b| {
        b.iter(|| {
            let score = manager.get_score(black_box(&peer_id));
            black_box(score);
        });
    });

    // Add some peers for ranking
    for _ in 0..100 {
        let pid = PeerId::random();
        manager.record_transfer(&pid, true, 50);
    }

    group.bench_function("get_peers_by_score", |b| {
        b.iter(|| {
            let peers = manager.get_peers_by_score();
            black_box(peers);
        });
    });

    group.finish();
}

/// Benchmark metrics collection.
fn bench_metrics_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics");

    let collector = create_metrics_collector(MetricsConfig::default());

    group.bench_function("record_sent_bytes", |b| {
        b.iter(|| {
            collector.bandwidth.record_sent(black_box(1024));
        });
    });

    group.bench_function("record_received_bytes", |b| {
        b.iter(|| {
            collector.bandwidth.record_received(black_box(1024));
        });
    });

    group.bench_function("record_connection", |b| {
        b.iter(|| {
            collector.connections.connection_established();
        });
    });

    group.bench_function("get_uptime", |b| {
        b.iter(|| {
            let uptime = collector.uptime();
            black_box(uptime);
        });
    });

    group.finish();
}

/// Benchmark discovery operations.
fn bench_discovery_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("discovery");

    let mut manager = ContentAdvertisementManager::default();

    group.bench_function("add_content", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let cid = format!("QmTest{}", i);
            manager.add_content(black_box(cid), black_box(1024 * 1024), black_box(4));
            i += 1;
        });
    });

    // Add some content first
    for i in 0..100 {
        manager.add_content(format!("QmTest{}", i), 1024 * 1024, 4);
    }

    group.bench_function("has_content", |b| {
        b.iter(|| {
            let has = manager.has_content(black_box("QmTest50"));
            black_box(has);
        });
    });

    group.bench_function("get_pending_advertisements", |b| {
        b.iter(|| {
            let pending = manager.get_pending_advertisements();
            black_box(pending);
        });
    });

    group.bench_function("cid_to_dht_key", |b| {
        b.iter(|| {
            let key = cid_to_dht_key(black_box("QmTest123456789"));
            black_box(key);
        });
    });

    group.finish();
}

/// Benchmark bootstrap manager operations.
fn bench_bootstrap_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("bootstrap");

    let custom_addrs = vec![
        "/ip4/127.0.0.1/tcp/4001".to_string(),
        "/ip4/127.0.0.1/tcp/4002".to_string(),
        "/ip4/127.0.0.1/tcp/4003".to_string(),
    ];

    let config =
        DiscoveryConfig::default().with_bootstrap_source(BootstrapSource::Custom(custom_addrs));

    group.bench_function("create_manager", |b| {
        b.iter(|| {
            let manager = BootstrapManager::new(black_box(config.clone()));
            black_box(manager);
        });
    });

    let mut manager = BootstrapManager::new(config);
    manager.load_bootstrap_nodes().unwrap();

    group.bench_function("get_healthy_nodes", |b| {
        b.iter(|| {
            let nodes = manager.get_healthy_nodes();
            black_box(nodes);
        });
    });

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            let stats = manager.get_stats();
            black_box(stats);
        });
    });

    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    group.bench_function("update_node_health", |b| {
        b.iter(|| {
            manager.update_node_health(black_box(&addr), black_box(true));
        });
    });

    group.finish();
}

/// Benchmark connection manager operations.
fn bench_connection_manager_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_manager");

    let config = ConnectionManagerConfig::default();
    let mut manager = ConnectionManager::new(config);

    let peer_id = PeerId::random();

    group.bench_function("check_connection", |b| {
        b.iter(|| {
            let result = manager.check_connection(black_box(&peer_id));
            black_box(result);
        });
    });

    group.bench_function("record_success", |b| {
        b.iter(|| {
            manager.record_success(
                black_box(&peer_id),
                black_box(1024),
                black_box(Duration::from_millis(50)),
            );
        });
    });

    // Record some successes
    for _ in 0..10 {
        let pid = PeerId::random();
        manager.record_success(&pid, 1024, Duration::from_millis(50));
    }

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            let stats = manager.stats();
            black_box(stats);
        });
    });

    group.finish();
}

/// Benchmark protocol version negotiation.
fn bench_protocol_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol");

    let negotiator = VersionNegotiator::new();
    let remote_version = ProtocolVersion::new(1, 0, 0);

    group.bench_function("create_version_request", |b| {
        b.iter(|| {
            let request = negotiator.create_request();
            black_box(request);
        });
    });

    group.bench_function("handle_version_request", |b| {
        let request = negotiator.create_request();
        b.iter(|| {
            let response = negotiator.handle_request(black_box(&request));
            black_box(response);
        });
    });

    group.bench_function("check_version_compatibility", |b| {
        b.iter(|| {
            let result = remote_version.is_compatible_with(black_box(&CURRENT_VERSION));
            black_box(result);
        });
    });

    let caps = NodeCapabilities::default();
    group.bench_function("check_capability_compatibility", |b| {
        b.iter(|| {
            let result = caps.is_compatible_with(black_box(&caps));
            black_box(result);
        });
    });

    group.finish();
}

/// Benchmark varying data sizes.
fn bench_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("varying_sizes");

    // Test different chunk sizes
    for size_kb in [1, 16, 64, 256, 1024].iter() {
        let size_bytes = size_kb * 1024;

        group.bench_with_input(
            BenchmarkId::new("serialize_chunk", size_kb),
            &size_bytes,
            |b, &size| {
                let response = ChunkResponse {
                    encrypted_chunk: vec![0u8; size],
                    chunk_hash: [0u8; 32],
                    provider_signature: vec![0u8; 64],
                    provider_public_key: [0u8; 32],
                    challenge_echo: [0u8; 32],
                    timestamp_ms: 1234567890000,
                };

                b.iter(|| {
                    let data = oxicode::serde::encode_to_vec(
                        black_box(&response),
                        oxicode::config::standard(),
                    )
                    .unwrap();
                    black_box(data);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_codec_operations,
    bench_throttle_operations,
    bench_reputation_operations,
    bench_metrics_operations,
    bench_discovery_operations,
    bench_bootstrap_operations,
    bench_connection_manager_operations,
    bench_protocol_operations,
    bench_varying_sizes,
);

criterion_main!(benches);
