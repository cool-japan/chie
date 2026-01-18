use chie_core::{ReputationConfig, ReputationTracker};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn create_test_manager() -> ReputationTracker {
    let config = ReputationConfig {
        initial_score: 0.5,
        min_score: 0.0,
        max_score: 1.0,
        success_weight: 0.01,
        failure_weight: 0.05,
        latency_weight: 0.001,
        decay_rate: 0.1,
        max_decay_duration: Duration::from_secs(7 * 24 * 3600),
    };
    ReputationTracker::new(config)
}

fn bench_record_success(c: &mut Criterion) {
    let mut manager = create_test_manager();

    c.bench_function("reputation_record_success", |b| {
        let mut peer_id = 0u64;
        b.iter(|| {
            let peer = format!("peer-{}", peer_id);
            manager.record_success(black_box(peer), black_box(1024 * 1024));
            peer_id += 1;
        });
    });
}

fn bench_record_failure(c: &mut Criterion) {
    let mut manager = create_test_manager();

    c.bench_function("reputation_record_failure", |b| {
        let mut peer_id = 0u64;
        b.iter(|| {
            let peer = format!("peer-{}", peer_id);
            manager.record_failure(black_box(peer), black_box(1024));
            peer_id += 1;
        });
    });
}

fn bench_record_latency(c: &mut Criterion) {
    let mut manager = create_test_manager();

    // Pre-populate with some peers
    for i in 0..100 {
        let peer = format!("peer-{}", i);
        manager.record_success(peer, 1024);
    }

    c.bench_function("reputation_record_latency", |b| {
        b.iter(|| {
            let peer = format!("peer-{}", black_box(50));
            manager.record_latency(black_box(peer), black_box(100));
        });
    });
}

fn bench_get_reputation(c: &mut Criterion) {
    let mut manager = create_test_manager();

    // Pre-populate with peers
    for i in 0..1000 {
        let peer = format!("peer-{}", i);
        manager.record_success(peer, 1024);
    }

    c.bench_function("reputation_get_reputation", |b| {
        b.iter(|| {
            let peer = format!("peer-{}", black_box(500));
            black_box(manager.get_reputation(&peer));
        });
    });
}

fn bench_get_trusted_peers(c: &mut Criterion) {
    let mut manager = create_test_manager();

    // Create diverse peer scores
    for i in 0..100 {
        let peer = format!("peer-{}", i);
        for _j in 0..(i % 10) {
            manager.record_success(peer.clone(), 1024);
        }
    }

    c.bench_function("reputation_get_trusted_peers", |b| {
        b.iter(|| {
            black_box(manager.get_trusted_peers(black_box(0.6)));
        });
    });
}

fn bench_get_top_peers(c: &mut Criterion) {
    let mut manager = create_test_manager();

    // Create diverse peer scores
    for i in 0..100 {
        let peer = format!("peer-{}", i);
        for _j in 0..(i % 10) {
            manager.record_success(peer.clone(), 1024);
        }
    }

    let mut group = c.benchmark_group("reputation_get_top_peers");
    for n in [5, 10, 20, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            b.iter(|| {
                black_box(manager.get_top_peers(black_box(n)));
            });
        });
    }
    group.finish();
}

fn bench_ban_unban_operations(c: &mut Criterion) {
    let mut manager = create_test_manager();

    c.bench_function("reputation_ban_peer", |b| {
        let mut peer_id = 0u64;
        b.iter(|| {
            let peer = format!("peer-{}", peer_id);
            manager.ban_peer(black_box(peer));
            peer_id += 1;
        });
    });

    // Reset for unban test
    let mut manager = create_test_manager();
    for i in 0..1000 {
        let peer = format!("peer-{}", i);
        manager.ban_peer(peer);
    }

    c.bench_function("reputation_unban_peer", |b| {
        b.iter(|| {
            let peer = format!("peer-{}", black_box(500));
            manager.unban_peer(black_box(&peer));
        });
    });
}

fn bench_statistics(c: &mut Criterion) {
    let mut manager = create_test_manager();

    // Populate with data
    for i in 0..100 {
        let peer = format!("peer-{}", i);
        for _j in 0..(i % 10) {
            manager.record_success(peer.clone(), 1024);
        }
        if i % 5 == 0 {
            manager.ban_peer(peer);
        }
    }

    c.bench_function("reputation_statistics", |b| {
        b.iter(|| {
            black_box(manager.get_stats());
        });
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    let mut manager = create_test_manager();

    c.bench_function("reputation_mixed_operations", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let peer_id = counter % 100;
            manager.record_success(format!("peer-{}", peer_id), 1024);
            manager.record_latency(format!("peer-{}", peer_id), 50);
            if counter % 10 == 0 {
                manager.record_failure(format!("peer-{}", peer_id), 100);
            }
            let _ = manager.get_reputation(&format!("peer-{}", peer_id));
            counter += 1;
        });
    });
}

criterion_group!(
    benches,
    bench_record_success,
    bench_record_failure,
    bench_record_latency,
    bench_get_reputation,
    bench_get_trusted_peers,
    bench_get_top_peers,
    bench_ban_unban_operations,
    bench_statistics,
    bench_mixed_operations
);

criterion_main!(benches);
