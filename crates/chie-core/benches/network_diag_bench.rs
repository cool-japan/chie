use chie_core::NetworkMonitor;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn create_monitor() -> NetworkMonitor {
    NetworkMonitor::new()
}

#[allow(dead_code)]
fn create_monitor_with_history(size: usize) -> NetworkMonitor {
    NetworkMonitor::with_history_size(size)
}

fn bench_monitor_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_monitor_creation");

    group.bench_function("default", |b| {
        b.iter(NetworkMonitor::new);
    });

    let sizes = [50, 100, 500, 1000];
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| NetworkMonitor::with_history_size(black_box(size)));
        });
    }

    group.finish();
}

fn bench_record_latency(c: &mut Criterion) {
    let mut monitor = create_monitor();
    let mut group = c.benchmark_group("record_latency");

    // Pre-populate with some peers
    for i in 0..10 {
        monitor.record_latency(format!("peer-{}", i), 100);
    }

    group.bench_function("new_peer", |b| {
        let mut counter = 100u64;
        b.iter(|| {
            let peer = format!("peer-{}", counter);
            monitor.record_latency(black_box(peer), black_box(50));
            counter += 1;
        });
    });

    group.bench_function("existing_peer", |b| {
        b.iter(|| {
            monitor.record_latency(black_box("peer-5".to_string()), black_box(75));
        });
    });

    group.finish();
}

fn bench_record_bandwidth(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Pre-populate
    for i in 0..10 {
        monitor.record_latency(format!("peer-{}", i), 100);
    }

    c.bench_function("record_bandwidth", |b| {
        b.iter(|| {
            monitor.record_bandwidth(black_box("peer-5"), black_box(1024.0 * 1024.0));
        });
    });
}

fn bench_record_packet_loss(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Pre-populate
    for i in 0..10 {
        monitor.record_latency(format!("peer-{}", i), 100);
    }

    c.bench_function("record_packet_loss", |b| {
        b.iter(|| {
            monitor.record_packet_loss(black_box("peer-5"), black_box(5), black_box(100));
        });
    });
}

fn bench_quality_calculation(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Pre-populate with varied latencies
    for i in 0..50 {
        let latency = (i * 10) % 500;
        monitor.record_latency(format!("peer-{}", i), latency);
    }

    let mut group = c.benchmark_group("quality_calculation");

    group.bench_function("get_quality", |b| {
        b.iter(|| black_box(monitor.get_quality(black_box("peer-25"))));
    });

    group.bench_function("health_score", |b| {
        b.iter(|| black_box(monitor.health_score(black_box("peer-25"))));
    });

    group.finish();
}

fn bench_peer_filtering(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Create diverse peer quality levels
    for i in 0..100 {
        let latency = i * 5; // 0ms to 500ms
        monitor.record_latency(format!("peer-{}", i), latency);
    }

    let mut group = c.benchmark_group("peer_filtering");

    group.bench_function("get_healthy_peers", |b| {
        b.iter(|| black_box(monitor.get_healthy_peers()));
    });

    group.bench_function("get_excellent_peers", |b| {
        b.iter(|| black_box(monitor.get_excellent_peers()));
    });

    group.finish();
}

fn bench_statistics_aggregation(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Populate with extensive data
    for i in 0..100 {
        let peer = format!("peer-{}", i);
        for j in 0..10 {
            let latency = (i * 10 + j) % 500;
            monitor.record_latency(peer.clone(), latency);
        }
        monitor.record_bandwidth(&peer, (i * 1024) as f64);
        if i % 5 == 0 {
            monitor.record_packet_loss(&peer, 2, 100);
        }
    }

    let mut group = c.benchmark_group("statistics");

    group.bench_function("get_stats", |b| {
        b.iter(|| black_box(monitor.get_stats(black_box("peer-50"))));
    });

    group.bench_function("average_health", |b| {
        b.iter(|| black_box(monitor.average_health()));
    });

    group.finish();
}

fn bench_cleanup_old(c: &mut Criterion) {
    let mut group = c.benchmark_group("cleanup");

    group.bench_function("cleanup_old_peers", |b| {
        b.iter(|| {
            let mut monitor = create_monitor();
            // Add peers
            for i in 0..100 {
                monitor.record_latency(format!("peer-{}", i), 100);
            }
            // Cleanup (should remove peers older than threshold)
            monitor.cleanup_old_peers(black_box(0));
        });
    });

    group.finish();
}

fn bench_stability_detection(c: &mut Criterion) {
    let mut monitor = create_monitor();

    // Create stable and unstable peers
    for i in 0..10 {
        let peer = format!("stable-{}", i);
        for _ in 0..20 {
            monitor.record_latency(peer.clone(), 100); // Consistent latency
        }
    }

    for i in 0..10 {
        let peer = format!("unstable-{}", i);
        for j in 0..20 {
            monitor.record_latency(peer.clone(), 50 + (j * 20)); // Variable latency
        }
    }

    c.bench_function("check_stable_connection", |b| {
        b.iter(|| {
            if let Some(stats) = monitor.get_stats(black_box("stable-5")) {
                black_box(stats.is_stable());
            }
        });
    });
}

fn bench_quality_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("quality_classification");

    let qualities = [
        (10u64, "excellent"),
        (60u64, "good"),
        (150u64, "fair"),
        (350u64, "poor"),
        (600u64, "very_poor"),
    ];

    for (latency, name) in qualities.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(name), latency, |b, &latency| {
            b.iter(|| {
                let mut monitor = create_monitor();
                monitor.record_latency("test-peer".to_string(), black_box(latency));
                black_box(monitor.get_quality("test-peer"))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_monitor_creation,
    bench_record_latency,
    bench_record_bandwidth,
    bench_record_packet_loss,
    bench_quality_calculation,
    bench_peer_filtering,
    bench_statistics_aggregation,
    bench_cleanup_old,
    bench_stability_detection,
    bench_quality_classification
);

criterion_main!(benches);
