use chie_core::degradation::ResourcePressure;
use chie_core::qos::{Priority, QosConfig, QosManager, RequestInfo};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use std::hint::black_box;
use tokio::runtime::Runtime;

/// Helper to create a test request.
fn create_request(id: &str, cid: &str, size: u64, priority: Priority) -> RequestInfo {
    RequestInfo {
        id: id.to_string(),
        cid: cid.to_string(),
        size_bytes: size,
        priority,
        deadline_ms: None,
    }
}

/// Helper to create a request with deadline.
fn create_request_with_deadline(
    id: &str,
    cid: &str,
    size: u64,
    priority: Priority,
    deadline_ms: i64,
) -> RequestInfo {
    RequestInfo {
        id: id.to_string(),
        cid: cid.to_string(),
        size_bytes: size,
        priority,
        deadline_ms: Some(deadline_ms),
    }
}

/// Benchmark QosManager creation.
fn bench_qos_manager_creation(c: &mut Criterion) {
    c.bench_function("qos_manager_creation", |b| {
        b.iter(|| {
            let config = QosConfig::default();
            let manager = QosManager::new(black_box(config));
            black_box(manager);
        });
    });
}

/// Benchmark QosManager creation with custom config.
fn bench_qos_manager_custom_creation(c: &mut Criterion) {
    c.bench_function("qos_manager_custom_creation", |b| {
        b.iter(|| {
            let mut bandwidth_allocation = HashMap::new();
            bandwidth_allocation.insert(Priority::Critical, 50);
            bandwidth_allocation.insert(Priority::High, 30);
            bandwidth_allocation.insert(Priority::Normal, 15);
            bandwidth_allocation.insert(Priority::Low, 5);

            let mut sla_target_latency_ms = HashMap::new();
            sla_target_latency_ms.insert(Priority::Critical, 50);
            sla_target_latency_ms.insert(Priority::High, 200);
            sla_target_latency_ms.insert(Priority::Normal, 1000);
            sla_target_latency_ms.insert(Priority::Low, 5000);

            let config = QosConfig {
                max_queue_size: 10000,
                bandwidth_allocation,
                strict_priority: false,
                time_slice_ms: 50,
                sla_target_latency_ms,
            };
            let manager = QosManager::new(black_box(config));
            black_box(manager);
        });
    });
}

/// Benchmark enqueue operations with different priorities.
fn bench_enqueue_by_priority(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("qos_enqueue_by_priority");

    for priority in [
        Priority::Critical,
        Priority::High,
        Priority::Normal,
        Priority::Low,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", priority)),
            &priority,
            |b, &p| {
                b.iter(|| {
                    rt.block_on(async {
                        let config = QosConfig::default();
                        let mut manager = QosManager::new(config);
                        let request = create_request("req1", "QmTest", 1024, p);
                        let result = manager.enqueue(black_box(request)).await;
                        black_box(result);
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bulk enqueue operations.
fn bench_bulk_enqueue(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("qos_bulk_enqueue");

    for count in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_requests", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let config = QosConfig::default();
                        let mut manager = QosManager::new(config);

                        for i in 0..n {
                            let priority = match i % 4 {
                                0 => Priority::Critical,
                                1 => Priority::High,
                                2 => Priority::Normal,
                                _ => Priority::Low,
                            };
                            let request = create_request(
                                &format!("req{}", i),
                                &format!("QmTest{}", i),
                                1024,
                                priority,
                            );
                            let _ = manager.enqueue(request).await;
                        }

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark dequeue operations with strict priority.
fn bench_dequeue_strict_priority(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_dequeue_strict_priority", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig {
                    strict_priority: true,
                    ..QosConfig::default()
                };
                let mut manager = QosManager::new(config);

                // Enqueue requests with mixed priorities
                let _ = manager
                    .enqueue(create_request("low", "QmLow", 1024, Priority::Low))
                    .await;
                let _ = manager
                    .enqueue(create_request("normal", "QmNormal", 1024, Priority::Normal))
                    .await;
                let _ = manager
                    .enqueue(create_request("high", "QmHigh", 1024, Priority::High))
                    .await;
                let _ = manager
                    .enqueue(create_request(
                        "critical",
                        "QmCritical",
                        1024,
                        Priority::Critical,
                    ))
                    .await;

                // Dequeue should get critical first
                let result = manager.dequeue().await;
                black_box(result);
            });
        });
    });
}

/// Benchmark dequeue operations with fair scheduling.
fn bench_dequeue_fair_scheduling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_dequeue_fair_scheduling", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig {
                    strict_priority: false,
                    time_slice_ms: 100,
                    ..QosConfig::default()
                };
                let mut manager = QosManager::new(config);

                // Enqueue multiple requests per priority
                for i in 0..10 {
                    let _ = manager
                        .enqueue(create_request(
                            &format!("low{}", i),
                            "QmLow",
                            1024,
                            Priority::Low,
                        ))
                        .await;
                    let _ = manager
                        .enqueue(create_request(
                            &format!("normal{}", i),
                            "QmNormal",
                            1024,
                            Priority::Normal,
                        ))
                        .await;
                    let _ = manager
                        .enqueue(create_request(
                            &format!("high{}", i),
                            "QmHigh",
                            1024,
                            Priority::High,
                        ))
                        .await;
                }

                // Dequeue with fair scheduling
                let result = manager.dequeue().await;
                black_box(result);
            });
        });
    });
}

/// Benchmark deadline-based scheduling.
fn bench_deadline_scheduling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_deadline_scheduling", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                let now = chie_core::utils::current_timestamp_ms();

                // Enqueue requests with various deadlines
                let _ = manager
                    .enqueue(create_request_with_deadline(
                        "far_future",
                        "QmFar",
                        1024,
                        Priority::Low,
                        now + 10000,
                    ))
                    .await;
                let _ = manager
                    .enqueue(create_request_with_deadline(
                        "urgent",
                        "QmUrgent",
                        1024,
                        Priority::Low,
                        now + 50, // Within 100ms threshold
                    ))
                    .await;
                let _ = manager
                    .enqueue(create_request("high_prio", "QmHigh", 1024, Priority::High))
                    .await;

                // Dequeue should prioritize urgent deadline over high priority
                let result = manager.dequeue().await;
                black_box(result);
            });
        });
    });
}

/// Benchmark queue depth queries.
fn bench_queue_depth_queries(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_queue_depth_queries", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                // Populate queues
                for i in 0..100 {
                    let priority = match i % 4 {
                        0 => Priority::Critical,
                        1 => Priority::High,
                        2 => Priority::Normal,
                        _ => Priority::Low,
                    };
                    let _ = manager
                        .enqueue(create_request(
                            &format!("req{}", i),
                            "QmTest",
                            1024,
                            priority,
                        ))
                        .await;
                }

                // Query depths
                let critical_depth = manager.queue_depth(Priority::Critical);
                let high_depth = manager.queue_depth(Priority::High);
                let normal_depth = manager.queue_depth(Priority::Normal);
                let low_depth = manager.queue_depth(Priority::Low);
                let total_depth = manager.total_queue_depth();

                black_box((
                    critical_depth,
                    high_depth,
                    normal_depth,
                    low_depth,
                    total_depth,
                ));
            });
        });
    });
}

/// Benchmark SLA metrics tracking.
fn bench_sla_metrics_tracking(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_sla_metrics_tracking", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                // Enqueue and dequeue to generate metrics
                for i in 0..50 {
                    let priority = if i % 2 == 0 {
                        Priority::High
                    } else {
                        Priority::Normal
                    };
                    let _ = manager
                        .enqueue(create_request(
                            &format!("req{}", i),
                            "QmTest",
                            1024,
                            priority,
                        ))
                        .await;
                }

                for _ in 0..25 {
                    let _ = manager.dequeue().await;
                }

                // Query SLA metrics
                let high_metrics = manager.get_sla_metrics(Priority::High);
                let normal_metrics = manager.get_sla_metrics(Priority::Normal);
                let all_metrics = manager.get_all_sla_metrics();
                let compliance = manager.overall_compliance_rate();

                black_box((high_metrics, normal_metrics, all_metrics, compliance));
            });
        });
    });
}

/// Benchmark resource pressure updates.
fn bench_resource_pressure_updates(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_resource_pressure_updates", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                let pressure = ResourcePressure {
                    cpu_usage: 0.75,
                    memory_usage: 0.80,
                    disk_usage: 0.60,
                    bandwidth_usage: 0.85,
                };

                manager.update_resource_pressure(black_box(pressure));

                let retrieved = manager.get_resource_pressure();
                let is_high = manager.is_under_high_pressure();
                let adaptive_limit = manager.adaptive_queue_limit();
                let should_throttle_low = manager.should_throttle_priority(Priority::Low);

                black_box((retrieved, is_high, adaptive_limit, should_throttle_low));
            });
        });
    });
}

/// Benchmark capacity checks.
fn bench_capacity_checks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_capacity_checks", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig {
                    max_queue_size: 100,
                    ..QosConfig::default()
                };
                let mut manager = QosManager::new(config);

                // Fill queue to near capacity
                for i in 0..80 {
                    let _ = manager
                        .enqueue(create_request(
                            &format!("req{}", i),
                            "QmTest",
                            1024,
                            Priority::Normal,
                        ))
                        .await;
                }

                let is_near = manager.is_near_capacity();
                black_box(is_near);
            });
        });
    });
}

/// Benchmark realistic scenario: web content delivery with mixed priorities.
fn bench_realistic_web_delivery(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_realistic_web_delivery", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                // Simulate web delivery scenario:
                // - Critical: API requests (small, fast)
                // - High: User-requested content
                // - Normal: Prefetched content
                // - Low: Background sync

                // Enqueue mixed requests
                let _ = manager
                    .enqueue(create_request("api1", "QmAPI", 512, Priority::Critical))
                    .await;
                let _ = manager
                    .enqueue(create_request(
                        "user_video",
                        "QmVideo",
                        5_000_000,
                        Priority::High,
                    ))
                    .await;
                let _ = manager
                    .enqueue(create_request(
                        "prefetch1",
                        "QmPrefetch",
                        100_000,
                        Priority::Normal,
                    ))
                    .await;
                let _ = manager
                    .enqueue(create_request("sync", "QmSync", 50_000, Priority::Low))
                    .await;
                let _ = manager
                    .enqueue(create_request("api2", "QmAPI2", 1024, Priority::Critical))
                    .await;

                // Process requests
                let mut results = Vec::new();
                while let Some(req) = manager.dequeue().await {
                    results.push(req);
                }

                black_box(results);
            });
        });
    });
}

/// Benchmark realistic scenario: video streaming with deadline scheduling.
fn bench_realistic_video_streaming(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("qos_realistic_video_streaming", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QosConfig::default();
                let mut manager = QosManager::new(config);

                let now = chie_core::utils::current_timestamp_ms();

                // Simulate video streaming with playback deadlines
                // Each chunk has a deadline based on playback time
                for i in 0..20 {
                    let deadline = now + (i * 100); // 100ms per chunk
                    let _ = manager
                        .enqueue(create_request_with_deadline(
                            &format!("chunk{}", i),
                            &format!("QmChunk{}", i),
                            100_000,
                            Priority::High,
                            deadline,
                        ))
                        .await;
                }

                // Also add some background requests
                for i in 0..5 {
                    let _ = manager
                        .enqueue(create_request(
                            &format!("bg{}", i),
                            &format!("QmBg{}", i),
                            10_000,
                            Priority::Low,
                        ))
                        .await;
                }

                // Process all requests
                let mut results = Vec::new();
                while let Some(req) = manager.dequeue().await {
                    results.push(req);
                }

                black_box(results);
            });
        });
    });
}

criterion_group!(
    benches,
    bench_qos_manager_creation,
    bench_qos_manager_custom_creation,
    bench_enqueue_by_priority,
    bench_bulk_enqueue,
    bench_dequeue_strict_priority,
    bench_dequeue_fair_scheduling,
    bench_deadline_scheduling,
    bench_queue_depth_queries,
    bench_sla_metrics_tracking,
    bench_resource_pressure_updates,
    bench_capacity_checks,
    bench_realistic_web_delivery,
    bench_realistic_video_streaming,
);
criterion_main!(benches);
