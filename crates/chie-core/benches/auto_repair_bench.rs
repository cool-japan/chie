//! Benchmarks for automatic chunk repair operations.
//!
//! Measures performance of:
//! - Repair strategy creation and initialization
//! - Repair candidate selection
//! - Status tracking and updates
//! - Batch repair operations

use chie_core::auto_repair::{ChunkRepairConfig, ChunkRepairRequest, ChunkRepairStrategy};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

/// Benchmark creating a new repair strategy.
fn bench_repair_strategy_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_strategy_creation");

    let configs = vec![
        ("default", ChunkRepairConfig::default()),
        (
            "high_retries",
            ChunkRepairConfig {
                max_retries: 10,
                ..Default::default()
            },
        ),
        (
            "fast_retry",
            ChunkRepairConfig {
                retry_delay: Duration::from_millis(10),
                ..Default::default()
            },
        ),
        (
            "no_verify",
            ChunkRepairConfig {
                verify_after_repair: false,
                ..Default::default()
            },
        ),
    ];

    for (name, config) in configs {
        group.bench_function(name, |b| {
            b.iter(|| {
                let strategy = ChunkRepairStrategy::new(black_box(config.clone()));
                black_box(strategy)
            });
        });
    }

    group.finish();
}

/// Benchmark initializing repair requests.
fn bench_repair_initialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_initialization");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig::default();
                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };

                b.iter(|| {
                    let mut strategy = ChunkRepairStrategy::new(config.clone());
                    strategy.initialize_repair(black_box(request.clone()));
                    black_box(strategy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark finding the next repair candidate.
fn bench_next_repair_candidate(c: &mut Criterion) {
    let mut group = c.benchmark_group("next_repair_candidate");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_pending", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig {
                    retry_delay: Duration::from_millis(1),
                    ..Default::default()
                };

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };

                b.iter(|| {
                    let mut strategy = ChunkRepairStrategy::new(config.clone());
                    strategy.initialize_repair(black_box(request.clone()));
                    let candidate = strategy.next_repair_candidate();
                    black_box(candidate)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark marking repair attempts.
fn bench_mark_repair_attempt(c: &mut Criterion) {
    let mut group = c.benchmark_group("mark_repair_attempt");

    group.bench_function("single_attempt", |b| {
        let config = ChunkRepairConfig::default();

        b.iter(|| {
            let mut strategy = ChunkRepairStrategy::new(config.clone());
            let request = ChunkRepairRequest {
                content_id: "QmTest".to_string(),
                failed_chunk_indices: vec![0, 1, 2],
                total_chunks: 10,
            };
            strategy.initialize_repair(request);

            strategy.mark_repair_attempt(black_box(0), black_box("peer1".to_string()));
            black_box(strategy)
        });
    });

    group.bench_function("multiple_attempts", |b| {
        let config = ChunkRepairConfig::default();

        b.iter(|| {
            let mut strategy = ChunkRepairStrategy::new(config.clone());
            let request = ChunkRepairRequest {
                content_id: "QmTest".to_string(),
                failed_chunk_indices: vec![0, 1, 2, 3, 4],
                total_chunks: 10,
            };
            strategy.initialize_repair(request);

            for i in 0..5 {
                strategy.mark_repair_attempt(black_box(i), black_box(format!("peer{}", i)));
            }
            black_box(strategy)
        });
    });

    group.finish();
}

/// Benchmark marking repairs as successful.
fn bench_mark_repaired(c: &mut Criterion) {
    let mut group = c.benchmark_group("mark_repaired");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let config = ChunkRepairConfig::default();
                    let mut strategy = ChunkRepairStrategy::new(config);

                    let request = ChunkRepairRequest {
                        content_id: "QmTest".to_string(),
                        failed_chunk_indices: (0..size).collect(),
                        total_chunks: size * 2,
                    };
                    strategy.initialize_repair(request);

                    for i in 0..size {
                        strategy.mark_repaired(black_box(i), black_box(1024));
                    }
                    black_box(strategy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark marking repairs as failed.
fn bench_mark_failed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mark_failed");

    group.bench_function("single_failure", |b| {
        let config = ChunkRepairConfig {
            max_retries: 1,
            ..Default::default()
        };

        b.iter(|| {
            let mut strategy = ChunkRepairStrategy::new(config.clone());
            let request = ChunkRepairRequest {
                content_id: "QmTest".to_string(),
                failed_chunk_indices: vec![0],
                total_chunks: 10,
            };
            strategy.initialize_repair(request);
            strategy.mark_repair_attempt(0, "peer1".to_string());

            strategy.mark_failed(black_box(0));
            black_box(strategy)
        });
    });

    group.finish();
}

/// Benchmark checking repair completion status.
fn bench_is_complete(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_complete");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig::default();
                let mut strategy = ChunkRepairStrategy::new(config);

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };
                strategy.initialize_repair(request);

                // Mark half as repaired
                for i in 0..size / 2 {
                    strategy.mark_repaired(i, 1024);
                }

                b.iter(|| {
                    let complete = strategy.is_complete();
                    black_box(complete)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting repair statistics.
fn bench_stats_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_access");

    group.bench_function("get_stats", |b| {
        let config = ChunkRepairConfig::default();
        let mut strategy = ChunkRepairStrategy::new(config);

        let request = ChunkRepairRequest {
            content_id: "QmTest".to_string(),
            failed_chunk_indices: vec![0, 1, 2, 3, 4],
            total_chunks: 10,
        };
        strategy.initialize_repair(request);
        strategy.mark_repaired(0, 1024);
        strategy.mark_repaired(1, 2048);

        b.iter(|| {
            let stats = strategy.stats();
            black_box(stats)
        });
    });

    group.finish();
}

/// Benchmark getting chunk status.
fn bench_chunk_status(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_status");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig::default();
                let mut strategy = ChunkRepairStrategy::new(config);

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };
                strategy.initialize_repair(request);

                b.iter(|| {
                    // Check status of middle chunk
                    let status = strategy.chunk_status(black_box(size / 2));
                    black_box(status)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting pending repairs list.
fn bench_pending_repairs(c: &mut Criterion) {
    let mut group = c.benchmark_group("pending_repairs");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig::default();
                let mut strategy = ChunkRepairStrategy::new(config);

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };
                strategy.initialize_repair(request);

                // Mark half as repaired
                for i in 0..size / 2 {
                    strategy.mark_repaired(i, 1024);
                }

                b.iter(|| {
                    let pending = strategy.pending_repairs();
                    black_box(pending)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting repaired chunks list.
fn bench_repaired_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("repaired_chunks");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig::default();
                let mut strategy = ChunkRepairStrategy::new(config);

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };
                strategy.initialize_repair(request);

                // Mark all as repaired
                for i in 0..size {
                    strategy.mark_repaired(i, 1024);
                }

                b.iter(|| {
                    let repaired = strategy.repaired_chunks();
                    black_box(repaired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting failed chunks list.
fn bench_failed_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("failed_chunks");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                let config = ChunkRepairConfig {
                    max_retries: 1,
                    ..Default::default()
                };
                let mut strategy = ChunkRepairStrategy::new(config);

                let request = ChunkRepairRequest {
                    content_id: "QmTest".to_string(),
                    failed_chunk_indices: (0..size).collect(),
                    total_chunks: size * 2,
                };
                strategy.initialize_repair(request);

                // Mark all as failed
                for i in 0..size {
                    strategy.mark_repair_attempt(i, format!("peer{}", i));
                    strategy.mark_failed(i);
                }

                b.iter(|| {
                    let failed = strategy.failed_chunks();
                    black_box(failed)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark a complete repair workflow.
fn bench_repair_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("repair_workflow");

    let sizes = vec![10, 50, 100];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let config = ChunkRepairConfig {
                        retry_delay: Duration::from_millis(0),
                        ..Default::default()
                    };
                    let mut strategy = ChunkRepairStrategy::new(config);

                    // Initialize repair
                    let request = ChunkRepairRequest {
                        content_id: "QmTest".to_string(),
                        failed_chunk_indices: (0..size).collect(),
                        total_chunks: size * 2,
                    };
                    strategy.initialize_repair(black_box(request));

                    // Simulate repair workflow
                    for i in 0..size {
                        if let Some(candidate) = strategy.next_repair_candidate() {
                            strategy.mark_repair_attempt(candidate, format!("peer{}", i));
                            // Simulate 80% success rate
                            if i % 5 != 0 {
                                strategy.mark_repaired(candidate, 1024);
                            } else {
                                strategy.mark_failed(candidate);
                            }
                        }
                    }

                    black_box(strategy)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_repair_strategy_creation,
    bench_repair_initialization,
    bench_next_repair_candidate,
    bench_mark_repair_attempt,
    bench_mark_repaired,
    bench_mark_failed,
    bench_is_complete,
    bench_stats_access,
    bench_chunk_status,
    bench_pending_repairs,
    bench_repaired_chunks,
    bench_failed_chunks,
    bench_repair_workflow,
);
criterion_main!(benches);
