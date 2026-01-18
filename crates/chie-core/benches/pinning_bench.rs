use chie_core::pinning::{ContentMetrics, PinningConfig, PinningOptimizer};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

// Benchmark config creation
fn bench_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/config");

    group.bench_function("default", |b| {
        b.iter(|| black_box(PinningConfig::default()))
    });

    group.bench_function("custom", |b| {
        b.iter(|| {
            black_box(PinningConfig {
                max_storage_bytes: 500 * 1024 * 1024 * 1024,
                min_revenue_per_gb: 0.05,
                popularity_weight: 0.5,
                revenue_weight: 0.3,
                freshness_weight: 0.2,
                recalc_interval: Duration::from_secs(1800),
                min_pin_duration: Duration::from_secs(43200),
            })
        })
    });

    group.finish();
}

// Benchmark optimizer creation
fn bench_optimizer_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/optimizer_creation");

    group.bench_function("default", |b| {
        b.iter(|| black_box(PinningOptimizer::default()))
    });

    group.bench_function("with_config", |b| {
        let config = PinningConfig::default();
        b.iter(|| black_box(PinningOptimizer::new(config.clone())))
    });

    group.finish();
}

// Benchmark content metrics operations
fn bench_content_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/metrics");

    group.bench_function("new", |b| {
        b.iter(|| {
            black_box(ContentMetrics::new(
                black_box("QmTest123".to_string()),
                black_box(1024 * 1024 * 100),
            ))
        })
    });

    group.bench_function("record_request", |b| {
        let mut metrics = ContentMetrics::new("QmTest123".to_string(), 1024 * 1024 * 100);
        b.iter(|| {
            metrics.record_request(black_box(100));
        })
    });

    group.bench_function("revenue_per_gb", |b| {
        let mut metrics = ContentMetrics::new("QmTest123".to_string(), 1024 * 1024 * 1024); // 1 GB
        metrics.record_request(1000);
        b.iter(|| black_box(metrics.revenue_per_gb()))
    });

    group.bench_function("daily_revenue_per_gb", |b| {
        let mut metrics = ContentMetrics::new("QmTest123".to_string(), 1024 * 1024 * 1024);
        metrics.record_request(1000);
        b.iter(|| black_box(metrics.daily_revenue_per_gb()))
    });

    group.bench_function("time_since_last_request", |b| {
        let mut metrics = ContentMetrics::new("QmTest123".to_string(), 1024 * 1024 * 100);
        metrics.record_request(100);
        b.iter(|| black_box(metrics.time_since_last_request()))
    });

    group.finish();
}

// Benchmark register content
fn bench_register_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/register");

    group.bench_function("single_content", |b| {
        let mut optimizer = PinningOptimizer::default();
        let mut counter = 0u64;
        b.iter(|| {
            let cid = format!("QmContent{}", counter);
            counter += 1;
            optimizer.register_content(black_box(cid), black_box(1024 * 1024 * 100));
        })
    });

    for count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", count),
            count,
            |b, &content_count| {
                b.iter(|| {
                    let mut optimizer = PinningOptimizer::default();
                    for i in 0..content_count {
                        optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);
                    }
                    black_box(optimizer)
                })
            },
        );
    }

    group.finish();
}

// Benchmark unregister content
fn bench_unregister_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/unregister");

    group.bench_function("single_content", |b| {
        let mut optimizer = PinningOptimizer::default();
        // Pre-populate
        for i in 0..100 {
            optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);
        }

        let mut counter = 0u64;
        b.iter(|| {
            let cid = format!("QmContent{}", counter % 100);
            counter += 1;
            black_box(optimizer.unregister_content(&cid))
        })
    });

    group.finish();
}

// Benchmark record request
fn bench_record_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/record_request");

    group.bench_function("single_request", |b| {
        let mut optimizer = PinningOptimizer::default();
        optimizer.register_content("QmTest".to_string(), 1024 * 1024 * 100);

        b.iter(|| {
            optimizer.record_request(black_box("QmTest"), black_box(100));
        })
    });

    for count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", count),
            count,
            |b, &request_count| {
                let mut optimizer = PinningOptimizer::default();
                for i in 0..10 {
                    optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);
                }

                b.iter(|| {
                    for i in 0..request_count {
                        optimizer.record_request(&format!("QmContent{}", i % 10), 100);
                    }
                })
            },
        );
    }

    group.finish();
}

// Benchmark update demand
fn bench_update_demand(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/update_demand");

    group.bench_function("single_update", |b| {
        let mut optimizer = PinningOptimizer::default();
        optimizer.register_content("QmTest".to_string(), 1024 * 1024 * 100);

        b.iter(|| {
            optimizer.update_demand(black_box("QmTest"), black_box(1.5));
        })
    });

    group.finish();
}

// Benchmark get recommendations
fn bench_get_recommendations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/recommendations");

    for count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", count),
            count,
            |b, &content_count| {
                let mut optimizer = PinningOptimizer::default();

                // Pre-populate with varied activity
                for i in 0..content_count {
                    optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);

                    // Vary request counts for scoring diversity
                    for _ in 0..(i % 10) {
                        optimizer.record_request(&format!("QmContent{}", i), 10);
                    }
                }

                b.iter(|| black_box(optimizer.get_recommendations()))
            },
        );
    }

    group.finish();
}

// Benchmark get unpin candidates
fn bench_get_unpin_candidates(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/unpin_candidates");

    for count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", count),
            count,
            |b, &content_count| {
                let config = PinningConfig {
                    min_pin_duration: Duration::from_secs(0), // Allow immediate unpin for testing
                    ..Default::default()
                };
                let mut optimizer = PinningOptimizer::new(config);

                // Pre-populate with varied activity
                for i in 0..content_count {
                    optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);

                    // Vary request counts for scoring diversity
                    for _ in 0..(i % 10) {
                        optimizer.record_request(&format!("QmContent{}", i), 10);
                    }
                }

                b.iter(|| {
                    black_box(optimizer.get_unpin_candidates(black_box(1024 * 1024 * 500))) // 500 MB
                })
            },
        );
    }

    group.finish();
}

// Benchmark should_pin
fn bench_should_pin(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/should_pin");

    group.bench_function("accept_decision", |b| {
        let optimizer = PinningOptimizer::default();

        b.iter(|| {
            black_box(optimizer.should_pin(
                black_box("QmNew"),
                black_box(1024 * 1024 * 100), // 100 MB
                black_box(1.0),
            ))
        })
    });

    group.bench_function("reject_decision", |b| {
        let optimizer = PinningOptimizer::default();

        b.iter(|| {
            black_box(optimizer.should_pin(
                black_box("QmNew"),
                black_box(1024 * 1024 * 100),
                black_box(0.1), // Low demand
            ))
        })
    });

    group.bench_function("unpin_required_decision", |b| {
        let config = PinningConfig {
            max_storage_bytes: 1024 * 1024 * 500, // 500 MB
            min_pin_duration: Duration::from_secs(0),
            ..Default::default()
        };
        let mut optimizer = PinningOptimizer::new(config);

        // Fill storage
        optimizer.register_content("QmExisting".to_string(), 1024 * 1024 * 400); // 400 MB

        b.iter(|| {
            black_box(optimizer.should_pin(
                black_box("QmNew"),
                black_box(1024 * 1024 * 200), // 200 MB (will require unpin)
                black_box(1.0),
            ))
        })
    });

    group.finish();
}

// Benchmark stats
fn bench_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/stats");

    for count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", count),
            count,
            |b, &content_count| {
                let mut optimizer = PinningOptimizer::default();

                for i in 0..content_count {
                    optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);
                    for _ in 0..(i % 10) {
                        optimizer.record_request(&format!("QmContent{}", i), 10);
                    }
                }

                b.iter(|| black_box(optimizer.stats()))
            },
        );
    }

    group.finish();
}

// Benchmark reset daily metrics
fn bench_reset_daily_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/reset_daily");

    for count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", count),
            count,
            |b, &content_count| {
                let mut optimizer = PinningOptimizer::default();

                for i in 0..content_count {
                    optimizer.register_content(format!("QmContent{}", i), 1024 * 1024 * 100);
                    for _ in 0..10 {
                        optimizer.record_request(&format!("QmContent{}", i), 10);
                    }
                }

                b.iter(|| {
                    optimizer.reset_daily_metrics();
                })
            },
        );
    }

    group.finish();
}

// Benchmark mixed operations
fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pinning/mixed");

    group.bench_function("typical_workflow", |b| {
        let mut optimizer = PinningOptimizer::default();
        let mut counter = 0u64;

        b.iter(|| {
            // Register new content
            let cid = format!("QmContent{}", counter);
            counter += 1;
            optimizer.register_content(cid.clone(), 1024 * 1024 * 100);

            // Record some requests
            for _ in 0..5 {
                optimizer.record_request(&cid, 10);
            }

            // Update demand
            optimizer.update_demand(&cid, 1.2);

            // Get recommendations
            let _recs = optimizer.get_recommendations();

            // Get stats
            black_box(optimizer.stats());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_optimizer_creation,
    bench_content_metrics,
    bench_register_content,
    bench_unregister_content,
    bench_record_request,
    bench_update_demand,
    bench_get_recommendations,
    bench_get_unpin_candidates,
    bench_should_pin,
    bench_stats,
    bench_reset_daily_metrics,
    bench_mixed_operations,
);

criterion_main!(benches);
