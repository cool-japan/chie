use chie_core::popularity::{DemandLevel, PopularityConfig, PopularityTracker};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

// Benchmark config creation
fn bench_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/config");

    group.bench_function("default", |b| {
        b.iter(|| black_box(PopularityConfig::default()))
    });

    group.bench_function("custom", |b| {
        b.iter(|| {
            black_box(PopularityConfig {
                max_tracked_content: 5000,
                hot_window: Duration::from_secs(1800),
                trending_window: Duration::from_secs(12 * 3600),
                min_requests_for_popular: 20,
                prune_interval: Duration::from_secs(1800),
            })
        })
    });

    group.finish();
}

// Benchmark tracker creation
fn bench_tracker_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/tracker_creation");

    group.bench_function("default", |b| {
        b.iter(|| black_box(PopularityTracker::default()))
    });

    group.bench_function("with_config", |b| {
        let config = PopularityConfig::default();
        b.iter(|| black_box(PopularityTracker::new(config.clone())))
    });

    group.finish();
}

// Benchmark record access
fn bench_record_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/record_access");

    group.bench_function("single_content_new_peer", |b| {
        let mut tracker = PopularityTracker::default();
        let mut counter = 0u64;
        b.iter(|| {
            let peer_id = format!("peer{}", counter);
            counter += 1;
            tracker.record_access(black_box("QmTest123"), black_box(1024), black_box(&peer_id));
        })
    });

    group.bench_function("single_content_existing_peer", |b| {
        let mut tracker = PopularityTracker::default();
        // Pre-populate with one peer
        tracker.record_access("QmTest123", 1024, "peer1");

        b.iter(|| {
            tracker.record_access(black_box("QmTest123"), black_box(1024), black_box("peer1"));
        })
    });

    group.bench_function("multiple_content", |b| {
        let mut tracker = PopularityTracker::default();
        let mut counter = 0u64;
        b.iter(|| {
            let cid = format!("QmContent{}", counter % 10);
            let peer = format!("peer{}", counter % 5);
            counter += 1;
            tracker.record_access(black_box(&cid), black_box(1024), black_box(&peer));
        })
    });

    group.finish();
}

// Benchmark get popularity
fn bench_get_popularity(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/get_popularity");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(content_count),
            content_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate with content
                for i in 0..count {
                    let cid = format!("QmContent{}", i);
                    for j in 0..10 {
                        tracker.record_access(&cid, 1024, &format!("peer{}", j));
                    }
                }

                b.iter(|| {
                    let cid = format!("QmContent{}", count / 2);
                    black_box(tracker.get_popularity(&cid))
                })
            },
        );
    }

    group.finish();
}

// Benchmark calculate score
fn bench_calculate_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/calculate_score");

    for request_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("requests", request_count),
            request_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate with varying numbers of requests
                for i in 0..count {
                    tracker.record_access("QmTest", 1024, &format!("peer{}", i));
                }

                b.iter(|| black_box(tracker.calculate_score(black_box("QmTest"))))
            },
        );
    }

    group.finish();
}

// Benchmark get top content
fn bench_get_top_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/get_top");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", content_count),
            content_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate with content of varying popularity
                for i in 0..count {
                    let cid = format!("QmContent{}", i);
                    let requests = (i % 20) + 1; // Vary popularity
                    for j in 0..requests {
                        tracker.record_access(&cid, 1024, &format!("peer{}", j));
                    }
                }

                b.iter(|| black_box(tracker.get_top_content(black_box(10))))
            },
        );
    }

    group.finish();
}

// Benchmark get hot content
fn bench_get_hot_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/get_hot");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", content_count),
            content_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate with content
                for i in 0..count {
                    let cid = format!("QmContent{}", i);
                    let requests = (i % 20) + 1;
                    for j in 0..requests {
                        tracker.record_access(&cid, 1024, &format!("peer{}", j));
                    }
                }

                b.iter(|| black_box(tracker.get_hot_content()))
            },
        );
    }

    group.finish();
}

// Benchmark get trending content
fn bench_get_trending_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/get_trending");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("content_count", content_count),
            content_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate with content
                for i in 0..count {
                    let cid = format!("QmContent{}", i);
                    let requests = (i % 20) + 1;
                    for j in 0..requests {
                        tracker.record_access(&cid, 1024, &format!("peer{}", j));
                    }
                }

                b.iter(|| black_box(tracker.get_trending_content()))
            },
        );
    }

    group.finish();
}

// Benchmark get stats
fn bench_get_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/stats");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(content_count),
            content_count,
            |b, &count| {
                let mut tracker = PopularityTracker::default();

                // Pre-populate
                for i in 0..count {
                    let cid = format!("QmContent{}", i);
                    for j in 0..10 {
                        tracker.record_access(&cid, 1024, &format!("peer{}", j));
                    }
                }

                b.iter(|| black_box(tracker.get_stats()))
            },
        );
    }

    group.finish();
}

// Benchmark demand level
fn bench_demand_level(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/demand_level");

    group.bench_function("price_multiplier", |b| {
        let levels = [
            DemandLevel::Low,
            DemandLevel::Medium,
            DemandLevel::High,
            DemandLevel::VeryHigh,
        ];
        let mut idx = 0;
        b.iter(|| {
            let level = levels[idx % 4];
            idx += 1;
            black_box(level.price_multiplier())
        })
    });

    group.finish();
}

// Benchmark mixed operations
fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("popularity/mixed");

    group.bench_function("typical_workflow", |b| {
        let mut tracker = PopularityTracker::default();
        let mut counter = 0u64;

        b.iter(|| {
            // Record some accesses
            for i in 0..5 {
                let cid = format!("QmContent{}", counter % 10);
                let peer = format!("peer{}", i);
                tracker.record_access(&cid, 1024, &peer);
            }

            // Get top content
            let _top = tracker.get_top_content(5);

            // Calculate score for one
            let cid = format!("QmContent{}", counter % 10);
            let _score = tracker.calculate_score(&cid);

            // Get stats
            black_box(tracker.get_stats());

            counter += 1;
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_tracker_creation,
    bench_record_access,
    bench_get_popularity,
    bench_calculate_score,
    bench_get_top_content,
    bench_get_hot_content,
    bench_get_trending_content,
    bench_get_stats,
    bench_demand_level,
    bench_mixed_operations,
);

criterion_main!(benches);
