use chie_core::{ContentGcResult, GarbageCollectionConfig, GcStats};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_gc_config_creation(c: &mut Criterion) {
    c.bench_function("gc_config_default", |b| {
        b.iter(|| black_box(GarbageCollectionConfig::default()));
    });
}

fn bench_gc_config_custom(c: &mut Criterion) {
    c.bench_function("gc_config_custom", |b| {
        b.iter(|| {
            black_box(GarbageCollectionConfig {
                gc_interval: Duration::from_secs(black_box(1800)),
                max_unpin_per_run: black_box(20),
                aggressive_threshold: black_box(0.85),
                target_usage: black_box(0.75),
                auto_gc_enabled: black_box(true),
            })
        });
    });
}

fn bench_gc_config_variations(c: &mut Criterion) {
    let mut group = c.benchmark_group("gc_config_thresholds");

    for &threshold in [0.7, 0.8, 0.9, 0.95].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}%", (threshold * 100.0) as u8)),
            &threshold,
            |b, &thresh| {
                b.iter(|| {
                    black_box(GarbageCollectionConfig {
                        gc_interval: Duration::from_secs(3600),
                        max_unpin_per_run: 10,
                        aggressive_threshold: black_box(thresh),
                        target_usage: 0.8,
                        auto_gc_enabled: true,
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_gc_result_creation(c: &mut Criterion) {
    c.bench_function("gc_result_new", |b| {
        b.iter(|| {
            let mut result = ContentGcResult {
                unpinned_count: black_box(0),
                bytes_freed: black_box(0),
                unpinned_cids: Vec::new(),
                was_aggressive: black_box(false),
                errors: Vec::new(),
            };
            result.unpinned_count = black_box(10);
            result.bytes_freed = black_box(1024 * 1024 * 100); // 100 MB
            black_box(result)
        });
    });
}

fn bench_gc_result_with_cids(c: &mut Criterion) {
    let mut group = c.benchmark_group("gc_result_with_cids");

    for cid_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(cid_count),
            cid_count,
            |b, &count| {
                b.iter(|| {
                    let cids: Vec<String> = (0..count).map(|i| format!("QmTest{:06}", i)).collect();
                    black_box(ContentGcResult {
                        unpinned_count: black_box(count),
                        bytes_freed: black_box(count as u64 * 1024 * 1024),
                        unpinned_cids: black_box(cids),
                        was_aggressive: black_box(false),
                        errors: Vec::new(),
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_gc_stats_creation(c: &mut Criterion) {
    c.bench_function("gc_stats_new", |b| {
        b.iter(|| {
            black_box(GcStats {
                storage_used_bytes: black_box(50 * 1024 * 1024 * 1024), // 50 GB
                storage_max_bytes: black_box(100 * 1024 * 1024 * 1024), // 100 GB
                storage_usage_percent: black_box(50.0),
                unpin_candidates: black_box(100),
                bytes_reclaimable: black_box(5 * 1024 * 1024 * 1024), // 5 GB
                is_aggressive_threshold: black_box(false),
            })
        });
    });
}

fn bench_gc_stats_usage_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("gc_stats_usage_calc");

    for &used_pct in [50, 75, 85, 90, 95].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}%", used_pct)),
            &used_pct,
            |b, &pct| {
                let max_bytes = 100 * 1024 * 1024 * 1024u64; // 100 GB
                let used_bytes = (max_bytes * pct) / 100;
                b.iter(|| {
                    black_box(GcStats {
                        storage_used_bytes: black_box(used_bytes),
                        storage_max_bytes: black_box(max_bytes),
                        storage_usage_percent: black_box(pct as f64),
                        unpin_candidates: black_box(100),
                        bytes_reclaimable: black_box(5 * 1024 * 1024 * 1024),
                        is_aggressive_threshold: black_box(pct >= 90),
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_gc_aggressive_threshold_check(c: &mut Criterion) {
    c.bench_function("gc_aggressive_threshold_check", |b| {
        let config = GarbageCollectionConfig::default();
        b.iter(|| {
            let usage_percent = black_box(92.0);
            let is_aggressive = usage_percent >= config.aggressive_threshold * 100.0;
            black_box(is_aggressive)
        });
    });
}

fn bench_gc_target_usage_calculation(c: &mut Criterion) {
    c.bench_function("gc_target_usage_calc", |b| {
        let config = GarbageCollectionConfig::default();
        let max_bytes = 100 * 1024 * 1024 * 1024u64; // 100 GB
        b.iter(|| {
            let target_bytes = (max_bytes as f64 * config.target_usage) as u64;
            black_box(target_bytes)
        });
    });
}

fn bench_gc_bytes_to_free_calculation(c: &mut Criterion) {
    c.bench_function("gc_bytes_to_free", |b| {
        let config = GarbageCollectionConfig::default();
        let max_bytes = 100 * 1024 * 1024 * 1024u64; // 100 GB
        let used_bytes = 95 * 1024 * 1024 * 1024u64; // 95 GB
        b.iter(|| {
            let target_bytes = (max_bytes as f64 * config.target_usage) as u64;
            let bytes_to_free = used_bytes.saturating_sub(target_bytes);
            black_box(bytes_to_free)
        });
    });
}

fn bench_gc_config_interval_variations(c: &mut Criterion) {
    let mut group = c.benchmark_group("gc_config_intervals");

    for &secs in [300, 600, 1800, 3600, 7200].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}s", secs)),
            &secs,
            |b, &interval_secs| {
                b.iter(|| {
                    black_box(GarbageCollectionConfig {
                        gc_interval: Duration::from_secs(black_box(interval_secs)),
                        max_unpin_per_run: 10,
                        aggressive_threshold: 0.9,
                        target_usage: 0.8,
                        auto_gc_enabled: true,
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_gc_result_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("gc_result_errors");

    for error_count in [0, 5, 10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(error_count),
            error_count,
            |b, &count| {
                b.iter(|| {
                    let errors: Vec<String> = (0..count)
                        .map(|i| format!("Error unpinning content {}", i))
                        .collect();
                    black_box(ContentGcResult {
                        unpinned_count: black_box(10),
                        bytes_freed: black_box(1024 * 1024 * 100),
                        unpinned_cids: Vec::new(),
                        was_aggressive: black_box(false),
                        errors: black_box(errors),
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_gc_stats_reclaimable_ratio(c: &mut Criterion) {
    c.bench_function("gc_stats_reclaimable_ratio", |b| {
        let stats = GcStats {
            storage_used_bytes: 90 * 1024 * 1024 * 1024,
            storage_max_bytes: 100 * 1024 * 1024 * 1024,
            storage_usage_percent: 90.0,
            unpin_candidates: 100,
            bytes_reclaimable: 5 * 1024 * 1024 * 1024,
            is_aggressive_threshold: true,
        };

        b.iter(|| {
            let reclaimable_ratio = if stats.storage_used_bytes > 0 {
                stats.bytes_reclaimable as f64 / stats.storage_used_bytes as f64
            } else {
                0.0
            };
            black_box(reclaimable_ratio * 100.0) // as percentage
        });
    });
}

criterion_group!(
    benches,
    bench_gc_config_creation,
    bench_gc_config_custom,
    bench_gc_config_variations,
    bench_gc_result_creation,
    bench_gc_result_with_cids,
    bench_gc_stats_creation,
    bench_gc_stats_usage_calculations,
    bench_gc_aggressive_threshold_check,
    bench_gc_target_usage_calculation,
    bench_gc_bytes_to_free_calculation,
    bench_gc_config_interval_variations,
    bench_gc_result_error_handling,
    bench_gc_stats_reclaimable_ratio,
);
criterion_main!(benches);
