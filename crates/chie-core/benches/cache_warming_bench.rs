//! Benchmarks for cache warming operations.
//!
//! Measures performance of:
//! - Warmer creation and configuration
//! - Score calculation for different strategies
//! - Candidate selection and sorting
//! - Statistics generation

use chie_core::cache_warming::{CacheWarmer, WarmingConfig, WarmingStrategy};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

/// Benchmark creating cache warmers.
fn bench_warmer_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("warmer_creation");

    let strategies = vec![
        ("frequency", WarmingStrategy::FrequencyBased),
        ("recency", WarmingStrategy::RecencyBased),
        ("hybrid", WarmingStrategy::Hybrid),
        ("predictive", WarmingStrategy::Predictive),
    ];

    for (name, strategy) in strategies {
        group.bench_function(name, |b| {
            b.iter(|| {
                let config = WarmingConfig {
                    strategy: black_box(strategy),
                    max_items: black_box(100),
                    max_bytes: black_box(100 * 1024 * 1024),
                    access_log_path: PathBuf::from("/tmp/test.log"),
                    warmup_on_startup: false,
                };
                let warmer = CacheWarmer::new(config).unwrap();
                black_box(warmer)
            });
        });
    }

    group.finish();
}

/// Benchmark configuration validation.
fn bench_config_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_validation");

    group.bench_function("valid_config", |b| {
        b.iter(|| {
            let config = WarmingConfig {
                strategy: WarmingStrategy::Hybrid,
                max_items: black_box(100),
                max_bytes: black_box(1024 * 1024),
                access_log_path: PathBuf::from("/tmp/test.log"),
                warmup_on_startup: true,
            };
            let warmer = CacheWarmer::new(black_box(config));
            black_box(warmer)
        });
    });

    group.bench_function("invalid_max_items", |b| {
        b.iter(|| {
            let config = WarmingConfig {
                strategy: WarmingStrategy::Hybrid,
                max_items: black_box(0), // Invalid
                max_bytes: black_box(1024 * 1024),
                access_log_path: PathBuf::from("/tmp/test.log"),
                warmup_on_startup: true,
            };
            let warmer = CacheWarmer::new(black_box(config));
            black_box(warmer)
        });
    });

    group.finish();
}

/// Benchmark getting warming candidates with different numbers of access records.
fn bench_get_warming_candidates(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_warming_candidates");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_records", size)),
            &size,
            |b, &size| {
                let config = WarmingConfig {
                    strategy: WarmingStrategy::Hybrid,
                    max_items: size / 2, // Select half
                    max_bytes: 100 * 1024 * 1024,
                    access_log_path: PathBuf::from("/tmp/test.log"),
                    warmup_on_startup: false,
                };
                let mut warmer = CacheWarmer::new(config).unwrap();

                // Pre-populate with access records (synchronously for benchmarking)
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    for i in 0..size {
                        warmer
                            .record_access(format!("QmTest{}", i), 1024 * (i as u64 + 1))
                            .await;
                    }
                });

                b.iter(|| {
                    let candidates = warmer.get_warming_candidates().unwrap();
                    black_box(candidates)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark different warming strategies.
fn bench_warming_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("warming_strategies");

    let strategies = vec![
        ("frequency", WarmingStrategy::FrequencyBased),
        ("recency", WarmingStrategy::RecencyBased),
        ("hybrid", WarmingStrategy::Hybrid),
        ("predictive", WarmingStrategy::Predictive),
    ];

    for (name, strategy) in strategies {
        group.bench_function(name, |b| {
            let config = WarmingConfig {
                strategy,
                max_items: 50,
                max_bytes: 100 * 1024 * 1024,
                access_log_path: PathBuf::from("/tmp/test.log"),
                warmup_on_startup: false,
            };
            let mut warmer = CacheWarmer::new(config).unwrap();

            // Pre-populate with varied access patterns
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                // Hot items (accessed frequently)
                for i in 0..20 {
                    for _ in 0..10 {
                        warmer.record_access(format!("QmHot{}", i), 1024).await;
                    }
                }

                // Warm items (moderate access)
                for i in 0..30 {
                    for _ in 0..3 {
                        warmer.record_access(format!("QmWarm{}", i), 2048).await;
                    }
                }

                // Cold items (rare access)
                for i in 0..50 {
                    warmer.record_access(format!("QmCold{}", i), 512).await;
                }
            });

            b.iter(|| {
                let candidates = warmer.get_warming_candidates().unwrap();
                black_box(candidates)
            });
        });
    }

    group.finish();
}

/// Benchmark clearing access records.
fn bench_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("clear");

    let sizes = vec![100, 1000, 10000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_records", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let config = WarmingConfig::default();
                    let mut warmer = CacheWarmer::new(config).unwrap();

                    let runtime = tokio::runtime::Runtime::new().unwrap();
                    runtime.block_on(async {
                        for i in 0..size {
                            warmer.record_access(format!("QmTest{}", i), 1024).await;
                        }
                    });

                    warmer.clear();
                    black_box(warmer)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting warming statistics.
fn bench_warming_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("warming_stats");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_records", size)),
            &size,
            |b, &size| {
                let config = WarmingConfig::default();
                let mut warmer = CacheWarmer::new(config).unwrap();

                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    for i in 0..size {
                        warmer
                            .record_access(format!("QmTest{}", i), 1024 * (i as u64 + 1))
                            .await;
                    }
                });

                b.iter(|| {
                    let stats = warmer.warming_stats();
                    black_box(stats)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark candidate selection with different constraints.
fn bench_constraint_application(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_application");

    // Test with different max_items limits
    let max_items_values = vec![10, 50, 100];

    for max_items in max_items_values {
        group.bench_with_input(
            BenchmarkId::new("max_items", max_items),
            &max_items,
            |b, &max_items| {
                let config = WarmingConfig {
                    strategy: WarmingStrategy::FrequencyBased,
                    max_items,
                    max_bytes: u64::MAX, // No byte limit
                    access_log_path: PathBuf::from("/tmp/test.log"),
                    warmup_on_startup: false,
                };
                let mut warmer = CacheWarmer::new(config).unwrap();

                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    for i in 0..200 {
                        warmer.record_access(format!("QmTest{}", i), 1024).await;
                    }
                });

                b.iter(|| {
                    let candidates = warmer.get_warming_candidates().unwrap();
                    black_box(candidates)
                });
            },
        );
    }

    // Test with different max_bytes limits
    let max_bytes_values = vec![10 * 1024, 100 * 1024, 1024 * 1024]; // 10KB, 100KB, 1MB

    for max_bytes in max_bytes_values {
        group.bench_with_input(
            BenchmarkId::new("max_bytes", max_bytes),
            &max_bytes,
            |b, &max_bytes| {
                let config = WarmingConfig {
                    strategy: WarmingStrategy::FrequencyBased,
                    max_items: usize::MAX, // No item limit
                    max_bytes,
                    access_log_path: PathBuf::from("/tmp/test.log"),
                    warmup_on_startup: false,
                };
                let mut warmer = CacheWarmer::new(config).unwrap();

                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    for i in 0..200 {
                        warmer.record_access(format!("QmTest{}", i), 1024).await;
                    }
                });

                b.iter(|| {
                    let candidates = warmer.get_warming_candidates().unwrap();
                    black_box(candidates)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark realistic warming scenarios.
fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    group.bench_function("zipfian_distribution", |b| {
        let config = WarmingConfig {
            strategy: WarmingStrategy::Hybrid,
            max_items: 20,
            max_bytes: 10 * 1024 * 1024,
            access_log_path: PathBuf::from("/tmp/test.log"),
            warmup_on_startup: false,
        };
        let mut warmer = CacheWarmer::new(config).unwrap();

        // Simulate Zipfian distribution (80-20 rule)
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // 20% of content gets 80% of accesses
            for i in 0..20 {
                for _ in 0..80 {
                    warmer.record_access(format!("QmHot{}", i), 1024).await;
                }
            }

            // 80% of content gets 20% of accesses
            for i in 0..80 {
                for _ in 0..5 {
                    warmer.record_access(format!("QmCold{}", i), 2048).await;
                }
            }
        });

        b.iter(|| {
            let candidates = warmer.get_warming_candidates().unwrap();
            black_box(candidates)
        });
    });

    group.bench_function("temporal_locality", |b| {
        let config = WarmingConfig {
            strategy: WarmingStrategy::RecencyBased,
            max_items: 50,
            max_bytes: 100 * 1024 * 1024,
            access_log_path: PathBuf::from("/tmp/test.log"),
            warmup_on_startup: false,
        };
        let mut warmer = CacheWarmer::new(config).unwrap();

        // Simulate temporal locality - recent items accessed more
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for i in 0..100 {
                // More recent items get more accesses
                let access_count = (100 - i) / 10 + 1;
                for _ in 0..access_count {
                    warmer.record_access(format!("QmContent{}", i), 1024).await;
                }
            }
        });

        b.iter(|| {
            let candidates = warmer.get_warming_candidates().unwrap();
            black_box(candidates)
        });
    });

    group.finish();
}

/// Benchmark default configuration.
fn bench_default_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("default_config");

    group.bench_function("create_default", |b| {
        b.iter(|| {
            let config = WarmingConfig::default();
            black_box(config)
        });
    });

    group.bench_function("use_default", |b| {
        b.iter(|| {
            let config = WarmingConfig::default();
            let warmer = CacheWarmer::new(config).unwrap();
            black_box(warmer)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_warmer_creation,
    bench_config_validation,
    bench_get_warming_candidates,
    bench_warming_strategies,
    bench_clear,
    bench_warming_stats,
    bench_constraint_application,
    bench_realistic_scenarios,
    bench_default_config,
);
criterion_main!(benches);
