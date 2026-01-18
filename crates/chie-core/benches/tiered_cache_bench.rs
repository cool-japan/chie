//! Benchmark suite for multi-level tiered cache module.
//!
//! This file benchmarks the performance of tiered caching with L1/L2/L3:
//! - Cache creation and initialization
//! - Put/Get/Remove operations
//! - Automatic tier promotion and demotion
//! - Cache warming strategies
//! - Hit rate and statistics
//!
//! Run with: cargo bench --bench tiered_cache_bench

use chie_core::compression::CompressionAlgorithm;
use chie_core::tiered_cache::{TieredCache, TieredCacheConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

async fn create_test_cache() -> TieredCache {
    let temp_l2 = tempfile::tempdir().unwrap();
    let temp_l3 = tempfile::tempdir().unwrap();

    let config = TieredCacheConfig {
        l1_capacity_bytes: 10 * 1024 * 1024,  // 10 MB
        l2_capacity_bytes: 50 * 1024 * 1024,  // 50 MB
        l3_capacity_bytes: 200 * 1024 * 1024, // 200 MB
        l2_path: temp_l2.path().to_path_buf(),
        l3_path: temp_l3.path().to_path_buf(),
        promotion_threshold: 3,
        compression: CompressionAlgorithm::None,
    };

    TieredCache::new(config).await.unwrap()
}

fn create_test_data(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

// ============================================================================
// Cache Creation Benchmarks
// ============================================================================

fn bench_cache_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("cache_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _cache = black_box(create_test_cache().await);
            });
        });
    });
}

// ============================================================================
// Put Operation Benchmarks
// ============================================================================

fn bench_put(c: &mut Criterion) {
    let mut group = c.benchmark_group("put");
    let rt = Runtime::new().unwrap();

    for size in [1024, 4096, 16384, 65536] {
        let size_kb = size / 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size,
            |b, &s| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut cache = create_test_cache().await;
                        let data = create_test_data(s);
                        cache.put("test_key".to_string(), data).await.unwrap();
                        black_box(cache);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Get Operation Benchmarks
// ============================================================================

fn bench_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("get");
    let rt = Runtime::new().unwrap();

    for size in [1024, 4096, 16384] {
        let size_kb = size / 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size,
            |b, &s| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut cache = create_test_cache().await;
                        let data = create_test_data(s);
                        cache.put("test_key".to_string(), data).await.unwrap();

                        // Benchmark get
                        let _result = black_box(cache.get("test_key").await.unwrap());
                        black_box(cache);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Remove Operation Benchmarks
// ============================================================================

fn bench_remove(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("remove", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;
                let data = create_test_data(4096);
                cache.put("test_key".to_string(), data).await.unwrap();

                // Benchmark remove
                cache.remove("test_key").await.unwrap();
                black_box(cache);
            });
        });
    });
}

// ============================================================================
// Batch Operations Benchmarks
// ============================================================================

fn bench_batch_put(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_put");
    let rt = Runtime::new().unwrap();

    for num_items in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_items),
            &num_items,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut cache = create_test_cache().await;
                        for i in 0..n {
                            let key = format!("key_{}", i);
                            let data = create_test_data(2048);
                            cache.put(key, data).await.unwrap();
                        }
                        black_box(cache);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_get");
    let rt = Runtime::new().unwrap();

    for num_items in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_items),
            &num_items,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut cache = create_test_cache().await;

                        // Populate cache
                        for i in 0..n {
                            let key = format!("key_{}", i);
                            let data = create_test_data(2048);
                            cache.put(key, data).await.unwrap();
                        }

                        // Benchmark gets
                        for i in 0..n {
                            let key = format!("key_{}", i);
                            let _result = cache.get(&key).await.unwrap();
                        }

                        black_box(cache);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Cache Statistics Benchmarks
// ============================================================================

fn bench_statistics(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("statistics");

    group.bench_function("stats", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;
                // Add some data
                for i in 0..10 {
                    cache
                        .put(format!("key_{}", i), create_test_data(1024))
                        .await
                        .unwrap();
                }
                let _stats = black_box(cache.stats());
            });
        });
    });

    group.bench_function("len", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;
                for i in 0..10 {
                    cache
                        .put(format!("key_{}", i), create_test_data(1024))
                        .await
                        .unwrap();
                }
                let _len = black_box(cache.len());
            });
        });
    });

    group.bench_function("is_empty", |b| {
        b.iter(|| {
            rt.block_on(async {
                let cache = create_test_cache().await;
                let _empty = black_box(cache.is_empty());
            });
        });
    });

    group.finish();
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_web_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Simulate web caching with varying sizes
    c.bench_function("web_cache_pattern", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;

                // Add 20 items of varying sizes
                for i in 0..20 {
                    let size = match i % 4 {
                        0 => 1024,  // Small (1KB)
                        1 => 4096,  // Medium (4KB)
                        2 => 16384, // Large (16KB)
                        _ => 65536, // XLarge (64KB)
                    };
                    cache
                        .put(format!("page_{}", i), create_test_data(size))
                        .await
                        .unwrap();
                }

                // Simulate access pattern (some keys accessed more)
                for _ in 0..10 {
                    cache.get("page_0").await.unwrap(); // Hot
                    cache.get("page_1").await.unwrap(); // Hot
                    cache.get("page_5").await.unwrap(); // Warm
                }

                black_box(cache);
            });
        });
    });
}

fn bench_realistic_promotion_pattern(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Test automatic promotion from frequent access
    c.bench_function("promotion_pattern", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;

                // Add item
                cache
                    .put("hot_item".to_string(), create_test_data(4096))
                    .await
                    .unwrap();

                // Access multiple times to trigger promotion
                for _ in 0..5 {
                    cache.get("hot_item").await.unwrap();
                }

                black_box(cache);
            });
        });
    });
}

fn bench_realistic_mixed_workload(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Mixed put, get, remove operations
    c.bench_function("mixed_workload", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut cache = create_test_cache().await;

                // Initial population
                for i in 0..30 {
                    cache
                        .put(format!("item_{}", i), create_test_data(2048))
                        .await
                        .unwrap();
                }

                // Mixed operations
                for i in 0..30 {
                    match i % 3 {
                        0 => {
                            // Get
                            let _result = cache.get(&format!("item_{}", i / 3)).await.unwrap();
                        }
                        1 => {
                            // Put new
                            cache
                                .put(format!("new_{}", i), create_test_data(2048))
                                .await
                                .unwrap();
                        }
                        _ => {
                            // Remove
                            let _ = cache.remove(&format!("item_{}", i / 3)).await;
                        }
                    }
                }

                black_box(cache);
            });
        });
    });
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(creation_benches, bench_cache_creation,);

criterion_group!(basic_benches, bench_put, bench_get, bench_remove,);

criterion_group!(batch_benches, bench_batch_put, bench_batch_get,);

criterion_group!(stats_benches, bench_statistics,);

criterion_group!(
    realistic_benches,
    bench_realistic_web_cache,
    bench_realistic_promotion_pattern,
    bench_realistic_mixed_workload,
);

criterion_main!(
    creation_benches,
    basic_benches,
    batch_benches,
    stats_benches,
    realistic_benches,
);
