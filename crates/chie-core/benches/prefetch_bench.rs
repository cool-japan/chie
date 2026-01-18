#![allow(clippy::unit_arg)]

use chie_core::prefetch::{ChunkPrefetcher, PrefetchConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_prefetcher_creation(c: &mut Criterion) {
    c.bench_function("prefetcher_new", |b| {
        b.iter(|| {
            let config = PrefetchConfig::default();
            black_box(ChunkPrefetcher::new(black_box(config)))
        })
    });
}

fn bench_put_cached(c: &mut Criterion) {
    let mut group = c.benchmark_group("put_cached");
    let rt = Runtime::new().unwrap();

    for size in &[1024, 10240, 102_400] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &chunk_size| {
            let config = PrefetchConfig::default();
            let prefetcher = ChunkPrefetcher::new(config);
            let data = vec![0u8; chunk_size];
            let mut counter = 0u64;

            b.iter(|| {
                let chunk_idx = counter;
                counter += 1;
                rt.block_on(async {
                    black_box(
                        prefetcher
                            .put_cached(
                                black_box("QmTest123"),
                                black_box(chunk_idx),
                                black_box(data.clone()),
                            )
                            .await,
                    )
                })
            })
        });
    }

    group.finish();
}

fn bench_get_cached_hit(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);
    let data = vec![0u8; 10240];

    // Pre-populate cache
    rt.block_on(async {
        for i in 0..50 {
            prefetcher.put_cached("QmTest123", i, data.clone()).await;
        }
    });

    c.bench_function("get_cached_hit", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    prefetcher
                        .get_cached(black_box("QmTest123"), black_box(25))
                        .await,
                )
            })
        })
    });
}

fn bench_get_cached_miss(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);

    c.bench_function("get_cached_miss", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    prefetcher
                        .get_cached(black_box("QmNotInCache"), black_box(999))
                        .await,
                )
            })
        })
    });
}

fn bench_record_access(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);
    let mut counter = 0u64;

    c.bench_function("record_access", |b| {
        b.iter(|| {
            let idx = counter;
            counter += 1;
            rt.block_on(async {
                black_box(
                    prefetcher
                        .record_access(black_box("QmTest123"), black_box(idx))
                        .await,
                )
            })
        })
    });
}

fn bench_record_access_sequential(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);

    // Pre-populate sequential pattern
    rt.block_on(async {
        for i in 0..20 {
            prefetcher.record_access("QmSeq123", i).await;
        }
    });

    c.bench_function("record_access_sequential", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    prefetcher
                        .record_access(black_box("QmSeq123"), black_box(21))
                        .await,
                )
            })
        })
    });
}

fn bench_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);
    let data = vec![0u8; 10240];

    // Pre-populate with activity
    rt.block_on(async {
        for i in 0..50 {
            prefetcher.put_cached("QmTest123", i, data.clone()).await;
            let _ = prefetcher.get_cached("QmTest123", i).await;
        }
    });

    c.bench_function("stats", |b| {
        b.iter(|| rt.block_on(async { black_box(prefetcher.stats().await) }))
    });
}

fn bench_clear_cache(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("clear_cache", |b| {
        b.iter_batched(
            || {
                let config = PrefetchConfig::default();
                let prefetcher = ChunkPrefetcher::new(config);
                let data = vec![0u8; 10240];

                // Pre-populate cache
                rt.block_on(async {
                    for i in 0..50 {
                        prefetcher.put_cached("QmTest123", i, data.clone()).await;
                    }
                });
                prefetcher
            },
            |prefetcher| rt.block_on(async { black_box(prefetcher.clear_cache().await) }),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_cache_eviction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig {
        max_cached_chunks: 50, // Small limit to trigger eviction
        ..PrefetchConfig::default()
    };
    let prefetcher = ChunkPrefetcher::new(config);
    let data = vec![0u8; 10240];

    // Pre-fill cache to capacity
    rt.block_on(async {
        for i in 0..50 {
            prefetcher.put_cached("QmTest123", i, data.clone()).await;
        }
    });

    let mut counter = 50u64;

    c.bench_function("cache_eviction", |b| {
        b.iter(|| {
            let idx = counter;
            counter += 1;
            rt.block_on(async {
                // This should trigger eviction
                black_box(
                    prefetcher
                        .put_cached(
                            black_box("QmTest123"),
                            black_box(idx),
                            black_box(data.clone()),
                        )
                        .await,
                )
            })
        })
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);
    let data = vec![0u8; 10240];
    let mut counter = 0u64;

    // Pre-populate some data
    rt.block_on(async {
        for i in 0..20 {
            prefetcher.put_cached("QmTest123", i, data.clone()).await;
        }
    });

    c.bench_function("mixed_operations", |b| {
        b.iter(|| {
            let idx = counter % 30;
            counter += 1;

            rt.block_on(async {
                // Mix of cache hits, misses, and puts
                if idx < 20 {
                    // Should be a hit
                    let _ = prefetcher.get_cached("QmTest123", idx).await;
                } else {
                    // Should be a miss, then put
                    let _ = prefetcher.get_cached("QmTest123", idx).await;
                    prefetcher.put_cached("QmTest123", idx, data.clone()).await;
                }

                // Record access for pattern detection
                prefetcher.record_access("QmTest123", idx).await;

                // Occasionally get stats
                if counter % 10 == 0 {
                    let _ = prefetcher.stats().await;
                }

                black_box(())
            })
        })
    });
}

fn bench_config_builder(c: &mut Criterion) {
    c.bench_function("config_builder", |b| {
        b.iter(|| {
            black_box(PrefetchConfig {
                max_cached_chunks: black_box(200),
                prefetch_ahead: black_box(5),
                max_cache_memory: black_box(512 * 1024 * 1024),
                cache_ttl: black_box(Duration::from_secs(600)),
                enable_sequential_prediction: black_box(true),
                enable_popularity_prefetch: black_box(true),
            })
        })
    });
}

fn bench_pattern_detection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = PrefetchConfig::default();
    let prefetcher = ChunkPrefetcher::new(config);

    // Pre-populate with clear sequential pattern
    rt.block_on(async {
        for i in 0..15 {
            prefetcher.record_access("QmPattern123", i).await;
        }
    });

    c.bench_function("pattern_detection", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    prefetcher
                        .record_access(black_box("QmPattern123"), black_box(16))
                        .await,
                )
            })
        })
    });
}

criterion_group!(
    benches,
    bench_prefetcher_creation,
    bench_put_cached,
    bench_get_cached_hit,
    bench_get_cached_miss,
    bench_record_access,
    bench_record_access_sequential,
    bench_stats,
    bench_clear_cache,
    bench_cache_eviction,
    bench_mixed_operations,
    bench_config_builder,
    bench_pattern_detection,
);
criterion_main!(benches);
