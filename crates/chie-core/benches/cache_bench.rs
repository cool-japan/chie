use chie_core::cache::{SizedCache, TieredCache, TtlCache};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_ttl_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("ttl_cache_insert");

    for size in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut cache = TtlCache::new(size, Duration::from_secs(60));
            let mut counter = 0;

            b.iter(|| {
                cache.insert(black_box(counter), black_box("value"));
                counter += 1;
            });
        });
    }

    group.finish();
}

fn bench_ttl_cache_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("ttl_cache_get");

    for size in [100, 1000, 10000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut cache = TtlCache::new(size, Duration::from_secs(60));

            // Pre-populate cache
            for i in 0..size {
                cache.insert(i, format!("value_{}", i));
            }

            let mut counter = 0;
            b.iter(|| {
                let key = counter % size;
                let result = cache.get(black_box(&key));
                counter += 1;
                black_box(result)
            });
        });
    }

    group.finish();
}

fn bench_ttl_cache_mixed_ops(c: &mut Criterion) {
    let mut cache = TtlCache::new(1000, Duration::from_secs(60));

    // Pre-populate
    for i in 0..500 {
        cache.insert(i, format!("value_{}", i));
    }

    let mut counter = 500;

    c.bench_function("ttl_cache_mixed_ops", |b| {
        b.iter(|| {
            // 70% reads, 30% writes
            if counter % 10 < 7 {
                let key = counter % 1000;
                black_box(cache.get(&key));
            } else {
                cache.insert(counter, format!("value_{}", counter));
            }
            counter += 1;
        });
    });
}

fn bench_ttl_cache_eviction(c: &mut Criterion) {
    c.bench_function("ttl_cache_eviction", |b| {
        b.iter(|| {
            let mut cache = TtlCache::new(black_box(100), Duration::from_secs(60));

            // Fill cache beyond capacity to trigger evictions
            for i in 0..200 {
                cache.insert(i, format!("value_{}", i));
            }

            black_box(cache)
        });
    });
}

fn bench_ttl_cache_hit_rate(c: &mut Criterion) {
    let mut cache = TtlCache::new(1000, Duration::from_secs(60));

    for i in 0..1000 {
        cache.insert(i, format!("value_{}", i));
    }

    c.bench_function("ttl_cache_hit_rate", |b| {
        b.iter(|| {
            let stats = cache.stats();
            black_box(stats.hit_rate)
        });
    });
}

fn bench_tiered_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_cache");

    group.bench_function("l1_hit", |b| {
        let mut cache = TieredCache::new(100, 1000, Duration::from_secs(60));

        // Populate L1
        for i in 0..100 {
            cache.insert(i, format!("value_{}", i));
        }

        b.iter(|| {
            let result = cache.get(black_box(&50));
            black_box(result)
        });
    });

    group.bench_function("l2_hit_with_promotion", |b| {
        let mut cache = TieredCache::new(10, 100, Duration::from_secs(60));

        // Populate L1
        for i in 0..10 {
            cache.insert(i, format!("value_{}", i));
        }

        // This would be in L2 (evicted from L1)
        b.iter(|| {
            let result = cache.get(black_box(&5));
            black_box(result)
        });
    });

    group.finish();
}

fn bench_sized_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("sized_cache");

    group.bench_function("insert_small_items", |b| {
        let mut cache = SizedCache::new(10_000, Duration::from_secs(60));
        let data = vec![0u8; 100]; // 100 bytes
        let mut counter = 0;

        b.iter(|| {
            cache.insert(black_box(counter), black_box(data.clone()));
            counter += 1;
        });
    });

    group.bench_function("insert_large_items", |b| {
        let mut cache = SizedCache::new(100_000, Duration::from_secs(60));
        let data = vec![0u8; 10_000]; // 10 KB
        let mut counter = 0;

        b.iter(|| {
            cache.insert(black_box(counter), black_box(data.clone()));
            counter += 1;
        });
    });

    group.bench_function("get_with_cleanup", |b| {
        let mut cache = SizedCache::new(10_000, Duration::from_secs(60));

        // Pre-populate
        for i in 0..100 {
            cache.insert(i, vec![0u8; 100]);
        }

        b.iter(|| {
            let result = cache.get(black_box(&50));
            black_box(result)
        });
    });

    group.finish();
}

fn bench_cache_expiration(c: &mut Criterion) {
    c.bench_function("cache_expiration_check", |b| {
        b.iter(|| {
            let mut cache = TtlCache::new(1000, Duration::from_millis(black_box(10)));

            // Insert items
            for i in 0..100 {
                cache.insert(i, format!("value_{}", i));
            }

            // Wait for expiration
            std::thread::sleep(Duration::from_millis(15));

            // Try to get (will check expiration)
            black_box(cache.get(&50))
        });
    });
}

criterion_group!(
    benches,
    bench_ttl_cache_insert,
    bench_ttl_cache_get,
    bench_ttl_cache_mixed_ops,
    bench_ttl_cache_eviction,
    bench_ttl_cache_hit_rate,
    bench_tiered_cache_operations,
    bench_sized_cache_operations,
    bench_cache_expiration,
);

criterion_main!(benches);
