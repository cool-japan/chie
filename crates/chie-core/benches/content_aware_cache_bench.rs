use chie_core::content_aware_cache::{CacheContentMetrics, ContentAwareCache, ContentType};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Helper to create test content metrics.
fn create_metrics(
    content_type: ContentType,
    size: usize,
    freq: u32,
    priority: u8,
) -> CacheContentMetrics {
    CacheContentMetrics {
        content_type,
        size_bytes: size,
        access_frequency: freq,
        priority,
    }
}

/// Helper to create test data.
fn create_data(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// Benchmark ContentAwareCache creation.
fn bench_cache_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_creation");

    for &size_mb in &[10, 100, 500, 1000] {
        let size_bytes = size_mb * 1024 * 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", size_mb)),
            &size_bytes,
            |b, &s| {
                b.iter(|| {
                    let cache = ContentAwareCache::new(black_box(s));
                    black_box(cache);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark insert operations with different content types.
fn bench_insert_by_content_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert_by_content_type");

    let content_types = vec![
        ("Metadata", ContentType::Metadata, 1024),
        ("ImageChunk", ContentType::ImageChunk, 100 * 1024),
        ("VideoChunk", ContentType::VideoChunk, 256 * 1024),
        ("AudioChunk", ContentType::AudioChunk, 64 * 1024),
        ("DocumentChunk", ContentType::DocumentChunk, 50 * 1024),
        ("Generic", ContentType::Generic, 128 * 1024),
    ];

    for (name, content_type, size) in content_types {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(content_type, size),
            |b, &(ct, sz)| {
                b.iter(|| {
                    let mut cache = ContentAwareCache::new(100 * 1024 * 1024);
                    let metrics = create_metrics(ct, sz, 10, 5);
                    let data = create_data(sz);
                    cache.insert(black_box("key1".to_string()), data, metrics);
                    black_box(cache);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark insert operations with different sizes.
fn bench_insert_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert_by_size");

    for &size_kb in &[1, 10, 100, 1000] {
        let size_bytes = size_kb * 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size_bytes,
            |b, &sz| {
                b.iter(|| {
                    let mut cache = ContentAwareCache::new(100 * 1024 * 1024);
                    let metrics = create_metrics(ContentType::VideoChunk, sz, 10, 5);
                    let data = create_data(sz);
                    cache.insert(black_box("key1".to_string()), data, metrics);
                    black_box(cache);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bulk insert operations.
fn bench_bulk_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_bulk_insert");

    for &count in &[10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

                    for i in 0..n {
                        let content_type = match i % 6 {
                            0 => ContentType::Metadata,
                            1 => ContentType::ImageChunk,
                            2 => ContentType::VideoChunk,
                            3 => ContentType::AudioChunk,
                            4 => ContentType::DocumentChunk,
                            _ => ContentType::Generic,
                        };
                        let size = 10 * 1024; // 10KB each
                        let metrics = create_metrics(content_type, size, 10, 5);
                        let data = create_data(size);
                        cache.insert(format!("key{}", i), data, metrics);
                    }

                    black_box(cache);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark get operations (cache hit).
fn bench_get_hit(c: &mut Criterion) {
    c.bench_function("cache_get_hit", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);
            let metrics = create_metrics(ContentType::VideoChunk, 256 * 1024, 10, 5);
            let data = create_data(256 * 1024);
            cache.insert("key1".to_string(), data, metrics);

            // Get the entry
            let result = cache.get(black_box("key1"));
            black_box(result);
        });
    });
}

/// Benchmark get operations (cache miss).
fn bench_get_miss(c: &mut Criterion) {
    c.bench_function("cache_get_miss", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);
            let metrics = create_metrics(ContentType::VideoChunk, 256 * 1024, 10, 5);
            let data = create_data(256 * 1024);
            cache.insert("key1".to_string(), data, metrics);

            // Try to get non-existent entry
            let result = cache.get(black_box("nonexistent"));
            black_box(result);
        });
    });
}

/// Benchmark repeated access (hit rate tracking).
fn bench_repeated_access(c: &mut Criterion) {
    c.bench_function("cache_repeated_access", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

            // Insert 10 entries
            for i in 0..10 {
                let metrics = create_metrics(ContentType::VideoChunk, 100 * 1024, 10, 5);
                let data = create_data(100 * 1024);
                cache.insert(format!("key{}", i), data, metrics);
            }

            // Access some entries multiple times
            for _ in 0..20 {
                let _ = cache.get("key0");
                let _ = cache.get("key5");
                let _ = cache.get("key9");
                let _ = cache.get("nonexistent");
            }

            let hit_rate = cache.hit_rate();
            black_box(hit_rate);
        });
    });
}

/// Benchmark remove operations.
fn bench_remove(c: &mut Criterion) {
    c.bench_function("cache_remove", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);
            let metrics = create_metrics(ContentType::VideoChunk, 256 * 1024, 10, 5);
            let data = create_data(256 * 1024);
            cache.insert("key1".to_string(), data, metrics);

            // Remove the entry
            let result = cache.remove(black_box("key1"));
            black_box(result);
        });
    });
}

/// Benchmark clear operations.
fn bench_clear(c: &mut Criterion) {
    c.bench_function("cache_clear", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

            // Insert many entries
            for i in 0..100 {
                let metrics = create_metrics(ContentType::Generic, 10 * 1024, 10, 5);
                let data = create_data(10 * 1024);
                cache.insert(format!("key{}", i), data, metrics);
            }

            // Clear the cache
            cache.clear();
            black_box(cache);
        });
    });
}

/// Benchmark statistics queries.
fn bench_stats_queries(c: &mut Criterion) {
    c.bench_function("cache_stats_queries", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

            // Insert entries with different types
            for i in 0..50 {
                let content_type = match i % 3 {
                    0 => ContentType::Metadata,
                    1 => ContentType::VideoChunk,
                    _ => ContentType::ImageChunk,
                };
                let metrics = create_metrics(content_type, 50 * 1024, 10, 5);
                let data = create_data(50 * 1024);
                cache.insert(format!("key{}", i), data, metrics);
            }

            // Query statistics
            let entry_count = cache.entry_count();
            let usage = cache.usage_percentage();
            let metadata_size = cache.size_by_type(ContentType::Metadata);
            let video_size = cache.size_by_type(ContentType::VideoChunk);
            let stats = cache.stats();

            black_box((entry_count, usage, metadata_size, video_size, stats));
        });
    });
}

/// Benchmark size adjustment with eviction.
fn bench_adjust_size_with_eviction(c: &mut Criterion) {
    c.bench_function("cache_adjust_size_eviction", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

            // Fill cache
            for i in 0..100 {
                let metrics = create_metrics(ContentType::VideoChunk, 500 * 1024, 10, 5);
                let data = create_data(500 * 1024);
                cache.insert(format!("key{}", i), data, metrics);
            }

            // Reduce cache size (triggers eviction)
            cache.adjust_size(black_box(20 * 1024 * 1024));
            black_box(cache);
        });
    });
}

/// Benchmark recommended size calculation.
fn bench_recommended_size(c: &mut Criterion) {
    c.bench_function("cache_recommended_size", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024);

            // Add various content types
            for i in 0..50 {
                let content_type = match i % 4 {
                    0 => ContentType::Metadata,
                    1 => ContentType::ImageChunk,
                    2 => ContentType::VideoChunk,
                    _ => ContentType::DocumentChunk,
                };
                let metrics = create_metrics(content_type, 100 * 1024, i as u32, 5);
                let data = create_data(100 * 1024);
                cache.insert(format!("key{}", i), data, metrics);
            }

            // Access some entries
            for i in 0..25 {
                let _ = cache.get(&format!("key{}", i));
            }

            let recommended = cache.recommended_size();
            black_box(recommended);
        });
    });
}

/// Benchmark automatic eviction with different priorities.
fn bench_eviction_by_priority(c: &mut Criterion) {
    c.bench_function("cache_eviction_by_priority", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(5 * 1024 * 1024); // Small cache

            // Insert low priority items
            for i in 0..10 {
                let metrics = create_metrics(ContentType::Generic, 500 * 1024, 1, 1);
                let data = create_data(500 * 1024);
                cache.insert(format!("low{}", i), data, metrics);
            }

            // Insert high priority items (should evict low priority)
            for i in 0..10 {
                let metrics = create_metrics(ContentType::Metadata, 500 * 1024, 100, 9);
                let data = create_data(500 * 1024);
                cache.insert(format!("high{}", i), data, metrics);
            }

            black_box(cache);
        });
    });
}

/// Benchmark realistic scenario: video streaming cache.
fn bench_realistic_video_streaming(c: &mut Criterion) {
    c.bench_function("cache_realistic_video_streaming", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(50 * 1024 * 1024); // 50MB cache

            // Simulate video streaming scenario:
            // - Metadata (manifests, playlists) - small, high priority
            // - Video chunks - large, medium priority
            // - Preview images - medium, low priority

            // Add metadata
            for i in 0..10 {
                let metrics = create_metrics(ContentType::Metadata, 2 * 1024, 50, 9);
                let data = create_data(2 * 1024);
                cache.insert(format!("manifest:{}", i), data, metrics);
            }

            // Add video chunks (sequentially)
            for i in 0..100 {
                let metrics = create_metrics(ContentType::VideoChunk, 256 * 1024, 10, 5);
                let data = create_data(256 * 1024);
                cache.insert(format!("video:chunk:{}", i), data, metrics);
            }

            // Add preview images
            for i in 0..20 {
                let metrics = create_metrics(ContentType::ImageChunk, 50 * 1024, 2, 3);
                let data = create_data(50 * 1024);
                cache.insert(format!("preview:{}", i), data, metrics);
            }

            // Simulate playback (accessing recent chunks)
            for i in 80..100 {
                let _ = cache.get(&format!("video:chunk:{}", i));
            }

            // Check cache efficiency
            let stats = cache.stats();
            let hit_rate = cache.hit_rate();

            black_box((stats, hit_rate, cache));
        });
    });
}

/// Benchmark realistic scenario: web content cache.
fn bench_realistic_web_content(c: &mut Criterion) {
    c.bench_function("cache_realistic_web_content", |b| {
        b.iter(|| {
            let mut cache = ContentAwareCache::new(100 * 1024 * 1024); // 100MB cache

            // Simulate web content caching:
            // - HTML pages (documents) - high priority
            // - Images - medium priority
            // - API responses (metadata) - very high priority

            // Add API responses
            for i in 0..50 {
                let metrics = create_metrics(ContentType::Metadata, 5 * 1024, 100, 10);
                let data = create_data(5 * 1024);
                cache.insert(format!("api:/users/{}", i), data, metrics);
            }

            // Add HTML pages
            for i in 0..100 {
                let metrics = create_metrics(ContentType::DocumentChunk, 30 * 1024, 20, 7);
                let data = create_data(30 * 1024);
                cache.insert(format!("page:/article/{}", i), data, metrics);
            }

            // Add images
            for i in 0..200 {
                let metrics = create_metrics(ContentType::ImageChunk, 100 * 1024, 5, 4);
                let data = create_data(100 * 1024);
                cache.insert(format!("img:/photo/{}.jpg", i), data, metrics);
            }

            // Simulate user browsing (repeated access to popular content)
            for _ in 0..5 {
                let _ = cache.get("api:/users/1");
                let _ = cache.get("page:/article/0");
                let _ = cache.get("img:/photo/0.jpg");
            }

            // Check cache performance
            let usage = cache.usage_percentage();
            let recommended = cache.recommended_size();
            let hit_rate = cache.hit_rate();

            black_box((usage, recommended, hit_rate, cache));
        });
    });
}

criterion_group!(
    benches,
    bench_cache_creation,
    bench_insert_by_content_type,
    bench_insert_by_size,
    bench_bulk_insert,
    bench_get_hit,
    bench_get_miss,
    bench_repeated_access,
    bench_remove,
    bench_clear,
    bench_stats_queries,
    bench_adjust_size_with_eviction,
    bench_recommended_size,
    bench_eviction_by_priority,
    bench_realistic_video_streaming,
    bench_realistic_web_content,
);
criterion_main!(benches);
