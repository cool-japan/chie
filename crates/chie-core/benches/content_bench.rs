use chie_core::ContentManager;
use chie_shared::{ContentCategory, ContentMetadata, ContentStatus};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

fn create_test_metadata(cid: &str, size_bytes: u64, category: ContentCategory) -> ContentMetadata {
    ContentMetadata {
        id: uuid::Uuid::new_v4(),
        cid: cid.to_string(),
        title: format!("Test Content {}", cid),
        description: format!("Description for {}", cid),
        category,
        tags: vec!["test".to_string(), "benchmark".to_string(), cid.to_string()],
        size_bytes,
        chunk_count: size_bytes / 1024,
        price: 100,
        creator_id: uuid::Uuid::new_v4(),
        status: ContentStatus::Active,
        preview_images: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn bench_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_cache");

    for size in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::new("put", size), size, |b, &size| {
            b.iter(|| {
                let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), size);
                for i in 0..size {
                    let metadata = create_test_metadata(
                        &format!("QmTest{}", i),
                        1024 * 1024,
                        ContentCategory::ThreeDModels,
                    );
                    manager.cache_metadata(format!("QmTest{}", i), metadata);
                }
                black_box(manager)
            });
        });

        group.bench_with_input(BenchmarkId::new("get", size), size, |b, &size| {
            let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), size);
            for i in 0..size {
                let metadata = create_test_metadata(
                    &format!("QmTest{}", i),
                    1024 * 1024,
                    ContentCategory::ThreeDModels,
                );
                manager.cache_metadata(format!("QmTest{}", i), metadata);
            }
            b.iter(|| {
                for i in 0..size {
                    black_box(manager.get_metadata(&format!("QmTest{}", i)));
                }
            });
        });
    }

    group.finish();
}

fn bench_search_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_search");

    for size in [100, 500, 1000].iter() {
        // Setup manager with diverse content
        let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), *size);
        let categories = [
            ContentCategory::ThreeDModels,
            ContentCategory::Textures,
            ContentCategory::Audio,
            ContentCategory::Scripts,
        ];

        for i in 0..*size {
            let category = categories[i % categories.len()];
            let metadata =
                create_test_metadata(&format!("QmTest{}", i), 1024 * 1024 * i as u64, category);
            manager.cache_metadata(format!("QmTest{}", i), metadata);
        }

        group.bench_with_input(BenchmarkId::new("by_category", size), size, |b, _| {
            b.iter(|| {
                let results = manager.search_by_category(ContentCategory::ThreeDModels);
                black_box(results.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("by_tag", size), size, |b, _| {
            b.iter(|| {
                let results = manager.search_by_tag("benchmark");
                black_box(results.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("by_text", size), size, |b, _| {
            b.iter(|| {
                let results = manager.search_by_text("Test");
                black_box(results.len())
            });
        });
    }

    group.finish();
}

fn bench_discovery_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_discovery");

    for size in [100, 500, 1000].iter() {
        let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), *size);

        for i in 0..*size {
            let metadata = create_test_metadata(
                &format!("QmTest{}", i),
                1024 * 1024 * (i as u64 + 1),
                ContentCategory::ThreeDModels,
            );
            manager.cache_metadata(format!("QmTest{}", i), metadata);
        }

        group.bench_with_input(BenchmarkId::new("largest_10", size), size, |b, _| {
            b.iter(|| {
                let results = manager.get_largest_content(10);
                black_box(results.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("largest_100", size), size, |b, _| {
            b.iter(|| {
                let results = manager.get_largest_content(100);
                black_box(results.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("newest_10", size), size, |b, _| {
            b.iter(|| {
                let results = manager.get_newest_content(10);
                black_box(results.len())
            });
        });
    }

    group.finish();
}

fn bench_lru_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru_eviction");

    group.bench_function("eviction_100_cap_50", |b| {
        b.iter(|| {
            let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), 50);
            for i in 0..100 {
                let metadata = create_test_metadata(
                    &format!("QmTest{}", i),
                    1024 * 1024,
                    ContentCategory::ThreeDModels,
                );
                manager.cache_metadata(format!("QmTest{}", i), metadata);
            }
            black_box(manager)
        });
    });

    group.bench_function("eviction_1000_cap_100", |b| {
        b.iter(|| {
            let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), 100);
            for i in 0..1000 {
                let metadata = create_test_metadata(
                    &format!("QmTest{}", i),
                    1024 * 1024,
                    ContentCategory::ThreeDModels,
                );
                manager.cache_metadata(format!("QmTest{}", i), metadata);
            }
            black_box(manager)
        });
    });

    group.finish();
}

fn bench_statistics(c: &mut Criterion) {
    let mut group = c.benchmark_group("statistics");

    let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp"), 1000);
    for i in 0..1000 {
        let metadata = create_test_metadata(
            &format!("QmTest{}", i),
            1024 * 1024,
            ContentCategory::ThreeDModels,
        );
        manager.cache_metadata(format!("QmTest{}", i), metadata);
    }

    group.bench_function("cache_hit_rate", |b| {
        b.iter(|| {
            for i in 0..100 {
                manager.get_metadata(&format!("QmTest{}", i));
            }
            black_box(manager.stats().hit_rate())
        });
    });

    group.bench_function("total_storage_used", |b| {
        b.iter(|| black_box(manager.total_storage_used()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cache_operations,
    bench_search_operations,
    bench_discovery_operations,
    bench_lru_eviction,
    bench_statistics
);
criterion_main!(benches);
