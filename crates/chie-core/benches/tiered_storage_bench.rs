use chie_core::tiered_storage::{
    StorageTier, TierConfig, TieredStorageConfig, TieredStorageManager,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempfile::TempDir;

// Benchmark config creation
fn bench_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/config");

    group.bench_function("tier_config", |b| {
        b.iter(|| {
            black_box(TierConfig::new(
                StorageTier::Hot,
                "/tmp/hot",
                100 * 1024 * 1024 * 1024,
            ))
        })
    });

    group.bench_function("tiered_config_default", |b| {
        b.iter(|| black_box(TieredStorageConfig::default()))
    });

    group.bench_function("tiered_config_custom", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            black_box(TieredStorageConfig {
                hot: Some(TierConfig::new(
                    StorageTier::Hot,
                    temp_dir.path().join("hot"),
                    50 * 1024 * 1024 * 1024,
                )),
                warm: TierConfig::new(
                    StorageTier::Warm,
                    temp_dir.path().join("warm"),
                    200 * 1024 * 1024 * 1024,
                ),
                cold: Some(TierConfig::new(
                    StorageTier::Cold,
                    temp_dir.path().join("cold"),
                    500 * 1024 * 1024 * 1024,
                )),
                hot_promotion_threshold: 20,
                hot_demotion_inactive_secs: 7 * 24 * 3600,
                cold_demotion_inactive_secs: 30 * 24 * 3600,
                max_move_per_cycle: 10,
                rebalance_interval_secs: 3600,
            })
        })
    });

    group.finish();
}

// Benchmark manager creation
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/manager_creation");

    group.bench_function("with_default_config", |b| {
        b.iter(|| {
            let config = TieredStorageConfig::default();
            black_box(TieredStorageManager::new(config))
        })
    });

    group.bench_function("with_custom_config", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = TieredStorageConfig {
            hot: Some(TierConfig::new(
                StorageTier::Hot,
                temp_dir.path().join("hot"),
                50 * 1024 * 1024 * 1024,
            )),
            warm: TierConfig::new(
                StorageTier::Warm,
                temp_dir.path().join("warm"),
                200 * 1024 * 1024 * 1024,
            ),
            cold: Some(TierConfig::new(
                StorageTier::Cold,
                temp_dir.path().join("cold"),
                500 * 1024 * 1024 * 1024,
            )),
            ..Default::default()
        };

        b.iter(|| black_box(TieredStorageManager::new(config.clone())))
    });

    group.finish();
}

// Benchmark register content
fn bench_register_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/register");

    group.bench_function("single_content", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);
        let mut counter = 0u64;

        b.iter(|| {
            let cid = format!("QmContent{}", counter);
            counter += 1;
            black_box(manager.register_content(&cid, 1024 * 1024 * 100))
        })
    });

    for count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", count),
            count,
            |b, &content_count| {
                b.iter(|| {
                    let config = TieredStorageConfig::default();
                    let manager = TieredStorageManager::new(config);

                    for i in 0..content_count {
                        let _ =
                            manager.register_content(&format!("QmContent{}", i), 1024 * 1024 * 100);
                    }

                    black_box(manager)
                })
            },
        );
    }

    group.finish();
}

// Benchmark record access
fn bench_record_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/record_access");

    group.bench_function("single_access", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);
        let _ = manager.register_content("QmTest", 1024 * 1024 * 100);

        b.iter(|| {
            manager.record_access(black_box("QmTest"));
        })
    });

    for count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch", count),
            count,
            |b, &access_count| {
                let config = TieredStorageConfig::default();
                let manager = TieredStorageManager::new(config);

                // Register some content
                for i in 0..10 {
                    let _ = manager.register_content(&format!("QmContent{}", i), 1024 * 1024 * 100);
                }

                b.iter(|| {
                    for i in 0..access_count {
                        manager.record_access(&format!("QmContent{}", i % 10));
                    }
                })
            },
        );
    }

    group.finish();
}

// Benchmark get location
fn bench_get_location(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/get_location");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(content_count),
            content_count,
            |b, &count| {
                let config = TieredStorageConfig::default();
                let manager = TieredStorageManager::new(config);

                // Pre-populate
                for i in 0..count {
                    let _ = manager.register_content(&format!("QmContent{}", i), 1024 * 1024 * 100);
                }

                b.iter(|| {
                    let cid = format!("QmContent{}", count / 2);
                    black_box(manager.get_location(&cid))
                })
            },
        );
    }

    group.finish();
}

// Benchmark get content path
fn bench_get_content_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/get_path");

    group.bench_function("existing_content", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);
        let _ = manager.register_content("QmTest", 1024 * 1024 * 100);

        b.iter(|| black_box(manager.get_content_path(black_box("QmTest"))))
    });

    group.bench_function("nonexistent_content", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        b.iter(|| black_box(manager.get_content_path(black_box("QmNonexistent"))))
    });

    group.finish();
}

// Benchmark tier stats
fn bench_tier_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/stats");

    for content_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(content_count),
            content_count,
            |b, &count| {
                let config = TieredStorageConfig::default();
                let manager = TieredStorageManager::new(config);

                // Pre-populate
                for i in 0..count {
                    let _ = manager.register_content(&format!("QmContent{}", i), 1024 * 1024 * 100);
                }

                b.iter(|| black_box(manager.tier_stats()))
            },
        );
    }

    group.finish();
}

// Benchmark remove content
fn bench_remove_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/remove");

    group.bench_function("single_remove", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        // Pre-populate with many items
        for i in 0..1000 {
            let _ = manager.register_content(&format!("QmContent{}", i), 1024 * 1024 * 100);
        }

        let mut counter = 0u64;
        b.iter(|| {
            let cid = format!("QmContent{}", counter % 1000);
            counter += 1;
            manager.remove_content(&cid);
        })
    });

    group.finish();
}

// Benchmark storage tier enum operations
fn bench_storage_tier(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/tier_enum");

    group.bench_function("tier_equality", |b| {
        let tiers = [StorageTier::Hot, StorageTier::Warm, StorageTier::Cold];
        let mut idx = 0;
        b.iter(|| {
            let tier1 = tiers[idx % 3];
            let tier2 = tiers[(idx + 1) % 3];
            idx += 1;
            black_box(tier1 == tier2)
        })
    });

    group.finish();
}

// Benchmark mixed operations
fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered_storage/mixed");

    group.bench_function("typical_workflow", |b| {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);
        let mut counter = 0u64;

        b.iter(|| {
            // Register new content
            let cid = format!("QmContent{}", counter);
            counter += 1;
            let _tier = manager.register_content(&cid, 1024 * 1024 * 100);

            // Record some accesses
            for _ in 0..5 {
                manager.record_access(&cid);
            }

            // Get location
            let _location = manager.get_location(&cid);

            // Get path
            let _path = manager.get_content_path(&cid);

            // Get stats
            black_box(manager.tier_stats());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_manager_creation,
    bench_register_content,
    bench_record_access,
    bench_get_location,
    bench_get_content_path,
    bench_tier_stats,
    bench_remove_content,
    bench_storage_tier,
    bench_mixed_operations,
);

criterion_main!(benches);
