//! Benchmarks for tier migration operations.

use chie_core::tier_migration::{MigrationConfig, MigrationStatus, MigrationTask, TierMigration};
use chie_core::tiered_storage::{
    PendingMove, StorageTier, TieredStorageConfig, TieredStorageManager,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;

/// Benchmark creating migration tasks.
fn bench_create_migration_task(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    c.bench_function("tier_migration/create_task", |b| {
        b.iter(|| {
            let pm = PendingMove {
                cid: black_box("QmTest123".to_string()),
                from: StorageTier::Warm,
                to: StorageTier::Hot,
                size: black_box(1024 * 1024),
                priority: black_box(10),
            };
            black_box(migration.create_task(pm));
        });
    });
}

/// Benchmark migration task status checks.
fn bench_migration_status(c: &mut Criterion) {
    let statuses = vec![
        MigrationStatus::Pending,
        MigrationStatus::InProgress,
        MigrationStatus::Completed,
        MigrationStatus::Failed("error".to_string()),
        MigrationStatus::Cancelled,
    ];

    c.bench_function("tier_migration/status_check", |b| {
        b.iter(|| {
            for status in &statuses {
                black_box(status == &MigrationStatus::Completed);
            }
        });
    });
}

/// Benchmark migration config access.
fn bench_migration_config_access(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    c.bench_function("tier_migration/config_access", |b| {
        b.iter(|| {
            let config = migration.config();
            black_box(config.max_concurrent);
            black_box(config.migration_timeout_secs);
            black_box(config.verify_after_move);
        });
    });
}

/// Benchmark cancel pending migrations.
fn bench_cancel_pending(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    c.bench_function("tier_migration/cancel_pending", |b| {
        b.iter(|| {
            black_box(migration.cancel_pending());
        });
    });
}

/// Benchmark creating migration tasks with varying sizes.
fn bench_create_tasks_varying_sizes(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    let mut group = c.benchmark_group("tier_migration/create_tasks_by_size");

    for size in [1024, 1024 * 1024, 100 * 1024 * 1024, 1024 * 1024 * 1024u64] {
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let pm = PendingMove {
                    cid: format!("QmTest{}", size),
                    from: StorageTier::Warm,
                    to: StorageTier::Hot,
                    size: black_box(size),
                    priority: 10,
                };
                black_box(migration.create_task(pm));
            });
        });
    }
    group.finish();
}

/// Benchmark migration task creation for different tier transitions.
fn bench_tier_transitions(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    let transitions = vec![
        ("warm_to_hot", StorageTier::Warm, StorageTier::Hot),
        ("hot_to_warm", StorageTier::Hot, StorageTier::Warm),
        ("warm_to_cold", StorageTier::Warm, StorageTier::Cold),
        ("cold_to_warm", StorageTier::Cold, StorageTier::Warm),
    ];

    let mut group = c.benchmark_group("tier_migration/transitions");

    for (name, from, to) in transitions {
        group.bench_function(name, |b| {
            b.iter(|| {
                let pm = PendingMove {
                    cid: "QmTest123".to_string(),
                    from: black_box(from),
                    to: black_box(to),
                    size: 1024 * 1024,
                    priority: 10,
                };
                black_box(migration.create_task(pm));
            });
        });
    }
    group.finish();
}

/// Benchmark batch task creation.
fn bench_batch_task_creation(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));
    let migration_config = MigrationConfig::default();
    let migration = TierMigration::new(storage, migration_config);

    let mut group = c.benchmark_group("tier_migration/batch_create");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                for i in 0..count {
                    let pm = PendingMove {
                        cid: format!("QmTest{}", i),
                        from: StorageTier::Warm,
                        to: StorageTier::Hot,
                        size: 1024 * 1024,
                        priority: 10,
                    };
                    black_box(migration.create_task(pm));
                }
            });
        });
    }
    group.finish();
}

/// Benchmark migration configuration with different settings.
fn bench_migration_config_variants(c: &mut Criterion) {
    let storage_config = TieredStorageConfig::default();
    let storage = Arc::new(TieredStorageManager::new(storage_config));

    let mut group = c.benchmark_group("tier_migration/config_variants");

    // Default config
    group.bench_function("default", |b| {
        b.iter(|| {
            let config = MigrationConfig::default();
            black_box(TierMigration::new(storage.clone(), config));
        });
    });

    // High concurrency config
    group.bench_function("high_concurrency", |b| {
        b.iter(|| {
            let config = MigrationConfig {
                max_concurrent: 16,
                ..Default::default()
            };
            black_box(TierMigration::new(storage.clone(), config));
        });
    });

    // No verification config
    group.bench_function("no_verification", |b| {
        b.iter(|| {
            let config = MigrationConfig {
                verify_after_move: false,
                ..Default::default()
            };
            black_box(TierMigration::new(storage.clone(), config));
        });
    });

    group.finish();
}

/// Benchmark migration task updates.
fn bench_task_updates(c: &mut Criterion) {
    let mut task = MigrationTask {
        cid: "QmTest123".to_string(),
        from: StorageTier::Warm,
        to: StorageTier::Hot,
        size: 1024 * 1024,
        status: MigrationStatus::Pending,
        retries: 0,
        created_at: 1000000,
        updated_at: 1000000,
    };

    c.bench_function("tier_migration/update_status", |b| {
        b.iter(|| {
            task.status = black_box(MigrationStatus::InProgress);
            task.updated_at = black_box(1000001);
            task.retries = black_box(task.retries + 1);
        });
    });
}

criterion_group!(
    benches,
    bench_create_migration_task,
    bench_migration_status,
    bench_migration_config_access,
    bench_cancel_pending,
    bench_create_tasks_varying_sizes,
    bench_tier_transitions,
    bench_batch_task_creation,
    bench_migration_config_variants,
    bench_task_updates,
);
criterion_main!(benches);
