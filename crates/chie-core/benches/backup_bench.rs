use chie_core::{BackupConfig, BackupManager, BackupProgress};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_backup_config_creation(c: &mut Criterion) {
    c.bench_function("backup_config_default", |b| {
        b.iter(|| black_box(BackupConfig::default()));
    });
}

fn bench_backup_config_custom(c: &mut Criterion) {
    c.bench_function("backup_config_custom", |b| {
        b.iter(|| {
            black_box(BackupConfig {
                compress: black_box(true),
                archive_chunk_size: black_box(4 * 1024 * 1024),
                verify_on_backup: black_box(true),
                verify_on_restore: black_box(true),
                include_metadata: black_box(true),
            })
        });
    });
}

fn bench_backup_manager_creation(c: &mut Criterion) {
    c.bench_function("backup_manager_new", |b| {
        b.iter(|| {
            let config = BackupConfig::default();
            black_box(BackupManager::new(black_box(config)))
        });
    });
}

fn bench_backup_progress_creation(c: &mut Criterion) {
    c.bench_function("backup_progress_new", |b| {
        b.iter(|| black_box(BackupProgress::new()));
    });
}

fn bench_backup_progress_percentage(c: &mut Criterion) {
    c.bench_function("backup_progress_percentage", |b| {
        let progress = BackupProgress::new();
        progress
            .total_bytes
            .store(1000, std::sync::atomic::Ordering::Relaxed);
        progress
            .processed_bytes
            .store(500, std::sync::atomic::Ordering::Relaxed);

        b.iter(|| black_box(progress.percentage()));
    });
}

fn bench_backup_progress_is_cancelled(c: &mut Criterion) {
    c.bench_function("backup_progress_is_cancelled", |b| {
        let progress = BackupProgress::new();
        b.iter(|| black_box(progress.is_cancelled()));
    });
}

fn bench_backup_progress_add_bytes(c: &mut Criterion) {
    c.bench_function("backup_progress_add_bytes", |b| {
        let progress = BackupProgress::new();
        let mut count = 0u64;
        b.iter(|| {
            count = (count + 1) % 1000;
            progress.add_bytes(black_box(count));
        });
    });
}

fn bench_backup_progress_increment_items(c: &mut Criterion) {
    c.bench_function("backup_progress_increment_items", |b| {
        let progress = BackupProgress::new();
        b.iter(|| {
            progress.increment_items();
        });
    });
}

fn bench_backup_progress_cancel(c: &mut Criterion) {
    c.bench_function("backup_progress_cancel", |b| {
        b.iter(|| {
            let progress = BackupProgress::new();
            progress.cancel();
            black_box(progress.is_cancelled())
        });
    });
}

fn bench_backup_progress_set_operation(c: &mut Criterion) {
    c.bench_function("backup_progress_set_operation", |b| {
        let progress = BackupProgress::new();
        b.iter(|| {
            progress.set_operation(black_box("Backing up chunk data"));
        });
    });
}

fn bench_backup_progress_mixed_operations(c: &mut Criterion) {
    c.bench_function("backup_progress_mixed_ops", |b| {
        b.iter(|| {
            let progress = BackupProgress::new();
            progress
                .total_bytes
                .store(1024 * 1024 * 1024, std::sync::atomic::Ordering::Relaxed);
            progress
                .total_items
                .store(1000, std::sync::atomic::Ordering::Relaxed);
            progress.add_bytes(black_box(1024 * 1024)); // 1 MB
            progress.increment_items();
            progress.set_operation(black_box("Processing"));
            let _pct = progress.percentage();
            let _cancelled = progress.is_cancelled();
            black_box(progress)
        });
    });
}

fn bench_backup_progress_percentage_with_varying_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("backup_progress_percentage_varying");

    for percentage in [0, 25, 50, 75, 100].iter() {
        let total_bytes = 1024 * 1024 * 1024u64; // 1 GB
        let completed_bytes = (total_bytes * percentage) / 100;

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}%", percentage)),
            &completed_bytes,
            |b, &completed| {
                b.iter(|| {
                    let progress = BackupProgress::new();
                    progress
                        .total_bytes
                        .store(total_bytes, std::sync::atomic::Ordering::Relaxed);
                    progress
                        .processed_bytes
                        .store(black_box(completed), std::sync::atomic::Ordering::Relaxed);
                    black_box(progress.percentage())
                });
            },
        );
    }
    group.finish();
}

fn bench_backup_config_variations(c: &mut Criterion) {
    let mut group = c.benchmark_group("backup_config_variations");

    for &compress in [true, false].iter() {
        for &verify in [true, false].iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("comp_{}_verify_{}", compress, verify)),
                &(compress, verify),
                |b, &(comp, ver)| {
                    b.iter(|| {
                        black_box(BackupConfig {
                            compress: black_box(comp),
                            archive_chunk_size: 4 * 1024 * 1024,
                            verify_on_backup: black_box(ver),
                            verify_on_restore: black_box(ver),
                            include_metadata: true,
                        })
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_backup_config_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("backup_config_chunk_sizes");

    for &chunk_size_mb in [1, 2, 4, 8].iter() {
        let chunk_size_bytes = chunk_size_mb * 1024 * 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", chunk_size_mb)),
            &chunk_size_bytes,
            |b, &size| {
                b.iter(|| {
                    black_box(BackupConfig {
                        compress: true,
                        archive_chunk_size: black_box(size),
                        verify_on_backup: true,
                        verify_on_restore: true,
                        include_metadata: true,
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_backup_progress_atomic_operations(c: &mut Criterion) {
    c.bench_function("backup_progress_atomic_store_load", |b| {
        let progress = BackupProgress::new();
        b.iter(|| {
            progress.total_bytes.store(
                black_box(1024 * 1024 * 1024),
                std::sync::atomic::Ordering::Relaxed,
            );
            let value = progress
                .total_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            black_box(value)
        });
    });
}

criterion_group!(
    benches,
    bench_backup_config_creation,
    bench_backup_config_custom,
    bench_backup_manager_creation,
    bench_backup_progress_creation,
    bench_backup_progress_percentage,
    bench_backup_progress_is_cancelled,
    bench_backup_progress_add_bytes,
    bench_backup_progress_increment_items,
    bench_backup_progress_cancel,
    bench_backup_progress_set_operation,
    bench_backup_progress_mixed_operations,
    bench_backup_progress_percentage_with_varying_data,
    bench_backup_config_variations,
    bench_backup_config_chunk_sizes,
    bench_backup_progress_atomic_operations,
);
criterion_main!(benches);
