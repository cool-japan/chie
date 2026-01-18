//! Benchmarks for checkpoint operations.
//!
//! Measures performance of:
//! - Checkpoint manager creation
//! - State serialization and deserialization
//! - Checkpoint list operations
//! - Metadata age calculation

use chie_core::checkpoint::{CheckpointConfig, CheckpointManager, Checkpointable};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use tempfile::TempDir;

/// Test state for benchmarking.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestState {
    id: u64,
    data: Vec<u8>,
    metadata: std::collections::HashMap<String, String>,
}

impl Checkpointable for TestState {
    fn checkpoint_id(&self) -> String {
        format!("test_state_{}", self.id)
    }
}

impl TestState {
    fn new(id: u64, data_size: usize) -> Self {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("version".to_string(), "1.0".to_string());
        metadata.insert("type".to_string(), "test".to_string());

        Self {
            id,
            data: vec![0u8; data_size],
            metadata,
        }
    }
}

/// Benchmark creating checkpoint managers.
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("manager_creation");

    group.bench_function("create_new_manager", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: black_box(10),
                compression_enabled: black_box(false),
            };
            let manager = CheckpointManager::new(config).unwrap();
            black_box(manager)
        });
    });

    group.bench_function("create_with_compression", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: black_box(10),
                compression_enabled: black_box(true),
            };
            let manager = CheckpointManager::new(config).unwrap();
            black_box(manager)
        });
    });

    group.finish();
}

/// Benchmark saving checkpoints of different sizes.
fn bench_save_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("save_checkpoint");

    let sizes = vec![1024, 10 * 1024, 100 * 1024]; // 1KB, 10KB, 100KB

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, &size| {
                let temp_dir = TempDir::new().unwrap();
                let config = CheckpointConfig {
                    base_path: temp_dir.path().to_path_buf(),
                    max_checkpoints: 10,
                    compression_enabled: false,
                };
                let mut manager = CheckpointManager::new(config).unwrap();

                b.iter(|| {
                    let state = TestState::new(black_box(1), size);
                    manager.save_checkpoint(&state).unwrap();
                });
            },
        );
    }

    group.finish();
}

/// Benchmark restoring checkpoints.
fn bench_restore_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("restore_checkpoint");

    let sizes = vec![1024, 10 * 1024, 100 * 1024]; // 1KB, 10KB, 100KB

    for size in sizes {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", size)),
            &size,
            |b, &size| {
                let temp_dir = TempDir::new().unwrap();
                let config = CheckpointConfig {
                    base_path: temp_dir.path().to_path_buf(),
                    max_checkpoints: 10,
                    compression_enabled: false,
                };
                let mut manager = CheckpointManager::new(config).unwrap();

                // Save a checkpoint first
                let state = TestState::new(1, size);
                manager.save_checkpoint(&state).unwrap();

                b.iter(|| {
                    let restored: TestState = manager.restore_latest().unwrap();
                    black_box(restored)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark listing checkpoints.
fn bench_list_checkpoints(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_checkpoints");

    let counts = vec![1, 10, 50];

    for count in counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_checkpoints", count)),
            &count,
            |b, &count| {
                let temp_dir = TempDir::new().unwrap();
                let config = CheckpointConfig {
                    base_path: temp_dir.path().to_path_buf(),
                    max_checkpoints: 100,
                    compression_enabled: false,
                };
                let mut manager = CheckpointManager::new(config).unwrap();

                // Create multiple checkpoints
                for i in 0..count {
                    let state = TestState::new(i as u64, 1024);
                    manager.save_checkpoint(&state).unwrap();
                }

                b.iter(|| {
                    let list = manager.list_checkpoints();
                    black_box(list)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting checkpoint count.
fn bench_checkpoint_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint_count");

    let counts = vec![0, 10, 50];

    for count in counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_checkpoints", count)),
            &count,
            |b, &count| {
                let temp_dir = TempDir::new().unwrap();
                let config = CheckpointConfig {
                    base_path: temp_dir.path().to_path_buf(),
                    max_checkpoints: 100,
                    compression_enabled: false,
                };
                let mut manager = CheckpointManager::new(config).unwrap();

                // Create checkpoints
                for i in 0..count {
                    let state = TestState::new(i as u64, 1024);
                    manager.save_checkpoint(&state).unwrap();
                }

                b.iter(|| {
                    let cnt = manager.checkpoint_count();
                    black_box(cnt)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark metadata age calculation.
fn bench_metadata_age(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_age");

    group.bench_function("age_calculation", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = CheckpointConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_checkpoints: 10,
            compression_enabled: false,
        };
        let mut manager = CheckpointManager::new(config).unwrap();

        // Create a checkpoint
        let state = TestState::new(1, 1024);
        manager.save_checkpoint(&state).unwrap();

        b.iter(|| {
            let checkpoints = manager.list_checkpoints();
            if let Some(metadata) = checkpoints.first() {
                let age = metadata.age_ms();
                black_box(age);
            }
        });
    });

    group.finish();
}

/// Benchmark checkpoint cleanup.
fn bench_cleanup_old_checkpoints(c: &mut Criterion) {
    let mut group = c.benchmark_group("cleanup_old_checkpoints");

    group.bench_function("cleanup_when_limit_exceeded", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: black_box(5),
                compression_enabled: false,
            };
            let mut manager = CheckpointManager::new(config).unwrap();

            // Create more checkpoints than the limit
            for i in 0..10 {
                let state = TestState::new(i, 1024);
                manager.save_checkpoint(&state).unwrap();
            }

            black_box(manager)
        });
    });

    group.finish();
}

/// Benchmark deleting specific checkpoints.
fn bench_delete_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("delete_checkpoint");

    group.bench_function("delete_single", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: 10,
                compression_enabled: false,
            };
            let mut manager = CheckpointManager::new(config).unwrap();

            // Create checkpoints
            for i in 0..5 {
                let state = TestState::new(i, 1024);
                manager.save_checkpoint(&state).unwrap();
            }

            // Delete one
            let _ = manager.delete_checkpoint("test_state_2");
        });
    });

    group.finish();
}

/// Benchmark default configuration.
fn bench_default_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("default_config");

    group.bench_function("create_default", |b| {
        b.iter(|| {
            let config = CheckpointConfig::default();
            black_box(config)
        });
    });

    group.finish();
}

/// Benchmark saving multiple checkpoints in sequence.
fn bench_sequential_checkpoints(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_checkpoints");

    let counts = vec![5, 10, 20];

    for count in counts {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_sequential", count)),
            &count,
            |b, &count| {
                b.iter(|| {
                    let temp_dir = TempDir::new().unwrap();
                    let config = CheckpointConfig {
                        base_path: temp_dir.path().to_path_buf(),
                        max_checkpoints: 100,
                        compression_enabled: false,
                    };
                    let mut manager = CheckpointManager::new(config).unwrap();

                    for i in 0..count {
                        let state = TestState::new(i as u64, 1024);
                        manager.save_checkpoint(&state).unwrap();
                    }

                    black_box(manager)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark realistic checkpoint scenarios.
fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    group.bench_function("periodic_checkpointing", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: 5,
                compression_enabled: false,
            };
            let mut manager = CheckpointManager::new(config).unwrap();

            // Simulate periodic checkpointing (every 10 operations)
            for i in 0..50 {
                if i % 10 == 0 {
                    let state = TestState::new(i, 10 * 1024); // 10KB state
                    manager.save_checkpoint(&state).unwrap();
                }
            }

            black_box(manager)
        });
    });

    group.bench_function("checkpoint_and_restore", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = CheckpointConfig {
                base_path: temp_dir.path().to_path_buf(),
                max_checkpoints: 5,
                compression_enabled: false,
            };
            let mut manager = CheckpointManager::new(config).unwrap();

            // Save checkpoint
            let state = TestState::new(42, 10 * 1024);
            manager.save_checkpoint(&state).unwrap();

            // Restore checkpoint
            let restored: TestState = manager.restore_latest().unwrap();

            black_box(restored)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_save_checkpoint,
    bench_restore_checkpoint,
    bench_list_checkpoints,
    bench_checkpoint_count,
    bench_metadata_age,
    bench_cleanup_old_checkpoints,
    bench_delete_checkpoint,
    bench_default_config,
    bench_sequential_checkpoints,
    bench_realistic_scenarios,
);
criterion_main!(benches);
