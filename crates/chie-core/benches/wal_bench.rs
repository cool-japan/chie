//! Benchmark suite for Write-Ahead Logging (WAL) module.
//!
//! This file benchmarks the performance of WAL operations for crash recovery:
//! - LogEntry creation
//! - WAL append operations
//! - Log operation recording
//! - Replay operations
//! - Truncation and checkpointing
//! - Batch operations
//!
//! Run with: cargo bench --bench wal_bench

use chie_core::wal::{LogEntry, Operation, WriteAheadLog};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

async fn create_temp_wal() -> WriteAheadLog {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_path = temp_dir.path().join("wal.log");
    WriteAheadLog::new(log_path).await.unwrap()
}

fn create_write_chunk_operation(size: usize) -> Operation {
    Operation::WriteChunk {
        cid: "QmTest".to_string(),
        chunk_index: 0,
        data: vec![0u8; size],
    }
}

fn create_delete_chunk_operation() -> Operation {
    Operation::DeleteChunk {
        cid: "QmTest".to_string(),
        chunk_index: 0,
    }
}

fn create_pin_operation() -> Operation {
    Operation::PinContent {
        cid: "QmTest".to_string(),
        chunk_count: 10,
    }
}

fn create_checkpoint_operation(sequence: u64) -> Operation {
    Operation::Checkpoint { sequence }
}

// ============================================================================
// LogEntry Benchmarks
// ============================================================================

fn bench_log_entry_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_entry_creation");

    group.bench_function("write_chunk_1KB", |b| {
        let op = create_write_chunk_operation(1024);
        b.iter(|| {
            let _entry = black_box(LogEntry::new(1, op.clone()));
        });
    });

    group.bench_function("write_chunk_64KB", |b| {
        let op = create_write_chunk_operation(65536);
        b.iter(|| {
            let _entry = black_box(LogEntry::new(1, op.clone()));
        });
    });

    group.bench_function("delete_chunk", |b| {
        let op = create_delete_chunk_operation();
        b.iter(|| {
            let _entry = black_box(LogEntry::new(1, op.clone()));
        });
    });

    group.bench_function("pin_content", |b| {
        let op = create_pin_operation();
        b.iter(|| {
            let _entry = black_box(LogEntry::new(1, op.clone()));
        });
    });

    group.bench_function("checkpoint", |b| {
        let op = create_checkpoint_operation(100);
        b.iter(|| {
            let _entry = black_box(LogEntry::new(1, op.clone()));
        });
    });

    group.finish();
}

// ============================================================================
// WAL Creation and Append Benchmarks
// ============================================================================

fn bench_wal_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("wal_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _wal = black_box(create_temp_wal().await);
            });
        });
    });
}

fn bench_append_entry(c: &mut Criterion) {
    let mut group = c.benchmark_group("append_entry");
    let rt = Runtime::new().unwrap();

    for size in [1024, 4096, 16384, 65536] {
        let size_kb = size / 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size,
            |b, &s| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;
                        let op = create_write_chunk_operation(s);
                        let entry = LogEntry::new(1, op);
                        wal.append(&entry).await.unwrap();
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_log_operation(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_operation");
    let rt = Runtime::new().unwrap();

    for size in [1024, 4096, 16384] {
        let size_kb = size / 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size,
            |b, &s| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;
                        let op = create_write_chunk_operation(s);
                        let _seq = wal.log_operation(op).await.unwrap();
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Batch Append Benchmarks
// ============================================================================

fn bench_batch_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_append");
    let rt = Runtime::new().unwrap();

    for num_entries in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_entries),
            &num_entries,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;
                        for i in 0..n {
                            let op = Operation::WriteChunk {
                                cid: format!("Qm{}", i),
                                chunk_index: 0,
                                data: vec![0u8; 1024],
                            };
                            let entry = LogEntry::new(i as u64, op);
                            wal.append(&entry).await.unwrap();
                        }
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_log_operation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_log_operation");
    let rt = Runtime::new().unwrap();

    for num_ops in [10, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(num_ops), &num_ops, |b, &n| {
            b.iter(|| {
                rt.block_on(async {
                    let mut wal = create_temp_wal().await;
                    for i in 0..n {
                        let op = Operation::WriteChunk {
                            cid: format!("Qm{}", i),
                            chunk_index: 0,
                            data: vec![0u8; 1024],
                        };
                        wal.log_operation(op).await.unwrap();
                    }
                    black_box(wal);
                });
            });
        });
    }

    group.finish();
}

// ============================================================================
// Replay Benchmarks
// ============================================================================

fn bench_replay(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay");
    let rt = Runtime::new().unwrap();

    for num_entries in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_entries),
            &num_entries,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;

                        // Populate WAL
                        for _i in 0..n {
                            let op = create_write_chunk_operation(1024);
                            wal.log_operation(op).await.unwrap();
                        }

                        // Benchmark replay
                        let _entries = black_box(wal.replay().await.unwrap());
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Truncate Benchmarks
// ============================================================================

fn bench_truncate(c: &mut Criterion) {
    let mut group = c.benchmark_group("truncate");
    let rt = Runtime::new().unwrap();

    for (total, keep) in [(100, 50), (500, 250), (1000, 500)] {
        group.bench_with_input(
            BenchmarkId::new(format!("total_{}", total), format!("keep_{}", keep)),
            &(total, keep),
            |b, &(t, k)| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;

                        // Populate WAL
                        for _i in 0..t {
                            let op = create_write_chunk_operation(512);
                            wal.log_operation(op).await.unwrap();
                        }

                        // Truncate
                        wal.truncate(k).await.unwrap();
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Checkpoint Benchmarks
// ============================================================================

fn bench_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint");
    let rt = Runtime::new().unwrap();

    for num_entries in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_entries),
            &num_entries,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;

                        // Populate WAL
                        for _ in 0..n {
                            let op = create_write_chunk_operation(1024);
                            wal.log_operation(op).await.unwrap();
                        }

                        // Checkpoint
                        let _seq = black_box(wal.checkpoint().await.unwrap());
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_entries_since_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("entries_since_checkpoint");
    let rt = Runtime::new().unwrap();

    for (before, after) in [(50, 50), (100, 100), (200, 200)] {
        group.bench_with_input(
            BenchmarkId::new(format!("before_{}", before), format!("after_{}", after)),
            &(before, after),
            |b, &(bef, aft)| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut wal = create_temp_wal().await;

                        // Populate before checkpoint
                        for _ in 0..bef {
                            let op = create_write_chunk_operation(512);
                            wal.log_operation(op).await.unwrap();
                        }

                        // Checkpoint
                        wal.checkpoint().await.unwrap();

                        // Populate after checkpoint
                        for _ in 0..aft {
                            let op = create_write_chunk_operation(512);
                            wal.log_operation(op).await.unwrap();
                        }

                        // Get entries since checkpoint
                        let _entries = black_box(wal.entries_since_checkpoint().await.unwrap());
                        black_box(wal);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_clear(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("clear", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut wal = create_temp_wal().await;

                // Populate WAL
                for _ in 0..100 {
                    let op = create_write_chunk_operation(1024);
                    wal.log_operation(op).await.unwrap();
                }

                // Clear
                wal.clear().await.unwrap();
                black_box(wal);
            });
        });
    });
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_transaction_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_transaction_logging");
    let rt = Runtime::new().unwrap();

    // Simulate logging a transaction with 10 chunk writes
    group.bench_function("transaction_10_chunks", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut wal = create_temp_wal().await;

                // Log 10 chunk writes
                for i in 0..10 {
                    let op = Operation::WriteChunk {
                        cid: "QmTransaction".to_string(),
                        chunk_index: i,
                        data: vec![0u8; 4096],
                    };
                    wal.log_operation(op).await.unwrap();
                }

                // Log checkpoint at end
                wal.checkpoint().await.unwrap();

                black_box(wal);
            });
        });
    });

    group.finish();
}

fn bench_realistic_crash_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_crash_recovery");
    let rt = Runtime::new().unwrap();

    // Simulate crash recovery: log operations, then replay
    group.bench_function("recovery_100_ops", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut wal = create_temp_wal().await;

                // Log 100 operations before "crash"
                for i in 0..100 {
                    let op = Operation::WriteChunk {
                        cid: format!("Qm{}", i),
                        chunk_index: 0,
                        data: vec![0u8; 2048],
                    };
                    wal.log_operation(op).await.unwrap();
                }

                // Simulate crash recovery by replaying
                let _entries = wal.replay().await.unwrap();

                black_box(wal);
            });
        });
    });

    group.finish();
}

fn bench_realistic_periodic_checkpoint(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Simulate periodic checkpointing: write 50 ops, checkpoint, truncate, repeat
    c.bench_function("periodic_checkpoint_pattern", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut wal = create_temp_wal().await;

                // 3 cycles of: 50 ops -> checkpoint -> truncate
                for cycle in 0..3 {
                    // Log 50 operations
                    for i in 0..50 {
                        let op = Operation::WriteChunk {
                            cid: format!("Qm{}_{}", cycle, i),
                            chunk_index: 0,
                            data: vec![0u8; 1024],
                        };
                        wal.log_operation(op).await.unwrap();
                    }

                    // Checkpoint
                    let seq = wal.checkpoint().await.unwrap();

                    // Truncate old entries
                    wal.truncate(seq).await.unwrap();
                }

                black_box(wal);
            });
        });
    });
}

fn bench_realistic_mixed_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Mix of different operation types
    c.bench_function("mixed_operations_50", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut wal = create_temp_wal().await;

                for i in 0..50 {
                    let op = match i % 5 {
                        0 => Operation::WriteChunk {
                            cid: format!("Qm{}", i),
                            chunk_index: 0,
                            data: vec![0u8; 2048],
                        },
                        1 => Operation::DeleteChunk {
                            cid: format!("Qm{}", i),
                            chunk_index: 0,
                        },
                        2 => Operation::PinContent {
                            cid: format!("Qm{}", i),
                            chunk_count: 5,
                        },
                        3 => Operation::UnpinContent {
                            cid: format!("Qm{}", i),
                        },
                        _ => Operation::UpdateMetadata {
                            cid: format!("Qm{}", i),
                            metadata: vec![0u8; 256],
                        },
                    };
                    wal.log_operation(op).await.unwrap();
                }

                black_box(wal);
            });
        });
    });
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(entry_benches, bench_log_entry_creation,);

criterion_group!(
    basic_benches,
    bench_wal_creation,
    bench_append_entry,
    bench_log_operation,
);

criterion_group!(batch_benches, bench_batch_append, bench_batch_log_operation,);

criterion_group!(
    recovery_benches,
    bench_replay,
    bench_truncate,
    bench_checkpoint,
    bench_entries_since_checkpoint,
    bench_clear,
);

criterion_group!(
    realistic_benches,
    bench_realistic_transaction_logging,
    bench_realistic_crash_recovery,
    bench_realistic_periodic_checkpoint,
    bench_realistic_mixed_operations,
);

criterion_main!(
    entry_benches,
    basic_benches,
    batch_benches,
    recovery_benches,
    realistic_benches,
);
