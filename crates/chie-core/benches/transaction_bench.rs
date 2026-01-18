//! Benchmark suite for transactional chunk operations module.
//!
//! This file benchmarks the performance of ACID-compliant transaction support:
//! - Transaction creation and management
//! - Transactional write operations
//! - Commit and rollback operations
//! - Multi-chunk atomic writes
//! - Transaction manager operations
//!
//! Run with: cargo bench --bench transaction_bench

use chie_core::storage::ChunkStorage;
use chie_core::transaction::TransactionManager;
use chie_crypto::{generate_key, generate_nonce};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_chunks(num_chunks: usize, chunk_size: usize) -> Vec<Vec<u8>> {
    (0..num_chunks)
        .map(|i| (0..chunk_size).map(|j| ((i + j) % 256) as u8).collect())
        .collect()
}

async fn setup_storage() -> ChunkStorage {
    let temp_dir = tempfile::tempdir().unwrap();
    ChunkStorage::new(temp_dir.path().to_path_buf(), 1_000_000_000)
        .await
        .unwrap()
}

// ============================================================================
// TransactionManager Benchmarks
// ============================================================================

fn bench_transaction_manager_creation(c: &mut Criterion) {
    c.bench_function("transaction_manager_creation", |b| {
        b.iter(|| {
            let _manager = black_box(TransactionManager::new());
        });
    });
}

fn bench_begin_transaction(c: &mut Criterion) {
    let mut manager = TransactionManager::new();

    c.bench_function("begin_transaction", |b| {
        b.iter(|| {
            let _tx_id = black_box(manager.begin_transaction());
        });
    });
}

fn bench_get_transaction(c: &mut Criterion) {
    let mut manager = TransactionManager::new();
    let tx_id = manager.begin_transaction();

    c.bench_function("get_transaction", |b| {
        b.iter(|| {
            let _tx = black_box(manager.get_transaction(tx_id));
        });
    });
}

fn bench_commit_transaction(c: &mut Criterion) {
    c.bench_function("commit_transaction", |b| {
        b.iter(|| {
            let mut manager = TransactionManager::new();
            let tx_id = manager.begin_transaction();
            let _result = black_box(manager.commit(tx_id));
        });
    });
}

fn bench_active_transaction_count(c: &mut Criterion) {
    let mut manager = TransactionManager::new();
    // Create 10 active transactions
    for _ in 0..10 {
        manager.begin_transaction();
    }

    c.bench_function("active_transaction_count", |b| {
        b.iter(|| {
            let _count = black_box(manager.active_transaction_count());
        });
    });
}

// ============================================================================
// Transaction State Benchmarks
// ============================================================================

fn bench_transaction_state_queries(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage = rt.block_on(setup_storage());
    let mut manager = TransactionManager::new();
    let tx_id = manager.begin_transaction();

    let mut group = c.benchmark_group("transaction_state_queries");

    group.bench_function("id", |b| {
        let tx = manager.get_transaction(tx_id).unwrap();
        b.iter(|| {
            let _id = black_box(tx.id());
        });
    });

    group.bench_function("state", |b| {
        let tx = manager.get_transaction(tx_id).unwrap();
        b.iter(|| {
            let _state = black_box(tx.state());
        });
    });

    group.bench_function("total_bytes", |b| {
        let tx = manager.get_transaction(tx_id).unwrap();
        b.iter(|| {
            let _bytes = black_box(tx.total_bytes());
        });
    });

    group.bench_function("is_active", |b| {
        let tx = manager.get_transaction(tx_id).unwrap();
        b.iter(|| {
            let _active = black_box(tx.is_active());
        });
    });

    group.finish();
    drop(storage);
}

// ============================================================================
// Transactional Write Benchmarks
// ============================================================================

fn bench_transactional_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("transactional_write");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    for num_chunks in [1, 5, 10, 20] {
        let chunks = create_test_chunks(num_chunks, 4096); // 4 KB chunks

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", num_chunks)),
            &chunks,
            |b, cks| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut storage = setup_storage().await;
                        let mut manager = TransactionManager::new();
                        let tx_id = manager.begin_transaction();

                        let cid = format!("QmTest_{}", num_chunks);

                        let _result = manager
                            .transactional_write(&mut storage, tx_id, &cid, cks, &key, &nonce)
                            .await;

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_transactional_write_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("transactional_write_commit");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    for num_chunks in [1, 5, 10] {
        let chunks = create_test_chunks(num_chunks, 4096);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", num_chunks)),
            &chunks,
            |b, cks| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut storage = setup_storage().await;
                        let mut manager = TransactionManager::new();
                        let tx_id = manager.begin_transaction();

                        let cid = format!("QmTest_{}", num_chunks);

                        let result = manager
                            .transactional_write(&mut storage, tx_id, &cid, cks, &key, &nonce)
                            .await;

                        if result.is_ok() {
                            let _commit = manager.commit(tx_id);
                        }

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_transactional_write_rollback(c: &mut Criterion) {
    let mut group = c.benchmark_group("transactional_write_rollback");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    for num_chunks in [1, 5, 10] {
        let chunks = create_test_chunks(num_chunks, 4096);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chunks", num_chunks)),
            &chunks,
            |b, cks| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut storage = setup_storage().await;
                        let mut manager = TransactionManager::new();
                        let tx_id = manager.begin_transaction();

                        let cid = format!("QmTest_{}", num_chunks);

                        let _result = manager
                            .transactional_write(&mut storage, tx_id, &cid, cks, &key, &nonce)
                            .await;

                        // Always rollback for this benchmark
                        let _rollback = manager.rollback(&mut storage, tx_id).await;

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Different Chunk Sizes
// ============================================================================

fn bench_different_chunk_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("different_chunk_sizes");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    for (name, chunk_size) in [
        ("1KB", 1024),
        ("4KB", 4096),
        ("16KB", 16384),
        ("64KB", 65536),
    ] {
        let chunks = create_test_chunks(5, chunk_size);

        group.bench_function(name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut storage = setup_storage().await;
                    let mut manager = TransactionManager::new();
                    let tx_id = manager.begin_transaction();

                    let _result = manager
                        .transactional_write(&mut storage, tx_id, "QmTest", &chunks, &key, &nonce)
                        .await;

                    black_box(manager);
                });
            });
        });
    }

    group.finish();
}

// ============================================================================
// Concurrent Transactions
// ============================================================================

fn bench_multiple_concurrent_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_transactions");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    for num_txs in [2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_transactions", num_txs)),
            &num_txs,
            |b, &num| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut storage = setup_storage().await;
                        let mut manager = TransactionManager::new();

                        let mut tx_ids = Vec::new();
                        for _ in 0..num {
                            tx_ids.push(manager.begin_transaction());
                        }

                        for (i, tx_id) in tx_ids.iter().enumerate() {
                            let chunks = create_test_chunks(2, 1024);
                            let cid = format!("QmTest_{}", i);

                            let _result = manager
                                .transactional_write(
                                    &mut storage,
                                    *tx_id,
                                    &cid,
                                    &chunks,
                                    &key,
                                    &nonce,
                                )
                                .await;
                        }

                        // Commit all transactions
                        for tx_id in tx_ids {
                            let _commit = manager.commit(tx_id);
                        }

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_file_upload(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_file_upload");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    // Simulate uploading a 1 MB file in 256 KB chunks
    let chunks = create_test_chunks(4, 262_144); // 4 x 256 KB = 1 MB

    group.bench_function("1MB_file_upload_commit", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut storage = setup_storage().await;
                let mut manager = TransactionManager::new();
                let tx_id = manager.begin_transaction();

                let result = manager
                    .transactional_write(&mut storage, tx_id, "QmFile1MB", &chunks, &key, &nonce)
                    .await;

                if result.is_ok() {
                    let _commit = manager.commit(tx_id);
                } else {
                    let _rollback = manager.rollback(&mut storage, tx_id).await;
                }

                black_box(manager);
            });
        });
    });

    group.finish();
}

fn bench_realistic_batch_upload(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_batch_upload");
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    // Simulate uploading 10 small files (each 64 KB) in separate transactions
    group.bench_function("10_files_64KB_each", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut storage = setup_storage().await;
                let mut manager = TransactionManager::new();

                for i in 0..10 {
                    let tx_id = manager.begin_transaction();
                    let chunks = create_test_chunks(1, 65536); // 64 KB
                    let cid = format!("QmFile_{}", i);

                    let result = manager
                        .transactional_write(&mut storage, tx_id, &cid, &chunks, &key, &nonce)
                        .await;

                    if result.is_ok() {
                        let _commit = manager.commit(tx_id);
                    } else {
                        let _rollback = manager.rollback(&mut storage, tx_id).await;
                    }
                }

                black_box(manager);
            });
        });
    });

    group.finish();
}

fn bench_realistic_failure_recovery(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let key = generate_key();
    let nonce = generate_nonce();

    c.bench_function("failure_recovery_rollback", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut storage = setup_storage().await;
                let mut manager = TransactionManager::new();

                // Start transaction
                let tx_id = manager.begin_transaction();

                // Write some chunks
                let chunks = create_test_chunks(5, 4096);
                let _result = manager
                    .transactional_write(&mut storage, tx_id, "QmFailed", &chunks, &key, &nonce)
                    .await;

                // Simulate failure and rollback
                let _rollback = manager.rollback(&mut storage, tx_id).await;

                black_box(manager);
            });
        });
    });
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    manager_benches,
    bench_transaction_manager_creation,
    bench_begin_transaction,
    bench_get_transaction,
    bench_commit_transaction,
    bench_active_transaction_count,
    bench_transaction_state_queries,
);

criterion_group!(
    write_benches,
    bench_transactional_write,
    bench_transactional_write_commit,
    bench_transactional_write_rollback,
    bench_different_chunk_sizes,
);

criterion_group!(concurrent_benches, bench_multiple_concurrent_transactions,);

criterion_group!(
    realistic_benches,
    bench_realistic_file_upload,
    bench_realistic_batch_upload,
    bench_realistic_failure_recovery,
);

criterion_main!(
    manager_benches,
    write_benches,
    concurrent_benches,
    realistic_benches,
);
