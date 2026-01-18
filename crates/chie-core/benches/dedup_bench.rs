use chie_core::dedup::{DedupConfig, DedupStore, StoreResult};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempfile::TempDir;
use tokio::runtime::Runtime;

fn bench_store_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("dedup_store_new", |b| {
        b.iter(|| {
            let temp_dir = TempDir::new().unwrap();
            let config = DedupConfig::default();
            rt.block_on(async {
                black_box(
                    DedupStore::new(black_box(temp_dir.path().to_path_buf()), black_box(config))
                        .await
                        .unwrap(),
                )
            })
        })
    });
}

fn bench_store_chunk_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_chunk_new");
    let rt = Runtime::new().unwrap();

    for size in &[1024, 10240, 102_400] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &chunk_size| {
            let temp_dir = TempDir::new().unwrap();
            let config = DedupConfig::default();
            let store = rt.block_on(async {
                DedupStore::new(temp_dir.path().to_path_buf(), config)
                    .await
                    .unwrap()
            });
            let data = vec![0u8; chunk_size];
            let mut counter = 0u64;

            b.iter(|| {
                let cid = format!("cid_{}", counter);
                let chunk_index = counter;
                counter += 1;
                rt.block_on(async {
                    black_box(
                        store
                            .store_chunk(black_box(&cid), black_box(chunk_index), black_box(&data))
                            .await
                            .unwrap(),
                    )
                })
            })
        });
    }

    group.finish();
}

fn bench_store_chunk_duplicate(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_chunk_duplicate");
    let rt = Runtime::new().unwrap();

    for size in &[1024, 10240, 102_400] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &chunk_size| {
            let temp_dir = TempDir::new().unwrap();
            let config = DedupConfig::default();
            let store = rt.block_on(async {
                DedupStore::new(temp_dir.path().to_path_buf(), config)
                    .await
                    .unwrap()
            });
            let data = vec![0u8; chunk_size];
            let cid = "duplicate_cid";

            // Store once to get hash
            rt.block_on(async { store.store_chunk(cid, 0, &data).await.unwrap() });

            let mut counter = 1u64;

            b.iter(|| {
                let chunk_index = counter;
                counter += 1;
                rt.block_on(async {
                    black_box(
                        store
                            .store_chunk(black_box(cid), black_box(chunk_index), black_box(&data))
                            .await
                            .unwrap(),
                    )
                })
            })
        });
    }

    group.finish();
}

fn bench_get_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_chunk");
    let rt = Runtime::new().unwrap();

    for size in &[1024, 10240, 102_400] {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &chunk_size| {
            let temp_dir = TempDir::new().unwrap();
            let config = DedupConfig::default();
            let store = rt.block_on(async {
                DedupStore::new(temp_dir.path().to_path_buf(), config)
                    .await
                    .unwrap()
            });
            let data = vec![0u8; chunk_size];
            let cid = "test_cid";

            // Store chunk first to get hash
            let hash = rt.block_on(async {
                match store.store_chunk(cid, 0, &data).await.unwrap() {
                    StoreResult::Stored { hash, .. } => hash,
                    StoreResult::Deduplicated { hash, .. } => hash,
                }
            });

            b.iter(|| {
                rt.block_on(async { black_box(store.get_chunk(black_box(&hash)).await.unwrap()) })
            })
        });
    }

    group.finish();
}

fn bench_get_content_chunk(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 10240];
    let cid = "test_cid";

    // Store several chunks
    rt.block_on(async {
        for i in 0..10 {
            store.store_chunk(cid, i, &data).await.unwrap();
        }
    });

    c.bench_function("get_content_chunk", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    store
                        .get_content_chunk(black_box(cid), black_box(5))
                        .await
                        .unwrap(),
                )
            })
        })
    });
}

fn bench_contains(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 1024];

    // Store some chunks
    let hashes: Vec<_> = rt.block_on(async {
        let mut h = Vec::new();
        for i in 0..100 {
            let cid = format!("cid_{}", i);
            let result = store.store_chunk(&cid, 0, &data).await.unwrap();
            let hash = match result {
                StoreResult::Stored { hash, .. } => hash,
                StoreResult::Deduplicated { hash, .. } => hash,
            };
            h.push(hash);
        }
        h
    });

    c.bench_function("contains", |b| {
        b.iter(|| rt.block_on(async { black_box(store.contains(black_box(&hashes[50])).await) }))
    });
}

fn bench_ref_count(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 1024];
    let cid = "test_cid";

    // Store chunk multiple times
    let hash = rt.block_on(async {
        let mut h = [0u8; 32];
        for i in 0..10 {
            let result = store.store_chunk(cid, i, &data).await.unwrap();
            h = match result {
                StoreResult::Stored { hash, .. } => hash,
                StoreResult::Deduplicated { hash, .. } => hash,
            };
        }
        h
    });

    c.bench_function("ref_count", |b| {
        b.iter(|| rt.block_on(async { black_box(store.ref_count(black_box(&hash)).await) }))
    });
}

fn bench_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 1024];

    // Store some chunks with duplicates
    rt.block_on(async {
        for i in 0..50 {
            let cid = format!("cid_{}", i % 10);
            store.store_chunk(&cid, i, &data).await.unwrap();
        }
    });

    c.bench_function("stats", |b| {
        b.iter(|| rt.block_on(async { black_box(store.stats().await) }))
    });
}

fn bench_list_content(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 1024];

    // Store many chunks
    rt.block_on(async {
        for i in 0..100 {
            let cid = format!("cid_{}", i);
            store.store_chunk(&cid, 0, &data).await.unwrap();
        }
    });

    c.bench_function("list_content", |b| {
        b.iter(|| rt.block_on(async { black_box(store.list_content().await) }))
    });
}

fn bench_content_info(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let config = DedupConfig::default();
    let store = rt.block_on(async {
        DedupStore::new(temp_dir.path().to_path_buf(), config)
            .await
            .unwrap()
    });
    let data = vec![0u8; 1024];
    let cid = "test_cid";

    // Store several chunks for this content
    rt.block_on(async {
        for i in 0..10 {
            store.store_chunk(cid, i, &data).await.unwrap();
        }
    });

    c.bench_function("content_info", |b| {
        b.iter(|| rt.block_on(async { black_box(store.content_info(black_box(cid)).await) }))
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("mixed_operations", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = DedupConfig::default();
        let store = rt.block_on(async {
            DedupStore::new(temp_dir.path().to_path_buf(), config)
                .await
                .unwrap()
        });
        let data = vec![0u8; 1024];
        let mut counter = 0u64;

        b.iter(|| {
            let cid = format!("cid_{}", counter % 20);
            let chunk_index = counter;
            counter += 1;

            rt.block_on(async {
                // Store chunk
                let result = store.store_chunk(&cid, chunk_index, &data).await.unwrap();
                let hash = match result {
                    StoreResult::Stored { hash, .. } => hash,
                    StoreResult::Deduplicated { hash, .. } => hash,
                };

                // Occasionally retrieve
                if counter % 5 == 0 {
                    let _ = store.get_chunk(&hash).await;
                }

                // Occasionally check ref count
                if counter % 7 == 0 {
                    let _ = store.ref_count(&hash).await;
                }

                // Occasionally check stats
                if counter % 10 == 0 {
                    let _ = store.stats().await;
                }

                black_box(())
            })
        })
    });
}

criterion_group!(
    benches,
    bench_store_creation,
    bench_store_chunk_new,
    bench_store_chunk_duplicate,
    bench_get_chunk,
    bench_get_content_chunk,
    bench_contains,
    bench_ref_count,
    bench_stats,
    bench_list_content,
    bench_content_info,
    bench_mixed_operations,
);
criterion_main!(benches);
