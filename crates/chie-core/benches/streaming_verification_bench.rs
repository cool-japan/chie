//! Benchmark suite for incremental streaming verification module.
//!
//! This file benchmarks the performance of streaming hash verification:
//! - StreamingVerifier creation and updates
//! - Incremental hash computation with varying chunk sizes
//! - MerkleVerifier chunk-by-chunk verification
//! - Verification progress tracking
//! - Large file verification scenarios
//!
//! Run with: cargo bench --bench streaming_verification_bench

use chie_core::streaming_verification::{MerkleVerifier, StreamingVerifier};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// ============================================================================
// Constants
// ============================================================================

const SMALL_DATA: usize = 1024; // 1 KB
const MEDIUM_DATA: usize = 262_144; // 256 KB
const LARGE_DATA: usize = 1_048_576; // 1 MB
const XLARGE_DATA: usize = 10_485_760; // 10 MB

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    use chie_crypto::hash::hash;
    hash(data)
}

// ============================================================================
// StreamingVerifier Benchmarks
// ============================================================================

fn bench_streaming_verifier_creation(c: &mut Criterion) {
    let expected_hash = [0u8; 32];

    let mut group = c.benchmark_group("streaming_verifier_creation");

    group.bench_function("new", |b| {
        b.iter(|| {
            let _verifier = black_box(StreamingVerifier::new(expected_hash));
        });
    });

    group.bench_function("with_size", |b| {
        b.iter(|| {
            let _verifier = black_box(StreamingVerifier::with_size(expected_hash, 1_000_000));
        });
    });

    group.finish();
}

fn bench_streaming_verifier_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_verifier_update");

    let expected_hash = [0u8; 32];

    for size in [SMALL_DATA, MEDIUM_DATA, LARGE_DATA] {
        let data = generate_test_data(size);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &data,
            |b, d| {
                b.iter(|| {
                    let mut verifier = StreamingVerifier::new(expected_hash);
                    verifier.update(d);
                    black_box(verifier);
                });
            },
        );
    }

    group.finish();
}

fn bench_streaming_verifier_incremental_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_verifier_incremental");

    let expected_hash = [0u8; 32];

    // Test different chunk sizes for incremental updates
    for (total_size, chunk_size) in [
        (MEDIUM_DATA, 1024),  // 256 KB in 1 KB chunks
        (MEDIUM_DATA, 4096),  // 256 KB in 4 KB chunks
        (LARGE_DATA, 4096),   // 1 MB in 4 KB chunks
        (LARGE_DATA, 16384),  // 1 MB in 16 KB chunks
        (XLARGE_DATA, 65536), // 10 MB in 64 KB chunks
    ] {
        let data = generate_test_data(total_size);

        group.bench_with_input(
            BenchmarkId::new(
                format!("total_{}KB", total_size / 1024),
                format!("chunk_{}KB", chunk_size / 1024),
            ),
            &(data, chunk_size),
            |b, (d, cs)| {
                b.iter(|| {
                    let mut verifier = StreamingVerifier::new(expected_hash);
                    for chunk in d.chunks(*cs) {
                        verifier.update(chunk);
                    }
                    black_box(verifier);
                });
            },
        );
    }

    group.finish();
}

fn bench_streaming_verifier_progress(c: &mut Criterion) {
    let expected_hash = [0u8; 32];
    let mut verifier = StreamingVerifier::with_size(expected_hash, 1_000_000);
    let data = generate_test_data(MEDIUM_DATA);
    verifier.update(&data);

    c.bench_function("streaming_verifier_progress", |b| {
        b.iter(|| {
            let _progress = black_box(verifier.progress());
        });
    });
}

fn bench_streaming_verifier_finalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_verifier_finalize");

    for size in [SMALL_DATA, MEDIUM_DATA, LARGE_DATA] {
        let data = generate_test_data(size);
        let expected_hash = compute_hash(&data);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            &(data, expected_hash),
            |b, (d, hash)| {
                b.iter(|| {
                    let mut verifier = StreamingVerifier::new(*hash);
                    verifier.update(d);
                    let _result = black_box(verifier.finalize().unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_streaming_verifier_reset(c: &mut Criterion) {
    let expected_hash = [0u8; 32];
    let mut verifier = StreamingVerifier::new(expected_hash);
    let data = generate_test_data(MEDIUM_DATA);
    verifier.update(&data);

    c.bench_function("streaming_verifier_reset", |b| {
        b.iter(|| {
            verifier.reset();
            black_box(&verifier);
        });
    });
}

// ============================================================================
// MerkleVerifier Benchmarks
// ============================================================================

fn bench_merkle_verifier_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verifier_creation");

    let expected_root = [0u8; 32];

    for total_chunks in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(total_chunks),
            &total_chunks,
            |b, &chunks| {
                b.iter(|| {
                    let _verifier = black_box(MerkleVerifier::new(expected_root, 262_144, chunks));
                });
            },
        );
    }

    group.finish();
}

fn bench_merkle_verifier_with_default_chunk_size(c: &mut Criterion) {
    let expected_root = [0u8; 32];

    c.bench_function("merkle_verifier_with_default_chunk_size", |b| {
        b.iter(|| {
            let _verifier = black_box(MerkleVerifier::with_default_chunk_size(expected_root, 100));
        });
    });
}

fn bench_merkle_verifier_verify_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verifier_verify_chunk");

    let expected_root = [0u8; 32];
    let chunk_data = generate_test_data(MEDIUM_DATA);

    for total_chunks in [10, 100, 1000] {
        let mut verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, total_chunks);

        group.bench_with_input(
            BenchmarkId::from_parameter(total_chunks),
            &chunk_data,
            |b, data| {
                b.iter(|| {
                    let _result = black_box(verifier.verify_chunk(0, data));
                });
            },
        );
    }

    group.finish();
}

fn bench_merkle_verifier_sequential_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verifier_sequential_chunks");

    let expected_root = [0u8; 32];
    let chunk_data = generate_test_data(MEDIUM_DATA);

    for num_chunks in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_chunks),
            &num_chunks,
            |b, &chunks| {
                b.iter(|| {
                    let mut verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, chunks);
                    for i in 0..chunks {
                        let _ = verifier.verify_chunk(i, &chunk_data);
                    }
                    black_box(verifier);
                });
            },
        );
    }

    group.finish();
}

fn bench_merkle_verifier_verify_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verifier_verify_merkle_root");

    let expected_root = [0u8; 32];
    let chunk_data = generate_test_data(MEDIUM_DATA);

    for num_chunks in [10, 50, 100] {
        let mut verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, num_chunks);

        // Verify all chunks first
        for i in 0..num_chunks {
            let _ = verifier.verify_chunk(i, &chunk_data);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(num_chunks),
            &num_chunks,
            |b, &_chunks| {
                b.iter(|| {
                    let _result = black_box(verifier.verify_merkle_root());
                });
            },
        );
    }

    group.finish();
}

fn bench_merkle_verifier_progress(c: &mut Criterion) {
    let expected_root = [0u8; 32];
    let verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, 100);

    c.bench_function("merkle_verifier_progress", |b| {
        b.iter(|| {
            let _progress = black_box(verifier.progress());
        });
    });
}

fn bench_merkle_verifier_chunks_verified(c: &mut Criterion) {
    let expected_root = [0u8; 32];
    let verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, 100);

    c.bench_function("merkle_verifier_chunks_verified", |b| {
        b.iter(|| {
            let _count = black_box(verifier.chunks_verified());
        });
    });
}

fn bench_merkle_verifier_is_complete(c: &mut Criterion) {
    let expected_root = [0u8; 32];
    let verifier = MerkleVerifier::new(expected_root, MEDIUM_DATA, 100);

    c.bench_function("merkle_verifier_is_complete", |b| {
        b.iter(|| {
            let _complete = black_box(verifier.is_complete());
        });
    });
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_video_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_video_verification");

    // Simulate verifying a 50 MB video in 256 KB chunks
    let chunk_size = 262_144; // 256 KB
    let total_size = 52_428_800; // 50 MB
    let num_chunks = total_size / chunk_size;

    let data = generate_test_data(chunk_size);
    let expected_hash = compute_hash(&data);

    group.bench_function("streaming_50MB_video", |b| {
        b.iter(|| {
            let mut verifier = StreamingVerifier::with_size(expected_hash, total_size as u64);
            for _ in 0..num_chunks {
                verifier.update(&data);
            }
            let _result = black_box(verifier.finalize().unwrap());
        });
    });

    group.finish();
}

fn bench_realistic_large_file_download(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_large_file_download");

    // Simulate verifying a 100 MB file in 1 MB chunks
    let chunk_size = 1_048_576; // 1 MB
    let total_size = 104_857_600; // 100 MB
    let num_chunks = total_size / chunk_size;

    let data = generate_test_data(chunk_size);
    let expected_root = [0u8; 32];

    group.bench_function("merkle_100MB_file_100_chunks", |b| {
        b.iter(|| {
            let mut verifier = MerkleVerifier::new(expected_root, chunk_size, num_chunks as u64);
            for i in 0..num_chunks {
                let _ = verifier.verify_chunk(i as u64, &data);
            }
            black_box(verifier);
        });
    });

    group.finish();
}

fn bench_realistic_progressive_download(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_progressive_download");

    // Simulate progressive download with verification
    // Small chunks arriving progressively
    let chunk_size = 4096; // 4 KB chunks
    let total_chunks = 1000; // 4 MB total
    let expected_hash = [0u8; 32];

    group.bench_function("progressive_4MB_in_4KB_chunks", |b| {
        b.iter(|| {
            let mut verifier = StreamingVerifier::new(expected_hash);
            for _ in 0..total_chunks {
                let chunk = generate_test_data(chunk_size);
                verifier.update(&chunk);
            }
            black_box(verifier);
        });
    });

    group.finish();
}

fn bench_comparison_streaming_vs_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison_streaming_vs_merkle");

    let total_size = 10_485_760; // 10 MB
    let chunk_size = 262_144; // 256 KB
    let num_chunks = total_size / chunk_size;

    let data = generate_test_data(chunk_size);
    let expected_hash = compute_hash(&data);
    let expected_root = [0u8; 32];

    group.bench_function("streaming_10MB", |b| {
        b.iter(|| {
            let mut verifier = StreamingVerifier::with_size(expected_hash, total_size as u64);
            for _ in 0..num_chunks {
                verifier.update(&data);
            }
            let _result = black_box(verifier.finalize().unwrap());
        });
    });

    group.bench_function("merkle_10MB", |b| {
        b.iter(|| {
            let mut verifier = MerkleVerifier::new(expected_root, chunk_size, num_chunks as u64);
            for i in 0..num_chunks {
                let _ = verifier.verify_chunk(i as u64, &data);
            }
            let _result = black_box(verifier.verify_merkle_root());
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    streaming_benches,
    bench_streaming_verifier_creation,
    bench_streaming_verifier_update,
    bench_streaming_verifier_incremental_update,
    bench_streaming_verifier_progress,
    bench_streaming_verifier_finalize,
    bench_streaming_verifier_reset,
);

criterion_group!(
    merkle_benches,
    bench_merkle_verifier_creation,
    bench_merkle_verifier_with_default_chunk_size,
    bench_merkle_verifier_verify_chunk,
    bench_merkle_verifier_sequential_chunks,
    bench_merkle_verifier_verify_merkle_root,
    bench_merkle_verifier_progress,
    bench_merkle_verifier_chunks_verified,
    bench_merkle_verifier_is_complete,
);

criterion_group!(
    realistic_benches,
    bench_realistic_video_verification,
    bench_realistic_large_file_download,
    bench_realistic_progressive_download,
    bench_comparison_streaming_vs_merkle,
);

criterion_main!(streaming_benches, merkle_benches, realistic_benches);
