//! Benchmarks for content integrity verification.

use chie_core::integrity::{ContentVerifier, ManifestBuilder, verify_single_chunk};
use chie_crypto::hash;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_verify_single_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_single_chunk");

    for size in [1024, 4096, 16384, 65536] {
        let data = vec![0u8; size];
        let expected_hash = hash(&data);

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(verify_single_chunk(&data, &expected_hash));
            });
        });
    }

    group.finish();
}

fn bench_manifest_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("manifest_builder");

    for chunk_count in [10, 50, 100, 500] {
        let chunks: Vec<Vec<u8>> = (0..chunk_count).map(|_| vec![0u8; 4096]).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_count),
            &chunk_count,
            |b, _| {
                b.iter(|| {
                    let mut builder = ManifestBuilder::new(4096);
                    for chunk in &chunks {
                        builder.add_chunk(chunk);
                    }
                    black_box(builder.build());
                });
            },
        );
    }

    group.finish();
}

fn bench_content_verifier_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_verifier");

    for chunk_count in [10, 50, 100] {
        let chunks: Vec<Vec<u8>> = (0..chunk_count).map(|_| vec![0u8; 4096]).collect();

        let mut builder = ManifestBuilder::new(4096);
        for chunk in &chunks {
            builder.add_chunk(chunk);
        }
        let manifest = builder.build();

        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_count),
            &chunk_count,
            |b, _| {
                b.iter(|| {
                    let mut verifier = ContentVerifier::new(manifest.clone());
                    for (i, chunk) in chunks.iter().enumerate() {
                        let _ = black_box(verifier.verify_chunk(i, chunk));
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_verify_single_chunk,
    bench_manifest_builder,
    bench_content_verifier_verify
);
criterion_main!(benches);
