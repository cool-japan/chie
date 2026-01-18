use chie_core::{calculate_chunk_count, split_into_chunks};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_split_into_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_into_chunks");

    for size in [1024, 10_240, 102_400, 1_024_000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let chunks = split_into_chunks(black_box(&data), black_box(262_144));
                black_box(chunks)
            });
        });
    }

    group.finish();
}

fn bench_calculate_chunk_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("calculate_chunk_count");

    for size in [1024, 1_048_576, 10_485_760, 104_857_600].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let count = calculate_chunk_count(black_box(size));
                black_box(count)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_split_into_chunks,
    bench_calculate_chunk_count
);
criterion_main!(benches);
