use chie_core::compression::{CompressionAlgorithm, Compressor};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Generate test data with different characteristics
fn generate_text_data(size: usize) -> Vec<u8> {
    // Highly compressible text (repeated pattern)
    "The quick brown fox jumps over the lazy dog. "
        .repeat(size / 45)
        .into_bytes()
}

fn generate_random_data(size: usize) -> Vec<u8> {
    // Less compressible random data
    (0..size).map(|i| ((i * 13 + 7) % 256) as u8).collect()
}

fn generate_structured_data(size: usize) -> Vec<u8> {
    // JSON-like structured data (medium compressibility)
    let pattern = r#"{"id":12345,"name":"test","value":67890,"data":"x"}"#;
    pattern.repeat(size / pattern.len()).into_bytes()
}

fn bench_compress_text_data(c: &mut Criterion) {
    let sizes = [1024, 10 * 1024, 100 * 1024, 1024 * 1024];
    let mut group = c.benchmark_group("compression_text");

    for size in sizes.iter() {
        let data = generate_text_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("fast", size), size, |b, _| {
            b.iter(|| {
                let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Fast));
                compressor.compress(black_box(&data))
            });
        });

        group.bench_with_input(BenchmarkId::new("balanced", size), size, |b, _| {
            b.iter(|| {
                let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Balanced));
                compressor.compress(black_box(&data))
            });
        });

        group.bench_with_input(BenchmarkId::new("maximum", size), size, |b, _| {
            b.iter(|| {
                let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Maximum));
                compressor.compress(black_box(&data))
            });
        });
    }

    group.finish();
}

fn bench_compress_random_data(c: &mut Criterion) {
    let sizes = [1024, 10 * 1024, 100 * 1024];
    let mut group = c.benchmark_group("compression_random");

    for size in sizes.iter() {
        let data = generate_random_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("balanced", size), size, |b, _| {
            b.iter(|| {
                let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Balanced));
                compressor.compress(black_box(&data))
            });
        });
    }

    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    let sizes = [1024, 10 * 1024, 100 * 1024];
    let mut group = c.benchmark_group("decompression");

    for size in sizes.iter() {
        let data = generate_text_data(*size);
        let mut compressor = Compressor::new(CompressionAlgorithm::Balanced);
        let compressed = compressor.compress(&data).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("balanced", size),
            &compressed,
            |b, comp| {
                b.iter(|| {
                    let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Balanced));
                    compressor.decompress(black_box(comp))
                });
            },
        );
    }

    group.finish();
}

fn bench_compressor_creation(c: &mut Criterion) {
    c.bench_function("compressor_creation", |b| {
        b.iter(|| Compressor::new(black_box(CompressionAlgorithm::Balanced)));
    });
}

fn bench_compression_stats(c: &mut Criterion) {
    let data = generate_structured_data(10 * 1024);
    let mut compressor = Compressor::new(CompressionAlgorithm::Balanced);
    let _ = compressor.compress(&data);

    c.bench_function("get_stats", |b| {
        b.iter(|| black_box(compressor.stats()));
    });
}

fn bench_compression_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratio_calculation");

    let data = generate_text_data(100 * 1024);

    group.bench_function("compress_and_measure", |b| {
        b.iter(|| {
            let mut compressor = Compressor::new(black_box(CompressionAlgorithm::Balanced));
            let compressed = compressor.compress(black_box(&data)).unwrap();
            black_box(compressed.len() as f64 / data.len() as f64)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_compress_text_data,
    bench_compress_random_data,
    bench_decompress,
    bench_compressor_creation,
    bench_compression_stats,
    bench_compression_ratio
);

criterion_main!(benches);
