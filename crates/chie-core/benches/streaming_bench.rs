use chie_core::streaming::{ChunkWriter, ContentStream, StreamConfig};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::Cursor;
use tokio::runtime::Runtime;

/// Create a runtime for async benchmarks
fn create_runtime() -> Runtime {
    Runtime::new().unwrap()
}

/// Generate test data
fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_stream_creation(c: &mut Criterion) {
    let rt = create_runtime();
    let sizes = [1024, 10 * 1024, 100 * 1024, 1024 * 1024];
    let mut group = c.benchmark_group("stream_creation");

    for size in sizes.iter() {
        let data = generate_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let cursor = Cursor::new(data.clone());
                let config = StreamConfig::default();
                rt.block_on(async {
                    ContentStream::new(black_box(cursor), black_box(config), Some(*size as u64))
                })
            });
        });
    }

    group.finish();
}

fn bench_chunk_reading(c: &mut Criterion) {
    let rt = create_runtime();
    let chunk_sizes = [256, 1024, 4096, 16 * 1024];
    let mut group = c.benchmark_group("chunk_reading");

    for chunk_size in chunk_sizes.iter() {
        let data = generate_data(100 * 1024);

        group.throughput(Throughput::Bytes(100 * 1024));

        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            chunk_size,
            |b, _| {
                b.iter(|| {
                    let cursor = Cursor::new(data.clone());
                    rt.block_on(async {
                        let config =
                            StreamConfig::default().with_chunk_size(black_box(*chunk_size));
                        let mut stream =
                            ContentStream::new(cursor, config, Some(data.len() as u64)).unwrap();

                        while let Ok(Some(_chunk)) = stream.next_chunk().await {
                            // Process chunk
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_read_to_vec(c: &mut Criterion) {
    let rt = create_runtime();
    let sizes = [1024, 10 * 1024, 100 * 1024];
    let mut group = c.benchmark_group("read_to_vec");

    for size in sizes.iter() {
        let data = generate_data(*size);

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let cursor = Cursor::new(data.clone());
                rt.block_on(async {
                    let config = StreamConfig::default();
                    let mut stream =
                        ContentStream::new(cursor, config, Some(*size as u64)).unwrap();
                    stream.read_to_vec().await
                })
            });
        });
    }

    group.finish();
}

fn bench_chunk_writing(c: &mut Criterion) {
    let rt = create_runtime();
    let chunk_sizes = [256, 1024, 4096, 16 * 1024];
    let mut group = c.benchmark_group("chunk_writing");

    for chunk_size in chunk_sizes.iter() {
        let data = generate_data(*chunk_size);

        group.throughput(Throughput::Bytes(*chunk_size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(chunk_size), &data, |b, data| {
            b.iter(|| {
                rt.block_on(async {
                    let mut buffer = Vec::new();
                    let mut writer = ChunkWriter::new(&mut buffer);
                    writer.write_chunk(black_box(data)).await
                })
            });
        });
    }

    group.finish();
}

fn bench_bandwidth_calculation(c: &mut Criterion) {
    let rt = create_runtime();
    let data = generate_data(100 * 1024);

    c.bench_function("bandwidth_tracking", |b| {
        b.iter(|| {
            let cursor = Cursor::new(data.clone());
            rt.block_on(async {
                let config = StreamConfig::default();
                let mut stream =
                    ContentStream::new(cursor, config, Some(data.len() as u64)).unwrap();

                while let Ok(Some(_chunk)) = stream.next_chunk().await {
                    black_box(stream.bandwidth_bps());
                    black_box(stream.bandwidth_mbps());
                }
            })
        });
    });
}

fn bench_progress_tracking(c: &mut Criterion) {
    let rt = create_runtime();
    let data = generate_data(100 * 1024);

    c.bench_function("progress_calculation", |b| {
        b.iter(|| {
            let cursor = Cursor::new(data.clone());
            rt.block_on(async {
                let config = StreamConfig::default();
                let mut stream =
                    ContentStream::new(cursor, config, Some(data.len() as u64)).unwrap();

                while let Ok(Some(_chunk)) = stream.next_chunk().await {
                    black_box(stream.progress());
                    black_box(stream.bytes_read());
                    black_box(stream.time_remaining_secs());
                }
            })
        });
    });
}

fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("config_creation", |b| {
        b.iter(|| {
            StreamConfig::default()
                .with_chunk_size(black_box(4096))
                .with_bandwidth_tracking(black_box(true))
                .with_max_retries(black_box(3))
        });
    });
}

criterion_group!(
    benches,
    bench_stream_creation,
    bench_chunk_reading,
    bench_read_to_vec,
    bench_chunk_writing,
    bench_bandwidth_calculation,
    bench_progress_tracking,
    bench_config_creation
);

criterion_main!(benches);
