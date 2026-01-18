use chie_core::{
    bytes_to_human_readable, calculate_bandwidth_mbps, calculate_percentage,
    chunk_size_with_overhead, current_timestamp_ms, is_valid_peer_id,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_bytes_to_human_readable(c: &mut Criterion) {
    c.bench_function("bytes_to_human_readable", |b| {
        b.iter(|| {
            let result = bytes_to_human_readable(black_box(1_234_567_890));
            black_box(result)
        });
    });
}

fn bench_calculate_bandwidth_mbps(c: &mut Criterion) {
    c.bench_function("calculate_bandwidth_mbps", |b| {
        b.iter(|| {
            let result =
                calculate_bandwidth_mbps(black_box(1_048_576), black_box(Duration::from_secs(1)));
            black_box(result)
        });
    });
}

fn bench_calculate_percentage(c: &mut Criterion) {
    c.bench_function("calculate_percentage", |b| {
        b.iter(|| {
            let result = calculate_percentage(black_box(50), black_box(100));
            black_box(result)
        });
    });
}

fn bench_current_timestamp_ms(c: &mut Criterion) {
    c.bench_function("current_timestamp_ms", |b| {
        b.iter(|| {
            let result = current_timestamp_ms();
            black_box(result)
        });
    });
}

fn bench_is_valid_peer_id(c: &mut Criterion) {
    c.bench_function("is_valid_peer_id", |b| {
        b.iter(|| {
            let result = is_valid_peer_id(black_box("peer-abc123"));
            black_box(result)
        });
    });
}

fn bench_chunk_size_with_overhead(c: &mut Criterion) {
    c.bench_function("chunk_size_with_overhead", |b| {
        b.iter(|| {
            let result = chunk_size_with_overhead(black_box(262_144));
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_bytes_to_human_readable,
    bench_calculate_bandwidth_mbps,
    bench_calculate_percentage,
    bench_current_timestamp_ms,
    bench_is_valid_peer_id,
    bench_chunk_size_with_overhead
);
criterion_main!(benches);
