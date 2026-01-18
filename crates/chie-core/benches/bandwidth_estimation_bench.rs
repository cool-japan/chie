//! Benchmarks for bandwidth estimation.

use chie_core::bandwidth_estimation::{BandwidthEstimator, EstimatorConfig};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark recording transfers.
fn bench_record_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandwidth_estimation_record_transfer");

    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    for (bytes, duration_ms) in [
        (1024, 10),               // 1 KB in 10ms
        (1024 * 1024, 100),       // 1 MB in 100ms
        (10 * 1024 * 1024, 1000), // 10 MB in 1s
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes_{}ms", bytes, duration_ms)),
            &(bytes, duration_ms),
            |b, &(bytes, duration)| {
                b.iter(|| {
                    estimator.record_transfer(black_box(bytes), black_box(duration));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark bandwidth estimation.
fn bench_estimate_mbps(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add some samples
    for _ in 0..10 {
        estimator.record_transfer(1024 * 1024, 100);
    }

    c.bench_function("bandwidth_estimation_estimate_mbps", |b| {
        b.iter(|| {
            let _ = estimator.estimate_mbps();
        });
    });
}

/// Benchmark estimate_bps.
fn bench_estimate_bps(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add samples
    for _ in 0..20 {
        estimator.record_transfer(1024 * 1024, 100);
    }

    c.bench_function("bandwidth_estimation_estimate_bps", |b| {
        b.iter(|| {
            let _ = estimator.estimate_bps();
        });
    });
}

/// Benchmark is_reliable check.
fn bench_is_reliable(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add enough samples to be reliable
    for _ in 0..10 {
        estimator.record_transfer(1024 * 1024, 100);
    }

    c.bench_function("bandwidth_estimation_is_reliable", |b| {
        b.iter(|| {
            let _ = estimator.is_reliable();
        });
    });
}

/// Benchmark packet loss percentage.
fn bench_packet_loss_percent(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add samples with varying packet loss
    for i in 0..50 {
        let packet_loss = i % 10 == 0;
        estimator.record_transfer_with_rtt(1024 * 1024, 100, Some(50.0), packet_loss);
    }

    c.bench_function("bandwidth_estimation_packet_loss_percent", |b| {
        b.iter(|| {
            let _ = estimator.packet_loss_percent();
        });
    });
}

/// Benchmark RTT variation percentage.
fn bench_rtt_variation_percent(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add samples with varying RTT
    for i in 0..50 {
        estimator.record_transfer_with_rtt(1024 * 1024, 100, Some(50.0 + (i as f64 * 2.0)), false);
    }

    c.bench_function("bandwidth_estimation_rtt_variation_percent", |b| {
        b.iter(|| {
            let _ = estimator.rtt_variation_percent();
        });
    });
}

/// Benchmark recommended rate calculation.
fn bench_recommended_rate(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add samples
    for i in 0..100 {
        estimator.record_transfer(1024 * 1024, 100 + (i % 50));
    }

    c.bench_function("bandwidth_estimation_recommended_rate", |b| {
        b.iter(|| {
            let _ = estimator.recommended_rate_bps();
        });
    });
}

/// Benchmark getting statistics.
fn bench_stats(c: &mut Criterion) {
    let config = EstimatorConfig::default();
    let mut estimator = BandwidthEstimator::new(config);

    // Add history
    for i in 0..100 {
        estimator.record_transfer(1024 * 1024, 100 + i);
    }

    c.bench_function("bandwidth_estimation_stats", |b| {
        b.iter(|| {
            let _ = estimator.stats();
        });
    });
}

/// Benchmark bulk transfers (many transfers in sequence).
fn bench_bulk_transfers(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandwidth_estimation_bulk");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_transfers", count)),
            &count,
            |b, &cnt| {
                b.iter(|| {
                    let config = EstimatorConfig::default();
                    let mut estimator = BandwidthEstimator::new(config);
                    for i in 0..cnt {
                        estimator.record_transfer(1024 * 1024, 100 + (i % 50));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark with different history sizes.
fn bench_history_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandwidth_estimation_history_size");

    for max_history in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("history_{}", max_history)),
            &max_history,
            |b, &hist_size| {
                b.iter(|| {
                    let config = EstimatorConfig {
                        max_history: hist_size,
                        ..Default::default()
                    };
                    let mut estimator = BandwidthEstimator::new(config);

                    // Fill history
                    for _ in 0..hist_size {
                        estimator.record_transfer(1024 * 1024, 100);
                    }

                    // One more to trigger eviction
                    estimator.record_transfer(1024 * 1024, 100);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_record_transfer,
    bench_estimate_mbps,
    bench_estimate_bps,
    bench_is_reliable,
    bench_packet_loss_percent,
    bench_rtt_variation_percent,
    bench_recommended_rate,
    bench_stats,
    bench_bulk_transfers,
    bench_history_sizes
);
criterion_main!(benches);
