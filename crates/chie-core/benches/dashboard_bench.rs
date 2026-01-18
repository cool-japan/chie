//! Benchmarks for performance dashboard.

use chie_core::dashboard::DashboardData;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark updating storage metrics.
fn bench_update_storage(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_storage", |b| {
        b.iter(|| {
            dashboard.update_storage(black_box(1024 * 1024 * 500), black_box(1024 * 1024 * 1024));
        });
    });
}

/// Benchmark updating bandwidth metrics.
fn bench_update_bandwidth(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_bandwidth", |b| {
        b.iter(|| {
            dashboard.update_bandwidth(black_box(500 * 1024), black_box(250 * 1024));
        });
    });
}

/// Benchmark updating latency metrics.
fn bench_update_latency(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_latency", |b| {
        b.iter(|| {
            dashboard.update_latency(black_box(50), black_box(120));
        });
    });
}

/// Benchmark updating connection count.
fn bench_update_connections(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_connections", |b| {
        b.iter(|| {
            dashboard.update_connections(black_box(42));
        });
    });
}

/// Benchmark updating requests.
fn bench_update_requests(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_requests", |b| {
        b.iter(|| {
            dashboard.update_requests(black_box(1000));
        });
    });
}

/// Benchmark updating cache metrics.
fn bench_update_cache(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_cache", |b| {
        b.iter(|| {
            dashboard.update_cache(black_box(0.85));
        });
    });
}

/// Benchmark updating errors.
fn bench_update_errors(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_errors", |b| {
        b.iter(|| {
            dashboard.update_errors(black_box(5));
        });
    });
}

/// Benchmark updating alerts.
fn bench_update_alerts(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    c.bench_function("dashboard_update_alerts", |b| {
        b.iter(|| {
            dashboard.update_alerts(black_box(3));
        });
    });
}

/// Benchmark getting snapshot.
fn bench_snapshot(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    // Add some data
    dashboard.update_storage(500 * 1024 * 1024, 1024 * 1024 * 1024);
    dashboard.update_bandwidth(500 * 1024, 250 * 1024);
    dashboard.update_latency(50, 120);
    dashboard.update_connections(25);
    dashboard.update_requests(1000);
    dashboard.update_cache(0.85);
    dashboard.update_errors(5);
    dashboard.update_alerts(2);

    c.bench_function("dashboard_snapshot", |b| {
        b.iter(|| {
            let _ = dashboard.snapshot();
        });
    });
}

/// Benchmark getting storage trend.
fn bench_storage_trend(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    // Add historical data
    for i in 0..100 {
        dashboard.update_storage(i * 1024 * 1024, 1024 * 1024 * 1024);
    }

    c.bench_function("dashboard_storage_trend", |b| {
        b.iter(|| {
            let _ = dashboard.storage_trend();
        });
    });
}

/// Benchmark getting latency trend.
fn bench_latency_trend(c: &mut Criterion) {
    let mut dashboard = DashboardData::new();

    // Add historical data
    for i in 0..100 {
        dashboard.update_latency((50 + i % 100) as u64, (120 + i % 150) as u64);
    }

    c.bench_function("dashboard_latency_trend", |b| {
        b.iter(|| {
            let _ = dashboard.latency_trend();
        });
    });
}

/// Benchmark bulk updates.
fn bench_bulk_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_bulk_updates");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_updates", count)),
            &count,
            |b, &cnt| {
                b.iter(|| {
                    let mut dashboard = DashboardData::new();

                    for i in 0..cnt {
                        dashboard.update_storage((i * 1024 * 1024) as u64, 10 * 1024 * 1024 * 1024);
                        dashboard.update_bandwidth((i * 1024) as u64, (i * 512) as u64);
                        dashboard.update_latency((50 + i % 100) as u64, (120 + i % 150) as u64);
                        dashboard.update_requests((i * 10) as u64);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark trend analysis operations.
fn bench_trend_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_trends");

    let mut dashboard = DashboardData::new();

    // Add comprehensive historical data
    for i in 0..100 {
        dashboard.update_storage((i * 1024 * 1024) as u64, 10 * 1024 * 1024 * 1024);
        dashboard.update_bandwidth((i * 1024) as u64, (i * 512) as u64);
        dashboard.update_latency((50 + i % 100) as u64, (120 + i % 150) as u64);
        dashboard.update_requests((i * 10) as u64);
        dashboard.update_errors((i % 10) as u64);
    }

    group.bench_function("all_trends", |b| {
        b.iter(|| {
            let _ = dashboard.storage_trend();
            let _ = dashboard.bandwidth_upload_trend();
            let _ = dashboard.bandwidth_download_trend();
            let _ = dashboard.latency_trend();
            let _ = dashboard.error_trend();
        });
    });

    group.finish();
}

/// Benchmark snapshot with varying data.
fn bench_snapshot_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("dashboard_snapshot_sizes");

    for data_points in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_points", data_points)),
            &data_points,
            |b, &points| {
                let mut dashboard = DashboardData::new();

                // Add historical data
                for i in 0..points {
                    dashboard.update_storage((i * 1024 * 1024) as u64, 10 * 1024 * 1024 * 1024);
                    dashboard.update_latency((50 + i % 100) as u64, (120 + i % 150) as u64);
                }

                b.iter(|| {
                    let _ = dashboard.snapshot();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_update_storage,
    bench_update_bandwidth,
    bench_update_latency,
    bench_update_connections,
    bench_update_requests,
    bench_update_cache,
    bench_update_errors,
    bench_update_alerts,
    bench_snapshot,
    bench_storage_trend,
    bench_latency_trend,
    bench_bulk_updates,
    bench_trend_analysis,
    bench_snapshot_sizes
);
criterion_main!(benches);
