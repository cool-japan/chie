//! Benchmarks for system coordinator operations.

use chie_core::system_coordinator::{SystemConfig, SystemCoordinator};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark creating a system coordinator.
fn bench_coordinator_creation(c: &mut Criterion) {
    c.bench_function("system_coordinator/create", |b| {
        b.iter(|| {
            let config = SystemConfig::default();
            black_box(SystemCoordinator::new(config));
        });
    });
}

/// Benchmark coordinator with different configurations.
fn bench_coordinator_configs(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_coordinator/configs");

    // Default config
    group.bench_function("default", |b| {
        b.iter(|| {
            let config = SystemConfig::default();
            black_box(SystemCoordinator::new(config));
        });
    });

    // All features disabled
    group.bench_function("minimal", |b| {
        b.iter(|| {
            let config = SystemConfig {
                enable_health_checks: false,
                enable_profiling: false,
                enable_metrics: false,
                enable_alerting: false,
                enable_forecasting: false,
                ..Default::default()
            };
            black_box(SystemCoordinator::new(config));
        });
    });

    // All features enabled (default already has this)
    group.bench_function("full", |b| {
        b.iter(|| {
            let config = SystemConfig {
                enable_health_checks: true,
                enable_profiling: true,
                enable_metrics: true,
                enable_alerting: true,
                enable_forecasting: true,
                ..Default::default()
            };
            black_box(SystemCoordinator::new(config));
        });
    });

    group.finish();
}

/// Benchmark accessor method performance.
fn bench_accessor_methods(c: &mut Criterion) {
    let config = SystemConfig::default();
    let coordinator = SystemCoordinator::new(config);

    let mut group = c.benchmark_group("system_coordinator/accessors");

    group.bench_function("get_uptime_secs", |b| {
        b.iter(|| {
            black_box(coordinator.get_uptime_secs());
        });
    });

    group.bench_function("profiler", |b| {
        b.iter(|| {
            black_box(coordinator.profiler());
        });
    });

    group.bench_function("metrics", |b| {
        b.iter(|| {
            black_box(coordinator.metrics());
        });
    });

    group.bench_function("health_checker", |b| {
        b.iter(|| {
            black_box(coordinator.health_checker());
        });
    });

    group.bench_function("alerts", |b| {
        b.iter(|| {
            black_box(coordinator.alerts());
        });
    });

    group.bench_function("dashboard", |b| {
        b.iter(|| {
            black_box(coordinator.dashboard());
        });
    });

    group.finish();
}

/// Benchmark uptime calculation with different elapsed times.
fn bench_uptime_calculation(c: &mut Criterion) {
    let config = SystemConfig::default();

    let mut group = c.benchmark_group("system_coordinator/uptime");

    for _ in 0..3 {
        let coordinator = SystemCoordinator::new(config.clone());
        group.bench_function("immediate", |b| {
            b.iter(|| {
                black_box(coordinator.get_uptime_secs());
            });
        });
    }

    group.finish();
}

/// Benchmark batch accessor calls.
fn bench_batch_accessors(c: &mut Criterion) {
    let config = SystemConfig::default();
    let coordinator = SystemCoordinator::new(config);

    let mut group = c.benchmark_group("system_coordinator/batch_access");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                for _ in 0..count {
                    black_box(coordinator.get_uptime_secs());
                    black_box(coordinator.profiler());
                    black_box(coordinator.metrics());
                }
            });
        });
    }

    group.finish();
}

/// Benchmark coordinator creation with varying health check intervals.
fn bench_health_check_intervals(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_coordinator/health_intervals");

    for interval in [10, 60, 300, 3600] {
        group.bench_with_input(
            BenchmarkId::from_parameter(interval),
            &interval,
            |b, &interval| {
                b.iter(|| {
                    let config = SystemConfig {
                        health_check_interval_secs: black_box(interval),
                        ..Default::default()
                    };
                    black_box(SystemCoordinator::new(config));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark multiple coordinator instances.
fn bench_multiple_coordinators(c: &mut Criterion) {
    let mut group = c.benchmark_group("system_coordinator/multiple_instances");

    for count in [1, 5, 10, 20] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let config = SystemConfig::default();
                let coordinators: Vec<_> = (0..count)
                    .map(|_| SystemCoordinator::new(config.clone()))
                    .collect();
                black_box(coordinators);
            });
        });
    }

    group.finish();
}

/// Benchmark Arc cloning performance for shared components.
fn bench_arc_cloning(c: &mut Criterion) {
    let config = SystemConfig::default();
    let coordinator = SystemCoordinator::new(config);

    let mut group = c.benchmark_group("system_coordinator/arc_clone");

    group.bench_function("profiler_clone", |b| {
        b.iter(|| {
            black_box(coordinator.profiler());
        });
    });

    group.bench_function("metrics_clone", |b| {
        b.iter(|| {
            black_box(coordinator.metrics());
        });
    });

    group.bench_function("health_checker_clone", |b| {
        b.iter(|| {
            black_box(coordinator.health_checker());
        });
    });

    group.bench_function("alerts_clone", |b| {
        b.iter(|| {
            black_box(coordinator.alerts());
        });
    });

    group.bench_function("dashboard_clone", |b| {
        b.iter(|| {
            black_box(coordinator.dashboard());
        });
    });

    group.finish();
}

/// Benchmark coordinator with different log levels.
fn bench_log_levels(c: &mut Criterion) {
    use chie_core::logging::LogLevel;

    let mut group = c.benchmark_group("system_coordinator/log_levels");

    for level in [
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    ] {
        group.bench_function(format!("{:?}", level), |b| {
            b.iter(|| {
                let config = SystemConfig {
                    log_level: black_box(level),
                    ..Default::default()
                };
                black_box(SystemCoordinator::new(config));
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_coordinator_creation,
    bench_coordinator_configs,
    bench_accessor_methods,
    bench_uptime_calculation,
    bench_batch_accessors,
    bench_health_check_intervals,
    bench_multiple_coordinators,
    bench_arc_cloning,
    bench_log_levels,
);
criterion_main!(benches);
