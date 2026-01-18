//! Benchmarks for alerting system operations.

use chie_core::alerting::{Alert, AlertManager, AlertMetric, AlertSeverity, ThresholdConfig};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark creating an alert manager.
fn bench_alert_manager_creation(c: &mut Criterion) {
    c.bench_function("alerting/create_manager", |b| {
        b.iter(|| {
            black_box(AlertManager::new());
        });
    });
}

/// Benchmark alert metric name lookup.
fn bench_metric_name(c: &mut Criterion) {
    let metrics = vec![
        AlertMetric::StorageUsagePercent,
        AlertMetric::BandwidthUsageBps,
        AlertMetric::CpuUsagePercent,
        AlertMetric::MemoryUsagePercent,
        AlertMetric::ErrorRate,
        AlertMetric::LatencyMs,
        AlertMetric::FailedVerifications,
        AlertMetric::PeerReputation,
        AlertMetric::CacheHitRate,
        AlertMetric::QueueDepth,
    ];

    c.bench_function("alerting/metric_name", |b| {
        b.iter(|| {
            for metric in &metrics {
                black_box(metric.name());
            }
        });
    });
}

/// Benchmark alert metric unit lookup.
fn bench_metric_unit(c: &mut Criterion) {
    let metrics = vec![
        AlertMetric::StorageUsagePercent,
        AlertMetric::BandwidthUsageBps,
        AlertMetric::CpuUsagePercent,
        AlertMetric::MemoryUsagePercent,
        AlertMetric::ErrorRate,
        AlertMetric::LatencyMs,
    ];

    c.bench_function("alerting/metric_unit", |b| {
        b.iter(|| {
            for metric in &metrics {
                black_box(metric.unit());
            }
        });
    });
}

/// Benchmark threshold evaluation.
fn bench_threshold_evaluation(c: &mut Criterion) {
    let config = ThresholdConfig {
        metric: AlertMetric::StorageUsagePercent,
        warning_threshold: 75.0,
        error_threshold: 90.0,
        critical_threshold: 95.0,
        check_interval_secs: 60,
    };

    let mut group = c.benchmark_group("alerting/threshold_eval");

    for value in [50.0, 80.0, 92.0, 98.0] {
        group.bench_with_input(
            BenchmarkId::from_parameter(value as u32),
            &value,
            |b, &value| {
                b.iter(|| {
                    black_box(config.evaluate(value));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark adding thresholds.
fn bench_add_threshold(c: &mut Criterion) {
    c.bench_function("alerting/add_threshold", |b| {
        b.iter(|| {
            let mut manager = AlertManager::new();
            let config = ThresholdConfig {
                metric: AlertMetric::StorageUsagePercent,
                warning_threshold: 75.0,
                error_threshold: 90.0,
                critical_threshold: 95.0,
                check_interval_secs: 60,
            };
            manager.add_threshold(config);
            black_box(manager);
        });
    });
}

/// Benchmark checking values against thresholds.
fn bench_check_metric(c: &mut Criterion) {
    let mut manager = AlertManager::new();
    manager.add_threshold(ThresholdConfig {
        metric: AlertMetric::StorageUsagePercent,
        warning_threshold: 75.0,
        error_threshold: 90.0,
        critical_threshold: 95.0,
        check_interval_secs: 0, // No interval for benchmarking
    });

    let mut group = c.benchmark_group("alerting/check_metric");

    for value in [50.0, 80.0, 92.0, 98.0] {
        group.bench_with_input(
            BenchmarkId::from_parameter(value as u32),
            &value,
            |b, &value| {
                b.iter(|| {
                    manager.check_metric(AlertMetric::StorageUsagePercent, black_box(value));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting active alerts.
fn bench_get_active_alerts(c: &mut Criterion) {
    let mut manager = AlertManager::new();
    manager.add_threshold(ThresholdConfig {
        metric: AlertMetric::StorageUsagePercent,
        warning_threshold: 75.0,
        error_threshold: 90.0,
        critical_threshold: 95.0,
        check_interval_secs: 0,
    });

    // Trigger some alerts
    manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
    manager.check_metric(AlertMetric::StorageUsagePercent, 92.0);

    c.bench_function("alerting/get_active_alerts", |b| {
        b.iter(|| {
            black_box(manager.get_active_alerts());
        });
    });
}

/// Benchmark filtering alerts by metric.
fn bench_filter_by_metric(c: &mut Criterion) {
    let mut manager = AlertManager::new();

    // Add multiple thresholds
    for metric in [
        AlertMetric::StorageUsagePercent,
        AlertMetric::BandwidthUsageBps,
        AlertMetric::CpuUsagePercent,
    ] {
        manager.add_threshold(ThresholdConfig {
            metric,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        });
    }

    // Trigger alerts
    manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
    manager.check_metric(AlertMetric::BandwidthUsageBps, 85.0);
    manager.check_metric(AlertMetric::CpuUsagePercent, 95.0);

    c.bench_function("alerting/filter_by_metric", |b| {
        b.iter(|| {
            black_box(manager.get_alerts_for_metric(AlertMetric::StorageUsagePercent));
        });
    });
}

/// Benchmark filtering alerts by severity.
fn bench_filter_by_severity(c: &mut Criterion) {
    let mut manager = AlertManager::new();
    manager.add_threshold(ThresholdConfig {
        metric: AlertMetric::StorageUsagePercent,
        warning_threshold: 75.0,
        error_threshold: 90.0,
        critical_threshold: 95.0,
        check_interval_secs: 0,
    });

    // Trigger alerts at different severities
    manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
    manager.check_metric(AlertMetric::StorageUsagePercent, 92.0);
    manager.check_metric(AlertMetric::StorageUsagePercent, 98.0);

    let mut group = c.benchmark_group("alerting/filter_by_severity");

    for severity in [
        AlertSeverity::Warning,
        AlertSeverity::Error,
        AlertSeverity::Critical,
    ] {
        group.bench_function(format!("{:?}", severity), |b| {
            b.iter(|| {
                black_box(manager.get_alerts_by_severity(severity));
            });
        });
    }

    group.finish();
}

/// Benchmark alert counting operations.
fn bench_alert_counts(c: &mut Criterion) {
    let mut manager = AlertManager::new();
    manager.add_threshold(ThresholdConfig {
        metric: AlertMetric::StorageUsagePercent,
        warning_threshold: 75.0,
        error_threshold: 90.0,
        critical_threshold: 95.0,
        check_interval_secs: 0,
    });

    // Trigger various alerts
    manager.check_metric(AlertMetric::StorageUsagePercent, 80.0);
    manager.check_metric(AlertMetric::StorageUsagePercent, 92.0);
    manager.check_metric(AlertMetric::StorageUsagePercent, 98.0);

    let mut group = c.benchmark_group("alerting/counts");

    group.bench_function("active_alert_count", |b| {
        b.iter(|| {
            black_box(manager.active_alert_count());
        });
    });

    group.bench_function("critical_alert_count", |b| {
        b.iter(|| {
            black_box(manager.critical_alert_count());
        });
    });

    group.bench_function("has_critical_alerts", |b| {
        b.iter(|| {
            black_box(manager.has_critical_alerts());
        });
    });

    group.finish();
}

/// Benchmark batch threshold checks.
fn bench_batch_checks(c: &mut Criterion) {
    let mut manager = AlertManager::new();

    for metric in [
        AlertMetric::StorageUsagePercent,
        AlertMetric::CpuUsagePercent,
        AlertMetric::MemoryUsagePercent,
    ] {
        manager.add_threshold(ThresholdConfig {
            metric,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 0,
        });
    }

    let mut group = c.benchmark_group("alerting/batch_checks");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                for i in 0..count {
                    let value = 50.0 + (i % 50) as f64;
                    manager.check_metric(AlertMetric::StorageUsagePercent, black_box(value));
                }
            });
        });
    }

    group.finish();
}

/// Benchmark alert age calculation.
fn bench_alert_age(c: &mut Criterion) {
    let alert = Alert::new(
        AlertSeverity::Warning,
        AlertMetric::StorageUsagePercent,
        80.0,
        75.0,
    );

    c.bench_function("alerting/alert_age", |b| {
        b.iter(|| {
            black_box(alert.age_secs());
        });
    });
}

/// Benchmark clearing alert history.
fn bench_clear_history(c: &mut Criterion) {
    c.bench_function("alerting/clear_history", |b| {
        b.iter(|| {
            let mut manager = AlertManager::new();
            manager.add_threshold(ThresholdConfig {
                metric: AlertMetric::StorageUsagePercent,
                warning_threshold: 75.0,
                error_threshold: 90.0,
                critical_threshold: 95.0,
                check_interval_secs: 0,
            });

            // Generate some alerts
            for i in 0..100 {
                manager.check_metric(AlertMetric::StorageUsagePercent, 50.0 + i as f64 * 0.5);
            }

            manager.clear_history();
            black_box(manager);
        });
    });
}

criterion_group!(
    benches,
    bench_alert_manager_creation,
    bench_metric_name,
    bench_metric_unit,
    bench_threshold_evaluation,
    bench_add_threshold,
    bench_check_metric,
    bench_get_active_alerts,
    bench_filter_by_metric,
    bench_filter_by_severity,
    bench_alert_counts,
    bench_batch_checks,
    bench_alert_age,
    bench_clear_history,
);
criterion_main!(benches);
