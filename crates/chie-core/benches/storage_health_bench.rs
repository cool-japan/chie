use chie_core::storage_health::{HealthConfig, PredictiveStorageMonitor};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

/// Benchmark HealthConfig creation.
fn bench_health_config_creation(c: &mut Criterion) {
    c.bench_function("storage_health_config_creation", |b| {
        b.iter(|| {
            let config = HealthConfig::default();
            black_box(config);
        });
    });
}

/// Benchmark HealthConfig creation with custom settings.
fn bench_health_config_custom_creation(c: &mut Criterion) {
    c.bench_function("storage_health_config_custom_creation", |b| {
        b.iter(|| {
            let config = HealthConfig {
                check_interval: black_box(Duration::from_secs(30)),
                latency_warning_threshold_ms: black_box(50),
                latency_critical_threshold_ms: black_box(200),
                min_free_space_percent: black_box(15.0),
                critical_failure_count: black_box(5),
                enable_prediction: black_box(true),
                failure_risk_threshold: black_box(0.75),
            };
            black_box(config);
        });
    });
}

/// Benchmark HealthConfig cloning.
fn bench_health_config_clone(c: &mut Criterion) {
    c.bench_function("storage_health_config_clone", |b| {
        let config = HealthConfig::default();

        b.iter(|| {
            let cloned = config.clone();
            black_box(cloned);
        });
    });
}

/// Benchmark PredictiveStorageMonitor creation.
fn bench_monitor_creation(c: &mut Criterion) {
    c.bench_function("storage_health_monitor_creation", |b| {
        b.iter(|| {
            let path = PathBuf::from(black_box("/tmp/test-storage"));
            let config = HealthConfig::default();
            let monitor = PredictiveStorageMonitor::new(path, config);
            black_box(monitor);
        });
    });
}

/// Benchmark monitor creation with different check intervals.
fn bench_monitor_creation_by_interval(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_health_monitor_by_interval");

    for &seconds in &[10, 30, 60, 300] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}s", seconds)),
            &seconds,
            |b, &s| {
                b.iter(|| {
                    let path = PathBuf::from("/tmp/test-storage");
                    let config = HealthConfig {
                        check_interval: Duration::from_secs(s),
                        ..HealthConfig::default()
                    };
                    let monitor = PredictiveStorageMonitor::new(path, config);
                    black_box(monitor);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark monitor creation with different latency thresholds.
fn bench_monitor_creation_by_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_health_monitor_by_latency");

    let thresholds = vec![
        ("conservative", 50, 200), // Low thresholds
        ("moderate", 100, 500),    // Default
        ("permissive", 200, 1000), // High thresholds
    ];

    for (name, warning, critical) in thresholds {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(warning, critical),
            |b, &(w, c_thresh)| {
                b.iter(|| {
                    let path = PathBuf::from("/tmp/test-storage");
                    let config = HealthConfig {
                        latency_warning_threshold_ms: w,
                        latency_critical_threshold_ms: c_thresh,
                        ..HealthConfig::default()
                    };
                    let monitor = PredictiveStorageMonitor::new(path, config);
                    black_box(monitor);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark storage_path accessor.
fn bench_storage_path_accessor(c: &mut Criterion) {
    c.bench_function("storage_health_storage_path_accessor", |b| {
        let path = PathBuf::from("/tmp/test-storage");
        let config = HealthConfig::default();
        let monitor = PredictiveStorageMonitor::new(path, config);

        b.iter(|| {
            let path = monitor.storage_path();
            black_box(path);
        });
    });
}

/// Benchmark sample_count accessor.
fn bench_sample_count_accessor(c: &mut Criterion) {
    c.bench_function("storage_health_sample_count_accessor", |b| {
        let path = PathBuf::from("/tmp/test-storage");
        let config = HealthConfig::default();
        let monitor = PredictiveStorageMonitor::new(path, config);

        b.iter(|| {
            let count = monitor.sample_count();
            black_box(count);
        });
    });
}

/// Benchmark PathBuf creation for different storage sizes.
fn bench_path_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_health_path_creation");

    let paths = vec![
        ("root", "/storage".to_string()),
        ("data", "/var/lib/chie/storage".to_string()),
        ("user", "/home/user/.local/share/chie/storage".to_string()),
        ("nested", "/mnt/storage/chie/data/chunks/v1".to_string()),
    ];

    for (name, path_str) in paths {
        group.bench_with_input(BenchmarkId::from_parameter(name), &path_str, |b, p| {
            b.iter(|| {
                let path = PathBuf::from(black_box(p));
                black_box(path);
            });
        });
    }

    group.finish();
}

/// Benchmark realistic scenario: multiple monitors for different storage tiers.
fn bench_realistic_multi_tier_monitoring(c: &mut Criterion) {
    c.bench_function("storage_health_realistic_multi_tier", |b| {
        b.iter(|| {
            // Simulate monitoring setup for tiered storage system
            // Tier 1: Fast SSD (strict latency requirements)
            let tier1_config = HealthConfig {
                check_interval: Duration::from_secs(30),
                latency_warning_threshold_ms: 50,
                latency_critical_threshold_ms: 100,
                min_free_space_percent: 20.0,
                critical_failure_count: 2,
                enable_prediction: true,
                failure_risk_threshold: 0.6,
            };
            let tier1_monitor =
                PredictiveStorageMonitor::new(PathBuf::from("/mnt/ssd/storage"), tier1_config);

            // Tier 2: Regular HDD (moderate requirements)
            let tier2_config = HealthConfig {
                check_interval: Duration::from_secs(60),
                latency_warning_threshold_ms: 100,
                latency_critical_threshold_ms: 500,
                min_free_space_percent: 15.0,
                critical_failure_count: 3,
                enable_prediction: true,
                failure_risk_threshold: 0.7,
            };
            let tier2_monitor =
                PredictiveStorageMonitor::new(PathBuf::from("/mnt/hdd/storage"), tier2_config);

            // Tier 3: Archive storage (relaxed requirements)
            let tier3_config = HealthConfig {
                check_interval: Duration::from_secs(300),
                latency_warning_threshold_ms: 500,
                latency_critical_threshold_ms: 2000,
                min_free_space_percent: 10.0,
                critical_failure_count: 5,
                enable_prediction: false,
                failure_risk_threshold: 0.8,
            };
            let tier3_monitor =
                PredictiveStorageMonitor::new(PathBuf::from("/mnt/archive/storage"), tier3_config);

            black_box((tier1_monitor, tier2_monitor, tier3_monitor));
        });
    });
}

/// Benchmark realistic scenario: monitoring configuration for different deployment sizes.
fn bench_realistic_deployment_configs(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_health_realistic_deployments");

    let deployments = vec![
        ("small_node", 120, 150, 500, 15.0), // Small personal node
        ("medium_node", 60, 100, 500, 12.0), // Medium community node
        ("large_node", 30, 50, 200, 10.0),   // Large provider node
        ("enterprise", 10, 20, 100, 5.0),    // Enterprise deployment
    ];

    for (name, interval, warn_lat, crit_lat, min_space) in deployments {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(interval, warn_lat, crit_lat, min_space),
            |b, &(int, w, c, space)| {
                b.iter(|| {
                    let config = HealthConfig {
                        check_interval: Duration::from_secs(int),
                        latency_warning_threshold_ms: w,
                        latency_critical_threshold_ms: c,
                        min_free_space_percent: space,
                        critical_failure_count: 3,
                        enable_prediction: true,
                        failure_risk_threshold: 0.7,
                    };
                    let monitor = PredictiveStorageMonitor::new(PathBuf::from("/storage"), config);
                    black_box(monitor);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark config comparison.
fn bench_config_comparison(c: &mut Criterion) {
    c.bench_function("storage_health_config_comparison", |b| {
        let config1 = HealthConfig {
            latency_warning_threshold_ms: 100,
            latency_critical_threshold_ms: 500,
            ..HealthConfig::default()
        };

        let config2 = HealthConfig {
            latency_warning_threshold_ms: 50,
            latency_critical_threshold_ms: 200,
            ..HealthConfig::default()
        };

        b.iter(|| {
            let is_stricter = black_box(config1.latency_critical_threshold_ms)
                < black_box(config2.latency_critical_threshold_ms);
            black_box(is_stricter);
        });
    });
}

/// Benchmark Duration creation for different check intervals.
fn bench_duration_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_health_duration_creation");

    for &seconds in &[10, 30, 60, 120, 300, 600] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}s", seconds)),
            &seconds,
            |b, &s| {
                b.iter(|| {
                    let duration = Duration::from_secs(black_box(s));
                    black_box(duration);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_health_config_creation,
    bench_health_config_custom_creation,
    bench_health_config_clone,
    bench_monitor_creation,
    bench_monitor_creation_by_interval,
    bench_monitor_creation_by_latency,
    bench_storage_path_accessor,
    bench_sample_count_accessor,
    bench_path_creation,
    bench_realistic_multi_tier_monitoring,
    bench_realistic_deployment_configs,
    bench_config_comparison,
    bench_duration_creation,
);
criterion_main!(benches);
