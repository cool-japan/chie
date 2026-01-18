use chie_core::config::*;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

fn bench_storage_settings_creation(c: &mut Criterion) {
    c.bench_function("config_storage_settings_new", |b| {
        b.iter(|| {
            let settings = StorageSettings::new(
                black_box(PathBuf::from("/tmp/chie-data")),
                black_box(50 * 1024 * 1024 * 1024),
            );
            black_box(settings);
        });
    });

    c.bench_function("config_storage_settings_default", |b| {
        b.iter(|| {
            let settings = StorageSettings::default();
            black_box(settings);
        });
    });
}

fn bench_storage_settings_operations(c: &mut Criterion) {
    let settings = StorageSettings::default();

    c.bench_function("config_storage_max_bytes_gb", |b| {
        b.iter(|| {
            let gb = settings.max_bytes_gb();
            black_box(gb);
        });
    });

    c.bench_function("config_storage_validate", |b| {
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    // Invalid settings validation
    c.bench_function("config_storage_validate_invalid", |b| {
        let invalid = StorageSettings::new(PathBuf::from("/tmp"), 0);
        b.iter(|| {
            let result = invalid.validate();
            let _ = black_box(result);
        });
    });
}

fn bench_network_settings_creation(c: &mut Criterion) {
    c.bench_function("config_network_settings_new", |b| {
        b.iter(|| {
            let settings = NetworkSettings::new(black_box(100 * 1024 * 1024 / 8));
            black_box(settings);
        });
    });

    c.bench_function("config_network_settings_default", |b| {
        b.iter(|| {
            let settings = NetworkSettings::default();
            black_box(settings);
        });
    });
}

fn bench_network_settings_operations(c: &mut Criterion) {
    let settings = NetworkSettings::default();

    c.bench_function("config_network_max_bandwidth_mbps", |b| {
        b.iter(|| {
            let mbps = settings.max_bandwidth_mbps();
            black_box(mbps);
        });
    });

    c.bench_function("config_network_validate", |b| {
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    // Invalid settings validation
    c.bench_function("config_network_validate_invalid", |b| {
        let invalid = NetworkSettings::new(0);
        b.iter(|| {
            let result = invalid.validate();
            let _ = black_box(result);
        });
    });
}

fn bench_coordinator_settings_creation(c: &mut Criterion) {
    c.bench_function("config_coordinator_settings_new", |b| {
        b.iter(|| {
            let settings =
                CoordinatorSettings::new(black_box("https://coordinator.chie.network".to_string()));
            black_box(settings);
        });
    });

    c.bench_function("config_coordinator_settings_default", |b| {
        b.iter(|| {
            let settings = CoordinatorSettings::default();
            black_box(settings);
        });
    });
}

fn bench_coordinator_settings_operations(c: &mut Criterion) {
    let settings = CoordinatorSettings::default();

    c.bench_function("config_coordinator_validate", |b| {
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    // Invalid URL validation
    c.bench_function("config_coordinator_validate_invalid_url", |b| {
        let invalid = CoordinatorSettings::new("invalid-url".to_string());
        b.iter(|| {
            let result = invalid.validate();
            let _ = black_box(result);
        });
    });

    // Empty URL validation
    c.bench_function("config_coordinator_validate_empty_url", |b| {
        let invalid = CoordinatorSettings::new(String::new());
        b.iter(|| {
            let result = invalid.validate();
            let _ = black_box(result);
        });
    });
}

fn bench_performance_settings_creation(c: &mut Criterion) {
    c.bench_function("config_performance_settings_default", |b| {
        b.iter(|| {
            let settings = PerformanceSettings::default();
            black_box(settings);
        });
    });
}

fn bench_performance_settings_operations(c: &mut Criterion) {
    let settings = PerformanceSettings::default();

    c.bench_function("config_performance_validate", |b| {
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });
}

fn bench_node_settings_creation(c: &mut Criterion) {
    c.bench_function("config_node_settings_default", |b| {
        b.iter(|| {
            let settings = NodeSettings::default();
            black_box(settings);
        });
    });

    c.bench_function("config_node_settings_builder", |b| {
        b.iter(|| {
            let settings = NodeSettings::builder()
                .storage(black_box(StorageSettings::default()))
                .network(black_box(NetworkSettings::default()))
                .coordinator(black_box(CoordinatorSettings::default()))
                .performance(black_box(PerformanceSettings::default()))
                .build()
                .unwrap();
            black_box(settings);
        });
    });
}

fn bench_node_settings_operations(c: &mut Criterion) {
    let settings = NodeSettings::default();

    c.bench_function("config_node_validate", |b| {
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    // Clone operation
    c.bench_function("config_node_clone", |b| {
        b.iter(|| {
            let cloned = settings.clone();
            black_box(cloned);
        });
    });
}

fn bench_builder_pattern(c: &mut Criterion) {
    c.bench_function("config_builder_minimal", |b| {
        b.iter(|| {
            let settings = NodeSettings::builder().build().unwrap();
            black_box(settings);
        });
    });

    c.bench_function("config_builder_full", |b| {
        b.iter(|| {
            let storage = StorageSettings {
                enable_tiering: true,
                ssd_path: Some(PathBuf::from("/ssd")),
                hdd_path: Some(PathBuf::from("/hdd")),
                ..StorageSettings::default()
            };

            let network = NetworkSettings {
                max_connections: 200,
                rate_limit_rps: 200.0,
                ..NetworkSettings::default()
            };

            let coordinator = CoordinatorSettings {
                api_key: Some("test-key".to_string()),
                proof_batch_size: 20,
                ..CoordinatorSettings::default()
            };

            let performance = PerformanceSettings {
                enable_profiling: true,
                prefetch_cache_size: 200,
                ..PerformanceSettings::default()
            };

            let settings = NodeSettings::builder()
                .storage(storage)
                .network(network)
                .coordinator(coordinator)
                .performance(performance)
                .build()
                .unwrap();
            black_box(settings);
        });
    });
}

fn bench_validation_cascade(c: &mut Criterion) {
    c.bench_function("config_validate_all_valid", |b| {
        let settings = NodeSettings::default();
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    c.bench_function("config_validate_storage_invalid", |b| {
        let mut settings = NodeSettings::default();
        settings.storage.max_bytes = 0;
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    c.bench_function("config_validate_network_invalid", |b| {
        let mut settings = NodeSettings::default();
        settings.network.max_bandwidth_bps = 0;
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });

    c.bench_function("config_validate_coordinator_invalid", |b| {
        let mut settings = NodeSettings::default();
        settings.coordinator.url = String::new();
        b.iter(|| {
            let result = settings.validate();
            let _ = black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_storage_settings_creation,
    bench_storage_settings_operations,
    bench_network_settings_creation,
    bench_network_settings_operations,
    bench_coordinator_settings_creation,
    bench_coordinator_settings_operations,
    bench_performance_settings_creation,
    bench_performance_settings_operations,
    bench_node_settings_creation,
    bench_node_settings_operations,
    bench_builder_pattern,
    bench_validation_cascade,
);
criterion_main!(benches);
