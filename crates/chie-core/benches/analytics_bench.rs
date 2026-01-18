use chie_core::{AnalyticsCollector, AnalyticsConfig, ChunkStorage};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::{Arc, RwLock};
use tempfile::TempDir;

/// Create a test analytics collector
fn create_test_collector() -> (AnalyticsCollector, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().to_path_buf();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let storage = rt.block_on(async {
        ChunkStorage::new(storage_path, 1024 * 1024 * 1024)
            .await
            .unwrap()
    });

    let config = AnalyticsConfig {
        max_latency_samples: 1000,
        max_transfer_records: 1000,
        history_retention_days: 30,
    };

    let collector = AnalyticsCollector::new(Arc::new(RwLock::new(storage)), config);
    (collector, temp_dir)
}

fn bench_record_upload(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    c.bench_function("analytics_record_upload", |b| {
        b.iter(|| {
            collector.record_upload(black_box(1024 * 1024), black_box(true));
        });
    });
}

fn bench_record_download(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    c.bench_function("analytics_record_download", |b| {
        b.iter(|| {
            collector.record_download(black_box(1024 * 1024), black_box(true));
        });
    });
}

fn bench_record_earning(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    c.bench_function("analytics_record_earning", |b| {
        b.iter(|| {
            collector.record_earning(black_box(1000), Some("QmTest123"));
        });
    });
}

fn bench_record_latency(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    c.bench_function("analytics_record_latency", |b| {
        b.iter(|| {
            collector.record_latency(black_box(50.0));
        });
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    c.bench_function("analytics_mixed_operations", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            collector.record_upload(black_box(1024), true);
            collector.record_download(black_box(2048), true);
            collector.record_earning(black_box(100), Some("QmTest"));
            collector.record_latency(black_box(25.0));
            counter += 1;
            black_box(counter);
        });
    });
}

fn bench_concurrent_recording(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();
    let collector = Arc::new(collector);

    c.bench_function("analytics_concurrent_recording", |b| {
        b.iter(|| {
            let mut handles = vec![];
            for i in 0..10 {
                let c = Arc::clone(&collector);
                let handle = std::thread::spawn(move || {
                    c.record_upload(black_box(i * 1024), true);
                    c.record_download(black_box(i * 2048), true);
                });
                handles.push(handle);
            }
            for handle in handles {
                handle.join().unwrap();
            }
        });
    });
}

fn bench_statistics_retrieval(c: &mut Criterion) {
    let (collector, _temp) = create_test_collector();

    // Pre-populate with some data
    for i in 0..100 {
        collector.record_upload(i * 1024, true);
        collector.record_download(i * 2048, true);
        collector.record_earning(i * 10, Some("QmTest"));
        collector.record_latency(i as f64);
    }

    c.bench_function("analytics_transfer_analytics", |b| {
        b.iter(|| {
            black_box(collector.transfer_analytics());
        });
    });

    c.bench_function("analytics_earning_analytics", |b| {
        b.iter(|| {
            black_box(collector.earning_analytics());
        });
    });

    c.bench_function("analytics_performance_analytics", |b| {
        b.iter(|| {
            black_box(collector.performance_analytics());
        });
    });
}

criterion_group!(
    benches,
    bench_record_upload,
    bench_record_download,
    bench_record_earning,
    bench_record_latency,
    bench_mixed_operations,
    bench_concurrent_recording,
    bench_statistics_retrieval
);

criterion_main!(benches);
