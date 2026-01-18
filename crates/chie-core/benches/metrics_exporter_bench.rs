use chie_core::metrics_exporter::{
    CommonMetrics, ExportFormat, MetricValue, MetricsBatch, MetricsExporter,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark MetricsExporter creation.
fn bench_exporter_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("exporter_creation");

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(black_box(f));
                    black_box(exporter);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark MetricsExporter creation with tags.
fn bench_exporter_with_tags_creation(c: &mut Criterion) {
    c.bench_function("exporter_with_tags_creation", |b| {
        b.iter(|| {
            let tags = [("node", "node1"), ("region", "us-east-1"), ("env", "prod")];
            let exporter = MetricsExporter::with_tags(black_box(ExportFormat::StatsD), &tags);
            black_box(exporter);
        });
    });
}

/// Benchmark export_counter with different formats.
fn bench_export_counter(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_counter");

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(f);
                    let tags = [("node", "node1"), ("region", "us-east")];
                    let output = exporter.export_counter(
                        black_box("chie.chunks.stored"),
                        black_box(42),
                        black_box(&tags),
                    );
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark export_gauge with different formats.
fn bench_export_gauge(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_gauge");

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(f);
                    let tags = [("node", "node1")];
                    let output = exporter.export_gauge(
                        black_box("chie.storage.used_bytes"),
                        black_box(1024000),
                        black_box(&tags),
                    );
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark export_timing with different formats.
fn bench_export_timing(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_timing");

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(f);
                    let tags = [("operation", "store_chunk")];
                    let output = exporter.export_timing(
                        black_box("chie.operation.duration"),
                        black_box(125),
                        black_box(&tags),
                    );
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark export_histogram with different formats.
fn bench_export_histogram(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_histogram");

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(f);
                    let tags = [("type", "latency")];
                    let output = exporter.export_histogram(
                        black_box("chie.request.latency"),
                        black_box(45.7),
                        black_box(&tags),
                    );
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark export_metric with different value types.
fn bench_export_metric_by_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_metric_by_type");

    let metric_types = vec![
        ("Counter", MetricValue::Counter(100)),
        ("Gauge", MetricValue::Gauge(-50)),
        ("Timing", MetricValue::Timing(200)),
        ("Histogram", MetricValue::Histogram(75.5)),
    ];

    for (name, value) in metric_types {
        group.bench_with_input(BenchmarkId::from_parameter(name), &value, |b, &v| {
            b.iter(|| {
                let exporter = MetricsExporter::new(ExportFormat::StatsD);
                let tags = [("node", "node1")];
                let output = exporter.export_metric(
                    black_box("test.metric"),
                    black_box(v),
                    black_box(&tags),
                );
                black_box(output);
            });
        });
    }

    group.finish();
}

/// Benchmark export_batch with different batch sizes.
fn bench_export_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_batch");

    for &count in &[10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_metrics", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(ExportFormat::StatsD);

                    // Build batch
                    let mut batch = Vec::new();
                    for i in 0..n {
                        let name = format!("metric.{}", i);
                        let value = MetricValue::Counter(i as u64);
                        let tags = vec![("idx".to_string(), i.to_string())];
                        batch.push((name, value, tags));
                    }

                    let output = exporter.export_batch(black_box(&batch));
                    black_box(output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark MetricsBatch builder pattern.
fn bench_metric_batch_builder(c: &mut Criterion) {
    c.bench_function("metric_batch_builder", |b| {
        b.iter(|| {
            let batch = MetricsBatch::new()
                .add_counter("chie.chunks.stored".to_string(), 100, vec![])
                .add_gauge("chie.storage.used".to_string(), 5000, vec![])
                .add_timing("chie.operation.duration".to_string(), 150, vec![])
                .add_histogram(
                    "chie.request.size".to_string(),
                    1024.5,
                    vec![("type".to_string(), "video".to_string())],
                );

            black_box(batch);
        });
    });
}

/// Benchmark MetricsBatch export.
fn bench_metric_batch_export(c: &mut Criterion) {
    c.bench_function("metric_batch_export", |b| {
        b.iter(|| {
            let batch = MetricsBatch::new()
                .add_counter("chie.chunks.stored".to_string(), 100, vec![])
                .add_gauge("chie.storage.used".to_string(), 5000, vec![])
                .add_timing("chie.operation.duration".to_string(), 150, vec![])
                .add_histogram("chie.request.size".to_string(), 1024.5, vec![]);

            let exporter = MetricsExporter::new(ExportFormat::StatsD);
            let output = batch.export(&exporter);
            black_box(output);
        });
    });
}

/// Benchmark CommonMetrics::storage_metrics.
fn bench_standard_storage_metrics(c: &mut Criterion) {
    c.bench_function("standard_storage_metrics", |b| {
        b.iter(|| {
            let exporter = MetricsExporter::new(ExportFormat::StatsD);
            let metrics = CommonMetrics::storage_metrics(
                black_box(&exporter),
                black_box(500 * 1024 * 1024),
                black_box(1024 * 1024 * 1024),
                black_box(1000),
            );
            black_box(metrics);
        });
    });
}

/// Benchmark CommonMetrics::bandwidth_metrics.
fn bench_standard_bandwidth_metrics(c: &mut Criterion) {
    c.bench_function("standard_bandwidth_metrics", |b| {
        b.iter(|| {
            let exporter = MetricsExporter::new(ExportFormat::StatsD);
            let metrics = CommonMetrics::bandwidth_metrics(
                black_box(&exporter),
                black_box(50 * 1024 * 1024),
                black_box(30 * 1024 * 1024),
                black_box(500),
            );
            black_box(metrics);
        });
    });
}

/// Benchmark CommonMetrics::performance_metrics.
fn bench_standard_performance_metrics(c: &mut Criterion) {
    c.bench_function("standard_performance_metrics", |b| {
        b.iter(|| {
            let exporter = MetricsExporter::new(ExportFormat::StatsD);
            let metrics = CommonMetrics::performance_metrics(
                black_box(&exporter),
                black_box(125),
                black_box(150),
                black_box(200),
            );
            black_box(metrics);
        });
    });
}

/// Benchmark CommonMetrics::cache_metrics.
fn bench_standard_cache_metrics(c: &mut Criterion) {
    c.bench_function("standard_cache_metrics", |b| {
        b.iter(|| {
            let exporter = MetricsExporter::new(ExportFormat::StatsD);
            let metrics = CommonMetrics::cache_metrics(
                black_box(&exporter),
                black_box(5000),
                black_box(1500),
                black_box(500),
            );
            black_box(metrics);
        });
    });
}

/// Benchmark adding default tags.
fn bench_add_default_tag(c: &mut Criterion) {
    c.bench_function("add_default_tag", |b| {
        b.iter(|| {
            let mut exporter = MetricsExporter::new(ExportFormat::StatsD);
            exporter.add_default_tag("node".to_string(), "node1".to_string());
            exporter.add_default_tag("region".to_string(), "us-east-1".to_string());
            exporter.add_default_tag("env".to_string(), "production".to_string());
            black_box(exporter);
        });
    });
}

/// Benchmark realistic scenario: node metrics reporting.
fn bench_realistic_node_metrics(c: &mut Criterion) {
    c.bench_function("realistic_node_metrics", |b| {
        b.iter(|| {
            let exporter = MetricsExporter::with_tags(
                ExportFormat::InfluxDB,
                &[("node", "node1"), ("region", "us-east-1")],
            );

            // Collect various node metrics
            let batch = MetricsBatch::new()
                // Storage metrics
                .add_counter("chie.chunks.stored".to_string(), 1542, vec![])
                .add_gauge(
                    "chie.storage.used_bytes".to_string(),
                    500 * 1024 * 1024,
                    vec![],
                )
                .add_gauge(
                    "chie.storage.available_bytes".to_string(),
                    3 * 1024 * 1024 * 1024,
                    vec![],
                )
                // Bandwidth metrics
                .add_counter(
                    "chie.bandwidth.bytes_uploaded".to_string(),
                    150 * 1024 * 1024,
                    vec![],
                )
                .add_counter(
                    "chie.bandwidth.bytes_downloaded".to_string(),
                    75 * 1024 * 1024,
                    vec![],
                )
                // Performance metrics
                .add_timing("chie.chunk.store_duration".to_string(), 125, vec![])
                .add_timing("chie.chunk.retrieve_duration".to_string(), 85, vec![])
                .add_histogram("chie.request.latency".to_string(), 45.7, vec![])
                // Cache metrics
                .add_gauge("chie.cache.entries".to_string(), 5000, vec![])
                .add_counter("chie.cache.hits".to_string(), 8500, vec![])
                .add_counter("chie.cache.misses".to_string(), 1500, vec![]);

            let output = batch.export(&exporter);
            black_box(output);
        });
    });
}

/// Benchmark realistic scenario: real-time monitoring export.
fn bench_realistic_realtime_monitoring(c: &mut Criterion) {
    c.bench_function("realistic_realtime_monitoring", |b| {
        b.iter(|| {
            // Create StatsD exporter for real-time metrics
            let exporter = MetricsExporter::with_tags(
                ExportFormat::StatsD,
                &[("service", "chie-core"), ("env", "production")],
            );

            // Simulate 1-minute worth of metrics collection
            let mut all_metrics = Vec::new();

            // Storage metrics (collected every 10s, so 6 samples)
            for i in 0..6 {
                let storage = CommonMetrics::storage_metrics(
                    &exporter,
                    (500 + i * 5) * 1024 * 1024,
                    1024 * 1024 * 1024,
                    1000 + i * 10,
                );
                all_metrics.extend(storage);
            }

            // Bandwidth metrics (collected every 5s, so 12 samples)
            for i in 0..12 {
                let bandwidth = CommonMetrics::bandwidth_metrics(
                    &exporter,
                    (50 + i * 2) * 1024 * 1024,
                    (30 + i) * 1024 * 1024,
                    500 + i * 5,
                );
                all_metrics.extend(bandwidth);
            }

            // Performance metrics (collected every 1s, so 60 samples)
            for i in 0..60 {
                let perf = CommonMetrics::performance_metrics(
                    &exporter,
                    100 + (i % 50),
                    150 + (i % 50),
                    200 + (i % 50),
                );
                all_metrics.extend(perf);
            }

            // All metrics are already exported as strings
            black_box(all_metrics);
        });
    });
}

/// Benchmark format comparison: StatsD vs InfluxDB.
fn bench_format_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("format_comparison");

    let metrics = vec![
        ("counter", "chie.requests", MetricValue::Counter(100)),
        ("gauge", "chie.memory", MetricValue::Gauge(1024000)),
        ("timing", "chie.duration", MetricValue::Timing(250)),
        ("histogram", "chie.size", MetricValue::Histogram(512.5)),
    ];

    for format in [ExportFormat::StatsD, ExportFormat::InfluxDB] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", format)),
            &format,
            |b, &f| {
                b.iter(|| {
                    let exporter = MetricsExporter::new(f);
                    let tags = [("node", "node1"), ("env", "prod")];

                    let mut outputs = Vec::new();
                    for (_, name, value) in &metrics {
                        let output = exporter.export_metric(name, *value, &tags);
                        outputs.push(output);
                    }

                    black_box(outputs);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_exporter_creation,
    bench_exporter_with_tags_creation,
    bench_export_counter,
    bench_export_gauge,
    bench_export_timing,
    bench_export_histogram,
    bench_export_metric_by_type,
    bench_export_batch,
    bench_metric_batch_builder,
    bench_metric_batch_export,
    bench_standard_storage_metrics,
    bench_standard_bandwidth_metrics,
    bench_standard_performance_metrics,
    bench_standard_cache_metrics,
    bench_add_default_tag,
    bench_realistic_node_metrics,
    bench_realistic_realtime_monitoring,
    bench_format_comparison,
);
criterion_main!(benches);
