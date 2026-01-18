use chie_core::metrics::{Counter, Gauge, Histogram, MetricsRegistry, create_standard_registry};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_counter_creation(c: &mut Criterion) {
    c.bench_function("metrics_counter_create", |b| {
        b.iter(|| {
            black_box(Counter::new());
        });
    });
}

fn bench_gauge_creation(c: &mut Criterion) {
    c.bench_function("metrics_gauge_create", |b| {
        b.iter(|| {
            black_box(Gauge::new());
        });
    });
}

fn bench_histogram_creation(c: &mut Criterion) {
    c.bench_function("metrics_histogram_create", |b| {
        b.iter(|| {
            black_box(Histogram::new());
        });
    });
}

fn bench_counter_increment(c: &mut Criterion) {
    let counter = Counter::new();

    c.bench_function("metrics_counter_inc", |b| {
        b.iter(|| {
            counter.inc();
            black_box(&counter);
        });
    });
}

fn bench_counter_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_counter_add");
    let counter = Counter::new();

    for value in [1.0, 10.0, 100.0, 1000.0] {
        group.bench_with_input(BenchmarkId::new("value", value as u64), &value, |b, &v| {
            b.iter(|| {
                counter.add(v);
                black_box(&counter);
            });
        });
    }

    group.finish();
}

fn bench_counter_get(c: &mut Criterion) {
    let counter = Counter::new();
    counter.add(12345.0);

    c.bench_function("metrics_counter_get", |b| {
        b.iter(|| {
            black_box(counter.get());
        });
    });
}

fn bench_gauge_set(c: &mut Criterion) {
    let gauge = Gauge::new();
    let mut value = 0.0;

    c.bench_function("metrics_gauge_set", |b| {
        b.iter(|| {
            value += 1.0;
            gauge.set(value);
            black_box(&gauge);
        });
    });
}

fn bench_gauge_inc_dec(c: &mut Criterion) {
    let gauge = Gauge::new();

    c.bench_function("metrics_gauge_inc_dec", |b| {
        b.iter(|| {
            gauge.inc();
            gauge.dec();
            black_box(&gauge);
        });
    });
}

fn bench_gauge_add_sub(c: &mut Criterion) {
    let gauge = Gauge::new();

    c.bench_function("metrics_gauge_add_sub", |b| {
        b.iter(|| {
            gauge.add(10.0);
            gauge.sub(5.0);
            black_box(&gauge);
        });
    });
}

fn bench_histogram_observe(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_histogram_observe");
    let histogram = Histogram::new();

    for value in [1.0, 10.0, 100.0, 1000.0] {
        group.bench_with_input(BenchmarkId::new("value", value as u64), &value, |b, &v| {
            b.iter(|| {
                histogram.observe(v);
                black_box(&histogram);
            });
        });
    }

    group.finish();
}

fn bench_histogram_stats(c: &mut Criterion) {
    let histogram = Histogram::new();

    // Add some observations
    for i in 0..100 {
        histogram.observe(i as f64);
    }

    c.bench_function("metrics_histogram_sum", |b| {
        b.iter(|| {
            black_box(histogram.sum());
        });
    });

    c.bench_function("metrics_histogram_count", |b| {
        b.iter(|| {
            black_box(histogram.count());
        });
    });
}

fn bench_registry_creation(c: &mut Criterion) {
    c.bench_function("metrics_registry_create", |b| {
        b.iter(|| {
            black_box(MetricsRegistry::new());
        });
    });
}

fn bench_registry_counter_registration(c: &mut Criterion) {
    c.bench_function("metrics_registry_register_counter", |b| {
        b.iter_batched(
            MetricsRegistry::new,
            |mut registry| {
                black_box(registry.counter("test_counter", "A test counter"));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_registry_gauge_registration(c: &mut Criterion) {
    c.bench_function("metrics_registry_register_gauge", |b| {
        b.iter_batched(
            MetricsRegistry::new,
            |mut registry| {
                black_box(registry.gauge("test_gauge", "A test gauge"));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_registry_histogram_registration(c: &mut Criterion) {
    c.bench_function("metrics_registry_register_histogram", |b| {
        b.iter_batched(
            MetricsRegistry::new,
            |mut registry| {
                black_box(registry.histogram("test_histogram", "A test histogram"));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_registry_multiple_registrations(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_registry_multiple");

    for count in [10, 50, 100] {
        group.bench_with_input(BenchmarkId::new("metrics", count), &count, |b, &c| {
            b.iter_batched(
                MetricsRegistry::new,
                |mut registry| {
                    for i in 0..c {
                        let name = format!("metric_{}", i);
                        match i % 3 {
                            0 => {
                                registry.counter(&name, "counter");
                            }
                            1 => {
                                registry.gauge(&name, "gauge");
                            }
                            _ => {
                                registry.histogram(&name, "histogram");
                            }
                        }
                    }
                    black_box(registry);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_registry_get_counter(c: &mut Criterion) {
    let mut registry = MetricsRegistry::new();
    registry.counter("test_counter", "Test counter");

    c.bench_function("metrics_registry_get_counter", |b| {
        b.iter(|| {
            black_box(registry.get_counter("test_counter"));
        });
    });
}

fn bench_registry_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_registry_export");

    for metric_count in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("metrics", metric_count),
            &metric_count,
            |b, &count| {
                let mut registry = MetricsRegistry::new();

                // Register metrics
                for i in 0..count {
                    let counter = registry.counter(&format!("counter_{}", i), "Counter metric");
                    counter.add(i as f64);

                    let gauge = registry.gauge(&format!("gauge_{}", i), "Gauge metric");
                    gauge.set(i as f64);

                    let histogram =
                        registry.histogram(&format!("histogram_{}", i), "Histogram metric");
                    histogram.observe(i as f64);
                }

                b.iter(|| {
                    black_box(registry.export());
                });
            },
        );
    }

    group.finish();
}

fn bench_registry_reset_all(c: &mut Criterion) {
    c.bench_function("metrics_registry_reset_all", |b| {
        b.iter_batched(
            || {
                let mut registry = MetricsRegistry::new();
                for i in 0..50 {
                    let counter = registry.counter(&format!("counter_{}", i), "Counter");
                    counter.add(100.0);
                    let histogram = registry.histogram(&format!("histogram_{}", i), "Histogram");
                    histogram.observe(100.0);
                }
                registry
            },
            |registry| {
                registry.reset_all();
                black_box(&registry);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_standard_registry_creation(c: &mut Criterion) {
    c.bench_function("metrics_create_standard_registry", |b| {
        b.iter(|| {
            black_box(create_standard_registry());
        });
    });
}

fn bench_concurrent_counter_updates(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    c.bench_function("metrics_concurrent_counter_updates", |b| {
        b.iter_batched(
            || Arc::new(Counter::new()),
            |counter| {
                let handles: Vec<_> = (0..4)
                    .map(|_| {
                        let counter_clone = Arc::clone(&counter);
                        thread::spawn(move || {
                            for _ in 0..100 {
                                counter_clone.inc();
                            }
                        })
                    })
                    .collect();

                for handle in handles {
                    handle.join().unwrap();
                }

                black_box(counter);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_mixed_metric_operations(c: &mut Criterion) {
    c.bench_function("metrics_mixed_operations", |b| {
        let mut registry = MetricsRegistry::new();
        let counter = registry.counter("requests", "Request counter");
        let gauge = registry.gauge("memory", "Memory gauge");
        let histogram = registry.histogram("latency", "Latency histogram");

        let mut idx = 0;
        b.iter(|| {
            match idx % 6 {
                0 => counter.inc(),
                1 => counter.add(5.0),
                2 => gauge.set(idx as f64),
                3 => gauge.inc(),
                4 => histogram.observe(idx as f64),
                _ => {
                    black_box(counter.get());
                }
            }
            idx += 1;
        });
    });
}

criterion_group!(
    benches,
    bench_counter_creation,
    bench_gauge_creation,
    bench_histogram_creation,
    bench_counter_increment,
    bench_counter_add,
    bench_counter_get,
    bench_gauge_set,
    bench_gauge_inc_dec,
    bench_gauge_add_sub,
    bench_histogram_observe,
    bench_histogram_stats,
    bench_registry_creation,
    bench_registry_counter_registration,
    bench_registry_gauge_registration,
    bench_registry_histogram_registration,
    bench_registry_multiple_registrations,
    bench_registry_get_counter,
    bench_registry_export,
    bench_registry_reset_all,
    bench_standard_registry_creation,
    bench_concurrent_counter_updates,
    bench_mixed_metric_operations
);

criterion_main!(benches);
