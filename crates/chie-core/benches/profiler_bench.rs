use chie_core::profiler::Profiler;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_profiler_scope_overhead(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    c.bench_function("profiler_scope_overhead", |b| {
        b.iter(|| {
            let _scope = profiler.scope(black_box("test_op"));
            // Minimal work to measure pure overhead
            black_box(42);
        });
    });
}

fn bench_profiler_disabled_overhead(c: &mut Criterion) {
    let mut profiler = Profiler::disabled();

    c.bench_function("profiler_disabled_overhead", |b| {
        b.iter(|| {
            let _scope = profiler.scope(black_box("test_op"));
            black_box(42);
        });
    });
}

fn bench_profiler_record_manual(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    c.bench_function("profiler_record_manual", |b| {
        b.iter(|| {
            profiler.record(black_box("test_op"), black_box(Duration::from_micros(100)));
        });
    });
}

fn bench_profiler_get_stats(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    // Pre-populate with data
    for i in 0..100 {
        profiler.record(&format!("op_{}", i), Duration::from_millis(10));
    }

    c.bench_function("profiler_get_stats", |b| {
        b.iter(|| {
            let stats = profiler.get_stats(black_box("op_50"));
            black_box(stats)
        });
    });
}

fn bench_profiler_many_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler_many_operations");

    for num_ops in [10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_ops),
            &num_ops,
            |b, &num_ops| {
                b.iter(|| {
                    let mut profiler = Profiler::new();

                    for i in 0..num_ops {
                        let _scope = profiler.scope(&format!("op_{}", i % 10));
                        black_box(i * 2);
                    }

                    black_box(profiler)
                });
            },
        );
    }

    group.finish();
}

fn bench_profiler_generate_report(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    // Populate with realistic data
    for i in 0..50 {
        for _ in 0..10 {
            profiler.record(&format!("operation_{}", i), Duration::from_millis(i as u64));
        }
    }

    c.bench_function("profiler_generate_report", |b| {
        b.iter(|| {
            let report = profiler.generate_report();
            black_box(report)
        });
    });
}

fn bench_profiler_export_json(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    // Populate with realistic data
    for i in 0..50 {
        for _ in 0..10 {
            profiler.record(&format!("operation_{}", i), Duration::from_millis(i as u64));
        }
    }

    c.bench_function("profiler_export_json", |b| {
        b.iter(|| {
            let json = profiler.export_json();
            black_box(json)
        });
    });
}

fn bench_operation_stats_record(c: &mut Criterion) {
    c.bench_function("operation_stats_record", |b| {
        b.iter(|| {
            let mut profiler = Profiler::new();

            for i in 0..100 {
                let duration = Duration::from_micros(i * 10);
                profiler.record("test_operation", duration);
            }

            black_box(profiler.get_stats("test_operation").unwrap().clone())
        });
    });
}

fn bench_profiler_total_time(c: &mut Criterion) {
    let mut profiler = Profiler::new();

    for i in 0..100 {
        profiler.record(&format!("op_{}", i), Duration::from_millis(i));
    }

    c.bench_function("profiler_total_time", |b| {
        b.iter(|| {
            let total = profiler.total_time();
            black_box(total)
        });
    });
}

fn bench_profiler_nested_scopes(c: &mut Criterion) {
    c.bench_function("profiler_nested_scopes", |b| {
        b.iter(|| {
            let mut profiler = Profiler::new();

            {
                let _outer = profiler.scope("outer");
                black_box(42);
            }

            // We can't actually nest scopes due to mutable borrow,
            // but we can simulate the pattern by recording after the outer scope
            for i in 0..10 {
                profiler.record(&format!("inner_{}", i), Duration::from_micros(i * 10));
            }

            black_box(profiler)
        });
    });
}

criterion_group!(
    benches,
    bench_profiler_scope_overhead,
    bench_profiler_disabled_overhead,
    bench_profiler_record_manual,
    bench_profiler_get_stats,
    bench_profiler_many_operations,
    bench_profiler_generate_report,
    bench_profiler_export_json,
    bench_operation_stats_record,
    bench_profiler_total_time,
    bench_profiler_nested_scopes,
);

criterion_main!(benches);
