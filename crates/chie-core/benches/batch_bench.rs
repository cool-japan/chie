use chie_core::batch::{BatchConfig, BatchIteratorExt, BatchProcessor};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

async fn simple_async_task(value: u64) -> Result<u64, String> {
    Ok(value * 2)
}

async fn failing_async_task(value: u64) -> Result<u64, String> {
    if value % 10 == 0 {
        Err(format!("Failed on value {}", value))
    } else {
        Ok(value * 2)
    }
}

fn bench_batch_processor_creation(c: &mut Criterion) {
    c.bench_function("batch_create_default", |b| {
        b.iter(|| {
            black_box(BatchProcessor::new(BatchConfig::default()));
        });
    });

    c.bench_function("batch_create_custom", |b| {
        let config = BatchConfig {
            max_concurrent: 100,
            operation_timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_millis(200),
            max_failures: Some(10),
            track_progress: true,
        };
        b.iter(|| {
            black_box(BatchProcessor::new(config.clone()));
        });
    });
}

fn bench_batch_config_builder(c: &mut Criterion) {
    c.bench_function("batch_config_builder", |b| {
        b.iter(|| {
            black_box(
                BatchConfig::new()
                    .with_max_concurrent(100)
                    .with_timeout(Duration::from_secs(30))
                    .with_max_retries(2)
                    .with_max_failures(5),
            );
        });
    });
}

fn bench_process_all_success(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_process_all_success");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for task_count in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("tasks", task_count),
            &task_count,
            |b, &count| {
                let processor = BatchProcessor::new(BatchConfig::default());
                b.iter(|| {
                    rt.block_on(async {
                        let items: Vec<u64> = (0..count).collect();
                        let result = processor.process_all(items, simple_async_task).await;
                        black_box(result);
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_process_all_with_failures(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_process_all_failures");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for task_count in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("tasks", task_count),
            &task_count,
            |b, &count| {
                let processor = BatchProcessor::new(BatchConfig::default());
                b.iter(|| {
                    rt.block_on(async {
                        let items: Vec<u64> = (0..count).collect();
                        let result = processor.process_all(items, failing_async_task).await;
                        black_box(result);
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_process_all_ok(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_process_all_ok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for task_count in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("tasks", task_count),
            &task_count,
            |b, &count| {
                let processor = BatchProcessor::new(BatchConfig::default());
                b.iter(|| {
                    rt.block_on(async {
                        let items: Vec<u64> = (0..count).collect();
                        let results = processor.process_all_ok(items, simple_async_task).await;
                        black_box(results);
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_iterator(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_iterator");

    for batch_size in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("batch_size", batch_size),
            &batch_size,
            |b, &size| {
                b.iter(|| {
                    let items: Vec<u64> = (0..1000).collect();
                    let batches: Vec<Vec<u64>> = items.into_iter().batches(size).collect();
                    black_box(batches);
                });
            },
        );
    }

    group.finish();
}

fn bench_concurrency_limits(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_concurrency_limits");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for max_concurrent in [1, 5, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("concurrent", max_concurrent),
            &max_concurrent,
            |b, &limit| {
                let config = BatchConfig {
                    max_concurrent: limit,
                    ..Default::default()
                };
                let processor = BatchProcessor::new(config);

                b.iter(|| {
                    rt.block_on(async {
                        let items: Vec<u64> = (0..100).collect();
                        let result = processor.process_all(items, simple_async_task).await;
                        black_box(result);
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_with_retries(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_with_retries");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for max_retries in [0, 1, 2, 3] {
        group.bench_with_input(
            BenchmarkId::new("retries", max_retries),
            &max_retries,
            |b, &retries| {
                let config = BatchConfig {
                    max_retries: retries,
                    ..Default::default()
                };
                let processor = BatchProcessor::new(config);

                b.iter(|| {
                    rt.block_on(async {
                        let items: Vec<u64> = (0..50).collect();
                        let result = processor.process_all(items, failing_async_task).await;
                        black_box(result);
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_result_success_rate(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("batch_result_success_rate", |b| {
        let processor = BatchProcessor::new(BatchConfig::default());

        b.iter(|| {
            rt.block_on(async {
                let items: Vec<u64> = (0..100).collect();
                let result = processor.process_all(items, failing_async_task).await;
                black_box(result.success_rate());
            })
        });
    });
}

fn bench_mixed_batch_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_mixed_sizes");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for (small, medium, large) in [(10, 50, 100), (20, 100, 500)] {
        group.bench_with_input(
            BenchmarkId::new("sizes", format!("{}-{}-{}", small, medium, large)),
            &(small, medium, large),
            |b, &(s, m, l)| {
                let processor = BatchProcessor::new(BatchConfig::default());

                b.iter(|| {
                    rt.block_on(async {
                        // Process three different batch sizes
                        let items1: Vec<u64> = (0..s).collect();
                        let items2: Vec<u64> = (0..m).collect();
                        let items3: Vec<u64> = (0..l).collect();

                        let r1 = processor.process_all(items1, simple_async_task).await;
                        let r2 = processor.process_all(items2, simple_async_task).await;
                        let r3 = processor.process_all(items3, simple_async_task).await;

                        black_box((r1, r2, r3));
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_batch_processor_creation,
    bench_batch_config_builder,
    bench_process_all_success,
    bench_process_all_with_failures,
    bench_process_all_ok,
    bench_batch_iterator,
    bench_concurrency_limits,
    bench_with_retries,
    bench_batch_result_success_rate,
    bench_mixed_batch_sizes
);

criterion_main!(benches);
