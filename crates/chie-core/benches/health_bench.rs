use chie_core::health::{HealthChecker, HealthStatus};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

async fn healthy_check() -> Result<HealthStatus, String> {
    Ok(HealthStatus::Healthy)
}

async fn degraded_check() -> Result<HealthStatus, String> {
    Ok(HealthStatus::Degraded)
}

async fn failing_check() -> Result<HealthStatus, String> {
    Err("Check failed".to_string())
}

fn bench_health_checker_creation(c: &mut Criterion) {
    c.bench_function("health_create_checker", |b| {
        b.iter(|| {
            black_box(HealthChecker::new());
        });
    });
}

fn bench_register_health_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_register_check", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut checker = HealthChecker::new();
                checker
                    .register("test_component", Box::new(|| Box::pin(healthy_check())))
                    .await;
                black_box(checker);
            })
        });
    });
}

fn bench_register_multiple_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_register_multiple");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for count in [5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::new("checks", count), &count, |b, &c| {
            b.iter(|| {
                rt.block_on(async move {
                    let mut checker = HealthChecker::new();
                    for i in 0..c {
                        checker
                            .register(
                                &format!("component_{}", i),
                                Box::new(|| Box::pin(healthy_check())),
                            )
                            .await;
                    }
                    black_box(checker);
                })
            });
        });
    }

    group.finish();
}

fn bench_check_all_healthy(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_check_all_healthy");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for count in [5, 10, 20] {
        group.bench_with_input(BenchmarkId::new("components", count), &count, |b, &c| {
            b.iter_batched(
                || {
                    let mut checker = HealthChecker::new();
                    for i in 0..c {
                        rt.block_on(checker.register(
                            &format!("component_{}", i),
                            Box::new(|| Box::pin(healthy_check())),
                        ));
                    }
                    checker
                },
                |checker| {
                    rt.block_on(async move {
                        let report = checker.check_all().await;
                        black_box(report);
                    })
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_check_all_mixed_status(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_check_all_mixed", |b| {
        b.iter_batched(
            || {
                let mut checker = HealthChecker::new();
                rt.block_on(async {
                    checker
                        .register("healthy1", Box::new(|| Box::pin(healthy_check())))
                        .await;
                    checker
                        .register("degraded1", Box::new(|| Box::pin(degraded_check())))
                        .await;
                    checker
                        .register("healthy2", Box::new(|| Box::pin(healthy_check())))
                        .await;
                    checker
                        .register("failing1", Box::new(|| Box::pin(failing_check())))
                        .await;
                    checker
                        .register("healthy3", Box::new(|| Box::pin(healthy_check())))
                        .await;
                });
                checker
            },
            |checker| {
                rt.block_on(async move {
                    let report = checker.check_all().await;
                    black_box(report);
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_check_single_component(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_check_single", |b| {
        b.iter_batched(
            || {
                let mut checker = HealthChecker::new();
                rt.block_on(
                    checker.register("test_component", Box::new(|| Box::pin(healthy_check()))),
                );
                checker
            },
            |checker| {
                rt.block_on(async move {
                    let result = checker.check("test_component").await;
                    black_box(result);
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_unregister_component(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_unregister", |b| {
        b.iter_batched(
            || {
                let mut checker = HealthChecker::new();
                rt.block_on(async {
                    for i in 0..10 {
                        checker
                            .register(
                                &format!("component_{}", i),
                                Box::new(|| Box::pin(healthy_check())),
                            )
                            .await;
                    }
                });
                checker
            },
            |mut checker| {
                rt.block_on(async move {
                    checker.unregister("component_5").await;
                    black_box(checker);
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_overall_status_calculation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_overall_status", |b| {
        b.iter_batched(
            || {
                let mut checker = HealthChecker::new();
                rt.block_on(async {
                    checker
                        .register("healthy", Box::new(|| Box::pin(healthy_check())))
                        .await;
                    checker
                        .register("degraded", Box::new(|| Box::pin(degraded_check())))
                        .await;
                    checker
                        .register("healthy2", Box::new(|| Box::pin(healthy_check())))
                        .await;
                });
                checker
            },
            |checker| {
                rt.block_on(async move {
                    let report = checker.check_all().await;
                    black_box(report.overall_status());
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_health_status_score(c: &mut Criterion) {
    c.bench_function("health_status_score", |b| {
        b.iter(|| {
            black_box(HealthStatus::Healthy.score());
            black_box(HealthStatus::Degraded.score());
            black_box(HealthStatus::Unhealthy.score());
        });
    });
}

fn bench_concurrent_health_checks(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("health_concurrent_checks", |b| {
        b.iter_batched(
            || {
                let mut checker = HealthChecker::new();
                rt.block_on(async {
                    for i in 0..20 {
                        checker
                            .register(
                                &format!("component_{}", i),
                                Box::new(|| Box::pin(healthy_check())),
                            )
                            .await;
                    }
                });
                checker
            },
            |checker| {
                rt.block_on(async move {
                    // Run sequential checks for all components
                    let mut results = Vec::new();
                    for i in 0..20 {
                        let comp_name = format!("component_{}", i);
                        results.push(checker.check(&comp_name).await);
                    }
                    black_box(results);
                })
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_health_checker_creation,
    bench_register_health_check,
    bench_register_multiple_checks,
    bench_check_all_healthy,
    bench_check_all_mixed_status,
    bench_check_single_component,
    bench_unregister_component,
    bench_overall_status_calculation,
    bench_health_status_score,
    bench_concurrent_health_checks
);

criterion_main!(benches);
