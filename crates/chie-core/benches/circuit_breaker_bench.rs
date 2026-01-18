use chie_core::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

fn bench_circuit_breaker_creation(c: &mut Criterion) {
    c.bench_function("circuit_breaker_create_default", |b| {
        b.iter(|| {
            black_box(CircuitBreaker::new(
                "test_breaker",
                CircuitBreakerConfig::default(),
            ));
        });
    });

    c.bench_function("circuit_breaker_create_custom", |b| {
        let config = CircuitBreakerConfig {
            failure_threshold: 10,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
        };
        b.iter(|| {
            black_box(CircuitBreaker::new("test_breaker", config.clone()));
        });
    });
}

fn bench_circuit_breaker_config_creation(c: &mut Criterion) {
    c.bench_function("circuit_breaker_config_default", |b| {
        b.iter(|| {
            black_box(CircuitBreakerConfig::default());
        });
    });

    c.bench_function("circuit_breaker_config_custom", |b| {
        b.iter(|| {
            black_box(CircuitBreakerConfig {
                failure_threshold: 10,
                success_threshold: 3,
                timeout: Duration::from_secs(30),
            });
        });
    });
}

fn bench_call_success(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_call_success", |b| {
        let breaker = CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default());

        b.iter(|| {
            rt.block_on(async {
                let result = breaker.call(|| async { Ok::<i32, String>(42) }).await;
                let _ = black_box(result);
            });
        });
    });
}

fn bench_call_failure(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_call_failure", |b| {
        b.iter_batched(
            || CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default()),
            |breaker| {
                rt.block_on(async {
                    let result = breaker
                        .call(|| async { Err::<i32, String>("error".to_string()) })
                        .await;
                    let _ = black_box(result);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_state_queries(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_state", |b| {
        let breaker = CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default());

        b.iter(|| {
            rt.block_on(async {
                black_box(breaker.state().await);
            });
        });
    });

    c.bench_function("circuit_breaker_name", |b| {
        let breaker = CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default());

        b.iter(|| {
            black_box(breaker.name());
        });
    });
}

fn bench_state_transitions(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_transition_to_open", |b| {
        b.iter_batched(
            || {
                CircuitBreaker::new(
                    "test_breaker",
                    CircuitBreakerConfig {
                        failure_threshold: 3,
                        success_threshold: 2,
                        timeout: Duration::from_secs(60),
                    },
                )
            },
            |breaker| {
                rt.block_on(async {
                    // Trigger failures to open the circuit
                    for _ in 0..3 {
                        let _ = breaker
                            .call(|| async { Err::<i32, String>("error".to_string()) })
                            .await;
                    }
                    black_box(breaker.state().await);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_reset(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_reset", |b| {
        b.iter_batched(
            || {
                let breaker = CircuitBreaker::new(
                    "test_breaker",
                    CircuitBreakerConfig {
                        failure_threshold: 2,
                        success_threshold: 2,
                        timeout: Duration::from_secs(60),
                    },
                );
                let rt = tokio::runtime::Runtime::new().unwrap();
                // Open the circuit
                rt.block_on(async {
                    let _r1 = breaker
                        .call(|| async { Err::<i32, String>("error".to_string()) })
                        .await;
                    let _r2 = breaker
                        .call(|| async { Err::<i32, String>("error".to_string()) })
                        .await;
                    let _ = black_box((_r1, _r2));
                });
                breaker
            },
            |breaker| {
                rt.block_on(async {
                    breaker.reset().await;
                    black_box(&breaker);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_state_check_after_failures(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_state_after_failures", |b| {
        b.iter_batched(
            || {
                let breaker = CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default());
                let rt = tokio::runtime::Runtime::new().unwrap();
                // Add some failures
                rt.block_on(async {
                    for _ in 0..3 {
                        let _ = breaker
                            .call(|| async { Err::<i32, String>("error".to_string()) })
                            .await;
                    }
                });
                breaker
            },
            |breaker| {
                rt.block_on(async {
                    black_box(breaker.state().await);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_state_check_after_successes(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_state_after_successes", |b| {
        b.iter_batched(
            || {
                let breaker = CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default());
                let rt = tokio::runtime::Runtime::new().unwrap();
                // Add some successes
                rt.block_on(async {
                    for _ in 0..5 {
                        let _ = breaker.call(|| async { Ok::<i32, String>(42) }).await;
                    }
                });
                breaker
            },
            |breaker| {
                rt.block_on(async {
                    black_box(breaker.state().await);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_concurrent_calls(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_concurrent_success", |b| {
        b.iter_batched(
            || {
                Arc::new(CircuitBreaker::new(
                    "test_breaker",
                    CircuitBreakerConfig::default(),
                ))
            },
            |breaker| {
                rt.block_on(async {
                    let mut handles = Vec::new();

                    for _ in 0..10 {
                        let breaker_clone = Arc::clone(&breaker);
                        let handle = tokio::spawn(async move {
                            breaker_clone.call(|| async { Ok::<i32, String>(42) }).await
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        let _ = handle.await;
                    }

                    black_box(&breaker);
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("circuit_breaker_mixed_operations", |b| {
        b.iter_batched(
            || CircuitBreaker::new("test_breaker", CircuitBreakerConfig::default()),
            |breaker| {
                rt.block_on(async {
                    // Mix of operations
                    for i in 0..10 {
                        if i % 3 == 0 {
                            let _ = breaker
                                .call(|| async { Err::<i32, String>("error".to_string()) })
                                .await;
                        } else {
                            let _ = breaker.call(|| async { Ok::<i32, String>(42) }).await;
                        }
                    }

                    // Query state
                    black_box(breaker.state().await);
                    black_box(breaker.name());
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_failure_thresholds(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_breaker_failure_thresholds");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for threshold in [3, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::new("threshold", threshold),
            &threshold,
            |b, &th| {
                b.iter_batched(
                    || {
                        CircuitBreaker::new(
                            "test_breaker",
                            CircuitBreakerConfig {
                                failure_threshold: th,
                                success_threshold: 2,
                                timeout: Duration::from_secs(60),
                            },
                        )
                    },
                    |breaker| {
                        rt.block_on(async {
                            // Trigger failures up to threshold
                            for _ in 0..th {
                                let _ = breaker
                                    .call(|| async { Err::<i32, String>("error".to_string()) })
                                    .await;
                            }
                            black_box(breaker.state().await);
                        });
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_circuit_breaker_creation,
    bench_circuit_breaker_config_creation,
    bench_call_success,
    bench_call_failure,
    bench_state_queries,
    bench_state_transitions,
    bench_reset,
    bench_state_check_after_failures,
    bench_state_check_after_successes,
    bench_concurrent_calls,
    bench_mixed_operations,
    bench_failure_thresholds
);

criterion_main!(benches);
