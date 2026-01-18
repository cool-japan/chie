//! Benchmarks for resilience features (circuit breaker, retry logic).

use chie_core::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use chie_core::utils::{RetryConfig, exponential_backoff};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_exponential_backoff(c: &mut Criterion) {
    c.bench_function("exponential_backoff_without_jitter", |b| {
        b.iter(|| {
            for attempt in 0..10 {
                black_box(exponential_backoff(attempt, 100, 10_000, false));
            }
        });
    });

    c.bench_function("exponential_backoff_with_jitter", |b| {
        b.iter(|| {
            for attempt in 0..10 {
                black_box(exponential_backoff(attempt, 100, 10_000, true));
            }
        });
    });
}

fn bench_retry_config(c: &mut Criterion) {
    let config = RetryConfig::default();

    c.bench_function("retry_config_delay_calculation", |b| {
        b.iter(|| {
            for attempt in 0..10 {
                black_box(config.delay_for_attempt(attempt));
            }
        });
    });
}

fn bench_circuit_breaker_success(c: &mut Criterion) {
    c.bench_function("circuit_breaker_successful_call", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                let config = CircuitBreakerConfig {
                    failure_threshold: 5,
                    timeout: Duration::from_secs(60),
                    success_threshold: 2,
                };
                let breaker = CircuitBreaker::new("bench", config);

                // Successful call
                let _ = breaker.call(|| async { Ok::<_, String>("success") }).await;
            });
        });
    });
}

fn bench_circuit_breaker_failure(c: &mut Criterion) {
    c.bench_function("circuit_breaker_failed_call", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                let config = CircuitBreakerConfig {
                    failure_threshold: 5,
                    timeout: Duration::from_secs(60),
                    success_threshold: 2,
                };
                let breaker = CircuitBreaker::new("bench", config);

                // Failed call
                let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
            });
        });
    });
}

fn bench_circuit_breaker_open_rejection(c: &mut Criterion) {
    c.bench_function("circuit_breaker_open_rejection", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                let config = CircuitBreakerConfig {
                    failure_threshold: 2,
                    timeout: Duration::from_secs(60),
                    success_threshold: 2,
                };
                let breaker = CircuitBreaker::new("bench", config);

                // Open the circuit
                for _ in 0..2 {
                    let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
                }

                // This should be rejected quickly
                let _ = breaker.call(|| async { Ok::<_, String>("success") }).await;
            });
        });
    });
}

criterion_group!(
    benches,
    bench_exponential_backoff,
    bench_retry_config,
    bench_circuit_breaker_success,
    bench_circuit_breaker_failure,
    bench_circuit_breaker_open_rejection
);
criterion_main!(benches);
