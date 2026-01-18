//! Benchmarks for HTTP connection pooling.

use chie_core::http_pool::{HttpClientPool, HttpConfig, HttpError};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_http_config_creation(c: &mut Criterion) {
    c.bench_function("http_config_default", |b| {
        b.iter(|| black_box(HttpConfig::default()));
    });

    c.bench_function("http_config_builder", |b| {
        b.iter(|| {
            black_box(
                HttpConfig::new()
                    .with_connect_timeout(10_000)
                    .with_request_timeout(60_000)
                    .with_pool_size(20, 100),
            )
        });
    });
}

fn bench_http_pool_creation(c: &mut Criterion) {
    let config = HttpConfig::default();

    c.bench_function("http_pool_creation", |b| {
        b.iter(|| black_box(HttpClientPool::new(config.clone())));
    });

    c.bench_function("http_pool_default", |b| {
        b.iter(|| black_box(HttpClientPool::default()));
    });
}

fn bench_http_pool_accessors(c: &mut Criterion) {
    let pool = HttpClientPool::default();

    c.bench_function("http_pool_client_access", |b| {
        b.iter(|| black_box(pool.client()));
    });

    c.bench_function("http_pool_config_access", |b| {
        b.iter(|| black_box(pool.config()));
    });
}

fn bench_http_error_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_error_checks");

    let errors = vec![
        ("timeout", HttpError::Timeout),
        ("rate_limit", HttpError::RateLimitExceeded),
        (
            "request_failed",
            HttpError::RequestFailed("test".to_string()),
        ),
        ("invalid_url", HttpError::InvalidUrl("test".to_string())),
    ];

    for (name, error) in &errors {
        group.bench_with_input(BenchmarkId::new("is_retryable", name), error, |b, e| {
            b.iter(|| black_box(e.is_retryable()));
        });

        group.bench_with_input(BenchmarkId::new("is_timeout", name), error, |b, e| {
            b.iter(|| black_box(e.is_timeout()));
        });

        group.bench_with_input(BenchmarkId::new("is_rate_limit", name), error, |b, e| {
            b.iter(|| black_box(e.is_rate_limit()));
        });
    }

    group.finish();
}

fn bench_http_config_builder_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_config_builders");

    group.bench_function("connect_timeout", |b| {
        b.iter(|| black_box(HttpConfig::new().with_connect_timeout(5_000)));
    });

    group.bench_function("request_timeout", |b| {
        b.iter(|| black_box(HttpConfig::new().with_request_timeout(30_000)));
    });

    group.bench_function("pool_size", |b| {
        b.iter(|| black_box(HttpConfig::new().with_pool_size(10, 50)));
    });

    group.bench_function("full_chain", |b| {
        b.iter(|| {
            black_box(
                HttpConfig::new()
                    .with_connect_timeout(5_000)
                    .with_request_timeout(30_000)
                    .with_pool_size(10, 50),
            )
        });
    });

    group.finish();
}

fn bench_http_error_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_error_creation");

    group.bench_function("timeout", |b| {
        b.iter(|| black_box(HttpError::Timeout));
    });

    group.bench_function("rate_limit", |b| {
        b.iter(|| black_box(HttpError::RateLimitExceeded));
    });

    group.bench_function("request_failed", |b| {
        b.iter(|| black_box(HttpError::RequestFailed("test error".to_string())));
    });

    group.bench_function("invalid_url", |b| {
        b.iter(|| black_box(HttpError::InvalidUrl("http://invalid".to_string())));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_http_config_creation,
    bench_http_pool_creation,
    bench_http_pool_accessors,
    bench_http_error_checks,
    bench_http_config_builder_patterns,
    bench_http_error_creation,
);
criterion_main!(benches);
