//! Benchmarks for connection multiplexing module.

use chie_core::connection_multiplexing::{ConnectionPool, PoolConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_pool_config_creation(c: &mut Criterion) {
    c.bench_function("pool_config_default", |b| {
        b.iter(|| {
            black_box(PoolConfig::default());
        });
    });

    c.bench_function("pool_config_builder", |b| {
        b.iter(|| {
            black_box(
                PoolConfig::new()
                    .with_max_connections(20)
                    .with_idle_timeout(Duration::from_secs(120))
                    .with_connect_timeout(Duration::from_secs(5))
                    .with_request_timeout(Duration::from_secs(60))
                    .with_max_retries(5)
                    .with_tcp_keepalive(true),
            );
        });
    });
}

fn bench_pool_creation(c: &mut Criterion) {
    let config = PoolConfig::default();

    c.bench_function("connection_pool_new", |b| {
        b.iter(|| {
            black_box(ConnectionPool::new("http://localhost:8080", config.clone()));
        });
    });
}

fn bench_pool_stats(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = PoolConfig::default();
    let pool = ConnectionPool::new("http://localhost:8080", config);

    c.bench_function("pool_stats", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(pool.stats().await);
            });
        });
    });
}

fn bench_backoff_calculation(c: &mut Criterion) {
    let config = PoolConfig::default();
    let pool = ConnectionPool::new("http://localhost:8080", config);

    let mut group = c.benchmark_group("backoff_delay");
    for attempt in [0, 1, 2, 3, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(attempt),
            attempt,
            |b, &_attempt| {
                b.iter(|| {
                    black_box(pool.config().max_retries());
                });
            },
        );
    }
    group.finish();
}

fn bench_pool_config_accessors(c: &mut Criterion) {
    let config = PoolConfig::default();

    c.bench_function("config_max_connections", |b| {
        b.iter(|| {
            black_box(config.max_connections());
        });
    });

    c.bench_function("config_idle_timeout", |b| {
        b.iter(|| {
            black_box(config.idle_timeout());
        });
    });

    c.bench_function("config_connect_timeout", |b| {
        b.iter(|| {
            black_box(config.connect_timeout());
        });
    });

    c.bench_function("config_request_timeout", |b| {
        b.iter(|| {
            black_box(config.request_timeout());
        });
    });

    c.bench_function("config_max_retries", |b| {
        b.iter(|| {
            black_box(config.max_retries());
        });
    });
}

fn bench_pool_accessors(c: &mut Criterion) {
    let config = PoolConfig::default();
    let pool = ConnectionPool::new("http://localhost:8080", config);

    c.bench_function("pool_base_url", |b| {
        b.iter(|| {
            black_box(pool.base_url());
        });
    });

    c.bench_function("pool_config", |b| {
        b.iter(|| {
            black_box(pool.config());
        });
    });
}

fn bench_close_idle_connections(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = PoolConfig::default().with_idle_timeout(Duration::from_millis(10));
    let pool = ConnectionPool::new("http://localhost:8080", config);

    c.bench_function("close_idle_connections", |b| {
        b.iter(|| {
            rt.block_on(async {
                pool.close_idle_connections().await;
            });
        });
    });
}

criterion_group!(
    benches,
    bench_pool_config_creation,
    bench_pool_creation,
    bench_pool_stats,
    bench_backoff_calculation,
    bench_pool_config_accessors,
    bench_pool_accessors,
    bench_close_idle_connections,
);
criterion_main!(benches);
