#![allow(clippy::unit_arg)]

use chie_core::orchestrator::{OrchestratorConfig, RequestOrchestrator, RetrievalStrategy};
use chie_core::qos::QosConfig;
use chie_core::utils::RetryConfig;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_orchestrator_creation(c: &mut Criterion) {
    c.bench_function("orchestrator_new", |b| {
        b.iter(|| {
            let config = OrchestratorConfig::default();
            black_box(RequestOrchestrator::new(black_box(config)))
        })
    });
}

fn bench_orchestrator_custom_config(c: &mut Criterion) {
    c.bench_function("orchestrator_custom_config", |b| {
        b.iter(|| {
            let config = OrchestratorConfig {
                max_concurrent: black_box(200),
                request_timeout_ms: black_box(60_000),
                retry_config: black_box(RetryConfig::aggressive()),
                enable_caching: black_box(true),
                cache_ttl_secs: black_box(600),
                max_peers_per_request: black_box(10),
                min_reputation: black_box(0.5),
                enable_qos: black_box(true),
                qos_config: black_box(QosConfig::default()),
            };
            black_box(RequestOrchestrator::new(black_box(config)))
        })
    });
}

fn bench_get_stats(c: &mut Criterion) {
    let config = OrchestratorConfig::default();
    let orchestrator = RequestOrchestrator::new(config);

    c.bench_function("get_stats", |b| b.iter(|| black_box(orchestrator.stats())));
}

fn bench_reset_stats(c: &mut Criterion) {
    let config = OrchestratorConfig::default();
    let orchestrator = RequestOrchestrator::new(config);

    c.bench_function("reset_stats", |b| {
        b.iter(|| black_box(orchestrator.reset_stats()))
    });
}

fn bench_clear_cache(c: &mut Criterion) {
    let config = OrchestratorConfig::default();
    let orchestrator = RequestOrchestrator::new(config);

    c.bench_function("clear_cache", |b| {
        b.iter(|| black_box(orchestrator.clear_cache()))
    });
}

fn bench_config_default(c: &mut Criterion) {
    c.bench_function("config_default", |b| {
        b.iter(|| black_box(OrchestratorConfig::default()))
    });
}

fn bench_config_construction(c: &mut Criterion) {
    c.bench_function("config_construction", |b| {
        b.iter(|| {
            black_box(OrchestratorConfig {
                max_concurrent: black_box(100),
                request_timeout_ms: black_box(30_000),
                retry_config: black_box(RetryConfig::default()),
                enable_caching: black_box(true),
                cache_ttl_secs: black_box(300),
                max_peers_per_request: black_box(5),
                min_reputation: black_box(0.3),
                enable_qos: black_box(true),
                qos_config: black_box(QosConfig::default()),
            })
        })
    });
}

fn bench_retrieval_strategy_comparison(c: &mut Criterion) {
    c.bench_function("strategy_comparison", |b| {
        let strategies = [
            RetrievalStrategy::BestEffort,
            RetrievalStrategy::Strict,
            RetrievalStrategy::Redundant,
            RetrievalStrategy::Fastest,
        ];
        let mut idx = 0;

        b.iter(|| {
            let strategy = strategies[idx % strategies.len()];
            idx += 1;
            black_box(strategy)
        })
    });
}

fn bench_config_with_retries(c: &mut Criterion) {
    c.bench_function("config_with_retries", |b| {
        b.iter(|| {
            let retry = RetryConfig::builder()
                .max_attempts(black_box(5))
                .base_delay_ms(black_box(100))
                .max_delay_ms(black_box(10_000))
                .with_jitter(black_box(true))
                .build();

            black_box(OrchestratorConfig {
                max_concurrent: black_box(100),
                request_timeout_ms: black_box(30_000),
                retry_config: black_box(retry),
                enable_caching: black_box(true),
                cache_ttl_secs: black_box(300),
                max_peers_per_request: black_box(5),
                min_reputation: black_box(0.3),
                enable_qos: black_box(true),
                qos_config: black_box(QosConfig::default()),
            })
        })
    });
}

fn bench_multiple_orchestrators(c: &mut Criterion) {
    c.bench_function("multiple_orchestrators", |b| {
        b.iter(|| {
            let orchestrators: Vec<_> = (0..10)
                .map(|_| {
                    let config = OrchestratorConfig::default();
                    RequestOrchestrator::new(config)
                })
                .collect();
            black_box(orchestrators)
        })
    });
}

fn bench_stats_operations(c: &mut Criterion) {
    let config = OrchestratorConfig::default();
    let orchestrator = RequestOrchestrator::new(config);

    c.bench_function("stats_operations", |b| {
        b.iter(|| {
            let stats = orchestrator.stats();
            let _ = stats.success_rate();
            let _ = stats.cache_hit_rate();
            black_box(stats)
        })
    });
}

fn bench_config_variations(c: &mut Criterion) {
    c.bench_function("config_variations", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            idx += 1;
            let config = OrchestratorConfig {
                max_concurrent: black_box(50 + (idx % 200) as usize),
                request_timeout_ms: black_box(10_000 + (idx % 50_000)),
                retry_config: black_box(if idx % 2 == 0 {
                    RetryConfig::aggressive()
                } else {
                    RetryConfig::conservative()
                }),
                enable_caching: black_box(idx % 3 != 0),
                cache_ttl_secs: black_box(60 + (idx % 540)),
                max_peers_per_request: black_box(3 + (idx % 7) as usize),
                min_reputation: black_box(0.1 + ((idx % 7) as f64 * 0.1)),
                enable_qos: black_box(idx % 4 != 0),
                qos_config: black_box(QosConfig::default()),
            };
            black_box(config)
        })
    });
}

fn bench_cache_management(c: &mut Criterion) {
    c.bench_function("cache_management", |b| {
        let config = OrchestratorConfig::default();
        let orchestrator = RequestOrchestrator::new(config);
        let mut counter = 0u64;

        b.iter(|| {
            counter += 1;

            // Occasionally clear cache
            if counter % 100 == 0 {
                orchestrator.clear_cache();
            }

            // Occasionally reset stats
            if counter % 50 == 0 {
                orchestrator.reset_stats();
            }

            // Frequently get stats
            let _ = orchestrator.stats();

            black_box(())
        })
    });
}

criterion_group!(
    benches,
    bench_orchestrator_creation,
    bench_orchestrator_custom_config,
    bench_get_stats,
    bench_reset_stats,
    bench_clear_cache,
    bench_config_default,
    bench_config_construction,
    bench_retrieval_strategy_comparison,
    bench_config_with_retries,
    bench_multiple_orchestrators,
    bench_stats_operations,
    bench_config_variations,
    bench_cache_management,
);
criterion_main!(benches);
