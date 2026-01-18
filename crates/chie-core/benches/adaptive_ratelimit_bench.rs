use chie_core::adaptive_ratelimit::{AdaptiveRateLimitConfig, AdaptiveRateLimiter};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_rate_limiter_creation(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_create_default", |b| {
        b.iter(|| {
            black_box(AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default()));
        });
    });

    c.bench_function("adaptive_ratelimit_create_custom", |b| {
        let config = AdaptiveRateLimitConfig {
            base_rate: 1000,
            base_window_secs: 60,
            min_rate: 10,
            max_rate: 10000,
            reputation_multiplier: 3.0,
            burst_multiplier: 2.0,
            cleanup_interval_secs: 300,
        };
        b.iter(|| {
            black_box(AdaptiveRateLimiter::new(config.clone()));
        });
    });
}

fn bench_check_rate_limit(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_ratelimit_check");

    for peer_count in [1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("new_peer", peer_count),
            &peer_count,
            |b, &count| {
                let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());
                let mut peer_idx = 0;

                b.iter(|| {
                    let peer_id = format!("peer_{}", peer_idx % count);
                    peer_idx += 1;
                    black_box(limiter.check_rate_limit(&peer_id, 0.8));
                });
            },
        );
    }

    group.finish();
}

fn bench_check_with_existing_peers(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_check_existing", |b| {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        // Pre-populate with peers
        for i in 0..100 {
            let peer_id = format!("peer_{}", i);
            limiter.check_rate_limit(&peer_id, 0.5 + (i as f64 / 200.0));
        }

        let mut idx = 0;
        b.iter(|| {
            let peer_id = format!("peer_{}", idx % 100);
            idx += 1;
            black_box(limiter.check_rate_limit(&peer_id, 0.7));
        });
    });
}

fn bench_get_limit(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_ratelimit_get_limit");

    for reputation in [0.0, 0.25, 0.5, 0.75, 1.0] {
        group.bench_with_input(
            BenchmarkId::new("reputation", (reputation * 100.0) as u32),
            &reputation,
            |b, &rep| {
                let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());
                let peer_id = "test_peer";

                // Initialize peer
                limiter.check_rate_limit(peer_id, rep);

                b.iter(|| {
                    black_box(limiter.get_limit(peer_id, rep));
                });
            },
        );
    }

    group.finish();
}

fn bench_get_remaining(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_get_remaining", |b| {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        // Pre-populate
        for i in 0..100 {
            let peer_id = format!("peer_{}", i);
            limiter.check_rate_limit(&peer_id, 0.6);
        }

        let mut idx = 0;
        b.iter(|| {
            let peer_id = format!("peer_{}", idx % 100);
            idx += 1;
            black_box(limiter.get_remaining(&peer_id, 0.6));
        });
    });
}

fn bench_get_reset_time(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_get_reset_time", |b| {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        // Pre-populate
        for i in 0..100 {
            let peer_id = format!("peer_{}", i);
            limiter.check_rate_limit(&peer_id, 0.6);
        }

        let mut idx = 0;
        b.iter(|| {
            let peer_id = format!("peer_{}", idx % 100);
            idx += 1;
            black_box(limiter.get_reset_time(&peer_id));
        });
    });
}

fn bench_reset_peer(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_reset_peer", |b| {
        b.iter_batched(
            || {
                let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());
                for i in 0..100 {
                    let peer_id = format!("peer_{}", i);
                    limiter.check_rate_limit(&peer_id, 0.5);
                }
                limiter
            },
            |mut limiter| {
                limiter.reset_peer("peer_50");
                black_box(&limiter);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_clear(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_clear", |b| {
        b.iter_batched(
            || {
                let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());
                for i in 0..1000 {
                    let peer_id = format!("peer_{}", i);
                    limiter.check_rate_limit(&peer_id, 0.5);
                }
                limiter
            },
            |mut limiter| {
                limiter.clear();
                black_box(&limiter);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_peer_stats(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_peer_stats", |b| {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        // Pre-populate
        for i in 0..100 {
            let peer_id = format!("peer_{}", i);
            limiter.check_rate_limit(&peer_id, 0.5);
        }

        let mut idx = 0;
        b.iter(|| {
            let peer_id = format!("peer_{}", idx % 100);
            idx += 1;
            black_box(limiter.get_peer_stats(&peer_id));
        });
    });
}

fn bench_global_stats(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_global_stats", |b| {
        let limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        b.iter(|| {
            black_box(limiter.get_global_stats());
        });
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    c.bench_function("adaptive_ratelimit_mixed_operations", |b| {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default());

        let mut idx = 0;
        b.iter(|| {
            let peer_id = format!("peer_{}", idx % 50);
            let reputation = 0.5 + (idx % 10) as f64 / 20.0;

            // Mix of operations
            match idx % 8 {
                0..=4 => {
                    black_box(limiter.check_rate_limit(&peer_id, reputation));
                }
                5 => {
                    black_box(limiter.get_remaining(&peer_id, reputation));
                }
                6 => {
                    black_box(limiter.get_limit(&peer_id, reputation));
                }
                _ => {
                    black_box(limiter.get_reset_time(&peer_id));
                }
            }

            idx += 1;
        });
    });
}

criterion_group!(
    benches,
    bench_rate_limiter_creation,
    bench_check_rate_limit,
    bench_check_with_existing_peers,
    bench_get_limit,
    bench_get_remaining,
    bench_get_reset_time,
    bench_reset_peer,
    bench_clear,
    bench_peer_stats,
    bench_global_stats,
    bench_mixed_operations
);

criterion_main!(benches);
