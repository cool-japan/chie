use chie_core::{BandwidthLimiter, PeerRateLimiter, RateLimitConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;

// Benchmark config creation
fn bench_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit/config");

    group.bench_function("default", |b| {
        b.iter(|| black_box(RateLimitConfig::default()))
    });

    group.bench_function("with_rates", |b| {
        b.iter(|| black_box(RateLimitConfig::with_rates(100.0, 50.0)))
    });

    group.bench_function("symmetric", |b| {
        b.iter(|| black_box(RateLimitConfig::symmetric(100.0)))
    });

    group.bench_function("unlimited", |b| {
        b.iter(|| black_box(RateLimitConfig::unlimited()))
    });

    group.finish();
}

// Benchmark limiter creation
fn bench_limiter_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit/limiter_creation");

    group.bench_function("unlimited", |b| {
        let config = RateLimitConfig::unlimited();
        b.iter(|| black_box(BandwidthLimiter::new(config.clone())))
    });

    group.bench_function("limited_100mbps", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        b.iter(|| black_box(BandwidthLimiter::new(config.clone())))
    });

    group.bench_function("asymmetric", |b| {
        let config = RateLimitConfig::with_rates(100.0, 50.0);
        b.iter(|| black_box(BandwidthLimiter::new(config.clone())))
    });

    group.finish();
}

// Benchmark upload limiting (unlimited for speed)
fn bench_limit_upload(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/limit_upload");

    // Unlimited (should be fast)
    group.bench_function("unlimited_1MB", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.limit_upload(black_box(1_000_000)).await }))
    });

    // Below min_transfer_size (should be fast)
    group.bench_function("below_min_512B", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.limit_upload(black_box(512)).await }))
    });

    group.finish();
}

// Benchmark download limiting
fn bench_limit_download(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/limit_download");

    group.bench_function("unlimited_1MB", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.limit_download(black_box(1_000_000)).await }))
    });

    group.bench_function("below_min_512B", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.limit_download(black_box(512)).await }))
    });

    group.finish();
}

// Benchmark stats recording
fn bench_record_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/record_stats");

    group.bench_function("record_upload", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.record_upload(black_box(1_000_000)).await }))
    });

    group.bench_function("record_download", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { limiter.record_download(black_box(1_000_000)).await }))
    });

    group.bench_function("get_stats", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| rt.block_on(async { black_box(limiter.stats().await) }))
    });

    group.finish();
}

// Benchmark accessor methods
fn bench_accessors(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit/accessors");

    group.bench_function("available_upload", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| black_box(limiter.available_upload()))
    });

    group.bench_function("available_download", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| black_box(limiter.available_download()))
    });

    group.bench_function("is_enabled", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| black_box(limiter.is_enabled()))
    });

    group.bench_function("upload_rate", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| black_box(limiter.upload_rate()))
    });

    group.bench_function("download_rate", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| black_box(limiter.download_rate()))
    });

    group.finish();
}

// Benchmark peer rate limiter
fn bench_peer_limiter_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit/peer_limiter");

    group.bench_function("creation", |b| {
        let config = RateLimitConfig::symmetric(100.0);
        b.iter(|| black_box(PeerRateLimiter::new(config.clone(), 0.25)))
    });

    group.finish();
}

// Benchmark peer operations
fn bench_peer_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/peer_operations");

    group.bench_function("get_peer_limiter_new", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        let mut counter = 0u64;
        b.iter(|| {
            let peer_id = format!("peer{}", counter);
            counter += 1;
            rt.block_on(async { black_box(peer_limiter.get_peer_limiter(&peer_id).await) })
        })
    });

    group.bench_function("get_peer_limiter_cached", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| rt.block_on(async { black_box(peer_limiter.get_peer_limiter("peer1").await) }))
    });

    group.bench_function("peer_count", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| rt.block_on(async { black_box(peer_limiter.peer_count().await) }))
    });

    group.bench_function("remove_peer", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        let mut counter = 0u64;
        b.iter(|| {
            let peer_id = format!("peer{}", counter);
            counter += 1;
            rt.block_on(async { peer_limiter.remove_peer(&peer_id).await })
        })
    });

    group.bench_function("global_stats", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| rt.block_on(async { black_box(peer_limiter.global_stats().await) }))
    });

    group.finish();
}

// Benchmark peer upload/download limiting
fn bench_peer_limit_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/peer_limit");

    group.bench_function("limit_upload_1MB", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| {
            rt.block_on(async {
                peer_limiter
                    .limit_upload("peer1", black_box(1_000_000))
                    .await
            })
        })
    });

    group.bench_function("limit_download_1MB", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| {
            rt.block_on(async {
                peer_limiter
                    .limit_download("peer1", black_box(1_000_000))
                    .await
            })
        })
    });

    group.finish();
}

// Benchmark with different peer counts
fn bench_peer_scale(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/peer_scale");

    for peer_count in [1, 5, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                let config = RateLimitConfig::unlimited();
                let peer_limiter = PeerRateLimiter::new(config, 0.25);

                // Pre-populate with peers
                rt.block_on(async {
                    for i in 0..count {
                        let _ = peer_limiter.get_peer_limiter(&format!("peer{}", i)).await;
                    }
                });

                b.iter(|| {
                    rt.block_on(async {
                        // Get a random peer's stats
                        let peer_id = format!("peer{}", count / 2);
                        black_box(peer_limiter.peer_stats(&peer_id).await)
                    })
                })
            },
        );
    }

    group.finish();
}

// Benchmark mixed operations
fn bench_mixed_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("ratelimit/mixed");

    group.bench_function("bandwidth_limiter_workflow", |b| {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);
        b.iter(|| {
            rt.block_on(async {
                limiter.limit_upload(1_000).await;
                limiter.limit_download(1_000).await;
                limiter.record_upload(500).await;
                limiter.record_download(500).await;
                black_box(limiter.stats().await);
            })
        })
    });

    group.bench_function("peer_limiter_workflow", |b| {
        let config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(config, 0.25);
        b.iter(|| {
            rt.block_on(async {
                let _limiter = peer_limiter.get_peer_limiter("peer1").await;
                peer_limiter.limit_upload("peer1", 1_000).await;
                peer_limiter.limit_download("peer1", 1_000).await;
                black_box(peer_limiter.peer_stats("peer1").await);
                black_box(peer_limiter.global_stats().await);
            })
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_limiter_creation,
    bench_limit_upload,
    bench_limit_download,
    bench_record_stats,
    bench_accessors,
    bench_peer_limiter_creation,
    bench_peer_operations,
    bench_peer_limit_operations,
    bench_peer_scale,
    bench_mixed_operations,
);

criterion_main!(benches);
