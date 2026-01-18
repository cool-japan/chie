#![allow(clippy::unit_arg)]

use chie_core::content_router::{ContentRouter, PeerContentLocation, RoutingStrategy};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_router_creation(c: &mut Criterion) {
    c.bench_function("router_new", |b| b.iter(|| black_box(ContentRouter::new())));
}

fn bench_router_with_strategy(c: &mut Criterion) {
    c.bench_function("router_with_strategy", |b| {
        b.iter(|| {
            black_box(ContentRouter::with_strategy(black_box(
                RoutingStrategy::Closest,
            )))
        })
    });
}

fn bench_register_location(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_location");

    for peer_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                let mut router = ContentRouter::new();
                let mut counter = 0u64;

                b.iter(|| {
                    let peer_id = format!("peer_{}", counter % count);
                    let cid = format!("cid_{}", counter / count);
                    counter += 1;

                    let location = PeerContentLocation {
                        peer_id,
                        cid: cid.clone(),
                        availability_score: 0.9,
                        last_verified: std::time::SystemTime::now(),
                        chunk_count: 100,
                        complete: true,
                    };

                    black_box(router.register_location(black_box(&cid), black_box(location)))
                })
            },
        );
    }

    group.finish();
}

fn bench_unregister_location(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with locations
    for i in 0..100 {
        let peer_id = format!("peer_{}", i);
        let cid = "test_cid";
        let location = PeerContentLocation {
            peer_id,
            cid: cid.to_string(),
            availability_score: 0.9,
            last_verified: std::time::SystemTime::now(),
            chunk_count: 100,
            complete: true,
        };
        router.register_location(cid, location);
    }

    let mut counter = 0u64;

    c.bench_function("unregister_location", |b| {
        b.iter(|| {
            let peer_id = format!("peer_{}", counter % 100);
            counter += 1;
            black_box(router.unregister_location(black_box("test_cid"), black_box(&peer_id)))
        })
    });
}

fn bench_find_peers(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_peers");

    for strategy in [
        RoutingStrategy::Closest,
        RoutingStrategy::MostAvailable,
        RoutingStrategy::LoadBalanced,
        RoutingStrategy::Redundant,
    ]
    .iter()
    {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", strategy)),
            strategy,
            |b, &strategy| {
                let mut router = ContentRouter::with_strategy(strategy);

                // Pre-populate with locations
                for i in 0..50 {
                    let peer_id = format!("peer_{}", i);
                    let location = PeerContentLocation {
                        peer_id,
                        cid: "test_cid".to_string(),
                        availability_score: 0.5 + (i as f64 * 0.01),
                        last_verified: std::time::SystemTime::now(),
                        chunk_count: 100 + i,
                        complete: i % 3 == 0,
                    };
                    router.register_location("test_cid", location);
                }

                b.iter(|| black_box(router.find_peers(black_box("test_cid"), black_box(10))))
            },
        );
    }

    group.finish();
}

fn bench_get_all_peers(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with locations
    for i in 0..100 {
        let peer_id = format!("peer_{}", i);
        let location = PeerContentLocation {
            peer_id,
            cid: "test_cid".to_string(),
            availability_score: 0.9,
            last_verified: std::time::SystemTime::now(),
            chunk_count: 100,
            complete: true,
        };
        router.register_location("test_cid", location);
    }

    c.bench_function("get_all_peers", |b| {
        b.iter(|| black_box(router.get_all_peers(black_box("test_cid"))))
    });
}

fn bench_get_availability(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with locations
    for i in 0..50 {
        let peer_id = format!("peer_{}", i);
        let location = PeerContentLocation {
            peer_id,
            cid: "test_cid".to_string(),
            availability_score: 0.9,
            last_verified: std::time::SystemTime::now(),
            chunk_count: 100,
            complete: i % 3 == 0,
        };
        router.register_location("test_cid", location);
    }

    c.bench_function("get_availability", |b| {
        b.iter(|| black_box(router.get_availability(black_box("test_cid"))))
    });
}

fn bench_has_content(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with locations
    for i in 0..100 {
        let cid = format!("cid_{}", i);
        let location = PeerContentLocation {
            peer_id: "peer_0".to_string(),
            cid: cid.to_string(),
            availability_score: 0.9,
            last_verified: std::time::SystemTime::now(),
            chunk_count: 100,
            complete: true,
        };
        router.register_location(&cid, location);
    }

    c.bench_function("has_content", |b| {
        b.iter(|| black_box(router.has_content(black_box("cid_50"))))
    });
}

fn bench_find_popular_content(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with varying peer counts
    for i in 0..100 {
        let cid = format!("cid_{}", i);
        let peer_count = (i % 20) + 1;
        for j in 0..peer_count {
            let peer_id = format!("peer_{}_{}", i, j);
            let location = PeerContentLocation {
                peer_id,
                cid: cid.clone(),
                availability_score: 0.9,
                last_verified: std::time::SystemTime::now(),
                chunk_count: 100,
                complete: true,
            };
            router.register_location(&cid, location);
        }
    }

    c.bench_function("find_popular_content", |b| {
        b.iter(|| black_box(router.find_popular_content(black_box(10))))
    });
}

fn bench_find_rare_content(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with varying peer counts
    for i in 0..100 {
        let cid = format!("cid_{}", i);
        let peer_count = (i % 20) + 1;
        for j in 0..peer_count {
            let peer_id = format!("peer_{}_{}", i, j);
            let location = PeerContentLocation {
                peer_id,
                cid: cid.clone(),
                availability_score: 0.9,
                last_verified: std::time::SystemTime::now(),
                chunk_count: 100,
                complete: true,
            };
            router.register_location(&cid, location);
        }
    }

    c.bench_function("find_rare_content", |b| {
        b.iter(|| black_box(router.find_rare_content(black_box(10))))
    });
}

fn bench_get_statistics(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with data
    for i in 0..100 {
        let cid = format!("cid_{}", i);
        for j in 0..10 {
            let peer_id = format!("peer_{}_{}", i, j);
            let location = PeerContentLocation {
                peer_id,
                cid: cid.clone(),
                availability_score: 0.9,
                last_verified: std::time::SystemTime::now(),
                chunk_count: 100,
                complete: true,
            };
            router.register_location(&cid, location);
        }
    }

    // Trigger some cache operations
    for i in 0..10 {
        let cid = format!("cid_{}", i);
        let _ = router.find_peers(&cid, 5);
    }

    c.bench_function("get_statistics", |b| {
        b.iter(|| black_box(router.get_statistics()))
    });
}

fn bench_clear_cache(c: &mut Criterion) {
    c.bench_function("clear_cache", |b| {
        b.iter_batched(
            || {
                let mut router = ContentRouter::new();
                // Pre-populate cache by doing searches
                for i in 0..50 {
                    let cid = format!("cid_{}", i);
                    let location = PeerContentLocation {
                        peer_id: "peer_0".to_string(),
                        cid: cid.clone(),
                        availability_score: 0.9,
                        last_verified: std::time::SystemTime::now(),
                        chunk_count: 100,
                        complete: true,
                    };
                    router.register_location(&cid, location);
                    let _ = router.find_peers(&cid, 5);
                }
                router
            },
            |mut router| black_box(router.clear_cache()),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_find_complete_peers(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    // Pre-populate with mix of complete and incomplete
    for i in 0..50 {
        let peer_id = format!("peer_{}", i);
        let location = PeerContentLocation {
            peer_id,
            cid: "test_cid".to_string(),
            availability_score: 0.9,
            last_verified: std::time::SystemTime::now(),
            chunk_count: 100,
            complete: i % 2 == 0,
        };
        router.register_location("test_cid", location);
    }

    c.bench_function("find_complete_peers", |b| {
        b.iter(|| black_box(router.find_complete_peers(black_box("test_cid"))))
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    c.bench_function("mixed_operations", |b| {
        let mut router = ContentRouter::new();
        let mut counter = 0u64;

        // Pre-populate
        for i in 0..50 {
            let cid = format!("cid_{}", i);
            let location = PeerContentLocation {
                peer_id: format!("peer_{}", i),
                cid: cid.clone(),
                availability_score: 0.9,
                last_verified: std::time::SystemTime::now(),
                chunk_count: 100,
                complete: true,
            };
            router.register_location(&cid, location);
        }

        b.iter(|| {
            counter += 1;
            let cid = format!("cid_{}", counter % 50);

            // Mix of operations
            match counter % 5 {
                0 => {
                    let _ = router.find_peers(&cid, 5);
                }
                1 => {
                    let _ = router.get_availability(&cid);
                }
                2 => {
                    let _ = router.has_content(&cid);
                }
                3 => {
                    let _ = router.get_all_peers(&cid);
                }
                _ => {
                    let _ = router.find_complete_peers(&cid);
                }
            }

            // Occasionally get stats
            if counter % 10 == 0 {
                let _ = router.get_statistics();
            }

            black_box(())
        })
    });
}

fn bench_set_strategy(c: &mut Criterion) {
    let mut router = ContentRouter::new();
    let strategies = [
        RoutingStrategy::Closest,
        RoutingStrategy::MostAvailable,
        RoutingStrategy::LoadBalanced,
        RoutingStrategy::Redundant,
    ];
    let mut idx = 0;

    c.bench_function("set_strategy", |b| {
        b.iter(|| {
            let strategy = strategies[idx % strategies.len()];
            idx += 1;
            black_box(router.set_strategy(black_box(strategy)))
        })
    });
}

fn bench_set_cache_ttl(c: &mut Criterion) {
    let mut router = ContentRouter::new();

    c.bench_function("set_cache_ttl", |b| {
        b.iter(|| black_box(router.set_cache_ttl(black_box(Duration::from_secs(600)))))
    });
}

criterion_group!(
    benches,
    bench_router_creation,
    bench_router_with_strategy,
    bench_register_location,
    bench_unregister_location,
    bench_find_peers,
    bench_get_all_peers,
    bench_get_availability,
    bench_has_content,
    bench_find_popular_content,
    bench_find_rare_content,
    bench_get_statistics,
    bench_clear_cache,
    bench_find_complete_peers,
    bench_mixed_operations,
    bench_set_strategy,
    bench_set_cache_ttl,
);
criterion_main!(benches);
