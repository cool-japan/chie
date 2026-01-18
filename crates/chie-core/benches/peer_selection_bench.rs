use chie_core::{PeerCandidate, PeerSelector, SelectionStrategy};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::SystemTime;

fn create_test_selector() -> PeerSelector {
    PeerSelector::new()
}

fn create_test_candidates(count: usize) -> Vec<PeerCandidate> {
    (0..count)
        .map(|i| PeerCandidate {
            peer_id: format!("peer-{}", i),
            reputation_score: (i as f64 / count as f64) * 0.5 + 0.25,
            network_health: (i as f64 / count as f64) * 0.8 + 0.1,
            current_load: (count - i) as f64 / count as f64,
            latency_ms: 10.0 + (i % 100) as f64,
            bandwidth_mbps: 50.0 + (i % 50) as f64,
            distance_km: Some((i % 1000) as f64),
            last_seen: SystemTime::now(),
        })
        .collect()
}

fn bench_add_candidate(c: &mut Criterion) {
    let mut selector = create_test_selector();
    let candidates = create_test_candidates(1000);

    c.bench_function("peer_selection_add_candidate", |b| {
        let mut idx = 0;
        b.iter(|| {
            selector.add_candidate(black_box(candidates[idx % candidates.len()].clone()));
            idx += 1;
        });
    });
}

fn bench_select_best(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_selection_select_best");

    for size in [10, 50, 100, 500].iter() {
        let mut selector = create_test_selector();
        let candidates = create_test_candidates(*size);
        for candidate in candidates {
            selector.add_candidate(candidate);
        }

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(selector.select_best());
            });
        });
    }
    group.finish();
}

fn bench_select_top_n(c: &mut Criterion) {
    let mut selector = create_test_selector();
    let candidates = create_test_candidates(100);
    for candidate in candidates {
        selector.add_candidate(candidate);
    }

    let mut group = c.benchmark_group("peer_selection_select_top_n");
    for n in [5, 10, 20, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            b.iter(|| {
                black_box(selector.select_top_n(black_box(n)));
            });
        });
    }
    group.finish();
}

fn bench_get_qualified_peers(c: &mut Criterion) {
    let mut selector = create_test_selector();
    let candidates = create_test_candidates(100);
    for candidate in candidates {
        selector.add_candidate(candidate);
    }

    c.bench_function("peer_selection_get_qualified_peers", |b| {
        b.iter(|| {
            black_box(selector.get_qualified_peers(black_box(0.5)));
        });
    });
}

fn bench_strategy_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_selection_strategy");

    let strategies = vec![
        SelectionStrategy::Best,
        SelectionStrategy::WeightedRandom,
        SelectionStrategy::RoundRobin,
        SelectionStrategy::LeastLoaded,
        SelectionStrategy::LowestLatency,
    ];

    for strategy in strategies {
        let mut selector = create_test_selector();
        selector.set_strategy(strategy);
        let candidates = create_test_candidates(50);
        for candidate in candidates {
            selector.add_candidate(candidate);
        }

        group.bench_with_input(
            BenchmarkId::new("strategy", format!("{:?}", strategy)),
            &strategy,
            |b, _| {
                b.iter(|| {
                    black_box(selector.select_best());
                });
            },
        );
    }
    group.finish();
}

fn bench_remove_candidate(c: &mut Criterion) {
    let mut selector = create_test_selector();
    let candidates = create_test_candidates(1000);
    for candidate in candidates.clone() {
        selector.add_candidate(candidate);
    }

    c.bench_function("peer_selection_remove_candidate", |b| {
        let mut idx = 0;
        b.iter(|| {
            selector.remove_candidate(black_box(&candidates[idx % candidates.len()].peer_id));
            idx += 1;
        });
    });
}

fn bench_statistics(c: &mut Criterion) {
    let mut selector = create_test_selector();
    let candidates = create_test_candidates(100);
    for candidate in candidates {
        selector.add_candidate(candidate);
    }

    // Perform some selections to generate statistics
    for _ in 0..50 {
        let _ = selector.select_best();
    }

    c.bench_function("peer_selection_get_statistics", |b| {
        b.iter(|| {
            black_box(selector.get_statistics());
        });
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    c.bench_function("peer_selection_mixed_operations", |b| {
        let mut selector = create_test_selector();
        let candidates = create_test_candidates(50);

        b.iter(|| {
            // Add candidates
            for candidate in candidates.iter().take(10) {
                selector.add_candidate(candidate.clone());
            }

            // Select best
            let _ = selector.select_best();

            // Get top N
            let _ = selector.select_top_n(5);

            // Get qualified
            let _ = selector.get_qualified_peers(0.5);

            // Remove some
            if let Some(candidate) = candidates.first() {
                selector.remove_candidate(&candidate.peer_id);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_add_candidate,
    bench_select_best,
    bench_select_top_n,
    bench_get_qualified_peers,
    bench_strategy_comparison,
    bench_remove_candidate,
    bench_statistics,
    bench_mixed_operations
);

criterion_main!(benches);
