//! Benchmark suite for geographic peer selection module.
//!
//! This file benchmarks the performance of geographic calculations and peer selection:
//! - Geographic location distance calculations (Haversine formula)
//! - Bearing calculations
//! - Peer geographic scoring
//! - Geographic peer selection and ranking
//! - Region-based grouping and diversity
//!
//! Run with: cargo bench --bench geo_selection_bench

use chie_core::geo_selection::{GeoConfig, GeoLocation, GeoPeer, GeoSelector};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_sample_location(lat: f64, lon: f64) -> GeoLocation {
    GeoLocation::new(lat, lon)
}

fn create_sample_peer(id: usize, lat: f64, lon: f64, region: &str) -> GeoPeer {
    GeoPeer {
        peer_id: format!("peer_{}", id),
        location: GeoLocation::new(lat, lon),
        region: region.to_string(),
        latency_ms: 50.0 + (id as f64 * 10.0),
        bandwidth_mbps: 100.0,
    }
}

fn create_selector_with_peers(count: usize) -> GeoSelector {
    let config = GeoConfig::default();
    let mut selector = GeoSelector::new(config);

    // Add peers distributed around the world
    for i in 0..count {
        let lat = -90.0 + (i as f64 * 180.0 / count as f64);
        let lon = -180.0 + (i as f64 * 360.0 / count as f64);
        let region = format!("region_{}", i % 10);
        selector.add_peer(create_sample_peer(i, lat, lon, &region));
    }

    selector
}

// ============================================================================
// GeoLocation Benchmarks
// ============================================================================

fn bench_geolocation_creation(c: &mut Criterion) {
    c.bench_function("geolocation_creation", |b| {
        b.iter(|| {
            let _loc = black_box(create_sample_location(37.7749, -122.4194));
        });
    });
}

fn bench_haversine_distance(c: &mut Criterion) {
    let loc1 = create_sample_location(37.7749, -122.4194); // San Francisco
    let loc2 = create_sample_location(40.7128, -74.0060); // New York

    c.bench_function("haversine_distance", |b| {
        b.iter(|| {
            let _dist = black_box(loc1.distance_to(&loc2));
        });
    });
}

fn bench_distance_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("distance_calculations");

    // Different distance ranges
    let locations = vec![
        (
            create_sample_location(37.7749, -122.4194),
            create_sample_location(37.3382, -121.8863),
            "short_distance_50km",
        ),
        (
            create_sample_location(37.7749, -122.4194),
            create_sample_location(34.0522, -118.2437),
            "medium_distance_500km",
        ),
        (
            create_sample_location(37.7749, -122.4194),
            create_sample_location(40.7128, -74.0060),
            "long_distance_4000km",
        ),
        (
            create_sample_location(37.7749, -122.4194),
            create_sample_location(51.5074, -0.1278),
            "intercontinental_8000km",
        ),
    ];

    for (loc1, loc2, name) in locations {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(loc1, loc2),
            |b, (l1, l2)| {
                b.iter(|| {
                    let _dist = black_box(l1.distance_to(l2));
                });
            },
        );
    }

    group.finish();
}

fn bench_is_within_radius(c: &mut Criterion) {
    let loc1 = create_sample_location(37.7749, -122.4194);
    let loc2 = create_sample_location(37.3382, -121.8863);

    c.bench_function("is_within_radius", |b| {
        b.iter(|| {
            let _result = black_box(loc1.is_within(&loc2, 100.0));
        });
    });
}

fn bench_bearing_calculation(c: &mut Criterion) {
    let loc1 = create_sample_location(37.7749, -122.4194);
    let loc2 = create_sample_location(40.7128, -74.0060);

    c.bench_function("bearing_calculation", |b| {
        b.iter(|| {
            let _bearing = black_box(loc1.bearing_to(&loc2));
        });
    });
}

// ============================================================================
// GeoPeer Benchmarks
// ============================================================================

fn bench_peer_creation(c: &mut Criterion) {
    c.bench_function("peer_creation", |b| {
        b.iter(|| {
            let _peer = black_box(create_sample_peer(0, 37.7749, -122.4194, "us-west"));
        });
    });
}

fn bench_peer_distance_to(c: &mut Criterion) {
    let peer = create_sample_peer(0, 37.7749, -122.4194, "us-west");
    let target = create_sample_location(40.7128, -74.0060);

    c.bench_function("peer_distance_to", |b| {
        b.iter(|| {
            let _dist = black_box(peer.distance_to(&target));
        });
    });
}

fn bench_peer_geo_score(c: &mut Criterion) {
    let peer = create_sample_peer(0, 37.7749, -122.4194, "us-west");
    let target = create_sample_location(40.7128, -74.0060);

    c.bench_function("peer_geo_score", |b| {
        b.iter(|| {
            let _score = black_box(peer.geo_score(&target));
        });
    });
}

// ============================================================================
// GeoSelector Benchmarks
// ============================================================================

fn bench_selector_creation(c: &mut Criterion) {
    let config = GeoConfig::default();

    c.bench_function("selector_creation", |b| {
        b.iter(|| {
            let _selector = black_box(GeoSelector::new(config.clone()));
        });
    });
}

fn bench_add_peer(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_peer");

    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &s| {
            b.iter(|| {
                let mut selector = GeoSelector::new(GeoConfig::default());
                for i in 0..s {
                    let peer = create_sample_peer(i, 37.0, -122.0, "us-west");
                    selector.add_peer(peer);
                }
                black_box(selector);
            });
        });
    }

    group.finish();
}

fn bench_remove_peer(c: &mut Criterion) {
    let mut selector = create_selector_with_peers(100);

    c.bench_function("remove_peer", |b| {
        b.iter(|| {
            let _removed = black_box(selector.remove_peer("peer_50"));
            // Re-add it for next iteration
            if let Some(peer) = _removed {
                selector.add_peer(peer);
            }
        });
    });
}

fn bench_find_nearest(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_nearest");

    let target = create_sample_location(37.7749, -122.4194);

    for peer_count in [10, 100, 1000] {
        for n in [1, 5, 10] {
            if n <= peer_count {
                group.bench_with_input(
                    BenchmarkId::new(format!("peers_{}", peer_count), n),
                    &n,
                    |b, &n_val| {
                        let selector = create_selector_with_peers(peer_count);
                        b.iter(|| {
                            let _nearest = black_box(selector.find_nearest(&target, n_val));
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

fn bench_find_within_radius(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_within_radius");

    let target = create_sample_location(37.7749, -122.4194);

    for peer_count in [10, 100, 1000] {
        for radius in [500.0, 2000.0, 10000.0] {
            group.bench_with_input(
                BenchmarkId::new(
                    format!("peers_{}", peer_count),
                    format!("{}km", radius as i32),
                ),
                &radius,
                |b, &r| {
                    let selector = create_selector_with_peers(peer_count);
                    b.iter(|| {
                        let _within = black_box(selector.find_within_radius(&target, r));
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_select_best(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_best");

    let target = create_sample_location(37.7749, -122.4194);

    for peer_count in [10, 100, 1000] {
        for n in [1, 5, 10] {
            if n <= peer_count {
                group.bench_with_input(
                    BenchmarkId::new(format!("peers_{}", peer_count), n),
                    &n,
                    |b, &n_val| {
                        let selector = create_selector_with_peers(peer_count);
                        b.iter(|| {
                            let _best = black_box(selector.select_best(&target, n_val));
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_peer_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_peer_selection");

    // Scenario: Client in San Francisco selecting from 100 global peers
    let target = create_sample_location(37.7749, -122.4194);
    let selector = create_selector_with_peers(100);

    group.bench_function("client_selects_5_best_from_100", |b| {
        b.iter(|| {
            let _best = black_box(selector.select_best(&target, 5));
        });
    });

    group.bench_function("client_finds_peers_within_1000km", |b| {
        b.iter(|| {
            let _within = black_box(selector.find_within_radius(&target, 1000.0));
        });
    });

    group.finish();
}

fn bench_batch_distance_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_distance_calculations");

    let origin = create_sample_location(37.7749, -122.4194);

    for count in [10, 100, 1000] {
        let locations: Vec<GeoLocation> = (0..count)
            .map(|i| {
                let lat = -90.0 + (i as f64 * 180.0 / count as f64);
                let lon = -180.0 + (i as f64 * 360.0 / count as f64);
                create_sample_location(lat, lon)
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(count), &locations, |b, locs| {
            b.iter(|| {
                let _distances: Vec<f64> = locs
                    .iter()
                    .map(|loc| black_box(origin.distance_to(loc)))
                    .collect();
            });
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    geolocation_benches,
    bench_geolocation_creation,
    bench_haversine_distance,
    bench_distance_calculations,
    bench_is_within_radius,
    bench_bearing_calculation,
);

criterion_group!(
    geopeer_benches,
    bench_peer_creation,
    bench_peer_distance_to,
    bench_peer_geo_score,
);

criterion_group!(
    geoselector_benches,
    bench_selector_creation,
    bench_add_peer,
    bench_remove_peer,
    bench_find_nearest,
    bench_find_within_radius,
    bench_select_best,
);

criterion_group!(
    realistic_benches,
    bench_realistic_peer_selection,
    bench_batch_distance_calculations,
);

criterion_main!(
    geolocation_benches,
    geopeer_benches,
    geoselector_benches,
    realistic_benches,
);
