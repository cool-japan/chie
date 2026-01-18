//! Benchmark suite for priority-based content eviction module.
//!
//! This file benchmarks the performance of intelligent content eviction:
//! - ContentPriority creation and configuration
//! - Priority score calculation with different weights
//! - Content addition and updates
//! - Eviction candidate selection
//! - Different eviction strategies (revenue, performance, space-focused)
//!
//! Run with: cargo bench --bench priority_eviction_bench

use chie_core::priority_eviction::{ContentPriority, EvictionConfig, PriorityEvictor};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_sample_priority(size_bytes: u64) -> ContentPriority {
    ContentPriority {
        manual_priority: 5,
        access_frequency: 10.0,
        size_bytes,
        revenue_per_gb: 5.0,
        last_access_age_secs: 3600,
    }
}

fn create_evictor_with_content(count: usize) -> PriorityEvictor {
    let config = EvictionConfig::default();
    let mut evictor = PriorityEvictor::new(config);

    for i in 0..count {
        let cid = format!("content:{}", i);
        let size = 1_048_576 * (i as u64 % 10 + 1); // 1-10 MB
        let priority = ContentPriority {
            manual_priority: (i % 10) as u8,
            access_frequency: (i % 100) as f64,
            size_bytes: size,
            revenue_per_gb: (i % 20) as f64,
            last_access_age_secs: (i as u64 % 7200),
        };
        evictor.add_content(cid, priority);
    }

    evictor
}

// ============================================================================
// ContentPriority Benchmarks
// ============================================================================

fn bench_content_priority_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_priority_creation");

    group.bench_function("new", |b| {
        b.iter(|| {
            let _priority = black_box(ContentPriority::new(1_048_576));
        });
    });

    group.bench_function("with_manual_priority", |b| {
        b.iter(|| {
            let _priority = black_box(ContentPriority::new(1_048_576).with_manual_priority(8));
        });
    });

    group.bench_function("with_frequency", |b| {
        b.iter(|| {
            let _priority = black_box(ContentPriority::new(1_048_576).with_frequency(15.0));
        });
    });

    group.bench_function("with_revenue", |b| {
        b.iter(|| {
            let _priority = black_box(ContentPriority::new(1_048_576).with_revenue(10.0));
        });
    });

    group.bench_function("full_configuration", |b| {
        b.iter(|| {
            let _priority = black_box(
                ContentPriority::new(1_048_576)
                    .with_manual_priority(8)
                    .with_frequency(15.0)
                    .with_revenue(10.0),
            );
        });
    });

    group.finish();
}

// ============================================================================
// EvictionConfig Benchmarks
// ============================================================================

fn bench_eviction_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("eviction_config_creation");

    group.bench_function("default", |b| {
        b.iter(|| {
            let _config = black_box(EvictionConfig::default());
        });
    });

    group.bench_function("revenue_focused", |b| {
        b.iter(|| {
            let _config = black_box(EvictionConfig::revenue_focused());
        });
    });

    group.bench_function("performance_focused", |b| {
        b.iter(|| {
            let _config = black_box(EvictionConfig::performance_focused());
        });
    });

    group.bench_function("space_focused", |b| {
        b.iter(|| {
            let _config = black_box(EvictionConfig::space_focused());
        });
    });

    group.bench_function("custom", |b| {
        b.iter(|| {
            let _config = black_box(EvictionConfig::new(0.3, 0.2, 0.3, 0.2, 2.0));
        });
    });

    group.finish();
}

// ============================================================================
// PriorityEvictor Benchmarks
// ============================================================================

fn bench_evictor_creation(c: &mut Criterion) {
    let config = EvictionConfig::default();

    c.bench_function("evictor_creation", |b| {
        b.iter(|| {
            let _evictor = black_box(PriorityEvictor::new(config.clone()));
        });
    });
}

fn bench_add_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_content");

    for count in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &n| {
            b.iter(|| {
                let mut evictor = PriorityEvictor::new(EvictionConfig::default());
                for i in 0..n {
                    let cid = format!("content:{}", i);
                    let priority = create_sample_priority(1_048_576);
                    evictor.add_content(cid, priority);
                }
                black_box(evictor);
            });
        });
    }

    group.finish();
}

fn bench_update_priority(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_priority");

    for count in [10, 100, 1000] {
        let mut evictor = create_evictor_with_content(count);
        let new_priority = ContentPriority {
            manual_priority: 8,
            access_frequency: 50.0,
            size_bytes: 2_097_152,
            revenue_per_gb: 15.0,
            last_access_age_secs: 1800,
        };

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &_n| {
            b.iter(|| {
                let _updated =
                    black_box(evictor.update_priority("content:50", new_priority.clone()));
            });
        });
    }

    group.finish();
}

fn bench_remove_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_content");

    for count in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &n| {
            b.iter(|| {
                let mut evictor = create_evictor_with_content(n);
                let _removed = black_box(evictor.remove_content("content:50"));
            });
        });
    }

    group.finish();
}

fn bench_get_eviction_candidates(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_eviction_candidates");

    for (content_count, target_bytes) in [
        (100, 10_485_760),   // 100 items, evict 10 MB
        (1000, 104_857_600), // 1000 items, evict 100 MB
        (5000, 524_288_000), // 5000 items, evict 500 MB
    ] {
        let evictor = create_evictor_with_content(content_count);

        group.bench_with_input(
            BenchmarkId::new(
                format!("items_{}", content_count),
                format!("{}MB", target_bytes / 1_048_576),
            ),
            &target_bytes,
            |b, &target| {
                b.iter(|| {
                    let _candidates = black_box(evictor.get_eviction_candidates(target));
                });
            },
        );
    }

    group.finish();
}

fn bench_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats");

    for count in [10, 100, 1000] {
        let evictor = create_evictor_with_content(count);

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &_n| {
            b.iter(|| {
                let _stats = black_box(evictor.stats());
            });
        });
    }

    group.finish();
}

fn bench_entry_count(c: &mut Criterion) {
    let evictor = create_evictor_with_content(1000);

    c.bench_function("entry_count", |b| {
        b.iter(|| {
            let _count = black_box(evictor.entry_count());
        });
    });
}

fn bench_total_bytes(c: &mut Criterion) {
    let evictor = create_evictor_with_content(1000);

    c.bench_function("total_bytes", |b| {
        b.iter(|| {
            let _bytes = black_box(evictor.total_bytes());
        });
    });
}

// ============================================================================
// Different Eviction Strategies
// ============================================================================

fn bench_eviction_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("eviction_strategies");

    let configs = vec![
        ("default", EvictionConfig::default()),
        ("revenue_focused", EvictionConfig::revenue_focused()),
        ("performance_focused", EvictionConfig::performance_focused()),
        ("space_focused", EvictionConfig::space_focused()),
    ];

    for (name, config) in configs {
        let mut evictor = PriorityEvictor::new(config);

        // Add 100 diverse content items
        for i in 0..100 {
            let cid = format!("content:{}", i);
            let priority = ContentPriority {
                manual_priority: (i % 10) as u8,
                access_frequency: (i % 50) as f64,
                size_bytes: 1_048_576 * (i as u64 % 10 + 1),
                revenue_per_gb: (i % 30) as f64,
                last_access_age_secs: (i as u64 % 7200),
            };
            evictor.add_content(cid, priority);
        }

        group.bench_function(name, |b| {
            b.iter(|| {
                let _candidates = black_box(evictor.get_eviction_candidates(52_428_800)); // 50 MB
            });
        });
    }

    group.finish();
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_cache_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_cache_eviction");

    // Scenario 1: Small cache with frequent updates
    group.bench_function("small_cache_frequent_updates", |b| {
        b.iter(|| {
            let mut evictor = PriorityEvictor::new(EvictionConfig::performance_focused());

            // Add 50 items
            for i in 0..50 {
                let cid = format!("content:{}", i);
                evictor.add_content(cid, create_sample_priority(524_288)); // 512 KB
            }

            // Simulate 20 accesses (update priorities)
            for i in 0..20 {
                let cid = format!("content:{}", i % 50);
                let updated = ContentPriority {
                    manual_priority: 5,
                    access_frequency: 20.0,
                    size_bytes: 524_288,
                    revenue_per_gb: 5.0,
                    last_access_age_secs: 100,
                };
                evictor.update_priority(&cid, updated);
            }

            // Evict when full
            let _candidates = evictor.get_eviction_candidates(10_485_760); // 10 MB

            black_box(evictor);
        });
    });

    // Scenario 2: Large CDN cache with revenue optimization
    group.bench_function("cdn_revenue_optimization", |b| {
        b.iter(|| {
            let mut evictor = PriorityEvictor::new(EvictionConfig::revenue_focused());

            // Add 1000 diverse content items
            for i in 0..1000 {
                let cid = format!("content:{}", i);
                let priority = ContentPriority {
                    manual_priority: (i % 10) as u8,
                    access_frequency: (i % 100) as f64,
                    size_bytes: 1_048_576 * (i as u64 % 20 + 1),
                    revenue_per_gb: (i % 50) as f64,
                    last_access_age_secs: (i as u64 % 86400),
                };
                evictor.add_content(cid, priority);
            }

            // Evict 1 GB
            let _candidates = evictor.get_eviction_candidates(1_073_741_824);

            black_box(evictor);
        });
    });

    // Scenario 3: Space-constrained storage
    group.bench_function("space_constrained_storage", |b| {
        b.iter(|| {
            let mut evictor = PriorityEvictor::new(EvictionConfig::space_focused());

            // Add various sized items
            for i in 0..500 {
                let cid = format!("content:{}", i);
                let size = match i % 5 {
                    0 => 104_857_600, // 100 MB
                    1 => 52_428_800,  // 50 MB
                    2 => 10_485_760,  // 10 MB
                    3 => 1_048_576,   // 1 MB
                    _ => 524_288,     // 512 KB
                };
                evictor.add_content(cid, create_sample_priority(size));
            }

            // Evict to free 500 MB
            let _candidates = evictor.get_eviction_candidates(524_288_000);

            black_box(evictor);
        });
    });

    group.finish();
}

fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");

    // Batch addition
    group.bench_function("batch_add_100", |b| {
        b.iter(|| {
            let mut evictor = PriorityEvictor::new(EvictionConfig::default());
            for i in 0..100 {
                let cid = format!("content:{}", i);
                evictor.add_content(cid, create_sample_priority(1_048_576));
            }
            black_box(evictor);
        });
    });

    // Batch update
    group.bench_function("batch_update_100", |b| {
        let mut evictor = create_evictor_with_content(100);
        let new_priority = create_sample_priority(2_097_152);

        b.iter(|| {
            for i in 0..100 {
                let cid = format!("content:{}", i);
                evictor.update_priority(&cid, new_priority.clone());
            }
            black_box(&evictor);
        });
    });

    // Batch removal
    group.bench_function("batch_remove_50", |b| {
        b.iter(|| {
            let mut evictor = create_evictor_with_content(100);
            for i in 0..50 {
                let cid = format!("content:{}", i);
                evictor.remove_content(&cid);
            }
            black_box(evictor);
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    priority_benches,
    bench_content_priority_creation,
    bench_eviction_config_creation,
);

criterion_group!(
    evictor_benches,
    bench_evictor_creation,
    bench_add_content,
    bench_update_priority,
    bench_remove_content,
    bench_get_eviction_candidates,
    bench_stats,
    bench_entry_count,
    bench_total_bytes,
);

criterion_group!(strategy_benches, bench_eviction_strategies,);

criterion_group!(
    realistic_benches,
    bench_realistic_cache_eviction,
    bench_batch_operations,
);

criterion_main!(
    priority_benches,
    evictor_benches,
    strategy_benches,
    realistic_benches,
);
