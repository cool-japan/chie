//! Benchmarks for cache invalidation operations.
//!
//! Measures performance of:
//! - Invalidation event creation
//! - Pattern matching for cache keys
//! - Notifier creation and subscription

use chie_core::cache_invalidation::{
    InvalidationEvent, InvalidationNotifier, InvalidationPattern, InvalidationReason,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::collections::HashSet;
use std::hint::black_box;

/// Benchmark creating invalidation events.
fn bench_event_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_creation");

    let reasons = vec![
        ("updated", InvalidationReason::Updated),
        ("deleted", InvalidationReason::Deleted),
        ("expired", InvalidationReason::Expired),
        ("manual", InvalidationReason::Manual),
        ("error", InvalidationReason::Error),
        ("memory_pressure", InvalidationReason::MemoryPressure),
    ];

    for (name, reason) in reasons {
        group.bench_function(name, |b| {
            b.iter(|| {
                let event = InvalidationEvent::new(
                    black_box("content:QmTest123".to_string()),
                    black_box(reason.clone()),
                );
                black_box(event)
            });
        });
    }

    group.finish();
}

/// Benchmark adding metadata to events.
fn bench_event_with_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_with_metadata");

    group.bench_function("single_metadata", |b| {
        b.iter(|| {
            let event = InvalidationEvent::new(
                black_box("content:QmTest123".to_string()),
                black_box(InvalidationReason::Updated),
            )
            .with_metadata(
                black_box("version".to_string()),
                black_box("2.0".to_string()),
            );
            black_box(event)
        });
    });

    group.bench_function("multiple_metadata", |b| {
        b.iter(|| {
            let event = InvalidationEvent::new(
                black_box("content:QmTest123".to_string()),
                black_box(InvalidationReason::Updated),
            )
            .with_metadata(
                black_box("version".to_string()),
                black_box("2.0".to_string()),
            )
            .with_metadata(
                black_box("author".to_string()),
                black_box("user123".to_string()),
            )
            .with_metadata(
                black_box("timestamp".to_string()),
                black_box("2024-01-01".to_string()),
            );
            black_box(event)
        });
    });

    group.finish();
}

/// Benchmark setting origin node ID.
fn bench_event_with_origin(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_with_origin");

    group.bench_function("set_origin", |b| {
        b.iter(|| {
            let event = InvalidationEvent::new(
                black_box("content:QmTest123".to_string()),
                black_box(InvalidationReason::Updated),
            )
            .with_origin(black_box("node_abc123".to_string()));
            black_box(event)
        });
    });

    group.finish();
}

/// Benchmark pattern matching for cache keys.
fn bench_pattern_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_matching");

    // Test various pattern types
    let test_key = "content:QmTest123:metadata";

    group.bench_function("exact_match", |b| {
        let pattern = InvalidationPattern::Exact(test_key.to_string());
        b.iter(|| {
            let matches = pattern.matches(black_box(test_key));
            black_box(matches)
        });
    });

    group.bench_function("prefix_match", |b| {
        let pattern = InvalidationPattern::Prefix("content:".to_string());
        b.iter(|| {
            let matches = pattern.matches(black_box(test_key));
            black_box(matches)
        });
    });

    group.bench_function("suffix_match", |b| {
        let pattern = InvalidationPattern::Suffix(":metadata".to_string());
        b.iter(|| {
            let matches = pattern.matches(black_box(test_key));
            black_box(matches)
        });
    });

    group.bench_function("contains_match", |b| {
        let pattern = InvalidationPattern::Contains("QmTest".to_string());
        b.iter(|| {
            let matches = pattern.matches(black_box(test_key));
            black_box(matches)
        });
    });

    group.finish();
}

/// Benchmark pattern matching across multiple keys.
fn bench_pattern_matching_bulk(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_matching_bulk");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_keys", size)),
            &size,
            |b, &size| {
                let keys: Vec<String> = (0..size)
                    .map(|i| format!("content:QmTest{}:metadata", i))
                    .collect();

                let pattern = InvalidationPattern::Prefix("content:".to_string());

                b.iter(|| {
                    let mut matched = 0;
                    for key in &keys {
                        if pattern.matches(black_box(key)) {
                            matched += 1;
                        }
                    }
                    black_box(matched)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark creating invalidation notifiers.
fn bench_notifier_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("notifier_creation");

    group.bench_function("create_notifier", |b| {
        b.iter(|| {
            let notifier = InvalidationNotifier::new();
            black_box(notifier)
        });
    });

    group.finish();
}

/// Benchmark subscribing to invalidation events.
fn bench_subscription(c: &mut Criterion) {
    let mut group = c.benchmark_group("subscription");

    group.bench_function("single_subscription", |b| {
        let notifier = InvalidationNotifier::new();
        b.iter(|| {
            let receiver = notifier.subscribe();
            black_box(receiver)
        });
    });

    group.bench_function("multiple_subscriptions", |b| {
        let notifier = InvalidationNotifier::new();
        b.iter(|| {
            let receivers: Vec<_> = (0..10).map(|_| notifier.subscribe()).collect();
            black_box(receivers)
        });
    });

    group.finish();
}

/// Benchmark checking subscriber count.
fn bench_subscriber_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("subscriber_count");

    let counts = vec![0, 1, 10, 100];

    for count in counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_subscribers", count)),
            &count,
            |b, &count| {
                let notifier = InvalidationNotifier::new();
                let _receivers: Vec<_> = (0..count).map(|_| notifier.subscribe()).collect();

                b.iter(|| {
                    let sub_count = notifier.subscriber_count();
                    black_box(sub_count)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark pattern creation.
fn bench_pattern_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_creation");

    group.bench_function("exact_pattern", |b| {
        b.iter(|| {
            let pattern = InvalidationPattern::Exact(black_box("key".to_string()));
            black_box(pattern)
        });
    });

    group.bench_function("prefix_pattern", |b| {
        b.iter(|| {
            let pattern = InvalidationPattern::Prefix(black_box("prefix:".to_string()));
            black_box(pattern)
        });
    });

    group.bench_function("suffix_pattern", |b| {
        b.iter(|| {
            let pattern = InvalidationPattern::Suffix(black_box(":suffix".to_string()));
            black_box(pattern)
        });
    });

    group.bench_function("contains_pattern", |b| {
        b.iter(|| {
            let pattern = InvalidationPattern::Contains(black_box("substring".to_string()));
            black_box(pattern)
        });
    });

    group.bench_function("tags_pattern", |b| {
        let tags: HashSet<String> =
            vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()]
                .into_iter()
                .collect();

        b.iter(|| {
            let pattern = InvalidationPattern::Tags(black_box(tags.clone()));
            black_box(pattern)
        });
    });

    group.finish();
}

/// Benchmark pattern matching with varying key lengths.
fn bench_pattern_key_lengths(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_key_lengths");

    let lengths = vec![10, 50, 100, 500];

    for length in lengths {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_chars", length)),
            &length,
            |b, &length| {
                let key = "a".repeat(length);
                let pattern = InvalidationPattern::Prefix("a".to_string());

                b.iter(|| {
                    let matches = pattern.matches(black_box(&key));
                    black_box(matches)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark event creation with full metadata chain.
fn bench_event_full_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_full_chain");

    group.bench_function("complete_event", |b| {
        b.iter(|| {
            let event = InvalidationEvent::new(
                black_box("content:QmTest123:v2:metadata".to_string()),
                black_box(InvalidationReason::Updated),
            )
            .with_metadata(
                black_box("version".to_string()),
                black_box("2.0".to_string()),
            )
            .with_metadata(
                black_box("author".to_string()),
                black_box("user123".to_string()),
            )
            .with_metadata(black_box("size".to_string()), black_box("1024".to_string()))
            .with_origin(black_box("node_xyz789".to_string()));
            black_box(event)
        });
    });

    group.finish();
}

/// Benchmark realistic invalidation scenarios.
fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    group.bench_function("content_update", |b| {
        b.iter(|| {
            // Simulate invalidating content after update
            let keys: Vec<String> = (0..10)
                .map(|i| format!("content:QmTest{}:metadata", i))
                .collect();

            let pattern = InvalidationPattern::Prefix("content:QmTest5".to_string());

            let mut invalidated = Vec::new();
            for key in &keys {
                if pattern.matches(key) {
                    let event = InvalidationEvent::new(key.clone(), InvalidationReason::Updated);
                    invalidated.push(event);
                }
            }
            black_box(invalidated)
        });
    });

    group.bench_function("batch_expiration", |b| {
        b.iter(|| {
            // Simulate batch expiration
            let events: Vec<_> = (0..100)
                .map(|i| {
                    InvalidationEvent::new(
                        format!("temp:session_{}", i),
                        InvalidationReason::Expired,
                    )
                })
                .collect();
            black_box(events)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_event_creation,
    bench_event_with_metadata,
    bench_event_with_origin,
    bench_pattern_matching,
    bench_pattern_matching_bulk,
    bench_notifier_creation,
    bench_subscription,
    bench_subscriber_count,
    bench_pattern_creation,
    bench_pattern_key_lengths,
    bench_event_full_chain,
    bench_realistic_scenarios,
);
criterion_main!(benches);
