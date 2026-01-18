//! Benchmarks for automatic content expiration operations.
//!
//! Measures performance of:
//! - Expiration manager creation
//! - Content registration and tracking
//! - Expiration policy evaluation
//! - Expired content detection and removal

use chie_core::expiration::{ContentEntry, ExpirationManager, ExpirationPolicy};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Benchmark creating expiration managers.
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("manager_creation");

    let policies = vec![
        (
            "ttl_1hour",
            ExpirationPolicy::ttl(Duration::from_secs(3600)),
        ),
        (
            "idle_timeout_30min",
            ExpirationPolicy::idle_timeout(Duration::from_secs(1800)),
        ),
        ("lru_1000", ExpirationPolicy::lru(1000)),
        (
            "size_quota_100mb",
            ExpirationPolicy::size_quota(100 * 1024 * 1024),
        ),
        ("never", ExpirationPolicy::Never),
    ];

    for (name, policy) in policies {
        group.bench_function(name, |b| {
            b.iter(|| {
                let manager = ExpirationManager::new(black_box(policy.clone()));
                black_box(manager)
            });
        });
    }

    group.finish();
}

/// Benchmark content entry creation.
fn bench_content_entry_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_entry_creation");

    group.bench_function("new_entry", |b| {
        b.iter(|| {
            let entry = ContentEntry::new(black_box("QmTest123".to_string()), black_box(1024));
            black_box(entry)
        });
    });

    group.bench_function("with_expiration", |b| {
        let expires_at = Instant::now() + Duration::from_secs(3600);

        b.iter(|| {
            let entry = ContentEntry::with_expiration(
                black_box("QmTest123".to_string()),
                black_box(1024),
                black_box(expires_at),
            );
            black_box(entry)
        });
    });

    group.finish();
}

/// Benchmark content entry methods.
fn bench_content_entry_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_entry_methods");

    let entry = ContentEntry::new("QmTest123".to_string(), 1024);

    group.bench_function("age", |b| {
        b.iter(|| {
            let age = entry.age();
            black_box(age)
        });
    });

    group.bench_function("idle_time", |b| {
        b.iter(|| {
            let idle = entry.idle_time();
            black_box(idle)
        });
    });

    group.bench_function("has_explicit_expiration", |b| {
        b.iter(|| {
            let has_exp = entry.has_explicit_expiration();
            black_box(has_exp)
        });
    });

    group.bench_function("record_access", |b| {
        let mut entry = ContentEntry::new("QmTest123".to_string(), 1024);
        b.iter(|| {
            entry.record_access();
        });
    });

    group.finish();
}

/// Benchmark expiration policy checks.
fn bench_policy_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_checks");

    let policies = vec![
        (
            "ttl_1hour",
            ExpirationPolicy::ttl(Duration::from_secs(3600)),
        ),
        (
            "idle_timeout_30min",
            ExpirationPolicy::idle_timeout(Duration::from_secs(1800)),
        ),
        ("lru_1000", ExpirationPolicy::lru(1000)),
        (
            "size_quota_100mb",
            ExpirationPolicy::size_quota(100 * 1024 * 1024),
        ),
    ];

    let entry = ContentEntry::new("QmTest123".to_string(), 1024);

    for (name, policy) in policies {
        group.bench_function(name, |b| {
            b.iter(|| {
                let should_expire = policy.should_expire(black_box(&entry));
                black_box(should_expire)
            });
        });
    }

    group.finish();
}

/// Benchmark registering content.
fn bench_register_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_content");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let policy = ExpirationPolicy::Never;
                    let mut manager = ExpirationManager::new(policy);

                    for i in 0..size {
                        manager.register(black_box(format!("QmTest{}", i)), black_box(1024));
                    }

                    black_box(manager)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark recording accesses.
fn bench_record_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_access");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_accesses", size)),
            &size,
            |b, &size| {
                let policy = ExpirationPolicy::Never;
                let mut manager = ExpirationManager::new(policy);

                // Pre-populate
                for i in 0..100 {
                    manager.register(format!("QmTest{}", i), 1024);
                }

                b.iter(|| {
                    for i in 0..size {
                        manager.record_access(&black_box(format!("QmTest{}", i % 100)));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting expired content.
fn bench_get_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_expired");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", size)),
            &size,
            |b, &size| {
                // TTL policy that expires everything immediately
                let policy = ExpirationPolicy::ttl(Duration::from_nanos(1));
                let mut manager = ExpirationManager::new(policy);

                // Pre-populate
                for i in 0..size {
                    manager.register(format!("QmTest{}", i), 1024);
                }

                // Wait a bit so everything expires
                std::thread::sleep(Duration::from_millis(10));

                b.iter(|| {
                    let expired = manager.get_expired();
                    black_box(expired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark expiring content.
fn bench_expire(c: &mut Criterion) {
    let mut group = c.benchmark_group("expire");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_entries", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    // TTL policy that expires everything immediately
                    let policy = ExpirationPolicy::ttl(Duration::from_nanos(1));
                    let mut manager = ExpirationManager::new(policy);

                    // Populate
                    for i in 0..size {
                        manager.register(format!("QmTest{}", i), 1024);
                    }

                    // Wait so everything expires
                    std::thread::sleep(Duration::from_millis(10));

                    // Expire all
                    let expired = manager.expire();
                    black_box(expired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark batch expiration.
fn bench_expire_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("expire_batch");

    let batch_sizes = vec![10, 50, 100];

    for batch_size in batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("batch_{}", batch_size)),
            &batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    let policy = ExpirationPolicy::ttl(Duration::from_nanos(1));
                    let mut manager = ExpirationManager::new(policy);

                    // Populate with more than batch size
                    for i in 0..200 {
                        manager.register(format!("QmTest{}", i), 1024);
                    }

                    std::thread::sleep(Duration::from_millis(10));

                    // Expire in batch
                    let expired = manager.expire_batch(black_box(batch_size));
                    black_box(expired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark removing specific content.
fn bench_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove");

    group.bench_function("single_remove", |b| {
        b.iter(|| {
            let policy = ExpirationPolicy::Never;
            let mut manager = ExpirationManager::new(policy);

            // Pre-populate
            for i in 0..100 {
                manager.register(format!("QmTest{}", i), 1024);
            }

            // Remove one
            let removed = manager.remove(black_box("QmTest50"));
            black_box(removed)
        });
    });

    group.finish();
}

/// Benchmark statistics queries.
fn bench_stats_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_queries");

    let policy = ExpirationPolicy::Never;
    let mut manager = ExpirationManager::new(policy);

    // Pre-populate
    for i in 0..100 {
        manager.register(format!("QmTest{}", i), 1024);
    }

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            let stats = manager.stats();
            black_box(stats)
        });
    });

    group.bench_function("entry_count", |b| {
        b.iter(|| {
            let count = manager.entry_count();
            black_box(count)
        });
    });

    group.bench_function("total_bytes", |b| {
        b.iter(|| {
            let bytes = manager.total_bytes();
            black_box(bytes)
        });
    });

    group.bench_function("contains", |b| {
        b.iter(|| {
            let contains = manager.contains(black_box("QmTest50"));
            black_box(contains)
        });
    });

    group.bench_function("get", |b| {
        b.iter(|| {
            let entry = manager.get(black_box("QmTest50"));
            black_box(entry)
        });
    });

    group.finish();
}

/// Benchmark LRU policy.
fn bench_lru_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("lru_policy");

    let sizes = vec![50, 100, 200];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_max_entries", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let policy = ExpirationPolicy::lru(black_box(size));
                    let mut manager = ExpirationManager::new(policy);

                    // Add more than max
                    for i in 0..size * 2 {
                        manager.register(format!("QmTest{}", i), 1024);
                    }

                    // Check expired (should be size entries)
                    let expired = manager.get_expired();
                    black_box(expired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark size quota policy.
fn bench_size_quota_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("size_quota_policy");

    let quotas = vec![10 * 1024, 100 * 1024, 1024 * 1024]; // 10KB, 100KB, 1MB

    for quota in quotas {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_bytes", quota)),
            &quota,
            |b, &quota| {
                b.iter(|| {
                    let policy = ExpirationPolicy::size_quota(black_box(quota));
                    let mut manager = ExpirationManager::new(policy);

                    // Add content exceeding quota
                    for i in 0..100 {
                        manager.register(format!("QmTest{}", i), 2048);
                    }

                    // Check expired
                    let expired = manager.get_expired();
                    black_box(expired)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark realistic expiration scenarios.
fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    group.bench_function("cache_with_ttl", |b| {
        b.iter(|| {
            // 1 hour TTL
            let policy = ExpirationPolicy::ttl(Duration::from_secs(3600));
            let mut manager = ExpirationManager::new(policy);

            // Simulate adding content over time
            for i in 0..100 {
                manager.register(format!("QmContent{}", i), 1024 * (i as u64 + 1));

                // Access some content
                if i % 3 == 0 {
                    manager.record_access(&format!("QmContent{}", i / 2));
                }
            }

            // Check for expired content
            let expired = manager.get_expired();
            black_box(expired)
        });
    });

    group.bench_function("lru_cache_simulation", |b| {
        b.iter(|| {
            // LRU with 50 max entries
            let policy = ExpirationPolicy::lru(50);
            let mut manager = ExpirationManager::new(policy);

            // Add 100 items
            for i in 0..100 {
                manager.register(format!("QmContent{}", i), 1024);

                // Access recent items more
                if i > 0 {
                    manager.record_access(&format!("QmContent{}", i - 1));
                }
            }

            // Expire to enforce LRU
            let expired = manager.expire();
            black_box(expired)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_content_entry_creation,
    bench_content_entry_methods,
    bench_policy_checks,
    bench_register_content,
    bench_record_access,
    bench_get_expired,
    bench_expire,
    bench_expire_batch,
    bench_remove,
    bench_stats_queries,
    bench_lru_policy,
    bench_size_quota_policy,
    bench_realistic_scenarios,
);
criterion_main!(benches);
