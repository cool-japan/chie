//! Benchmarks for cache admission policies.
//!
//! Measures performance of:
//! - TinyLFU admission decisions and frequency tracking
//! - SLRU segment management and promotion logic
//! - Access recording across different scales
//! - Admission decision performance

use chie_core::cache_admission::{AdmissionPolicy, SLRU, TinyLFU};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark creating TinyLFU policies.
fn bench_tinylfu_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_creation");

    let capacities = vec![100, 1000, 10000];

    for capacity in capacities {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("cap_{}", capacity)),
            &capacity,
            |b, &capacity| {
                b.iter(|| {
                    let policy = TinyLFU::new(black_box(capacity), black_box(4));
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark recording accesses in TinyLFU.
fn bench_tinylfu_record_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_record_access");

    let sizes = vec![100, 1000, 10000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_accesses", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut policy = TinyLFU::new(1000, 4);
                    for i in 0..size {
                        policy.record_access(&black_box(format!("key_{}", i % 100)));
                    }
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark frequency estimation in TinyLFU.
fn bench_tinylfu_estimate_frequency(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_estimate_frequency");

    group.bench_function("single_key", |b| {
        let mut policy = TinyLFU::new(1000, 4);

        // Pre-populate with accesses
        for _ in 0..100 {
            policy.record_access(&"hot_key");
        }

        b.iter(|| {
            let freq = policy.estimate_frequency(&black_box("hot_key"));
            black_box(freq)
        });
    });

    group.bench_function("multiple_keys", |b| {
        let mut policy = TinyLFU::new(1000, 4);

        // Pre-populate with accesses
        for i in 0..100 {
            policy.record_access(&format!("key_{}", i));
        }

        b.iter(|| {
            for i in 0..10 {
                let freq = policy.estimate_frequency(&black_box(format!("key_{}", i)));
                black_box(freq);
            }
        });
    });

    group.finish();
}

/// Benchmark admission decisions in TinyLFU.
fn bench_tinylfu_should_admit(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_should_admit");

    group.bench_function("hot_vs_cold", |b| {
        let mut policy = TinyLFU::new(1000, 4);

        // Make "hot" key frequently accessed
        for _ in 0..100 {
            policy.record_access(&"hot");
        }

        // Make "cold" key rarely accessed
        policy.record_access(&"cold");

        b.iter(|| {
            let admit = policy.should_admit(&black_box("hot"), &black_box("cold"));
            black_box(admit)
        });
    });

    group.bench_function("similar_frequency", |b| {
        let mut policy = TinyLFU::new(1000, 4);

        // Both keys accessed similar number of times
        for _ in 0..50 {
            policy.record_access(&"key1");
            policy.record_access(&"key2");
        }

        b.iter(|| {
            let admit = policy.should_admit(&black_box("key1"), &black_box("key2"));
            black_box(admit)
        });
    });

    group.finish();
}

/// Benchmark TinyLFU reset operation.
fn bench_tinylfu_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_reset");

    let capacities = vec![100, 1000, 10000];

    for capacity in capacities {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("cap_{}", capacity)),
            &capacity,
            |b, &capacity| {
                b.iter(|| {
                    let mut policy = TinyLFU::new(capacity, 4);

                    // Populate with some data
                    for i in 0..100 {
                        AdmissionPolicy::<String>::record_access(
                            &mut policy,
                            &format!("key_{}", i),
                        );
                    }

                    AdmissionPolicy::<String>::reset(&mut policy);
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark creating SLRU policies.
fn bench_slru_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_creation");

    let ratios = vec![0.5, 0.8, 0.9];

    for ratio in ratios {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("ratio_{}", (ratio * 100.0) as u32)),
            &ratio,
            |b, &ratio| {
                b.iter(|| {
                    let policy: SLRU<String> = SLRU::new(black_box(ratio));
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark recording accesses in SLRU.
fn bench_slru_record_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_record_access");

    let sizes = vec![100, 1000, 10000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_accesses", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut policy: SLRU<String> = SLRU::new(0.8);
                    for i in 0..size {
                        policy.record_access(&black_box(format!("key_{}", i % 100)));
                    }
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark SLRU segment operations.
fn bench_slru_segment_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_segment_operations");

    group.bench_function("is_protected", |b| {
        let mut policy: SLRU<String> = SLRU::new(0.8);

        // Add some items and promote them
        policy.record_access(&"item1".to_string());
        policy.record_access(&"item1".to_string()); // Promote

        b.iter(|| {
            let protected = policy.is_protected(&black_box("item1".to_string()));
            black_box(protected)
        });
    });

    group.bench_function("get_segment", |b| {
        let mut policy: SLRU<String> = SLRU::new(0.8);

        policy.record_access(&"probationary".to_string());
        policy.record_access(&"protected".to_string());
        policy.record_access(&"protected".to_string()); // Promote

        b.iter(|| {
            let seg1 = policy.get_segment(&black_box("probationary".to_string()));
            let seg2 = policy.get_segment(&black_box("protected".to_string()));
            black_box((seg1, seg2))
        });
    });

    group.finish();
}

/// Benchmark SLRU promotion logic.
fn bench_slru_promotion(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_promotion");

    let sizes = vec![10, 100, 1000];

    for size in sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_items", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut policy: SLRU<String> = SLRU::new(0.8);

                    // Add items and promote half of them
                    for i in 0..size {
                        let key = format!("key_{}", i);
                        policy.record_access(&key);

                        // Promote half
                        if i % 2 == 0 {
                            policy.record_access(&key);
                        }
                    }

                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark SLRU admission decisions.
fn bench_slru_should_admit(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_should_admit");

    group.bench_function("probationary_vs_protected", |b| {
        let mut policy: SLRU<String> = SLRU::new(0.8);

        // Create probationary item
        policy.record_access(&"probationary".to_string());

        // Create protected item
        policy.record_access(&"protected".to_string());
        policy.record_access(&"protected".to_string()); // Promote

        b.iter(|| {
            let admit = policy.should_admit(
                &black_box("probationary".to_string()),
                &black_box("protected".to_string()),
            );
            black_box(admit)
        });
    });

    group.bench_function("protected_vs_protected", |b| {
        let mut policy: SLRU<String> = SLRU::new(0.8);

        // Create two protected items with different access times
        policy.record_access(&"old".to_string());
        policy.record_access(&"old".to_string()); // Promote

        std::thread::sleep(std::time::Duration::from_millis(1));

        policy.record_access(&"new".to_string());
        policy.record_access(&"new".to_string()); // Promote

        b.iter(|| {
            let admit =
                policy.should_admit(&black_box("new".to_string()), &black_box("old".to_string()));
            black_box(admit)
        });
    });

    group.finish();
}

/// Benchmark SLRU reset operation.
fn bench_slru_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_reset");

    let sizes = vec![100, 1000, 10000];

    for size in sizes {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_items", size)),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut policy: SLRU<String> = SLRU::new(0.8);

                    // Populate with data
                    for i in 0..size {
                        policy.record_access(&format!("key_{}", i));
                    }

                    policy.reset();
                    black_box(policy)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark TinyLFU with realistic workload.
fn bench_tinylfu_realistic_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("tinylfu_realistic_workload");

    group.throughput(Throughput::Elements(1000));
    group.bench_function("zipf_distribution", |b| {
        b.iter(|| {
            let mut policy = TinyLFU::new(1000, 4);

            // Simulate Zipfian distribution (80-20 rule)
            // 20% of keys get 80% of accesses
            for _ in 0..1000 {
                // Hot keys (20%)
                for i in 0..20 {
                    policy.record_access(&black_box(format!("hot_{}", i)));
                }

                // Cold keys (80%)
                for i in 0..80 {
                    if i % 5 == 0 {
                        // Only 20% of cold keys get accessed
                        policy.record_access(&black_box(format!("cold_{}", i)));
                    }
                }
            }

            black_box(policy)
        });
    });

    group.finish();
}

/// Benchmark SLRU with realistic workload.
fn bench_slru_realistic_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("slru_realistic_workload");

    group.throughput(Throughput::Elements(1000));
    group.bench_function("temporal_locality", |b| {
        b.iter(|| {
            let mut policy: SLRU<String> = SLRU::new(0.8);

            // Simulate temporal locality - recent items accessed more frequently
            let mut recent_keys = Vec::new();

            for i in 0..1000 {
                let key = format!("key_{}", i);

                // Access new key
                policy.record_access(&key);

                // Also access recent keys with higher probability
                recent_keys.push(key);
                if recent_keys.len() > 20 {
                    recent_keys.remove(0);
                }

                // Re-access recent keys
                for recent in &recent_keys {
                    if i % 3 == 0 {
                        policy.record_access(recent);
                    }
                }
            }

            black_box(policy)
        });
    });

    group.finish();
}

/// Benchmark comparing TinyLFU vs SLRU.
fn bench_policy_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_comparison");

    let access_counts = vec![100, 1000];

    for count in access_counts {
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("tinylfu", count), &count, |b, &count| {
            b.iter(|| {
                let mut policy = TinyLFU::new(1000, 4);
                for i in 0..count {
                    policy.record_access(&black_box(format!("key_{}", i % 100)));
                }
                black_box(policy)
            });
        });

        group.bench_with_input(BenchmarkId::new("slru", count), &count, |b, &count| {
            b.iter(|| {
                let mut policy: SLRU<String> = SLRU::new(0.8);
                for i in 0..count {
                    policy.record_access(&black_box(format!("key_{}", i % 100)));
                }
                black_box(policy)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_tinylfu_creation,
    bench_tinylfu_record_access,
    bench_tinylfu_estimate_frequency,
    bench_tinylfu_should_admit,
    bench_tinylfu_reset,
    bench_slru_creation,
    bench_slru_record_access,
    bench_slru_segment_operations,
    bench_slru_promotion,
    bench_slru_should_admit,
    bench_slru_reset,
    bench_tinylfu_realistic_workload,
    bench_slru_realistic_workload,
    bench_policy_comparison,
);
criterion_main!(benches);
