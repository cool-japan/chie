//! Benchmarks for adaptive retry policy.

use chie_core::adaptive_retry::{AdaptiveRetryPolicy, FailureType};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark recording failures.
fn bench_record_failure(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_retry_record_failure");

    for failure_type in [
        FailureType::Timeout,
        FailureType::ConnectionFailed,
        FailureType::RateLimited,
        FailureType::ServerError,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", failure_type)),
            &failure_type,
            |b, &ft| {
                let mut policy = AdaptiveRetryPolicy::new();
                let peer_id = "peer1";
                b.iter(|| {
                    policy.record_failure(black_box(peer_id), black_box(ft));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark recording successes.
fn bench_record_success(c: &mut Criterion) {
    let mut policy = AdaptiveRetryPolicy::new();

    c.bench_function("adaptive_retry_record_success", |b| {
        b.iter(|| {
            policy.record_success(black_box("peer1"));
        });
    });
}

/// Benchmark checking if should retry.
fn bench_should_retry(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_retry_should_retry");

    // Setup: policy with various failure patterns
    let mut policy_no_failures = AdaptiveRetryPolicy::new();
    policy_no_failures.record_success("peer1");

    let mut policy_few_failures = AdaptiveRetryPolicy::new();
    for _ in 0..3 {
        policy_few_failures.record_failure("peer1", FailureType::Timeout);
    }

    let mut policy_many_failures = AdaptiveRetryPolicy::new();
    for _ in 0..10 {
        policy_many_failures.record_failure("peer1", FailureType::ConnectionFailed);
    }

    group.bench_function("no_failures", |b| {
        b.iter(|| {
            let _ = policy_no_failures.should_retry(black_box("peer1"), black_box(1));
        });
    });

    group.bench_function("few_failures", |b| {
        b.iter(|| {
            let _ = policy_few_failures.should_retry(black_box("peer1"), black_box(2));
        });
    });

    group.bench_function("many_failures", |b| {
        b.iter(|| {
            let _ = policy_many_failures.should_retry(black_box("peer1"), black_box(5));
        });
    });

    group.finish();
}

/// Benchmark calculating retry delay.
fn bench_retry_delay(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_retry_delay");

    let mut policy = AdaptiveRetryPolicy::new();
    policy.record_failure("peer1", FailureType::Timeout);

    for attempt in [1, 3, 5, 10] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("attempt_{}", attempt)),
            &attempt,
            |b, &att| {
                b.iter(|| {
                    let _ = policy.retry_delay(black_box("peer1"), black_box(att));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark getting success rate.
fn bench_success_rate(c: &mut Criterion) {
    let mut policy = AdaptiveRetryPolicy::new();

    // Add some history
    for _ in 0..50 {
        policy.record_failure("peer1", FailureType::Timeout);
        policy.record_success("peer1");
    }

    c.bench_function("adaptive_retry_success_rate", |b| {
        b.iter(|| {
            let _ = policy.success_rate(black_box("peer1"));
        });
    });
}

/// Benchmark bulk operations (recording multiple failures/successes).
fn bench_bulk_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_retry_bulk");

    for count in [10, 100, 1000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_operations", count)),
            &count,
            |b, &cnt| {
                b.iter(|| {
                    let mut policy = AdaptiveRetryPolicy::new();
                    for i in 0..cnt {
                        let peer_id = format!("peer{}", i % 10);
                        if i % 3 == 0 {
                            policy.record_failure(&peer_id, FailureType::Timeout);
                        } else {
                            policy.record_success(&peer_id);
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark failure pattern detection.
fn bench_failure_patterns(c: &mut Criterion) {
    let mut policy = AdaptiveRetryPolicy::new();

    // Add lots of varied failures
    for i in 0..100 {
        let failure_type = match i % 4 {
            0 => FailureType::Timeout,
            1 => FailureType::ConnectionFailed,
            2 => FailureType::ServerError,
            _ => FailureType::RateLimited,
        };
        policy.record_failure("peer1", failure_type);
    }

    c.bench_function("adaptive_retry_failure_patterns", |b| {
        b.iter(|| {
            let _ = policy.failure_patterns(black_box("peer1"));
        });
    });
}

criterion_group!(
    benches,
    bench_record_failure,
    bench_record_success,
    bench_should_retry,
    bench_retry_delay,
    bench_success_rate,
    bench_bulk_operations,
    bench_failure_patterns
);
criterion_main!(benches);
