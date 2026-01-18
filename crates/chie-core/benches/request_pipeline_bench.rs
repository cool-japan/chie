use chie_core::request_pipeline::{PipelineConfig, PipelineRequest, RequestPriority};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Benchmark PipelineConfig creation.
fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("pipeline_config_creation", |b| {
        b.iter(|| {
            let config = PipelineConfig::default();
            black_box(config);
        });
    });
}

/// Benchmark PipelineConfig creation with custom settings.
fn bench_config_custom_creation(c: &mut Criterion) {
    c.bench_function("pipeline_config_custom_creation", |b| {
        b.iter(|| {
            let config = PipelineConfig {
                max_batch_size: black_box(100),
                max_concurrent: black_box(20),
                batch_timeout_ms: black_box(50),
                max_queue_time_ms: black_box(10_000),
                enable_deduplication: black_box(true),
            };
            black_box(config);
        });
    });
}

/// Benchmark PipelineRequest creation.
fn bench_request_creation(c: &mut Criterion) {
    c.bench_function("pipeline_request_creation", |b| {
        b.iter(|| {
            let payload = vec![1, 2, 3, 4, 5];
            let request = PipelineRequest::new(black_box("submit_proof"), black_box(payload));
            black_box(request);
        });
    });
}

/// Benchmark PipelineRequest creation with different payload sizes.
fn bench_request_creation_by_payload_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_request_creation_by_payload");

    for &size_kb in &[1, 10, 100, 1000] {
        let size_bytes = size_kb * 1024;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size_kb)),
            &size_bytes,
            |b, &sz| {
                b.iter(|| {
                    let payload = vec![0u8; sz];
                    let request = PipelineRequest::new("submit_proof", payload);
                    black_box(request);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark PipelineRequest with priority.
fn bench_request_with_priority(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_request_with_priority");

    for priority in [
        RequestPriority::Low,
        RequestPriority::Normal,
        RequestPriority::High,
        RequestPriority::Critical,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", priority)),
            &priority,
            |b, &p| {
                b.iter(|| {
                    let payload = vec![1, 2, 3, 4, 5];
                    let request =
                        PipelineRequest::new("submit_proof", payload).with_priority(black_box(p));
                    black_box(request);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark PipelineRequest with request ID.
fn bench_request_with_id(c: &mut Criterion) {
    c.bench_function("pipeline_request_with_id", |b| {
        b.iter(|| {
            let payload = vec![1, 2, 3, 4, 5];
            let request = PipelineRequest::new("submit_proof", payload)
                .with_request_id(black_box("req-12345".to_string()));
            black_box(request);
        });
    });
}

/// Benchmark creating multiple requests (batching scenario).
fn bench_bulk_request_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_bulk_request_creation");

    for &count in &[10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_requests", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    let mut requests = Vec::new();
                    for i in 0..n {
                        let payload = vec![i as u8; 100];
                        let priority = match i % 4 {
                            0 => RequestPriority::Critical,
                            1 => RequestPriority::High,
                            2 => RequestPriority::Normal,
                            _ => RequestPriority::Low,
                        };
                        let request = PipelineRequest::new(format!("operation_{}", i), payload)
                            .with_priority(priority)
                            .with_request_id(format!("req-{}", i));
                        requests.push(request);
                    }
                    black_box(requests);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark request serialization.
fn bench_request_serialization(c: &mut Criterion) {
    c.bench_function("pipeline_request_serialization", |b| {
        b.iter(|| {
            let payload = vec![1, 2, 3, 4, 5];
            let request = PipelineRequest::new("submit_proof", payload)
                .with_priority(RequestPriority::High)
                .with_request_id("req-12345".to_string());

            let serialized = serde_json::to_string(&request).unwrap();
            black_box(serialized);
        });
    });
}

/// Benchmark request deserialization.
fn bench_request_deserialization(c: &mut Criterion) {
    c.bench_function("pipeline_request_deserialization", |b| {
        let payload = vec![1, 2, 3, 4, 5];
        let request = PipelineRequest::new("submit_proof", payload)
            .with_priority(RequestPriority::High)
            .with_request_id("req-12345".to_string());
        let json = serde_json::to_string(&request).unwrap();

        b.iter(|| {
            let deserialized: PipelineRequest = serde_json::from_str(&json).unwrap();
            black_box(deserialized);
        });
    });
}

/// Benchmark batch serialization.
fn bench_batch_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_batch_serialization");

    for &count in &[10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_requests", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    let mut requests = Vec::new();
                    for i in 0..n {
                        let payload = vec![i as u8; 100];
                        let request = PipelineRequest::new(format!("op_{}", i), payload);
                        requests.push(request);
                    }

                    let serialized = serde_json::to_string(&requests).unwrap();
                    black_box(serialized);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark priority comparison.
fn bench_priority_comparison(c: &mut Criterion) {
    c.bench_function("pipeline_priority_comparison", |b| {
        b.iter(|| {
            let p1 = black_box(RequestPriority::High);
            let p2 = black_box(RequestPriority::Normal);
            let result = p1 > p2;
            black_box(result);
        });
    });
}

/// Benchmark realistic scenario: proof submission batching.
fn bench_realistic_proof_batching(c: &mut Criterion) {
    c.bench_function("pipeline_realistic_proof_batching", |b| {
        b.iter(|| {
            // Simulate collecting proof submissions for batching
            let mut batch = Vec::new();

            // High priority: Recent chunks (last 20)
            for i in 0..20 {
                let payload = vec![i as u8; 256]; // Proof data
                let request = PipelineRequest::new("submit_proof", payload)
                    .with_priority(RequestPriority::High)
                    .with_request_id(format!("proof-recent-{}", i));
                batch.push(request);
            }

            // Normal priority: Regular chunks
            for i in 0..50 {
                let payload = vec![i as u8; 256];
                let request = PipelineRequest::new("submit_proof", payload)
                    .with_priority(RequestPriority::Normal)
                    .with_request_id(format!("proof-regular-{}", i));
                batch.push(request);
            }

            // Low priority: Background chunks
            for i in 0..30 {
                let payload = vec![i as u8; 256];
                let request = PipelineRequest::new("submit_proof", payload)
                    .with_priority(RequestPriority::Low)
                    .with_request_id(format!("proof-background-{}", i));
                batch.push(request);
            }

            // Sort by priority for processing
            batch.sort_by(|a, b| b.priority.cmp(&a.priority));

            black_box(batch);
        });
    });
}

/// Benchmark realistic scenario: mixed operation batching.
fn bench_realistic_mixed_operations(c: &mut Criterion) {
    c.bench_function("pipeline_realistic_mixed_operations", |b| {
        b.iter(|| {
            let mut operations = Vec::new();

            // Critical: Storage quota checks
            for i in 0..5 {
                let payload = vec![i as u8; 50];
                let request = PipelineRequest::new("check_quota", payload)
                    .with_priority(RequestPriority::Critical)
                    .with_request_id(format!("quota-{}", i));
                operations.push(request);
            }

            // High: Proof submissions
            for i in 0..30 {
                let payload = vec![i as u8; 256];
                let request = PipelineRequest::new("submit_proof", payload)
                    .with_priority(RequestPriority::High)
                    .with_request_id(format!("proof-{}", i));
                operations.push(request);
            }

            // Normal: Content metadata updates
            for i in 0..40 {
                let payload = vec![i as u8; 128];
                let request = PipelineRequest::new("update_metadata", payload)
                    .with_priority(RequestPriority::Normal)
                    .with_request_id(format!("metadata-{}", i));
                operations.push(request);
            }

            // Low: Analytics reporting
            for i in 0..25 {
                let payload = vec![i as u8; 100];
                let request = PipelineRequest::new("report_analytics", payload)
                    .with_priority(RequestPriority::Low)
                    .with_request_id(format!("analytics-{}", i));
                operations.push(request);
            }

            // Group by operation type for potential deduplication
            let mut by_operation: std::collections::HashMap<String, Vec<PipelineRequest>> =
                std::collections::HashMap::new();

            for req in operations {
                by_operation
                    .entry(req.operation.clone())
                    .or_default()
                    .push(req);
            }

            black_box(by_operation);
        });
    });
}

/// Benchmark request cloning (for deduplication scenarios).
fn bench_request_clone(c: &mut Criterion) {
    c.bench_function("pipeline_request_clone", |b| {
        let payload = vec![1, 2, 3, 4, 5];
        let request = PipelineRequest::new("submit_proof", payload)
            .with_priority(RequestPriority::High)
            .with_request_id("req-12345".to_string());

        b.iter(|| {
            let cloned = request.clone();
            black_box(cloned);
        });
    });
}

/// Benchmark bulk request cloning.
fn bench_bulk_request_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_bulk_request_clone");

    for &count in &[10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_requests", count)),
            &count,
            |b, &n| {
                let mut requests = Vec::new();
                for i in 0..n {
                    let payload = vec![i as u8; 100];
                    let request = PipelineRequest::new(format!("op_{}", i), payload);
                    requests.push(request);
                }

                b.iter(|| {
                    let cloned = requests.to_vec();
                    black_box(cloned);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_config_custom_creation,
    bench_request_creation,
    bench_request_creation_by_payload_size,
    bench_request_with_priority,
    bench_request_with_id,
    bench_bulk_request_creation,
    bench_request_serialization,
    bench_request_deserialization,
    bench_batch_serialization,
    bench_priority_comparison,
    bench_realistic_proof_batching,
    bench_realistic_mixed_operations,
    bench_request_clone,
    bench_bulk_request_clone,
);
criterion_main!(benches);
