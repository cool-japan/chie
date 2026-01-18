use chie_core::proof_submit::{ProofSubmitConfig, ProofSubmitter, SubmitState};
use chie_shared::types::BandwidthProof;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

// Helper to create a test proof
fn create_test_proof(index: u64) -> BandwidthProof {
    BandwidthProof {
        session_id: uuid::Uuid::new_v4(),
        content_cid: format!("QmTest{}", index),
        chunk_index: 0,
        bytes_transferred: 1024 * 1024,
        provider_peer_id: format!("provider{}", index),
        requester_peer_id: format!("requester{}", index),
        provider_public_key: vec![0u8; 32],
        requester_public_key: vec![0u8; 32],
        provider_signature: vec![0u8; 64],
        requester_signature: vec![0u8; 64],
        challenge_nonce: vec![0u8; 24],
        chunk_hash: vec![0u8; 32],
        start_timestamp_ms: 1_000_000,
        end_timestamp_ms: 1_001_000,
        latency_ms: 1000,
    }
}

// Benchmark config creation
fn bench_config_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/config");

    group.bench_function("default", |b| {
        b.iter(|| black_box(ProofSubmitConfig::default()))
    });

    group.bench_function("custom", |b| {
        b.iter(|| {
            black_box(ProofSubmitConfig {
                coordinator_url: "http://coordinator.example.com".to_string(),
                max_retries: 3,
                initial_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 1.5,
                timeout: Duration::from_secs(15),
                max_queue_size: 500,
                persist_queue: false,
            })
        })
    });

    group.finish();
}

// Benchmark submitter creation
fn bench_submitter_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/submitter_creation");

    group.bench_function("default_config", |b| {
        let config = ProofSubmitConfig::default();
        b.iter(|| black_box(ProofSubmitter::new(config.clone())))
    });

    group.bench_function("custom_config", |b| {
        let config = ProofSubmitConfig {
            max_queue_size: 100,
            persist_queue: false,
            ..Default::default()
        };
        b.iter(|| black_box(ProofSubmitter::new(config.clone())))
    });

    group.finish();
}

// Benchmark queue size queries
fn bench_queue_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/queue_size");

    for count in [0, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            count,
            |b, &_proof_count| {
                let config = ProofSubmitConfig::default();
                let submitter = ProofSubmitter::new(config);

                // Pre-populate queue (note: actual implementation would need to support this)
                // This is a simplified benchmark focusing on the query operation

                b.iter(|| black_box(submitter.queue_size()))
            },
        );
    }

    group.finish();
}

// Benchmark stats retrieval
fn bench_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/stats");

    group.bench_function("get_stats", |b| {
        let config = ProofSubmitConfig::default();
        let submitter = ProofSubmitter::new(config);

        b.iter(|| black_box(submitter.stats()))
    });

    group.finish();
}

// Benchmark submit state checking
fn bench_submit_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/state");

    group.bench_function("state_equality", |b| {
        let states = [
            SubmitState::Pending,
            SubmitState::Submitting,
            SubmitState::Submitted,
            SubmitState::Failed,
        ];
        let mut idx = 0;
        b.iter(|| {
            let state1 = states[idx % 4];
            let state2 = states[(idx + 1) % 4];
            idx += 1;
            black_box(state1 == state2)
        })
    });

    group.finish();
}

// Benchmark proof creation
fn bench_proof_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/proof_creation");

    group.bench_function("create_test_proof", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let proof = create_test_proof(counter);
            counter += 1;
            black_box(proof)
        })
    });

    group.finish();
}

// Benchmark configuration variations
fn bench_config_variations(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/config_variations");

    group.bench_function("high_retry", |b| {
        b.iter(|| {
            black_box(ProofSubmitConfig {
                max_retries: 10,
                ..Default::default()
            })
        })
    });

    group.bench_function("low_timeout", |b| {
        b.iter(|| {
            black_box(ProofSubmitConfig {
                timeout: Duration::from_secs(5),
                ..Default::default()
            })
        })
    });

    group.bench_function("large_queue", |b| {
        b.iter(|| {
            black_box(ProofSubmitConfig {
                max_queue_size: 10000,
                ..Default::default()
            })
        })
    });

    group.finish();
}

// Benchmark mixed operations
fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_submit/mixed");

    group.bench_function("create_submitter_and_proof", |b| {
        let config = ProofSubmitConfig::default();
        let mut counter = 0u64;

        b.iter(|| {
            let _submitter = ProofSubmitter::new(config.clone());
            let _proof = create_test_proof(counter);
            counter += 1;
            black_box(counter)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_submitter_creation,
    bench_queue_size,
    bench_stats,
    bench_submit_state,
    bench_proof_creation,
    bench_config_variations,
    bench_mixed_operations,
);

criterion_main!(benches);
