use chie_core::validation::*;
use chie_crypto::KeyPair;
use chie_shared::{BandwidthProof, ChunkRequest, ChunkResponse};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

fn bench_validate_content_size(c: &mut Criterion) {
    let limits = ContentLimits::default();

    c.bench_function("validate_content_size", |b| {
        b.iter(|| {
            let result = validate_content_size(
                black_box(10 * 1024 * 1024), // 10 MB
                black_box(&limits),
            );
            black_box(result)
        });
    });
}

fn bench_validate_chunk_index(c: &mut Criterion) {
    c.bench_function("validate_chunk_index", |b| {
        b.iter(|| {
            let result = validate_chunk_index(black_box(50), black_box(100));
            black_box(result)
        });
    });
}

fn bench_validate_request_timestamp(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let request = ChunkRequest {
        content_cid: "QmTest123".to_string(),
        chunk_index: 0,
        challenge_nonce: [1u8; 32],
        requester_peer_id: "peer1".to_string(),
        requester_public_key: keypair.public_key(),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    let max_age = Duration::from_secs(300);

    c.bench_function("validate_request_timestamp", |b| {
        b.iter(|| {
            let result = validate_request_timestamp(black_box(&request), black_box(max_age));
            black_box(result)
        });
    });
}

fn bench_validate_response_signature(c: &mut Criterion) {
    let response = ChunkResponse {
        encrypted_chunk: vec![1u8; 1024],
        chunk_hash: [2u8; 32],
        provider_signature: vec![3u8; 64],
        provider_public_key: [4u8; 32],
        challenge_echo: [5u8; 32],
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    c.bench_function("validate_response_signature", |b| {
        b.iter(|| {
            let result = validate_response_signature(black_box(&response));
            black_box(result)
        });
    });
}

fn bench_validate_proof_structure(c: &mut Criterion) {
    let proof = BandwidthProof {
        session_id: uuid::Uuid::new_v4(),
        content_cid: "QmTest123".to_string(),
        chunk_index: 0,
        bytes_transferred: 1024,
        start_timestamp_ms: 1000,
        end_timestamp_ms: 2000,
        provider_peer_id: "provider".to_string(),
        requester_peer_id: "requester".to_string(),
        provider_public_key: vec![1u8; 32],
        requester_public_key: vec![2u8; 32],
        provider_signature: vec![3u8; 64],
        requester_signature: vec![4u8; 64],
        challenge_nonce: vec![5u8; 32],
        chunk_hash: vec![6u8; 32],
        latency_ms: 1000,
    };

    c.bench_function("validate_proof_structure", |b| {
        b.iter(|| {
            let result = validate_proof_structure(black_box(&proof));
            black_box(result)
        });
    });
}

fn bench_calculate_expected_chunks(c: &mut Criterion) {
    c.bench_function("calculate_expected_chunks", |b| {
        b.iter(|| {
            let chunks = calculate_expected_chunks(black_box(100 * 1024 * 1024)); // 100 MB
            black_box(chunks)
        });
    });
}

fn bench_validate_bandwidth(c: &mut Criterion) {
    c.bench_function("validate_bandwidth", |b| {
        b.iter(|| {
            let result = validate_bandwidth(
                black_box(100_000_000), // 100 MB
                black_box(10_000),      // 10 seconds
                black_box(1000.0),      // 1 Gbps max
            );
            black_box(result)
        });
    });
}

fn bench_sanitize_cid(c: &mut Criterion) {
    let cid = "QmTest123WithSome../../../SpecialChars!@#$%";

    c.bench_function("sanitize_cid", |b| {
        b.iter(|| {
            let sanitized = sanitize_cid(black_box(cid));
            black_box(sanitized)
        });
    });
}

fn bench_validate_all_checks(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let limits = ContentLimits::default();
    let request = ChunkRequest {
        content_cid: "QmTest123".to_string(),
        chunk_index: 0,
        challenge_nonce: [1u8; 32],
        requester_peer_id: "peer1".to_string(),
        requester_public_key: keypair.public_key(),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    c.bench_function("validate_all_checks", |b| {
        b.iter(|| {
            // Simulate a full validation pipeline
            let content_size = 10 * 1024 * 1024u64;
            let _ = validate_content_size(content_size, &limits);

            let total_chunks = calculate_expected_chunks(content_size);
            let _ = validate_chunk_index(0, total_chunks);

            let _ = validate_request_timestamp(&request, Duration::from_secs(300));

            let _ = validate_bandwidth(1024 * 1024, 1000, 1000.0);

            black_box(())
        });
    });
}

fn bench_content_limits_default(c: &mut Criterion) {
    c.bench_function("content_limits_default", |b| {
        b.iter(|| {
            let limits = ContentLimits::default();
            black_box(limits)
        });
    });
}

criterion_group!(
    benches,
    bench_validate_content_size,
    bench_validate_chunk_index,
    bench_validate_request_timestamp,
    bench_validate_response_signature,
    bench_validate_proof_structure,
    bench_calculate_expected_chunks,
    bench_validate_bandwidth,
    bench_sanitize_cid,
    bench_validate_all_checks,
    bench_content_limits_default,
);

criterion_main!(benches);
