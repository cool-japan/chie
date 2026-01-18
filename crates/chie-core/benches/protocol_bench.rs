use chie_core::protocol::{
    calculate_latency, create_bandwidth_proof, create_chunk_request, generate_challenge_nonce,
    is_valid_cid, validate_bandwidth_proof, validate_chunk_request, validate_chunk_response,
};
use chie_crypto::KeyPair;
use chie_shared::ChunkResponse;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_generate_challenge_nonce(c: &mut Criterion) {
    c.bench_function("generate_challenge_nonce", |b| {
        b.iter(|| {
            let nonce = generate_challenge_nonce();
            black_box(nonce)
        });
    });
}

fn bench_create_chunk_request(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let public_key = keypair.public_key();

    c.bench_function("create_chunk_request", |b| {
        b.iter(|| {
            let request = create_chunk_request(
                black_box("QmTest123".to_string()),
                black_box(0),
                black_box("peer-123".to_string()),
                black_box(public_key),
            );
            black_box(request)
        });
    });
}

fn bench_validate_chunk_request(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "peer-123".to_string(),
        keypair.public_key(),
    );

    c.bench_function("validate_chunk_request", |b| {
        b.iter(|| {
            let result = validate_chunk_request(black_box(&request));
            black_box(result)
        });
    });
}

fn bench_is_valid_cid(c: &mut Criterion) {
    c.bench_function("is_valid_cid", |b| {
        b.iter(|| {
            let result = is_valid_cid(black_box("QmTest1234567890123456789012345678901234567890"));
            black_box(result)
        });
    });
}

fn bench_calculate_latency(c: &mut Criterion) {
    c.bench_function("calculate_latency", |b| {
        b.iter(|| {
            let result = calculate_latency(black_box(1000), black_box(1500));
            black_box(result)
        });
    });
}

fn bench_validate_chunk_response(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "peer-123".to_string(),
        keypair.public_key(),
    );

    let response = ChunkResponse {
        encrypted_chunk: vec![1u8; 1024],
        chunk_hash: [2u8; 32],
        provider_signature: vec![3u8; 64],
        provider_public_key: [4u8; 32],
        challenge_echo: request.challenge_nonce,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    c.bench_function("validate_chunk_response", |b| {
        b.iter(|| {
            let result = validate_chunk_response(black_box(&response), black_box(&request));
            black_box(result)
        });
    });
}

fn bench_create_bandwidth_proof(c: &mut Criterion) {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "peer-requester".to_string(),
        requester_keypair.public_key(),
    );

    c.bench_function("create_bandwidth_proof", |b| {
        b.iter(|| {
            let proof = create_bandwidth_proof(
                black_box(&request),
                black_box("peer-provider".to_string()),
                black_box(provider_keypair.public_key().to_vec()),
                black_box(1_048_576), // 1 MB
                black_box(vec![1u8; 64]),
                black_box(vec![2u8; 64]),
                black_box(vec![3u8; 32]),
                black_box(1_000_000),
                black_box(1_100_000),
                black_box(100),
            );
            black_box(proof)
        });
    });
}

fn bench_validate_bandwidth_proof(c: &mut Criterion) {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "peer-requester".to_string(),
        requester_keypair.public_key(),
    );

    let proof = create_bandwidth_proof(
        &request,
        "peer-provider".to_string(),
        provider_keypair.public_key().to_vec(),
        1_048_576,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        1_000_000,
        1_100_000,
        100,
    );

    c.bench_function("validate_bandwidth_proof", |b| {
        b.iter(|| {
            let result = validate_bandwidth_proof(black_box(&proof));
            black_box(result)
        });
    });
}

fn bench_full_proof_verification_pipeline(c: &mut Criterion) {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    c.bench_function("full_proof_verification_pipeline", |b| {
        b.iter(|| {
            // Step 1: Create chunk request
            let request = create_chunk_request(
                black_box("QmTest123".to_string()),
                black_box(0),
                black_box("peer-requester".to_string()),
                black_box(requester_keypair.public_key()),
            );

            // Step 2: Validate chunk request
            let _ = validate_chunk_request(black_box(&request));

            // Step 3: Create chunk response
            let response = ChunkResponse {
                encrypted_chunk: vec![1u8; 1024],
                chunk_hash: [2u8; 32],
                provider_signature: vec![3u8; 64],
                provider_public_key: provider_keypair.public_key(),
                challenge_echo: request.challenge_nonce,
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
            };

            // Step 4: Validate chunk response
            let _ = validate_chunk_response(black_box(&response), black_box(&request));

            // Step 5: Create bandwidth proof
            let proof = create_bandwidth_proof(
                black_box(&request),
                black_box("peer-provider".to_string()),
                black_box(provider_keypair.public_key().to_vec()),
                black_box(1024),
                black_box(vec![1u8; 64]),
                black_box(vec![2u8; 64]),
                black_box(vec![3u8; 32]),
                black_box(1_000_000),
                black_box(1_100_000),
                black_box(100),
            );

            // Step 6: Validate bandwidth proof
            let result = validate_bandwidth_proof(black_box(&proof));
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_generate_challenge_nonce,
    bench_create_chunk_request,
    bench_validate_chunk_request,
    bench_is_valid_cid,
    bench_calculate_latency,
    bench_validate_chunk_response,
    bench_create_bandwidth_proof,
    bench_validate_bandwidth_proof,
    bench_full_proof_verification_pipeline
);
criterion_main!(benches);
