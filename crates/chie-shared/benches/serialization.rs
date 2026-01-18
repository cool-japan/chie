//! Benchmarks for serialization performance of chie-shared types.

use chie_shared::*;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn create_sample_bandwidth_proof() -> BandwidthProof {
    BandwidthProofBuilder::new()
        .content_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        .chunk_index(42)
        .bytes_transferred(CHUNK_SIZE as u64)
        .provider_peer_id("12D3KooWProviderPeerID1234567890ABCDEFGHIJ")
        .requester_peer_id("12D3KooWRequesterPeerID1234567890ABCDEFGHI")
        .provider_public_key(vec![1u8; 32])
        .requester_public_key(vec![2u8; 32])
        .provider_signature(vec![3u8; 64])
        .requester_signature(vec![4u8; 64])
        .challenge_nonce(vec![5u8; 32])
        .chunk_hash(vec![6u8; 32])
        .timestamps(1000000, 1000100)
        .build()
        .unwrap()
}

fn create_sample_content_metadata() -> ContentMetadata {
    ContentMetadataBuilder::new()
        .cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
        .title("Sample 3D Model - Lowpoly Character")
        .description("A beautiful lowpoly character model optimized for games")
        .category(ContentCategory::ThreeDModels)
        .add_tag("blender")
        .add_tag("lowpoly")
        .add_tag("character")
        .add_tag("game-ready")
        .size_bytes(5 * 1024 * 1024)
        .price(1000)
        .creator_id(uuid::Uuid::new_v4())
        .status(ContentStatus::Active)
        .build()
        .unwrap()
}

fn create_sample_chunk_request() -> ChunkRequest {
    ChunkRequest {
        content_cid: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
        chunk_index: 10,
        challenge_nonce: [7u8; 32],
        requester_peer_id: "12D3KooWRequester".to_string(),
        requester_public_key: [8u8; 32],
        timestamp_ms: 1234567890,
    }
}

fn create_sample_chunk_response() -> ChunkResponse {
    ChunkResponse {
        encrypted_chunk: vec![42u8; CHUNK_SIZE],
        chunk_hash: [9u8; 32],
        provider_signature: vec![10u8; 64],
        provider_public_key: [11u8; 32],
        challenge_echo: [12u8; 32],
        timestamp_ms: 1234567990,
    }
}

fn bench_bandwidth_proof_serialization(c: &mut Criterion) {
    let proof = create_sample_bandwidth_proof();

    c.bench_function("bandwidth_proof_serialize", |b| {
        b.iter(|| {
            let _ = black_box(serde_json::to_string(&proof).unwrap());
        });
    });

    let json = serde_json::to_string(&proof).unwrap();
    c.bench_function("bandwidth_proof_deserialize", |b| {
        b.iter(|| {
            let _: BandwidthProof = black_box(serde_json::from_str(&json).unwrap());
        });
    });

    c.bench_function("bandwidth_proof_validation", |b| {
        b.iter(|| {
            let _ = black_box(proof.validate());
        });
    });
}

fn bench_content_metadata_serialization(c: &mut Criterion) {
    let metadata = create_sample_content_metadata();

    c.bench_function("content_metadata_serialize", |b| {
        b.iter(|| {
            let _ = black_box(serde_json::to_string(&metadata).unwrap());
        });
    });

    let json = serde_json::to_string(&metadata).unwrap();
    c.bench_function("content_metadata_deserialize", |b| {
        b.iter(|| {
            let _: ContentMetadata = black_box(serde_json::from_str(&json).unwrap());
        });
    });

    c.bench_function("content_metadata_validation", |b| {
        b.iter(|| {
            let _ = black_box(metadata.validate());
        });
    });
}

fn bench_chunk_request_serialization(c: &mut Criterion) {
    let request = create_sample_chunk_request();

    c.bench_function("chunk_request_serialize", |b| {
        b.iter(|| {
            let _ = black_box(serde_json::to_string(&request).unwrap());
        });
    });

    let json = serde_json::to_string(&request).unwrap();
    c.bench_function("chunk_request_deserialize", |b| {
        b.iter(|| {
            let _: ChunkRequest = black_box(serde_json::from_str(&json).unwrap());
        });
    });
}

fn bench_chunk_response_serialization(c: &mut Criterion) {
    let response = create_sample_chunk_response();

    c.bench_function("chunk_response_serialize", |b| {
        b.iter(|| {
            let _ = black_box(serde_json::to_string(&response).unwrap());
        });
    });

    let json = serde_json::to_string(&response).unwrap();
    c.bench_function("chunk_response_deserialize", |b| {
        b.iter(|| {
            let _: ChunkResponse = black_box(serde_json::from_str(&json).unwrap());
        });
    });
}

fn bench_builder_patterns(c: &mut Criterion) {
    c.bench_function("bandwidth_proof_builder", |b| {
        b.iter(|| {
            let _ = black_box(create_sample_bandwidth_proof());
        });
    });

    c.bench_function("content_metadata_builder", |b| {
        b.iter(|| {
            let _ = black_box(create_sample_content_metadata());
        });
    });
}

fn bench_utility_functions(c: &mut Criterion) {
    use chie_shared::{
        calculate_bandwidth_mbps, calculate_demand_multiplier, calculate_latency_ms,
        calculate_percentage, format_bytes, format_duration_ms, format_points, generate_nonce,
        is_timestamp_valid, is_valid_cid, is_valid_email, is_valid_username, now_ms,
    };

    c.bench_function("generate_nonce", |b| {
        b.iter(|| {
            let _ = black_box(generate_nonce());
        });
    });

    c.bench_function("is_timestamp_valid", |b| {
        let now = now_ms();
        b.iter(|| {
            let _ = black_box(is_timestamp_valid(now, 5000));
        });
    });

    c.bench_function("calculate_latency_ms", |b| {
        b.iter(|| {
            let _ = black_box(calculate_latency_ms(1000, 2000));
        });
    });

    c.bench_function("format_bytes", |b| {
        b.iter(|| {
            let _ = black_box(format_bytes(1024 * 1024 * 500));
        });
    });

    c.bench_function("format_duration_ms", |b| {
        b.iter(|| {
            let _ = black_box(format_duration_ms(3_600_000));
        });
    });

    c.bench_function("format_points", |b| {
        b.iter(|| {
            let _ = black_box(format_points(1_234_567));
        });
    });

    c.bench_function("calculate_percentage", |b| {
        b.iter(|| {
            let _ = black_box(calculate_percentage(750, 1000));
        });
    });

    c.bench_function("calculate_bandwidth_mbps", |b| {
        b.iter(|| {
            let _ = black_box(calculate_bandwidth_mbps(CHUNK_SIZE as u64, 100));
        });
    });

    c.bench_function("calculate_demand_multiplier", |b| {
        b.iter(|| {
            let _ = black_box(calculate_demand_multiplier(100, 50));
        });
    });

    c.bench_function("is_valid_cid", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_cid(
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            ));
        });
    });

    c.bench_function("is_valid_email", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_email("user@example.com"));
        });
    });

    c.bench_function("is_valid_username", |b| {
        b.iter(|| {
            let _ = black_box(is_valid_username("user_name_123"));
        });
    });
}

criterion_group!(
    benches,
    bench_bandwidth_proof_serialization,
    bench_content_metadata_serialization,
    bench_chunk_request_serialization,
    bench_chunk_response_serialization,
    bench_builder_patterns,
    bench_utility_functions
);
criterion_main!(benches);
