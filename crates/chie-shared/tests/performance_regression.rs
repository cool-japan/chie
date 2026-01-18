//! Performance regression tests for chie-shared.
//!
//! These tests ensure that critical operations don't regress in performance.
//! They run as part of the regular test suite and fail if operations take
//! longer than expected thresholds.

use chie_shared::*;
use std::time::Instant;

/// Maximum acceptable time for serializing a bandwidth proof (microseconds).
/// Higher threshold when schema feature is enabled due to extra derive overhead.
#[cfg(not(feature = "schema"))]
const MAX_BANDWIDTH_PROOF_SERIALIZE_US: u128 = 500;
#[cfg(feature = "schema")]
const MAX_BANDWIDTH_PROOF_SERIALIZE_US: u128 = 1000;

/// Maximum acceptable time for deserializing a bandwidth proof (microseconds).
/// Higher threshold when schema feature is enabled due to extra derive overhead.
#[cfg(not(feature = "schema"))]
const MAX_BANDWIDTH_PROOF_DESERIALIZE_US: u128 = 500;
#[cfg(feature = "schema")]
const MAX_BANDWIDTH_PROOF_DESERIALIZE_US: u128 = 1000;

/// Maximum acceptable time for validating a bandwidth proof (microseconds).
/// Higher threshold when schema feature is enabled due to extra derive overhead.
#[cfg(not(feature = "schema"))]
const MAX_BANDWIDTH_PROOF_VALIDATE_US: u128 = 100;
#[cfg(feature = "schema")]
const MAX_BANDWIDTH_PROOF_VALIDATE_US: u128 = 200;

/// Maximum acceptable time for content metadata serialization (microseconds).
/// Higher threshold when schema feature is enabled due to extra derive overhead.
#[cfg(not(feature = "schema"))]
const MAX_CONTENT_METADATA_SERIALIZE_US: u128 = 500;
#[cfg(feature = "schema")]
const MAX_CONTENT_METADATA_SERIALIZE_US: u128 = 1000;

/// Maximum acceptable time for building a bandwidth proof (microseconds).
/// Higher threshold when schema feature is enabled due to extra derive overhead.
#[cfg(not(feature = "schema"))]
const MAX_BUILDER_PATTERN_US: u128 = 250;
#[cfg(feature = "schema")]
const MAX_BUILDER_PATTERN_US: u128 = 400;

/// Maximum acceptable time for utility functions (microseconds).
const MAX_UTILITY_FUNCTION_US: u128 = 50;

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
        .title("Sample 3D Model")
        .description("A test model")
        .category(ContentCategory::ThreeDModels)
        .size_bytes(5 * 1024 * 1024)
        .price(1000)
        .creator_id(uuid::Uuid::new_v4())
        .build()
        .unwrap()
}

/// Measure the average time to execute a function over multiple iterations.
fn measure_avg_time<F>(iterations: usize, mut f: F) -> u128
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    elapsed.as_micros() / iterations as u128
}

#[test]
fn test_bandwidth_proof_serialization_performance() {
    let proof = create_sample_bandwidth_proof();

    let avg_time = measure_avg_time(100, || {
        let _ = serde_json::to_string(&proof).unwrap();
    });

    assert!(
        avg_time < MAX_BANDWIDTH_PROOF_SERIALIZE_US,
        "Bandwidth proof serialization took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_BANDWIDTH_PROOF_SERIALIZE_US
    );
}

#[test]
fn test_bandwidth_proof_deserialization_performance() {
    let proof = create_sample_bandwidth_proof();
    let json = serde_json::to_string(&proof).unwrap();

    let avg_time = measure_avg_time(100, || {
        let _: BandwidthProof = serde_json::from_str(&json).unwrap();
    });

    assert!(
        avg_time < MAX_BANDWIDTH_PROOF_DESERIALIZE_US,
        "Bandwidth proof deserialization took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_BANDWIDTH_PROOF_DESERIALIZE_US
    );
}

#[test]
fn test_bandwidth_proof_validation_performance() {
    let proof = create_sample_bandwidth_proof();

    let avg_time = measure_avg_time(100, || {
        let _ = proof.validate();
    });

    assert!(
        avg_time < MAX_BANDWIDTH_PROOF_VALIDATE_US,
        "Bandwidth proof validation took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_BANDWIDTH_PROOF_VALIDATE_US
    );
}

#[test]
fn test_content_metadata_serialization_performance() {
    let metadata = create_sample_content_metadata();

    let avg_time = measure_avg_time(100, || {
        let _ = serde_json::to_string(&metadata).unwrap();
    });

    assert!(
        avg_time < MAX_CONTENT_METADATA_SERIALIZE_US,
        "Content metadata serialization took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_CONTENT_METADATA_SERIALIZE_US
    );
}

#[test]
fn test_content_metadata_deserialization_performance() {
    let metadata = create_sample_content_metadata();
    let json = serde_json::to_string(&metadata).unwrap();

    let avg_time = measure_avg_time(100, || {
        let _: ContentMetadata = serde_json::from_str(&json).unwrap();
    });

    assert!(
        avg_time < MAX_CONTENT_METADATA_SERIALIZE_US,
        "Content metadata deserialization took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_CONTENT_METADATA_SERIALIZE_US
    );
}

#[test]
fn test_builder_pattern_performance() {
    let avg_time = measure_avg_time(100, || {
        let _ = create_sample_bandwidth_proof();
    });

    assert!(
        avg_time < MAX_BUILDER_PATTERN_US,
        "Builder pattern took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_BUILDER_PATTERN_US
    );
}

#[test]
fn test_generate_nonce_performance() {
    let avg_time = measure_avg_time(100, || {
        let _ = generate_nonce();
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "generate_nonce took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_format_bytes_performance() {
    let avg_time = measure_avg_time(1000, || {
        let _ = format_bytes(1024 * 1024 * 500);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "format_bytes took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_calculate_demand_multiplier_performance() {
    let avg_time = measure_avg_time(1000, || {
        let _ = calculate_demand_multiplier(100, 50);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "calculate_demand_multiplier took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_is_valid_cid_performance() {
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    let avg_time = measure_avg_time(1000, || {
        let _ = is_valid_cid(cid);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "is_valid_cid took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_is_valid_email_performance() {
    let email = "user@example.com";

    let avg_time = measure_avg_time(1000, || {
        let _ = is_valid_email(email);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "is_valid_email took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_sanitize_string_performance() {
    let input = "Hello, World! This is a test string with some special chars: <>&\"'";

    let avg_time = measure_avg_time(1000, || {
        let _ = sanitize_string(input);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "sanitize_string took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_sanitize_tags_performance() {
    let tags = vec![
        "Blender".to_string(),
        "  LowPoly  ".to_string(),
        "Game-Ready".to_string(),
        "CHARACTER".to_string(),
    ];

    let avg_time = measure_avg_time(1000, || {
        let _ = sanitize_tags(&tags);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "sanitize_tags took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_calculate_z_score_performance() {
    let avg_time = measure_avg_time(1000, || {
        let _ = calculate_z_score(100.0, 75.0, 15.0);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "calculate_z_score took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_calculate_ema_performance() {
    let avg_time = measure_avg_time(1000, || {
        let _ = calculate_ema(100.0, 95.0, 0.2);
    });

    assert!(
        avg_time < MAX_UTILITY_FUNCTION_US,
        "calculate_ema took {}μs, expected <{}μs (regression detected)",
        avg_time,
        MAX_UTILITY_FUNCTION_US
    );
}

#[test]
fn test_bulk_serialization_performance() {
    // Test serializing multiple proofs (simulating batch operations)
    let proofs: Vec<_> = (0..10).map(|_| create_sample_bandwidth_proof()).collect();

    let start = Instant::now();
    for proof in &proofs {
        let _ = serde_json::to_string(proof).unwrap();
    }
    let elapsed = start.elapsed();

    // Should handle 10 serializations in under 15ms (20ms with schema feature)
    #[cfg(not(feature = "schema"))]
    const MAX_BULK_SERIALIZE_MS: u128 = 15;
    #[cfg(feature = "schema")]
    const MAX_BULK_SERIALIZE_MS: u128 = 20;

    assert!(
        elapsed.as_millis() < MAX_BULK_SERIALIZE_MS,
        "Bulk serialization (10 items) took {}ms, expected <{}ms (regression detected)",
        elapsed.as_millis(),
        MAX_BULK_SERIALIZE_MS
    );
}

#[test]
fn test_bulk_validation_performance() {
    // Test validating multiple proofs
    let proofs: Vec<_> = (0..10).map(|_| create_sample_bandwidth_proof()).collect();

    let start = Instant::now();
    for proof in &proofs {
        let _ = proof.validate();
    }
    let elapsed = start.elapsed();

    // Should validate 10 proofs in under 1ms
    assert!(
        elapsed.as_millis() < 1,
        "Bulk validation (10 items) took {}ms, expected <1ms (regression detected)",
        elapsed.as_millis()
    );
}
