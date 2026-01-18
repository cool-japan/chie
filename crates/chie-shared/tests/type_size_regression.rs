//! Type size regression tests to ensure we don't accidentally grow type sizes.
//!
//! These tests help catch unintentional memory bloat from adding fields or
//! changing representations. If a test fails, consider if the size increase
//! is justified or if there's a more efficient representation.

use chie_shared::*;

/// Test core protocol types don't grow unexpectedly
#[test]
fn test_bandwidth_proof_size() {
    // BandwidthProof is a critical type sent over the network frequently
    let size = std::mem::size_of::<types::bandwidth::BandwidthProof>();
    // Current size on 64-bit systems (adjust if intentionally changed)
    // Contains: proof_id (UUID=16), cid (String=24), chunk_index (4), peer_id (String=24),
    // chunk_data (Vec=24), challenge_nonce (32), challenge_echo (32), timestamp_ms (8),
    // latency_ms (4), bandwidth_bps (8), provider_signature (Vec=24), requester_signature (Option<Vec>=32)
    // Actual size: 272 bytes (measured on 64-bit)
    assert!(
        size <= 288,
        "BandwidthProof size is {size} bytes, expected <= 288 bytes"
    );
}

#[test]
fn test_content_metadata_size() {
    let size = std::mem::size_of::<types::content::ContentMetadata>();
    // Contains: cid (String=24), title (String=24), description (String=24), creator_id (UUID=16),
    // file_size (8), chunk_count (4), category (1), price (8), tags (Vec=24), created_at (12)
    assert!(
        size <= 256,
        "ContentMetadata size is {size} bytes, expected <= 256 bytes"
    );
}

#[test]
fn test_chunk_request_size() {
    let size = std::mem::size_of::<ChunkRequest>();
    // Contains: cid (String=24), chunk_index (4), challenge_nonce (32), requester_peer_id (String=24)
    assert!(
        size <= 128,
        "ChunkRequest size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_chunk_response_size() {
    let size = std::mem::size_of::<ChunkResponse>();
    // Contains: cid (String=24), chunk_index (4), chunk_data (Vec=24), challenge_echo (32), provider_signature (Vec=24)
    // Actual size: 152 bytes (measured on 64-bit)
    assert!(
        size <= 160,
        "ChunkResponse size is {size} bytes, expected <= 160 bytes"
    );
}

/// Test API response types stay reasonable
#[test]
fn test_api_response_size() {
    let size = std::mem::size_of::<types::api::ApiResponse<()>>();
    // Contains: success (1), data (0 for ()), message (Option<String>=32), timestamp (12)
    assert!(
        size <= 64,
        "ApiResponse<()> size is {size} bytes, expected <= 64 bytes"
    );
}

#[test]
fn test_api_error_size() {
    let size = std::mem::size_of::<types::api::ApiError>();
    // Contains: success (1), error_code (String=24), message (String=24), details (Option<Vec>=32), timestamp (12)
    assert!(
        size <= 128,
        "ApiError size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_paginated_response_size() {
    let size = std::mem::size_of::<types::api::PaginatedResponse<()>>();
    // Contains: items (Vec=24), total (8), offset (8), limit (8), has_more (1)
    assert!(
        size <= 64,
        "PaginatedResponse<()> size is {size} bytes, expected <= 64 bytes"
    );
}

/// Test statistics types are efficiently sized
#[test]
fn test_bandwidth_stats_size() {
    let size = std::mem::size_of::<types::stats::BandwidthStats>();
    // Contains multiple u64/f64 fields for totals and averages
    assert!(
        size <= 128,
        "BandwidthStats size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_cache_stats_size() {
    let size = std::mem::size_of::<types::cache::CacheStats>();
    // Contains multiple u64 fields for cache metrics
    assert!(
        size <= 128,
        "CacheStats size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_user_quota_size() {
    let size = std::mem::size_of::<types::quota::UserQuota>();
    // Contains: user_id (UUID=16), storage (StorageQuota), bandwidth (BandwidthQuota), rate_limit (RateLimitQuota)
    assert!(
        size <= 256,
        "UserQuota size is {size} bytes, expected <= 256 bytes"
    );
}

/// Test configuration types
#[test]
fn test_network_config_size() {
    let size = std::mem::size_of::<NetworkConfig>();
    // Contains several primitives and two Vec<String>
    assert!(
        size <= 128,
        "NetworkConfig size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_timeout_config_size() {
    let size = std::mem::size_of::<TimeoutConfig>();
    // Contains 6 u64 fields
    assert!(
        size <= 64,
        "TimeoutConfig size is {size} bytes, expected <= 64 bytes"
    );
}

#[test]
fn test_retry_config_size() {
    let size = std::mem::size_of::<RetryConfig>();
    // Contains: max_attempts (4), initial_backoff_ms (8), max_backoff_ms (8), multiplier (8), enable_jitter (1)
    assert!(
        size <= 64,
        "RetryConfig size is {size} bytes, expected <= 64 bytes"
    );
}

/// Test ID wrapper types are zero-cost
#[test]
fn test_content_id_size() {
    let size = std::mem::size_of::<types::ids::ContentId>();
    // Should be same size as String (24 bytes on 64-bit)
    let string_size = std::mem::size_of::<String>();
    assert_eq!(
        size, string_size,
        "ContentId size is {size} bytes, expected {string_size} bytes (same as String)"
    );
}

#[test]
fn test_peer_id_size() {
    let size = std::mem::size_of::<types::ids::PeerId>();
    let string_size = std::mem::size_of::<String>();
    assert_eq!(
        size, string_size,
        "PeerId size is {size} bytes, expected {string_size} bytes (same as String)"
    );
}

#[test]
fn test_proof_id_size() {
    let size = std::mem::size_of::<types::ids::ProofId>();
    let string_size = std::mem::size_of::<String>();
    assert_eq!(
        size, string_size,
        "ProofId size is {size} bytes, expected {string_size} bytes (same as String)"
    );
}

/// Test result types
#[test]
fn test_chie_result_size() {
    let size = std::mem::size_of::<ChieResult<()>>();
    // Result<(), ChieError> where ChieError contains Box<ChieErrorInner>
    // Actual size: 56 bytes (measured on 64-bit)
    assert!(
        size <= 64,
        "ChieResult<()> size is {size} bytes, expected <= 64 bytes"
    );
}

#[test]
fn test_rate_limit_headers_size() {
    let size = std::mem::size_of::<types::api::RateLimitHeaders>();
    // Contains: limit (4), remaining (4), reset (8), retry_after (Option<u64>=16)
    assert_eq!(
        size, 32,
        "RateLimitHeaders size is {size} bytes, expected 32 bytes"
    );
}

/// Test enum sizes are reasonable
#[test]
fn test_content_category_size() {
    let size = std::mem::size_of::<types::enums::ContentCategory>();
    // Simple enum should be 1 byte
    assert_eq!(
        size, 1,
        "ContentCategory size is {size} bytes, expected 1 byte"
    );
}

#[test]
fn test_user_role_size() {
    let size = std::mem::size_of::<types::enums::UserRole>();
    assert_eq!(size, 1, "UserRole size is {size} bytes, expected 1 byte");
}

#[test]
fn test_service_status_size() {
    let size = std::mem::size_of::<types::enums::ServiceStatus>();
    assert_eq!(
        size, 1,
        "ServiceStatus size is {size} bytes, expected 1 byte"
    );
}

/// Test utility types
#[test]
fn test_circuit_breaker_size() {
    let size = std::mem::size_of::<utils::CircuitBreaker>();
    // Contains: state (1), failure_count (4), last_state_change (8), config fields
    assert!(
        size <= 128,
        "CircuitBreaker size is {size} bytes, expected <= 128 bytes"
    );
}

#[test]
fn test_streaming_stats_size() {
    let size = std::mem::size_of::<utils::StreamingStats>();
    // Contains: count (8), mean (8), m2 (8)
    assert_eq!(
        size, 24,
        "StreamingStats size is {size} bytes, expected 24 bytes"
    );
}

#[test]
fn test_histogram_size() {
    let size = std::mem::size_of::<utils::Histogram>();
    // Contains: Vec<u64> (24), total_count (8), sum (8)
    assert!(
        size <= 64,
        "Histogram size is {size} bytes, expected <= 64 bytes"
    );
}

#[test]
fn test_api_version_size() {
    let size = std::mem::size_of::<types::api::ApiVersion>();
    // Simple enum should be 1 byte
    assert_eq!(size, 1, "ApiVersion size is {size} bytes, expected 1 byte");
}
