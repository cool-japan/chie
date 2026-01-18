//! Fuzz-like tests for deserialization robustness.
//!
//! These tests ensure that deserialization of malformed input doesn't panic
//! and handles errors gracefully.

use chie_shared::*;
use proptest::prelude::*;

/// Generate arbitrary byte sequences for fuzzing.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn fuzz_bandwidth_proof_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<BandwidthProof>(&bytes);
    }

    #[test]
    fn fuzz_content_metadata_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<ContentMetadata>(&bytes);
    }

    #[test]
    fn fuzz_chunk_request_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<ChunkRequest>(&bytes);
    }

    #[test]
    fn fuzz_chunk_response_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<ChunkResponse>(&bytes);
    }

    #[test]
    fn fuzz_api_response_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<ApiResponse<String>>(&bytes);
    }

    #[test]
    fn fuzz_paginated_response_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<PaginatedResponse<String>>(&bytes);
    }

    #[test]
    fn fuzz_user_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<User>(&bytes);
    }

    #[test]
    fn fuzz_node_stats_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<NodeStats>(&bytes);
    }

    #[test]
    fn fuzz_bandwidth_stats_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<BandwidthStats>(&bytes);
    }

    #[test]
    fn fuzz_content_stats_json_deserialize(bytes in arb_bytes()) {
        // Should not panic on invalid JSON
        let _ = serde_json::from_slice::<ContentStats>(&bytes);
    }

    /// Fuzz with semi-valid JSON structures that might have type mismatches.
    #[test]
    fn fuzz_with_malformed_json_objects(
        s in r#"\{"[a-z]{1,10}":\s*("[a-z0-9 ]{0,20}"|[0-9]{1,5}|true|false|null)\}"#
    ) {
        // Should not panic on type mismatches
        let _ = serde_json::from_str::<BandwidthProof>(&s);
        let _ = serde_json::from_str::<ContentMetadata>(&s);
        let _ = serde_json::from_str::<ChunkRequest>(&s);
    }

    /// Fuzz with UTF-8 edge cases.
    #[test]
    fn fuzz_with_utf8_edge_cases(
        s in r#"[\x00-\x7F\u{80}-\u{10FFFF}]{0,100}"#
    ) {
        let json = format!(r#"{{"data": "{}"}}"#, s);
        // Should not panic on UTF-8 edge cases
        let _ = serde_json::from_str::<ApiResponse<String>>(&json);
    }

    /// Fuzz validation functions with random inputs.
    #[test]
    fn fuzz_email_validation(s in r#"[^\x00]{0,100}"#) {
        // Should not panic
        let _ = is_valid_email(&s);
    }

    #[test]
    fn fuzz_username_validation(s in r#"[^\x00]{0,100}"#) {
        // Should not panic
        let _ = is_valid_username(&s);
    }

    #[test]
    fn fuzz_cid_validation(s in r#"[^\x00]{0,100}"#) {
        // Should not panic
        let _ = is_valid_cid(&s);
    }

    #[test]
    fn fuzz_peer_id_validation(s in r#"[^\x00]{0,100}"#) {
        // Should not panic
        let _ = is_valid_peer_id(&s);
    }

    #[test]
    fn fuzz_sanitize_string(s in r#"[\x00-\u{10FFFF}]{0,1000}"#) {
        // Should not panic
        let _ = sanitize_string(&s);
    }

    #[test]
    fn fuzz_truncate_string(
        s in r#"[\x00-\u{10FFFF}]{0,1000}"#,
        max_len in 0usize..500usize
    ) {
        // Should not panic - just call the function
        let _ = truncate_string(&s, max_len);
    }

    #[test]
    fn fuzz_parse_bandwidth_str(s in r#"[^\x00]{0,50}"#) {
        // Should not panic
        let _ = parse_bandwidth_str(&s);
    }

    /// Fuzz content category conversion.
    #[test]
    fn fuzz_content_category_from_sql(s in r#"[a-z_]{0,20}"#) {
        // Should not panic, just return error for invalid strings
        let _ = ContentCategory::from_sql_enum(&s);
    }

    #[test]
    fn fuzz_node_status_from_sql(s in r#"[a-z_]{0,20}"#) {
        // Should not panic
        let _ = NodeStatus::from_sql_enum(&s);
    }

    #[test]
    fn fuzz_user_role_from_sql(s in r#"[a-z_]{0,20}"#) {
        // Should not panic
        let _ = UserRole::from_sql_enum(&s);
    }

    #[test]
    fn fuzz_content_status_from_sql(s in r#"[a-z_]{0,20}"#) {
        // Should not panic
        let _ = ContentStatus::from_sql_enum(&s);
    }

    /// Fuzz calculation functions with extreme values.
    #[test]
    fn fuzz_calculate_z_score(
        value in -1e308f64..1e308f64,
        mean in -1e308f64..1e308f64,
        std_dev in -1e308f64..1e308f64,
    ) {
        // Should not panic even with extreme values
        let result = calculate_z_score(value, mean, std_dev);
        assert!(result.is_finite() || result.is_nan() || result.is_infinite());
    }

    #[test]
    fn fuzz_calculate_ema(
        current in -1e308f64..1e308f64,
        new_value in -1e308f64..1e308f64,
        alpha in -10.0f64..10.0f64,
    ) {
        // Should not panic even with out-of-range alpha
        let result = calculate_ema(current, new_value, alpha);
        assert!(result.is_finite() || result.is_nan() || result.is_infinite());
    }
}

#[cfg(test)]
mod unit_fuzz_tests {
    use super::*;

    #[test]
    fn test_deserialize_empty_bytes() {
        let bytes = b"";
        assert!(serde_json::from_slice::<BandwidthProof>(bytes).is_err());
        assert!(serde_json::from_slice::<ContentMetadata>(bytes).is_err());
    }

    #[test]
    fn test_deserialize_random_bytes() {
        let bytes = b"\x00\x01\x02\x03\x04\x05";
        assert!(serde_json::from_slice::<BandwidthProof>(bytes).is_err());
        assert!(serde_json::from_slice::<ChunkRequest>(bytes).is_err());
    }

    #[test]
    fn test_deserialize_partial_json() {
        let partial = b"{\"session_id\":\"test\"";
        assert!(serde_json::from_slice::<BandwidthProof>(partial).is_err());
    }

    #[test]
    fn test_deserialize_wrong_types() {
        let json = r#"{"session_id": 12345}"#;
        assert!(serde_json::from_str::<BandwidthProof>(json).is_err());
    }

    #[test]
    fn test_validation_with_empty_strings() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_username(""));
        assert!(!is_valid_cid(""));
        assert!(!is_valid_peer_id(""));
    }

    #[test]
    fn test_validation_with_null_bytes() {
        // Validation functions should handle null bytes gracefully (may or may not reject them)
        let _ = is_valid_email("test\x00@example.com");
        let _ = is_valid_username("user\x00name");
        // The key is that they don't panic
    }

    #[test]
    fn test_sanitize_with_extreme_lengths() {
        let long_string = "a".repeat(100_000);
        let result = sanitize_string(&long_string);
        assert_eq!(result.len(), long_string.len());
    }
}
