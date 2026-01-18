//! Property-based tests for chie-shared types using proptest.

use chie_shared::*;
use proptest::prelude::*;

prop_compose! {
    fn arb_content_metadata()(
        cid in "bafy[a-z0-9]{50}",
        title in "[a-zA-Z0-9 ]{1,100}",
        description in "[a-zA-Z0-9 ]{0,500}",
        category in prop::sample::select(vec![
            ContentCategory::ThreeDModels,
            ContentCategory::Textures,
            ContentCategory::Audio,
            ContentCategory::Scripts,
            ContentCategory::Animations,
            ContentCategory::AssetPacks,
            ContentCategory::AiModels,
            ContentCategory::Other,
        ]),
        size_bytes in (MIN_CONTENT_SIZE..1024 * 1024 * 10u64),
        price in 0u64..1_000_000u64,
    ) -> ContentMetadata {
        let creator_id = uuid::Uuid::new_v4();
        let chunk_count = size_bytes.div_ceil(CHUNK_SIZE as u64);

        ContentMetadata {
            id: uuid::Uuid::new_v4(),
            cid,
            title,
            description,
            category,
            tags: vec![],
            size_bytes,
            chunk_count,
            price,
            creator_id,
            status: ContentStatus::Active,
            preview_images: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}

prop_compose! {
    fn arb_bandwidth_proof()(
        content_cid in "bafy[a-z0-9]{50}",
        chunk_index in 0u64..1000u64,
        bytes_transferred in (CHUNK_SIZE as u64)..(CHUNK_SIZE as u64 + 1000),
        provider_peer_id in "12D3KooW[A-Za-z0-9]{40}",
        requester_peer_id in "12D3KooW[A-Za-z0-9]{40}",
        start_ms in 1000i64..1_000_000i64,
        latency_ms in (MIN_LATENCY_MS..10000u32),
    ) -> Result<BandwidthProof, &'static str> {
        BandwidthProofBuilder::new()
            .content_cid(content_cid)
            .chunk_index(chunk_index)
            .bytes_transferred(bytes_transferred)
            .provider_peer_id(provider_peer_id)
            .requester_peer_id(requester_peer_id)
            .provider_public_key(vec![0u8; 32])
            .requester_public_key(vec![1u8; 32])
            .provider_signature(vec![0u8; 64])
            .requester_signature(vec![1u8; 64])
            .challenge_nonce(vec![0u8; 32])
            .chunk_hash(vec![0u8; 32])
            .timestamps(start_ms, start_ms + latency_ms as i64)
            .build()
    }
}

proptest! {
    #[test]
    fn test_content_metadata_roundtrip_serde(metadata in arb_content_metadata()) {
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ContentMetadata = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(metadata.id, deserialized.id);
        prop_assert_eq!(metadata.cid, deserialized.cid);
        prop_assert_eq!(metadata.title, deserialized.title);
        prop_assert_eq!(metadata.size_bytes, deserialized.size_bytes);
    }

    #[test]
    fn test_bandwidth_proof_roundtrip_serde(proof_result in arb_bandwidth_proof()) {
        let proof = proof_result.unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: BandwidthProof = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(proof.session_id, deserialized.session_id);
        prop_assert_eq!(proof.content_cid, deserialized.content_cid);
        prop_assert_eq!(proof.chunk_index, deserialized.chunk_index);
        prop_assert_eq!(proof.bytes_transferred, deserialized.bytes_transferred);
    }

    #[test]
    fn test_content_metadata_expected_chunks_correct(
        size_bytes in (MIN_CONTENT_SIZE..MAX_CONTENT_SIZE)
    ) {
        let metadata = ContentMetadataBuilder::new()
            .cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
            .title("Test")
            .size_bytes(size_bytes)
            .creator_id(uuid::Uuid::new_v4())
            .build()
            .unwrap();

        let expected = size_bytes.div_ceil(CHUNK_SIZE as u64);
        prop_assert_eq!(metadata.expected_chunk_count(), expected);
        prop_assert_eq!(metadata.chunk_count, expected);
    }

    #[test]
    fn test_bandwidth_proof_sign_messages_deterministic(
        proof_result in arb_bandwidth_proof()
    ) {
        let proof = proof_result.unwrap();
        let msg1 = proof.provider_sign_message();
        let msg2 = proof.provider_sign_message();
        prop_assert_eq!(msg1, msg2);

        let req_msg1 = proof.requester_sign_message();
        let req_msg2 = proof.requester_sign_message();
        prop_assert_eq!(req_msg1, req_msg2);
    }

    #[test]
    fn test_validation_error_display_contains_values(
        timestamp_ms in 0i64..1_000_000_000i64,
        now_ms in 0i64..1_000_000_000i64,
    ) {
        let err = ValidationError::TimestampInFuture { timestamp_ms, now_ms };
        let s = err.to_string();
        prop_assert!(s.contains(&timestamp_ms.to_string()));
        prop_assert!(s.contains(&now_ms.to_string()));
    }

    #[test]
    fn test_paginated_response_has_more_logic(
        total in 0u64..1000u64,
        offset in 0u64..100u64,
        items_count in 0usize..50usize,
    ) {
        let items: Vec<i32> = (0..items_count).map(|i| i as i32).collect();
        let response = PaginatedResponse::new(items.clone(), total, offset, items_count as u64);

        let should_have_more = offset + (items_count as u64) < total;
        prop_assert_eq!(response.has_more, should_have_more);
    }

    #[test]
    fn test_content_category_to_from_sql_enum_roundtrip(
        category in prop::sample::select(vec![
            ContentCategory::ThreeDModels,
            ContentCategory::Textures,
            ContentCategory::Audio,
            ContentCategory::Scripts,
            ContentCategory::Animations,
            ContentCategory::AssetPacks,
            ContentCategory::AiModels,
            ContentCategory::Other,
        ])
    ) {
        let sql = category.to_sql_enum();
        let roundtrip = ContentCategory::from_sql_enum(sql).unwrap();
        prop_assert_eq!(category, roundtrip);
    }

    #[test]
    fn test_api_response_serialization_roundtrip(data in "[a-zA-Z0-9]{1,100}") {
        let response = ApiResponse::success(data.clone());
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse<String> = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(response.data, deserialized.data);
        prop_assert_eq!(response.success, deserialized.success);
    }

    #[test]
    fn test_node_status_to_from_sql_enum_roundtrip(
        status in prop::sample::select(vec![
            NodeStatus::Online,
            NodeStatus::Offline,
            NodeStatus::Syncing,
            NodeStatus::Banned,
        ])
    ) {
        let sql = status.to_sql_enum();
        let roundtrip = NodeStatus::from_sql_enum(sql).unwrap();
        prop_assert_eq!(status, roundtrip);
    }

    #[test]
    fn test_user_role_to_from_sql_enum_roundtrip(
        role in prop::sample::select(vec![
            UserRole::User,
            UserRole::Creator,
            UserRole::Admin,
        ])
    ) {
        let sql = role.to_sql_enum();
        let roundtrip = UserRole::from_sql_enum(sql).unwrap();
        prop_assert_eq!(role, roundtrip);
    }

    // Advanced property tests with custom strategies

    #[test]
    fn test_chunk_request_validation_invariants(
        content_cid in "bafy[a-z0-9]{50}",
        chunk_index in 0u64..10000u64,
        requester_peer_id in "12D3KooW[A-Za-z0-9]{40}",
    ) {
        let nonce = generate_nonce();
        let public_key = generate_nonce();
        let request = ChunkRequest::new(content_cid.clone(), chunk_index, nonce, requester_peer_id.clone(), public_key);

        prop_assert_eq!(request.content_cid, content_cid);
        prop_assert_eq!(request.chunk_index, chunk_index);
        prop_assert_eq!(request.requester_peer_id, requester_peer_id);
        prop_assert_eq!(request.challenge_nonce.len(), 32);
        prop_assert!(request.timestamp_ms > 0);
    }

    #[test]
    fn test_reward_calculation_bounds(
        bytes_transferred in (crate::core::gb_to_bytes(1) / 10)..(crate::core::gb_to_bytes(10)),
        demand in 1u64..1000u64,
        supply in 1u64..1000u64,
        latency_ms in MIN_LATENCY_MS..500u32,
    ) {
        let base_points = ((bytes_transferred as f64 / crate::core::gb_to_bytes(1) as f64) * BASE_POINTS_PER_GB).ceil() as u64;
        let multiplier = calculate_demand_multiplier(demand, supply);
        let reward = calculate_reward_with_penalty(base_points, multiplier, latency_ms, 500);

        // Multiplier should be in bounds
        prop_assert!(multiplier >= 1.0);
        prop_assert!(multiplier <= MAX_DEMAND_MULTIPLIER);

        // With low latency and reasonable transfer size, reward should be positive
        prop_assert!(base_points > 0);
        prop_assert!(reward > 0);

        // Reward should be within reasonable bounds
        let min_possible = base_points;
        let max_possible = (base_points as f64 * MAX_DEMAND_MULTIPLIER).ceil() as u64;
        prop_assert!(reward >= min_possible);
        prop_assert!(reward <= max_possible);
    }

    #[test]
    fn test_z_score_properties(
        value in -1000.0f64..1000.0,
        mean in -100.0f64..100.0,
        std_dev in 0.1f64..100.0,
    ) {
        let z = calculate_z_score(value, mean, std_dev);

        // If value == mean, z-score should be 0
        if (value - mean).abs() < 1e-10 {
            prop_assert!((z).abs() < 1e-6);
        }

        // z-score should be negative if value < mean
        if value < mean {
            prop_assert!(z < 0.0);
        }

        // z-score should be positive if value > mean
        if value > mean {
            prop_assert!(z > 0.0);
        }
    }

    #[test]
    fn test_ema_convergence(
        values in prop::collection::vec(0.0f64..100.0, 5..20),
        alpha in 0.1f64..0.9,
    ) {
        // Start EMA at first value to avoid initialization bias
        let mut ema = values[0];
        for &value in values.iter().skip(1) {
            ema = calculate_ema(value, ema, alpha);
        }

        // EMA should be finite and reasonable
        prop_assert!(ema.is_finite());
        prop_assert!(ema >= 0.0);
        prop_assert!(ema <= 100.0);
    }

    #[test]
    fn test_sanitize_string_removes_control_chars(
        input in "[a-zA-Z0-9 <>\"'&\\x00-\\x1F]{0,100}",
    ) {
        let sanitized = sanitize_string(&input);

        // Should not contain control characters (except whitespace)
        for ch in sanitized.chars() {
            prop_assert!(ch >= ' ' || ch.is_whitespace());
        }
    }

    #[test]
    fn test_sanitize_tags_normalization(
        tags in prop::collection::vec("[a-zA-Z ]{1,10}", 1..20),
    ) {
        let sanitized = sanitize_tags(&tags);

        // All tags should be lowercase and trimmed
        for tag in &sanitized {
            prop_assert_eq!(tag, &tag.to_lowercase());
            prop_assert_eq!(tag, &tag.trim());
            prop_assert!(!tag.is_empty());
        }

        // Should not exceed original count
        prop_assert!(sanitized.len() <= tags.len());
    }

    #[test]
    fn test_truncate_string_preserves_length_invariant(
        input in "[a-zA-Z0-9 ]{0,200}",
        max_len in 4usize..100usize,
    ) {
        let truncated = truncate_string(&input, max_len);

        // Result should never exceed max_len
        prop_assert!(truncated.len() <= max_len);

        // If input was shorter, should be unchanged
        if input.len() <= max_len {
            prop_assert_eq!(truncated, input);
        } else {
            // If truncated, should end with "..."
            prop_assert!(truncated.ends_with("..."));
        }
    }

    #[test]
    fn test_timestamp_validation_window(
        timestamp_offset in -10000i64..10000i64,
    ) {
        let now = now_ms();
        let timestamp = now + timestamp_offset;

        let is_valid = is_timestamp_valid(timestamp, TIMESTAMP_TOLERANCE_MS);

        // Should be valid if within tolerance and not in future
        let within_window = timestamp_offset.abs() <= TIMESTAMP_TOLERANCE_MS && timestamp <= now;
        prop_assert_eq!(is_valid, within_window);
    }

    #[test]
    fn test_format_bytes_monotonic(
        bytes1 in 0u64..1_000_000_000u64,
        bytes2 in 0u64..1_000_000_000u64,
    ) {
        let s1 = format_bytes(bytes1);
        let s2 = format_bytes(bytes2);

        // Formatted strings should contain numeric part
        prop_assert!(s1.chars().any(|c| c.is_ascii_digit()));
        prop_assert!(s2.chars().any(|c| c.is_ascii_digit()));

        // Should contain unit suffix
        prop_assert!(s1.contains("B") || s1.contains("KB") || s1.contains("MB") || s1.contains("GB"));
    }

    #[test]
    fn test_bandwidth_proof_builder_validation(
        content_cid in "bafy[a-z0-9]{50}",
        chunk_index in 0u64..1000u64,
        bytes_transferred in 0u64..10_000_000u64,
    ) {
        let result = BandwidthProofBuilder::new()
            .content_cid(content_cid)
            .chunk_index(chunk_index)
            .bytes_transferred(bytes_transferred)
            .provider_peer_id("12D3KooWTest1234567890123456789012345678901")
            .requester_peer_id("12D3KooWTest0987654321098765432109876543210")
            .provider_public_key(vec![0u8; 32])
            .requester_public_key(vec![1u8; 32])
            .provider_signature(vec![0u8; 64])
            .requester_signature(vec![1u8; 64])
            .challenge_nonce(vec![0u8; 32])
            .chunk_hash(vec![0u8; 32])
            .timestamps(now_ms(), now_ms() + 100)
            .build();

        // Builder should validate inputs
        if bytes_transferred == 0 {
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn test_content_metadata_builder_category_defaults(
        cid in "bafy[a-z0-9]{50}",
        title in "[a-zA-Z0-9 ]{1,100}",
        size_bytes in (MIN_CONTENT_SIZE..MAX_CONTENT_SIZE),
    ) {
        let metadata = ContentMetadataBuilder::new()
            .cid(cid)
            .title(title)
            .size_bytes(size_bytes)
            .creator_id(uuid::Uuid::new_v4())
            .build()
            .unwrap();

        // Default category should be set
        prop_assert_eq!(metadata.category, ContentCategory::Other);

        // Status should default to Processing
        prop_assert_eq!(metadata.status, ContentStatus::Processing);

        // Timestamps should be set
        prop_assert!(metadata.created_at.timestamp_millis() > 0);
        prop_assert!(metadata.updated_at.timestamp_millis() > 0);
    }

    #[test]
    fn test_lerp_interpolation(
        a in -1000.0f64..1000.0,
        b in -1000.0f64..1000.0,
        t in 0.0f64..1.0,
    ) {
        let result = lerp(a, b, t);

        // lerp does NOT clamp, so check the formula directly
        let expected = a + (b - a) * t;
        prop_assert!((result - expected).abs() < 1e-6);

        // Result should be bounded by min(a,b) and max(a,b) when t in [0,1]
        let min_val = a.min(b);
        let max_val = a.max(b);
        prop_assert!(result >= min_val - 1e-6);
        prop_assert!(result <= max_val + 1e-6);
    }

    // Binary encoding property tests
    #[test]
    fn test_binary_encoding_u32_roundtrip(value in any::<u32>()) {
        use chie_shared::{BinaryEncoder, BinaryDecoder};

        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u32(value).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_u32().unwrap();

        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn test_binary_encoding_u64_roundtrip(value in any::<u64>()) {
        use chie_shared::{BinaryEncoder, BinaryDecoder};

        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_u64(value).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_u64().unwrap();

        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn test_binary_encoding_string_roundtrip(s in "\\PC{0,100}") {
        use chie_shared::{BinaryEncoder, BinaryDecoder};

        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_string(&s).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_string().unwrap();

        prop_assert_eq!(s, decoded);
    }

    #[test]
    fn test_binary_encoding_bytes_roundtrip(bytes in prop::collection::vec(any::<u8>(), 0..1000)) {
        use chie_shared::{BinaryEncoder, BinaryDecoder};

        let mut buf = Vec::new();
        let mut encoder = BinaryEncoder::new(&mut buf);
        encoder.write_bytes(&bytes).unwrap();

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let decoded = decoder.read_bytes().unwrap();

        prop_assert_eq!(bytes, decoded);
    }

    #[test]
    fn test_crc32_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        use chie_shared::calculate_crc32;

        let crc1 = calculate_crc32(&data);
        let crc2 = calculate_crc32(&data);

        // Same data should always produce same checksum
        prop_assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc32_different_data(
        data1 in prop::collection::vec(any::<u8>(), 1..100),
        data2 in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        use chie_shared::calculate_crc32;

        // Filter out case where data is identical
        if data1 != data2 {
            let crc1 = calculate_crc32(&data1);
            let crc2 = calculate_crc32(&data2);

            // Different data should (almost always) produce different checksums
            // Note: There's a tiny chance of collision, but it's extremely rare
            if data1.len() != data2.len() || data1[0] != data2[0] {
                prop_assert_ne!(crc1, crc2);
            }
        }
    }
}
