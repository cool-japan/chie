//! Integration tests for the bandwidth proof verification pipeline.
//!
//! These tests verify the complete end-to-end workflow of:
//! 1. Creating chunk requests
//! 2. Validating requests
//! 3. Creating chunk responses
//! 4. Validating responses
//! 5. Creating bandwidth proofs
//! 6. Validating bandwidth proofs

use chie_core::protocol::{
    calculate_latency, create_bandwidth_proof, create_chunk_request, generate_challenge_nonce,
    validate_bandwidth_proof, validate_chunk_request, validate_chunk_response,
};
use chie_crypto::KeyPair;
use chie_shared::{BandwidthProof, ChunkRequest, ChunkResponse};

/// Test the complete bandwidth proof pipeline with valid data.
#[test]
fn test_valid_bandwidth_proof_pipeline() {
    // Setup: Generate keypairs for requester and provider
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    // Step 1: Requester creates a chunk request
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooRequester".to_string(),
        requester_keypair.public_key(),
    );

    // Step 2: Validate the chunk request
    let validation_result = validate_chunk_request(&request);
    assert!(
        validation_result.is_ok(),
        "Request validation failed: {:?}",
        validation_result
    );

    // Step 3: Provider creates a chunk response
    let encrypted_chunk = vec![1u8; 1024];
    let chunk_hash = [2u8; 32];
    let provider_signature = vec![3u8; 64];

    let response = ChunkResponse {
        encrypted_chunk: encrypted_chunk.clone(),
        chunk_hash,
        provider_signature: provider_signature.clone(),
        provider_public_key: provider_keypair.public_key(),
        challenge_echo: request.challenge_nonce,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    // Step 4: Validate the chunk response
    let response_validation = validate_chunk_response(&response, &request);
    assert!(
        response_validation.is_ok(),
        "Response validation failed: {:?}",
        response_validation
    );

    // Step 5: Create bandwidth proof
    let start_time = chrono::Utc::now().timestamp_millis();
    let end_time = start_time + 100; // 100ms latency
    let latency_ms = calculate_latency(start_time, end_time);

    let proof = create_bandwidth_proof(
        &request,
        "12D3KooProvider".to_string(),
        provider_keypair.public_key().to_vec(),
        1024,
        provider_signature,
        vec![4u8; 64], // requester signature
        chunk_hash.to_vec(),
        start_time,
        end_time,
        latency_ms,
    );

    // Step 6: Validate bandwidth proof structure
    let proof_validation = validate_bandwidth_proof(&proof);
    assert!(
        proof_validation.is_ok(),
        "Proof validation failed: {:?}",
        proof_validation
    );

    // Additional checks
    assert_eq!(proof.content_cid, "QmTest123");
    assert_eq!(proof.chunk_index, 0);
    assert_eq!(proof.bytes_transferred, 1024);
    assert_eq!(proof.latency_ms, latency_ms);
    assert!(proof.is_valid());
}

/// Test that invalid chunk requests are rejected.
#[test]
fn test_invalid_chunk_request() {
    let keypair = KeyPair::generate();

    // Create a request with an invalid CID (empty)
    let mut request = create_chunk_request(
        "".to_string(), // Invalid empty CID
        0,
        "12D3KooRequester".to_string(),
        keypair.public_key(),
    );

    // Manually set empty CID to bypass any client-side validation
    request.content_cid = "".to_string();

    let validation_result = validate_chunk_request(&request);
    assert!(
        validation_result.is_err(),
        "Expected validation to fail for empty CID"
    );
}

/// Test that mismatched challenge nonces are rejected.
#[test]
fn test_mismatched_challenge_nonce() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    // Create request
    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooRequester".to_string(),
        requester_keypair.public_key(),
    );

    // Create response with wrong challenge echo
    let response = ChunkResponse {
        encrypted_chunk: vec![1u8; 1024],
        chunk_hash: [2u8; 32],
        provider_signature: vec![3u8; 64],
        provider_public_key: provider_keypair.public_key(),
        challenge_echo: [99u8; 32], // Wrong nonce!
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    let validation_result = validate_chunk_response(&response, &request);
    assert!(
        validation_result.is_err(),
        "Expected validation to fail for mismatched nonce"
    );
}

/// Test that bandwidth proofs with invalid latency are rejected.
#[test]
fn test_invalid_latency_bandwidth_proof() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooRequester".to_string(),
        requester_keypair.public_key(),
    );

    let start_time = chrono::Utc::now().timestamp_millis();
    let end_time = start_time + 100;

    // Create proof with latency that doesn't match timestamps
    let proof = create_bandwidth_proof(
        &request,
        "12D3KooProvider".to_string(),
        provider_keypair.public_key().to_vec(),
        1024,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        start_time,
        end_time,
        9999, // Wrong latency!
    );

    let validation_result = validate_bandwidth_proof(&proof);
    assert!(
        validation_result.is_err(),
        "Expected validation to fail for mismatched latency"
    );
}

/// Test that self-transfers (same peer ID for provider and requester) are rejected.
#[test]
fn test_self_transfer_rejection() {
    let keypair = KeyPair::generate();

    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooSamePeer".to_string(),
        keypair.public_key(),
    );

    let start_time = chrono::Utc::now().timestamp_millis();
    let end_time = start_time + 100;
    let latency_ms = calculate_latency(start_time, end_time);

    // Use same peer ID for both provider and requester
    let proof = create_bandwidth_proof(
        &request,
        "12D3KooSamePeer".to_string(), // Same as requester!
        keypair.public_key().to_vec(),
        1024,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        start_time,
        end_time,
        latency_ms,
    );

    // The proof structure validation (in chie-shared) checks for self-transfer
    let validation_result = proof.validate();
    assert!(
        validation_result.is_err(),
        "Expected validation to fail for self-transfer"
    );
}

/// Test bandwidth proof quality multipliers.
#[test]
fn test_bandwidth_proof_quality_metrics() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooRequester".to_string(),
        requester_keypair.public_key(),
    );

    // Test with good latency (< 500ms)
    let start_time = chrono::Utc::now().timestamp_millis();
    let end_time_good = start_time + 300; // 300ms
    let latency_good = calculate_latency(start_time, end_time_good);

    let proof_good = create_bandwidth_proof(
        &request,
        "12D3KooProvider".to_string(),
        provider_keypair.public_key().to_vec(),
        1024,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        start_time,
        end_time_good,
        latency_good,
    );

    assert!(proof_good.meets_quality_threshold());
    assert_eq!(proof_good.quality_multiplier(), 1.0);

    // Test with poor latency (> 500ms)
    let end_time_bad = start_time + 700; // 700ms
    let latency_bad = calculate_latency(start_time, end_time_bad);

    let proof_bad = create_bandwidth_proof(
        &request,
        "12D3KooProvider".to_string(),
        provider_keypair.public_key().to_vec(),
        1024,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        start_time,
        end_time_bad,
        latency_bad,
    );

    assert!(!proof_bad.meets_quality_threshold());
    assert_eq!(proof_bad.quality_multiplier(), 0.5);
}

/// Test bandwidth calculation.
#[test]
fn test_bandwidth_calculation() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let request = create_chunk_request(
        "QmTest123".to_string(),
        0,
        "12D3KooRequester".to_string(),
        requester_keypair.public_key(),
    );

    let start_time = chrono::Utc::now().timestamp_millis();
    let end_time = start_time + 1000; // 1 second
    let latency_ms = calculate_latency(start_time, end_time);

    let bytes = 1_000_000; // 1 MB

    let proof = create_bandwidth_proof(
        &request,
        "12D3KooProvider".to_string(),
        provider_keypair.public_key().to_vec(),
        bytes,
        vec![1u8; 64],
        vec![2u8; 64],
        vec![3u8; 32],
        start_time,
        end_time,
        latency_ms,
    );

    let bandwidth_bps = proof.bandwidth_bps();
    // 1 MB in 1 second = 1,000,000 bytes/second
    assert!((bandwidth_bps - 1_000_000.0).abs() < 1.0);
}

/// Test multiple sequential proofs (simulating a real transfer session).
#[test]
fn test_sequential_chunk_transfers() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let content_cid = "QmLargeContent123".to_string();
    let num_chunks = 5;

    let mut proofs: Vec<BandwidthProof> = Vec::new();

    for chunk_index in 0..num_chunks {
        // Create request for this chunk
        let request = ChunkRequest::new(
            content_cid.clone(),
            chunk_index,
            generate_challenge_nonce(),
            "12D3KooRequester",
            requester_keypair.public_key(),
        );

        // Validate request
        assert!(validate_chunk_request(&request).is_ok());

        // Create response
        let response = ChunkResponse::new(
            vec![42u8; 1024],
            chie_crypto::hash(&vec![42u8; 1024]),
            vec![1u8; 64],
            provider_keypair.public_key(),
            request.challenge_nonce,
        );

        // Validate response
        assert!(validate_chunk_response(&response, &request).is_ok());

        // Create proof
        let start_time = chrono::Utc::now().timestamp_millis();
        let end_time = start_time + 100;
        let latency_ms = calculate_latency(start_time, end_time);

        let proof = create_bandwidth_proof(
            &request,
            "12D3KooProvider".to_string(),
            provider_keypair.public_key().to_vec(),
            1024,
            vec![1u8; 64],
            vec![2u8; 64],
            response.chunk_hash.to_vec(),
            start_time,
            end_time,
            latency_ms,
        );

        // Validate proof
        assert!(validate_bandwidth_proof(&proof).is_ok());
        assert_eq!(proof.chunk_index, chunk_index);

        proofs.push(proof);
    }

    // Verify we created proofs for all chunks
    assert_eq!(proofs.len(), num_chunks as usize);

    // Verify all proofs are for the same content
    for proof in &proofs {
        assert_eq!(proof.content_cid, content_cid);
    }

    // Verify chunk indices are sequential
    for (i, proof) in proofs.iter().enumerate() {
        assert_eq!(proof.chunk_index, i as u64);
    }
}

/// Test concurrent proof creation (simulating multiple parallel transfers).
#[test]
fn test_concurrent_chunk_transfers() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let num_concurrent_transfers = 10;
    let proofs = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];

    for i in 0..num_concurrent_transfers {
        let proofs_clone = Arc::clone(&proofs);

        let handle = thread::spawn(move || {
            let requester_keypair = KeyPair::generate();
            let provider_keypair = KeyPair::generate();

            let request = create_chunk_request(
                format!("QmContent{}", i),
                0,
                format!("12D3KooRequester{}", i),
                requester_keypair.public_key(),
            );

            let start_time = chrono::Utc::now().timestamp_millis();
            let end_time = start_time + 100;
            let latency_ms = calculate_latency(start_time, end_time);

            let proof = create_bandwidth_proof(
                &request,
                format!("12D3KooProvider{}", i),
                provider_keypair.public_key().to_vec(),
                1024,
                vec![1u8; 64],
                vec![2u8; 64],
                vec![3u8; 32],
                start_time,
                end_time,
                latency_ms,
            );

            assert!(validate_bandwidth_proof(&proof).is_ok());

            let mut proofs_guard = proofs_clone.lock().unwrap();
            proofs_guard.push(proof);
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    let final_proofs = proofs.lock().unwrap();
    assert_eq!(final_proofs.len(), num_concurrent_transfers);

    // Verify all proofs are valid
    for proof in final_proofs.iter() {
        assert!(proof.is_valid());
    }
}
