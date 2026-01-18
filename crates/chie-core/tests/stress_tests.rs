//! Stress tests for chie-core under high load scenarios.
//!
//! These tests verify system behavior under stress:
//! 1. High concurrency chunk transfers
//! 2. Large-scale proof generation
//! 3. Memory pressure scenarios
//! 4. Rapid request/response cycles

use chie_core::protocol::{
    calculate_latency, create_bandwidth_proof, create_chunk_request, generate_challenge_nonce,
    validate_bandwidth_proof, validate_chunk_request,
};
use chie_crypto::KeyPair;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Test high concurrency chunk request creation and validation.
#[tokio::test]
async fn test_high_concurrency_requests() {
    let num_concurrent = 1000;
    let semaphore = Arc::new(Semaphore::new(100)); // Limit to 100 concurrent

    let mut handles = vec![];

    for i in 0..num_concurrent {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let keypair = KeyPair::generate();
            let request = create_chunk_request(
                format!("QmContent{}", i),
                i as u64,
                format!("Peer{}", i),
                keypair.public_key(),
            );

            // Validate the request
            let result = validate_chunk_request(&request);
            assert!(result.is_ok());

            request
        });

        handles.push(handle);
    }

    // Wait for all to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Verify all requests created successfully
    assert_eq!(results.len(), num_concurrent);

    // Verify all have unique nonces
    let nonces: std::collections::HashSet<_> = results.iter().map(|r| r.challenge_nonce).collect();
    assert_eq!(nonces.len(), num_concurrent, "All nonces should be unique");
}

/// Test rapid sequential proof generation.
#[tokio::test]
async fn test_rapid_proof_generation() {
    let num_proofs = 10000;
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let mut proofs = Vec::with_capacity(num_proofs);

    let start = std::time::Instant::now();

    for i in 0..num_proofs {
        let request = create_chunk_request(
            "QmTestContent".to_string(),
            i as u64,
            "Requester".to_string(),
            requester_keypair.public_key(),
        );

        let start_time = chrono::Utc::now().timestamp_millis();
        let end_time = start_time + 50; // 50ms latency
        let latency_ms = calculate_latency(start_time, end_time);

        let proof = create_bandwidth_proof(
            &request,
            "Provider".to_string(),
            provider_keypair.public_key().to_vec(),
            1024,
            vec![1u8; 64],
            vec![2u8; 64],
            vec![3u8; 32],
            start_time,
            end_time,
            latency_ms,
        );

        proofs.push(proof);
    }

    let duration = start.elapsed();

    // Verify all proofs created
    assert_eq!(proofs.len(), num_proofs);

    // Log performance
    let proofs_per_sec = num_proofs as f64 / duration.as_secs_f64();
    println!(
        "Generated {} proofs in {:?} ({:.0} proofs/sec)",
        num_proofs, duration, proofs_per_sec
    );

    // Should be able to generate at least 1000 proofs/sec
    assert!(
        proofs_per_sec > 1000.0,
        "Expected >1000 proofs/sec, got {}",
        proofs_per_sec
    );
}

/// Test validation under high load.
#[tokio::test]
async fn test_high_load_validation() {
    let num_validations = 5000;

    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    // Pre-generate proofs
    let proofs: Vec<_> = (0..num_validations)
        .map(|i| {
            let request = create_chunk_request(
                "QmTest".to_string(),
                i,
                "Requester".to_string(),
                requester_keypair.public_key(),
            );

            let start_time = chrono::Utc::now().timestamp_millis();
            let end_time = start_time + 100;
            let latency_ms = calculate_latency(start_time, end_time);

            create_bandwidth_proof(
                &request,
                "Provider".to_string(),
                provider_keypair.public_key().to_vec(),
                1024,
                vec![1u8; 64],
                vec![2u8; 64],
                vec![3u8; 32],
                start_time,
                end_time,
                latency_ms,
            )
        })
        .collect();

    let start = std::time::Instant::now();

    // Validate all proofs
    let mut valid_count = 0;
    for proof in &proofs {
        if validate_bandwidth_proof(proof).is_ok() {
            valid_count += 1;
        }
    }

    let duration = start.elapsed();

    // All should be valid
    assert_eq!(valid_count, num_validations);

    let validations_per_sec = num_validations as f64 / duration.as_secs_f64();
    println!(
        "Validated {} proofs in {:?} ({:.0} validations/sec)",
        num_validations, duration, validations_per_sec
    );

    // Should validate quickly
    assert!(
        validations_per_sec > 5000.0,
        "Expected >5000 validations/sec, got {}",
        validations_per_sec
    );
}

/// Test memory efficiency with large number of proofs.
#[tokio::test]
async fn test_memory_efficiency() {
    let num_proofs = 100_000;
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let mut proofs = Vec::with_capacity(num_proofs);

    // Generate many proofs
    for i in 0..num_proofs {
        let request = create_chunk_request(
            "QmContent".to_string(),
            i as u64,
            "Requester".to_string(),
            requester_keypair.public_key(),
        );

        let start_time = chrono::Utc::now().timestamp_millis();
        let end_time = start_time + 100;
        let latency_ms = calculate_latency(start_time, end_time);

        let proof = create_bandwidth_proof(
            &request,
            "Provider".to_string(),
            provider_keypair.public_key().to_vec(),
            1024,
            vec![1u8; 64],
            vec![2u8; 64],
            vec![3u8; 32],
            start_time,
            end_time,
            latency_ms,
        );

        proofs.push(proof);

        // Clear every 10000 to test cleanup
        if proofs.len() >= 10_000 {
            proofs.clear();
        }
    }

    // Test passed if we didn't OOM
}

/// Test concurrent proof validation.
#[tokio::test]
async fn test_concurrent_validation() {
    let num_concurrent = 1000;
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    // Pre-generate proofs
    let proofs: Vec<_> = (0..num_concurrent)
        .map(|i| {
            let request = create_chunk_request(
                format!("QmContent{}", i),
                i,
                "Requester".to_string(),
                requester_keypair.public_key(),
            );

            let start_time = chrono::Utc::now().timestamp_millis();
            let end_time = start_time + 100;
            let latency_ms = calculate_latency(start_time, end_time);

            create_bandwidth_proof(
                &request,
                "Provider".to_string(),
                provider_keypair.public_key().to_vec(),
                1024,
                vec![1u8; 64],
                vec![2u8; 64],
                vec![3u8; 32],
                start_time,
                end_time,
                latency_ms,
            )
        })
        .collect();

    let proofs = Arc::new(proofs);

    let mut handles = vec![];

    // Validate concurrently
    for i in 0..num_concurrent {
        let proofs_clone = proofs.clone();
        let handle = tokio::spawn(async move {
            let proof = &proofs_clone[i as usize];
            validate_bandwidth_proof(proof).is_ok()
        });

        handles.push(handle);
    }

    // Wait for all validations
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // All should be valid
    let valid_count = results.iter().filter(|&&v| v).count();
    assert_eq!(valid_count, num_concurrent as usize);
}

/// Test sustained throughput over time.
#[tokio::test]
async fn test_sustained_throughput() {
    let duration = std::time::Duration::from_secs(5);
    let keypair = KeyPair::generate();

    let start = std::time::Instant::now();
    let mut count = 0;

    while start.elapsed() < duration {
        let request = create_chunk_request(
            "QmTest".to_string(),
            count,
            "Peer".to_string(),
            keypair.public_key(),
        );

        let result = validate_chunk_request(&request);
        assert!(result.is_ok());

        count += 1;
    }

    let actual_duration = start.elapsed();
    let throughput = count as f64 / actual_duration.as_secs_f64();

    println!(
        "Sustained {} operations over {:?} ({:.0} ops/sec)",
        count, actual_duration, throughput
    );

    // Should maintain high throughput
    assert!(throughput > 5000.0);
}

/// Test nonce uniqueness under high generation rate.
#[test]
fn test_nonce_uniqueness_at_scale() {
    let num_nonces = 1_000_000;

    let mut nonces = std::collections::HashSet::with_capacity(num_nonces);

    let start = std::time::Instant::now();

    for _ in 0..num_nonces {
        let nonce = generate_challenge_nonce();
        nonces.insert(nonce);
    }

    let duration = start.elapsed();

    // All nonces should be unique
    assert_eq!(
        nonces.len(),
        num_nonces,
        "All {} nonces should be unique",
        num_nonces
    );

    let nonces_per_sec = num_nonces as f64 / duration.as_secs_f64();
    println!(
        "Generated {} unique nonces in {:?} ({:.0} nonces/sec)",
        num_nonces, duration, nonces_per_sec
    );
}

/// Test latency calculation accuracy at various timescales.
#[test]
fn test_latency_calculation_accuracy() {
    let test_cases = vec![
        (1000, 1001, 1),      // 1ms
        (1000, 1010, 10),     // 10ms
        (1000, 1100, 100),    // 100ms
        (1000, 2000, 1000),   // 1s
        (1000, 11000, 10000), // 10s
    ];

    for (start, end, expected_latency) in test_cases {
        let latency = calculate_latency(start, end);
        assert_eq!(
            latency, expected_latency,
            "Latency from {} to {} should be {}",
            start, end, expected_latency
        );
    }
}

/// Test proof generation with varying sizes.
#[tokio::test]
async fn test_variable_size_proofs() {
    let requester_keypair = KeyPair::generate();
    let provider_keypair = KeyPair::generate();

    let sizes = vec![
        1024,               // 1 KB
        256 * 1024,         // 256 KB
        1024 * 1024,        // 1 MB
        10 * 1024 * 1024,   // 10 MB
        100 * 1024 * 1024,  // 100 MB
        1024 * 1024 * 1024, // 1 GB
    ];

    for size in sizes {
        let request = create_chunk_request(
            "QmTest".to_string(),
            0,
            "Requester".to_string(),
            requester_keypair.public_key(),
        );

        let start_time = chrono::Utc::now().timestamp_millis();
        let end_time = start_time + 100;
        let latency_ms = calculate_latency(start_time, end_time);

        let proof = create_bandwidth_proof(
            &request,
            "Provider".to_string(),
            provider_keypair.public_key().to_vec(),
            size,
            vec![1u8; 64],
            vec![2u8; 64],
            vec![3u8; 32],
            start_time,
            end_time,
            latency_ms,
        );

        // Verify proof is valid
        assert!(validate_bandwidth_proof(&proof).is_ok());
        assert_eq!(proof.bytes_transferred, size);

        // Calculate bandwidth
        let bandwidth = proof.bandwidth_bps();
        let expected_bandwidth = (size as f64 * 1000.0) / latency_ms as f64;
        assert!(
            (bandwidth - expected_bandwidth).abs() < 0.1,
            "Bandwidth mismatch for size {}: expected {}, got {}",
            size,
            expected_bandwidth,
            bandwidth
        );
    }
}

/// Test parallel proof streams.
#[tokio::test]
async fn test_parallel_proof_streams() {
    let num_streams = 100;
    let proofs_per_stream = 100;

    let mut handles = vec![];

    for stream_id in 0..num_streams {
        let handle = tokio::spawn(async move {
            let keypair = KeyPair::generate();
            let provider_keypair = KeyPair::generate();
            let mut stream_proofs = Vec::new();

            for i in 0..proofs_per_stream {
                let request = create_chunk_request(
                    format!("QmStream{}", stream_id),
                    i,
                    format!("Peer{}", stream_id),
                    keypair.public_key(),
                );

                let start_time = chrono::Utc::now().timestamp_millis();
                let end_time = start_time + 50;
                let latency_ms = calculate_latency(start_time, end_time);

                let proof = create_bandwidth_proof(
                    &request,
                    format!("Provider{}", stream_id),
                    provider_keypair.public_key().to_vec(),
                    1024,
                    vec![1u8; 64],
                    vec![2u8; 64],
                    vec![3u8; 32],
                    start_time,
                    end_time,
                    latency_ms,
                );

                stream_proofs.push(proof);
            }

            stream_proofs.len()
        });

        handles.push(handle);
    }

    // Wait for all streams
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Verify all streams completed
    assert_eq!(results.len(), num_streams);
    for count in results {
        assert_eq!(count, proofs_per_stream as usize);
    }
}
