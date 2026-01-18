//! Integration tests for codec serialization and deserialization.

use chie_shared::{ChunkRequest, ChunkResponse};
use serde::{Deserialize, Serialize};

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, oxicode::error::Error> {
    oxicode::serde::encode_to_vec(value, oxicode::config::standard())
}

fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, oxicode::error::Error> {
    oxicode::serde::decode_from_slice(bytes, oxicode::config::standard()).map(|(v, _)| v)
}

#[test]
fn test_request_serialization_roundtrip() {
    let request = ChunkRequest {
        content_cid: "bafytest123".to_string(),
        chunk_index: 42,
        challenge_nonce: [0xAB; 32],
        requester_peer_id: "12D3KooWTest".to_string(),
        requester_public_key: [0xCD; 32],
        timestamp_ms: 1234567890000,
    };

    // Serialize with bincode
    let serialized = encode(&request).expect("Failed to serialize");

    // Deserialize
    let deserialized: ChunkRequest = decode(&serialized).expect("Failed to deserialize");

    assert_eq!(deserialized.content_cid, request.content_cid);
    assert_eq!(deserialized.chunk_index, request.chunk_index);
    assert_eq!(deserialized.challenge_nonce, request.challenge_nonce);
    assert_eq!(deserialized.requester_peer_id, request.requester_peer_id);
    assert_eq!(
        deserialized.requester_public_key,
        request.requester_public_key
    );
}

#[test]
fn test_response_serialization_roundtrip() {
    let response = ChunkResponse {
        encrypted_chunk: vec![1, 2, 3, 4, 5],
        chunk_hash: [0xAB; 32],
        provider_signature: vec![6, 7, 8, 9],
        provider_public_key: [0xCD; 32],
        challenge_echo: [0xEF; 32],
        timestamp_ms: 1234567890000,
    };

    // Serialize with bincode
    let serialized = encode(&response).expect("Failed to serialize");

    // Deserialize
    let deserialized: ChunkResponse = decode(&serialized).expect("Failed to deserialize");

    assert_eq!(deserialized.encrypted_chunk, response.encrypted_chunk);
    assert_eq!(deserialized.chunk_hash, response.chunk_hash);
    assert_eq!(deserialized.provider_signature, response.provider_signature);
    assert_eq!(
        deserialized.provider_public_key,
        response.provider_public_key
    );
    assert_eq!(deserialized.challenge_echo, response.challenge_echo);
    assert_eq!(deserialized.timestamp_ms, response.timestamp_ms);
}

#[test]
fn test_large_chunk_serialization() {
    // Test with 1MB chunk
    let large_data = vec![0xAB; 1024 * 1024];
    let response = ChunkResponse {
        encrypted_chunk: large_data.clone(),
        chunk_hash: [0xCD; 32],
        provider_signature: vec![0xEF; 64],
        provider_public_key: [0x12; 32],
        challenge_echo: [0x34; 32],
        timestamp_ms: 1234567890000,
    };

    // Serialize
    let serialized = encode(&response).expect("Failed to serialize");

    // Deserialize
    let deserialized: ChunkResponse = decode(&serialized).expect("Failed to deserialize");

    assert_eq!(deserialized.encrypted_chunk.len(), 1024 * 1024);
    assert_eq!(deserialized.encrypted_chunk, large_data);
}

#[test]
fn test_bincode_vs_json_size() {
    let request = ChunkRequest {
        content_cid: "bafyreigbtj4x7ip5legnfznufuopl4sg4knzc2cof6duas4b3q2fy6swua".to_string(),
        chunk_index: 42,
        challenge_nonce: [0xAB; 32],
        requester_peer_id: "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".to_string(),
        requester_public_key: [0xCD; 32],
        timestamp_ms: 1234567890000,
    };

    let bincode_data = encode(&request).unwrap();
    let json_data = serde_json::to_vec(&request).unwrap();

    // Bincode should be more compact than JSON
    assert!(
        bincode_data.len() < json_data.len(),
        "Bincode ({}) should be smaller than JSON ({})",
        bincode_data.len(),
        json_data.len()
    );
}

#[test]
fn test_binary_data_integrity() {
    // Create chunk with various byte patterns
    let mut chunk_data = Vec::new();
    chunk_data.extend_from_slice(&[0x00; 100]); // Zeros
    chunk_data.extend_from_slice(&[0xFF; 100]); // Ones
    chunk_data.extend_from_slice(&(0..=255).collect::<Vec<u8>>()); // All byte values
    chunk_data.extend_from_slice(&[0xAA, 0x55].repeat(50)); // Alternating pattern

    let response = ChunkResponse {
        encrypted_chunk: chunk_data.clone(),
        chunk_hash: [0x12; 32],
        provider_signature: vec![0x34; 64],
        provider_public_key: [0x56; 32],
        challenge_echo: [0x78; 32],
        timestamp_ms: 1234567890000,
    };

    let serialized = encode(&response).expect("Failed to serialize");
    let deserialized: ChunkResponse = decode(&serialized).expect("Failed to deserialize");

    assert_eq!(
        deserialized.encrypted_chunk, chunk_data,
        "Binary data corrupted"
    );
}

#[test]
fn test_concurrent_serialization() {
    use std::thread;

    let handles: Vec<_> = (0..100)
        .map(|i| {
            thread::spawn(move || {
                let request = ChunkRequest {
                    content_cid: format!("bafy{}", i),
                    chunk_index: i as u64,
                    challenge_nonce: [i as u8; 32],
                    requester_peer_id: format!("12D3KooW{}", i),
                    requester_public_key: [(i % 256) as u8; 32],
                    timestamp_ms: i as i64,
                };

                let serialized = encode(&request).expect("Serialization failed");
                let deserialized: ChunkRequest =
                    decode(&serialized).expect("Deserialization failed");

                assert_eq!(deserialized.chunk_index, i as u64);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_stress_serialization() {
    // Perform many serializations to test for memory issues
    for i in 0..1000 {
        let response = ChunkResponse {
            encrypted_chunk: vec![i as u8; 1024],
            chunk_hash: [(i % 256) as u8; 32],
            provider_signature: vec![(i % 128) as u8; 64],
            provider_public_key: [(i % 64) as u8; 32],
            challenge_echo: [(i % 32) as u8; 32],
            timestamp_ms: i as i64,
        };

        let serialized = encode(&response).expect("Serialization failed");
        let _deserialized: ChunkResponse = decode(&serialized).expect("Deserialization failed");
    }
}
