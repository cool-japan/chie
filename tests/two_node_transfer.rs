//! Integration test for 2-node chunk transfer with proof generation.
//!
//! This test simulates a complete transfer flow:
//! 1. Provider node starts and pins content
//! 2. Requester node connects and requests a chunk
//! 3. Provider responds with signed chunk
//! 4. Requester verifies and creates bandwidth proof
//! 5. Proof is verified by the coordinator verification pipeline

use chie_crypto::{hash, KeyPair};
use chie_shared::{BandwidthProof, ChunkRequest, ChunkResponse, CHUNK_SIZE};
use chrono::Utc;
use uuid::Uuid;

/// Simulates a provider node that serves content.
struct MockProvider {
    keypair: KeyPair,
    peer_id: String,
    content_data: Vec<u8>,
}

impl MockProvider {
    fn new() -> Self {
        let keypair = KeyPair::generate();
        Self {
            peer_id: format!("12D3KooWProvider{}", rand::random::<u32>()),
            keypair,
            content_data: vec![0xAB; CHUNK_SIZE], // Mock content
        }
    }

    fn handle_request(&self, request: &ChunkRequest) -> ChunkResponse {
        // Get chunk data (in real implementation, read from storage)
        let chunk_data = &self.content_data;
        let chunk_hash = hash(chunk_data);

        // Build message to sign: nonce || hash || requester_pubkey
        let mut message = Vec::new();
        message.extend_from_slice(&request.challenge_nonce);
        message.extend_from_slice(&chunk_hash);
        message.extend_from_slice(&request.requester_public_key);

        let signature = self.keypair.sign(&message);

        // In production, this would be encrypted
        let encrypted_chunk = chunk_data.clone();

        ChunkResponse {
            encrypted_chunk,
            chunk_hash,
            provider_signature: signature.to_vec(),
            provider_public_key: self.keypair.public_key(),
            challenge_echo: request.challenge_nonce,
            timestamp_ms: Utc::now().timestamp_millis(),
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }
}

/// Simulates a requester node that downloads content.
struct MockRequester {
    keypair: KeyPair,
    peer_id: String,
}

impl MockRequester {
    fn new() -> Self {
        let keypair = KeyPair::generate();
        Self {
            peer_id: format!("12D3KooWRequester{}", rand::random::<u32>()),
            keypair,
        }
    }

    fn create_request(&self, content_cid: &str, chunk_index: u64) -> ChunkRequest {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

        ChunkRequest {
            content_cid: content_cid.to_string(),
            chunk_index,
            challenge_nonce: nonce,
            requester_peer_id: self.peer_id.clone(),
            requester_public_key: self.keypair.public_key(),
            timestamp_ms: Utc::now().timestamp_millis(),
        }
    }

    fn verify_response(&self, request: &ChunkRequest, response: &ChunkResponse) -> bool {
        // Verify challenge echo
        if request.challenge_nonce != response.challenge_echo {
            return false;
        }

        // Verify chunk hash
        let computed_hash = hash(&response.encrypted_chunk);
        if computed_hash != response.chunk_hash {
            return false;
        }

        // Verify provider signature
        let mut message = Vec::new();
        message.extend_from_slice(&request.challenge_nonce);
        message.extend_from_slice(&response.chunk_hash);
        message.extend_from_slice(&request.requester_public_key);

        chie_crypto::verify(
            &response.provider_public_key,
            &message,
            response.provider_signature.as_slice().try_into().unwrap(),
        )
        .is_ok()
    }

    fn create_proof(
        &self,
        request: &ChunkRequest,
        response: &ChunkResponse,
        provider_peer_id: &str,
        start_time_ms: i64,
        end_time_ms: i64,
    ) -> BandwidthProof {
        // Sign the proof: nonce || hash || provider_pubkey || provider_sig
        let mut message = Vec::new();
        message.extend_from_slice(&request.challenge_nonce);
        message.extend_from_slice(&response.chunk_hash);
        message.extend_from_slice(&response.provider_public_key);
        message.extend_from_slice(&response.provider_signature);

        let requester_signature = self.keypair.sign(&message);

        BandwidthProof {
            session_id: Uuid::new_v4(),
            content_cid: request.content_cid.clone(),
            chunk_index: request.chunk_index,
            bytes_transferred: response.encrypted_chunk.len() as u64,
            provider_peer_id: provider_peer_id.to_string(),
            requester_peer_id: self.peer_id.clone(),
            provider_public_key: response.provider_public_key.to_vec(),
            requester_public_key: request.requester_public_key.to_vec(),
            provider_signature: response.provider_signature.clone(),
            requester_signature: requester_signature.to_vec(),
            challenge_nonce: request.challenge_nonce.to_vec(),
            chunk_hash: response.chunk_hash.to_vec(),
            start_timestamp_ms: start_time_ms,
            end_timestamp_ms: end_time_ms,
            latency_ms: (end_time_ms - start_time_ms) as u32,
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }
}

/// Verify a bandwidth proof (simplified version without database).
fn verify_proof(proof: &BandwidthProof) -> Result<(), String> {
    // 1. Verify timestamp is recent
    let now_ms = Utc::now().timestamp_millis();
    let drift = (now_ms - proof.end_timestamp_ms).abs();
    if drift > 300_000 {
        // 5 minutes
        return Err(format!("Timestamp too old: {}ms drift", drift));
    }

    // 2. Verify minimum latency
    if proof.latency_ms < 1 {
        return Err("Impossible latency".to_string());
    }

    // 3. Verify provider signature
    let provider_pubkey: [u8; 32] = proof
        .provider_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid provider public key length")?;
    let provider_sig: [u8; 64] = proof
        .provider_signature
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid provider signature length")?;

    let mut provider_message = Vec::new();
    provider_message.extend_from_slice(&proof.challenge_nonce);
    provider_message.extend_from_slice(&proof.chunk_hash);
    provider_message.extend_from_slice(&proof.requester_public_key);

    chie_crypto::verify(&provider_pubkey, &provider_message, &provider_sig)
        .map_err(|_| "Invalid provider signature")?;

    // 4. Verify requester signature
    let requester_pubkey: [u8; 32] = proof
        .requester_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid requester public key length")?;
    let requester_sig: [u8; 64] = proof
        .requester_signature
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid requester signature length")?;

    let mut requester_message = Vec::new();
    requester_message.extend_from_slice(&proof.challenge_nonce);
    requester_message.extend_from_slice(&proof.chunk_hash);
    requester_message.extend_from_slice(&proof.provider_public_key);
    requester_message.extend_from_slice(&proof.provider_signature);

    chie_crypto::verify(&requester_pubkey, &requester_message, &requester_sig)
        .map_err(|_| "Invalid requester signature")?;

    Ok(())
}

#[test]
fn test_two_node_transfer() {
    // Setup
    let provider = MockProvider::new();
    let requester = MockRequester::new();
    let content_cid = "QmTestContent123";

    // Step 1: Requester creates chunk request
    let start_time = Utc::now().timestamp_millis();
    let request = requester.create_request(content_cid, 0);

    // Step 2: Provider handles request
    let response = provider.handle_request(&request);

    // Step 3: Requester verifies response
    assert!(
        requester.verify_response(&request, &response),
        "Response verification failed"
    );

    // Step 4: Requester creates bandwidth proof
    let end_time = Utc::now().timestamp_millis();
    let proof = requester.create_proof(&request, &response, &provider.peer_id, start_time, end_time);

    // Step 5: Verify the proof
    let verification = verify_proof(&proof);
    assert!(verification.is_ok(), "Proof verification failed: {:?}", verification);

    // Assertions
    assert_eq!(proof.content_cid, content_cid);
    assert_eq!(proof.chunk_index, 0);
    assert_eq!(proof.bytes_transferred, CHUNK_SIZE as u64);
    assert!(proof.latency_ms > 0);
    assert_eq!(proof.provider_public_key.len(), 32);
    assert_eq!(proof.requester_public_key.len(), 32);
    assert_eq!(proof.provider_signature.len(), 64);
    assert_eq!(proof.requester_signature.len(), 64);
}

#[test]
fn test_replay_attack_detection() {
    let provider = MockProvider::new();
    let requester = MockRequester::new();

    // Create first request and response
    let request = requester.create_request("QmContent", 0);
    let response = provider.handle_request(&request);

    // Verify first transfer works
    assert!(requester.verify_response(&request, &response));

    // Create proof for first transfer
    let start = Utc::now().timestamp_millis();
    let end = start + 100;
    let proof1 = requester.create_proof(&request, &response, &provider.peer_id, start, end);

    // First proof should verify
    assert!(verify_proof(&proof1).is_ok());

    // In a real system, reusing the same nonce would be detected by the database
    // Here we just verify that the nonce is included in the proof
    assert_eq!(proof1.challenge_nonce.len(), 32);
    assert!(!proof1.challenge_nonce.iter().all(|&b| b == 0));
}

#[test]
fn test_tampered_signature_detection() {
    let provider = MockProvider::new();
    let requester = MockRequester::new();

    let request = requester.create_request("QmContent", 0);
    let mut response = provider.handle_request(&request);

    // Tamper with provider signature
    response.provider_signature[0] ^= 0xFF;

    // Verification should fail
    assert!(
        !requester.verify_response(&request, &response),
        "Should detect tampered signature"
    );
}

#[test]
fn test_wrong_chunk_hash_detection() {
    let provider = MockProvider::new();
    let requester = MockRequester::new();

    let request = requester.create_request("QmContent", 0);
    let mut response = provider.handle_request(&request);

    // Tamper with chunk hash
    response.chunk_hash[0] ^= 0xFF;

    // Verification should fail (hash mismatch)
    assert!(
        !requester.verify_response(&request, &response),
        "Should detect wrong chunk hash"
    );
}

#[test]
fn test_challenge_echo_mismatch() {
    let provider = MockProvider::new();
    let requester = MockRequester::new();

    let request = requester.create_request("QmContent", 0);
    let mut response = provider.handle_request(&request);

    // Tamper with challenge echo
    response.challenge_echo[0] ^= 0xFF;

    // Verification should fail
    assert!(
        !requester.verify_response(&request, &response),
        "Should detect challenge echo mismatch"
    );
}

#[test]
fn test_multiple_chunk_transfer() {
    let provider = MockProvider::new();
    let requester = MockRequester::new();
    let content_cid = "QmMultiChunkContent";

    // Simulate transferring multiple chunks
    for chunk_index in 0..5 {
        let start_time = Utc::now().timestamp_millis();
        let request = requester.create_request(content_cid, chunk_index);
        let response = provider.handle_request(&request);

        assert!(requester.verify_response(&request, &response));

        let end_time = Utc::now().timestamp_millis();
        let proof = requester.create_proof(
            &request,
            &response,
            &provider.peer_id,
            start_time,
            end_time,
        );

        assert!(verify_proof(&proof).is_ok());
        assert_eq!(proof.chunk_index, chunk_index);
    }
}
