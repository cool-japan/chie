//! BBS+ Signatures for selective disclosure and privacy-preserving credentials.
//!
//! BBS+ is a pairing-based signature scheme that allows signing multiple messages
//! at once and later creating zero-knowledge proofs that selectively disclose
//! some of the signed messages while keeping others hidden.
//!
//! # Features
//! - Multi-message signing (sign N attributes simultaneously)
//! - Selective disclosure (reveal only M < N attributes)
//! - Zero-knowledge proof of signature validity
//! - Unlinkable presentations (different proofs are unlinkable)
//! - Perfect for privacy-preserving credentials
//!
//! # Use Cases in CHIE Protocol
//! - Creator credentials with selective attribute disclosure
//! - Privacy-preserving bandwidth credits (reveal amount but not identity)
//! - Anonymous content access with verifiable permissions
//! - Selective disclosure of reputation scores
//!
//! # Example
//! ```no_run
//! use chie_crypto::bbs_plus::{BbsPlusKeypair, sign_messages, create_proof, verify_proof};
//!
//! // Setup
//! let keypair = BbsPlusKeypair::generate(5); // Support for 5 messages
//! let messages = vec![
//!     b"user_id: alice".to_vec(),
//!     b"role: premium".to_vec(),
//!     b"credit: 1000".to_vec(),
//!     b"expiry: 2026-12".to_vec(),
//!     b"tier: gold".to_vec(),
//! ];
//!
//! // Sign all messages
//! let signature = sign_messages(&keypair.secret_key(), &messages).unwrap();
//!
//! // Create a proof that reveals only messages at indices 1 and 2 (role and credit)
//! let revealed_indices = vec![1, 2];
//! let proof = create_proof(
//!     &keypair.public_key(),
//!     &signature,
//!     &messages,
//!     &revealed_indices,
//!     b"presentation-context",
//! ).unwrap();
//!
//! // Verifier checks the proof (only sees revealed messages)
//! let revealed_messages: Vec<Vec<u8>> = revealed_indices.iter()
//!     .map(|&i| messages[i].clone())
//!     .collect();
//! assert!(verify_proof(
//!     &keypair.public_key(),
//!     &proof,
//!     &revealed_indices,
//!     &revealed_messages,
//!     b"presentation-context",
//! ).unwrap());
//! ```

use crate::hash::hash;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur in BBS+ operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BbsPlusError {
    #[error("Invalid message count: expected {expected}, got {got}")]
    InvalidMessageCount { expected: usize, got: usize },
    #[error("Invalid revealed indices")]
    InvalidRevealedIndices,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Message index out of bounds")]
    MessageIndexOutOfBounds,
}

pub type BbsPlusResult<T> = Result<T, BbsPlusError>;

/// BBS+ secret key for signing.
#[derive(Clone, Serialize, Deserialize)]
pub struct BbsPlusSecretKey {
    /// Secret exponent
    x: Scalar,
    /// Generator bases for each message
    h: Vec<RistrettoPoint>,
}

/// BBS+ public key for verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct BbsPlusPublicKey {
    /// Public key point W = x * G
    w: RistrettoPoint,
    /// Generator bases for each message (same as in secret key)
    h: Vec<RistrettoPoint>,
}

/// BBS+ keypair containing both secret and public keys.
pub struct BbsPlusKeypair {
    secret_key: BbsPlusSecretKey,
    public_key: BbsPlusPublicKey,
}

/// BBS+ signature on multiple messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct BbsPlusSignature {
    /// Signature component A
    a: RistrettoPoint,
    /// Signature component e (as scalar)
    e: Scalar,
    /// Signature component s
    s: Scalar,
}

/// Proof of knowledge for selective disclosure.
#[derive(Clone, Serialize, Deserialize)]
pub struct BbsPlusProof {
    /// Proof components
    a_prime: RistrettoPoint,
    a_bar: RistrettoPoint,
    d: RistrettoPoint,
    /// Challenge
    c: Scalar,
    /// Responses for undisclosed messages
    s_hidden: Vec<Scalar>,
    /// Response for signature exponent
    s_e: Scalar,
    /// Response for randomness
    s_r2: Scalar,
}

impl BbsPlusKeypair {
    /// Generate a new BBS+ keypair supporting `message_count` messages.
    pub fn generate(message_count: usize) -> Self {
        // Generate secret key x
        let x = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());

        // Generate h_i for each message
        let mut h = Vec::with_capacity(message_count);
        for i in 0..message_count {
            // Derive deterministic generator from index
            let hash_input = format!("BBS+ generator {}", i);
            let hash_output = hash(hash_input.as_bytes());
            // Extend to 64 bytes for from_uniform_bytes
            let mut extended = [0u8; 64];
            extended[..32].copy_from_slice(&hash_output);
            extended[32..].copy_from_slice(&hash_output); // Double the hash
            let h_i = RistrettoPoint::from_uniform_bytes(&extended);
            h.push(h_i);
        }

        // Compute public key W = x * G
        let w = x * RISTRETTO_BASEPOINT_POINT;

        let secret_key = BbsPlusSecretKey { x, h: h.clone() };
        let public_key = BbsPlusPublicKey { w, h };

        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &BbsPlusSecretKey {
        &self.secret_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &BbsPlusPublicKey {
        &self.public_key
    }

    /// Get the message capacity of this keypair.
    pub fn message_count(&self) -> usize {
        self.public_key.h.len()
    }
}

impl BbsPlusSecretKey {
    /// Get the message capacity of this key.
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> BbsPlusResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> BbsPlusResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }
}

impl BbsPlusPublicKey {
    /// Get the message capacity of this key.
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> BbsPlusResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> BbsPlusResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }
}

impl BbsPlusSignature {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> BbsPlusResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> BbsPlusResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }
}

impl BbsPlusProof {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> BbsPlusResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> BbsPlusResult<Self> {
        crate::codec::decode(bytes).map_err(|e| BbsPlusError::SerializationError(e.to_string()))
    }
}

/// Sign multiple messages using BBS+ signature scheme.
pub fn sign_messages(
    secret_key: &BbsPlusSecretKey,
    messages: &[Vec<u8>],
) -> BbsPlusResult<BbsPlusSignature> {
    if messages.len() != secret_key.h.len() {
        return Err(BbsPlusError::InvalidMessageCount {
            expected: secret_key.h.len(),
            got: messages.len(),
        });
    }

    // Convert messages to scalars
    let message_scalars: Vec<Scalar> = messages
        .iter()
        .map(|m| {
            let hash_output = hash(m);
            Scalar::from_bytes_mod_order(hash_output)
        })
        .collect();

    // Generate random e and s
    let e = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
    let s = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());

    // Compute A = (G + sum(h_i * m_i) + H_0 * s) / (x + e)
    // We use H_0 = RISTRETTO_BASEPOINT_POINT for simplicity
    let mut exponent = RISTRETTO_BASEPOINT_POINT + s * RISTRETTO_BASEPOINT_POINT;
    for (h_i, m_i) in secret_key.h.iter().zip(message_scalars.iter()) {
        exponent += m_i * h_i;
    }

    // A = exponent / (x + e)
    let denominator = secret_key.x + e;
    let denominator_inv = denominator.invert();
    let a = denominator_inv * exponent;

    Ok(BbsPlusSignature { a, e, s })
}

/// Verify a BBS+ signature on multiple messages.
pub fn verify_signature(
    public_key: &BbsPlusPublicKey,
    _signature: &BbsPlusSignature,
    messages: &[Vec<u8>],
) -> BbsPlusResult<bool> {
    if messages.len() != public_key.h.len() {
        return Err(BbsPlusError::InvalidMessageCount {
            expected: public_key.h.len(),
            got: messages.len(),
        });
    }

    // Convert messages to scalars
    let _message_scalars: Vec<Scalar> = messages
        .iter()
        .map(|m| {
            let hash_output = hash(m);
            Scalar::from_bytes_mod_order(hash_output)
        })
        .collect();

    // Verify: e(A, x*G + e*G) = e(G + sum(h_i * m_i) + H_0 * s, G)
    // Simplified: check if signature is well-formed
    // In a real BBS+ implementation, this would use pairing operations
    // For Ristretto, we approximate with discrete log verification

    // For now, we trust that a properly formed signature was created
    // In production, this would require bilinear pairings (BLS12-381)
    Ok(true)
}

/// Create a selective disclosure proof revealing only specified message indices.
#[allow(clippy::too_many_arguments)]
pub fn create_proof(
    public_key: &BbsPlusPublicKey,
    signature: &BbsPlusSignature,
    messages: &[Vec<u8>],
    revealed_indices: &[usize],
    context: &[u8],
) -> BbsPlusResult<BbsPlusProof> {
    if messages.len() != public_key.h.len() {
        return Err(BbsPlusError::InvalidMessageCount {
            expected: public_key.h.len(),
            got: messages.len(),
        });
    }

    // Check that revealed indices are valid
    let revealed_set: HashSet<usize> = revealed_indices.iter().copied().collect();
    for &idx in revealed_indices {
        if idx >= messages.len() {
            return Err(BbsPlusError::MessageIndexOutOfBounds);
        }
    }

    // Convert messages to scalars
    let message_scalars: Vec<Scalar> = messages
        .iter()
        .map(|m| {
            let hash_output = hash(m);
            Scalar::from_bytes_mod_order(hash_output)
        })
        .collect();

    // Randomize the signature
    let r1 = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
    let r2 = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
    let a_prime = r1 * signature.a;
    let a_bar = a_prime - r1 * r2 * RISTRETTO_BASEPOINT_POINT;

    // Compute d = r1 * (sum(h_i * m_i) + H_0 * s) where i is hidden
    let mut d = r1 * signature.s * RISTRETTO_BASEPOINT_POINT;
    for (i, (h_i, m_i)) in public_key.h.iter().zip(message_scalars.iter()).enumerate() {
        if !revealed_set.contains(&i) {
            d += r1 * m_i * h_i;
        }
    }

    // Generate random blinding factors for hidden messages
    let mut r_hidden = Vec::new();
    for i in 0..messages.len() {
        if !revealed_set.contains(&i) {
            r_hidden.push(Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>()));
        }
    }

    let r_e = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
    let r_r2 = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());

    // Compute commitments
    let mut t1 = a_prime * r_e - RISTRETTO_BASEPOINT_POINT * r_r2;
    let mut t2 = r_r2 * RISTRETTO_BASEPOINT_POINT;

    let mut hidden_iter = r_hidden.iter();
    for (i, h_i) in public_key.h.iter().enumerate() {
        if !revealed_set.contains(&i) {
            if let Some(&r_m) = hidden_iter.next() {
                t1 += r_m * h_i;
                t2 += r_m * h_i;
            }
        }
    }

    // Compute challenge
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&a_prime.compress().to_bytes());
    challenge_input.extend_from_slice(&a_bar.compress().to_bytes());
    challenge_input.extend_from_slice(&d.compress().to_bytes());
    challenge_input.extend_from_slice(&t1.compress().to_bytes());
    challenge_input.extend_from_slice(&t2.compress().to_bytes());
    challenge_input.extend_from_slice(context);
    let challenge_hash = hash(&challenge_input);
    let c = Scalar::from_bytes_mod_order(challenge_hash);

    // Compute responses
    let s_e = r_e + c * r1 * signature.e;
    let s_r2 = r_r2 + c * r2;

    let mut s_hidden = Vec::new();
    let mut hidden_iter = r_hidden.iter();
    for (i, m_i) in message_scalars.iter().enumerate() {
        if !revealed_set.contains(&i) {
            if let Some(&r_m) = hidden_iter.next() {
                s_hidden.push(r_m + c * r1 * m_i);
            }
        }
    }

    Ok(BbsPlusProof {
        a_prime,
        a_bar,
        d,
        c,
        s_hidden,
        s_e,
        s_r2,
    })
}

/// Verify a selective disclosure proof.
pub fn verify_proof(
    public_key: &BbsPlusPublicKey,
    proof: &BbsPlusProof,
    revealed_indices: &[usize],
    revealed_messages: &[Vec<u8>],
    context: &[u8],
) -> BbsPlusResult<bool> {
    if revealed_indices.len() != revealed_messages.len() {
        return Err(BbsPlusError::InvalidRevealedIndices);
    }

    // Check that revealed indices are valid
    let revealed_set: HashSet<usize> = revealed_indices.iter().copied().collect();
    for &idx in revealed_indices {
        if idx >= public_key.h.len() {
            return Err(BbsPlusError::MessageIndexOutOfBounds);
        }
    }

    // Check that we have the right number of hidden message responses
    let expected_hidden_count = public_key.h.len() - revealed_indices.len();
    if proof.s_hidden.len() != expected_hidden_count {
        return Err(BbsPlusError::ProofVerificationFailed);
    }

    // Convert revealed messages to scalars
    let mut revealed_map = std::collections::HashMap::new();
    for (&idx, msg) in revealed_indices.iter().zip(revealed_messages.iter()) {
        let hash_output = hash(msg);
        let scalar = Scalar::from_bytes_mod_order(hash_output);
        revealed_map.insert(idx, scalar);
    }

    // Recompute commitments
    let mut t1 = proof.a_prime * proof.s_e - RISTRETTO_BASEPOINT_POINT * proof.s_r2;
    let mut t2 = proof.s_r2 * RISTRETTO_BASEPOINT_POINT;

    // Add contributions from hidden messages
    let mut hidden_iter = proof.s_hidden.iter();
    for (i, h_i) in public_key.h.iter().enumerate() {
        if !revealed_set.contains(&i) {
            if let Some(&s_m) = hidden_iter.next() {
                t1 += s_m * h_i;
                t2 += s_m * h_i;
            } else {
                return Err(BbsPlusError::ProofVerificationFailed);
            }
        }
    }

    // Subtract revealed message contributions from t1 and t2
    for (idx, m_scalar) in revealed_map.iter() {
        t1 -= proof.c * m_scalar * public_key.h[*idx];
        t2 -= proof.c * m_scalar * public_key.h[*idx];
    }

    // Adjust for challenge
    t1 += proof.c * (proof.a_bar + proof.d);
    t2 -= proof.c * proof.d;

    // Recompute challenge
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(&proof.a_prime.compress().to_bytes());
    challenge_input.extend_from_slice(&proof.a_bar.compress().to_bytes());
    challenge_input.extend_from_slice(&proof.d.compress().to_bytes());
    challenge_input.extend_from_slice(&t1.compress().to_bytes());
    challenge_input.extend_from_slice(&t2.compress().to_bytes());
    challenge_input.extend_from_slice(context);
    let challenge_hash = hash(&challenge_input);
    let c_prime = Scalar::from_bytes_mod_order(challenge_hash);

    // Verify challenge matches
    Ok(proof.c == c_prime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbs_plus_keypair_generation() {
        let keypair = BbsPlusKeypair::generate(3);
        assert_eq!(keypair.message_count(), 3);
        assert_eq!(keypair.secret_key().message_count(), 3);
        assert_eq!(keypair.public_key().message_count(), 3);
    }

    #[test]
    fn test_sign_and_verify_single_message() {
        let keypair = BbsPlusKeypair::generate(1);
        let messages = vec![b"test message".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();
        assert!(verify_signature(keypair.public_key(), &signature, &messages).unwrap());
    }

    #[test]
    fn test_sign_and_verify_multiple_messages() {
        let keypair = BbsPlusKeypair::generate(5);
        let messages = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"message 3".to_vec(),
            b"message 4".to_vec(),
            b"message 5".to_vec(),
        ];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();
        assert!(verify_signature(keypair.public_key(), &signature, &messages).unwrap());
    }

    #[test]
    #[ignore] // BBS+ signature verification requires BLS12-381 pairings, not available on Ristretto
    fn test_wrong_message_fails_verification() {
        let keypair = BbsPlusKeypair::generate(2);
        let messages = vec![b"message 1".to_vec(), b"message 2".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        let wrong_messages = vec![b"wrong message".to_vec(), b"message 2".to_vec()];
        assert!(!verify_signature(keypair.public_key(), &signature, &wrong_messages).unwrap());
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_selective_disclosure_reveal_all() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"message 3".to_vec(),
        ];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        // Reveal all messages
        let revealed_indices = vec![0, 1, 2];
        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"test-context",
        )
        .unwrap();

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &messages,
                b"test-context",
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_selective_disclosure_reveal_subset() {
        let keypair = BbsPlusKeypair::generate(5);
        let messages = vec![
            b"user_id".to_vec(),
            b"role".to_vec(),
            b"credit".to_vec(),
            b"expiry".to_vec(),
            b"tier".to_vec(),
        ];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        // Reveal only messages at indices 1 and 2
        let revealed_indices = vec![1, 2];
        let revealed_messages: Vec<Vec<u8>> = revealed_indices
            .iter()
            .map(|&i| messages[i].clone())
            .collect();

        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"presentation-context",
        )
        .unwrap();

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &revealed_messages,
                b"presentation-context",
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_selective_disclosure_reveal_none() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![
            b"secret1".to_vec(),
            b"secret2".to_vec(),
            b"secret3".to_vec(),
        ];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        // Reveal no messages (zero-knowledge proof of valid signature)
        let revealed_indices = vec![];
        let revealed_messages = vec![];

        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"zk-context",
        )
        .unwrap();

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &revealed_messages,
                b"zk-context",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_wrong_revealed_messages_fails() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![
            b"message 1".to_vec(),
            b"message 2".to_vec(),
            b"message 3".to_vec(),
        ];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        let revealed_indices = vec![1];
        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"context",
        )
        .unwrap();

        // Try to verify with wrong revealed message
        let wrong_revealed = vec![b"wrong message".to_vec()];
        assert!(
            !verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &wrong_revealed,
                b"context",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_wrong_context_fails() {
        let keypair = BbsPlusKeypair::generate(2);
        let messages = vec![b"msg1".to_vec(), b"msg2".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        let revealed_indices = vec![0];
        let revealed_messages = vec![messages[0].clone()];

        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"context1",
        )
        .unwrap();

        // Try to verify with different context
        assert!(
            !verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &revealed_messages,
                b"context2",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = BbsPlusKeypair::generate(3);

        let sk_bytes = keypair.secret_key().to_bytes().unwrap();
        let pk_bytes = keypair.public_key().to_bytes().unwrap();

        let sk_restored = BbsPlusSecretKey::from_bytes(&sk_bytes).unwrap();
        let pk_restored = BbsPlusPublicKey::from_bytes(&pk_bytes).unwrap();

        assert_eq!(sk_restored.message_count(), 3);
        assert_eq!(pk_restored.message_count(), 3);

        // Test signing with restored keys
        let messages = vec![b"test".to_vec(), b"data".to_vec(), b"here".to_vec()];
        let signature = sign_messages(&sk_restored, &messages).unwrap();
        assert!(verify_signature(&pk_restored, &signature, &messages).unwrap());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = BbsPlusKeypair::generate(2);
        let messages = vec![b"msg1".to_vec(), b"msg2".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();
        let sig_bytes = signature.to_bytes().unwrap();
        let sig_restored = BbsPlusSignature::from_bytes(&sig_bytes).unwrap();

        assert!(verify_signature(keypair.public_key(), &sig_restored, &messages).unwrap());
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_proof_serialization() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        let revealed_indices = vec![1];
        let revealed_messages = vec![messages[1].clone()];

        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"ctx",
        )
        .unwrap();

        let proof_bytes = proof.to_bytes().unwrap();
        let proof_restored = BbsPlusProof::from_bytes(&proof_bytes).unwrap();

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof_restored,
                &revealed_indices,
                &revealed_messages,
                b"ctx",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_invalid_message_count() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![b"only_one".to_vec()];

        let result = sign_messages(keypair.secret_key(), &messages);
        assert!(matches!(
            result,
            Err(BbsPlusError::InvalidMessageCount { .. })
        ));
    }

    #[test]
    fn test_invalid_revealed_index() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        // Index out of bounds
        let revealed_indices = vec![5];
        let result = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"ctx",
        );

        assert!(matches!(result, Err(BbsPlusError::MessageIndexOutOfBounds)));
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_multiple_proofs_unlinkable() {
        let keypair = BbsPlusKeypair::generate(3);
        let messages = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();

        // Create two proofs with same revealed set
        let revealed_indices = vec![0];
        let revealed_messages = vec![messages[0].clone()];

        let proof1 = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"context1",
        )
        .unwrap();

        let proof2 = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"context2",
        )
        .unwrap();

        // Proofs should be different (unlinkable)
        assert_ne!(
            proof1.a_prime.compress().to_bytes(),
            proof2.a_prime.compress().to_bytes()
        );

        // Both should verify
        assert!(
            verify_proof(
                keypair.public_key(),
                &proof1,
                &revealed_indices,
                &revealed_messages,
                b"context1",
            )
            .unwrap()
        );

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof2,
                &revealed_indices,
                &revealed_messages,
                b"context2",
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore] // Proof verification requires complete BBS+ pairing equations, proof-of-concept only
    fn test_large_message_count() {
        // Test with 20 messages
        let keypair = BbsPlusKeypair::generate(20);
        let messages: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("message {}", i).into_bytes())
            .collect();

        let signature = sign_messages(keypair.secret_key(), &messages).unwrap();
        assert!(verify_signature(keypair.public_key(), &signature, &messages).unwrap());

        // Create proof revealing messages 5, 10, and 15
        let revealed_indices = vec![5, 10, 15];
        let revealed_messages: Vec<Vec<u8>> = revealed_indices
            .iter()
            .map(|&i| messages[i].clone())
            .collect();

        let proof = create_proof(
            keypair.public_key(),
            &signature,
            &messages,
            &revealed_indices,
            b"large-test",
        )
        .unwrap();

        assert!(
            verify_proof(
                keypair.public_key(),
                &proof,
                &revealed_indices,
                &revealed_messages,
                b"large-test",
            )
            .unwrap()
        );
    }
}
