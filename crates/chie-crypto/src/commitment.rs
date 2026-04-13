//! Cryptographic commitments for zero-knowledge proofs and challenge-response.
//!
//! This module provides commitment schemes used in the bandwidth proof protocol:
//! - Hash-based commitments (Pedersen-style)
//! - Challenge-response protocols
//! - Proof-of-possession for chunk data

use crate::hash::{Hash, hash, keyed_hash};
use crate::{PublicKey, SecretKey, SignatureBytes};
use rand::Rng as _;
use thiserror::Error;

/// Commitment value (256 bits).
pub type Commitment = Hash;

/// Opening value for a commitment.
#[derive(Debug, Clone)]
pub struct CommitmentOpening {
    /// The committed value.
    pub value: Vec<u8>,
    /// Random blinding factor.
    pub blinding: [u8; 32],
}

/// Commitment error types.
#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("Invalid commitment opening")]
    InvalidOpening,

    #[error("Commitment verification failed")]
    VerificationFailed,

    #[error("Invalid proof")]
    InvalidProof,
}

/// Create a cryptographic commitment to a value.
///
/// Uses a hash-based commitment scheme: C = H(value || blinding)
pub fn commit(value: &[u8]) -> (Commitment, CommitmentOpening) {
    let mut blinding = [0u8; 32];
    rand::rng().fill_bytes(&mut blinding);

    let mut data = Vec::with_capacity(value.len() + 32);
    data.extend_from_slice(value);
    data.extend_from_slice(&blinding);

    let commitment = hash(&data);

    let opening = CommitmentOpening {
        value: value.to_vec(),
        blinding,
    };

    (commitment, opening)
}

/// Verify a commitment opening.
pub fn verify_commitment(
    commitment: &Commitment,
    opening: &CommitmentOpening,
) -> Result<(), CommitmentError> {
    let mut data = Vec::with_capacity(opening.value.len() + 32);
    data.extend_from_slice(&opening.value);
    data.extend_from_slice(&opening.blinding);

    let computed = hash(&data);

    if &computed == commitment {
        Ok(())
    } else {
        Err(CommitmentError::VerificationFailed)
    }
}

/// Proof of possession for chunk data.
///
/// This proves that a node has access to the actual chunk data
/// without revealing the data itself.
#[derive(Debug, Clone)]
pub struct ChunkPossessionProof {
    /// Challenge nonce used in the proof.
    pub challenge: [u8; 32],
    /// Response: HMAC(chunk_data, challenge).
    pub response: Hash,
}

impl ChunkPossessionProof {
    /// Generate a proof of possession for chunk data.
    ///
    /// # Arguments
    /// * `chunk_data` - The actual chunk data to prove possession of
    /// * `challenge` - Challenge nonce from the requester
    pub fn generate(chunk_data: &[u8], challenge: &[u8; 32]) -> Self {
        // Response is keyed hash: H_k(chunk_data) where k = challenge
        let response = keyed_hash(challenge, chunk_data);

        Self {
            challenge: *challenge,
            response,
        }
    }

    /// Verify the proof of possession.
    ///
    /// # Arguments
    /// * `chunk_data` - The chunk data to verify against
    pub fn verify(&self, chunk_data: &[u8]) -> Result<(), CommitmentError> {
        let expected = keyed_hash(&self.challenge, chunk_data);

        if expected == self.response {
            Ok(())
        } else {
            Err(CommitmentError::InvalidProof)
        }
    }
}

/// Challenge for requesting proof of chunk possession.
#[derive(Debug, Clone)]
pub struct ChunkChallenge {
    /// Random challenge nonce.
    pub nonce: [u8; 32],
    /// Chunk index being challenged.
    pub chunk_index: u64,
    /// Expected chunk hash (for verification).
    pub expected_hash: Hash,
}

impl ChunkChallenge {
    /// Create a new chunk challenge.
    pub fn new(chunk_index: u64, expected_hash: Hash) -> Self {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        Self {
            nonce,
            chunk_index,
            expected_hash,
        }
    }

    /// Verify a chunk possession proof against this challenge.
    pub fn verify_proof(
        &self,
        chunk_data: &[u8],
        proof: &ChunkPossessionProof,
    ) -> Result<(), CommitmentError> {
        // Check the chunk hash matches
        let chunk_hash = hash(chunk_data);
        if chunk_hash != self.expected_hash {
            return Err(CommitmentError::InvalidProof);
        }

        // Check the nonce matches
        if proof.challenge != self.nonce {
            return Err(CommitmentError::InvalidProof);
        }

        // Verify the proof
        proof.verify(chunk_data)
    }
}

/// Bandwidth proof commitment for challenge-response protocol.
///
/// Used in the CHIE bandwidth proof protocol to prevent cheating.
#[derive(Debug, Clone)]
pub struct BandwidthProofCommitment {
    /// Commitment to the chunk data.
    pub chunk_commitment: Commitment,
    /// Timestamp of commitment.
    pub timestamp: i64,
    /// Chunk index.
    pub chunk_index: u64,
}

impl BandwidthProofCommitment {
    /// Create a commitment to chunk data before transfer.
    pub fn new(chunk_data: &[u8], chunk_index: u64, timestamp: i64) -> (Self, CommitmentOpening) {
        let (commitment, opening) = commit(chunk_data);

        let bw_commitment = Self {
            chunk_commitment: commitment,
            timestamp,
            chunk_index,
        };

        (bw_commitment, opening)
    }

    /// Verify the commitment against the actual chunk data.
    pub fn verify(
        &self,
        opening: &CommitmentOpening,
        expected_chunk_data: &[u8],
    ) -> Result<(), CommitmentError> {
        // Verify the commitment opening
        verify_commitment(&self.chunk_commitment, opening)?;

        // Verify the opened value matches expected chunk data
        if opening.value != expected_chunk_data {
            return Err(CommitmentError::VerificationFailed);
        }

        Ok(())
    }
}

/// Proof-of-possession for a signing key (proves knowledge of secret key).
#[derive(Debug, Clone)]
pub struct KeyPossessionProof {
    /// Public key being proven.
    pub public_key: PublicKey,
    /// Challenge nonce.
    pub challenge: [u8; 32],
    /// Signature of challenge.
    pub signature: SignatureBytes,
}

impl KeyPossessionProof {
    /// Generate a proof of possession for a signing key.
    pub fn generate(
        secret_key: &SecretKey,
        challenge: &[u8; 32],
    ) -> Result<Self, crate::SigningError> {
        use crate::signing::KeyPair;

        let keypair = KeyPair::from_secret_key(secret_key)?;
        let public_key = keypair.public_key();
        let signature = keypair.sign(challenge);

        Ok(Self {
            public_key,
            challenge: *challenge,
            signature,
        })
    }

    /// Verify the proof of possession.
    pub fn verify(&self) -> Result<(), CommitmentError> {
        use crate::signing::verify;

        verify(&self.public_key, &self.challenge, &self.signature)
            .map_err(|_| CommitmentError::InvalidProof)
    }
}

/// Generate a random challenge nonce.
pub fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_verify() {
        let value = b"test data to commit";
        let (commitment, opening) = commit(value);

        assert!(verify_commitment(&commitment, &opening).is_ok());

        // Wrong value should fail
        let mut wrong_opening = opening.clone();
        wrong_opening.value = b"wrong data".to_vec();
        assert!(verify_commitment(&commitment, &wrong_opening).is_err());
    }

    #[test]
    fn test_chunk_possession_proof() {
        let chunk_data = b"chunk data that needs to be proven";
        let challenge = generate_challenge();

        let proof = ChunkPossessionProof::generate(chunk_data, &challenge);
        assert!(proof.verify(chunk_data).is_ok());

        // Wrong data should fail
        assert!(proof.verify(b"wrong data").is_err());
    }

    #[test]
    fn test_chunk_challenge() {
        let chunk_data = b"test chunk data";
        let chunk_hash = hash(chunk_data);
        let challenge = ChunkChallenge::new(0, chunk_hash);

        let proof = ChunkPossessionProof::generate(chunk_data, &challenge.nonce);
        assert!(challenge.verify_proof(chunk_data, &proof).is_ok());

        // Wrong chunk should fail
        assert!(challenge.verify_proof(b"wrong chunk", &proof).is_err());
    }

    #[test]
    fn test_bandwidth_proof_commitment() {
        let chunk_data = b"bandwidth proof chunk";
        let (commitment, opening) = BandwidthProofCommitment::new(chunk_data, 0, 1234567890);

        assert!(commitment.verify(&opening, chunk_data).is_ok());
        assert!(commitment.verify(&opening, b"wrong data").is_err());
    }

    #[test]
    fn test_key_possession_proof() {
        use crate::signing::KeyPair;

        let keypair = KeyPair::generate();
        let secret = keypair.secret_key();
        let challenge = generate_challenge();

        let proof = KeyPossessionProof::generate(&secret, &challenge).unwrap();
        assert!(proof.verify().is_ok());

        // Tampered signature should fail
        let mut bad_proof = proof.clone();
        bad_proof.signature[0] ^= 1;
        assert!(bad_proof.verify().is_err());
    }

    #[test]
    fn test_different_blindings() {
        let value = b"same value";

        let (c1, _) = commit(value);
        let (c2, _) = commit(value);

        // Same value with different blindings should produce different commitments
        assert_ne!(c1, c2);
    }
}
