//! Zero-Knowledge Proof Composition Framework
//!
//! This module provides a framework for composing multiple zero-knowledge proofs
//! into complex protocols with AND/OR logic and proof aggregation.
//!
//! Perfect for building complex privacy-preserving protocols where you need to prove
//! multiple statements together (e.g., "I know a secret AND it's in a certain range").

use blake3;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur in ZK proof operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ZkProofError {
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("Invalid proof composition")]
    InvalidComposition,
    #[error("Proof not found")]
    ProofNotFound,
    #[error("Invalid proof type")]
    InvalidProofType,
}

pub type ZkProofResult<T> = Result<T, ZkProofError>;

/// A zero-knowledge proof with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    /// Unique identifier for this proof type
    proof_type: String,
    /// The actual proof data
    proof_data: Vec<u8>,
    /// Public inputs/statements
    public_inputs: Vec<Vec<u8>>,
    /// Optional metadata
    metadata: Vec<(String, Vec<u8>)>,
}

impl ZkProof {
    /// Create a new ZK proof
    pub fn new(
        proof_type: impl Into<String>,
        proof_data: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            proof_type: proof_type.into(),
            proof_data,
            public_inputs,
            metadata: Vec::new(),
        }
    }

    /// Add metadata to the proof
    pub fn with_metadata(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.metadata.push((key.into(), value));
        self
    }

    /// Get the proof type
    pub fn proof_type(&self) -> &str {
        &self.proof_type
    }

    /// Get the proof data
    pub fn proof_data(&self) -> &[u8] {
        &self.proof_data
    }

    /// Get the public inputs
    pub fn public_inputs(&self) -> &[Vec<u8>] {
        &self.public_inputs
    }

    /// Get metadata by key
    pub fn get_metadata(&self, key: &str) -> Option<&[u8]> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Compute a hash commitment to this proof
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ZK_PROOF_COMMITMENT:");
        hasher.update(self.proof_type.as_bytes());
        hasher.update(&self.proof_data);
        for input in &self.public_inputs {
            hasher.update(input);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Composite proof combining multiple proofs with AND logic
///
/// All constituent proofs must verify for the composite to be valid
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AndProof {
    proofs: Vec<ZkProof>,
    /// Optional binding to ensure all proofs relate to the same statement
    binding: Option<[u8; 32]>,
}

impl AndProof {
    /// Create a new AND composition of proofs
    pub fn new(proofs: Vec<ZkProof>) -> Self {
        Self {
            proofs,
            binding: None,
        }
    }

    /// Add a binding value that links all proofs together
    pub fn with_binding(mut self, binding: [u8; 32]) -> Self {
        self.binding = Some(binding);
        self
    }

    /// Get all constituent proofs
    pub fn proofs(&self) -> &[ZkProof] {
        &self.proofs
    }

    /// Get a proof by type
    pub fn get_proof(&self, proof_type: &str) -> Option<&ZkProof> {
        self.proofs.iter().find(|p| p.proof_type() == proof_type)
    }

    /// Verify the binding if present
    pub fn verify_binding(&self) -> ZkProofResult<()> {
        if let Some(binding) = self.binding {
            // Compute expected binding from all proof commitments
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AND_PROOF_BINDING:");
            for proof in &self.proofs {
                hasher.update(&proof.commitment());
            }
            let expected = hasher.finalize();

            if expected.as_bytes() != &binding {
                return Err(ZkProofError::VerificationFailed);
            }
        }
        Ok(())
    }

    /// Compute the AND composition's commitment
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AND_COMPOSITION:");
        for proof in &self.proofs {
            hasher.update(&proof.commitment());
        }
        if let Some(binding) = &self.binding {
            hasher.update(binding);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Composite proof combining multiple proofs with OR logic
///
/// At least one constituent proof must verify for the composite to be valid
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrProof {
    /// The valid proof (only one is revealed)
    proof: ZkProof,
    /// Commitments to all possible proofs (for privacy)
    commitments: Vec<[u8; 32]>,
    /// Index of the revealed proof
    revealed_index: usize,
}

impl OrProof {
    /// Create a new OR composition (reveals one proof, hides others)
    pub fn new(all_proofs: Vec<ZkProof>, revealed_index: usize) -> ZkProofResult<Self> {
        if revealed_index >= all_proofs.len() {
            return Err(ZkProofError::InvalidComposition);
        }

        let commitments: Vec<[u8; 32]> = all_proofs.iter().map(|p| p.commitment()).collect();

        Ok(Self {
            proof: all_proofs[revealed_index].clone(),
            commitments,
            revealed_index,
        })
    }

    /// Get the revealed proof
    pub fn proof(&self) -> &ZkProof {
        &self.proof
    }

    /// Get all commitments
    pub fn commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }

    /// Get the revealed index
    pub fn revealed_index(&self) -> usize {
        self.revealed_index
    }

    /// Verify that the revealed proof matches its commitment
    pub fn verify_commitment(&self) -> ZkProofResult<()> {
        let commitment = self.proof.commitment();
        if commitment != self.commitments[self.revealed_index] {
            return Err(ZkProofError::VerificationFailed);
        }
        Ok(())
    }
}

/// Builder for creating composite proofs
pub struct ZkProofBuilder {
    proofs: Vec<ZkProof>,
}

impl ZkProofBuilder {
    /// Create a new proof builder
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    /// Add a proof to the composition
    pub fn add_proof(mut self, proof: ZkProof) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Build an AND composition
    pub fn build_and(self) -> AndProof {
        AndProof::new(self.proofs)
    }

    /// Build an AND composition with binding
    pub fn build_and_with_binding(self, binding: [u8; 32]) -> AndProof {
        AndProof::new(self.proofs).with_binding(binding)
    }

    /// Build an OR composition (reveal one proof)
    pub fn build_or(self, revealed_index: usize) -> ZkProofResult<OrProof> {
        OrProof::new(self.proofs, revealed_index)
    }
}

impl Default for ZkProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for types that can be proven in zero-knowledge
pub trait ZkProvable {
    /// Generate a zero-knowledge proof
    fn prove(&self) -> ZkProofResult<ZkProof>;

    /// Verify a zero-knowledge proof
    fn verify(proof: &ZkProof) -> ZkProofResult<bool>;
}

/// Helper to create a binding value for AND compositions
pub fn create_binding(proofs: &[&ZkProof]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AND_PROOF_BINDING:");
    for proof in proofs {
        hasher.update(&proof.commitment());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_proof(proof_type: &str, data: &[u8]) -> ZkProof {
        ZkProof::new(proof_type, data.to_vec(), vec![b"public_input".to_vec()])
    }

    #[test]
    fn test_zkproof_creation() {
        let proof = create_test_proof("range", b"proof_data");
        assert_eq!(proof.proof_type(), "range");
        assert_eq!(proof.proof_data(), b"proof_data");
        assert_eq!(proof.public_inputs().len(), 1);
    }

    #[test]
    fn test_zkproof_metadata() {
        let proof = create_test_proof("range", b"proof_data")
            .with_metadata("key1", b"value1".to_vec())
            .with_metadata("key2", b"value2".to_vec());

        assert_eq!(proof.get_metadata("key1"), Some(b"value1".as_slice()));
        assert_eq!(proof.get_metadata("key2"), Some(b"value2".as_slice()));
        assert_eq!(proof.get_metadata("key3"), None);
    }

    #[test]
    fn test_zkproof_commitment() {
        let proof1 = create_test_proof("range", b"proof_data");
        let proof2 = create_test_proof("range", b"proof_data");
        let proof3 = create_test_proof("range", b"different_data");

        // Same data should produce same commitment
        assert_eq!(proof1.commitment(), proof2.commitment());

        // Different data should produce different commitment
        assert_ne!(proof1.commitment(), proof3.commitment());
    }

    #[test]
    fn test_and_proof_basic() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");
        let proof3 = create_test_proof("signature", b"proof3");

        let and_proof = AndProof::new(vec![proof1, proof2, proof3]);

        assert_eq!(and_proof.proofs().len(), 3);
        assert!(and_proof.get_proof("range").is_some());
        assert!(and_proof.get_proof("membership").is_some());
        assert!(and_proof.get_proof("signature").is_some());
        assert!(and_proof.get_proof("nonexistent").is_none());
    }

    #[test]
    fn test_and_proof_binding() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");

        // Clone for binding computation since we need to move them into AndProof
        let binding = create_binding(&[&proof1, &proof2]);
        let and_proof = AndProof::new(vec![proof1.clone(), proof2.clone()]).with_binding(binding);

        // Correct binding should verify
        assert!(and_proof.verify_binding().is_ok());
    }

    #[test]
    fn test_and_proof_invalid_binding() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");

        // Create with wrong binding
        let wrong_binding = [0u8; 32];
        let and_proof = AndProof::new(vec![proof1, proof2]).with_binding(wrong_binding);

        // Wrong binding should fail
        assert!(and_proof.verify_binding().is_err());
    }

    #[test]
    fn test_or_proof_basic() {
        let proof1 = create_test_proof("option1", b"proof1");
        let proof2 = create_test_proof("option2", b"proof2");
        let proof3 = create_test_proof("option3", b"proof3");

        let or_proof = OrProof::new(vec![proof1, proof2.clone(), proof3], 1).unwrap();

        assert_eq!(or_proof.revealed_index(), 1);
        assert_eq!(or_proof.proof().proof_type(), "option2");
        assert_eq!(or_proof.commitments().len(), 3);
    }

    #[test]
    fn test_or_proof_commitment_verification() {
        let proof1 = create_test_proof("option1", b"proof1");
        let proof2 = create_test_proof("option2", b"proof2");

        let or_proof = OrProof::new(vec![proof1, proof2], 0).unwrap();

        // Commitment should verify
        assert!(or_proof.verify_commitment().is_ok());
    }

    #[test]
    fn test_or_proof_invalid_index() {
        let proof1 = create_test_proof("option1", b"proof1");
        let proof2 = create_test_proof("option2", b"proof2");

        // Index out of bounds should error
        let result = OrProof::new(vec![proof1, proof2], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_builder_and() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");

        let and_proof = ZkProofBuilder::new()
            .add_proof(proof1)
            .add_proof(proof2)
            .build_and();

        assert_eq!(and_proof.proofs().len(), 2);
    }

    #[test]
    fn test_proof_builder_and_with_binding() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");

        let binding = create_binding(&[&proof1, &proof2]);
        let and_proof = ZkProofBuilder::new()
            .add_proof(proof1.clone())
            .add_proof(proof2.clone())
            .build_and_with_binding(binding);

        assert!(and_proof.verify_binding().is_ok());
    }

    #[test]
    fn test_proof_builder_or() {
        let proof1 = create_test_proof("option1", b"proof1");
        let proof2 = create_test_proof("option2", b"proof2");
        let proof3 = create_test_proof("option3", b"proof3");

        let or_proof = ZkProofBuilder::new()
            .add_proof(proof1)
            .add_proof(proof2)
            .add_proof(proof3)
            .build_or(1)
            .unwrap();

        assert_eq!(or_proof.revealed_index(), 1);
        assert_eq!(or_proof.proof().proof_type(), "option2");
    }

    #[test]
    fn test_serialization() {
        let proof1 = create_test_proof("range", b"proof1");
        let proof2 = create_test_proof("membership", b"proof2");

        let and_proof = AndProof::new(vec![proof1, proof2]);

        // Serialize with bincode
        let serialized = crate::codec::encode(&and_proof).unwrap();
        let deserialized: AndProof = crate::codec::decode(&serialized).unwrap();

        assert_eq!(deserialized.proofs().len(), 2);
        assert_eq!(deserialized.commitment(), and_proof.commitment());
    }
}
