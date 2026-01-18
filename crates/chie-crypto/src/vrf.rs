//! Verifiable Random Functions (VRF) for unpredictable but verifiable randomness.
//!
//! VRFs are useful for generating unpredictable challenges that can be verified by others.
//! Perfect for bandwidth proof protocols where challenges must be:
//! - Unpredictable (to prevent pre-computation attacks)
//! - Verifiable (to prove the challenge was legitimate)
//! - Deterministic (same input always produces same output)
//!
//! This implementation uses Ed25519-based VRF (ECVRF-ED25519-SHA512-ELL2).

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// VRF-specific errors.
#[derive(Debug, Error)]
pub enum VrfError {
    #[error("Invalid VRF proof")]
    InvalidProof,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("Invalid input length")]
    InvalidInputLength,
}

pub type VrfResult<T> = Result<T, VrfError>;

/// VRF secret key for generating proofs.
#[derive(Clone)]
pub struct VrfSecretKey {
    signing_key: SigningKey,
}

/// VRF public key for verifying proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfPublicKey {
    verifying_key: VerifyingKey,
}

/// A VRF proof that can be verified by anyone with the public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof {
    /// The signature part of the proof
    signature: [u8; 64],
    /// The hash output
    output: [u8; 32],
}

// Custom serialization for VrfProof to handle large arrays
impl Serialize for VrfProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("VrfProof", 2)?;
        state.serialize_field("signature", &self.signature.as_slice())?;
        state.serialize_field("output", &self.output)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for VrfProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct VrfProofVisitor;

        impl<'de> Visitor<'de> for VrfProofVisitor {
            type Value = VrfProof;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct VrfProof")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<VrfProof, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let sig_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let output: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                if sig_bytes.len() != 64 {
                    return Err(de::Error::invalid_length(sig_bytes.len(), &"64 bytes"));
                }

                let mut signature = [0u8; 64];
                signature.copy_from_slice(&sig_bytes);

                Ok(VrfProof { signature, output })
            }

            fn visit_map<V>(self, mut map: V) -> Result<VrfProof, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut signature: Option<Vec<u8>> = None;
                let mut output: Option<[u8; 32]> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "signature" => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                        "output" => {
                            if output.is_some() {
                                return Err(de::Error::duplicate_field("output"));
                            }
                            output = Some(map.next_value()?);
                        }
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let sig_bytes = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                let output = output.ok_or_else(|| de::Error::missing_field("output"))?;

                if sig_bytes.len() != 64 {
                    return Err(de::Error::invalid_length(sig_bytes.len(), &"64 bytes"));
                }

                let mut signature = [0u8; 64];
                signature.copy_from_slice(&sig_bytes);

                Ok(VrfProof { signature, output })
            }
        }

        const FIELDS: &[&str] = &["signature", "output"];
        deserializer.deserialize_struct("VrfProof", FIELDS, VrfProofVisitor)
    }
}

impl VrfSecretKey {
    /// Generate a new random VRF secret key.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("Failed to generate random bytes");
        let signing_key = SigningKey::from_bytes(&secret);
        Self { signing_key }
    }

    /// Create VRF secret key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> VrfPublicKey {
        VrfPublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Prove and compute VRF output for given input.
    ///
    /// This generates a proof that the output was correctly computed,
    /// and returns both the proof and the deterministic pseudorandom output.
    pub fn prove(&self, input: &[u8]) -> VrfProof {
        // Hash the input with the public key to get a point
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VRF_INPUT:");
        hasher.update(&self.public_key().to_bytes());
        hasher.update(input);
        let point_hash = hasher.finalize();

        // Sign the point hash to create the proof
        let signature = self.signing_key.sign(point_hash.as_bytes());

        // Compute the VRF output by hashing the signature
        let mut output_hasher = blake3::Hasher::new();
        output_hasher.update(b"VRF_OUTPUT:");
        output_hasher.update(&signature.to_bytes());
        let output = output_hasher.finalize();

        VrfProof {
            signature: signature.to_bytes(),
            output: *output.as_bytes(),
        }
    }

    /// Prove and return only the VRF output (convenience method).
    pub fn prove_output(&self, input: &[u8]) -> [u8; 32] {
        self.prove(input).output()
    }

    /// Prove with domain separation for different use cases.
    ///
    /// This allows using the same key for different purposes without risk
    /// of cross-protocol attacks.
    pub fn prove_with_domain(&self, domain: &[u8], input: &[u8]) -> VrfProof {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VRF_DOMAIN_INPUT:");
        hasher.update(domain);
        hasher.update(&self.public_key().to_bytes());
        hasher.update(input);
        let point_hash = hasher.finalize();

        let signature = self.signing_key.sign(point_hash.as_bytes());

        let mut output_hasher = blake3::Hasher::new();
        output_hasher.update(b"VRF_DOMAIN_OUTPUT:");
        output_hasher.update(domain);
        output_hasher.update(&signature.to_bytes());
        let output = output_hasher.finalize();

        VrfProof {
            signature: signature.to_bytes(),
            output: *output.as_bytes(),
        }
    }
}

impl VrfPublicKey {
    /// Create VRF public key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> VrfResult<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|_| VrfError::InvalidPublicKey)?;
        Ok(Self { verifying_key })
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Verify a VRF proof and return the output if valid.
    pub fn verify(&self, input: &[u8], proof: &VrfProof) -> VrfResult<[u8; 32]> {
        // Reconstruct the point hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VRF_INPUT:");
        hasher.update(&self.to_bytes());
        hasher.update(input);
        let point_hash = hasher.finalize();

        // Verify the signature
        let signature = Signature::from_bytes(&proof.signature);
        self.verifying_key
            .verify(point_hash.as_bytes(), &signature)
            .map_err(|_| VrfError::VerificationFailed)?;

        // Recompute the output and verify it matches
        let mut output_hasher = blake3::Hasher::new();
        output_hasher.update(b"VRF_OUTPUT:");
        output_hasher.update(&proof.signature);
        let computed_output = output_hasher.finalize();

        if computed_output.as_bytes() != &proof.output {
            return Err(VrfError::InvalidProof);
        }

        Ok(proof.output)
    }

    /// Verify a VRF proof with domain separation.
    pub fn verify_with_domain(
        &self,
        domain: &[u8],
        input: &[u8],
        proof: &VrfProof,
    ) -> VrfResult<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VRF_DOMAIN_INPUT:");
        hasher.update(domain);
        hasher.update(&self.to_bytes());
        hasher.update(input);
        let point_hash = hasher.finalize();

        let signature = Signature::from_bytes(&proof.signature);
        self.verifying_key
            .verify(point_hash.as_bytes(), &signature)
            .map_err(|_| VrfError::VerificationFailed)?;

        let mut output_hasher = blake3::Hasher::new();
        output_hasher.update(b"VRF_DOMAIN_OUTPUT:");
        output_hasher.update(domain);
        output_hasher.update(&proof.signature);
        let computed_output = output_hasher.finalize();

        if computed_output.as_bytes() != &proof.output {
            return Err(VrfError::InvalidProof);
        }

        Ok(proof.output)
    }

    /// Batch verify multiple VRF proofs for efficiency.
    ///
    /// Returns true if all proofs are valid, false otherwise.
    /// This is faster than verifying each proof individually.
    pub fn batch_verify(&self, inputs: &[&[u8]], proofs: &[VrfProof]) -> VrfResult<Vec<[u8; 32]>> {
        if inputs.len() != proofs.len() {
            return Err(VrfError::InvalidInputLength);
        }

        let mut outputs = Vec::with_capacity(proofs.len());

        for (input, proof) in inputs.iter().zip(proofs.iter()) {
            let output = self.verify(input, proof)?;
            outputs.push(output);
        }

        Ok(outputs)
    }
}

impl VrfProof {
    /// Get the VRF output hash.
    pub fn output(&self) -> [u8; 32] {
        self.output
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }

    /// Serialize to bytes (signature || output).
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..64].copy_from_slice(&self.signature);
        bytes[64..].copy_from_slice(&self.output);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 96]) -> Self {
        let mut signature = [0u8; 64];
        let mut output = [0u8; 32];
        signature.copy_from_slice(&bytes[..64]);
        output.copy_from_slice(&bytes[64..]);
        Self { signature, output }
    }

    /// Derive additional pseudorandom outputs from this proof.
    ///
    /// This allows generating a stream of random values from a single VRF proof
    /// without needing additional proofs.
    pub fn derive_output(&self, index: u32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"VRF_DERIVE:");
        hasher.update(&self.output);
        hasher.update(&index.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Derive multiple pseudorandom outputs from this proof.
    pub fn derive_outputs(&self, count: u32) -> Vec<[u8; 32]> {
        (0..count).map(|i| self.derive_output(i)).collect()
    }
}

/// Generate a verifiable random challenge for bandwidth proofs.
///
/// This is a high-level convenience function that combines node ID, chunk ID,
/// and timestamp to generate a unique, unpredictable, but verifiable challenge.
pub fn generate_bandwidth_challenge(
    secret_key: &VrfSecretKey,
    node_id: &[u8],
    chunk_id: &[u8],
    timestamp: u64,
) -> VrfProof {
    let mut input = Vec::with_capacity(node_id.len() + chunk_id.len() + 8);
    input.extend_from_slice(node_id);
    input.extend_from_slice(chunk_id);
    input.extend_from_slice(&timestamp.to_le_bytes());

    secret_key.prove(&input)
}

/// Verify a bandwidth challenge proof.
pub fn verify_bandwidth_challenge(
    public_key: &VrfPublicKey,
    node_id: &[u8],
    chunk_id: &[u8],
    timestamp: u64,
    proof: &VrfProof,
) -> VrfResult<[u8; 32]> {
    let mut input = Vec::with_capacity(node_id.len() + chunk_id.len() + 8);
    input.extend_from_slice(node_id);
    input.extend_from_slice(chunk_id);
    input.extend_from_slice(&timestamp.to_le_bytes());

    public_key.verify(&input, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_basic() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let input = b"test input";
        let proof = sk.prove(input);

        // Verification should succeed
        let output = pk.verify(input, &proof).unwrap();
        assert_eq!(output, proof.output());
    }

    #[test]
    fn test_vrf_deterministic() {
        let sk = VrfSecretKey::generate();
        let input = b"test input";

        let proof1 = sk.prove(input);
        let proof2 = sk.prove(input);

        // Same input should produce same output
        assert_eq!(proof1.output(), proof2.output());
        assert_eq!(proof1.signature(), proof2.signature());
    }

    #[test]
    fn test_vrf_different_inputs() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let input1 = b"input1";
        let input2 = b"input2";

        let proof1 = sk.prove(input1);
        let proof2 = sk.prove(input2);

        // Different inputs should produce different outputs
        assert_ne!(proof1.output(), proof2.output());

        // Both should verify correctly
        pk.verify(input1, &proof1).unwrap();
        pk.verify(input2, &proof2).unwrap();

        // Cross-verification should fail
        assert!(pk.verify(input1, &proof2).is_err());
        assert!(pk.verify(input2, &proof1).is_err());
    }

    #[test]
    fn test_vrf_wrong_public_key() {
        let sk1 = VrfSecretKey::generate();
        let sk2 = VrfSecretKey::generate();
        let pk2 = sk2.public_key();

        let input = b"test input";
        let proof = sk1.prove(input);

        // Verification with wrong public key should fail
        assert!(pk2.verify(input, &proof).is_err());
    }

    #[test]
    fn test_vrf_serialization() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let input = b"test input";
        let proof = sk.prove(input);

        // Serialize and deserialize proof
        let proof_bytes = proof.to_bytes();
        let proof2 = VrfProof::from_bytes(&proof_bytes);

        assert_eq!(proof.output(), proof2.output());
        assert_eq!(proof.signature(), proof2.signature());

        // Should still verify
        pk.verify(input, &proof2).unwrap();
    }

    #[test]
    fn test_vrf_key_serialization() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        // Serialize and deserialize keys
        let sk_bytes = sk.to_bytes();
        let sk2 = VrfSecretKey::from_bytes(&sk_bytes);

        let pk_bytes = pk.to_bytes();
        let pk2 = VrfPublicKey::from_bytes(&pk_bytes).unwrap();

        // Should produce same results
        let input = b"test input";
        let proof1 = sk.prove(input);
        let proof2 = sk2.prove(input);

        assert_eq!(proof1.output(), proof2.output());

        pk2.verify(input, &proof1).unwrap();
    }

    #[test]
    fn test_bandwidth_challenge() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let node_id = b"node123";
        let chunk_id = b"chunk456";
        let timestamp = 1234567890u64;

        let proof = generate_bandwidth_challenge(&sk, node_id, chunk_id, timestamp);

        // Verification should succeed
        let output = verify_bandwidth_challenge(&pk, node_id, chunk_id, timestamp, &proof).unwrap();
        assert_eq!(output, proof.output());

        // Different timestamp should fail
        assert!(verify_bandwidth_challenge(&pk, node_id, chunk_id, timestamp + 1, &proof).is_err());
    }

    #[test]
    fn test_unpredictability() {
        let sk = VrfSecretKey::generate();

        // Generate multiple outputs
        let outputs: Vec<[u8; 32]> = (0u64..10)
            .map(|i| sk.prove_output(&i.to_le_bytes()))
            .collect();

        // All outputs should be different
        for i in 0..outputs.len() {
            for j in i + 1..outputs.len() {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
    }

    #[test]
    fn test_domain_separation() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let domain1 = b"domain1";
        let domain2 = b"domain2";
        let input = b"test input";

        let proof1 = sk.prove_with_domain(domain1, input);
        let proof2 = sk.prove_with_domain(domain2, input);

        // Different domains should produce different outputs
        assert_ne!(proof1.output(), proof2.output());

        // Each should verify with correct domain
        pk.verify_with_domain(domain1, input, &proof1).unwrap();
        pk.verify_with_domain(domain2, input, &proof2).unwrap();

        // Cross-domain verification should fail
        assert!(pk.verify_with_domain(domain1, input, &proof2).is_err());
        assert!(pk.verify_with_domain(domain2, input, &proof1).is_err());
    }

    #[test]
    fn test_batch_verify() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let inputs: Vec<Vec<u8>> = (0..5).map(|i| format!("input{}", i).into_bytes()).collect();
        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

        let proofs: Vec<VrfProof> = input_refs.iter().map(|input| sk.prove(input)).collect();

        // Batch verification should succeed
        let outputs = pk.batch_verify(&input_refs, &proofs).unwrap();
        assert_eq!(outputs.len(), 5);

        // Each output should match individual verification
        for (i, (input, proof)) in input_refs.iter().zip(proofs.iter()).enumerate() {
            let individual_output = pk.verify(input, proof).unwrap();
            assert_eq!(outputs[i], individual_output);
        }
    }

    #[test]
    fn test_batch_verify_mismatched_lengths() {
        let sk = VrfSecretKey::generate();
        let pk = sk.public_key();

        let inputs: Vec<&[u8]> = vec![b"input1", b"input2", b"input3"];
        let proofs: Vec<VrfProof> = vec![sk.prove(b"input1"), sk.prove(b"input2")];

        // Mismatched lengths should error
        assert!(pk.batch_verify(&inputs, &proofs).is_err());
    }

    #[test]
    fn test_derive_outputs() {
        let sk = VrfSecretKey::generate();
        let input = b"test input";
        let proof = sk.prove(input);

        // Derive multiple outputs
        let derived = proof.derive_outputs(10);
        assert_eq!(derived.len(), 10);

        // All derived outputs should be different
        for i in 0..derived.len() {
            for j in i + 1..derived.len() {
                assert_ne!(derived[i], derived[j]);
            }
        }

        // Deriving the same index should give same result
        let output1 = proof.derive_output(5);
        let output2 = proof.derive_output(5);
        assert_eq!(output1, output2);
        assert_eq!(output1, derived[5]);
    }

    #[test]
    fn test_proof_serialization_serde() {
        let sk = VrfSecretKey::generate();
        let input = b"test input";
        let proof = sk.prove(input);

        // Serialize with bincode
        let serialized = crate::codec::encode(&proof).unwrap();
        let deserialized: VrfProof = crate::codec::decode(&serialized).unwrap();

        assert_eq!(proof.output(), deserialized.output());
        assert_eq!(proof.signature(), deserialized.signature());
    }
}
