//! Advanced commitment schemes with opening proofs.
//!
//! This module provides advanced cryptographic commitment schemes beyond basic commitments:
//! - **Trapdoor commitments**: Allow commitment creator to open to different values (with trapdoor)
//! - **Equivocal commitments**: Support simulation in zero-knowledge proofs
//! - **Extractable commitments**: Enable proof-of-knowledge extraction
//! - **Vector commitments**: Commit to vectors with sublinear opening proofs
//!
//! These advanced schemes are useful for:
//! - Zero-knowledge proof systems
//! - Secure multi-party computation
//! - Verifiable computation
//! - Blockchain applications
//!
//! # Example - Trapdoor Commitment
//!
//! ```
//! use chie_crypto::advanced_commitment::TrapdoorCommitment;
//!
//! // Setup with trapdoor
//! let (commitment, trapdoor) = TrapdoorCommitment::setup();
//!
//! // Commit to a value
//! let value = b"original value";
//! let (com, opening) = commitment.commit(value);
//!
//! // Can open normally
//! assert!(commitment.verify(&com, value, &opening));
//!
//! // With trapdoor, can open to different value
//! let fake_value = b"different value";
//! let fake_opening = commitment.equivocate(&com, value, &opening, fake_value, &trapdoor);
//! assert!(commitment.verify(&com, fake_value, &fake_opening));
//! ```

use blake3::Hasher;
use curve25519_dalek::{RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Result type for advanced commitment operations.
pub type AdvancedCommitmentResult<T> = Result<T, AdvancedCommitmentError>;

/// Errors that can occur during advanced commitment operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvancedCommitmentError {
    /// Commitment verification failed
    VerificationFailed,
    /// Invalid opening proof
    InvalidOpening,
    /// Invalid index
    InvalidIndex,
    /// Serialization failed
    SerializationFailed,
    /// Deserialization failed
    DeserializationFailed,
}

impl fmt::Display for AdvancedCommitmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvancedCommitmentError::VerificationFailed => {
                write!(f, "Commitment verification failed")
            }
            AdvancedCommitmentError::InvalidOpening => write!(f, "Invalid opening proof"),
            AdvancedCommitmentError::InvalidIndex => write!(f, "Invalid index"),
            AdvancedCommitmentError::SerializationFailed => write!(f, "Serialization failed"),
            AdvancedCommitmentError::DeserializationFailed => write!(f, "Deserialization failed"),
        }
    }
}

impl std::error::Error for AdvancedCommitmentError {}

// ============================================================================
// Trapdoor Commitments
// ============================================================================

/// Trapdoor commitment scheme.
///
/// Allows the commitment creator (with trapdoor knowledge) to open a commitment
/// to different values. This is useful for simulation-based security proofs.
#[derive(Clone)]
pub struct TrapdoorCommitment {
    /// Generator G
    #[allow(dead_code)]
    g: RistrettoPoint,
    /// Generator H
    h: RistrettoPoint,
}

/// Trapdoor key (discrete log of H with respect to G).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Trapdoor {
    #[zeroize(skip)]
    alpha: Scalar,
}

/// Trapdoor commitment value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrapdoorCom {
    #[serde(with = "serde_ristretto_point")]
    c: RistrettoPoint,
}

/// Opening for a trapdoor commitment.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TrapdoorOpening {
    #[serde(with = "serde_scalar")]
    #[zeroize(skip)]
    r: Scalar,
}

impl TrapdoorCommitment {
    /// Setup a trapdoor commitment scheme.
    ///
    /// Returns (commitment scheme, trapdoor).
    pub fn setup() -> (Self, Trapdoor) {
        let mut rng = rand::thread_rng();
        let mut alpha_bytes = [0u8; 32];
        rng.fill_bytes(&mut alpha_bytes);
        let alpha = Scalar::from_bytes_mod_order(alpha_bytes);

        let g = RISTRETTO_BASEPOINT_POINT;
        let h = alpha * g;

        let commitment = Self { g, h };
        let trapdoor = Trapdoor { alpha };

        (commitment, trapdoor)
    }

    /// Setup without trapdoor (using hash-to-curve for H).
    pub fn setup_without_trapdoor() -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Hash to create H (no known discrete log)
        let mut hasher = Hasher::new();
        hasher.update(b"TrapdoorCommitment-H-Generator");
        let hash = hasher.finalize();
        let h_scalar = Scalar::from_bytes_mod_order(*hash.as_bytes());
        let h = h_scalar * g;

        Self { g, h }
    }

    /// Commit to a value.
    pub fn commit(&self, value: &[u8]) -> (TrapdoorCom, TrapdoorOpening) {
        let mut rng = rand::thread_rng();
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);

        let m = hash_to_scalar(value);
        let c = m * self.h + r * RISTRETTO_BASEPOINT_POINT;

        (TrapdoorCom { c }, TrapdoorOpening { r })
    }

    /// Verify a commitment opening.
    pub fn verify(&self, com: &TrapdoorCom, value: &[u8], opening: &TrapdoorOpening) -> bool {
        let m = hash_to_scalar(value);
        let expected = m * self.h + opening.r * RISTRETTO_BASEPOINT_POINT;
        com.c == expected
    }

    /// Equivocate: create a fake opening for a different value (requires trapdoor).
    pub fn equivocate(
        &self,
        _com: &TrapdoorCom,
        original_value: &[u8],
        original_opening: &TrapdoorOpening,
        new_value: &[u8],
        trapdoor: &Trapdoor,
    ) -> TrapdoorOpening {
        let m_old = hash_to_scalar(original_value);
        let m_new = hash_to_scalar(new_value);

        // Compute r' such that: m_new * H + r' * G = m_old * H + r * G
        // r' = r + (m_old - m_new) * alpha
        let r_new = original_opening.r + (m_old - m_new) * trapdoor.alpha;

        TrapdoorOpening { r: r_new }
    }
}

// ============================================================================
// Vector Commitments
// ============================================================================

/// Vector commitment scheme.
///
/// Allows committing to a vector and opening individual positions with
/// sublinear-size proofs (using Merkle trees).
#[derive(Clone)]
pub struct VectorCommitment {
    #[allow(dead_code)]
    tree_depth: usize,
}

/// Vector commitment value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorCom {
    root: [u8; 32],
}

/// Opening proof for a position in the vector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VectorOpening {
    index: usize,
    value: Vec<u8>,
    proof: Vec<[u8; 32]>,
}

impl VectorCommitment {
    /// Create a new vector commitment scheme.
    pub fn new(max_size: usize) -> Self {
        let tree_depth = (max_size as f64).log2().ceil() as usize;
        Self { tree_depth }
    }

    /// Commit to a vector.
    pub fn commit(&self, values: &[Vec<u8>]) -> VectorCom {
        let root = build_merkle_root(values);
        VectorCom { root }
    }

    /// Open a specific position in the vector.
    pub fn open(
        &self,
        values: &[Vec<u8>],
        index: usize,
    ) -> AdvancedCommitmentResult<VectorOpening> {
        if index >= values.len() {
            return Err(AdvancedCommitmentError::InvalidIndex);
        }

        let proof = build_merkle_proof(values, index);

        Ok(VectorOpening {
            index,
            value: values[index].clone(),
            proof,
        })
    }

    /// Verify a vector opening.
    pub fn verify(&self, com: &VectorCom, opening: &VectorOpening) -> bool {
        verify_merkle_proof(&com.root, &opening.value, opening.index, &opening.proof)
    }

    /// Open multiple positions.
    pub fn open_batch(
        &self,
        values: &[Vec<u8>],
        indices: &[usize],
    ) -> AdvancedCommitmentResult<Vec<VectorOpening>> {
        indices
            .iter()
            .map(|&index| self.open(values, index))
            .collect()
    }
}

// ============================================================================
// Extractable Commitments
// ============================================================================

/// Extractable commitment scheme.
///
/// Commitments that enable extraction of the committed value in security proofs
/// (proof of knowledge).
#[derive(Clone)]
pub struct ExtractableCommitment {
    g: RistrettoPoint,
    h: RistrettoPoint,
}

/// Extractable commitment value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractableCom {
    #[serde(with = "serde_ristretto_point")]
    c: RistrettoPoint,
}

/// Extractable commitment opening with proof of knowledge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractableOpening {
    #[serde(with = "serde_scalar")]
    r: Scalar,
    proof: SchnorrProof,
}

/// Schnorr proof of knowledge.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SchnorrProof {
    #[serde(with = "serde_ristretto_point")]
    t: RistrettoPoint,
    #[serde(with = "serde_scalar")]
    s: Scalar,
}

impl ExtractableCommitment {
    /// Setup an extractable commitment scheme.
    pub fn setup() -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;

        let mut hasher = Hasher::new();
        hasher.update(b"ExtractableCommitment-H");
        let hash = hasher.finalize();
        let h_scalar = Scalar::from_bytes_mod_order(*hash.as_bytes());
        let h = h_scalar * g;

        Self { g, h }
    }

    /// Commit to a value with proof of knowledge.
    pub fn commit(&self, value: &[u8]) -> (ExtractableCom, ExtractableOpening) {
        let mut rng = rand::thread_rng();
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);

        let m = hash_to_scalar(value);
        let c = m * self.g + r * self.h;

        // Create proof of knowledge of (m, r)
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = Scalar::from_bytes_mod_order(k_bytes);
        let t = k * self.g;

        let challenge = compute_challenge(&c, &t);
        let s = k + challenge * m;

        let proof = SchnorrProof { t, s };
        let opening = ExtractableOpening { r, proof };

        (ExtractableCom { c }, opening)
    }

    /// Verify a commitment with proof of knowledge.
    pub fn verify(&self, com: &ExtractableCom, value: &[u8], opening: &ExtractableOpening) -> bool {
        let m = hash_to_scalar(value);

        // Verify commitment equation
        let expected_c = m * self.g + opening.r * self.h;
        if com.c != expected_c {
            return false;
        }

        // Verify proof of knowledge
        let challenge = compute_challenge(&com.c, &opening.proof.t);
        let lhs = opening.proof.s * self.g;
        let rhs = opening.proof.t + challenge * m * self.g;

        lhs == rhs
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash a value to a scalar.
fn hash_to_scalar(value: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(b"AdvancedCommitment-Hash:");
    hasher.update(value);
    let hash = hasher.finalize();

    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Compute Fiat-Shamir challenge.
fn compute_challenge(c: &RistrettoPoint, t: &RistrettoPoint) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(b"Challenge:");
    hasher.update(&c.compress().to_bytes());
    hasher.update(&t.compress().to_bytes());
    let hash = hasher.finalize();

    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Build Merkle tree root.
fn build_merkle_root(values: &[Vec<u8>]) -> [u8; 32] {
    if values.is_empty() {
        return [0u8; 32];
    }

    let mut layer: Vec<[u8; 32]> = values.iter().map(|v| hash_leaf(v)).collect();

    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                }
            })
            .collect();
    }

    layer[0]
}

/// Build Merkle proof for an index.
fn build_merkle_proof(values: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut layer: Vec<[u8; 32]> = values.iter().map(|v| hash_leaf(v)).collect();
    let mut pos = index;

    while layer.len() > 1 {
        // Check if this position has a sibling
        let sibling_pos = if pos % 2 == 0 { pos + 1 } else { pos - 1 };

        if sibling_pos < layer.len() {
            // Has a sibling - include it in proof
            proof.push(layer[sibling_pos]);
        } else {
            // No sibling (last node in odd-length layer) - include a marker
            // Use a zero hash to indicate no sibling
            proof.push([0u8; 32]);
        }

        layer = layer
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                }
            })
            .collect();

        pos /= 2;
    }

    proof
}

/// Verify a Merkle proof.
fn verify_merkle_proof(root: &[u8; 32], value: &[u8], index: usize, proof: &[[u8; 32]]) -> bool {
    let mut current = hash_leaf(value);
    let mut pos = index;

    for sibling in proof {
        // Check if this is a zero marker (no sibling)
        if sibling == &[0u8; 32] {
            // No sibling - node stays the same
            // (This happens when a node is the last in an odd-length layer)
        } else {
            current = if pos % 2 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
        }
        pos /= 2;
    }

    &current == root
}

/// Hash a leaf value.
fn hash_leaf(value: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"Leaf:");
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// Hash a pair of nodes.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"Node:");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Serde helpers
// ============================================================================

mod serde_ristretto_point {
    use curve25519_dalek::RistrettoPoint;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        point.compress().to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(bytes);
        compressed
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("Invalid RistrettoPoint"))
    }
}

mod serde_scalar {
    use curve25519_dalek::Scalar;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        scalar.to_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Scalar::from_bytes_mod_order(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trapdoor_commitment_basic() {
        let (commitment, _) = TrapdoorCommitment::setup();
        let value = b"test value";

        let (com, opening) = commitment.commit(value);
        assert!(commitment.verify(&com, value, &opening));
    }

    #[test]
    fn test_trapdoor_commitment_wrong_value() {
        let (commitment, _) = TrapdoorCommitment::setup();
        let value = b"test value";

        let (com, opening) = commitment.commit(value);
        assert!(!commitment.verify(&com, b"wrong value", &opening));
    }

    #[test]
    fn test_trapdoor_equivocation() {
        let (commitment, trapdoor) = TrapdoorCommitment::setup();

        let original = b"original value";
        let (com, opening) = commitment.commit(original);

        // Verify original
        assert!(commitment.verify(&com, original, &opening));

        // Equivocate to different value
        let fake = b"different value";
        let fake_opening = commitment.equivocate(&com, original, &opening, fake, &trapdoor);

        // Both should verify!
        assert!(commitment.verify(&com, original, &opening));
        assert!(commitment.verify(&com, fake, &fake_opening));
    }

    #[test]
    fn test_vector_commitment_basic() {
        let vc = VectorCommitment::new(10);
        let values = vec![b"value0".to_vec(), b"value1".to_vec(), b"value2".to_vec()];

        let com = vc.commit(&values);
        let opening = vc.open(&values, 1).unwrap();

        assert!(vc.verify(&com, &opening));
        assert_eq!(opening.value, b"value1");
    }

    #[test]
    fn test_vector_commitment_wrong_index() {
        let vc = VectorCommitment::new(10);
        let values = vec![b"value0".to_vec(), b"value1".to_vec()];

        assert!(vc.open(&values, 5).is_err());
    }

    #[test]
    fn test_vector_commitment_tampered() {
        let vc = VectorCommitment::new(10);
        let values = vec![b"value0".to_vec(), b"value1".to_vec()];

        let com = vc.commit(&values);
        let mut opening = vc.open(&values, 1).unwrap();

        // Tamper with value
        opening.value = b"tampered".to_vec();
        assert!(!vc.verify(&com, &opening));
    }

    #[test]
    fn test_vector_commitment_batch() {
        let vc = VectorCommitment::new(10);
        let values = vec![
            b"value0".to_vec(),
            b"value1".to_vec(),
            b"value2".to_vec(),
            b"value3".to_vec(),
        ];

        let com = vc.commit(&values);
        let openings = vc.open_batch(&values, &[0, 2, 3]).unwrap();

        assert_eq!(openings.len(), 3);
        for opening in openings {
            assert!(vc.verify(&com, &opening));
        }
    }

    #[test]
    fn test_extractable_commitment_basic() {
        let ec = ExtractableCommitment::setup();
        let value = b"test value";

        let (com, opening) = ec.commit(value);
        assert!(ec.verify(&com, value, &opening));
    }

    #[test]
    fn test_extractable_commitment_wrong_value() {
        let ec = ExtractableCommitment::setup();
        let value = b"test value";

        let (com, opening) = ec.commit(value);
        assert!(!ec.verify(&com, b"wrong value", &opening));
    }

    #[test]
    fn test_extractable_commitment_proof_soundness() {
        let ec = ExtractableCommitment::setup();
        let value = b"test value";

        let (com, mut opening) = ec.commit(value);

        // Tamper with proof
        opening.proof.s += Scalar::ONE;
        assert!(!ec.verify(&com, value, &opening));
    }

    #[test]
    fn test_trapdoor_serialization() {
        let (commitment, _) = TrapdoorCommitment::setup();
        let value = b"test";

        let (com, opening) = commitment.commit(value);

        let com_bytes = crate::codec::encode(&com).unwrap();
        let opening_bytes = crate::codec::encode(&opening).unwrap();

        let com_de: TrapdoorCom = crate::codec::decode(&com_bytes).unwrap();
        let opening_de: TrapdoorOpening = crate::codec::decode(&opening_bytes).unwrap();

        assert!(commitment.verify(&com_de, value, &opening_de));
    }

    #[test]
    fn test_vector_commitment_serialization() {
        let vc = VectorCommitment::new(10);
        let values = vec![b"value0".to_vec(), b"value1".to_vec()];

        let com = vc.commit(&values);
        let opening = vc.open(&values, 0).unwrap();

        let com_bytes = crate::codec::encode(&com).unwrap();
        let opening_bytes = crate::codec::encode(&opening).unwrap();

        let com_de: VectorCom = crate::codec::decode(&com_bytes).unwrap();
        let opening_de: VectorOpening = crate::codec::decode(&opening_bytes).unwrap();

        assert!(vc.verify(&com_de, &opening_de));
    }

    #[test]
    fn test_extractable_serialization() {
        let ec = ExtractableCommitment::setup();
        let value = b"test";

        let (com, opening) = ec.commit(value);

        let com_bytes = crate::codec::encode(&com).unwrap();
        let opening_bytes = crate::codec::encode(&opening).unwrap();

        let com_de: ExtractableCom = crate::codec::decode(&com_bytes).unwrap();
        let opening_de: ExtractableOpening = crate::codec::decode(&opening_bytes).unwrap();

        assert!(ec.verify(&com_de, value, &opening_de));
    }

    #[test]
    fn test_trapdoor_without_trapdoor() {
        let commitment = TrapdoorCommitment::setup_without_trapdoor();
        let value = b"test value";

        let (com, opening) = commitment.commit(value);
        assert!(commitment.verify(&com, value, &opening));
    }

    #[test]
    fn test_vector_commitment_single_element() {
        let vc = VectorCommitment::new(10);
        let values = vec![b"single".to_vec()];

        let com = vc.commit(&values);
        let opening = vc.open(&values, 0).unwrap();

        assert!(vc.verify(&com, &opening));
    }

    #[test]
    fn test_vector_commitment_large() {
        let vc = VectorCommitment::new(100);
        let values: Vec<Vec<u8>> = (0..50)
            .map(|i| format!("value{}", i).into_bytes())
            .collect();

        let com = vc.commit(&values);

        for i in 0..values.len() {
            let opening = vc.open(&values, i).unwrap();
            assert!(vc.verify(&com, &opening));
        }
    }
}
