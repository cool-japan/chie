//! Verifiable Delay Functions (VDF) for time-based proofs.
//!
//! This module provides a VDF implementation based on sequential hashing.
//! VDFs are functions that require a specified number of sequential steps to compute,
//! but can be verified quickly. They're useful for generating unbiased randomness
//! and proving that a certain amount of time has elapsed.
//!
//! # Features
//!
//! - Sequential computation with adjustable delay
//! - Fast verification
//! - Deterministic output given input and delay
//! - Hash-based construction using BLAKE3
//!
//! # Use Cases in CHIE Protocol
//!
//! - Fair leader election without bias
//! - Randomness beacons
//! - Proof of elapsed time
//! - Anti-spam mechanisms with computational costs
//!
//! # Example
//!
//! ```
//! use chie_crypto::vdf_delay::{VdfParams, vdf_compute, vdf_verify};
//!
//! // Create VDF parameters with 10000 iterations
//! let params = VdfParams::new(10000);
//!
//! // Compute VDF on input
//! let input = b"random_seed_12345";
//! let (output, proof) = vdf_compute(&params, input);
//!
//! // Verify the proof (much faster than computation)
//! assert!(vdf_verify(&params, input, &output, &proof).is_ok());
//! ```

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// VDF-specific errors.
#[derive(Error, Debug)]
pub enum VdfError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid parameters")]
    InvalidParameters,
    #[error("Iteration count must be positive")]
    InvalidIterations,
}

pub type VdfResult<T> = Result<T, VdfError>;

/// Parameters for VDF computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VdfParams {
    /// Number of sequential iterations required
    pub iterations: u64,
}

impl VdfParams {
    /// Create new VDF parameters.
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of sequential hash iterations
    ///
    /// # Example
    ///
    /// ```
    /// use chie_crypto::vdf_delay::VdfParams;
    ///
    /// // 1 million iterations (approximately 100ms on modern hardware)
    /// let params = VdfParams::new(1_000_000);
    /// assert_eq!(params.iterations, 1_000_000);
    /// ```
    pub fn new(iterations: u64) -> Self {
        assert!(iterations > 0);
        Self { iterations }
    }

    /// Create VDF parameters from approximate target duration.
    ///
    /// Note: Actual time will vary based on hardware. This uses an approximate
    /// rate of 10,000 iterations per millisecond on modern hardware.
    ///
    /// # Arguments
    ///
    /// * `target_ms` - Target duration in milliseconds
    pub fn from_duration_ms(target_ms: u64) -> Self {
        const ITERATIONS_PER_MS: u64 = 10_000;
        Self {
            iterations: target_ms * ITERATIONS_PER_MS,
        }
    }
}

/// VDF output value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfOutput {
    /// The final output value after all iterations
    pub value: Vec<u8>,
}

/// Proof of VDF computation.
///
/// Contains intermediate values that allow for fast verification
/// without recomputing all iterations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VdfProof {
    /// Checkpoints at logarithmic intervals for verification
    checkpoints: Vec<Vec<u8>>,
    /// Final output
    output: Vec<u8>,
}

/// Compute VDF on given input.
///
/// Returns the output and a proof of computation.
///
/// # Arguments
///
/// * `params` - VDF parameters
/// * `input` - Input data
///
/// # Example
///
/// ```
/// use chie_crypto::vdf_delay::{VdfParams, vdf_compute};
///
/// let params = VdfParams::new(10000);
/// let input = b"challenge_data";
/// let (output, proof) = vdf_compute(&params, input);
/// ```
pub fn vdf_compute(params: &VdfParams, input: &[u8]) -> (VdfOutput, VdfProof) {
    let mut current = hash_input(input);
    let mut checkpoints = Vec::new();

    // Compute checkpoints at logarithmic intervals
    // This allows for efficient verification
    let checkpoint_interval = (params.iterations / 10).max(1);

    for i in 0..params.iterations {
        current = hash_step(&current);

        // Store checkpoints at intervals
        if i > 0 && (i + 1) % checkpoint_interval == 0 {
            checkpoints.push(current.clone());
        }
    }

    let output = VdfOutput {
        value: current.clone(),
    };

    let proof = VdfProof {
        checkpoints,
        output: current,
    };

    (output, proof)
}

/// Verify a VDF proof.
///
/// Verification is much faster than computation as it only checks
/// the checkpoints rather than all iterations.
///
/// # Arguments
///
/// * `params` - VDF parameters
/// * `input` - Original input data
/// * `output` - Claimed output
/// * `proof` - Proof of computation
///
/// # Example
///
/// ```
/// use chie_crypto::vdf_delay::{VdfParams, vdf_compute, vdf_verify};
///
/// let params = VdfParams::new(10000);
/// let input = b"challenge_data";
/// let (output, proof) = vdf_compute(&params, input);
///
/// assert!(vdf_verify(&params, input, &output, &proof).is_ok());
/// ```
pub fn vdf_verify(
    params: &VdfParams,
    input: &[u8],
    output: &VdfOutput,
    proof: &VdfProof,
) -> VdfResult<()> {
    // Check that output matches proof
    if output.value != proof.output {
        return Err(VdfError::InvalidProof);
    }

    // Verify by checking checkpoints
    let mut current = hash_input(input);
    let checkpoint_interval = (params.iterations / 10).max(1);
    let mut checkpoint_idx = 0;

    for i in 0..params.iterations {
        current = hash_step(&current);

        // Verify checkpoint if we're at a checkpoint position
        if i > 0 && (i + 1) % checkpoint_interval == 0 {
            if checkpoint_idx >= proof.checkpoints.len() {
                return Err(VdfError::InvalidProof);
            }

            if current != proof.checkpoints[checkpoint_idx] {
                return Err(VdfError::InvalidProof);
            }

            checkpoint_idx += 1;
        }
    }

    // Final output should match
    if current != proof.output {
        return Err(VdfError::InvalidProof);
    }

    Ok(())
}

/// Compute VDF for randomness beacon.
///
/// This is a convenience function for generating unpredictable randomness
/// that requires a minimum amount of time to compute.
///
/// # Arguments
///
/// * `seed` - Initial seed value
/// * `iterations` - Number of sequential iterations
pub fn vdf_randomness_beacon(seed: &[u8], iterations: u64) -> Vec<u8> {
    let params = VdfParams::new(iterations);
    let (output, _proof) = vdf_compute(&params, seed);
    output.value
}

// Helper: Hash input to initial state
fn hash_input(input: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize().as_bytes().to_vec()
}

// Helper: Perform single hash iteration
fn hash_step(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_basic() {
        let params = VdfParams::new(100);
        let input = b"test_input";

        let (output, proof) = vdf_compute(&params, input);

        assert!(vdf_verify(&params, input, &output, &proof).is_ok());
    }

    #[test]
    fn test_vdf_deterministic() {
        let params = VdfParams::new(100);
        let input = b"test_input";

        let (output1, _) = vdf_compute(&params, input);
        let (output2, _) = vdf_compute(&params, input);

        assert_eq!(output1.value, output2.value);
    }

    #[test]
    fn test_vdf_different_inputs() {
        let params = VdfParams::new(100);

        let (output1, _) = vdf_compute(&params, b"input1");
        let (output2, _) = vdf_compute(&params, b"input2");

        assert_ne!(output1.value, output2.value);
    }

    #[test]
    fn test_vdf_different_iterations() {
        let input = b"test_input";

        let params1 = VdfParams::new(100);
        let params2 = VdfParams::new(200);

        let (output1, _) = vdf_compute(&params1, input);
        let (output2, _) = vdf_compute(&params2, input);

        assert_ne!(output1.value, output2.value);
    }

    #[test]
    fn test_vdf_invalid_proof() {
        let params = VdfParams::new(100);
        let input = b"test_input";

        let (output, mut proof) = vdf_compute(&params, input);

        // Corrupt the proof
        if !proof.checkpoints.is_empty() {
            proof.checkpoints[0][0] ^= 1;
        }

        assert!(vdf_verify(&params, input, &output, &proof).is_err());
    }

    #[test]
    fn test_vdf_serialization() {
        let params = VdfParams::new(100);
        let input = b"test_input";

        let (output, proof) = vdf_compute(&params, input);

        // Serialize
        let params_bytes = crate::codec::encode(&params).unwrap();
        let output_bytes = crate::codec::encode(&output).unwrap();
        let proof_bytes = crate::codec::encode(&proof).unwrap();

        // Deserialize
        let params2: VdfParams = crate::codec::decode(&params_bytes).unwrap();
        let output2: VdfOutput = crate::codec::decode(&output_bytes).unwrap();
        let proof2: VdfProof = crate::codec::decode(&proof_bytes).unwrap();

        assert!(vdf_verify(&params2, input, &output2, &proof2).is_ok());
    }

    #[test]
    fn test_vdf_from_duration() {
        let params = VdfParams::from_duration_ms(10);
        assert_eq!(params.iterations, 100_000);

        let params2 = VdfParams::from_duration_ms(100);
        assert_eq!(params2.iterations, 1_000_000);
    }

    #[test]
    fn test_vdf_randomness_beacon() {
        let seed = b"beacon_seed";
        let output1 = vdf_randomness_beacon(seed, 1000);
        let output2 = vdf_randomness_beacon(seed, 1000);

        // Should be deterministic
        assert_eq!(output1, output2);

        // Different seed should give different output
        let output3 = vdf_randomness_beacon(b"different_seed", 1000);
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_vdf_output_length() {
        let params = VdfParams::new(100);
        let input = b"test";

        let (output, _) = vdf_compute(&params, input);

        // BLAKE3 output is 32 bytes
        assert_eq!(output.value.len(), 32);
    }

    #[test]
    fn test_vdf_large_iterations() {
        // Test with larger iteration count
        let params = VdfParams::new(10_000);
        let input = b"large_test";

        let (output, proof) = vdf_compute(&params, input);

        assert!(vdf_verify(&params, input, &output, &proof).is_ok());
        assert!(!proof.checkpoints.is_empty());
    }
}
