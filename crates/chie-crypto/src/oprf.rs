//! Oblivious Pseudorandom Function (OPRF) implementation.
//!
//! OPRF allows a client to compute PRF(key, input) where:
//! - Server holds the secret key
//! - Client provides the input
//! - Server learns nothing about the input
//! - Client learns only PRF(key, input), not the key
//!
//! Perfect for:
//! - Private rate limiting (check if user exceeded quota without revealing identity)
//! - Password-authenticated key exchange
//! - Anonymous credentials
//! - Privacy-preserving set membership tests
//!
//! # Example
//! ```
//! use chie_crypto::oprf::{OprfServer, OprfClient};
//!
//! // Server setup
//! let server = OprfServer::new();
//!
//! // Client blind request
//! let input = b"user@example.com";
//! let (client, blinded_input) = OprfClient::blind(input);
//!
//! // Server evaluates on blinded input
//! let blinded_output = server.evaluate(&blinded_input);
//!
//! // Client unblinds to get PRF output
//! let prf_output = client.unblind(&blinded_output);
//!
//! // Can verify this matches direct evaluation (for testing)
//! assert_eq!(prf_output, server.evaluate_direct(input));
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

/// OPRF error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OprfError {
    /// Invalid blinded input
    InvalidBlindedInput,
    /// Invalid blinded output
    InvalidBlindedOutput,
    /// Serialization error
    SerializationError,
}

impl std::fmt::Display for OprfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlindedInput => write!(f, "Invalid blinded input"),
            Self::InvalidBlindedOutput => write!(f, "Invalid blinded output"),
            Self::SerializationError => write!(f, "Serialization error"),
        }
    }
}

impl std::error::Error for OprfError {}

pub type OprfResult<T> = Result<T, OprfError>;

/// OPRF server holding the secret key.
#[derive(Clone)]
pub struct OprfServer {
    /// Secret key for the PRF
    secret_key: Scalar,
}

/// Blinded input sent from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedInput {
    point: CompressedRistretto,
}

/// Blinded output sent from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedOutput {
    point: CompressedRistretto,
}

/// PRF output after unblinding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OprfOutput {
    value: [u8; 32],
}

/// OPRF client state during the protocol.
pub struct OprfClient {
    /// Blinding factor (kept secret)
    blind: Scalar,
    /// Original input (for verification)
    input: Vec<u8>,
}

impl OprfServer {
    /// Create a new OPRF server with random secret key.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let secret_key = Scalar::from_bytes_mod_order(bytes);
        Self { secret_key }
    }

    /// Create OPRF server from existing secret key.
    pub fn from_key(secret_key: Scalar) -> Self {
        Self { secret_key }
    }

    /// Evaluate the OPRF on a blinded input.
    ///
    /// Returns blinded output that client can unblind.
    pub fn evaluate(&self, blinded_input: &BlindedInput) -> BlindedOutput {
        let point = blinded_input.point.decompress().unwrap_or_default();
        let blinded_output_point = point * self.secret_key;
        BlindedOutput {
            point: blinded_output_point.compress(),
        }
    }

    /// Evaluate OPRF directly on input (for testing/verification).
    ///
    /// In real protocol, server never sees the actual input.
    pub fn evaluate_direct(&self, input: &[u8]) -> OprfOutput {
        // Hash input to point
        let point = hash_to_point(input);
        // Apply secret key
        let output_point = point * self.secret_key;
        // Hash to final output
        OprfOutput {
            value: blake3::hash(output_point.compress().as_bytes()).into(),
        }
    }

    /// Batch evaluate multiple blinded inputs.
    pub fn batch_evaluate(&self, inputs: &[BlindedInput]) -> Vec<BlindedOutput> {
        inputs.iter().map(|input| self.evaluate(input)).collect()
    }

    /// Get the server's public key (for verification protocols).
    pub fn public_key(&self) -> CompressedRistretto {
        (&self.secret_key * RISTRETTO_BASEPOINT_TABLE).compress()
    }

    /// Serialize server secret key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    /// Deserialize server secret key.
    pub fn from_bytes(bytes: &[u8; 32]) -> OprfResult<Self> {
        let scalar = Scalar::from_canonical_bytes(*bytes)
            .into_option()
            .ok_or(OprfError::SerializationError)?;
        Ok(Self::from_key(scalar))
    }
}

impl Default for OprfServer {
    fn default() -> Self {
        Self::new()
    }
}

impl OprfClient {
    /// Blind an input to send to the server.
    ///
    /// Returns (client state, blinded input to send to server).
    pub fn blind(input: &[u8]) -> (Self, BlindedInput) {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let blind = Scalar::from_bytes_mod_order(bytes);

        // Hash input to point
        let point = hash_to_point(input);

        // Blind the point
        let blinded_point = point * blind;

        let client = Self {
            blind,
            input: input.to_vec(),
        };

        let blinded_input = BlindedInput {
            point: blinded_point.compress(),
        };

        (client, blinded_input)
    }

    /// Unblind the server's response to get the final PRF output.
    pub fn unblind(&self, blinded_output: &BlindedOutput) -> OprfOutput {
        let point = blinded_output.point.decompress().unwrap_or_default();

        // Unblind by multiplying by blind^(-1)
        let blind_inv = self.blind.invert();
        let output_point = point * blind_inv;

        // Hash to final output
        OprfOutput {
            value: blake3::hash(output_point.compress().as_bytes()).into(),
        }
    }

    /// Get the original input (for debugging).
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

impl BlindedInput {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> OprfResult<Self> {
        Ok(Self {
            point: CompressedRistretto(*bytes),
        })
    }
}

impl BlindedOutput {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> OprfResult<Self> {
        Ok(Self {
            point: CompressedRistretto(*bytes),
        })
    }
}

impl OprfOutput {
    /// Get output as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.value
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { value: bytes }
    }
}

/// Hash arbitrary input to a Ristretto point.
fn hash_to_point(input: &[u8]) -> RistrettoPoint {
    // Hash input using SHA-512 and convert to scalar
    let scalar = Scalar::hash_from_bytes::<Sha512>(input);
    // Multiply base point to get deterministic point
    &scalar * RISTRETTO_BASEPOINT_TABLE
}

/// Batch OPRF client for multiple inputs.
pub struct BatchOprfClient {
    clients: Vec<OprfClient>,
}

impl BatchOprfClient {
    /// Blind multiple inputs at once.
    pub fn blind_batch(inputs: &[&[u8]]) -> (Self, Vec<BlindedInput>) {
        let mut clients = Vec::with_capacity(inputs.len());
        let mut blinded_inputs = Vec::with_capacity(inputs.len());

        for input in inputs {
            let (client, blinded_input) = OprfClient::blind(input);
            clients.push(client);
            blinded_inputs.push(blinded_input);
        }

        (Self { clients }, blinded_inputs)
    }

    /// Unblind multiple outputs.
    pub fn unblind_batch(&self, blinded_outputs: &[BlindedOutput]) -> Vec<OprfOutput> {
        self.clients
            .iter()
            .zip(blinded_outputs.iter())
            .map(|(client, output)| client.unblind(output))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_basic() {
        let server = OprfServer::new();
        let input = b"test-input";

        let (client, blinded_input) = OprfClient::blind(input);
        let blinded_output = server.evaluate(&blinded_input);
        let output = client.unblind(&blinded_output);

        // Verify output matches direct evaluation
        let direct_output = server.evaluate_direct(input);
        assert_eq!(output, direct_output);
    }

    #[test]
    fn test_oprf_deterministic() {
        let server = OprfServer::new();
        let input = b"deterministic-test";

        // Multiple evaluations should give same result
        let (client1, blinded1) = OprfClient::blind(input);
        let output1 = client1.unblind(&server.evaluate(&blinded1));

        let (client2, blinded2) = OprfClient::blind(input);
        let output2 = client2.unblind(&server.evaluate(&blinded2));

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_oprf_different_inputs() {
        let server = OprfServer::new();

        let (client1, blinded1) = OprfClient::blind(b"input1");
        let output1 = client1.unblind(&server.evaluate(&blinded1));

        let (client2, blinded2) = OprfClient::blind(b"input2");
        let output2 = client2.unblind(&server.evaluate(&blinded2));

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_oprf_different_servers() {
        let server1 = OprfServer::new();
        let server2 = OprfServer::new();
        let input = b"test";

        let (client1, blinded1) = OprfClient::blind(input);
        let output1 = client1.unblind(&server1.evaluate(&blinded1));

        let (client2, blinded2) = OprfClient::blind(input);
        let output2 = client2.unblind(&server2.evaluate(&blinded2));

        // Different servers should give different outputs
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_oprf_serialization() {
        let server = OprfServer::new();
        let bytes = server.to_bytes();
        let server2 = OprfServer::from_bytes(&bytes).unwrap();

        let input = b"serialize-test";
        let output1 = server.evaluate_direct(input);
        let output2 = server2.evaluate_direct(input);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_blinded_input_serialization() {
        let (_client, blinded) = OprfClient::blind(b"test");
        let bytes = blinded.to_bytes();
        let blinded2 = BlindedInput::from_bytes(&bytes).unwrap();

        assert_eq!(blinded.point, blinded2.point);
    }

    #[test]
    fn test_blinded_output_serialization() {
        let server = OprfServer::new();
        let (_client, blinded_input) = OprfClient::blind(b"test");
        let blinded_output = server.evaluate(&blinded_input);

        let bytes = blinded_output.to_bytes();
        let blinded_output2 = BlindedOutput::from_bytes(&bytes).unwrap();

        assert_eq!(blinded_output.point, blinded_output2.point);
    }

    #[test]
    fn test_batch_oprf() {
        let server = OprfServer::new();
        let inputs = vec![b"input1".as_ref(), b"input2".as_ref(), b"input3".as_ref()];

        let (batch_client, blinded_inputs) = BatchOprfClient::blind_batch(&inputs);
        let blinded_outputs = server.batch_evaluate(&blinded_inputs);
        let outputs = batch_client.unblind_batch(&blinded_outputs);

        // Verify each output matches direct evaluation
        for (input, output) in inputs.iter().zip(outputs.iter()) {
            let direct = server.evaluate_direct(input);
            assert_eq!(*output, direct);
        }
    }

    #[test]
    fn test_batch_oprf_different_outputs() {
        let server = OprfServer::new();
        let inputs = vec![b"a".as_ref(), b"b".as_ref(), b"c".as_ref()];

        let (batch_client, blinded_inputs) = BatchOprfClient::blind_batch(&inputs);
        let blinded_outputs = server.batch_evaluate(&blinded_inputs);
        let outputs = batch_client.unblind_batch(&blinded_outputs);

        // All outputs should be different
        assert_ne!(outputs[0], outputs[1]);
        assert_ne!(outputs[1], outputs[2]);
        assert_ne!(outputs[0], outputs[2]);
    }

    #[test]
    fn test_oprf_public_key() {
        let server = OprfServer::new();
        let pk = server.public_key();

        // Public key should be valid compressed point
        assert!(pk.decompress().is_some());
    }

    #[test]
    fn test_oprf_empty_input() {
        let server = OprfServer::new();
        let input = b"";

        let (client, blinded_input) = OprfClient::blind(input);
        let blinded_output = server.evaluate(&blinded_input);
        let output = client.unblind(&blinded_output);

        let direct = server.evaluate_direct(input);
        assert_eq!(output, direct);
    }

    #[test]
    fn test_oprf_large_input() {
        let server = OprfServer::new();
        let input = vec![0xAB; 10000]; // 10KB input

        let (client, blinded_input) = OprfClient::blind(&input);
        let blinded_output = server.evaluate(&blinded_input);
        let output = client.unblind(&blinded_output);

        let direct = server.evaluate_direct(&input);
        assert_eq!(output, direct);
    }

    #[test]
    fn test_oprf_output_uniqueness() {
        let server = OprfServer::new();
        let mut outputs = std::collections::HashSet::new();

        // Generate many outputs
        for i in 0..100 {
            let input = format!("input-{}", i);
            let (client, blinded) = OprfClient::blind(input.as_bytes());
            let output = client.unblind(&server.evaluate(&blinded));
            outputs.insert(output.value);
        }

        // All should be unique
        assert_eq!(outputs.len(), 100);
    }
}
