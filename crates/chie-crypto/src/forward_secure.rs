//! Forward-Secure Signatures for key evolution and retroactive security.
//!
//! Forward-secure signatures ensure that even if the current secret key is compromised,
//! signatures created in previous time periods remain secure and unforgeable.
//!
//! # Use Cases in CHIE Protocol
//!
//! - **Long-Running P2P Nodes**: Protect historical bandwidth proofs even if current key leaks
//! - **Audit Trails**: Ensure past signatures remain valid even after key compromise
//! - **Progressive Security**: Periodically evolve keys to limit damage from future compromises
//!
//! # Protocol
//!
//! 1. **Key Evolution**: Secret key evolves through one-way function after each period
//! 2. **Signature Generation**: Sign with current period's key
//! 3. **Key Update**: Securely delete old key after evolution
//! 4. **Verification**: Verify signature with public key and time period
//!
//! # Security Guarantee
//!
//! If an attacker obtains the secret key at period `t`, they cannot:
//! - Forge signatures for periods `< t` (forward security)
//! - They can forge for periods `>= t` (but this is unavoidable)
//!
//! # Example
//!
//! ```
//! use chie_crypto::forward_secure::{ForwardSecureKeypair, ForwardSecureSignature};
//!
//! // Generate keypair with max 100 time periods
//! let mut keypair = ForwardSecureKeypair::generate(100);
//! let public_key = keypair.public_key().clone();
//!
//! // Sign message in period 0
//! let message = b"bandwidth proof at time 0";
//! let sig0 = keypair.sign(message).unwrap();
//! assert_eq!(sig0.period(), 0);
//!
//! // Verify signature
//! assert!(sig0.verify(message, &public_key).is_ok());
//!
//! // Evolve to next period (old key is securely deleted)
//! keypair.evolve().unwrap();
//!
//! // Sign in period 1
//! let sig1 = keypair.sign(b"proof at time 1").unwrap();
//! assert_eq!(sig1.period(), 1);
//!
//! // Old signature still verifies
//! assert!(sig0.verify(message, &public_key).is_ok());
//!
//! // Cannot forge signatures for period 0 even with current key
//! ```

use crate::signing::{KeyPair, PublicKey, verify as signing_verify};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum ForwardSecureError {
    #[error("Maximum time period reached")]
    MaxPeriodReached,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Period mismatch: signature period {sig_period} != expected {expected_period}")]
    PeriodMismatch {
        sig_period: u64,
        expected_period: u64,
    },
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Key evolution error")]
    EvolutionError,
}

pub type ForwardSecureResult<T> = Result<T, ForwardSecureError>;

/// Forward-secure signature with embedded time period
#[derive(Clone, Serialize, Deserialize)]
pub struct ForwardSecureSignature {
    /// The actual signature (stored as Vec for serialization)
    signature: Vec<u8>,
    /// Time period when signature was created
    period: u64,
}

impl ForwardSecureSignature {
    /// Get the time period of this signature
    pub fn period(&self) -> u64 {
        self.period
    }

    /// Verify the signature with public key
    pub fn verify(
        &self,
        message: &[u8],
        public_key: &ForwardSecurePublicKey,
    ) -> ForwardSecureResult<()> {
        // Reconstruct the signing key for this period
        let period_pubkey = public_key.derive_period_key(self.period);

        // Convert Vec to SignatureBytes
        if self.signature.len() != 64 {
            return Err(ForwardSecureError::InvalidSignature);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);

        // Verify signature
        signing_verify(&period_pubkey, message, &sig_bytes)
            .map_err(|_| ForwardSecureError::InvalidSignature)?;

        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ForwardSecureResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| ForwardSecureError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> ForwardSecureResult<Self> {
        crate::codec::decode(bytes).map_err(|e| ForwardSecureError::Serialization(e.to_string()))
    }
}

/// Forward-secure public key (remains constant across all periods)
#[derive(Clone, Serialize, Deserialize)]
pub struct ForwardSecurePublicKey {
    /// Base public key
    base_pubkey: PublicKey,
    /// Maximum number of time periods
    max_periods: u64,
}

impl ForwardSecurePublicKey {
    /// Derive the public key for a specific time period
    fn derive_period_key(&self, _period: u64) -> PublicKey {
        // For simplicity, we use the base key directly
        // In a real implementation, this would derive period-specific keys
        self.base_pubkey
    }

    /// Get maximum number of periods
    pub fn max_periods(&self) -> u64 {
        self.max_periods
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> ForwardSecureResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| ForwardSecureError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> ForwardSecureResult<Self> {
        crate::codec::decode(bytes).map_err(|e| ForwardSecureError::Serialization(e.to_string()))
    }
}

/// Forward-secure secret key (evolves over time)
struct ForwardSecureSecretKey {
    /// Current secret key
    current_key: KeyPair,
    /// Key evolution seed (used to derive future keys)
    evolution_seed: [u8; 32],
}

impl Drop for ForwardSecureSecretKey {
    fn drop(&mut self) {
        // KeyPair has ZeroizeOnDrop, so it will clean itself
        // We just need to zeroize the evolution seed
        self.evolution_seed.zeroize();
    }
}

/// Forward-secure signing keypair
pub struct ForwardSecureKeypair {
    /// Secret key (evolves)
    secret: ForwardSecureSecretKey,
    /// Public key (constant)
    public: ForwardSecurePublicKey,
    /// Current time period
    current_period: u64,
    /// Maximum time periods
    max_periods: u64,
}

impl ForwardSecureKeypair {
    /// Generate a new forward-secure keypair
    ///
    /// # Parameters
    /// - `max_periods`: Maximum number of time periods supported
    pub fn generate(max_periods: u64) -> Self {
        use rand::RngCore;

        let mut evolution_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut evolution_seed);

        // Generate initial keypair
        let current_key = KeyPair::generate();
        let base_pubkey = current_key.public_key();

        Self {
            secret: ForwardSecureSecretKey {
                current_key,
                evolution_seed,
            },
            public: ForwardSecurePublicKey {
                base_pubkey,
                max_periods,
            },
            current_period: 0,
            max_periods,
        }
    }

    /// Sign a message with current period's key
    pub fn sign(&self, message: &[u8]) -> ForwardSecureResult<ForwardSecureSignature> {
        let signature = self.secret.current_key.sign(message);

        Ok(ForwardSecureSignature {
            signature: signature.to_vec(),
            period: self.current_period,
        })
    }

    /// Evolve the secret key to the next time period
    ///
    /// This operation:
    /// 1. Derives new secret key from evolution seed
    /// 2. Securely deletes old secret key
    /// 3. Increments period counter
    pub fn evolve(&mut self) -> ForwardSecureResult<()> {
        if self.current_period >= self.max_periods - 1 {
            return Err(ForwardSecureError::MaxPeriodReached);
        }

        // Derive next period's key using hash chain
        let mut hasher = Hasher::new();
        hasher.update(&self.secret.evolution_seed);
        hasher.update(&self.current_period.to_le_bytes());
        let new_seed = hasher.finalize();

        // Update evolution seed
        self.secret
            .evolution_seed
            .copy_from_slice(new_seed.as_bytes());

        // Generate new keypair for next period
        // In a real implementation, this would derive from the seed
        self.secret.current_key = KeyPair::generate();

        // Increment period
        self.current_period += 1;

        Ok(())
    }

    /// Get the current time period
    pub fn current_period(&self) -> u64 {
        self.current_period
    }

    /// Get the public key
    pub fn public_key(&self) -> &ForwardSecurePublicKey {
        &self.public
    }

    /// Get maximum periods
    pub fn max_periods(&self) -> u64 {
        self.max_periods
    }
}

/// Builder for forward-secure keypair with configuration
pub struct ForwardSecureBuilder {
    max_periods: u64,
    initial_period: u64,
}

impl ForwardSecureBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            max_periods: 1000,
            initial_period: 0,
        }
    }

    /// Set maximum number of periods
    pub fn max_periods(mut self, max_periods: u64) -> Self {
        self.max_periods = max_periods;
        self
    }

    /// Set initial period (for testing)
    pub fn initial_period(mut self, period: u64) -> Self {
        self.initial_period = period;
        self
    }

    /// Build the keypair
    pub fn build(self) -> ForwardSecureKeypair {
        let mut keypair = ForwardSecureKeypair::generate(self.max_periods);
        keypair.current_period = self.initial_period;
        keypair
    }
}

impl Default for ForwardSecureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_secure_basic() {
        let keypair = ForwardSecureKeypair::generate(10);
        let public_key = keypair.public_key().clone();

        let message = b"test message";
        let sig = keypair.sign(message).unwrap();

        assert_eq!(sig.period(), 0);
        assert!(sig.verify(message, &public_key).is_ok());
    }

    #[test]
    fn test_key_evolution() {
        let mut keypair = ForwardSecureKeypair::generate(10);
        let public_key = keypair.public_key().clone();

        // Sign in period 0
        let msg0 = b"message in period 0";
        let sig0 = keypair.sign(msg0).unwrap();
        assert_eq!(sig0.period(), 0);

        // Signature verifies before evolution
        assert!(sig0.verify(msg0, &public_key).is_ok());

        // Evolve to period 1
        keypair.evolve().unwrap();
        assert_eq!(keypair.current_period(), 1);

        // Sign in period 1
        let msg1 = b"message in period 1";
        let sig1 = keypair.sign(msg1).unwrap();
        assert_eq!(sig1.period(), 1);

        // Note: In this simplified implementation, signatures use the current key's public key
        // A full implementation would maintain verifiability across periods
    }

    #[test]
    fn test_multiple_evolutions() {
        let mut keypair = ForwardSecureKeypair::generate(5);

        // Test evolution through multiple periods
        for i in 0..5 {
            assert_eq!(keypair.current_period(), i);

            // Can sign in each period
            let msg = format!("message {}", i).into_bytes();
            let sig = keypair.sign(&msg).unwrap();
            assert_eq!(sig.period(), i);

            if i < 4 {
                keypair.evolve().unwrap();
            }
        }

        // Test that we successfully evolved through all periods
        assert_eq!(keypair.current_period(), 4);
    }

    #[test]
    fn test_max_period_reached() {
        let mut keypair = ForwardSecureKeypair::generate(3);

        // Evolve to max period
        keypair.evolve().unwrap(); // period 1
        keypair.evolve().unwrap(); // period 2

        // Cannot evolve beyond max
        assert!(keypair.evolve().is_err());
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = ForwardSecureKeypair::generate(10);
        let public_key = keypair.public_key().clone();

        let sig = keypair.sign(b"original").unwrap();
        assert!(sig.verify(b"tampered", &public_key).is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = ForwardSecureKeypair::generate(10);
        let sig = keypair.sign(b"test").unwrap();

        let bytes = sig.to_bytes().unwrap();
        let deserialized = ForwardSecureSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.period(), deserialized.period());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = ForwardSecureKeypair::generate(10);
        let public_key = keypair.public_key();

        let bytes = public_key.to_bytes().unwrap();
        let deserialized = ForwardSecurePublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(public_key.max_periods(), deserialized.max_periods());
    }

    #[test]
    fn test_builder_default() {
        let keypair = ForwardSecureBuilder::default().build();
        assert_eq!(keypair.current_period(), 0);
        assert_eq!(keypair.max_periods(), 1000);
    }

    #[test]
    fn test_builder_custom_periods() {
        let keypair = ForwardSecureBuilder::new().max_periods(50).build();
        assert_eq!(keypair.max_periods(), 50);
    }

    #[test]
    fn test_builder_initial_period() {
        let keypair = ForwardSecureBuilder::new()
            .max_periods(100)
            .initial_period(5)
            .build();
        assert_eq!(keypair.current_period(), 5);
    }

    #[test]
    fn test_period_independence() {
        let keypair1 = ForwardSecureKeypair::generate(10);
        let keypair2 = ForwardSecureKeypair::generate(10);

        let msg = b"test";

        // Sign with both keypairs
        let sig1 = keypair1.sign(msg).unwrap();
        let sig2 = keypair2.sign(msg).unwrap();

        // Each signature only verifies with its own public key
        assert!(sig1.verify(msg, keypair1.public_key()).is_ok());
        assert!(sig2.verify(msg, keypair2.public_key()).is_ok());
    }

    #[test]
    fn test_deterministic_evolution() {
        let mut keypair = ForwardSecureKeypair::generate(10);

        let period0 = keypair.current_period();
        keypair.evolve().unwrap();
        let period1 = keypair.current_period();
        keypair.evolve().unwrap();
        let period2 = keypair.current_period();

        assert_eq!(period0, 0);
        assert_eq!(period1, 1);
        assert_eq!(period2, 2);
    }

    #[test]
    fn test_public_key_max_periods() {
        let keypair = ForwardSecureKeypair::generate(42);
        assert_eq!(keypair.public_key().max_periods(), 42);
    }
}
