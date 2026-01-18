//! SPAKE2 - Simple Password-Authenticated Key Exchange.
//!
//! SPAKE2 is a password-authenticated key exchange (PAKE) protocol that allows two parties
//! who share a password to derive a strong shared secret. It provides protection against
//! offline dictionary attacks.
//!
//! # Features
//! - Symmetric PAKE (both parties use same password)
//! - Protection against offline dictionary attacks
//! - Forward secrecy
//! - Simple and efficient
//!
//! # Example
//! ```
//! use chie_crypto::spake2::{Spake2, Spake2Side};
//!
//! // Alice and Bob share a password
//! let password = b"shared-secret-password";
//!
//! // Alice starts the protocol
//! let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);
//!
//! // Bob starts the protocol
//! let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, password);
//!
//! // They exchange messages and derive the shared secret
//! let alice_secret = alice.finish(&bob_msg).unwrap();
//! let bob_secret = bob.finish(&alice_msg).unwrap();
//!
//! // Shared secrets match
//! assert_eq!(alice_secret, bob_secret);
//! ```

use crate::{hash, hkdf_extract_expand};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SPAKE2 error types.
#[derive(Error, Debug)]
pub enum Spake2Error {
    #[error("Invalid message format")]
    InvalidMessage,
    #[error("Protocol not in correct state")]
    InvalidState,
    #[error("Shared secret derivation failed")]
    DerivationFailed,
    #[error("Point decompression failed")]
    DecompressionFailed,
}

/// SPAKE2 result type.
pub type Spake2Result<T> = Result<T, Spake2Error>;

/// Side in the SPAKE2 protocol (Alice or Bob).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Side {
    Alice,
    Bob,
}

/// SPAKE2 protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spake2Message {
    point: [u8; 32],
}

impl Spake2Message {
    /// Create message from a point.
    fn new(point: &RistrettoPoint) -> Self {
        Self {
            point: point.compress().to_bytes(),
        }
    }

    /// Decompress the point.
    fn to_point(&self) -> Spake2Result<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.point)
            .map_err(|_| Spake2Error::InvalidMessage)?
            .decompress()
            .ok_or(Spake2Error::DecompressionFailed)
    }
}

/// Shared secret derived from SPAKE2.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Spake2SharedSecret {
    secret: Vec<u8>,
}

impl Spake2SharedSecret {
    /// Get the shared secret as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Derive a key from the shared secret.
    pub fn derive_key(&self, info: &[u8], len: usize) -> Spake2Result<Vec<u8>> {
        let mut output = vec![0u8; len];
        let expanded = hkdf_extract_expand(&self.secret, b"", info);
        output[..len.min(32)].copy_from_slice(&expanded[..len.min(32)]);
        if len > 32 {
            // For longer keys, hash multiple times
            for i in (32..len).step_by(32) {
                let mut info_extended = info.to_vec();
                info_extended.extend_from_slice(&[i as u8]);
                let expanded = hkdf_extract_expand(&self.secret, b"", &info_extended);
                let end = (i + 32).min(len);
                output[i..end].copy_from_slice(&expanded[..(end - i)]);
            }
        }
        Ok(output)
    }
}

impl PartialEq for Spake2SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.secret.ct_eq(&other.secret).into()
    }
}

impl Eq for Spake2SharedSecret {}

/// SPAKE2 protocol state machine.
pub struct Spake2 {
    side: Spake2Side,
    password_scalar: Scalar,
    secret_scalar: Scalar,
    public_point: RistrettoPoint,
}

impl Spake2 {
    // SPAKE2 constants M and N (nothing-up-my-sleeve values)
    // These are derived from the string "chie-spake2-M" and "chie-spake2-N"
    fn constant_m() -> RistrettoPoint {
        let hash1 = hash(b"chie-spake2-M");
        let hash2 = hash(b"chie-spake2-M-2");
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash1);
        bytes[32..].copy_from_slice(&hash2);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }

    fn constant_n() -> RistrettoPoint {
        let hash1 = hash(b"chie-spake2-N");
        let hash2 = hash(b"chie-spake2-N-2");
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&hash1);
        bytes[32..].copy_from_slice(&hash2);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }

    /// Start the SPAKE2 protocol.
    ///
    /// Returns the protocol state and the message to send to the other party.
    pub fn start(side: Spake2Side, password: &[u8]) -> (Self, Spake2Message) {
        // Hash password to scalar
        let password_hash = hash(password);
        let password_scalar = Scalar::from_bytes_mod_order(password_hash);

        // Generate random secret scalar
        let mut rng = rand::thread_rng();
        let secret_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            rng.fill(&mut arr);
            arr
        };
        let secret_scalar = Scalar::from_bytes_mod_order(secret_bytes);

        // Compute public point: X = x*G + w*M (Alice) or Y = y*G + w*N (Bob)
        let base_point = secret_scalar * RISTRETTO_BASEPOINT_POINT;
        let password_point = match side {
            Spake2Side::Alice => password_scalar * Self::constant_m(),
            Spake2Side::Bob => password_scalar * Self::constant_n(),
        };
        let public_point = base_point + password_point;

        let message = Spake2Message::new(&public_point);

        let state = Self {
            side,
            password_scalar,
            secret_scalar,
            public_point,
        };

        (state, message)
    }

    /// Finish the SPAKE2 protocol using the other party's message.
    ///
    /// Returns the shared secret.
    pub fn finish(self, other_message: &Spake2Message) -> Spake2Result<Spake2SharedSecret> {
        // Decompress received point
        let received_point = other_message.to_point()?;

        // Remove password component from received point
        let password_component = match self.side {
            // Alice computes: Z = Y - w*N
            Spake2Side::Alice => self.password_scalar * Self::constant_n(),
            // Bob computes: Z = X - w*M
            Spake2Side::Bob => self.password_scalar * Self::constant_m(),
        };

        let shared_point = received_point - password_component;

        // Compute shared secret: K = x*Z (Alice) or K = y*Z (Bob)
        let key_point = self.secret_scalar * shared_point;

        // Derive shared secret using transcript hash
        let transcript = self.compute_transcript(&received_point);
        let key_material = key_point.compress().to_bytes();

        // Use HKDF to derive the shared secret
        let secret = hkdf_extract_expand(&key_material, &transcript, b"SPAKE2 Key").to_vec();

        Ok(Spake2SharedSecret { secret })
    }

    /// Compute protocol transcript for key derivation.
    fn compute_transcript(&self, other_point: &RistrettoPoint) -> Vec<u8> {
        let mut transcript = Vec::new();

        // Include both public points in a canonical order (Alice's first, Bob's second)
        let (alice_point, bob_point) = match self.side {
            Spake2Side::Alice => (self.public_point, *other_point),
            Spake2Side::Bob => (*other_point, self.public_point),
        };

        transcript.extend_from_slice(&alice_point.compress().to_bytes());
        transcript.extend_from_slice(&bob_point.compress().to_bytes());

        transcript
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spake2_basic() {
        let password = b"shared-secret-password";

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_spake2_different_passwords_fail() {
        let alice_password = b"password1";
        let bob_password = b"password2";

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, alice_password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, bob_password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        assert_ne!(alice_secret, bob_secret);
    }

    #[test]
    fn test_spake2_deterministic_with_same_password() {
        let password = b"test-password";

        // Run protocol twice
        let (alice1, _alice_msg1) = Spake2::start(Spake2Side::Alice, password);
        let (_bob1, bob_msg1) = Spake2::start(Spake2Side::Bob, password);

        let (alice2, _alice_msg2) = Spake2::start(Spake2Side::Alice, password);
        let (_bob2, bob_msg2) = Spake2::start(Spake2Side::Bob, password);

        let secret1 = alice1.finish(&bob_msg1).unwrap();
        let secret2 = alice2.finish(&bob_msg2).unwrap();

        // Secrets should be different due to random nonces
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_spake2_key_derivation() {
        let password = b"shared-secret";

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        // Derive keys from shared secret
        let alice_key = alice_secret.derive_key(b"app-key", 32).unwrap();
        let bob_key = bob_secret.derive_key(b"app-key", 32).unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_spake2_message_serialization() {
        let password = b"test";
        let (_alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);

        // Serialize and deserialize
        let serialized = crate::codec::encode(&alice_msg).unwrap();
        let deserialized: Spake2Message = crate::codec::decode(&serialized).unwrap();

        // Should be able to decompress
        assert!(deserialized.to_point().is_ok());
    }

    #[test]
    fn test_spake2_wrong_side_fails() {
        let password = b"password";

        let (alice1, alice_msg1) = Spake2::start(Spake2Side::Alice, password);
        let (alice2, alice_msg2) = Spake2::start(Spake2Side::Alice, password);

        // Both as Alice (wrong!)
        let secret1 = alice1.finish(&alice_msg2).unwrap();
        let secret2 = alice2.finish(&alice_msg1).unwrap();

        // Secrets should not match
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_spake2_multiple_sessions() {
        let password = b"shared-password";

        // Session 1
        let (alice1, alice_msg1) = Spake2::start(Spake2Side::Alice, password);
        let (bob1, bob_msg1) = Spake2::start(Spake2Side::Bob, password);
        let secret1_a = alice1.finish(&bob_msg1).unwrap();
        let secret1_b = bob1.finish(&alice_msg1).unwrap();
        assert_eq!(secret1_a, secret1_b);

        // Session 2 (should have different keys due to fresh randomness)
        let (alice2, alice_msg2) = Spake2::start(Spake2Side::Alice, password);
        let (bob2, bob_msg2) = Spake2::start(Spake2Side::Bob, password);
        let secret2_a = alice2.finish(&bob_msg2).unwrap();
        let secret2_b = bob2.finish(&alice_msg2).unwrap();
        assert_eq!(secret2_a, secret2_b);

        // Different sessions should have different keys
        assert_ne!(secret1_a, secret2_a);
    }

    #[test]
    fn test_spake2_empty_password() {
        let password = b"";

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_spake2_long_password() {
        let password =
            b"this-is-a-very-long-password-with-many-characters-to-test-long-input-handling";

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_spake2_binary_password() {
        let password: Vec<u8> = (0..=255).collect();

        let (alice, alice_msg) = Spake2::start(Spake2Side::Alice, &password);
        let (bob, bob_msg) = Spake2::start(Spake2Side::Bob, &password);

        let alice_secret = alice.finish(&bob_msg).unwrap();
        let bob_secret = bob.finish(&alice_msg).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_spake2_constants_different() {
        let m = Spake2::constant_m();
        let n = Spake2::constant_n();

        // M and N should be different
        assert_ne!(m.compress().to_bytes(), n.compress().to_bytes());
    }
}
