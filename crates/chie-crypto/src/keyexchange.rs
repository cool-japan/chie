//! X25519 key exchange for secure P2P communication.
//!
//! This module provides Diffie-Hellman key exchange using the X25519 elliptic curve,
//! enabling peers in the CHIE network to establish secure encrypted channels.
//!
//! # Features
//! - X25519 Diffie-Hellman key exchange
//! - Ephemeral and static key support
//! - Shared secret derivation with HKDF
//! - Key serialization for network transmission
//!
//! # Example
//! ```
//! use chie_crypto::keyexchange::{KeyExchange, KeyExchangeKeypair};
//!
//! // Alice generates a keypair
//! let alice = KeyExchangeKeypair::generate();
//! // Bob generates a keypair
//! let bob = KeyExchangeKeypair::generate();
//!
//! // Exchange public keys and derive shared secret
//! let alice_shared = alice.exchange(bob.public_key());
//! let bob_shared = bob.exchange(alice.public_key());
//!
//! // Both parties now have the same shared secret
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! ```

use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Shared secret derived from key exchange (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

/// Key exchange keypair for X25519 Diffie-Hellman.
pub struct KeyExchangeKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

/// Key exchange trait for performing Diffie-Hellman.
pub trait KeyExchange {
    /// Perform key exchange to derive a shared secret.
    fn exchange(&self, their_public: &X25519PublicKey) -> SharedSecret;
}

/// Errors that can occur during key exchange operations.
#[derive(Debug, Error)]
pub enum KeyExchangeError {
    /// Invalid public key (low-order point).
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Shared secret derivation failed.
    #[error("Shared secret derivation failed")]
    DerivationFailed,
}

pub type KeyExchangeResult<T> = Result<T, KeyExchangeError>;

impl SharedSecret {
    /// Create a new shared secret from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the shared secret as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Derive an encryption key from the shared secret using HKDF.
    ///
    /// # Arguments
    /// * `info` - Context-specific information for key derivation
    ///
    /// # Returns
    /// A 32-byte derived key suitable for symmetric encryption.
    pub fn derive_key(&self, info: &[u8]) -> [u8; 32] {
        use crate::kdf::hkdf_extract_expand;
        let salt = b"chie-p2p-v1";
        hkdf_extract_expand(&self.0, salt, info)
    }

    /// Derive multiple keys from the shared secret.
    ///
    /// # Arguments
    /// * `infos` - Slice of context information for each key
    ///
    /// # Returns
    /// Vector of 32-byte derived keys.
    pub fn derive_keys(&self, infos: &[&[u8]]) -> Vec<[u8; 32]> {
        infos.iter().map(|info| self.derive_key(info)).collect()
    }
}

impl KeyExchangeKeypair {
    /// Generate a new random keypair.
    ///
    /// # Example
    /// ```
    /// use chie_crypto::keyexchange::KeyExchangeKeypair;
    ///
    /// let keypair = KeyExchangeKeypair::generate();
    /// ```
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core06::OsRng);
        let public = X25519PublicKey::from(&secret);

        Self { secret, public }
    }

    /// Create a keypair from a secret key (32 bytes).
    ///
    /// # Arguments
    /// * `secret_bytes` - 32-byte secret key
    ///
    /// # Example
    /// ```
    /// use chie_crypto::keyexchange::KeyExchangeKeypair;
    ///
    /// let secret = [1u8; 32];
    /// let keypair = KeyExchangeKeypair::from_bytes(secret);
    /// ```
    pub fn from_bytes(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);

        Self { secret, public }
    }

    /// Get the public key.
    ///
    /// # Returns
    /// Reference to the X25519 public key.
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Get the public key as bytes.
    ///
    /// # Returns
    /// 32-byte array containing the public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

impl KeyExchange for KeyExchangeKeypair {
    /// Perform X25519 Diffie-Hellman key exchange.
    ///
    /// # Arguments
    /// * `their_public` - The other party's public key
    ///
    /// # Returns
    /// Shared secret derived from the key exchange.
    ///
    /// # Example
    /// ```
    /// use chie_crypto::keyexchange::{KeyExchange, KeyExchangeKeypair};
    ///
    /// let alice = KeyExchangeKeypair::generate();
    /// let bob = KeyExchangeKeypair::generate();
    ///
    /// let shared = alice.exchange(bob.public_key());
    /// ```
    fn exchange(&self, their_public: &X25519PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(their_public);
        SharedSecret(*shared.as_bytes())
    }
}

/// Create an ephemeral keypair for one-time key exchange.
///
/// # Returns
/// A newly generated keypair intended for ephemeral use.
///
/// # Example
/// ```
/// use chie_crypto::keyexchange::ephemeral_keypair;
///
/// let ephemeral = ephemeral_keypair();
/// ```
pub fn ephemeral_keypair() -> KeyExchangeKeypair {
    KeyExchangeKeypair::generate()
}

/// Perform a complete key exchange and derive an encryption key.
///
/// # Arguments
/// * `our_secret` - Our keypair
/// * `their_public` - The other party's public key
/// * `context` - Context information for key derivation
///
/// # Returns
/// A 32-byte encryption key derived from the shared secret.
///
/// # Example
/// ```
/// use chie_crypto::keyexchange::{KeyExchangeKeypair, exchange_and_derive};
///
/// let alice = KeyExchangeKeypair::generate();
/// let bob = KeyExchangeKeypair::generate();
///
/// let alice_key = exchange_and_derive(&alice, bob.public_key(), b"session-1");
/// let bob_key = exchange_and_derive(&bob, alice.public_key(), b"session-1");
///
/// assert_eq!(alice_key, bob_key);
/// ```
pub fn exchange_and_derive(
    our_secret: &KeyExchangeKeypair,
    their_public: &X25519PublicKey,
    context: &[u8],
) -> [u8; 32] {
    let shared = our_secret.exchange(their_public);
    shared.derive_key(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_roundtrip() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let alice_shared = alice.exchange(bob.public_key());
        let bob_shared = bob.exchange(alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_different_pairs_different_secrets() {
        let alice1 = KeyExchangeKeypair::generate();
        let alice2 = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let shared1 = alice1.exchange(bob.public_key());
        let shared2 = alice2.exchange(bob.public_key());

        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_derive_key_from_shared_secret() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let alice_shared = alice.exchange(bob.public_key());
        let bob_shared = bob.exchange(alice.public_key());

        let alice_key = alice_shared.derive_key(b"encryption");
        let bob_key = bob_shared.derive_key(b"encryption");

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_different_info_different_keys() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let shared = alice.exchange(bob.public_key());

        let key1 = shared.derive_key(b"encryption");
        let key2 = shared.derive_key(b"authentication");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KeyExchangeKeypair::generate();
        let public_bytes = keypair.public_key_bytes();

        // Should be 32 bytes
        assert_eq!(public_bytes.len(), 32);

        // Should be non-zero
        assert_ne!(public_bytes, [0u8; 32]);
    }

    #[test]
    fn test_keypair_from_bytes() {
        let secret_bytes = [42u8; 32];
        let keypair = KeyExchangeKeypair::from_bytes(secret_bytes);

        // Should produce valid public key
        assert_ne!(keypair.public_key_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_commutative_exchange() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();
        let carol = KeyExchangeKeypair::generate();

        let alice_bob = alice.exchange(bob.public_key());
        let bob_alice = bob.exchange(alice.public_key());
        let alice_carol = alice.exchange(carol.public_key());

        // Same pair = same secret
        assert_eq!(alice_bob.as_bytes(), bob_alice.as_bytes());

        // Different pair = different secret
        assert_ne!(alice_bob.as_bytes(), alice_carol.as_bytes());
    }

    #[test]
    fn test_ephemeral_keypair() {
        let ephemeral1 = ephemeral_keypair();
        let ephemeral2 = ephemeral_keypair();

        // Different ephemeral keypairs
        assert_ne!(ephemeral1.public_key_bytes(), ephemeral2.public_key_bytes());
    }

    #[test]
    fn test_exchange_and_derive() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let alice_key = exchange_and_derive(&alice, bob.public_key(), b"test-session");
        let bob_key = exchange_and_derive(&bob, alice.public_key(), b"test-session");

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_derive_multiple_keys() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let shared = alice.exchange(bob.public_key());

        let keys = shared.derive_keys(&[b"key1", b"key2", b"key3"]);

        assert_eq!(keys.len(), 3);
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_shared_secret_serialization() {
        let alice = KeyExchangeKeypair::generate();
        let bob = KeyExchangeKeypair::generate();

        let shared = alice.exchange(bob.public_key());

        let bytes = shared.to_bytes();
        let restored = SharedSecret::from_bytes(bytes);

        assert_eq!(shared.as_bytes(), restored.as_bytes());
    }
}
