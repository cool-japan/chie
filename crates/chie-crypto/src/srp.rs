//! SRP - Secure Remote Password Protocol (SRP-6a).
//!
//! SRP is a password-authenticated key exchange (PAKE) protocol that allows a client
//! to authenticate to a server using a password, without the server ever seeing the password.
//! The server stores a "verifier" instead of the actual password.
//!
//! # Features
//! - Server never sees the password
//! - Protection against offline dictionary attacks
//! - Mutual authentication
//! - Perfect forward secrecy
//!
//! # Example
//! ```
//! use chie_crypto::srp::{SrpClient, SrpServer, SrpVerifier};
//!
//! // 1. Registration: Client creates verifier for server to store
//! let username = b"alice";
//! let password = b"secure-password";
//! let verifier = SrpVerifier::generate(username, password);
//!
//! // Server stores: username, salt, and verifier (NOT the password!)
//!
//! // 2. Authentication: Client initiates login
//! let (client, client_public) = SrpClient::new(username, password, verifier.salt());
//!
//! // 3. Server responds with server public key
//! let (server, server_public) = SrpServer::new(username, &verifier);
//!
//! // 4. Client computes session key
//! let client_key = client.compute_key(&server_public).unwrap();
//!
//! // 5. Server computes session key
//! let server_key = server.compute_key(&client_public).unwrap();
//!
//! // Keys match!
//! assert_eq!(client_key.as_bytes(), server_key.as_bytes());
//! ```

use crate::{hash, hkdf_extract_expand};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SRP error types.
#[derive(Error, Debug)]
pub enum SrpError {
    #[error("Invalid verifier")]
    InvalidVerifier,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Computation failed")]
    ComputationFailed,
    #[error("Point decompression failed")]
    DecompressionFailed,
}

/// SRP result type.
pub type SrpResult<T> = Result<T, SrpError>;

/// SRP verifier stored by the server.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SrpVerifier {
    #[zeroize(skip)]
    salt: [u8; 32],
    verifier: [u8; 32],
}

impl SrpVerifier {
    /// Generate a verifier for registration.
    ///
    /// The server stores this instead of the password.
    pub fn generate(username: &[u8], password: &[u8]) -> Self {
        // Generate random salt
        let mut rng = rand::rng();
        let salt: [u8; 32] = {
            let mut arr = [0u8; 32];
            rng.fill(&mut arr);
            arr
        };

        // Compute x = H(salt || H(username || ":" || password))
        let mut identity = Vec::new();
        identity.extend_from_slice(username);
        identity.push(b':');
        identity.extend_from_slice(password);
        let identity_hash = hash(&identity);

        let mut x_input = Vec::new();
        x_input.extend_from_slice(&salt);
        x_input.extend_from_slice(&identity_hash);
        let x_hash = hash(&x_input);
        let x = Scalar::from_bytes_mod_order(x_hash);

        // Compute verifier v = g^x
        let v_point = x * RISTRETTO_BASEPOINT_POINT;
        let verifier = v_point.compress().to_bytes();

        Self { salt, verifier }
    }

    /// Get the salt.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Get the verifier point.
    fn verifier_point(&self) -> SrpResult<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.verifier)
            .map_err(|_| SrpError::InvalidVerifier)?
            .decompress()
            .ok_or(SrpError::DecompressionFailed)
    }

    /// Serialize the verifier.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).unwrap()
    }

    /// Deserialize the verifier.
    pub fn from_bytes(bytes: &[u8]) -> SrpResult<Self> {
        crate::codec::decode(bytes).map_err(|_| SrpError::InvalidVerifier)
    }
}

/// Session key derived from SRP.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SrpSessionKey {
    key: Vec<u8>,
}

impl SrpSessionKey {
    /// Get the session key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Derive an encryption key from the session key.
    pub fn derive_key(&self, info: &[u8], len: usize) -> SrpResult<Vec<u8>> {
        let mut output = vec![0u8; len];
        let expanded = hkdf_extract_expand(&self.key, b"", info);
        output[..len.min(32)].copy_from_slice(&expanded[..len.min(32)]);
        if len > 32 {
            // For longer keys, hash multiple times
            for i in (32..len).step_by(32) {
                let mut info_extended = info.to_vec();
                info_extended.extend_from_slice(&[i as u8]);
                let expanded = hkdf_extract_expand(&self.key, b"", &info_extended);
                let end = (i + 32).min(len);
                output[i..end].copy_from_slice(&expanded[..(end - i)]);
            }
        }
        Ok(output)
    }
}

impl PartialEq for SrpSessionKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.key.ct_eq(&other.key).into()
    }
}

impl Eq for SrpSessionKey {}

/// SRP public key (exchanged over network).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrpPublicKey {
    point: [u8; 32],
}

impl SrpPublicKey {
    fn new(point: &RistrettoPoint) -> Self {
        Self {
            point: point.compress().to_bytes(),
        }
    }

    fn to_point(&self) -> SrpResult<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.point)
            .map_err(|_| SrpError::InvalidPublicKey)?
            .decompress()
            .ok_or(SrpError::DecompressionFailed)
    }
}

/// SRP client state.
pub struct SrpClient {
    #[allow(dead_code)]
    username: Vec<u8>,
    #[allow(dead_code)]
    salt: [u8; 32],
    x: Scalar,
    a: Scalar,
    big_a: RistrettoPoint,
}

impl SrpClient {
    /// Create a new SRP client session.
    ///
    /// Returns the client state and the public key to send to the server.
    pub fn new(username: &[u8], password: &[u8], salt: &[u8; 32]) -> (Self, SrpPublicKey) {
        // Compute x = H(salt || H(username || ":" || password))
        let mut identity = Vec::new();
        identity.extend_from_slice(username);
        identity.push(b':');
        identity.extend_from_slice(password);
        let identity_hash = hash(&identity);

        let mut x_input = Vec::new();
        x_input.extend_from_slice(salt);
        x_input.extend_from_slice(&identity_hash);
        let x_hash = hash(&x_input);
        let x = Scalar::from_bytes_mod_order(x_hash);

        // Generate random a
        let mut rng = rand::rng();
        let a_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            rng.fill(&mut arr);
            arr
        };
        let a = Scalar::from_bytes_mod_order(a_bytes);

        // Compute A = g^a
        let big_a = a * RISTRETTO_BASEPOINT_POINT;

        let public_key = SrpPublicKey::new(&big_a);

        let client = Self {
            username: username.to_vec(),
            salt: *salt,
            x,
            a,
            big_a,
        };

        (client, public_key)
    }

    /// Compute the session key using the server's public key.
    pub fn compute_key(self, server_public: &SrpPublicKey) -> SrpResult<SrpSessionKey> {
        let big_b = server_public.to_point()?;

        // Compute u = H(A || B)
        let mut u_input = Vec::new();
        u_input.extend_from_slice(&self.big_a.compress().to_bytes());
        u_input.extend_from_slice(&big_b.compress().to_bytes());
        let u_hash = hash(&u_input);
        let u = Scalar::from_bytes_mod_order(u_hash);

        // Compute k = H(g)
        let k_hash = hash(&RISTRETTO_BASEPOINT_POINT.compress().to_bytes());
        let k = Scalar::from_bytes_mod_order(k_hash);

        // Compute x
        let g_x = self.x * RISTRETTO_BASEPOINT_POINT;

        // Compute S = (B - k * g^x) ^ (a + u * x)
        let base = big_b - (k * g_x);
        let exponent = self.a + (u * self.x);
        let s_point = exponent * base;

        // Derive session key
        let s_bytes = s_point.compress().to_bytes();
        let key = hkdf_extract_expand(&s_bytes, b"", b"SRP Session Key").to_vec();

        Ok(SrpSessionKey { key })
    }
}

/// SRP server state.
pub struct SrpServer {
    #[allow(dead_code)]
    username: Vec<u8>,
    v: RistrettoPoint,
    b: Scalar,
    big_b: RistrettoPoint,
}

impl SrpServer {
    /// Create a new SRP server session.
    ///
    /// Returns the server state and the public key to send to the client.
    pub fn new(username: &[u8], verifier: &SrpVerifier) -> (Self, SrpPublicKey) {
        let v = verifier.verifier_point().expect("Invalid verifier");

        // Generate random b
        let mut rng = rand::rng();
        let b_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            rng.fill(&mut arr);
            arr
        };
        let b = Scalar::from_bytes_mod_order(b_bytes);

        // Compute k = H(g)
        let k_hash = hash(&RISTRETTO_BASEPOINT_POINT.compress().to_bytes());
        let k = Scalar::from_bytes_mod_order(k_hash);

        // Compute B = k*v + g^b
        let g_b = b * RISTRETTO_BASEPOINT_POINT;
        let big_b = (k * v) + g_b;

        let public_key = SrpPublicKey::new(&big_b);

        let server = Self {
            username: username.to_vec(),
            v,
            b,
            big_b,
        };

        (server, public_key)
    }

    /// Compute the session key using the client's public key.
    pub fn compute_key(self, client_public: &SrpPublicKey) -> SrpResult<SrpSessionKey> {
        let big_a = client_public.to_point()?;

        // Compute u = H(A || B)
        let mut u_input = Vec::new();
        u_input.extend_from_slice(&big_a.compress().to_bytes());
        u_input.extend_from_slice(&self.big_b.compress().to_bytes());
        let u_hash = hash(&u_input);
        let u = Scalar::from_bytes_mod_order(u_hash);

        // Compute S = (A * v^u) ^ b
        let v_u = u * self.v;
        let base = big_a + v_u;
        let s_point = self.b * base;

        // Derive session key
        let s_bytes = s_point.compress().to_bytes();
        let key = hkdf_extract_expand(&s_bytes, b"", b"SRP Session Key").to_vec();

        Ok(SrpSessionKey { key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srp_basic() {
        let username = b"alice";
        let password = b"secure-password";

        // Registration
        let verifier = SrpVerifier::generate(username, password);

        // Authentication
        let (client, client_public) = SrpClient::new(username, password, verifier.salt());
        let (server, server_public) = SrpServer::new(username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_srp_wrong_password() {
        let username = b"alice";
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let verifier = SrpVerifier::generate(username, password);

        let (client, client_public) = SrpClient::new(username, wrong_password, verifier.salt());
        let (server, server_public) = SrpServer::new(username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        // Keys should not match
        assert_ne!(client_key, server_key);
    }

    #[test]
    fn test_srp_multiple_sessions() {
        let username = b"bob";
        let password = b"secret";

        let verifier = SrpVerifier::generate(username, password);

        // Session 1
        let (client1, client_public1) = SrpClient::new(username, password, verifier.salt());
        let (server1, server_public1) = SrpServer::new(username, &verifier);
        let key1_c = client1.compute_key(&server_public1).unwrap();
        let key1_s = server1.compute_key(&client_public1).unwrap();
        assert_eq!(key1_c, key1_s);

        // Session 2 (should have different keys due to fresh randomness)
        let (client2, client_public2) = SrpClient::new(username, password, verifier.salt());
        let (server2, server_public2) = SrpServer::new(username, &verifier);
        let key2_c = client2.compute_key(&server_public2).unwrap();
        let key2_s = server2.compute_key(&client_public2).unwrap();
        assert_eq!(key2_c, key2_s);

        // Different sessions should have different keys
        assert_ne!(key1_c, key2_c);
    }

    #[test]
    fn test_srp_verifier_serialization() {
        let username = b"test";
        let password = b"password";

        let verifier = SrpVerifier::generate(username, password);

        let bytes = verifier.to_bytes();
        let deserialized = SrpVerifier::from_bytes(&bytes).unwrap();

        assert_eq!(verifier.salt, deserialized.salt);
        assert_eq!(verifier.verifier, deserialized.verifier);
    }

    #[test]
    fn test_srp_key_derivation() {
        let username = b"user";
        let password = b"pass";

        let verifier = SrpVerifier::generate(username, password);

        let (client, client_public) = SrpClient::new(username, password, verifier.salt());
        let (server, server_public) = SrpServer::new(username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        // Derive encryption keys
        let client_enc_key = client_key.derive_key(b"encryption", 32).unwrap();
        let server_enc_key = server_key.derive_key(b"encryption", 32).unwrap();

        assert_eq!(client_enc_key, server_enc_key);

        // Different info should give different keys
        let client_mac_key = client_key.derive_key(b"mac", 32).unwrap();
        assert_ne!(client_enc_key, client_mac_key);
    }

    #[test]
    fn test_srp_different_usernames() {
        let password = b"same-password";

        let verifier1 = SrpVerifier::generate(b"alice", password);
        let verifier2 = SrpVerifier::generate(b"bob", password);

        // Verifiers should be different even with same password
        assert_ne!(verifier1.verifier, verifier2.verifier);
    }

    #[test]
    fn test_srp_empty_username() {
        let username = b"";
        let password = b"password";

        let verifier = SrpVerifier::generate(username, password);

        let (client, client_public) = SrpClient::new(username, password, verifier.salt());
        let (server, server_public) = SrpServer::new(username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_srp_long_credentials() {
        let username = b"very-long-username-with-many-characters-for-testing";
        let password = b"very-long-password-with-many-characters-for-testing-purposes";

        let verifier = SrpVerifier::generate(username, password);

        let (client, client_public) = SrpClient::new(username, password, verifier.salt());
        let (server, server_public) = SrpServer::new(username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_srp_binary_data() {
        let username: Vec<u8> = (0..32).collect();
        let password: Vec<u8> = (32..64).collect();

        let verifier = SrpVerifier::generate(&username, &password);

        let (client, client_public) = SrpClient::new(&username, &password, verifier.salt());
        let (server, server_public) = SrpServer::new(&username, &verifier);

        let client_key = client.compute_key(&server_public).unwrap();
        let server_key = server.compute_key(&client_public).unwrap();

        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_srp_public_key_serialization() {
        let username = b"test";
        let password = b"test";
        let verifier = SrpVerifier::generate(username, password);

        let (_client, client_public) = SrpClient::new(username, password, verifier.salt());

        // Serialize and deserialize
        let serialized = crate::codec::encode(&client_public).unwrap();
        let deserialized: SrpPublicKey = crate::codec::decode(&serialized).unwrap();

        assert!(deserialized.to_point().is_ok());
    }

    #[test]
    fn test_srp_session_key_constant_time_eq() {
        let username = b"alice";
        let password = b"password123";

        let verifier = SrpVerifier::generate(username, password);

        let (client1, client_public1) = SrpClient::new(username, password, verifier.salt());
        let (server1, server_public1) = SrpServer::new(username, &verifier);

        let key1 = client1.compute_key(&server_public1).unwrap();
        let key2 = server1.compute_key(&client_public1).unwrap();

        // Test constant-time comparison
        assert_eq!(key1, key2);
        assert!(key1 == key2);
    }
}
