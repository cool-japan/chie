//! TLS 1.3 Key Schedule Support
//!
//! This module implements the TLS 1.3 key schedule as defined in RFC 8446.
//! Provides key derivation for handshake and application traffic secrets.
//!
//! # Examples
//!
//! ```
//! use chie_crypto::tls13::Tls13KeySchedule;
//!
//! // Create key schedule with shared secret
//! let shared_secret = [0u8; 32];
//! let mut schedule = Tls13KeySchedule::new(&shared_secret);
//!
//! // Derive handshake traffic secrets
//! let client_hello = b"client hello";
//! let server_hello = b"server hello";
//! let (client_hs_secret, server_hs_secret) = schedule.derive_handshake_secrets(
//!     client_hello,
//!     server_hello
//! );
//!
//! // Derive application traffic secrets
//! let (client_app_secret, server_app_secret) = schedule.derive_application_secrets().unwrap();
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// TLS 1.3 key schedule errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Tls13Error {
    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// Key schedule not initialized
    #[error("Key schedule not initialized")]
    NotInitialized,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Result type for TLS 1.3 operations
pub type Tls13Result<T> = Result<T, Tls13Error>;

/// TLS 1.3 Key Schedule
///
/// Manages the key derivation process for TLS 1.3 connections.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tls13KeySchedule {
    /// Early secret (derived from PSK or zeros)
    early_secret: [u8; 32],
    /// Handshake secret
    handshake_secret: Option<[u8; 32]>,
    /// Master secret
    master_secret: Option<[u8; 32]>,
}

impl Tls13KeySchedule {
    /// Create a new TLS 1.3 key schedule
    ///
    /// # Arguments
    /// * `shared_secret` - Shared secret from key exchange (e.g., ECDHE)
    pub fn new(shared_secret: &[u8]) -> Self {
        // Early secret = HKDF-Extract(salt=0, IKM=0)
        let zero_salt = [0u8; 32];
        let early_secret = hkdf_extract(&zero_salt, &zero_salt);

        // Derive handshake secret
        let handshake_secret = derive_secret(&early_secret, b"derived", &[]);
        let handshake_secret = hkdf_extract(&handshake_secret, shared_secret);

        Self {
            early_secret,
            handshake_secret: Some(handshake_secret),
            master_secret: None,
        }
    }

    /// Derive handshake traffic secrets
    ///
    /// # Arguments
    /// * `client_hello` - Client hello message
    /// * `server_hello` - Server hello message
    ///
    /// # Returns
    /// Tuple of (client_handshake_traffic_secret, server_handshake_traffic_secret)
    pub fn derive_handshake_secrets(
        &mut self,
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> ([u8; 32], [u8; 32]) {
        let handshake_secret = self
            .handshake_secret
            .expect("Handshake secret not initialized");

        // Transcript hash = SHA-256(ClientHello || ServerHello)
        let mut hasher = Sha256::new();
        hasher.update(client_hello);
        hasher.update(server_hello);
        let transcript_hash = hasher.finalize();

        // Client handshake traffic secret
        let client_hs_traffic_secret =
            derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);

        // Server handshake traffic secret
        let server_hs_traffic_secret =
            derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);

        // Derive master secret for application traffic
        let derived = derive_secret(&handshake_secret, b"derived", &[]);
        let master_secret = hkdf_extract(&derived, &[0u8; 32]);
        self.master_secret = Some(master_secret);

        (client_hs_traffic_secret, server_hs_traffic_secret)
    }

    /// Derive application traffic secrets
    ///
    /// # Returns
    /// Tuple of (client_application_traffic_secret, server_application_traffic_secret)
    pub fn derive_application_secrets(&self) -> Tls13Result<([u8; 32], [u8; 32])> {
        let master_secret = self.master_secret.ok_or(Tls13Error::NotInitialized)?;

        // Empty transcript hash for application traffic
        let empty_hash = Sha256::digest([]);

        // Client application traffic secret
        let client_app_traffic_secret = derive_secret(&master_secret, b"c ap traffic", &empty_hash);

        // Server application traffic secret
        let server_app_traffic_secret = derive_secret(&master_secret, b"s ap traffic", &empty_hash);

        Ok((client_app_traffic_secret, server_app_traffic_secret))
    }

    /// Derive exporter master secret
    ///
    /// Used for exporting keying material outside of TLS
    pub fn derive_exporter_secret(&self) -> Tls13Result<[u8; 32]> {
        let master_secret = self.master_secret.ok_or(Tls13Error::NotInitialized)?;

        let empty_hash = Sha256::digest([]);
        Ok(derive_secret(&master_secret, b"exp master", &empty_hash))
    }

    /// Derive resumption master secret
    ///
    /// Used for session resumption
    pub fn derive_resumption_secret(&self, transcript_hash: &[u8]) -> Tls13Result<[u8; 32]> {
        let master_secret = self.master_secret.ok_or(Tls13Error::NotInitialized)?;

        Ok(derive_secret(
            &master_secret,
            b"res master",
            transcript_hash,
        ))
    }

    /// Update traffic keys (key update)
    ///
    /// Derives new traffic secret from current one
    pub fn update_traffic_secret(current_secret: &[u8; 32]) -> [u8; 32] {
        derive_secret(current_secret, b"traffic upd", &[])
    }
}

/// HKDF-Extract operation
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC can take key of any size");
    mac.update(ikm);
    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// HKDF-Expand-Label operation (TLS 1.3 specific)
fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    // HkdfLabel structure:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } HkdfLabel;

    let mut hkdf_label = Vec::new();

    // Length (2 bytes)
    hkdf_label.extend_from_slice(&length.to_be_bytes());

    // Label = "tls13 " + label
    let full_label = [b"tls13 ", label].concat();
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);

    // Context
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand
    hkdf_expand(secret, &hkdf_label, length as usize)
}

/// HKDF-Expand operation
fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut counter = 1u8;

    while output.len() < length {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC can take key of any size");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);

        t = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&t);
        counter += 1;
    }

    output.truncate(length);
    output
}

/// Derive-Secret operation (TLS 1.3 specific)
fn derive_secret(secret: &[u8], label: &[u8], messages: &[u8]) -> [u8; 32] {
    // Transcript-Hash(Messages)
    let transcript_hash = if messages.is_empty() {
        Sha256::digest([]).to_vec()
    } else {
        messages.to_vec()
    };

    let expanded = hkdf_expand_label(secret, label, &transcript_hash, 32);
    let mut output = [0u8; 32];
    output.copy_from_slice(&expanded[..32]);
    output
}

/// Derive traffic keys from traffic secret
///
/// # Returns
/// Tuple of (key, iv) for AEAD encryption
pub fn derive_traffic_keys(traffic_secret: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    // Key = HKDF-Expand-Label(Secret, "key", "", key_length)
    let key_bytes = hkdf_expand_label(traffic_secret, b"key", &[], 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes[..32]);

    // IV = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    let iv_bytes = hkdf_expand_label(traffic_secret, b"iv", &[], 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes[..12]);

    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_schedule_creation() {
        let shared_secret = [0x42u8; 32];
        let schedule = Tls13KeySchedule::new(&shared_secret);

        assert!(schedule.handshake_secret.is_some());
        assert!(schedule.master_secret.is_none());
    }

    #[test]
    fn test_handshake_secrets_derivation() {
        let shared_secret = [0x42u8; 32];
        let mut schedule = Tls13KeySchedule::new(&shared_secret);

        let client_hello = b"client hello message";
        let server_hello = b"server hello message";

        let (client_hs, server_hs) = schedule.derive_handshake_secrets(client_hello, server_hello);

        // Secrets should be different
        assert_ne!(client_hs, server_hs);

        // Master secret should now be set
        assert!(schedule.master_secret.is_some());
    }

    #[test]
    fn test_application_secrets_derivation() {
        let shared_secret = [0x42u8; 32];
        let mut schedule = Tls13KeySchedule::new(&shared_secret);

        // Must derive handshake secrets first
        let client_hello = b"client hello";
        let server_hello = b"server hello";
        schedule.derive_handshake_secrets(client_hello, server_hello);

        // Now derive application secrets
        let result = schedule.derive_application_secrets();
        assert!(result.is_ok());

        let (client_app, server_app) = result.unwrap();
        assert_ne!(client_app, server_app);
    }

    #[test]
    fn test_application_secrets_before_handshake() {
        let shared_secret = [0x42u8; 32];
        let schedule = Tls13KeySchedule::new(&shared_secret);

        // Should fail because handshake secrets not derived yet
        let result = schedule.derive_application_secrets();
        assert!(result.is_err());
    }

    #[test]
    fn test_exporter_secret() {
        let shared_secret = [0x42u8; 32];
        let mut schedule = Tls13KeySchedule::new(&shared_secret);

        schedule.derive_handshake_secrets(b"client hello", b"server hello");

        let exporter_secret = schedule.derive_exporter_secret();
        assert!(exporter_secret.is_ok());
        assert_eq!(exporter_secret.unwrap().len(), 32);
    }

    #[test]
    fn test_resumption_secret() {
        let shared_secret = [0x42u8; 32];
        let mut schedule = Tls13KeySchedule::new(&shared_secret);

        schedule.derive_handshake_secrets(b"client hello", b"server hello");

        let transcript = Sha256::digest(b"full handshake transcript");
        let resumption_secret = schedule.derive_resumption_secret(&transcript);
        assert!(resumption_secret.is_ok());
        assert_eq!(resumption_secret.unwrap().len(), 32);
    }

    #[test]
    fn test_traffic_key_update() {
        let current_secret = [0x42u8; 32];
        let new_secret = Tls13KeySchedule::update_traffic_secret(&current_secret);

        // New secret should be different
        assert_ne!(current_secret, new_secret);
    }

    #[test]
    fn test_derive_traffic_keys() {
        let traffic_secret = [0x42u8; 32];
        let (key, iv) = derive_traffic_keys(&traffic_secret);

        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_hkdf_extract() {
        let salt = [0x01u8; 32];
        let ikm = [0x02u8; 32];

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.len(), 32);

        // Should be deterministic
        let prk2 = hkdf_extract(&salt, &ikm);
        assert_eq!(prk, prk2);
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; 32];
        let info = b"test info";

        let okm = hkdf_expand(&prk, info, 64);
        assert_eq!(okm.len(), 64);

        // Should be deterministic
        let okm2 = hkdf_expand(&prk, info, 64);
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = [0x42u8; 32];
        let label = b"test label";
        let context = b"test context";

        let output = hkdf_expand_label(&secret, label, context, 32);
        assert_eq!(output.len(), 32);

        // Should be deterministic
        let output2 = hkdf_expand_label(&secret, label, context, 32);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_derive_secret() {
        let secret = [0x42u8; 32];
        let label = b"test";
        let messages = b"messages";

        let derived = derive_secret(&secret, label, messages);
        assert_eq!(derived.len(), 32);

        // Should be deterministic
        let derived2 = derive_secret(&secret, label, messages);
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_serialization() {
        let shared_secret = [0x42u8; 32];
        let schedule = Tls13KeySchedule::new(&shared_secret);

        let serialized = crate::codec::encode(&schedule).unwrap();
        let deserialized: Tls13KeySchedule = crate::codec::decode(&serialized).unwrap();

        assert_eq!(deserialized.early_secret, schedule.early_secret);
        assert_eq!(deserialized.handshake_secret, schedule.handshake_secret);
    }
}
