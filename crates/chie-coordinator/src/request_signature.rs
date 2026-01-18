//! Request signature verification middleware for API security
//!
//! This module provides Ed25519 signature-based request authentication.
//! Clients sign their requests with their private key and include the signature
//! in the request headers for verification.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// Signature verification error
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Missing signature header")]
    MissingSignature,
    #[error("Missing timestamp header")]
    MissingTimestamp,
    #[error("Missing public key header")]
    MissingPublicKey,
    #[error("Invalid signature format")]
    InvalidFormat,
    #[error("Invalid public key format")]
    InvalidPublicKey,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Request expired (timestamp too old)")]
    RequestExpired,
    #[error("Timestamp in the future")]
    TimestampFuture,
    #[error("Replay attack detected")]
    ReplayAttack,
    #[error("Public key not registered")]
    UnknownPublicKey,
}

/// Configuration for signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Time window in seconds for request validity
    pub time_window_secs: i64,
    /// Whether to check for replay attacks using nonces
    pub check_replay: bool,
    /// Whether to require public key registration
    pub require_registration: bool,
    /// Endpoints that require signature verification
    pub protected_endpoints: Vec<String>,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            time_window_secs: 300, // 5 minutes
            check_replay: true,
            require_registration: false, // Allow any valid signature by default
            protected_endpoints: vec![
                "/api/proofs".to_string(),
                "/api/content/register".to_string(),
            ],
        }
    }
}

/// Registered public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// Public key (hex-encoded)
    pub public_key: String,
    /// Associated peer ID or user ID
    pub owner_id: String,
    /// Registration timestamp
    pub registered_at: DateTime<Utc>,
    /// Whether the key is active
    pub active: bool,
}

/// Signature verifier that validates request signatures
#[derive(Debug, Clone)]
pub struct SignatureVerifier {
    config: Arc<SignatureConfig>,
    registered_keys: Arc<RwLock<HashMap<String, RegisteredKey>>>,
    used_nonces: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl SignatureVerifier {
    /// Create a new signature verifier
    pub fn new(config: SignatureConfig) -> Self {
        Self {
            config: Arc::new(config),
            registered_keys: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SignatureConfig::default())
    }

    /// Register a public key
    pub fn register_key(&self, public_key: String, owner_id: String) -> Result<(), String> {
        // Validate the public key format (should be 64 hex characters for Ed25519)
        if public_key.len() != 64 {
            return Err("Invalid public key length".to_string());
        }
        if hex::decode(&public_key).is_err() {
            return Err("Invalid hex format".to_string());
        }

        let key_info = RegisteredKey {
            public_key: public_key.clone(),
            owner_id,
            registered_at: Utc::now(),
            active: true,
        };

        let mut keys = self.registered_keys.write().unwrap();
        keys.insert(public_key, key_info);

        Ok(())
    }

    /// Revoke a public key
    pub fn revoke_key(&self, public_key: &str) -> bool {
        let mut keys = self.registered_keys.write().unwrap();
        if let Some(key_info) = keys.get_mut(public_key) {
            key_info.active = false;
            true
        } else {
            false
        }
    }

    /// Verify a request signature
    pub fn verify_signature(
        &self,
        public_key: &str,
        signature: &str,
        message: &[u8],
        timestamp: &str,
        nonce: Option<&str>,
    ) -> Result<(), SignatureError> {
        // Check if public key is registered (if required)
        if self.config.require_registration {
            let keys = self.registered_keys.read().unwrap();
            match keys.get(public_key) {
                Some(key_info) if key_info.active => {}
                Some(_) => return Err(SignatureError::UnknownPublicKey),
                None => return Err(SignatureError::UnknownPublicKey),
            }
        }

        // Verify timestamp
        let request_time = timestamp
            .parse::<DateTime<Utc>>()
            .map_err(|_| SignatureError::InvalidFormat)?;
        let now = Utc::now();
        let age = (now - request_time).num_seconds().abs();

        if age > self.config.time_window_secs {
            if request_time > now {
                return Err(SignatureError::TimestampFuture);
            }
            return Err(SignatureError::RequestExpired);
        }

        // Check for replay attacks using nonce
        if self.config.check_replay {
            if let Some(nonce_str) = nonce {
                let mut nonces = self.used_nonces.write().unwrap();

                // Clean up old nonces
                let cutoff = now - chrono::Duration::seconds(self.config.time_window_secs);
                nonces.retain(|_, &mut ts| ts > cutoff);

                // Check if nonce was already used
                if nonces.contains_key(nonce_str) {
                    warn!(nonce = nonce_str, "Replay attack detected");
                    crate::metrics::record_nonce_check(true);
                    return Err(SignatureError::ReplayAttack);
                }

                // Store the nonce
                nonces.insert(nonce_str.to_string(), now);
                crate::metrics::record_nonce_check(false);
            }
        }

        // Decode public key and signature
        let public_key_bytes =
            hex::decode(public_key).map_err(|_| SignatureError::InvalidPublicKey)?;
        let signature_bytes = hex::decode(signature).map_err(|_| SignatureError::InvalidFormat)?;

        // Convert to fixed-size arrays
        if public_key_bytes.len() != 32 {
            return Err(SignatureError::InvalidPublicKey);
        }
        if signature_bytes.len() != 64 {
            return Err(SignatureError::InvalidFormat);
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&public_key_bytes);

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);

        // Verify using chie-crypto
        match chie_crypto::verify(&pk_array, message, &sig_array) {
            Ok(_) => {
                debug!(public_key = %public_key, "Signature verified successfully");
                Ok(())
            }
            Err(_) => {
                warn!(public_key = %public_key, "Signature verification failed");
                Err(SignatureError::VerificationFailed)
            }
        }
    }

    /// Check if an endpoint requires signature verification
    pub fn is_protected(&self, path: &str) -> bool {
        self.config
            .protected_endpoints
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Get registered keys
    pub fn get_registered_keys(&self) -> Vec<RegisteredKey> {
        let keys = self.registered_keys.read().unwrap();
        keys.values().cloned().collect()
    }

    /// Get configuration
    pub fn config(&self) -> &SignatureConfig {
        &self.config
    }
}

/// Extract signature components from request headers
#[allow(dead_code)]
fn extract_signature_components(
    headers: &HeaderMap,
) -> Result<(String, String, String, Option<String>), SignatureError> {
    let public_key = headers
        .get("X-Public-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(SignatureError::MissingPublicKey)?
        .to_string();

    let signature = headers
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(SignatureError::MissingSignature)?
        .to_string();

    let timestamp = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or(SignatureError::MissingTimestamp)?
        .to_string();

    let nonce = headers
        .get("X-Nonce")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    Ok((public_key, signature, timestamp, nonce))
}

/// Middleware for signature verification
#[allow(dead_code)]
pub async fn signature_verification_middleware(
    verifier: Arc<SignatureVerifier>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let path = req.uri().path();

    // Skip verification for unprotected endpoints
    if !verifier.is_protected(path) {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();

    // Extract signature components
    let (public_key, signature, timestamp, nonce) = match extract_signature_components(headers) {
        Ok(components) => components,
        Err(e) => {
            warn!(error = %e, path = %path, "Signature extraction failed");
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("Signature verification failed: {}", e),
            ));
        }
    };

    // Construct the message to verify
    // Message format: METHOD|PATH|TIMESTAMP|NONCE (if present)
    let method = req.method().as_str();
    let message = if let Some(ref n) = nonce {
        format!("{}|{}|{}|{}", method, path, timestamp, n)
    } else {
        format!("{}|{}|{}", method, path, timestamp)
    };

    // Verify the signature
    match verifier.verify_signature(
        &public_key,
        &signature,
        message.as_bytes(),
        &timestamp,
        nonce.as_deref(),
    ) {
        Ok(_) => {
            debug!(path = %path, public_key = %public_key, "Request signature verified");
            Ok(next.run(req).await)
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %path,
                public_key = %public_key,
                "Signature verification failed"
            );
            Err((
                StatusCode::UNAUTHORIZED,
                format!("Signature verification failed: {}", e),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_verifier_creation() {
        let verifier = SignatureVerifier::with_defaults();
        assert_eq!(verifier.config().time_window_secs, 300);
        assert!(verifier.config().check_replay);
    }

    #[test]
    fn test_register_key() {
        let verifier = SignatureVerifier::with_defaults();

        // Valid public key (64 hex characters)
        let public_key = "a".repeat(64);
        assert!(
            verifier
                .register_key(public_key.clone(), "user123".to_string())
                .is_ok()
        );

        let keys = verifier.get_registered_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].owner_id, "user123");
    }

    #[test]
    fn test_register_invalid_key() {
        let verifier = SignatureVerifier::with_defaults();

        // Invalid length
        let result = verifier.register_key("abc".to_string(), "user123".to_string());
        assert!(result.is_err());

        // Invalid hex
        let result = verifier.register_key("z".repeat(64), "user123".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_key() {
        let verifier = SignatureVerifier::with_defaults();

        let public_key = "a".repeat(64);
        verifier
            .register_key(public_key.clone(), "user123".to_string())
            .unwrap();

        assert!(verifier.revoke_key(&public_key));

        let keys = verifier.get_registered_keys();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].active);
    }

    #[test]
    fn test_is_protected() {
        let verifier = SignatureVerifier::with_defaults();

        assert!(verifier.is_protected("/api/proofs"));
        assert!(verifier.is_protected("/api/proofs/submit"));
        assert!(verifier.is_protected("/api/content/register"));
        assert!(!verifier.is_protected("/api/users"));
        assert!(!verifier.is_protected("/health"));
    }

    #[test]
    fn test_timestamp_validation() {
        let verifier = SignatureVerifier::with_defaults();
        let public_key = "0".repeat(64);

        // Future timestamp
        let future_time = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let result = verifier.verify_signature(
            &public_key,
            &"0".repeat(128),
            b"test message",
            &future_time,
            None,
        );
        assert!(matches!(result, Err(SignatureError::TimestampFuture)));

        // Expired timestamp
        let past_time = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let result = verifier.verify_signature(
            &public_key,
            &"0".repeat(128),
            b"test message",
            &past_time,
            None,
        );
        assert!(matches!(result, Err(SignatureError::RequestExpired)));
    }

    #[test]
    fn test_replay_detection() {
        let verifier = SignatureVerifier::with_defaults();
        let public_key = "0".repeat(64);
        let timestamp = Utc::now().to_rfc3339();
        let nonce = "test-nonce-123";

        // First request with nonce (will fail due to invalid signature, but nonce will be stored)
        let _ = verifier.verify_signature(
            &public_key,
            &"0".repeat(128),
            b"test message",
            &timestamp,
            Some(nonce),
        );

        // Second request with same nonce should be detected as replay
        let result = verifier.verify_signature(
            &public_key,
            &"0".repeat(128),
            b"test message",
            &timestamp,
            Some(nonce),
        );
        assert!(matches!(result, Err(SignatureError::ReplayAttack)));
    }
}
