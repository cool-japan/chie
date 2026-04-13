//! Adaptor Signatures for Atomic Swaps.
//!
//! Adaptor signatures enable atomic swaps and scriptless scripts by "locking"
//! a signature to a secret value. Once the signature is published, the secret
//! is automatically revealed, enabling trustless cross-chain atomic swaps.
//!
//! # Protocol Overview
//!
//! 1. Alice generates a secret `t` and publishes the adaptor point `T = t*G`
//! 2. Bob creates a pre-signature that's "locked" to `T`
//! 3. Alice can verify the pre-signature is correct
//! 4. Alice completes the signature using her secret `t`
//! 5. When Alice publishes the complete signature, Bob can extract `t`
//! 6. Bob can now use `t` to claim funds on another chain
//!
//! # Example
//!
//! ```
//! use chie_crypto::adaptor::*;
//!
//! // Alice generates a secret for the atomic swap
//! let secret = AdaptorSecret::random();
//! let adaptor_point = secret.to_point();
//!
//! // Bob creates a locked signature
//! let signer = AdaptorSigner::new();
//! let message = b"Payment to Alice";
//!
//! let pre_sig = signer.create_pre_signature_with_secret(message, &secret).unwrap();
//!
//! // Alice verifies the pre-signature is valid
//! assert!(verify_pre_signature(&signer.public_key(), message, &pre_sig, &adaptor_point));
//!
//! // Alice completes the signature using her secret
//! let complete_sig = complete_signature(&pre_sig, &secret).unwrap();
//!
//! // Alice publishes the complete signature
//! assert!(verify_adaptor_signature(&signer.public_key(), message, &complete_sig));
//!
//! // Bob extracts Alice's secret from the signatures
//! let extracted = extract_secret(&pre_sig, &complete_sig, &adaptor_point).unwrap();
//! assert_eq!(secret.to_bytes(), extracted.to_bytes());
//! ```

use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdaptorError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid adaptor point")]
    InvalidAdaptorPoint,
    #[error("Secret extraction failed")]
    SecretExtractionFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type AdaptorResult<T> = Result<T, AdaptorError>;

/// Generate a random scalar
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

/// Secret key for adaptor signatures
#[derive(Clone, Serialize, Deserialize)]
pub struct AdaptorSecretKey(Scalar);

/// Public key for adaptor signatures
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AdaptorPublicKey(RistrettoPoint);

/// The secret value used to lock/unlock signatures
#[derive(Clone, Serialize, Deserialize)]
pub struct AdaptorSecret(Scalar);

/// The public adaptor point (commitment to the secret)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AdaptorPoint(RistrettoPoint);

/// Signer for adaptor signatures
#[derive(Clone)]
pub struct AdaptorSigner {
    secret_key: AdaptorSecretKey,
    public_key: AdaptorPublicKey,
}

/// Pre-signature (locked to an adaptor point)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PreSignature {
    r_prime: RistrettoPoint, // R' = R + T
    s_prime: Scalar,         // s' (partial signature)
}

/// Complete signature (standard Schnorr signature)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AdaptorSignature {
    r: RistrettoPoint,
    s: Scalar,
}

impl AdaptorSecret {
    /// Generate a random secret
    pub fn random() -> Self {
        Self(random_scalar())
    }

    /// Create secret from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(*bytes))
    }

    /// Export secret to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the adaptor point (public commitment)
    pub fn to_point(&self) -> AdaptorPoint {
        AdaptorPoint(RISTRETTO_BASEPOINT_POINT * self.0)
    }
}

impl AdaptorPoint {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> AdaptorResult<Self> {
        let point = curve25519_dalek::ristretto::CompressedRistretto(*bytes)
            .decompress()
            .ok_or(AdaptorError::InvalidAdaptorPoint)?;
        Ok(Self(point))
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

impl AdaptorSigner {
    /// Create a new random signer
    pub fn new() -> Self {
        let secret = random_scalar();
        let public = RISTRETTO_BASEPOINT_POINT * secret;

        Self {
            secret_key: AdaptorSecretKey(secret),
            public_key: AdaptorPublicKey(public),
        }
    }

    /// Create from secret key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> AdaptorResult<Self> {
        let secret = Scalar::from_bytes_mod_order(*bytes);
        let public = RISTRETTO_BASEPOINT_POINT * secret;

        Ok(Self {
            secret_key: AdaptorSecretKey(secret),
            public_key: AdaptorPublicKey(public),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> AdaptorPublicKey {
        self.public_key
    }

    /// Export secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.0.to_bytes()
    }

    /// Create a pre-signature (locked to adaptor point)
    ///
    /// This creates a signature that can only be completed by someone who knows
    /// the adaptor secret `t` corresponding to the adaptor point `T = t*G`.
    ///
    /// The pre-signature is (R', s') where R' = R + T and s' = k + c*x (standard Schnorr).
    /// To complete, the holder of t computes s = s' + t.
    pub fn create_pre_signature_with_secret(
        &self,
        message: &[u8],
        adaptor_secret: &AdaptorSecret,
    ) -> AdaptorResult<PreSignature> {
        let adaptor = adaptor_secret.to_point();

        // Generate nonce
        let k = random_scalar();
        let r = RISTRETTO_BASEPOINT_POINT * k;

        // R' = R + T (this is what gets transmitted)
        let r_prime = r + adaptor.0;

        // Compute challenge: c = H(R', X, m) - use R'!
        let challenge = compute_challenge(&r_prime, &self.public_key, message);

        // s' = k + c*x (standard Schnorr, NO adaptor secret!)
        let s_prime = k + challenge * self.secret_key.0;

        Ok(PreSignature { r_prime, s_prime })
    }

    /// Create a pre-signature (for compatibility - same as create_pre_signature_with_secret)
    ///
    /// Note: This version requires the adaptor point but internally needs the secret.
    /// This is a simplified API. For proper adaptor signatures where the signer
    /// doesn't know the adaptor secret, see ECDSA adaptor signatures.
    pub fn create_pre_signature(
        &self,
        message: &[u8],
        adaptor: &AdaptorPoint,
    ) -> AdaptorResult<PreSignature> {
        // For this simplified version, we generate a temporary secret
        // In practice, the adaptor secret should be provided by the protocol

        // Generate nonce
        let k = random_scalar();
        let r = RISTRETTO_BASEPOINT_POINT * k;

        // R' = R + T
        let r_prime = r + adaptor.0;

        // Compute challenge: c = H(R', X, m)
        let challenge = compute_challenge(&r_prime, &self.public_key, message);

        // For now, create a standard signature that can be verified
        // s' = k + c*x (we can't include t since we don't have it)
        let s_prime = k + challenge * self.secret_key.0;

        Ok(PreSignature { r_prime, s_prime })
    }
}

impl Default for AdaptorSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptorPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> AdaptorResult<Self> {
        let point = curve25519_dalek::ristretto::CompressedRistretto(*bytes)
            .decompress()
            .ok_or(AdaptorError::InvalidPublicKey)?;
        Ok(Self(point))
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// Compute challenge for Schnorr signature
fn compute_challenge(r: &RistrettoPoint, pubkey: &AdaptorPublicKey, message: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&r.compress().to_bytes());
    hasher.update(&pubkey.0.compress().to_bytes());
    hasher.update(message);

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(*hash.as_bytes())
}

/// Verify a pre-signature is valid
///
/// Checks that s'*G = R + c*X where R = R' - T and c = H(R', X, m)
pub fn verify_pre_signature(
    pubkey: &AdaptorPublicKey,
    message: &[u8],
    pre_sig: &PreSignature,
    adaptor: &AdaptorPoint,
) -> bool {
    // Recover R = R' - T
    let r = pre_sig.r_prime - adaptor.0;

    // Compute challenge: c = H(R', X, m) - using R'!
    let challenge = compute_challenge(&pre_sig.r_prime, pubkey, message);

    // Verify: s'*G = R + c*X
    let lhs = RISTRETTO_BASEPOINT_POINT * pre_sig.s_prime;
    let rhs = r + challenge * pubkey.0;

    lhs == rhs
}

/// Complete a pre-signature using the adaptor secret
///
/// Given a pre-signature (R', s') where s' = k + c*x,
/// this produces a complete signature (R', s) where s = s' + t.
pub fn complete_signature(
    pre_sig: &PreSignature,
    secret: &AdaptorSecret,
) -> AdaptorResult<AdaptorSignature> {
    // R stays as R'
    let r = pre_sig.r_prime;

    // s = s' + t (ADD the adaptor secret!)
    let s = pre_sig.s_prime + secret.0;

    Ok(AdaptorSignature { r, s })
}

/// Verify a complete adaptor signature
pub fn verify_adaptor_signature(
    pubkey: &AdaptorPublicKey,
    message: &[u8],
    signature: &AdaptorSignature,
) -> bool {
    // Compute challenge: c = H(R, X, m)
    let challenge = compute_challenge(&signature.r, pubkey, message);

    // Verify standard Schnorr signature: s*G = R + c*X
    let lhs = RISTRETTO_BASEPOINT_POINT * signature.s;
    let rhs = signature.r + challenge * pubkey.0;

    lhs == rhs
}

/// Extract the secret from pre-signature and complete signature
///
/// Given s' and s where s = s' + t, this computes t = s - s'.
pub fn extract_secret(
    pre_sig: &PreSignature,
    complete_sig: &AdaptorSignature,
    adaptor: &AdaptorPoint,
) -> AdaptorResult<AdaptorSecret> {
    // t = s - s' (since s = s' + t)
    let t = complete_sig.s - pre_sig.s_prime;

    // Verify: T = t*G
    let computed_adaptor = RISTRETTO_BASEPOINT_POINT * t;
    if computed_adaptor != adaptor.0 {
        return Err(AdaptorError::SecretExtractionFailed);
    }

    Ok(AdaptorSecret(t))
}

impl PreSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r_prime.compress().to_bytes());
        bytes[32..].copy_from_slice(&self.s_prime.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> AdaptorResult<Self> {
        let r_prime =
            curve25519_dalek::ristretto::CompressedRistretto(bytes[..32].try_into().unwrap())
                .decompress()
                .ok_or(AdaptorError::InvalidSignature)?;
        let s_prime = Scalar::from_bytes_mod_order(bytes[32..].try_into().unwrap());

        Ok(Self { r_prime, s_prime })
    }
}

impl AdaptorSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r.compress().to_bytes());
        bytes[32..].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> AdaptorResult<Self> {
        let r = curve25519_dalek::ristretto::CompressedRistretto(bytes[..32].try_into().unwrap())
            .decompress()
            .ok_or(AdaptorError::InvalidSignature)?;
        let s = Scalar::from_bytes_mod_order(bytes[32..].try_into().unwrap());

        Ok(Self { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptor_basic() {
        let secret = AdaptorSecret::random();
        let adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        assert!(verify_pre_signature(
            &signer.public_key(),
            message,
            &pre_sig,
            &adaptor
        ));

        let complete_sig = complete_signature(&pre_sig, &secret).unwrap();
        assert!(verify_adaptor_signature(
            &signer.public_key(),
            message,
            &complete_sig
        ));

        let extracted = extract_secret(&pre_sig, &complete_sig, &adaptor).unwrap();
        assert_eq!(secret.to_bytes(), extracted.to_bytes());
    }

    #[test]
    fn test_adaptor_wrong_secret() {
        let secret = AdaptorSecret::random();
        let _adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();

        // Use wrong secret to complete
        let wrong_secret = AdaptorSecret::random();
        let complete_sig = complete_signature(&pre_sig, &wrong_secret).unwrap();

        // Signature won't verify
        assert!(!verify_adaptor_signature(
            &signer.public_key(),
            message,
            &complete_sig
        ));
    }

    #[test]
    fn test_adaptor_wrong_message() {
        let secret = AdaptorSecret::random();
        let _adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Original message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        let complete_sig = complete_signature(&pre_sig, &secret).unwrap();

        // Verify with wrong message
        assert!(!verify_adaptor_signature(
            &signer.public_key(),
            b"Wrong message",
            &complete_sig
        ));
    }

    #[test]
    fn test_secret_extraction_fails_wrong_adaptor() {
        let secret = AdaptorSecret::random();
        let _adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        let complete_sig = complete_signature(&pre_sig, &secret).unwrap();

        // Try to extract with wrong adaptor
        let wrong_adaptor = AdaptorSecret::random().to_point();
        let result = extract_secret(&pre_sig, &complete_sig, &wrong_adaptor);
        assert!(result.is_err());
    }

    #[test]
    fn test_pre_signature_serialization() {
        let secret = AdaptorSecret::random();
        let adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        let bytes = pre_sig.to_bytes();
        let recovered = PreSignature::from_bytes(&bytes).unwrap();

        assert!(verify_pre_signature(
            &signer.public_key(),
            message,
            &recovered,
            &adaptor
        ));
    }

    #[test]
    fn test_complete_signature_serialization() {
        let secret = AdaptorSecret::random();
        let _adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        let complete_sig = complete_signature(&pre_sig, &secret).unwrap();

        let bytes = complete_sig.to_bytes();
        let recovered = AdaptorSignature::from_bytes(&bytes).unwrap();

        assert!(verify_adaptor_signature(
            &signer.public_key(),
            message,
            &recovered
        ));
    }

    #[test]
    fn test_signer_serialization() {
        let signer = AdaptorSigner::new();
        let bytes = signer.to_bytes();
        let recovered = AdaptorSigner::from_bytes(&bytes).unwrap();

        assert_eq!(
            signer.public_key().to_bytes(),
            recovered.public_key().to_bytes()
        );
    }

    #[test]
    fn test_secret_serialization() {
        let secret = AdaptorSecret::random();
        let bytes = secret.to_bytes();
        let recovered = AdaptorSecret::from_bytes(&bytes);

        assert_eq!(secret.to_bytes(), recovered.to_bytes());
        assert_eq!(
            secret.to_point().to_bytes(),
            recovered.to_point().to_bytes()
        );
    }

    #[test]
    fn test_adaptor_point_serialization() {
        let secret = AdaptorSecret::random();
        let adaptor = secret.to_point();

        let bytes = adaptor.to_bytes();
        let recovered = AdaptorPoint::from_bytes(&bytes).unwrap();

        assert_eq!(adaptor.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_multiple_pre_signatures_same_message() {
        let secret = AdaptorSecret::random();
        let adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Same message";

        let pre_sig1 = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();
        let pre_sig2 = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();

        // Both pre-signatures should be valid
        assert!(verify_pre_signature(
            &signer.public_key(),
            message,
            &pre_sig1,
            &adaptor
        ));
        assert!(verify_pre_signature(
            &signer.public_key(),
            message,
            &pre_sig2,
            &adaptor
        ));

        // But they should be different (different nonces)
        assert_ne!(pre_sig1.to_bytes(), pre_sig2.to_bytes());
    }

    #[test]
    fn test_atomic_swap_scenario() {
        // Alice and Bob want to do an atomic swap
        // Alice generates a secret
        let alice_secret = AdaptorSecret::random();
        let adaptor = alice_secret.to_point();

        // Bob creates a locked payment to Alice
        let bob = AdaptorSigner::new();
        let payment_to_alice = b"Payment from Bob to Alice for 1 BTC";

        let pre_sig = bob
            .create_pre_signature_with_secret(payment_to_alice, &alice_secret)
            .unwrap();

        // Alice verifies Bob's pre-signature
        assert!(verify_pre_signature(
            &bob.public_key(),
            payment_to_alice,
            &pre_sig,
            &adaptor
        ));

        // Alice completes the signature to claim the payment
        let complete_sig = complete_signature(&pre_sig, &alice_secret).unwrap();
        assert!(verify_adaptor_signature(
            &bob.public_key(),
            payment_to_alice,
            &complete_sig
        ));

        // Bob extracts Alice's secret from the published signature
        let extracted_secret = extract_secret(&pre_sig, &complete_sig, &adaptor).unwrap();
        assert_eq!(alice_secret.to_bytes(), extracted_secret.to_bytes());

        // Bob can now use the secret to claim funds on another chain
    }

    #[test]
    fn test_public_key_serialization() {
        let signer = AdaptorSigner::new();
        let pubkey = signer.public_key();

        let bytes = pubkey.to_bytes();
        let recovered = AdaptorPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(pubkey.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_deterministic_completion() {
        let secret = AdaptorSecret::random();
        let _adaptor = secret.to_point();

        let signer = AdaptorSigner::new();
        let message = b"Test message";

        let pre_sig = signer
            .create_pre_signature_with_secret(message, &secret)
            .unwrap();

        // Complete the same pre-signature twice
        let sig1 = complete_signature(&pre_sig, &secret).unwrap();
        let sig2 = complete_signature(&pre_sig, &secret).unwrap();

        // Should produce identical signatures
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
