//! Digital signatures using Ed25519.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Secret key for signing (32 bytes).
pub type SecretKey = [u8; 32];

/// Public key for verification (32 bytes).
pub type PublicKey = [u8; 32];

/// Signature (64 bytes).
pub type SignatureBytes = [u8; 64];

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Key pair for signing and verification.
///
/// The secret key material is automatically zeroized when dropped.
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        // Clone by reconstructing from secret key bytes
        let secret = self.signing_key.to_bytes();
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("Failed to generate random bytes");
        let signing_key = SigningKey::from_bytes(&secret);
        Self { signing_key }
    }

    /// Create a key pair from a secret key.
    pub fn from_secret_key(secret: &SecretKey) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_bytes(secret);
        Ok(Self { signing_key })
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> SecretKey {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> PublicKey {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Verify a signature using this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        verify(&self.public_key(), message, &sig_bytes).is_ok()
    }
}

/// Verify a signature.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), SigningError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SigningError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(signature);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| SigningError::VerificationFailed)
}

/// Item for batch verification.
#[derive(Debug, Clone)]
pub struct BatchVerifyItem {
    /// Public key for verification.
    pub public_key: PublicKey,
    /// Message that was signed.
    pub message: Vec<u8>,
    /// Signature to verify.
    pub signature: SignatureBytes,
}

impl BatchVerifyItem {
    /// Create a new batch verification item.
    pub fn new(public_key: PublicKey, message: Vec<u8>, signature: SignatureBytes) -> Self {
        Self {
            public_key,
            message,
            signature,
        }
    }
}

/// Result of batch verification.
#[derive(Debug, Clone)]
pub struct BatchVerifyResult {
    /// Total items verified.
    pub total: usize,
    /// Number of valid signatures.
    pub valid_count: usize,
    /// Number of invalid signatures.
    pub invalid_count: usize,
    /// Indices of invalid signatures (if tracking enabled).
    pub invalid_indices: Vec<usize>,
    /// Whether all signatures are valid.
    pub all_valid: bool,
}

/// Verify multiple signatures in batch.
///
/// This is more efficient than verifying signatures individually as it can
/// use batch verification optimizations. However, if any signature is invalid,
/// it falls back to individual verification to identify which ones failed.
pub fn verify_batch(items: &[BatchVerifyItem]) -> Result<BatchVerifyResult, SigningError> {
    if items.is_empty() {
        return Ok(BatchVerifyResult {
            total: 0,
            valid_count: 0,
            invalid_count: 0,
            invalid_indices: vec![],
            all_valid: true,
        });
    }

    // Prepare vectors for batch verification
    let mut verifying_keys = Vec::with_capacity(items.len());
    let mut signatures = Vec::with_capacity(items.len());
    let messages: Vec<&[u8]> = items.iter().map(|item| item.message.as_slice()).collect();

    for item in items {
        let vk = VerifyingKey::from_bytes(&item.public_key)
            .map_err(|_| SigningError::InvalidPublicKey)?;
        let sig = Signature::from_bytes(&item.signature);
        verifying_keys.push(vk);
        signatures.push(sig);
    }

    // Try batch verification first
    let batch_result = ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys);

    if batch_result.is_ok() {
        // All signatures valid
        return Ok(BatchVerifyResult {
            total: items.len(),
            valid_count: items.len(),
            invalid_count: 0,
            invalid_indices: vec![],
            all_valid: true,
        });
    }

    // Batch failed - verify individually to find which ones failed
    let mut invalid_indices = Vec::new();
    let mut valid_count = 0;

    for (i, item) in items.iter().enumerate() {
        match verify(&item.public_key, &item.message, &item.signature) {
            Ok(()) => valid_count += 1,
            Err(_) => invalid_indices.push(i),
        }
    }

    Ok(BatchVerifyResult {
        total: items.len(),
        valid_count,
        invalid_count: invalid_indices.len(),
        invalid_indices,
        all_valid: false,
    })
}

/// Verify multiple signatures, returning only success/failure.
///
/// This is a faster version that doesn't track which signatures failed.
pub fn verify_batch_fast(items: &[BatchVerifyItem]) -> bool {
    if items.is_empty() {
        return true;
    }

    // Prepare vectors for batch verification
    let mut verifying_keys = Vec::with_capacity(items.len());
    let mut signatures = Vec::with_capacity(items.len());
    let messages: Vec<&[u8]> = items.iter().map(|item| item.message.as_slice()).collect();

    for item in items {
        match VerifyingKey::from_bytes(&item.public_key) {
            Ok(vk) => verifying_keys.push(vk),
            Err(_) => return false,
        }
        signatures.push(Signature::from_bytes(&item.signature));
    }

    ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys).is_ok()
}

/// Verify dual signatures (provider + requester) common in CHIE Protocol.
pub fn verify_dual_signatures(
    provider_pubkey: &PublicKey,
    requester_pubkey: &PublicKey,
    provider_message: &[u8],
    requester_message: &[u8],
    provider_signature: &SignatureBytes,
    requester_signature: &SignatureBytes,
) -> Result<(), SigningError> {
    let items = vec![
        BatchVerifyItem::new(
            *provider_pubkey,
            provider_message.to_vec(),
            *provider_signature,
        ),
        BatchVerifyItem::new(
            *requester_pubkey,
            requester_message.to_vec(),
            *requester_signature,
        ),
    ];

    let result = verify_batch(&items)?;
    if result.all_valid {
        Ok(())
    } else {
        Err(SigningError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let keypair = KeyPair::generate();
        let message = b"Hello, CHIE Protocol!";

        let signature = keypair.sign(message);
        let public_key = keypair.public_key();

        assert!(verify(&public_key, message, &signature).is_ok());
        assert!(verify(&public_key, b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_keypair_from_secret() {
        let keypair1 = KeyPair::generate();
        let secret = keypair1.secret_key();
        let keypair2 = KeyPair::from_secret_key(&secret).unwrap();

        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_verify_with_wrong_public_key() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let message = b"Test message";

        let signature = keypair1.sign(message);
        let wrong_pubkey = keypair2.public_key();

        let result = verify(&wrong_pubkey, message, &signature);
        assert!(result.is_err());
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_invalid_signature_format() {
        let keypair = KeyPair::generate();
        let message = b"Test message";

        let mut signature = keypair.sign(message);
        // Corrupt the signature
        signature[0] ^= 0xFF;

        let result = verify(&keypair.public_key(), message, &signature);
        assert!(result.is_err());
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_keypair_verify_method() {
        let keypair = KeyPair::generate();
        let message = b"Test message";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));
        assert!(!keypair.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_keypair_verify_invalid_signature_length() {
        let keypair = KeyPair::generate();
        let message = b"Test message";

        // Too short signature
        let short_sig = [0u8; 32];
        assert!(!keypair.verify(message, &short_sig));

        // Too long signature
        let long_sig = [0u8; 96];
        assert!(!keypair.verify(message, &long_sig));
    }

    #[test]
    fn test_batch_verify_all_valid() {
        let mut items = Vec::new();
        for _ in 0..10 {
            let keypair = KeyPair::generate();
            let message = b"Test message";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                message.to_vec(),
                signature,
            ));
        }

        let result = verify_batch(&items).unwrap();
        assert_eq!(result.total, 10);
        assert_eq!(result.valid_count, 10);
        assert_eq!(result.invalid_count, 0);
        assert!(result.all_valid);
        assert!(result.invalid_indices.is_empty());
    }

    #[test]
    fn test_batch_verify_some_invalid() {
        let mut items = Vec::new();

        // Add 5 valid signatures
        for _ in 0..5 {
            let keypair = KeyPair::generate();
            let message = b"Valid message";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                message.to_vec(),
                signature,
            ));
        }

        // Add 3 invalid signatures
        for _ in 0..3 {
            let keypair = KeyPair::generate();
            let message = b"Original message";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                b"Different message".to_vec(), // Wrong message!
                signature,
            ));
        }

        let result = verify_batch(&items).unwrap();
        assert_eq!(result.total, 8);
        assert_eq!(result.valid_count, 5);
        assert_eq!(result.invalid_count, 3);
        assert!(!result.all_valid);
        assert_eq!(result.invalid_indices, vec![5, 6, 7]);
    }

    #[test]
    fn test_batch_verify_empty() {
        let items = vec![];
        let result = verify_batch(&items).unwrap();
        assert_eq!(result.total, 0);
        assert_eq!(result.valid_count, 0);
        assert_eq!(result.invalid_count, 0);
        assert!(result.all_valid);
    }

    #[test]
    fn test_batch_verify_fast_all_valid() {
        let mut items = Vec::new();
        for _ in 0..10 {
            let keypair = KeyPair::generate();
            let message = b"Test message";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                message.to_vec(),
                signature,
            ));
        }

        assert!(verify_batch_fast(&items));
    }

    #[test]
    fn test_batch_verify_fast_one_invalid() {
        let mut items = Vec::new();

        // Add valid signatures
        for _ in 0..5 {
            let keypair = KeyPair::generate();
            let message = b"Valid message";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                message.to_vec(),
                signature,
            ));
        }

        // Add one invalid signature
        let keypair = KeyPair::generate();
        let signature = keypair.sign(b"Original");
        items.push(BatchVerifyItem::new(
            keypair.public_key(),
            b"Modified".to_vec(),
            signature,
        ));

        assert!(!verify_batch_fast(&items));
    }

    #[test]
    fn test_batch_verify_fast_empty() {
        let items = vec![];
        assert!(verify_batch_fast(&items));
    }

    #[test]
    fn test_dual_signatures_valid() {
        let provider = KeyPair::generate();
        let requester = KeyPair::generate();

        let provider_msg = b"Provider proof";
        let requester_msg = b"Requester proof";

        let provider_sig = provider.sign(provider_msg);
        let requester_sig = requester.sign(requester_msg);

        let result = verify_dual_signatures(
            &provider.public_key(),
            &requester.public_key(),
            provider_msg,
            requester_msg,
            &provider_sig,
            &requester_sig,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_dual_signatures_invalid_provider() {
        let provider = KeyPair::generate();
        let requester = KeyPair::generate();

        let provider_msg = b"Provider proof";
        let requester_msg = b"Requester proof";

        let provider_sig = provider.sign(b"Wrong message");
        let requester_sig = requester.sign(requester_msg);

        let result = verify_dual_signatures(
            &provider.public_key(),
            &requester.public_key(),
            provider_msg,
            requester_msg,
            &provider_sig,
            &requester_sig,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_dual_signatures_invalid_requester() {
        let provider = KeyPair::generate();
        let requester = KeyPair::generate();

        let provider_msg = b"Provider proof";
        let requester_msg = b"Requester proof";

        let provider_sig = provider.sign(provider_msg);
        let requester_sig = requester.sign(b"Wrong message");

        let result = verify_dual_signatures(
            &provider.public_key(),
            &requester.public_key(),
            provider_msg,
            requester_msg,
            &provider_sig,
            &requester_sig,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_keypair_clone() {
        let keypair1 = KeyPair::generate();
        let keypair2 = keypair1.clone();

        let message = b"Test message";
        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);

        // Both signatures should be valid with either public key
        assert!(verify(&keypair1.public_key(), message, &sig1).is_ok());
        assert!(verify(&keypair2.public_key(), message, &sig2).is_ok());
        assert!(verify(&keypair1.public_key(), message, &sig2).is_ok());
        assert!(verify(&keypair2.public_key(), message, &sig1).is_ok());

        // Public keys should be identical
        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_signature_determinism() {
        let keypair = KeyPair::generate();
        let message = b"Deterministic test";

        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        // Ed25519 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let keypair = KeyPair::generate();
        let message1 = b"First message";
        let message2 = b"Second message";

        let sig1 = keypair.sign(message1);
        let sig2 = keypair.sign(message2);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_keypair_generation_randomness() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        // All keypairs should have different public keys
        assert_ne!(keypair1.public_key(), keypair2.public_key());
        assert_ne!(keypair2.public_key(), keypair3.public_key());
        assert_ne!(keypair1.public_key(), keypair3.public_key());
    }
}
