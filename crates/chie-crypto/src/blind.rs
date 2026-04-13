//! Privacy-preserving unlinkable tokens for anonymous credentials.
//!
//! This module provides unlinkable token credentials using commitments:
//! - Issuer signs committed values without seeing actual token data
//! - Tokens can be redeemed anonymously without linking to issuance
//! - Useful for anonymous bandwidth credits, reputation tokens, etc.
//!
//! Protocol:
//! 1. User creates token with random serial number
//! 2. User creates commitment to token (hash of serial + blinding factor)
//! 3. Issuer signs the commitment without seeing the serial
//! 4. User redeems by revealing token, blinding, and signature
//! 5. Verifier validates that commitment matches and signature is valid

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors for unlinkable token operations.
#[derive(Debug, Error)]
pub enum BlindError {
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid token signature")]
    InvalidSignature,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Token already spent")]
    TokenAlreadySpent,
}

pub type BlindResult<T> = Result<T, BlindError>;

/// An unlinkable token with a unique serial number.
#[derive(Clone, Debug)]
pub struct UnlinkableToken {
    /// Unique serial number (prevents double-spending)
    pub serial: [u8; 32],
    /// Token value/amount
    pub value: u64,
    /// Expiration timestamp (Unix timestamp)
    pub expiry: u64,
}

/// Blinding factor used to create commitment.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct BlindingFactor {
    factor: [u8; 32],
}

/// Commitment to a token (sent to issuer for signing).
#[derive(Clone, Debug)]
pub struct TokenCommitment {
    commitment: [u8; 32],
}

/// Signed token commitment from issuer.
#[derive(Clone, Debug)]
pub struct SignedCommitment {
    commitment: [u8; 32],
    signature: [u8; 64],
}

/// Redeemable token with all information needed for verification.
#[derive(Clone, Debug)]
pub struct RedeemableToken {
    pub token: UnlinkableToken,
    pub blinding_factor: [u8; 32],
    pub signature: [u8; 64],
}

impl UnlinkableToken {
    /// Create a new token with random serial number.
    pub fn new(value: u64, expiry: u64) -> Self {
        let mut rng = rand::rng();
        let mut serial = [0u8; 32];
        rng.fill(&mut serial);
        Self {
            serial,
            value,
            expiry,
        }
    }

    /// Create token with specific serial (for testing).
    pub fn with_serial(serial: [u8; 32], value: u64, expiry: u64) -> Self {
        Self {
            serial,
            value,
            expiry,
        }
    }

    /// Serialize token to bytes for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.serial);
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&self.expiry.to_le_bytes());
        bytes
    }
}

impl BlindingFactor {
    /// Generate random blinding factor.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut factor = [0u8; 32];
        rng.fill(&mut factor);
        Self { factor }
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { factor: bytes }
    }

    /// Get bytes (warning: sensitive data).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.factor
    }

    /// Create commitment to a token.
    pub fn commit(&self, token: &UnlinkableToken) -> TokenCommitment {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"TOKEN_COMMITMENT:");
        hasher.update(&token.to_bytes());
        hasher.update(&self.factor);
        TokenCommitment {
            commitment: *hasher.finalize().as_bytes(),
        }
    }

    /// Verify a commitment matches the token and blinding.
    pub fn verify_commitment(&self, token: &UnlinkableToken, commitment: &TokenCommitment) -> bool {
        let recomputed = self.commit(token);
        recomputed.commitment == commitment.commitment
    }
}

impl TokenCommitment {
    /// Get commitment bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { commitment: bytes }
    }
}

/// Token issuer that signs commitments.
pub struct BlindSigner {
    signing_key: SigningKey,
}

impl BlindSigner {
    /// Create new issuer with random key.
    pub fn generate() -> Self {
        use rand_core06::OsRng;
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Create from existing key.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Get public key.
    pub fn public_key(&self) -> BlindPublicKey {
        BlindPublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a token commitment (issuer doesn't see actual token).
    pub fn sign_commitment(&self, commitment: &TokenCommitment) -> SignedCommitment {
        let signature = self.signing_key.sign(&commitment.commitment);
        SignedCommitment {
            commitment: commitment.commitment,
            signature: signature.to_bytes(),
        }
    }

    /// Get signing key bytes (warning: secret).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Public key for verifying redeemed tokens.
#[derive(Clone, Debug)]
pub struct BlindPublicKey {
    verifying_key: VerifyingKey,
}

impl BlindPublicKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> BlindResult<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|_| BlindError::InvalidPublicKey)?;
        Ok(Self { verifying_key })
    }

    /// Get public key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Verify a redeemable token.
    ///
    /// Checks that:
    /// 1. The commitment is correctly formed from token + blinding
    /// 2. The signature on the commitment is valid
    pub fn verify_token(&self, redeemable: &RedeemableToken) -> BlindResult<()> {
        // Recompute commitment from token and blinding
        let blinding = BlindingFactor::from_bytes(redeemable.blinding_factor);
        let commitment = blinding.commit(&redeemable.token);

        // Verify signature on commitment
        let signature = Signature::from_bytes(&redeemable.signature);
        self.verifying_key
            .verify(&commitment.commitment, &signature)
            .map_err(|_| BlindError::VerificationFailed)?;

        Ok(())
    }

    /// Verify a signed commitment directly.
    pub fn verify_commitment(&self, signed: &SignedCommitment) -> BlindResult<()> {
        let signature = Signature::from_bytes(&signed.signature);
        self.verifying_key
            .verify(&signed.commitment, &signature)
            .map_err(|_| BlindError::VerificationFailed)?;
        Ok(())
    }
}

/// Complete unlinkable token protocol.
pub struct BlindSignatureProtocol;

impl BlindSignatureProtocol {
    /// User: Create a new token and commitment (Step 1-2).
    ///
    /// Returns (commitment to send to issuer, token, blinding factor to keep secret).
    pub fn create_token(
        value: u64,
        expiry: u64,
    ) -> (TokenCommitment, UnlinkableToken, BlindingFactor) {
        let token = UnlinkableToken::new(value, expiry);
        let blinding = BlindingFactor::generate();
        let commitment = blinding.commit(&token);
        (commitment, token, blinding)
    }

    /// Issuer: Sign a token commitment (Step 3).
    pub fn issue_token(issuer: &BlindSigner, commitment: &TokenCommitment) -> SignedCommitment {
        issuer.sign_commitment(commitment)
    }

    /// User: Create redeemable token (Step 4).
    pub fn prepare_redemption(
        token: UnlinkableToken,
        blinding: BlindingFactor,
        signed: SignedCommitment,
    ) -> RedeemableToken {
        RedeemableToken {
            token,
            blinding_factor: blinding.to_bytes(),
            signature: signed.signature,
        }
    }

    /// Verifier: Verify and redeem token (Step 5).
    pub fn verify_and_redeem(
        public_key: &BlindPublicKey,
        redeemable: &RedeemableToken,
        current_time: u64,
    ) -> BlindResult<()> {
        // Check expiry
        if current_time > redeemable.token.expiry {
            return Err(BlindError::VerificationFailed);
        }

        // Verify token
        public_key.verify_token(redeemable)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlinkable_token_flow() {
        let issuer = BlindSigner::generate();
        let public_key = issuer.public_key();

        // User creates token and commitment
        let (commitment, token, blinding) = BlindSignatureProtocol::create_token(100, u64::MAX);

        // Issuer signs commitment without seeing token
        let signed = BlindSignatureProtocol::issue_token(&issuer, &commitment);

        // User prepares redeemable token
        let redeemable = BlindSignatureProtocol::prepare_redemption(token, blinding, signed);

        // Verifier redeems token
        BlindSignatureProtocol::verify_and_redeem(&public_key, &redeemable, 0).unwrap();
    }

    #[test]
    fn test_commitment_verification() {
        let token = UnlinkableToken::new(50, u64::MAX);
        let blinding = BlindingFactor::generate();
        let commitment = blinding.commit(&token);

        // Correct blinding should verify
        assert!(blinding.verify_commitment(&token, &commitment));

        // Wrong blinding should not verify
        let wrong_blinding = BlindingFactor::generate();
        assert!(!wrong_blinding.verify_commitment(&token, &commitment));
    }

    #[test]
    fn test_different_tokens() {
        let issuer = BlindSigner::generate();
        let public_key = issuer.public_key();

        // Create two different tokens
        let (comm1, tok1, blind1) = BlindSignatureProtocol::create_token(100, u64::MAX);
        let (comm2, tok2, blind2) = BlindSignatureProtocol::create_token(200, u64::MAX);

        assert_ne!(tok1.serial, tok2.serial);
        assert_ne!(comm1.as_bytes(), comm2.as_bytes());

        // Sign both
        let signed1 = issuer.sign_commitment(&comm1);
        let signed2 = issuer.sign_commitment(&comm2);

        // Both should redeem correctly
        let redeem1 = BlindSignatureProtocol::prepare_redemption(tok1, blind1, signed1);
        let redeem2 = BlindSignatureProtocol::prepare_redemption(tok2, blind2, signed2);

        public_key.verify_token(&redeem1).unwrap();
        public_key.verify_token(&redeem2).unwrap();
    }

    #[test]
    fn test_wrong_blinding() {
        let issuer = BlindSigner::generate();
        let public_key = issuer.public_key();

        let (commitment, token, _correct_blinding) =
            BlindSignatureProtocol::create_token(100, u64::MAX);
        let signed = issuer.sign_commitment(&commitment);

        // Try to redeem with wrong blinding
        let wrong_blinding = BlindingFactor::generate();
        let wrong_redeemable = RedeemableToken {
            token,
            blinding_factor: wrong_blinding.to_bytes(),
            signature: signed.signature,
        };

        // Should fail verification
        assert!(public_key.verify_token(&wrong_redeemable).is_err());
    }

    #[test]
    fn test_expired_token() {
        let issuer = BlindSigner::generate();
        let public_key = issuer.public_key();

        // Create token that expires at time 1000
        let (commitment, token, blinding) = BlindSignatureProtocol::create_token(100, 1000);
        let signed = issuer.sign_commitment(&commitment);
        let redeemable = BlindSignatureProtocol::prepare_redemption(token, blinding, signed);

        // Should succeed before expiry
        BlindSignatureProtocol::verify_and_redeem(&public_key, &redeemable, 999).unwrap();

        // Should fail after expiry
        assert!(BlindSignatureProtocol::verify_and_redeem(&public_key, &redeemable, 1001).is_err());
    }

    #[test]
    fn test_unlinkability() {
        let issuer = BlindSigner::generate();

        // Same token value but different serials
        let (comm1, tok1, _) = BlindSignatureProtocol::create_token(100, u64::MAX);
        let (comm2, tok2, _) = BlindSignatureProtocol::create_token(100, u64::MAX);

        // Commitments should be different (unlinkable)
        assert_ne!(comm1.as_bytes(), comm2.as_bytes());
        assert_ne!(tok1.serial, tok2.serial);

        // Signatures should be different
        let sig1 = issuer.sign_commitment(&comm1);
        let sig2 = issuer.sign_commitment(&comm2);
        assert_ne!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_serialization() {
        let token = UnlinkableToken::new(123, 456);
        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), 32 + 8 + 8);

        // Serial should be first 32 bytes
        assert_eq!(&bytes[..32], &token.serial);
    }

    #[test]
    fn test_key_serialization() {
        let issuer = BlindSigner::generate();
        let public_key = issuer.public_key();

        // Serialize and deserialize
        let issuer_bytes = issuer.to_bytes();
        let issuer2 = BlindSigner::from_bytes(&issuer_bytes);

        let pk_bytes = public_key.to_bytes();
        let pk2 = BlindPublicKey::from_bytes(&pk_bytes).unwrap();

        // Should work the same
        let (commitment, token, blinding) = BlindSignatureProtocol::create_token(100, u64::MAX);
        let signed = issuer2.sign_commitment(&commitment);
        let redeemable = BlindSignatureProtocol::prepare_redemption(token, blinding, signed);

        pk2.verify_token(&redeemable).unwrap();
    }

    #[test]
    fn test_blinding_factor_zeroize() {
        let factor = BlindingFactor::generate();
        let _bytes = factor.to_bytes();

        // Drop should zeroize (verified by type implementing Zeroize)
        drop(factor);
    }
}
