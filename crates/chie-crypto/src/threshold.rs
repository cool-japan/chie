//! Threshold signatures and multi-signature schemes.
//!
//! This module provides simple threshold signature functionality
//! for scenarios where multiple parties need to sign together.

use crate::{PublicKey, SignatureBytes};
use thiserror::Error;

/// Threshold signature error types.
#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("Not enough signatures: need {threshold}, got {actual}")]
    InsufficientSignatures { threshold: usize, actual: usize },

    #[error("Invalid signature at index {0}")]
    InvalidSignature(usize),

    #[error("Duplicate public key")]
    DuplicatePublicKey,

    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("Signing error: {0}")]
    SigningError(#[from] crate::SigningError),
}

/// Multi-signature aggregator.
///
/// This aggregates signatures from multiple parties on the same message.
/// All parties must sign for the multi-sig to be valid.
#[derive(Debug, Clone)]
pub struct MultiSig {
    /// Public keys of all signers.
    pub signers: Vec<PublicKey>,
    /// Signatures from each signer (must be in same order as signers).
    pub signatures: Vec<SignatureBytes>,
}

impl MultiSig {
    /// Create a new multi-signature.
    pub fn new(signers: Vec<PublicKey>, signatures: Vec<SignatureBytes>) -> Self {
        Self {
            signers,
            signatures,
        }
    }

    /// Verify all signatures.
    pub fn verify(&self, message: &[u8]) -> Result<(), ThresholdError> {
        use crate::signing::verify;

        if self.signers.len() != self.signatures.len() {
            return Err(ThresholdError::InsufficientSignatures {
                threshold: self.signers.len(),
                actual: self.signatures.len(),
            });
        }

        for (i, (pubkey, sig)) in self.signers.iter().zip(self.signatures.iter()).enumerate() {
            verify(pubkey, message, sig).map_err(|_| ThresholdError::InvalidSignature(i))?;
        }

        Ok(())
    }

    /// Get the number of signers.
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }
}

/// Threshold signature scheme (M-of-N).
///
/// Requires at least M signatures out of N possible signers.
#[derive(Debug, Clone)]
pub struct ThresholdSig {
    /// All possible signers (N).
    pub possible_signers: Vec<PublicKey>,
    /// Minimum required signatures (M).
    pub threshold: usize,
    /// Actual signatures provided (pubkey, signature pairs).
    pub signatures: Vec<(PublicKey, SignatureBytes)>,
}

impl ThresholdSig {
    /// Create a new threshold signature.
    pub fn new(possible_signers: Vec<PublicKey>, threshold: usize) -> Result<Self, ThresholdError> {
        if threshold == 0 || threshold > possible_signers.len() {
            return Err(ThresholdError::InvalidThreshold(format!(
                "threshold must be 1 <= M <= {}, got {}",
                possible_signers.len(),
                threshold
            )));
        }

        // Check for duplicates
        let mut sorted = possible_signers.clone();
        sorted.sort();
        for i in 1..sorted.len() {
            if sorted[i] == sorted[i - 1] {
                return Err(ThresholdError::DuplicatePublicKey);
            }
        }

        Ok(Self {
            possible_signers,
            threshold,
            signatures: Vec::new(),
        })
    }

    /// Add a signature from one of the signers.
    pub fn add_signature(
        &mut self,
        signer: PublicKey,
        signature: SignatureBytes,
    ) -> Result<(), ThresholdError> {
        // Check the signer is in the possible signers list
        if !self.possible_signers.contains(&signer) {
            return Err(ThresholdError::InvalidSignature(0));
        }

        // Check for duplicate signature from same signer
        if self.signatures.iter().any(|(pk, _)| pk == &signer) {
            return Err(ThresholdError::DuplicatePublicKey);
        }

        self.signatures.push((signer, signature));
        Ok(())
    }

    /// Verify the threshold signature.
    pub fn verify(&self, message: &[u8]) -> Result<(), ThresholdError> {
        use crate::signing::verify;

        if self.signatures.len() < self.threshold {
            return Err(ThresholdError::InsufficientSignatures {
                threshold: self.threshold,
                actual: self.signatures.len(),
            });
        }

        // Verify each signature
        for (i, (pubkey, sig)) in self.signatures.iter().enumerate() {
            // Ensure the signer is in the allowed list
            if !self.possible_signers.contains(pubkey) {
                return Err(ThresholdError::InvalidSignature(i));
            }

            // Verify the signature
            verify(pubkey, message, sig).map_err(|_| ThresholdError::InvalidSignature(i))?;
        }

        Ok(())
    }

    /// Check if threshold is met.
    pub fn is_complete(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    /// Get the number of signatures collected.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

/// Multi-party signature builder for collecting signatures.
pub struct MultiSigBuilder {
    signers: Vec<PublicKey>,
    signatures: Vec<Option<SignatureBytes>>,
}

impl MultiSigBuilder {
    /// Create a new multi-sig builder.
    pub fn new(signers: Vec<PublicKey>) -> Self {
        let count = signers.len();
        Self {
            signers,
            signatures: vec![None; count],
        }
    }

    /// Add a signature from a signer.
    pub fn add_signature(
        &mut self,
        signer: &PublicKey,
        signature: SignatureBytes,
    ) -> Result<(), ThresholdError> {
        let index = self
            .signers
            .iter()
            .position(|pk| pk == signer)
            .ok_or(ThresholdError::InvalidSignature(0))?;

        self.signatures[index] = Some(signature);
        Ok(())
    }

    /// Check if all signatures are collected.
    pub fn is_complete(&self) -> bool {
        self.signatures.iter().all(|s| s.is_some())
    }

    /// Build the final multi-signature.
    pub fn build(self) -> Result<MultiSig, ThresholdError> {
        let signatures: Option<Vec<SignatureBytes>> = self.signatures.into_iter().collect();

        match signatures {
            Some(sigs) => Ok(MultiSig::new(self.signers, sigs)),
            None => Err(ThresholdError::InsufficientSignatures {
                threshold: self.signers.len(),
                actual: 0,
            }),
        }
    }
}

/// Simple coordinator-based threshold signing.
///
/// This provides a simple threshold signing scheme where a coordinator
/// collects partial signatures and combines them.
pub struct ThresholdCoordinator {
    /// Threshold signature being built.
    threshold_sig: ThresholdSig,
    /// Message being signed.
    message: Vec<u8>,
}

impl ThresholdCoordinator {
    /// Create a new threshold coordinator.
    pub fn new(
        possible_signers: Vec<PublicKey>,
        threshold: usize,
        message: Vec<u8>,
    ) -> Result<Self, ThresholdError> {
        let threshold_sig = ThresholdSig::new(possible_signers, threshold)?;

        Ok(Self {
            threshold_sig,
            message,
        })
    }

    /// Add a signature from a participant.
    pub fn add_signature(
        &mut self,
        signer: PublicKey,
        signature: SignatureBytes,
    ) -> Result<(), ThresholdError> {
        use crate::signing::verify;

        // Verify the signature before adding
        verify(&signer, &self.message, &signature)?;

        self.threshold_sig.add_signature(signer, signature)
    }

    /// Check if threshold is met.
    pub fn is_complete(&self) -> bool {
        self.threshold_sig.is_complete()
    }

    /// Finalize and get the threshold signature.
    pub fn finalize(self) -> Result<ThresholdSig, ThresholdError> {
        if !self.threshold_sig.is_complete() {
            return Err(ThresholdError::InsufficientSignatures {
                threshold: self.threshold_sig.threshold,
                actual: self.threshold_sig.signature_count(),
            });
        }

        Ok(self.threshold_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_multi_sig() {
        let message = b"Multi-sig test message";

        // Create 3 signers
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();

        let signers = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let signatures = vec![kp1.sign(message), kp2.sign(message), kp3.sign(message)];

        let multi_sig = MultiSig::new(signers, signatures);
        assert!(multi_sig.verify(message).is_ok());
    }

    #[test]
    fn test_multi_sig_invalid() {
        let message = b"Test message";
        let wrong_message = b"Wrong message";

        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        let signers = vec![kp1.public_key(), kp2.public_key()];
        let signatures = vec![kp1.sign(message), kp2.sign(wrong_message)];

        let multi_sig = MultiSig::new(signers, signatures);
        assert!(multi_sig.verify(message).is_err());
    }

    #[test]
    fn test_threshold_sig_2_of_3() {
        let message = b"Threshold sig test";

        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();

        let possible_signers = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let mut threshold_sig = ThresholdSig::new(possible_signers, 2).unwrap();

        // Add first signature
        threshold_sig
            .add_signature(kp1.public_key(), kp1.sign(message))
            .unwrap();
        assert!(!threshold_sig.is_complete());

        // Add second signature - now threshold is met
        threshold_sig
            .add_signature(kp2.public_key(), kp2.sign(message))
            .unwrap();
        assert!(threshold_sig.is_complete());

        // Verify
        assert!(threshold_sig.verify(message).is_ok());
    }

    #[test]
    fn test_threshold_insufficient_signatures() {
        let message = b"Test";

        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();

        let possible_signers = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let mut threshold_sig = ThresholdSig::new(possible_signers, 2).unwrap();

        // Only add one signature
        threshold_sig
            .add_signature(kp1.public_key(), kp1.sign(message))
            .unwrap();

        // Verify should fail - not enough signatures
        assert!(threshold_sig.verify(message).is_err());
    }

    #[test]
    fn test_multi_sig_builder() {
        let message = b"Builder test";

        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        let signers = vec![kp1.public_key(), kp2.public_key()];
        let mut builder = MultiSigBuilder::new(signers);

        assert!(!builder.is_complete());

        builder
            .add_signature(&kp1.public_key(), kp1.sign(message))
            .unwrap();
        assert!(!builder.is_complete());

        builder
            .add_signature(&kp2.public_key(), kp2.sign(message))
            .unwrap();
        assert!(builder.is_complete());

        let multi_sig = builder.build().unwrap();
        assert!(multi_sig.verify(message).is_ok());
    }

    #[test]
    fn test_threshold_coordinator() {
        let message = b"Coordinator test";

        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();

        let signers = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

        let mut coordinator = ThresholdCoordinator::new(signers, 2, message.to_vec()).unwrap();

        coordinator
            .add_signature(kp1.public_key(), kp1.sign(message))
            .unwrap();
        assert!(!coordinator.is_complete());

        coordinator
            .add_signature(kp2.public_key(), kp2.sign(message))
            .unwrap();
        assert!(coordinator.is_complete());

        let threshold_sig = coordinator.finalize().unwrap();
        assert!(threshold_sig.verify(message).is_ok());
    }

    #[test]
    fn test_invalid_threshold() {
        let kp1 = KeyPair::generate();
        let signers = vec![kp1.public_key()];

        // Threshold 0 should fail
        assert!(ThresholdSig::new(signers.clone(), 0).is_err());

        // Threshold > N should fail
        assert!(ThresholdSig::new(signers, 2).is_err());
    }
}
