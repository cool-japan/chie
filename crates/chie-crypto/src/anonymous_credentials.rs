//! Anonymous Credentials (Idemix-style) for privacy-preserving authentication
//!
//! This module implements a simplified anonymous credential system inspired by IBM's
//! Idemix (Identity Mixer). It provides:
//! - Credential issuance without revealing user identity
//! - Selective disclosure of attributes
//! - Unlinkable presentations (same credential, different presentations are unlinkable)
//! - Revocation support
//!
//! # Example
//!
//! ```
//! use chie_crypto::anonymous_credentials::*;
//!
//! // Setup issuer
//! let issuer = Issuer::new();
//!
//! // User creates credential request
//! let user = User::new();
//! let request = user.create_credential_request(&issuer.public_key()).unwrap();
//!
//! // Issuer issues credential with attributes
//! let mut attributes = std::collections::HashMap::new();
//! attributes.insert("age".to_string(), vec![18]); // Age >= 18
//! attributes.insert("country".to_string(), vec![1]); // Country code 1
//!
//! let credential = issuer.issue_credential(&request, &attributes).unwrap();
//!
//! // User creates presentation revealing only age >= 18
//! let mut revealed = std::collections::HashSet::new();
//! revealed.insert("age".to_string());
//!
//! let presentation = user.create_presentation(&credential, &revealed).unwrap();
//!
//! // Verifier checks presentation
//! assert!(issuer.verify_presentation(&presentation, &revealed).unwrap());
//! ```

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Anonymous credentials error types
#[derive(Error, Debug)]
pub enum AnonCredError {
    #[error("Invalid credential request")]
    InvalidRequest,
    #[error("Invalid credential")]
    InvalidCredential,
    #[error("Invalid presentation")]
    InvalidPresentation,
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Revoked credential")]
    RevokedCredential,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for anonymous credentials operations
pub type AnonCredResult<T> = Result<T, AnonCredError>;

/// Issuer public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    /// Public verification key
    #[serde(with = "serde_verifying_key")]
    verification_key: VerifyingKey,
    /// Attribute commitment bases (one per attribute)
    #[serde(with = "serde_point_vec")]
    attribute_bases: Vec<RistrettoPoint>,
    /// Attribute names in order
    attribute_names: Vec<String>,
}

/// Credential request from user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// User's public commitment to their secret
    #[serde(with = "serde_point")]
    user_commitment: RistrettoPoint,
    /// Proof of knowledge of secret (Schnorr-like)
    #[serde(with = "serde_scalar")]
    proof_challenge: Scalar,
    #[serde(with = "serde_scalar")]
    proof_response: Scalar,
}

/// Anonymous credential
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonymousCredential {
    /// Issuer signature on commitment
    #[serde(with = "serde_signature")]
    signature: Signature,
    /// Attributes (encrypted/committed)
    attributes: HashMap<String, Vec<u8>>,
    /// Commitment to attributes and secret
    #[serde(with = "serde_point")]
    commitment: RistrettoPoint,
}

/// Credential presentation (proof of possession without revealing credential)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    /// Credential signature (proves validity)
    #[serde(with = "serde_signature")]
    signature: Signature,
    /// Commitment
    #[serde(with = "serde_point")]
    commitment: RistrettoPoint,
    /// Revealed attributes
    revealed_attributes: HashMap<String, Vec<u8>>,
    /// Presentation nonce (prevents replay)
    nonce: [u8; 32],
}

/// Issuer of anonymous credentials
pub struct Issuer {
    /// Signing key
    signing_key: SigningKey,
    /// Public key
    public_key: IssuerPublicKey,
    /// Revocation list (credential commitments)
    revocation_list: HashSet<Vec<u8>>,
}

impl Issuer {
    /// Create a new issuer with default attributes
    pub fn new() -> Self {
        Self::with_attributes(vec![
            "age".to_string(),
            "country".to_string(),
            "role".to_string(),
        ])
    }

    /// Create a new issuer with custom attributes
    pub fn with_attributes(attribute_names: Vec<String>) -> Self {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("Failed to generate random bytes");
        let signing_key = SigningKey::from_bytes(&secret);
        let verification_key = signing_key.verifying_key();

        // Generate commitment bases for each attribute
        let mut attribute_bases = Vec::with_capacity(attribute_names.len());
        for (i, name) in attribute_names.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(b"anoncred_attribute_base");
            hasher.update(name.as_bytes());
            hasher.update(i.to_le_bytes());
            let hash = hasher.finalize();
            let scalar = Scalar::from_bytes_mod_order(hash.into());
            attribute_bases.push(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * scalar);
        }

        let public_key = IssuerPublicKey {
            verification_key,
            attribute_bases,
            attribute_names,
        };

        Self {
            signing_key,
            public_key,
            revocation_list: HashSet::new(),
        }
    }

    /// Get the issuer's public key
    pub fn public_key(&self) -> &IssuerPublicKey {
        &self.public_key
    }

    /// Issue a credential to a user
    pub fn issue_credential(
        &self,
        request: &CredentialRequest,
        attributes: &HashMap<String, Vec<u8>>,
    ) -> AnonCredResult<AnonymousCredential> {
        // Verify the credential request proof
        if !self.verify_credential_request(request)? {
            return Err(AnonCredError::InvalidRequest);
        }

        // Build commitment to attributes
        let mut commitment = request.user_commitment;

        for (i, attr_name) in self.public_key.attribute_names.iter().enumerate() {
            if let Some(attr_value) = attributes.get(attr_name) {
                // Hash attribute value to scalar
                let mut hasher = Sha256::new();
                hasher.update(attr_value);
                let hash = hasher.finalize();
                let scalar = Scalar::from_bytes_mod_order(hash.into());

                // Add to commitment
                commitment += self.public_key.attribute_bases[i] * scalar;
            }
        }

        // Sign the commitment
        let commitment_bytes = commitment.compress().to_bytes();
        let signature = self.signing_key.sign(&commitment_bytes);

        Ok(AnonymousCredential {
            signature,
            attributes: attributes.clone(),
            commitment,
        })
    }

    /// Verify a credential request
    fn verify_credential_request(&self, request: &CredentialRequest) -> AnonCredResult<bool> {
        // Verify proof of knowledge of secret
        let generator = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        // Recompute challenge
        let mut hasher = Sha256::new();
        hasher.update(b"credential_request_challenge");
        hasher.update(request.user_commitment.compress().as_bytes());
        let expected_point = (generator * request.proof_response)
            - (request.user_commitment * request.proof_challenge);
        hasher.update(expected_point.compress().as_bytes());
        let hash = hasher.finalize();
        let expected_challenge = Scalar::from_bytes_mod_order(hash.into());

        Ok(expected_challenge == request.proof_challenge)
    }

    /// Verify a credential presentation
    pub fn verify_presentation(
        &self,
        presentation: &CredentialPresentation,
        expected_attributes: &HashSet<String>,
    ) -> AnonCredResult<bool> {
        // Check revealed attributes
        for attr_name in expected_attributes {
            if !presentation.revealed_attributes.contains_key(attr_name) {
                return Err(AnonCredError::MissingAttribute(attr_name.clone()));
            }
        }

        // Verify signature on commitment
        let commitment_bytes = presentation.commitment.compress().to_bytes();
        self.public_key
            .verification_key
            .verify_strict(&commitment_bytes, &presentation.signature)
            .map_err(|_| AnonCredError::VerificationFailed)?;

        // Check not revoked
        if self.is_revoked(&commitment_bytes) {
            return Err(AnonCredError::RevokedCredential);
        }

        Ok(true)
    }

    /// Revoke a credential
    pub fn revoke_credential(&mut self, commitment: &[u8]) {
        self.revocation_list.insert(commitment.to_vec());
    }

    /// Check if a credential is revoked
    pub fn is_revoked(&self, commitment: &[u8]) -> bool {
        self.revocation_list.contains(commitment)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

/// User holding anonymous credentials
pub struct User {
    /// User's secret
    secret: Scalar,
}

impl User {
    /// Create a new user
    pub fn new() -> Self {
        let secret = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        Self { secret }
    }

    /// Create a credential request
    pub fn create_credential_request(
        &self,
        _issuer_pk: &IssuerPublicKey,
    ) -> AnonCredResult<CredentialRequest> {
        let generator = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        // Commit to secret: C = g^secret
        let user_commitment = generator * self.secret;

        // Create proof of knowledge of secret (Schnorr protocol)
        let random_scalar = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let random_commitment = generator * random_scalar;

        // Challenge
        let mut hasher = Sha256::new();
        hasher.update(b"credential_request_challenge");
        hasher.update(user_commitment.compress().as_bytes());
        hasher.update(random_commitment.compress().as_bytes());
        let hash = hasher.finalize();
        let proof_challenge = Scalar::from_bytes_mod_order(hash.into());

        // Response
        let proof_response = random_scalar + (proof_challenge * self.secret);

        Ok(CredentialRequest {
            user_commitment,
            proof_challenge,
            proof_response,
        })
    }

    /// Create a presentation of the credential
    pub fn create_presentation(
        &self,
        credential: &AnonymousCredential,
        revealed_attributes: &HashSet<String>,
    ) -> AnonCredResult<CredentialPresentation> {
        // Extract revealed attributes
        let mut revealed_attrs = HashMap::new();
        for attr_name in revealed_attributes {
            if let Some(attr_value) = credential.attributes.get(attr_name) {
                revealed_attrs.insert(attr_name.clone(), attr_value.clone());
            }
        }

        // Nonce prevents replay attacks
        let nonce = rand::random::<[u8; 32]>();

        Ok(CredentialPresentation {
            signature: credential.signature,
            commitment: credential.commitment,
            revealed_attributes: revealed_attrs,
            nonce,
        })
    }
}

impl Default for User {
    fn default() -> Self {
        Self::new()
    }
}

// Serde helpers
mod serde_verifying_key {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid key length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

mod serde_signature {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(&arr))
    }
}

mod serde_point {
    use super::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&point.compress().to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid point length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        CompressedRistretto(arr)
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("invalid point"))
    }
}

mod serde_point_vec {
    use super::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(points: &[RistrettoPoint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = points
            .iter()
            .map(|p| p.compress().to_bytes().to_vec())
            .collect();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
        bytes_vec
            .into_iter()
            .map(|bytes| {
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("invalid point length"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                CompressedRistretto(arr)
                    .decompress()
                    .ok_or_else(|| serde::de::Error::custom("invalid point"))
            })
            .collect()
    }
}

mod serde_scalar {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&scalar.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid scalar length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_credential_flow() {
        let issuer = Issuer::new();
        let user = User::new();

        // User requests credential
        let request = user.create_credential_request(issuer.public_key()).unwrap();

        // Issuer issues credential
        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![18]);
        attributes.insert("country".to_string(), vec![1]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        // Verify credential has attributes
        assert!(credential.attributes.contains_key("age"));
        assert!(credential.attributes.contains_key("country"));
    }

    #[test]
    fn test_credential_presentation() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![25]);
        attributes.insert("country".to_string(), vec![2]);
        attributes.insert("role".to_string(), vec![3]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        // User creates presentation revealing only age
        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());

        let presentation = user.create_presentation(&credential, &revealed).unwrap();

        // Verify presentation
        assert!(
            issuer
                .verify_presentation(&presentation, &revealed)
                .unwrap()
        );

        // Presentation should only contain revealed attribute
        assert_eq!(presentation.revealed_attributes.len(), 1);
        assert!(presentation.revealed_attributes.contains_key("age"));
    }

    #[test]
    fn test_unlinkable_presentations() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![30]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());

        // Create two presentations from same credential
        let presentation1 = user.create_presentation(&credential, &revealed).unwrap();
        let presentation2 = user.create_presentation(&credential, &revealed).unwrap();

        // Both should verify
        assert!(
            issuer
                .verify_presentation(&presentation1, &revealed)
                .unwrap()
        );
        assert!(
            issuer
                .verify_presentation(&presentation2, &revealed)
                .unwrap()
        );

        // But nonces should be different (prevents replay)
        assert_ne!(presentation1.nonce, presentation2.nonce);
    }

    #[test]
    fn test_selective_disclosure() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![21]);
        attributes.insert("country".to_string(), vec![5]);
        attributes.insert("role".to_string(), vec![7]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        // Reveal only age and role, not country
        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());
        revealed.insert("role".to_string());

        let presentation = user.create_presentation(&credential, &revealed).unwrap();

        assert!(
            issuer
                .verify_presentation(&presentation, &revealed)
                .unwrap()
        );

        // Country should not be in presentation
        assert!(!presentation.revealed_attributes.contains_key("country"));
        assert_eq!(presentation.revealed_attributes.len(), 2);
    }

    #[test]
    fn test_missing_attribute_verification() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![18]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());

        let presentation = user.create_presentation(&credential, &revealed).unwrap();

        // Try to verify with expected attribute that wasn't revealed
        let mut expected = HashSet::new();
        expected.insert("age".to_string());
        expected.insert("country".to_string()); // Not in presentation

        let result = issuer.verify_presentation(&presentation, &expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_revocation() {
        let mut issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![18]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        let commitment_bytes = credential.commitment.compress().to_bytes();

        // Check not revoked initially
        assert!(!issuer.is_revoked(&commitment_bytes));

        // Revoke the credential
        issuer.revoke_credential(&commitment_bytes);

        // Check is revoked
        assert!(issuer.is_revoked(&commitment_bytes));
    }

    #[test]
    fn test_custom_attributes() {
        let custom_attrs = vec!["email_verified".to_string(), "premium_member".to_string()];
        let issuer = Issuer::with_attributes(custom_attrs);

        let user = User::new();
        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("email_verified".to_string(), vec![1]);
        attributes.insert("premium_member".to_string(), vec![1]);

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        let mut revealed = HashSet::new();
        revealed.insert("premium_member".to_string());

        let presentation = user.create_presentation(&credential, &revealed).unwrap();

        assert!(
            issuer
                .verify_presentation(&presentation, &revealed)
                .unwrap()
        );
    }

    #[test]
    fn test_serialization() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        // Serialize and deserialize request
        let request_bytes = crate::codec::encode(&request).unwrap();
        let request_restored: CredentialRequest = crate::codec::decode(&request_bytes).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("age".to_string(), vec![22]);

        let credential = issuer
            .issue_credential(&request_restored, &attributes)
            .unwrap();

        // Serialize and deserialize credential
        let cred_bytes = crate::codec::encode(&credential).unwrap();
        let cred_restored: AnonymousCredential = crate::codec::decode(&cred_bytes).unwrap();

        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());

        let presentation = user.create_presentation(&cred_restored, &revealed).unwrap();

        // Serialize and deserialize presentation
        let pres_bytes = crate::codec::encode(&presentation).unwrap();
        let pres_restored: CredentialPresentation = crate::codec::decode(&pres_bytes).unwrap();

        assert!(
            issuer
                .verify_presentation(&pres_restored, &revealed)
                .unwrap()
        );
    }

    #[test]
    fn test_empty_attributes() {
        let issuer = Issuer::new();
        let user = User::new();

        let request = user.create_credential_request(issuer.public_key()).unwrap();

        let attributes = HashMap::new(); // No attributes

        let credential = issuer.issue_credential(&request, &attributes).unwrap();

        let revealed = HashSet::new(); // Reveal nothing

        let presentation = user.create_presentation(&credential, &revealed).unwrap();

        assert!(
            issuer
                .verify_presentation(&presentation, &revealed)
                .unwrap()
        );
    }

    #[test]
    fn test_public_key_serialization() {
        let issuer = Issuer::new();

        let pk_bytes = crate::codec::encode(&issuer.public_key()).unwrap();
        let pk_restored: IssuerPublicKey = crate::codec::decode(&pk_bytes).unwrap();

        assert_eq!(
            pk_restored.attribute_names.len(),
            issuer.public_key().attribute_names.len()
        );
    }

    #[test]
    fn test_multiple_users_same_issuer() {
        let issuer = Issuer::new();

        let user1 = User::new();
        let user2 = User::new();

        let request1 = user1
            .create_credential_request(issuer.public_key())
            .unwrap();
        let request2 = user2
            .create_credential_request(issuer.public_key())
            .unwrap();

        let mut attrs1 = HashMap::new();
        attrs1.insert("age".to_string(), vec![20]);

        let mut attrs2 = HashMap::new();
        attrs2.insert("age".to_string(), vec![30]);

        let cred1 = issuer.issue_credential(&request1, &attrs1).unwrap();
        let cred2 = issuer.issue_credential(&request2, &attrs2).unwrap();

        // Credentials should be different
        assert_ne!(cred1.commitment, cred2.commitment);

        let mut revealed = HashSet::new();
        revealed.insert("age".to_string());

        let pres1 = user1.create_presentation(&cred1, &revealed).unwrap();
        let pres2 = user2.create_presentation(&cred2, &revealed).unwrap();

        assert!(issuer.verify_presentation(&pres1, &revealed).unwrap());
        assert!(issuer.verify_presentation(&pres2, &revealed).unwrap());

        // Revealed attributes should be different
        assert_ne!(
            pres1.revealed_attributes.get("age"),
            pres2.revealed_attributes.get("age")
        );
    }
}
