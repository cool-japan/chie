//! Attribute-Based Encryption (ABE) for fine-grained access control.
//!
//! This module provides Ciphertext-Policy ABE (CP-ABE), where access policies
//! are embedded in ciphertexts and user keys are associated with attributes.
//!
//! # Overview
//!
//! ABE enables encryption to a set of attributes rather than to specific public keys.
//! Only users whose attributes satisfy the access policy can decrypt.
//!
//! # Architecture
//!
//! - **Authority**: Generates master keys and issues user keys based on attributes
//! - **Encryptor**: Encrypts data with an access policy (e.g., "admin AND (vip OR premium)")
//! - **Decryptor**: Can decrypt if their attributes satisfy the policy
//!
//! # Use Cases in CHIE
//!
//! - Content access control based on subscription tiers
//! - Geographic restrictions (region attributes)
//! - Time-based access (time-period attributes)
//! - Role-based access (role attributes)
//!
//! # Example
//!
//! ```
//! use chie_crypto::abe::{AbeAuthority, AccessPolicy, PolicyNode};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Authority generates master keys
//! let mut authority = AbeAuthority::new();
//!
//! // Issue user key with attributes
//! let user_attrs = vec!["premium".to_string(), "us-region".to_string()];
//! let user_key = authority.generate_user_key(&user_attrs)?;
//!
//! // Encrypt with policy: premium AND us-region
//! let policy = AccessPolicy::and(vec![
//!     PolicyNode::Attribute("premium".to_string()),
//!     PolicyNode::Attribute("us-region".to_string()),
//! ]);
//! let plaintext = b"Premium US content";
//! let ciphertext = authority.encrypt(&policy, plaintext)?;
//!
//! // User can decrypt because they have both attributes
//! let decrypted = authority.decrypt(&user_key, &ciphertext)?;
//! assert_eq!(decrypted, plaintext);
//! # Ok(())
//! # }
//! ```

#![allow(dead_code)]

use crate::encryption::{EncryptionKey, decrypt, encrypt, generate_nonce};
use blake3::Hasher;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Errors that can occur in ABE operations.
#[derive(Debug, Error)]
pub enum AbeError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Policy evaluation failed: {0}")]
    PolicyFailed(String),

    #[error("Invalid attributes: {0}")]
    InvalidAttributes(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for ABE operations.
pub type AbeResult<T> = Result<T, AbeError>;

/// A node in an access policy tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyNode {
    /// Leaf node: requires a specific attribute
    Attribute(String),
    /// AND gate: all children must be satisfied
    And(Vec<PolicyNode>),
    /// OR gate: at least one child must be satisfied
    Or(Vec<PolicyNode>),
    /// Threshold gate: at least k of n children must be satisfied
    Threshold { k: usize, children: Vec<PolicyNode> },
}

impl PolicyNode {
    /// Evaluate if a set of attributes satisfies this policy node.
    pub fn evaluate(&self, attributes: &HashSet<String>) -> bool {
        match self {
            PolicyNode::Attribute(attr) => attributes.contains(attr),
            PolicyNode::And(children) => children.iter().all(|c| c.evaluate(attributes)),
            PolicyNode::Or(children) => children.iter().any(|c| c.evaluate(attributes)),
            PolicyNode::Threshold { k, children } => {
                let satisfied = children.iter().filter(|c| c.evaluate(attributes)).count();
                satisfied >= *k
            }
        }
    }

    /// Get all attributes mentioned in this policy.
    pub fn get_attributes(&self) -> HashSet<String> {
        let mut attrs = HashSet::new();
        self.collect_attributes(&mut attrs);
        attrs
    }

    fn collect_attributes(&self, attrs: &mut HashSet<String>) {
        match self {
            PolicyNode::Attribute(attr) => {
                attrs.insert(attr.clone());
            }
            PolicyNode::And(children) | PolicyNode::Or(children) => {
                for child in children {
                    child.collect_attributes(attrs);
                }
            }
            PolicyNode::Threshold { children, .. } => {
                for child in children {
                    child.collect_attributes(attrs);
                }
            }
        }
    }
}

/// Access policy for CP-ABE encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Root of the policy tree
    root: PolicyNode,
}

impl AccessPolicy {
    /// Create a new access policy from a policy node.
    pub fn new(root: PolicyNode) -> Self {
        Self { root }
    }

    /// Create an AND policy (all attributes required).
    pub fn and(nodes: Vec<PolicyNode>) -> Self {
        Self::new(PolicyNode::And(nodes))
    }

    /// Create an OR policy (any attribute suffices).
    pub fn or(nodes: Vec<PolicyNode>) -> Self {
        Self::new(PolicyNode::Or(nodes))
    }

    /// Create a threshold policy (k-of-n).
    pub fn threshold(k: usize, children: Vec<PolicyNode>) -> Self {
        Self::new(PolicyNode::Threshold { k, children })
    }

    /// Evaluate if attributes satisfy this policy.
    pub fn evaluate(&self, attributes: &HashSet<String>) -> bool {
        self.root.evaluate(attributes)
    }

    /// Get all attributes mentioned in this policy.
    pub fn get_attributes(&self) -> HashSet<String> {
        self.root.get_attributes()
    }
}

/// Master secret key for ABE authority.
#[derive(Clone)]
pub struct MasterSecretKey {
    /// Secret seed for key derivation
    seed: [u8; 32],
}

impl MasterSecretKey {
    /// Generate a new random master secret key.
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill(&mut seed);
        Self { seed }
    }

    /// Derive an attribute key from the master secret.
    fn derive_attribute_key(&self, attribute: &str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(b"attribute:");
        hasher.update(attribute.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// User secret key containing keys for specific attributes.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecretKey {
    /// Map from attribute to derived key
    attribute_keys: HashMap<String, [u8; 32]>,
}

impl UserSecretKey {
    /// Create a new user secret key.
    fn new(attribute_keys: HashMap<String, [u8; 32]>) -> Self {
        Self { attribute_keys }
    }

    /// Get the set of attributes this key possesses.
    pub fn get_attributes(&self) -> HashSet<String> {
        self.attribute_keys.keys().cloned().collect()
    }

    /// Check if this key has a specific attribute.
    pub fn has_attribute(&self, attribute: &str) -> bool {
        self.attribute_keys.contains_key(attribute)
    }
}

/// Encrypted DEK with its nonce.
#[derive(Clone, Serialize, Deserialize)]
struct EncryptedDek {
    /// Encrypted DEK bytes
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; 12],
}

/// Attribute-based ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct AbeCiphertext {
    /// Access policy for this ciphertext
    policy: AccessPolicy,
    /// Encrypted data encryption key for each attribute with nonces
    encrypted_keys: HashMap<String, EncryptedDek>,
    /// Encrypted payload
    ciphertext: Vec<u8>,
    /// Nonce for payload encryption
    nonce: [u8; 12],
}

impl AbeCiphertext {
    /// Get the access policy for this ciphertext.
    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> AbeResult<Vec<u8>> {
        crate::codec::encode(self)
            .map_err(|e| AbeError::SerializationError(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AbeResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| AbeError::SerializationError(format!("Deserialization failed: {}", e)))
    }
}

/// ABE authority that manages keys and performs encryption/decryption.
pub struct AbeAuthority {
    /// Master secret key
    master_key: MasterSecretKey,
}

impl AbeAuthority {
    /// Create a new ABE authority with a random master key.
    pub fn new() -> Self {
        Self {
            master_key: MasterSecretKey::new(),
        }
    }

    /// Create an authority from existing master key bytes.
    pub fn from_master_key(seed: [u8; 32]) -> Self {
        Self {
            master_key: MasterSecretKey { seed },
        }
    }

    /// Generate a user secret key for a set of attributes.
    pub fn generate_user_key(&self, attributes: &[String]) -> AbeResult<UserSecretKey> {
        if attributes.is_empty() {
            return Err(AbeError::InvalidAttributes(
                "Attributes list cannot be empty".to_string(),
            ));
        }

        let mut attribute_keys = HashMap::new();
        for attr in attributes {
            let key = self.master_key.derive_attribute_key(attr);
            attribute_keys.insert(attr.clone(), key);
        }

        Ok(UserSecretKey::new(attribute_keys))
    }

    /// Encrypt data with an access policy.
    pub fn encrypt(&self, policy: &AccessPolicy, plaintext: &[u8]) -> AbeResult<AbeCiphertext> {
        // Generate random data encryption key
        let mut dek = [0u8; 32];
        rand::rng().fill(&mut dek);

        // Generate nonce
        let nonce = generate_nonce();

        // Encrypt plaintext with DEK
        let encryption_key = EncryptionKey::from(dek);
        let ciphertext = encrypt(plaintext, &encryption_key, &nonce)
            .map_err(|e| AbeError::EncryptionFailed(format!("Failed to encrypt: {}", e)))?;

        // Encrypt DEK for each attribute in the policy
        let mut encrypted_keys = HashMap::new();
        for attr in policy.get_attributes() {
            let attr_key = self.master_key.derive_attribute_key(&attr);

            // Derive encryption key from attribute key
            let attr_enc_key = EncryptionKey::from(attr_key);

            // Generate unique nonce for this attribute
            let attr_nonce = generate_nonce();

            let encrypted_dek_bytes = encrypt(&dek, &attr_enc_key, &attr_nonce)
                .map_err(|e| AbeError::EncryptionFailed(format!("Failed to encrypt DEK: {}", e)))?;

            encrypted_keys.insert(
                attr,
                EncryptedDek {
                    ciphertext: encrypted_dek_bytes,
                    nonce: attr_nonce,
                },
            );
        }

        Ok(AbeCiphertext {
            policy: policy.clone(),
            encrypted_keys,
            ciphertext,
            nonce,
        })
    }

    /// Decrypt ciphertext using a user secret key.
    pub fn decrypt(
        &self,
        user_key: &UserSecretKey,
        ciphertext: &AbeCiphertext,
    ) -> AbeResult<Vec<u8>> {
        // Check if user attributes satisfy the policy
        let user_attrs = user_key.get_attributes();
        if !ciphertext.policy.evaluate(&user_attrs) {
            return Err(AbeError::DecryptionFailed(
                "User attributes do not satisfy access policy".to_string(),
            ));
        }

        // Find an attribute the user has that can decrypt the DEK
        let mut dek = None;
        for (attr, attr_key) in &user_key.attribute_keys {
            if let Some(encrypted_dek) = ciphertext.encrypted_keys.get(attr) {
                // Try to decrypt the DEK with this attribute key
                let attr_enc_key = EncryptionKey::from(*attr_key);

                // Try to decrypt the DEK
                let decrypted = decrypt(
                    &encrypted_dek.ciphertext,
                    &attr_enc_key,
                    &encrypted_dek.nonce,
                );

                if let Ok(dek_bytes) = decrypted {
                    if dek_bytes.len() == 32 {
                        let mut dek_arr = [0u8; 32];
                        dek_arr.copy_from_slice(&dek_bytes);
                        dek = Some(dek_arr);
                        break;
                    }
                }
            }
        }

        let dek = dek.ok_or_else(|| {
            AbeError::DecryptionFailed("Could not recover data encryption key".to_string())
        })?;

        // Decrypt the payload
        let encryption_key = EncryptionKey::from(dek);
        decrypt(&ciphertext.ciphertext, &encryption_key, &ciphertext.nonce)
            .map_err(|e| AbeError::DecryptionFailed(format!("Failed to decrypt payload: {}", e)))
    }

    /// Get the master key seed (for backup/recovery).
    pub fn export_master_key(&self) -> [u8; 32] {
        self.master_key.seed
    }
}

impl Default for AbeAuthority {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_evaluation_single_attribute() {
        let policy = PolicyNode::Attribute("admin".to_string());

        let mut attrs = HashSet::new();
        attrs.insert("admin".to_string());
        assert!(policy.evaluate(&attrs));

        attrs.clear();
        attrs.insert("user".to_string());
        assert!(!policy.evaluate(&attrs));
    }

    #[test]
    fn test_policy_evaluation_and() {
        let policy = PolicyNode::And(vec![
            PolicyNode::Attribute("admin".to_string()),
            PolicyNode::Attribute("premium".to_string()),
        ]);

        let mut attrs = HashSet::new();
        attrs.insert("admin".to_string());
        attrs.insert("premium".to_string());
        assert!(policy.evaluate(&attrs));

        attrs.clear();
        attrs.insert("admin".to_string());
        assert!(!policy.evaluate(&attrs));
    }

    #[test]
    fn test_policy_evaluation_or() {
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attribute("admin".to_string()),
            PolicyNode::Attribute("moderator".to_string()),
        ]);

        let mut attrs = HashSet::new();
        attrs.insert("admin".to_string());
        assert!(policy.evaluate(&attrs));

        attrs.clear();
        attrs.insert("moderator".to_string());
        assert!(policy.evaluate(&attrs));

        attrs.clear();
        attrs.insert("user".to_string());
        assert!(!policy.evaluate(&attrs));
    }

    #[test]
    fn test_policy_evaluation_threshold() {
        let policy = PolicyNode::Threshold {
            k: 2,
            children: vec![
                PolicyNode::Attribute("admin".to_string()),
                PolicyNode::Attribute("moderator".to_string()),
                PolicyNode::Attribute("premium".to_string()),
            ],
        };

        let mut attrs = HashSet::new();
        attrs.insert("admin".to_string());
        attrs.insert("moderator".to_string());
        assert!(policy.evaluate(&attrs));

        attrs.clear();
        attrs.insert("admin".to_string());
        assert!(!policy.evaluate(&attrs));
    }

    #[test]
    fn test_user_key_generation() {
        let authority = AbeAuthority::new();
        let attrs = vec!["admin".to_string(), "premium".to_string()];

        let user_key = authority.generate_user_key(&attrs).unwrap();
        assert_eq!(user_key.get_attributes().len(), 2);
        assert!(user_key.has_attribute("admin"));
        assert!(user_key.has_attribute("premium"));
        assert!(!user_key.has_attribute("user"));
    }

    #[test]
    fn test_encrypt_decrypt_simple() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::new(PolicyNode::Attribute("premium".to_string()));
        let user_key = authority
            .generate_user_key(&["premium".to_string()])
            .unwrap();

        let plaintext = b"Secret premium content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();
        let decrypted = authority.decrypt(&user_key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_and_policy() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::and(vec![
            PolicyNode::Attribute("premium".to_string()),
            PolicyNode::Attribute("us-region".to_string()),
        ]);

        let user_key = authority
            .generate_user_key(&["premium".to_string(), "us-region".to_string()])
            .unwrap();

        let plaintext = b"Premium US content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();
        let decrypted = authority.decrypt(&user_key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_without_attributes() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::new(PolicyNode::Attribute("premium".to_string()));
        let user_key = authority.generate_user_key(&["basic".to_string()]).unwrap();

        let plaintext = b"Secret premium content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();

        assert!(authority.decrypt(&user_key, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_fails_partial_and() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::and(vec![
            PolicyNode::Attribute("premium".to_string()),
            PolicyNode::Attribute("us-region".to_string()),
        ]);

        // User has only one of the required attributes
        let user_key = authority
            .generate_user_key(&["premium".to_string()])
            .unwrap();

        let plaintext = b"Premium US content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();

        assert!(authority.decrypt(&user_key, &ciphertext).is_err());
    }

    #[test]
    fn test_or_policy_decryption() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::or(vec![
            PolicyNode::Attribute("admin".to_string()),
            PolicyNode::Attribute("premium".to_string()),
        ]);

        // User with admin attribute
        let user_key1 = authority.generate_user_key(&["admin".to_string()]).unwrap();

        // User with premium attribute
        let user_key2 = authority
            .generate_user_key(&["premium".to_string()])
            .unwrap();

        let plaintext = b"Admin or Premium content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();

        // Both should be able to decrypt
        let decrypted1 = authority.decrypt(&user_key1, &ciphertext).unwrap();
        assert_eq!(decrypted1, plaintext);

        let decrypted2 = authority.decrypt(&user_key2, &ciphertext).unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_threshold_policy() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::threshold(
            2,
            vec![
                PolicyNode::Attribute("attr1".to_string()),
                PolicyNode::Attribute("attr2".to_string()),
                PolicyNode::Attribute("attr3".to_string()),
            ],
        );

        // User with 2 of 3 attributes
        let user_key = authority
            .generate_user_key(&["attr1".to_string(), "attr2".to_string()])
            .unwrap();

        let plaintext = b"Threshold content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();
        let decrypted = authority.decrypt(&user_key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_complex_nested_policy() {
        let authority = AbeAuthority::new();

        // (admin OR moderator) AND premium
        let policy = AccessPolicy::and(vec![
            PolicyNode::Or(vec![
                PolicyNode::Attribute("admin".to_string()),
                PolicyNode::Attribute("moderator".to_string()),
            ]),
            PolicyNode::Attribute("premium".to_string()),
        ]);

        let user_key = authority
            .generate_user_key(&["moderator".to_string(), "premium".to_string()])
            .unwrap();

        let plaintext = b"Complex policy content";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();
        let decrypted = authority.decrypt(&user_key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let authority = AbeAuthority::new();

        let policy = AccessPolicy::new(PolicyNode::Attribute("test".to_string()));
        let plaintext = b"Serialization test";
        let ciphertext = authority.encrypt(&policy, plaintext).unwrap();

        let bytes = ciphertext.to_bytes().unwrap();
        let restored = AbeCiphertext::from_bytes(&bytes).unwrap();

        let user_key = authority.generate_user_key(&["test".to_string()]).unwrap();
        let decrypted = authority.decrypt(&user_key, &restored).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_attributes_fails() {
        let authority = AbeAuthority::new();
        let result = authority.generate_user_key(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_master_key_export_import() {
        let authority1 = AbeAuthority::new();
        let seed = authority1.export_master_key();

        let authority2 = AbeAuthority::from_master_key(seed);

        // Keys generated by both authorities should be compatible
        let user_key = authority1.generate_user_key(&["test".to_string()]).unwrap();

        let policy = AccessPolicy::new(PolicyNode::Attribute("test".to_string()));
        let plaintext = b"Cross-authority test";
        let ciphertext = authority2.encrypt(&policy, plaintext).unwrap();

        let decrypted = authority1.decrypt(&user_key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_plaintexts_same_policy() {
        let authority = AbeAuthority::new();
        let policy = AccessPolicy::new(PolicyNode::Attribute("premium".to_string()));
        let user_key = authority
            .generate_user_key(&["premium".to_string()])
            .unwrap();

        let plaintext1 = b"First message";
        let plaintext2 = b"Second message";

        let ciphertext1 = authority.encrypt(&policy, plaintext1).unwrap();
        let ciphertext2 = authority.encrypt(&policy, plaintext2).unwrap();

        let decrypted1 = authority.decrypt(&user_key, &ciphertext1).unwrap();
        let decrypted2 = authority.decrypt(&user_key, &ciphertext2).unwrap();

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }
}
