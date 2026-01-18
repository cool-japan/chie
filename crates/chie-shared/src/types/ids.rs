//! Strongly-typed ID wrappers for better type safety
//!
//! This module provides newtype wrappers around string IDs to prevent mixing up
//! different types of identifiers (e.g., passing a peer ID where a content ID is expected).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Content identifier (CID) - IPFS content hash
///
/// A strongly-typed wrapper around content identifiers to prevent mixing with other ID types.
///
/// # Examples
///
/// ```
/// use chie_shared::ContentId;
///
/// let cid = ContentId::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
/// assert_eq!(cid.as_str(), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentId(String);

impl ContentId {
    /// Create a new `ContentId`
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Get a short display format (first 8 characters)
    #[inline]
    #[must_use]
    pub fn short(&self) -> &str {
        if self.0.len() > 8 {
            &self.0[..8]
        } else {
            &self.0
        }
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ContentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ContentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for ContentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Peer identifier - libp2p peer ID
///
/// A strongly-typed wrapper around peer identifiers to prevent mixing with other ID types.
///
/// # Examples
///
/// ```
/// use chie_shared::PeerId;
///
/// let peer_id = PeerId::new("12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhfGFRHPZ");
/// assert_eq!(peer_id.as_str(), "12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhfGFRHPZ");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

impl PeerId {
    /// Create a new `PeerId`
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Get a short display format (first 8 characters after prefix)
    #[inline]
    #[must_use]
    pub fn short(&self) -> &str {
        // Handle common peer ID prefixes (Qm, 12D3, bafz)
        let start_idx = if self.0.starts_with("12D3") {
            4
        } else if self.0.starts_with("Qm") || self.0.starts_with("bafz") {
            2
        } else {
            0
        };

        let end_idx = (start_idx + 8).min(self.0.len());
        if start_idx < self.0.len() {
            &self.0[start_idx..end_idx]
        } else {
            &self.0
        }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Bandwidth proof identifier
///
/// A strongly-typed wrapper around proof identifiers to prevent mixing with other ID types.
///
/// # Examples
///
/// ```
/// use chie_shared::ProofId;
///
/// let proof_id = ProofId::new("proof_abc123");
/// assert_eq!(proof_id.as_str(), "proof_abc123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofId(String);

impl ProofId {
    /// Create a new `ProofId`
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ProofId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ProofId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for ProofId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// User identifier
///
/// A strongly-typed wrapper around user identifiers to prevent mixing with other ID types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    /// Create a new `UserId`
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Transaction identifier for tracking payments and rewards
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(String);

impl TransactionId {
    /// Create a new `TransactionId`
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TransactionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TransactionId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for TransactionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_id_creation() {
        let cid = ContentId::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
        assert_eq!(
            cid.as_str(),
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
    }

    #[test]
    fn test_content_id_short() {
        let cid = ContentId::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
        assert_eq!(cid.short(), "bafybeig");
    }

    #[test]
    fn test_content_id_display() {
        let cid = ContentId::new("test_cid");
        assert_eq!(cid.to_string(), "test_cid");
    }

    #[test]
    fn test_content_id_from_string() {
        let cid: ContentId = "test_cid".into();
        assert_eq!(cid.as_str(), "test_cid");
    }

    #[test]
    fn test_peer_id_creation() {
        let peer = PeerId::new("12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhfGFRHPZ");
        assert_eq!(
            peer.as_str(),
            "12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhfGFRHPZ"
        );
    }

    #[test]
    fn test_peer_id_short() {
        let peer = PeerId::new("12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhfGFRHPZ");
        assert_eq!(peer.short(), "KooWRBhw");
    }

    #[test]
    fn test_peer_id_short_qm_prefix() {
        let peer = PeerId::new("QmTest123456789");
        assert_eq!(peer.short(), "Test1234");
    }

    #[test]
    fn test_proof_id_creation() {
        let proof = ProofId::new("proof_abc123");
        assert_eq!(proof.as_str(), "proof_abc123");
    }

    #[test]
    fn test_user_id_creation() {
        let user = UserId::new("user_123");
        assert_eq!(user.as_str(), "user_123");
    }

    #[test]
    fn test_transaction_id_creation() {
        let tx = TransactionId::new("tx_abc123");
        assert_eq!(tx.as_str(), "tx_abc123");
    }

    #[test]
    fn test_content_id_serde() {
        let cid = ContentId::new("test_cid");
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(json, "\"test_cid\"");

        let decoded: ContentId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cid);
    }

    #[test]
    fn test_peer_id_as_ref() {
        let peer = PeerId::new("test_peer");
        let s: &str = peer.as_ref();
        assert_eq!(s, "test_peer");
    }

    #[test]
    fn test_ids_equality() {
        let cid1 = ContentId::new("same_id");
        let cid2 = ContentId::new("same_id");
        let cid3 = ContentId::new("different_id");

        assert_eq!(cid1, cid2);
        assert_ne!(cid1, cid3);
    }

    #[test]
    fn test_ids_hash_map() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let cid = ContentId::new("test");
        map.insert(cid.clone(), 42);

        assert_eq!(map.get(&cid), Some(&42));
    }
}
