//! Gossipsub-based content announcements for CHIE Protocol.
//!
//! This module provides structured content announcements using libp2p Gossipsub:
//! - Content availability announcements (new content or provider)
//! - Content removal announcements (no longer hosting)
//! - Content metadata updates
//! - Provider status updates

use libp2p::PeerId;
use libp2p::gossipsub::{IdentTopic, TopicHash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Default gossipsub topic for content announcements.
pub const CONTENT_ANNOUNCEMENT_TOPIC: &str = "/chie/content/v1";

/// Default gossipsub topic for provider status.
pub const PROVIDER_STATUS_TOPIC: &str = "/chie/provider/v1";

/// Maximum message size for announcements (64KB).
pub const MAX_ANNOUNCEMENT_SIZE: usize = 64 * 1024;

/// Content announcement message types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnnouncementType {
    /// New content is available from a provider.
    ContentAvailable,
    /// Content is no longer available from a provider.
    ContentRemoved,
    /// Content metadata has been updated.
    ContentUpdated,
    /// Provider is going online.
    ProviderOnline,
    /// Provider is going offline (graceful shutdown).
    ProviderOffline,
    /// Provider status update (capacity, stats).
    ProviderStatus,
}

/// Content availability announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnnouncement {
    /// Announcement type.
    pub announcement_type: AnnouncementType,
    /// Content CID (IPFS-style content identifier).
    pub cid: String,
    /// Provider's peer ID (as base58 string).
    pub provider_id: String,
    /// Content size in bytes.
    pub size_bytes: u64,
    /// Number of chunks.
    pub chunk_count: u32,
    /// Content title (optional).
    pub title: Option<String>,
    /// Content category (optional).
    pub category: Option<String>,
    /// Unix timestamp when this announcement was created.
    pub timestamp: u64,
    /// Announcement TTL in seconds.
    pub ttl_secs: u64,
    /// Provider's signature over the announcement (hex-encoded).
    pub signature: Option<String>,
}

impl ContentAnnouncement {
    /// Create a new content available announcement.
    pub fn content_available(
        cid: impl Into<String>,
        provider_id: impl Into<String>,
        size_bytes: u64,
        chunk_count: u32,
    ) -> Self {
        Self {
            announcement_type: AnnouncementType::ContentAvailable,
            cid: cid.into(),
            provider_id: provider_id.into(),
            size_bytes,
            chunk_count,
            title: None,
            category: None,
            timestamp: current_timestamp(),
            ttl_secs: 24 * 60 * 60, // 24 hours default
            signature: None,
        }
    }

    /// Create a new content removed announcement.
    pub fn content_removed(cid: impl Into<String>, provider_id: impl Into<String>) -> Self {
        Self {
            announcement_type: AnnouncementType::ContentRemoved,
            cid: cid.into(),
            provider_id: provider_id.into(),
            size_bytes: 0,
            chunk_count: 0,
            title: None,
            category: None,
            timestamp: current_timestamp(),
            ttl_secs: 60 * 60, // 1 hour for removal announcements
            signature: None,
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set the TTL.
    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Sign the announcement with a keypair.
    pub fn sign(mut self, keypair: &chie_crypto::KeyPair) -> Self {
        let message = self.signing_message();
        let signature = keypair.sign(&message);
        self.signature = Some(hex::encode(signature));
        self
    }

    /// Get the message to sign.
    fn signing_message(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}:{}:{}",
            self.cid, self.provider_id, self.size_bytes, self.chunk_count, self.timestamp
        )
        .into_bytes()
    }

    /// Verify the announcement signature.
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        match &self.signature {
            Some(sig_hex) => {
                let Ok(sig_bytes) = hex::decode(sig_hex) else {
                    return false;
                };
                if sig_bytes.len() != 64 {
                    return false;
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&sig_bytes);
                let message = self.signing_message();
                chie_crypto::verify(public_key, &message, &sig).is_ok()
            }
            None => false,
        }
    }

    /// Check if this announcement has expired.
    pub fn is_expired(&self) -> bool {
        let now = current_timestamp();
        now > self.timestamp + self.ttl_secs
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GossipError> {
        crate::serde_helpers::encode(self)
            .map_err(|e| GossipError::SerializationFailed(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GossipError> {
        crate::serde_helpers::decode(bytes)
            .map_err(|e| GossipError::DeserializationFailed(e.to_string()))
    }
}

/// Provider status announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAnnouncement {
    /// Announcement type.
    pub announcement_type: AnnouncementType,
    /// Provider's peer ID (as base58 string).
    pub provider_id: String,
    /// Available storage capacity in bytes.
    pub available_storage: u64,
    /// Number of content items being hosted.
    pub content_count: u32,
    /// Uptime in seconds since last restart.
    pub uptime_secs: u64,
    /// Provider version string.
    pub version: String,
    /// Unix timestamp.
    pub timestamp: u64,
}

impl ProviderAnnouncement {
    /// Create a provider online announcement.
    pub fn online(provider_id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            announcement_type: AnnouncementType::ProviderOnline,
            provider_id: provider_id.into(),
            available_storage: 0,
            content_count: 0,
            uptime_secs: 0,
            version: version.into(),
            timestamp: current_timestamp(),
        }
    }

    /// Create a provider offline announcement.
    pub fn offline(provider_id: impl Into<String>) -> Self {
        Self {
            announcement_type: AnnouncementType::ProviderOffline,
            provider_id: provider_id.into(),
            available_storage: 0,
            content_count: 0,
            uptime_secs: 0,
            version: String::new(),
            timestamp: current_timestamp(),
        }
    }

    /// Create a provider status update announcement.
    pub fn status(
        provider_id: impl Into<String>,
        available_storage: u64,
        content_count: u32,
        uptime_secs: u64,
    ) -> Self {
        Self {
            announcement_type: AnnouncementType::ProviderStatus,
            provider_id: provider_id.into(),
            available_storage,
            content_count,
            uptime_secs,
            version: String::new(),
            timestamp: current_timestamp(),
        }
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GossipError> {
        crate::serde_helpers::encode(self)
            .map_err(|e| GossipError::SerializationFailed(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GossipError> {
        crate::serde_helpers::decode(bytes)
            .map_err(|e| GossipError::DeserializationFailed(e.to_string()))
    }
}

/// Errors from the gossip module.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid topic: {0}")]
    InvalidTopic(String),

    #[error("Not subscribed to topic: {0}")]
    NotSubscribed(String),

    #[error("Gossipsub error: {0}")]
    GossipsubError(String),

    #[error("Invalid signature")]
    InvalidSignature,
}

/// Configuration for the gossip announcement system.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Content announcement topic.
    pub content_topic: String,
    /// Provider status topic.
    pub provider_topic: String,
    /// How often to re-announce content (seconds).
    pub reannounce_interval_secs: u64,
    /// How often to send provider status updates (seconds).
    pub status_interval_secs: u64,
    /// Maximum cached announcements per content.
    pub max_cached_per_content: usize,
    /// Require signatures on announcements.
    pub require_signatures: bool,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            content_topic: CONTENT_ANNOUNCEMENT_TOPIC.to_string(),
            provider_topic: PROVIDER_STATUS_TOPIC.to_string(),
            reannounce_interval_secs: 6 * 60 * 60, // 6 hours
            status_interval_secs: 5 * 60,          // 5 minutes
            max_cached_per_content: 50,
            require_signatures: false, // Disabled for PoC
        }
    }
}

/// Received announcement from gossipsub.
#[derive(Debug, Clone)]
pub struct ReceivedAnnouncement {
    /// The announcement content.
    pub content: ContentAnnouncement,
    /// Source peer ID.
    pub source: PeerId,
    /// When we received this announcement.
    pub received_at: Instant,
}

/// Manager for gossipsub content announcements.
pub struct ContentAnnouncementGossip {
    /// Configuration.
    config: GossipConfig,
    /// Content topic.
    content_topic: IdentTopic,
    /// Provider topic.
    provider_topic: IdentTopic,
    /// Cached content announcements (cid -> announcements).
    content_cache: HashMap<String, Vec<ReceivedAnnouncement>>,
    /// Known providers (provider_id -> last status).
    provider_cache: HashMap<String, ProviderAnnouncement>,
    /// Our provider ID.
    local_provider_id: String,
    /// Content we're announcing (cid -> last announced).
    local_content: HashMap<String, Instant>,
}

impl ContentAnnouncementGossip {
    /// Create a new content announcement gossip manager.
    pub fn new(local_provider_id: impl Into<String>, config: GossipConfig) -> Self {
        let content_topic = IdentTopic::new(&config.content_topic);
        let provider_topic = IdentTopic::new(&config.provider_topic);

        Self {
            config,
            content_topic,
            provider_topic,
            content_cache: HashMap::new(),
            provider_cache: HashMap::new(),
            local_provider_id: local_provider_id.into(),
            local_content: HashMap::new(),
        }
    }

    /// Get the content topic for subscription.
    pub fn content_topic(&self) -> &IdentTopic {
        &self.content_topic
    }

    /// Get the provider topic for subscription.
    pub fn provider_topic(&self) -> &IdentTopic {
        &self.provider_topic
    }

    /// Get topics to subscribe to.
    pub fn topics(&self) -> Vec<&IdentTopic> {
        vec![&self.content_topic, &self.provider_topic]
    }

    /// Create a content available announcement.
    pub fn create_content_announcement(
        &self,
        cid: impl Into<String>,
        size_bytes: u64,
        chunk_count: u32,
        keypair: Option<&chie_crypto::KeyPair>,
    ) -> ContentAnnouncement {
        let mut announcement = ContentAnnouncement::content_available(
            cid,
            &self.local_provider_id,
            size_bytes,
            chunk_count,
        );

        if let Some(kp) = keypair {
            announcement = announcement.sign(kp);
        }

        announcement
    }

    /// Create a content removed announcement.
    pub fn create_removal_announcement(
        &self,
        cid: impl Into<String>,
        keypair: Option<&chie_crypto::KeyPair>,
    ) -> ContentAnnouncement {
        let mut announcement = ContentAnnouncement::content_removed(cid, &self.local_provider_id);

        if let Some(kp) = keypair {
            announcement = announcement.sign(kp);
        }

        announcement
    }

    /// Record that we're announcing content locally.
    pub fn record_local_content(&mut self, cid: impl Into<String>) {
        self.local_content.insert(cid.into(), Instant::now());
    }

    /// Remove local content from announcements.
    pub fn remove_local_content(&mut self, cid: &str) {
        self.local_content.remove(cid);
    }

    /// Get content that needs re-announcement.
    pub fn get_content_needing_reannounce(&self) -> Vec<String> {
        let reannounce_interval = Duration::from_secs(self.config.reannounce_interval_secs);
        let now = Instant::now();

        self.local_content
            .iter()
            .filter(|(_, last_announced)| {
                now.duration_since(**last_announced) >= reannounce_interval
            })
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Handle a received gossipsub message.
    pub fn handle_message(
        &mut self,
        topic: &TopicHash,
        source: PeerId,
        data: &[u8],
    ) -> Result<GossipMessageResult, GossipError> {
        if *topic == self.content_topic.hash() {
            self.handle_content_message(source, data)
        } else if *topic == self.provider_topic.hash() {
            self.handle_provider_message(source, data)
        } else {
            Err(GossipError::InvalidTopic(format!("{:?}", topic)))
        }
    }

    /// Handle a content announcement message.
    fn handle_content_message(
        &mut self,
        source: PeerId,
        data: &[u8],
    ) -> Result<GossipMessageResult, GossipError> {
        let announcement = ContentAnnouncement::from_bytes(data)?;

        // Validate announcement
        if self.config.require_signatures && announcement.signature.is_none() {
            warn!("Received unsigned content announcement, ignoring");
            return Ok(GossipMessageResult::Ignored);
        }

        if announcement.is_expired() {
            debug!("Received expired content announcement, ignoring");
            return Ok(GossipMessageResult::Ignored);
        }

        let cid = announcement.cid.clone();
        let announcement_type = announcement.announcement_type.clone();

        // Cache the announcement
        let received = ReceivedAnnouncement {
            content: announcement,
            source,
            received_at: Instant::now(),
        };

        let entries = self.content_cache.entry(cid.clone()).or_default();

        // Remove old announcements from same provider
        entries.retain(|a| a.content.provider_id != received.content.provider_id);

        // Add new announcement
        entries.push(received.clone());

        // Trim to max cached
        if entries.len() > self.config.max_cached_per_content {
            entries.sort_by_key(|a| std::cmp::Reverse(a.received_at));
            entries.truncate(self.config.max_cached_per_content);
        }

        info!(
            "Received {:?} announcement for {} from {}",
            announcement_type, cid, source
        );

        Ok(GossipMessageResult::ContentAnnouncement(received))
    }

    /// Handle a provider status message.
    fn handle_provider_message(
        &mut self,
        source: PeerId,
        data: &[u8],
    ) -> Result<GossipMessageResult, GossipError> {
        let announcement = ProviderAnnouncement::from_bytes(data)?;

        let provider_id = announcement.provider_id.clone();
        let announcement_type = announcement.announcement_type.clone();

        // Cache provider status
        self.provider_cache
            .insert(provider_id.clone(), announcement.clone());

        info!(
            "Received {:?} announcement from provider {} via {}",
            announcement_type, provider_id, source
        );

        Ok(GossipMessageResult::ProviderAnnouncement(announcement))
    }

    /// Get known providers for content.
    pub fn get_content_providers(&self, cid: &str) -> Vec<&ReceivedAnnouncement> {
        self.content_cache
            .get(cid)
            .map(|v| {
                v.iter()
                    .filter(|a| a.content.announcement_type == AnnouncementType::ContentAvailable)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all cached content CIDs.
    pub fn get_known_content(&self) -> Vec<String> {
        self.content_cache.keys().cloned().collect()
    }

    /// Get provider status.
    pub fn get_provider_status(&self, provider_id: &str) -> Option<&ProviderAnnouncement> {
        self.provider_cache.get(provider_id)
    }

    /// Get all known providers.
    pub fn get_known_providers(&self) -> Vec<&ProviderAnnouncement> {
        self.provider_cache.values().collect()
    }

    /// Prune expired announcements.
    pub fn prune_expired(&mut self) {
        // Prune content announcements
        for announcements in self.content_cache.values_mut() {
            announcements.retain(|a| !a.content.is_expired());
        }
        self.content_cache
            .retain(|_, announcements| !announcements.is_empty());

        // Prune old provider status (older than 1 hour)
        let cutoff = current_timestamp() - 3600;
        self.provider_cache
            .retain(|_, status| status.timestamp > cutoff);
    }

    /// Get statistics.
    pub fn stats(&self) -> GossipStats {
        GossipStats {
            known_content_count: self.content_cache.len(),
            total_announcements: self.content_cache.values().map(|v| v.len()).sum(),
            known_provider_count: self.provider_cache.len(),
            local_content_count: self.local_content.len(),
        }
    }
}

/// Result of handling a gossip message.
#[derive(Debug, Clone)]
pub enum GossipMessageResult {
    /// A content announcement was received.
    ContentAnnouncement(ReceivedAnnouncement),
    /// A provider announcement was received.
    ProviderAnnouncement(ProviderAnnouncement),
    /// The message was ignored (expired, invalid, etc.).
    Ignored,
}

/// Statistics about the gossip system.
#[derive(Debug, Clone, Default)]
pub struct GossipStats {
    /// Number of unique content items known.
    pub known_content_count: usize,
    /// Total announcements cached.
    pub total_announcements: usize,
    /// Number of known providers.
    pub known_provider_count: usize,
    /// Number of content items we're announcing.
    pub local_content_count: usize,
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Gossipsub message validator for CHIE announcements.
pub struct AnnouncementValidator {
    /// Maximum message size.
    max_size: usize,
    /// Require signatures.
    require_signatures: bool,
}

impl AnnouncementValidator {
    /// Create a new validator.
    pub fn new(require_signatures: bool) -> Self {
        Self {
            max_size: MAX_ANNOUNCEMENT_SIZE,
            require_signatures,
        }
    }

    /// Validate a content announcement message.
    pub fn validate_content(&self, data: &[u8]) -> Result<ContentAnnouncement, GossipError> {
        if data.len() > self.max_size {
            return Err(GossipError::MessageTooLarge {
                size: data.len(),
                max: self.max_size,
            });
        }

        let announcement = ContentAnnouncement::from_bytes(data)?;

        if self.require_signatures && announcement.signature.is_none() {
            return Err(GossipError::InvalidSignature);
        }

        Ok(announcement)
    }

    /// Validate a provider announcement message.
    pub fn validate_provider(&self, data: &[u8]) -> Result<ProviderAnnouncement, GossipError> {
        if data.len() > self.max_size {
            return Err(GossipError::MessageTooLarge {
                size: data.len(),
                max: self.max_size,
            });
        }

        ProviderAnnouncement::from_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_announcement_serialization() {
        let announcement =
            ContentAnnouncement::content_available("QmTest123", "12D3KooWTest", 1024 * 1024, 4)
                .with_title("Test Content")
                .with_category("test");

        let bytes = announcement.to_bytes().unwrap();
        let restored = ContentAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(announcement.cid, restored.cid);
        assert_eq!(announcement.provider_id, restored.provider_id);
        assert_eq!(announcement.size_bytes, restored.size_bytes);
        assert_eq!(announcement.title, restored.title);
    }

    #[test]
    fn test_provider_announcement_serialization() {
        let announcement =
            ProviderAnnouncement::status("12D3KooWTest", 100 * 1024 * 1024 * 1024, 42, 3600);

        let bytes = announcement.to_bytes().unwrap();
        let restored = ProviderAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(announcement.provider_id, restored.provider_id);
        assert_eq!(announcement.available_storage, restored.available_storage);
        assert_eq!(announcement.content_count, restored.content_count);
    }

    #[test]
    fn test_content_announcement_signing() {
        let keypair = chie_crypto::KeyPair::generate();

        let announcement =
            ContentAnnouncement::content_available("QmTest123", "12D3KooWTest", 1024 * 1024, 4)
                .sign(&keypair);

        assert!(announcement.signature.is_some());
        assert!(announcement.verify(&keypair.public_key()));

        // Verify fails with wrong key
        let other_keypair = chie_crypto::KeyPair::generate();
        assert!(!announcement.verify(&other_keypair.public_key()));
    }

    #[test]
    fn test_gossip_manager() {
        let mut manager = ContentAnnouncementGossip::new("12D3KooWLocal", GossipConfig::default());

        // Record local content
        manager.record_local_content("QmTest123");

        // Verify stats
        let stats = manager.stats();
        assert_eq!(stats.local_content_count, 1);

        // Remove local content
        manager.remove_local_content("QmTest123");
        let stats = manager.stats();
        assert_eq!(stats.local_content_count, 0);
    }

    #[test]
    fn test_announcement_expiry() {
        let mut announcement =
            ContentAnnouncement::content_available("QmTest123", "12D3KooWTest", 1024, 1);

        // Set timestamp to the past
        announcement.timestamp = 0;
        announcement.ttl_secs = 1;

        assert!(announcement.is_expired());
    }
}
