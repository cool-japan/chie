//! Distributed cache invalidation notifications.
//!
//! This module provides a system for propagating cache invalidation notifications
//! across distributed nodes, ensuring cache consistency in the CHIE network.
//!
//! # Example
//!
//! ```
//! use chie_core::cache_invalidation::{InvalidationNotifier, InvalidationEvent, InvalidationReason};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let notifier = InvalidationNotifier::new();
//!
//! // Subscribe to invalidation events
//! let mut receiver = notifier.subscribe();
//!
//! // Invalidate a specific cache entry
//! notifier.invalidate_key("content:QmTest123", InvalidationReason::Updated).await;
//!
//! // Receive the invalidation event
//! if let Some(event) = receiver.recv().await {
//!     println!("Cache invalidated: {:?}", event.key);
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{RwLock, broadcast};

/// Maximum number of invalidation events to buffer per subscriber.
const INVALIDATION_BUFFER_SIZE: usize = 1024;

/// Errors that can occur during cache invalidation.
#[derive(Debug, Error)]
pub enum InvalidationError {
    #[error("Failed to send invalidation notification: {0}")]
    SendError(String),

    #[error("Invalid invalidation pattern: {0}")]
    InvalidPattern(String),

    #[error("Receiver disconnected")]
    ReceiverDisconnected,
}

/// Reason for cache invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationReason {
    /// Content was updated.
    Updated,
    /// Content was deleted.
    Deleted,
    /// Cache entry expired.
    Expired,
    /// Explicit invalidation request.
    Manual,
    /// Storage error or corruption detected.
    Error,
    /// Memory pressure requires eviction.
    MemoryPressure,
}

/// Cache invalidation event.
#[derive(Debug, Clone)]
pub struct InvalidationEvent {
    /// Cache key being invalidated.
    pub key: String,
    /// Reason for invalidation.
    pub reason: InvalidationReason,
    /// Timestamp of the invalidation event.
    pub timestamp: u64,
    /// Optional metadata about the invalidation.
    pub metadata: HashMap<String, String>,
    /// Node ID that originated this invalidation.
    pub origin_node_id: Option<String>,
}

impl InvalidationEvent {
    /// Create a new invalidation event.
    #[must_use]
    #[inline]
    pub fn new(key: String, reason: InvalidationReason) -> Self {
        Self {
            key,
            reason,
            timestamp: current_timestamp(),
            metadata: HashMap::new(),
            origin_node_id: None,
        }
    }

    /// Add metadata to the event.
    #[must_use]
    #[inline]
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set the origin node ID.
    #[must_use]
    #[inline]
    pub fn with_origin(mut self, node_id: String) -> Self {
        self.origin_node_id = Some(node_id);
        self
    }
}

/// Pattern for matching cache keys during invalidation.
#[derive(Debug, Clone)]
pub enum InvalidationPattern {
    /// Exact key match.
    Exact(String),
    /// Prefix match (e.g., "content:*").
    Prefix(String),
    /// Suffix match (e.g., "*:metadata").
    Suffix(String),
    /// Contains substring.
    Contains(String),
    /// Matches any of the provided tags.
    Tags(HashSet<String>),
}

impl InvalidationPattern {
    #[inline]
    /// Check if a key matches this pattern.
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Exact(exact) => key == exact,
            Self::Prefix(prefix) => key.starts_with(prefix),
            Self::Suffix(suffix) => key.ends_with(suffix),
            Self::Contains(substring) => key.contains(substring),
            Self::Tags(_) => false, // Tags require additional context
        }
    }
}

/// Statistics for cache invalidation.
#[derive(Debug, Clone, Default)]
pub struct InvalidationStats {
    /// Total invalidations sent.
    pub total_invalidations: u64,
    /// Invalidations by reason.
    pub by_reason: HashMap<String, u64>,
    /// Number of active subscribers.
    pub active_subscribers: usize,
    /// Failed invalidation attempts.
    pub failed_sends: u64,
}

/// Cache invalidation notifier for distributed systems.
pub struct InvalidationNotifier {
    /// Broadcast channel for invalidation events.
    sender: broadcast::Sender<InvalidationEvent>,
    /// Statistics tracking.
    stats: Arc<RwLock<InvalidationStats>>,
    /// Tag-based key mapping for efficient invalidation.
    tag_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl InvalidationNotifier {
    /// Create a new invalidation notifier.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(INVALIDATION_BUFFER_SIZE);
        Self {
            sender,
            stats: Arc::new(RwLock::new(InvalidationStats::default())),
            tag_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to invalidation events.
    #[must_use]
    #[inline]
    pub fn subscribe(&self) -> InvalidationReceiver {
        let receiver = self.sender.subscribe();
        InvalidationReceiver { receiver }
    }

    /// Invalidate a specific cache key.
    pub async fn invalidate_key(&self, key: &str, reason: InvalidationReason) {
        let event = InvalidationEvent::new(key.to_string(), reason.clone());
        self.send_event(event).await;
    }

    /// Invalidate multiple keys at once.
    pub async fn invalidate_keys(&self, keys: &[String], reason: InvalidationReason) {
        for key in keys {
            let event = InvalidationEvent::new(key.clone(), reason.clone());
            self.send_event(event).await;
        }
    }

    /// Invalidate all keys matching a pattern.
    pub async fn invalidate_pattern(
        &self,
        pattern: InvalidationPattern,
        reason: InvalidationReason,
        known_keys: &[String],
    ) {
        for key in known_keys {
            if pattern.matches(key) {
                let event = InvalidationEvent::new(key.clone(), reason.clone());
                self.send_event(event).await;
            }
        }
    }

    /// Invalidate all keys associated with a tag.
    pub async fn invalidate_tag(&self, tag: &str, reason: InvalidationReason) {
        let keys = {
            let index = self.tag_index.read().await;
            index.get(tag).cloned().unwrap_or_default()
        };

        for key in keys {
            let event = InvalidationEvent::new(key, reason.clone());
            self.send_event(event).await;
        }
    }

    /// Associate a key with tags for future invalidation.
    pub async fn tag_key(&self, key: String, tags: Vec<String>) {
        let mut index = self.tag_index.write().await;
        for tag in tags {
            index
                .entry(tag)
                .or_insert_with(HashSet::new)
                .insert(key.clone());
        }
    }

    /// Remove tag associations for a key.
    pub async fn untag_key(&self, key: &str) {
        let mut index = self.tag_index.write().await;
        for keys in index.values_mut() {
            keys.remove(key);
        }
    }

    /// Send an invalidation event.
    async fn send_event(&self, event: InvalidationEvent) {
        let reason_key = format!("{:?}", event.reason);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_invalidations += 1;
            *stats.by_reason.entry(reason_key).or_insert(0) += 1;
            stats.active_subscribers = self.sender.receiver_count();
        }

        // Send the event (ignore errors if no subscribers)
        if self.sender.send(event).is_err() {
            let mut stats = self.stats.write().await;
            stats.failed_sends += 1;
        }
    }

    /// Get current invalidation statistics.
    #[must_use]
    #[inline]
    pub async fn stats(&self) -> InvalidationStats {
        self.stats.read().await.clone()
    }

    /// Get the number of active subscribers.
    #[must_use]
    #[inline]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for InvalidationNotifier {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Receiver for invalidation events.
pub struct InvalidationReceiver {
    receiver: broadcast::Receiver<InvalidationEvent>,
}

impl InvalidationReceiver {
    /// Receive the next invalidation event.
    pub async fn recv(&mut self) -> Option<InvalidationEvent> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    eprintln!(
                        "Warning: Invalidation receiver lagged, skipped {} events",
                        skipped
                    );
                    // Continue to next iteration to try receiving again
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// Try to receive an event without blocking.
    pub fn try_recv(&mut self) -> Result<InvalidationEvent, InvalidationError> {
        self.receiver.try_recv().map_err(|e| match e {
            broadcast::error::TryRecvError::Empty => InvalidationError::ReceiverDisconnected,
            broadcast::error::TryRecvError::Lagged(_) => InvalidationError::ReceiverDisconnected,
            broadcast::error::TryRecvError::Closed => InvalidationError::ReceiverDisconnected,
        })
    }
}

/// Batch invalidation manager for efficient bulk operations.
pub struct BatchInvalidation {
    notifier: Arc<InvalidationNotifier>,
    batch: Vec<(String, InvalidationReason)>,
    max_batch_size: usize,
}

impl BatchInvalidation {
    /// Create a new batch invalidation manager.
    #[must_use]
    #[inline]
    pub fn new(notifier: Arc<InvalidationNotifier>, max_batch_size: usize) -> Self {
        Self {
            notifier,
            batch: Vec::with_capacity(max_batch_size),
            max_batch_size,
        }
    }

    /// Add a key to the batch.
    #[inline]
    pub fn add(&mut self, key: String, reason: InvalidationReason) {
        self.batch.push((key, reason));
        if self.batch.len() >= self.max_batch_size {
            // Note: In real implementation, this would trigger async flush
            // For now, we just track the batch
        }
    }

    /// Flush the batch and send all invalidations.
    pub async fn flush(&mut self) {
        for (key, reason) in self.batch.drain(..) {
            self.notifier.invalidate_key(&key, reason).await;
        }
    }

    /// Get the current batch size.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Check if the batch is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

/// Get current Unix timestamp.
#[inline]
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_invalidation() {
        let notifier = InvalidationNotifier::new();
        let mut receiver = notifier.subscribe();

        notifier
            .invalidate_key("test:key", InvalidationReason::Updated)
            .await;

        let event = receiver.recv().await.unwrap();
        assert_eq!(event.key, "test:key");
        assert_eq!(event.reason, InvalidationReason::Updated);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let notifier = InvalidationNotifier::new();
        let mut receiver1 = notifier.subscribe();
        let mut receiver2 = notifier.subscribe();

        notifier
            .invalidate_key("test:key", InvalidationReason::Deleted)
            .await;

        let event1 = receiver1.recv().await.unwrap();
        let event2 = receiver2.recv().await.unwrap();

        assert_eq!(event1.key, event2.key);
        assert_eq!(event1.reason, event2.reason);
    }

    #[tokio::test]
    async fn test_batch_invalidation() {
        let notifier = InvalidationNotifier::new();
        let mut receiver = notifier.subscribe();

        let keys = vec!["key1".to_string(), "key2".to_string(), "key3".to_string()];
        notifier
            .invalidate_keys(&keys, InvalidationReason::Expired)
            .await;

        for _ in 0..3 {
            let event = receiver.recv().await.unwrap();
            assert!(keys.contains(&event.key));
            assert_eq!(event.reason, InvalidationReason::Expired);
        }
    }

    #[tokio::test]
    async fn test_pattern_prefix() {
        let pattern = InvalidationPattern::Prefix("content:".to_string());
        assert!(pattern.matches("content:abc123"));
        assert!(!pattern.matches("metadata:abc123"));
    }

    #[tokio::test]
    async fn test_pattern_suffix() {
        let pattern = InvalidationPattern::Suffix(":metadata".to_string());
        assert!(pattern.matches("content:metadata"));
        assert!(!pattern.matches("content:data"));
    }

    #[tokio::test]
    async fn test_pattern_contains() {
        let pattern = InvalidationPattern::Contains("temp".to_string());
        assert!(pattern.matches("cache:temp:data"));
        assert!(!pattern.matches("cache:perm:data"));
    }

    #[tokio::test]
    async fn test_tag_based_invalidation() {
        let notifier = InvalidationNotifier::new();
        let mut receiver = notifier.subscribe();

        // Tag some keys
        notifier
            .tag_key("key1".to_string(), vec!["user:123".to_string()])
            .await;
        notifier
            .tag_key("key2".to_string(), vec!["user:123".to_string()])
            .await;
        notifier
            .tag_key("key3".to_string(), vec!["user:456".to_string()])
            .await;

        // Invalidate by tag
        notifier
            .invalidate_tag("user:123", InvalidationReason::Updated)
            .await;

        // Should receive 2 invalidation events
        let mut received_keys = HashSet::new();
        for _ in 0..2 {
            if let Some(event) = receiver.recv().await {
                received_keys.insert(event.key.clone());
            }
        }

        assert!(received_keys.contains("key1"));
        assert!(received_keys.contains("key2"));
        assert!(!received_keys.contains("key3"));
    }

    #[tokio::test]
    async fn test_invalidation_stats() {
        let notifier = InvalidationNotifier::new();

        notifier
            .invalidate_key("key1", InvalidationReason::Updated)
            .await;
        notifier
            .invalidate_key("key2", InvalidationReason::Deleted)
            .await;
        notifier
            .invalidate_key("key3", InvalidationReason::Updated)
            .await;

        let stats = notifier.stats().await;
        assert_eq!(stats.total_invalidations, 3);
        assert_eq!(*stats.by_reason.get("Updated").unwrap_or(&0), 2);
        assert_eq!(*stats.by_reason.get("Deleted").unwrap_or(&0), 1);
    }

    #[tokio::test]
    async fn test_untag_key() {
        let notifier = InvalidationNotifier::new();

        notifier
            .tag_key("key1".to_string(), vec!["tag1".to_string()])
            .await;
        notifier.untag_key("key1").await;

        let mut receiver = notifier.subscribe();
        notifier
            .invalidate_tag("tag1", InvalidationReason::Manual)
            .await;

        // Should not receive any events since key was untagged
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_batch_invalidation_manager() {
        let notifier = Arc::new(InvalidationNotifier::new());
        let mut receiver = notifier.subscribe();

        let mut batch = BatchInvalidation::new(notifier.clone(), 10);
        batch.add("key1".to_string(), InvalidationReason::Manual);
        batch.add("key2".to_string(), InvalidationReason::Manual);

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());

        batch.flush().await;
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());

        // Should receive 2 events
        for _ in 0..2 {
            assert!(receiver.recv().await.is_some());
        }
    }

    #[tokio::test]
    async fn test_subscriber_count() {
        let notifier = InvalidationNotifier::new();
        assert_eq!(notifier.subscriber_count(), 0);

        let _receiver1 = notifier.subscribe();
        assert_eq!(notifier.subscriber_count(), 1);

        let _receiver2 = notifier.subscribe();
        assert_eq!(notifier.subscriber_count(), 2);
    }

    #[test]
    fn test_invalidation_event_builder() {
        let event = InvalidationEvent::new("test:key".to_string(), InvalidationReason::Updated)
            .with_metadata("version".to_string(), "2".to_string())
            .with_origin("node123".to_string());

        assert_eq!(event.key, "test:key");
        assert_eq!(event.metadata.get("version").unwrap(), "2");
        assert_eq!(event.origin_node_id.as_ref().unwrap(), "node123");
    }
}
