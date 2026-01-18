//! Distributed cache invalidation and propagation system.
//!
//! This module provides cache invalidation capabilities across a P2P network,
//! ensuring cache consistency when content is updated or deleted. Essential
//! for distributed CDNs where cached content must be invalidated across
//! multiple nodes efficiently.
//!
//! # Features
//!
//! - Pattern-based invalidation (exact, prefix, wildcard)
//! - Invalidation event propagation via gossip protocol
//! - Tag-based cache invalidation for grouped content
//! - Time-to-live (TTL) for invalidation messages
//! - Purge vs. invalidate semantics (delete vs. mark stale)
//! - Invalidation deduplication to prevent storms
//! - Batch invalidation for efficiency
//! - Comprehensive invalidation statistics
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{CacheInvalidation, InvalidationPattern, InvalidationType};
//!
//! let mut invalidator = CacheInvalidation::new();
//!
//! // Invalidate specific content
//! invalidator.invalidate(
//!     "content-123",
//!     InvalidationPattern::Exact("video/movie.mp4".to_string()),
//!     InvalidationType::Invalidate,
//! );
//!
//! // Invalidate by prefix (all videos)
//! invalidator.invalidate(
//!     "batch-1",
//!     InvalidationPattern::Prefix("video/".to_string()),
//!     InvalidationType::Purge,
//! );
//!
//! // Check if content should be invalidated
//! if invalidator.should_invalidate("video/movie.mp4") {
//!     println!("Content is invalidated");
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Type of invalidation operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationType {
    /// Mark content as stale (soft invalidation)
    Invalidate,
    /// Remove content immediately (hard invalidation)
    Purge,
    /// Refresh content (fetch new version)
    Refresh,
}

/// Pattern matching for cache invalidation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationPattern {
    /// Exact key match
    Exact(String),
    /// Prefix match (e.g., "images/" matches "images/photo.jpg")
    Prefix(String),
    /// Suffix match (e.g., ".jpg" matches "photo.jpg")
    Suffix(String),
    /// Wildcard pattern (simple glob-style)
    Wildcard(String),
    /// Tag-based (invalidate all content with this tag)
    Tag(String),
}

impl InvalidationPattern {
    /// Check if a key matches this pattern
    pub fn matches(&self, key: &str) -> bool {
        match self {
            InvalidationPattern::Exact(pattern) => key == pattern,
            InvalidationPattern::Prefix(pattern) => key.starts_with(pattern),
            InvalidationPattern::Suffix(pattern) => key.ends_with(pattern),
            InvalidationPattern::Wildcard(pattern) => Self::wildcard_match(pattern, key),
            InvalidationPattern::Tag(_) => false, // Tags require separate handling
        }
    }

    /// Simple wildcard matching (* and ?)
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let mut pattern_chars = pattern.chars().peekable();
        let mut text_chars = text.chars().peekable();

        while let Some(&p) = pattern_chars.peek() {
            match p {
                '*' => {
                    pattern_chars.next();
                    if pattern_chars.peek().is_none() {
                        return true; // * at end matches everything
                    }

                    // Try to match rest of pattern with rest of text
                    while text_chars.peek().is_some() {
                        let remaining_pattern: String = pattern_chars.clone().collect();
                        let remaining_text: String = text_chars.clone().collect();
                        if Self::wildcard_match(&remaining_pattern, &remaining_text) {
                            return true;
                        }
                        text_chars.next();
                    }
                    return false;
                }
                '?' => {
                    pattern_chars.next();
                    if text_chars.next().is_none() {
                        return false;
                    }
                }
                _ => {
                    pattern_chars.next();
                    if text_chars.next() != Some(p) {
                        return false;
                    }
                }
            }
        }

        text_chars.peek().is_none()
    }
}

/// Invalidation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationEvent {
    /// Unique event ID
    pub id: String,
    /// Pattern to match for invalidation
    pub pattern: InvalidationPattern,
    /// Type of invalidation
    pub invalidation_type: InvalidationType,
    /// When this event was created
    pub created_at: u64, // Unix timestamp
    /// TTL for this event (seconds)
    pub ttl: u64,
    /// Origin node that initiated this invalidation
    pub origin: String,
    /// Optional reason for invalidation
    pub reason: Option<String>,
    /// Tags associated with this invalidation
    pub tags: Vec<String>,
}

impl InvalidationEvent {
    /// Check if this event has expired
    pub fn is_expired(&self, now: u64) -> bool {
        self.created_at + self.ttl < now
    }

    /// Get remaining TTL in seconds
    pub fn remaining_ttl(&self, now: u64) -> u64 {
        let expires_at = self.created_at + self.ttl;
        expires_at.saturating_sub(now)
    }
}

/// Statistics for cache invalidation
#[derive(Debug, Clone, Default)]
pub struct InvalidationStats {
    /// Total invalidation events processed
    pub total_events: u64,
    /// Total exact match invalidations
    pub exact_matches: u64,
    /// Total prefix invalidations
    pub prefix_invalidations: u64,
    /// Total wildcard invalidations
    pub wildcard_invalidations: u64,
    /// Total tag-based invalidations
    pub tag_invalidations: u64,
    /// Total purge operations
    pub purges: u64,
    /// Total refresh operations
    pub refreshes: u64,
    /// Number of deduplicated events
    pub deduplicated: u64,
    /// Number of expired events cleaned up
    pub expired_cleaned: u64,
    /// Number of currently active patterns
    pub active_patterns: usize,
}

/// Cache invalidation manager
pub struct CacheInvalidation {
    /// Active invalidation events
    events: Arc<parking_lot::RwLock<HashMap<String, InvalidationEvent>>>,
    /// Tag to content ID mapping
    tag_map: Arc<parking_lot::RwLock<HashMap<String, HashSet<String>>>>,
    /// Content ID to tags mapping
    content_tags: Arc<parking_lot::RwLock<HashMap<String, HashSet<String>>>>,
    /// Statistics
    stats: Arc<parking_lot::RwLock<InvalidationStats>>,
    /// Last cleanup time
    last_cleanup: Arc<parking_lot::RwLock<Instant>>,
    /// Default TTL for invalidation events (seconds)
    default_ttl: u64,
    /// Node ID
    node_id: String,
}

impl CacheInvalidation {
    /// Create a new cache invalidation manager
    pub fn new() -> Self {
        Self::with_config("node-0".to_string(), 3600)
    }

    /// Create with custom configuration
    pub fn with_config(node_id: String, default_ttl: u64) -> Self {
        Self {
            events: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            tag_map: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            content_tags: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            stats: Arc::new(parking_lot::RwLock::new(InvalidationStats::default())),
            last_cleanup: Arc::new(parking_lot::RwLock::new(Instant::now())),
            default_ttl,
            node_id,
        }
    }

    /// Trigger an invalidation
    pub fn invalidate(
        &mut self,
        id: impl Into<String>,
        pattern: InvalidationPattern,
        invalidation_type: InvalidationType,
    ) -> InvalidationEvent {
        self.invalidate_with_reason(id, pattern, invalidation_type, None)
    }

    /// Trigger an invalidation with a reason
    pub fn invalidate_with_reason(
        &mut self,
        id: impl Into<String>,
        pattern: InvalidationPattern,
        invalidation_type: InvalidationType,
        reason: Option<String>,
    ) -> InvalidationEvent {
        let id = id.into();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = InvalidationEvent {
            id: id.clone(),
            pattern: pattern.clone(),
            invalidation_type,
            created_at: now,
            ttl: self.default_ttl,
            origin: self.node_id.clone(),
            reason,
            tags: Vec::new(),
        };

        // Check for duplicates
        if self.events.read().contains_key(&id) {
            self.stats.write().deduplicated += 1;
            return event;
        }

        self.events.write().insert(id, event.clone());

        // Update stats
        let mut stats = self.stats.write();
        stats.total_events += 1;
        match &pattern {
            InvalidationPattern::Exact(_) => stats.exact_matches += 1,
            InvalidationPattern::Prefix(_) => stats.prefix_invalidations += 1,
            InvalidationPattern::Wildcard(_) => stats.wildcard_invalidations += 1,
            InvalidationPattern::Tag(_) => stats.tag_invalidations += 1,
            InvalidationPattern::Suffix(_) => stats.prefix_invalidations += 1,
        }
        match invalidation_type {
            InvalidationType::Purge => stats.purges += 1,
            InvalidationType::Refresh => stats.refreshes += 1,
            _ => {}
        }
        stats.active_patterns = self.events.read().len();

        event
    }

    /// Batch invalidate multiple patterns
    pub fn batch_invalidate(
        &mut self,
        patterns: Vec<(String, InvalidationPattern, InvalidationType)>,
    ) -> Vec<InvalidationEvent> {
        patterns
            .into_iter()
            .map(|(id, pattern, inv_type)| self.invalidate(id, pattern, inv_type))
            .collect()
    }

    /// Associate a tag with content
    pub fn tag_content(&mut self, content_id: &str, tag: &str) {
        self.tag_map
            .write()
            .entry(tag.to_string())
            .or_default()
            .insert(content_id.to_string());

        self.content_tags
            .write()
            .entry(content_id.to_string())
            .or_default()
            .insert(tag.to_string());
    }

    /// Remove tag from content
    pub fn untag_content(&mut self, content_id: &str, tag: &str) {
        if let Some(content_ids) = self.tag_map.write().get_mut(tag) {
            content_ids.remove(content_id);
        }

        if let Some(tags) = self.content_tags.write().get_mut(content_id) {
            tags.remove(tag);
        }
    }

    /// Check if content should be invalidated
    pub fn should_invalidate(&self, key: &str) -> bool {
        self.cleanup_expired();

        let events = self.events.read();

        for event in events.values() {
            match &event.pattern {
                InvalidationPattern::Tag(tag) => {
                    if let Some(content_ids) = self.tag_map.read().get(tag) {
                        if content_ids.contains(key) {
                            return true;
                        }
                    }
                }
                pattern => {
                    if pattern.matches(key) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Get invalidation type for content
    pub fn get_invalidation_type(&self, key: &str) -> Option<InvalidationType> {
        self.cleanup_expired();

        let events = self.events.read();

        for event in events.values() {
            let matches = match &event.pattern {
                InvalidationPattern::Tag(tag) => {
                    if let Some(content_ids) = self.tag_map.read().get(tag) {
                        content_ids.contains(key)
                    } else {
                        false
                    }
                }
                pattern => pattern.matches(key),
            };

            if matches {
                return Some(event.invalidation_type);
            }
        }

        None
    }

    /// Receive an invalidation event from another node
    pub fn receive_event(&mut self, event: InvalidationEvent) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Ignore expired events
        if event.is_expired(now) {
            return;
        }

        // Check for duplicates
        if self.events.read().contains_key(&event.id) {
            self.stats.write().deduplicated += 1;
            return;
        }

        self.events.write().insert(event.id.clone(), event);
        self.stats.write().total_events += 1;
        self.stats.write().active_patterns = self.events.read().len();
    }

    /// Get all active events
    pub fn get_active_events(&self) -> Vec<InvalidationEvent> {
        self.cleanup_expired();
        self.events.read().values().cloned().collect()
    }

    /// Clear all invalidation events
    pub fn clear_all(&mut self) {
        self.events.write().clear();
        self.stats.write().active_patterns = 0;
    }

    /// Clear specific event
    pub fn clear_event(&mut self, id: &str) -> bool {
        let result = self.events.write().remove(id).is_some();
        if result {
            self.stats.write().active_patterns = self.events.read().len();
        }
        result
    }

    /// Clean up expired events
    fn cleanup_expired(&self) {
        let now_instant = Instant::now();

        // Only cleanup every 60 seconds
        if now_instant.duration_since(*self.last_cleanup.read()) < Duration::from_secs(60) {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut events = self.events.write();
        let before_count = events.len();

        events.retain(|_, event| !event.is_expired(now));

        let removed = before_count - events.len();
        drop(events);

        let mut stats = self.stats.write();
        stats.expired_cleaned += removed as u64;
        stats.active_patterns = self.events.read().len();

        *self.last_cleanup.write() = now_instant;
    }

    /// Get current statistics
    pub fn stats(&self) -> InvalidationStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        *self.stats.write() = InvalidationStats {
            active_patterns: self.events.read().len(),
            ..Default::default()
        };
    }
}

impl Default for CacheInvalidation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pattern() {
        let pattern = InvalidationPattern::Exact("test.jpg".to_string());
        assert!(pattern.matches("test.jpg"));
        assert!(!pattern.matches("test2.jpg"));
    }

    #[test]
    fn test_prefix_pattern() {
        let pattern = InvalidationPattern::Prefix("images/".to_string());
        assert!(pattern.matches("images/photo.jpg"));
        assert!(pattern.matches("images/subfolder/pic.png"));
        assert!(!pattern.matches("videos/movie.mp4"));
    }

    #[test]
    fn test_suffix_pattern() {
        let pattern = InvalidationPattern::Suffix(".jpg".to_string());
        assert!(pattern.matches("photo.jpg"));
        assert!(pattern.matches("images/photo.jpg"));
        assert!(!pattern.matches("photo.png"));
    }

    #[test]
    fn test_wildcard_pattern() {
        let pattern = InvalidationPattern::Wildcard("*.jpg".to_string());
        assert!(pattern.matches("photo.jpg"));
        assert!(pattern.matches("test.jpg"));
        assert!(!pattern.matches("photo.png"));

        let pattern2 = InvalidationPattern::Wildcard("video/*.mp4".to_string());
        assert!(pattern2.matches("video/movie.mp4"));
        assert!(!pattern2.matches("audio/song.mp3"));
    }

    #[test]
    fn test_wildcard_question_mark() {
        let pattern = InvalidationPattern::Wildcard("test?.jpg".to_string());
        assert!(pattern.matches("test1.jpg"));
        assert!(pattern.matches("testa.jpg"));
        assert!(!pattern.matches("test.jpg"));
        assert!(!pattern.matches("test12.jpg"));
    }

    #[test]
    fn test_invalidate() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        assert!(invalidator.should_invalidate("test.jpg"));
        assert!(!invalidator.should_invalidate("other.jpg"));
    }

    #[test]
    fn test_invalidate_with_reason() {
        let mut invalidator = CacheInvalidation::new();
        let event = invalidator.invalidate_with_reason(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Purge,
            Some("Content updated".to_string()),
        );

        assert_eq!(event.reason, Some("Content updated".to_string()));
        assert_eq!(event.invalidation_type, InvalidationType::Purge);
    }

    #[test]
    fn test_batch_invalidate() {
        let mut invalidator = CacheInvalidation::new();
        let patterns = vec![
            (
                "event-1".to_string(),
                InvalidationPattern::Exact("test1.jpg".to_string()),
                InvalidationType::Invalidate,
            ),
            (
                "event-2".to_string(),
                InvalidationPattern::Exact("test2.jpg".to_string()),
                InvalidationType::Purge,
            ),
        ];

        let events = invalidator.batch_invalidate(patterns);
        assert_eq!(events.len(), 2);
        assert!(invalidator.should_invalidate("test1.jpg"));
        assert!(invalidator.should_invalidate("test2.jpg"));
    }

    #[test]
    fn test_tag_content() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.tag_content("photo1.jpg", "user:123");
        invalidator.tag_content("photo2.jpg", "user:123");

        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Tag("user:123".to_string()),
            InvalidationType::Invalidate,
        );

        assert!(invalidator.should_invalidate("photo1.jpg"));
        assert!(invalidator.should_invalidate("photo2.jpg"));
    }

    #[test]
    fn test_untag_content() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.tag_content("photo1.jpg", "user:123");
        invalidator.untag_content("photo1.jpg", "user:123");

        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Tag("user:123".to_string()),
            InvalidationType::Invalidate,
        );

        assert!(!invalidator.should_invalidate("photo1.jpg"));
    }

    #[test]
    fn test_get_invalidation_type() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Purge,
        );

        assert_eq!(
            invalidator.get_invalidation_type("test.jpg"),
            Some(InvalidationType::Purge)
        );
        assert_eq!(invalidator.get_invalidation_type("other.jpg"), None);
    }

    #[test]
    fn test_deduplication() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        assert_eq!(invalidator.stats().deduplicated, 1);
        assert_eq!(invalidator.stats().total_events, 1);
    }

    #[test]
    fn test_clear_event() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        assert!(invalidator.clear_event("event-1"));
        assert!(!invalidator.should_invalidate("test.jpg"));
    }

    #[test]
    fn test_clear_all() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test1.jpg".to_string()),
            InvalidationType::Invalidate,
        );
        invalidator.invalidate(
            "event-2",
            InvalidationPattern::Exact("test2.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        invalidator.clear_all();
        assert!(!invalidator.should_invalidate("test1.jpg"));
        assert!(!invalidator.should_invalidate("test2.jpg"));
        assert_eq!(invalidator.stats().active_patterns, 0);
    }

    #[test]
    fn test_get_active_events() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        let events = invalidator.get_active_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "event-1");
    }

    #[test]
    fn test_stats() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Purge,
        );
        invalidator.invalidate(
            "event-2",
            InvalidationPattern::Prefix("images/".to_string()),
            InvalidationType::Refresh,
        );

        let stats = invalidator.stats();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.exact_matches, 1);
        assert_eq!(stats.prefix_invalidations, 1);
        assert_eq!(stats.purges, 1);
        assert_eq!(stats.refreshes, 1);
    }

    #[test]
    fn test_reset_stats() {
        let mut invalidator = CacheInvalidation::new();
        invalidator.invalidate(
            "event-1",
            InvalidationPattern::Exact("test.jpg".to_string()),
            InvalidationType::Invalidate,
        );

        invalidator.reset_stats();
        let stats = invalidator.stats();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.exact_matches, 0);
    }

    #[test]
    fn test_event_expiration() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = InvalidationEvent {
            id: "test".to_string(),
            pattern: InvalidationPattern::Exact("test.jpg".to_string()),
            invalidation_type: InvalidationType::Invalidate,
            created_at: now - 3600,
            ttl: 1800,
            origin: "node-1".to_string(),
            reason: None,
            tags: Vec::new(),
        };

        assert!(event.is_expired(now));
        assert_eq!(event.remaining_ttl(now), 0);
    }

    #[test]
    fn test_receive_event() {
        let mut invalidator = CacheInvalidation::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let event = InvalidationEvent {
            id: "remote-1".to_string(),
            pattern: InvalidationPattern::Exact("test.jpg".to_string()),
            invalidation_type: InvalidationType::Invalidate,
            created_at: now,
            ttl: 3600,
            origin: "node-2".to_string(),
            reason: None,
            tags: Vec::new(),
        };

        invalidator.receive_event(event);
        assert!(invalidator.should_invalidate("test.jpg"));
    }
}
