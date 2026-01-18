//! Content lifecycle event system for webhooks and callbacks.
//!
//! This module provides an event-driven system for tracking content lifecycle operations.
//! Applications can register event handlers to react to content additions, accesses, removals,
//! and other lifecycle events.
//!
//! # Example
//!
//! ```rust
//! use chie_core::lifecycle::{LifecycleEventManager, LifecycleEventType, ContentEvent};
//!
//! #[tokio::main]
//! async fn main() {
//!     let mut manager = LifecycleEventManager::new();
//!
//!     // Register an event handler
//!     manager.on(LifecycleEventType::ContentAdded, |event| {
//!         println!("Content added: {}", event.cid);
//!     });
//!
//!     // Emit an event
//!     manager.emit(ContentEvent {
//!         cid: "QmExample".to_string(),
//!         event_type: LifecycleEventType::ContentAdded,
//!         size_bytes: Some(1024),
//!         peer_id: None,
//!         metadata: None,
//!     }).await;
//! }
//! ```

use crate::http_pool::{HttpClientPool, HttpConfig};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Type of lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum LifecycleEventType {
    /// Content was added to storage.
    ContentAdded,
    /// Content was accessed/requested.
    ContentAccessed,
    /// Content was removed from storage.
    ContentRemoved,
    /// Content was pinned.
    ContentPinned,
    /// Content was unpinned.
    ContentUnpinned,
    /// Chunk was transferred.
    ChunkTransferred,
    /// Bandwidth proof was generated.
    ProofGenerated,
    /// Storage quota exceeded.
    QuotaExceeded,
    /// Content verification failed.
    VerificationFailed,
    /// Peer connection established.
    PeerConnected,
    /// Peer connection lost.
    PeerDisconnected,
}

/// A content lifecycle event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentEvent {
    /// Content identifier.
    pub cid: String,
    /// Type of event.
    pub event_type: LifecycleEventType,
    /// Content size in bytes (if applicable).
    pub size_bytes: Option<u64>,
    /// Peer ID involved (if applicable).
    pub peer_id: Option<String>,
    /// Additional metadata (JSON-compatible).
    pub metadata: Option<HashMap<String, String>>,
}

impl ContentEvent {
    /// Create a simple event without optional fields.
    #[inline]
    #[must_use]
    pub fn simple(cid: String, event_type: LifecycleEventType) -> Self {
        Self {
            cid,
            event_type,
            size_bytes: None,
            peer_id: None,
            metadata: None,
        }
    }

    /// Create an event with size information.
    #[inline]
    #[must_use]
    pub fn with_size(cid: String, event_type: LifecycleEventType, size_bytes: u64) -> Self {
        Self {
            cid,
            event_type,
            size_bytes: Some(size_bytes),
            peer_id: None,
            metadata: None,
        }
    }

    /// Create an event with peer information.
    #[inline]
    #[must_use]
    pub fn with_peer(cid: String, event_type: LifecycleEventType, peer_id: String) -> Self {
        Self {
            cid,
            event_type,
            size_bytes: None,
            peer_id: Some(peer_id),
            metadata: None,
        }
    }

    /// Add metadata to the event.
    #[inline]
    #[must_use]
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        if self.metadata.is_none() {
            self.metadata = Some(HashMap::new());
        }
        if let Some(ref mut metadata) = self.metadata {
            metadata.insert(key, value);
        }
        self
    }
}

/// Type alias for event handler functions.
pub type EventHandler = Arc<dyn Fn(&ContentEvent) + Send + Sync>;

/// Webhook configuration for HTTP callbacks.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Webhook URL.
    pub url: String,
    /// Events to trigger this webhook.
    pub events: Vec<LifecycleEventType>,
    /// Authentication header (optional).
    pub auth_header: Option<String>,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl WebhookConfig {
    /// Create a new webhook config for a URL.
    #[inline]
    #[must_use]
    pub fn new(url: String) -> Self {
        Self {
            url,
            events: vec![],
            auth_header: None,
            max_retries: 3,
            timeout_ms: 5000,
        }
    }

    /// Set which events should trigger this webhook.
    #[inline]
    #[must_use]
    pub fn for_events(mut self, events: Vec<LifecycleEventType>) -> Self {
        self.events = events;
        self
    }

    /// Add an authentication header.
    #[inline]
    #[must_use]
    pub fn with_auth(mut self, header: String) -> Self {
        self.auth_header = Some(header);
        self
    }
}

/// Event history entry.
#[derive(Debug, Clone)]
pub struct EventHistoryEntry {
    /// The event that occurred.
    pub event: ContentEvent,
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
}

/// Lifecycle event manager for handling content events.
pub struct LifecycleEventManager {
    /// Event handlers by event type.
    handlers: Arc<Mutex<HashMap<LifecycleEventType, Vec<EventHandler>>>>,
    /// Webhook configurations.
    webhooks: Arc<Mutex<Vec<WebhookConfig>>>,
    /// Event history (limited size).
    history: Arc<Mutex<VecDeque<EventHistoryEntry>>>,
    /// Maximum history size.
    max_history_size: usize,
    /// Event statistics.
    stats: Arc<Mutex<HashMap<LifecycleEventType, u64>>>,
    /// HTTP client pool for webhook requests.
    http_pool: Arc<HttpClientPool>,
}

use std::collections::VecDeque;

/// Send a webhook HTTP POST request for an event.
async fn send_webhook_request(
    http_pool: &HttpClientPool,
    webhook: &WebhookConfig,
    event: &ContentEvent,
) -> Result<(), crate::http_pool::HttpError> {
    // Serialize event to JSON
    let json_body = serde_json::to_value(event)
        .map_err(|e| crate::http_pool::HttpError::Serialization(e.to_string()))?;

    // Build the request with timeout
    let request = http_pool.post_json(&webhook.url, json_body).await?;

    // Check response status
    if request.status().is_success() {
        Ok(())
    } else {
        Err(crate::http_pool::HttpError::Response {
            status: request.status(),
            message: format!("Webhook failed with status {}", request.status()),
        })
    }
}

impl LifecycleEventManager {
    /// Create a new lifecycle event manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            webhooks: Arc::new(Mutex::new(Vec::new())),
            history: Arc::new(Mutex::new(VecDeque::new())),
            max_history_size: 1000,
            stats: Arc::new(Mutex::new(HashMap::new())),
            http_pool: Arc::new(HttpClientPool::new(HttpConfig::default())),
        }
    }

    /// Create a new manager with custom history size.
    #[must_use]
    #[inline]
    pub fn with_history_size(max_history_size: usize) -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            webhooks: Arc::new(Mutex::new(Vec::new())),
            history: Arc::new(Mutex::new(VecDeque::new())),
            max_history_size,
            stats: Arc::new(Mutex::new(HashMap::new())),
            http_pool: Arc::new(HttpClientPool::new(HttpConfig::default())),
        }
    }

    /// Register an event handler for a specific event type.
    pub fn on<F>(&mut self, event_type: LifecycleEventType, handler: F)
    where
        F: Fn(&ContentEvent) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.lock().unwrap();
        handlers
            .entry(event_type)
            .or_default()
            .push(Arc::new(handler));
    }

    /// Register a webhook for HTTP callbacks.
    pub fn register_webhook(&mut self, config: WebhookConfig) {
        let mut webhooks = self.webhooks.lock().unwrap();
        webhooks.push(config);
    }

    /// Emit an event, triggering all registered handlers.
    pub async fn emit(&self, event: ContentEvent) {
        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            *stats.entry(event.event_type).or_insert(0) += 1;
        }

        // Add to history
        {
            let mut history = self.history.lock().unwrap();
            history.push_back(EventHistoryEntry {
                event: event.clone(),
                timestamp_ms: crate::utils::current_timestamp_ms() as u64,
            });

            // Trim history if needed
            while history.len() > self.max_history_size {
                history.pop_front();
            }
        }

        // Call handlers
        {
            let handlers = self.handlers.lock().unwrap();
            if let Some(handlers_list) = handlers.get(&event.event_type) {
                for handler in handlers_list {
                    handler(&event);
                }
            }
        }

        // Trigger webhooks (in background)
        self.trigger_webhooks(&event).await;
    }

    /// Trigger webhooks for an event (async).
    async fn trigger_webhooks(&self, event: &ContentEvent) {
        let webhooks = self.webhooks.lock().unwrap().clone();

        for webhook in webhooks {
            // Check if this webhook should be triggered for this event type
            if !webhook.events.is_empty() && !webhook.events.contains(&event.event_type) {
                continue;
            }

            // Clone the http_pool Arc for this task
            let http_pool = Arc::clone(&self.http_pool);
            let event_clone = event.clone();
            let webhook_clone = webhook.clone();

            // Spawn a background task to send the webhook
            tokio::spawn(async move {
                // Attempt to send webhook with retries
                for attempt in 0..=webhook_clone.max_retries {
                    match send_webhook_request(&http_pool, &webhook_clone, &event_clone).await {
                        Ok(_) => {
                            // Success - webhook delivered
                            break;
                        }
                        Err(e) => {
                            // Log error (in production, use proper logging)
                            eprintln!(
                                "Webhook delivery failed (attempt {}/{}): {}",
                                attempt + 1,
                                webhook_clone.max_retries + 1,
                                e
                            );

                            // Don't retry if this was the last attempt
                            if attempt < webhook_clone.max_retries {
                                // Brief delay before retry
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            });
        }
    }

    /// Get event history for a specific event type.
    #[must_use]
    #[inline]
    pub fn get_history(&self, event_type: Option<LifecycleEventType>) -> Vec<EventHistoryEntry> {
        let history = self.history.lock().unwrap();
        match event_type {
            Some(et) => history
                .iter()
                .filter(|entry| entry.event.event_type == et)
                .cloned()
                .collect(),
            None => history.iter().cloned().collect(),
        }
    }

    /// Get recent events (last N).
    #[must_use]
    #[inline]
    pub fn get_recent(&self, count: usize) -> Vec<EventHistoryEntry> {
        let history = self.history.lock().unwrap();
        history.iter().rev().take(count).cloned().collect()
    }

    /// Get event count for a specific type.
    #[must_use]
    #[inline]
    pub fn get_event_count(&self, event_type: LifecycleEventType) -> u64 {
        self.stats
            .lock()
            .unwrap()
            .get(&event_type)
            .copied()
            .unwrap_or(0)
    }

    /// Get total event count across all types.
    #[must_use]
    #[inline]
    pub fn get_total_event_count(&self) -> u64 {
        self.stats.lock().unwrap().values().sum()
    }

    /// Get all event statistics.
    #[must_use]
    #[inline]
    pub fn get_stats(&self) -> HashMap<LifecycleEventType, u64> {
        self.stats.lock().unwrap().clone()
    }

    /// Clear event history.
    pub fn clear_history(&mut self) {
        self.history.lock().unwrap().clear();
    }

    /// Reset event statistics.
    pub fn reset_stats(&mut self) {
        self.stats.lock().unwrap().clear();
    }

    /// Remove all handlers for an event type.
    pub fn clear_handlers(&mut self, event_type: LifecycleEventType) {
        self.handlers.lock().unwrap().remove(&event_type);
    }

    /// Remove all webhooks.
    pub fn clear_webhooks(&mut self) {
        self.webhooks.lock().unwrap().clear();
    }
}

impl Default for LifecycleEventManager {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_event_creation() {
        let event = ContentEvent::simple("QmTest".to_string(), LifecycleEventType::ContentAdded);
        assert_eq!(event.cid, "QmTest");
        assert_eq!(event.event_type, LifecycleEventType::ContentAdded);
        assert!(event.size_bytes.is_none());
    }

    #[tokio::test]
    async fn test_event_with_size() {
        let event =
            ContentEvent::with_size("QmTest".to_string(), LifecycleEventType::ContentAdded, 1024);
        assert_eq!(event.size_bytes, Some(1024));
    }

    #[tokio::test]
    async fn test_event_with_peer() {
        let event = ContentEvent::with_peer(
            "QmTest".to_string(),
            LifecycleEventType::ChunkTransferred,
            "peer123".to_string(),
        );
        assert_eq!(event.peer_id, Some("peer123".to_string()));
    }

    #[tokio::test]
    async fn test_event_with_metadata() {
        let event = ContentEvent::simple("QmTest".to_string(), LifecycleEventType::ContentAdded)
            .with_metadata("key1".to_string(), "value1".to_string())
            .with_metadata("key2".to_string(), "value2".to_string());

        assert!(event.metadata.is_some());
        let metadata = event.metadata.unwrap();
        assert_eq!(metadata.get("key1"), Some(&"value1".to_string()));
        assert_eq!(metadata.get("key2"), Some(&"value2".to_string()));
    }

    #[tokio::test]
    async fn test_handler_registration() {
        let mut manager = LifecycleEventManager::new();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        manager.on(LifecycleEventType::ContentAdded, move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let event = ContentEvent::simple("QmTest".to_string(), LifecycleEventType::ContentAdded);
        manager.emit(event).await;

        // Wait a bit for handler to execute
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_multiple_handlers() {
        let mut manager = LifecycleEventManager::new();
        let counter = Arc::new(AtomicU32::new(0));

        let counter1 = counter.clone();
        manager.on(LifecycleEventType::ContentAdded, move |_event| {
            counter1.fetch_add(1, Ordering::SeqCst);
        });

        let counter2 = counter.clone();
        manager.on(LifecycleEventType::ContentAdded, move |_event| {
            counter2.fetch_add(1, Ordering::SeqCst);
        });

        let event = ContentEvent::simple("QmTest".to_string(), LifecycleEventType::ContentAdded);
        manager.emit(event).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_event_history() {
        let manager = LifecycleEventManager::new();

        let event1 = ContentEvent::simple("QmTest1".to_string(), LifecycleEventType::ContentAdded);
        let event2 =
            ContentEvent::simple("QmTest2".to_string(), LifecycleEventType::ContentAccessed);

        manager.emit(event1).await;
        manager.emit(event2).await;

        let history = manager.get_history(None);
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn test_filtered_history() {
        let manager = LifecycleEventManager::new();

        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        manager
            .emit(ContentEvent::simple(
                "Qm2".to_string(),
                LifecycleEventType::ContentAccessed,
            ))
            .await;
        manager
            .emit(ContentEvent::simple(
                "Qm3".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;

        let history = manager.get_history(Some(LifecycleEventType::ContentAdded));
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn test_recent_events() {
        let manager = LifecycleEventManager::new();

        for i in 0..5 {
            manager
                .emit(ContentEvent::simple(
                    format!("Qm{}", i),
                    LifecycleEventType::ContentAdded,
                ))
                .await;
        }

        let recent = manager.get_recent(3);
        assert_eq!(recent.len(), 3);
    }

    #[tokio::test]
    async fn test_event_statistics() {
        let manager = LifecycleEventManager::new();

        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        manager
            .emit(ContentEvent::simple(
                "Qm2".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        manager
            .emit(ContentEvent::simple(
                "Qm3".to_string(),
                LifecycleEventType::ContentAccessed,
            ))
            .await;

        assert_eq!(manager.get_event_count(LifecycleEventType::ContentAdded), 2);
        assert_eq!(
            manager.get_event_count(LifecycleEventType::ContentAccessed),
            1
        );
        assert_eq!(manager.get_total_event_count(), 3);
    }

    #[tokio::test]
    async fn test_history_size_limit() {
        let manager = LifecycleEventManager::with_history_size(5);

        for i in 0..10 {
            manager
                .emit(ContentEvent::simple(
                    format!("Qm{}", i),
                    LifecycleEventType::ContentAdded,
                ))
                .await;
        }

        let history = manager.get_history(None);
        assert_eq!(history.len(), 5);
    }

    #[tokio::test]
    async fn test_clear_history() {
        let mut manager = LifecycleEventManager::new();

        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        manager
            .emit(ContentEvent::simple(
                "Qm2".to_string(),
                LifecycleEventType::ContentAccessed,
            ))
            .await;

        assert_eq!(manager.get_history(None).len(), 2);

        manager.clear_history();
        assert_eq!(manager.get_history(None).len(), 0);
    }

    #[tokio::test]
    async fn test_reset_stats() {
        let mut manager = LifecycleEventManager::new();

        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        assert_eq!(manager.get_total_event_count(), 1);

        manager.reset_stats();
        assert_eq!(manager.get_total_event_count(), 0);
    }

    #[tokio::test]
    async fn test_webhook_config() {
        let webhook = WebhookConfig::new("https://example.com/webhook".to_string())
            .for_events(vec![
                LifecycleEventType::ContentAdded,
                LifecycleEventType::ContentRemoved,
            ])
            .with_auth("Bearer token123".to_string());

        assert_eq!(webhook.url, "https://example.com/webhook");
        assert_eq!(webhook.events.len(), 2);
        assert_eq!(webhook.auth_header, Some("Bearer token123".to_string()));
    }

    #[tokio::test]
    async fn test_webhook_registration() {
        let mut manager = LifecycleEventManager::new();
        let webhook = WebhookConfig::new("https://example.com/webhook".to_string());

        manager.register_webhook(webhook);

        // Emit event (webhook will be logged in debug mode)
        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
    }

    #[tokio::test]
    async fn test_clear_handlers() {
        let mut manager = LifecycleEventManager::new();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        manager.on(LifecycleEventType::ContentAdded, move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        manager
            .emit(ContentEvent::simple(
                "Qm1".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        manager.clear_handlers(LifecycleEventType::ContentAdded);
        manager
            .emit(ContentEvent::simple(
                "Qm2".to_string(),
                LifecycleEventType::ContentAdded,
            ))
            .await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should still be 1
    }
}
