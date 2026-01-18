//! Event bus for internal pub/sub communication.
//!
//! This module provides a lightweight event system for decoupled communication
//! between different parts of the CHIE node. It supports both sync and async
//! event buses, event filtering, and event batching.
//!
//! # Features
//!
//! - **Sync Event Bus**: Standard multi-producer, multi-consumer channels
//! - **Async Event Bus**: Tokio broadcast channels for async/await code
//! - **Event Filtering**: Filter events by type, timestamp, or payload
//! - **Event Batching**: Efficient bulk event processing
//! - **Statistics**: Track event counts and subscriber metrics
//!
//! # Example (Sync)
//!
//! ```rust
//! use chie_core::events::{EventBus, Event, EventType};
//!
//! let bus = EventBus::new();
//!
//! // Subscribe to content events
//! let rx = bus.subscribe(EventType::ContentAdded);
//!
//! // Publish an event
//! bus.publish(Event::content_added("QmExample123", 1024 * 1024));
//!
//! // Receive events (non-blocking)
//! if let Ok(event) = rx.try_recv() {
//!     println!("Received: {:?}", event);
//! }
//! ```
//!
//! # Example (Async)
//!
//! ```rust
//! use chie_core::events::{AsyncEventBus, Event, EventType};
//!
//! # async fn example() {
//! let bus = AsyncEventBus::new(100);
//! let mut rx = bus.subscribe(EventType::ContentAdded);
//!
//! // Publish an event
//! let _ = bus.publish(Event::content_added("QmExample123", 1024 * 1024));
//!
//! // Receive events (async)
//! if let Ok(event) = rx.recv().await {
//!     println!("Received: {:?}", event);
//! }
//! # }
//! ```
//!
//! # Example (Filtering)
//!
//! ```rust
//! use chie_core::events::{EventFilter, Event, EventType, PayloadFilter};
//!
//! let filter = EventFilter::new()
//!     .with_types(vec![EventType::ContentAdded])
//!     .with_payload_filter(PayloadFilter::MinBytes(1024 * 1024));
//!
//! let event = Event::content_added("QmExample123", 2 * 1024 * 1024);
//! assert!(filter.matches(&event));
//! ```

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Event types in the CHIE system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EventType {
    /// Content was added to storage.
    ContentAdded,
    /// Content was removed from storage.
    ContentRemoved,
    /// Content was requested.
    ContentRequested,
    /// Bandwidth proof was generated.
    ProofGenerated,
    /// Bandwidth proof was submitted.
    ProofSubmitted,
    /// Peer connected.
    PeerConnected,
    /// Peer disconnected.
    PeerDisconnected,
    /// Peer reputation changed.
    ReputationChanged,
    /// Storage quota exceeded.
    QuotaExceeded,
    /// Garbage collection completed.
    GarbageCollected,
    /// Node started.
    NodeStarted,
    /// Node stopped.
    NodeStopped,
}

/// Event data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Event {
    /// Event type.
    pub event_type: EventType,
    /// Timestamp in milliseconds.
    pub timestamp_ms: i64,
    /// Event payload.
    pub payload: EventPayload,
}

/// Event payload data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum EventPayload {
    /// Content event (CID, size in bytes).
    Content { cid: String, size_bytes: u64 },
    /// Proof event (proof ID, bytes transferred).
    Proof { proof_id: String, bytes: u64 },
    /// Peer event (peer ID).
    Peer { peer_id: String },
    /// Reputation event (peer ID, old score, new score).
    Reputation {
        peer_id: String,
        old_score: f64,
        new_score: f64,
    },
    /// Quota event (used bytes, max bytes).
    Quota { used_bytes: u64, max_bytes: u64 },
    /// Garbage collection event (freed bytes, items removed).
    GarbageCollection {
        freed_bytes: u64,
        items_removed: usize,
    },
    /// Node lifecycle event.
    Node,
}

impl Event {
    /// Create a content added event.
    #[must_use]
    #[inline]
    pub fn content_added(cid: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            event_type: EventType::ContentAdded,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Content {
                cid: cid.into(),
                size_bytes,
            },
        }
    }

    /// Create a content removed event.
    #[must_use]
    #[inline]
    pub fn content_removed(cid: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            event_type: EventType::ContentRemoved,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Content {
                cid: cid.into(),
                size_bytes,
            },
        }
    }

    /// Create a content requested event.
    #[must_use]
    #[inline]
    pub fn content_requested(cid: impl Into<String>, size_bytes: u64) -> Self {
        Self {
            event_type: EventType::ContentRequested,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Content {
                cid: cid.into(),
                size_bytes,
            },
        }
    }

    /// Create a proof generated event.
    #[must_use]
    #[inline]
    pub fn proof_generated(proof_id: impl Into<String>, bytes: u64) -> Self {
        Self {
            event_type: EventType::ProofGenerated,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Proof {
                proof_id: proof_id.into(),
                bytes,
            },
        }
    }

    /// Create a proof submitted event.
    #[must_use]
    #[inline]
    pub fn proof_submitted(proof_id: impl Into<String>, bytes: u64) -> Self {
        Self {
            event_type: EventType::ProofSubmitted,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Proof {
                proof_id: proof_id.into(),
                bytes,
            },
        }
    }

    /// Create a peer connected event.
    #[must_use]
    #[inline]
    pub fn peer_connected(peer_id: impl Into<String>) -> Self {
        Self {
            event_type: EventType::PeerConnected,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Peer {
                peer_id: peer_id.into(),
            },
        }
    }

    /// Create a peer disconnected event.
    #[must_use]
    #[inline]
    pub fn peer_disconnected(peer_id: impl Into<String>) -> Self {
        Self {
            event_type: EventType::PeerDisconnected,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Peer {
                peer_id: peer_id.into(),
            },
        }
    }

    /// Create a reputation changed event.
    #[must_use]
    #[inline]
    pub fn reputation_changed(peer_id: impl Into<String>, old_score: f64, new_score: f64) -> Self {
        Self {
            event_type: EventType::ReputationChanged,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Reputation {
                peer_id: peer_id.into(),
                old_score,
                new_score,
            },
        }
    }

    /// Create a quota exceeded event.
    #[must_use]
    #[inline]
    pub fn quota_exceeded(used_bytes: u64, max_bytes: u64) -> Self {
        Self {
            event_type: EventType::QuotaExceeded,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Quota {
                used_bytes,
                max_bytes,
            },
        }
    }

    /// Create a garbage collected event.
    #[must_use]
    #[inline]
    pub fn garbage_collected(freed_bytes: u64, items_removed: usize) -> Self {
        Self {
            event_type: EventType::GarbageCollected,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::GarbageCollection {
                freed_bytes,
                items_removed,
            },
        }
    }

    /// Create a node started event.
    #[must_use]
    #[inline]
    pub fn node_started() -> Self {
        Self {
            event_type: EventType::NodeStarted,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Node,
        }
    }

    /// Create a node stopped event.
    #[must_use]
    #[inline]
    pub fn node_stopped() -> Self {
        Self {
            event_type: EventType::NodeStopped,
            timestamp_ms: crate::utils::current_timestamp_ms(),
            payload: EventPayload::Node,
        }
    }
}

/// Event bus for pub/sub communication.
pub struct EventBus {
    subscribers: Arc<Mutex<HashMap<EventType, Vec<Sender<Event>>>>>,
    stats: Arc<Mutex<EventStats>>,
}

impl EventBus {
    /// Create a new event bus.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(EventStats::default())),
        }
    }

    /// Subscribe to events of a specific type.
    #[inline]
    #[must_use]
    pub fn subscribe(&self, event_type: EventType) -> Receiver<Event> {
        let (tx, rx) = channel();
        let mut subs = self.subscribers.lock().unwrap();
        subs.entry(event_type).or_default().push(tx);
        rx
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: Event) {
        let event_type = event.event_type;

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_events += 1;
            *stats.events_by_type.entry(event_type).or_insert(0) += 1;
        }

        // Send to subscribers
        let mut subs = self.subscribers.lock().unwrap();
        if let Some(subscribers) = subs.get_mut(&event_type) {
            // Remove disconnected subscribers
            subscribers.retain(|tx| tx.send(event.clone()).is_ok());

            // Update subscriber count
            self.stats.lock().unwrap().active_subscribers = subs.values().map(|v| v.len()).sum();
        }
    }

    /// Get event bus statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> EventStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics.
    #[inline]
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = EventStats::default();
    }

    /// Get number of subscribers for an event type.
    #[must_use]
    #[inline]
    pub fn subscriber_count(&self, event_type: EventType) -> usize {
        self.subscribers
            .lock()
            .unwrap()
            .get(&event_type)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Clear all subscribers.
    #[inline]
    pub fn clear_subscribers(&self) {
        self.subscribers.lock().unwrap().clear();
        self.stats.lock().unwrap().active_subscribers = 0;
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Event bus statistics.
#[derive(Debug, Clone, Default)]
pub struct EventStats {
    /// Total events published.
    pub total_events: u64,
    /// Events by type.
    pub events_by_type: HashMap<EventType, u64>,
    /// Active subscribers.
    pub active_subscribers: usize,
}

impl EventStats {
    /// Get the most common event type.
    #[inline]
    #[must_use]
    pub fn most_common_event(&self) -> Option<(EventType, u64)> {
        self.events_by_type
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(t, c)| (*t, *c))
    }

    /// Get event count for a specific type.
    #[must_use]
    #[inline]
    pub fn event_count(&self, event_type: EventType) -> u64 {
        self.events_by_type.get(&event_type).copied().unwrap_or(0)
    }
}

/// Async event bus using tokio broadcast channels.
///
/// This provides a high-performance async-friendly event bus suitable
/// for use in async/await code with better backpressure handling.
pub struct AsyncEventBus {
    broadcasters: Arc<Mutex<HashMap<EventType, broadcast::Sender<Event>>>>,
    stats: Arc<Mutex<EventStats>>,
    capacity: usize,
}

impl AsyncEventBus {
    /// Create a new async event bus with specified channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            broadcasters: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(EventStats::default())),
            capacity,
        }
    }

    /// Subscribe to events of a specific type (async).
    #[inline]
    #[must_use]
    pub fn subscribe(&self, event_type: EventType) -> broadcast::Receiver<Event> {
        let mut broadcasters = self.broadcasters.lock().unwrap();
        let tx = broadcasters
            .entry(event_type)
            .or_insert_with(|| broadcast::channel(self.capacity).0);
        tx.subscribe()
    }

    /// Publish an event to all async subscribers.
    pub fn publish(&self, event: Event) -> Result<usize, broadcast::error::SendError<Event>> {
        let event_type = event.event_type;

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_events += 1;
            *stats.events_by_type.entry(event_type).or_insert(0) += 1;
        }

        // Send to subscribers
        let broadcasters = self.broadcasters.lock().unwrap();
        if let Some(tx) = broadcasters.get(&event_type) {
            let receiver_count = tx.receiver_count();
            let _ = tx.send(event);
            Ok(receiver_count)
        } else {
            Ok(0)
        }
    }

    /// Get event bus statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> EventStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics.
    #[inline]
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = EventStats::default();
    }

    /// Get number of active receivers for an event type.
    #[inline]
    #[must_use]
    pub fn receiver_count(&self, event_type: EventType) -> usize {
        self.broadcasters
            .lock()
            .unwrap()
            .get(&event_type)
            .map(|tx| tx.receiver_count())
            .unwrap_or(0)
    }
}

impl Default for AsyncEventBus {
    fn default() -> Self {
        Self::new(100) // Default capacity
    }
}

/// Event filter for selective event processing.
#[derive(Debug, Clone)]
pub struct EventFilter {
    /// Allowed event types (None = all allowed).
    pub allowed_types: Option<Vec<EventType>>,
    /// Minimum timestamp (milliseconds).
    pub min_timestamp: Option<i64>,
    /// Filter by payload content.
    pub payload_filter: Option<PayloadFilter>,
}

/// Payload filter criteria.
#[derive(Debug, Clone)]
pub enum PayloadFilter {
    /// Filter by CID prefix.
    CidPrefix(String),
    /// Filter by peer ID.
    PeerId(String),
    /// Filter by minimum bytes.
    MinBytes(u64),
}

impl EventFilter {
    /// Create a new empty filter (allows all events).
    #[must_use]
    pub fn new() -> Self {
        Self {
            allowed_types: None,
            min_timestamp: None,
            payload_filter: None,
        }
    }

    /// Set allowed event types.
    #[must_use]
    pub fn with_types(mut self, types: Vec<EventType>) -> Self {
        self.allowed_types = Some(types);
        self
    }

    /// Set minimum timestamp.
    #[must_use]
    pub fn with_min_timestamp(mut self, timestamp: i64) -> Self {
        self.min_timestamp = Some(timestamp);
        self
    }

    /// Set payload filter.
    #[must_use]
    pub fn with_payload_filter(mut self, filter: PayloadFilter) -> Self {
        self.payload_filter = Some(filter);
        self
    }

    /// Check if an event matches this filter.
    #[inline]
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        // Check event type
        if let Some(ref allowed) = self.allowed_types {
            if !allowed.contains(&event.event_type) {
                return false;
            }
        }

        // Check timestamp
        if let Some(min_ts) = self.min_timestamp {
            if event.timestamp_ms < min_ts {
                return false;
            }
        }

        // Check payload filter
        if let Some(ref pf) = self.payload_filter {
            let matches = match pf {
                PayloadFilter::CidPrefix(prefix) => {
                    if let EventPayload::Content { cid, .. } = &event.payload {
                        cid.starts_with(prefix)
                    } else {
                        false
                    }
                }
                PayloadFilter::PeerId(peer_id) => match &event.payload {
                    EventPayload::Peer { peer_id: p } => p == peer_id,
                    EventPayload::Reputation { peer_id: p, .. } => p == peer_id,
                    _ => false,
                },
                PayloadFilter::MinBytes(min_bytes) => match &event.payload {
                    EventPayload::Content { size_bytes, .. } => size_bytes >= min_bytes,
                    EventPayload::Proof { bytes, .. } => bytes >= min_bytes,
                    _ => false,
                },
            };
            if !matches {
                return false;
            }
        }

        true
    }
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Event batch for efficient bulk processing.
#[derive(Debug, Clone)]
pub struct EventBatch {
    /// Events in this batch.
    pub events: Vec<Event>,
    /// Batch creation timestamp.
    pub created_at: i64,
}

impl EventBatch {
    /// Create a new event batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            created_at: crate::utils::current_timestamp_ms(),
        }
    }

    /// Add an event to the batch.
    #[inline]
    pub fn add(&mut self, event: Event) {
        self.events.push(event);
    }

    /// Get the number of events in the batch.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the batch is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get total bytes across all events in the batch.
    #[must_use]
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.events
            .iter()
            .filter_map(|e| match &e.payload {
                EventPayload::Content { size_bytes, .. } => Some(*size_bytes),
                EventPayload::Proof { bytes, .. } => Some(*bytes),
                EventPayload::GarbageCollection { freed_bytes, .. } => Some(*freed_bytes),
                _ => None,
            })
            .sum()
    }

    /// Filter events in the batch.
    #[inline]
    #[must_use]
    pub fn filter(&self, filter: &EventFilter) -> Vec<Event> {
        self.events
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect()
    }
}

impl Default for EventBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Event persistence and replay system.
///
/// Stores events to disk in JSON Lines format (one JSON object per line)
/// for efficient append-only writes and sequential replay.
pub struct EventStore {
    file_path: std::path::PathBuf,
    file: Arc<Mutex<Option<std::fs::File>>>,
    events_written: Arc<Mutex<u64>>,
}

impl EventStore {
    /// Create a new event store at the specified file path.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path where events will be stored (JSON Lines format)
    ///
    /// # Returns
    ///
    /// Returns `Ok(EventStore)` if the file can be created/opened, or an error otherwise.
    pub fn new<P: Into<std::path::PathBuf>>(file_path: P) -> std::io::Result<Self> {
        let file_path = file_path.into();

        // Create parent directory if it doesn't exist
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open file in append mode
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        Ok(Self {
            file_path,
            file: Arc::new(Mutex::new(Some(file))),
            events_written: Arc::new(Mutex::new(0)),
        })
    }

    /// Persist an event to disk.
    ///
    /// Events are written in JSON Lines format (one JSON object per line)
    /// for efficient append-only writes.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to persist
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the event was successfully written, or an error otherwise.
    pub fn persist(&self, event: &Event) -> std::io::Result<()> {
        use std::io::Write;

        let mut file_guard = self.file.lock().unwrap();
        if let Some(file) = file_guard.as_mut() {
            // Serialize event to JSON
            let json = serde_json::to_string(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            // Write JSON line
            writeln!(file, "{}", json)?;
            file.flush()?;

            // Update counter
            let mut count = self.events_written.lock().unwrap();
            *count += 1;

            Ok(())
        } else {
            Err(std::io::Error::other("Event store is closed"))
        }
    }

    /// Persist multiple events in a batch.
    ///
    /// More efficient than calling `persist()` multiple times individually.
    ///
    /// # Arguments
    ///
    /// * `events` - Iterator of events to persist
    ///
    /// # Returns
    ///
    /// Returns `Ok(count)` with the number of events written, or an error if any write fails.
    pub fn persist_batch<I>(&self, events: I) -> std::io::Result<usize>
    where
        I: IntoIterator<Item = Event>,
    {
        use std::io::Write;

        let mut file_guard = self.file.lock().unwrap();
        if let Some(file) = file_guard.as_mut() {
            let mut count = 0;

            for event in events {
                let json = serde_json::to_string(&event)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                writeln!(file, "{}", json)?;
                count += 1;
            }

            file.flush()?;

            // Update counter
            let mut total = self.events_written.lock().unwrap();
            *total += count as u64;

            Ok(count)
        } else {
            Err(std::io::Error::other("Event store is closed"))
        }
    }

    /// Get the number of events written to this store.
    #[must_use]
    #[inline]
    pub fn events_written(&self) -> u64 {
        *self.events_written.lock().unwrap()
    }

    /// Get the file path of this event store.
    #[must_use]
    #[inline]
    pub fn file_path(&self) -> &std::path::Path {
        &self.file_path
    }

    /// Close the event store, flushing any remaining data.
    pub fn close(&self) -> std::io::Result<()> {
        use std::io::Write;

        let mut file_guard = self.file.lock().unwrap();
        if let Some(mut file) = file_guard.take() {
            file.flush()?;
        }
        Ok(())
    }
}

/// Event replay system for reading persisted events.
pub struct EventReplay {
    file_path: std::path::PathBuf,
}

impl EventReplay {
    /// Create a new event replay from the specified file path.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the event store file (JSON Lines format)
    #[must_use]
    pub fn new<P: Into<std::path::PathBuf>>(file_path: P) -> Self {
        Self {
            file_path: file_path.into(),
        }
    }

    /// Replay all events from the store.
    ///
    /// Reads the entire event log and returns all events in chronological order.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<Event>)` with all events, or an error if reading fails.
    pub fn replay_all(&self) -> std::io::Result<Vec<Event>> {
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            let event: Event = serde_json::from_str(&line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse event at line {}: {}", line_num + 1, e),
                )
            })?;
            events.push(event);
        }

        Ok(events)
    }

    /// Replay events matching a specific filter.
    ///
    /// Only returns events that match the provided filter criteria.
    ///
    /// # Arguments
    ///
    /// * `filter` - Event filter to apply during replay
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<Event>)` with matching events, or an error if reading fails.
    pub fn replay_filtered(&self, filter: &EventFilter) -> std::io::Result<Vec<Event>> {
        let all_events = self.replay_all()?;
        Ok(all_events
            .into_iter()
            .filter(|e| filter.matches(e))
            .collect())
    }

    /// Replay events since a specific timestamp.
    ///
    /// Returns only events that occurred after the specified timestamp.
    ///
    /// # Arguments
    ///
    /// * `since_timestamp_ms` - Timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<Event>)` with events since the timestamp, or an error if reading fails.
    pub fn replay_since(&self, since_timestamp_ms: i64) -> std::io::Result<Vec<Event>> {
        let filter = EventFilter::new().with_min_timestamp(since_timestamp_ms);
        self.replay_filtered(&filter)
    }

    /// Count the total number of events in the store.
    ///
    /// # Returns
    ///
    /// Returns `Ok(count)` with the number of events, or an error if reading fails.
    pub fn count_events(&self) -> std::io::Result<usize> {
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .filter(|l| l.as_ref().is_ok_and(|line| !line.trim().is_empty()))
            .count())
    }

    /// Check if the event store file exists.
    #[must_use]
    #[inline]
    pub fn exists(&self) -> bool {
        self.file_path.exists()
    }

    /// Get the file path of the event store.
    #[must_use]
    #[inline]
    pub fn file_path(&self) -> &std::path::Path {
        &self.file_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_creation() {
        let bus = EventBus::new();
        let stats = bus.stats();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.active_subscribers, 0);
    }

    #[test]
    fn test_subscribe_and_publish() {
        let bus = EventBus::new();
        let rx = bus.subscribe(EventType::ContentAdded);

        bus.publish(Event::content_added("QmTest", 1024));

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, EventType::ContentAdded);
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let rx1 = bus.subscribe(EventType::ContentAdded);
        let rx2 = bus.subscribe(EventType::ContentAdded);

        assert_eq!(bus.subscriber_count(EventType::ContentAdded), 2);

        bus.publish(Event::content_added("QmTest", 1024));

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_event_type_filtering() {
        let bus = EventBus::new();
        let rx_content = bus.subscribe(EventType::ContentAdded);
        let rx_peer = bus.subscribe(EventType::PeerConnected);

        bus.publish(Event::content_added("QmTest", 1024));

        assert!(rx_content.try_recv().is_ok());
        assert!(rx_peer.try_recv().is_err()); // Should not receive
    }

    #[test]
    fn test_event_creation_helpers() {
        let event = Event::content_added("QmTest", 1024);
        assert_eq!(event.event_type, EventType::ContentAdded);

        let event = Event::peer_connected("peer1");
        assert_eq!(event.event_type, EventType::PeerConnected);

        let event = Event::proof_generated("proof1", 2048);
        assert_eq!(event.event_type, EventType::ProofGenerated);
    }

    #[test]
    fn test_statistics_tracking() {
        let bus = EventBus::new();

        bus.publish(Event::content_added("QmTest1", 1024));
        bus.publish(Event::content_added("QmTest2", 2048));
        bus.publish(Event::peer_connected("peer1"));

        let stats = bus.stats();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.event_count(EventType::ContentAdded), 2);
        assert_eq!(stats.event_count(EventType::PeerConnected), 1);
    }

    #[test]
    fn test_most_common_event() {
        let bus = EventBus::new();

        bus.publish(Event::content_added("QmTest1", 1024));
        bus.publish(Event::content_added("QmTest2", 2048));
        bus.publish(Event::peer_connected("peer1"));

        let stats = bus.stats();
        let (event_type, count) = stats.most_common_event().unwrap();
        assert_eq!(event_type, EventType::ContentAdded);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_reset_stats() {
        let bus = EventBus::new();
        bus.publish(Event::content_added("QmTest", 1024));

        assert_eq!(bus.stats().total_events, 1);

        bus.reset_stats();
        assert_eq!(bus.stats().total_events, 0);
    }

    #[test]
    fn test_clear_subscribers() {
        let bus = EventBus::new();
        let _rx1 = bus.subscribe(EventType::ContentAdded);
        let _rx2 = bus.subscribe(EventType::ContentAdded);

        assert_eq!(bus.subscriber_count(EventType::ContentAdded), 2);

        bus.clear_subscribers();
        assert_eq!(bus.subscriber_count(EventType::ContentAdded), 0);
    }

    #[test]
    fn test_reputation_changed_event() {
        let event = Event::reputation_changed("peer1", 0.5, 0.8);
        assert_eq!(event.event_type, EventType::ReputationChanged);

        if let EventPayload::Reputation {
            peer_id,
            old_score,
            new_score,
        } = event.payload
        {
            assert_eq!(peer_id, "peer1");
            assert_eq!(old_score, 0.5);
            assert_eq!(new_score, 0.8);
        } else {
            panic!("Wrong payload type");
        }
    }

    #[test]
    fn test_quota_exceeded_event() {
        let event = Event::quota_exceeded(1000, 500);
        assert_eq!(event.event_type, EventType::QuotaExceeded);
    }

    #[test]
    fn test_garbage_collected_event() {
        let event = Event::garbage_collected(1024 * 1024, 5);
        assert_eq!(event.event_type, EventType::GarbageCollected);

        if let EventPayload::GarbageCollection {
            freed_bytes,
            items_removed,
        } = event.payload
        {
            assert_eq!(freed_bytes, 1024 * 1024);
            assert_eq!(items_removed, 5);
        } else {
            panic!("Wrong payload type");
        }
    }

    #[test]
    fn test_node_lifecycle_events() {
        let started = Event::node_started();
        assert_eq!(started.event_type, EventType::NodeStarted);

        let stopped = Event::node_stopped();
        assert_eq!(stopped.event_type, EventType::NodeStopped);
    }

    #[tokio::test]
    async fn test_async_event_bus() {
        let bus = AsyncEventBus::new(10);
        let mut rx = bus.subscribe(EventType::ContentAdded);

        let event = Event::content_added("QmTest", 1024);
        let result = bus.publish(event.clone());
        assert!(result.is_ok());

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::ContentAdded);
    }

    #[tokio::test]
    async fn test_async_event_bus_multiple_receivers() {
        let bus = AsyncEventBus::new(10);
        let mut rx1 = bus.subscribe(EventType::ContentAdded);
        let mut rx2 = bus.subscribe(EventType::ContentAdded);

        assert_eq!(bus.receiver_count(EventType::ContentAdded), 2);

        let event = Event::content_added("QmTest", 1024);
        let _ = bus.publish(event);

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_async_event_bus_stats() {
        let bus = AsyncEventBus::new(10);
        let _rx = bus.subscribe(EventType::ContentAdded);

        let _ = bus.publish(Event::content_added("QmTest1", 1024));
        let _ = bus.publish(Event::content_added("QmTest2", 2048));

        let stats = bus.stats();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.event_count(EventType::ContentAdded), 2);
    }

    #[test]
    fn test_event_filter_type() {
        let filter =
            EventFilter::new().with_types(vec![EventType::ContentAdded, EventType::ContentRemoved]);

        let event1 = Event::content_added("QmTest", 1024);
        assert!(filter.matches(&event1));

        let event2 = Event::peer_connected("peer1");
        assert!(!filter.matches(&event2));
    }

    #[test]
    fn test_event_filter_timestamp() {
        let now = crate::utils::current_timestamp_ms();
        let filter = EventFilter::new().with_min_timestamp(now);

        let mut old_event = Event::content_added("QmTest", 1024);
        old_event.timestamp_ms = now - 1000;
        assert!(!filter.matches(&old_event));

        let new_event = Event::content_added("QmTest", 1024);
        assert!(filter.matches(&new_event));
    }

    #[test]
    fn test_event_filter_cid_prefix() {
        let filter =
            EventFilter::new().with_payload_filter(PayloadFilter::CidPrefix("Qm".to_string()));

        let event1 = Event::content_added("QmTest123", 1024);
        assert!(filter.matches(&event1));

        let event2 = Event::content_added("Bafytest", 1024);
        assert!(!filter.matches(&event2));
    }

    #[test]
    fn test_event_filter_peer_id() {
        let filter =
            EventFilter::new().with_payload_filter(PayloadFilter::PeerId("peer1".to_string()));

        let event1 = Event::peer_connected("peer1");
        assert!(filter.matches(&event1));

        let event2 = Event::peer_connected("peer2");
        assert!(!filter.matches(&event2));

        let event3 = Event::reputation_changed("peer1", 0.5, 0.8);
        assert!(filter.matches(&event3));
    }

    #[test]
    fn test_event_filter_min_bytes() {
        let filter = EventFilter::new().with_payload_filter(PayloadFilter::MinBytes(2048));

        let event1 = Event::content_added("QmTest", 4096);
        assert!(filter.matches(&event1));

        let event2 = Event::content_added("QmTest", 1024);
        assert!(!filter.matches(&event2));

        let event3 = Event::proof_generated("proof1", 3072);
        assert!(filter.matches(&event3));
    }

    #[test]
    fn test_event_batch() {
        let mut batch = EventBatch::new();
        assert!(batch.is_empty());

        batch.add(Event::content_added("QmTest1", 1024));
        batch.add(Event::content_added("QmTest2", 2048));
        batch.add(Event::peer_connected("peer1"));

        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());
        assert_eq!(batch.total_bytes(), 3072);
    }

    #[test]
    fn test_event_batch_filter() {
        let mut batch = EventBatch::new();
        batch.add(Event::content_added("QmTest1", 1024));
        batch.add(Event::content_added("QmTest2", 2048));
        batch.add(Event::peer_connected("peer1"));

        let filter = EventFilter::new().with_types(vec![EventType::ContentAdded]);
        let filtered = batch.filter(&filter);

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_event_batch_total_bytes() {
        let mut batch = EventBatch::new();
        batch.add(Event::content_added("QmTest", 1024));
        batch.add(Event::proof_generated("proof1", 2048));
        batch.add(Event::garbage_collected(512, 3));
        batch.add(Event::peer_connected("peer1")); // No bytes

        assert_eq!(batch.total_bytes(), 3584); // 1024 + 2048 + 512
    }

    #[test]
    fn test_event_store_creation() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_store_creation.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        let store = EventStore::new(&store_path).unwrap();
        assert_eq!(store.events_written(), 0);
        assert_eq!(store.file_path(), store_path.as_path());

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_store_persist() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_store_persist.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        let store = EventStore::new(&store_path).unwrap();
        let event = Event::content_added("QmTest123", 1024);

        store.persist(&event).unwrap();
        assert_eq!(store.events_written(), 1);

        store.close().unwrap();

        // Verify file exists and has content
        let content = std::fs::read_to_string(&store_path).unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("QmTest123"));

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_store_persist_batch() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_store_persist_batch.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        let store = EventStore::new(&store_path).unwrap();
        let events = vec![
            Event::content_added("QmTest1", 1024),
            Event::content_added("QmTest2", 2048),
            Event::peer_connected("peer1"),
        ];

        let count = store.persist_batch(events).unwrap();
        assert_eq!(count, 3);
        assert_eq!(store.events_written(), 3);

        store.close().unwrap();

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_replay_all() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_replay_all.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        // Write some events
        let store = EventStore::new(&store_path).unwrap();
        let events = vec![
            Event::content_added("QmTest1", 1024),
            Event::content_added("QmTest2", 2048),
            Event::peer_connected("peer1"),
        ];
        store.persist_batch(events).unwrap();
        store.close().unwrap();

        // Replay events
        let replay = EventReplay::new(&store_path);
        assert!(replay.exists());

        let replayed = replay.replay_all().unwrap();
        assert_eq!(replayed.len(), 3);
        assert_eq!(replayed[0].event_type, EventType::ContentAdded);
        assert_eq!(replayed[1].event_type, EventType::ContentAdded);
        assert_eq!(replayed[2].event_type, EventType::PeerConnected);

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_replay_filtered() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_replay_filtered.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        // Write some events
        let store = EventStore::new(&store_path).unwrap();
        let events = vec![
            Event::content_added("QmTest1", 1024),
            Event::content_added("QmTest2", 2048),
            Event::peer_connected("peer1"),
            Event::proof_generated("proof1", 512),
        ];
        store.persist_batch(events).unwrap();
        store.close().unwrap();

        // Replay with filter
        let replay = EventReplay::new(&store_path);
        let filter = EventFilter::new().with_types(vec![EventType::ContentAdded]);
        let filtered = replay.replay_filtered(&filter).unwrap();

        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .all(|e| e.event_type == EventType::ContentAdded)
        );

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_replay_since() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_replay_since.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        // Write some events with known timestamps
        let store = EventStore::new(&store_path).unwrap();
        let now = crate::utils::current_timestamp_ms();

        let mut old_event = Event::content_added("QmOld", 1024);
        old_event.timestamp_ms = now - 10000;

        let mut new_event = Event::content_added("QmNew", 2048);
        new_event.timestamp_ms = now + 1000;

        store.persist(&old_event).unwrap();
        store.persist(&new_event).unwrap();
        store.close().unwrap();

        // Replay events since timestamp
        let replay = EventReplay::new(&store_path);
        let recent = replay.replay_since(now).unwrap();

        assert_eq!(recent.len(), 1);
        if let EventPayload::Content { cid, .. } = &recent[0].payload {
            assert_eq!(cid, "QmNew");
        } else {
            panic!("Expected Content payload");
        }

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn test_event_replay_count() {
        let temp_dir = std::env::temp_dir();
        let store_path = temp_dir.join("test_event_replay_count.jsonl");

        // Clean up any existing file
        let _ = std::fs::remove_file(&store_path);

        // Write some events
        let store = EventStore::new(&store_path).unwrap();
        let events = vec![
            Event::content_added("QmTest1", 1024),
            Event::content_added("QmTest2", 2048),
            Event::peer_connected("peer1"),
        ];
        store.persist_batch(events).unwrap();
        store.close().unwrap();

        // Count events
        let replay = EventReplay::new(&store_path);
        let count = replay.count_events().unwrap();
        assert_eq!(count, 3);

        // Clean up
        let _ = std::fs::remove_file(&store_path);
    }
}
