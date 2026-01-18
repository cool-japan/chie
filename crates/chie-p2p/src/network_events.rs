// Network event system for unified observability across P2P modules
//
// Provides centralized event management:
// - Event emission from all major subsystems
// - Event subscription with filtering
// - Event aggregation and statistics
// - Real-time network state changes
// - Integration with pubsub for distributed events

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Network event types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// Peer connected
    PeerConnected { peer_id: String, address: String },
    /// Peer disconnected
    PeerDisconnected { peer_id: String, reason: String },
    /// Content discovered
    ContentDiscovered {
        content_id: String,
        provider: String,
    },
    /// Content uploaded
    ContentUploaded { content_id: String, size: u64 },
    /// Content downloaded
    ContentDownloaded {
        content_id: String,
        size: u64,
        duration_ms: u64,
    },
    /// Transfer started
    TransferStarted {
        transfer_id: String,
        peer_id: String,
        size: u64,
    },
    /// Transfer completed
    TransferCompleted {
        transfer_id: String,
        peer_id: String,
    },
    /// Transfer failed
    TransferFailed {
        transfer_id: String,
        peer_id: String,
        error: String,
    },
    /// Relay path established
    RelayPathEstablished {
        source: String,
        destination: String,
        hops: usize,
    },
    /// Relay path failed
    RelayPathFailed {
        source: String,
        destination: String,
        reason: String,
    },
    /// Network partition detected
    PartitionDetected {
        severity: f64,
        affected_peers: usize,
    },
    /// Network partition recovered
    PartitionRecovered { duration_ms: u64 },
    /// Peer reputation changed
    ReputationChanged {
        peer_id: String,
        old_score: f64,
        new_score: f64,
    },
    /// Peer banned
    PeerBanned {
        peer_id: String,
        reason: String,
        duration_ms: Option<u64>,
    },
    /// Bandwidth limit exceeded
    BandwidthLimitExceeded {
        peer_id: String,
        limit: u64,
        actual: u64,
    },
    /// Rate limit triggered
    RateLimitTriggered { peer_id: String, limit_type: String },
    /// Malicious activity detected
    MaliciousActivity {
        peer_id: String,
        behavior: String,
        confidence: f64,
    },
    /// Sybil attack detected
    SybilAttack { peer_count: usize, confidence: f64 },
    /// Content verification failed
    VerificationFailed {
        content_id: String,
        provider: String,
    },
    /// Health check failed
    HealthCheckFailed { peer_id: String, check_type: String },
    /// Network quality degraded
    QualityDegraded {
        metric: String,
        old_value: f64,
        new_value: f64,
    },
    /// Circuit breaker opened
    CircuitBreakerOpened { service: String, failure_rate: f64 },
    /// Custom event for extensions
    Custom { event_type: String, data: String },
}

impl NetworkEvent {
    /// Get event category for filtering
    pub fn category(&self) -> EventCategory {
        match self {
            Self::PeerConnected { .. } | Self::PeerDisconnected { .. } => EventCategory::Connection,
            Self::ContentDiscovered { .. }
            | Self::ContentUploaded { .. }
            | Self::ContentDownloaded { .. } => EventCategory::Content,
            Self::TransferStarted { .. }
            | Self::TransferCompleted { .. }
            | Self::TransferFailed { .. } => EventCategory::Transfer,
            Self::RelayPathEstablished { .. } | Self::RelayPathFailed { .. } => {
                EventCategory::Relay
            }
            Self::PartitionDetected { .. } | Self::PartitionRecovered { .. } => {
                EventCategory::NetworkHealth
            }
            Self::ReputationChanged { .. } | Self::PeerBanned { .. } => EventCategory::Reputation,
            Self::BandwidthLimitExceeded { .. } | Self::RateLimitTriggered { .. } => {
                EventCategory::RateLimit
            }
            Self::MaliciousActivity { .. }
            | Self::SybilAttack { .. }
            | Self::VerificationFailed { .. } => EventCategory::Security,
            Self::HealthCheckFailed { .. }
            | Self::QualityDegraded { .. }
            | Self::CircuitBreakerOpened { .. } => EventCategory::Monitoring,
            Self::Custom { .. } => EventCategory::Custom,
        }
    }

    /// Get event severity
    pub fn severity(&self) -> EventSeverity {
        match self {
            Self::PeerConnected { .. }
            | Self::PeerDisconnected { .. }
            | Self::ContentDiscovered { .. } => EventSeverity::Info,
            Self::ContentUploaded { .. }
            | Self::ContentDownloaded { .. }
            | Self::TransferStarted { .. }
            | Self::TransferCompleted { .. } => EventSeverity::Info,
            Self::RelayPathEstablished { .. } => EventSeverity::Info,
            Self::ReputationChanged { .. } => EventSeverity::Info,
            Self::TransferFailed { .. } | Self::RelayPathFailed { .. } => EventSeverity::Warning,
            Self::BandwidthLimitExceeded { .. } | Self::RateLimitTriggered { .. } => {
                EventSeverity::Warning
            }
            Self::HealthCheckFailed { .. } | Self::QualityDegraded { .. } => EventSeverity::Warning,
            Self::CircuitBreakerOpened { .. } => EventSeverity::Warning,
            Self::PartitionDetected { .. } => EventSeverity::Error,
            Self::PeerBanned { .. }
            | Self::MaliciousActivity { .. }
            | Self::SybilAttack { .. }
            | Self::VerificationFailed { .. } => EventSeverity::Error,
            Self::PartitionRecovered { .. } => EventSeverity::Info,
            Self::Custom { .. } => EventSeverity::Info,
        }
    }
}

/// Event category for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    Connection,
    Content,
    Transfer,
    Relay,
    NetworkHealth,
    Reputation,
    RateLimit,
    Security,
    Monitoring,
    Custom,
}

/// Event severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
}

/// Timestamped event
#[derive(Debug, Clone)]
pub struct TimestampedEvent {
    pub event: NetworkEvent,
    pub timestamp: Instant,
    pub id: u64,
}

/// Event filter for subscriptions
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Filter by categories
    pub categories: Option<Vec<EventCategory>>,
    /// Filter by minimum severity
    pub min_severity: Option<EventSeverity>,
    /// Filter by peer ID (as string)
    pub peer_id: Option<String>,
}

impl EventFilter {
    /// Create a filter for all events
    pub fn all() -> Self {
        Self::default()
    }

    /// Create a filter for specific categories
    pub fn categories(categories: Vec<EventCategory>) -> Self {
        Self {
            categories: Some(categories),
            ..Default::default()
        }
    }

    /// Create a filter for minimum severity
    pub fn min_severity(severity: EventSeverity) -> Self {
        Self {
            min_severity: Some(severity),
            ..Default::default()
        }
    }

    /// Create a filter for specific peer
    pub fn peer(peer_id: PeerId) -> Self {
        Self {
            peer_id: Some(peer_id.to_string()),
            ..Default::default()
        }
    }

    /// Check if event matches filter
    pub fn matches(&self, event: &NetworkEvent) -> bool {
        // Check category filter
        if let Some(ref categories) = self.categories {
            if !categories.contains(&event.category()) {
                return false;
            }
        }

        // Check severity filter
        if let Some(min_severity) = self.min_severity {
            if event.severity() < min_severity {
                return false;
            }
        }

        // Check peer filter
        if let Some(ref filter_peer_id) = self.peer_id {
            let event_peer_id = match event {
                NetworkEvent::PeerConnected { peer_id, .. }
                | NetworkEvent::PeerDisconnected { peer_id, .. }
                | NetworkEvent::ContentDiscovered {
                    provider: peer_id, ..
                }
                | NetworkEvent::TransferStarted { peer_id, .. }
                | NetworkEvent::TransferCompleted { peer_id, .. }
                | NetworkEvent::TransferFailed { peer_id, .. }
                | NetworkEvent::ReputationChanged { peer_id, .. }
                | NetworkEvent::PeerBanned { peer_id, .. }
                | NetworkEvent::BandwidthLimitExceeded { peer_id, .. }
                | NetworkEvent::RateLimitTriggered { peer_id, .. }
                | NetworkEvent::MaliciousActivity { peer_id, .. }
                | NetworkEvent::HealthCheckFailed { peer_id, .. }
                | NetworkEvent::VerificationFailed {
                    provider: peer_id, ..
                } => Some(peer_id.as_str()),
                _ => None,
            };

            if event_peer_id != Some(filter_peer_id.as_str()) {
                return false;
            }
        }

        true
    }
}

/// Event statistics
#[derive(Debug, Clone, Default)]
pub struct EventStats {
    /// Total events emitted
    pub total_events: usize,
    /// Events by category
    pub events_by_category: HashMap<EventCategory, usize>,
    /// Events by severity
    pub events_by_severity: HashMap<EventSeverity, usize>,
    /// Active subscriptions
    pub active_subscriptions: usize,
}

/// Configuration for event manager
#[derive(Debug, Clone)]
pub struct EventManagerConfig {
    /// Maximum events to keep in history
    pub max_history_size: usize,
    /// Maximum age for events in history
    pub max_event_age: Duration,
    /// Enable event deduplication
    pub enable_deduplication: bool,
    /// Deduplication window
    pub dedup_window: Duration,
}

impl Default for EventManagerConfig {
    fn default() -> Self {
        Self {
            max_history_size: 10000,
            max_event_age: Duration::from_secs(3600), // 1 hour
            enable_deduplication: true,
            dedup_window: Duration::from_secs(5),
        }
    }
}

/// Event subscription handle
pub type SubscriptionId = u64;

/// Event subscriber callback type
pub type EventCallback = Arc<dyn Fn(&TimestampedEvent) + Send + Sync>;

struct Subscription {
    id: SubscriptionId,
    filter: EventFilter,
    callback: EventCallback,
}

/// Network event manager
pub struct NetworkEventManager {
    config: EventManagerConfig,
    /// Event history
    history: Arc<RwLock<VecDeque<TimestampedEvent>>>,
    /// Event subscriptions
    subscriptions: Arc<RwLock<Vec<Subscription>>>,
    /// Event statistics
    stats: Arc<RwLock<EventStats>>,
    /// Next event ID
    next_event_id: Arc<RwLock<u64>>,
    /// Next subscription ID
    next_subscription_id: Arc<RwLock<u64>>,
    /// Recent event hashes for deduplication
    recent_events: Arc<RwLock<HashMap<String, Instant>>>,
}

impl Default for NetworkEventManager {
    fn default() -> Self {
        Self::new(EventManagerConfig::default())
    }
}

impl NetworkEventManager {
    /// Create a new event manager
    pub fn new(config: EventManagerConfig) -> Self {
        Self {
            config,
            history: Arc::new(RwLock::new(VecDeque::new())),
            subscriptions: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(EventStats::default())),
            next_event_id: Arc::new(RwLock::new(0)),
            next_subscription_id: Arc::new(RwLock::new(0)),
            recent_events: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Emit a network event
    pub fn emit(&self, event: NetworkEvent) {
        // Check for duplicate
        if self.config.enable_deduplication {
            let event_hash = format!("{:?}", event);
            let mut recent = self.recent_events.write().unwrap();

            if let Some(last_time) = recent.get(&event_hash) {
                if last_time.elapsed() < self.config.dedup_window {
                    return; // Duplicate event, skip
                }
            }

            recent.insert(event_hash, Instant::now());
        }

        // Create timestamped event
        let mut next_id = self.next_event_id.write().unwrap();
        let timestamped = TimestampedEvent {
            event: event.clone(),
            timestamp: Instant::now(),
            id: *next_id,
        };
        *next_id += 1;
        drop(next_id);

        // Add to history
        let mut history = self.history.write().unwrap();
        history.push_back(timestamped.clone());

        // Trim history
        while history.len() > self.config.max_history_size {
            history.pop_front();
        }
        drop(history);

        // Update statistics
        let mut stats = self.stats.write().unwrap();
        stats.total_events += 1;
        *stats
            .events_by_category
            .entry(event.category())
            .or_insert(0) += 1;
        *stats
            .events_by_severity
            .entry(event.severity())
            .or_insert(0) += 1;
        drop(stats);

        // Notify subscribers
        let subscriptions = self.subscriptions.read().unwrap();
        for subscription in subscriptions.iter() {
            if subscription.filter.matches(&event) {
                (subscription.callback)(&timestamped);
            }
        }
    }

    /// Subscribe to events with a filter
    pub fn subscribe<F>(&self, filter: EventFilter, callback: F) -> SubscriptionId
    where
        F: Fn(&TimestampedEvent) + Send + Sync + 'static,
    {
        let mut next_id = self.next_subscription_id.write().unwrap();
        let id = *next_id;
        *next_id += 1;
        drop(next_id);

        let subscription = Subscription {
            id,
            filter,
            callback: Arc::new(callback),
        };

        let mut subscriptions = self.subscriptions.write().unwrap();
        subscriptions.push(subscription);

        let mut stats = self.stats.write().unwrap();
        stats.active_subscriptions = subscriptions.len();

        id
    }

    /// Unsubscribe from events
    pub fn unsubscribe(&self, subscription_id: SubscriptionId) {
        let mut subscriptions = self.subscriptions.write().unwrap();
        subscriptions.retain(|s| s.id != subscription_id);

        let mut stats = self.stats.write().unwrap();
        stats.active_subscriptions = subscriptions.len();
    }

    /// Get event history matching a filter
    pub fn get_history(&self, filter: &EventFilter, limit: usize) -> Vec<TimestampedEvent> {
        let history = self.history.read().unwrap();
        history
            .iter()
            .rev()
            .filter(|e| filter.matches(&e.event))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get all events in history
    pub fn get_all_history(&self, limit: usize) -> Vec<TimestampedEvent> {
        let history = self.history.read().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get event statistics
    pub fn stats(&self) -> EventStats {
        self.stats.read().unwrap().clone()
    }

    /// Clear event history
    pub fn clear_history(&self) {
        let mut history = self.history.write().unwrap();
        history.clear();
    }

    /// Clean up old events
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean up old events from history
        let mut history = self.history.write().unwrap();
        history.retain(|e| now.duration_since(e.timestamp) <= self.config.max_event_age);

        // Clean up old deduplication entries
        let mut recent = self.recent_events.write().unwrap();
        recent.retain(|_, time| now.duration_since(*time) <= self.config.dedup_window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_event() {
        let manager = NetworkEventManager::default();

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        let stats = manager.stats();
        assert_eq!(stats.total_events, 1);
        assert_eq!(
            stats.events_by_category.get(&EventCategory::Connection),
            Some(&1)
        );
    }

    #[test]
    fn test_event_subscription() {
        let manager = NetworkEventManager::default();
        let received = Arc::new(RwLock::new(0));
        let received_clone = received.clone();

        let _sub_id = manager.subscribe(EventFilter::all(), move |_event| {
            *received_clone.write().unwrap() += 1;
        });

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1);
    }

    #[test]
    fn test_event_filter_category() {
        let manager = NetworkEventManager::default();
        let received = Arc::new(RwLock::new(0));
        let received_clone = received.clone();

        let filter = EventFilter::categories(vec![EventCategory::Connection]);
        let _sub_id = manager.subscribe(filter, move |_event| {
            *received_clone.write().unwrap() += 1;
        });

        // Should match
        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        // Should not match
        manager.emit(NetworkEvent::ContentDiscovered {
            content_id: "test".to_string(),
            provider: PeerId::random().to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1);
    }

    #[test]
    fn test_event_filter_severity() {
        let manager = NetworkEventManager::default();
        let received = Arc::new(RwLock::new(0));
        let received_clone = received.clone();

        let filter = EventFilter::min_severity(EventSeverity::Warning);
        let _sub_id = manager.subscribe(filter, move |_event| {
            *received_clone.write().unwrap() += 1;
        });

        // Info event - should not match
        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        // Warning event - should match
        manager.emit(NetworkEvent::TransferFailed {
            transfer_id: "test".to_string(),
            peer_id: PeerId::random().to_string(),
            error: "timeout".to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1);
    }

    #[test]
    fn test_unsubscribe() {
        let manager = NetworkEventManager::default();
        let received = Arc::new(RwLock::new(0));
        let received_clone = received.clone();

        let sub_id = manager.subscribe(EventFilter::all(), move |_event| {
            *received_clone.write().unwrap() += 1;
        });

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1);

        manager.unsubscribe(sub_id);

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8081".to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1); // Still 1, not 2
    }

    #[test]
    fn test_event_history() {
        let manager = NetworkEventManager::default();

        for i in 0..5 {
            manager.emit(NetworkEvent::PeerConnected {
                peer_id: PeerId::random().to_string(),
                address: format!("127.0.0.1:{}", 8080 + i),
            });
        }

        let history = manager.get_all_history(10);
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_event_history_filter() {
        let manager = NetworkEventManager::default();

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        manager.emit(NetworkEvent::ContentDiscovered {
            content_id: "test".to_string(),
            provider: PeerId::random().to_string(),
        });

        let filter = EventFilter::categories(vec![EventCategory::Connection]);
        let history = manager.get_history(&filter, 10);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_event_deduplication() {
        let config = EventManagerConfig {
            enable_deduplication: true,
            dedup_window: Duration::from_secs(1),
            ..Default::default()
        };
        let manager = NetworkEventManager::new(config);

        let peer_id = PeerId::random().to_string();
        let address = "127.0.0.1:8080".to_string();

        // Emit same event twice quickly
        manager.emit(NetworkEvent::PeerConnected {
            peer_id: peer_id.clone(),
            address: address.clone(),
        });
        manager.emit(NetworkEvent::PeerConnected {
            peer_id,
            address: address.clone(),
        });

        let stats = manager.stats();
        assert_eq!(stats.total_events, 1); // Should only count once
    }

    #[test]
    fn test_cleanup() {
        let config = EventManagerConfig {
            max_event_age: Duration::from_millis(100),
            ..Default::default()
        };
        let manager = NetworkEventManager::new(config);

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        assert_eq!(manager.get_all_history(10).len(), 1);

        std::thread::sleep(Duration::from_millis(150));
        manager.cleanup();

        assert_eq!(manager.get_all_history(10).len(), 0);
    }

    #[test]
    fn test_clear_history() {
        let manager = NetworkEventManager::default();

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        assert_eq!(manager.get_all_history(10).len(), 1);

        manager.clear_history();

        assert_eq!(manager.get_all_history(10).len(), 0);
    }

    #[test]
    fn test_event_categories() {
        let peer_id = PeerId::random().to_string();

        assert_eq!(
            NetworkEvent::PeerConnected {
                peer_id: peer_id.clone(),
                address: "test".to_string()
            }
            .category(),
            EventCategory::Connection
        );
        assert_eq!(
            NetworkEvent::ContentDiscovered {
                content_id: "test".to_string(),
                provider: peer_id.clone()
            }
            .category(),
            EventCategory::Content
        );
        assert_eq!(
            NetworkEvent::TransferStarted {
                transfer_id: "test".to_string(),
                peer_id: peer_id.clone(),
                size: 100
            }
            .category(),
            EventCategory::Transfer
        );
        assert_eq!(
            NetworkEvent::RelayPathEstablished {
                source: peer_id.clone(),
                destination: peer_id.clone(),
                hops: 1
            }
            .category(),
            EventCategory::Relay
        );
        assert_eq!(
            NetworkEvent::PartitionDetected {
                severity: 0.5,
                affected_peers: 10
            }
            .category(),
            EventCategory::NetworkHealth
        );
        assert_eq!(
            NetworkEvent::ReputationChanged {
                peer_id: peer_id.clone(),
                old_score: 0.5,
                new_score: 0.7
            }
            .category(),
            EventCategory::Reputation
        );
        assert_eq!(
            NetworkEvent::RateLimitTriggered {
                peer_id: peer_id.clone(),
                limit_type: "bandwidth".to_string()
            }
            .category(),
            EventCategory::RateLimit
        );
        assert_eq!(
            NetworkEvent::MaliciousActivity {
                peer_id: peer_id.clone(),
                behavior: "spam".to_string(),
                confidence: 0.9
            }
            .category(),
            EventCategory::Security
        );
        assert_eq!(
            NetworkEvent::HealthCheckFailed {
                peer_id,
                check_type: "ping".to_string()
            }
            .category(),
            EventCategory::Monitoring
        );
    }

    #[test]
    fn test_event_severity() {
        let peer_id = PeerId::random().to_string();

        assert_eq!(
            NetworkEvent::PeerConnected {
                peer_id: peer_id.clone(),
                address: "test".to_string()
            }
            .severity(),
            EventSeverity::Info
        );
        assert_eq!(
            NetworkEvent::TransferFailed {
                transfer_id: "test".to_string(),
                peer_id,
                error: "timeout".to_string()
            }
            .severity(),
            EventSeverity::Warning
        );
        assert_eq!(
            NetworkEvent::PartitionDetected {
                severity: 0.8,
                affected_peers: 100
            }
            .severity(),
            EventSeverity::Error
        );
    }

    #[test]
    fn test_statistics() {
        let manager = NetworkEventManager::default();

        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8080".to_string(),
        });

        manager.emit(NetworkEvent::ContentDiscovered {
            content_id: "test".to_string(),
            provider: PeerId::random().to_string(),
        });

        let stats = manager.stats();
        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.events_by_category.len(), 2);
    }

    #[test]
    fn test_peer_filter() {
        let manager = NetworkEventManager::default();
        let peer_id = PeerId::random();
        let peer_id_str = peer_id.to_string();
        let received = Arc::new(RwLock::new(0));
        let received_clone = received.clone();

        let filter = EventFilter::peer(peer_id);
        let _sub_id = manager.subscribe(filter, move |_event| {
            *received_clone.write().unwrap() += 1;
        });

        // Should match
        manager.emit(NetworkEvent::PeerConnected {
            peer_id: peer_id_str,
            address: "127.0.0.1:8080".to_string(),
        });

        // Should not match
        manager.emit(NetworkEvent::PeerConnected {
            peer_id: PeerId::random().to_string(),
            address: "127.0.0.1:8081".to_string(),
        });

        assert_eq!(*received.read().unwrap(), 1);
    }
}
