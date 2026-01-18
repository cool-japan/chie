// Publish-Subscribe system for real-time network updates
//
// Provides topic-based message distribution with:
// - Topic-based subscription management
// - Message publishing to interested subscribers
// - Subscription filtering and priority routing
// - Message history for late joiners
// - Automatic cleanup of stale subscriptions
// - Delivery statistics and monitoring

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Topic identifier for subscriptions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Topic(String);

impl Topic {
    /// Creates a new topic
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the topic name
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Checks if topic matches a pattern (supports wildcards)
    pub fn matches(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return self.0.starts_with(prefix);
        }
        self.0 == pattern
    }
}

/// Priority level for messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Background = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Published message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message ID
    pub id: String,
    /// Topic the message belongs to
    pub topic: Topic,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message priority
    pub priority: MessagePriority,
    /// Timestamp when message was published
    pub timestamp: u64,
    /// Publisher peer ID (as string for serialization)
    pub publisher: Option<String>,
}

impl Message {
    /// Create a new message with a PeerId publisher
    pub fn with_publisher(mut self, peer_id: PeerId) -> Self {
        self.publisher = Some(peer_id.to_string());
        self
    }
}

/// Subscription information
#[derive(Debug, Clone)]
struct Subscription {
    /// Topics subscribed to (supports wildcards)
    topics: HashSet<String>,
    /// When subscription was created
    created_at: Instant,
    /// Last message delivery time
    last_delivery: Option<Instant>,
    /// Number of messages delivered
    messages_delivered: usize,
    /// Number of failed deliveries
    failed_deliveries: usize,
}

/// Message history entry
#[derive(Debug, Clone)]
struct HistoryEntry {
    message: Message,
    stored_at: Instant,
}

/// Publish-Subscribe manager configuration
#[derive(Debug, Clone)]
pub struct PubSubConfig {
    /// Maximum number of messages to keep in history per topic
    pub max_history_per_topic: usize,
    /// How long to keep messages in history
    pub history_ttl: Duration,
    /// Maximum time before considering a subscription stale
    pub subscription_ttl: Duration,
    /// Maximum number of subscribers per topic
    pub max_subscribers_per_topic: usize,
    /// Whether to enable message deduplication
    pub enable_deduplication: bool,
}

impl Default for PubSubConfig {
    fn default() -> Self {
        Self {
            max_history_per_topic: 100,
            history_ttl: Duration::from_secs(300), // 5 minutes
            subscription_ttl: Duration::from_secs(3600), // 1 hour
            max_subscribers_per_topic: 1000,
            enable_deduplication: true,
        }
    }
}

/// Publish-Subscribe manager
pub struct PubSubManager {
    config: PubSubConfig,
    subscriptions: HashMap<PeerId, Subscription>,
    topic_index: HashMap<String, HashSet<PeerId>>,
    message_history: HashMap<String, VecDeque<HistoryEntry>>,
    seen_messages: HashSet<String>,
    stats: PubSubStats,
}

/// Statistics for the pubsub system
#[derive(Debug, Clone, Default)]
pub struct PubSubStats {
    /// Total messages published
    pub messages_published: usize,
    /// Total messages delivered
    pub messages_delivered: usize,
    /// Total failed deliveries
    pub failed_deliveries: usize,
    /// Total subscriptions created
    pub subscriptions_created: usize,
    /// Total subscriptions removed
    pub subscriptions_removed: usize,
    /// Current number of active subscriptions
    pub active_subscriptions: usize,
    /// Current number of topics with subscribers
    pub active_topics: usize,
}

impl Default for PubSubManager {
    fn default() -> Self {
        Self::new(PubSubConfig::default())
    }
}

impl PubSubManager {
    /// Creates a new pubsub manager
    pub fn new(config: PubSubConfig) -> Self {
        Self {
            config,
            subscriptions: HashMap::new(),
            topic_index: HashMap::new(),
            message_history: HashMap::new(),
            seen_messages: HashSet::new(),
            stats: PubSubStats::default(),
        }
    }

    /// Subscribe a peer to topics
    pub fn subscribe(&mut self, peer_id: PeerId, topics: Vec<String>) -> Result<(), String> {
        // Check if adding new subscription would exceed limits
        for topic in &topics {
            let subscriber_count = self.topic_index.get(topic).map_or(0, |s| s.len());
            if subscriber_count >= self.config.max_subscribers_per_topic
                && !self
                    .subscriptions
                    .get(&peer_id)
                    .is_some_and(|s| s.topics.contains(topic))
            {
                return Err(format!("Topic {} has reached maximum subscribers", topic));
            }
        }

        let is_new = !self.subscriptions.contains_key(&peer_id);

        let subscription = self.subscriptions.entry(peer_id).or_insert_with(|| {
            self.stats.subscriptions_created += 1;
            Subscription {
                topics: HashSet::new(),
                created_at: Instant::now(),
                last_delivery: None,
                messages_delivered: 0,
                failed_deliveries: 0,
            }
        });

        // Add topics to subscription
        for topic in topics {
            if subscription.topics.insert(topic.clone()) {
                // Add to topic index
                self.topic_index.entry(topic).or_default().insert(peer_id);
            }
        }

        if is_new {
            self.stats.active_subscriptions += 1;
        }

        self.stats.active_topics = self.topic_index.len();

        Ok(())
    }

    /// Unsubscribe a peer from topics (or all if topics is empty)
    pub fn unsubscribe(&mut self, peer_id: &PeerId, topics: Vec<String>) {
        if let Some(subscription) = self.subscriptions.get_mut(peer_id) {
            let topics_to_remove: Vec<String> = if topics.is_empty() {
                subscription.topics.iter().cloned().collect()
            } else {
                topics
            };

            for topic in topics_to_remove {
                subscription.topics.remove(&topic);

                // Remove from topic index
                if let Some(subscribers) = self.topic_index.get_mut(&topic) {
                    subscribers.remove(peer_id);
                    if subscribers.is_empty() {
                        self.topic_index.remove(&topic);
                    }
                }
            }

            // Remove subscription if no topics left
            if subscription.topics.is_empty() {
                self.subscriptions.remove(peer_id);
                self.stats.subscriptions_removed += 1;
                self.stats.active_subscriptions = self.stats.active_subscriptions.saturating_sub(1);
            }
        }

        self.stats.active_topics = self.topic_index.len();
    }

    /// Publish a message to a topic
    pub fn publish(&mut self, message: Message) -> Vec<PeerId> {
        // Check for duplicate
        if self.config.enable_deduplication && !self.seen_messages.insert(message.id.clone()) {
            return Vec::new(); // Duplicate message
        }

        self.stats.messages_published += 1;

        // Find matching subscribers
        let mut recipients = Vec::new();
        for (peer_id, subscription) in &self.subscriptions {
            // Check if any of the subscription topics match the message topic
            for topic_pattern in &subscription.topics {
                if message.topic.matches(topic_pattern) {
                    recipients.push(*peer_id);
                    break;
                }
            }
        }

        // Store in history
        let topic_name = message.topic.name().to_string();
        let history = self.message_history.entry(topic_name).or_default();

        history.push_back(HistoryEntry {
            message: message.clone(),
            stored_at: Instant::now(),
        });

        // Trim history
        while history.len() > self.config.max_history_per_topic {
            history.pop_front();
        }

        recipients
    }

    /// Record successful message delivery
    pub fn record_delivery_success(&mut self, peer_id: &PeerId) {
        if let Some(subscription) = self.subscriptions.get_mut(peer_id) {
            subscription.last_delivery = Some(Instant::now());
            subscription.messages_delivered += 1;
            self.stats.messages_delivered += 1;
        }
    }

    /// Record failed message delivery
    pub fn record_delivery_failure(&mut self, peer_id: &PeerId) {
        if let Some(subscription) = self.subscriptions.get_mut(peer_id) {
            subscription.failed_deliveries += 1;
            self.stats.failed_deliveries += 1;
        }
    }

    /// Get message history for a topic
    pub fn get_history(&self, topic: &str, limit: usize) -> Vec<Message> {
        self.message_history
            .get(topic)
            .map(|history| {
                history
                    .iter()
                    .rev()
                    .take(limit)
                    .map(|entry| entry.message.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all topics a peer is subscribed to
    pub fn get_subscriptions(&self, peer_id: &PeerId) -> Vec<String> {
        self.subscriptions
            .get(peer_id)
            .map(|s| s.topics.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all subscribers for a topic
    pub fn get_subscribers(&self, topic: &str) -> Vec<PeerId> {
        self.topic_index
            .get(topic)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get subscriber count for a topic
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.topic_index.get(topic).map_or(0, |s| s.len())
    }

    /// Get all active topics
    pub fn get_topics(&self) -> Vec<String> {
        self.topic_index.keys().cloned().collect()
    }

    /// Clean up stale subscriptions and old history
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        // Remove stale subscriptions
        let stale_peers: Vec<PeerId> = self
            .subscriptions
            .iter()
            .filter(|(_, sub)| {
                sub.last_delivery
                    .is_none_or(|t| now.duration_since(t) > self.config.subscription_ttl)
                    && now.duration_since(sub.created_at) > self.config.subscription_ttl
            })
            .map(|(peer_id, _)| *peer_id)
            .collect();

        for peer_id in stale_peers {
            self.unsubscribe(&peer_id, Vec::new());
        }

        // Clean up old message history
        for history in self.message_history.values_mut() {
            history.retain(|entry| now.duration_since(entry.stored_at) <= self.config.history_ttl);
        }

        // Remove empty histories
        self.message_history
            .retain(|_, history| !history.is_empty());

        // Limit seen messages set size
        if self.seen_messages.len() > 10000 {
            self.seen_messages.clear();
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> &PubSubStats {
        &self.stats
    }

    /// Get subscription info for a peer
    pub fn get_subscription_info(&self, peer_id: &PeerId) -> Option<SubscriptionInfo> {
        self.subscriptions.get(peer_id).map(|sub| SubscriptionInfo {
            topics: sub.topics.iter().cloned().collect(),
            created_at: sub.created_at,
            last_delivery: sub.last_delivery,
            messages_delivered: sub.messages_delivered,
            failed_deliveries: sub.failed_deliveries,
            success_rate: if sub.messages_delivered + sub.failed_deliveries > 0 {
                sub.messages_delivered as f64
                    / (sub.messages_delivered + sub.failed_deliveries) as f64
            } else {
                0.0
            },
        })
    }
}

/// Subscription information for a peer
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub topics: Vec<String>,
    pub created_at: Instant,
    pub last_delivery: Option<Instant>,
    pub messages_delivered: usize,
    pub failed_deliveries: usize,
    pub success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    fn create_test_message(topic: &str, id: &str) -> Message {
        Message {
            id: id.to_string(),
            topic: Topic::new(topic),
            payload: b"test".to_vec(),
            priority: MessagePriority::Normal,
            timestamp: 0,
            publisher: None,
        }
    }

    #[test]
    fn test_topic_creation() {
        let topic = Topic::new("test.topic");
        assert_eq!(topic.name(), "test.topic");
    }

    #[test]
    fn test_topic_matching() {
        let topic = Topic::new("content.video.upload");

        assert!(topic.matches("content.video.upload"));
        assert!(topic.matches("content.video.*"));
        assert!(topic.matches("content.*"));
        assert!(topic.matches("*"));
        assert!(!topic.matches("content.audio.*"));
    }

    #[test]
    fn test_subscribe() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();

        assert_eq!(manager.stats().active_subscriptions, 1);
        assert_eq!(manager.get_subscriptions(&peer), vec!["topic1".to_string()]);
    }

    #[test]
    fn test_subscribe_multiple_topics() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager
            .subscribe(peer, vec!["topic1".to_string(), "topic2".to_string()])
            .unwrap();

        let subs = manager.get_subscriptions(&peer);
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&"topic1".to_string()));
        assert!(subs.contains(&"topic2".to_string()));
    }

    #[test]
    fn test_unsubscribe() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();
        manager.unsubscribe(&peer, vec!["topic1".to_string()]);

        assert_eq!(manager.stats().active_subscriptions, 0);
        assert_eq!(manager.get_subscriptions(&peer).len(), 0);
    }

    #[test]
    fn test_unsubscribe_all() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager
            .subscribe(peer, vec!["topic1".to_string(), "topic2".to_string()])
            .unwrap();
        manager.unsubscribe(&peer, Vec::new());

        assert_eq!(manager.stats().active_subscriptions, 0);
    }

    #[test]
    fn test_publish_to_subscribers() {
        let mut manager = PubSubManager::default();
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager
            .subscribe(peer1, vec!["topic1".to_string()])
            .unwrap();
        manager
            .subscribe(peer2, vec!["topic2".to_string()])
            .unwrap();

        let msg = create_test_message("topic1", "msg1");
        let recipients = manager.publish(msg);

        assert_eq!(recipients.len(), 1);
        assert!(recipients.contains(&peer1));
    }

    #[test]
    fn test_publish_with_wildcard() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager
            .subscribe(peer, vec!["content.*".to_string()])
            .unwrap();

        let msg = create_test_message("content.video", "msg1");
        let recipients = manager.publish(msg);

        assert_eq!(recipients.len(), 1);
        assert!(recipients.contains(&peer));
    }

    #[test]
    fn test_message_deduplication() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();

        let msg = create_test_message("topic1", "msg1");
        let recipients1 = manager.publish(msg.clone());
        let recipients2 = manager.publish(msg);

        assert_eq!(recipients1.len(), 1);
        assert_eq!(recipients2.len(), 0); // Duplicate
    }

    #[test]
    fn test_message_history() {
        let mut manager = PubSubManager::default();

        let msg1 = create_test_message("topic1", "msg1");
        let msg2 = create_test_message("topic1", "msg2");

        manager.publish(msg1);
        manager.publish(msg2);

        let history = manager.get_history("topic1", 10);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_history_limit() {
        let config = PubSubConfig {
            max_history_per_topic: 2,
            ..Default::default()
        };
        let mut manager = PubSubManager::new(config);

        for i in 0..5 {
            let msg = create_test_message("topic1", &format!("msg{}", i));
            manager.publish(msg);
        }

        let history = manager.get_history("topic1", 10);
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_get_subscribers() {
        let mut manager = PubSubManager::default();
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager
            .subscribe(peer1, vec!["topic1".to_string()])
            .unwrap();
        manager
            .subscribe(peer2, vec!["topic1".to_string()])
            .unwrap();

        let subscribers = manager.get_subscribers("topic1");
        assert_eq!(subscribers.len(), 2);
    }

    #[test]
    fn test_subscriber_count() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        assert_eq!(manager.subscriber_count("topic1"), 0);

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();

        assert_eq!(manager.subscriber_count("topic1"), 1);
    }

    #[test]
    fn test_get_topics() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager
            .subscribe(peer, vec!["topic1".to_string(), "topic2".to_string()])
            .unwrap();

        let topics = manager.get_topics();
        assert_eq!(topics.len(), 2);
    }

    #[test]
    fn test_record_delivery() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();
        manager.record_delivery_success(&peer);

        let info = manager.get_subscription_info(&peer).unwrap();
        assert_eq!(info.messages_delivered, 1);
    }

    #[test]
    fn test_delivery_failure() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();
        manager.record_delivery_failure(&peer);

        let info = manager.get_subscription_info(&peer).unwrap();
        assert_eq!(info.failed_deliveries, 1);
    }

    #[test]
    fn test_success_rate() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();
        manager.record_delivery_success(&peer);
        manager.record_delivery_success(&peer);
        manager.record_delivery_failure(&peer);

        let info = manager.get_subscription_info(&peer).unwrap();
        assert!((info.success_rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_max_subscribers() {
        let config = PubSubConfig {
            max_subscribers_per_topic: 2,
            ..Default::default()
        };
        let mut manager = PubSubManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        manager
            .subscribe(peer1, vec!["topic1".to_string()])
            .unwrap();
        manager
            .subscribe(peer2, vec!["topic1".to_string()])
            .unwrap();

        let result = manager.subscribe(peer3, vec!["topic1".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_statistics() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();

        let msg = create_test_message("topic1", "msg1");
        manager.publish(msg);

        let stats = manager.stats();
        assert_eq!(stats.messages_published, 1);
        assert_eq!(stats.active_subscriptions, 1);
    }

    #[test]
    fn test_cleanup_removes_empty_subscriptions() {
        let mut manager = PubSubManager::default();
        let peer = create_test_peer();

        manager.subscribe(peer, vec!["topic1".to_string()]).unwrap();
        manager.cleanup();

        // Should still exist right after creation
        assert_eq!(manager.stats().active_subscriptions, 1);
    }

    #[test]
    fn test_message_priority() {
        assert!(MessagePriority::Critical > MessagePriority::High);
        assert!(MessagePriority::High > MessagePriority::Normal);
        assert!(MessagePriority::Normal > MessagePriority::Low);
        assert!(MessagePriority::Low > MessagePriority::Background);
    }
}
