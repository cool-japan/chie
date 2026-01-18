//! WebSocket support for real-time updates.
//!
//! This module provides:
//! - WebSocket connection handling
//! - Event broadcasting to connected clients
//! - Real-time proof submission notifications
//! - Live statistics streaming
//! - Subscription-based updates

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Maximum number of pending messages in the broadcast channel.
const BROADCAST_CAPACITY: usize = 1000;

/// Types of WebSocket events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// A new proof was submitted and verified.
    ProofSubmitted,
    /// Rewards were distributed.
    RewardsDistributed,
    /// Fraud was detected.
    FraudDetected,
    /// Content was registered.
    ContentRegistered,
    /// System statistics update.
    StatsUpdate,
    /// Node status change.
    NodeStatus,
    /// General notification.
    Notification,
}

/// A WebSocket event to broadcast to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsEvent {
    /// Event type.
    pub event_type: EventType,
    /// Event ID.
    pub event_id: String,
    /// Timestamp (Unix millis).
    pub timestamp: u64,
    /// Event payload (JSON value).
    pub payload: serde_json::Value,
}

impl WsEvent {
    /// Create a new event.
    pub fn new(event_type: EventType, payload: impl Serialize) -> Self {
        Self {
            event_type,
            event_id: Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            payload: serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Create a proof submitted event.
    pub fn proof_submitted(proof_id: Uuid, provider_id: Uuid, reward: i64) -> Self {
        Self::new(
            EventType::ProofSubmitted,
            serde_json::json!({
                "proof_id": proof_id,
                "provider_id": provider_id,
                "reward": reward
            }),
        )
    }

    /// Create a rewards distributed event.
    pub fn rewards_distributed(
        proof_id: Uuid,
        provider_reward: u64,
        creator_reward: u64,
        total: u64,
    ) -> Self {
        Self::new(
            EventType::RewardsDistributed,
            serde_json::json!({
                "proof_id": proof_id,
                "provider_reward": provider_reward,
                "creator_reward": creator_reward,
                "total_distributed": total
            }),
        )
    }

    /// Create a fraud detected event.
    pub fn fraud_detected(provider_id: Uuid, fraud_type: &str, details: &str) -> Self {
        Self::new(
            EventType::FraudDetected,
            serde_json::json!({
                "provider_id": provider_id,
                "fraud_type": fraud_type,
                "details": details
            }),
        )
    }

    /// Create a stats update event.
    pub fn stats_update(stats: SystemStats) -> Self {
        Self::new(EventType::StatsUpdate, stats)
    }
}

/// System statistics for real-time dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemStats {
    /// Total active nodes.
    pub active_nodes: u64,
    /// Total content items.
    pub total_content: u64,
    /// Total proofs verified (last hour).
    pub proofs_last_hour: u64,
    /// Total rewards distributed (last hour).
    pub rewards_last_hour: u64,
    /// Average proof latency (ms).
    pub avg_proof_latency_ms: f64,
    /// Fraud detections (last hour).
    pub fraud_last_hour: u64,
    /// Current bandwidth throughput (bytes/sec).
    pub bandwidth_throughput: u64,
}

/// Subscription request from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    /// Action: "subscribe" or "unsubscribe".
    pub action: String,
    /// Event types to subscribe to.
    pub event_types: Vec<EventType>,
}

/// Client connection state.
#[derive(Debug)]
#[allow(dead_code)]
struct ClientState {
    /// Client ID.
    id: String,
    /// Subscribed event types (empty = all).
    subscriptions: Vec<EventType>,
}

/// WebSocket hub for managing connections and broadcasting events.
pub struct WsHub {
    /// Broadcast channel sender.
    tx: broadcast::Sender<WsEvent>,
    /// Connected clients (for tracking).
    clients: RwLock<HashMap<String, ClientState>>,
}

impl WsHub {
    /// Create a new WebSocket hub.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            tx,
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Broadcast an event to all connected clients.
    pub fn broadcast(&self, event: WsEvent) {
        // Log broadcast (only log if there are receivers)
        if self.tx.receiver_count() > 0 {
            debug!(
                "Broadcasting {:?} event to {} clients",
                event.event_type,
                self.tx.receiver_count()
            );
            if let Err(e) = self.tx.send(event) {
                warn!("Failed to broadcast event: {}", e);
            }
        }
    }

    /// Get a receiver for events.
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }

    /// Register a client connection.
    async fn register_client(&self, id: String) {
        let mut clients = self.clients.write().await;
        clients.insert(
            id.clone(),
            ClientState {
                id,
                subscriptions: vec![], // Subscribe to all by default
            },
        );
    }

    /// Unregister a client.
    async fn unregister_client(&self, id: &str) {
        let mut clients = self.clients.write().await;
        clients.remove(id);
    }

    /// Update client subscriptions.
    async fn update_subscriptions(&self, id: &str, event_types: Vec<EventType>) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(id) {
            client.subscriptions = event_types;
        }
    }

    /// Get number of connected clients.
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Get receiver count (more accurate for active connections).
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for WsHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared WebSocket hub type.
pub type SharedWsHub = Arc<WsHub>;

/// Create a shared WebSocket hub.
pub fn create_ws_hub() -> SharedWsHub {
    Arc::new(WsHub::new())
}

/// WebSocket handler for Axum.
pub async fn ws_handler(ws: WebSocketUpgrade, State(hub): State<SharedWsHub>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, hub))
}

/// Handle a WebSocket connection.
async fn handle_socket(socket: WebSocket, hub: SharedWsHub) {
    let client_id = Uuid::new_v4().to_string();
    info!("WebSocket client connected: {}", client_id);

    hub.register_client(client_id.clone()).await;

    let (mut sender, mut receiver) = socket.split();
    let mut rx = hub.subscribe();

    // Clone for the receive task
    let hub_clone = hub.clone();
    let client_id_clone = client_id.clone();

    // Spawn task to receive messages from client
    let receive_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Handle subscription requests
                    if let Ok(req) = serde_json::from_str::<SubscriptionRequest>(&text) {
                        match req.action.as_str() {
                            "subscribe" => {
                                hub_clone
                                    .update_subscriptions(&client_id_clone, req.event_types)
                                    .await;
                                debug!("Client {} updated subscriptions", client_id_clone);
                            }
                            "unsubscribe" => {
                                hub_clone
                                    .update_subscriptions(&client_id_clone, vec![])
                                    .await;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    debug!("Client {} sent close", client_id_clone);
                    break;
                }
                Ok(Message::Ping(data)) => {
                    debug!("Ping from client {}", client_id_clone);
                    // Pong is automatically sent by axum
                    let _ = data; // silence unused warning
                }
                Err(e) => {
                    warn!("WebSocket receive error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Send events to client
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let json = match serde_json::to_string(&event) {
                        Ok(j) => j,
                        Err(e) => {
                            error!("Failed to serialize event: {}", e);
                            continue;
                        }
                    };

                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Client lagged behind by {} messages", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = receive_task => {},
        _ = send_task => {},
    }

    hub.unregister_client(&client_id).await;
    info!("WebSocket client disconnected: {}", client_id);
}

/// Event broadcaster for use in other modules.
#[derive(Clone)]
pub struct EventBroadcaster {
    hub: SharedWsHub,
}

impl EventBroadcaster {
    /// Create a new broadcaster.
    pub fn new(hub: SharedWsHub) -> Self {
        Self { hub }
    }

    /// Broadcast a proof submitted event.
    pub fn proof_submitted(&self, proof_id: Uuid, provider_id: Uuid, reward: i64) {
        self.hub
            .broadcast(WsEvent::proof_submitted(proof_id, provider_id, reward));
    }

    /// Broadcast a rewards distributed event.
    pub fn rewards_distributed(
        &self,
        proof_id: Uuid,
        provider_reward: u64,
        creator_reward: u64,
        total: u64,
    ) {
        self.hub.broadcast(WsEvent::rewards_distributed(
            proof_id,
            provider_reward,
            creator_reward,
            total,
        ));
    }

    /// Broadcast a fraud detected event.
    pub fn fraud_detected(&self, provider_id: Uuid, fraud_type: &str, details: &str) {
        self.hub
            .broadcast(WsEvent::fraud_detected(provider_id, fraud_type, details));
    }

    /// Broadcast a stats update.
    pub fn stats_update(&self, stats: SystemStats) {
        self.hub.broadcast(WsEvent::stats_update(stats));
    }

    /// Broadcast a custom event.
    pub fn custom(&self, event_type: EventType, payload: impl Serialize) {
        self.hub.broadcast(WsEvent::new(event_type, payload));
    }
}

/// Create router for WebSocket endpoints.
pub fn ws_routes<S>(hub: SharedWsHub) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use axum::routing::get;

    axum::Router::new()
        .route("/ws", get(ws_handler))
        .route("/ws/stats", get(ws_stats_handler))
        .with_state(hub)
}

/// Handler to get WebSocket stats.
async fn ws_stats_handler(State(hub): State<SharedWsHub>) -> impl IntoResponse {
    let count = hub.client_count().await;
    let receiver_count = hub.receiver_count();

    axum::Json(serde_json::json!({
        "connected_clients": count,
        "active_receivers": receiver_count
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_event_creation() {
        let event = WsEvent::proof_submitted(Uuid::new_v4(), Uuid::new_v4(), 100);

        assert_eq!(event.event_type, EventType::ProofSubmitted);
        assert!(!event.event_id.is_empty());
    }

    #[test]
    fn test_ws_event_serialization() {
        let event = WsEvent::stats_update(SystemStats {
            active_nodes: 100,
            total_content: 500,
            proofs_last_hour: 1000,
            rewards_last_hour: 50000,
            avg_proof_latency_ms: 25.5,
            fraud_last_hour: 2,
            bandwidth_throughput: 1024 * 1024 * 100,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("stats_update"));
        assert!(json.contains("active_nodes"));
    }

    #[tokio::test]
    async fn test_ws_hub() {
        let hub = create_ws_hub();

        // Subscribe before broadcast
        let mut rx = hub.subscribe();

        // Broadcast event
        hub.broadcast(WsEvent::new(
            EventType::Notification,
            serde_json::json!({"message": "test"}),
        ));

        // Receive event
        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, EventType::Notification);
    }

    #[tokio::test]
    async fn test_client_registration() {
        let hub = create_ws_hub();

        hub.register_client("client1".to_string()).await;
        assert_eq!(hub.client_count().await, 1);

        hub.unregister_client("client1").await;
        assert_eq!(hub.client_count().await, 0);
    }
}
