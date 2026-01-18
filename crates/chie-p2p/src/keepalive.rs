// Keepalive management for detecting and maintaining active connections
// Provides configurable keepalive intervals, timeout detection, and automatic cleanup

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Peer identifier type
pub type PeerId = String;

/// Configuration for keepalive behavior
#[derive(Debug, Clone)]
pub struct KeepaliveConfig {
    /// Interval between keepalive messages
    pub keepalive_interval: Duration,

    /// Timeout waiting for keepalive response
    pub response_timeout: Duration,

    /// Maximum consecutive failures before marking connection as dead
    pub max_failures: u32,

    /// Whether to automatically remove dead connections
    pub auto_cleanup: bool,

    /// Minimum interval between keepalives (rate limiting)
    pub min_interval: Duration,

    /// Enable statistics tracking
    pub enable_stats: bool,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(30),
            response_timeout: Duration::from_secs(10),
            max_failures: 3,
            auto_cleanup: true,
            min_interval: Duration::from_secs(5),
            enable_stats: true,
        }
    }
}

/// Keepalive message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeepaliveMessage {
    /// Ping message with sequence number
    Ping { sequence: u64, timestamp: u64 },

    /// Pong response with sequence number
    Pong { sequence: u64, timestamp: u64 },
}

/// Connection state for keepalive tracking
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Peer ID
    pub peer_id: PeerId,

    /// Last time we sent a ping
    pub last_ping_sent: Option<Instant>,

    /// Last time we received a pong
    pub last_pong_received: Option<Instant>,

    /// Last ping sequence number
    pub last_sequence: u64,

    /// Consecutive failures (no pong received)
    pub consecutive_failures: u32,

    /// Whether connection is considered alive
    pub is_alive: bool,

    /// Total pings sent
    pub total_pings: u64,

    /// Total pongs received
    pub total_pongs: u64,

    /// Average round-trip time
    pub avg_rtt: Duration,
}

impl ConnectionState {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            last_ping_sent: None,
            last_pong_received: None,
            last_sequence: 0,
            consecutive_failures: 0,
            is_alive: true,
            total_pings: 0,
            total_pongs: 0,
            avg_rtt: Duration::ZERO,
        }
    }
}

/// Statistics for keepalive operations
#[derive(Debug, Clone, Default)]
pub struct KeepaliveStats {
    /// Total connections being monitored
    pub total_connections: usize,

    /// Active (alive) connections
    pub active_connections: usize,

    /// Dead connections
    pub dead_connections: usize,

    /// Total pings sent across all connections
    pub total_pings_sent: u64,

    /// Total pongs received across all connections
    pub total_pongs_received: u64,

    /// Total timeouts
    pub total_timeouts: u64,

    /// Average RTT across all connections
    pub avg_rtt: Duration,

    /// Maximum RTT observed
    pub max_rtt: Duration,

    /// Minimum RTT observed
    pub min_rtt: Duration,
}

/// Events emitted by the keepalive manager
#[derive(Debug, Clone)]
pub enum KeepaliveEvent {
    /// Connection became alive (first pong or recovery)
    ConnectionAlive { peer_id: PeerId },

    /// Connection timeout (no pong received)
    ConnectionTimeout {
        peer_id: PeerId,
        consecutive_failures: u32,
    },

    /// Connection marked as dead (exceeded max failures)
    ConnectionDead { peer_id: PeerId },

    /// Ping sent
    PingSent { peer_id: PeerId, sequence: u64 },

    /// Pong received
    PongReceived {
        peer_id: PeerId,
        sequence: u64,
        rtt: Duration,
    },
}

/// Keepalive manager for connection health monitoring
pub struct KeepaliveManager {
    config: KeepaliveConfig,
    connections: Arc<RwLock<HashMap<PeerId, ConnectionState>>>,
    stats: Arc<RwLock<KeepaliveStats>>,
    event_tx: mpsc::UnboundedSender<KeepaliveEvent>,
}

impl KeepaliveManager {
    /// Create a new keepalive manager
    pub fn new(config: KeepaliveConfig) -> (Self, mpsc::UnboundedReceiver<KeepaliveEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let manager = Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(KeepaliveStats::default())),
            event_tx,
        };

        (manager, event_rx)
    }

    /// Register a new connection for keepalive monitoring
    pub fn register_connection(&self, peer_id: PeerId) {
        let mut connections = self.connections.write();
        connections.insert(peer_id.clone(), ConnectionState::new(peer_id.clone()));

        if self.config.enable_stats {
            let mut stats = self.stats.write();
            stats.total_connections = connections.len();
            stats.active_connections = connections.values().filter(|c| c.is_alive).count();
        }

        debug!("Registered connection for keepalive: {}", peer_id);
    }

    /// Unregister a connection from keepalive monitoring
    pub fn unregister_connection(&self, peer_id: &PeerId) -> Option<ConnectionState> {
        let removed = self.connections.write().remove(peer_id);

        if self.config.enable_stats {
            let connections = self.connections.read();
            let mut stats = self.stats.write();
            stats.total_connections = connections.len();
            stats.active_connections = connections.values().filter(|c| c.is_alive).count();
            stats.dead_connections = connections.values().filter(|c| !c.is_alive).count();
        }

        if removed.is_some() {
            debug!("Unregistered connection from keepalive: {}", peer_id);
        }

        removed
    }

    /// Check if a connection needs a keepalive ping
    pub fn needs_keepalive(&self, peer_id: &PeerId) -> bool {
        let connections = self.connections.read();
        if let Some(state) = connections.get(peer_id) {
            if !state.is_alive {
                return false; // Don't ping dead connections
            }

            match state.last_ping_sent {
                None => true, // Never pinged, needs keepalive
                Some(last_ping) => {
                    let elapsed = last_ping.elapsed();
                    elapsed >= self.config.keepalive_interval
                }
            }
        } else {
            false
        }
    }

    /// Generate a ping message for a connection
    pub fn create_ping(&self, peer_id: &PeerId) -> Option<KeepaliveMessage> {
        let mut connections = self.connections.write();
        if let Some(state) = connections.get_mut(peer_id) {
            // Check minimum interval
            if let Some(last_ping) = state.last_ping_sent {
                if last_ping.elapsed() < self.config.min_interval {
                    return None;
                }
            }

            state.last_sequence += 1;
            state.last_ping_sent = Some(Instant::now());
            state.total_pings += 1;

            let sequence = state.last_sequence;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            // Update stats
            if self.config.enable_stats {
                let mut stats = self.stats.write();
                stats.total_pings_sent += 1;
            }

            // Emit event
            let _ = self.event_tx.send(KeepaliveEvent::PingSent {
                peer_id: peer_id.clone(),
                sequence,
            });

            debug!("Created ping for {}: seq={}", peer_id, sequence);

            Some(KeepaliveMessage::Ping {
                sequence,
                timestamp,
            })
        } else {
            None
        }
    }

    /// Handle received pong message
    pub fn handle_pong(&self, peer_id: &PeerId, sequence: u64) -> Result<Duration, KeepaliveError> {
        let mut connections = self.connections.write();
        if let Some(state) = connections.get_mut(peer_id) {
            // Verify sequence number
            if sequence != state.last_sequence {
                warn!(
                    "Received pong with unexpected sequence: expected {}, got {}",
                    state.last_sequence, sequence
                );
                return Err(KeepaliveError::SequenceMismatch {
                    expected: state.last_sequence,
                    received: sequence,
                });
            }

            // Calculate RTT
            let rtt = if let Some(ping_time) = state.last_ping_sent {
                ping_time.elapsed()
            } else {
                return Err(KeepaliveError::NoPingRecorded);
            };

            // Update state
            state.last_pong_received = Some(Instant::now());
            state.total_pongs += 1;
            state.consecutive_failures = 0;

            // Mark as alive if it was dead
            let was_dead = !state.is_alive;
            state.is_alive = true;

            // Update average RTT
            let total_pongs = state.total_pongs;
            let old_avg = state.avg_rtt;
            state.avg_rtt = Duration::from_nanos(
                ((old_avg.as_nanos() * (total_pongs - 1) as u128 + rtt.as_nanos())
                    / total_pongs as u128) as u64,
            );

            // Update stats
            if self.config.enable_stats {
                let mut stats = self.stats.write();
                stats.total_pongs_received += 1;

                // Update global RTT stats
                if rtt > stats.max_rtt {
                    stats.max_rtt = rtt;
                }
                if stats.min_rtt.is_zero() || rtt < stats.min_rtt {
                    stats.min_rtt = rtt;
                }

                // Update average RTT
                let total_conns = connections.len() as u128;
                if total_conns > 0 {
                    let sum_rtt: Duration = connections.values().map(|c| c.avg_rtt).sum();
                    stats.avg_rtt = Duration::from_nanos((sum_rtt.as_nanos() / total_conns) as u64);
                }

                stats.active_connections = connections.values().filter(|c| c.is_alive).count();
                stats.dead_connections = connections.values().filter(|c| !c.is_alive).count();
            }

            // Emit event
            if was_dead {
                let _ = self.event_tx.send(KeepaliveEvent::ConnectionAlive {
                    peer_id: peer_id.clone(),
                });
            }

            let _ = self.event_tx.send(KeepaliveEvent::PongReceived {
                peer_id: peer_id.clone(),
                sequence,
                rtt,
            });

            debug!(
                "Received pong from {}: seq={}, rtt={:?}",
                peer_id, sequence, rtt
            );

            Ok(rtt)
        } else {
            Err(KeepaliveError::ConnectionNotFound(peer_id.clone()))
        }
    }

    /// Check for timed-out connections and mark them appropriately
    pub fn check_timeouts(&self) -> Vec<PeerId> {
        let mut dead_peers = Vec::new();

        let mut connections = self.connections.write();
        for (peer_id, state) in connections.iter_mut() {
            if !state.is_alive {
                continue; // Already marked as dead
            }

            // Check if we're waiting for a pong
            if let Some(last_ping) = state.last_ping_sent {
                let elapsed = last_ping.elapsed();

                // Check if response timed out
                if elapsed > self.config.response_timeout {
                    // Only count as timeout if we haven't received a pong yet
                    if state.last_pong_received.is_none()
                        || state.last_pong_received.unwrap() < last_ping
                    {
                        state.consecutive_failures += 1;

                        if self.config.enable_stats {
                            let mut stats = self.stats.write();
                            stats.total_timeouts += 1;
                        }

                        let _ = self.event_tx.send(KeepaliveEvent::ConnectionTimeout {
                            peer_id: peer_id.clone(),
                            consecutive_failures: state.consecutive_failures,
                        });

                        warn!(
                            "Keepalive timeout for {}: {} consecutive failures",
                            peer_id, state.consecutive_failures
                        );

                        // Check if exceeded max failures
                        if state.consecutive_failures >= self.config.max_failures {
                            state.is_alive = false;
                            dead_peers.push(peer_id.clone());

                            let _ = self.event_tx.send(KeepaliveEvent::ConnectionDead {
                                peer_id: peer_id.clone(),
                            });

                            error!("Connection marked as dead: {}", peer_id);
                        }
                    }
                }
            }
        }

        // Update stats
        if self.config.enable_stats && !dead_peers.is_empty() {
            let mut stats = self.stats.write();
            stats.active_connections = connections.values().filter(|c| c.is_alive).count();
            stats.dead_connections = connections.values().filter(|c| !c.is_alive).count();
        }

        // Auto cleanup if enabled
        if self.config.auto_cleanup {
            for peer_id in &dead_peers {
                connections.remove(peer_id);
            }

            if self.config.enable_stats && !dead_peers.is_empty() {
                let mut stats = self.stats.write();
                stats.total_connections = connections.len();
            }
        }

        dead_peers
    }

    /// Get connection state for a peer
    pub fn get_connection_state(&self, peer_id: &PeerId) -> Option<ConnectionState> {
        self.connections.read().get(peer_id).cloned()
    }

    /// Get list of all alive connections
    pub fn get_alive_connections(&self) -> Vec<PeerId> {
        self.connections
            .read()
            .iter()
            .filter(|(_, state)| state.is_alive)
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// Get list of all dead connections
    pub fn get_dead_connections(&self) -> Vec<PeerId> {
        self.connections
            .read()
            .iter()
            .filter(|(_, state)| !state.is_alive)
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// Get current statistics
    pub fn get_stats(&self) -> KeepaliveStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write();
        *stats = KeepaliveStats::default();

        let connections = self.connections.read();
        stats.total_connections = connections.len();
        stats.active_connections = connections.values().filter(|c| c.is_alive).count();
        stats.dead_connections = connections.values().filter(|c| !c.is_alive).count();
    }

    /// Start background keepalive task
    pub fn start_keepalive_task(
        self: Arc<Self>,
        mut ping_sender: impl FnMut(&PeerId, KeepaliveMessage) + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.config.keepalive_interval / 2);

            loop {
                interval.tick().await;

                // Send pings to connections that need them
                let peer_ids: Vec<PeerId> = self.connections.read().keys().cloned().collect();

                for peer_id in peer_ids {
                    if self.needs_keepalive(&peer_id) {
                        if let Some(ping) = self.create_ping(&peer_id) {
                            ping_sender(&peer_id, ping);
                        }
                    }
                }

                // Check for timeouts
                self.check_timeouts();
            }
        })
    }
}

/// Errors that can occur during keepalive operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeepaliveError {
    #[error("Connection not found: {0}")]
    ConnectionNotFound(PeerId),

    #[error("Sequence mismatch: expected {expected}, received {received}")]
    SequenceMismatch { expected: u64, received: u64 },

    #[error("No ping recorded for this connection")]
    NoPingRecorded,

    #[error("Connection is dead")]
    ConnectionDead,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[test]
    fn test_default_config() {
        let config = KeepaliveConfig::default();
        assert_eq!(config.keepalive_interval, Duration::from_secs(30));
        assert_eq!(config.response_timeout, Duration::from_secs(10));
        assert_eq!(config.max_failures, 3);
        assert!(config.auto_cleanup);
        assert!(config.enable_stats);
    }

    #[test]
    fn test_register_unregister() {
        let config = KeepaliveConfig::default();
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        assert!(manager.get_connection_state(&"peer1".to_string()).is_some());

        let state = manager.unregister_connection(&"peer1".to_string());
        assert!(state.is_some());
        assert!(manager.get_connection_state(&"peer1".to_string()).is_none());
    }

    #[test]
    fn test_create_ping() {
        let config = KeepaliveConfig {
            min_interval: Duration::from_millis(0), // No throttling for test
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        let ping = manager.create_ping(&"peer1".to_string());
        assert!(ping.is_some());

        if let Some(KeepaliveMessage::Ping { sequence, .. }) = ping {
            assert_eq!(sequence, 1);
        }

        // Second ping should have incremented sequence
        let ping2 = manager.create_ping(&"peer1".to_string());
        assert!(ping2.is_some());

        if let Some(KeepaliveMessage::Ping { sequence, .. }) = ping2 {
            assert_eq!(sequence, 2);
        }
    }

    #[test]
    fn test_handle_pong() {
        let config = KeepaliveConfig::default();
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        // Send ping first
        manager.create_ping(&"peer1".to_string());

        // Handle pong
        let result = manager.handle_pong(&"peer1".to_string(), 1);
        assert!(result.is_ok());

        let state = manager.get_connection_state(&"peer1".to_string()).unwrap();
        assert_eq!(state.total_pongs, 1);
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.is_alive);
    }

    #[test]
    fn test_sequence_mismatch() {
        let config = KeepaliveConfig::default();
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        manager.create_ping(&"peer1".to_string());

        // Wrong sequence number
        let result = manager.handle_pong(&"peer1".to_string(), 999);
        assert!(matches!(
            result,
            Err(KeepaliveError::SequenceMismatch { .. })
        ));
    }

    #[test]
    fn test_no_ping_recorded() {
        let config = KeepaliveConfig::default();
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        // Try to handle pong without sending ping
        let result = manager.handle_pong(&"peer1".to_string(), 0);
        assert!(matches!(result, Err(KeepaliveError::NoPingRecorded)));
    }

    #[tokio::test]
    async fn test_timeout_detection() {
        let config = KeepaliveConfig {
            response_timeout: Duration::from_millis(50),
            max_failures: 2,
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        manager.create_ping(&"peer1".to_string());

        // Wait for timeout
        sleep(Duration::from_millis(60)).await;

        let dead_peers = manager.check_timeouts();
        assert_eq!(dead_peers.len(), 0); // First timeout, not dead yet

        let state = manager.get_connection_state(&"peer1".to_string()).unwrap();
        assert_eq!(state.consecutive_failures, 1);

        // Send another ping and timeout again
        manager.create_ping(&"peer1".to_string());
        sleep(Duration::from_millis(60)).await;

        let dead_peers = manager.check_timeouts();
        assert_eq!(dead_peers.len(), 1); // Second timeout, now dead
        assert_eq!(dead_peers[0], "peer1");
    }

    #[tokio::test]
    async fn test_auto_cleanup() {
        let config = KeepaliveConfig {
            response_timeout: Duration::from_millis(50),
            max_failures: 1,
            auto_cleanup: true,
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        manager.create_ping(&"peer1".to_string());

        // Wait for timeout
        sleep(Duration::from_millis(60)).await;

        manager.check_timeouts();

        // Should be removed due to auto_cleanup
        assert!(manager.get_connection_state(&"peer1".to_string()).is_none());
    }

    #[test]
    fn test_get_alive_dead_connections() {
        let config = KeepaliveConfig {
            auto_cleanup: false,
            max_failures: 1,
            response_timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        manager.register_connection("peer2".to_string());

        // Mark peer1 as dead manually
        {
            let mut connections = manager.connections.write();
            if let Some(state) = connections.get_mut(&"peer1".to_string()) {
                state.is_alive = false;
            }
        }

        let alive = manager.get_alive_connections();
        let dead = manager.get_dead_connections();

        assert_eq!(alive.len(), 1);
        assert_eq!(dead.len(), 1);
        assert!(alive.contains(&"peer2".to_string()));
        assert!(dead.contains(&"peer1".to_string()));
    }

    #[test]
    fn test_statistics() {
        let config = KeepaliveConfig {
            enable_stats: true,
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());
        manager.register_connection("peer2".to_string());

        manager.create_ping(&"peer1".to_string());
        manager.create_ping(&"peer2".to_string());

        manager.handle_pong(&"peer1".to_string(), 1).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_pings_sent, 2);
        assert_eq!(stats.total_pongs_received, 1);
    }

    #[tokio::test]
    async fn test_events() {
        let config = KeepaliveConfig::default();
        let (manager, mut event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        // Should emit PingSent event
        manager.create_ping(&"peer1".to_string());

        if let Ok(event) = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await {
            if let Some(KeepaliveEvent::PingSent { peer_id, sequence }) = event {
                assert_eq!(peer_id, "peer1");
                assert_eq!(sequence, 1);
            } else {
                panic!("Expected PingSent event");
            }
        }

        // Should emit PongReceived event
        manager.handle_pong(&"peer1".to_string(), 1).unwrap();

        if let Ok(event) = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await {
            if let Some(KeepaliveEvent::PongReceived {
                peer_id, sequence, ..
            }) = event
            {
                assert_eq!(peer_id, "peer1");
                assert_eq!(sequence, 1);
            } else {
                panic!("Expected PongReceived event");
            }
        }
    }

    #[test]
    fn test_min_interval_enforcement() {
        let config = KeepaliveConfig {
            min_interval: Duration::from_secs(10),
            ..Default::default()
        };
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        // First ping should succeed
        let ping1 = manager.create_ping(&"peer1".to_string());
        assert!(ping1.is_some());

        // Second ping immediately should fail due to min_interval
        let ping2 = manager.create_ping(&"peer1".to_string());
        assert!(ping2.is_none());
    }

    #[test]
    fn test_rtt_calculation() {
        let config = KeepaliveConfig::default();
        let (manager, _event_rx) = KeepaliveManager::new(config);

        manager.register_connection("peer1".to_string());

        manager.create_ping(&"peer1".to_string());
        let rtt = manager.handle_pong(&"peer1".to_string(), 1).unwrap();

        assert!(rtt.as_nanos() > 0);

        let state = manager.get_connection_state(&"peer1".to_string()).unwrap();
        assert_eq!(state.avg_rtt, rtt);

        let stats = manager.get_stats();
        assert_eq!(stats.max_rtt, rtt);
        assert_eq!(stats.min_rtt, rtt);
    }
}
