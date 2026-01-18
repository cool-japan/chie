//! Session management for peer connections.
//!
//! This module provides session lifecycle management including creation,
//! renewal, expiration, and authentication tracking.
//!
//! # Example
//! ```
//! use chie_p2p::session_manager::{SessionManager, SessionConfig};
//! use std::time::Duration;
//!
//! let config = SessionConfig {
//!     session_ttl: Duration::from_secs(3600),
//!     renewal_threshold: 0.8,
//!     max_sessions_per_peer: 5,
//!     enable_auto_renewal: true,
//! };
//!
//! let mut manager = SessionManager::new(config);
//! let session_id = manager.create_session("peer1".to_string(), vec![]);
//! assert!(manager.is_valid(&session_id));
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Session identifier (UUID-like)
pub type SessionId = String;

/// Peer identifier
pub type PeerId = String;

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active and valid
    Active,
    /// Session is expiring soon and should be renewed
    Expiring,
    /// Session has expired
    Expired,
    /// Session was explicitly terminated
    Terminated,
}

/// Session information
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier
    pub id: SessionId,
    /// Peer this session belongs to
    pub peer_id: PeerId,
    /// When the session was created
    pub created_at: Instant,
    /// When the session was last renewed
    pub last_renewed: Instant,
    /// When the session expires
    pub expires_at: Instant,
    /// Current session state
    pub state: SessionState,
    /// Custom session metadata
    pub metadata: HashMap<String, String>,
    /// Number of times this session has been renewed
    pub renewal_count: u32,
    /// Session activity counter (requests/responses)
    pub activity_count: u64,
}

impl Session {
    /// Check if session needs renewal
    pub fn needs_renewal(&self, threshold: f64) -> bool {
        let elapsed = self.last_renewed.elapsed();
        let total_duration = self.expires_at.duration_since(self.last_renewed);
        elapsed.as_secs_f64() / total_duration.as_secs_f64() >= threshold
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get remaining session time
    pub fn remaining_time(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Session manager configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session time-to-live
    pub session_ttl: Duration,
    /// Renewal threshold (0.0-1.0) - when to trigger renewal warning
    pub renewal_threshold: f64,
    /// Maximum sessions per peer
    pub max_sessions_per_peer: usize,
    /// Enable automatic renewal tracking
    pub enable_auto_renewal: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_ttl: Duration::from_secs(3600), // 1 hour
            renewal_threshold: 0.8,                 // Renew at 80% of TTL
            max_sessions_per_peer: 5,
            enable_auto_renewal: true,
        }
    }
}

/// Session manager
pub struct SessionManager {
    /// Configuration
    config: SessionConfig,
    /// Active sessions by ID
    sessions: HashMap<SessionId, Session>,
    /// Sessions by peer ID
    peer_sessions: HashMap<PeerId, Vec<SessionId>>,
    /// Total sessions created
    total_created: u64,
    /// Total sessions expired
    total_expired: u64,
    /// Total sessions renewed
    total_renewed: u64,
    /// Total sessions terminated
    total_terminated: u64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            peer_sessions: HashMap::new(),
            total_created: 0,
            total_expired: 0,
            total_renewed: 0,
            total_terminated: 0,
        }
    }

    /// Generate a unique session ID
    fn generate_session_id(&self) -> SessionId {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let random = rand::random::<u64>();
        format!("session-{:x}-{:x}", timestamp, random)
    }

    /// Create a new session for a peer
    pub fn create_session(
        &mut self,
        peer_id: PeerId,
        metadata: Vec<(String, String)>,
    ) -> SessionId {
        // Check peer session limit
        let peer_session_count = self
            .peer_sessions
            .get(&peer_id)
            .map(|v| v.len())
            .unwrap_or(0);

        if peer_session_count >= self.config.max_sessions_per_peer {
            // Remove oldest session
            if let Some(sessions) = self.peer_sessions.get_mut(&peer_id) {
                if let Some(oldest_id) = sessions.first().cloned() {
                    self.terminate_session(&oldest_id);
                }
            }
        }

        let session_id = self.generate_session_id();
        let now = Instant::now();
        let expires_at = now + self.config.session_ttl;

        let session = Session {
            id: session_id.clone(),
            peer_id: peer_id.clone(),
            created_at: now,
            last_renewed: now,
            expires_at,
            state: SessionState::Active,
            metadata: metadata.into_iter().collect(),
            renewal_count: 0,
            activity_count: 0,
        };

        self.sessions.insert(session_id.clone(), session);
        self.peer_sessions
            .entry(peer_id)
            .or_default()
            .push(session_id.clone());

        self.total_created += 1;
        session_id
    }

    /// Renew an existing session
    pub fn renew_session(&mut self, session_id: &SessionId) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.state != SessionState::Active && session.state != SessionState::Expiring {
                return false;
            }

            let now = Instant::now();
            session.last_renewed = now;
            session.expires_at = now + self.config.session_ttl;
            session.state = SessionState::Active;
            session.renewal_count += 1;

            self.total_renewed += 1;
            true
        } else {
            false
        }
    }

    /// Terminate a session
    pub fn terminate_session(&mut self, session_id: &SessionId) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.state = SessionState::Terminated;

            let peer_id = session.peer_id.clone();

            // Remove from peer sessions
            if let Some(sessions) = self.peer_sessions.get_mut(&peer_id) {
                sessions.retain(|id| id != session_id);
                // Remove peer entry if no more sessions
                if sessions.is_empty() {
                    self.peer_sessions.remove(&peer_id);
                }
            }

            self.total_terminated += 1;
            true
        } else {
            false
        }
    }

    /// Check if a session is valid
    pub fn is_valid(&self, session_id: &SessionId) -> bool {
        self.sessions
            .get(session_id)
            .map(|s| s.state == SessionState::Active || s.state == SessionState::Expiring)
            .unwrap_or(false)
    }

    /// Get a session
    pub fn get_session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    /// Get all sessions for a peer
    pub fn get_peer_sessions(&self, peer_id: &PeerId) -> Vec<&Session> {
        self.peer_sessions
            .get(peer_id)
            .map(|session_ids| {
                session_ids
                    .iter()
                    .filter_map(|id| self.sessions.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record activity on a session
    pub fn record_activity(&mut self, session_id: &SessionId) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.activity_count += 1;
        }
    }

    /// Update session metadata
    pub fn update_metadata(&mut self, session_id: &SessionId, key: String, value: String) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.metadata.insert(key, value);
            true
        } else {
            false
        }
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let expired_ids: Vec<SessionId> = self
            .sessions
            .iter_mut()
            .filter_map(|(id, session)| {
                if session.is_expired() {
                    session.state = SessionState::Expired;
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = expired_ids.len();

        for id in expired_ids {
            if let Some(session) = self.sessions.get(&id) {
                if let Some(sessions) = self.peer_sessions.get_mut(&session.peer_id) {
                    sessions.retain(|sid| sid != &id);
                }
            }
            self.sessions.remove(&id);
        }

        self.total_expired += count as u64;
        count
    }

    /// Update session states based on renewal threshold
    pub fn update_states(&mut self) {
        if !self.config.enable_auto_renewal {
            return;
        }

        for session in self.sessions.values_mut() {
            if session.state == SessionState::Active
                && session.needs_renewal(self.config.renewal_threshold)
            {
                session.state = SessionState::Expiring;
            }
        }
    }

    /// Get sessions that need renewal
    pub fn get_expiring_sessions(&self) -> Vec<&Session> {
        self.sessions
            .values()
            .filter(|s| s.state == SessionState::Expiring)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> SessionStats {
        let active_count = self
            .sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count();
        let expiring_count = self
            .sessions
            .values()
            .filter(|s| s.state == SessionState::Expiring)
            .count();

        SessionStats {
            total_sessions: self.sessions.len(),
            active_sessions: active_count,
            expiring_sessions: expiring_count,
            total_created: self.total_created,
            total_expired: self.total_expired,
            total_renewed: self.total_renewed,
            total_terminated: self.total_terminated,
            unique_peers: self.peer_sessions.len(),
        }
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Total sessions currently managed
    pub total_sessions: usize,
    /// Active sessions
    pub active_sessions: usize,
    /// Expiring sessions
    pub expiring_sessions: usize,
    /// Total sessions created
    pub total_created: u64,
    /// Total sessions expired
    pub total_expired: u64,
    /// Total sessions renewed
    pub total_renewed: u64,
    /// Total sessions terminated
    pub total_terminated: u64,
    /// Number of unique peers with sessions
    pub unique_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);
        assert!(manager.is_valid(&session_id));

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.peer_id, "peer1");
        assert_eq!(session.state, SessionState::Active);
        assert_eq!(session.renewal_count, 0);
    }

    #[test]
    fn test_session_with_metadata() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let metadata = vec![
            ("version".to_string(), "1.0".to_string()),
            ("client".to_string(), "test".to_string()),
        ];
        let session_id = manager.create_session("peer1".to_string(), metadata);

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.metadata.get("version"), Some(&"1.0".to_string()));
        assert_eq!(session.metadata.get("client"), Some(&"test".to_string()));
    }

    #[test]
    fn test_session_renewal() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        std::thread::sleep(Duration::from_millis(10));

        assert!(manager.renew_session(&session_id));

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.renewal_count, 1);
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_session_termination() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);
        assert!(manager.is_valid(&session_id));

        assert!(manager.terminate_session(&session_id));

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.state, SessionState::Terminated);
        assert!(!manager.is_valid(&session_id));
    }

    #[test]
    fn test_max_sessions_per_peer() {
        let config = SessionConfig {
            max_sessions_per_peer: 2,
            ..Default::default()
        };
        let mut manager = SessionManager::new(config);

        let session1 = manager.create_session("peer1".to_string(), vec![]);
        let session2 = manager.create_session("peer1".to_string(), vec![]);
        let session3 = manager.create_session("peer1".to_string(), vec![]);

        // session1 should be terminated
        assert!(!manager.is_valid(&session1));
        assert!(manager.is_valid(&session2));
        assert!(manager.is_valid(&session3));

        let peer_sessions = manager.get_peer_sessions(&"peer1".to_string());
        assert_eq!(peer_sessions.len(), 2);
    }

    #[test]
    fn test_session_expiry() {
        let config = SessionConfig {
            session_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        std::thread::sleep(Duration::from_millis(100));

        let session = manager.get_session(&session_id).unwrap();
        assert!(session.is_expired());

        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert!(manager.get_session(&session_id).is_none());
    }

    #[test]
    fn test_needs_renewal() {
        let config = SessionConfig {
            session_ttl: Duration::from_millis(100),
            renewal_threshold: 0.5,
            max_sessions_per_peer: 5,
            enable_auto_renewal: true,
        };
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        let session = manager.get_session(&session_id).unwrap();
        assert!(!session.needs_renewal(0.5));

        std::thread::sleep(Duration::from_millis(60));

        let session = manager.get_session(&session_id).unwrap();
        assert!(session.needs_renewal(0.5));
    }

    #[test]
    fn test_update_states() {
        let config = SessionConfig {
            session_ttl: Duration::from_millis(100),
            renewal_threshold: 0.5,
            max_sessions_per_peer: 5,
            enable_auto_renewal: true,
        };
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        std::thread::sleep(Duration::from_millis(60));

        manager.update_states();

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.state, SessionState::Expiring);
    }

    #[test]
    fn test_get_expiring_sessions() {
        let config = SessionConfig {
            session_ttl: Duration::from_millis(100),
            renewal_threshold: 0.5,
            max_sessions_per_peer: 5,
            enable_auto_renewal: true,
        };
        let mut manager = SessionManager::new(config);

        manager.create_session("peer1".to_string(), vec![]);
        manager.create_session("peer2".to_string(), vec![]);

        std::thread::sleep(Duration::from_millis(60));

        manager.update_states();

        let expiring = manager.get_expiring_sessions();
        assert_eq!(expiring.len(), 2);
    }

    #[test]
    fn test_record_activity() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        manager.record_activity(&session_id);
        manager.record_activity(&session_id);

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.activity_count, 2);
    }

    #[test]
    fn test_update_metadata() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        assert!(manager.update_metadata(&session_id, "key1".to_string(), "value1".to_string()));

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.metadata.get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_session_stats() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session1 = manager.create_session("peer1".to_string(), vec![]);
        manager.create_session("peer2".to_string(), vec![]);
        manager.create_session("peer3".to_string(), vec![]);

        manager.terminate_session(&session1);

        let stats = manager.stats();
        assert_eq!(stats.total_sessions, 3);
        assert_eq!(stats.active_sessions, 2);
        assert_eq!(stats.total_created, 3);
        assert_eq!(stats.total_terminated, 1);
        assert_eq!(stats.unique_peers, 2); // peer1's session was terminated
    }

    #[test]
    fn test_session_age() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        std::thread::sleep(Duration::from_millis(50));

        let session = manager.get_session(&session_id).unwrap();
        assert!(session.age() >= Duration::from_millis(50));
    }

    #[test]
    fn test_session_remaining_time() {
        let config = SessionConfig {
            session_ttl: Duration::from_secs(1),
            ..Default::default()
        };
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);

        let session = manager.get_session(&session_id).unwrap();
        let remaining = session.remaining_time();
        assert!(remaining <= Duration::from_secs(1));
        assert!(remaining > Duration::from_millis(900));
    }

    #[test]
    fn test_get_peer_sessions() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        manager.create_session("peer1".to_string(), vec![]);
        manager.create_session("peer1".to_string(), vec![]);
        manager.create_session("peer2".to_string(), vec![]);

        let peer1_sessions = manager.get_peer_sessions(&"peer1".to_string());
        assert_eq!(peer1_sessions.len(), 2);

        let peer2_sessions = manager.get_peer_sessions(&"peer2".to_string());
        assert_eq!(peer2_sessions.len(), 1);
    }

    #[test]
    fn test_invalid_session_operations() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        assert!(!manager.renew_session(&"invalid-id".to_string()));
        assert!(!manager.terminate_session(&"invalid-id".to_string()));
        assert!(!manager.is_valid(&"invalid-id".to_string()));
        assert!(manager.get_session(&"invalid-id".to_string()).is_none());
    }

    #[test]
    fn test_renew_terminated_session() {
        let config = SessionConfig::default();
        let mut manager = SessionManager::new(config);

        let session_id = manager.create_session("peer1".to_string(), vec![]);
        manager.terminate_session(&session_id);

        assert!(!manager.renew_session(&session_id));
    }
}
