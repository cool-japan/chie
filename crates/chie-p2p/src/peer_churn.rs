//! Peer churn detection and management module.
//!
//! This module provides mechanisms to detect, track, and respond to peer churn
//! (peers joining and leaving the network) to maintain network stability.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Represents the churn level of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChurnLevel {
    /// Very low churn (< 5% peers changing per minute)
    VeryLow,
    /// Low churn (5-15% peers changing per minute)
    Low,
    /// Moderate churn (15-30% peers changing per minute)
    Moderate,
    /// High churn (30-50% peers changing per minute)
    High,
    /// Very high churn (> 50% peers changing per minute)
    VeryHigh,
}

/// Peer lifecycle event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    /// Peer joined the network
    Joined,
    /// Peer left the network gracefully
    LeftGraceful,
    /// Peer disconnected abruptly
    LeftAbrupt,
}

/// Information about a peer's stability.
#[derive(Debug, Clone)]
pub struct PeerStability {
    /// Peer identifier
    pub peer_id: String,
    /// Total time peer has been online
    pub total_online_duration: Duration,
    /// Number of times peer has joined
    pub join_count: u32,
    /// Number of times peer has left
    pub leave_count: u32,
    /// Number of abrupt disconnections
    pub abrupt_disconnect_count: u32,
    /// Current session start time (if online)
    pub current_session_start: Option<Instant>,
    /// Average session duration
    pub avg_session_duration: Duration,
    /// Stability score (0.0 = very unstable, 1.0 = very stable)
    pub stability_score: f64,
}

/// Churn detection configuration.
#[derive(Debug, Clone)]
pub struct ChurnConfig {
    /// Time window for calculating churn rate
    pub churn_window: Duration,
    /// Maximum number of events to track
    pub max_tracked_events: usize,
    /// Minimum session duration to be considered stable
    pub min_stable_session: Duration,
    /// Time window for peer history retention
    pub history_retention: Duration,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            churn_window: Duration::from_secs(60),
            max_tracked_events: 1000,
            min_stable_session: Duration::from_secs(300), // 5 minutes
            history_retention: Duration::from_secs(3600 * 24), // 24 hours
        }
    }
}

/// Event record for churn tracking.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ChurnEvent {
    timestamp: Instant,
    peer_id: String,
    event_type: PeerEvent,
}

/// Session information for a peer.
#[derive(Debug, Clone)]
struct PeerSession {
    start_time: Instant,
    join_count: u32,
    leave_count: u32,
    abrupt_count: u32,
    session_durations: Vec<Duration>,
}

/// Manages peer churn detection and analysis.
pub struct ChurnHandler {
    config: ChurnConfig,
    events: VecDeque<ChurnEvent>,
    peer_sessions: HashMap<String, PeerSession>,
    current_peer_count: usize,
}

impl ChurnHandler {
    /// Creates a new churn handler with default configuration.
    pub fn new() -> Self {
        Self::with_config(ChurnConfig::default())
    }

    /// Creates a new churn handler with custom configuration.
    pub fn with_config(config: ChurnConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            peer_sessions: HashMap::new(),
            current_peer_count: 0,
        }
    }

    /// Records a peer event (join, leave, etc.).
    pub fn record_event(&mut self, peer_id: String, event_type: PeerEvent) {
        let event = ChurnEvent {
            timestamp: Instant::now(),
            peer_id: peer_id.clone(),
            event_type,
        };

        // Add event to history
        self.events.push_back(event);

        // Limit event history size
        while self.events.len() > self.config.max_tracked_events {
            self.events.pop_front();
        }

        // Update peer session tracking
        match event_type {
            PeerEvent::Joined => {
                self.current_peer_count += 1;
                let session = self
                    .peer_sessions
                    .entry(peer_id)
                    .or_insert_with(|| PeerSession {
                        start_time: Instant::now(),
                        join_count: 0,
                        leave_count: 0,
                        abrupt_count: 0,
                        session_durations: Vec::new(),
                    });
                session.start_time = Instant::now();
                session.join_count += 1;
            }
            PeerEvent::LeftGraceful | PeerEvent::LeftAbrupt => {
                if self.current_peer_count > 0 {
                    self.current_peer_count -= 1;
                }

                if let Some(session) = self.peer_sessions.get_mut(&peer_id) {
                    let duration = session.start_time.elapsed();
                    session.session_durations.push(duration);
                    session.leave_count += 1;

                    if event_type == PeerEvent::LeftAbrupt {
                        session.abrupt_count += 1;
                    }

                    // Limit session history
                    if session.session_durations.len() > 100 {
                        session.session_durations.remove(0);
                    }
                }
            }
        }

        self.cleanup_old_data();
    }

    /// Calculates the current churn level.
    pub fn churn_level(&self) -> ChurnLevel {
        let rate = self.churn_rate();

        if rate < 0.05 {
            ChurnLevel::VeryLow
        } else if rate < 0.15 {
            ChurnLevel::Low
        } else if rate < 0.30 {
            ChurnLevel::Moderate
        } else if rate < 0.50 {
            ChurnLevel::High
        } else {
            ChurnLevel::VeryHigh
        }
    }

    /// Calculates the churn rate (percentage of peers changing per minute).
    pub fn churn_rate(&self) -> f64 {
        if self.current_peer_count == 0 {
            return 0.0;
        }

        let cutoff = Instant::now() - self.config.churn_window;
        let recent_events = self.events.iter().filter(|e| e.timestamp >= cutoff).count();

        // Calculate rate as (events / peers) normalized to per-minute
        let window_minutes = self.config.churn_window.as_secs_f64() / 60.0;
        (recent_events as f64 / self.current_peer_count as f64) / window_minutes
    }

    /// Gets stability information for a specific peer.
    pub fn peer_stability(&self, peer_id: &str) -> Option<PeerStability> {
        let session = self.peer_sessions.get(peer_id)?;

        let total_duration: Duration = session.session_durations.iter().sum();
        let avg_duration = if session.session_durations.is_empty() {
            Duration::from_secs(0)
        } else {
            total_duration / session.session_durations.len() as u32
        };

        // Calculate stability score
        let stability_score = self.calculate_stability_score(session);

        Some(PeerStability {
            peer_id: peer_id.to_string(),
            total_online_duration: total_duration,
            join_count: session.join_count,
            leave_count: session.leave_count,
            abrupt_disconnect_count: session.abrupt_count,
            current_session_start: if self.is_peer_online(peer_id) {
                Some(session.start_time)
            } else {
                None
            },
            avg_session_duration: avg_duration,
            stability_score,
        })
    }

    /// Calculates a stability score for a peer session.
    fn calculate_stability_score(&self, session: &PeerSession) -> f64 {
        if session.join_count == 0 {
            return 0.0;
        }

        // Factors that contribute to stability:
        // 1. Long average session duration
        // 2. Low number of disconnections relative to joins
        // 3. Low number of abrupt disconnections

        let avg_duration = if session.session_durations.is_empty() {
            Duration::from_secs(0)
        } else {
            session.session_durations.iter().sum::<Duration>()
                / session.session_durations.len() as u32
        };

        // Duration score: longer is better (capped at min_stable_session)
        let duration_score =
            (avg_duration.as_secs_f64() / self.config.min_stable_session.as_secs_f64()).min(1.0);

        // Disconnect ratio: fewer disconnects is better
        let disconnect_ratio = session.leave_count as f64 / session.join_count as f64;
        let disconnect_score = (1.0 - disconnect_ratio).max(0.0);

        // Abrupt disconnect penalty
        let abrupt_ratio = if session.leave_count == 0 {
            0.0
        } else {
            session.abrupt_count as f64 / session.leave_count as f64
        };
        let graceful_score = 1.0 - abrupt_ratio;

        // Weighted combination
        (duration_score * 0.5 + disconnect_score * 0.3 + graceful_score * 0.2).min(1.0)
    }

    /// Checks if a peer is currently online.
    fn is_peer_online(&self, peer_id: &str) -> bool {
        if let Some(session) = self.peer_sessions.get(peer_id) {
            // Peer is online if join_count > leave_count
            session.join_count > session.leave_count
        } else {
            false
        }
    }

    /// Gets the list of most stable peers (top N by stability score).
    pub fn most_stable_peers(&self, count: usize) -> Vec<PeerStability> {
        let mut stabilities: Vec<PeerStability> = self
            .peer_sessions
            .keys()
            .filter_map(|peer_id| self.peer_stability(peer_id))
            .collect();

        stabilities.sort_by(|a, b| {
            b.stability_score
                .partial_cmp(&a.stability_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        stabilities.into_iter().take(count).collect()
    }

    /// Gets churn statistics.
    pub fn stats(&self) -> ChurnStats {
        ChurnStats {
            current_peer_count: self.current_peer_count,
            total_tracked_peers: self.peer_sessions.len(),
            churn_level: self.churn_level(),
            churn_rate: self.churn_rate(),
            total_events: self.events.len(),
            recent_joins: self.count_recent_events(PeerEvent::Joined),
            recent_graceful_leaves: self.count_recent_events(PeerEvent::LeftGraceful),
            recent_abrupt_leaves: self.count_recent_events(PeerEvent::LeftAbrupt),
        }
    }

    /// Counts recent events of a specific type within the churn window.
    fn count_recent_events(&self, event_type: PeerEvent) -> usize {
        let cutoff = Instant::now() - self.config.churn_window;
        self.events
            .iter()
            .filter(|e| e.timestamp >= cutoff && e.event_type == event_type)
            .count()
    }

    /// Predicts the departure probability for a peer (0.0 = unlikely, 1.0 = very likely).
    pub fn predict_departure_probability(&self, peer_id: &str) -> f64 {
        match self.peer_stability(peer_id) {
            Some(stability) => {
                // Inverse of stability score
                let base_probability = 1.0 - stability.stability_score;

                // Adjust based on current session duration
                if let Some(session_start) = stability.current_session_start {
                    let current_duration = session_start.elapsed();
                    let avg_duration = stability.avg_session_duration;

                    if avg_duration.as_secs() > 0 {
                        let duration_ratio =
                            current_duration.as_secs_f64() / avg_duration.as_secs_f64();

                        // If current session is already longer than average,
                        // departure becomes more likely
                        if duration_ratio > 1.0 {
                            return (base_probability + (duration_ratio - 1.0) * 0.3).min(1.0);
                        }
                    }
                }

                base_probability
            }
            None => 0.5, // Unknown peer, assume 50% probability
        }
    }

    /// Recommends replication factor based on churn level.
    pub fn recommended_replication_factor(&self) -> u32 {
        match self.churn_level() {
            ChurnLevel::VeryLow => 2,
            ChurnLevel::Low => 3,
            ChurnLevel::Moderate => 4,
            ChurnLevel::High => 5,
            ChurnLevel::VeryHigh => 6,
        }
    }

    /// Removes old events and peer data beyond retention period.
    fn cleanup_old_data(&mut self) {
        let cutoff = Instant::now() - self.config.history_retention;

        // Remove old events
        while let Some(event) = self.events.front() {
            if event.timestamp >= cutoff {
                break;
            }
            self.events.pop_front();
        }

        // Remove inactive peers (no recent activity)
        self.peer_sessions.retain(|_, session| {
            if session.session_durations.is_empty() {
                // No completed sessions, check if currently active
                session.start_time.elapsed() < self.config.history_retention
            } else {
                // Has completed sessions, keep if recent
                true
            }
        });
    }

    /// Gets the current peer count.
    pub fn current_peer_count(&self) -> usize {
        self.current_peer_count
    }
}

impl Default for ChurnHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about peer churn.
#[derive(Debug, Clone)]
pub struct ChurnStats {
    /// Current number of connected peers
    pub current_peer_count: usize,
    /// Total number of peers tracked in history
    pub total_tracked_peers: usize,
    /// Current churn level
    pub churn_level: ChurnLevel,
    /// Current churn rate (peers changing per minute)
    pub churn_rate: f64,
    /// Total number of events tracked
    pub total_events: usize,
    /// Number of recent joins
    pub recent_joins: usize,
    /// Number of recent graceful leaves
    pub recent_graceful_leaves: usize,
    /// Number of recent abrupt leaves
    pub recent_abrupt_leaves: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_churn_handler_new() {
        let handler = ChurnHandler::new();
        assert_eq!(handler.current_peer_count(), 0);
        assert_eq!(handler.churn_rate(), 0.0);
        assert_eq!(handler.churn_level(), ChurnLevel::VeryLow);
    }

    #[test]
    fn test_record_join_event() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        assert_eq!(handler.current_peer_count(), 1);

        let stats = handler.stats();
        assert_eq!(stats.current_peer_count, 1);
    }

    #[test]
    fn test_record_leave_event() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);
        assert_eq!(handler.current_peer_count(), 0);
    }

    #[test]
    fn test_peer_stability() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        std::thread::sleep(Duration::from_millis(50));
        handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);

        let stability = handler.peer_stability("peer1");
        assert!(stability.is_some());

        let stab = stability.unwrap();
        assert_eq!(stab.join_count, 1);
        assert_eq!(stab.leave_count, 1);
        assert_eq!(stab.abrupt_disconnect_count, 0);
    }

    #[test]
    fn test_abrupt_disconnect_tracking() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        handler.record_event("peer1".to_string(), PeerEvent::LeftAbrupt);

        let stability = handler.peer_stability("peer1").unwrap();
        assert_eq!(stability.abrupt_disconnect_count, 1);
        assert_eq!(stability.leave_count, 1);
    }

    #[test]
    fn test_churn_level_classification() {
        let config = ChurnConfig {
            churn_window: Duration::from_secs(1),
            ..Default::default()
        };
        let mut handler = ChurnHandler::with_config(config);

        // Add initial peers
        for i in 0..10 {
            handler.record_event(format!("peer{}", i), PeerEvent::Joined);
        }

        // Low churn: 1 event among 10 peers per second = ~6 per minute = 60% rate
        handler.record_event("peer10".to_string(), PeerEvent::Joined);

        let level = handler.churn_level();
        assert!(matches!(level, ChurnLevel::VeryHigh | ChurnLevel::High));
    }

    #[test]
    fn test_most_stable_peers() {
        let mut handler = ChurnHandler::new();

        // Create peers with different stability
        handler.record_event("stable_peer".to_string(), PeerEvent::Joined);
        std::thread::sleep(Duration::from_millis(100));
        handler.record_event("stable_peer".to_string(), PeerEvent::LeftGraceful);

        handler.record_event("unstable_peer".to_string(), PeerEvent::Joined);
        std::thread::sleep(Duration::from_millis(10));
        handler.record_event("unstable_peer".to_string(), PeerEvent::LeftAbrupt);

        let stable_peers = handler.most_stable_peers(1);
        assert_eq!(stable_peers.len(), 1);
        assert_eq!(stable_peers[0].peer_id, "stable_peer");
    }

    #[test]
    fn test_departure_probability() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);

        let probability = handler.predict_departure_probability("peer1");
        assert!((0.0..=1.0).contains(&probability));
    }

    #[test]
    fn test_unknown_peer_departure_probability() {
        let handler = ChurnHandler::new();
        let probability = handler.predict_departure_probability("unknown");
        assert_eq!(probability, 0.5);
    }

    #[test]
    fn test_replication_factor_recommendation() {
        let config = ChurnConfig {
            churn_window: Duration::from_secs(60),
            ..Default::default()
        };
        let handler = ChurnHandler::with_config(config);

        // Very low churn should recommend lower replication
        let factor = handler.recommended_replication_factor();
        assert_eq!(factor, 2);
    }

    #[test]
    fn test_churn_stats() {
        let mut handler = ChurnHandler::new();
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        handler.record_event("peer2".to_string(), PeerEvent::Joined);
        handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);

        let stats = handler.stats();
        assert_eq!(stats.current_peer_count, 1);
        assert_eq!(stats.total_tracked_peers, 2);
    }

    #[test]
    fn test_multiple_sessions() {
        let mut handler = ChurnHandler::new();

        // Peer joins and leaves multiple times
        for _ in 0..3 {
            handler.record_event("peer1".to_string(), PeerEvent::Joined);
            std::thread::sleep(Duration::from_millis(10));
            handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);
        }

        let stability = handler.peer_stability("peer1").unwrap();
        assert_eq!(stability.join_count, 3);
        assert_eq!(stability.leave_count, 3);
    }

    #[test]
    fn test_stability_score_calculation() {
        let mut handler = ChurnHandler::new();

        // Long stable session
        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        std::thread::sleep(Duration::from_millis(100));
        handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);

        let stability = handler.peer_stability("peer1").unwrap();
        assert!(stability.stability_score > 0.0);
        assert!(stability.stability_score <= 1.0);
    }

    #[test]
    fn test_event_limit() {
        let config = ChurnConfig {
            max_tracked_events: 10,
            ..Default::default()
        };
        let mut handler = ChurnHandler::with_config(config);

        // Add more events than the limit
        for i in 0..20 {
            handler.record_event(format!("peer{}", i), PeerEvent::Joined);
        }

        let stats = handler.stats();
        assert_eq!(stats.total_events, 10);
    }

    #[test]
    fn test_churn_rate_calculation() {
        let config = ChurnConfig {
            churn_window: Duration::from_secs(60),
            ..Default::default()
        };
        let mut handler = ChurnHandler::with_config(config);

        // Add 10 peers
        for i in 0..10 {
            handler.record_event(format!("peer{}", i), PeerEvent::Joined);
        }

        let rate = handler.churn_rate();
        assert!(rate >= 0.0);
    }

    #[test]
    fn test_graceful_vs_abrupt_tracking() {
        let mut handler = ChurnHandler::new();

        handler.record_event("peer1".to_string(), PeerEvent::Joined);
        handler.record_event("peer1".to_string(), PeerEvent::LeftGraceful);

        handler.record_event("peer2".to_string(), PeerEvent::Joined);
        handler.record_event("peer2".to_string(), PeerEvent::LeftAbrupt);

        let stats = handler.stats();
        assert!(stats.recent_graceful_leaves > 0 || stats.recent_abrupt_leaves > 0);
    }
}
