//! Peer connection scheduling for optimized network resource usage.
//!
//! This module provides intelligent scheduling of peer connections to
//! optimize network resource usage, reduce connection churn, and improve
//! overall system performance.

use libp2p::PeerId;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Connection priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConnectionPriority {
    Critical = 5,
    High = 4,
    Normal = 3,
    Low = 2,
    Background = 1,
}

/// Connection schedule entry
#[derive(Debug, Clone)]
pub struct ScheduledConnection {
    pub peer_id: PeerId,
    pub priority: ConnectionPriority,
    pub scheduled_time: Instant,
    pub reason: String,
    pub retry_count: u32,
}

impl PartialEq for ScheduledConnection {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for ScheduledConnection {}

impl PartialOrd for ScheduledConnection {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledConnection {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first, then earlier scheduled time
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => other.scheduled_time.cmp(&self.scheduled_time),
            ord => ord,
        }
    }
}

/// Scheduling strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingStrategy {
    /// Priority-based (highest priority first)
    Priority,
    /// Time-based (earliest scheduled first)
    TimeOrdered,
    /// Round-robin across priorities
    RoundRobin,
    /// Adaptive (considers network conditions)
    Adaptive,
}

/// Connection scheduler configuration
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Scheduling strategy
    pub strategy: SchedulingStrategy,
    /// Maximum concurrent connections
    pub max_concurrent: usize,
    /// Maximum scheduled connections
    pub max_scheduled: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Retry delay multiplier
    pub retry_multiplier: f64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Batch size for batch connections
    pub batch_size: usize,
    /// Minimum interval between connections to same peer
    pub min_reconnect_interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            strategy: SchedulingStrategy::Adaptive,
            max_concurrent: 50,
            max_scheduled: 500,
            connection_timeout: Duration::from_secs(30),
            retry_multiplier: 2.0,
            max_retries: 3,
            batch_size: 10,
            min_reconnect_interval: Duration::from_secs(60),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    #[allow(dead_code)]
    Scheduled,
    Connecting,
    Connected,
    Failed,
}

/// Connection info
#[derive(Debug, Clone)]
struct ConnectionInfo {
    state: ConnectionState,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    retry_count: u32,
}

/// Connection scheduler
pub struct ConnectionScheduler {
    config: SchedulerConfig,
    scheduled_queue: Arc<RwLock<BinaryHeap<ScheduledConnection>>>,
    active_connections: Arc<RwLock<HashMap<PeerId, ConnectionInfo>>>,
    round_robin_index: Arc<RwLock<usize>>,
}

impl ConnectionScheduler {
    /// Create a new connection scheduler
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            scheduled_queue: Arc::new(RwLock::new(BinaryHeap::new())),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    /// Schedule a connection
    pub fn schedule(
        &self,
        peer_id: PeerId,
        priority: ConnectionPriority,
        delay: Duration,
        reason: String,
    ) -> bool {
        let mut queue = self.scheduled_queue.write().unwrap();

        // Check if already scheduled or connected
        if queue.iter().any(|s| s.peer_id == peer_id) {
            return false;
        }

        let connections = self.active_connections.read().unwrap();
        if let Some(info) = connections.get(&peer_id) {
            if info.state == ConnectionState::Connected {
                return false;
            }

            // Check reconnect interval
            if let Some(last_attempt) = info.last_attempt {
                if last_attempt.elapsed() < self.config.min_reconnect_interval {
                    return false;
                }
            }
        }
        drop(connections);

        // Check queue size limit
        if queue.len() >= self.config.max_scheduled {
            // Remove lowest priority item if current is higher priority
            if let Some(lowest) = queue.peek() {
                if priority > lowest.priority {
                    queue.pop();
                } else {
                    return false;
                }
            }
        }

        let scheduled = ScheduledConnection {
            peer_id,
            priority,
            scheduled_time: Instant::now() + delay,
            reason,
            retry_count: 0,
        };

        queue.push(scheduled);
        true
    }

    /// Get next connection to process
    pub fn get_next(&self) -> Option<ScheduledConnection> {
        let active_count = self
            .active_connections
            .read()
            .unwrap()
            .values()
            .filter(|info| {
                info.state == ConnectionState::Connecting
                    || info.state == ConnectionState::Connected
            })
            .count();

        if active_count >= self.config.max_concurrent {
            return None;
        }

        match self.config.strategy {
            SchedulingStrategy::Priority => self.get_next_priority(),
            SchedulingStrategy::TimeOrdered => self.get_next_time_ordered(),
            SchedulingStrategy::RoundRobin => self.get_next_round_robin(),
            SchedulingStrategy::Adaptive => self.get_next_adaptive(),
        }
    }

    /// Get next by priority
    fn get_next_priority(&self) -> Option<ScheduledConnection> {
        let mut queue = self.scheduled_queue.write().unwrap();
        if let Some(conn) = queue.pop() {
            if conn.scheduled_time <= Instant::now() {
                self.mark_connecting(conn.peer_id);
                return Some(conn);
            } else {
                queue.push(conn);
            }
        }
        None
    }

    /// Get next by time
    fn get_next_time_ordered(&self) -> Option<ScheduledConnection> {
        let mut queue = self.scheduled_queue.write().unwrap();
        let now = Instant::now();

        // Find earliest scheduled connection that's due
        let mut earliest: Option<ScheduledConnection> = None;
        let mut remaining = Vec::new();

        while let Some(conn) = queue.pop() {
            if conn.scheduled_time <= now {
                if earliest.is_none()
                    || conn.scheduled_time < earliest.as_ref().unwrap().scheduled_time
                {
                    if let Some(prev) = earliest.take() {
                        remaining.push(prev);
                    }
                    earliest = Some(conn);
                } else {
                    remaining.push(conn);
                }
            } else {
                remaining.push(conn);
            }
        }

        // Put remaining back
        for conn in remaining {
            queue.push(conn);
        }

        if let Some(ref conn) = earliest {
            self.mark_connecting(conn.peer_id);
        }

        earliest
    }

    /// Get next using round-robin
    fn get_next_round_robin(&self) -> Option<ScheduledConnection> {
        let mut queue = self.scheduled_queue.write().unwrap();
        let now = Instant::now();

        // Group by priority
        let priorities = [
            ConnectionPriority::Critical,
            ConnectionPriority::High,
            ConnectionPriority::Normal,
            ConnectionPriority::Low,
            ConnectionPriority::Background,
        ];

        let mut index = self.round_robin_index.write().unwrap();
        let start_index = *index;

        // Try each priority in round-robin fashion
        loop {
            let priority = priorities[*index % priorities.len()];
            *index = (*index + 1) % priorities.len();

            // Find a connection with this priority that's due
            let mut found = None;
            let mut remaining = Vec::new();

            while let Some(conn) = queue.pop() {
                if conn.priority == priority && conn.scheduled_time <= now {
                    found = Some(conn);
                    break;
                } else {
                    remaining.push(conn);
                }
            }

            // Put remaining back
            for conn in remaining {
                queue.push(conn);
            }

            if let Some(conn) = found {
                self.mark_connecting(conn.peer_id);
                return Some(conn);
            }

            if *index % priorities.len() == start_index {
                break; // Completed full round
            }
        }

        None
    }

    /// Get next using adaptive strategy
    fn get_next_adaptive(&self) -> Option<ScheduledConnection> {
        let active_count = self
            .active_connections
            .read()
            .unwrap()
            .values()
            .filter(|info| {
                info.state == ConnectionState::Connecting
                    || info.state == ConnectionState::Connected
            })
            .count();

        let utilization = active_count as f64 / self.config.max_concurrent as f64;

        // Under low load, use time-ordered for fairness
        // Under high load, use priority for important connections
        if utilization < 0.5 {
            self.get_next_time_ordered()
        } else {
            self.get_next_priority()
        }
    }

    /// Mark peer as connecting
    fn mark_connecting(&self, peer_id: PeerId) {
        self.active_connections.write().unwrap().insert(
            peer_id,
            ConnectionInfo {
                state: ConnectionState::Connecting,
                last_attempt: Some(Instant::now()),
                last_success: None,
                retry_count: 0,
            },
        );
    }

    /// Mark connection as successful
    pub fn mark_success(&self, peer_id: &PeerId) {
        if let Some(info) = self.active_connections.write().unwrap().get_mut(peer_id) {
            info.state = ConnectionState::Connected;
            info.last_success = Some(Instant::now());
            info.retry_count = 0;
        }
    }

    /// Mark connection as failed
    pub fn mark_failed(&self, peer_id: &PeerId) -> bool {
        let retry_info = {
            let mut connections = self.active_connections.write().unwrap();
            if let Some(info) = connections.get_mut(peer_id) {
                info.state = ConnectionState::Failed;
                info.retry_count += 1;

                // Check if should retry
                if info.retry_count < self.config.max_retries {
                    let delay = Duration::from_secs_f64(
                        self.config.connection_timeout.as_secs_f64()
                            * self.config.retry_multiplier.powi(info.retry_count as i32),
                    );
                    Some((info.retry_count, delay))
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Schedule retry outside the lock
        if let Some((retry_count, delay)) = retry_info {
            return self.schedule(
                *peer_id,
                ConnectionPriority::Low,
                delay,
                format!("Retry #{}", retry_count),
            );
        }
        false
    }

    /// Disconnect peer
    pub fn disconnect(&self, peer_id: &PeerId) {
        self.active_connections.write().unwrap().remove(peer_id);
    }

    /// Cancel scheduled connection
    pub fn cancel(&self, peer_id: &PeerId) -> bool {
        let mut queue = self.scheduled_queue.write().unwrap();
        let original_len = queue.len();

        let remaining: Vec<_> = queue.drain().filter(|s| s.peer_id != *peer_id).collect();

        queue.clear();
        for conn in remaining {
            queue.push(conn);
        }

        queue.len() < original_len
    }

    /// Get scheduled count
    pub fn scheduled_count(&self) -> usize {
        self.scheduled_queue.read().unwrap().len()
    }

    /// Get active connection count
    pub fn active_count(&self) -> usize {
        self.active_connections
            .read()
            .unwrap()
            .values()
            .filter(|info| info.state == ConnectionState::Connected)
            .count()
    }

    /// Get connecting count
    pub fn connecting_count(&self) -> usize {
        self.active_connections
            .read()
            .unwrap()
            .values()
            .filter(|info| info.state == ConnectionState::Connecting)
            .count()
    }

    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        let connections = self.active_connections.read().unwrap();
        let connected = connections
            .values()
            .filter(|info| info.state == ConnectionState::Connected)
            .count();
        let connecting = connections
            .values()
            .filter(|info| info.state == ConnectionState::Connecting)
            .count();
        let failed = connections
            .values()
            .filter(|info| info.state == ConnectionState::Failed)
            .count();

        SchedulerStats {
            scheduled: self.scheduled_count(),
            connected,
            connecting,
            failed,
            total_tracked: connections.len(),
        }
    }

    /// Cleanup old failed connections
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour

        self.active_connections.write().unwrap().retain(|_, info| {
            if info.state == ConnectionState::Failed {
                if let Some(last_attempt) = info.last_attempt {
                    return last_attempt > cutoff;
                }
            }
            true
        });
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub scheduled: usize,
    pub connected: usize,
    pub connecting: usize,
    pub failed: usize,
    pub total_tracked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_scheduler_new() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_schedule_connection() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        let result = scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );

        assert!(result);
        assert_eq!(scheduler.scheduled_count(), 1);
    }

    #[test]
    fn test_schedule_duplicate() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        let result = scheduler.schedule(
            peer,
            ConnectionPriority::High,
            Duration::from_secs(0),
            "Test 2".to_string(),
        );

        assert!(!result); // Should not schedule duplicate
        assert_eq!(scheduler.scheduled_count(), 1);
    }

    #[test]
    fn test_get_next_priority() {
        let config = SchedulerConfig {
            strategy: SchedulingStrategy::Priority,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        scheduler.schedule(
            peer1,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "Low".to_string(),
        );
        scheduler.schedule(
            peer2,
            ConnectionPriority::High,
            Duration::from_secs(0),
            "High".to_string(),
        );

        let next = scheduler.get_next().unwrap();
        assert_eq!(next.peer_id, peer2); // High priority should come first
        assert_eq!(next.priority, ConnectionPriority::High);
    }

    #[test]
    fn test_get_next_time_ordered() {
        let config = SchedulerConfig {
            strategy: SchedulingStrategy::TimeOrdered,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        scheduler.schedule(
            peer1,
            ConnectionPriority::Normal,
            Duration::from_millis(100),
            "Later".to_string(),
        );
        scheduler.schedule(
            peer2,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Now".to_string(),
        );

        let next = scheduler.get_next().unwrap();
        assert_eq!(next.peer_id, peer2); // Earlier scheduled time
    }

    #[test]
    fn test_mark_success() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        scheduler.get_next();

        scheduler.mark_success(&peer);
        assert_eq!(scheduler.active_count(), 1);
    }

    #[test]
    fn test_mark_failed_retry() {
        let config = SchedulerConfig {
            min_reconnect_interval: Duration::from_secs(0), // Allow immediate retry
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        scheduler.get_next();

        let should_retry = scheduler.mark_failed(&peer);
        assert!(should_retry); // Should schedule retry
    }

    #[test]
    fn test_max_retries() {
        let config = SchedulerConfig {
            max_retries: 2,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);
        let peer = create_test_peer();

        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        scheduler.get_next();

        scheduler.mark_failed(&peer);
        scheduler.mark_failed(&peer);
        let should_retry = scheduler.mark_failed(&peer);

        assert!(!should_retry); // Exceeded max retries
    }

    #[test]
    fn test_disconnect() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        scheduler.get_next();
        scheduler.mark_success(&peer);

        assert_eq!(scheduler.active_count(), 1);

        scheduler.disconnect(&peer);
        assert_eq!(scheduler.active_count(), 0);
    }

    #[test]
    fn test_cancel_scheduled() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(10),
            "Test".to_string(),
        );

        assert_eq!(scheduler.scheduled_count(), 1);

        let cancelled = scheduler.cancel(&peer);
        assert!(cancelled);
        assert_eq!(scheduler.scheduled_count(), 0);
    }

    #[test]
    fn test_max_concurrent() {
        let config = SchedulerConfig {
            max_concurrent: 2,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        scheduler.schedule(
            peer1,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "1".to_string(),
        );
        scheduler.schedule(
            peer2,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "2".to_string(),
        );
        scheduler.schedule(
            peer3,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "3".to_string(),
        );

        scheduler.get_next();
        scheduler.get_next();

        // Should not return third as max_concurrent is 2
        let next = scheduler.get_next();
        assert!(next.is_none());
    }

    #[test]
    fn test_max_scheduled() {
        let config = SchedulerConfig {
            max_scheduled: 2,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        assert!(scheduler.schedule(
            peer1,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "1".to_string()
        ));
        assert!(scheduler.schedule(
            peer2,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "2".to_string()
        ));

        // Should not schedule as queue is full and priority is same
        assert!(!scheduler.schedule(
            peer3,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "3".to_string()
        ));
    }

    #[test]
    fn test_max_scheduled_higher_priority() {
        let config = SchedulerConfig {
            max_scheduled: 2,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        scheduler.schedule(
            peer1,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "1".to_string(),
        );
        scheduler.schedule(
            peer2,
            ConnectionPriority::Low,
            Duration::from_secs(0),
            "2".to_string(),
        );

        // Should evict lowest priority and schedule high priority
        assert!(scheduler.schedule(
            peer3,
            ConnectionPriority::Critical,
            Duration::from_secs(0),
            "3".to_string()
        ));
        assert_eq!(scheduler.scheduled_count(), 2);
    }

    #[test]
    fn test_cleanup() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );
        scheduler.get_next();
        scheduler.mark_failed(&peer);

        scheduler.cleanup();
        // Recent failure should still be tracked
        assert!(scheduler.get_stats().total_tracked > 0);
    }

    #[test]
    fn test_stats() {
        let config = SchedulerConfig::default();
        let scheduler = ConnectionScheduler::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        scheduler.schedule(
            peer1,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "1".to_string(),
        );
        scheduler.schedule(
            peer2,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "2".to_string(),
        );

        scheduler.get_next();
        scheduler.mark_success(&peer1);

        let stats = scheduler.get_stats();
        assert_eq!(stats.scheduled, 1);
        assert_eq!(stats.connected, 1);
    }

    #[test]
    fn test_connection_priority_ordering() {
        assert!(ConnectionPriority::Critical > ConnectionPriority::High);
        assert!(ConnectionPriority::High > ConnectionPriority::Normal);
        assert!(ConnectionPriority::Normal > ConnectionPriority::Low);
        assert!(ConnectionPriority::Low > ConnectionPriority::Background);
    }

    #[test]
    fn test_scheduled_connection_ordering() {
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        let conn1 = ScheduledConnection {
            peer_id: peer1,
            priority: ConnectionPriority::High,
            scheduled_time: Instant::now(),
            reason: "High".to_string(),
            retry_count: 0,
        };

        let conn2 = ScheduledConnection {
            peer_id: peer2,
            priority: ConnectionPriority::Low,
            scheduled_time: Instant::now(),
            reason: "Low".to_string(),
            retry_count: 0,
        };

        assert!(conn1 > conn2); // Higher priority is "greater"
    }

    #[test]
    fn test_adaptive_strategy_low_load() {
        let config = SchedulerConfig {
            strategy: SchedulingStrategy::Adaptive,
            max_concurrent: 100,
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);

        let peer = create_test_peer();
        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Test".to_string(),
        );

        // Under low load, should use time-ordered
        let next = scheduler.get_next();
        assert!(next.is_some());
    }

    #[test]
    fn test_min_reconnect_interval() {
        let config = SchedulerConfig {
            min_reconnect_interval: Duration::from_secs(10),
            ..Default::default()
        };

        let scheduler = ConnectionScheduler::new(config);
        let peer = create_test_peer();

        scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "First".to_string(),
        );
        scheduler.get_next();

        // Try to schedule again immediately
        let result = scheduler.schedule(
            peer,
            ConnectionPriority::Normal,
            Duration::from_secs(0),
            "Second".to_string(),
        );
        assert!(!result); // Should be blocked by min_reconnect_interval
    }
}
