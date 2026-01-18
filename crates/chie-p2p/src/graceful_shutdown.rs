// SPDX-License-Identifier: MIT OR Apache-2.0
//! Graceful shutdown with connection draining
//!
//! This module provides graceful shutdown functionality for P2P nodes,
//! ensuring clean termination of connections and proper resource cleanup.
//!
//! # Features
//!
//! - Connection draining with configurable timeout
//! - Staged shutdown process
//! - In-flight request tracking and completion
//! - Resource cleanup coordination
//! - Shutdown progress monitoring
//! - Emergency shutdown mode
//!
//! # Example
//!
//! ```
//! use chie_p2p::graceful_shutdown::{ShutdownManager, ShutdownConfig};
//! use std::time::Duration;
//!
//! let config = ShutdownConfig {
//!     drain_timeout: Duration::from_secs(30),
//!     force_timeout: Duration::from_secs(60),
//!     ..Default::default()
//! };
//!
//! let mut manager = ShutdownManager::new(config);
//!
//! // Initiate shutdown
//! manager.initiate();
//!
//! // Check if can accept new connections
//! assert!(!manager.can_accept_new_connections());
//!
//! // Wait for in-flight requests to complete
//! while !manager.is_drained() {
//!     // Process remaining requests
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Configuration for graceful shutdown
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    /// Time to wait for connection draining
    pub drain_timeout: Duration,
    /// Time to forcefully terminate if draining fails
    pub force_timeout: Duration,
    /// Enable staged shutdown
    pub enable_staged: bool,
    /// Time between shutdown stages
    pub stage_delay: Duration,
    /// Maximum inflight requests to track
    pub max_tracked_requests: usize,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(30),
            force_timeout: Duration::from_secs(60),
            enable_staged: true,
            stage_delay: Duration::from_secs(2),
            max_tracked_requests: 10000,
        }
    }
}

/// Shutdown stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownStage {
    /// Normal operation
    Running,
    /// Stop accepting new connections
    StopAccepting,
    /// Draining existing connections
    Draining,
    /// Waiting for in-flight requests
    WaitingForRequests,
    /// Cleanup resources
    Cleanup,
    /// Force terminate
    Terminating,
    /// Shutdown complete
    Completed,
}

/// Shutdown mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Graceful shutdown (wait for completion)
    Graceful,
    /// Emergency shutdown (immediate)
    Emergency,
}

/// Statistics for shutdown
#[derive(Debug, Clone, Default)]
pub struct ShutdownStats {
    /// Current stage
    pub stage: Option<ShutdownStage>,
    /// Active connections
    pub active_connections: usize,
    /// In-flight requests
    pub inflight_requests: usize,
    /// Drained connections
    pub drained_connections: usize,
    /// Forcefully closed connections
    pub forcefully_closed: usize,
    /// Time elapsed since shutdown started
    pub elapsed: Duration,
    /// Estimated time remaining
    pub estimated_remaining: Duration,
}

/// Graceful shutdown manager
#[derive(Debug)]
pub struct ShutdownManager {
    config: ShutdownConfig,
    /// Current shutdown stage
    stage: ShutdownStage,
    /// Shutdown mode
    mode: ShutdownMode,
    /// Active connections
    active_connections: HashSet<String>,
    /// In-flight requests per connection
    inflight_requests: HashMap<String, Vec<String>>,
    /// Shutdown start time
    start_time: Option<Instant>,
    /// Stage start time
    stage_start_time: Option<Instant>,
    /// Drained connections count
    drained_count: usize,
    /// Forcefully closed count
    forced_count: usize,
    /// Completed requests
    completed_requests: HashSet<String>,
}

impl ShutdownManager {
    /// Create a new shutdown manager
    pub fn new(config: ShutdownConfig) -> Self {
        Self {
            config,
            stage: ShutdownStage::Running,
            mode: ShutdownMode::Graceful,
            active_connections: HashSet::new(),
            inflight_requests: HashMap::new(),
            start_time: None,
            stage_start_time: None,
            drained_count: 0,
            forced_count: 0,
            completed_requests: HashSet::new(),
        }
    }

    /// Initiate graceful shutdown
    pub fn initiate(&mut self) {
        self.initiate_with_mode(ShutdownMode::Graceful);
    }

    /// Initiate shutdown with specific mode
    pub fn initiate_with_mode(&mut self, mode: ShutdownMode) {
        if self.stage == ShutdownStage::Running {
            self.mode = mode;
            self.start_time = Some(Instant::now());

            self.stage = if mode == ShutdownMode::Emergency {
                ShutdownStage::Terminating
            } else if self.config.enable_staged {
                ShutdownStage::StopAccepting
            } else {
                ShutdownStage::Draining
            };

            self.stage_start_time = Some(Instant::now());
        }
    }

    /// Check if can accept new connections
    pub fn can_accept_new_connections(&self) -> bool {
        self.stage == ShutdownStage::Running
    }

    /// Check if shutdown is in progress
    pub fn is_shutting_down(&self) -> bool {
        self.stage != ShutdownStage::Running && self.stage != ShutdownStage::Completed
    }

    /// Check if shutdown is complete
    pub fn is_complete(&self) -> bool {
        self.stage == ShutdownStage::Completed
    }

    /// Check if all connections are drained
    pub fn is_drained(&self) -> bool {
        self.active_connections.is_empty() && self.inflight_requests.is_empty()
    }

    /// Register a new connection
    pub fn register_connection(&mut self, conn_id: impl Into<String>) {
        if self.can_accept_new_connections() {
            self.active_connections.insert(conn_id.into());
        }
    }

    /// Unregister a connection
    pub fn unregister_connection(&mut self, conn_id: &str) {
        self.active_connections.remove(conn_id);
        self.inflight_requests.remove(conn_id);

        if self.is_shutting_down() {
            self.drained_count += 1;
        }
    }

    /// Register an in-flight request
    pub fn register_request(&mut self, conn_id: &str, request_id: impl Into<String>) {
        let total_requests: usize = self.inflight_requests.values().map(|v| v.len()).sum();
        if total_requests < self.config.max_tracked_requests {
            self.inflight_requests
                .entry(conn_id.to_string())
                .or_default()
                .push(request_id.into());
        }
    }

    /// Complete a request
    pub fn complete_request(&mut self, conn_id: &str, request_id: &str) {
        if let Some(requests) = self.inflight_requests.get_mut(conn_id) {
            requests.retain(|r| r != request_id);
            if requests.is_empty() {
                self.inflight_requests.remove(conn_id);
            }
        }
        self.completed_requests.insert(request_id.to_string());
    }

    /// Get current stage
    pub fn stage(&self) -> ShutdownStage {
        self.stage
    }

    /// Update shutdown progress and advance stages
    pub fn update(&mut self) {
        if !self.is_shutting_down() {
            return;
        }

        // Check for force timeout
        if let Some(start) = self.start_time {
            if start.elapsed() > self.config.force_timeout {
                self.force_terminate();
                return;
            }
        }

        // Progress through stages
        match self.stage {
            ShutdownStage::StopAccepting => {
                if self.should_advance_stage() {
                    self.advance_to(ShutdownStage::Draining);
                }
            }
            ShutdownStage::Draining => {
                if self.is_drained() || self.is_drain_timeout() {
                    self.advance_to(ShutdownStage::WaitingForRequests);
                }
            }
            ShutdownStage::WaitingForRequests => {
                if self.inflight_requests.is_empty() || self.is_drain_timeout() {
                    self.advance_to(ShutdownStage::Cleanup);
                }
            }
            ShutdownStage::Cleanup => {
                if self.should_advance_stage() {
                    self.advance_to(ShutdownStage::Terminating);
                }
            }
            ShutdownStage::Terminating => {
                self.force_close_all();
                self.advance_to(ShutdownStage::Completed);
            }
            _ => {}
        }
    }

    /// Check if drain timeout has been reached
    fn is_drain_timeout(&self) -> bool {
        if let Some(start) = self.start_time {
            start.elapsed() > self.config.drain_timeout
        } else {
            false
        }
    }

    /// Check if should advance to next stage
    fn should_advance_stage(&self) -> bool {
        if let Some(stage_start) = self.stage_start_time {
            stage_start.elapsed() > self.config.stage_delay
        } else {
            true
        }
    }

    /// Advance to next stage
    fn advance_to(&mut self, stage: ShutdownStage) {
        self.stage = stage;
        self.stage_start_time = Some(Instant::now());
    }

    /// Force terminate all connections
    fn force_terminate(&mut self) {
        self.stage = ShutdownStage::Terminating;
        self.force_close_all();
        self.stage = ShutdownStage::Completed;
    }

    /// Force close all remaining connections
    fn force_close_all(&mut self) {
        self.forced_count += self.active_connections.len();
        self.active_connections.clear();
        self.inflight_requests.clear();
    }

    /// Get connections that need to be drained
    pub fn connections_to_drain(&self) -> Vec<String> {
        self.active_connections.iter().cloned().collect()
    }

    /// Get number of in-flight requests for a connection
    pub fn inflight_count(&self, conn_id: &str) -> usize {
        self.inflight_requests
            .get(conn_id)
            .map(|r| r.len())
            .unwrap_or(0)
    }

    /// Get total number of in-flight requests
    pub fn total_inflight(&self) -> usize {
        self.inflight_requests.values().map(|r| r.len()).sum()
    }

    /// Get shutdown statistics
    pub fn stats(&self) -> ShutdownStats {
        let elapsed = self.start_time.map(|t| t.elapsed()).unwrap_or_default();

        let estimated_remaining = if self.is_complete() {
            Duration::ZERO
        } else {
            let progress_ratio = if self.stage == ShutdownStage::Draining {
                let total = self.drained_count + self.active_connections.len();
                if total > 0 {
                    self.drained_count as f64 / total as f64
                } else {
                    0.0
                }
            } else {
                0.5 // Rough estimate for other stages
            };

            if progress_ratio > 0.0 {
                let expected_total = elapsed.as_secs_f64() / progress_ratio;
                Duration::from_secs_f64((expected_total - elapsed.as_secs_f64()).max(0.0))
            } else {
                self.config.drain_timeout.saturating_sub(elapsed)
            }
        };

        ShutdownStats {
            stage: Some(self.stage),
            active_connections: self.active_connections.len(),
            inflight_requests: self.total_inflight(),
            drained_connections: self.drained_count,
            forcefully_closed: self.forced_count,
            elapsed,
            estimated_remaining,
        }
    }

    /// Reset to running state (for testing)
    #[allow(dead_code)]
    fn reset(&mut self) {
        self.stage = ShutdownStage::Running;
        self.mode = ShutdownMode::Graceful;
        self.active_connections.clear();
        self.inflight_requests.clear();
        self.start_time = None;
        self.stage_start_time = None;
        self.drained_count = 0;
        self.forced_count = 0;
        self.completed_requests.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_shutdown_manager() {
        let config = ShutdownConfig::default();
        let manager = ShutdownManager::new(config);

        assert_eq!(manager.stage(), ShutdownStage::Running);
        assert!(manager.can_accept_new_connections());
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_initiate_shutdown() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.initiate();

        assert!(!manager.can_accept_new_connections());
        assert!(manager.is_shutting_down());
        assert_eq!(manager.stage(), ShutdownStage::StopAccepting);
    }

    #[test]
    fn test_emergency_shutdown() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.initiate_with_mode(ShutdownMode::Emergency);

        assert_eq!(manager.stage(), ShutdownStage::Terminating);
    }

    #[test]
    fn test_register_unregister_connection() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.register_connection("conn1");
        manager.register_connection("conn2");

        let stats = manager.stats();
        assert_eq!(stats.active_connections, 2);

        manager.unregister_connection("conn1");

        let stats = manager.stats();
        assert_eq!(stats.active_connections, 1);
    }

    #[test]
    fn test_inflight_requests() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.register_connection("conn1");
        manager.register_request("conn1", "req1");
        manager.register_request("conn1", "req2");

        assert_eq!(manager.inflight_count("conn1"), 2);
        assert_eq!(manager.total_inflight(), 2);

        manager.complete_request("conn1", "req1");

        assert_eq!(manager.inflight_count("conn1"), 1);
        assert_eq!(manager.total_inflight(), 1);
    }

    #[test]
    fn test_is_drained() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        assert!(manager.is_drained());

        manager.register_connection("conn1");
        assert!(!manager.is_drained());

        manager.unregister_connection("conn1");
        assert!(manager.is_drained());
    }

    #[test]
    fn test_force_close_all() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.register_connection("conn1");
        manager.register_connection("conn2");
        manager.register_request("conn1", "req1");

        manager.force_close_all();

        assert!(manager.is_drained());
        assert_eq!(manager.stats().forcefully_closed, 2);
    }

    #[test]
    fn test_staged_shutdown() {
        let mut manager = ShutdownManager::new(ShutdownConfig {
            enable_staged: true,
            stage_delay: Duration::from_millis(50),
            ..Default::default()
        });

        manager.initiate();
        assert_eq!(manager.stage(), ShutdownStage::StopAccepting);

        thread::sleep(Duration::from_millis(60));
        manager.update();

        assert_eq!(manager.stage(), ShutdownStage::Draining);
    }

    #[test]
    fn test_drain_timeout() {
        let mut manager = ShutdownManager::new(ShutdownConfig {
            drain_timeout: Duration::from_millis(50),
            enable_staged: false,
            ..Default::default()
        });

        manager.register_connection("conn1");
        manager.initiate();

        assert_eq!(manager.stage(), ShutdownStage::Draining);

        thread::sleep(Duration::from_millis(60));
        manager.update();

        // Should advance even with active connections due to timeout
        assert!(manager.stage() >= ShutdownStage::WaitingForRequests);
    }

    #[test]
    fn test_force_timeout() {
        let mut manager = ShutdownManager::new(ShutdownConfig {
            force_timeout: Duration::from_millis(50),
            drain_timeout: Duration::from_millis(100),
            ..Default::default()
        });

        manager.register_connection("conn1");
        manager.initiate();

        thread::sleep(Duration::from_millis(60));
        manager.update();

        assert_eq!(manager.stage(), ShutdownStage::Completed);
    }

    #[test]
    fn test_connections_to_drain() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.register_connection("conn1");
        manager.register_connection("conn2");

        let conns = manager.connections_to_drain();
        assert_eq!(conns.len(), 2);
        assert!(conns.contains(&"conn1".to_string()));
        assert!(conns.contains(&"conn2".to_string()));
    }

    #[test]
    fn test_stats() {
        let mut manager = ShutdownManager::new(ShutdownConfig::default());

        manager.register_connection("conn1");
        manager.register_request("conn1", "req1");
        manager.initiate();

        thread::sleep(Duration::from_millis(10));

        let stats = manager.stats();
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.inflight_requests, 1);
        assert!(stats.elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_complete_shutdown_cycle() {
        let mut manager = ShutdownManager::new(ShutdownConfig {
            enable_staged: false,
            drain_timeout: Duration::from_secs(5),
            ..Default::default()
        });

        manager.register_connection("conn1");
        manager.register_request("conn1", "req1");

        manager.initiate();
        assert!(manager.is_shutting_down());

        // Complete request and drain connection
        manager.complete_request("conn1", "req1");
        manager.unregister_connection("conn1");

        manager.update();

        // Should eventually complete
        while !manager.is_complete() && !manager.is_drain_timeout() {
            manager.update();
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn test_max_tracked_requests() {
        let mut manager = ShutdownManager::new(ShutdownConfig {
            max_tracked_requests: 2,
            ..Default::default()
        });

        manager.register_connection("conn1");
        manager.register_request("conn1", "req1");
        manager.register_request("conn1", "req2");
        manager.register_request("conn1", "req3"); // Should not be tracked

        assert_eq!(manager.inflight_count("conn1"), 2);
    }
}
