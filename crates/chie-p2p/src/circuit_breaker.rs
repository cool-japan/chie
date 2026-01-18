//! Circuit breaker pattern for protecting against cascading failures.
//!
//! The circuit breaker prevents repeated attempts to connect to or transfer
//! data from peers that are known to be failing, allowing the system to
//! fail fast and recover gracefully.

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed (normal operation).
    Closed,
    /// Circuit is open (blocking requests).
    Open,
    /// Circuit is half-open (testing if service recovered).
    HalfOpen,
}

/// Result of a circuit breaker check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitCheck {
    /// Request is allowed.
    Allowed,
    /// Request is blocked (circuit is open).
    Blocked,
}

/// Configuration for circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open the circuit.
    pub failure_threshold: u32,
    /// Success threshold to close the circuit from half-open.
    pub success_threshold: u32,
    /// Timeout before attempting to close an open circuit.
    pub timeout: Duration,
    /// Window size for counting failures.
    pub window_size: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            window_size: Duration::from_secs(120),
        }
    }
}

/// Circuit breaker for a single peer.
#[derive(Debug, Clone)]
struct Circuit {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    state_changed_at: Instant,
    failures_in_window: Vec<Instant>,
}

impl Circuit {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            state_changed_at: Instant::now(),
            failures_in_window: Vec::new(),
        }
    }

    fn check(&mut self, config: &CircuitBreakerConfig) -> CircuitCheck {
        let now = Instant::now();

        match self.state {
            CircuitState::Closed => CircuitCheck::Allowed,
            CircuitState::Open => {
                // Check if timeout has elapsed
                if now.duration_since(self.state_changed_at) >= config.timeout {
                    self.transition_to_half_open();
                    debug!("Circuit transitioned to HalfOpen");
                    CircuitCheck::Allowed
                } else {
                    CircuitCheck::Blocked
                }
            }
            CircuitState::HalfOpen => CircuitCheck::Allowed,
        }
    }

    fn record_success(&mut self, config: &CircuitBreakerConfig) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
                self.failures_in_window.clear();
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= config.success_threshold {
                    self.transition_to_closed();
                    debug!("Circuit transitioned to Closed after successful recovery");
                }
            }
            CircuitState::Open => {
                // Success in open state shouldn't happen, but reset if it does
                self.transition_to_closed();
            }
        }
    }

    fn record_failure(&mut self, config: &CircuitBreakerConfig) {
        let now = Instant::now();
        self.last_failure_time = Some(now);

        // Clean old failures outside the window
        self.failures_in_window
            .retain(|&t| now.duration_since(t) <= config.window_size);

        self.failures_in_window.push(now);

        match self.state {
            CircuitState::Closed => {
                if self.failures_in_window.len() >= config.failure_threshold as usize {
                    self.transition_to_open();
                    warn!(
                        "Circuit opened after {} failures",
                        self.failures_in_window.len()
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state reopens the circuit
                self.transition_to_open();
                warn!("Circuit reopened after failure in HalfOpen state");
            }
            CircuitState::Open => {
                self.failure_count += 1;
            }
        }
    }

    fn transition_to_closed(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.state_changed_at = Instant::now();
        self.failures_in_window.clear();
    }

    fn transition_to_open(&mut self) {
        self.state = CircuitState::Open;
        self.success_count = 0;
        self.state_changed_at = Instant::now();
    }

    fn transition_to_half_open(&mut self) {
        self.state = CircuitState::HalfOpen;
        self.success_count = 0;
        self.failure_count = 0;
        self.state_changed_at = Instant::now();
    }
}

/// Circuit breaker manager for all peers.
pub struct CircuitBreakerManager {
    config: CircuitBreakerConfig,
    circuits: HashMap<PeerId, Circuit>,
}

impl Default for CircuitBreakerManager {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuits: HashMap::new(),
        }
    }

    /// Check if a request to a peer should be allowed.
    pub fn check(&mut self, peer_id: &PeerId) -> CircuitCheck {
        let circuit = self.circuits.entry(*peer_id).or_insert_with(Circuit::new);
        circuit.check(&self.config)
    }

    /// Record a successful request to a peer.
    pub fn record_success(&mut self, peer_id: &PeerId) {
        let circuit = self.circuits.entry(*peer_id).or_insert_with(Circuit::new);
        circuit.record_success(&self.config);
    }

    /// Record a failed request to a peer.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        let circuit = self.circuits.entry(*peer_id).or_insert_with(Circuit::new);
        circuit.record_failure(&self.config);
    }

    /// Get the circuit state for a peer.
    pub fn get_state(&self, peer_id: &PeerId) -> CircuitState {
        self.circuits
            .get(peer_id)
            .map(|c| c.state)
            .unwrap_or(CircuitState::Closed)
    }

    /// Reset the circuit for a peer.
    pub fn reset(&mut self, peer_id: &PeerId) {
        if let Some(circuit) = self.circuits.get_mut(peer_id) {
            circuit.transition_to_closed();
            debug!("Circuit reset for peer {:?}", peer_id);
        }
    }

    /// Remove a peer from the circuit breaker.
    pub fn remove(&mut self, peer_id: &PeerId) {
        self.circuits.remove(peer_id);
    }

    /// Get statistics about the circuit breaker.
    pub fn stats(&self) -> CircuitBreakerStats {
        let mut closed = 0;
        let mut open = 0;
        let mut half_open = 0;

        for circuit in self.circuits.values() {
            match circuit.state {
                CircuitState::Closed => closed += 1,
                CircuitState::Open => open += 1,
                CircuitState::HalfOpen => half_open += 1,
            }
        }

        CircuitBreakerStats {
            total_circuits: self.circuits.len(),
            closed_circuits: closed,
            open_circuits: open,
            half_open_circuits: half_open,
        }
    }

    /// Get all peers with open circuits.
    pub fn get_open_circuits(&self) -> Vec<PeerId> {
        self.circuits
            .iter()
            .filter(|(_, c)| c.state == CircuitState::Open)
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Get all peers with half-open circuits.
    pub fn get_half_open_circuits(&self) -> Vec<PeerId> {
        self.circuits
            .iter()
            .filter(|(_, c)| c.state == CircuitState::HalfOpen)
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }
}

/// Statistics about the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Total number of circuits being tracked.
    pub total_circuits: usize,
    /// Number of closed circuits (normal operation).
    pub closed_circuits: usize,
    /// Number of open circuits (blocking requests).
    pub open_circuits: usize,
    /// Number of half-open circuits (testing recovery).
    pub half_open_circuits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_starts_closed() {
        let manager = CircuitBreakerManager::default();
        let peer = PeerId::random();
        assert_eq!(manager.get_state(&peer), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut manager = CircuitBreakerManager::new(config);
        let peer = PeerId::random();

        // Record failures
        for _ in 0..3 {
            manager.record_failure(&peer);
        }

        assert_eq!(manager.get_state(&peer), CircuitState::Open);
        assert_eq!(manager.check(&peer), CircuitCheck::Blocked);
    }

    #[test]
    fn test_circuit_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut manager = CircuitBreakerManager::new(config);
        let peer = PeerId::random();

        // Open the circuit
        manager.record_failure(&peer);
        manager.record_failure(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Check should transition to half-open
        let result = manager.check(&peer);
        assert_eq!(result, CircuitCheck::Allowed);
        assert_eq!(manager.get_state(&peer), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_closes_after_success_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut manager = CircuitBreakerManager::new(config);
        let peer = PeerId::random();

        // Open the circuit
        manager.record_failure(&peer);
        manager.record_failure(&peer);

        // Transition to half-open
        std::thread::sleep(Duration::from_millis(100));
        manager.check(&peer);

        // Record successes
        manager.record_success(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::HalfOpen);

        manager.record_success(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_reopens_on_failure_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut manager = CircuitBreakerManager::new(config);
        let peer = PeerId::random();

        // Open the circuit
        manager.record_failure(&peer);
        manager.record_failure(&peer);

        // Transition to half-open
        std::thread::sleep(Duration::from_millis(100));
        manager.check(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::HalfOpen);

        // Failure should reopen
        manager.record_failure(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::Open);
    }

    #[test]
    fn test_reset_circuit() {
        let mut manager = CircuitBreakerManager::default();
        let peer = PeerId::random();

        // Open the circuit
        for _ in 0..5 {
            manager.record_failure(&peer);
        }
        assert_eq!(manager.get_state(&peer), CircuitState::Open);

        // Reset
        manager.reset(&peer);
        assert_eq!(manager.get_state(&peer), CircuitState::Closed);
    }

    #[test]
    fn test_failure_window() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            window_size: Duration::from_millis(100),
            ..Default::default()
        };
        let mut manager = CircuitBreakerManager::new(config);
        let peer = PeerId::random();

        // Record failures
        manager.record_failure(&peer);
        manager.record_failure(&peer);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));

        // These should be in a new window
        manager.record_failure(&peer);
        manager.record_failure(&peer);

        // Should not open (only 2 failures in current window)
        assert_eq!(manager.get_state(&peer), CircuitState::Closed);
    }

    #[test]
    fn test_stats() {
        let mut manager = CircuitBreakerManager::default();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        // Closed circuit
        manager.record_success(&peer1);

        // Open circuit
        for _ in 0..5 {
            manager.record_failure(&peer2);
        }

        // Half-open circuit (via timeout)
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        manager.config = config;
        manager.record_failure(&peer3);
        manager.record_failure(&peer3);
        std::thread::sleep(Duration::from_millis(100));
        manager.check(&peer3);

        let stats = manager.stats();
        assert_eq!(stats.total_circuits, 3);
        assert!(stats.closed_circuits >= 1);
        assert!(stats.open_circuits >= 1);
    }

    #[test]
    fn test_get_open_circuits() {
        let mut manager = CircuitBreakerManager::default();
        let peer = PeerId::random();

        for _ in 0..5 {
            manager.record_failure(&peer);
        }

        let open = manager.get_open_circuits();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0], peer);
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = CircuitBreakerManager::default();
        let peer = PeerId::random();

        manager.record_failure(&peer);
        assert_eq!(manager.stats().total_circuits, 1);

        manager.remove(&peer);
        assert_eq!(manager.stats().total_circuits, 0);
    }
}
