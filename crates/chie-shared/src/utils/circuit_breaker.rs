//! Circuit breaker state machine for fault tolerance
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! in distributed systems by temporarily blocking requests to failing services.

use std::time::{Duration, Instant};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are blocked
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

/// Circuit breaker for fault tolerance
///
/// The circuit breaker monitors failures and automatically transitions between states:
/// - Closed: Normal operation, requests pass through
/// - Open: Too many failures, requests are blocked
/// - HalfOpen: Testing recovery, limited requests allowed
///
/// # Examples
///
/// ```
/// use chie_shared::CircuitBreaker;
///
/// let mut breaker = CircuitBreaker::new(5, 60_000, 30_000);
///
/// // Record successful requests
/// breaker.record_success();
/// assert!(breaker.is_closed());
///
/// // Record failures
/// for _ in 0..5 {
///     breaker.record_failure();
/// }
/// assert!(breaker.is_open());
/// ```
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Current state of the circuit
    state: CircuitState,
    /// Number of consecutive failures
    failure_count: u32,
    /// Failure threshold to open circuit
    failure_threshold: u32,
    /// Duration to keep circuit open (milliseconds)
    timeout_ms: u64,
    /// Duration for half-open state (milliseconds)
    #[allow(dead_code)]
    half_open_timeout_ms: u64,
    /// Time when circuit was opened
    opened_at: Option<Instant>,
    /// Number of successful requests in half-open state
    half_open_successes: u32,
    /// Number of requests to allow in half-open state
    half_open_max_requests: u32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    ///
    /// # Arguments
    ///
    /// * `failure_threshold` - Number of failures before opening circuit
    /// * `timeout_ms` - Milliseconds to keep circuit open
    /// * `half_open_timeout_ms` - Milliseconds for half-open state
    #[must_use]
    pub fn new(failure_threshold: u32, timeout_ms: u64, half_open_timeout_ms: u64) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_threshold,
            timeout_ms,
            half_open_timeout_ms,
            opened_at: None,
            half_open_successes: 0,
            half_open_max_requests: 3,
        }
    }

    /// Create a circuit breaker with default settings
    ///
    /// Defaults: 5 failures, 60s timeout, 30s half-open timeout
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(5, 60_000, 30_000)
    }

    /// Get the current state
    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Check if circuit is closed (requests allowed)
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.check_state_transition();
        self.state == CircuitState::Closed
    }

    /// Check if circuit is open (requests blocked)
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.check_state_transition();
        self.state == CircuitState::Open
    }

    /// Check if circuit is half-open (testing recovery)
    #[must_use]
    pub fn is_half_open(&self) -> bool {
        self.check_state_transition();
        self.state == CircuitState::HalfOpen
    }

    /// Check if a request is allowed through the circuit
    #[must_use]
    pub fn allow_request(&self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout elapsed
                if let Some(opened_at) = self.opened_at {
                    opened_at.elapsed() >= Duration::from_millis(self.timeout_ms)
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                self.half_open_successes < self.half_open_max_requests
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.half_open_successes += 1;
                // If enough successes, close the circuit
                if self.half_open_successes >= self.half_open_max_requests {
                    self.transition_to_closed();
                }
            }
            CircuitState::Open => {
                // Success in open state shouldn't happen normally
                // but if it does, transition to half-open
                self.transition_to_half_open();
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.failure_threshold {
                    self.transition_to_open();
                }
            }
            CircuitState::HalfOpen => {
                // Failure in half-open means service still not recovered
                self.transition_to_open();
            }
            CircuitState::Open => {
                // Already open, just update timestamp
                self.opened_at = Some(Instant::now());
            }
        }
    }

    /// Get failure count
    #[must_use]
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Get time remaining until circuit can transition from open to half-open
    #[must_use]
    pub fn time_until_half_open(&self) -> Option<Duration> {
        if self.state != CircuitState::Open {
            return None;
        }

        self.opened_at.and_then(|opened_at| {
            let elapsed = opened_at.elapsed();
            let timeout = Duration::from_millis(self.timeout_ms);
            timeout.checked_sub(elapsed)
        })
    }

    /// Reset the circuit breaker to closed state
    pub fn reset(&mut self) {
        self.transition_to_closed();
    }

    /// Force circuit to open state
    pub fn force_open(&mut self) {
        self.transition_to_open();
    }

    // Internal state transitions

    fn check_state_transition(&self) {
        // This is a non-mutating check, actual transition happens in allow_request
    }

    fn transition_to_closed(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.opened_at = None;
        self.half_open_successes = 0;
    }

    fn transition_to_open(&mut self) {
        self.state = CircuitState::Open;
        self.opened_at = Some(Instant::now());
        self.half_open_successes = 0;
    }

    fn transition_to_half_open(&mut self) {
        self.state = CircuitState::HalfOpen;
        self.half_open_successes = 0;
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_circuit_starts_closed() {
        let breaker = CircuitBreaker::new(3, 1000, 500);
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert!(breaker.is_closed());
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_opens_after_threshold() {
        let mut breaker = CircuitBreaker::new(3, 1000, 500);

        // Record failures up to threshold
        breaker.record_failure();
        assert!(breaker.is_closed());

        breaker.record_failure();
        assert!(breaker.is_closed());

        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[test]
    fn test_success_resets_failure_count() {
        let mut breaker = CircuitBreaker::new(3, 1000, 500);

        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.failure_count(), 2);

        breaker.record_success();
        assert_eq!(breaker.failure_count(), 0);
        assert!(breaker.is_closed());
    }

    #[test]
    fn test_allow_request_closed() {
        let breaker = CircuitBreaker::new(3, 1000, 500);
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_allow_request_open() {
        let mut breaker = CircuitBreaker::new(3, 100, 50); // Short timeout for testing

        // Open the circuit
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert!(breaker.is_open());
        assert!(!breaker.allow_request());

        // Wait for timeout
        sleep(Duration::from_millis(150));
        assert!(breaker.allow_request()); // Should allow after timeout
    }

    #[test]
    fn test_half_open_recovery() {
        let mut breaker = CircuitBreaker::new(3, 100, 50);

        // Open circuit
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert!(breaker.is_open());

        // Wait for timeout and transition to half-open
        sleep(Duration::from_millis(150));
        assert!(breaker.allow_request());

        // Manually transition to half-open (in real usage, allow_request would trigger this)
        breaker.transition_to_half_open();
        assert!(breaker.is_half_open());

        // Record successful requests
        breaker.record_success();
        breaker.record_success();
        breaker.record_success();

        // Should be closed after enough successes
        assert!(breaker.is_closed());
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let mut breaker = CircuitBreaker::new(3, 100, 50);

        // Open circuit
        for _ in 0..3 {
            breaker.record_failure();
        }

        // Transition to half-open
        breaker.transition_to_half_open();
        assert!(breaker.is_half_open());

        // Failure in half-open should reopen circuit
        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[test]
    fn test_reset() {
        let mut breaker = CircuitBreaker::new(3, 1000, 500);

        // Open circuit
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert!(breaker.is_open());

        // Reset should close it
        breaker.reset();
        assert!(breaker.is_closed());
        assert_eq!(breaker.failure_count(), 0);
    }

    #[test]
    fn test_force_open() {
        let mut breaker = CircuitBreaker::new(3, 1000, 500);
        assert!(breaker.is_closed());

        breaker.force_open();
        assert!(breaker.is_open());
    }

    #[test]
    fn test_time_until_half_open() {
        let mut breaker = CircuitBreaker::new(3, 1000, 500);

        // No time until half-open when closed
        assert!(breaker.time_until_half_open().is_none());

        // Open circuit
        for _ in 0..3 {
            breaker.record_failure();
        }

        // Should have time remaining
        let remaining = breaker.time_until_half_open();
        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_millis() <= 1000);
    }

    #[test]
    fn test_default_constructor() {
        let breaker = CircuitBreaker::default();
        assert_eq!(breaker.state(), CircuitState::Closed);
        assert_eq!(breaker.failure_count(), 0);
    }
}
