//! Circuit breaker pattern for resilient external service calls.
//!
//! The circuit breaker prevents cascading failures by stopping requests to failing services
//! and allowing them time to recover.
//!
//! # States
//!
//! - **Closed**: Normal operation, requests flow through
//! - **Open**: Service is failing, requests are rejected immediately
//! - **HalfOpen**: Testing if service has recovered
//!
//! # Example
//!
//! ```
//! use chie_core::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = CircuitBreakerConfig::default();
//! let mut breaker = CircuitBreaker::new("api-service", config);
//!
//! // Try calling a service
//! match breaker.call(|| async {
//!     // Make API call here
//!     Ok::<_, String>("success")
//! }).await {
//!     Ok(result) => println!("Success: {}", result),
//!     Err(e) => eprintln!("Failed: {}", e),
//! }
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow through normally
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, testing if service recovered
    HalfOpen,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Time to wait before attempting to close circuit
    pub timeout: Duration,
    /// Number of successful calls needed to close circuit from half-open
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    #[inline]
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker for resilient service calls.
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Debug)]
struct CircuitBreakerState {
    circuit_state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    #[must_use]
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState {
                circuit_state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
            })),
        }
    }

    /// Get the current state of the circuit breaker.
    #[must_use]
    pub async fn state(&self) -> CircuitState {
        self.state.read().await.circuit_state
    }

    /// Get the name of the circuit breaker.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Execute a function with circuit breaker protection.
    pub async fn call<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        // Check if we should attempt the call
        if let Err(CircuitBreakerError::CircuitOpen) = self.check_state::<E>().await {
            return Err(CircuitBreakerError::CircuitOpen);
        }

        // Execute the function
        match f().await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(CircuitBreakerError::CallFailed(e))
            }
        }
    }

    /// Check if we can make a call based on current state.
    async fn check_state<E>(&self) -> Result<(), CircuitBreakerError<E>> {
        let mut state = self.state.write().await;

        match state.circuit_state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() >= self.config.timeout {
                        // Transition to half-open
                        state.circuit_state = CircuitState::HalfOpen;
                        state.success_count = 0;
                        tracing::info!(
                            circuit_breaker = %self.name,
                            "Circuit breaker transitioning to half-open"
                        );
                        Ok(())
                    } else {
                        Err(CircuitBreakerError::CircuitOpen)
                    }
                } else {
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    /// Handle successful call.
    async fn on_success(&self) {
        let mut state = self.state.write().await;

        match state.circuit_state {
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                state.success_count += 1;
                if state.success_count >= self.config.success_threshold {
                    // Close the circuit
                    state.circuit_state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    tracing::info!(
                        circuit_breaker = %self.name,
                        "Circuit breaker closed after recovery"
                    );
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Handle failed call.
    async fn on_failure(&self) {
        let mut state = self.state.write().await;

        match state.circuit_state {
            CircuitState::Closed => {
                state.failure_count += 1;
                if state.failure_count >= self.config.failure_threshold {
                    // Open the circuit
                    state.circuit_state = CircuitState::Open;
                    state.last_failure_time = Some(Instant::now());
                    tracing::warn!(
                        circuit_breaker = %self.name,
                        failures = state.failure_count,
                        "Circuit breaker opened due to failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Failed during half-open, go back to open
                state.circuit_state = CircuitState::Open;
                state.last_failure_time = Some(Instant::now());
                state.success_count = 0;
                tracing::warn!(
                    circuit_breaker = %self.name,
                    "Circuit breaker reopened after failed recovery attempt"
                );
            }
            CircuitState::Open => {
                // Update last failure time
                state.last_failure_time = Some(Instant::now());
            }
        }
    }

    /// Manually reset the circuit breaker to closed state.
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        state.circuit_state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.last_failure_time = None;
        tracing::info!(circuit_breaker = %self.name, "Circuit breaker manually reset");
    }
}

/// Circuit breaker error types.
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    /// The circuit is open and not accepting requests
    #[error("Circuit breaker is open")]
    CircuitOpen,
    /// The underlying call failed
    #[error("Call failed: {0}")]
    CallFailed(E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            timeout: Duration::from_secs(1),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        assert_eq!(breaker.state().await, CircuitState::Closed);

        // Successful call
        let result = breaker.call(|| async { Ok::<_, String>("success") }).await;
        assert!(result.is_ok());
        assert_eq!(breaker.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            timeout: Duration::from_secs(1),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        // Make 3 failing calls
        for _ in 0..3 {
            let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
        }

        assert_eq!(breaker.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_secs(10),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
        }

        // Next call should be rejected
        let result = breaker.call(|| async { Ok::<_, String>("success") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
        }

        assert_eq!(breaker.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Next call should transition to half-open
        let _ = breaker.call(|| async { Ok::<_, String>("success") }).await;
        let state = breaker.state().await;
        assert!(state == CircuitState::HalfOpen || state == CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
        }

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Make 2 successful calls to close circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Ok::<_, String>("success") }).await;
        }

        assert_eq!(breaker.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_secs(10),
            success_threshold: 2,
        };
        let breaker = CircuitBreaker::new("test", config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<(), _>("error") }).await;
        }

        assert_eq!(breaker.state().await, CircuitState::Open);

        // Reset manually
        breaker.reset().await;
        assert_eq!(breaker.state().await, CircuitState::Closed);
    }
}
