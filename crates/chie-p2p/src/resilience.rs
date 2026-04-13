//! Resilience patterns for fault-tolerant P2P operations.
//!
//! This module provides comprehensive resilience capabilities including:
//! - Advanced retry strategies with exponential backoff
//! - Bulkhead pattern for resource isolation
//! - Graceful degradation mechanisms
//! - Chaos engineering test utilities

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

/// Retry strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryStrategy {
    /// Fixed delay between retries
    Fixed {
        /// Delay between retries
        delay: Duration,
    },
    /// Exponential backoff
    Exponential {
        /// Initial delay
        initial_delay: Duration,
        /// Maximum delay
        max_delay: Duration,
        /// Multiplier for each retry
        multiplier: f64,
    },
    /// Exponential backoff with jitter
    ExponentialWithJitter {
        /// Initial delay
        initial_delay: Duration,
        /// Maximum delay
        max_delay: Duration,
        /// Multiplier for each retry
        multiplier: f64,
        /// Jitter factor (0.0 to 1.0)
        jitter: f64,
    },
    /// Fibonacci backoff
    Fibonacci {
        /// Initial delay
        initial_delay: Duration,
        /// Maximum delay
        max_delay: Duration,
    },
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::ExponentialWithJitter {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.1,
        }
    }
}

impl RetryStrategy {
    /// Calculate delay for a given attempt number
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        match self {
            RetryStrategy::Fixed { delay } => *delay,
            RetryStrategy::Exponential {
                initial_delay,
                max_delay,
                multiplier,
            } => {
                let delay_ms = initial_delay.as_millis() as f64 * multiplier.powi(attempt as i32);
                let delay = Duration::from_millis(delay_ms as u64);
                delay.min(*max_delay)
            }
            RetryStrategy::ExponentialWithJitter {
                initial_delay,
                max_delay,
                multiplier,
                jitter,
            } => {
                let base_delay_ms =
                    initial_delay.as_millis() as f64 * multiplier.powi(attempt as i32);
                let jitter_factor = 1.0 + (rand::rng().random::<f64>() - 0.5) * 2.0 * jitter;
                let delay_ms = base_delay_ms * jitter_factor;
                let delay = Duration::from_millis(delay_ms as u64);
                delay.min(*max_delay)
            }
            RetryStrategy::Fibonacci {
                initial_delay,
                max_delay,
            } => {
                let fib = fibonacci(attempt);
                let delay_ms = initial_delay.as_millis() as u64 * fib;
                let delay = Duration::from_millis(delay_ms);
                delay.min(*max_delay)
            }
        }
    }
}

/// Calculate nth Fibonacci number
fn fibonacci(n: u32) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        _ => {
            let mut a = 1u64;
            let mut b = 1u64;
            for _ in 2..=n {
                let temp = a + b;
                a = b;
                b = temp;
            }
            b
        }
    }
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Retry strategy
    pub strategy: RetryStrategy,
    /// Maximum number of retries
    pub max_attempts: u32,
    /// Timeout for each attempt
    pub attempt_timeout: Option<Duration>,
    /// Which errors should trigger a retry
    pub retry_on: Vec<String>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            strategy: RetryStrategy::default(),
            max_attempts: 3,
            attempt_timeout: Some(Duration::from_secs(10)),
            retry_on: vec!["timeout".to_string(), "connection_refused".to_string()],
        }
    }
}

/// Retry executor
pub struct RetryExecutor {
    /// Policy
    policy: RetryPolicy,
    /// Statistics
    stats: Arc<Mutex<RetryStats>>,
}

/// Retry statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetryStats {
    /// Total operations attempted
    pub total_operations: u64,
    /// Operations that succeeded
    pub successful_operations: u64,
    /// Operations that failed after all retries
    pub failed_operations: u64,
    /// Total retry attempts
    pub total_retries: u64,
    /// Average retries per operation
    pub avg_retries_per_operation: f64,
}

impl RetryExecutor {
    /// Create a new retry executor
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            stats: Arc::new(Mutex::new(RetryStats::default())),
        }
    }

    /// Execute with retry
    pub async fn execute<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: std::fmt::Display,
    {
        let mut stats = self.stats.lock().await;
        stats.total_operations += 1;
        drop(stats);

        let mut last_error = None;
        let mut retries = 0;

        for attempt in 0..self.policy.max_attempts {
            let result = operation().await;

            match result {
                Ok(value) => {
                    let mut stats = self.stats.lock().await;
                    stats.successful_operations += 1;
                    stats.total_retries += retries;
                    if stats.total_operations > 0 {
                        stats.avg_retries_per_operation =
                            stats.total_retries as f64 / stats.total_operations as f64;
                    }
                    return Ok(value);
                }
                Err(e) => {
                    last_error = Some(e);
                    retries += 1;

                    if attempt < self.policy.max_attempts - 1 {
                        let delay = self.policy.strategy.calculate_delay(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        let mut stats = self.stats.lock().await;
        stats.failed_operations += 1;
        stats.total_retries += retries;
        if stats.total_operations > 0 {
            stats.avg_retries_per_operation =
                stats.total_retries as f64 / stats.total_operations as f64;
        }

        Err(last_error.unwrap())
    }

    /// Get statistics
    pub async fn stats(&self) -> RetryStats {
        self.stats.lock().await.clone()
    }
}

/// Bulkhead configuration for resource isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkheadConfig {
    /// Maximum concurrent operations
    pub max_concurrent: usize,
    /// Maximum queue size
    pub max_queue: usize,
    /// Timeout for acquiring a permit
    pub acquire_timeout: Duration,
}

impl Default for BulkheadConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            max_queue: 100,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

/// Bulkhead for resource isolation
pub struct Bulkhead {
    /// Configuration
    config: BulkheadConfig,
    /// Semaphore for limiting concurrency
    semaphore: Arc<Semaphore>,
    /// Statistics
    stats: Arc<Mutex<BulkheadStats>>,
}

/// Bulkhead statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulkheadStats {
    /// Total operations attempted
    pub total_operations: u64,
    /// Operations that succeeded
    pub successful_operations: u64,
    /// Operations that were rejected
    pub rejected_operations: u64,
    /// Current active operations
    pub active_operations: u64,
    /// Peak concurrent operations
    pub peak_concurrent: u64,
}

impl Bulkhead {
    /// Create a new bulkhead
    pub fn new(config: BulkheadConfig) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            config,
            stats: Arc::new(Mutex::new(BulkheadStats::default())),
        }
    }

    /// Execute operation within bulkhead
    pub async fn execute<F, T>(&self, operation: F) -> Result<T, BulkheadError>
    where
        F: std::future::Future<Output = T>,
    {
        let mut stats = self.stats.lock().await;
        stats.total_operations += 1;
        drop(stats);

        // Try to acquire permit
        let permit = match tokio::time::timeout(
            self.config.acquire_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                let mut stats = self.stats.lock().await;
                stats.rejected_operations += 1;
                return Err(BulkheadError::SemaphoreClosed);
            }
            Err(_) => {
                let mut stats = self.stats.lock().await;
                stats.rejected_operations += 1;
                return Err(BulkheadError::Timeout);
            }
        };

        // Update active operations
        let mut stats = self.stats.lock().await;
        stats.active_operations += 1;
        stats.peak_concurrent = stats.peak_concurrent.max(stats.active_operations);
        drop(stats);

        // Execute operation
        let result = operation.await;

        // Release permit and update stats
        drop(permit);
        let mut stats = self.stats.lock().await;
        stats.active_operations -= 1;
        stats.successful_operations += 1;

        Ok(result)
    }

    /// Get statistics
    pub async fn stats(&self) -> BulkheadStats {
        self.stats.lock().await.clone()
    }

    /// Get available permits
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Bulkhead error
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BulkheadError {
    /// Timeout acquiring permit
    #[error("Timeout acquiring bulkhead permit")]
    Timeout,
    /// Semaphore closed
    #[error("Bulkhead semaphore closed")]
    SemaphoreClosed,
}

/// Degradation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DegradationLevel {
    /// Full functionality
    None = 0,
    /// Minor degradation
    Minor = 1,
    /// Moderate degradation
    Moderate = 2,
    /// Severe degradation
    Severe = 3,
    /// Critical - minimal functionality
    Critical = 4,
}

/// Graceful degradation manager
pub struct GracefulDegradation {
    /// Current degradation level
    level: Arc<Mutex<DegradationLevel>>,
    /// Feature flags for each degradation level
    features: Arc<Mutex<HashMap<String, DegradationLevel>>>,
    /// Statistics
    stats: Arc<Mutex<DegradationStats>>,
}

/// Degradation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DegradationStats {
    /// Current degradation level
    pub current_level: u8,
    /// Time in each degradation level
    pub time_in_level: HashMap<u8, Duration>,
    /// Number of level changes
    pub level_changes: u64,
    /// Features currently disabled
    pub disabled_features: usize,
}

impl GracefulDegradation {
    /// Create a new graceful degradation manager
    pub fn new() -> Self {
        Self {
            level: Arc::new(Mutex::new(DegradationLevel::None)),
            features: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(DegradationStats::default())),
        }
    }

    /// Set degradation level
    pub async fn set_level(&self, level: DegradationLevel) {
        let mut current = self.level.lock().await;
        if *current != level {
            *current = level;
            let mut stats = self.stats.lock().await;
            stats.current_level = level as u8;
            stats.level_changes += 1;
        }
    }

    /// Get current degradation level
    pub async fn level(&self) -> DegradationLevel {
        *self.level.lock().await
    }

    /// Register a feature with its minimum required level
    pub async fn register_feature(&self, name: impl Into<String>, min_level: DegradationLevel) {
        let mut features = self.features.lock().await;
        features.insert(name.into(), min_level);
    }

    /// Check if a feature is available at current degradation level
    pub async fn is_feature_available(&self, name: &str) -> bool {
        let current_level = self.level().await;
        let features = self.features.lock().await;

        if let Some(&min_level) = features.get(name) {
            current_level <= min_level
        } else {
            true // Unknown features are available by default
        }
    }

    /// Get list of available features
    pub async fn available_features(&self) -> Vec<String> {
        let current_level = self.level().await;
        let features = self.features.lock().await;

        features
            .iter()
            .filter(|(_, min_level)| current_level <= **min_level)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get statistics
    pub async fn stats(&self) -> DegradationStats {
        let mut stats = self.stats.lock().await;
        let current_level = self.level().await;
        stats.current_level = current_level as u8;

        let features = self.features.lock().await;
        stats.disabled_features = features
            .iter()
            .filter(|(_, min_level)| current_level > **min_level)
            .count();

        stats.clone()
    }
}

impl Default for GracefulDegradation {
    fn default() -> Self {
        Self::new()
    }
}

/// Chaos engineering fault injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosFault {
    /// Inject latency
    Latency {
        /// Duration of latency
        duration: Duration,
    },
    /// Fail the operation
    Failure {
        /// Error message
        message: String,
    },
    /// Drop the operation (no response)
    Drop,
    /// Corrupt data
    Corruption {
        /// Corruption probability (0.0 to 1.0)
        probability: f64,
    },
}

/// Chaos engineering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    /// Enabled chaos testing
    pub enabled: bool,
    /// Fault injection probability (0.0 to 1.0)
    pub fault_probability: f64,
    /// Faults to inject
    pub faults: Vec<ChaosFault>,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fault_probability: 0.0,
            faults: Vec::new(),
        }
    }
}

/// Chaos engineering test utility
pub struct ChaosEngineer {
    /// Configuration
    config: ChaosConfig,
    /// Statistics
    stats: Arc<Mutex<ChaosStats>>,
}

/// Chaos statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChaosStats {
    /// Total operations
    pub total_operations: u64,
    /// Operations with faults injected
    pub faults_injected: u64,
    /// Faults by type
    pub faults_by_type: HashMap<String, u64>,
}

impl ChaosEngineer {
    /// Create a new chaos engineer
    pub fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Mutex::new(ChaosStats::default())),
        }
    }

    /// Maybe inject a fault
    pub async fn maybe_inject_fault(&self) -> Option<ChaosFault> {
        if !self.config.enabled {
            return None;
        }

        let mut stats = self.stats.lock().await;
        stats.total_operations += 1;
        drop(stats);

        let mut rng = rand::rng();
        if rng.random::<f64>() < self.config.fault_probability {
            if let Some(fault) = self
                .config
                .faults
                .get(rng.random_range(0..self.config.faults.len()))
            {
                let mut stats = self.stats.lock().await;
                stats.faults_injected += 1;

                let fault_type = match fault {
                    ChaosFault::Latency { .. } => "latency",
                    ChaosFault::Failure { .. } => "failure",
                    ChaosFault::Drop => "drop",
                    ChaosFault::Corruption { .. } => "corruption",
                };
                *stats
                    .faults_by_type
                    .entry(fault_type.to_string())
                    .or_insert(0) += 1;

                return Some(fault.clone());
            }
        }

        None
    }

    /// Execute operation with chaos injection
    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, ChaosError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        if let Some(fault) = self.maybe_inject_fault().await {
            match fault {
                ChaosFault::Latency { duration } => {
                    tokio::time::sleep(duration).await;
                    operation.await.map_err(ChaosError::Operation)
                }
                ChaosFault::Failure { message } => Err(ChaosError::InjectedFailure(message)),
                ChaosFault::Drop => Err(ChaosError::Dropped),
                ChaosFault::Corruption { .. } => {
                    // For corruption, still execute but mark as corrupted
                    operation.await.map_err(ChaosError::Operation)
                }
            }
        } else {
            operation.await.map_err(ChaosError::Operation)
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> ChaosStats {
        self.stats.lock().await.clone()
    }

    /// Enable chaos testing
    pub fn enable(&mut self) {
        self.config.enabled = true;
    }

    /// Disable chaos testing
    pub fn disable(&mut self) {
        self.config.enabled = false;
    }
}

/// Chaos error
#[derive(Debug, thiserror::Error)]
pub enum ChaosError<E> {
    /// Injected failure
    #[error("Chaos injected failure: {0}")]
    InjectedFailure(String),
    /// Operation dropped
    #[error("Chaos dropped operation")]
    Dropped,
    /// Original operation error
    #[error("Operation error: {0}")]
    Operation(E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci() {
        assert_eq!(fibonacci(0), 1);
        assert_eq!(fibonacci(1), 1);
        assert_eq!(fibonacci(2), 2);
        assert_eq!(fibonacci(3), 3);
        assert_eq!(fibonacci(4), 5);
        assert_eq!(fibonacci(5), 8);
    }

    #[test]
    fn test_retry_strategy_fixed() {
        let strategy = RetryStrategy::Fixed {
            delay: Duration::from_millis(100),
        };
        assert_eq!(strategy.calculate_delay(0), Duration::from_millis(100));
        assert_eq!(strategy.calculate_delay(5), Duration::from_millis(100));
    }

    #[test]
    fn test_retry_strategy_exponential() {
        let strategy = RetryStrategy::Exponential {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
        };
        assert_eq!(strategy.calculate_delay(0), Duration::from_millis(100));
        assert_eq!(strategy.calculate_delay(1), Duration::from_millis(200));
        assert_eq!(strategy.calculate_delay(2), Duration::from_millis(400));
    }

    #[test]
    fn test_retry_strategy_fibonacci() {
        let strategy = RetryStrategy::Fibonacci {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        };
        assert_eq!(strategy.calculate_delay(0), Duration::from_millis(100));
        assert_eq!(strategy.calculate_delay(1), Duration::from_millis(100));
        assert_eq!(strategy.calculate_delay(2), Duration::from_millis(200));
        assert_eq!(strategy.calculate_delay(3), Duration::from_millis(300));
    }

    #[tokio::test]
    async fn test_retry_executor_success() {
        let policy = RetryPolicy::default();
        let executor = RetryExecutor::new(policy);

        let result = executor
            .execute(|| Box::pin(async { Ok::<_, String>(42) }))
            .await;

        assert_eq!(result, Ok(42));

        let stats = executor.stats().await;
        assert_eq!(stats.successful_operations, 1);
    }

    #[tokio::test]
    async fn test_retry_executor_with_retries() {
        let policy = RetryPolicy {
            strategy: RetryStrategy::Fixed {
                delay: Duration::from_millis(10),
            },
            max_attempts: 3,
            attempt_timeout: None,
            retry_on: vec![],
        };
        let executor = RetryExecutor::new(policy);

        let counter = Arc::new(Mutex::new(0));
        let counter_clone = counter.clone();

        let result = executor
            .execute(|| {
                let counter = counter_clone.clone();
                Box::pin(async move {
                    let mut c = counter.lock().await;
                    *c += 1;
                    if *c < 3 { Err("not yet") } else { Ok(42) }
                })
            })
            .await;

        assert_eq!(result, Ok(42));
        assert_eq!(*counter.lock().await, 3);
    }

    #[tokio::test]
    async fn test_bulkhead() {
        let config = BulkheadConfig {
            max_concurrent: 2,
            max_queue: 10,
            acquire_timeout: Duration::from_secs(1),
        };
        let bulkhead = Bulkhead::new(config);

        let result = bulkhead.execute(async { 42 }).await;
        assert_eq!(result, Ok(42));

        let stats = bulkhead.stats().await;
        assert_eq!(stats.successful_operations, 1);
    }

    #[tokio::test]
    async fn test_bulkhead_concurrent_limit() {
        let config = BulkheadConfig {
            max_concurrent: 2,
            max_queue: 10,
            acquire_timeout: Duration::from_millis(100),
        };
        let bulkhead = Arc::new(Bulkhead::new(config));

        // Start 2 operations that will block
        let bulkhead1 = bulkhead.clone();
        let bulkhead2 = bulkhead.clone();

        let handle1 = tokio::spawn(async move {
            bulkhead1
                .execute(async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    1
                })
                .await
        });

        let handle2 = tokio::spawn(async move {
            bulkhead2
                .execute(async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    2
                })
                .await
        });

        // Wait a bit for the operations to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Try a third operation - should timeout
        let result = bulkhead.execute(async { 3 }).await;

        assert!(result.is_err());

        // Clean up
        let _ = handle1.await;
        let _ = handle2.await;
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let degradation = GracefulDegradation::new();

        assert_eq!(degradation.level().await, DegradationLevel::None);

        degradation
            .register_feature("premium_feature", DegradationLevel::None)
            .await;
        degradation
            .register_feature("standard_feature", DegradationLevel::Moderate)
            .await;

        assert!(degradation.is_feature_available("premium_feature").await);
        assert!(degradation.is_feature_available("standard_feature").await);

        degradation.set_level(DegradationLevel::Severe).await;

        assert!(!degradation.is_feature_available("premium_feature").await);
        assert!(!degradation.is_feature_available("standard_feature").await);
    }

    #[tokio::test]
    async fn test_chaos_engineer_disabled() {
        let config = ChaosConfig::default();
        let chaos = ChaosEngineer::new(config);

        let fault = chaos.maybe_inject_fault().await;
        assert!(fault.is_none());
    }

    #[tokio::test]
    async fn test_chaos_engineer_enabled() {
        let config = ChaosConfig {
            enabled: true,
            fault_probability: 1.0,
            faults: vec![ChaosFault::Failure {
                message: "test failure".to_string(),
            }],
        };
        let chaos = ChaosEngineer::new(config);

        let result = chaos.execute(async { Ok::<_, String>(42) }).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_degradation_level_ordering() {
        assert!(DegradationLevel::None < DegradationLevel::Minor);
        assert!(DegradationLevel::Minor < DegradationLevel::Moderate);
        assert!(DegradationLevel::Moderate < DegradationLevel::Severe);
        assert!(DegradationLevel::Severe < DegradationLevel::Critical);
    }

    #[tokio::test]
    async fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert!(policy.attempt_timeout.is_some());
    }

    #[tokio::test]
    async fn test_bulkhead_stats() {
        let config = BulkheadConfig::default();
        let bulkhead = Bulkhead::new(config);

        let _ = bulkhead.execute(async { 1 }).await;
        let _ = bulkhead.execute(async { 2 }).await;

        let stats = bulkhead.stats().await;
        assert_eq!(stats.total_operations, 2);
        assert_eq!(stats.successful_operations, 2);
    }
}
