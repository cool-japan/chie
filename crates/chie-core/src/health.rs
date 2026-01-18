//! Health check system for monitoring node components.
//!
//! Provides a comprehensive health monitoring system for tracking the status
//! of various node components and subsystems.
//!
//! # Example
//!
//! ```
//! use chie_core::health::{HealthChecker, HealthStatus};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut checker = HealthChecker::new();
//!
//! // Register health checks
//! checker.register("storage", Box::new(|| async {
//!     // Check storage health
//!     Ok(HealthStatus::Healthy)
//! })).await;
//!
//! // Run all health checks
//! let report = checker.check_all().await;
//! println!("Overall health: {:?}", report.overall_status());
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Health status of a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Component is healthy and functioning normally
    Healthy,
    /// Component is degraded but still functional
    Degraded,
    /// Component is unhealthy and not functioning
    Unhealthy,
}

impl HealthStatus {
    /// Get a numeric score for the health status (higher is better).
    #[must_use]
    pub const fn score(&self) -> u8 {
        match self {
            Self::Healthy => 2,
            Self::Degraded => 1,
            Self::Unhealthy => 0,
        }
    }
}

/// Health check result for a component.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Component name
    pub component: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message providing additional context
    pub message: Option<String>,
    /// Time taken to perform the check
    pub check_duration: Duration,
    /// Timestamp when the check was performed
    pub timestamp: Instant,
}

impl HealthCheckResult {
    /// Create a new health check result.
    pub fn new(component: String, status: HealthStatus) -> Self {
        Self {
            component,
            status,
            message: None,
            check_duration: Duration::ZERO,
            timestamp: Instant::now(),
        }
    }

    /// Add a message to the health check result.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Set the check duration.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.check_duration = duration;
        self
    }
}

/// Type alias for health check functions.
type HealthCheckFn = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<HealthStatus, String>> + Send>> + Send + Sync,
>;

/// Health checker for monitoring node components.
pub struct HealthChecker {
    checks: Arc<RwLock<HashMap<String, HealthCheckFn>>>,
}

impl HealthChecker {
    /// Create a new health checker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a health check for a component.
    pub async fn register<F, Fut>(&mut self, component: impl Into<String>, check: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HealthStatus, String>> + Send + 'static,
    {
        let component_name = component.into();
        let check_fn: HealthCheckFn = Box::new(move || Box::pin(check()));
        self.checks.write().await.insert(component_name, check_fn);
    }

    /// Unregister a health check.
    pub async fn unregister(&mut self, component: &str) -> bool {
        self.checks.write().await.remove(component).is_some()
    }

    /// Run a single health check.
    pub async fn check(&self, component: &str) -> Option<HealthCheckResult> {
        let checks = self.checks.read().await;
        let check_fn = checks.get(component)?;

        let start = Instant::now();
        let result = check_fn().await;
        let duration = start.elapsed();

        let (status, message) = match result {
            Ok(status) => (status, None),
            Err(msg) => (HealthStatus::Unhealthy, Some(msg)),
        };

        Some(
            HealthCheckResult::new(component.to_string(), status)
                .with_duration(duration)
                .with_message(message.unwrap_or_default()),
        )
    }

    /// Run all registered health checks.
    pub async fn check_all(&self) -> HealthReport {
        let checks = self.checks.read().await;
        let mut results = Vec::new();

        for component in checks.keys() {
            if let Some(result) = self.check(component).await {
                results.push(result);
            }
        }

        HealthReport { results }
    }

    /// Get the number of registered health checks.
    #[must_use]
    pub async fn count(&self) -> usize {
        self.checks.read().await.len()
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Health report containing results from multiple checks.
#[derive(Debug, Clone)]
pub struct HealthReport {
    results: Vec<HealthCheckResult>,
}

impl HealthReport {
    /// Get all health check results.
    #[must_use]
    #[inline]
    pub fn results(&self) -> &[HealthCheckResult] {
        &self.results
    }

    /// Get the overall health status.
    #[must_use]
    #[inline]
    pub fn overall_status(&self) -> HealthStatus {
        if self.results.is_empty() {
            return HealthStatus::Healthy;
        }

        // If any component is unhealthy, overall is unhealthy
        if self
            .results
            .iter()
            .any(|r| r.status == HealthStatus::Unhealthy)
        {
            return HealthStatus::Unhealthy;
        }

        // If any component is degraded, overall is degraded
        if self
            .results
            .iter()
            .any(|r| r.status == HealthStatus::Degraded)
        {
            return HealthStatus::Degraded;
        }

        HealthStatus::Healthy
    }

    /// Get the number of healthy components.
    #[must_use]
    #[inline]
    pub fn healthy_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == HealthStatus::Healthy)
            .count()
    }

    /// Get the number of degraded components.
    #[must_use]
    #[inline]
    pub fn degraded_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == HealthStatus::Degraded)
            .count()
    }

    /// Get the number of unhealthy components.
    #[must_use]
    #[inline]
    pub fn unhealthy_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.status == HealthStatus::Unhealthy)
            .count()
    }

    /// Get total check duration across all components.
    #[must_use]
    #[inline]
    pub fn total_duration(&self) -> Duration {
        self.results.iter().map(|r| r.check_duration).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_score() {
        assert_eq!(HealthStatus::Healthy.score(), 2);
        assert_eq!(HealthStatus::Degraded.score(), 1);
        assert_eq!(HealthStatus::Unhealthy.score(), 0);
    }

    #[test]
    fn test_health_check_result() {
        let result = HealthCheckResult::new("storage".to_string(), HealthStatus::Healthy)
            .with_message("All systems operational");

        assert_eq!(result.component, "storage");
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.message, Some("All systems operational".to_string()));
    }

    #[tokio::test]
    async fn test_health_checker_register() {
        let mut checker = HealthChecker::new();

        checker
            .register("test", || async { Ok(HealthStatus::Healthy) })
            .await;

        assert_eq!(checker.count().await, 1);
    }

    #[tokio::test]
    async fn test_health_checker_unregister() {
        let mut checker = HealthChecker::new();

        checker
            .register("test", || async { Ok(HealthStatus::Healthy) })
            .await;

        assert!(checker.unregister("test").await);
        assert_eq!(checker.count().await, 0);
        assert!(!checker.unregister("nonexistent").await);
    }

    #[tokio::test]
    async fn test_health_checker_check() {
        let mut checker = HealthChecker::new();

        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;

        let result = checker.check("storage").await;
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.component, "storage");
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_checker_check_all() {
        let mut checker = HealthChecker::new();

        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;

        checker
            .register("network", || async { Ok(HealthStatus::Degraded) })
            .await;

        checker
            .register("database", || async {
                Err("Connection failed".to_string())
            })
            .await;

        let report = checker.check_all().await;
        assert_eq!(report.results().len(), 3);
        assert_eq!(report.healthy_count(), 1);
        assert_eq!(report.degraded_count(), 1);
        assert_eq!(report.unhealthy_count(), 1);
        assert_eq!(report.overall_status(), HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_report_overall_status() {
        let mut checker = HealthChecker::new();

        // All healthy
        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;
        checker
            .register("network", || async { Ok(HealthStatus::Healthy) })
            .await;

        let report = checker.check_all().await;
        assert_eq!(report.overall_status(), HealthStatus::Healthy);

        // One degraded
        let mut checker = HealthChecker::new();
        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;
        checker
            .register("network", || async { Ok(HealthStatus::Degraded) })
            .await;

        let report = checker.check_all().await;
        assert_eq!(report.overall_status(), HealthStatus::Degraded);

        // One unhealthy
        let mut checker = HealthChecker::new();
        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;
        checker
            .register("network", || async { Ok(HealthStatus::Unhealthy) })
            .await;

        let report = checker.check_all().await;
        assert_eq!(report.overall_status(), HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_health_report_empty() {
        let checker = HealthChecker::new();
        let report = checker.check_all().await;

        assert_eq!(report.results().len(), 0);
        assert_eq!(report.overall_status(), HealthStatus::Healthy);
        assert_eq!(report.total_duration(), Duration::ZERO);
    }
}
