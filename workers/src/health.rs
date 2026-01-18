//! Worker health checks and monitoring.
//!
//! This module provides:
//! - Health check endpoints for load balancers
//! - Liveness and readiness probes
//! - Service dependency checks
//! - Graceful shutdown handling

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn};

/// Health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy.
    Healthy,
    /// Service is degraded but functional.
    Degraded,
    /// Service is unhealthy.
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Overall status.
    pub status: HealthStatus,
    /// Individual component checks.
    pub components: HashMap<String, ComponentHealth>,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Version string.
    pub version: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Individual component health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,
    /// Component status.
    pub status: HealthStatus,
    /// Response time (ms).
    pub response_time_ms: Option<u64>,
    /// Error message if unhealthy.
    pub error: Option<String>,
    /// Last checked.
    pub last_check: chrono::DateTime<chrono::Utc>,
}

/// Health checker for workers.
pub struct HealthChecker {
    /// Start time.
    start_time: Instant,
    /// Version string.
    version: String,
    /// Component checkers.
    checkers: Arc<RwLock<HashMap<String, CheckFn>>>,
    /// Cached results.
    cache: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    /// Cache TTL.
    #[allow(dead_code)]
    cache_ttl: Duration,
    /// Last full check.
    #[allow(dead_code)]
    last_check: Arc<RwLock<Instant>>,
}

/// Type alias for async health check function.
pub type CheckFn =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = ComponentHealth> + Send>> + Send + Sync>;

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            start_time: Instant::now(),
            version: version.into(),
            checkers: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(10),
            last_check: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Register a component checker function.
    pub async fn register(&self, name: impl Into<String>, checker: CheckFn) {
        let mut checkers = self.checkers.write().await;
        checkers.insert(name.into(), checker);
    }

    /// Perform a full health check.
    pub async fn check(&self) -> HealthCheck {
        let checkers = self.checkers.read().await;
        let mut components = HashMap::new();
        let mut overall_status = HealthStatus::Healthy;

        for (name, checker) in checkers.iter() {
            let result = checker().await;

            // Update overall status
            match result.status {
                HealthStatus::Unhealthy => overall_status = HealthStatus::Unhealthy,
                HealthStatus::Degraded if overall_status == HealthStatus::Healthy => {
                    overall_status = HealthStatus::Degraded;
                }
                _ => {}
            }

            components.insert(name.clone(), result);
        }

        // Update cache
        {
            let mut cache = self.cache.write().await;
            *cache = components.clone();
        }
        {
            let mut last = self.last_check.write().await;
            *last = Instant::now();
        }

        HealthCheck {
            status: overall_status,
            components,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: self.version.clone(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Quick liveness check (is the process running?).
    pub fn liveness(&self) -> bool {
        true // If we can respond, we're alive
    }

    /// Readiness check (is the service ready to accept traffic?).
    pub async fn readiness(&self) -> bool {
        let cache = self.cache.read().await;

        // Ready if all components are healthy or degraded
        cache.values().all(|c| c.status != HealthStatus::Unhealthy)
    }

    /// Get uptime in seconds.
    pub fn uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

/// Create a Redis health checker function.
pub fn redis_checker(url: impl Into<String>) -> CheckFn {
    let url = url.into();
    Box::new(move || {
        let url = url.clone();
        Box::pin(async move {
            let start = Instant::now();

            match redis::Client::open(url.as_str()) {
                Ok(client) => match client.get_multiplexed_async_connection().await {
                    Ok(mut conn) => {
                        match redis::cmd("PING").query_async::<String>(&mut conn).await {
                            Ok(_) => ComponentHealth {
                                name: "redis".to_string(),
                                status: HealthStatus::Healthy,
                                response_time_ms: Some(start.elapsed().as_millis() as u64),
                                error: None,
                                last_check: chrono::Utc::now(),
                            },
                            Err(e) => ComponentHealth {
                                name: "redis".to_string(),
                                status: HealthStatus::Unhealthy,
                                response_time_ms: Some(start.elapsed().as_millis() as u64),
                                error: Some(e.to_string()),
                                last_check: chrono::Utc::now(),
                            },
                        }
                    }
                    Err(e) => ComponentHealth {
                        name: "redis".to_string(),
                        status: HealthStatus::Unhealthy,
                        response_time_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some(e.to_string()),
                        last_check: chrono::Utc::now(),
                    },
                },
                Err(e) => ComponentHealth {
                    name: "redis".to_string(),
                    status: HealthStatus::Unhealthy,
                    response_time_ms: None,
                    error: Some(e.to_string()),
                    last_check: chrono::Utc::now(),
                },
            }
        })
    })
}

/// Graceful shutdown handler.
pub struct GracefulShutdown {
    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,
    /// Whether shutdown has been requested.
    shutdown_requested: Arc<AtomicBool>,
    /// Number of active tasks.
    active_tasks: Arc<AtomicU64>,
    /// Shutdown timeout.
    timeout: Duration,
}

impl GracefulShutdown {
    /// Create a new graceful shutdown handler.
    pub fn new(timeout: Duration) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            shutdown_tx,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            active_tasks: Arc::new(AtomicU64::new(0)),
            timeout,
        }
    }

    /// Subscribe to shutdown signals.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Check if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Register a task as active.
    pub fn register_task(&self) -> TaskGuard {
        self.active_tasks.fetch_add(1, Ordering::SeqCst);
        TaskGuard {
            active_tasks: Arc::clone(&self.active_tasks),
        }
    }

    /// Get the number of active tasks.
    pub fn active_task_count(&self) -> u64 {
        self.active_tasks.load(Ordering::SeqCst)
    }

    /// Request shutdown.
    pub async fn shutdown(&self) {
        if self.shutdown_requested.swap(true, Ordering::SeqCst) {
            // Already shutting down
            return;
        }

        info!("Graceful shutdown requested");

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for active tasks to complete
        let deadline = Instant::now() + self.timeout;

        while self.active_tasks.load(Ordering::SeqCst) > 0 {
            if Instant::now() > deadline {
                let remaining = self.active_tasks.load(Ordering::SeqCst);
                warn!(
                    "Shutdown timeout reached with {} tasks still active",
                    remaining
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("Graceful shutdown complete");
    }

    /// Setup signal handlers for SIGTERM and SIGINT.
    pub async fn wait_for_signal(&self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");
            let mut sigint =
                signal(SignalKind::interrupt()).expect("Failed to setup SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to setup Ctrl-C handler");
            info!("Received Ctrl-C");
        }

        self.shutdown().await;
    }
}

/// Guard that decrements active task count when dropped.
pub struct TaskGuard {
    active_tasks: Arc<AtomicU64>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.active_tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Worker metrics for health monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerMetrics {
    /// Jobs processed successfully.
    pub jobs_completed: u64,
    /// Jobs failed.
    pub jobs_failed: u64,
    /// Jobs currently processing.
    pub jobs_in_progress: u64,
    /// Average job duration (ms).
    pub avg_job_duration_ms: f64,
    /// Current queue depth.
    pub queue_depth: u64,
    /// Last heartbeat.
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
}

impl WorkerMetrics {
    /// Create new worker metrics.
    pub fn new() -> Self {
        Self {
            last_heartbeat: chrono::Utc::now(),
            ..Default::default()
        }
    }

    /// Update heartbeat.
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = chrono::Utc::now();
    }

    /// Record a completed job.
    pub fn record_completion(&mut self, duration_ms: u64) {
        let n = self.jobs_completed as f64;
        self.avg_job_duration_ms = (self.avg_job_duration_ms * n + duration_ms as f64) / (n + 1.0);
        self.jobs_completed += 1;
    }

    /// Record a failed job.
    pub fn record_failure(&mut self) {
        self.jobs_failed += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[tokio::test]
    async fn test_health_checker() {
        let checker = HealthChecker::new("1.0.0");

        let health = checker.check().await;
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(checker.liveness());
        assert!(checker.readiness().await);
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let shutdown = GracefulShutdown::new(Duration::from_secs(5));

        // Register a task
        let guard = shutdown.register_task();
        assert_eq!(shutdown.active_task_count(), 1);

        // Drop the guard
        drop(guard);
        assert_eq!(shutdown.active_task_count(), 0);
    }

    #[test]
    fn test_worker_metrics() {
        let mut metrics = WorkerMetrics::new();

        metrics.record_completion(100);
        metrics.record_completion(200);

        assert_eq!(metrics.jobs_completed, 2);
        assert_eq!(metrics.avg_job_duration_ms, 150.0);
    }
}
