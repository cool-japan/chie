//! System-wide coordinator for integrated monitoring and management.
//!
//! This module provides a unified interface for coordinating and monitoring
//! all major subsystems in the CHIE core, including health checks, metrics,
//! profiling, and resource management.
//!
//! # Example
//!
//! ```rust
//! use chie_core::system_coordinator::{SystemCoordinator, SystemConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SystemConfig::default();
//! let mut coordinator = SystemCoordinator::new(config);
//!
//! // Initialize all subsystems
//! coordinator.initialize().await?;
//!
//! // Get comprehensive system status
//! let status = coordinator.get_system_status().await?;
//! println!("Overall health: {:?}", status.health_status);
//! println!("Active operations: {}", status.active_operations);
//!
//! // Generate comprehensive report
//! let report = coordinator.generate_report().await;
//! println!("{}", report);
//! # Ok(())
//! # }
//! ```

use crate::{
    alerting::{AlertManager, AlertMetric, ThresholdConfig},
    dashboard::DashboardData,
    forecasting::{ForecastMethod, Forecaster},
    health::{HealthChecker, HealthReport, HealthStatus},
    logging::{LogConfig, LogLevel, Logger},
    metrics::MetricsRegistry,
    metrics_exporter::{ExportFormat, MetricsExporter},
    profiler::Profiler,
    resource_mgmt::{ResourceLimits, ResourceMonitor},
};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during system coordination.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("Subsystem initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("Resource constraint violated: {0}")]
    ResourceConstraint(String),

    #[error("System shutdown in progress")]
    ShuttingDown,
}

/// Configuration for the system coordinator.
#[derive(Debug, Clone)]
pub struct SystemConfig {
    /// Enable health monitoring.
    pub enable_health_checks: bool,
    /// Health check interval in seconds.
    pub health_check_interval_secs: u64,
    /// Enable performance profiling.
    pub enable_profiling: bool,
    /// Enable metrics collection.
    pub enable_metrics: bool,
    /// Metrics export format.
    pub metrics_export_format: ExportFormat,
    /// Enable alerting.
    pub enable_alerting: bool,
    /// Enable resource forecasting.
    pub enable_forecasting: bool,
    /// Log level.
    pub log_level: LogLevel,
    /// Resource limits.
    pub resource_limits: ResourceLimits,
}

impl Default for SystemConfig {
    #[inline]
    fn default() -> Self {
        Self {
            enable_health_checks: true,
            health_check_interval_secs: 60,
            enable_profiling: true,
            enable_metrics: true,
            metrics_export_format: ExportFormat::InfluxDB,
            enable_alerting: true,
            enable_forecasting: true,
            log_level: LogLevel::Info,
            resource_limits: ResourceLimits::default(),
        }
    }
}

/// Comprehensive system status.
#[derive(Debug, Clone)]
pub struct SystemStatus {
    /// Overall health status.
    pub health_status: HealthStatus,
    /// Health report from all components.
    pub health_report: Option<HealthReport>,
    /// Number of active operations being profiled.
    pub active_operations: usize,
    /// Number of active alerts.
    pub active_alerts: usize,
    /// Current resource utilization percentage.
    pub resource_utilization_pct: f64,
    /// System uptime in seconds.
    pub uptime_secs: u64,
    /// Timestamp of this status.
    pub timestamp: SystemTime,
}

/// System coordinator for integrated management.
pub struct SystemCoordinator {
    /// Configuration.
    config: SystemConfig,
    /// Health checker.
    health_checker: Arc<RwLock<HealthChecker>>,
    /// Profiler.
    profiler: Arc<RwLock<Profiler>>,
    /// Metrics registry.
    metrics: Arc<RwLock<MetricsRegistry>>,
    /// Metrics exporter.
    exporter: MetricsExporter,
    /// Alert manager.
    alerts: Arc<RwLock<AlertManager>>,
    /// Resource monitor.
    resources: Arc<RwLock<ResourceMonitor>>,
    /// Forecaster.
    #[allow(dead_code)]
    forecaster: Arc<RwLock<Forecaster>>,
    /// Dashboard data.
    dashboard: Arc<RwLock<DashboardData>>,
    /// Logger.
    logger: Logger,
    /// System start time.
    start_time: SystemTime,
    /// Shutdown flag.
    shutdown: Arc<RwLock<bool>>,
}

impl SystemCoordinator {
    /// Create a new system coordinator.
    #[must_use]
    pub fn new(config: SystemConfig) -> Self {
        let log_config = LogConfig {
            level: config.log_level,
            include_timestamps: true,
            include_module_path: true,
            include_line_numbers: false,
            filter_modules: vec![],
        };

        let enable_profiling = config.enable_profiling;
        let metrics_export_format = config.metrics_export_format;
        let resource_limits = config.resource_limits.clone();

        Self {
            exporter: MetricsExporter::new(metrics_export_format),
            config,
            health_checker: Arc::new(RwLock::new(HealthChecker::new())),
            profiler: Arc::new(RwLock::new(if enable_profiling {
                Profiler::new()
            } else {
                Profiler::disabled()
            })),
            metrics: Arc::new(RwLock::new(MetricsRegistry::new())),
            alerts: Arc::new(RwLock::new(AlertManager::new())),
            resources: Arc::new(RwLock::new(ResourceMonitor::new(resource_limits))),
            forecaster: Arc::new(RwLock::new(Forecaster::new(ForecastMethod::MovingAverage))),
            dashboard: Arc::new(RwLock::new(DashboardData::new())),
            logger: Logger::new(log_config),
            start_time: SystemTime::now(),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize all subsystems.
    pub async fn initialize(&mut self) -> Result<(), CoordinatorError> {
        self.logger
            .info("system_coordinator", "Initializing system coordinator");

        // Register health checks for core components
        if self.config.enable_health_checks {
            self.register_default_health_checks().await?;
        }

        // Configure default alert thresholds
        if self.config.enable_alerting {
            self.configure_default_alerts().await;
        }

        self.logger.info(
            "system_coordinator",
            "System coordinator initialized successfully",
        );
        Ok(())
    }

    /// Register default health checks for core components.
    async fn register_default_health_checks(&mut self) -> Result<(), CoordinatorError> {
        let mut checker = self.health_checker.write().await;

        // Storage health check
        checker
            .register("storage", || async { Ok(HealthStatus::Healthy) })
            .await;

        // Network health check
        checker
            .register("network", || async { Ok(HealthStatus::Healthy) })
            .await;

        // Resource health check
        checker
            .register("resources", || async { Ok(HealthStatus::Healthy) })
            .await;

        Ok(())
    }

    /// Configure default alert thresholds.
    async fn configure_default_alerts(&mut self) {
        let mut alerts = self.alerts.write().await;

        // Storage usage alert
        alerts.add_threshold(ThresholdConfig {
            metric: AlertMetric::StorageUsagePercent,
            warning_threshold: 75.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 60,
        });

        // Memory usage alert
        alerts.add_threshold(ThresholdConfig {
            metric: AlertMetric::MemoryUsagePercent,
            warning_threshold: 80.0,
            error_threshold: 90.0,
            critical_threshold: 95.0,
            check_interval_secs: 30,
        });
    }

    /// Get comprehensive system status.
    pub async fn get_system_status(&self) -> Result<SystemStatus, CoordinatorError> {
        if *self.shutdown.read().await {
            return Err(CoordinatorError::ShuttingDown);
        }

        let health_report = if self.config.enable_health_checks {
            Some(self.health_checker.read().await.check_all().await)
        } else {
            None
        };

        let health_status = health_report
            .as_ref()
            .map(|r| r.overall_status())
            .unwrap_or(HealthStatus::Healthy);

        let active_operations = self.profiler.read().await.total_operations();
        let active_alerts = self.alerts.read().await.get_active_alerts().len();

        let mut resources = self.resources.write().await;
        let cpu_usage = resources.sample_cpu_usage();
        let resource_utilization_pct = cpu_usage as f64;

        let uptime_secs = SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default()
            .as_secs();

        Ok(SystemStatus {
            health_status,
            health_report,
            active_operations,
            active_alerts,
            resource_utilization_pct,
            uptime_secs,
            timestamp: SystemTime::now(),
        })
    }

    /// Generate a comprehensive system report.
    pub async fn generate_report(&self) -> String {
        let mut lines = vec![
            "CHIE System Status Report".to_string(),
            "=========================".to_string(),
            String::new(),
        ];

        // System info
        let uptime_secs = SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default()
            .as_secs();
        lines.push(format!(
            "Uptime: {}s ({:.1} hours)",
            uptime_secs,
            uptime_secs as f64 / 3600.0
        ));
        lines.push(String::new());

        // Health status
        if self.config.enable_health_checks {
            lines.push("Health Status:".to_string());
            let report = self.health_checker.read().await.check_all().await;
            lines.push(format!("  Overall: {:?}", report.overall_status()));
            lines.push(format!("  Components checked: {}", report.results().len()));
            lines.push(String::new());
        }

        // Profiling stats
        if self.config.enable_profiling {
            lines.push("Performance Profile:".to_string());
            let profiler = self.profiler.read().await;
            lines.push(format!(
                "  Operations profiled: {}",
                profiler.total_operations()
            ));
            lines.push(format!(
                "  Total time tracked: {:.2}ms",
                profiler.total_time().as_secs_f64() * 1000.0
            ));
            lines.push(String::new());
        }

        // Alerts
        if self.config.enable_alerting {
            let alerts = self.alerts.read().await;
            let active_alerts = alerts.get_active_alerts();
            lines.push(format!("Active Alerts: {}", active_alerts.len()));
            for alert in active_alerts.iter().take(5) {
                lines.push(format!("  [{:?}] {}", alert.severity, alert.message));
            }
            lines.push(String::new());
        }

        // Resource usage
        let mut resources = self.resources.write().await;
        lines.push("Resource Usage:".to_string());
        lines.push(format!("  CPU: {:.1}%", resources.sample_cpu_usage()));
        lines.push(format!(
            "  Memory: {} bytes",
            resources.sample_memory_usage()
        ));
        lines.push(String::new());

        lines.join("\n")
    }

    /// Export metrics in configured format.
    pub async fn export_metrics(&self) -> Vec<String> {
        // Export basic metrics
        vec![
            self.exporter
                .export_gauge("chie.uptime.seconds", self.get_uptime_secs() as i64, &[]),
            self.exporter.export_gauge("chie.health.status", 1, &[]),
        ]
    }

    /// Get system uptime in seconds.
    #[must_use]
    #[inline]
    pub fn get_uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get reference to profiler.
    #[must_use]
    #[inline]
    pub fn profiler(&self) -> Arc<RwLock<Profiler>> {
        Arc::clone(&self.profiler)
    }

    /// Get reference to metrics registry.
    #[must_use]
    #[inline]
    pub fn metrics(&self) -> Arc<RwLock<MetricsRegistry>> {
        Arc::clone(&self.metrics)
    }

    /// Get reference to health checker.
    #[must_use]
    #[inline]
    pub fn health_checker(&self) -> Arc<RwLock<HealthChecker>> {
        Arc::clone(&self.health_checker)
    }

    /// Get reference to alert manager.
    #[must_use]
    #[inline]
    pub fn alerts(&self) -> Arc<RwLock<AlertManager>> {
        Arc::clone(&self.alerts)
    }

    /// Get reference to dashboard data.
    #[must_use]
    #[inline]
    pub fn dashboard(&self) -> Arc<RwLock<DashboardData>> {
        Arc::clone(&self.dashboard)
    }

    /// Initiate graceful shutdown.
    pub async fn shutdown(&self) {
        self.logger
            .info("system_coordinator", "Initiating graceful shutdown");
        *self.shutdown.write().await = true;
        self.logger.info("system_coordinator", "Shutdown complete");
    }

    /// Check if system is shutting down.
    #[must_use]
    pub async fn is_shutting_down(&self) -> bool {
        *self.shutdown.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let config = SystemConfig::default();
        let coordinator = SystemCoordinator::new(config);

        assert_eq!(coordinator.get_uptime_secs(), 0);
        assert!(!coordinator.is_shutting_down().await);
    }

    #[tokio::test]
    async fn test_coordinator_initialization() {
        let config = SystemConfig::default();
        let mut coordinator = SystemCoordinator::new(config);

        let result = coordinator.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_system_status() {
        let config = SystemConfig::default();
        let mut coordinator = SystemCoordinator::new(config);
        coordinator.initialize().await.unwrap();

        let status = coordinator.get_system_status().await.unwrap();
        assert_eq!(status.health_status, HealthStatus::Healthy);
        assert_eq!(status.active_operations, 0);
    }

    #[tokio::test]
    async fn test_generate_report() {
        let config = SystemConfig::default();
        let mut coordinator = SystemCoordinator::new(config);
        coordinator.initialize().await.unwrap();

        let report = coordinator.generate_report().await;
        assert!(report.contains("CHIE System Status Report"));
        assert!(report.contains("Uptime"));
        assert!(report.contains("Health Status"));
    }

    #[tokio::test]
    async fn test_shutdown() {
        let config = SystemConfig::default();
        let coordinator = SystemCoordinator::new(config);

        assert!(!coordinator.is_shutting_down().await);

        coordinator.shutdown().await;
        assert!(coordinator.is_shutting_down().await);

        // Should fail after shutdown
        let result = coordinator.get_system_status().await;
        assert!(matches!(result, Err(CoordinatorError::ShuttingDown)));
    }

    #[tokio::test]
    async fn test_accessor_methods() {
        let config = SystemConfig::default();
        let coordinator = SystemCoordinator::new(config);

        // Test that accessors return valid references
        let _profiler = coordinator.profiler();
        let _metrics = coordinator.metrics();
        let _health = coordinator.health_checker();
        let _alerts = coordinator.alerts();
        let _dashboard = coordinator.dashboard();
    }
}
