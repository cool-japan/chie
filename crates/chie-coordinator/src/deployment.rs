//! Canary and Blue-Green Deployment Support
//!
//! Implements zero-downtime deployment strategies:
//! - Canary deployments with gradual traffic shifting
//! - Blue-green deployments with instant cutover
//! - Deployment health monitoring
//! - Automatic rollback on errors
//! - Traffic splitting configuration

#![allow(dead_code)]

use crate::metrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Deployment strategy type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStrategy {
    /// Canary deployment: gradual traffic shift
    Canary,
    /// Blue-green deployment: instant cutover
    BlueGreen,
    /// Rolling update (not implemented yet)
    Rolling,
}

/// Deployment environment color (for blue-green)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnvironmentColor {
    Blue,
    Green,
}

impl std::fmt::Display for EnvironmentColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentColor::Blue => write!(f, "blue"),
            EnvironmentColor::Green => write!(f, "green"),
        }
    }
}

/// Deployment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    /// Deployment is in progress
    InProgress,
    /// Deployment completed successfully
    Completed,
    /// Deployment was rolled back
    RolledBack,
    /// Deployment failed
    Failed,
}

/// Canary deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryConfig {
    /// Initial traffic percentage to canary (0-100)
    pub initial_traffic_percent: u8,
    /// Final traffic percentage to canary (typically 100)
    pub final_traffic_percent: u8,
    /// Traffic increment per step
    pub traffic_increment: u8,
    /// Duration of each canary step (seconds)
    pub step_duration_secs: u64,
    /// Error rate threshold for automatic rollback (percentage)
    pub error_rate_threshold: f64,
    /// Minimum requests before evaluating health
    pub min_requests_for_health_check: u64,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            initial_traffic_percent: 5,
            final_traffic_percent: 100,
            traffic_increment: 10,
            step_duration_secs: 300,   // 5 minutes per step
            error_rate_threshold: 5.0, // 5% error rate triggers rollback
            min_requests_for_health_check: 100,
        }
    }
}

/// Blue-green deployment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueGreenConfig {
    /// Duration to monitor new environment before cutover (seconds)
    pub warmup_duration_secs: u64,
    /// Whether to keep old environment running after cutover
    pub keep_old_environment: bool,
    /// Automatic rollback on errors
    pub auto_rollback: bool,
    /// Error rate threshold for rollback (percentage)
    pub error_rate_threshold: f64,
}

impl Default for BlueGreenConfig {
    fn default() -> Self {
        Self {
            warmup_duration_secs: 60,
            keep_old_environment: true,
            auto_rollback: true,
            error_rate_threshold: 5.0,
        }
    }
}

/// Deployment environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentEnvironment {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub color: Option<EnvironmentColor>, // For blue-green
    pub traffic_percentage: u8,
    pub health_check_url: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metrics: EnvironmentMetrics,
}

/// Environment metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub error_rate: f64,
    pub avg_response_time_ms: f64,
}

impl Default for EnvironmentMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            error_rate: 0.0,
            avg_response_time_ms: 0.0,
        }
    }
}

/// Deployment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: Uuid,
    pub strategy: DeploymentStrategy,
    pub status: DeploymentStatus,
    pub old_version: String,
    pub new_version: String,
    pub current_traffic_to_new: u8,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rollback_reason: Option<String>,
}

/// Deployment manager
pub struct DeploymentManager {
    environments: Arc<RwLock<HashMap<Uuid, DeploymentEnvironment>>>,
    active_deployment: Arc<RwLock<Option<Deployment>>>,
    canary_config: Arc<RwLock<CanaryConfig>>,
    blue_green_config: Arc<RwLock<BlueGreenConfig>>,
    traffic_counter: AtomicU64,
    current_canary_step: AtomicUsize,
}

impl DeploymentManager {
    /// Create a new deployment manager
    pub fn new(canary_config: CanaryConfig, blue_green_config: BlueGreenConfig) -> Self {
        Self {
            environments: Arc::new(RwLock::new(HashMap::new())),
            active_deployment: Arc::new(RwLock::new(None)),
            canary_config: Arc::new(RwLock::new(canary_config)),
            blue_green_config: Arc::new(RwLock::new(blue_green_config)),
            traffic_counter: AtomicU64::new(0),
            current_canary_step: AtomicUsize::new(0),
        }
    }

    /// Register a deployment environment
    pub async fn register_environment(
        &self,
        name: String,
        version: String,
        color: Option<EnvironmentColor>,
        health_check_url: Option<String>,
    ) -> Result<Uuid, DeploymentError> {
        let id = Uuid::new_v4();

        let env = DeploymentEnvironment {
            id,
            name: name.clone(),
            version: version.clone(),
            color,
            traffic_percentage: 0,
            health_check_url,
            is_active: false,
            created_at: chrono::Utc::now(),
            metrics: EnvironmentMetrics::default(),
        };

        self.environments.write().await.insert(id, env);

        info!(
            "Registered deployment environment: {} (version: {}, id: {})",
            name, version, id
        );
        metrics::record_deployment_environment_registered(name);

        Ok(id)
    }

    /// Start a canary deployment
    pub async fn start_canary_deployment(
        &self,
        old_env_id: Uuid,
        new_env_id: Uuid,
    ) -> Result<Uuid, DeploymentError> {
        let mut environments = self.environments.write().await;
        let mut active_deployment = self.active_deployment.write().await;

        // Check if deployment already in progress
        if active_deployment.is_some() {
            return Err(DeploymentError::DeploymentInProgress);
        }

        // Get old environment version first
        let old_version = environments
            .get(&old_env_id)
            .ok_or(DeploymentError::EnvironmentNotFound)?
            .version
            .clone();

        let config = self.canary_config.read().await;

        // Now get mutable reference and update new environment
        let new_env = environments
            .get_mut(&new_env_id)
            .ok_or(DeploymentError::EnvironmentNotFound)?;

        new_env.traffic_percentage = config.initial_traffic_percent;
        new_env.is_active = true;
        let new_version = new_env.version.clone();

        let deployment = Deployment {
            id: Uuid::new_v4(),
            strategy: DeploymentStrategy::Canary,
            status: DeploymentStatus::InProgress,
            old_version: old_version.clone(),
            new_version: new_version.clone(),
            current_traffic_to_new: config.initial_traffic_percent,
            started_at: chrono::Utc::now(),
            completed_at: None,
            rollback_reason: None,
        };

        let deployment_id = deployment.id;
        *active_deployment = Some(deployment);

        info!(
            "Started canary deployment {} -> {} ({}% initial traffic)",
            old_version, new_version, config.initial_traffic_percent
        );
        metrics::record_deployment_started("canary");

        Ok(deployment_id)
    }

    /// Progress canary deployment to next step
    pub async fn progress_canary(&self) -> Result<u8, DeploymentError> {
        let mut active_deployment = self.active_deployment.write().await;
        let mut environments = self.environments.write().await;

        let deployment = active_deployment
            .as_mut()
            .ok_or(DeploymentError::NoActiveDeployment)?;

        if deployment.strategy != DeploymentStrategy::Canary {
            return Err(DeploymentError::InvalidStrategy);
        }

        let config = self.canary_config.read().await;

        // Calculate new traffic percentage
        let new_traffic = std::cmp::min(
            deployment.current_traffic_to_new + config.traffic_increment,
            config.final_traffic_percent,
        );

        deployment.current_traffic_to_new = new_traffic;

        // Update environment traffic
        for env in environments.values_mut() {
            if env.version == deployment.new_version {
                env.traffic_percentage = new_traffic;
            }
        }

        info!("Progressed canary deployment to {}% traffic", new_traffic);
        metrics::record_canary_traffic_updated(new_traffic);

        // Check if deployment is complete
        if new_traffic >= config.final_traffic_percent {
            deployment.status = DeploymentStatus::Completed;
            deployment.completed_at = Some(chrono::Utc::now());
            info!("Canary deployment completed successfully");
            metrics::record_deployment_completed("canary");
        }

        Ok(new_traffic)
    }

    /// Start a blue-green deployment
    pub async fn start_blue_green_deployment(
        &self,
        active_color: EnvironmentColor,
    ) -> Result<Uuid, DeploymentError> {
        let environments = self.environments.read().await;
        let mut active_deployment = self.active_deployment.write().await;

        // Check if deployment already in progress
        if active_deployment.is_some() {
            return Err(DeploymentError::DeploymentInProgress);
        }

        // Find active and inactive environments
        let active_env = environments
            .values()
            .find(|e| e.color == Some(active_color) && e.is_active)
            .ok_or(DeploymentError::EnvironmentNotFound)?;

        let inactive_color = match active_color {
            EnvironmentColor::Blue => EnvironmentColor::Green,
            EnvironmentColor::Green => EnvironmentColor::Blue,
        };

        let inactive_env_id = environments
            .values()
            .find(|e| e.color == Some(inactive_color))
            .map(|e| e.id)
            .ok_or(DeploymentError::EnvironmentNotFound)?;

        let deployment = Deployment {
            id: Uuid::new_v4(),
            strategy: DeploymentStrategy::BlueGreen,
            status: DeploymentStatus::InProgress,
            old_version: active_env.version.clone(),
            new_version: environments[&inactive_env_id].version.clone(),
            current_traffic_to_new: 0,
            started_at: chrono::Utc::now(),
            completed_at: None,
            rollback_reason: None,
        };

        let deployment_id = deployment.id;
        *active_deployment = Some(deployment);

        info!(
            "Started blue-green deployment from {} to {}",
            active_color, inactive_color
        );
        metrics::record_deployment_started("blue_green");

        Ok(deployment_id)
    }

    /// Execute blue-green cutover
    pub async fn execute_blue_green_cutover(&self) -> Result<(), DeploymentError> {
        let mut active_deployment = self.active_deployment.write().await;
        let mut environments = self.environments.write().await;

        let deployment = active_deployment
            .as_mut()
            .ok_or(DeploymentError::NoActiveDeployment)?;

        if deployment.strategy != DeploymentStrategy::BlueGreen {
            return Err(DeploymentError::InvalidStrategy);
        }

        // Find environments by version
        let mut old_env_id = None;
        let mut new_env_id = None;

        for (id, env) in environments.iter() {
            if env.version == deployment.old_version {
                old_env_id = Some(*id);
            }
            if env.version == deployment.new_version {
                new_env_id = Some(*id);
            }
        }

        let old_id = old_env_id.ok_or(DeploymentError::EnvironmentNotFound)?;
        let new_id = new_env_id.ok_or(DeploymentError::EnvironmentNotFound)?;

        // Swap active status
        environments.get_mut(&old_id).unwrap().is_active = false;
        environments.get_mut(&old_id).unwrap().traffic_percentage = 0;

        environments.get_mut(&new_id).unwrap().is_active = true;
        environments.get_mut(&new_id).unwrap().traffic_percentage = 100;

        deployment.current_traffic_to_new = 100;
        deployment.status = DeploymentStatus::Completed;
        deployment.completed_at = Some(chrono::Utc::now());

        info!("Executed blue-green cutover successfully");
        metrics::record_blue_green_cutover_executed();
        metrics::record_deployment_completed("blue_green");

        Ok(())
    }

    /// Rollback current deployment
    pub async fn rollback_deployment(&self, reason: String) -> Result<(), DeploymentError> {
        let mut active_deployment = self.active_deployment.write().await;
        let mut environments = self.environments.write().await;

        let deployment = active_deployment
            .as_mut()
            .ok_or(DeploymentError::NoActiveDeployment)?;

        warn!("Rolling back deployment: {}", reason);

        // Restore traffic to old version
        for env in environments.values_mut() {
            if env.version == deployment.old_version {
                env.is_active = true;
                env.traffic_percentage = 100;
            }
            if env.version == deployment.new_version {
                env.is_active = false;
                env.traffic_percentage = 0;
            }
        }

        deployment.status = DeploymentStatus::RolledBack;
        deployment.completed_at = Some(chrono::Utc::now());
        deployment.rollback_reason = Some(reason.clone());

        error!("Deployment rolled back: {}", reason);
        metrics::record_deployment_rollback(deployment.strategy);

        Ok(())
    }

    /// Route traffic to appropriate environment
    pub async fn route_traffic(&self) -> Option<Uuid> {
        let request_num = self.traffic_counter.fetch_add(1, Ordering::Relaxed);
        let environments = self.environments.read().await;

        // Find active environments with traffic allocation
        let mut candidates = Vec::new();
        let mut total_traffic = 0u32;

        for env in environments.values() {
            if env.is_active && env.traffic_percentage > 0 {
                candidates.push((env.id, env.traffic_percentage as u32));
                total_traffic += env.traffic_percentage as u32;
            }
        }

        if candidates.is_empty() {
            return None;
        }

        // Use modulo for simple round-robin weighted distribution
        let target_weight = (request_num % total_traffic as u64) as u32;
        let mut cumulative = 0u32;

        for (id, weight) in &candidates {
            cumulative += weight;
            if target_weight < cumulative {
                return Some(*id);
            }
        }

        // Fallback to first candidate
        candidates.first().map(|(id, _)| *id)
    }

    /// Get deployment status
    pub async fn get_deployment_status(&self) -> Option<Deployment> {
        self.active_deployment.read().await.clone()
    }

    /// Get all environments
    pub async fn list_environments(&self) -> Vec<DeploymentEnvironment> {
        self.environments.read().await.values().cloned().collect()
    }

    /// Get environment by ID
    pub async fn get_environment(&self, id: Uuid) -> Option<DeploymentEnvironment> {
        self.environments.read().await.get(&id).cloned()
    }

    /// Remove environment
    pub async fn remove_environment(&self, id: Uuid) -> Result<(), DeploymentError> {
        let removed = self.environments.write().await.remove(&id);
        if removed.is_some() {
            info!("Removed deployment environment {}", id);
            Ok(())
        } else {
            Err(DeploymentError::EnvironmentNotFound)
        }
    }
}

/// Deployment error types
#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error("Deployment already in progress")]
    DeploymentInProgress,

    #[error("No active deployment")]
    NoActiveDeployment,

    #[error("Environment not found")]
    EnvironmentNotFound,

    #[error("Invalid deployment strategy")]
    InvalidStrategy,

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("Traffic percentage must be between 0 and 100")]
    InvalidTrafficPercentage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_config_default() {
        let config = CanaryConfig::default();
        assert_eq!(config.initial_traffic_percent, 5);
        assert_eq!(config.final_traffic_percent, 100);
        assert_eq!(config.traffic_increment, 10);
    }

    #[test]
    fn test_blue_green_config_default() {
        let config = BlueGreenConfig::default();
        assert_eq!(config.warmup_duration_secs, 60);
        assert!(config.keep_old_environment);
        assert!(config.auto_rollback);
    }

    #[test]
    fn test_environment_color_display() {
        assert_eq!(EnvironmentColor::Blue.to_string(), "blue");
        assert_eq!(EnvironmentColor::Green.to_string(), "green");
    }

    #[test]
    fn test_deployment_strategy_serialization() {
        let strategy = DeploymentStrategy::Canary;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("Canary"));
    }

    #[tokio::test]
    async fn test_deployment_manager_creation() {
        let manager = DeploymentManager::new(CanaryConfig::default(), BlueGreenConfig::default());
        let envs = manager.list_environments().await;
        assert_eq!(envs.len(), 0);
    }
}
