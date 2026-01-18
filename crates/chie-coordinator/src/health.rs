//! Enhanced health check system with component status monitoring.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::AppState;

/// Overall system health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All components healthy.
    Healthy,
    /// Some components degraded but system operational.
    Degraded,
    /// Critical components down.
    Unhealthy,
}

/// Individual component health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentStatus {
    /// Component is operational.
    Up,
    /// Component is degraded.
    Degraded,
    /// Component is down.
    Down,
}

/// Health check response with detailed component status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall system status.
    pub status: HealthStatus,
    /// Timestamp of the health check.
    pub timestamp: String,
    /// Individual component statuses.
    pub components: ComponentHealths,
    /// Additional system information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<SystemInfo>,
}

/// Component health statuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealths {
    /// Database connection status.
    pub database: ComponentHealth,
    /// Redis connection status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<ComponentHealth>,
    /// WebSocket hub status.
    pub websocket: ComponentHealth,
    /// Verification service status.
    pub verification: ComponentHealth,
    /// Reward engine status.
    pub rewards: ComponentHealth,
}

/// Individual component health details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status.
    pub status: ComponentStatus,
    /// Response time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
    /// Error message if component is down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Additional system information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Service version.
    pub version: String,
    /// Service name.
    pub service: String,
    /// Environment.
    pub environment: String,
}

impl IntoResponse for HealthCheckResponse {
    fn into_response(self) -> Response {
        let status_code = match self.status {
            HealthStatus::Healthy => StatusCode::OK,
            HealthStatus::Degraded => StatusCode::OK,
            HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        };

        (status_code, Json(self)).into_response()
    }
}

/// Basic health check endpoint (lightweight).
pub async fn health_check_simple() -> &'static str {
    "OK"
}

/// Detailed health check with all component statuses.
pub async fn health_check_detailed(State(state): State<AppState>) -> HealthCheckResponse {
    let start = Instant::now();

    // Check database
    let db_health = check_database(&state).await;

    // Check Redis (optional)
    let redis_health = check_redis().await;

    // Check WebSocket hub
    let ws_health = check_websocket(&state);

    // Check verification service
    let verification_health = check_verification();

    // Check reward engine
    let rewards_health = check_rewards();

    // Determine overall status
    let overall_status = calculate_overall_status(&[
        db_health.status,
        redis_health
            .as_ref()
            .map_or(ComponentStatus::Up, |h| h.status),
        ws_health.status,
        verification_health.status,
        rewards_health.status,
    ]);

    let elapsed = start.elapsed().as_millis() as u64;

    tracing::debug!(
        "Health check completed in {}ms, status: {:?}",
        elapsed,
        overall_status
    );

    HealthCheckResponse {
        status: overall_status,
        timestamp: chrono::Utc::now().to_rfc3339(),
        components: ComponentHealths {
            database: db_health,
            redis: redis_health,
            websocket: ws_health,
            verification: verification_health,
            rewards: rewards_health,
        },
        info: Some(SystemInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            service: "chie-coordinator".to_string(),
            environment: std::env::var("ENV").unwrap_or_else(|_| "development".to_string()),
        }),
    }
}

/// Database health check endpoint.
pub async fn health_check_db(
    State(state): State<AppState>,
) -> Result<&'static str, (StatusCode, String)> {
    let health = check_database(&state).await;

    match health.status {
        ComponentStatus::Up => Ok("DB OK"),
        ComponentStatus::Degraded => Ok("DB DEGRADED"),
        ComponentStatus::Down => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            health.error.unwrap_or_else(|| "Database error".to_string()),
        )),
    }
}

// ============================================================================
// Internal health check functions
// ============================================================================

async fn check_database(state: &AppState) -> ComponentHealth {
    let start = Instant::now();

    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => {
            let response_time = start.elapsed().as_millis() as u64;
            ComponentHealth {
                status: if response_time > 1000 {
                    ComponentStatus::Degraded
                } else {
                    ComponentStatus::Up
                },
                response_time_ms: Some(response_time),
                error: None,
            }
        }
        Err(e) => ComponentHealth {
            status: ComponentStatus::Down,
            response_time_ms: Some(start.elapsed().as_millis() as u64),
            error: Some(e.to_string()),
        },
    }
}

async fn check_redis() -> Option<ComponentHealth> {
    // Redis is optional, so we return None if not configured
    // In a real implementation, you'd check the Redis connection here
    if std::env::var("REDIS_ENABLED").is_ok() {
        Some(ComponentHealth {
            status: ComponentStatus::Up,
            response_time_ms: Some(0),
            error: None,
        })
    } else {
        None
    }
}

fn check_websocket(_state: &AppState) -> ComponentHealth {
    // Check if WebSocket hub is operational
    // Note: We can't easily check client count synchronously,
    // but if the server is running, the WS hub is operational

    ComponentHealth {
        status: ComponentStatus::Up,
        response_time_ms: Some(0),
        error: None,
    }
}

fn check_verification() -> ComponentHealth {
    // Verification service is always up if the server is running
    ComponentHealth {
        status: ComponentStatus::Up,
        response_time_ms: Some(0),
        error: None,
    }
}

fn check_rewards() -> ComponentHealth {
    // Reward engine is always up if the server is running
    ComponentHealth {
        status: ComponentStatus::Up,
        response_time_ms: Some(0),
        error: None,
    }
}

fn calculate_overall_status(component_statuses: &[ComponentStatus]) -> HealthStatus {
    let down_count = component_statuses
        .iter()
        .filter(|&&s| s == ComponentStatus::Down)
        .count();
    let degraded_count = component_statuses
        .iter()
        .filter(|&&s| s == ComponentStatus::Degraded)
        .count();

    if down_count > 0 {
        HealthStatus::Unhealthy
    } else if degraded_count > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus::Healthy;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""healthy""#);
    }

    #[test]
    fn test_component_status_serialization() {
        let status = ComponentStatus::Up;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""up""#);
    }

    #[test]
    fn test_calculate_overall_status_all_up() {
        let statuses = vec![
            ComponentStatus::Up,
            ComponentStatus::Up,
            ComponentStatus::Up,
        ];
        assert_eq!(calculate_overall_status(&statuses), HealthStatus::Healthy);
    }

    #[test]
    fn test_calculate_overall_status_degraded() {
        let statuses = vec![
            ComponentStatus::Up,
            ComponentStatus::Degraded,
            ComponentStatus::Up,
        ];
        assert_eq!(calculate_overall_status(&statuses), HealthStatus::Degraded);
    }

    #[test]
    fn test_calculate_overall_status_down() {
        let statuses = vec![
            ComponentStatus::Up,
            ComponentStatus::Down,
            ComponentStatus::Up,
        ];
        assert_eq!(calculate_overall_status(&statuses), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_component_health_with_error() {
        let health = ComponentHealth {
            status: ComponentStatus::Down,
            response_time_ms: Some(500),
            error: Some("Connection failed".to_string()),
        };

        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("down"));
        assert!(json.contains("Connection failed"));
    }
}
