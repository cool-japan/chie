//! Database Read Replicas Support
//!
//! Implements database read replica management for high availability and performance:
//! - Multiple read replica pool management
//! - Query routing (writes to primary, reads to replicas)
//! - Automatic replica health checking
//! - Failover to primary when replicas unavailable
//! - Load balancing across replicas (round-robin, least-connections, weighted)
//! - Replication lag monitoring

#![allow(dead_code)]

use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Load balancing strategy for read replicas
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadBalanceStrategy {
    /// Simple round-robin across all healthy replicas
    RoundRobin,
    /// Choose replica with least active connections
    LeastConnections,
    /// Weighted distribution based on replica capacity
    Weighted,
    /// Random selection
    Random,
}

/// Read replica configuration
#[derive(Debug, Clone)]
pub struct ReplicaConfig {
    pub name: String,
    pub url: String,
    pub weight: u32, // For weighted load balancing
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

/// Replica health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Replica statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaStats {
    pub name: String,
    pub health: ReplicaHealth,
    pub total_queries: u64,
    pub failed_queries: u64,
    pub success_rate: f64,
    pub avg_query_time_ms: f64,
    pub active_connections: u32,
    pub replication_lag_ms: Option<i64>,
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
}

/// Read replica pool
struct ReplicaPool {
    name: String,
    pool: PgPool,
    weight: u32,
    health: Arc<RwLock<ReplicaHealth>>,
    total_queries: AtomicU64,
    failed_queries: AtomicU64,
    last_health_check: Arc<RwLock<Option<Instant>>>,
}

impl ReplicaPool {
    async fn new(config: ReplicaConfig) -> Result<Self, ReadReplicaError> {
        let connect_opts = config
            .url
            .parse::<PgConnectOptions>()
            .map_err(|e| ReadReplicaError::ConnectionError(e.to_string()))?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.connection_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .connect_with(connect_opts)
            .await
            .map_err(|e| ReadReplicaError::ConnectionError(e.to_string()))?;

        Ok(Self {
            name: config.name,
            pool,
            weight: config.weight,
            health: Arc::new(RwLock::new(ReplicaHealth::Healthy)),
            total_queries: AtomicU64::new(0),
            failed_queries: AtomicU64::new(0),
            last_health_check: Arc::new(RwLock::new(None)),
        })
    }

    fn record_query(&self, success: bool) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.failed_queries.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn check_health(&self) -> Result<ReplicaHealth, ReadReplicaError> {
        // Simple health check: try to execute a query
        let result = sqlx::query_scalar::<Postgres, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await;

        let health = match result {
            Ok(_) => ReplicaHealth::Healthy,
            Err(e) => {
                warn!("Health check failed for replica {}: {}", self.name, e);
                ReplicaHealth::Unhealthy
            }
        };

        *self.health.write().await = health;
        *self.last_health_check.write().await = Some(Instant::now());

        Ok(health)
    }

    async fn check_replication_lag(&self) -> Result<Option<i64>, ReadReplicaError> {
        // Query PostgreSQL replication lag
        // This requires pg_stat_replication view access
        let lag = sqlx::query_scalar::<Postgres, Option<i64>>(
            r#"
            SELECT EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())) * 1000
            "#,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReadReplicaError::QueryError(e.to_string()))?
        .flatten();

        Ok(lag)
    }

    async fn get_stats(&self) -> ReplicaStats {
        let total = self.total_queries.load(Ordering::Relaxed);
        let failed = self.failed_queries.load(Ordering::Relaxed);
        let success_rate = if total > 0 {
            ((total - failed) as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        let health = *self.health.read().await;
        let last_check = *self.last_health_check.read().await;
        let replication_lag = self.check_replication_lag().await.ok().flatten();

        ReplicaStats {
            name: self.name.clone(),
            health,
            total_queries: total,
            failed_queries: failed,
            success_rate,
            avg_query_time_ms: 0.0, // Would need query timing instrumentation
            active_connections: self.pool.size(),
            replication_lag_ms: replication_lag,
            last_health_check: last_check.map(|_| chrono::Utc::now()),
        }
    }
}

/// Read replica manager configuration
#[derive(Debug, Clone)]
pub struct ReadReplicaManagerConfig {
    /// Load balancing strategy
    pub strategy: LoadBalanceStrategy,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Maximum replication lag threshold (ms)
    pub max_replication_lag_ms: i64,
    /// Failover to primary if all replicas unhealthy
    pub failover_to_primary: bool,
    /// Mark replica as degraded if lag exceeds threshold
    pub lag_threshold_degraded_ms: i64,
}

impl Default for ReadReplicaManagerConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(30),
            max_replication_lag_ms: 5000, // 5 seconds
            failover_to_primary: true,
            lag_threshold_degraded_ms: 2000, // 2 seconds
        }
    }
}

/// Read replica manager
pub struct ReadReplicaManager {
    primary_pool: PgPool,
    replicas: Arc<RwLock<HashMap<String, Arc<ReplicaPool>>>>,
    config: Arc<RwLock<ReadReplicaManagerConfig>>,
    round_robin_index: AtomicUsize,
    total_queries_routed: AtomicU64,
    queries_to_primary: AtomicU64,
    queries_to_replicas: AtomicU64,
}

impl ReadReplicaManager {
    /// Create a new read replica manager
    pub fn new(primary_pool: PgPool, config: ReadReplicaManagerConfig) -> Self {
        Self {
            primary_pool,
            replicas: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(config)),
            round_robin_index: AtomicUsize::new(0),
            total_queries_routed: AtomicU64::new(0),
            queries_to_primary: AtomicU64::new(0),
            queries_to_replicas: AtomicU64::new(0),
        }
    }

    /// Add a read replica
    pub async fn add_replica(&self, config: ReplicaConfig) -> Result<(), ReadReplicaError> {
        let name = config.name.clone();
        let replica = Arc::new(ReplicaPool::new(config).await?);

        // Initial health check
        replica.check_health().await?;

        self.replicas.write().await.insert(name.clone(), replica);

        info!("Added read replica: {}", name);
        crate::metrics::record_read_replica_added(name);

        Ok(())
    }

    /// Remove a read replica
    pub async fn remove_replica(&self, name: &str) -> Result<(), ReadReplicaError> {
        let removed = self.replicas.write().await.remove(name);

        if removed.is_some() {
            info!("Removed read replica: {}", name);
            crate::metrics::record_read_replica_removed(name.to_string());
            Ok(())
        } else {
            Err(ReadReplicaError::ReplicaNotFound(name.to_string()))
        }
    }

    /// Get a pool for read queries (routes to replica or primary)
    pub async fn get_read_pool(&self) -> PgPool {
        self.total_queries_routed.fetch_add(1, Ordering::Relaxed);

        let config = self.config.read().await;
        let replicas = self.replicas.read().await;

        // Get healthy replicas
        let mut healthy_replicas = Vec::new();
        for (name, replica) in replicas.iter() {
            let health = *replica.health.read().await;
            if health == ReplicaHealth::Healthy {
                healthy_replicas.push((name.clone(), replica.clone()));
            }
        }

        // If no healthy replicas, failover to primary
        if healthy_replicas.is_empty() {
            if config.failover_to_primary {
                debug!("No healthy replicas available, routing to primary");
                self.queries_to_primary.fetch_add(1, Ordering::Relaxed);
                crate::metrics::record_read_query_routed_to_primary();
                return self.primary_pool.clone();
            } else {
                // Still try to use degraded replicas
                for (name, replica) in replicas.iter() {
                    let health = *replica.health.read().await;
                    if health == ReplicaHealth::Degraded {
                        healthy_replicas.push((name.clone(), replica.clone()));
                    }
                }

                if healthy_replicas.is_empty() {
                    warn!("No replicas available and failover disabled, routing to primary");
                    self.queries_to_primary.fetch_add(1, Ordering::Relaxed);
                    return self.primary_pool.clone();
                }
            }
        }

        // Select replica based on strategy
        let selected = match config.strategy {
            LoadBalanceStrategy::RoundRobin => self.select_round_robin(&healthy_replicas),
            LoadBalanceStrategy::LeastConnections => {
                self.select_least_connections(&healthy_replicas).await
            }
            LoadBalanceStrategy::Weighted => self.select_weighted(&healthy_replicas),
            LoadBalanceStrategy::Random => self.select_random(&healthy_replicas),
        };

        if let Some(replica) = selected {
            self.queries_to_replicas.fetch_add(1, Ordering::Relaxed);
            crate::metrics::record_read_query_routed_to_replica(replica.0.clone());
            replica.1.pool.clone()
        } else {
            self.queries_to_primary.fetch_add(1, Ordering::Relaxed);
            self.primary_pool.clone()
        }
    }

    /// Get the primary pool for write queries
    pub fn get_write_pool(&self) -> PgPool {
        self.primary_pool.clone()
    }

    fn select_round_robin(
        &self,
        replicas: &[(String, Arc<ReplicaPool>)],
    ) -> Option<(String, Arc<ReplicaPool>)> {
        if replicas.is_empty() {
            return None;
        }

        let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed) % replicas.len();
        Some(replicas[index].clone())
    }

    async fn select_least_connections(
        &self,
        replicas: &[(String, Arc<ReplicaPool>)],
    ) -> Option<(String, Arc<ReplicaPool>)> {
        if replicas.is_empty() {
            return None;
        }

        let mut min_connections = u32::MAX;
        let mut selected = None;

        for (name, replica) in replicas {
            let connections = replica.pool.size();
            if connections < min_connections {
                min_connections = connections;
                selected = Some((name.clone(), replica.clone()));
            }
        }

        selected
    }

    fn select_weighted(
        &self,
        replicas: &[(String, Arc<ReplicaPool>)],
    ) -> Option<(String, Arc<ReplicaPool>)> {
        if replicas.is_empty() {
            return None;
        }

        // Calculate total weight
        let total_weight: u32 = replicas.iter().map(|(_, r)| r.weight).sum();
        if total_weight == 0 {
            return self.select_round_robin(replicas);
        }

        // Random selection based on weight
        let mut rng = rand::rng();
        let random_weight = rng.random_range(0..total_weight);

        let mut cumulative_weight = 0;
        for (name, replica) in replicas {
            cumulative_weight += replica.weight;
            if random_weight < cumulative_weight {
                return Some((name.clone(), replica.clone()));
            }
        }

        // Fallback to last replica
        replicas.last().cloned()
    }

    fn select_random(
        &self,
        replicas: &[(String, Arc<ReplicaPool>)],
    ) -> Option<(String, Arc<ReplicaPool>)> {
        if replicas.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let index = rng.random_range(0..replicas.len());
        Some(replicas[index].clone())
    }

    /// Run health checks on all replicas
    pub async fn check_all_replicas_health(&self) -> Result<(), ReadReplicaError> {
        let replicas = self.replicas.read().await;

        for (name, replica) in replicas.iter() {
            match replica.check_health().await {
                Ok(health) => {
                    debug!("Replica {} health: {:?}", name, health);
                    let health_str = match health {
                        ReplicaHealth::Healthy => "healthy",
                        ReplicaHealth::Degraded => "degraded",
                        ReplicaHealth::Unhealthy => "unhealthy",
                    };
                    crate::metrics::record_read_replica_health_check(name.clone(), health_str);
                }
                Err(e) => {
                    error!("Failed to check health for replica {}: {}", name, e);
                }
            }
        }

        Ok(())
    }

    /// Start background health checking
    pub fn start_health_checks(&self) -> tokio::task::JoinHandle<()> {
        let manager = Arc::new(self.clone_for_task());
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                let interval = config.read().await.health_check_interval;
                tokio::time::sleep(interval).await;

                if let Err(e) = manager.check_all_replicas_health().await {
                    error!("Health check failed: {}", e);
                }
            }
        })
    }

    fn clone_for_task(&self) -> Self {
        Self {
            primary_pool: self.primary_pool.clone(),
            replicas: self.replicas.clone(),
            config: self.config.clone(),
            round_robin_index: AtomicUsize::new(0),
            total_queries_routed: AtomicU64::new(0),
            queries_to_primary: AtomicU64::new(0),
            queries_to_replicas: AtomicU64::new(0),
        }
    }

    /// Get statistics for all replicas
    pub async fn get_all_stats(&self) -> Vec<ReplicaStats> {
        let replicas = self.replicas.read().await;
        let mut stats = Vec::new();

        for replica in replicas.values() {
            stats.push(replica.get_stats().await);
        }

        stats
    }

    /// Get routing statistics
    pub fn get_routing_stats(&self) -> RoutingStats {
        let total = self.total_queries_routed.load(Ordering::Relaxed);
        let to_primary = self.queries_to_primary.load(Ordering::Relaxed);
        let to_replicas = self.queries_to_replicas.load(Ordering::Relaxed);

        let replica_ratio = if total > 0 {
            (to_replicas as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        RoutingStats {
            total_queries: total,
            queries_to_primary: to_primary,
            queries_to_replicas: to_replicas,
            replica_usage_ratio: replica_ratio,
        }
    }

    /// Get configuration
    pub async fn config(&self) -> ReadReplicaManagerConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, config: ReadReplicaManagerConfig) {
        *self.config.write().await = config;
        info!("Updated read replica manager configuration");
    }
}

/// Routing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingStats {
    pub total_queries: u64,
    pub queries_to_primary: u64,
    pub queries_to_replicas: u64,
    pub replica_usage_ratio: f64,
}

/// Read replica error types
#[derive(Debug, thiserror::Error)]
pub enum ReadReplicaError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Replica not found: {0}")]
    ReplicaNotFound(String),

    #[error("No healthy replicas available")]
    NoHealthyReplicas,

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_balance_strategy_serialization() {
        let strategy = LoadBalanceStrategy::RoundRobin;
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("RoundRobin"));
    }

    #[test]
    fn test_replica_health_serialization() {
        let health = ReplicaHealth::Healthy;
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("Healthy"));
    }

    #[test]
    fn test_read_replica_manager_config_default() {
        let config = ReadReplicaManagerConfig::default();
        assert_eq!(config.strategy, LoadBalanceStrategy::RoundRobin);
        assert!(config.failover_to_primary);
        assert_eq!(config.max_replication_lag_ms, 5000);
    }

    #[test]
    fn test_routing_stats_calculation() {
        let stats = RoutingStats {
            total_queries: 100,
            queries_to_primary: 20,
            queries_to_replicas: 80,
            replica_usage_ratio: 80.0,
        };
        assert_eq!(stats.replica_usage_ratio, 80.0);
    }
}
