//! Connection pool management for efficient P2P connections.
//!
//! This module provides connection pooling with:
//! - Connection reuse and lifecycle management
//! - Automatic connection expiry and refresh
//! - Connection quality tracking
//! - Load balancing across available connections

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Connection pool configuration.
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections per peer.
    pub max_connections_per_peer: usize,

    /// Maximum total connections in the pool.
    pub max_total_connections: usize,

    /// Connection idle timeout before cleanup.
    pub idle_timeout: Duration,

    /// Maximum connection age before refresh.
    pub max_connection_age: Duration,

    /// Minimum number of connections to maintain per peer (if peer is active).
    pub min_connections_per_peer: usize,

    /// Enable automatic connection refresh.
    pub enable_auto_refresh: bool,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_peer: 3,
            max_total_connections: 100,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            max_connection_age: Duration::from_secs(3600), // 1 hour
            min_connections_per_peer: 1,
            enable_auto_refresh: true,
        }
    }
}

/// Information about a pooled connection.
#[derive(Debug, Clone)]
pub struct PooledConnection {
    /// Peer ID.
    pub peer_id: PeerId,

    /// Connection address.
    pub addr: Multiaddr,

    /// When the connection was created.
    pub created_at: Instant,

    /// Last time the connection was used.
    pub last_used: Instant,

    /// Number of times this connection has been used.
    pub use_count: u64,

    /// Connection quality score (0.0 to 1.0).
    pub quality_score: f64,

    /// Whether the connection is currently in use.
    pub in_use: bool,

    /// Number of failed requests on this connection.
    pub failure_count: u32,

    /// Average latency for this connection (milliseconds).
    pub avg_latency_ms: f64,
}

impl PooledConnection {
    /// Create a new pooled connection.
    pub fn new(peer_id: PeerId, addr: Multiaddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addr,
            created_at: now,
            last_used: now,
            use_count: 0,
            quality_score: 1.0,
            in_use: false,
            failure_count: 0,
            avg_latency_ms: 0.0,
        }
    }

    /// Check if the connection is idle.
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        !self.in_use && Instant::now().duration_since(self.last_used) >= idle_timeout
    }

    /// Check if the connection is old and needs refresh.
    pub fn needs_refresh(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.created_at) >= max_age
    }

    /// Mark the connection as used.
    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
        self.in_use = true;
    }

    /// Mark the connection as released.
    pub fn mark_released(&mut self) {
        self.in_use = false;
    }

    /// Record a successful request.
    pub fn record_success(&mut self, latency_ms: f64) {
        // Update average latency using exponential moving average
        if self.avg_latency_ms == 0.0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = 0.8 * self.avg_latency_ms + 0.2 * latency_ms;
        }

        // Improve quality score based on success
        self.quality_score = (self.quality_score * 0.95 + 0.05).min(1.0);
    }

    /// Record a failed request.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;

        // Decrease quality score based on failure
        self.quality_score = (self.quality_score * 0.8).max(0.1);
    }

    /// Get the connection age.
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Check if the connection is healthy.
    pub fn is_healthy(&self) -> bool {
        self.quality_score > 0.5 && self.failure_count < 10
    }
}

/// Connection pool manager.
pub struct ConnectionPool {
    /// Active connections indexed by peer ID.
    connections: HashMap<PeerId, Vec<PooledConnection>>,

    /// Configuration.
    config: ConnectionPoolConfig,

    /// Pool statistics.
    stats: ConnectionPoolStats,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            connections: HashMap::new(),
            config,
            stats: ConnectionPoolStats::default(),
        }
    }

    /// Add a connection to the pool.
    pub fn add_connection(&mut self, peer_id: PeerId, addr: Multiaddr) -> Result<(), PoolError> {
        // Check total connections limit
        if self.total_connections() >= self.config.max_total_connections {
            return Err(PoolError::PoolFull);
        }

        let peer_conns = self.connections.entry(peer_id).or_default();

        // Check per-peer limit
        if peer_conns.len() >= self.config.max_connections_per_peer {
            return Err(PoolError::PeerLimitReached);
        }

        let conn = PooledConnection::new(peer_id, addr);
        peer_conns.push(conn);

        self.stats.total_connections_created += 1;

        Ok(())
    }

    /// Get an available connection for a peer.
    pub fn get_connection(&mut self, peer_id: &PeerId) -> Option<&mut PooledConnection> {
        let peer_conns = self.connections.get_mut(peer_id)?;

        // Find the best available connection:
        // 1. Not in use
        // 2. Healthy
        // 3. Highest quality score
        let mut best_idx = None;
        let mut best_score = 0.0;

        for (i, conn) in peer_conns.iter().enumerate() {
            if !conn.in_use && conn.is_healthy() && conn.quality_score > best_score {
                best_score = conn.quality_score;
                best_idx = Some(i);
            }
        }

        if let Some(idx) = best_idx {
            let conn = &mut peer_conns[idx];
            conn.mark_used();
            self.stats.connections_acquired += 1;
            Some(conn)
        } else {
            self.stats.connection_misses += 1;
            None
        }
    }

    /// Release a connection back to the pool.
    pub fn release_connection(&mut self, peer_id: &PeerId, addr: &Multiaddr) {
        if let Some(peer_conns) = self.connections.get_mut(peer_id) {
            if let Some(conn) = peer_conns.iter_mut().find(|c| &c.addr == addr) {
                conn.mark_released();
                self.stats.connections_released += 1;
            }
        }
    }

    /// Remove a connection from the pool.
    pub fn remove_connection(&mut self, peer_id: &PeerId, addr: &Multiaddr) {
        if let Some(peer_conns) = self.connections.get_mut(peer_id) {
            peer_conns.retain(|c| &c.addr != addr);
            if peer_conns.is_empty() {
                self.connections.remove(peer_id);
            }
            self.stats.connections_removed += 1;
        }
    }

    /// Get all connections for a peer.
    pub fn get_peer_connections(&self, peer_id: &PeerId) -> Vec<&PooledConnection> {
        self.connections
            .get(peer_id)
            .map(|conns| conns.iter().collect())
            .unwrap_or_default()
    }

    /// Get the number of active connections for a peer.
    pub fn peer_connection_count(&self, peer_id: &PeerId) -> usize {
        self.connections.get(peer_id).map(|c| c.len()).unwrap_or(0)
    }

    /// Get total number of connections.
    pub fn total_connections(&self) -> usize {
        self.connections.values().map(|v| v.len()).sum()
    }

    /// Clean up idle and old connections.
    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;

        for (_, conns) in self.connections.iter_mut() {
            let initial_len = conns.len();

            conns.retain(|conn| {
                let keep = !conn.is_idle(self.config.idle_timeout)
                    && !conn.needs_refresh(self.config.max_connection_age)
                    && conn.is_healthy();

                if !keep {
                    self.stats.connections_cleaned_up += 1;
                }

                keep
            });

            removed += initial_len - conns.len();
        }

        // Remove peers with no connections
        self.connections.retain(|_, conns| !conns.is_empty());

        removed
    }

    /// Get connections that need refresh.
    pub fn get_connections_needing_refresh(&self) -> Vec<(PeerId, Multiaddr)> {
        if !self.config.enable_auto_refresh {
            return Vec::new();
        }

        let mut needs_refresh = Vec::new();

        for (peer_id, conns) in &self.connections {
            for conn in conns {
                if conn.needs_refresh(self.config.max_connection_age) && !conn.in_use {
                    needs_refresh.push((*peer_id, conn.addr.clone()));
                }
            }
        }

        needs_refresh
    }

    /// Get pool statistics.
    pub fn get_stats(&self) -> ConnectionPoolStats {
        let mut stats = self.stats.clone();
        stats.total_connections = self.total_connections();
        stats.total_peers = self.connections.len();

        let mut in_use = 0;
        let mut total_quality = 0.0;

        for conns in self.connections.values() {
            for conn in conns {
                if conn.in_use {
                    in_use += 1;
                }
                total_quality += conn.quality_score;
            }
        }

        stats.connections_in_use = in_use;
        stats.average_quality_score = if stats.total_connections > 0 {
            total_quality / stats.total_connections as f64
        } else {
            0.0
        };

        stats
    }

    /// Get connections sorted by quality.
    pub fn get_best_connections(&self, peer_id: &PeerId, limit: usize) -> Vec<&PooledConnection> {
        if let Some(conns) = self.connections.get(peer_id) {
            let mut sorted: Vec<_> = conns.iter().filter(|c| c.is_healthy()).collect();
            sorted.sort_by(|a, b| {
                b.quality_score
                    .partial_cmp(&a.quality_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            sorted.into_iter().take(limit).collect()
        } else {
            Vec::new()
        }
    }
}

/// Connection pool statistics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionPoolStats {
    /// Total connections currently in the pool.
    pub total_connections: usize,

    /// Total number of peers with connections.
    pub total_peers: usize,

    /// Connections currently in use.
    pub connections_in_use: usize,

    /// Total connections created.
    pub total_connections_created: u64,

    /// Total connections acquired from pool.
    pub connections_acquired: u64,

    /// Total connections released back to pool.
    pub connections_released: u64,

    /// Total connections removed.
    pub connections_removed: u64,

    /// Total connections cleaned up.
    pub connections_cleaned_up: u64,

    /// Connection acquisition misses (no available connection).
    pub connection_misses: u64,

    /// Average connection quality score.
    pub average_quality_score: f64,
}

/// Connection pool errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PoolError {
    /// Pool is at maximum capacity.
    #[error("Connection pool is full")]
    PoolFull,

    /// Per-peer connection limit reached.
    #[error("Peer connection limit reached")]
    PeerLimitReached,

    /// Connection not found.
    #[error("Connection not found")]
    ConnectionNotFound,

    /// Invalid connection state.
    #[error("Invalid connection state")]
    InvalidState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool_basic() {
        let config = ConnectionPoolConfig::default();
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        // Add connection
        assert!(pool.add_connection(peer_id, addr.clone()).is_ok());
        assert_eq!(pool.total_connections(), 1);
        assert_eq!(pool.peer_connection_count(&peer_id), 1);
    }

    #[test]
    fn test_connection_limits() {
        let config = ConnectionPoolConfig {
            max_connections_per_peer: 2,
            ..Default::default()
        };
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();

        // Add up to limit
        assert!(
            pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4001".parse().unwrap())
                .is_ok()
        );
        assert!(
            pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4002".parse().unwrap())
                .is_ok()
        );

        // Exceed limit
        assert!(
            pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4003".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn test_connection_acquisition() {
        let config = ConnectionPoolConfig::default();
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        pool.add_connection(peer_id, addr.clone()).unwrap();

        // Get connection
        let conn = pool.get_connection(&peer_id);
        assert!(conn.is_some());
        assert!(conn.unwrap().in_use);

        // Try to get again (should fail, already in use)
        let conn2 = pool.get_connection(&peer_id);
        assert!(conn2.is_none());

        // Release and try again
        pool.release_connection(&peer_id, &addr);
        let conn3 = pool.get_connection(&peer_id);
        assert!(conn3.is_some());
    }

    #[test]
    fn test_connection_quality() {
        let mut conn =
            PooledConnection::new(PeerId::random(), "/ip4/127.0.0.1/tcp/4001".parse().unwrap());

        assert_eq!(conn.quality_score, 1.0);
        assert!(conn.is_healthy());

        // Record success
        conn.record_success(50.0);
        assert!(conn.quality_score >= 0.95);
        assert_eq!(conn.avg_latency_ms, 50.0);

        // Record failure
        conn.record_failure();
        assert!(conn.quality_score < 1.0);
        assert_eq!(conn.failure_count, 1);
    }

    #[test]
    fn test_pool_cleanup() {
        let config = ConnectionPoolConfig {
            idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        pool.add_connection(peer_id, addr.clone()).unwrap();

        // Should not clean up immediately
        assert_eq!(pool.cleanup(), 0);
        assert_eq!(pool.total_connections(), 1);

        // Wait for idle timeout (simulated by setting last_used to past)
        if let Some(conns) = pool.connections.get_mut(&peer_id) {
            if let Some(conn) = conns.first_mut() {
                conn.last_used = Instant::now() - Duration::from_secs(1);
            }
        }

        // Should clean up now
        let cleaned = pool.cleanup();
        assert_eq!(cleaned, 1);
        assert_eq!(pool.total_connections(), 0);
    }

    #[test]
    fn test_best_connections() {
        let config = ConnectionPoolConfig::default();
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();

        // Add multiple connections with different qualities
        pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4001".parse().unwrap())
            .unwrap();
        pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4002".parse().unwrap())
            .unwrap();
        pool.add_connection(peer_id, "/ip4/127.0.0.1/tcp/4003".parse().unwrap())
            .unwrap();

        // Modify quality scores
        if let Some(conns) = pool.connections.get_mut(&peer_id) {
            conns[0].quality_score = 0.9;
            conns[1].quality_score = 0.7;
            conns[2].quality_score = 0.95;
        }

        let best = pool.get_best_connections(&peer_id, 2);
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].quality_score, 0.95);
        assert_eq!(best[1].quality_score, 0.9);
    }

    #[test]
    fn test_pool_stats() {
        let config = ConnectionPoolConfig::default();
        let mut pool = ConnectionPool::new(config);

        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        pool.add_connection(peer_id, addr.clone()).unwrap();

        let stats = pool.get_stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.connections_in_use, 0);
        assert_eq!(stats.total_connections_created, 1);

        pool.get_connection(&peer_id).unwrap();

        let stats2 = pool.get_stats();
        assert_eq!(stats2.connections_in_use, 1);
        assert_eq!(stats2.connections_acquired, 1);
    }
}
