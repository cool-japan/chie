//! Request rate limiting per peer for DoS protection.
//!
//! This module provides fine-grained rate limiting on a per-peer basis to prevent
//! denial of service attacks and ensure fair resource usage.

use chie_shared::ChieResult;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitType {
    /// Requests per second
    RequestsPerSecond,
    /// Bytes per second
    BytesPerSecond,
    /// Connections per minute
    ConnectionsPerMinute,
}

/// Rate limit decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Request is allowed
    Allowed,
    /// Request is rate limited (retry after duration)
    RateLimited { retry_after: Duration },
    /// Peer is blocked due to violations
    Blocked { reason: String },
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Requests per second limit
    pub requests_per_second: u32,
    /// Bytes per second limit
    pub bytes_per_second: u64,
    /// Connections per minute limit
    pub connections_per_minute: u32,
    /// Burst allowance (multiplier)
    pub burst_multiplier: f64,
    /// Violation threshold before blocking
    pub violation_threshold: u32,
    /// Violation reset period
    pub violation_reset_period: Duration,
    /// Block duration for violators
    pub block_duration: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            bytes_per_second: 10 * 1024 * 1024, // 10 MB/s
            connections_per_minute: 10,
            burst_multiplier: 2.0,
            violation_threshold: 5,
            violation_reset_period: Duration::from_secs(60),
            block_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucketState {
    /// Current token count
    tokens: f64,
    /// Maximum tokens (capacity)
    capacity: f64,
    /// Token refill rate per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucketState {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }

    fn try_consume(&mut self, amount: f64) -> bool {
        self.refill();
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn time_until_tokens(&self, amount: f64) -> Duration {
        if self.tokens >= amount {
            return Duration::ZERO;
        }
        let needed = amount - self.tokens;
        let seconds = needed / self.refill_rate;
        Duration::from_secs_f64(seconds)
    }
}

/// Per-peer rate limit state
#[derive(Debug, Clone)]
struct PeerLimitState {
    /// Request rate bucket
    request_bucket: TokenBucketState,
    /// Bandwidth rate bucket
    bandwidth_bucket: TokenBucketState,
    /// Connection rate bucket
    connection_bucket: TokenBucketState,
    /// Violation count
    violations: u32,
    /// Last violation time
    last_violation: Option<Instant>,
    /// Blocked until
    blocked_until: Option<Instant>,
    /// Block reason
    block_reason: Option<String>,
}

/// Rate limiter for peer requests
pub struct RateLimiter {
    /// Configuration
    config: RateLimiterConfig,
    /// Per-peer state
    peer_states: Arc<RwLock<HashMap<String, PeerLimitState>>>,
    /// Whitelisted peers (bypass limits)
    whitelist: Arc<RwLock<Vec<String>>>,
    /// Statistics
    stats: Arc<RwLock<RateLimiterStats>>,
}

/// Rate limiter statistics
#[derive(Debug, Clone, Default)]
pub struct RateLimiterStats {
    /// Total requests checked
    pub total_requests: u64,
    /// Requests allowed
    pub requests_allowed: u64,
    /// Requests rate limited
    pub requests_rate_limited: u64,
    /// Requests blocked
    pub requests_blocked: u64,
    /// Total violations recorded
    pub total_violations: u64,
    /// Currently blocked peers
    pub blocked_peers: u64,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(RateLimiterStats::default())),
        }
    }

    /// Check if request is allowed
    pub fn check_request(&self, peer_id: &str, bytes: u64) -> RateLimitDecision {
        let mut stats = self.stats.write();
        stats.total_requests += 1;

        // Check whitelist
        if self.whitelist.read().contains(&peer_id.to_string()) {
            stats.requests_allowed += 1;
            return RateLimitDecision::Allowed;
        }

        let mut peer_states = self.peer_states.write();
        let state = peer_states.entry(peer_id.to_string()).or_insert_with(|| {
            let request_capacity =
                self.config.requests_per_second as f64 * self.config.burst_multiplier;
            let bandwidth_capacity =
                self.config.bytes_per_second as f64 * self.config.burst_multiplier;
            let connection_capacity =
                self.config.connections_per_minute as f64 * self.config.burst_multiplier;

            PeerLimitState {
                request_bucket: TokenBucketState::new(
                    request_capacity,
                    self.config.requests_per_second as f64,
                ),
                bandwidth_bucket: TokenBucketState::new(
                    bandwidth_capacity,
                    self.config.bytes_per_second as f64,
                ),
                connection_bucket: TokenBucketState::new(
                    connection_capacity,
                    self.config.connections_per_minute as f64 / 60.0,
                ),
                violations: 0,
                last_violation: None,
                blocked_until: None,
                block_reason: None,
            }
        });

        // Check if peer is blocked
        if let Some(blocked_until) = state.blocked_until {
            if Instant::now() < blocked_until {
                stats.requests_blocked += 1;
                return RateLimitDecision::Blocked {
                    reason: state
                        .block_reason
                        .clone()
                        .unwrap_or_else(|| "Rate limit violations".to_string()),
                };
            } else {
                // Unblock peer
                state.blocked_until = None;
                state.block_reason = None;
                state.violations = 0;
                if stats.blocked_peers > 0 {
                    stats.blocked_peers -= 1;
                }
            }
        }

        // Check request rate limit
        if !state.request_bucket.try_consume(1.0) {
            self.record_violation(state, stats);
            let retry_after = state.request_bucket.time_until_tokens(1.0);
            return RateLimitDecision::RateLimited { retry_after };
        }

        // Check bandwidth limit
        if bytes > 0 && !state.bandwidth_bucket.try_consume(bytes as f64) {
            self.record_violation(state, stats);
            let retry_after = state.bandwidth_bucket.time_until_tokens(bytes as f64);
            return RateLimitDecision::RateLimited { retry_after };
        }

        stats.requests_allowed += 1;
        RateLimitDecision::Allowed
    }

    /// Record new connection attempt
    pub fn check_connection(&self, peer_id: &str) -> RateLimitDecision {
        let mut stats = self.stats.write();
        stats.total_requests += 1;

        // Check whitelist
        if self.whitelist.read().contains(&peer_id.to_string()) {
            stats.requests_allowed += 1;
            return RateLimitDecision::Allowed;
        }

        let mut peer_states = self.peer_states.write();
        let state = peer_states.entry(peer_id.to_string()).or_insert_with(|| {
            let request_capacity =
                self.config.requests_per_second as f64 * self.config.burst_multiplier;
            let bandwidth_capacity =
                self.config.bytes_per_second as f64 * self.config.burst_multiplier;
            let connection_capacity =
                self.config.connections_per_minute as f64 * self.config.burst_multiplier;

            PeerLimitState {
                request_bucket: TokenBucketState::new(
                    request_capacity,
                    self.config.requests_per_second as f64,
                ),
                bandwidth_bucket: TokenBucketState::new(
                    bandwidth_capacity,
                    self.config.bytes_per_second as f64,
                ),
                connection_bucket: TokenBucketState::new(
                    connection_capacity,
                    self.config.connections_per_minute as f64 / 60.0,
                ),
                violations: 0,
                last_violation: None,
                blocked_until: None,
                block_reason: None,
            }
        });

        // Check if peer is blocked
        if let Some(blocked_until) = state.blocked_until {
            if Instant::now() < blocked_until {
                stats.requests_blocked += 1;
                return RateLimitDecision::Blocked {
                    reason: state
                        .block_reason
                        .clone()
                        .unwrap_or_else(|| "Rate limit violations".to_string()),
                };
            }
        }

        // Check connection rate limit
        if !state.connection_bucket.try_consume(1.0) {
            self.record_violation(state, stats);
            let retry_after = state.connection_bucket.time_until_tokens(1.0);
            return RateLimitDecision::RateLimited { retry_after };
        }

        stats.requests_allowed += 1;
        RateLimitDecision::Allowed
    }

    /// Record a violation and potentially block peer
    fn record_violation(
        &self,
        state: &mut PeerLimitState,
        mut stats: parking_lot::RwLockWriteGuard<RateLimiterStats>,
    ) {
        stats.requests_rate_limited += 1;
        stats.total_violations += 1;

        // Reset violations if reset period has passed
        if let Some(last_violation) = state.last_violation {
            if Instant::now().duration_since(last_violation) > self.config.violation_reset_period {
                state.violations = 0;
            }
        }

        state.violations += 1;
        state.last_violation = Some(Instant::now());

        // Block peer if violation threshold exceeded
        if state.violations >= self.config.violation_threshold {
            state.blocked_until = Some(Instant::now() + self.config.block_duration);
            state.block_reason = Some(format!(
                "Exceeded {} violations",
                self.config.violation_threshold
            ));
            stats.blocked_peers += 1;
        }
    }

    /// Add peer to whitelist
    pub fn add_to_whitelist(&self, peer_id: &str) {
        let mut whitelist = self.whitelist.write();
        if !whitelist.contains(&peer_id.to_string()) {
            whitelist.push(peer_id.to_string());
        }
    }

    /// Remove peer from whitelist
    pub fn remove_from_whitelist(&self, peer_id: &str) {
        let mut whitelist = self.whitelist.write();
        whitelist.retain(|p| p != peer_id);
    }

    /// Check if peer is whitelisted
    pub fn is_whitelisted(&self, peer_id: &str) -> bool {
        self.whitelist.read().contains(&peer_id.to_string())
    }

    /// Manually block a peer
    pub fn block_peer(&self, peer_id: &str, reason: String, duration: Duration) -> ChieResult<()> {
        let mut peer_states = self.peer_states.write();
        let mut stats = self.stats.write();

        let state = peer_states.entry(peer_id.to_string()).or_insert_with(|| {
            let request_capacity =
                self.config.requests_per_second as f64 * self.config.burst_multiplier;
            let bandwidth_capacity =
                self.config.bytes_per_second as f64 * self.config.burst_multiplier;
            let connection_capacity =
                self.config.connections_per_minute as f64 * self.config.burst_multiplier;

            PeerLimitState {
                request_bucket: TokenBucketState::new(
                    request_capacity,
                    self.config.requests_per_second as f64,
                ),
                bandwidth_bucket: TokenBucketState::new(
                    bandwidth_capacity,
                    self.config.bytes_per_second as f64,
                ),
                connection_bucket: TokenBucketState::new(
                    connection_capacity,
                    self.config.connections_per_minute as f64 / 60.0,
                ),
                violations: 0,
                last_violation: None,
                blocked_until: None,
                block_reason: None,
            }
        });

        if state.blocked_until.is_none() {
            stats.blocked_peers += 1;
        }

        state.blocked_until = Some(Instant::now() + duration);
        state.block_reason = Some(reason);

        Ok(())
    }

    /// Unblock a peer
    pub fn unblock_peer(&self, peer_id: &str) -> ChieResult<()> {
        let mut peer_states = self.peer_states.write();
        let mut stats = self.stats.write();

        if let Some(state) = peer_states.get_mut(peer_id) {
            if state.blocked_until.is_some() {
                state.blocked_until = None;
                state.block_reason = None;
                state.violations = 0;
                if stats.blocked_peers > 0 {
                    stats.blocked_peers -= 1;
                }
            }
        }

        Ok(())
    }

    /// Check if peer is blocked
    pub fn is_blocked(&self, peer_id: &str) -> bool {
        let peer_states = self.peer_states.read();
        if let Some(state) = peer_states.get(peer_id) {
            if let Some(blocked_until) = state.blocked_until {
                return Instant::now() < blocked_until;
            }
        }
        false
    }

    /// Get peer violation count
    pub fn get_violations(&self, peer_id: &str) -> u32 {
        let peer_states = self.peer_states.read();
        peer_states.get(peer_id).map(|s| s.violations).unwrap_or(0)
    }

    /// Reset peer violations
    pub fn reset_violations(&self, peer_id: &str) {
        let mut peer_states = self.peer_states.write();
        if let Some(state) = peer_states.get_mut(peer_id) {
            state.violations = 0;
            state.last_violation = None;
        }
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimiterStats {
        self.stats.read().clone()
    }

    /// Clean up old peer states
    pub fn cleanup_old_states(&self, max_age: Duration) -> usize {
        let mut peer_states = self.peer_states.write();
        let now = Instant::now();
        let initial_count = peer_states.len();

        peer_states.retain(|_, state| {
            // Keep if blocked
            if let Some(blocked_until) = state.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }

            // Keep if recently active
            if let Some(last_violation) = state.last_violation {
                if now.duration_since(last_violation) < max_age {
                    return true;
                }
            }

            // Check bucket activity
            now.duration_since(state.request_bucket.last_refill) < max_age
        });

        initial_count - peer_states.len()
    }

    /// Get blocked peers
    pub fn get_blocked_peers(&self) -> Vec<String> {
        let peer_states = self.peer_states.read();
        let now = Instant::now();

        peer_states
            .iter()
            .filter(|(_, state)| {
                if let Some(blocked_until) = state.blocked_until {
                    now < blocked_until
                } else {
                    false
                }
            })
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimiterConfig {
            requests_per_second: 10,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // First 10 requests should be allowed
        for _ in 0..10 {
            assert_eq!(
                limiter.check_request("peer1", 0),
                RateLimitDecision::Allowed
            );
        }

        // 11th request should be rate limited
        let decision = limiter.check_request("peer1", 0);
        assert!(matches!(decision, RateLimitDecision::RateLimited { .. }));
    }

    #[test]
    fn test_whitelist() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter.add_to_whitelist("trusted_peer");

        // Whitelisted peer should always be allowed
        for _ in 0..1000 {
            assert_eq!(
                limiter.check_request("trusted_peer", 0),
                RateLimitDecision::Allowed
            );
        }
    }

    #[test]
    fn test_bandwidth_limit() {
        let config = RateLimiterConfig {
            bytes_per_second: 1000,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Should allow 1000 bytes
        assert_eq!(
            limiter.check_request("peer1", 1000),
            RateLimitDecision::Allowed
        );

        // Next byte should be rate limited
        let decision = limiter.check_request("peer1", 1);
        assert!(matches!(decision, RateLimitDecision::RateLimited { .. }));
    }

    #[test]
    fn test_connection_limit() {
        let config = RateLimiterConfig {
            connections_per_minute: 5,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // First 5 connections should be allowed
        for _ in 0..5 {
            assert_eq!(
                limiter.check_connection("peer1"),
                RateLimitDecision::Allowed
            );
        }

        // 6th connection should be rate limited
        let decision = limiter.check_connection("peer1");
        assert!(matches!(decision, RateLimitDecision::RateLimited { .. }));
    }

    #[test]
    fn test_violation_blocking() {
        let config = RateLimiterConfig {
            requests_per_second: 1,
            burst_multiplier: 1.0,
            violation_threshold: 3,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Trigger violations
        limiter.check_request("peer1", 0); // Allowed
        limiter.check_request("peer1", 0); // Violation 1
        limiter.check_request("peer1", 0); // Violation 2
        limiter.check_request("peer1", 0); // Violation 3 - should block

        // Next request should be blocked
        let decision = limiter.check_request("peer1", 0);
        assert!(matches!(decision, RateLimitDecision::Blocked { .. }));
    }

    #[test]
    fn test_manual_block() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter
            .block_peer("peer1", "Manual block".to_string(), Duration::from_secs(60))
            .unwrap();

        assert!(limiter.is_blocked("peer1"));

        let decision = limiter.check_request("peer1", 0);
        assert!(matches!(decision, RateLimitDecision::Blocked { .. }));
    }

    #[test]
    fn test_manual_unblock() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter
            .block_peer("peer1", "Test".to_string(), Duration::from_secs(60))
            .unwrap();
        assert!(limiter.is_blocked("peer1"));

        limiter.unblock_peer("peer1").unwrap();
        assert!(!limiter.is_blocked("peer1"));
    }

    #[test]
    fn test_violation_count() {
        let config = RateLimiterConfig {
            requests_per_second: 1,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        limiter.check_request("peer1", 0); // Allowed
        limiter.check_request("peer1", 0); // Violation 1
        limiter.check_request("peer1", 0); // Violation 2

        assert_eq!(limiter.get_violations("peer1"), 2);
    }

    #[test]
    fn test_reset_violations() {
        let config = RateLimiterConfig {
            requests_per_second: 1,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        limiter.check_request("peer1", 0); // Allowed
        limiter.check_request("peer1", 0); // Violation 1

        assert_eq!(limiter.get_violations("peer1"), 1);

        limiter.reset_violations("peer1");

        assert_eq!(limiter.get_violations("peer1"), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter.check_request("peer1", 0);
        limiter.check_request("peer2", 0);

        let stats = limiter.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.requests_allowed, 2);
    }

    #[test]
    fn test_get_blocked_peers() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter
            .block_peer("peer1", "Test".to_string(), Duration::from_secs(60))
            .unwrap();
        limiter
            .block_peer("peer2", "Test".to_string(), Duration::from_secs(60))
            .unwrap();

        let blocked = limiter.get_blocked_peers();
        assert_eq!(blocked.len(), 2);
        assert!(blocked.contains(&"peer1".to_string()));
        assert!(blocked.contains(&"peer2".to_string()));
    }

    #[test]
    fn test_cleanup_old_states() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        limiter.check_request("peer1", 0);
        limiter.check_request("peer2", 0);

        // Use Duration::ZERO to ensure entries are always considered old (non-flaky)
        let removed = limiter.cleanup_old_states(Duration::ZERO);
        assert_eq!(removed, 2);
    }

    #[test]
    fn test_burst_allowance() {
        let config = RateLimiterConfig {
            requests_per_second: 10,
            burst_multiplier: 2.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Should allow burst of 20 requests (10 * 2.0)
        for _ in 0..20 {
            assert_eq!(
                limiter.check_request("peer1", 0),
                RateLimitDecision::Allowed
            );
        }

        // 21st request should be rate limited
        let decision = limiter.check_request("peer1", 0);
        assert!(matches!(decision, RateLimitDecision::RateLimited { .. }));
    }

    #[test]
    fn test_whitelist_operations() {
        let limiter = RateLimiter::new(RateLimiterConfig::default());

        assert!(!limiter.is_whitelisted("peer1"));

        limiter.add_to_whitelist("peer1");
        assert!(limiter.is_whitelisted("peer1"));

        limiter.remove_from_whitelist("peer1");
        assert!(!limiter.is_whitelisted("peer1"));
    }

    #[test]
    fn test_per_peer_independence() {
        let config = RateLimiterConfig {
            requests_per_second: 5,
            burst_multiplier: 1.0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // peer1 uses all tokens
        for _ in 0..5 {
            limiter.check_request("peer1", 0);
        }

        // peer2 should still have tokens
        assert_eq!(
            limiter.check_request("peer2", 0),
            RateLimitDecision::Allowed
        );
    }
}
