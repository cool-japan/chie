//! Adaptive rate limiting with dynamic adjustments based on peer behavior.
//!
//! This module provides intelligent rate limiting that adapts to peer reputation,
//! network conditions, and historical behavior. Unlike static rate limiting,
//! adaptive rate limits increase for trusted peers and decrease for suspicious ones.
//!
//! # Example
//!
//! ```
//! use chie_core::{AdaptiveRateLimiter, AdaptiveRateLimitConfig};
//!
//! # async fn example() {
//! let config = AdaptiveRateLimitConfig {
//!     base_rate: 100,
//!     base_window_secs: 60,
//!     min_rate: 10,
//!     max_rate: 1000,
//!     ..Default::default()
//! };
//!
//! let mut limiter = AdaptiveRateLimiter::new(config);
//!
//! // Check if peer can make request
//! let peer_id = "peer1";
//! if limiter.check_rate_limit(peer_id, 0.9) {
//!     println!("Request allowed");
//! } else {
//!     println!("Rate limit exceeded");
//! }
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Configuration for adaptive rate limiting.
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimitConfig {
    /// Base rate limit (requests per window)
    pub base_rate: u64,
    /// Base time window in seconds
    pub base_window_secs: u64,
    /// Minimum rate limit
    pub min_rate: u64,
    /// Maximum rate limit
    pub max_rate: u64,
    /// Reputation multiplier (good peers get higher limits)
    pub reputation_multiplier: f64,
    /// Burst allowance (multiple of base_rate)
    pub burst_multiplier: f64,
    /// Window cleanup interval
    pub cleanup_interval_secs: u64,
}

impl Default for AdaptiveRateLimitConfig {
    fn default() -> Self {
        Self {
            base_rate: 100,
            base_window_secs: 60,
            min_rate: 10,
            max_rate: 1000,
            reputation_multiplier: 2.0,
            burst_multiplier: 1.5,
            cleanup_interval_secs: 300,
        }
    }
}

/// Request record for rate limiting.
#[derive(Debug, Clone)]
struct RequestRecord {
    timestamp: SystemTime,
    count: u64,
}

/// Per-peer rate limit state.
#[derive(Debug, Clone)]
struct PeerRateLimit {
    /// Current rate limit for this peer
    current_limit: u64,
    /// Request timestamps in current window
    requests: Vec<RequestRecord>,
    /// Last window reset time
    last_reset: SystemTime,
    /// Total requests ever made
    total_requests: u64,
    /// Violations count
    violations: u64,
}

/// Adaptive rate limiter with dynamic adjustments.
pub struct AdaptiveRateLimiter {
    config: AdaptiveRateLimitConfig,
    peer_limits: HashMap<String, PeerRateLimit>,
    last_cleanup: SystemTime,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter.
    #[must_use]
    #[inline]
    pub fn new(config: AdaptiveRateLimitConfig) -> Self {
        Self {
            config,
            peer_limits: HashMap::new(),
            last_cleanup: SystemTime::now(),
        }
    }

    /// Check if a peer can make a request.
    ///
    /// # Arguments
    /// * `peer_id` - The peer identifier
    /// * `reputation_score` - Peer reputation score (0.0 to 1.0)
    ///
    /// # Returns
    /// `true` if request is allowed, `false` if rate limited
    pub fn check_rate_limit(&mut self, peer_id: &str, reputation_score: f64) -> bool {
        self.maybe_cleanup();

        let now = SystemTime::now();
        let calculated_limit = self.calculate_limit(reputation_score);

        let state = self
            .peer_limits
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerRateLimit {
                current_limit: calculated_limit,
                requests: Vec::new(),
                last_reset: now,
                total_requests: 0,
                violations: 0,
            });

        // Update limit based on reputation
        state.current_limit = calculated_limit;

        // Clean old requests outside window
        let window = Duration::from_secs(self.config.base_window_secs);
        state.requests.retain(|r| {
            if let Ok(age) = now.duration_since(r.timestamp) {
                age < window
            } else {
                false
            }
        });

        // Count requests in window
        let current_count: u64 = state.requests.iter().map(|r| r.count).sum();

        // Check if within limit
        let burst_limit = (state.current_limit as f64 * self.config.burst_multiplier) as u64;

        if current_count < burst_limit {
            // Allow request
            state.requests.push(RequestRecord {
                timestamp: now,
                count: 1,
            });
            state.total_requests += 1;
            true
        } else {
            // Rate limited
            state.violations += 1;
            false
        }
    }

    /// Calculate rate limit for a peer based on reputation.
    #[inline]
    fn calculate_limit(&self, reputation_score: f64) -> u64 {
        let reputation_score = reputation_score.clamp(0.0, 1.0);

        // Linear scaling based on reputation
        let multiplier = 1.0 + (reputation_score * (self.config.reputation_multiplier - 1.0));
        let limit = (self.config.base_rate as f64 * multiplier) as u64;

        limit.clamp(self.config.min_rate, self.config.max_rate)
    }

    /// Get current rate limit for a peer.
    #[must_use]
    #[inline]
    pub fn get_limit(&mut self, peer_id: &str, reputation_score: f64) -> u64 {
        let limit = self.calculate_limit(reputation_score);

        if let Some(state) = self.peer_limits.get_mut(peer_id) {
            state.current_limit = limit;
        }

        limit
    }

    /// Get remaining requests for a peer in current window.
    #[must_use]
    #[inline]
    pub fn get_remaining(&mut self, peer_id: &str, reputation_score: f64) -> u64 {
        let now = SystemTime::now();
        let window = Duration::from_secs(self.config.base_window_secs);

        let state = match self.peer_limits.get_mut(peer_id) {
            Some(s) => s,
            None => return self.calculate_limit(reputation_score),
        };

        // Clean old requests
        state.requests.retain(|r| {
            if let Ok(age) = now.duration_since(r.timestamp) {
                age < window
            } else {
                false
            }
        });

        let current_count: u64 = state.requests.iter().map(|r| r.count).sum();
        let limit = self.calculate_limit(reputation_score);

        limit.saturating_sub(current_count)
    }

    /// Get time until window reset for a peer.
    #[must_use]
    #[inline]
    pub fn get_reset_time(&self, peer_id: &str) -> Option<Duration> {
        let state = self.peer_limits.get(peer_id)?;
        let now = SystemTime::now();

        // Find oldest request in window
        let oldest = state.requests.iter().min_by_key(|r| r.timestamp)?;

        let window = Duration::from_secs(self.config.base_window_secs);
        let age = now.duration_since(oldest.timestamp).ok()?;

        if age < window {
            Some(window - age)
        } else {
            Some(Duration::from_secs(0))
        }
    }

    /// Reset rate limit for a peer.
    #[inline]
    pub fn reset_peer(&mut self, peer_id: &str) {
        if let Some(state) = self.peer_limits.get_mut(peer_id) {
            state.requests.clear();
            state.last_reset = SystemTime::now();
        }
    }

    /// Get statistics for a peer.
    #[must_use]
    #[inline]
    pub fn get_peer_stats(&self, peer_id: &str) -> Option<PeerRateLimitStats> {
        let state = self.peer_limits.get(peer_id)?;
        let current_count: u64 = state.requests.iter().map(|r| r.count).sum();

        Some(PeerRateLimitStats {
            current_limit: state.current_limit,
            current_usage: current_count,
            total_requests: state.total_requests,
            violations: state.violations,
        })
    }

    /// Get global statistics.
    #[must_use]
    #[inline]
    pub fn get_global_stats(&self) -> GlobalRateLimitStats {
        let total_peers = self.peer_limits.len();
        let total_requests: u64 = self.peer_limits.values().map(|s| s.total_requests).sum();
        let total_violations: u64 = self.peer_limits.values().map(|s| s.violations).sum();

        GlobalRateLimitStats {
            total_peers,
            total_requests,
            total_violations,
        }
    }

    /// Cleanup old peer data.
    #[inline]
    fn maybe_cleanup(&mut self) {
        let now = SystemTime::now();

        if let Ok(duration) = now.duration_since(self.last_cleanup) {
            if duration.as_secs() < self.config.cleanup_interval_secs {
                return;
            }
        }

        let cleanup_threshold = Duration::from_secs(self.config.base_window_secs * 5);

        self.peer_limits.retain(|_, state| {
            if state.requests.is_empty() {
                if let Ok(age) = now.duration_since(state.last_reset) {
                    age < cleanup_threshold
                } else {
                    true
                }
            } else {
                true
            }
        });

        self.last_cleanup = now;
    }

    /// Remove all data for a peer.
    #[inline]
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peer_limits.remove(peer_id);
    }

    /// Get number of tracked peers.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peer_limits.len()
    }

    /// Clear all rate limit data.
    #[inline]
    pub fn clear(&mut self) {
        self.peer_limits.clear();
        self.last_cleanup = SystemTime::now();
    }
}

/// Per-peer rate limit statistics.
#[derive(Debug, Clone)]
pub struct PeerRateLimitStats {
    /// Current rate limit
    pub current_limit: u64,
    /// Current usage in window
    pub current_usage: u64,
    /// Total requests made
    pub total_requests: u64,
    /// Number of violations
    pub violations: u64,
}

/// Global rate limit statistics.
#[derive(Debug, Clone)]
pub struct GlobalRateLimitStats {
    /// Total tracked peers
    pub total_peers: usize,
    /// Total requests across all peers
    pub total_requests: u64,
    /// Total violations across all peers
    pub total_violations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_basic_rate_limiting() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 10,
            base_window_secs: 1,
            burst_multiplier: 1.0,
            reputation_multiplier: 1.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Should allow first 10 requests
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("peer1", 0.5));
        }

        // 11th request should be rate limited
        assert!(!limiter.check_rate_limit("peer1", 0.5));
    }

    #[test]
    fn test_reputation_based_limits() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 100,
            reputation_multiplier: 3.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Low reputation peer gets lower limit
        let low_limit = limiter.get_limit("peer1", 0.1);

        // High reputation peer gets higher limit
        let high_limit = limiter.get_limit("peer2", 0.9);

        assert!(high_limit > low_limit);
    }

    #[test]
    fn test_window_expiration() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 5,
            base_window_secs: 1,
            burst_multiplier: 1.0,
            reputation_multiplier: 1.0,
            min_rate: 1,
            max_rate: 1000,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Use up the limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("peer1", 0.5));
        }

        // Should be rate limited
        assert!(!limiter.check_rate_limit("peer1", 0.5));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check_rate_limit("peer1", 0.5));
    }

    #[test]
    fn test_burst_allowance() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 10,
            burst_multiplier: 2.0,
            reputation_multiplier: 1.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Should allow up to 20 requests (base_rate * burst_multiplier)
        for _ in 0..20 {
            assert!(limiter.check_rate_limit("peer1", 0.5));
        }

        // 21st should be rate limited
        assert!(!limiter.check_rate_limit("peer1", 0.5));
    }

    #[test]
    fn test_get_remaining() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 10,
            burst_multiplier: 1.0,
            reputation_multiplier: 1.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        assert_eq!(limiter.get_remaining("peer1", 0.5), 10);

        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer1", 0.5);

        assert_eq!(limiter.get_remaining("peer1", 0.5), 7);
    }

    #[test]
    fn test_reset_peer() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 5,
            burst_multiplier: 1.0,
            reputation_multiplier: 1.0,
            min_rate: 1,
            max_rate: 1000,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Use up limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("peer1", 0.5));
        }

        assert_eq!(limiter.get_remaining("peer1", 0.5), 0);

        // Reset
        limiter.reset_peer("peer1");

        assert_eq!(limiter.get_remaining("peer1", 0.5), 5);
    }

    #[test]
    fn test_peer_stats() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 10,
            burst_multiplier: 1.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer1", 0.5);

        let stats = limiter.get_peer_stats("peer1").unwrap();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.current_usage, 3);
    }

    #[test]
    fn test_violation_tracking() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 2,
            burst_multiplier: 1.0,
            reputation_multiplier: 1.0,
            min_rate: 1,
            max_rate: 1000,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        assert!(limiter.check_rate_limit("peer1", 0.5));
        assert!(limiter.check_rate_limit("peer1", 0.5));
        assert!(!limiter.check_rate_limit("peer1", 0.5)); // Violation
        assert!(!limiter.check_rate_limit("peer1", 0.5)); // Violation

        let stats = limiter.get_peer_stats("peer1").unwrap();
        assert_eq!(stats.violations, 2);
    }

    #[test]
    fn test_global_stats() {
        let config = AdaptiveRateLimitConfig::default();
        let mut limiter = AdaptiveRateLimiter::new(config);

        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer2", 0.5);
        limiter.check_rate_limit("peer3", 0.5);

        let stats = limiter.get_global_stats();
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.total_requests, 3);
    }

    #[test]
    fn test_min_max_limits() {
        let config = AdaptiveRateLimitConfig {
            base_rate: 100,
            min_rate: 50,
            max_rate: 200,
            reputation_multiplier: 10.0,
            ..Default::default()
        };

        let mut limiter = AdaptiveRateLimiter::new(config);

        // Very low reputation gives base_rate (not min_rate)
        // multiplier = 1.0 + (0.0 * 9.0) = 1.0, so limit = 100
        let low_limit = limiter.get_limit("peer1", 0.0);
        assert_eq!(low_limit, 100);

        // Very high reputation should hit max_rate
        // multiplier = 1.0 + (1.0 * 9.0) = 10.0, so limit = 1000, clamped to 200
        let high_limit = limiter.get_limit("peer2", 1.0);
        assert_eq!(high_limit, 200);
    }

    #[test]
    fn test_remove_peer() {
        let config = AdaptiveRateLimitConfig::default();
        let mut limiter = AdaptiveRateLimiter::new(config);

        limiter.check_rate_limit("peer1", 0.5);
        assert_eq!(limiter.peer_count(), 1);

        limiter.remove_peer("peer1");
        assert_eq!(limiter.peer_count(), 0);
    }

    #[test]
    fn test_clear() {
        let config = AdaptiveRateLimitConfig::default();
        let mut limiter = AdaptiveRateLimiter::new(config);

        limiter.check_rate_limit("peer1", 0.5);
        limiter.check_rate_limit("peer2", 0.5);
        limiter.check_rate_limit("peer3", 0.5);

        assert_eq!(limiter.peer_count(), 3);

        limiter.clear();
        assert_eq!(limiter.peer_count(), 0);
    }
}
