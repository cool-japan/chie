//! Bandwidth throttling for P2P transfers.
//!
//! This module provides:
//! - Per-peer bandwidth limiting
//! - Global bandwidth limiting
//! - Token bucket rate limiting
//! - Transfer statistics

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Configuration for bandwidth throttling.
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Maximum upload bandwidth per peer (bytes/sec).
    pub max_upload_per_peer: u64,
    /// Maximum download bandwidth per peer (bytes/sec).
    pub max_download_per_peer: u64,
    /// Maximum total upload bandwidth (bytes/sec).
    pub max_total_upload: u64,
    /// Maximum total download bandwidth (bytes/sec).
    pub max_total_download: u64,
    /// Bucket refill interval.
    pub refill_interval: Duration,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_upload_per_peer: 10 * 1024 * 1024,   // 10 MB/s per peer
            max_download_per_peer: 50 * 1024 * 1024, // 50 MB/s per peer
            max_total_upload: 50 * 1024 * 1024,      // 50 MB/s total
            max_total_download: 100 * 1024 * 1024,   // 100 MB/s total
            refill_interval: Duration::from_millis(100),
        }
    }
}

impl ThrottleConfig {
    /// Create an unlimited configuration (no throttling).
    pub fn unlimited() -> Self {
        Self {
            max_upload_per_peer: u64::MAX,
            max_download_per_peer: u64::MAX,
            max_total_upload: u64::MAX,
            max_total_download: u64::MAX,
            refill_interval: Duration::from_millis(100),
        }
    }
}

/// Token bucket for rate limiting.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current tokens available.
    tokens: u64,
    /// Maximum tokens (capacity).
    capacity: u64,
    /// Tokens added per second.
    refill_rate: u64,
    /// Last refill time.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    pub fn new(capacity: u64, refill_rate: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.refill_rate as f64) as u64;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Try to consume tokens. Returns true if successful.
    pub fn try_consume(&mut self, amount: u64) -> bool {
        self.refill();

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Get available tokens.
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens
    }

    /// Get time until `amount` tokens are available.
    pub fn time_until_available(&mut self, amount: u64) -> Duration {
        self.refill();

        if self.tokens >= amount {
            return Duration::ZERO;
        }

        let needed = amount - self.tokens;
        let seconds = needed as f64 / self.refill_rate as f64;
        Duration::from_secs_f64(seconds)
    }
}

/// Per-peer throttling state.
#[derive(Debug)]
pub struct PeerThrottle {
    /// Upload bucket.
    pub upload: TokenBucket,
    /// Download bucket.
    pub download: TokenBucket,
    /// Total bytes uploaded.
    pub total_uploaded: u64,
    /// Total bytes downloaded.
    pub total_downloaded: u64,
    /// First seen time.
    pub first_seen: Instant,
}

impl PeerThrottle {
    /// Create a new peer throttle.
    pub fn new(config: &ThrottleConfig) -> Self {
        Self {
            upload: TokenBucket::new(config.max_upload_per_peer, config.max_upload_per_peer),
            download: TokenBucket::new(config.max_download_per_peer, config.max_download_per_peer),
            total_uploaded: 0,
            total_downloaded: 0,
            first_seen: Instant::now(),
        }
    }

    /// Get average upload speed (bytes/sec).
    pub fn avg_upload_speed(&self) -> f64 {
        let elapsed = self.first_seen.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_uploaded as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get average download speed (bytes/sec).
    pub fn avg_download_speed(&self) -> f64 {
        let elapsed = self.first_seen.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.total_downloaded as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// Bandwidth throttle manager.
pub struct BandwidthThrottle {
    /// Configuration.
    config: ThrottleConfig,
    /// Global upload bucket.
    global_upload: TokenBucket,
    /// Global download bucket.
    global_download: TokenBucket,
    /// Per-peer state.
    peers: HashMap<String, PeerThrottle>,
    /// Statistics.
    stats: ThrottleStats,
}

impl BandwidthThrottle {
    /// Create a new bandwidth throttle.
    pub fn new(config: ThrottleConfig) -> Self {
        let global_upload = TokenBucket::new(config.max_total_upload, config.max_total_upload);
        let global_download =
            TokenBucket::new(config.max_total_download, config.max_total_download);

        Self {
            config,
            global_upload,
            global_download,
            peers: HashMap::new(),
            stats: ThrottleStats::default(),
        }
    }

    /// Get or create peer throttle.
    #[allow(dead_code)]
    fn get_or_create_peer(&mut self, peer_id: &str) -> &mut PeerThrottle {
        if !self.peers.contains_key(peer_id) {
            self.peers
                .insert(peer_id.to_string(), PeerThrottle::new(&self.config));
        }
        self.peers.get_mut(peer_id).unwrap()
    }

    /// Check if upload is allowed and consume tokens if so.
    pub fn try_upload(&mut self, peer_id: &str, bytes: u64) -> ThrottleResult {
        // Check global limit first
        if !self.global_upload.try_consume(bytes) {
            self.stats.upload_throttled_count += 1;
            return ThrottleResult::Throttled {
                wait_time: self.global_upload.time_until_available(bytes),
                reason: ThrottleReason::GlobalLimit,
            };
        }

        // Ensure peer exists
        if !self.peers.contains_key(peer_id) {
            self.peers
                .insert(peer_id.to_string(), PeerThrottle::new(&self.config));
        }

        // Check per-peer limit
        let peer = self.peers.get_mut(peer_id).unwrap();
        if !peer.upload.try_consume(bytes) {
            // Refund global tokens
            let wait_time = peer.upload.time_until_available(bytes);
            self.global_upload.tokens += bytes;
            self.stats.upload_throttled_count += 1;
            return ThrottleResult::Throttled {
                wait_time,
                reason: ThrottleReason::PeerLimit,
            };
        }

        // Update statistics
        peer.total_uploaded += bytes;
        self.stats.total_uploaded += bytes;
        self.stats.upload_count += 1;

        ThrottleResult::Allowed
    }

    /// Check if download is allowed and consume tokens if so.
    pub fn try_download(&mut self, peer_id: &str, bytes: u64) -> ThrottleResult {
        // Check global limit first
        if !self.global_download.try_consume(bytes) {
            self.stats.download_throttled_count += 1;
            return ThrottleResult::Throttled {
                wait_time: self.global_download.time_until_available(bytes),
                reason: ThrottleReason::GlobalLimit,
            };
        }

        // Ensure peer exists
        if !self.peers.contains_key(peer_id) {
            self.peers
                .insert(peer_id.to_string(), PeerThrottle::new(&self.config));
        }

        // Check per-peer limit
        let peer = self.peers.get_mut(peer_id).unwrap();
        if !peer.download.try_consume(bytes) {
            // Refund global tokens
            let wait_time = peer.download.time_until_available(bytes);
            self.global_download.tokens += bytes;
            self.stats.download_throttled_count += 1;
            return ThrottleResult::Throttled {
                wait_time,
                reason: ThrottleReason::PeerLimit,
            };
        }

        // Update statistics
        peer.total_downloaded += bytes;
        self.stats.total_downloaded += bytes;
        self.stats.download_count += 1;

        ThrottleResult::Allowed
    }

    /// Get statistics.
    pub fn stats(&self) -> &ThrottleStats {
        &self.stats
    }

    /// Get peer statistics.
    pub fn peer_stats(&self, peer_id: &str) -> Option<PeerTransferStats> {
        self.peers.get(peer_id).map(|p| PeerTransferStats {
            total_uploaded: p.total_uploaded,
            total_downloaded: p.total_downloaded,
            avg_upload_speed: p.avg_upload_speed(),
            avg_download_speed: p.avg_download_speed(),
            connection_duration: p.first_seen.elapsed(),
        })
    }

    /// Remove peer state.
    pub fn remove_peer(&mut self, peer_id: &str) -> Option<PeerTransferStats> {
        self.peers.remove(peer_id).map(|p| PeerTransferStats {
            total_uploaded: p.total_uploaded,
            total_downloaded: p.total_downloaded,
            avg_upload_speed: p.avg_upload_speed(),
            avg_download_speed: p.avg_download_speed(),
            connection_duration: p.first_seen.elapsed(),
        })
    }

    /// Get number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Result of throttle check.
#[derive(Debug, Clone)]
pub enum ThrottleResult {
    /// Transfer allowed.
    Allowed,
    /// Transfer throttled.
    Throttled {
        /// Time to wait before retrying.
        wait_time: Duration,
        /// Reason for throttling.
        reason: ThrottleReason,
    },
}

impl ThrottleResult {
    /// Check if allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, ThrottleResult::Allowed)
    }
}

/// Reason for throttling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleReason {
    /// Global bandwidth limit reached.
    GlobalLimit,
    /// Per-peer bandwidth limit reached.
    PeerLimit,
}

/// Statistics for per-peer transfers.
#[derive(Debug, Clone)]
pub struct PeerTransferStats {
    /// Total bytes uploaded to this peer.
    pub total_uploaded: u64,
    /// Total bytes downloaded from this peer.
    pub total_downloaded: u64,
    /// Average upload speed (bytes/sec).
    pub avg_upload_speed: f64,
    /// Average download speed (bytes/sec).
    pub avg_download_speed: f64,
    /// Connection duration.
    pub connection_duration: Duration,
}

/// Global throttle statistics.
#[derive(Debug, Clone, Default)]
pub struct ThrottleStats {
    /// Total bytes uploaded.
    pub total_uploaded: u64,
    /// Total bytes downloaded.
    pub total_downloaded: u64,
    /// Number of successful uploads.
    pub upload_count: u64,
    /// Number of successful downloads.
    pub download_count: u64,
    /// Number of throttled uploads.
    pub upload_throttled_count: u64,
    /// Number of throttled downloads.
    pub download_throttled_count: u64,
}

/// Shared bandwidth throttle.
pub type SharedBandwidthThrottle = Arc<Mutex<BandwidthThrottle>>;

/// Create a shared bandwidth throttle.
pub fn create_throttle(config: ThrottleConfig) -> SharedBandwidthThrottle {
    Arc::new(Mutex::new(BandwidthThrottle::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1000, 100);

        assert!(bucket.try_consume(500));
        assert_eq!(bucket.tokens, 500);

        assert!(bucket.try_consume(500));
        assert_eq!(bucket.tokens, 0);

        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_throttle_allowed() {
        let config = ThrottleConfig::default();
        let mut throttle = BandwidthThrottle::new(config);

        let result = throttle.try_upload("peer1", 1000);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_throttle_limited() {
        let config = ThrottleConfig {
            max_upload_per_peer: 1000,
            max_total_upload: 1000,
            ..Default::default()
        };
        let mut throttle = BandwidthThrottle::new(config);

        // First transfer should succeed
        assert!(throttle.try_upload("peer1", 1000).is_allowed());

        // Second transfer should be throttled
        let result = throttle.try_upload("peer1", 100);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_peer_stats() {
        let config = ThrottleConfig::default();
        let mut throttle = BandwidthThrottle::new(config);

        throttle.try_upload("peer1", 1000);
        throttle.try_download("peer1", 2000);

        let stats = throttle.peer_stats("peer1").unwrap();
        assert_eq!(stats.total_uploaded, 1000);
        assert_eq!(stats.total_downloaded, 2000);
    }
}
