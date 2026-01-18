//! Bandwidth rate limiting for P2P transfers.
//!
//! This module provides token bucket based rate limiting for controlling
//! upload and download bandwidth usage.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum upload rate in bytes per second (0 = unlimited).
    pub upload_rate: u64,
    /// Maximum download rate in bytes per second (0 = unlimited).
    pub download_rate: u64,
    /// Burst size multiplier (allows temporary bursts above the rate).
    pub burst_multiplier: f64,
    /// Minimum bytes to transfer before rate limiting kicks in.
    pub min_transfer_size: u64,
    /// Whether to enable rate limiting.
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            upload_rate: 0,          // Unlimited by default
            download_rate: 0,        // Unlimited by default
            burst_multiplier: 1.5,   // Allow 50% burst
            min_transfer_size: 1024, // Don't rate limit small transfers
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Create config with specific upload/download rates.
    #[must_use]
    #[inline]
    pub fn with_rates(upload_mbps: f64, download_mbps: f64) -> Self {
        Self {
            upload_rate: (upload_mbps * 1_000_000.0 / 8.0) as u64,
            download_rate: (download_mbps * 1_000_000.0 / 8.0) as u64,
            ..Default::default()
        }
    }

    /// Create config for symmetric rate.
    #[must_use]
    #[inline]
    pub fn symmetric(rate_mbps: f64) -> Self {
        Self::with_rates(rate_mbps, rate_mbps)
    }

    /// Disable rate limiting.
    #[must_use]
    #[inline]
    pub fn unlimited() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Token bucket for rate limiting.
struct TokenBucket {
    /// Current tokens (bytes allowed).
    tokens: AtomicU64,
    /// Maximum tokens (burst capacity).
    max_tokens: u64,
    /// Tokens added per second.
    rate: u64,
    /// Last refill time.
    last_refill: RwLock<Instant>,
}

impl TokenBucket {
    fn new(rate: u64, burst_multiplier: f64) -> Self {
        let max_tokens = (rate as f64 * burst_multiplier) as u64;
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            rate,
            last_refill: RwLock::new(Instant::now()),
        }
    }

    async fn refill(&self) {
        let mut last = self.last_refill.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed.as_millis() > 0 {
            let new_tokens = (elapsed.as_secs_f64() * self.rate as f64) as u64;
            let current = self.tokens.load(Ordering::Relaxed);
            let updated = current.saturating_add(new_tokens).min(self.max_tokens);
            self.tokens.store(updated, Ordering::Relaxed);
            *last = now;
        }
    }

    async fn consume(&self, bytes: u64) -> Duration {
        self.refill().await;

        let current = self.tokens.load(Ordering::Relaxed);

        if current >= bytes {
            self.tokens.fetch_sub(bytes, Ordering::Relaxed);
            Duration::ZERO
        } else {
            // Not enough tokens - calculate wait time
            let needed = bytes.saturating_sub(current);
            let wait_secs = needed as f64 / self.rate as f64;
            Duration::from_secs_f64(wait_secs)
        }
    }

    fn available(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

/// Bandwidth rate limiter.
pub struct BandwidthLimiter {
    config: RateLimitConfig,
    upload_bucket: Option<TokenBucket>,
    download_bucket: Option<TokenBucket>,
    stats: Arc<RwLock<BandwidthStats>>,
}

/// Bandwidth usage statistics.
#[derive(Debug, Clone, Default)]
pub struct BandwidthStats {
    /// Total bytes uploaded.
    pub bytes_uploaded: u64,
    /// Total bytes downloaded.
    pub bytes_downloaded: u64,
    /// Upload rate (bytes/sec, rolling average).
    pub upload_rate: f64,
    /// Download rate (bytes/sec, rolling average).
    pub download_rate: f64,
    /// Time spent waiting due to rate limiting.
    pub total_wait_time: Duration,
    /// Number of transfers that were rate limited.
    pub limited_transfers: u64,
    /// Start time for stats.
    pub started_at: Option<Instant>,
}

impl BandwidthStats {
    fn new() -> Self {
        Self {
            started_at: Some(Instant::now()),
            ..Default::default()
        }
    }

    fn update_rates(&mut self) {
        if let Some(start) = self.started_at {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.upload_rate = self.bytes_uploaded as f64 / elapsed;
                self.download_rate = self.bytes_downloaded as f64 / elapsed;
            }
        }
    }
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter.
    #[must_use]
    #[inline]
    pub fn new(config: RateLimitConfig) -> Self {
        let upload_bucket = if config.enabled && config.upload_rate > 0 {
            Some(TokenBucket::new(
                config.upload_rate,
                config.burst_multiplier,
            ))
        } else {
            None
        };

        let download_bucket = if config.enabled && config.download_rate > 0 {
            Some(TokenBucket::new(
                config.download_rate,
                config.burst_multiplier,
            ))
        } else {
            None
        };

        Self {
            config,
            upload_bucket,
            download_bucket,
            stats: Arc::new(RwLock::new(BandwidthStats::new())),
        }
    }

    /// Rate limit an upload operation.
    ///
    /// Returns when the transfer is allowed to proceed.
    pub async fn limit_upload(&self, bytes: u64) {
        if !self.config.enabled || bytes < self.config.min_transfer_size {
            return;
        }

        if let Some(ref bucket) = self.upload_bucket {
            let wait = bucket.consume(bytes).await;
            if !wait.is_zero() {
                let mut stats = self.stats.write().await;
                stats.total_wait_time += wait;
                stats.limited_transfers += 1;
                drop(stats);

                sleep(wait).await;
            }

            let mut stats = self.stats.write().await;
            stats.bytes_uploaded += bytes;
            stats.update_rates();
        }
    }

    /// Rate limit a download operation.
    pub async fn limit_download(&self, bytes: u64) {
        if !self.config.enabled || bytes < self.config.min_transfer_size {
            return;
        }

        if let Some(ref bucket) = self.download_bucket {
            let wait = bucket.consume(bytes).await;
            if !wait.is_zero() {
                let mut stats = self.stats.write().await;
                stats.total_wait_time += wait;
                stats.limited_transfers += 1;
                drop(stats);

                sleep(wait).await;
            }

            let mut stats = self.stats.write().await;
            stats.bytes_downloaded += bytes;
            stats.update_rates();
        }
    }

    /// Record bytes transferred without rate limiting (for stats only).
    pub async fn record_upload(&self, bytes: u64) {
        let mut stats = self.stats.write().await;
        stats.bytes_uploaded += bytes;
        stats.update_rates();
    }

    /// Record bytes transferred without rate limiting (for stats only).
    pub async fn record_download(&self, bytes: u64) {
        let mut stats = self.stats.write().await;
        stats.bytes_downloaded += bytes;
        stats.update_rates();
    }

    /// Get current bandwidth statistics.
    #[must_use]
    pub async fn stats(&self) -> BandwidthStats {
        self.stats.read().await.clone()
    }

    /// Get available upload tokens (for flow control decisions).
    #[must_use]
    #[inline]
    pub fn available_upload(&self) -> Option<u64> {
        self.upload_bucket.as_ref().map(|b| b.available())
    }

    /// Get available download tokens.
    #[must_use]
    #[inline]
    pub fn available_download(&self) -> Option<u64> {
        self.download_bucket.as_ref().map(|b| b.available())
    }

    /// Check if rate limiting is enabled.
    #[must_use]
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get configured upload rate.
    #[must_use]
    #[inline]
    pub fn upload_rate(&self) -> u64 {
        self.config.upload_rate
    }

    /// Get configured download rate.
    #[must_use]
    #[inline]
    pub fn download_rate(&self) -> u64 {
        self.config.download_rate
    }
}

/// Per-peer rate limiter for fair bandwidth distribution.
pub struct PeerRateLimiter {
    /// Global limiter.
    global: Arc<BandwidthLimiter>,
    /// Per-peer limiters.
    peer_limiters: RwLock<std::collections::HashMap<String, Arc<BandwidthLimiter>>>,
    /// Per-peer rate (fraction of global).
    peer_rate_fraction: f64,
}

impl PeerRateLimiter {
    /// Create a new per-peer rate limiter.
    #[must_use]
    #[inline]
    pub fn new(global_config: RateLimitConfig, peer_rate_fraction: f64) -> Self {
        Self {
            global: Arc::new(BandwidthLimiter::new(global_config)),
            peer_limiters: RwLock::new(std::collections::HashMap::new()),
            peer_rate_fraction,
        }
    }

    /// Get or create a rate limiter for a peer.
    #[must_use]
    pub async fn get_peer_limiter(&self, peer_id: &str) -> Arc<BandwidthLimiter> {
        {
            let limiters = self.peer_limiters.read().await;
            if let Some(limiter) = limiters.get(peer_id) {
                return Arc::clone(limiter);
            }
        }

        let peer_config = RateLimitConfig {
            upload_rate: (self.global.upload_rate() as f64 * self.peer_rate_fraction) as u64,
            download_rate: (self.global.download_rate() as f64 * self.peer_rate_fraction) as u64,
            burst_multiplier: 2.0, // Allow more burst per-peer
            min_transfer_size: 512,
            enabled: self.global.is_enabled(),
        };

        let limiter = Arc::new(BandwidthLimiter::new(peer_config));

        let mut limiters = self.peer_limiters.write().await;
        limiters.insert(peer_id.to_string(), Arc::clone(&limiter));

        limiter
    }

    /// Rate limit an upload to a specific peer.
    pub async fn limit_upload(&self, peer_id: &str, bytes: u64) {
        // Apply both global and per-peer limits
        self.global.limit_upload(bytes).await;

        let peer_limiter = self.get_peer_limiter(peer_id).await;
        peer_limiter.limit_upload(bytes).await;
    }

    /// Rate limit a download from a specific peer.
    pub async fn limit_download(&self, peer_id: &str, bytes: u64) {
        self.global.limit_download(bytes).await;

        let peer_limiter = self.get_peer_limiter(peer_id).await;
        peer_limiter.limit_download(bytes).await;
    }

    /// Get global statistics.
    #[must_use]
    pub async fn global_stats(&self) -> BandwidthStats {
        self.global.stats().await
    }

    /// Get statistics for a specific peer.
    #[must_use]
    pub async fn peer_stats(&self, peer_id: &str) -> Option<BandwidthStats> {
        let limiters = self.peer_limiters.read().await;
        if let Some(limiter) = limiters.get(peer_id) {
            Some(limiter.stats().await)
        } else {
            None
        }
    }

    /// Remove a peer's limiter (when disconnected).
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut limiters = self.peer_limiters.write().await;
        limiters.remove(peer_id);
    }

    /// Get number of tracked peers.
    #[must_use]
    pub async fn peer_count(&self) -> usize {
        self.peer_limiters.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert_eq!(config.upload_rate, 0);
        assert_eq!(config.download_rate, 0);
    }

    #[test]
    fn test_config_with_rates() {
        let config = RateLimitConfig::with_rates(100.0, 50.0); // 100 Mbps up, 50 Mbps down
        assert_eq!(config.upload_rate, 12_500_000); // 100 Mbps = 12.5 MB/s
        assert_eq!(config.download_rate, 6_250_000); // 50 Mbps = 6.25 MB/s
    }

    #[tokio::test]
    async fn test_unlimited_limiter() {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);

        // Should not block at all
        let start = Instant::now();
        limiter.limit_upload(10_000_000).await; // 10 MB
        limiter.limit_download(10_000_000).await;
        assert!(start.elapsed() < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_stats_recording() {
        let config = RateLimitConfig::unlimited();
        let limiter = BandwidthLimiter::new(config);

        limiter.record_upload(1000).await;
        limiter.record_download(2000).await;

        let stats = limiter.stats().await;
        assert_eq!(stats.bytes_uploaded, 1000);
        assert_eq!(stats.bytes_downloaded, 2000);
    }

    #[tokio::test]
    async fn test_peer_rate_limiter() {
        let global_config = RateLimitConfig::unlimited();
        let peer_limiter = PeerRateLimiter::new(global_config, 0.25);

        // Get limiter for a peer
        let _limiter = peer_limiter.get_peer_limiter("peer1").await;
        assert_eq!(peer_limiter.peer_count().await, 1);

        // Remove peer
        peer_limiter.remove_peer("peer1").await;
        assert_eq!(peer_limiter.peer_count().await, 0);
    }
}
