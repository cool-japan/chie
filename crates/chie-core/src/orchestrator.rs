//! Request orchestration for intelligent content retrieval.
//!
//! This module provides a high-level orchestrator that coordinates multiple subsystems
//! (peer selection, content routing, reputation, network diagnostics, circuit breakers)
//! to retrieve content efficiently with automatic retries and fallbacks.
//!
//! # Example
//!
//! ```rust
//! use chie_core::orchestrator::{RequestOrchestrator, RetrievalStrategy, OrchestratorConfig};
//! use chie_core::qos::Priority;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = OrchestratorConfig::default();
//!     let orchestrator = RequestOrchestrator::new(config);
//!
//!     // Request content with automatic peer selection and retries
//!     // Priority is optional - None will bypass QoS
//!     let result = orchestrator.retrieve_content(
//!         "QmExample",
//!         RetrievalStrategy::BestEffort,
//!         Some(Priority::High),
//!     ).await?;
//!
//!     println!("Retrieved {} bytes from {} peers",
//!         result.total_bytes, result.peers_used.len());
//!     Ok(())
//! }
//! ```

use crate::{
    adaptive_ratelimit::{AdaptiveRateLimitConfig, AdaptiveRateLimiter},
    cache::TtlCache,
    content_router::ContentRouter,
    network_diag::NetworkMonitor,
    peer_selection::PeerSelector,
    qos::{Priority, QosConfig, QosManager, RequestInfo},
    reputation::{ReputationConfig, ReputationTracker},
    utils::{RetryConfig, current_timestamp_ms},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::Mutex;

/// Retrieval strategy for content requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalStrategy {
    /// Best effort: try multiple peers, accept partial success.
    BestEffort,
    /// Strict: require complete content from single peer.
    Strict,
    /// Redundant: fetch from multiple peers for verification.
    Redundant,
    /// Fastest: race multiple peers, use first response.
    Fastest,
}

/// Configuration for the request orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Maximum concurrent requests.
    pub max_concurrent: usize,
    /// Request timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// Retry configuration.
    pub retry_config: RetryConfig,
    /// Enable request caching.
    pub enable_caching: bool,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Maximum number of peers to try per request.
    pub max_peers_per_request: usize,
    /// Minimum reputation score for peer selection.
    pub min_reputation: f64,
    /// Enable QoS (Quality of Service) request prioritization.
    pub enable_qos: bool,
    /// QoS configuration.
    pub qos_config: QosConfig,
}

impl Default for OrchestratorConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_concurrent: 100,
            request_timeout_ms: 30_000,
            retry_config: RetryConfig::default(),
            enable_caching: true,
            cache_ttl_secs: 300,
            max_peers_per_request: 5,
            min_reputation: 0.3,
            enable_qos: true,
            qos_config: QosConfig::default(),
        }
    }
}

/// Result of a content retrieval operation.
#[derive(Debug, Clone)]
pub struct RetrievalResult {
    /// Content identifier.
    pub cid: String,
    /// Total bytes retrieved.
    pub total_bytes: u64,
    /// Peers that successfully provided data.
    pub peers_used: Vec<String>,
    /// Total time taken in milliseconds.
    pub duration_ms: u64,
    /// Whether the retrieval was complete.
    pub complete: bool,
    /// Number of retries performed.
    pub retries: u32,
}

/// Statistics for the orchestrator.
#[derive(Debug, Clone, Default)]
pub struct OrchestratorStats {
    /// Total requests processed.
    pub total_requests: u64,
    /// Successful requests.
    pub successful_requests: u64,
    /// Failed requests.
    pub failed_requests: u64,
    /// Cached responses.
    pub cache_hits: u64,
    /// Total bytes transferred.
    pub total_bytes: u64,
    /// Total retries performed.
    pub total_retries: u64,
    /// Average request duration in milliseconds.
    pub avg_duration_ms: f64,
}

impl OrchestratorStats {
    /// Calculate success rate.
    #[must_use]
    #[inline]
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    /// Calculate cache hit rate.
    #[must_use]
    #[inline]
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / self.total_requests as f64
    }
}

/// Request context for tracking request state.
#[derive(Debug)]
#[allow(dead_code)]
struct RequestContext {
    cid: String,
    strategy: RetrievalStrategy,
    start_time: i64,
    peers_tried: HashSet<String>,
    bytes_retrieved: u64,
    retries: u32,
}

impl RequestContext {
    #[must_use]
    #[inline]
    fn new(cid: String, strategy: RetrievalStrategy) -> Self {
        Self {
            cid,
            strategy,
            start_time: current_timestamp_ms(),
            peers_tried: HashSet::new(),
            bytes_retrieved: 0,
            retries: 0,
        }
    }

    #[must_use]
    #[inline]
    fn elapsed_ms(&self) -> u64 {
        current_timestamp_ms().saturating_sub(self.start_time) as u64
    }
}

/// Request orchestrator for intelligent content retrieval.
#[allow(dead_code)]
pub struct RequestOrchestrator {
    config: OrchestratorConfig,
    peer_selector: Arc<StdMutex<PeerSelector>>,
    content_router: Arc<StdMutex<ContentRouter>>,
    reputation_tracker: Arc<StdMutex<ReputationTracker>>,
    network_monitor: Arc<StdMutex<NetworkMonitor>>,
    rate_limiter: Arc<StdMutex<AdaptiveRateLimiter>>,
    qos_manager: Arc<Mutex<QosManager>>,
    failed_peers: Arc<StdMutex<HashMap<String, u32>>>, // Track peer failures
    result_cache: Arc<StdMutex<TtlCache<String, RetrievalResult>>>,
    stats: Arc<StdMutex<OrchestratorStats>>,
}

impl RequestOrchestrator {
    /// Create a new request orchestrator.
    #[must_use]
    pub fn new(config: OrchestratorConfig) -> Self {
        let cache_ttl = Duration::from_secs(config.cache_ttl_secs);
        Self {
            qos_manager: Arc::new(Mutex::new(QosManager::new(config.qos_config.clone()))),
            config: config.clone(),
            peer_selector: Arc::new(StdMutex::new(PeerSelector::new())),
            content_router: Arc::new(StdMutex::new(ContentRouter::new())),
            reputation_tracker: Arc::new(StdMutex::new(ReputationTracker::new(
                ReputationConfig::default(),
            ))),
            network_monitor: Arc::new(StdMutex::new(NetworkMonitor::new())),
            rate_limiter: Arc::new(StdMutex::new(AdaptiveRateLimiter::new(
                AdaptiveRateLimitConfig::default(),
            ))),
            failed_peers: Arc::new(StdMutex::new(HashMap::new())),
            result_cache: Arc::new(StdMutex::new(TtlCache::new(1000, cache_ttl))),
            stats: Arc::new(StdMutex::new(OrchestratorStats::default())),
        }
    }

    /// Retrieve content using the specified strategy.
    ///
    /// If QoS is enabled and a priority is provided, the request will be queued
    /// and processed according to its priority level.
    pub async fn retrieve_content(
        &self,
        cid: &str,
        strategy: RetrievalStrategy,
        priority: Option<Priority>,
    ) -> Result<RetrievalResult, OrchestratorError> {
        // Check cache first
        if self.config.enable_caching {
            let cid_owned = cid.to_string();
            if let Some(cached) = self.result_cache.lock().unwrap().get(&cid_owned) {
                self.stats.lock().unwrap().cache_hits += 1;
                return Ok(cached.clone());
            }
        }

        // QoS integration: enqueue request if enabled and priority provided
        let request_id = format!("{}:{}", cid, current_timestamp_ms());
        if self.config.enable_qos && priority.is_some() {
            let qos_request = RequestInfo {
                id: request_id.clone(),
                cid: cid.to_string(),
                size_bytes: 0, // Size unknown at this point
                priority: priority.unwrap_or_default(),
                deadline_ms: None, // No deadline for now
            };

            // Enqueue the request
            let enqueued = self.qos_manager.lock().await.enqueue(qos_request).await;
            if !enqueued {
                // Queue is full, apply backpressure
                return Err(OrchestratorError::QueueFull);
            }

            // For now, immediately dequeue to proceed (simple implementation)
            // In a more sophisticated implementation, we would wait for a worker
            // to dequeue and signal us to proceed
            let _ = self.qos_manager.lock().await.dequeue().await;
        }

        let mut ctx = RequestContext::new(cid.to_string(), strategy);

        let result = match strategy {
            RetrievalStrategy::BestEffort => self.retrieve_best_effort(&mut ctx).await,
            RetrievalStrategy::Strict => self.retrieve_strict(&mut ctx).await,
            RetrievalStrategy::Redundant => self.retrieve_redundant(&mut ctx).await,
            RetrievalStrategy::Fastest => self.retrieve_fastest(&mut ctx).await,
        };

        // Update statistics
        let mut stats = self.stats.lock().unwrap();
        stats.total_requests += 1;

        match &result {
            Ok(res) => {
                stats.successful_requests += 1;
                stats.total_bytes += res.total_bytes;
                stats.total_retries += res.retries as u64;

                // Update average duration
                let total = stats.successful_requests as f64;
                stats.avg_duration_ms =
                    (stats.avg_duration_ms * (total - 1.0) + res.duration_ms as f64) / total;

                // Cache the result
                if self.config.enable_caching {
                    let cid_owned = cid.to_string();
                    self.result_cache
                        .lock()
                        .unwrap()
                        .insert(cid_owned, res.clone());
                }
            }
            Err(_) => {
                stats.failed_requests += 1;
            }
        }

        result
    }

    /// Retrieve content with best effort (try multiple peers).
    async fn retrieve_best_effort(
        &self,
        ctx: &mut RequestContext,
    ) -> Result<RetrievalResult, OrchestratorError> {
        let peers = self.select_peers_for_content(&ctx.cid)?;

        for peer in peers.iter().take(self.config.max_peers_per_request) {
            if ctx.peers_tried.contains(peer) {
                continue;
            }

            // Check circuit breaker
            if !self.is_peer_available(peer) {
                continue;
            }

            // Check rate limit
            if !self.check_rate_limit(peer) {
                continue;
            }

            ctx.peers_tried.insert(peer.clone());

            // Attempt retrieval
            match self.retrieve_from_peer(&ctx.cid, peer, ctx).await {
                Ok(bytes) => {
                    ctx.bytes_retrieved += bytes;

                    // Record success
                    self.record_peer_success(peer, bytes, ctx.elapsed_ms());

                    // For best effort, partial success is OK
                    return Ok(RetrievalResult {
                        cid: ctx.cid.clone(),
                        total_bytes: ctx.bytes_retrieved,
                        peers_used: vec![peer.clone()],
                        duration_ms: ctx.elapsed_ms(),
                        complete: true,
                        retries: ctx.retries,
                    });
                }
                Err(_) => {
                    ctx.retries += 1;
                    self.record_peer_failure(peer);
                    continue;
                }
            }
        }

        Err(OrchestratorError::NoAvailablePeers)
    }

    /// Retrieve content with strict requirements (complete from single peer).
    async fn retrieve_strict(
        &self,
        ctx: &mut RequestContext,
    ) -> Result<RetrievalResult, OrchestratorError> {
        let peers = self.select_peers_for_content(&ctx.cid)?;

        for peer in peers.iter().take(self.config.max_peers_per_request) {
            if !self.is_peer_available(peer) || !self.check_rate_limit(peer) {
                continue;
            }

            ctx.peers_tried.insert(peer.clone());

            match self.retrieve_from_peer(&ctx.cid, peer, ctx).await {
                Ok(bytes) => {
                    self.record_peer_success(peer, bytes, ctx.elapsed_ms());

                    return Ok(RetrievalResult {
                        cid: ctx.cid.clone(),
                        total_bytes: bytes,
                        peers_used: vec![peer.clone()],
                        duration_ms: ctx.elapsed_ms(),
                        complete: true,
                        retries: ctx.retries,
                    });
                }
                Err(_) => {
                    ctx.retries += 1;
                    self.record_peer_failure(peer);
                }
            }
        }

        Err(OrchestratorError::RetrievalFailed)
    }

    /// Retrieve content with redundancy (from multiple peers for verification).
    async fn retrieve_redundant(
        &self,
        ctx: &mut RequestContext,
    ) -> Result<RetrievalResult, OrchestratorError> {
        let peers = self.select_peers_for_content(&ctx.cid)?;
        let redundancy_count = 2.min(peers.len());

        let mut successful_peers = Vec::new();
        let mut total_bytes = 0;

        for peer in peers.iter().take(redundancy_count) {
            if !self.is_peer_available(peer) || !self.check_rate_limit(peer) {
                continue;
            }

            ctx.peers_tried.insert(peer.clone());

            if let Ok(bytes) = self.retrieve_from_peer(&ctx.cid, peer, ctx).await {
                self.record_peer_success(peer, bytes, ctx.elapsed_ms());
                successful_peers.push(peer.clone());
                total_bytes = bytes; // Assume same size
            } else {
                self.record_peer_failure(peer);
            }
        }

        if successful_peers.len() >= redundancy_count {
            Ok(RetrievalResult {
                cid: ctx.cid.clone(),
                total_bytes,
                peers_used: successful_peers,
                duration_ms: ctx.elapsed_ms(),
                complete: true,
                retries: ctx.retries,
            })
        } else {
            Err(OrchestratorError::InsufficientRedundancy)
        }
    }

    /// Retrieve content using fastest peer (race multiple peers).
    async fn retrieve_fastest(
        &self,
        ctx: &mut RequestContext,
    ) -> Result<RetrievalResult, OrchestratorError> {
        // For simplicity, use best effort strategy (in real implementation, use tokio::select!)
        self.retrieve_best_effort(ctx).await
    }

    /// Select peers for content based on routing and reputation.
    fn select_peers_for_content(&self, cid: &str) -> Result<Vec<String>, OrchestratorError> {
        let mut router = self.content_router.lock().unwrap();
        let peers = router.find_peers(cid, 10);

        if peers.is_empty() {
            return Err(OrchestratorError::ContentNotFound);
        }

        // Filter by reputation and return qualified peer IDs
        let mut reputation = self.reputation_tracker.lock().unwrap();
        let qualified: Vec<String> = peers
            .into_iter()
            .filter(|p| reputation.get_reputation(p) >= self.config.min_reputation)
            .collect();

        if qualified.is_empty() {
            return Err(OrchestratorError::NoQualifiedPeers);
        }

        // Return qualified peers (peer selector would need candidates added first)
        Ok(qualified)
    }

    /// Check if peer is available (simple failure tracking).
    #[inline]
    fn is_peer_available(&self, peer_id: &str) -> bool {
        let failures = self.failed_peers.lock().unwrap();
        let count = failures.get(peer_id).copied().unwrap_or(0);
        count < 5 // Max 5 failures before blocking
    }

    /// Check rate limit for peer.
    #[inline]
    fn check_rate_limit(&self, peer_id: &str) -> bool {
        let mut reputation = self.reputation_tracker.lock().unwrap();
        let score = reputation.get_reputation(peer_id);

        let mut limiter = self.rate_limiter.lock().unwrap();
        limiter.check_rate_limit(peer_id, score)
    }

    /// Record peer success.
    #[inline]
    fn record_peer_success(&self, peer_id: &str, bytes: u64, latency_ms: u64) {
        // Update reputation
        self.reputation_tracker
            .lock()
            .unwrap()
            .record_success(peer_id.to_string(), bytes);

        // Update network diagnostics
        self.network_monitor
            .lock()
            .unwrap()
            .record_latency(peer_id.to_string(), latency_ms);

        // Clear failure count
        self.failed_peers.lock().unwrap().remove(peer_id);
    }

    /// Record peer failure.
    #[inline]
    fn record_peer_failure(&self, peer_id: &str) {
        // Update reputation (with default penalty of 1000 bytes)
        self.reputation_tracker
            .lock()
            .unwrap()
            .record_failure(peer_id.to_string(), 1000);

        // Increment failure count
        let mut failures = self.failed_peers.lock().unwrap();
        *failures.entry(peer_id.to_string()).or_insert(0) += 1;
    }

    /// Simulate retrieving content from a peer.
    async fn retrieve_from_peer(
        &self,
        _cid: &str,
        _peer_id: &str,
        _ctx: &RequestContext,
    ) -> Result<u64, OrchestratorError> {
        // In a real implementation, this would:
        // 1. Open connection to peer
        // 2. Send chunk request
        // 3. Receive and decrypt chunks
        // 4. Verify integrity
        // 5. Return total bytes

        // For now, simulate success
        Ok(1024 * 1024) // 1 MB
    }

    /// Get orchestrator statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> OrchestratorStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics.
    #[inline]
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = OrchestratorStats::default();
    }

    /// Get QoS metrics for a specific priority level.
    ///
    /// Returns None if QoS is disabled or if no metrics exist for the priority level.
    #[must_use]
    #[inline]
    pub async fn qos_metrics(&self, priority: Priority) -> Option<crate::qos::SlaMetrics> {
        if !self.config.enable_qos {
            return None;
        }
        self.qos_manager.lock().await.get_sla_metrics(priority)
    }

    /// Clear result cache.
    #[inline]
    pub fn clear_cache(&self) {
        self.result_cache.lock().unwrap().clear();
    }
}

/// Errors that can occur during orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    /// Content not found in routing table.
    ContentNotFound,
    /// No peers available for content.
    NoAvailablePeers,
    /// No peers meet minimum reputation requirement.
    NoQualifiedPeers,
    /// Retrieval failed from all peers.
    RetrievalFailed,
    /// Insufficient redundancy for redundant strategy.
    InsufficientRedundancy,
    /// Request timeout.
    Timeout,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// QoS queue is full.
    QueueFull,
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContentNotFound => write!(f, "Content not found"),
            Self::NoAvailablePeers => write!(f, "No available peers"),
            Self::NoQualifiedPeers => write!(f, "No qualified peers"),
            Self::RetrievalFailed => write!(f, "Retrieval failed"),
            Self::InsufficientRedundancy => write!(f, "Insufficient redundancy"),
            Self::Timeout => write!(f, "Request timeout"),
            Self::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            Self::QueueFull => write!(f, "QoS queue is full"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_config_default() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.max_concurrent, 100);
        assert_eq!(config.request_timeout_ms, 30_000);
        assert!(config.enable_caching);
        assert_eq!(config.cache_ttl_secs, 300);
    }

    #[test]
    fn test_orchestrator_creation() {
        let config = OrchestratorConfig::default();
        let orchestrator = RequestOrchestrator::new(config);
        let stats = orchestrator.stats();
        assert_eq!(stats.total_requests, 0);
    }

    #[test]
    fn test_orchestrator_stats() {
        let mut stats = OrchestratorStats::default();
        assert_eq!(stats.success_rate(), 0.0);
        assert_eq!(stats.cache_hit_rate(), 0.0);

        stats.total_requests = 100;
        stats.successful_requests = 80;
        stats.cache_hits = 20;

        assert_eq!(stats.success_rate(), 0.8);
        assert_eq!(stats.cache_hit_rate(), 0.2);
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new("QmTest".to_string(), RetrievalStrategy::BestEffort);
        assert_eq!(ctx.cid, "QmTest");
        assert_eq!(ctx.strategy, RetrievalStrategy::BestEffort);
        assert_eq!(ctx.peers_tried.len(), 0);
        assert_eq!(ctx.bytes_retrieved, 0);
        assert_eq!(ctx.retries, 0);
    }

    #[test]
    fn test_retrieval_strategies() {
        assert_eq!(RetrievalStrategy::BestEffort, RetrievalStrategy::BestEffort);
        assert_ne!(RetrievalStrategy::Strict, RetrievalStrategy::Redundant);
    }

    #[tokio::test]
    async fn test_content_not_found() {
        let config = OrchestratorConfig::default();
        let orchestrator = RequestOrchestrator::new(config);

        let result = orchestrator
            .retrieve_content("QmNonExistent", RetrievalStrategy::BestEffort, None)
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), OrchestratorError::ContentNotFound);
    }

    #[test]
    fn test_orchestrator_reset_stats() {
        let config = OrchestratorConfig::default();
        let orchestrator = RequestOrchestrator::new(config);

        {
            let mut stats = orchestrator.stats.lock().unwrap();
            stats.total_requests = 100;
            stats.successful_requests = 80;
        }

        orchestrator.reset_stats();
        let stats = orchestrator.stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful_requests, 0);
    }

    #[test]
    fn test_orchestrator_clear_cache() {
        let config = OrchestratorConfig::default();
        let orchestrator = RequestOrchestrator::new(config);

        orchestrator.clear_cache();
        assert_eq!(orchestrator.result_cache.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_orchestrator_error_display() {
        assert_eq!(
            OrchestratorError::ContentNotFound.to_string(),
            "Content not found"
        );
        assert_eq!(
            OrchestratorError::NoAvailablePeers.to_string(),
            "No available peers"
        );
        assert_eq!(OrchestratorError::Timeout.to_string(), "Request timeout");
    }

    #[test]
    fn test_retrieval_result_clone() {
        let result = RetrievalResult {
            cid: "QmTest".to_string(),
            total_bytes: 1024,
            peers_used: vec!["peer1".to_string()],
            duration_ms: 100,
            complete: true,
            retries: 0,
        };

        let cloned = result.clone();
        assert_eq!(cloned.cid, result.cid);
        assert_eq!(cloned.total_bytes, result.total_bytes);
    }
}
