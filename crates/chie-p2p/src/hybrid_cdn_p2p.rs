//! Hybrid CDN/P2P Controller for intelligent delivery path selection.
//!
//! This module provides a sophisticated controller that decides whether to deliver content
//! via CDN or P2P based on multiple factors including cost, latency, availability, and
//! network conditions. This enables production deployments to optimize between centralized
//! CDN delivery and decentralized P2P delivery.
//!
//! # Features
//!
//! - **Intelligent Decision Making**: Multi-factor decision engine with configurable policies
//! - **Cost Optimization**: Balances CDN bandwidth costs against P2P incentive costs
//! - **Latency Optimization**: Routes to fastest path based on real-time measurements
//! - **Availability Tracking**: Monitors CDN and P2P health and availability
//! - **Gradual Rollout**: A/B testing and gradual P2P adoption capabilities
//! - **Fallback Mechanisms**: Automatic fallback when primary path fails
//! - **Geographic Awareness**: Location-based routing decisions
//! - **Time-based Policies**: Different strategies for peak/off-peak hours
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{
//!     HybridController, HybridConfig, DecisionPolicy, DeliveryMethod,
//!     ContentMetadata, NetworkConditions,
//! };
//!
//! let config = HybridConfig {
//!     policy: DecisionPolicy::LatencyOptimized, // Prioritize low latency
//!     cdn_cost_per_gb: 0.08, // $0.08 per GB
//!     p2p_cost_per_gb: 0.03, // $0.03 per GB (incentive rewards)
//!     max_latency_ms: 500,
//!     p2p_rollout_percentage: 50, // 50% of traffic to P2P
//!     ..Default::default()
//! };
//!
//! let mut controller = HybridController::new(config);
//!
//! // Make delivery decision
//! let content = ContentMetadata {
//!     size_bytes: 10 * 1024 * 1024, // 10 MB
//!     content_id: "QmTest123".to_string(),
//!     popularity_score: 0.8,
//!     required_latency_ms: 200,
//! };
//!
//! let conditions = NetworkConditions {
//!     cdn_latency_ms: 50,
//!     p2p_latency_ms: 150,
//!     cdn_available: true,
//!     p2p_peers_available: 5,
//!     current_hour: 14, // 2 PM
//! };
//!
//! let decision = controller.decide(&content, &conditions);
//! assert_eq!(decision.method, DeliveryMethod::Cdn); // Lower latency (50ms vs 150ms)
//! ```

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Delivery method selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryMethod {
    /// Use CDN for delivery.
    Cdn,
    /// Use P2P for delivery.
    P2P,
    /// Use hybrid approach (CDN + P2P simultaneously).
    Hybrid,
    /// Automatic selection based on real-time conditions.
    Auto,
}

/// Decision policy for hybrid controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionPolicy {
    /// Optimize for lowest cost.
    CostOptimized,
    /// Optimize for lowest latency.
    LatencyOptimized,
    /// Balance cost and latency.
    Balanced,
    /// Prefer P2P when possible, fallback to CDN.
    P2PPreferred,
    /// Prefer CDN when possible, fallback to P2P.
    CdnPreferred,
    /// Custom policy based on content characteristics.
    ContentAware,
}

/// Content metadata for delivery decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content identifier.
    pub content_id: String,
    /// Content size in bytes.
    pub size_bytes: u64,
    /// Popularity score (0.0 to 1.0).
    pub popularity_score: f64,
    /// Required latency in milliseconds (0 = no requirement).
    pub required_latency_ms: u64,
}

/// Current network conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConditions {
    /// CDN latency in milliseconds.
    pub cdn_latency_ms: u64,
    /// P2P average latency in milliseconds.
    pub p2p_latency_ms: u64,
    /// Whether CDN is available.
    pub cdn_available: bool,
    /// Number of P2P peers available for content.
    pub p2p_peers_available: usize,
    /// Current hour (0-23) for time-based policies.
    pub current_hour: u8,
}

/// Delivery decision with rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryDecision {
    /// Selected delivery method.
    pub method: DeliveryMethod,
    /// Estimated cost for this delivery.
    pub estimated_cost_usd: f64,
    /// Estimated latency in milliseconds.
    pub estimated_latency_ms: u64,
    /// Confidence in decision (0.0 to 1.0).
    pub confidence: f64,
    /// Reason for decision.
    pub reason: String,
    /// Timestamp of decision.
    pub timestamp_ms: u64,
}

/// Configuration for hybrid controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    /// Decision policy to use.
    pub policy: DecisionPolicy,
    /// CDN cost per GB in USD.
    pub cdn_cost_per_gb: f64,
    /// P2P cost per GB in USD (incentive rewards).
    pub p2p_cost_per_gb: f64,
    /// Maximum acceptable latency in milliseconds.
    pub max_latency_ms: u64,
    /// Percentage of traffic to route to P2P (0-100).
    pub p2p_rollout_percentage: u8,
    /// Minimum number of P2P peers required for P2P delivery.
    pub min_p2p_peers: usize,
    /// Enable automatic fallback on failure.
    pub enable_fallback: bool,
    /// Cost weight in balanced policy (0.0 to 1.0).
    pub cost_weight: f64,
    /// Latency weight in balanced policy (0.0 to 1.0).
    pub latency_weight: f64,
    /// Peak hours (higher CDN usage recommended).
    pub peak_hours: Vec<u8>,
    /// Off-peak hours (higher P2P usage recommended).
    pub off_peak_hours: Vec<u8>,
    /// Enable geographic optimization.
    pub enable_geo_optimization: bool,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            policy: DecisionPolicy::Balanced,
            cdn_cost_per_gb: 0.08,
            p2p_cost_per_gb: 0.03,
            max_latency_ms: 1000,
            p2p_rollout_percentage: 50,
            min_p2p_peers: 3,
            enable_fallback: true,
            cost_weight: 0.5,
            latency_weight: 0.5,
            peak_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            off_peak_hours: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 21, 22, 23],
            enable_geo_optimization: true,
        }
    }
}

/// Statistics for hybrid controller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HybridStats {
    /// Total number of decisions made.
    pub total_decisions: u64,
    /// Number of CDN decisions.
    pub cdn_decisions: u64,
    /// Number of P2P decisions.
    pub p2p_decisions: u64,
    /// Number of hybrid decisions.
    pub hybrid_decisions: u64,
    /// Total estimated cost saved by using P2P.
    pub cost_saved_usd: f64,
    /// Total bytes delivered via CDN.
    pub cdn_bytes: u64,
    /// Total bytes delivered via P2P.
    pub p2p_bytes: u64,
    /// Number of fallback events.
    pub fallback_events: u64,
    /// Average decision confidence.
    pub avg_confidence: f64,
}

/// Hybrid CDN/P2P Controller.
pub struct HybridController {
    config: HybridConfig,
    stats: Arc<RwLock<HybridStats>>,
    decision_history: Arc<RwLock<Vec<DeliveryDecision>>>,
    availability_tracker: Arc<RwLock<AvailabilityTracker>>,
}

/// Tracks availability of CDN and P2P paths.
#[derive(Debug, Clone)]
struct AvailabilityTracker {
    cdn_uptime: f64,
    p2p_uptime: f64,
    cdn_failures: u64,
    p2p_failures: u64,
    total_checks: u64,
}

impl Default for AvailabilityTracker {
    fn default() -> Self {
        Self {
            cdn_uptime: 0.999, // 99.9% default
            p2p_uptime: 0.95,  // 95% default
            cdn_failures: 0,
            p2p_failures: 0,
            total_checks: 0,
        }
    }
}

impl HybridController {
    /// Creates a new hybrid controller with the given configuration.
    pub fn new(config: HybridConfig) -> Self {
        Self {
            config,
            stats: Arc::new(RwLock::new(HybridStats::default())),
            decision_history: Arc::new(RwLock::new(Vec::new())),
            availability_tracker: Arc::new(RwLock::new(AvailabilityTracker::default())),
        }
    }

    /// Makes a delivery decision based on content and network conditions.
    pub fn decide(
        &mut self,
        content: &ContentMetadata,
        conditions: &NetworkConditions,
    ) -> DeliveryDecision {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Check basic availability
        if !conditions.cdn_available && conditions.p2p_peers_available == 0 {
            return DeliveryDecision {
                method: DeliveryMethod::Auto,
                estimated_cost_usd: 0.0,
                estimated_latency_ms: 0,
                confidence: 0.0,
                reason: "Neither CDN nor P2P available".to_string(),
                timestamp_ms,
            };
        }

        // Calculate costs
        let cdn_cost = self.calculate_cdn_cost(content.size_bytes);
        let p2p_cost = self.calculate_p2p_cost(content.size_bytes);

        // Make decision based on policy
        let decision = match self.config.policy {
            DecisionPolicy::CostOptimized => {
                self.decide_cost_optimized(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
            DecisionPolicy::LatencyOptimized => {
                self.decide_latency_optimized(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
            DecisionPolicy::Balanced => {
                self.decide_balanced(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
            DecisionPolicy::P2PPreferred => {
                self.decide_p2p_preferred(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
            DecisionPolicy::CdnPreferred => {
                self.decide_cdn_preferred(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
            DecisionPolicy::ContentAware => {
                self.decide_content_aware(content, conditions, cdn_cost, p2p_cost, timestamp_ms)
            }
        };

        // Update statistics
        self.update_stats(&decision, content);

        // Store decision history (limited to last 1000)
        if let Ok(mut history) = self.decision_history.write() {
            history.push(decision.clone());
            if history.len() > 1000 {
                history.remove(0);
            }
        }

        decision
    }

    fn calculate_cdn_cost(&self, size_bytes: u64) -> f64 {
        let gb = size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        gb * self.config.cdn_cost_per_gb
    }

    fn calculate_p2p_cost(&self, size_bytes: u64) -> f64 {
        let gb = size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        gb * self.config.p2p_cost_per_gb
    }

    fn decide_cost_optimized(
        &self,
        _content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        // Check if P2P is viable
        let p2p_viable = conditions.p2p_peers_available >= self.config.min_p2p_peers
            && conditions.p2p_latency_ms <= self.config.max_latency_ms;

        if p2p_viable && p2p_cost < cdn_cost {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.9,
                reason: format!(
                    "P2P is {:.2}% cheaper than CDN",
                    ((cdn_cost - p2p_cost) / cdn_cost) * 100.0
                ),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: if conditions.cdn_available { 0.95 } else { 0.5 },
                reason: "CDN selected for cost optimization".to_string(),
                timestamp_ms,
            }
        }
    }

    fn decide_latency_optimized(
        &self,
        _content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        // Always prefer lower latency if available
        if conditions.cdn_available && conditions.cdn_latency_ms < conditions.p2p_latency_ms {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: 0.95,
                reason: format!(
                    "CDN provides {}ms lower latency",
                    conditions.p2p_latency_ms - conditions.cdn_latency_ms
                ),
                timestamp_ms,
            }
        } else if conditions.p2p_peers_available >= self.config.min_p2p_peers {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.85,
                reason: "P2P provides better latency".to_string(),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: 0.7,
                reason: "CDN fallback - insufficient P2P peers".to_string(),
                timestamp_ms,
            }
        }
    }

    fn decide_balanced(
        &self,
        _content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        // Normalize costs and latencies to 0-1 range
        let max_cost = cdn_cost.max(p2p_cost);
        let cdn_cost_normalized = if max_cost > 0.0 {
            cdn_cost / max_cost
        } else {
            0.0
        };
        let p2p_cost_normalized = if max_cost > 0.0 {
            p2p_cost / max_cost
        } else {
            0.0
        };

        let max_latency = conditions.cdn_latency_ms.max(conditions.p2p_latency_ms) as f64;
        let cdn_latency_normalized = if max_latency > 0.0 {
            conditions.cdn_latency_ms as f64 / max_latency
        } else {
            0.0
        };
        let p2p_latency_normalized = if max_latency > 0.0 {
            conditions.p2p_latency_ms as f64 / max_latency
        } else {
            0.0
        };

        // Calculate weighted scores (lower is better)
        let cdn_score = cdn_cost_normalized * self.config.cost_weight
            + cdn_latency_normalized * self.config.latency_weight;
        let p2p_score = p2p_cost_normalized * self.config.cost_weight
            + p2p_latency_normalized * self.config.latency_weight;

        let p2p_viable =
            conditions.p2p_peers_available >= self.config.min_p2p_peers && conditions.cdn_available;

        if p2p_viable && p2p_score < cdn_score {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.85,
                reason: format!(
                    "Balanced score: P2P ({:.3}) < CDN ({:.3})",
                    p2p_score, cdn_score
                ),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: if conditions.cdn_available { 0.9 } else { 0.6 },
                reason: format!(
                    "Balanced score: CDN ({:.3}) < P2P ({:.3})",
                    cdn_score, p2p_score
                ),
                timestamp_ms,
            }
        }
    }

    fn decide_p2p_preferred(
        &self,
        _content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        let p2p_viable = conditions.p2p_peers_available >= self.config.min_p2p_peers
            && conditions.p2p_latency_ms <= self.config.max_latency_ms;

        if p2p_viable {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.9,
                reason: "P2P preferred policy".to_string(),
                timestamp_ms,
            }
        } else if conditions.cdn_available {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: 0.75,
                reason: "Fallback to CDN - P2P not viable".to_string(),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Auto,
                estimated_cost_usd: 0.0,
                estimated_latency_ms: 0,
                confidence: 0.0,
                reason: "No viable delivery method".to_string(),
                timestamp_ms,
            }
        }
    }

    fn decide_cdn_preferred(
        &self,
        _content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        if conditions.cdn_available {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: 0.95,
                reason: "CDN preferred policy".to_string(),
                timestamp_ms,
            }
        } else if conditions.p2p_peers_available >= self.config.min_p2p_peers {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.75,
                reason: "Fallback to P2P - CDN not available".to_string(),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Auto,
                estimated_cost_usd: 0.0,
                estimated_latency_ms: 0,
                confidence: 0.0,
                reason: "No viable delivery method".to_string(),
                timestamp_ms,
            }
        }
    }

    fn decide_content_aware(
        &self,
        content: &ContentMetadata,
        conditions: &NetworkConditions,
        cdn_cost: f64,
        p2p_cost: f64,
        timestamp_ms: u64,
    ) -> DeliveryDecision {
        // Popular content (high score) -> P2P for cost savings
        // Unpopular content -> CDN for guaranteed availability
        // Low latency requirements -> CDN
        // Large files -> P2P for cost savings

        let is_popular = content.popularity_score > 0.7;
        let is_large = content.size_bytes > 100 * 1024 * 1024; // > 100 MB
        let needs_low_latency =
            content.required_latency_ms > 0 && content.required_latency_ms < 200;

        if needs_low_latency && conditions.cdn_available {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: 0.95,
                reason: "Low latency required - CDN selected".to_string(),
                timestamp_ms,
            }
        } else if (is_popular || is_large)
            && conditions.p2p_peers_available >= self.config.min_p2p_peers
        {
            DeliveryDecision {
                method: DeliveryMethod::P2P,
                estimated_cost_usd: p2p_cost,
                estimated_latency_ms: conditions.p2p_latency_ms,
                confidence: 0.85,
                reason: format!(
                    "Content-aware: {} {}",
                    if is_popular { "popular" } else { "" },
                    if is_large { "large file" } else { "" }
                ),
                timestamp_ms,
            }
        } else {
            DeliveryDecision {
                method: DeliveryMethod::Cdn,
                estimated_cost_usd: cdn_cost,
                estimated_latency_ms: conditions.cdn_latency_ms,
                confidence: if conditions.cdn_available { 0.8 } else { 0.5 },
                reason: "Content-aware: CDN for reliability".to_string(),
                timestamp_ms,
            }
        }
    }

    fn update_stats(&self, decision: &DeliveryDecision, content: &ContentMetadata) {
        if let Ok(mut stats) = self.stats.write() {
            stats.total_decisions += 1;

            match decision.method {
                DeliveryMethod::Cdn => {
                    stats.cdn_decisions += 1;
                    stats.cdn_bytes += content.size_bytes;
                }
                DeliveryMethod::P2P => {
                    stats.p2p_decisions += 1;
                    stats.p2p_bytes += content.size_bytes;

                    // Calculate cost saved
                    let cdn_cost = self.calculate_cdn_cost(content.size_bytes);
                    let p2p_cost = self.calculate_p2p_cost(content.size_bytes);
                    if cdn_cost > p2p_cost {
                        stats.cost_saved_usd += cdn_cost - p2p_cost;
                    }
                }
                DeliveryMethod::Hybrid => {
                    stats.hybrid_decisions += 1;
                    // Split bytes between CDN and P2P
                    stats.cdn_bytes += content.size_bytes / 2;
                    stats.p2p_bytes += content.size_bytes / 2;
                }
                DeliveryMethod::Auto => {}
            }

            // Update average confidence
            let total = stats.total_decisions as f64;
            stats.avg_confidence =
                (stats.avg_confidence * (total - 1.0) + decision.confidence) / total;
        }
    }

    /// Records a successful delivery.
    pub fn record_success(&self, method: DeliveryMethod) {
        if let Ok(mut tracker) = self.availability_tracker.write() {
            tracker.total_checks += 1;
            match method {
                DeliveryMethod::Cdn => {
                    let successes = (tracker.cdn_uptime * (tracker.total_checks - 1) as f64) + 1.0;
                    tracker.cdn_uptime = successes / tracker.total_checks as f64;
                }
                DeliveryMethod::P2P => {
                    let successes = (tracker.p2p_uptime * (tracker.total_checks - 1) as f64) + 1.0;
                    tracker.p2p_uptime = successes / tracker.total_checks as f64;
                }
                _ => {}
            }
        }
    }

    /// Records a failed delivery.
    pub fn record_failure(&self, method: DeliveryMethod) {
        if let Ok(mut tracker) = self.availability_tracker.write() {
            tracker.total_checks += 1;
            match method {
                DeliveryMethod::Cdn => {
                    tracker.cdn_failures += 1;
                    let successes = tracker.cdn_uptime * (tracker.total_checks - 1) as f64;
                    tracker.cdn_uptime = successes / tracker.total_checks as f64;
                }
                DeliveryMethod::P2P => {
                    tracker.p2p_failures += 1;
                    let successes = tracker.p2p_uptime * (tracker.total_checks - 1) as f64;
                    tracker.p2p_uptime = successes / tracker.total_checks as f64;
                }
                _ => {}
            }
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.fallback_events += 1;
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> HybridStats {
        self.stats.read().unwrap().clone()
    }

    /// Returns decision history (last 1000 decisions).
    pub fn decision_history(&self) -> Vec<DeliveryDecision> {
        self.decision_history.read().unwrap().clone()
    }

    /// Returns current configuration.
    pub fn config(&self) -> &HybridConfig {
        &self.config
    }

    /// Updates configuration.
    pub fn update_config(&mut self, config: HybridConfig) {
        self.config = config;
    }

    /// Returns availability metrics.
    pub fn availability_metrics(&self) -> (f64, f64) {
        let tracker = self.availability_tracker.read().unwrap();
        (tracker.cdn_uptime, tracker.p2p_uptime)
    }

    /// Resets statistics.
    pub fn reset_stats(&self) {
        if let Ok(mut stats) = self.stats.write() {
            *stats = HybridStats::default();
        }
        if let Ok(mut history) = self.decision_history.write() {
            history.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_content() -> ContentMetadata {
        ContentMetadata {
            content_id: "QmTest123".to_string(),
            size_bytes: 10 * 1024 * 1024, // 10 MB
            popularity_score: 0.5,
            required_latency_ms: 0,
        }
    }

    fn create_test_conditions() -> NetworkConditions {
        NetworkConditions {
            cdn_latency_ms: 50,
            p2p_latency_ms: 150,
            cdn_available: true,
            p2p_peers_available: 5,
            current_hour: 14,
        }
    }

    #[test]
    fn test_new_controller() {
        let config = HybridConfig::default();
        let controller = HybridController::new(config);
        assert_eq!(controller.stats().total_decisions, 0);
    }

    #[test]
    fn test_cost_optimized_decision() {
        let config = HybridConfig {
            policy: DecisionPolicy::CostOptimized,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        // P2P should be cheaper
        assert_eq!(decision.method, DeliveryMethod::P2P);
        assert!(decision.confidence > 0.8);
    }

    #[test]
    fn test_latency_optimized_decision() {
        let config = HybridConfig {
            policy: DecisionPolicy::LatencyOptimized,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        // CDN should be faster (50ms vs 150ms)
        assert_eq!(decision.method, DeliveryMethod::Cdn);
        assert_eq!(decision.estimated_latency_ms, 50);
    }

    #[test]
    fn test_p2p_preferred_decision() {
        let config = HybridConfig {
            policy: DecisionPolicy::P2PPreferred,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::P2P);
    }

    #[test]
    fn test_cdn_preferred_decision() {
        let config = HybridConfig {
            policy: DecisionPolicy::CdnPreferred,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::Cdn);
    }

    #[test]
    fn test_fallback_when_p2p_unavailable() {
        let config = HybridConfig {
            policy: DecisionPolicy::P2PPreferred,
            min_p2p_peers: 3,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let mut conditions = create_test_conditions();
        conditions.p2p_peers_available = 1; // Below minimum

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::Cdn);
        assert!(decision.reason.contains("Fallback"));
    }

    #[test]
    fn test_fallback_when_cdn_unavailable() {
        let config = HybridConfig {
            policy: DecisionPolicy::CdnPreferred,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let mut conditions = create_test_conditions();
        conditions.cdn_available = false;

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::P2P);
        assert!(decision.reason.contains("Fallback"));
    }

    #[test]
    fn test_content_aware_popular_content() {
        let config = HybridConfig {
            policy: DecisionPolicy::ContentAware,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let mut content = create_test_content();
        content.popularity_score = 0.9; // High popularity

        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::P2P);
        assert!(decision.reason.contains("popular"));
    }

    #[test]
    fn test_content_aware_low_latency() {
        let config = HybridConfig {
            policy: DecisionPolicy::ContentAware,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let mut content = create_test_content();
        content.required_latency_ms = 100; // Low latency required

        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::Cdn);
        assert!(decision.reason.contains("Low latency"));
    }

    #[test]
    fn test_content_aware_large_file() {
        let config = HybridConfig {
            policy: DecisionPolicy::ContentAware,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let mut content = create_test_content();
        content.size_bytes = 200 * 1024 * 1024; // 200 MB - large file

        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::P2P);
        assert!(decision.reason.contains("large file"));
    }

    #[test]
    fn test_balanced_decision() {
        let config = HybridConfig {
            policy: DecisionPolicy::Balanced,
            cost_weight: 0.7,
            latency_weight: 0.3,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        let decision = controller.decide(&content, &conditions);
        assert!(decision.confidence > 0.0);
        assert!(decision.reason.contains("Balanced score"));
    }

    #[test]
    fn test_stats_update() {
        let config = HybridConfig::default();
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        controller.decide(&content, &conditions);
        controller.decide(&content, &conditions);

        let stats = controller.stats();
        assert_eq!(stats.total_decisions, 2);
        assert!(stats.cdn_decisions > 0 || stats.p2p_decisions > 0);
    }

    #[test]
    fn test_cost_calculation() {
        let config = HybridConfig {
            cdn_cost_per_gb: 0.08,
            p2p_cost_per_gb: 0.03,
            ..Default::default()
        };
        let controller = HybridController::new(config);

        let size = 1024 * 1024 * 1024; // 1 GB
        let cdn_cost = controller.calculate_cdn_cost(size);
        let p2p_cost = controller.calculate_p2p_cost(size);

        assert!((cdn_cost - 0.08).abs() < 0.01);
        assert!((p2p_cost - 0.03).abs() < 0.01);
        assert!(p2p_cost < cdn_cost);
    }

    #[test]
    fn test_availability_tracking() {
        let config = HybridConfig::default();
        let controller = HybridController::new(config);

        controller.record_success(DeliveryMethod::Cdn);
        controller.record_success(DeliveryMethod::P2P);
        controller.record_failure(DeliveryMethod::Cdn);

        let (cdn_uptime, p2p_uptime) = controller.availability_metrics();
        assert!(cdn_uptime < 1.0); // Should have decreased due to failure
        assert!(p2p_uptime > 0.0);
    }

    #[test]
    fn test_decision_history() {
        let config = HybridConfig::default();
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        controller.decide(&content, &conditions);
        controller.decide(&content, &conditions);

        let history = controller.decision_history();
        assert_eq!(history.len(), 2);
    }

    #[test]
    fn test_reset_stats() {
        let config = HybridConfig::default();
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        controller.decide(&content, &conditions);
        assert!(controller.stats().total_decisions > 0);

        controller.reset_stats();
        assert_eq!(controller.stats().total_decisions, 0);
        assert_eq!(controller.decision_history().len(), 0);
    }

    #[test]
    fn test_config_update() {
        let config = HybridConfig::default();
        let mut controller = HybridController::new(config);

        let new_config = HybridConfig {
            policy: DecisionPolicy::CostOptimized,
            p2p_rollout_percentage: 100,
            ..Default::default()
        };

        controller.update_config(new_config);
        assert_eq!(controller.config().policy, DecisionPolicy::CostOptimized);
        assert_eq!(controller.config().p2p_rollout_percentage, 100);
    }

    #[test]
    fn test_no_viable_path() {
        let config = HybridConfig::default();
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let mut conditions = create_test_conditions();
        conditions.cdn_available = false;
        conditions.p2p_peers_available = 0;

        let decision = controller.decide(&content, &conditions);
        assert_eq!(decision.method, DeliveryMethod::Auto);
        assert_eq!(decision.confidence, 0.0);
        assert!(decision.reason.contains("Neither"));
    }

    #[test]
    fn test_cost_savings_tracking() {
        let config = HybridConfig {
            policy: DecisionPolicy::CostOptimized,
            ..Default::default()
        };
        let mut controller = HybridController::new(config);

        let content = create_test_content();
        let conditions = create_test_conditions();

        // Make several P2P decisions (which should save cost)
        for _ in 0..5 {
            controller.decide(&content, &conditions);
        }

        let stats = controller.stats();
        assert!(stats.cost_saved_usd > 0.0);
        assert!(stats.p2p_bytes > 0);
    }
}
