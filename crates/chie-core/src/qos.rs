//! Quality of Service (QoS) for priority-based request handling.
//!
//! This module provides priority-based scheduling, bandwidth allocation, and SLA tracking
//! for content distribution requests. It ensures high-priority requests get preferential
//! treatment while maintaining fairness across different priority levels.
//!
//! # Example
//!
//! ```rust
//! use chie_core::qos::{QosManager, Priority, QosConfig, RequestInfo};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = QosConfig::default();
//!     let mut qos = QosManager::new(config);
//!
//!     // Enqueue requests with different priorities
//!     let req1 = RequestInfo {
//!         id: "req1".to_string(),
//!         cid: "QmCritical".to_string(),
//!         size_bytes: 1024 * 1024,
//!         priority: Priority::Critical,
//!         deadline_ms: None,
//!     };
//!     qos.enqueue(req1).await;
//!
//!     // Dequeue processes highest priority first
//!     if let Some(next) = qos.dequeue().await {
//!         println!("Processing: {} (priority: {:?})", next.id, next.priority);
//!     }
//! }
//! ```

use crate::degradation::ResourcePressure;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};

/// Request priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Critical priority (highest) - reserved for system-critical operations.
    Critical = 4,
    /// High priority - time-sensitive user requests.
    High = 3,
    /// Normal priority - standard user requests.
    Normal = 2,
    /// Low priority - background operations, prefetching.
    Low = 1,
}

impl Default for Priority {
    #[inline]
    fn default() -> Self {
        Self::Normal
    }
}

/// Configuration for QoS manager.
#[derive(Debug, Clone)]
pub struct QosConfig {
    /// Maximum queue size per priority level.
    pub max_queue_size: usize,
    /// Bandwidth allocation percentages by priority (must sum to 100).
    pub bandwidth_allocation: HashMap<Priority, u32>,
    /// Enable strict priority (higher priorities always go first).
    pub strict_priority: bool,
    /// Minimum time slice per priority in milliseconds (for fair scheduling).
    pub time_slice_ms: u64,
    /// SLA target latency in milliseconds per priority.
    pub sla_target_latency_ms: HashMap<Priority, u64>,
}

impl Default for QosConfig {
    #[inline]
    fn default() -> Self {
        let mut bandwidth_allocation = HashMap::new();
        bandwidth_allocation.insert(Priority::Critical, 40);
        bandwidth_allocation.insert(Priority::High, 30);
        bandwidth_allocation.insert(Priority::Normal, 20);
        bandwidth_allocation.insert(Priority::Low, 10);

        let mut sla_target_latency_ms = HashMap::new();
        sla_target_latency_ms.insert(Priority::Critical, 100);
        sla_target_latency_ms.insert(Priority::High, 500);
        sla_target_latency_ms.insert(Priority::Normal, 2000);
        sla_target_latency_ms.insert(Priority::Low, 10000);

        Self {
            max_queue_size: 1000,
            bandwidth_allocation,
            strict_priority: true,
            time_slice_ms: 100,
            sla_target_latency_ms,
        }
    }
}

/// Information about a queued request.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Unique request identifier.
    pub id: String,
    /// Content identifier.
    pub cid: String,
    /// Estimated size in bytes.
    pub size_bytes: u64,
    /// Request priority.
    pub priority: Priority,
    /// Optional deadline (absolute time in milliseconds since epoch).
    /// If set, requests approaching deadline get priority boost.
    pub deadline_ms: Option<i64>,
}

/// Internal queue entry with timing information.
#[derive(Debug, Clone)]
struct QueueEntry {
    info: RequestInfo,
    enqueued_at: Instant,
}

/// SLA metrics for a priority level.
#[derive(Debug, Clone, Default)]
pub struct SlaMetrics {
    /// Total requests processed.
    pub total_requests: u64,
    /// Requests that met SLA target.
    pub met_sla: u64,
    /// Requests that violated SLA target.
    pub violated_sla: u64,
    /// Average queue time in milliseconds.
    pub avg_queue_time_ms: u64,
    /// Maximum queue time in milliseconds.
    pub max_queue_time_ms: u64,
    /// Total bytes processed.
    pub total_bytes: u64,
}

impl SlaMetrics {
    /// Calculate SLA compliance rate (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn compliance_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        self.met_sla as f64 / self.total_requests as f64
    }

    /// Calculate violation rate (0.0 to 1.0).
    #[must_use]
    #[inline]
    pub fn violation_rate(&self) -> f64 {
        1.0 - self.compliance_rate()
    }
}

/// Quality of Service manager for priority-based request handling.
pub struct QosManager {
    config: QosConfig,
    /// Queues per priority level.
    queues: Arc<Mutex<HashMap<Priority, VecDeque<QueueEntry>>>>,
    /// SLA metrics per priority level.
    metrics: Arc<Mutex<HashMap<Priority, SlaMetrics>>>,
    /// Last service time per priority (for fair scheduling).
    last_service: Arc<Mutex<HashMap<Priority, Instant>>>,
    /// Current resource pressure for adaptive behavior.
    resource_pressure: Arc<Mutex<ResourcePressure>>,
}

impl QosManager {
    /// Create a new QoS manager with the given configuration.
    #[must_use]
    pub fn new(config: QosConfig) -> Self {
        let mut queues = HashMap::new();
        let mut metrics = HashMap::new();
        let mut last_service = HashMap::new();

        for &priority in &[
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
        ] {
            queues.insert(priority, VecDeque::new());
            metrics.insert(priority, SlaMetrics::default());
            last_service.insert(priority, Instant::now());
        }

        Self {
            config,
            queues: Arc::new(Mutex::new(queues)),
            metrics: Arc::new(Mutex::new(metrics)),
            last_service: Arc::new(Mutex::new(last_service)),
            resource_pressure: Arc::new(Mutex::new(ResourcePressure::default())),
        }
    }

    /// Enqueue a request with the specified priority.
    ///
    /// Returns `true` if the request was enqueued, `false` if the queue is full.
    #[must_use]
    pub async fn enqueue(&mut self, request: RequestInfo) -> bool {
        let priority = request.priority;
        let entry = QueueEntry {
            info: request,
            enqueued_at: Instant::now(),
        };

        let mut queues = self.queues.lock().unwrap();
        if let Some(queue) = queues.get_mut(&priority) {
            if queue.len() >= self.config.max_queue_size {
                return false;
            }
            queue.push_back(entry);
            true
        } else {
            false
        }
    }

    /// Dequeue the next request based on priority and scheduling policy.
    ///
    /// Supports deadline scheduling: requests with approaching deadlines are prioritized
    /// over normal priority scheduling.
    #[must_use]
    pub async fn dequeue(&mut self) -> Option<RequestInfo> {
        let mut queues = self.queues.lock().unwrap();
        let mut last_service = self.last_service.lock().unwrap();

        // First check for urgent deadline-critical requests
        if let Some((priority, index)) = self.find_urgent_deadline_request(&queues) {
            if let Some(queue) = queues.get_mut(&priority) {
                if let Some(entry) = queue.remove(index) {
                    let queue_time_ms = entry.enqueued_at.elapsed().as_millis() as u64;
                    last_service.insert(priority, Instant::now());
                    self.update_metrics(priority, entry.info.size_bytes, queue_time_ms);
                    return Some(entry.info);
                }
            }
        }

        // Otherwise, determine which priority to service next
        let priority = if self.config.strict_priority {
            // Strict priority: always serve highest priority first
            self.select_highest_priority(&queues)?
        } else {
            // Fair scheduling: weighted round-robin
            self.select_fair_priority(&queues, &last_service)?
        };

        // Dequeue from selected priority
        if let Some(queue) = queues.get_mut(&priority) {
            if let Some(entry) = queue.pop_front() {
                let queue_time_ms = entry.enqueued_at.elapsed().as_millis() as u64;

                // Update last service time
                last_service.insert(priority, Instant::now());

                // Update metrics
                self.update_metrics(priority, entry.info.size_bytes, queue_time_ms);

                return Some(entry.info);
            }
        }

        None
    }

    /// Find the most urgent request with an approaching deadline.
    ///
    /// Returns (priority, index) of the most urgent request, or None if no urgent requests.
    /// A request is considered urgent if its deadline is within 100ms.
    #[must_use]
    #[inline]
    fn find_urgent_deadline_request(
        &self,
        queues: &HashMap<Priority, VecDeque<QueueEntry>>,
    ) -> Option<(Priority, usize)> {
        let now = crate::utils::current_timestamp_ms();
        let mut most_urgent: Option<(Priority, usize, i64)> = None; // (priority, index, time_to_deadline)

        for (&priority, queue) in queues {
            for (idx, entry) in queue.iter().enumerate() {
                if let Some(deadline) = entry.info.deadline_ms {
                    let time_to_deadline = deadline - now;

                    // Consider urgent if deadline within next 100ms or already passed
                    if time_to_deadline < 100 {
                        // Update if this is more urgent (closer to/past deadline)
                        if let Some((_, _, prev_urgency)) = most_urgent {
                            if time_to_deadline < prev_urgency {
                                most_urgent = Some((priority, idx, time_to_deadline));
                            }
                        } else {
                            most_urgent = Some((priority, idx, time_to_deadline));
                        }
                    }
                }
            }
        }

        most_urgent.map(|(p, i, _)| (p, i))
    }

    /// Select the highest priority queue with items.
    #[must_use]
    #[inline]
    fn select_highest_priority(
        &self,
        queues: &HashMap<Priority, VecDeque<QueueEntry>>,
    ) -> Option<Priority> {
        for &priority in &[
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
        ] {
            if let Some(queue) = queues.get(&priority) {
                if !queue.is_empty() {
                    return Some(priority);
                }
            }
        }
        None
    }

    /// Select priority using fair scheduling (weighted round-robin).
    #[must_use]
    #[inline]
    fn select_fair_priority(
        &self,
        queues: &HashMap<Priority, VecDeque<QueueEntry>>,
        last_service: &HashMap<Priority, Instant>,
    ) -> Option<Priority> {
        let mut candidates = Vec::new();

        // Find non-empty queues
        for &priority in &[
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
        ] {
            if let Some(queue) = queues.get(&priority) {
                if !queue.is_empty() {
                    candidates.push(priority);
                }
            }
        }

        if candidates.is_empty() {
            return None;
        }

        // Select based on time since last service and priority weight
        candidates.into_iter().max_by_key(|&priority| {
            let time_since = last_service
                .get(&priority)
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            let weight = self
                .config
                .bandwidth_allocation
                .get(&priority)
                .copied()
                .unwrap_or(1);
            time_since * u64::from(weight)
        })
    }

    /// Update SLA metrics for a completed request.
    #[inline]
    fn update_metrics(&self, priority: Priority, bytes: u64, queue_time_ms: u64) {
        let mut metrics = self.metrics.lock().unwrap();
        if let Some(m) = metrics.get_mut(&priority) {
            m.total_requests += 1;
            m.total_bytes += bytes;

            // Update average queue time
            let total_time = m.avg_queue_time_ms * (m.total_requests - 1) + queue_time_ms;
            m.avg_queue_time_ms = total_time / m.total_requests;

            // Update max queue time
            if queue_time_ms > m.max_queue_time_ms {
                m.max_queue_time_ms = queue_time_ms;
            }

            // Check SLA compliance
            if let Some(&target) = self.config.sla_target_latency_ms.get(&priority) {
                if queue_time_ms <= target {
                    m.met_sla += 1;
                } else {
                    m.violated_sla += 1;
                }
            }
        }
    }

    /// Get current queue depth for a priority level.
    #[must_use]
    #[inline]
    pub fn queue_depth(&self, priority: Priority) -> usize {
        self.queues
            .lock()
            .unwrap()
            .get(&priority)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Get total queue depth across all priorities.
    #[must_use]
    #[inline]
    pub fn total_queue_depth(&self) -> usize {
        self.queues.lock().unwrap().values().map(|q| q.len()).sum()
    }

    /// Get SLA metrics for a priority level.
    #[must_use]
    #[inline]
    pub fn get_sla_metrics(&self, priority: Priority) -> Option<SlaMetrics> {
        self.metrics.lock().unwrap().get(&priority).cloned()
    }

    /// Get SLA metrics for all priority levels.
    #[must_use]
    #[inline]
    pub fn get_all_sla_metrics(&self) -> HashMap<Priority, SlaMetrics> {
        self.metrics.lock().unwrap().clone()
    }

    /// Reset all SLA metrics.
    pub fn reset_metrics(&mut self) {
        let mut metrics = self.metrics.lock().unwrap();
        for m in metrics.values_mut() {
            *m = SlaMetrics::default();
        }
    }

    /// Check if any queue is near capacity (>80% full).
    #[must_use]
    #[inline]
    pub fn is_near_capacity(&self) -> bool {
        let queues = self.queues.lock().unwrap();
        let threshold = (self.config.max_queue_size * 80) / 100;
        queues.values().any(|q| q.len() > threshold)
    }

    /// Get overall SLA compliance rate across all priorities.
    #[must_use]
    #[inline]
    pub fn overall_compliance_rate(&self) -> f64 {
        let metrics = self.metrics.lock().unwrap();
        let mut total_requests = 0u64;
        let mut total_met = 0u64;

        for m in metrics.values() {
            total_requests += m.total_requests;
            total_met += m.met_sla;
        }

        if total_requests == 0 {
            return 1.0;
        }
        total_met as f64 / total_requests as f64
    }

    /// Update current resource pressure.
    ///
    /// This allows QoS to adapt behavior based on system resource availability.
    pub fn update_resource_pressure(&mut self, pressure: ResourcePressure) {
        let mut current = self.resource_pressure.lock().unwrap();
        *current = pressure;
    }

    /// Get current resource pressure.
    #[must_use]
    pub fn get_resource_pressure(&self) -> ResourcePressure {
        *self.resource_pressure.lock().unwrap()
    }

    /// Check if system is under high resource pressure.
    ///
    /// Returns true if overall resource pressure exceeds 0.80.
    #[must_use]
    #[inline]
    pub fn is_under_high_pressure(&self) -> bool {
        let pressure = self.resource_pressure.lock().unwrap();
        pressure.overall_score() > 0.80
    }

    /// Get adaptive queue size limit based on resource pressure.
    ///
    /// Reduces queue size when under pressure to prevent resource exhaustion.
    #[must_use]
    #[inline]
    pub fn adaptive_queue_limit(&self) -> usize {
        let pressure = self.resource_pressure.lock().unwrap();
        let pressure_score = pressure.overall_score();

        if pressure_score > 0.90 {
            // Severe pressure: reduce to 25% capacity
            self.config.max_queue_size / 4
        } else if pressure_score > 0.80 {
            // High pressure: reduce to 50% capacity
            self.config.max_queue_size / 2
        } else if pressure_score > 0.70 {
            // Moderate pressure: reduce to 75% capacity
            (self.config.max_queue_size * 3) / 4
        } else {
            // Normal: full capacity
            self.config.max_queue_size
        }
    }

    /// Check if should throttle low-priority requests based on resource pressure.
    ///
    /// Returns true if resource pressure is high and priority is Low.
    #[must_use]
    #[inline]
    pub fn should_throttle_priority(&self, priority: Priority) -> bool {
        let pressure = self.resource_pressure.lock().unwrap();
        let pressure_score = pressure.overall_score();

        match priority {
            Priority::Critical => false,             // Never throttle critical
            Priority::High => pressure_score > 0.95, // Only under severe pressure
            Priority::Normal => pressure_score > 0.85,
            Priority::Low => pressure_score > 0.70,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_request(id: &str, priority: Priority) -> RequestInfo {
        RequestInfo {
            id: id.to_string(),
            cid: format!("Qm{}", id),
            size_bytes: 1024,
            priority,
            deadline_ms: None,
        }
    }

    #[tokio::test]
    async fn test_enqueue_dequeue() {
        let mut qos = QosManager::new(QosConfig::default());

        let req = create_request("test1", Priority::Normal);
        assert!(qos.enqueue(req.clone()).await);
        assert_eq!(qos.queue_depth(Priority::Normal), 1);

        let dequeued = qos.dequeue().await;
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().id, "test1");
        assert_eq!(qos.queue_depth(Priority::Normal), 0);
    }

    #[tokio::test]
    async fn test_strict_priority_ordering() {
        let config = QosConfig {
            strict_priority: true,
            ..Default::default()
        };
        let mut qos = QosManager::new(config);

        // Enqueue in reverse priority order
        let _ = qos.enqueue(create_request("low", Priority::Low)).await;
        let _ = qos
            .enqueue(create_request("normal", Priority::Normal))
            .await;
        let _ = qos.enqueue(create_request("high", Priority::High)).await;
        let _ = qos
            .enqueue(create_request("critical", Priority::Critical))
            .await;

        // Should dequeue in priority order
        assert_eq!(qos.dequeue().await.unwrap().id, "critical");
        assert_eq!(qos.dequeue().await.unwrap().id, "high");
        assert_eq!(qos.dequeue().await.unwrap().id, "normal");
        assert_eq!(qos.dequeue().await.unwrap().id, "low");
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let config = QosConfig {
            max_queue_size: 3,
            ..Default::default()
        };
        let mut qos = QosManager::new(config);

        assert!(qos.enqueue(create_request("1", Priority::Normal)).await);
        assert!(qos.enqueue(create_request("2", Priority::Normal)).await);
        assert!(qos.enqueue(create_request("3", Priority::Normal)).await);
        assert!(!qos.enqueue(create_request("4", Priority::Normal)).await); // Should fail

        assert_eq!(qos.queue_depth(Priority::Normal), 3);
    }

    #[tokio::test]
    async fn test_sla_metrics() {
        let mut qos = QosManager::new(QosConfig::default());

        let req = create_request("test", Priority::High);
        let _ = qos.enqueue(req).await;

        // Small delay to simulate queue time
        tokio::time::sleep(Duration::from_millis(10)).await;

        let _ = qos.dequeue().await;

        let metrics = qos.get_sla_metrics(Priority::High).unwrap();
        assert_eq!(metrics.total_requests, 1);
        assert!(metrics.avg_queue_time_ms >= 10);
    }

    #[tokio::test]
    async fn test_sla_compliance() {
        let mut config = QosConfig::default();
        config.sla_target_latency_ms.insert(Priority::Normal, 1000);
        let mut qos = QosManager::new(config);

        // Enqueue and immediately dequeue (should meet SLA)
        let _ = qos.enqueue(create_request("fast", Priority::Normal)).await;
        let _ = qos.dequeue().await;

        let metrics = qos.get_sla_metrics(Priority::Normal).unwrap();
        assert_eq!(metrics.met_sla, 1);
        assert_eq!(metrics.violated_sla, 0);
        assert_eq!(metrics.compliance_rate(), 1.0);
    }

    #[tokio::test]
    async fn test_total_queue_depth() {
        let mut qos = QosManager::new(QosConfig::default());

        let _ = qos.enqueue(create_request("1", Priority::Critical)).await;
        let _ = qos.enqueue(create_request("2", Priority::High)).await;
        let _ = qos.enqueue(create_request("3", Priority::Normal)).await;
        let _ = qos.enqueue(create_request("4", Priority::Low)).await;

        assert_eq!(qos.total_queue_depth(), 4);
    }

    #[tokio::test]
    async fn test_near_capacity() {
        let config = QosConfig {
            max_queue_size: 10,
            ..Default::default()
        };
        let mut qos = QosManager::new(config);

        assert!(!qos.is_near_capacity());

        // Fill to 85% (9 out of 10)
        for i in 0..9 {
            let _ = qos
                .enqueue(create_request(&format!("{}", i), Priority::Normal))
                .await;
        }

        assert!(qos.is_near_capacity());
    }

    #[tokio::test]
    async fn test_reset_metrics() {
        let mut qos = QosManager::new(QosConfig::default());

        let _ = qos.enqueue(create_request("test", Priority::Normal)).await;
        let _ = qos.dequeue().await;

        let metrics = qos.get_sla_metrics(Priority::Normal).unwrap();
        assert_eq!(metrics.total_requests, 1);

        qos.reset_metrics();

        let metrics = qos.get_sla_metrics(Priority::Normal).unwrap();
        assert_eq!(metrics.total_requests, 0);
    }

    #[tokio::test]
    async fn test_overall_compliance_rate() {
        let mut qos = QosManager::new(QosConfig::default());

        // Initially should be 1.0 (100%)
        assert_eq!(qos.overall_compliance_rate(), 1.0);

        // Process some requests
        for priority in &[
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
        ] {
            let _ = qos.enqueue(create_request("test", *priority)).await;
            let _ = qos.dequeue().await;
        }

        // Should still be high since we dequeued immediately
        assert!(qos.overall_compliance_rate() > 0.9);
    }

    #[tokio::test]
    async fn test_priority_default() {
        assert_eq!(Priority::default(), Priority::Normal);
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
    }

    #[tokio::test]
    async fn test_fair_scheduling() {
        let config = QosConfig {
            strict_priority: false,
            ..Default::default()
        };
        let mut qos = QosManager::new(config);

        // Enqueue multiple requests at different priorities
        for _ in 0..3 {
            let _ = qos.enqueue(create_request("low", Priority::Low)).await;
            let _ = qos
                .enqueue(create_request("normal", Priority::Normal))
                .await;
            let _ = qos.enqueue(create_request("high", Priority::High)).await;
        }

        // Fair scheduling should eventually serve all priorities
        let mut served_priorities = std::collections::HashSet::new();
        for _ in 0..9 {
            if let Some(req) = qos.dequeue().await {
                served_priorities.insert(req.priority);
            }
        }

        // All priorities should have been served
        assert_eq!(served_priorities.len(), 3);
    }

    #[tokio::test]
    async fn test_resource_pressure_integration() {
        let mut qos = QosManager::new(QosConfig::default());

        // Initial pressure should be default (all zeros)
        let initial_pressure = qos.get_resource_pressure();
        assert!((initial_pressure.cpu_usage - 0.0).abs() < 0.01);

        // Update with moderate pressure
        let moderate_pressure = ResourcePressure {
            cpu_usage: 0.60,
            memory_usage: 0.70,
            disk_usage: 0.65,
            bandwidth_usage: 0.55,
        };
        qos.update_resource_pressure(moderate_pressure);

        assert!(!qos.is_under_high_pressure());
        assert_eq!(qos.adaptive_queue_limit(), qos.config.max_queue_size);
    }

    #[tokio::test]
    async fn test_adaptive_queue_limit() {
        let mut qos = QosManager::new(QosConfig::default());
        let base_limit = qos.config.max_queue_size;

        // High pressure: 50% capacity
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.85,
            memory_usage: 0.80,
            disk_usage: 0.82,
            bandwidth_usage: 0.78,
        });
        assert_eq!(qos.adaptive_queue_limit(), base_limit / 2);

        // Severe pressure: 25% capacity
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.95,
            memory_usage: 0.92,
            disk_usage: 0.90,
            bandwidth_usage: 0.88,
        });
        assert_eq!(qos.adaptive_queue_limit(), base_limit / 4);
    }

    #[tokio::test]
    async fn test_throttle_priority_based_on_pressure() {
        let mut qos = QosManager::new(QosConfig::default());

        // Low pressure: no throttling
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.40,
            memory_usage: 0.50,
            disk_usage: 0.45,
            bandwidth_usage: 0.35,
        });

        assert!(!qos.should_throttle_priority(Priority::Critical));
        assert!(!qos.should_throttle_priority(Priority::High));
        assert!(!qos.should_throttle_priority(Priority::Normal));
        assert!(!qos.should_throttle_priority(Priority::Low));

        // High pressure: throttle low and normal
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.88,
            memory_usage: 0.90,
            disk_usage: 0.87,
            bandwidth_usage: 0.85,
        });

        assert!(!qos.should_throttle_priority(Priority::Critical));
        assert!(!qos.should_throttle_priority(Priority::High));
        assert!(qos.should_throttle_priority(Priority::Normal));
        assert!(qos.should_throttle_priority(Priority::Low));
    }

    #[tokio::test]
    async fn test_high_pressure_detection() {
        let mut qos = QosManager::new(QosConfig::default());

        // Just below threshold
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.75,
            memory_usage: 0.78,
            disk_usage: 0.72,
            bandwidth_usage: 0.70,
        });
        assert!(!qos.is_under_high_pressure());

        // Above threshold
        qos.update_resource_pressure(ResourcePressure {
            cpu_usage: 0.85,
            memory_usage: 0.88,
            disk_usage: 0.82,
            bandwidth_usage: 0.80,
        });
        assert!(qos.is_under_high_pressure());
    }
}
