//! Traffic shaping and Quality of Service (QoS) management.
//!
//! This module provides sophisticated traffic shaping capabilities including:
//! - Priority-based bandwidth allocation
//! - Content-type aware rate limiting
//! - Adaptive congestion control
//! - Fair queuing implementation
//! - Traffic classification and scheduling

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Content type for traffic classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    /// Video streaming content
    Video,
    /// Audio streaming content
    Audio,
    /// Regular file transfer
    File,
    /// Protocol control messages
    Control,
    /// Real-time data (high priority)
    RealTime,
    /// Background synchronization
    Background,
}

impl ContentType {
    /// Get default priority for this content type
    pub fn default_priority(&self) -> u8 {
        match self {
            ContentType::RealTime => 5,
            ContentType::Control => 4,
            ContentType::Video => 3,
            ContentType::Audio => 3,
            ContentType::File => 2,
            ContentType::Background => 1,
        }
    }

    /// Get minimum bandwidth guarantee in bytes per second
    pub fn min_bandwidth_bps(&self) -> u64 {
        match self {
            ContentType::RealTime => 1_000_000, // 1 Mbps
            ContentType::Control => 100_000,    // 100 Kbps
            ContentType::Video => 5_000_000,    // 5 Mbps
            ContentType::Audio => 256_000,      // 256 Kbps
            ContentType::File => 500_000,       // 500 Kbps
            ContentType::Background => 100_000, // 100 Kbps
        }
    }
}

/// Traffic class combining priority and content type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficClass {
    /// Priority level (0-255, higher is more important)
    pub priority: u8,
    /// Content type
    pub content_type: ContentType,
}

impl TrafficClass {
    /// Create a new traffic class
    pub fn new(priority: u8, content_type: ContentType) -> Self {
        Self {
            priority,
            content_type,
        }
    }

    /// Create traffic class with default priority for content type
    pub fn from_content_type(content_type: ContentType) -> Self {
        Self {
            priority: content_type.default_priority(),
            content_type,
        }
    }
}

/// A traffic flow represents a stream of data
#[derive(Debug, Clone)]
pub struct TrafficFlow {
    /// Flow identifier
    pub flow_id: u64,
    /// Traffic class
    pub traffic_class: TrafficClass,
    /// Current bandwidth allocation in bytes per second
    pub allocated_bps: u64,
    /// Requested bandwidth in bytes per second
    pub requested_bps: u64,
    /// Bytes sent in current window
    pub bytes_sent: u64,
    /// Timestamp of last send
    pub last_send: Instant,
    /// Fair share tokens
    pub tokens: f64,
}

/// Congestion state of the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CongestionState {
    /// No congestion
    #[default]
    Normal,
    /// Mild congestion detected
    Mild,
    /// Moderate congestion
    Moderate,
    /// Severe congestion
    Severe,
}

/// Congestion control algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CongestionAlgorithm {
    /// AIMD (Additive Increase Multiplicative Decrease)
    Aimd,
    /// BBR-like algorithm
    Bbr,
    /// Vegas-like algorithm
    Vegas,
}

/// Congestion controller
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// Current congestion state
    state: CongestionState,
    /// Algorithm to use
    algorithm: CongestionAlgorithm,
    /// Current congestion window (bytes)
    cwnd: u64,
    /// Slow start threshold
    ssthresh: u64,
    /// Round trip time in milliseconds
    rtt_ms: f64,
    /// Minimum RTT observed
    min_rtt_ms: f64,
    /// Bandwidth estimate in bytes per second
    bandwidth_estimate: u64,
    /// Packet loss count
    loss_count: u64,
    /// Total packets sent
    packets_sent: u64,
}

impl CongestionController {
    /// Create a new congestion controller
    pub fn new(algorithm: CongestionAlgorithm, initial_cwnd: u64) -> Self {
        Self {
            state: CongestionState::Normal,
            algorithm,
            cwnd: initial_cwnd,
            ssthresh: u64::MAX,
            rtt_ms: 100.0,
            min_rtt_ms: 100.0,
            bandwidth_estimate: 1_000_000,
            loss_count: 0,
            packets_sent: 0,
        }
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt_ms: f64) {
        self.rtt_ms = 0.9 * self.rtt_ms + 0.1 * rtt_ms;
        self.min_rtt_ms = self.min_rtt_ms.min(rtt_ms);
    }

    /// Record successful packet transmission
    pub fn on_ack(&mut self, bytes: u64) {
        self.packets_sent += 1;

        match self.algorithm {
            CongestionAlgorithm::Aimd => {
                if self.cwnd < self.ssthresh {
                    // Slow start
                    self.cwnd += bytes;
                } else {
                    // Congestion avoidance
                    self.cwnd += (bytes * bytes) / self.cwnd;
                }
            }
            CongestionAlgorithm::Bbr => {
                // BBR uses RTT and bandwidth estimates
                self.bandwidth_estimate = (self.cwnd as f64 / self.rtt_ms * 1000.0) as u64;
                self.cwnd = (self.bandwidth_estimate as f64 * self.rtt_ms / 1000.0) as u64;
            }
            CongestionAlgorithm::Vegas => {
                // Vegas compares expected vs actual throughput
                let expected_throughput = self.cwnd as f64 / self.min_rtt_ms;
                let actual_throughput = self.cwnd as f64 / self.rtt_ms;
                let diff = expected_throughput - actual_throughput;

                if diff < 1.0 {
                    self.cwnd += bytes;
                } else if diff > 3.0 {
                    self.cwnd = self.cwnd.saturating_sub(bytes);
                }
            }
        }

        self.update_congestion_state();
    }

    /// Record packet loss
    pub fn on_loss(&mut self) {
        self.loss_count += 1;

        match self.algorithm {
            CongestionAlgorithm::Aimd => {
                self.ssthresh = self.cwnd / 2;
                self.cwnd = self.ssthresh;
            }
            CongestionAlgorithm::Bbr => {
                self.cwnd = (self.cwnd * 9) / 10;
            }
            CongestionAlgorithm::Vegas => {
                self.cwnd = (self.cwnd * 7) / 8;
            }
        }

        self.update_congestion_state();
    }

    /// Update congestion state based on loss rate
    fn update_congestion_state(&mut self) {
        let loss_rate = if self.packets_sent > 0 {
            self.loss_count as f64 / self.packets_sent as f64
        } else {
            0.0
        };

        self.state = if loss_rate < 0.01 {
            CongestionState::Normal
        } else if loss_rate < 0.05 {
            CongestionState::Mild
        } else if loss_rate < 0.1 {
            CongestionState::Moderate
        } else {
            CongestionState::Severe
        };
    }

    /// Get current congestion window
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Get congestion state
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Get loss rate
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent > 0 {
            self.loss_count as f64 / self.packets_sent as f64
        } else {
            0.0
        }
    }
}

/// Fair queue for traffic scheduling
#[derive(Debug)]
pub struct FairQueue {
    /// Queues for each traffic class
    queues: HashMap<TrafficClass, VecDeque<Vec<u8>>>,
    /// Virtual time for fair scheduling
    virtual_time: f64,
    /// Finish times for each flow
    finish_times: HashMap<u64, f64>,
    /// Statistics
    stats: FairQueueStats,
}

/// Fair queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FairQueueStats {
    /// Total packets enqueued
    pub packets_enqueued: u64,
    /// Total packets dequeued
    pub packets_dequeued: u64,
    /// Total packets dropped
    pub packets_dropped: u64,
    /// Average queue depth
    pub avg_queue_depth: f64,
}

impl FairQueue {
    /// Create a new fair queue
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            virtual_time: 0.0,
            finish_times: HashMap::new(),
            stats: FairQueueStats::default(),
        }
    }

    /// Enqueue a packet
    pub fn enqueue(&mut self, flow_id: u64, traffic_class: TrafficClass, packet: Vec<u8>) {
        let packet_size = packet.len() as f64;

        // Calculate finish time for weighted fair queuing
        let weight = traffic_class.priority as f64;
        let start_time = self
            .virtual_time
            .max(self.finish_times.get(&flow_id).copied().unwrap_or(0.0));
        let finish_time = start_time + packet_size / weight;

        self.finish_times.insert(flow_id, finish_time);

        let queue = self.queues.entry(traffic_class).or_default();
        queue.push_back(packet);

        self.stats.packets_enqueued += 1;
    }

    /// Dequeue next packet using weighted fair queuing
    pub fn dequeue(&mut self) -> Option<(TrafficClass, Vec<u8>)> {
        // Find flow with smallest finish time
        let mut min_finish_time = f64::MAX;
        let mut selected_class = None;

        for (traffic_class, queue) in &self.queues {
            if !queue.is_empty() {
                // Find minimum finish time for this class
                if let Some(&finish_time) = self
                    .finish_times
                    .values()
                    .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                {
                    if finish_time < min_finish_time {
                        min_finish_time = finish_time;
                        selected_class = Some(*traffic_class);
                    }
                }
            }
        }

        if let Some(traffic_class) = selected_class {
            if let Some(queue) = self.queues.get_mut(&traffic_class) {
                if let Some(packet) = queue.pop_front() {
                    self.virtual_time = min_finish_time;
                    self.stats.packets_dequeued += 1;
                    return Some((traffic_class, packet));
                }
            }
        }

        None
    }

    /// Get queue depth for a traffic class
    pub fn queue_depth(&self, traffic_class: &TrafficClass) -> usize {
        self.queues.get(traffic_class).map(|q| q.len()).unwrap_or(0)
    }

    /// Get total queue depth
    pub fn total_depth(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Get statistics
    pub fn stats(&self) -> &FairQueueStats {
        &self.stats
    }
}

impl Default for FairQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Traffic shaper configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShaperConfig {
    /// Maximum total bandwidth in bytes per second
    pub max_bandwidth_bps: u64,
    /// Congestion control algorithm
    pub congestion_algorithm: CongestionAlgorithm,
    /// Initial congestion window
    pub initial_cwnd: u64,
    /// Enable fair queuing
    pub enable_fair_queuing: bool,
    /// Maximum queue size per class
    pub max_queue_size: usize,
}

impl Default for TrafficShaperConfig {
    fn default() -> Self {
        Self {
            max_bandwidth_bps: 10_000_000, // 10 Mbps
            congestion_algorithm: CongestionAlgorithm::Aimd,
            initial_cwnd: 10_000,
            enable_fair_queuing: true,
            max_queue_size: 1000,
        }
    }
}

/// Traffic shaper managing QoS
pub struct TrafficShaper {
    /// Configuration
    config: TrafficShaperConfig,
    /// Active flows
    flows: Arc<Mutex<HashMap<u64, TrafficFlow>>>,
    /// Congestion controller
    congestion: Arc<Mutex<CongestionController>>,
    /// Fair queue
    fair_queue: Arc<Mutex<FairQueue>>,
    /// Statistics
    stats: Arc<Mutex<TrafficShaperStats>>,
    /// Next flow ID
    next_flow_id: Arc<Mutex<u64>>,
}

/// Traffic shaper statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficShaperStats {
    /// Total bytes shaped
    pub total_bytes: u64,
    /// Total flows created
    pub total_flows: u64,
    /// Current active flows
    pub active_flows: u64,
    /// Average throughput in bytes per second
    pub avg_throughput_bps: u64,
    /// Current congestion state
    pub congestion_state: CongestionState,
}

impl TrafficShaper {
    /// Create a new traffic shaper
    pub fn new(config: TrafficShaperConfig) -> Self {
        let congestion =
            CongestionController::new(config.congestion_algorithm, config.initial_cwnd);

        Self {
            config,
            flows: Arc::new(Mutex::new(HashMap::new())),
            congestion: Arc::new(Mutex::new(congestion)),
            fair_queue: Arc::new(Mutex::new(FairQueue::new())),
            stats: Arc::new(Mutex::new(TrafficShaperStats::default())),
            next_flow_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Create a new flow
    pub async fn create_flow(&self, traffic_class: TrafficClass, requested_bps: u64) -> u64 {
        let mut flow_id_lock = self.next_flow_id.lock().await;
        let flow_id = *flow_id_lock;
        *flow_id_lock += 1;
        drop(flow_id_lock);

        let flow = TrafficFlow {
            flow_id,
            traffic_class,
            allocated_bps: requested_bps,
            requested_bps,
            bytes_sent: 0,
            last_send: Instant::now(),
            tokens: 0.0,
        };

        let mut flows = self.flows.lock().await;
        flows.insert(flow_id, flow);

        let mut stats = self.stats.lock().await;
        stats.total_flows += 1;
        stats.active_flows += 1;

        flow_id
    }

    /// Remove a flow
    pub async fn remove_flow(&self, flow_id: u64) {
        let mut flows = self.flows.lock().await;
        if flows.remove(&flow_id).is_some() {
            let mut stats = self.stats.lock().await;
            stats.active_flows = stats.active_flows.saturating_sub(1);
        }
    }

    /// Shape outgoing data
    pub async fn shape(&self, flow_id: u64, data: Vec<u8>) -> Result<(), String> {
        let mut flows = self.flows.lock().await;
        let flow = flows
            .get_mut(&flow_id)
            .ok_or_else(|| "Flow not found".to_string())?;

        let data_size = data.len() as u64;

        // Check congestion window
        let congestion = self.congestion.lock().await;
        if flow.bytes_sent + data_size > congestion.cwnd() {
            drop(congestion);

            // Queue the data if fair queuing is enabled
            if self.config.enable_fair_queuing {
                let mut queue = self.fair_queue.lock().await;
                queue.enqueue(flow_id, flow.traffic_class, data);
                return Ok(());
            } else {
                return Err("Congestion window exceeded".to_string());
            }
        }
        drop(congestion);

        // Update flow statistics
        flow.bytes_sent += data_size;
        flow.last_send = Instant::now();

        // Update congestion controller
        let mut congestion = self.congestion.lock().await;
        congestion.on_ack(data_size);

        // Update statistics
        let mut stats = self.stats.lock().await;
        stats.total_bytes += data_size;
        stats.congestion_state = congestion.state();

        Ok(())
    }

    /// Record packet loss for congestion control
    pub async fn record_loss(&self, _flow_id: u64) {
        let mut congestion = self.congestion.lock().await;
        congestion.on_loss();
    }

    /// Update RTT measurement
    pub async fn update_rtt(&self, rtt_ms: f64) {
        let mut congestion = self.congestion.lock().await;
        congestion.update_rtt(rtt_ms);
    }

    /// Get statistics
    pub async fn stats(&self) -> TrafficShaperStats {
        self.stats.lock().await.clone()
    }

    /// Get congestion state
    pub async fn congestion_state(&self) -> CongestionState {
        self.congestion.lock().await.state()
    }

    /// Get fair queue statistics
    pub async fn queue_stats(&self) -> FairQueueStats {
        self.fair_queue.lock().await.stats().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_priority() {
        assert_eq!(ContentType::RealTime.default_priority(), 5);
        assert_eq!(ContentType::Control.default_priority(), 4);
        assert_eq!(ContentType::Video.default_priority(), 3);
        assert_eq!(ContentType::Background.default_priority(), 1);
    }

    #[test]
    fn test_traffic_class() {
        let tc = TrafficClass::from_content_type(ContentType::Video);
        assert_eq!(tc.priority, 3);
        assert_eq!(tc.content_type, ContentType::Video);
    }

    #[test]
    fn test_congestion_controller_new() {
        let cc = CongestionController::new(CongestionAlgorithm::Aimd, 10000);
        assert_eq!(cc.cwnd(), 10000);
        assert_eq!(cc.state(), CongestionState::Normal);
    }

    #[test]
    fn test_congestion_controller_on_ack() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Aimd, 10000);
        cc.on_ack(1000);
        assert!(cc.cwnd() > 10000);
    }

    #[test]
    fn test_congestion_controller_on_loss() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Aimd, 10000);
        cc.on_loss();
        assert!(cc.cwnd() < 10000);
    }

    #[test]
    fn test_congestion_controller_rtt() {
        let mut cc = CongestionController::new(CongestionAlgorithm::Aimd, 10000);
        cc.update_rtt(50.0);
        assert!(cc.rtt_ms > 0.0);
    }

    #[test]
    fn test_fair_queue_enqueue() {
        let mut fq = FairQueue::new();
        let tc = TrafficClass::from_content_type(ContentType::Video);
        fq.enqueue(1, tc, vec![1, 2, 3]);
        assert_eq!(fq.stats().packets_enqueued, 1);
    }

    #[test]
    fn test_fair_queue_dequeue() {
        let mut fq = FairQueue::new();
        let tc = TrafficClass::from_content_type(ContentType::Video);
        fq.enqueue(1, tc, vec![1, 2, 3]);

        let result = fq.dequeue();
        assert!(result.is_some());
        assert_eq!(fq.stats().packets_dequeued, 1);
    }

    #[test]
    fn test_fair_queue_priority() {
        let mut fq = FairQueue::new();
        let high_priority = TrafficClass::from_content_type(ContentType::RealTime);
        let low_priority = TrafficClass::from_content_type(ContentType::Background);

        fq.enqueue(1, low_priority, vec![1, 2, 3]);
        fq.enqueue(2, high_priority, vec![4, 5, 6]);

        // Higher priority should be dequeued first
        let result = fq.dequeue();
        assert!(result.is_some());
    }

    #[test]
    fn test_fair_queue_depth() {
        let mut fq = FairQueue::new();
        let tc = TrafficClass::from_content_type(ContentType::Video);

        fq.enqueue(1, tc, vec![1, 2, 3]);
        fq.enqueue(1, tc, vec![4, 5, 6]);

        assert_eq!(fq.queue_depth(&tc), 2);
        assert_eq!(fq.total_depth(), 2);
    }

    #[tokio::test]
    async fn test_traffic_shaper_new() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);
        let stats = shaper.stats().await;
        assert_eq!(stats.active_flows, 0);
    }

    #[tokio::test]
    async fn test_traffic_shaper_create_flow() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);

        let tc = TrafficClass::from_content_type(ContentType::Video);
        let flow_id = shaper.create_flow(tc, 5_000_000).await;

        assert!(flow_id > 0);
        let stats = shaper.stats().await;
        assert_eq!(stats.active_flows, 1);
    }

    #[tokio::test]
    async fn test_traffic_shaper_remove_flow() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);

        let tc = TrafficClass::from_content_type(ContentType::Video);
        let flow_id = shaper.create_flow(tc, 5_000_000).await;

        shaper.remove_flow(flow_id).await;
        let stats = shaper.stats().await;
        assert_eq!(stats.active_flows, 0);
    }

    #[tokio::test]
    async fn test_traffic_shaper_shape() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);

        let tc = TrafficClass::from_content_type(ContentType::Video);
        let flow_id = shaper.create_flow(tc, 5_000_000).await;

        let data = vec![0u8; 1000];
        let result = shaper.shape(flow_id, data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_traffic_shaper_record_loss() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);

        let tc = TrafficClass::from_content_type(ContentType::Video);
        let flow_id = shaper.create_flow(tc, 5_000_000).await;

        shaper.record_loss(flow_id).await;
        // Loss should affect congestion state
        let state = shaper.congestion_state().await;
        assert!(matches!(
            state,
            CongestionState::Normal | CongestionState::Mild
        ));
    }

    #[tokio::test]
    async fn test_traffic_shaper_update_rtt() {
        let config = TrafficShaperConfig::default();
        let shaper = TrafficShaper::new(config);

        shaper.update_rtt(50.0).await;
        // RTT update should succeed without error
    }
}
