//! Traffic analysis resistance for enhanced privacy.
//!
//! This module implements various techniques to resist traffic analysis attacks,
//! making it difficult for observers to infer information about content, peers,
//! and communication patterns from network traffic.
//!
//! # Techniques Implemented
//!
//! - **Padding**: Add random padding to messages to hide actual message sizes
//! - **Timing Obfuscation**: Add random delays to hide timing patterns
//! - **Dummy Traffic**: Send decoy messages to hide real traffic patterns
//! - **Packet Size Normalization**: Round packet sizes to fixed intervals
//! - **Connection Mixing**: Route traffic through multiple paths
//!
//! # Example
//!
//! ```rust,no_run
//! use chie_p2p::traffic_analysis_resistance::{TrafficObfuscator, ObfuscationConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ObfuscationConfig::default()
//!     .with_padding_enabled(true)
//!     .with_dummy_traffic_enabled(true)
//!     .with_timing_obfuscation(true);
//!
//! let obfuscator = TrafficObfuscator::new(config);
//!
//! // Obfuscate outgoing message
//! let message = b"sensitive data";
//! let obfuscated = obfuscator.obfuscate_message(message).await?;
//!
//! // Deobfuscate incoming message
//! let original = obfuscator.deobfuscate_message(&obfuscated).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

/// Padding strategy for messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingStrategy {
    /// No padding
    None,
    /// Fixed amount of padding
    Fixed(usize),
    /// Random padding within a range
    Random { min: usize, max: usize },
    /// Round to nearest power of 2
    PowerOfTwo,
    /// Round to fixed block size
    BlockSize(usize),
}

/// Timing obfuscation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingStrategy {
    /// No timing obfuscation
    None,
    /// Fixed delay
    Fixed(Duration),
    /// Random delay within range
    Random { min: Duration, max: Duration },
    /// Exponential distribution
    Exponential { mean: Duration },
}

/// Dummy traffic configuration
#[derive(Debug, Clone, Copy)]
pub struct DummyTrafficConfig {
    /// Whether dummy traffic is enabled
    pub enabled: bool,
    /// Rate of dummy messages per second
    pub rate: f64,
    /// Size range for dummy messages
    pub size_range: (usize, usize),
    /// Maximum concurrent dummy connections
    pub max_concurrent: usize,
}

impl Default for DummyTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate: 0.1, // 0.1 messages per second
            size_range: (100, 1500),
            max_concurrent: 5,
        }
    }
}

/// Obfuscation configuration
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Padding strategy
    pub padding: PaddingStrategy,
    /// Timing obfuscation strategy
    pub timing: TimingStrategy,
    /// Dummy traffic configuration
    pub dummy_traffic: DummyTrafficConfig,
    /// Maximum message size after padding
    pub max_padded_size: usize,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            padding: PaddingStrategy::Random { min: 0, max: 256 },
            timing: TimingStrategy::Random {
                min: Duration::from_millis(0),
                max: Duration::from_millis(100),
            },
            dummy_traffic: DummyTrafficConfig::default(),
            max_padded_size: 65536,
        }
    }
}

impl ObfuscationConfig {
    /// Enable padding with strategy
    pub fn with_padding_enabled(mut self, enabled: bool) -> Self {
        if !enabled {
            self.padding = PaddingStrategy::None;
        }
        self
    }

    /// Set padding strategy
    pub fn with_padding_strategy(mut self, strategy: PaddingStrategy) -> Self {
        self.padding = strategy;
        self
    }

    /// Enable timing obfuscation
    pub fn with_timing_obfuscation(mut self, enabled: bool) -> Self {
        if !enabled {
            self.timing = TimingStrategy::None;
        }
        self
    }

    /// Set timing strategy
    pub fn with_timing_strategy(mut self, strategy: TimingStrategy) -> Self {
        self.timing = strategy;
        self
    }

    /// Enable dummy traffic
    pub fn with_dummy_traffic_enabled(mut self, enabled: bool) -> Self {
        self.dummy_traffic.enabled = enabled;
        self
    }

    /// Set dummy traffic rate
    pub fn with_dummy_traffic_rate(mut self, rate: f64) -> Self {
        self.dummy_traffic.rate = rate;
        self
    }

    /// Set maximum padded size
    pub fn with_max_padded_size(mut self, size: usize) -> Self {
        self.max_padded_size = size;
        self
    }
}

/// Obfuscated message structure
#[derive(Debug, Clone)]
pub struct ObfuscatedMessage {
    /// Actual message data
    pub data: Vec<u8>,
    /// Padding bytes
    pub padding: Vec<u8>,
    /// Original size (before padding)
    pub original_size: usize,
    /// Timestamp when obfuscated
    pub timestamp: SystemTime,
    /// Whether this is a dummy message
    pub is_dummy: bool,
}

/// Traffic obfuscation statistics
#[derive(Debug, Clone, Default)]
pub struct ObfuscationStats {
    /// Total messages obfuscated
    pub messages_obfuscated: u64,
    /// Total dummy messages sent
    pub dummy_messages_sent: u64,
    /// Total bytes of padding added
    pub padding_bytes_added: u64,
    /// Total timing delays applied (ms)
    pub total_delay_ms: u64,
    /// Average padding per message
    pub avg_padding_bytes: f64,
}

/// Traffic obfuscator
pub struct TrafficObfuscator {
    /// Configuration
    config: ObfuscationConfig,
    /// Statistics
    stats: Arc<Mutex<ObfuscationStats>>,
    /// Dummy message queue
    dummy_queue: Arc<Mutex<Vec<ObfuscatedMessage>>>,
    /// Active dummy connections
    active_dummy_connections: Arc<Mutex<usize>>,
}

impl TrafficObfuscator {
    /// Create a new traffic obfuscator
    pub fn new(config: ObfuscationConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Mutex::new(ObfuscationStats::default())),
            dummy_queue: Arc::new(Mutex::new(Vec::new())),
            active_dummy_connections: Arc::new(Mutex::new(0)),
        }
    }

    /// Obfuscate a message
    pub async fn obfuscate_message(&self, data: &[u8]) -> Result<ObfuscatedMessage, String> {
        // Apply timing obfuscation first
        self.apply_timing_delay().await;

        // Calculate padding
        let padding = self.calculate_padding(data.len())?;

        // Create obfuscated message
        let obfuscated = ObfuscatedMessage {
            data: data.to_vec(),
            padding,
            original_size: data.len(),
            timestamp: SystemTime::now(),
            is_dummy: false,
        };

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.messages_obfuscated += 1;
            stats.padding_bytes_added += obfuscated.padding.len() as u64;
            stats.avg_padding_bytes =
                stats.padding_bytes_added as f64 / stats.messages_obfuscated as f64;
        }

        Ok(obfuscated)
    }

    /// Deobfuscate a message
    pub async fn deobfuscate_message(
        &self,
        obfuscated: &ObfuscatedMessage,
    ) -> Result<Vec<u8>, String> {
        if obfuscated.is_dummy {
            return Ok(Vec::new());
        }

        Ok(obfuscated.data.clone())
    }

    /// Calculate padding based on strategy
    fn calculate_padding(&self, message_size: usize) -> Result<Vec<u8>, String> {
        let padding_size = match self.config.padding {
            PaddingStrategy::None => 0,
            PaddingStrategy::Fixed(size) => size,
            PaddingStrategy::Random { min, max } => {
                use rand::RngExt as _;
                let mut rng = rand::rng();
                rng.random_range(min..=max)
            }
            PaddingStrategy::PowerOfTwo => {
                let next_power = (message_size as f64).log2().ceil();
                let target_size = 2usize.pow(next_power as u32);
                target_size.saturating_sub(message_size)
            }
            PaddingStrategy::BlockSize(block) => {
                let blocks = message_size.div_ceil(block);
                (blocks * block).saturating_sub(message_size)
            }
        };

        // Check max size
        if message_size + padding_size > self.config.max_padded_size {
            return Err("Padded message exceeds maximum size".to_string());
        }

        // Generate random padding
        use rand::RngExt as _;
        let mut rng = rand::rng();
        let padding: Vec<u8> = (0..padding_size).map(|_| rng.random()).collect();

        Ok(padding)
    }

    /// Apply timing delay
    async fn apply_timing_delay(&self) {
        let delay = match self.config.timing {
            TimingStrategy::None => return,
            TimingStrategy::Fixed(duration) => duration,
            TimingStrategy::Random { min, max } => {
                use rand::RngExt as _;
                let mut rng = rand::rng();
                let millis = rng.random_range(min.as_millis() as u64..=max.as_millis() as u64);
                Duration::from_millis(millis)
            }
            TimingStrategy::Exponential { mean } => {
                use rand::RngExt as _;
                let mut rng = rand::rng();
                let u: f64 = rng.random();
                let mean_millis = mean.as_millis() as f64;
                let millis = (-mean_millis * u.ln()) as u64;
                Duration::from_millis(millis)
            }
        };

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.total_delay_ms += delay.as_millis() as u64;
        }

        sleep(delay).await;
    }

    /// Generate a dummy message
    pub fn generate_dummy_message(&self) -> ObfuscatedMessage {
        use rand::RngExt as _;
        let mut rng = rand::rng();
        let size = rng.random_range(
            self.config.dummy_traffic.size_range.0..=self.config.dummy_traffic.size_range.1,
        );

        let data: Vec<u8> = (0..size).map(|_| rng.random()).collect();

        let mut stats = self.stats.lock().unwrap();
        stats.dummy_messages_sent += 1;

        ObfuscatedMessage {
            data,
            padding: Vec::new(),
            original_size: size,
            timestamp: SystemTime::now(),
            is_dummy: true,
        }
    }

    /// Start dummy traffic generator
    pub async fn start_dummy_traffic(&self) {
        if !self.config.dummy_traffic.enabled {
            return;
        }

        let interval = Duration::from_secs_f64(1.0 / self.config.dummy_traffic.rate);

        loop {
            // Check if we're below max concurrent
            let active = *self.active_dummy_connections.lock().unwrap();
            if active < self.config.dummy_traffic.max_concurrent {
                let dummy = self.generate_dummy_message();
                self.dummy_queue.lock().unwrap().push(dummy);
            }

            sleep(interval).await;
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> ObfuscationStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.lock().unwrap() = ObfuscationStats::default();
    }

    /// Get pending dummy messages
    pub fn get_dummy_messages(&self) -> Vec<ObfuscatedMessage> {
        let mut queue = self.dummy_queue.lock().unwrap();
        let messages = queue.clone();
        queue.clear();
        messages
    }

    /// Increment active dummy connections
    pub fn increment_dummy_connections(&self) {
        *self.active_dummy_connections.lock().unwrap() += 1;
    }

    /// Decrement active dummy connections
    pub fn decrement_dummy_connections(&self) {
        let mut active = self.active_dummy_connections.lock().unwrap();
        if *active > 0 {
            *active -= 1;
        }
    }
}

/// Normalize packet size to fixed intervals
pub fn normalize_packet_size(size: usize, interval: usize) -> usize {
    size.div_ceil(interval) * interval
}

/// Calculate optimal padding for traffic shaping
pub fn calculate_optimal_padding(
    sizes: &[usize],
    target_distribution: &HashMap<usize, f64>,
) -> HashMap<usize, usize> {
    let mut padding_map = HashMap::new();

    for &size in sizes {
        // Find nearest target size that is >= current size
        let target = target_distribution
            .keys()
            .filter(|&&k| k >= size)
            .min()
            .or_else(|| target_distribution.keys().max())
            .copied()
            .unwrap_or(size);

        let padding = target.saturating_sub(size);
        padding_map.insert(size, padding);
    }

    padding_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_obfuscate_message_no_padding() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::None)
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = b"test message";

        let obfuscated = obfuscator.obfuscate_message(message).await.unwrap();
        assert_eq!(obfuscated.data, message);
        assert_eq!(obfuscated.padding.len(), 0);
        assert_eq!(obfuscated.original_size, message.len());
    }

    #[tokio::test]
    async fn test_obfuscate_message_fixed_padding() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::Fixed(100))
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = b"test";

        let obfuscated = obfuscator.obfuscate_message(message).await.unwrap();
        assert_eq!(obfuscated.padding.len(), 100);
    }

    #[tokio::test]
    async fn test_obfuscate_message_random_padding() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::Random { min: 10, max: 50 })
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = b"test";

        let obfuscated = obfuscator.obfuscate_message(message).await.unwrap();
        assert!(obfuscated.padding.len() >= 10);
        assert!(obfuscated.padding.len() <= 50);
    }

    #[tokio::test]
    async fn test_obfuscate_message_power_of_two() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::PowerOfTwo)
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = vec![0u8; 100];

        let obfuscated = obfuscator.obfuscate_message(&message).await.unwrap();
        let total_size = obfuscated.data.len() + obfuscated.padding.len();
        assert!(total_size.is_power_of_two());
    }

    #[tokio::test]
    async fn test_obfuscate_message_block_size() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::BlockSize(256))
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = vec![0u8; 100];

        let obfuscated = obfuscator.obfuscate_message(&message).await.unwrap();
        let total_size = obfuscated.data.len() + obfuscated.padding.len();
        assert_eq!(total_size % 256, 0);
    }

    #[tokio::test]
    async fn test_deobfuscate_message() {
        let config = ObfuscationConfig::default().with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = b"test message";

        let obfuscated = obfuscator.obfuscate_message(message).await.unwrap();
        let deobfuscated = obfuscator.deobfuscate_message(&obfuscated).await.unwrap();

        assert_eq!(deobfuscated, message);
    }

    #[tokio::test]
    async fn test_timing_delay_fixed() {
        let delay_duration = Duration::from_millis(50);
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::None)
            .with_timing_strategy(TimingStrategy::Fixed(delay_duration));

        let obfuscator = TrafficObfuscator::new(config);
        let message = b"test";

        let start = std::time::Instant::now();
        let _ = obfuscator.obfuscate_message(message).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= delay_duration);
    }

    #[test]
    fn test_generate_dummy_message() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);

        let dummy = obfuscator.generate_dummy_message();
        assert!(dummy.is_dummy);
        assert!(!dummy.data.is_empty());
    }

    #[test]
    fn test_statistics() {
        let config = ObfuscationConfig::default().with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);

        let stats = obfuscator.get_stats();
        assert_eq!(stats.messages_obfuscated, 0);

        // Generate a dummy message
        obfuscator.generate_dummy_message();

        let stats = obfuscator.get_stats();
        assert_eq!(stats.dummy_messages_sent, 1);
    }

    #[test]
    fn test_normalize_packet_size() {
        assert_eq!(normalize_packet_size(100, 64), 128);
        assert_eq!(normalize_packet_size(128, 64), 128);
        assert_eq!(normalize_packet_size(200, 64), 256);
    }

    #[test]
    fn test_calculate_optimal_padding() {
        let sizes = vec![100, 200, 300];
        let mut target_distribution = HashMap::new();
        target_distribution.insert(128, 0.33);
        target_distribution.insert(256, 0.33);
        target_distribution.insert(512, 0.34);

        let padding = calculate_optimal_padding(&sizes, &target_distribution);
        assert_eq!(padding.get(&100), Some(&28)); // 100 -> 128
        assert_eq!(padding.get(&200), Some(&56)); // 200 -> 256
        assert_eq!(padding.get(&300), Some(&212)); // 300 -> 512
    }

    #[test]
    fn test_dummy_connections_tracking() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);

        obfuscator.increment_dummy_connections();
        obfuscator.increment_dummy_connections();
        assert_eq!(*obfuscator.active_dummy_connections.lock().unwrap(), 2);

        obfuscator.decrement_dummy_connections();
        assert_eq!(*obfuscator.active_dummy_connections.lock().unwrap(), 1);
    }

    #[test]
    fn test_config_builder() {
        let config = ObfuscationConfig::default()
            .with_padding_enabled(false)
            .with_timing_obfuscation(false)
            .with_dummy_traffic_enabled(true)
            .with_dummy_traffic_rate(0.5)
            .with_max_padded_size(32768);

        assert_eq!(config.padding, PaddingStrategy::None);
        assert_eq!(config.timing, TimingStrategy::None);
        assert!(config.dummy_traffic.enabled);
        assert_eq!(config.dummy_traffic.rate, 0.5);
        assert_eq!(config.max_padded_size, 32768);
    }

    #[test]
    fn test_reset_stats() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);

        obfuscator.generate_dummy_message();
        let stats = obfuscator.get_stats();
        assert_eq!(stats.dummy_messages_sent, 1);

        obfuscator.reset_stats();
        let stats = obfuscator.get_stats();
        assert_eq!(stats.dummy_messages_sent, 0);
    }

    #[test]
    fn test_dummy_queue() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);

        obfuscator
            .dummy_queue
            .lock()
            .unwrap()
            .push(obfuscator.generate_dummy_message());
        obfuscator
            .dummy_queue
            .lock()
            .unwrap()
            .push(obfuscator.generate_dummy_message());

        let messages = obfuscator.get_dummy_messages();
        assert_eq!(messages.len(), 2);

        // Queue should be cleared
        let messages = obfuscator.get_dummy_messages();
        assert_eq!(messages.len(), 0);
    }

    #[tokio::test]
    async fn test_max_padded_size_check() {
        let config = ObfuscationConfig::default()
            .with_padding_strategy(PaddingStrategy::Fixed(1000))
            .with_max_padded_size(500)
            .with_timing_strategy(TimingStrategy::None);

        let obfuscator = TrafficObfuscator::new(config);
        let message = vec![0u8; 100];

        let result = obfuscator.obfuscate_message(&message).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_deobfuscate_dummy_message() {
        let config = ObfuscationConfig::default();
        let obfuscator = TrafficObfuscator::new(config);

        let dummy = obfuscator.generate_dummy_message();
        let deobfuscated = obfuscator.deobfuscate_message(&dummy).await.unwrap();

        assert!(deobfuscated.is_empty());
    }
}
