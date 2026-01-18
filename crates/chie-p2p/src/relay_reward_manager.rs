// Relay reward management for incentivized relay nodes
//
// Manages reward distribution and payment processing for relay nodes:
// - Token earning tracking per relay node
// - Reward distribution based on performance and quality
// - Payment processing and withdrawal management
// - Economic incentive calculations
// - Relay node profitability analysis
// - Integration with relay optimizer for comprehensive incentive system

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

/// Relay reward configuration
#[derive(Debug, Clone)]
pub struct RewardConfig {
    /// Base reward per GB relayed (in protocol tokens)
    pub base_reward_per_gb: u64,
    /// Quality multiplier range (min, max)
    pub quality_multiplier_range: (f64, f64),
    /// Minimum quality score to earn rewards
    pub min_quality_for_rewards: f64,
    /// Payment threshold (minimum tokens before withdrawal)
    pub payment_threshold: u64,
    /// Payment processing fee (percentage)
    pub payment_fee_percent: f64,
    /// Reward decay rate per day for inactive relays
    pub inactivity_decay_rate: f64,
    /// Maximum pending payment age before expiry (days)
    pub payment_expiry_days: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            base_reward_per_gb: 100, // 100 tokens per GB
            quality_multiplier_range: (0.5, 2.0),
            min_quality_for_rewards: 0.6,
            payment_threshold: 1000,     // 1000 tokens minimum
            payment_fee_percent: 2.0,    // 2% fee
            inactivity_decay_rate: 0.05, // 5% per day
            payment_expiry_days: 90,
        }
    }
}

/// Relay earnings record
#[derive(Debug, Clone)]
pub struct RelayEarnings {
    /// Relay peer ID
    pub peer_id: PeerId,
    /// Total tokens earned (all time)
    pub total_earned: u64,
    /// Pending tokens (not yet withdrawn)
    pub pending_tokens: u64,
    /// Withdrawn tokens (successfully paid)
    pub withdrawn_tokens: u64,
    /// Expired tokens (unclaimed)
    pub expired_tokens: u64,
    /// Total bytes relayed
    pub total_bytes_relayed: u64,
    /// Average quality score (0.0-1.0)
    pub avg_quality: f64,
    /// Number of successful relays
    pub successful_relays: u64,
    /// Number of failed relays
    pub failed_relays: u64,
    /// Last earning timestamp
    pub last_earned_at: Instant,
    /// Last withdrawal timestamp
    pub last_withdrawn_at: Option<Instant>,
}

impl RelayEarnings {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            total_earned: 0,
            pending_tokens: 0,
            withdrawn_tokens: 0,
            expired_tokens: 0,
            total_bytes_relayed: 0,
            avg_quality: 0.0,
            successful_relays: 0,
            failed_relays: 0,
            last_earned_at: Instant::now(),
            last_withdrawn_at: None,
        }
    }

    /// Success rate for this relay
    pub fn success_rate(&self) -> f64 {
        let total = self.successful_relays + self.failed_relays;
        if total == 0 {
            return 0.0;
        }
        self.successful_relays as f64 / total as f64
    }

    /// Earnings per GB
    pub fn earnings_per_gb(&self) -> f64 {
        if self.total_bytes_relayed == 0 {
            return 0.0;
        }
        let gb = self.total_bytes_relayed as f64 / 1_073_741_824.0;
        self.total_earned as f64 / gb
    }
}

/// Payment request
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Request ID
    pub id: u64,
    /// Relay peer requesting payment
    pub peer_id: PeerId,
    /// Amount requested (tokens)
    pub amount: u64,
    /// Payment fee (tokens)
    pub fee: u64,
    /// Net amount after fee
    pub net_amount: u64,
    /// Payment address/destination
    pub destination: String,
    /// Request timestamp
    pub requested_at: SystemTime,
    /// Payment status
    pub status: PaymentStatus,
}

/// Payment status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Payment requested but not processed
    Pending,
    /// Payment is being processed
    Processing,
    /// Payment completed successfully
    Completed,
    /// Payment failed
    Failed(String),
    /// Payment expired (unclaimed)
    Expired,
    /// Payment cancelled
    Cancelled,
}

/// Reward calculation result
#[derive(Debug, Clone)]
pub struct RewardCalculation {
    /// Base reward amount
    pub base_reward: u64,
    /// Quality multiplier applied
    pub quality_multiplier: f64,
    /// Final reward amount
    pub final_reward: u64,
    /// Quality score used
    pub quality_score: f64,
}

/// Relay reward manager statistics
#[derive(Debug, Clone, Default)]
pub struct RewardManagerStats {
    /// Total tokens distributed
    pub total_distributed: u64,
    /// Total tokens withdrawn
    pub total_withdrawn: u64,
    /// Total tokens pending
    pub total_pending: u64,
    /// Total tokens expired
    pub total_expired: u64,
    /// Total payment requests
    pub total_payment_requests: u64,
    /// Successful payments
    pub successful_payments: u64,
    /// Failed payments
    pub failed_payments: u64,
    /// Total relays rewarded
    pub total_relays: u64,
    /// Average reward per relay
    pub avg_reward_per_relay: f64,
}

/// Relay reward manager
pub struct RelayRewardManager {
    config: RewardConfig,
    earnings: HashMap<PeerId, RelayEarnings>,
    payments: HashMap<u64, PaymentRequest>,
    next_payment_id: u64,
    stats: RewardManagerStats,
}

impl RelayRewardManager {
    /// Create a new reward manager
    pub fn new(config: RewardConfig) -> Self {
        Self {
            config,
            earnings: HashMap::new(),
            payments: HashMap::new(),
            next_payment_id: 1,
            stats: RewardManagerStats::default(),
        }
    }

    /// Calculate reward for a relay operation
    pub fn calculate_reward(
        &self,
        bytes_relayed: u64,
        quality_score: f64,
    ) -> Option<RewardCalculation> {
        // Check minimum quality threshold
        if quality_score < self.config.min_quality_for_rewards {
            return None;
        }

        // Calculate base reward
        let gb = bytes_relayed as f64 / 1_073_741_824.0;
        let base_reward = (gb * self.config.base_reward_per_gb as f64) as u64;

        // Apply quality multiplier
        let (min_mult, max_mult) = self.config.quality_multiplier_range;
        let quality_multiplier = min_mult + (max_mult - min_mult) * quality_score;
        let final_reward = (base_reward as f64 * quality_multiplier) as u64;

        Some(RewardCalculation {
            base_reward,
            quality_multiplier,
            final_reward,
            quality_score,
        })
    }

    /// Award tokens to a relay node
    pub fn award_relay(
        &mut self,
        peer_id: &PeerId,
        bytes_relayed: u64,
        quality_score: f64,
        success: bool,
    ) -> Option<u64> {
        // Calculate reward
        let calculation = self.calculate_reward(bytes_relayed, quality_score)?;
        let reward = calculation.final_reward;

        // Get or create earnings record
        let earnings = self.earnings.entry(*peer_id).or_insert_with(|| {
            self.stats.total_relays += 1;
            RelayEarnings::new(*peer_id)
        });

        // Update earnings
        earnings.total_earned += reward;
        earnings.pending_tokens += reward;
        earnings.total_bytes_relayed += bytes_relayed;
        earnings.last_earned_at = Instant::now();

        // Update running average quality
        let total_ops = earnings.successful_relays + earnings.failed_relays + 1;
        earnings.avg_quality =
            (earnings.avg_quality * (total_ops - 1) as f64 + quality_score) / total_ops as f64;

        // Update success/failure counts
        if success {
            earnings.successful_relays += 1;
        } else {
            earnings.failed_relays += 1;
        }

        // Update global stats
        self.stats.total_distributed += reward;
        self.stats.total_pending += reward;
        self.stats.avg_reward_per_relay =
            self.stats.total_distributed as f64 / self.stats.total_relays as f64;

        Some(reward)
    }

    /// Request payment withdrawal
    pub fn request_payment(
        &mut self,
        peer_id: &PeerId,
        amount: u64,
        destination: String,
    ) -> Result<PaymentRequest, String> {
        // Get earnings
        let earnings = self
            .earnings
            .get_mut(peer_id)
            .ok_or("No earnings found for peer")?;

        // Check minimum threshold
        if earnings.pending_tokens < self.config.payment_threshold {
            return Err(format!(
                "Pending tokens ({}) below threshold ({})",
                earnings.pending_tokens, self.config.payment_threshold
            ));
        }

        // Check requested amount
        if amount > earnings.pending_tokens {
            return Err(format!(
                "Requested amount ({}) exceeds pending tokens ({})",
                amount, earnings.pending_tokens
            ));
        }

        // Calculate fee
        let fee = (amount as f64 * self.config.payment_fee_percent / 100.0) as u64;
        let net_amount = amount.saturating_sub(fee);

        // Create payment request
        let payment = PaymentRequest {
            id: self.next_payment_id,
            peer_id: *peer_id,
            amount,
            fee,
            net_amount,
            destination,
            requested_at: SystemTime::now(),
            status: PaymentStatus::Pending,
        };

        self.next_payment_id += 1;
        self.stats.total_payment_requests += 1;

        // Deduct from pending
        earnings.pending_tokens = earnings.pending_tokens.saturating_sub(amount);
        self.stats.total_pending = self.stats.total_pending.saturating_sub(amount);

        let payment_id = payment.id;
        self.payments.insert(payment_id, payment.clone());

        Ok(payment)
    }

    /// Complete a payment
    pub fn complete_payment(&mut self, payment_id: u64) -> Result<(), String> {
        let payment = self
            .payments
            .get_mut(&payment_id)
            .ok_or("Payment not found")?;

        if payment.status != PaymentStatus::Pending && payment.status != PaymentStatus::Processing {
            return Err(format!(
                "Payment not in processable state: {:?}",
                payment.status
            ));
        }

        payment.status = PaymentStatus::Completed;

        // Update earnings
        if let Some(earnings) = self.earnings.get_mut(&payment.peer_id) {
            earnings.withdrawn_tokens += payment.amount;
            earnings.last_withdrawn_at = Some(Instant::now());
        }

        // Update stats
        self.stats.total_withdrawn += payment.amount;
        self.stats.successful_payments += 1;

        Ok(())
    }

    /// Fail a payment
    pub fn fail_payment(&mut self, payment_id: u64, reason: String) -> Result<(), String> {
        let payment = self
            .payments
            .get_mut(&payment_id)
            .ok_or("Payment not found")?;

        payment.status = PaymentStatus::Failed(reason);

        // Return tokens to pending
        if let Some(earnings) = self.earnings.get_mut(&payment.peer_id) {
            earnings.pending_tokens += payment.amount;
            self.stats.total_pending += payment.amount;
        }

        self.stats.failed_payments += 1;

        Ok(())
    }

    /// Apply inactivity decay to all relay earnings
    pub fn apply_inactivity_decay(&mut self, days_inactive: u32) {
        let decay_rate = self.config.inactivity_decay_rate;

        for earnings in self.earnings.values_mut() {
            let days_since_earning = earnings.last_earned_at.elapsed().as_secs() / 86400;

            if days_since_earning >= days_inactive as u64 {
                let decay_factor = (1.0 - decay_rate).powi(days_inactive as i32);
                let decayed_amount = earnings.pending_tokens
                    - (earnings.pending_tokens as f64 * decay_factor) as u64;

                earnings.pending_tokens = (earnings.pending_tokens as f64 * decay_factor) as u64;
                earnings.expired_tokens += decayed_amount;

                self.stats.total_pending = self.stats.total_pending.saturating_sub(decayed_amount);
                self.stats.total_expired += decayed_amount;
            }
        }
    }

    /// Expire old payment requests
    pub fn expire_old_payments(&mut self) {
        let expiry_duration = Duration::from_secs(self.config.payment_expiry_days * 86400);
        let now = SystemTime::now();

        let expired_payments: Vec<u64> = self
            .payments
            .iter()
            .filter_map(|(id, payment)| {
                if payment.status == PaymentStatus::Pending {
                    if let Ok(age) = now.duration_since(payment.requested_at) {
                        if age > expiry_duration {
                            return Some(*id);
                        }
                    }
                }
                None
            })
            .collect();

        for payment_id in expired_payments {
            if let Some(payment) = self.payments.get_mut(&payment_id) {
                payment.status = PaymentStatus::Expired;

                // Return tokens to expired
                if let Some(earnings) = self.earnings.get_mut(&payment.peer_id) {
                    earnings.expired_tokens += payment.amount;
                    self.stats.total_expired += payment.amount;
                }
            }
        }
    }

    /// Get earnings for a relay
    pub fn get_earnings(&self, peer_id: &PeerId) -> Option<&RelayEarnings> {
        self.earnings.get(peer_id)
    }

    /// Get payment request
    pub fn get_payment(&self, payment_id: u64) -> Option<&PaymentRequest> {
        self.payments.get(&payment_id)
    }

    /// Get all earnings
    pub fn get_all_earnings(&self) -> Vec<&RelayEarnings> {
        self.earnings.values().collect()
    }

    /// Get top earners
    pub fn get_top_earners(&self, count: usize) -> Vec<&RelayEarnings> {
        let mut earners: Vec<&RelayEarnings> = self.earnings.values().collect();
        earners.sort_by(|a, b| b.total_earned.cmp(&a.total_earned));
        earners.into_iter().take(count).collect()
    }

    /// Get pending payments
    pub fn get_pending_payments(&self) -> Vec<&PaymentRequest> {
        self.payments
            .values()
            .filter(|p| p.status == PaymentStatus::Pending)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &RewardManagerStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &RewardConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_calculate_reward_basic() {
        let manager = RelayRewardManager::new(RewardConfig::default());
        let bytes_relayed = 1_073_741_824; // 1 GB
        let quality_score = 0.8;

        let calc = manager
            .calculate_reward(bytes_relayed, quality_score)
            .unwrap();
        assert_eq!(calc.base_reward, 100);
        assert!(calc.final_reward > calc.base_reward);
    }

    #[test]
    fn test_calculate_reward_below_threshold() {
        let manager = RelayRewardManager::new(RewardConfig::default());
        let bytes_relayed = 1_073_741_824; // 1 GB
        let quality_score = 0.5; // Below 0.6 threshold

        assert!(
            manager
                .calculate_reward(bytes_relayed, quality_score)
                .is_none()
        );
    }

    #[test]
    fn test_award_relay() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();
        let bytes = 1_073_741_824;

        let reward = manager.award_relay(&peer, bytes, 0.8, true).unwrap();
        assert!(reward > 0);

        let earnings = manager.get_earnings(&peer).unwrap();
        assert_eq!(earnings.total_earned, reward);
        assert_eq!(earnings.pending_tokens, reward);
        assert_eq!(earnings.successful_relays, 1);
    }

    #[test]
    fn test_award_relay_updates_average_quality() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 1_073_741_824, 0.8, true);
        manager.award_relay(&peer, 1_073_741_824, 0.9, true);

        let earnings = manager.get_earnings(&peer).unwrap();
        assert!((earnings.avg_quality - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_payment_request_success() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        // Award enough to meet threshold
        manager.award_relay(&peer, 10_737_418_240, 0.8, true); // 10 GB

        let payment = manager
            .request_payment(&peer, 1000, "test_address".to_string())
            .unwrap();

        assert_eq!(payment.status, PaymentStatus::Pending);
        assert!(payment.fee > 0);
        assert_eq!(payment.net_amount, payment.amount - payment.fee);
    }

    #[test]
    fn test_payment_request_below_threshold() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        // Award less than threshold
        manager.award_relay(&peer, 1_073_741_824, 0.8, true); // 1 GB

        let result = manager.request_payment(&peer, 100, "test_address".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_payment_request_exceeds_pending() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true); // 10 GB

        let result = manager.request_payment(&peer, 999999, "test_address".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_complete_payment() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true);
        let payment = manager
            .request_payment(&peer, 1000, "test_address".to_string())
            .unwrap();

        manager.complete_payment(payment.id).unwrap();

        let payment = manager.get_payment(payment.id).unwrap();
        assert_eq!(payment.status, PaymentStatus::Completed);

        let earnings = manager.get_earnings(&peer).unwrap();
        assert_eq!(earnings.withdrawn_tokens, 1000);
    }

    #[test]
    fn test_fail_payment() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true);
        let payment = manager
            .request_payment(&peer, 1000, "test_address".to_string())
            .unwrap();

        let pending_before = manager.get_earnings(&peer).unwrap().pending_tokens;

        manager
            .fail_payment(payment.id, "Test failure".to_string())
            .unwrap();

        let pending_after = manager.get_earnings(&peer).unwrap().pending_tokens;
        assert_eq!(pending_after, pending_before + 1000);
    }

    #[test]
    fn test_success_rate() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 1_073_741_824, 0.8, true);
        manager.award_relay(&peer, 1_073_741_824, 0.8, true);
        manager.award_relay(&peer, 1_073_741_824, 0.8, false);

        let earnings = manager.get_earnings(&peer).unwrap();
        assert!((earnings.success_rate() - 0.6667).abs() < 0.001);
    }

    #[test]
    fn test_earnings_per_gb() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 1_073_741_824, 0.8, true);

        let earnings = manager.get_earnings(&peer).unwrap();
        let per_gb = earnings.earnings_per_gb();
        assert!(per_gb > 0.0);
    }

    #[test]
    fn test_get_top_earners() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        manager.award_relay(&peer1, 1_073_741_824, 0.8, true);
        manager.award_relay(&peer2, 5_368_709_120, 0.9, true);
        manager.award_relay(&peer3, 2_147_483_648, 0.7, true);

        let top = manager.get_top_earners(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].peer_id, peer2); // Highest earner
    }

    #[test]
    fn test_stats_tracking() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true);
        manager
            .request_payment(&peer, 1000, "test".to_string())
            .unwrap();

        let stats = manager.stats();
        assert!(stats.total_distributed > 0);
        assert_eq!(stats.total_payment_requests, 1);
    }

    #[test]
    fn test_get_pending_payments() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true);
        manager
            .request_payment(&peer, 1000, "test".to_string())
            .unwrap();

        let pending = manager.get_pending_payments();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_quality_multiplier_range() {
        let manager = RelayRewardManager::new(RewardConfig::default());

        // Test minimum quality (0.6 threshold)
        let calc_min = manager.calculate_reward(1_073_741_824, 0.6).unwrap();

        // Test maximum quality (1.0)
        let calc_max = manager.calculate_reward(1_073_741_824, 1.0).unwrap();

        assert!(calc_max.final_reward > calc_min.final_reward);
    }

    #[test]
    fn test_payment_fee_calculation() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        manager.award_relay(&peer, 10_737_418_240, 0.8, true);
        let payment = manager
            .request_payment(&peer, 1000, "test".to_string())
            .unwrap();

        // 2% fee on 1000 = 20
        assert_eq!(payment.fee, 20);
        assert_eq!(payment.net_amount, 980);
    }

    #[test]
    fn test_multiple_relays_accumulate() {
        let mut manager = RelayRewardManager::new(RewardConfig::default());
        let peer = create_test_peer();

        let reward1 = manager
            .award_relay(&peer, 1_073_741_824, 0.8, true)
            .unwrap();
        let reward2 = manager
            .award_relay(&peer, 1_073_741_824, 0.8, true)
            .unwrap();

        let earnings = manager.get_earnings(&peer).unwrap();
        assert_eq!(earnings.total_earned, reward1 + reward2);
        assert_eq!(earnings.successful_relays, 2);
    }
}
