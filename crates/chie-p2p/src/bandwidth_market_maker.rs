//! Automated bandwidth market maker for intelligent auction participation.
//!
//! This module provides automated bidding strategies for the bandwidth auction system,
//! helping peers optimize their bandwidth allocation and costs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Market maker strategy for bandwidth auctions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketStrategy {
    /// Aggressive bidding - prioritize getting bandwidth over cost
    Aggressive,
    /// Conservative bidding - minimize cost, accept lower bandwidth
    Conservative,
    /// Balanced bidding - optimize for value (bandwidth per cost)
    Balanced,
    /// Adaptive bidding - adjust strategy based on market conditions
    Adaptive,
    /// Opportunistic bidding - bid only when prices are favorable
    Opportunistic,
}

/// Market condition assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketCondition {
    /// High supply, low demand - favorable for buyers
    Buyers,
    /// Low supply, high demand - favorable for sellers
    Sellers,
    /// Balanced market
    Neutral,
    /// Insufficient data to determine
    Unknown,
}

/// Bidding recommendation from the market maker.
#[derive(Debug, Clone)]
pub struct BidRecommendation {
    /// Recommended bid price per unit bandwidth
    pub price: u64,
    /// Recommended bandwidth amount to request
    pub bandwidth: u64,
    /// Confidence in this recommendation (0.0-1.0)
    pub confidence: f64,
    /// Estimated probability of winning (0.0-1.0)
    pub win_probability: f64,
    /// Expected value of this bid
    pub expected_value: f64,
}

/// Configuration for the market maker.
#[derive(Debug, Clone)]
pub struct MarketMakerConfig {
    /// Maximum price willing to pay per unit bandwidth
    pub max_price: u64,
    /// Minimum bandwidth required
    pub min_bandwidth: u64,
    /// Maximum bandwidth desired
    pub max_bandwidth: u64,
    /// Value assigned to each unit of bandwidth
    pub bandwidth_value: u64,
    /// How long to track market history
    pub history_window: Duration,
    /// Minimum number of historical auctions before making recommendations
    pub min_history_size: usize,
}

impl Default for MarketMakerConfig {
    fn default() -> Self {
        Self {
            max_price: 1000,
            min_bandwidth: 1024 * 1024,       // 1 MB/s
            max_bandwidth: 100 * 1024 * 1024, // 100 MB/s
            bandwidth_value: 500,
            history_window: Duration::from_secs(3600), // 1 hour
            min_history_size: 5,
        }
    }
}

/// Historical auction data point.
#[derive(Debug, Clone)]
struct AuctionHistory {
    timestamp: Instant,
    #[allow(dead_code)]
    winning_price: u64,
    clearing_price: u64,
    total_supply: u64,
    total_demand: u64,
    #[allow(dead_code)]
    num_bids: usize,
}

/// Statistics about market making activity.
#[derive(Debug, Clone)]
pub struct MarketMakerStats {
    /// Current market condition
    pub market_condition: MarketCondition,
    /// Number of recommendations made
    pub recommendations_made: usize,
    /// Number of successful bids
    pub successful_bids: usize,
    /// Average price paid
    pub avg_price_paid: f64,
    /// Average bandwidth allocated
    pub avg_bandwidth_allocated: f64,
    /// Total value obtained
    pub total_value: f64,
    /// Size of history
    pub history_size: usize,
}

/// Bandwidth market maker for automated auction participation.
pub struct BandwidthMarketMaker {
    config: MarketMakerConfig,
    strategy: MarketStrategy,
    history: Arc<Mutex<Vec<AuctionHistory>>>,
    stats: Arc<Mutex<MarketMakerStats>>,
}

impl BandwidthMarketMaker {
    /// Creates a new market maker with default configuration.
    pub fn new(strategy: MarketStrategy) -> Self {
        Self::with_config(strategy, MarketMakerConfig::default())
    }

    /// Creates a new market maker with custom configuration.
    pub fn with_config(strategy: MarketStrategy, config: MarketMakerConfig) -> Self {
        Self {
            config,
            strategy,
            history: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(MarketMakerStats {
                market_condition: MarketCondition::Unknown,
                recommendations_made: 0,
                successful_bids: 0,
                avg_price_paid: 0.0,
                avg_bandwidth_allocated: 0.0,
                total_value: 0.0,
                history_size: 0,
            })),
        }
    }

    /// Records the outcome of a completed auction.
    pub fn record_auction(
        &self,
        winning_price: u64,
        clearing_price: u64,
        total_supply: u64,
        total_demand: u64,
        num_bids: usize,
    ) {
        let mut history = self.history.lock().unwrap();

        history.push(AuctionHistory {
            timestamp: Instant::now(),
            winning_price,
            clearing_price,
            total_supply,
            total_demand,
            num_bids,
        });

        // Cleanup old history
        let cutoff = Instant::now() - self.config.history_window;
        history.retain(|h| h.timestamp >= cutoff);

        // Update stats
        let mut stats = self.stats.lock().unwrap();
        stats.history_size = history.len();
        stats.market_condition = self.assess_market_condition_internal(&history);
    }

    /// Records a successful bid allocation.
    pub fn record_allocation(&self, price_paid: u64, bandwidth_allocated: u64) {
        let mut stats = self.stats.lock().unwrap();
        stats.successful_bids += 1;

        let total_bids = stats.successful_bids as f64;
        let new_price = price_paid as f64;
        let new_bandwidth = bandwidth_allocated as f64;

        // Update running averages
        stats.avg_price_paid = (stats.avg_price_paid * (total_bids - 1.0) + new_price) / total_bids;
        stats.avg_bandwidth_allocated =
            (stats.avg_bandwidth_allocated * (total_bids - 1.0) + new_bandwidth) / total_bids;

        // Calculate value (benefit - cost)
        let value = (bandwidth_allocated as f64 * self.config.bandwidth_value as f64)
            - (price_paid * bandwidth_allocated) as f64;
        stats.total_value += value;
    }

    /// Gets a bidding recommendation based on current market conditions.
    pub fn recommend_bid(&self, desired_bandwidth: u64) -> Option<BidRecommendation> {
        let history = self.history.lock().unwrap();

        // Need sufficient history
        if history.len() < self.config.min_history_size {
            return None;
        }

        let market_condition = self.assess_market_condition_internal(&history);

        // Calculate base price from historical data
        let avg_clearing_price = self.calculate_average_clearing_price(&history);
        let price_volatility = self.calculate_price_volatility(&history);

        // Adjust price based on strategy and market conditions
        let recommended_price = self.calculate_recommended_price(
            avg_clearing_price,
            price_volatility,
            market_condition,
        );

        // Cap at max price
        let final_price = recommended_price.min(self.config.max_price);

        // Adjust bandwidth based on budget and market
        let recommended_bandwidth =
            self.calculate_recommended_bandwidth(desired_bandwidth, final_price, market_condition);

        // Estimate win probability
        let win_probability = self.estimate_win_probability(final_price, &history);

        // Calculate expected value
        let expected_value =
            self.calculate_expected_value(recommended_bandwidth, final_price, win_probability);

        // Confidence based on history size and volatility
        let confidence = self.calculate_confidence(history.len(), price_volatility);

        // Update stats
        let mut stats = self.stats.lock().unwrap();
        stats.recommendations_made += 1;

        Some(BidRecommendation {
            price: final_price,
            bandwidth: recommended_bandwidth,
            confidence,
            win_probability,
            expected_value,
        })
    }

    /// Assesses current market condition.
    pub fn assess_market_condition(&self) -> MarketCondition {
        let history = self.history.lock().unwrap();
        self.assess_market_condition_internal(&history)
    }

    fn assess_market_condition_internal(&self, history: &[AuctionHistory]) -> MarketCondition {
        if history.is_empty() {
            return MarketCondition::Unknown;
        }

        // Calculate average supply/demand ratio
        let ratios: Vec<f64> = history
            .iter()
            .map(|h| {
                if h.total_demand > 0 {
                    h.total_supply as f64 / h.total_demand as f64
                } else {
                    1.0
                }
            })
            .collect();

        let avg_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;

        if avg_ratio > 1.5 {
            MarketCondition::Buyers
        } else if avg_ratio < 0.67 {
            MarketCondition::Sellers
        } else {
            MarketCondition::Neutral
        }
    }

    fn calculate_average_clearing_price(&self, history: &[AuctionHistory]) -> u64 {
        if history.is_empty() {
            return 0;
        }

        let sum: u64 = history.iter().map(|h| h.clearing_price).sum();
        sum / history.len() as u64
    }

    fn calculate_price_volatility(&self, history: &[AuctionHistory]) -> f64 {
        if history.len() < 2 {
            return 0.0;
        }

        let prices: Vec<f64> = history.iter().map(|h| h.clearing_price as f64).collect();
        let mean = prices.iter().sum::<f64>() / prices.len() as f64;

        let variance = prices
            .iter()
            .map(|p| {
                let diff = p - mean;
                diff * diff
            })
            .sum::<f64>()
            / prices.len() as f64;

        variance.sqrt() / mean.max(1.0)
    }

    fn calculate_recommended_price(
        &self,
        avg_price: u64,
        volatility: f64,
        condition: MarketCondition,
    ) -> u64 {
        let base_multiplier = match self.strategy {
            MarketStrategy::Aggressive => 1.2,
            MarketStrategy::Conservative => 0.8,
            MarketStrategy::Balanced => 1.0,
            MarketStrategy::Adaptive => match condition {
                MarketCondition::Buyers => 0.9,
                MarketCondition::Sellers => 1.15,
                MarketCondition::Neutral => 1.0,
                MarketCondition::Unknown => 1.0,
            },
            MarketStrategy::Opportunistic => 0.7,
        };

        // Adjust for volatility - higher volatility means bid higher for safety
        let volatility_adjustment = 1.0 + (volatility * 0.2);

        let final_multiplier = base_multiplier * volatility_adjustment;
        (avg_price as f64 * final_multiplier) as u64
    }

    fn calculate_recommended_bandwidth(
        &self,
        desired: u64,
        _price: u64,
        condition: MarketCondition,
    ) -> u64 {
        let mut bandwidth = desired;

        // Adjust based on market condition
        bandwidth = match condition {
            MarketCondition::Buyers => {
                // Favorable market, request more
                (bandwidth as f64 * 1.2) as u64
            }
            MarketCondition::Sellers => {
                // Unfavorable market, request less
                (bandwidth as f64 * 0.8) as u64
            }
            _ => bandwidth,
        };

        // Ensure within bounds
        bandwidth.clamp(self.config.min_bandwidth, self.config.max_bandwidth)
    }

    fn estimate_win_probability(&self, price: u64, history: &[AuctionHistory]) -> f64 {
        if history.is_empty() {
            return 0.5;
        }

        // Count how many auctions would have been won at this price
        let wins = history.iter().filter(|h| price >= h.clearing_price).count();

        wins as f64 / history.len() as f64
    }

    fn calculate_expected_value(&self, bandwidth: u64, price: u64, win_prob: f64) -> f64 {
        let value =
            (bandwidth as f64 * self.config.bandwidth_value as f64) - (price * bandwidth) as f64;
        value * win_prob
    }

    fn calculate_confidence(&self, history_size: usize, volatility: f64) -> f64 {
        // Confidence increases with more data, decreases with volatility
        let size_factor = (history_size as f64 / 20.0).min(1.0);
        let volatility_factor = (1.0 - volatility).max(0.0);

        (size_factor + volatility_factor) / 2.0
    }

    /// Gets current statistics.
    pub fn stats(&self) -> MarketMakerStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clears all history and resets statistics.
    pub fn clear(&self) {
        self.history.lock().unwrap().clear();

        let mut stats = self.stats.lock().unwrap();
        *stats = MarketMakerStats {
            market_condition: MarketCondition::Unknown,
            recommendations_made: 0,
            successful_bids: 0,
            avg_price_paid: 0.0,
            avg_bandwidth_allocated: 0.0,
            total_value: 0.0,
            history_size: 0,
        };
    }
}

impl Clone for BandwidthMarketMaker {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            strategy: self.strategy,
            history: Arc::new(Mutex::new(self.history.lock().unwrap().clone())),
            stats: Arc::new(Mutex::new(self.stats.lock().unwrap().clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_market_maker_new() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);
        let stats = mm.stats();

        assert_eq!(stats.recommendations_made, 0);
        assert_eq!(stats.successful_bids, 0);
        assert_eq!(stats.market_condition, MarketCondition::Unknown);
    }

    #[test]
    fn test_record_auction() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        mm.record_auction(100, 90, 1000, 800, 5);

        let stats = mm.stats();
        assert_eq!(stats.history_size, 1);
    }

    #[test]
    fn test_record_allocation() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        mm.record_allocation(100, 1024 * 1024);

        let stats = mm.stats();
        assert_eq!(stats.successful_bids, 1);
        assert_eq!(stats.avg_price_paid, 100.0);
        assert_eq!(stats.avg_bandwidth_allocated, 1024.0 * 1024.0);
    }

    #[test]
    fn test_recommend_bid_insufficient_history() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        let recommendation = mm.recommend_bid(1024 * 1024);
        assert!(recommendation.is_none());
    }

    #[test]
    fn test_recommend_bid_with_history() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        // Add sufficient history
        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 800, 5);
        }

        let recommendation = mm.recommend_bid(1024 * 1024);
        assert!(recommendation.is_some());

        let rec = recommendation.unwrap();
        assert!(rec.price > 0);
        assert!(rec.bandwidth > 0);
        assert!(rec.confidence >= 0.0 && rec.confidence <= 1.0);
        assert!(rec.win_probability >= 0.0 && rec.win_probability <= 1.0);
    }

    #[test]
    fn test_market_condition_buyers() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        // High supply, low demand
        for _ in 0..5 {
            mm.record_auction(100, 90, 2000, 800, 5);
        }

        let condition = mm.assess_market_condition();
        assert_eq!(condition, MarketCondition::Buyers);
    }

    #[test]
    fn test_market_condition_sellers() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        // Low supply, high demand
        for _ in 0..5 {
            mm.record_auction(100, 90, 800, 2000, 5);
        }

        let condition = mm.assess_market_condition();
        assert_eq!(condition, MarketCondition::Sellers);
    }

    #[test]
    fn test_aggressive_strategy() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Aggressive);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Aggressive should bid higher than average
        assert!(rec.price > 90);
    }

    #[test]
    fn test_conservative_strategy() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Conservative);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Conservative should bid lower than aggressive
        assert!(rec.price < 100);
    }

    #[test]
    fn test_adaptive_strategy() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Adaptive);

        // Create sellers market (low supply, high demand)
        for _ in 0..10 {
            mm.record_auction(100, 90, 500, 2000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Adaptive should adjust to market conditions
        assert!(rec.price > 90);
    }

    #[test]
    fn test_clear() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        mm.record_auction(100, 90, 1000, 800, 5);
        mm.record_allocation(100, 1024 * 1024);

        mm.clear();

        let stats = mm.stats();
        assert_eq!(stats.history_size, 0);
        assert_eq!(stats.successful_bids, 0);
        assert_eq!(stats.recommendations_made, 0);
    }

    #[test]
    fn test_clone() {
        let mm1 = BandwidthMarketMaker::new(MarketStrategy::Balanced);
        mm1.record_auction(100, 90, 1000, 800, 5);

        let mm2 = mm1.clone();
        let stats = mm2.stats();

        assert_eq!(stats.history_size, 1);
    }

    #[test]
    fn test_config_default() {
        let config = MarketMakerConfig::default();

        assert_eq!(config.max_price, 1000);
        assert_eq!(config.min_bandwidth, 1024 * 1024);
        assert!(config.max_bandwidth > config.min_bandwidth);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_bandwidth_limits() {
        let mut config = MarketMakerConfig::default();
        config.min_bandwidth = 1024;
        config.max_bandwidth = 2048;

        let mm = BandwidthMarketMaker::with_config(MarketStrategy::Balanced, config);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(10000).unwrap();

        // Should be clamped to max
        assert!(rec.bandwidth <= 2048);
    }

    #[test]
    fn test_expected_value_calculation() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Expected value should be reasonable
        assert!(rec.expected_value.is_finite());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_price_capped_at_max() {
        let mut config = MarketMakerConfig::default();
        config.max_price = 50;

        let mm = BandwidthMarketMaker::with_config(MarketStrategy::Aggressive, config);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Price should be capped at max_price
        assert!(rec.price <= 50);
    }

    #[test]
    fn test_confidence_increases_with_history() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Balanced);

        // Add minimal history
        for _ in 0..5 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec1 = mm.recommend_bid(1024 * 1024).unwrap();

        // Add more history
        for _ in 0..15 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec2 = mm.recommend_bid(1024 * 1024).unwrap();

        // Confidence should increase with more data
        assert!(rec2.confidence >= rec1.confidence);
    }

    #[test]
    fn test_opportunistic_strategy() {
        let mm = BandwidthMarketMaker::new(MarketStrategy::Opportunistic);

        for _ in 0..10 {
            mm.record_auction(100, 90, 1000, 1000, 5);
        }

        let rec = mm.recommend_bid(1024 * 1024).unwrap();

        // Opportunistic should bid lower to get good deals
        assert!(rec.price < 90);
    }
}
