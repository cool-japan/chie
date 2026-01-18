//! Bandwidth auction system for dynamic resource allocation.
//!
//! This module implements a marketplace for bandwidth allocation where peers
//! can bid for bandwidth resources based on their needs and budget.
//!
//! # Example
//! ```
//! use chie_p2p::bandwidth_auction::{BandwidthAuction, AuctionConfig, Bid, BidType};
//! use std::time::Duration;
//!
//! let config = AuctionConfig {
//!     auction_duration: Duration::from_secs(60),
//!     min_bid_increment: 100,
//!     reserve_price: 1000,
//!     max_bids_per_peer: 10,
//! };
//!
//! let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);
//!
//! // Place a bid
//! auction.place_bid(Bid {
//!     bidder: "peer1".to_string(),
//!     amount: 5000,
//!     bandwidth_needed: 500_000,
//!     bid_type: BidType::Standard,
//! });
//! ```

use std::time::{Duration, Instant};

/// Auction identifier
pub type AuctionId = String;

/// Peer identifier
pub type PeerId = String;

/// Bid type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BidType {
    /// Standard bid
    Standard,
    /// All-or-nothing bid (must get full bandwidth or nothing)
    AllOrNothing,
    /// Pro-rata bid (willing to accept partial allocation)
    ProRata,
}

/// Auction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuctionState {
    /// Auction is open for bids
    Open,
    /// Auction is closed, determining winners
    Closed,
    /// Auction is finalized with winners determined
    Finalized,
    /// Auction was cancelled
    Cancelled,
}

/// Bid in the auction
#[derive(Debug, Clone)]
pub struct Bid {
    /// Bidder peer ID
    pub bidder: PeerId,
    /// Bid amount (points or tokens)
    pub amount: u64,
    /// Bandwidth needed (bytes/sec)
    pub bandwidth_needed: u64,
    /// Type of bid
    pub bid_type: BidType,
}

impl Bid {
    /// Calculate price per unit bandwidth
    pub fn price_per_unit(&self) -> f64 {
        if self.bandwidth_needed == 0 {
            return 0.0;
        }
        self.amount as f64 / self.bandwidth_needed as f64
    }
}

/// Allocation result
#[derive(Debug, Clone)]
pub struct Allocation {
    /// Winner peer ID
    pub winner: PeerId,
    /// Allocated bandwidth
    pub bandwidth: u64,
    /// Price paid
    pub price: u64,
}

/// Auction configuration
#[derive(Debug, Clone)]
pub struct AuctionConfig {
    /// Auction duration
    pub auction_duration: Duration,
    /// Minimum bid increment
    pub min_bid_increment: u64,
    /// Reserve price (minimum acceptable price)
    pub reserve_price: u64,
    /// Maximum bids per peer
    pub max_bids_per_peer: usize,
}

impl Default for AuctionConfig {
    fn default() -> Self {
        Self {
            auction_duration: Duration::from_secs(300), // 5 minutes
            min_bid_increment: 100,
            reserve_price: 1000,
            max_bids_per_peer: 10,
        }
    }
}

/// Bandwidth auction
pub struct BandwidthAuction {
    /// Auction ID
    id: AuctionId,
    /// Total bandwidth available
    total_bandwidth: u64,
    /// Configuration
    config: AuctionConfig,
    /// Current bids
    bids: Vec<Bid>,
    /// Auction state
    state: AuctionState,
    /// When auction started
    started_at: Instant,
    /// When auction ended
    ended_at: Option<Instant>,
    /// Final allocations
    allocations: Vec<Allocation>,
    /// Total bids received
    total_bids_received: u64,
}

impl BandwidthAuction {
    /// Create a new auction
    pub fn new(id: AuctionId, total_bandwidth: u64, config: AuctionConfig) -> Self {
        Self {
            id,
            total_bandwidth,
            config,
            bids: Vec::new(),
            state: AuctionState::Open,
            started_at: Instant::now(),
            ended_at: None,
            allocations: Vec::new(),
            total_bids_received: 0,
        }
    }

    /// Get auction ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get auction state
    pub fn state(&self) -> AuctionState {
        self.state
    }

    /// Place a bid
    pub fn place_bid(&mut self, bid: Bid) -> Result<(), String> {
        // Check if auction is open
        if self.state != AuctionState::Open {
            return Err("Auction is not open".to_string());
        }

        // Check if auction has expired
        if self.started_at.elapsed() > self.config.auction_duration {
            self.close();
            return Err("Auction has expired".to_string());
        }

        // Check bid amount against reserve price
        if bid.amount < self.config.reserve_price {
            return Err("Bid below reserve price".to_string());
        }

        // Check peer bid limit
        let peer_bid_count = self.bids.iter().filter(|b| b.bidder == bid.bidder).count();
        if peer_bid_count >= self.config.max_bids_per_peer {
            return Err("Maximum bids per peer exceeded".to_string());
        }

        self.bids.push(bid);
        self.total_bids_received += 1;
        Ok(())
    }

    /// Close the auction
    pub fn close(&mut self) {
        if self.state == AuctionState::Open {
            self.state = AuctionState::Closed;
            self.ended_at = Some(Instant::now());
        }
    }

    /// Finalize auction and determine winners
    pub fn finalize(&mut self) {
        if self.state != AuctionState::Closed {
            self.close();
        }

        // Sort bids by price per unit (descending)
        let mut sorted_bids = self.bids.clone();
        sorted_bids.sort_by(|a, b| {
            b.price_per_unit()
                .partial_cmp(&a.price_per_unit())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut remaining_bandwidth = self.total_bandwidth;
        let mut allocations = Vec::new();

        for bid in sorted_bids {
            if remaining_bandwidth == 0 {
                break;
            }

            match bid.bid_type {
                BidType::AllOrNothing => {
                    if remaining_bandwidth >= bid.bandwidth_needed {
                        allocations.push(Allocation {
                            winner: bid.bidder.clone(),
                            bandwidth: bid.bandwidth_needed,
                            price: bid.amount,
                        });
                        remaining_bandwidth -= bid.bandwidth_needed;
                    }
                }
                BidType::Standard | BidType::ProRata => {
                    let allocated = remaining_bandwidth.min(bid.bandwidth_needed);
                    if allocated > 0 {
                        // Pro-rate the price if partial allocation
                        let price = if allocated < bid.bandwidth_needed {
                            (bid.amount as f64 * allocated as f64 / bid.bandwidth_needed as f64)
                                as u64
                        } else {
                            bid.amount
                        };

                        allocations.push(Allocation {
                            winner: bid.bidder.clone(),
                            bandwidth: allocated,
                            price,
                        });
                        remaining_bandwidth -= allocated;
                    }
                }
            }
        }

        self.allocations = allocations;
        self.state = AuctionState::Finalized;
    }

    /// Cancel the auction
    pub fn cancel(&mut self) {
        self.state = AuctionState::Cancelled;
        self.ended_at = Some(Instant::now());
    }

    /// Get all bids
    pub fn get_bids(&self) -> &[Bid] {
        &self.bids
    }

    /// Get allocations (only after finalization)
    pub fn get_allocations(&self) -> &[Allocation] {
        &self.allocations
    }

    /// Get auction statistics
    pub fn stats(&self) -> AuctionStats {
        let total_allocated = self.allocations.iter().map(|a| a.bandwidth).sum();
        let total_revenue = self.allocations.iter().map(|a| a.price).sum();
        let unique_bidders = self
            .bids
            .iter()
            .map(|b| &b.bidder)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let unique_winners = self
            .allocations
            .iter()
            .map(|a| &a.winner)
            .collect::<std::collections::HashSet<_>>()
            .len();

        AuctionStats {
            total_bids: self.bids.len(),
            unique_bidders,
            unique_winners,
            total_bandwidth_allocated: total_allocated,
            total_revenue,
            utilization_rate: total_allocated as f64 / self.total_bandwidth as f64,
            average_price: if total_allocated > 0 {
                total_revenue as f64 / total_allocated as f64
            } else {
                0.0
            },
        }
    }

    /// Check if auction has expired
    pub fn is_expired(&self) -> bool {
        self.started_at.elapsed() > self.config.auction_duration
    }

    /// Get remaining time
    pub fn remaining_time(&self) -> Duration {
        self.config
            .auction_duration
            .saturating_sub(self.started_at.elapsed())
    }
}

/// Auction statistics
#[derive(Debug, Clone)]
pub struct AuctionStats {
    /// Total number of bids
    pub total_bids: usize,
    /// Unique bidders
    pub unique_bidders: usize,
    /// Unique winners
    pub unique_winners: usize,
    /// Total bandwidth allocated
    pub total_bandwidth_allocated: u64,
    /// Total revenue
    pub total_revenue: u64,
    /// Utilization rate (0.0-1.0)
    pub utilization_rate: f64,
    /// Average price per unit bandwidth
    pub average_price: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_auction() {
        let config = AuctionConfig::default();
        let auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        assert_eq!(auction.state(), AuctionState::Open);
        assert_eq!(auction.id(), "auction-1");
    }

    #[test]
    fn test_place_bid() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 5000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        assert!(auction.place_bid(bid).is_ok());
        assert_eq!(auction.get_bids().len(), 1);
    }

    #[test]
    fn test_bid_below_reserve() {
        let config = AuctionConfig {
            reserve_price: 10000,
            ..Default::default()
        };
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 5000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        assert!(auction.place_bid(bid).is_err());
    }

    #[test]
    fn test_max_bids_per_peer() {
        let config = AuctionConfig {
            max_bids_per_peer: 2,
            ..Default::default()
        };
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        for i in 0..3 {
            let bid = Bid {
                bidder: "peer1".to_string(),
                amount: 5000 + i * 100,
                bandwidth_needed: 500_000,
                bid_type: BidType::Standard,
            };

            if i < 2 {
                assert!(auction.place_bid(bid).is_ok());
            } else {
                assert!(auction.place_bid(bid).is_err());
            }
        }
    }

    #[test]
    fn test_close_auction() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        auction.close();
        assert_eq!(auction.state(), AuctionState::Closed);
    }

    #[test]
    fn test_finalize_auction() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let bid1 = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        let bid2 = Bid {
            bidder: "peer2".to_string(),
            amount: 15000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        auction.place_bid(bid1).unwrap();
        auction.place_bid(bid2).unwrap();

        auction.finalize();

        assert_eq!(auction.state(), AuctionState::Finalized);
        assert_eq!(auction.get_allocations().len(), 2);
    }

    #[test]
    fn test_price_per_unit() {
        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        assert_eq!(bid.price_per_unit(), 0.02);
    }

    #[test]
    fn test_allocation_ordering() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        // Higher price per unit should win
        let bid1 = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        let bid2 = Bid {
            bidder: "peer2".to_string(),
            amount: 20000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        auction.place_bid(bid1).unwrap();
        auction.place_bid(bid2).unwrap();

        auction.finalize();

        // peer2 should get first allocation due to higher price
        let allocations = auction.get_allocations();
        assert_eq!(allocations[0].winner, "peer2");
    }

    #[test]
    fn test_all_or_nothing_bid() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 600_000, config);

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 700_000, // More than available
            bid_type: BidType::AllOrNothing,
        };

        auction.place_bid(bid).unwrap();
        auction.finalize();

        // Should get no allocation
        assert_eq!(auction.get_allocations().len(), 0);
    }

    #[test]
    fn test_pro_rata_partial_allocation() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 300_000, config);

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::ProRata,
        };

        auction.place_bid(bid).unwrap();
        auction.finalize();

        let allocations = auction.get_allocations();
        assert_eq!(allocations.len(), 1);
        assert_eq!(allocations[0].bandwidth, 300_000);
        // Price should be pro-rated: 10000 * (300000/500000) = 6000
        assert_eq!(allocations[0].price, 6000);
    }

    #[test]
    fn test_cancel_auction() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        auction.cancel();
        assert_eq!(auction.state(), AuctionState::Cancelled);
    }

    #[test]
    fn test_bid_after_close() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        auction.close();

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 5000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        assert!(auction.place_bid(bid).is_err());
    }

    #[test]
    fn test_auction_stats() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let bid1 = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        let bid2 = Bid {
            bidder: "peer2".to_string(),
            amount: 15000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        auction.place_bid(bid1).unwrap();
        auction.place_bid(bid2).unwrap();
        auction.finalize();

        let stats = auction.stats();
        assert_eq!(stats.total_bids, 2);
        assert_eq!(stats.unique_bidders, 2);
        assert_eq!(stats.unique_winners, 2);
        assert_eq!(stats.total_bandwidth_allocated, 1_000_000);
    }

    #[test]
    fn test_utilization_rate() {
        let config = AuctionConfig::default();
        let mut auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let bid = Bid {
            bidder: "peer1".to_string(),
            amount: 10000,
            bandwidth_needed: 500_000,
            bid_type: BidType::Standard,
        };

        auction.place_bid(bid).unwrap();
        auction.finalize();

        let stats = auction.stats();
        assert_eq!(stats.utilization_rate, 0.5);
    }

    #[test]
    fn test_remaining_time() {
        let config = AuctionConfig {
            auction_duration: Duration::from_secs(10),
            ..Default::default()
        };
        let auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        let remaining = auction.remaining_time();
        assert!(remaining <= Duration::from_secs(10));
    }

    #[test]
    fn test_is_expired() {
        let config = AuctionConfig {
            auction_duration: Duration::from_millis(50),
            ..Default::default()
        };
        let auction = BandwidthAuction::new("auction-1".to_string(), 1_000_000, config);

        std::thread::sleep(Duration::from_millis(100));

        assert!(auction.is_expired());
    }
}
