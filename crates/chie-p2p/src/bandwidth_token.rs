//! Bandwidth Token System for economic incentives in P2P networks.
//!
//! This module implements a comprehensive token-based economic system for bandwidth
//! allocation, rewards, and penalties. It provides the economic layer for the CHIE
//! protocol's incentivized P2P network.
//!
//! # Features
//!
//! - **Token Balance Management**: Track token balances for each peer
//! - **Staking System**: Stake tokens for quality of service guarantees
//! - **Reward Distribution**: Distribute rewards for bandwidth provision
//! - **Penalty System**: Apply penalties for violations and poor behavior
//! - **Escrow Mechanism**: Hold tokens in escrow for pending transactions
//! - **Transaction History**: Complete audit trail of all token operations
//! - **Mint/Burn Controls**: Administrative token supply management
//! - **Slashing**: Stake slashing for severe violations
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{
//!     BandwidthTokenSystem, TokenConfig, TokenOperation,
//! };
//!
//! let config = TokenConfig {
//!     initial_balance: 1000,
//!     min_stake: 100,
//!     reward_per_gb: 10,
//!     penalty_rate: 0.1,
//!     slash_percentage: 50,
//!     ..Default::default()
//! };
//!
//! let mut system = BandwidthTokenSystem::new(config);
//!
//! // Register a peer with initial balance
//! let peer_id = "12D3KooWTest".to_string();
//! system.register_peer(&peer_id, 1000);
//!
//! // Stake tokens for QoS
//! system.stake(&peer_id, 200).unwrap();
//!
//! // Reward peer for bandwidth provision
//! system.reward(&peer_id, 50, "Provided 5 GB".to_string()).unwrap();
//!
//! // Check balance
//! let balance = system.balance(&peer_id).unwrap();
//! assert!(balance.available >= 850); // 1000 - 200 (staked) + 50 (reward)
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Token balance information for a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Total tokens owned by peer.
    pub total: u64,
    /// Available tokens (not staked or in escrow).
    pub available: u64,
    /// Tokens currently staked.
    pub staked: u64,
    /// Tokens held in escrow.
    pub escrowed: u64,
}

/// Token operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenOperation {
    /// Mint new tokens.
    Mint,
    /// Burn tokens.
    Burn,
    /// Transfer tokens between peers.
    Transfer,
    /// Stake tokens.
    Stake,
    /// Unstake tokens.
    Unstake,
    /// Reward tokens.
    Reward,
    /// Penalize tokens.
    Penalty,
    /// Move tokens to escrow.
    Escrow,
    /// Release tokens from escrow.
    Release,
    /// Slash staked tokens.
    Slash,
}

/// Transaction record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransaction {
    /// Transaction ID.
    pub tx_id: String,
    /// Operation type.
    pub operation: TokenOperation,
    /// Source peer ID (if applicable).
    pub from: Option<String>,
    /// Destination peer ID (if applicable).
    pub to: Option<String>,
    /// Amount of tokens.
    pub amount: u64,
    /// Reason or description.
    pub reason: String,
    /// Timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Success status.
    pub success: bool,
}

/// Configuration for token system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Initial balance for new peers.
    pub initial_balance: u64,
    /// Minimum stake requirement.
    pub min_stake: u64,
    /// Maximum stake allowed.
    pub max_stake: u64,
    /// Reward per GB provided.
    pub reward_per_gb: u64,
    /// Penalty rate (0.0 to 1.0).
    pub penalty_rate: f64,
    /// Slash percentage for severe violations (0-100).
    pub slash_percentage: u8,
    /// Enable transaction history.
    pub enable_history: bool,
    /// Maximum history size per peer.
    pub max_history_size: usize,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            initial_balance: 1000,
            min_stake: 100,
            max_stake: 10000,
            reward_per_gb: 10,
            penalty_rate: 0.1,
            slash_percentage: 50,
            enable_history: true,
            max_history_size: 1000,
        }
    }
}

/// Statistics for token system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenStats {
    /// Total supply of tokens in circulation.
    pub total_supply: u64,
    /// Total tokens staked across all peers.
    pub total_staked: u64,
    /// Total tokens in escrow.
    pub total_escrowed: u64,
    /// Total rewards distributed.
    pub total_rewards: u64,
    /// Total penalties applied.
    pub total_penalties: u64,
    /// Total tokens slashed.
    pub total_slashed: u64,
    /// Number of registered peers.
    pub peer_count: usize,
    /// Total number of transactions.
    pub transaction_count: u64,
}

/// Internal peer state.
#[derive(Debug, Clone)]
struct PeerState {
    balance: TokenBalance,
    history: Vec<TokenTransaction>,
}

impl PeerState {
    fn new(initial_balance: u64) -> Self {
        Self {
            balance: TokenBalance {
                total: initial_balance,
                available: initial_balance,
                staked: 0,
                escrowed: 0,
            },
            history: Vec::new(),
        }
    }
}

/// Bandwidth Token System.
pub struct BandwidthTokenSystem {
    config: TokenConfig,
    peers: Arc<RwLock<HashMap<String, PeerState>>>,
    stats: Arc<RwLock<TokenStats>>,
    tx_counter: Arc<RwLock<u64>>,
}

impl BandwidthTokenSystem {
    /// Creates a new token system with the given configuration.
    pub fn new(config: TokenConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(TokenStats::default())),
            tx_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Registers a new peer with initial balance.
    pub fn register_peer(&mut self, peer_id: &str, initial_balance: u64) -> bool {
        let mut peers = self.peers.write().unwrap();

        if peers.contains_key(peer_id) {
            return false; // Already registered
        }

        peers.insert(peer_id.to_string(), PeerState::new(initial_balance));

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_supply += initial_balance;
        stats.peer_count = peers.len();

        true
    }

    /// Returns the balance for a peer.
    pub fn balance(&self, peer_id: &str) -> Result<TokenBalance, String> {
        let peers = self.peers.read().unwrap();
        peers
            .get(peer_id)
            .map(|state| state.balance.clone())
            .ok_or_else(|| format!("Peer {} not found", peer_id))
    }

    /// Stakes tokens for a peer.
    pub fn stake(&mut self, peer_id: &str, amount: u64) -> Result<(), String> {
        if amount < self.config.min_stake {
            return Err(format!(
                "Amount {} below minimum stake {}",
                amount, self.config.min_stake
            ));
        }

        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        if state.balance.available < amount {
            return Err("Insufficient available balance".to_string());
        }

        if state.balance.staked + amount > self.config.max_stake {
            return Err(format!(
                "Stake would exceed maximum {}",
                self.config.max_stake
            ));
        }

        // Move tokens from available to staked
        state.balance.available -= amount;
        state.balance.staked += amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Stake,
            Some(peer_id.to_string()),
            None,
            amount,
            format!("Staked {} tokens", amount),
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_staked += amount;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Unstakes tokens for a peer.
    pub fn unstake(&mut self, peer_id: &str, amount: u64) -> Result<(), String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        if state.balance.staked < amount {
            return Err("Insufficient staked balance".to_string());
        }

        // Move tokens from staked to available
        state.balance.staked -= amount;
        state.balance.available += amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Unstake,
            Some(peer_id.to_string()),
            None,
            amount,
            format!("Unstaked {} tokens", amount),
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_staked -= amount;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Rewards a peer with tokens.
    pub fn reward(&mut self, peer_id: &str, amount: u64, reason: String) -> Result<(), String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        // Add tokens to available balance
        state.balance.available += amount;
        state.balance.total += amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Reward,
            None,
            Some(peer_id.to_string()),
            amount,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_supply += amount;
        stats.total_rewards += amount;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Penalizes a peer by reducing tokens.
    pub fn penalize(&mut self, peer_id: &str, amount: u64, reason: String) -> Result<(), String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        let penalty = (amount as f64 * self.config.penalty_rate) as u64;

        if state.balance.available < penalty {
            return Err("Insufficient balance for penalty".to_string());
        }

        // Deduct tokens from available balance
        state.balance.available -= penalty;
        state.balance.total -= penalty;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Penalty,
            Some(peer_id.to_string()),
            None,
            penalty,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_supply -= penalty;
        stats.total_penalties += penalty;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Slashes staked tokens for severe violations.
    pub fn slash(&mut self, peer_id: &str, reason: String) -> Result<u64, String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        if state.balance.staked == 0 {
            return Err("No staked tokens to slash".to_string());
        }

        let slash_amount =
            (state.balance.staked as f64 * self.config.slash_percentage as f64 / 100.0) as u64;

        // Remove tokens from staked and total
        state.balance.staked -= slash_amount;
        state.balance.total -= slash_amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Slash,
            Some(peer_id.to_string()),
            None,
            slash_amount,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_supply -= slash_amount;
        stats.total_staked -= slash_amount;
        stats.total_slashed += slash_amount;
        stats.transaction_count += 1;

        Ok(slash_amount)
    }

    /// Transfers tokens between peers.
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
        reason: String,
    ) -> Result<(), String> {
        if from == to {
            return Err("Cannot transfer to self".to_string());
        }

        let mut peers = self.peers.write().unwrap();

        // Check sender
        {
            let from_state = peers
                .get(from)
                .ok_or_else(|| format!("Sender {} not found", from))?;

            if from_state.balance.available < amount {
                return Err("Insufficient balance for transfer".to_string());
            }
        }

        // Check receiver exists
        if !peers.contains_key(to) {
            return Err(format!("Receiver {} not found", to));
        }

        // Perform transfer
        let from_state = peers.get_mut(from).unwrap();
        from_state.balance.available -= amount;
        from_state.balance.total -= amount;

        self.record_transaction(
            &mut from_state.history,
            TokenOperation::Transfer,
            Some(from.to_string()),
            Some(to.to_string()),
            amount,
            reason.clone(),
            true,
        );

        let to_state = peers.get_mut(to).unwrap();
        to_state.balance.available += amount;
        to_state.balance.total += amount;

        self.record_transaction(
            &mut to_state.history,
            TokenOperation::Transfer,
            Some(from.to_string()),
            Some(to.to_string()),
            amount,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.transaction_count += 2; // Both sender and receiver

        Ok(())
    }

    /// Moves tokens to escrow.
    pub fn escrow(&mut self, peer_id: &str, amount: u64, reason: String) -> Result<(), String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        if state.balance.available < amount {
            return Err("Insufficient available balance".to_string());
        }

        // Move tokens from available to escrow
        state.balance.available -= amount;
        state.balance.escrowed += amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Escrow,
            Some(peer_id.to_string()),
            None,
            amount,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_escrowed += amount;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Releases tokens from escrow.
    pub fn release(&mut self, peer_id: &str, amount: u64, reason: String) -> Result<(), String> {
        let mut peers = self.peers.write().unwrap();
        let state = peers
            .get_mut(peer_id)
            .ok_or_else(|| format!("Peer {} not found", peer_id))?;

        if state.balance.escrowed < amount {
            return Err("Insufficient escrowed balance".to_string());
        }

        // Move tokens from escrow to available
        state.balance.escrowed -= amount;
        state.balance.available += amount;

        // Record transaction
        self.record_transaction(
            &mut state.history,
            TokenOperation::Release,
            Some(peer_id.to_string()),
            None,
            amount,
            reason,
            true,
        );

        // Update stats
        let mut stats = self.stats.write().unwrap();
        stats.total_escrowed -= amount;
        stats.transaction_count += 1;

        Ok(())
    }

    /// Returns transaction history for a peer.
    pub fn history(&self, peer_id: &str) -> Result<Vec<TokenTransaction>, String> {
        let peers = self.peers.read().unwrap();
        peers
            .get(peer_id)
            .map(|state| state.history.clone())
            .ok_or_else(|| format!("Peer {} not found", peer_id))
    }

    /// Returns current statistics.
    pub fn stats(&self) -> TokenStats {
        self.stats.read().unwrap().clone()
    }

    /// Returns all peer balances.
    pub fn all_balances(&self) -> HashMap<String, TokenBalance> {
        let peers = self.peers.read().unwrap();
        peers
            .iter()
            .map(|(id, state)| (id.clone(), state.balance.clone()))
            .collect()
    }

    /// Calculates reward amount for bandwidth provided.
    pub fn calculate_reward(&self, bytes_provided: u64) -> u64 {
        let gb = bytes_provided as f64 / (1024.0 * 1024.0 * 1024.0);
        (gb * self.config.reward_per_gb as f64) as u64
    }

    #[allow(clippy::too_many_arguments)]
    fn record_transaction(
        &self,
        history: &mut Vec<TokenTransaction>,
        operation: TokenOperation,
        from: Option<String>,
        to: Option<String>,
        amount: u64,
        reason: String,
        success: bool,
    ) {
        if !self.config.enable_history {
            return;
        }

        let mut tx_counter = self.tx_counter.write().unwrap();
        *tx_counter += 1;

        let tx = TokenTransaction {
            tx_id: format!("tx_{}", *tx_counter),
            operation,
            from,
            to,
            amount,
            reason,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            success,
        };

        history.push(tx);

        // Limit history size
        if history.len() > self.config.max_history_size {
            history.remove(0);
        }
    }

    /// Returns configuration.
    pub fn config(&self) -> &TokenConfig {
        &self.config
    }

    /// Updates configuration (does not affect existing balances).
    pub fn update_config(&mut self, config: TokenConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_system() -> BandwidthTokenSystem {
        let config = TokenConfig::default();
        BandwidthTokenSystem::new(config)
    }

    #[test]
    fn test_new_system() {
        let system = create_test_system();
        let stats = system.stats();
        assert_eq!(stats.total_supply, 0);
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn test_register_peer() {
        let mut system = create_test_system();
        let peer_id = "peer1";

        assert!(system.register_peer(peer_id, 1000));

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.total, 1000);
        assert_eq!(balance.available, 1000);
        assert_eq!(balance.staked, 0);
        assert_eq!(balance.escrowed, 0);

        let stats = system.stats();
        assert_eq!(stats.total_supply, 1000);
        assert_eq!(stats.peer_count, 1);
    }

    #[test]
    fn test_register_duplicate_peer() {
        let mut system = create_test_system();
        let peer_id = "peer1";

        assert!(system.register_peer(peer_id, 1000));
        assert!(!system.register_peer(peer_id, 1000)); // Duplicate
    }

    #[test]
    fn test_stake_tokens() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        system.stake(peer_id, 200).unwrap();

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.total, 1000);
        assert_eq!(balance.available, 800);
        assert_eq!(balance.staked, 200);

        let stats = system.stats();
        assert_eq!(stats.total_staked, 200);
    }

    #[test]
    fn test_stake_insufficient_balance() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 100);

        let result = system.stake(peer_id, 200);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
    }

    #[test]
    fn test_stake_below_minimum() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        let result = system.stake(peer_id, 50); // Below min_stake of 100
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
    }

    #[test]
    fn test_unstake_tokens() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);
        system.stake(peer_id, 200).unwrap();

        system.unstake(peer_id, 100).unwrap();

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.available, 900);
        assert_eq!(balance.staked, 100);

        let stats = system.stats();
        assert_eq!(stats.total_staked, 100);
    }

    #[test]
    fn test_unstake_insufficient_stake() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);
        system.stake(peer_id, 100).unwrap();

        let result = system.unstake(peer_id, 200);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient staked"));
    }

    #[test]
    fn test_reward_peer() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        system
            .reward(peer_id, 50, "Good service".to_string())
            .unwrap();

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.total, 1050);
        assert_eq!(balance.available, 1050);

        let stats = system.stats();
        assert_eq!(stats.total_supply, 1050);
        assert_eq!(stats.total_rewards, 50);
    }

    #[test]
    fn test_penalize_peer() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        system
            .penalize(peer_id, 100, "Poor service".to_string())
            .unwrap();

        let penalty = (100.0 * 0.1) as u64; // penalty_rate = 0.1
        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.total, 1000 - penalty);
        assert_eq!(balance.available, 1000 - penalty);

        let stats = system.stats();
        assert_eq!(stats.total_penalties, penalty);
    }

    #[test]
    fn test_slash_stake() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);
        system.stake(peer_id, 200).unwrap();

        let slashed = system.slash(peer_id, "Violation".to_string()).unwrap();

        assert_eq!(slashed, 100); // 50% of 200

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.staked, 100);
        assert_eq!(balance.total, 900);

        let stats = system.stats();
        assert_eq!(stats.total_slashed, 100);
    }

    #[test]
    fn test_transfer_tokens() {
        let mut system = create_test_system();
        system.register_peer("peer1", 1000);
        system.register_peer("peer2", 500);

        system
            .transfer("peer1", "peer2", 200, "Payment".to_string())
            .unwrap();

        let balance1 = system.balance("peer1").unwrap();
        assert_eq!(balance1.total, 800);
        assert_eq!(balance1.available, 800);

        let balance2 = system.balance("peer2").unwrap();
        assert_eq!(balance2.total, 700);
        assert_eq!(balance2.available, 700);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let mut system = create_test_system();
        system.register_peer("peer1", 100);
        system.register_peer("peer2", 500);

        let result = system.transfer("peer1", "peer2", 200, "Payment".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient balance"));
    }

    #[test]
    fn test_transfer_to_self() {
        let mut system = create_test_system();
        system.register_peer("peer1", 1000);

        let result = system.transfer("peer1", "peer1", 200, "Self".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot transfer to self"));
    }

    #[test]
    fn test_escrow_tokens() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        system
            .escrow(peer_id, 300, "Pending transaction".to_string())
            .unwrap();

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.available, 700);
        assert_eq!(balance.escrowed, 300);

        let stats = system.stats();
        assert_eq!(stats.total_escrowed, 300);
    }

    #[test]
    fn test_release_from_escrow() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);
        system.escrow(peer_id, 300, "Pending".to_string()).unwrap();

        system
            .release(peer_id, 150, "Completed".to_string())
            .unwrap();

        let balance = system.balance(peer_id).unwrap();
        assert_eq!(balance.available, 850);
        assert_eq!(balance.escrowed, 150);

        let stats = system.stats();
        assert_eq!(stats.total_escrowed, 150);
    }

    #[test]
    fn test_transaction_history() {
        let mut system = create_test_system();
        let peer_id = "peer1";
        system.register_peer(peer_id, 1000);

        system.stake(peer_id, 200).unwrap();
        system.reward(peer_id, 50, "Good".to_string()).unwrap();

        let history = system.history(peer_id).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].operation, TokenOperation::Stake);
        assert_eq!(history[1].operation, TokenOperation::Reward);
    }

    #[test]
    fn test_calculate_reward() {
        let system = create_test_system();

        let gb = 1024 * 1024 * 1024; // 1 GB
        let reward = system.calculate_reward(gb);
        assert_eq!(reward, 10); // reward_per_gb = 10

        let reward_5gb = system.calculate_reward(gb * 5);
        assert_eq!(reward_5gb, 50);
    }

    #[test]
    fn test_all_balances() {
        let mut system = create_test_system();
        system.register_peer("peer1", 1000);
        system.register_peer("peer2", 500);

        let balances = system.all_balances();
        assert_eq!(balances.len(), 2);
        assert_eq!(balances.get("peer1").unwrap().total, 1000);
        assert_eq!(balances.get("peer2").unwrap().total, 500);
    }

    #[test]
    fn test_config_update() {
        let mut system = create_test_system();

        let new_config = TokenConfig {
            reward_per_gb: 20,
            ..Default::default()
        };

        system.update_config(new_config);
        assert_eq!(system.config().reward_per_gb, 20);
    }

    #[test]
    fn test_stats_tracking() {
        let mut system = create_test_system();
        system.register_peer("peer1", 1000);
        system.register_peer("peer2", 1000);

        system.stake("peer1", 200).unwrap();
        system.reward("peer2", 100, "Good".to_string()).unwrap();
        system.escrow("peer1", 100, "Pending".to_string()).unwrap();

        let stats = system.stats();
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.total_supply, 2100); // 2000 initial + 100 reward
        assert_eq!(stats.total_staked, 200);
        assert_eq!(stats.total_escrowed, 100);
        assert_eq!(stats.total_rewards, 100);
        assert!(stats.transaction_count >= 3);
    }
}
