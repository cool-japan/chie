//! Reward calculation engine.
//!
//! Implements dynamic pricing based on supply/demand and referral rewards.
//! Formula: base_reward * demand_multiplier * quality_factor
//!
//! - Higher demand = higher rewards (incentivize serving popular content)
//! - Lower supply = higher rewards (incentivize becoming a seeder)
//! - Better latency = higher rewards (incentivize quality service)

mod inner {
    use crate::db::{
        AnalyticsRepository, DbPool, ProofRepository, TransactionRepository, TransactionType,
        UserRepository,
    };
    use chie_shared::{BandwidthProof, Points, RewardDistribution, RewardError};
    use std::sync::Arc;
    use tracing::{debug, info};
    use uuid::Uuid;

    /// Configuration for reward calculation.
    #[derive(Debug, Clone)]
    pub struct RewardConfig {
        /// Base reward per GB transferred (in points).
        pub base_reward_per_gb: Points,
        /// Maximum demand multiplier.
        pub max_demand_multiplier: f64,
        /// Minimum demand multiplier (floor).
        pub min_demand_multiplier: f64,
        /// Latency threshold for full reward (ms).
        pub optimal_latency_ms: u32,
        /// Latency beyond which penalty applies.
        pub penalty_latency_ms: u32,
        /// Maximum latency penalty (as factor).
        pub max_latency_penalty: f64,
        /// Creator share of bandwidth rewards (0.0 to 1.0).
        pub creator_share: f64,
        /// Platform fee share (0.0 to 1.0).
        pub platform_fee_share: f64,
        /// Referral reward tiers (tier 1, tier 2, tier 3).
        pub referral_tiers: [f64; 3],
    }

    impl Default for RewardConfig {
        fn default() -> Self {
            Self {
                base_reward_per_gb: 10,
                max_demand_multiplier: 3.0,
                min_demand_multiplier: 0.5,
                optimal_latency_ms: 100,
                penalty_latency_ms: 500,
                max_latency_penalty: 0.5,
                creator_share: 0.1,                 // 10% to creator
                platform_fee_share: 0.1,            // 10% platform fee
                referral_tiers: [0.05, 0.02, 0.01], // 5%, 2%, 1%
            }
        }
    }

    /// Reward calculation engine.
    pub struct RewardEngine {
        pool: Arc<DbPool>,
        config: RewardConfig,
    }

    impl RewardEngine {
        /// Create a new reward engine.
        pub fn new(pool: Arc<DbPool>, config: RewardConfig) -> Self {
            Self { pool, config }
        }

        /// Calculate and distribute rewards for a verified proof.
        pub async fn calculate_and_distribute(
            &self,
            proof: &BandwidthProof,
            proof_id: Uuid,
            quality_score: f64,
            provider_user_id: Uuid,
            content_creator_id: Uuid,
        ) -> Result<RewardDistribution, RewardError> {
            // Step 1: Calculate base reward
            let bytes_gb = proof.bytes_transferred as f64 / (1024.0 * 1024.0 * 1024.0);
            let base_reward = (bytes_gb * self.config.base_reward_per_gb as f64) as Points;

            // Step 2: Get demand/supply multiplier
            let content_id = self
                .lookup_content_id(&proof.content_cid)
                .await
                .map_err(|e| {
                    RewardError::CalculationFailed(format!("Content lookup failed: {}", e))
                })?;

            let (demand, supply) = AnalyticsRepository::get_content_demand(&self.pool, content_id)
                .await
                .unwrap_or((1, 1));

            let demand_ratio = (demand.max(1) as f64) / (supply.max(1) as f64);
            let demand_multiplier = demand_ratio
                .sqrt()
                .min(self.config.max_demand_multiplier)
                .max(self.config.min_demand_multiplier);

            // Step 3: Calculate latency factor
            let latency_factor = self.calculate_latency_factor(proof.latency_ms);

            // Step 4: Calculate total reward
            let total_reward =
                (base_reward as f64 * demand_multiplier * latency_factor * quality_score) as Points;
            let total_reward = total_reward.max(1); // Minimum 1 point

            // Step 5: Calculate distribution
            let platform_fee = (total_reward as f64 * self.config.platform_fee_share) as Points;
            let creator_reward = (total_reward as f64 * self.config.creator_share) as Points;
            let provider_gross = total_reward - platform_fee - creator_reward;

            // Step 6: Calculate referral rewards
            let referrer_chain = UserRepository::get_referral_chain(&self.pool, provider_user_id)
                .await
                .unwrap_or_default();

            let mut referrer_rewards = Vec::new();
            let mut total_referral = 0_u64;

            for (referrer_id, tier) in referrer_chain.iter() {
                let tier_idx = (*tier as usize).saturating_sub(1).min(2);
                let reward =
                    (provider_gross as f64 * self.config.referral_tiers[tier_idx]) as Points;
                if reward > 0 {
                    referrer_rewards.push((*referrer_id, reward));
                    total_referral += reward;
                }
            }

            let provider_reward = provider_gross - total_referral;

            // Step 7: Record transactions
            self.distribute_rewards(
                proof_id,
                provider_user_id,
                provider_reward,
                content_creator_id,
                creator_reward,
                &referrer_rewards,
                Some(content_id),
            )
            .await?;

            // Step 8: Update proof with reward amount
            ProofRepository::record_reward(&self.pool, proof_id, total_reward as i64)
                .await
                .map_err(|e| RewardError::CalculationFailed(format!("DB error: {}", e)))?;

            info!(
                "Distributed {} points: provider={}, creator={}, referrals={}, platform={}",
                total_reward, provider_reward, creator_reward, total_referral, platform_fee
            );

            // Suppress unused warning for debug macro
            debug!("Reward calculation completed for proof {}", proof_id);

            Ok(RewardDistribution {
                proof_id,
                provider_reward,
                creator_reward,
                referrer_rewards,
                platform_fee,
                total_distributed: total_reward,
            })
        }

        /// Calculate latency quality factor.
        fn calculate_latency_factor(&self, latency_ms: u32) -> f64 {
            if latency_ms <= self.config.optimal_latency_ms {
                1.0
            } else if latency_ms >= self.config.penalty_latency_ms {
                self.config.max_latency_penalty
            } else {
                // Linear interpolation
                let range =
                    (self.config.penalty_latency_ms - self.config.optimal_latency_ms) as f64;
                let excess = (latency_ms - self.config.optimal_latency_ms) as f64;
                1.0 - (excess / range) * (1.0 - self.config.max_latency_penalty)
            }
        }

        /// Lookup content ID by CID.
        async fn lookup_content_id(&self, cid: &str) -> Result<Uuid, anyhow::Error> {
            use crate::db::ContentRepository;
            let content = ContentRepository::find_by_cid(&self.pool, cid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Content not found"))?;
            Ok(content.id)
        }

        /// Distribute rewards to all parties.
        #[allow(clippy::too_many_arguments)]
        async fn distribute_rewards(
            &self,
            proof_id: Uuid,
            provider_id: Uuid,
            provider_amount: Points,
            creator_id: Uuid,
            creator_amount: Points,
            referrer_rewards: &[(Uuid, Points)],
            content_id: Option<Uuid>,
        ) -> Result<(), RewardError> {
            // Provider reward
            if provider_amount > 0 {
                TransactionRepository::create(
                    &self.pool,
                    provider_id,
                    provider_amount as i64,
                    TransactionType::BandwidthReward,
                    Some(proof_id),
                    content_id,
                    None,
                    Some("Bandwidth provision reward"),
                )
                .await
                .map_err(|e| RewardError::CalculationFailed(format!("DB error: {}", e)))?;
            }

            // Creator reward
            if creator_amount > 0 {
                TransactionRepository::create(
                    &self.pool,
                    creator_id,
                    creator_amount as i64,
                    TransactionType::CreatorPayout,
                    Some(proof_id),
                    content_id,
                    None,
                    Some("Creator bandwidth share"),
                )
                .await
                .map_err(|e| RewardError::CalculationFailed(format!("DB error: {}", e)))?;
            }

            // Referral rewards
            for (referrer_id, amount) in referrer_rewards {
                if *amount > 0 {
                    TransactionRepository::create(
                        &self.pool,
                        *referrer_id,
                        *amount as i64,
                        TransactionType::ReferralReward,
                        Some(proof_id),
                        content_id,
                        Some(provider_id),
                        Some("Referral reward from bandwidth"),
                    )
                    .await
                    .map_err(|e| RewardError::CalculationFailed(format!("DB error: {}", e)))?;
                }
            }

            Ok(())
        }
    }

    /// Investment recommendation engine for content pinning.
    /// NOTE: This is prepared for future use in recommending content to pin.
    #[allow(dead_code)]
    pub struct InvestmentEngine {
        pool: Arc<DbPool>,
    }

    #[allow(dead_code)]
    impl InvestmentEngine {
        pub fn new(pool: Arc<DbPool>) -> Self {
            Self { pool }
        }

        /// Get recommended content to pin based on expected returns.
        pub async fn get_recommendations(
            &self,
            available_storage_gb: f64,
            limit: usize,
        ) -> Result<Vec<ContentRecommendation>, anyhow::Error> {
            use crate::db::ContentRepository;

            // Get trending content with demand metrics
            let trending = ContentRepository::get_trending(&self.pool, limit as i32).await?;

            let mut recommendations = Vec::new();

            for content in trending {
                let (demand, supply) =
                    AnalyticsRepository::get_content_demand(&self.pool, content.id)
                        .await
                        .unwrap_or((1, 1));

                let demand_ratio = (demand.max(1) as f64) / (supply.max(1) as f64);
                let expected_revenue_per_gb = 10.0 * demand_ratio.sqrt();

                let content_size_gb = content.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

                recommendations.push(ContentRecommendation {
                    content_id: content.id,
                    cid: content.cid,
                    title: content.title,
                    size_gb: content_size_gb,
                    current_seeders: supply as u64,
                    demand_score: demand_ratio,
                    expected_revenue_per_gb,
                    recommended: content_size_gb <= available_storage_gb && demand_ratio > 1.0,
                });
            }

            // Sort by expected revenue
            recommendations.sort_by(|a, b| {
                b.expected_revenue_per_gb
                    .partial_cmp(&a.expected_revenue_per_gb)
                    .unwrap()
            });

            Ok(recommendations)
        }
    }

    /// Content pinning recommendation.
    /// NOTE: This is prepared for future use in recommending content to pin.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[allow(dead_code)]
    pub struct ContentRecommendation {
        pub content_id: Uuid,
        pub cid: String,
        pub title: String,
        pub size_gb: f64,
        pub current_seeders: u64,
        pub demand_score: f64,
        pub expected_revenue_per_gb: f64,
        pub recommended: bool,
    }
}

// Re-export types for external use
pub use inner::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_factor_optimal() {
        let config = RewardConfig::default();
        let engine_latency_factor = |latency_ms: u32| -> f64 {
            if latency_ms <= config.optimal_latency_ms {
                1.0
            } else if latency_ms >= config.penalty_latency_ms {
                config.max_latency_penalty
            } else {
                let range = (config.penalty_latency_ms - config.optimal_latency_ms) as f64;
                let excess = (latency_ms - config.optimal_latency_ms) as f64;
                1.0 - (excess / range) * (1.0 - config.max_latency_penalty)
            }
        };

        assert_eq!(engine_latency_factor(50), 1.0);
        assert_eq!(engine_latency_factor(100), 1.0);
        assert_eq!(engine_latency_factor(500), 0.5);
        assert!(engine_latency_factor(300) > 0.5 && engine_latency_factor(300) < 1.0);
    }

    #[test]
    fn test_reward_config_defaults() {
        let config = RewardConfig::default();
        assert_eq!(config.base_reward_per_gb, 10);
        assert_eq!(config.max_demand_multiplier, 3.0);
        assert_eq!(config.referral_tiers, [0.05, 0.02, 0.01]);
    }
}
