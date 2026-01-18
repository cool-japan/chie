//! Rate limit quota purchase and management system.
//!
//! This module provides:
//! - Purchase additional rate limit quotas
//! - Quota tracking and usage monitoring
//! - Quota expiration and renewal
//! - Integration with payment system
//! - Per-user and per-API-key quota management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// Quota tier for rate limit purchases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaTier {
    /// Basic tier: +1,000 requests/hour.
    Basic,
    /// Standard tier: +5,000 requests/hour.
    Standard,
    /// Premium tier: +20,000 requests/hour.
    Premium,
    /// Enterprise tier: +100,000 requests/hour.
    Enterprise,
}

impl QuotaTier {
    /// Get the additional requests per hour for this tier.
    pub fn requests_per_hour(&self) -> u64 {
        match self {
            Self::Basic => 1_000,
            Self::Standard => 5_000,
            Self::Premium => 20_000,
            Self::Enterprise => 100_000,
        }
    }

    /// Get the price in cents for this tier (monthly).
    pub fn price_cents(&self) -> u64 {
        match self {
            Self::Basic => 500,         // $5/month
            Self::Standard => 2_000,    // $20/month
            Self::Premium => 7_500,     // $75/month
            Self::Enterprise => 30_000, // $300/month
        }
    }

    /// Get the duration in days for this tier.
    pub fn duration_days(&self) -> i64 {
        30 // All tiers are monthly by default
    }

    /// Get a description of this tier.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Basic => "Basic quota: +1,000 requests/hour",
            Self::Standard => "Standard quota: +5,000 requests/hour",
            Self::Premium => "Premium quota: +20,000 requests/hour",
            Self::Enterprise => "Enterprise quota: +100,000 requests/hour",
        }
    }
}

/// Status of a quota purchase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaStatus {
    /// Pending payment.
    Pending,
    /// Active and usable.
    Active,
    /// Expired.
    Expired,
    /// Cancelled/refunded.
    Cancelled,
}

/// A quota purchase record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaPurchase {
    /// Unique purchase ID.
    pub id: Uuid,
    /// User ID who purchased the quota.
    pub user_id: Uuid,
    /// Quota tier purchased.
    pub tier: QuotaTier,
    /// Purchase status.
    pub status: QuotaStatus,
    /// Price paid in cents.
    pub price_cents: u64,
    /// When the quota was purchased.
    pub purchased_at: DateTime<Utc>,
    /// When the quota becomes active.
    pub starts_at: DateTime<Utc>,
    /// When the quota expires.
    pub expires_at: DateTime<Utc>,
    /// Whether this quota auto-renews.
    pub auto_renew: bool,
    /// Payment transaction ID (if applicable).
    pub payment_id: Option<Uuid>,
}

/// Aggregated quota information for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuotaInfo {
    /// User ID.
    pub user_id: Uuid,
    /// Base rate limit (requests per hour).
    pub base_limit: u64,
    /// Additional quota from purchases (requests per hour).
    pub additional_quota: u64,
    /// Total effective limit.
    pub total_limit: u64,
    /// Active quota purchases.
    pub active_purchases: Vec<QuotaPurchase>,
    /// Current usage (requests in current hour).
    pub current_usage: u64,
    /// Usage percentage.
    pub usage_percentage: f64,
}

/// Configuration for quota purchase system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    /// Base rate limit for all users (requests per hour).
    pub base_rate_limit: u64,
    /// Whether quota purchases are enabled.
    pub enabled: bool,
    /// Maximum active quotas per user.
    pub max_quotas_per_user: usize,
    /// Whether to allow auto-renewal.
    pub allow_auto_renew: bool,
    /// Grace period after expiration (hours).
    pub grace_period_hours: i64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            base_rate_limit: 1000, // 1000 requests/hour default
            enabled: true,
            max_quotas_per_user: 5,
            allow_auto_renew: true,
            grace_period_hours: 24,
        }
    }
}

/// Statistics for quota purchases.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaStats {
    /// Total quota purchases.
    pub total_purchases: u64,
    /// Active quotas.
    pub active_quotas: u64,
    /// Expired quotas.
    pub expired_quotas: u64,
    /// Total revenue in cents.
    pub total_revenue_cents: u64,
    /// Purchases by tier.
    pub by_tier: HashMap<String, u64>,
    /// Auto-renewal count.
    pub auto_renewals: u64,
}

/// Quota purchase manager.
pub struct QuotaManager {
    /// Configuration.
    config: Arc<RwLock<QuotaConfig>>,
    /// Quota purchases (user_id -> purchases).
    purchases: Arc<RwLock<HashMap<Uuid, Vec<QuotaPurchase>>>>,
    /// Statistics.
    stats: Arc<RwLock<QuotaStats>>,
}

impl QuotaManager {
    /// Create a new quota manager.
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            purchases: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(QuotaStats::default())),
        }
    }

    /// Purchase a quota for a user.
    pub async fn purchase_quota(
        &self,
        user_id: Uuid,
        tier: QuotaTier,
        auto_renew: bool,
        payment_id: Option<Uuid>,
    ) -> Result<QuotaPurchase, String> {
        let config = self.config.read().await;

        if !config.enabled {
            return Err("Quota purchases are disabled".to_string());
        }

        // Check max quotas per user
        let purchases = self.purchases.read().await;
        let user_quotas = purchases.get(&user_id).map(|v| v.len()).unwrap_or(0);
        if user_quotas >= config.max_quotas_per_user {
            return Err(format!(
                "Maximum {} active quotas per user reached",
                config.max_quotas_per_user
            ));
        }

        if auto_renew && !config.allow_auto_renew {
            return Err("Auto-renewal is not allowed".to_string());
        }
        drop(purchases);
        drop(config);

        let now = Utc::now();
        let duration_days = tier.duration_days();

        let purchase = QuotaPurchase {
            id: Uuid::new_v4(),
            user_id,
            tier,
            status: if payment_id.is_some() {
                QuotaStatus::Active
            } else {
                QuotaStatus::Pending
            },
            price_cents: tier.price_cents(),
            purchased_at: now,
            starts_at: now,
            expires_at: now + chrono::Duration::days(duration_days),
            auto_renew,
            payment_id,
        };

        // Store purchase
        let mut purchases = self.purchases.write().await;
        purchases.entry(user_id).or_default().push(purchase.clone());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_purchases += 1;
        if purchase.status == QuotaStatus::Active {
            stats.active_quotas += 1;
            stats.total_revenue_cents += purchase.price_cents;
        }
        *stats.by_tier.entry(format!("{:?}", tier)).or_insert(0) += 1;

        info!(
            "Quota purchased: user={}, tier={:?}, id={}",
            user_id, tier, purchase.id
        );

        // Record metrics
        crate::metrics::record_quota_purchased(&format!("{:?}", tier), purchase.price_cents);

        Ok(purchase)
    }

    /// Activate a pending quota (after payment confirmation).
    pub async fn activate_quota(&self, purchase_id: Uuid) -> Result<(), String> {
        let mut purchases = self.purchases.write().await;

        for user_purchases in purchases.values_mut() {
            if let Some(purchase) = user_purchases.iter_mut().find(|p| p.id == purchase_id) {
                if purchase.status != QuotaStatus::Pending {
                    return Err(format!("Quota is not pending: {:?}", purchase.status));
                }

                purchase.status = QuotaStatus::Active;

                // Update stats
                let mut stats = self.stats.write().await;
                stats.active_quotas += 1;
                stats.total_revenue_cents += purchase.price_cents;

                info!("Quota activated: {}", purchase_id);
                return Ok(());
            }
        }

        Err("Purchase not found".to_string())
    }

    /// Cancel a quota purchase.
    pub async fn cancel_quota(&self, purchase_id: Uuid) -> Result<(), String> {
        let mut purchases = self.purchases.write().await;

        for user_purchases in purchases.values_mut() {
            if let Some(purchase) = user_purchases.iter_mut().find(|p| p.id == purchase_id) {
                let was_active = purchase.status == QuotaStatus::Active;
                purchase.status = QuotaStatus::Cancelled;

                if was_active {
                    let mut stats = self.stats.write().await;
                    stats.active_quotas = stats.active_quotas.saturating_sub(1);
                }

                info!("Quota cancelled: {}", purchase_id);
                return Ok(());
            }
        }

        Err("Purchase not found".to_string())
    }

    /// Get quota information for a user.
    pub async fn get_user_quota(&self, user_id: Uuid) -> UserQuotaInfo {
        let config = self.config.read().await;
        let base_limit = config.base_rate_limit;
        drop(config);

        let purchases = self.purchases.read().await;
        let user_purchases = purchases.get(&user_id).cloned().unwrap_or_default();

        // Calculate active quota
        let now = Utc::now();
        let active_purchases: Vec<QuotaPurchase> = user_purchases
            .into_iter()
            .filter(|p| p.status == QuotaStatus::Active && p.expires_at > now)
            .collect();

        let additional_quota: u64 = active_purchases
            .iter()
            .map(|p| p.tier.requests_per_hour())
            .sum();

        let total_limit = base_limit + additional_quota;

        UserQuotaInfo {
            user_id,
            base_limit,
            additional_quota,
            total_limit,
            active_purchases,
            current_usage: 0, // Would be populated from actual rate limiter
            usage_percentage: 0.0,
        }
    }

    /// Get all purchases for a user.
    pub async fn get_user_purchases(&self, user_id: Uuid) -> Vec<QuotaPurchase> {
        let purchases = self.purchases.read().await;
        purchases.get(&user_id).cloned().unwrap_or_default()
    }

    /// Get a specific purchase by ID.
    pub async fn get_purchase(&self, purchase_id: Uuid) -> Option<QuotaPurchase> {
        let purchases = self.purchases.read().await;
        for user_purchases in purchases.values() {
            if let Some(purchase) = user_purchases.iter().find(|p| p.id == purchase_id) {
                return Some(purchase.clone());
            }
        }
        None
    }

    /// Expire old quotas and handle auto-renewal.
    pub async fn expire_quotas(&self) -> usize {
        let now = Utc::now();
        let mut purchases = self.purchases.write().await;
        let mut expired_count = 0;
        let mut renewed_count = 0;

        for user_purchases in purchases.values_mut() {
            for purchase in user_purchases.iter_mut() {
                if purchase.status == QuotaStatus::Active && purchase.expires_at <= now {
                    if purchase.auto_renew {
                        // Auto-renew the quota
                        purchase.starts_at = purchase.expires_at;
                        purchase.expires_at +=
                            chrono::Duration::days(purchase.tier.duration_days());
                        renewed_count += 1;

                        info!("Quota auto-renewed: {}", purchase.id);
                    } else {
                        purchase.status = QuotaStatus::Expired;
                        expired_count += 1;

                        debug!("Quota expired: {}", purchase.id);
                    }
                }
            }
        }

        // Update stats
        if expired_count > 0 || renewed_count > 0 {
            let mut stats = self.stats.write().await;
            stats.expired_quotas += expired_count as u64;
            stats.active_quotas = stats.active_quotas.saturating_sub(expired_count as u64);
            stats.auto_renewals += renewed_count as u64;
        }

        // Record metrics
        if expired_count > 0 {
            info!("Expired {} quotas", expired_count);
            crate::metrics::record_quota_expired(expired_count as u64);
        }
        if renewed_count > 0 {
            info!("Auto-renewed {} quotas", renewed_count);
            crate::metrics::record_quota_auto_renewed(renewed_count as u64);
        }

        expired_count + renewed_count
    }

    /// Get quota statistics.
    pub async fn get_stats(&self) -> QuotaStats {
        self.stats.read().await.clone()
    }

    /// Get all active quotas.
    pub async fn get_active_quotas(&self) -> Vec<QuotaPurchase> {
        let now = Utc::now();
        let purchases = self.purchases.read().await;

        purchases
            .values()
            .flat_map(|v| v.iter())
            .filter(|p| p.status == QuotaStatus::Active && p.expires_at > now)
            .cloned()
            .collect()
    }

    /// Update configuration.
    pub async fn update_config(&self, new_config: QuotaConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        debug!("Quota configuration updated");
    }

    /// Get current configuration.
    pub async fn get_config(&self) -> QuotaConfig {
        self.config.read().await.clone()
    }

    /// Get available tiers with pricing.
    pub fn get_available_tiers() -> Vec<(QuotaTier, u64, u64, &'static str)> {
        vec![
            (
                QuotaTier::Basic,
                QuotaTier::Basic.requests_per_hour(),
                QuotaTier::Basic.price_cents(),
                QuotaTier::Basic.description(),
            ),
            (
                QuotaTier::Standard,
                QuotaTier::Standard.requests_per_hour(),
                QuotaTier::Standard.price_cents(),
                QuotaTier::Standard.description(),
            ),
            (
                QuotaTier::Premium,
                QuotaTier::Premium.requests_per_hour(),
                QuotaTier::Premium.price_cents(),
                QuotaTier::Premium.description(),
            ),
            (
                QuotaTier::Enterprise,
                QuotaTier::Enterprise.requests_per_hour(),
                QuotaTier::Enterprise.price_cents(),
                QuotaTier::Enterprise.description(),
            ),
        ]
    }
}

impl Clone for QuotaManager {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            purchases: Arc::clone(&self.purchases),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_tier_requests() {
        assert_eq!(QuotaTier::Basic.requests_per_hour(), 1_000);
        assert_eq!(QuotaTier::Standard.requests_per_hour(), 5_000);
        assert_eq!(QuotaTier::Premium.requests_per_hour(), 20_000);
        assert_eq!(QuotaTier::Enterprise.requests_per_hour(), 100_000);
    }

    #[test]
    fn test_quota_tier_pricing() {
        assert_eq!(QuotaTier::Basic.price_cents(), 500);
        assert_eq!(QuotaTier::Standard.price_cents(), 2_000);
        assert_eq!(QuotaTier::Premium.price_cents(), 7_500);
        assert_eq!(QuotaTier::Enterprise.price_cents(), 30_000);
    }

    #[tokio::test]
    async fn test_quota_manager_creation() {
        let manager = QuotaManager::new(QuotaConfig::default());
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_purchases, 0);
        assert_eq!(stats.active_quotas, 0);
    }

    #[tokio::test]
    async fn test_purchase_quota() {
        let manager = QuotaManager::new(QuotaConfig::default());
        let user_id = Uuid::new_v4();

        let purchase = manager
            .purchase_quota(user_id, QuotaTier::Basic, false, Some(Uuid::new_v4()))
            .await
            .unwrap();

        assert_eq!(purchase.user_id, user_id);
        assert_eq!(purchase.tier, QuotaTier::Basic);
        assert_eq!(purchase.status, QuotaStatus::Active);
        assert_eq!(purchase.price_cents, 500);
    }

    #[tokio::test]
    async fn test_get_user_quota() {
        let manager = QuotaManager::new(QuotaConfig::default());
        let user_id = Uuid::new_v4();

        // Purchase two quotas
        manager
            .purchase_quota(user_id, QuotaTier::Basic, false, Some(Uuid::new_v4()))
            .await
            .unwrap();
        manager
            .purchase_quota(user_id, QuotaTier::Standard, false, Some(Uuid::new_v4()))
            .await
            .unwrap();

        let quota_info = manager.get_user_quota(user_id).await;
        assert_eq!(quota_info.base_limit, 1000);
        assert_eq!(quota_info.additional_quota, 6_000); // 1000 + 5000
        assert_eq!(quota_info.total_limit, 7_000);
        assert_eq!(quota_info.active_purchases.len(), 2);
    }

    #[tokio::test]
    async fn test_max_quotas_per_user() {
        let config = QuotaConfig {
            max_quotas_per_user: 2,
            ..QuotaConfig::default()
        };
        let manager = QuotaManager::new(config);
        let user_id = Uuid::new_v4();

        // Purchase max quotas
        manager
            .purchase_quota(user_id, QuotaTier::Basic, false, Some(Uuid::new_v4()))
            .await
            .unwrap();
        manager
            .purchase_quota(user_id, QuotaTier::Standard, false, Some(Uuid::new_v4()))
            .await
            .unwrap();

        // Third purchase should fail
        let result = manager
            .purchase_quota(user_id, QuotaTier::Premium, false, Some(Uuid::new_v4()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cancel_quota() {
        let manager = QuotaManager::new(QuotaConfig::default());
        let user_id = Uuid::new_v4();

        let purchase = manager
            .purchase_quota(user_id, QuotaTier::Basic, false, Some(Uuid::new_v4()))
            .await
            .unwrap();

        manager.cancel_quota(purchase.id).await.unwrap();

        let updated = manager.get_purchase(purchase.id).await.unwrap();
        assert_eq!(updated.status, QuotaStatus::Cancelled);
    }
}
