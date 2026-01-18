//! Payment and Settlement System
//!
//! Handles point-to-currency conversion, settlement batch processing,
//! escrow for disputed proofs, payout thresholds, and payment provider integration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

// ============================================================================
// Types and Enums
// ============================================================================

/// Payment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "payment_status", rename_all = "lowercase")]
pub enum PaymentStatus {
    /// Pending payment processing
    Pending,
    /// Payment is being processed
    Processing,
    /// Payment completed successfully
    Completed,
    /// Payment failed
    Failed,
    /// Payment cancelled
    Cancelled,
    /// Payment refunded
    Refunded,
}

/// Settlement status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "settlement_status", rename_all = "lowercase")]
pub enum SettlementStatus {
    /// Pending settlement
    Pending,
    /// Batched for processing
    Batched,
    /// Processing settlement
    Processing,
    /// Settlement completed
    Completed,
    /// Settlement failed
    Failed,
}

/// Escrow status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "escrow_status", rename_all = "lowercase")]
pub enum EscrowStatus {
    /// Funds held in escrow
    Held,
    /// Funds released to recipient
    Released,
    /// Funds refunded to sender
    Refunded,
    /// Escrow expired
    Expired,
}

/// Payment provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentProvider {
    /// Stripe payment provider
    Stripe,
    /// PayPal payment provider
    PayPal,
    /// Bank transfer
    BankTransfer,
    /// Cryptocurrency (Bitcoin, Ethereum, etc.)
    Crypto,
    /// Manual/Admin payout
    Manual,
}

impl std::fmt::Display for PaymentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stripe => write!(f, "stripe"),
            Self::PayPal => write!(f, "paypal"),
            Self::BankTransfer => write!(f, "bank_transfer"),
            Self::Crypto => write!(f, "crypto"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

// ============================================================================
// Data Models
// ============================================================================

/// Payment ledger entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLedgerEntry {
    /// Payment ID
    pub id: Uuid,
    /// User ID (recipient)
    pub user_id: Uuid,
    /// Points converted
    pub points: i64,
    /// Currency amount (in cents/smallest unit)
    pub amount_cents: i64,
    /// Currency code (USD, EUR, etc.)
    pub currency: String,
    /// Exchange rate used (points to currency)
    pub exchange_rate: f64,
    /// Payment provider
    pub provider: String,
    /// Provider transaction ID
    pub provider_transaction_id: Option<String>,
    /// Payment status
    pub status: PaymentStatus,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Settlement batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementBatch {
    /// Batch ID
    pub id: Uuid,
    /// Batch creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Total payments in batch
    pub payment_count: i64,
    /// Total amount in batch (cents)
    pub total_amount_cents: i64,
    /// Settlement status
    pub status: SettlementStatus,
    /// Processing started at
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Completed at
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Escrow entry for disputed bandwidth proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowEntry {
    /// Escrow ID
    pub id: Uuid,
    /// Bandwidth proof ID
    pub proof_id: Uuid,
    /// Provider user ID
    pub provider_id: Uuid,
    /// Requester user ID
    pub requester_id: Uuid,
    /// Amount held in escrow (points)
    pub amount_points: i64,
    /// Escrow status
    pub status: EscrowStatus,
    /// Reason for escrow
    pub reason: String,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Released/refunded timestamp
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Revenue split configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueSplitConfig {
    /// Platform fee percentage (0.0-1.0)
    pub platform_fee: f64,
    /// Creator share percentage (0.0-1.0)
    pub creator_share: f64,
    /// Provider share percentage (0.0-1.0)
    pub provider_share: f64,
}

impl Default for RevenueSplitConfig {
    fn default() -> Self {
        Self {
            platform_fee: 0.05,   // 5% platform fee
            creator_share: 0.70,  // 70% to content creator
            provider_share: 0.25, // 25% to bandwidth provider
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Payment system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Points to USD exchange rate
    pub points_to_usd_rate: f64,
    /// Minimum payout threshold in points
    pub min_payout_threshold_points: i64,
    /// Settlement batch interval in seconds
    pub settlement_batch_interval_secs: u64,
    /// Maximum payments per batch
    pub max_payments_per_batch: i64,
    /// Escrow hold duration in days
    pub escrow_hold_duration_days: i64,
    /// Revenue split configuration
    pub revenue_split: RevenueSplitConfig,
    /// Enabled payment providers
    pub enabled_providers: Vec<String>,
}

impl Default for PaymentConfig {
    fn default() -> Self {
        Self {
            points_to_usd_rate: 0.001,             // 1000 points = $1 USD
            min_payout_threshold_points: 10000,    // $10 minimum payout
            settlement_batch_interval_secs: 86400, // Daily batches
            max_payments_per_batch: 1000,
            escrow_hold_duration_days: 7, // 7 days escrow hold
            revenue_split: RevenueSplitConfig::default(),
            enabled_providers: vec!["stripe".to_string(), "manual".to_string()],
        }
    }
}

// ============================================================================
// Payment Manager
// ============================================================================

/// Payment manager handles all payment operations
pub struct PaymentManager {
    db: PgPool,
    config: Arc<RwLock<PaymentConfig>>,
}

impl PaymentManager {
    /// Create a new payment manager
    pub fn new(db: PgPool, config: PaymentConfig) -> Self {
        Self {
            db,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Get current configuration
    pub async fn config(&self) -> PaymentConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, config: PaymentConfig) -> Result<()> {
        *self.config.write().await = config;
        info!("Payment configuration updated");
        Ok(())
    }

    // ========================================================================
    // Payment Ledger Operations
    // ========================================================================

    /// Convert points to currency and create payment entry
    pub async fn create_payment(
        &self,
        user_id: Uuid,
        points: i64,
        provider: PaymentProvider,
    ) -> Result<PaymentLedgerEntry> {
        let config = self.config.read().await;

        // Check minimum threshold
        if points < config.min_payout_threshold_points {
            anyhow::bail!(
                "Points {} below minimum threshold {}",
                points,
                config.min_payout_threshold_points
            );
        }

        // Calculate amount in cents
        let amount_cents = (points as f64 * config.points_to_usd_rate * 100.0) as i64;
        let exchange_rate = config.points_to_usd_rate;
        let provider_str = provider.to_string();

        drop(config);

        let row = sqlx::query(
            r#"
            INSERT INTO payment_ledger
                (user_id, points, amount_cents, currency, exchange_rate, provider, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING
                id, user_id, points, amount_cents, currency, exchange_rate, provider,
                provider_transaction_id, status, error_message, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(points)
        .bind(amount_cents)
        .bind("USD")
        .bind(exchange_rate)
        .bind(provider_str.clone())
        .bind(PaymentStatus::Pending)
        .fetch_one(&self.db)
        .await
        .context("Failed to create payment entry")?;

        let entry = PaymentLedgerEntry {
            id: row.get("id"),
            user_id: row.get("user_id"),
            points: row.get("points"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            exchange_rate: row.get("exchange_rate"),
            provider: row.get("provider"),
            provider_transaction_id: row.get("provider_transaction_id"),
            status: row.get("status"),
            error_message: row.get("error_message"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        info!(
            "Created payment entry {} for user {} ({} points = ${:.2})",
            entry.id,
            user_id,
            points,
            amount_cents as f64 / 100.0
        );

        crate::metrics::record_payment_created(provider_str.as_str(), amount_cents);

        Ok(entry)
    }

    /// Update payment status
    pub async fn update_payment_status(
        &self,
        payment_id: Uuid,
        status: PaymentStatus,
        provider_transaction_id: Option<String>,
        error_message: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE payment_ledger
            SET status = $1,
                provider_transaction_id = $2,
                error_message = $3,
                updated_at = NOW()
            WHERE id = $4
            "#,
        )
        .bind(status)
        .bind(provider_transaction_id)
        .bind(error_message)
        .bind(payment_id)
        .execute(&self.db)
        .await
        .context("Failed to update payment status")?;

        debug!("Updated payment {} status to {:?}", payment_id, status);

        if status == PaymentStatus::Completed {
            crate::metrics::record_payment_completed();
        } else if status == PaymentStatus::Failed {
            crate::metrics::record_payment_failed();
        }

        Ok(())
    }

    /// Get payment by ID
    pub async fn get_payment(&self, payment_id: Uuid) -> Result<Option<PaymentLedgerEntry>> {
        let entry = sqlx::query(
            r#"
            SELECT
                id, user_id, points, amount_cents, currency, exchange_rate, provider,
                provider_transaction_id, status, error_message, created_at, updated_at
            FROM payment_ledger
            WHERE id = $1
            "#,
        )
        .bind(payment_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch payment")?
        .map(|row| PaymentLedgerEntry {
            id: row.get("id"),
            user_id: row.get("user_id"),
            points: row.get("points"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            exchange_rate: row.get("exchange_rate"),
            provider: row.get("provider"),
            provider_transaction_id: row.get("provider_transaction_id"),
            status: row.get("status"),
            error_message: row.get("error_message"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        });

        Ok(entry)
    }

    /// Get all payments for a user
    pub async fn get_user_payments(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PaymentLedgerEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, user_id, points, amount_cents, currency, exchange_rate, provider,
                provider_transaction_id, status, error_message, created_at, updated_at
            FROM payment_ledger
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch user payments")?;

        let entries = rows
            .into_iter()
            .map(|row| PaymentLedgerEntry {
                id: row.get("id"),
                user_id: row.get("user_id"),
                points: row.get("points"),
                amount_cents: row.get("amount_cents"),
                currency: row.get("currency"),
                exchange_rate: row.get("exchange_rate"),
                provider: row.get("provider"),
                provider_transaction_id: row.get("provider_transaction_id"),
                status: row.get("status"),
                error_message: row.get("error_message"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect();

        Ok(entries)
    }

    /// Get user's total pending points
    pub async fn get_user_pending_points(&self, user_id: Uuid) -> Result<i64> {
        let row = sqlx::query(
            r#"
            SELECT COALESCE(SUM(points), 0)::BIGINT as total
            FROM payment_ledger
            WHERE user_id = $1 AND status = $2
            "#,
        )
        .bind(user_id)
        .bind(PaymentStatus::Pending)
        .fetch_one(&self.db)
        .await
        .context("Failed to fetch pending points")?;

        Ok(row.get::<i64, _>("total"))
    }

    // ========================================================================
    // Settlement Batch Processing
    // ========================================================================

    /// Create a new settlement batch from pending payments
    pub async fn create_settlement_batch(&self) -> Result<Option<SettlementBatch>> {
        let config = self.config.read().await;
        let _max_payments = config.max_payments_per_batch;
        drop(config);

        // Count pending payments
        let count_result = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM payment_ledger
            WHERE status = $1
            "#,
        )
        .bind(PaymentStatus::Pending)
        .fetch_one(&self.db)
        .await
        .context("Failed to count pending payments")?;

        let pending_count: i64 = count_result.get::<Option<i64>, _>("count").unwrap_or(0);

        if pending_count == 0 {
            debug!("No pending payments to batch");
            return Ok(None);
        }

        // Create batch
        let row = sqlx::query(
            r#"
            INSERT INTO settlement_batches (payment_count, total_amount_cents, status)
            VALUES (0, 0, $1)
            RETURNING
                id, created_at, payment_count, total_amount_cents,
                status, started_at, completed_at
            "#,
        )
        .bind(SettlementStatus::Pending)
        .fetch_one(&self.db)
        .await
        .context("Failed to create settlement batch")?;

        let batch = SettlementBatch {
            id: row.get("id"),
            created_at: row.get("created_at"),
            payment_count: row.get("payment_count"),
            total_amount_cents: row.get("total_amount_cents"),
            status: row.get("status"),
            started_at: row.get("started_at"),
            completed_at: row.get("completed_at"),
        };

        info!(
            "Created settlement batch {} with {} pending payments",
            batch.id, pending_count
        );

        crate::metrics::record_settlement_batch_created(pending_count as usize);

        Ok(Some(batch))
    }

    /// Process a settlement batch
    pub async fn process_settlement_batch(&self, batch_id: Uuid) -> Result<()> {
        // Update batch status to processing
        sqlx::query(
            r#"
            UPDATE settlement_batches
            SET status = $1, started_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(SettlementStatus::Processing)
        .bind(batch_id)
        .execute(&self.db)
        .await
        .context("Failed to update batch status")?;

        info!("Processing settlement batch {}", batch_id);

        // In a real implementation, this would:
        // 1. Fetch all pending payments
        // 2. Submit to payment providers
        // 3. Update payment statuses based on provider responses
        // 4. Update batch statistics

        // For now, just mark as completed
        sqlx::query(
            r#"
            UPDATE settlement_batches
            SET status = $1, completed_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(SettlementStatus::Completed)
        .bind(batch_id)
        .execute(&self.db)
        .await
        .context("Failed to complete batch")?;

        info!("Completed settlement batch {}", batch_id);

        crate::metrics::record_settlement_batch_processed();

        Ok(())
    }

    /// Get settlement batch by ID
    pub async fn get_settlement_batch(&self, batch_id: Uuid) -> Result<Option<SettlementBatch>> {
        let batch = sqlx::query(
            r#"
            SELECT
                id, created_at, payment_count, total_amount_cents,
                status, started_at, completed_at
            FROM settlement_batches
            WHERE id = $1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch settlement batch")?
        .map(|row| SettlementBatch {
            id: row.get("id"),
            created_at: row.get("created_at"),
            payment_count: row.get("payment_count"),
            total_amount_cents: row.get("total_amount_cents"),
            status: row.get("status"),
            started_at: row.get("started_at"),
            completed_at: row.get("completed_at"),
        });

        Ok(batch)
    }

    /// List settlement batches
    pub async fn list_settlement_batches(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SettlementBatch>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, created_at, payment_count, total_amount_cents,
                status, started_at, completed_at
            FROM settlement_batches
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .context("Failed to list settlement batches")?;

        let batches = rows
            .into_iter()
            .map(|row| SettlementBatch {
                id: row.get("id"),
                created_at: row.get("created_at"),
                payment_count: row.get("payment_count"),
                total_amount_cents: row.get("total_amount_cents"),
                status: row.get("status"),
                started_at: row.get("started_at"),
                completed_at: row.get("completed_at"),
            })
            .collect();

        Ok(batches)
    }

    // ========================================================================
    // Escrow Operations
    // ========================================================================

    /// Hold payment in escrow for a disputed proof
    pub async fn hold_in_escrow(
        &self,
        proof_id: Uuid,
        provider_id: Uuid,
        requester_id: Uuid,
        amount_points: i64,
        reason: String,
    ) -> Result<EscrowEntry> {
        let row = sqlx::query(
            r#"
            INSERT INTO escrow_entries
                (proof_id, provider_id, requester_id, amount_points, status, reason)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id, proof_id, provider_id, requester_id, amount_points,
                status, reason, created_at, resolved_at
            "#,
        )
        .bind(proof_id)
        .bind(provider_id)
        .bind(requester_id)
        .bind(amount_points)
        .bind(EscrowStatus::Held)
        .bind(reason)
        .fetch_one(&self.db)
        .await
        .context("Failed to create escrow entry")?;

        let entry = EscrowEntry {
            id: row.get("id"),
            proof_id: row.get("proof_id"),
            provider_id: row.get("provider_id"),
            requester_id: row.get("requester_id"),
            amount_points: row.get("amount_points"),
            status: row.get("status"),
            reason: row.get("reason"),
            created_at: row.get("created_at"),
            resolved_at: row.get("resolved_at"),
        };

        info!(
            "Held {} points in escrow for proof {} (escrow ID: {})",
            amount_points, proof_id, entry.id
        );

        crate::metrics::record_escrow_held(amount_points);

        Ok(entry)
    }

    /// Release escrow funds to provider
    pub async fn release_escrow(&self, escrow_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE escrow_entries
            SET status = $1, resolved_at = NOW()
            WHERE id = $2 AND status = $3
            "#,
        )
        .bind(EscrowStatus::Released)
        .bind(escrow_id)
        .bind(EscrowStatus::Held)
        .execute(&self.db)
        .await
        .context("Failed to release escrow")?;

        info!("Released escrow {}", escrow_id);

        crate::metrics::record_escrow_released();

        Ok(())
    }

    /// Refund escrow funds to requester
    pub async fn refund_escrow(&self, escrow_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE escrow_entries
            SET status = $1, resolved_at = NOW()
            WHERE id = $2 AND status = $3
            "#,
        )
        .bind(EscrowStatus::Refunded)
        .bind(escrow_id)
        .bind(EscrowStatus::Held)
        .execute(&self.db)
        .await
        .context("Failed to refund escrow")?;

        info!("Refunded escrow {}", escrow_id);

        crate::metrics::record_escrow_refunded();

        Ok(())
    }

    /// Get escrow entry by ID
    pub async fn get_escrow(&self, escrow_id: Uuid) -> Result<Option<EscrowEntry>> {
        let entry = sqlx::query(
            r#"
            SELECT
                id, proof_id, provider_id, requester_id, amount_points,
                status, reason, created_at, resolved_at
            FROM escrow_entries
            WHERE id = $1
            "#,
        )
        .bind(escrow_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch escrow entry")?
        .map(|row| EscrowEntry {
            id: row.get("id"),
            proof_id: row.get("proof_id"),
            provider_id: row.get("provider_id"),
            requester_id: row.get("requester_id"),
            amount_points: row.get("amount_points"),
            status: row.get("status"),
            reason: row.get("reason"),
            created_at: row.get("created_at"),
            resolved_at: row.get("resolved_at"),
        });

        Ok(entry)
    }

    /// List escrow entries for a proof
    pub async fn list_escrow_for_proof(&self, proof_id: Uuid) -> Result<Vec<EscrowEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, proof_id, provider_id, requester_id, amount_points,
                status, reason, created_at, resolved_at
            FROM escrow_entries
            WHERE proof_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(proof_id)
        .fetch_all(&self.db)
        .await
        .context("Failed to list escrow entries")?;

        let entries = rows
            .into_iter()
            .map(|row| EscrowEntry {
                id: row.get("id"),
                proof_id: row.get("proof_id"),
                provider_id: row.get("provider_id"),
                requester_id: row.get("requester_id"),
                amount_points: row.get("amount_points"),
                status: row.get("status"),
                reason: row.get("reason"),
                created_at: row.get("created_at"),
                resolved_at: row.get("resolved_at"),
            })
            .collect();

        Ok(entries)
    }

    // ========================================================================
    // Revenue Split Calculations
    // ========================================================================

    /// Calculate revenue split for a transaction
    pub fn calculate_revenue_split(
        &self,
        total_amount: i64,
        config: &RevenueSplitConfig,
    ) -> RevenueSplit {
        let platform_amount = (total_amount as f64 * config.platform_fee) as i64;
        let creator_amount = (total_amount as f64 * config.creator_share) as i64;
        let provider_amount = total_amount - platform_amount - creator_amount;

        RevenueSplit {
            total_amount,
            platform_amount,
            creator_amount,
            provider_amount,
        }
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get payment statistics
    pub async fn get_payment_stats(&self) -> Result<PaymentStats> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
                COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
                COALESCE(SUM(amount_cents) FILTER (WHERE status = 'completed'), 0)::BIGINT as total_paid_cents,
                COALESCE(SUM(amount_cents) FILTER (WHERE status = 'pending'), 0)::BIGINT as total_pending_cents
            FROM payment_ledger
            "#
        )
        .fetch_one(&self.db)
        .await
        .context("Failed to fetch payment statistics")?;

        Ok(PaymentStats {
            pending_count: row.get::<Option<i64>, _>("pending_count").unwrap_or(0),
            completed_count: row.get::<Option<i64>, _>("completed_count").unwrap_or(0),
            failed_count: row.get::<Option<i64>, _>("failed_count").unwrap_or(0),
            total_paid_cents: row.get::<i64, _>("total_paid_cents"),
            total_pending_cents: row.get::<i64, _>("total_pending_cents"),
        })
    }
}

// ============================================================================
// Helper Structures
// ============================================================================

/// Revenue split breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueSplit {
    /// Total transaction amount
    pub total_amount: i64,
    /// Platform fee amount
    pub platform_amount: i64,
    /// Creator share amount
    pub creator_amount: i64,
    /// Provider share amount
    pub provider_amount: i64,
}

/// Payment statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentStats {
    /// Number of pending payments
    pub pending_count: i64,
    /// Number of completed payments
    pub completed_count: i64,
    /// Number of failed payments
    pub failed_count: i64,
    /// Total amount paid (cents)
    pub total_paid_cents: i64,
    /// Total amount pending (cents)
    pub total_pending_cents: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revenue_split_default() {
        let config = RevenueSplitConfig::default();
        assert_eq!(config.platform_fee, 0.05);
        assert_eq!(config.creator_share, 0.70);
        assert_eq!(config.provider_share, 0.25);
        assert_eq!(
            config.platform_fee + config.creator_share + config.provider_share,
            1.0
        );
    }

    #[test]
    fn test_payment_config_default() {
        let config = PaymentConfig::default();
        assert_eq!(config.points_to_usd_rate, 0.001);
        assert_eq!(config.min_payout_threshold_points, 10000);
        assert_eq!(config.settlement_batch_interval_secs, 86400);
    }

    #[test]
    fn test_payment_provider_display() {
        assert_eq!(PaymentProvider::Stripe.to_string(), "stripe");
        assert_eq!(PaymentProvider::PayPal.to_string(), "paypal");
        assert_eq!(PaymentProvider::BankTransfer.to_string(), "bank_transfer");
        assert_eq!(PaymentProvider::Crypto.to_string(), "crypto");
        assert_eq!(PaymentProvider::Manual.to_string(), "manual");
    }
}
