//! Repository layer for database operations.
//!
//! NOTE: Many repository functions are not yet integrated with API handlers.
//! They are prepared for future use when full integration is implemented.

#![allow(dead_code)]

use super::DbPool;
use super::models::*;
use sqlx::Row;
use uuid::Uuid;

/// Repository for user operations.
pub struct UserRepository;

impl UserRepository {
    /// Create a new user.
    pub async fn create(pool: &DbPool, input: CreateUser) -> sqlx::Result<User> {
        sqlx::query_as(
            r#"
            INSERT INTO users (username, email, password_hash, role, referrer_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&input.username)
        .bind(&input.email)
        .bind(&input.password_hash)
        .bind(input.role)
        .bind(input.referrer_id)
        .fetch_one(pool)
        .await
    }

    /// Find user by ID.
    pub async fn find_by_id(pool: &DbPool, id: Uuid) -> sqlx::Result<Option<User>> {
        sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Find user by peer ID.
    pub async fn find_by_peer_id(pool: &DbPool, peer_id: &str) -> sqlx::Result<Option<User>> {
        sqlx::query_as("SELECT * FROM users WHERE peer_id = $1")
            .bind(peer_id)
            .fetch_optional(pool)
            .await
    }

    /// Update user points balance.
    pub async fn update_points(pool: &DbPool, id: Uuid, delta: i64) -> sqlx::Result<i64> {
        let row = sqlx::query(
            r#"
            UPDATE users
            SET points_balance = points_balance + $2
            WHERE id = $1
            RETURNING points_balance
            "#,
        )
        .bind(id)
        .bind(delta)
        .fetch_one(pool)
        .await?;

        Ok(row.get("points_balance"))
    }

    /// Get referral chain for a user (up to 3 levels).
    pub async fn get_referral_chain(
        pool: &DbPool,
        user_id: Uuid,
    ) -> sqlx::Result<Vec<(Uuid, i32)>> {
        sqlx::query_as("SELECT referrer_id, depth FROM get_referral_chain($1, 3)")
            .bind(user_id)
            .fetch_all(pool)
            .await
    }
}

/// Repository for content operations.
pub struct ContentRepository;

impl ContentRepository {
    /// Create new content.
    pub async fn create(pool: &DbPool, input: CreateContent) -> sqlx::Result<Content> {
        sqlx::query_as(
            r#"
            INSERT INTO content (
                creator_id, title, description, category, tags,
                cid, size_bytes, chunk_count, encryption_key, price
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(input.creator_id)
        .bind(&input.title)
        .bind(&input.description)
        .bind(input.category)
        .bind(&input.tags)
        .bind(&input.cid)
        .bind(input.size_bytes)
        .bind(input.chunk_count)
        .bind(&input.encryption_key)
        .bind(input.price)
        .fetch_one(pool)
        .await
    }

    /// Find content by ID.
    pub async fn find_by_id(pool: &DbPool, id: Uuid) -> sqlx::Result<Option<Content>> {
        sqlx::query_as("SELECT * FROM content WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Find content by CID.
    pub async fn find_by_cid(pool: &DbPool, cid: &str) -> sqlx::Result<Option<Content>> {
        sqlx::query_as("SELECT * FROM content WHERE cid = $1")
            .bind(cid)
            .fetch_optional(pool)
            .await
    }

    /// Update content status.
    pub async fn update_status(pool: &DbPool, id: Uuid, status: ContentStatus) -> sqlx::Result<()> {
        sqlx::query("UPDATE content SET status = $2 WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Get active content with demand info.
    pub async fn get_trending(pool: &DbPool, limit: i32) -> sqlx::Result<Vec<Content>> {
        sqlx::query_as(
            r#"
            SELECT c.*
            FROM content c
            LEFT JOIN content_demand_hourly d ON d.content_id = c.id
                AND d.hour > NOW() - INTERVAL '24 hours'
            WHERE c.status = 'ACTIVE'
            GROUP BY c.id
            ORDER BY COALESCE(SUM(d.download_requests), 0) DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

/// Repository for node operations.
pub struct NodeRepository;

impl NodeRepository {
    /// Register a new node.
    pub async fn create(pool: &DbPool, input: CreateNode) -> sqlx::Result<Node> {
        sqlx::query_as(
            r#"
            INSERT INTO nodes (
                user_id, peer_id, public_key,
                max_storage_bytes, max_bandwidth_bps
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(input.user_id)
        .bind(&input.peer_id)
        .bind(&input.public_key)
        .bind(input.max_storage_bytes)
        .bind(input.max_bandwidth_bps)
        .fetch_one(pool)
        .await
    }

    /// Find node by peer ID.
    pub async fn find_by_peer_id(pool: &DbPool, peer_id: &str) -> sqlx::Result<Option<Node>> {
        sqlx::query_as("SELECT * FROM nodes WHERE peer_id = $1")
            .bind(peer_id)
            .fetch_optional(pool)
            .await
    }

    /// Update node status and last seen.
    pub async fn update_heartbeat(
        pool: &DbPool,
        peer_id: &str,
        status: NodeStatus,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            UPDATE nodes
            SET status = $2, last_seen_at = NOW()
            WHERE peer_id = $1
            "#,
        )
        .bind(peer_id)
        .bind(status)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Get nodes hosting specific content.
    pub async fn get_seeders_for_content(
        pool: &DbPool,
        content_id: Uuid,
    ) -> sqlx::Result<Vec<Node>> {
        sqlx::query_as(
            r#"
            SELECT n.*
            FROM nodes n
            JOIN content_pins cp ON cp.node_id = n.id
            WHERE cp.content_id = $1 AND n.status = 'ONLINE'
            ORDER BY n.reputation_score DESC
            "#,
        )
        .bind(content_id)
        .fetch_all(pool)
        .await
    }

    /// Update node stats after successful transfer.
    pub async fn record_transfer(
        pool: &DbPool,
        node_id: Uuid,
        bytes: i64,
        success: bool,
    ) -> sqlx::Result<()> {
        if success {
            sqlx::query(
                r#"
                UPDATE nodes
                SET total_bandwidth_bytes = total_bandwidth_bytes + $2,
                    successful_transfers = successful_transfers + 1
                WHERE id = $1
                "#,
            )
            .bind(node_id)
            .bind(bytes)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE nodes
                SET failed_transfers = failed_transfers + 1
                WHERE id = $1
                "#,
            )
            .bind(node_id)
            .execute(pool)
            .await?;
        }
        Ok(())
    }
}

/// Repository for bandwidth proof operations.
pub struct ProofRepository;

impl ProofRepository {
    /// Store a new proof.
    pub async fn create(
        pool: &DbPool,
        input: CreateBandwidthProof,
    ) -> sqlx::Result<BandwidthProofRecord> {
        sqlx::query_as(
            r#"
            INSERT INTO bandwidth_proofs (
                session_id, content_id, chunk_index, bytes_transferred,
                provider_node_id, requester_node_id,
                provider_public_key, requester_public_key,
                provider_signature, requester_signature,
                challenge_nonce, chunk_hash,
                start_timestamp_ms, end_timestamp_ms, latency_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            "#,
        )
        .bind(input.session_id)
        .bind(input.content_id)
        .bind(input.chunk_index)
        .bind(input.bytes_transferred)
        .bind(input.provider_node_id)
        .bind(input.requester_node_id)
        .bind(&input.provider_public_key)
        .bind(&input.requester_public_key)
        .bind(&input.provider_signature)
        .bind(&input.requester_signature)
        .bind(&input.challenge_nonce)
        .bind(&input.chunk_hash)
        .bind(input.start_timestamp_ms)
        .bind(input.end_timestamp_ms)
        .bind(input.latency_ms)
        .fetch_one(pool)
        .await
    }

    /// Check if nonce was already used.
    pub async fn check_and_use_nonce(pool: &DbPool, nonce: &[u8]) -> sqlx::Result<bool> {
        let row = sqlx::query("SELECT check_and_use_nonce($1) as result")
            .bind(nonce)
            .fetch_one(pool)
            .await?;

        Ok(row.get("result"))
    }

    /// Update proof status after verification.
    pub async fn update_status(
        pool: &DbPool,
        id: Uuid,
        status: ProofStatus,
        rejection_reason: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            UPDATE bandwidth_proofs
            SET status = $2,
                verified_at = CASE WHEN $2 IN ('VERIFIED', 'REJECTED') THEN NOW() ELSE verified_at END,
                rejection_reason = $3
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(rejection_reason)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Record reward for a proof.
    pub async fn record_reward(pool: &DbPool, id: Uuid, amount: i64) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            UPDATE bandwidth_proofs
            SET status = 'REWARDED', reward_amount = $2, rewarded_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(amount)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Get average transfer speed for a node (for anomaly detection).
    pub async fn get_average_speed(pool: &DbPool, node_id: Uuid) -> sqlx::Result<Option<f64>> {
        let row = sqlx::query(
            r#"
            SELECT AVG(bytes_transferred::float / NULLIF(latency_ms, 0)) as avg_speed
            FROM bandwidth_proofs
            WHERE provider_node_id = $1
                AND created_at > NOW() - INTERVAL '1 hour'
                AND status IN ('VERIFIED', 'REWARDED')
            "#,
        )
        .bind(node_id)
        .fetch_one(pool)
        .await?;

        Ok(row.get("avg_speed"))
    }
}

/// Repository for transaction operations.
pub struct TransactionRepository;

impl TransactionRepository {
    /// Record a point transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &DbPool,
        user_id: Uuid,
        amount: i64,
        transaction_type: TransactionType,
        proof_id: Option<Uuid>,
        content_id: Option<Uuid>,
        related_user_id: Option<Uuid>,
        description: Option<&str>,
    ) -> sqlx::Result<PointTransaction> {
        // Get current balance
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;

        let balance_before = user.points_balance;
        let balance_after = balance_before + amount;

        // Update user balance
        sqlx::query("UPDATE users SET points_balance = $2 WHERE id = $1")
            .bind(user_id)
            .bind(balance_after)
            .execute(pool)
            .await?;

        // Record transaction
        sqlx::query_as(
            r#"
            INSERT INTO point_transactions (
                user_id, amount, type, proof_id, content_id,
                related_user_id, balance_before, balance_after, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(amount)
        .bind(transaction_type)
        .bind(proof_id)
        .bind(content_id)
        .bind(related_user_id)
        .bind(balance_before)
        .bind(balance_after)
        .bind(description)
        .fetch_one(pool)
        .await
    }
}

/// Repository for demand/analytics operations.
pub struct AnalyticsRepository;

impl AnalyticsRepository {
    /// Get demand statistics for a content.
    pub async fn get_content_demand(pool: &DbPool, content_id: Uuid) -> sqlx::Result<(i64, i64)> {
        // demand = download queue count, supply = active seeders
        let demand_row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM bandwidth_proofs
            WHERE content_id = $1
                AND created_at > NOW() - INTERVAL '10 minutes'
                AND status = 'PENDING'
            "#,
        )
        .bind(content_id)
        .fetch_one(pool)
        .await?;

        let supply_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT n.id) as count
            FROM nodes n
            JOIN content_pins cp ON cp.node_id = n.id
            WHERE cp.content_id = $1 AND n.status = 'ONLINE'
            "#,
        )
        .bind(content_id)
        .fetch_one(pool)
        .await?;

        let demand: i64 = demand_row.get("count");
        let supply: i64 = supply_row.get("count");

        Ok((demand, supply))
    }

    /// Record hourly demand metrics.
    pub async fn record_demand(
        pool: &DbPool,
        content_id: Uuid,
        download_requests: i64,
        bytes_transferred: i64,
        active_seeders: i32,
        average_latency_ms: Option<i32>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO content_demand_hourly (
                content_id, hour, download_requests, bytes_transferred,
                active_seeders, average_latency_ms
            )
            VALUES ($1, DATE_TRUNC('hour', NOW()), $2, $3, $4, $5)
            ON CONFLICT (content_id, hour) DO UPDATE SET
                download_requests = content_demand_hourly.download_requests + $2,
                bytes_transferred = content_demand_hourly.bytes_transferred + $3,
                active_seeders = $4,
                average_latency_ms = $5
            "#,
        )
        .bind(content_id)
        .bind(download_requests)
        .bind(bytes_transferred)
        .bind(active_seeders)
        .bind(average_latency_ms)
        .execute(pool)
        .await?;
        Ok(())
    }
}
