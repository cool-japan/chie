//! Referral system for CHIE Protocol.
//!
//! Manages referral code generation, lookup, and stats for the creator
//! referral programme. Referral codes are lazily generated on first request
//! and stored permanently in the `users` table.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::Serialize;
use uuid::Uuid;

use crate::{AppState, AuthenticatedUser};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A user's referral code together with aggregated usage statistics.
#[derive(Debug, Serialize)]
pub struct ReferralInfo {
    /// The user's unique referral code (e.g. `"A1B2C3D4XY"`).
    pub referral_code: String,
    /// A ready-to-share URL that pre-fills the referral code.
    pub referral_url: String,
    /// Total number of users who joined via this code.
    pub total_referrals: i64,
    /// Referrals that have been active in the last 30 days.
    pub active_referrals: i64,
    /// Total points earned from referral rewards.
    pub total_earned_from_referrals: i64,
}

/// A single person who joined via the current user's referral code.
#[derive(Debug, Serialize)]
pub struct ReferralEntry {
    /// User ID of the referred person.
    pub user_id: Uuid,
    /// When this person joined.
    pub joined_at: DateTime<Utc>,
    /// Whether this person has been active in the last 30 days.
    pub is_active: bool,
    /// Total points the current user earned from this referral relationship.
    pub total_earned_you: i64,
}

// ---------------------------------------------------------------------------
// Referral code helpers
// ---------------------------------------------------------------------------

/// Generate a deterministic-prefix referral code for the given UUID.
///
/// Format: first 8 hex chars of the UUID + 2 random uppercase alphanumeric
/// chars, e.g. `"A1B2C3D4XY"`.
fn generate_referral_code(user_id: Uuid) -> String {
    let hex_prefix: String = user_id
        .as_simple()
        .to_string()
        .chars()
        .take(8)
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let rng = rand::rng();
    let suffix: String = rng
        .sample_iter(rand::distr::Alphanumeric)
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .take(2)
        .map(|c| c as char)
        .collect();

    format!("{}{}", hex_prefix, suffix)
}

/// Ensure the user has a referral code stored in the database.
///
/// If the user already has a code it is returned immediately.  Otherwise a
/// fresh code is generated, persisted, and returned.
async fn ensure_referral_code(
    pool: &crate::db::DbPool,
    user_id: Uuid,
) -> Result<String, (StatusCode, String)> {
    // Check whether the user already has a code.
    let existing: Option<Option<String>> =
        sqlx::query_scalar::<_, Option<String>>("SELECT referral_code FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?;

    match existing {
        Some(Some(code)) => return Ok(code),
        None => {
            return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
        }
        Some(None) => { /* fall through to generate */ }
    }

    // Generate a code and persist it.  If there is a uniqueness collision we
    // retry up to 5 times before giving up.
    for _ in 0..5u8 {
        let code = generate_referral_code(user_id);

        let result = sqlx::query(
            "UPDATE users SET referral_code = $1 WHERE id = $2 AND referral_code IS NULL",
        )
        .bind(&code)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to store referral code: {}", e),
            )
        })?;

        if result.rows_affected() > 0 {
            return Ok(code);
        }

        // Another request raced us -- re-read the now-stored code.
        let stored: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT referral_code FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error on re-read: {}", e),
            )
        })?
        .flatten();

        if let Some(existing_code) = stored {
            return Ok(existing_code);
        }
        // else keep retrying
    }

    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to generate a unique referral code after multiple attempts".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/me/referral`
///
/// Returns the authenticated user's referral code and aggregated stats.
/// A code is generated and stored on first call if one does not exist.
pub async fn get_my_referral(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<ReferralInfo>, (StatusCode, String)> {
    let user_id = user.user_id;
    let code = ensure_referral_code(&state.db, user_id).await?;

    // Total referrals (all time).
    let total_referrals: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE referrer_id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to count referrals: {}", e),
                )
            })?;

    // Active referrals (seen in the last 30 days).
    let active_referrals: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE referrer_id = $1 AND last_seen_at > NOW() - INTERVAL '30 days'",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to count active referrals: {}", e),
        )
    })?;

    // Total points earned from referral rewards.
    // `transactions` uses `related_user_id` to track whose referral triggered
    // the reward.  We sum all REFERRAL_REWARD entries for this user.
    let total_earned: i64 = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COALESCE(SUM(amount), 0)
        FROM transactions
        WHERE user_id = $1
          AND type = 'REFERRAL_REWARD'
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to sum referral earnings: {}", e),
        )
    })?;

    let referral_url = format!("https://chie.network/join?ref={}", code);

    Ok(Json(ReferralInfo {
        referral_code: code,
        referral_url,
        total_referrals,
        active_referrals,
        total_earned_from_referrals: total_earned,
    }))
}

/// `GET /api/v1/me/referrals`
///
/// Returns the list of users who joined via the authenticated user's referral
/// code, along with per-referral earnings.  Returns at most 50 entries ordered
/// by join date descending.
pub async fn list_my_referrals(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ReferralEntry>>, (StatusCode, String)> {
    let user_id = user.user_id;

    // Query referred users with per-user earnings from the transactions table.
    // `related_user_id` on a REFERRAL_REWARD transaction stores the referred
    // user whose activity triggered the reward.
    let rows = sqlx::query_as::<_, (Uuid, DateTime<Utc>, bool, i64)>(
        r#"
        SELECT
            u.id,
            u.created_at,
            CASE
                WHEN u.last_seen_at > NOW() - INTERVAL '30 days' THEN true
                ELSE false
            END AS is_active,
            COALESCE(
                (
                    SELECT SUM(t.amount)
                    FROM transactions t
                    WHERE t.user_id = $1
                      AND t.related_user_id = u.id
                      AND t.type = 'REFERRAL_REWARD'
                ),
                0
            ) AS total_earned_you
        FROM users u
        WHERE u.referrer_id = $1
        ORDER BY u.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch referrals: {}", e),
        )
    })?;

    let entries = rows
        .into_iter()
        .map(|(uid, joined_at, is_active, earned)| ReferralEntry {
            user_id: uid,
            joined_at,
            is_active,
            total_earned_you: earned,
        })
        .collect();

    Ok(Json(entries))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build and return the referral sub-router.
///
/// Mounts at `/api/v1` alongside the other `/me/*` endpoints.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me/referral", get(get_my_referral))
        .route("/me/referrals", get(list_my_referrals))
}
