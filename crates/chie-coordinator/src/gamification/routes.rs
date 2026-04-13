//! HTTP handlers for gamification API endpoints.
//!
//! Provides the following REST endpoints:
//! - `GET /api/v1/gamification/leaderboard?limit=50`
//! - `GET /api/v1/gamification/leaderboard/history`
//! - `GET /api/v1/gamification/users/{user_id}/state`
//! - `GET /api/v1/gamification/users/{user_id}/quests`
//! - `POST /api/v1/gamification/users/{user_id}/quests/{quest_id}/progress`
//! - `GET /api/v1/gamification/users/{user_id}/badges`

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chie_shared::gamification::{Badge, LeaderboardEntry, Quest, UserGamificationState};

use crate::AppState;

/// Query parameters for the leaderboard endpoint.
#[derive(Debug, Deserialize)]
pub struct LeaderboardQuery {
    /// Maximum number of entries to return (default 50, max 200).
    #[serde(default = "default_leaderboard_limit")]
    pub limit: u32,
}

fn default_leaderboard_limit() -> u32 {
    50
}

/// Request body for updating quest progress.
#[derive(Debug, Deserialize)]
pub struct QuestProgressRequest {
    /// The amount to increment the quest's current progress.
    pub increment: u64,
}

/// Response wrapper for gamification API calls.
#[derive(Debug, Serialize)]
pub struct GamificationApiError {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

impl GamificationApiError {
    fn not_found(message: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::NOT_FOUND,
            Json(Self {
                code: "NOT_FOUND".to_string(),
                message: message.into(),
            }),
        )
    }

    fn bad_request(message: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self {
                code: "BAD_REQUEST".to_string(),
                message: message.into(),
            }),
        )
    }

    fn internal(message: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self {
                code: "INTERNAL_ERROR".to_string(),
                message: message.into(),
            }),
        )
    }
}

/// `GET /leaderboard?limit=N`
///
/// Returns the top N users ranked by monthly points.
/// Defaults to 50 entries; maximum 200.
pub async fn get_leaderboard(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardQuery>,
) -> Result<Json<Vec<LeaderboardEntry>>, (StatusCode, Json<GamificationApiError>)> {
    let limit = params.limit.min(200);
    let entries = state
        .gamification
        .get_leaderboard(limit)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;
    Ok(Json(entries))
}

/// `GET /users/{user_id}/state`
///
/// Returns the full gamification state for the specified user.
/// Creates an empty state if the user has never been seen.
pub async fn get_user_gamification_state(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserGamificationState>, (StatusCode, Json<GamificationApiError>)> {
    let user_state = state
        .gamification
        .get_user_state(user_id)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;
    Ok(Json(user_state))
}

/// `GET /users/{user_id}/quests`
///
/// Returns the active quests for the specified user.
/// Initializes the default quest set if none exist.
pub async fn get_user_quests(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Quest>>, (StatusCode, Json<GamificationApiError>)> {
    let quests = state
        .gamification
        .get_active_quests(user_id)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;
    Ok(Json(quests))
}

/// `POST /users/{user_id}/quests/{quest_id}/progress`
///
/// Increments progress on the specified quest by the given amount.
/// The quest is identified by type-matching, not by UUID, since
/// the engine matches on quest type. The `quest_id` path param is
/// used to identify the specific quest instance.
///
/// Request body: `{"increment": N}`
pub async fn update_quest_progress(
    State(state): State<AppState>,
    Path((user_id, quest_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<QuestProgressRequest>,
) -> Result<StatusCode, (StatusCode, Json<GamificationApiError>)> {
    if body.increment == 0 {
        return Err(GamificationApiError::bad_request(
            "increment must be greater than 0",
        ));
    }

    // Retrieve the quest type from the user's active quests
    let user_state = state
        .gamification
        .get_user_state(user_id)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;

    let quest_type = user_state
        .active_quests
        .iter()
        .find(|q| q.id == quest_id)
        .map(|q| q.quest_type.clone())
        .ok_or_else(|| {
            GamificationApiError::not_found(format!(
                "Quest {} not found for user {}",
                quest_id, user_id
            ))
        })?;

    state
        .gamification
        .update_quest_progress(user_id, quest_type, body.increment)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /users/{user_id}/badges`
///
/// Returns the list of badges earned by the specified user.
pub async fn get_user_badges(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Badge>>, (StatusCode, Json<GamificationApiError>)> {
    let user_state = state
        .gamification
        .get_user_state(user_id)
        .await
        .map_err(|e| GamificationApiError::internal(e.to_string()))?;
    Ok(Json(user_state.badges))
}

/// Lightweight metadata about a monthly leaderboard snapshot.
#[derive(Debug, Serialize)]
pub struct SnapshotMeta {
    /// Calendar year of the snapshot.
    pub year: i32,
    /// Calendar month of the snapshot (1–12).
    pub month: u32,
    /// RFC 3339 timestamp when the snapshot was captured.
    pub captured_at: String,
    /// Number of leaderboard entries stored in the snapshot.
    pub entry_count: u32,
}

/// `GET /leaderboard/history`
///
/// Returns lightweight metadata for all persisted monthly leaderboard snapshots,
/// sorted newest-first.  Full entry lists are omitted to keep the response small;
/// individual snapshots can be fetched from disk if needed.
pub async fn get_leaderboard_history(
    State(state): State<AppState>,
) -> Result<Json<Vec<SnapshotMeta>>, (StatusCode, Json<GamificationApiError>)> {
    let snapshots = state.gamification.load_snapshots().await;
    let meta: Vec<SnapshotMeta> = snapshots
        .into_iter()
        .map(|s| SnapshotMeta {
            year: s.year,
            month: s.month,
            captured_at: s.captured_at,
            entry_count: s.entries.len() as u32,
        })
        .collect();
    Ok(Json(meta))
}

/// Builds and returns the gamification Router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/leaderboard", get(get_leaderboard))
        .route("/leaderboard/history", get(get_leaderboard_history))
        .route("/users/{user_id}/state", get(get_user_gamification_state))
        .route("/users/{user_id}/quests", get(get_user_quests))
        .route(
            "/users/{user_id}/quests/{quest_id}/progress",
            post(update_quest_progress),
        )
        .route("/users/{user_id}/badges", get(get_user_badges))
}
