//! Gamification scheduler — periodic background maintenance.
//!
//! Spawns a single Tokio task that drives three maintenance cadences:
//!
//! | Cadence    | Interval    | Actions                                         |
//! |------------|-------------|-------------------------------------------------|
//! | Hourly     | 1 h         | Refresh expired quests, check badge eligibility |
//! | Daily      | 24 h        | Badge check, streak maintenance                 |
//! | Monthly    | Month start | Reset monthly points, rebuild leaderboard       |
//!
//! The scheduler never panics — all errors are logged and swallowed so
//! the background task keeps running.

use std::sync::Arc;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{info, warn};
use uuid::Uuid;

use chrono::Datelike;

use super::{GamificationEngine, GamificationError};

/// Spawn a background scheduler that drives periodic gamification maintenance.
///
/// The returned [`tokio::task::JoinHandle`] can be awaited to detect if the
/// scheduler ever exits (it should not under normal operation).
pub fn spawn_scheduler(engine: Arc<GamificationEngine>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_scheduler(engine).await;
    })
}

async fn run_scheduler(engine: Arc<GamificationEngine>) {
    // Hourly tick — main maintenance heartbeat.
    let mut hourly = interval(Duration::from_secs(3600));
    hourly.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut hour_counter: u32 = 0;
    let mut last_month: u32 = chrono::Utc::now().month();
    let mut last_year: i32 = chrono::Utc::now().year();

    info!("Gamification scheduler started");

    loop {
        hourly.tick().await;
        hour_counter = hour_counter.wrapping_add(1);

        let now = chrono::Utc::now();
        let current_month = now.month();
        let current_year = now.year();

        // ── Monthly reset ─────────────────────────────────────────────────
        // Trigger on the first tick after a month boundary.
        if current_month != last_month {
            // Capture the ending period before overwriting the trackers.
            let snapshot_year = last_year;
            let snapshot_month = last_month;
            last_month = current_month;
            last_year = current_year;

            // Persist snapshot of the completed month before wiping monthly points.
            if let Err(e) = engine
                .save_monthly_snapshot(snapshot_year, snapshot_month)
                .await
            {
                warn!(
                    "Gamification: failed to save monthly snapshot for {snapshot_year}/{snapshot_month:02}: {e}"
                );
            }

            info!("Gamification: performing monthly points reset for new month {current_month}");
            let reset_count = engine.perform_monthly_reset().await;
            info!("Gamification: monthly reset complete — {reset_count} users reset");
        }

        // ── Hourly maintenance ────────────────────────────────────────────
        run_hourly_maintenance(&engine).await;

        // ── Daily maintenance (every 24 ticks) ───────────────────────────
        if hour_counter % 24 == 0 {
            run_daily_maintenance(&engine).await;
        }
    }
}

/// Hourly: refresh expired quests and check badge eligibility for all users.
async fn run_hourly_maintenance(engine: &GamificationEngine) {
    let user_ids: Vec<Uuid> = engine.all_user_ids();
    if user_ids.is_empty() {
        return;
    }

    let mut badge_count = 0usize;
    let mut errors = 0usize;

    for user_id in &user_ids {
        // Calling get_active_quests triggers lazy expiry detection and
        // auto-refreshes expired quests for the user.
        if let Err(e) = engine.get_active_quests(*user_id).await {
            if !matches!(e, GamificationError::UserNotFound(_)) {
                warn!("Gamification: quest refresh error for {user_id}: {e}");
                errors += 1;
            }
        }

        // Check badge eligibility — awards any newly qualifying badges.
        match engine.check_badge_eligibility(*user_id).await {
            Ok(new_badges) if !new_badges.is_empty() => {
                badge_count += new_badges.len();
                info!(
                    "Gamification: awarded {} badge(s) to {user_id}: {:?}",
                    new_badges.len(),
                    new_badges
                );
            }
            Ok(_) => {}
            Err(e) => {
                if !matches!(e, GamificationError::UserNotFound(_)) {
                    warn!("Gamification: badge check error for {user_id}: {e}");
                    errors += 1;
                }
            }
        }
    }

    if badge_count > 0 || errors > 0 {
        info!(
            "Gamification: hourly maintenance — {} users, {} new badges, {} errors",
            user_ids.len(),
            badge_count,
            errors
        );
    }
}

/// Daily: additional maintenance — logs active user stats.
async fn run_daily_maintenance(engine: &GamificationEngine) {
    let user_count = engine.user_count();
    info!("Gamification: daily maintenance — {user_count} registered users");

    // Future: check for users with no activity in 48 h and reset their streaks.
    // For now, streaks are only incremented/reset via explicit API calls.
}
