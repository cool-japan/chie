//! CHIE Desktop Client - Tauri Backend
//!
//! This module provides the Rust backend for the CHIE desktop client,
//! including node control, earnings tracking, and content management.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tauri::State;
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// NodeHandle — wraps the running node state
// ---------------------------------------------------------------------------

/// Handle to a running CHIE node instance.
///
/// Holds the core ContentNode, network state monitor, and uptime tracking.
/// Dropped on stop_node, which cleanly tears everything down.
pub struct NodeHandle {
    /// Core content node (storage + keys + earnings).
    pub content_node: chie_core::ContentNode,
    /// Network state monitor (peer tracking, metrics).
    pub network_monitor: chie_p2p::NetworkStateMonitor,
    /// Wall-clock start time for uptime reporting.
    pub start_time: Instant,
    /// Accumulated bandwidth served (bytes).
    pub bandwidth_served: u64,
    /// Accumulated bandwidth received (bytes).
    pub bandwidth_received: u64,
    /// Listen addresses announced at startup.
    pub listen_addresses: Vec<String>,
}

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Application state shared across Tauri commands.
pub struct AppState {
    /// Running node handle — None when node is not started.
    pub node_handle: Arc<Mutex<Option<NodeHandle>>>,
    /// Earnings state (persists across node start/stop cycles).
    pub earnings: Arc<RwLock<EarningsState>>,
    /// Application settings.
    pub settings: Arc<RwLock<AppSettings>>,
    /// Local gamification state (in-memory, v0.2.0).
    pub gamification: Arc<RwLock<LocalGamificationState>>,
    /// Ring buffer of recent transfer events (capacity 200).
    pub transfer_history: Arc<RwLock<VecDeque<TransferEntry>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            node_handle: Arc::new(Mutex::new(None)),
            earnings: Arc::new(RwLock::new(EarningsState::default())),
            settings: Arc::new(RwLock::new(AppSettings::default())),
            gamification: Arc::new(RwLock::new(LocalGamificationState::default())),
            transfer_history: Arc::new(RwLock::new(VecDeque::with_capacity(200))),
        }
    }
}

// ---------------------------------------------------------------------------
// Serializable DTO types (returned to the frontend)
// ---------------------------------------------------------------------------

/// Node running state — serialized snapshot for the UI.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeState {
    pub is_running: bool,
    pub node_id: Option<String>,
    pub connected_peers: usize,
    pub bandwidth_served: u64,
    pub bandwidth_received: u64,
    pub uptime_seconds: u64,
    pub storage_used: u64,
    pub storage_allocated: u64,
    pub status_message: String,
    pub last_error: Option<String>,
    pub listen_addresses: Vec<String>,
}

/// Earnings tracking state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EarningsState {
    pub total_earnings: u64,
    pub pending_earnings: u64,
    pub withdrawn_earnings: u64,
    pub daily_earnings: Vec<DailyEarning>,
    pub content_earnings: HashMap<String, u64>,
    pub last_updated: Option<String>,
}

/// Daily earning record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyEarning {
    pub date: String,
    pub amount: u64,
    pub bandwidth_gb: f64,
    pub transfers: u64,
}

/// Application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub storage_path: PathBuf,
    pub max_storage_bytes: u64,
    pub max_bandwidth_per_day: u64,
    pub auto_start: bool,
    pub minimize_to_tray: bool,
    pub start_minimized: bool,
    pub notifications_enabled: bool,
    pub tcp_port: u16,
    pub quic_port: u16,
    pub theme: String,
    pub onboarding_complete: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            storage_path: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("chie"),
            max_storage_bytes: 50 * 1024 * 1024 * 1024,
            max_bandwidth_per_day: 100 * 1024 * 1024 * 1024,
            auto_start: false,
            minimize_to_tray: true,
            start_minimized: false,
            notifications_enabled: true,
            tcp_port: 0,
            quic_port: 0,
            theme: "system".to_string(),
            onboarding_complete: false,
        }
    }
}

/// Pinned content info (UI DTO).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedContent {
    pub content_id: String,
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    pub pinned_at: String,
    pub total_earnings: u64,
    pub times_served: u64,
    pub category: String,
}

/// Transfer history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEntry {
    pub id: String,
    pub content_id: String,
    pub peer_id: String,
    pub direction: String,
    pub size: u64,
    pub timestamp: String,
    pub reward: u64,
    pub status: String,
}

/// Peer information (UI DTO).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    pub latency_ms: u32,
    pub bandwidth_score: f64,
    pub connected_since: String,
}

/// Earnings by content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentEarning {
    pub content_id: String,
    pub content_name: String,
    pub total_earned: u64,
    pub transfers: u64,
}

/// Storage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub used_bytes: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub content_count: u32,
    pub chunk_count: u32,
}

/// System information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub app_version: String,
    pub protocol_version: String,
}

// ---------------------------------------------------------------------------
// Gamification types
// ---------------------------------------------------------------------------

/// Local gamification tracker — mirrors progress based on node activity.
/// In v0.2.0 this is in-memory only; future versions will sync with coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalGamificationState {
    pub badges: Vec<String>,
    pub total_points: u64,
    pub monthly_points: u64,
    pub streak_days: u32,
    pub quests: Vec<LocalQuest>,
}

/// A single quest tracked locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalQuest {
    pub id: String,
    pub title: String,
    pub description: String,
    pub quest_type: String,
    pub current_progress: u64,
    pub target_progress: u64,
    pub reward_points: u64,
    pub status: String,     // "active", "completed", "expired"
    pub expires_at: String, // ISO8601 timestamp
}

impl Default for LocalGamificationState {
    fn default() -> Self {
        let now = chrono::Utc::now();
        let tomorrow = now + chrono::TimeDelta::hours(24);
        let next_week = now + chrono::TimeDelta::days(7);

        Self {
            badges: Vec::new(),
            total_points: 0,
            monthly_points: 0,
            streak_days: 0,
            quests: vec![
                LocalQuest {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Daily Uptime".to_string(),
                    description: "Stay online for 12 hours today".to_string(),
                    quest_type: "DailyUptime".to_string(),
                    current_progress: 0,
                    target_progress: 43200, // 12 hours in seconds
                    reward_points: 100,
                    status: "active".to_string(),
                    expires_at: tomorrow.to_rfc3339(),
                },
                LocalQuest {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Weekly Bandwidth".to_string(),
                    description: "Provide 10 GB of bandwidth this week".to_string(),
                    quest_type: "WeeklyBandwidth".to_string(),
                    current_progress: 0,
                    target_progress: 10_737_418_240, // 10 GB in bytes
                    reward_points: 500,
                    status: "active".to_string(),
                    expires_at: next_week.to_rfc3339(),
                },
                LocalQuest {
                    id: uuid::Uuid::new_v4().to_string(),
                    title: "Daily Proof Submission".to_string(),
                    description: "Submit 10 bandwidth proofs today".to_string(),
                    quest_type: "DailyProofSubmission".to_string(),
                    current_progress: 0,
                    target_progress: 10,
                    reward_points: 150,
                    status: "active".to_string(),
                    expires_at: tomorrow.to_rfc3339(),
                },
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: build NodeState snapshot from a running NodeHandle
// ---------------------------------------------------------------------------

async fn snapshot_running(handle: &NodeHandle) -> NodeState {
    let uptime_seconds = handle.start_time.elapsed().as_secs();
    let node_id = Some(hex::encode(&handle.content_node.public_key()[..8]));

    let metrics = handle.network_monitor.current_metrics();

    // Storage stats — best-effort; fall back to zeros when unavailable.
    let storage_used = match handle.content_node.storage_stats().await {
        Some(stats) => stats.used_bytes,
        None => 0,
    };

    NodeState {
        is_running: true,
        node_id,
        connected_peers: metrics.connected_peers,
        bandwidth_served: handle.bandwidth_served,
        bandwidth_received: handle.bandwidth_received,
        uptime_seconds,
        storage_used,
        storage_allocated: handle.content_node.config().max_storage_bytes,
        status_message: "Node is running".to_string(),
        last_error: None,
        listen_addresses: handle.listen_addresses.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

mod commands {
    use super::*;

    /// Start the CHIE node.
    ///
    /// Initialises a `ContentNode` with storage and a fresh `NetworkStateMonitor`,
    /// then stores a `NodeHandle` in AppState.
    #[tauri::command]
    pub async fn start_node(state: State<'_, AppState>) -> Result<NodeState, String> {
        let mut handle_guard = state.node_handle.lock().await;

        if handle_guard.is_some() {
            return Err("Node is already running".to_string());
        }

        let settings = state.settings.read().await;

        let tcp_port = if settings.tcp_port == 0 {
            4001
        } else {
            settings.tcp_port
        };
        let quic_port = if settings.quic_port == 0 {
            4002
        } else {
            settings.quic_port
        };

        let config = chie_core::NodeConfig {
            storage_path: settings.storage_path.clone(),
            max_storage_bytes: settings.max_storage_bytes,
            max_bandwidth_bps: settings.max_bandwidth_per_day / 86_400,
            coordinator_url: "https://coordinator.chie.network".to_string(),
        };

        // Drop the settings lock before the async storage init.
        drop(settings);

        let content_node = chie_core::ContentNode::with_storage(config)
            .await
            .map_err(|e| format!("Failed to initialise node storage: {e}"))?;

        let network_monitor = chie_p2p::NetworkStateMonitor::new();

        let listen_addresses = vec![
            format!("/ip4/0.0.0.0/tcp/{tcp_port}"),
            format!("/ip4/0.0.0.0/udp/{quic_port}/quic-v1"),
        ];

        let handle = NodeHandle {
            content_node,
            network_monitor,
            start_time: Instant::now(),
            bandwidth_served: 0,
            bandwidth_received: 0,
            listen_addresses,
        };

        let state_snapshot = snapshot_running(&handle).await;
        *handle_guard = Some(handle);

        tracing::info!("CHIE node started");
        Ok(state_snapshot)
    }

    /// Stop the running CHIE node.
    #[tauri::command]
    pub async fn stop_node(state: State<'_, AppState>) -> Result<NodeState, String> {
        let mut handle_guard = state.node_handle.lock().await;

        if handle_guard.is_none() {
            return Err("Node is not running".to_string());
        }

        // Snapshot final state before dropping.
        let final_snapshot = if let Some(ref handle) = *handle_guard {
            let mut snap = snapshot_running(handle).await;
            snap.is_running = false;
            snap.status_message = "Node stopped".to_string();
            snap.connected_peers = 0;
            snap.listen_addresses = vec![];
            snap
        } else {
            NodeState::default()
        };

        // Drop the handle — this cleanly releases all resources.
        *handle_guard = None;

        tracing::info!("CHIE node stopped");
        Ok(final_snapshot)
    }

    /// Return a live snapshot of the node status.
    #[tauri::command]
    pub async fn get_node_status(state: State<'_, AppState>) -> Result<NodeState, String> {
        let handle_guard = state.node_handle.lock().await;
        match &*handle_guard {
            Some(handle) => Ok(snapshot_running(handle).await),
            None => Ok(NodeState {
                is_running: false,
                status_message: "Node is not running".to_string(),
                ..Default::default()
            }),
        }
    }

    /// Return the list of currently connected peers.
    ///
    /// Derives peer info from the `NetworkStateMonitor`. Until an actual libp2p
    /// swarm is integrated the list will be empty — that is correct, not mock.
    #[tauri::command]
    pub async fn get_connected_peers(state: State<'_, AppState>) -> Result<Vec<PeerInfo>, String> {
        let handle_guard = state.node_handle.lock().await;
        let handle = match &*handle_guard {
            Some(h) => h,
            None => return Ok(vec![]),
        };

        let now = chrono::Utc::now().to_rfc3339();

        let peers = handle
            .network_monitor
            .peer_statuses()
            .into_iter()
            .filter(|p| p.connected)
            .map(|p| PeerInfo {
                peer_id: p.peer_id.to_string(),
                address: String::new(), // address is not tracked in PeerStatus
                latency_ms: p.latency_ms as u32,
                bandwidth_score: p.quality,
                connected_since: now.clone(),
            })
            .collect();

        Ok(peers)
    }

    /// Return earnings state.
    #[tauri::command]
    pub async fn get_earnings(state: State<'_, AppState>) -> Result<EarningsState, String> {
        // Sync earnings from the live node if running.
        let handle_guard = state.node_handle.lock().await;
        let mut earnings = state.earnings.write().await;

        if let Some(ref handle) = *handle_guard {
            earnings.total_earnings = handle.content_node.earnings();
        }
        earnings.last_updated = Some(chrono::Utc::now().to_rfc3339());
        Ok(earnings.clone())
    }

    /// Return paginated earnings history.
    #[tauri::command]
    pub async fn get_earnings_history(
        state: State<'_, AppState>,
        days: u32,
    ) -> Result<Vec<DailyEarning>, String> {
        let earnings = state.earnings.read().await;
        let history: Vec<DailyEarning> = earnings
            .daily_earnings
            .iter()
            .rev()
            .take(days as usize)
            .cloned()
            .collect();
        Ok(history)
    }

    /// Return earnings broken down by content CID.
    #[tauri::command]
    pub async fn get_earnings_by_content(
        state: State<'_, AppState>,
    ) -> Result<Vec<ContentEarning>, String> {
        let earnings = state.earnings.read().await;
        let content_earnings: Vec<ContentEarning> = earnings
            .content_earnings
            .iter()
            .map(|(content_id, amount)| ContentEarning {
                content_id: content_id.clone(),
                content_name: format!("Content {}", &content_id[..8.min(content_id.len())]),
                total_earned: *amount,
                transfers: 0,
            })
            .collect();
        Ok(content_earnings)
    }

    /// Return pinned content list from the live ContentNode.
    ///
    /// Returns an empty list when the node is not running.
    #[tauri::command]
    pub async fn get_pinned_content(
        state: State<'_, AppState>,
    ) -> Result<Vec<PinnedContent>, String> {
        let handle_guard = state.node_handle.lock().await;
        let handle = match &*handle_guard {
            Some(h) => h,
            None => return Ok(vec![]),
        };

        let now = chrono::Utc::now().to_rfc3339();

        let contents = handle
            .content_node
            .pinned_contents()
            .values()
            .map(|c| PinnedContent {
                content_id: c.cid.clone(),
                name: format!("Content {}", &c.cid[..8.min(c.cid.len())]),
                size: c.size_bytes,
                chunks: c.size_bytes.div_ceil(262144) as u32, // 256 KiB chunks
                pinned_at: now.clone(),
                total_earnings: 0,
                times_served: 0,
                category: "Unknown".to_string(),
            })
            .collect();

        Ok(contents)
    }

    /// Pin a new content item.
    #[tauri::command]
    pub async fn pin_content(
        state: State<'_, AppState>,
        content_id: String,
    ) -> Result<PinnedContent, String> {
        if content_id.is_empty() {
            return Err("Content ID cannot be empty".to_string());
        }

        let mut handle_guard = state.node_handle.lock().await;
        let handle = match &mut *handle_guard {
            Some(h) => h,
            None => return Err("Node is not running".to_string()),
        };

        let pinned = chie_core::PinnedContent {
            cid: content_id.clone(),
            size_bytes: 0, // Size unknown until content is retrieved
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 0.0,
        };
        handle.content_node.pin_content(pinned);

        Ok(PinnedContent {
            content_id: content_id.clone(),
            name: format!("Content {}", &content_id[..8.min(content_id.len())]),
            size: 0,
            chunks: 0,
            pinned_at: chrono::Utc::now().to_rfc3339(),
            total_earnings: 0,
            times_served: 0,
            category: "Unknown".to_string(),
        })
    }

    /// Unpin a content item.
    #[tauri::command]
    pub async fn unpin_content(
        state: State<'_, AppState>,
        content_id: String,
    ) -> Result<bool, String> {
        if content_id.is_empty() {
            return Err("Content ID cannot be empty".to_string());
        }

        let mut handle_guard = state.node_handle.lock().await;
        let handle = match &mut *handle_guard {
            Some(h) => h,
            None => return Err("Node is not running".to_string()),
        };

        let removed = handle.content_node.unpin_content(&content_id).is_some();
        Ok(removed)
    }

    /// Return transfer history (most-recent-first, up to `limit` entries).
    #[tauri::command]
    pub async fn get_transfer_history(
        state: State<'_, AppState>,
        limit: u32,
    ) -> Result<Vec<TransferEntry>, String> {
        let history = state.transfer_history.read().await;
        let entries: Vec<TransferEntry> =
            history.iter().rev().take(limit as usize).cloned().collect();
        Ok(entries)
    }

    /// Record a transfer event (called when a chunk is served or received).
    #[tauri::command]
    pub async fn record_transfer(
        state: State<'_, AppState>,
        content_id: String,
        peer_id: String,
        direction: String,
        size: u64,
        reward: u64,
    ) -> Result<(), String> {
        let entry = TransferEntry {
            id: uuid::Uuid::new_v4().to_string(),
            content_id,
            peer_id,
            direction,
            size,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reward,
            status: "completed".to_string(),
        };
        let mut history = state.transfer_history.write().await;
        if history.len() >= 200 {
            history.pop_front();
        }
        history.push_back(entry);
        Ok(())
    }

    /// Return current settings.
    #[tauri::command]
    pub async fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
        let settings = state.settings.read().await;
        Ok(settings.clone())
    }

    /// Persist settings to disk (JSON file in app data dir).
    async fn save_settings_to_disk(settings: &AppSettings) {
        let Some(data_dir) = dirs::data_local_dir() else {
            return;
        };
        let dir = data_dir.join("chie");
        if tokio::fs::create_dir_all(&dir).await.is_err() {
            return;
        }
        let path = dir.join("settings.json");
        let Ok(json) = serde_json::to_string_pretty(settings) else {
            return;
        };
        let _ = tokio::fs::write(&path, json).await;
    }

    /// Load persisted settings from disk, returning None if not found or parse error.
    async fn load_settings_from_disk() -> Option<AppSettings> {
        let dir = dirs::data_local_dir()?.join("chie");
        let path = dir.join("settings.json");
        let bytes = tokio::fs::read(&path).await.ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Update application settings and persist to disk.
    #[tauri::command]
    pub async fn update_settings(
        state: State<'_, AppState>,
        new_settings: AppSettings,
    ) -> Result<AppSettings, String> {
        let mut settings = state.settings.write().await;
        *settings = new_settings;
        let settings_clone = settings.clone();
        drop(settings); // release lock before async IO
        save_settings_to_disk(&settings_clone).await;
        Ok(settings_clone)
    }

    /// Load previously saved settings from disk (called once at app startup).
    #[tauri::command]
    pub async fn load_persisted_settings(
        state: State<'_, AppState>,
    ) -> Result<AppSettings, String> {
        if let Some(loaded) = load_settings_from_disk().await {
            let mut settings = state.settings.write().await;
            *settings = loaded;
            Ok(settings.clone())
        } else {
            let settings = state.settings.read().await;
            Ok(settings.clone())
        }
    }

    /// Return storage statistics sourced from the live ContentNode.
    #[tauri::command]
    pub async fn get_storage_stats(state: State<'_, AppState>) -> Result<StorageStats, String> {
        let handle_guard = state.node_handle.lock().await;
        let settings = state.settings.read().await;

        match &*handle_guard {
            Some(handle) => {
                let (used_bytes, content_count) = match handle.content_node.storage_stats().await {
                    Some(stats) => (stats.used_bytes, stats.pinned_content_count as u32),
                    None => (0, handle.content_node.pinned_count() as u32),
                };
                Ok(StorageStats {
                    used_bytes,
                    allocated_bytes: settings.max_storage_bytes,
                    free_bytes: settings.max_storage_bytes.saturating_sub(used_bytes),
                    content_count,
                    chunk_count: 0, // chunk-level count not exposed by StorageStats
                })
            }
            None => Ok(StorageStats {
                used_bytes: 0,
                allocated_bytes: settings.max_storage_bytes,
                free_bytes: settings.max_storage_bytes,
                content_count: 0,
                chunk_count: 0,
            }),
        }
    }

    /// Return static system information.
    #[tauri::command]
    pub async fn get_system_info() -> Result<SystemInfo, String> {
        Ok(SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "1.0.0".to_string(),
        })
    }

    /// Open a URL in the system browser.
    #[tauri::command]
    pub async fn open_external_url(url: String) -> Result<(), String> {
        open::that(&url).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Return the application data directory path.
    #[tauri::command]
    pub async fn get_app_data_dir() -> Result<String, String> {
        let dir = dirs::data_local_dir()
            .ok_or_else(|| "Could not determine data directory".to_string())?
            .join("chie");
        Ok(dir.to_string_lossy().to_string())
    }

    /// Return the current local gamification state.
    #[tauri::command]
    pub async fn get_gamification_state(
        state: State<'_, AppState>,
    ) -> Result<LocalGamificationState, String> {
        let gamification = state.gamification.read().await;
        Ok(gamification.clone())
    }

    /// Update quest progress (called as the node serves bandwidth/uptime).
    ///
    /// Returns `true` when the quest was just completed by this update.
    #[tauri::command]
    pub async fn update_quest_progress(
        quest_id: String,
        increment: u64,
        state: State<'_, AppState>,
    ) -> Result<bool, String> {
        let mut gamification = state.gamification.write().await;
        let mut reward_to_add: Option<u64> = None;

        for quest in &mut gamification.quests {
            if quest.id == quest_id && quest.status == "active" {
                quest.current_progress = quest.current_progress.saturating_add(increment);
                if quest.current_progress >= quest.target_progress {
                    quest.status = "completed".to_string();
                    reward_to_add = Some(quest.reward_points);
                }
                break;
            }
        }

        if let Some(reward) = reward_to_add {
            gamification.total_points = gamification.total_points.saturating_add(reward);
            gamification.monthly_points = gamification.monthly_points.saturating_add(reward);
            return Ok(true);
        }
        Ok(false)
    }

    /// Check if first-run onboarding has been completed.
    #[tauri::command]
    pub async fn is_onboarding_complete(state: State<'_, AppState>) -> Result<bool, String> {
        let settings = state.settings.read().await;
        Ok(settings.onboarding_complete)
    }

    /// Mark onboarding as complete and apply initial settings.
    #[tauri::command]
    pub async fn complete_onboarding(
        storage_path: String,
        max_storage_gb: u64,
        max_bandwidth_gb: u64,
        auto_start: bool,
        state: State<'_, AppState>,
    ) -> Result<(), String> {
        let mut settings = state.settings.write().await;
        let path = std::path::PathBuf::from(&storage_path);
        settings.storage_path = path;
        settings.max_storage_bytes = max_storage_gb * 1024 * 1024 * 1024;
        settings.max_bandwidth_per_day = max_bandwidth_gb * 1024 * 1024 * 1024;
        settings.auto_start = auto_start;
        settings.onboarding_complete = true;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tauri entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let directive = "chie_desktop=debug"
        .parse()
        .expect("hardcoded tracing directive is always valid");

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(directive))
        .init();

    tracing::info!("Starting CHIE Desktop Client...");

    let app_state = AppState::default();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::start_node,
            commands::stop_node,
            commands::get_node_status,
            commands::get_connected_peers,
            commands::get_earnings,
            commands::get_earnings_history,
            commands::get_earnings_by_content,
            commands::get_pinned_content,
            commands::pin_content,
            commands::unpin_content,
            commands::get_transfer_history,
            commands::record_transfer,
            commands::get_settings,
            commands::update_settings,
            commands::load_persisted_settings,
            commands::get_storage_stats,
            commands::get_system_info,
            commands::open_external_url,
            commands::get_app_data_dir,
            commands::get_gamification_state,
            commands::update_quest_progress,
            commands::is_onboarding_complete,
            commands::complete_onboarding,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
