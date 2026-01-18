//! CHIE Desktop Client - Tauri Backend
//!
//! This module provides the Rust backend for the CHIE desktop client,
//! including node control, earnings tracking, and content management.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;

/// Application state shared across commands.
pub struct AppState {
    /// Node state.
    pub node: Arc<RwLock<NodeState>>,
    /// Earnings state.
    pub earnings: Arc<RwLock<EarningsState>>,
    /// Settings.
    pub settings: Arc<RwLock<AppSettings>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            node: Arc::new(RwLock::new(NodeState::default())),
            earnings: Arc::new(RwLock::new(EarningsState::default())),
            settings: Arc::new(RwLock::new(AppSettings::default())),
        }
    }
}

/// Node running state.
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
        }
    }
}

/// Pinned content info.
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

/// Peer information.
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

// Tauri Commands
mod commands {
    use super::*;

    #[tauri::command]
    pub async fn start_node(state: State<'_, AppState>) -> Result<NodeState, String> {
        let mut node_state = state.node.write().await;
        let settings = state.settings.read().await;

        if node_state.is_running {
            return Err("Node is already running".to_string());
        }

        if node_state.node_id.is_none() {
            let keypair = chie_crypto::KeyPair::generate();
            let public_key = keypair.public_key();
            node_state.node_id = Some(hex::encode(&public_key[..8]));
        }

        node_state.is_running = true;
        node_state.status_message = "Node started successfully".to_string();
        node_state.uptime_seconds = 0;
        node_state.last_error = None;
        node_state.listen_addresses = vec![
            format!(
                "/ip4/0.0.0.0/tcp/{}",
                if settings.tcp_port == 0 {
                    4001
                } else {
                    settings.tcp_port
                }
            ),
            format!(
                "/ip4/0.0.0.0/udp/{}/quic-v1",
                if settings.quic_port == 0 {
                    4002
                } else {
                    settings.quic_port
                }
            ),
        ];

        Ok(node_state.clone())
    }

    #[tauri::command]
    pub async fn stop_node(state: State<'_, AppState>) -> Result<NodeState, String> {
        let mut node_state = state.node.write().await;

        if !node_state.is_running {
            return Err("Node is not running".to_string());
        }

        node_state.is_running = false;
        node_state.status_message = "Node stopped".to_string();
        node_state.connected_peers = 0;
        node_state.listen_addresses.clear();

        Ok(node_state.clone())
    }

    #[tauri::command]
    pub async fn get_node_status(state: State<'_, AppState>) -> Result<NodeState, String> {
        let node_state = state.node.read().await;
        Ok(node_state.clone())
    }

    #[tauri::command]
    pub async fn get_connected_peers(state: State<'_, AppState>) -> Result<Vec<PeerInfo>, String> {
        let node_state = state.node.read().await;

        if !node_state.is_running {
            return Ok(vec![]);
        }

        Ok(vec![
            PeerInfo {
                peer_id: "12D3KooWA1b2c3d4".to_string(),
                address: "/ip4/192.168.1.100/tcp/4001".to_string(),
                latency_ms: 15,
                bandwidth_score: 0.95,
                connected_since: chrono::Utc::now().to_rfc3339(),
            },
            PeerInfo {
                peer_id: "12D3KooWE5f6g7h8".to_string(),
                address: "/ip4/10.0.0.50/udp/4002/quic-v1".to_string(),
                latency_ms: 8,
                bandwidth_score: 0.88,
                connected_since: chrono::Utc::now().to_rfc3339(),
            },
        ])
    }

    #[tauri::command]
    pub async fn get_earnings(state: State<'_, AppState>) -> Result<EarningsState, String> {
        let mut earnings = state.earnings.write().await;
        earnings.last_updated = Some(chrono::Utc::now().to_rfc3339());
        Ok(earnings.clone())
    }

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

    #[tauri::command]
    pub async fn get_pinned_content(
        _state: State<'_, AppState>,
    ) -> Result<Vec<PinnedContent>, String> {
        Ok(vec![
            PinnedContent {
                content_id: "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string(),
                name: "Sample AI Model".to_string(),
                size: 4_500_000_000,
                chunks: 450,
                pinned_at: chrono::Utc::now().to_rfc3339(),
                total_earnings: 15000,
                times_served: 42,
                category: "AI Model".to_string(),
            },
            PinnedContent {
                content_id: "QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx".to_string(),
                name: "Digital Art Collection".to_string(),
                size: 850_000_000,
                chunks: 85,
                pinned_at: chrono::Utc::now().to_rfc3339(),
                total_earnings: 8500,
                times_served: 128,
                category: "Digital Art".to_string(),
            },
        ])
    }

    #[tauri::command]
    pub async fn pin_content(
        _state: State<'_, AppState>,
        content_id: String,
    ) -> Result<PinnedContent, String> {
        if content_id.is_empty() {
            return Err("Content ID cannot be empty".to_string());
        }

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

    #[tauri::command]
    pub async fn unpin_content(
        _state: State<'_, AppState>,
        content_id: String,
    ) -> Result<bool, String> {
        if content_id.is_empty() {
            return Err("Content ID cannot be empty".to_string());
        }
        Ok(true)
    }

    #[tauri::command]
    pub async fn get_transfer_history(
        _state: State<'_, AppState>,
        limit: u32,
    ) -> Result<Vec<TransferEntry>, String> {
        let mut transfers = vec![];
        for i in 0..limit.min(10) {
            transfers.push(TransferEntry {
                id: uuid::Uuid::new_v4().to_string(),
                content_id: format!("Qm{:032x}", i),
                peer_id: format!("12D3KooW{:08x}", i * 1000),
                direction: if i % 2 == 0 { "upload" } else { "download" }.to_string(),
                size: 10_000_000 + (i as u64 * 1_000_000),
                timestamp: chrono::Utc::now().to_rfc3339(),
                reward: if i % 2 == 0 { 100 + i as u64 * 10 } else { 0 },
                status: "completed".to_string(),
            });
        }
        Ok(transfers)
    }

    #[tauri::command]
    pub async fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
        let settings = state.settings.read().await;
        Ok(settings.clone())
    }

    #[tauri::command]
    pub async fn update_settings(
        state: State<'_, AppState>,
        new_settings: AppSettings,
    ) -> Result<AppSettings, String> {
        let mut settings = state.settings.write().await;
        *settings = new_settings;
        Ok(settings.clone())
    }

    #[tauri::command]
    pub async fn get_storage_stats(state: State<'_, AppState>) -> Result<StorageStats, String> {
        let node_state = state.node.read().await;
        let settings = state.settings.read().await;

        Ok(StorageStats {
            used_bytes: node_state.storage_used,
            allocated_bytes: settings.max_storage_bytes,
            free_bytes: settings
                .max_storage_bytes
                .saturating_sub(node_state.storage_used),
            content_count: 2,
            chunk_count: 535,
        })
    }

    #[tauri::command]
    pub async fn get_system_info() -> Result<SystemInfo, String> {
        Ok(SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "1.0.0".to_string(),
        })
    }

    #[tauri::command]
    pub async fn open_external_url(url: String) -> Result<(), String> {
        open::that(&url).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[tauri::command]
    pub async fn get_app_data_dir() -> Result<String, String> {
        let dir = dirs::data_local_dir()
            .ok_or_else(|| "Could not determine data directory".to_string())?
            .join("chie");
        Ok(dir.to_string_lossy().to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("chie_desktop=debug".parse().unwrap()),
        )
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
            commands::get_settings,
            commands::update_settings,
            commands::get_storage_stats,
            commands::get_system_info,
            commands::open_external_url,
            commands::get_app_data_dir,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
