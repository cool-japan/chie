import { invoke } from "@tauri-apps/api/core";

// Types matching Rust backend
export interface NodeState {
  is_running: boolean;
  node_id: string | null;
  connected_peers: number;
  bandwidth_served: number;
  bandwidth_received: number;
  uptime_seconds: number;
  storage_used: number;
  storage_allocated: number;
  status_message: string;
  last_error: string | null;
  listen_addresses: string[];
}

export interface EarningsState {
  total_earnings: number;
  pending_earnings: number;
  withdrawn_earnings: number;
  daily_earnings: DailyEarning[];
  content_earnings: Record<string, number>;
  last_updated: string | null;
}

export interface DailyEarning {
  date: string;
  amount: number;
  bandwidth_gb: number;
  transfers: number;
}

export interface AppSettings {
  storage_path: string;
  max_storage_bytes: number;
  max_bandwidth_per_day: number;
  auto_start: boolean;
  minimize_to_tray: boolean;
  start_minimized: boolean;
  notifications_enabled: boolean;
  tcp_port: number;
  quic_port: number;
  theme: string;
}

export interface PinnedContent {
  content_id: string;
  name: string;
  size: number;
  chunks: number;
  pinned_at: string;
  total_earnings: number;
  times_served: number;
  category: string;
}

export interface TransferEntry {
  id: string;
  content_id: string;
  peer_id: string;
  direction: string;
  size: number;
  timestamp: string;
  reward: number;
  status: string;
}

export interface PeerInfo {
  peer_id: string;
  address: string;
  latency_ms: number;
  bandwidth_score: number;
  connected_since: string;
}

export interface StorageStats {
  used_bytes: number;
  allocated_bytes: number;
  free_bytes: number;
  content_count: number;
  chunk_count: number;
}

export interface SystemInfo {
  os: string;
  arch: string;
  app_version: string;
  protocol_version: string;
}

export interface ContentEarning {
  content_id: string;
  content_name: string;
  total_earned: number;
  transfers: number;
}

// Node Control API
export const nodeApi = {
  start: () => invoke<NodeState>("start_node"),
  stop: () => invoke<NodeState>("stop_node"),
  getStatus: () => invoke<NodeState>("get_node_status"),
  getPeers: () => invoke<PeerInfo[]>("get_connected_peers"),
};

// Earnings API
export const earningsApi = {
  get: () => invoke<EarningsState>("get_earnings"),
  getHistory: (days: number) =>
    invoke<DailyEarning[]>("get_earnings_history", { days }),
  getByContent: () => invoke<ContentEarning[]>("get_earnings_by_content"),
};

// Content/Pinning API
export const contentApi = {
  getPinned: () => invoke<PinnedContent[]>("get_pinned_content"),
  pin: (contentId: string) =>
    invoke<PinnedContent>("pin_content", { contentId }),
  unpin: (contentId: string) =>
    invoke<boolean>("unpin_content", { contentId }),
  getTransferHistory: (limit: number) =>
    invoke<TransferEntry[]>("get_transfer_history", { limit }),
};

// Settings API
export const settingsApi = {
  get: () => invoke<AppSettings>("get_settings"),
  update: (settings: AppSettings) =>
    invoke<AppSettings>("update_settings", { newSettings: settings }),
  getStorageStats: () => invoke<StorageStats>("get_storage_stats"),
};

// System API
export const systemApi = {
  getInfo: () => invoke<SystemInfo>("get_system_info"),
  openUrl: (url: string) => invoke<void>("open_external_url", { url }),
  getDataDir: () => invoke<string>("get_app_data_dir"),
};

// Utility functions
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

export function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num);
}

export function formatCurrency(amount: number): string {
  // Amount is in smallest unit, convert to display currency
  return `${(amount / 100).toFixed(2)} CHIE`;
}
