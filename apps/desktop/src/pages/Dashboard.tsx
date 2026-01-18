import { useState, useEffect } from "react";
import {
  Play,
  Square,
  Activity,
  HardDrive,
  Users,
  ArrowUpRight,
  ArrowDownLeft,
  Clock,
} from "lucide-react";
import {
  nodeApi,
  earningsApi,
  settingsApi,
  NodeState,
  EarningsState,
  StorageStats,
  formatBytes,
  formatDuration,
  formatCurrency,
} from "../lib/api";

function Dashboard() {
  const [nodeState, setNodeState] = useState<NodeState | null>(null);
  const [earnings, setEarnings] = useState<EarningsState | null>(null);
  const [storage, setStorage] = useState<StorageStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [nodeData, earningsData, storageData] = await Promise.all([
        nodeApi.getStatus(),
        earningsApi.get(),
        settingsApi.getStorageStats(),
      ]);
      setNodeState(nodeData);
      setEarnings(earningsData);
      setStorage(storageData);
    } catch (error) {
      console.error("Failed to load data:", error);
    } finally {
      setLoading(false);
    }
  }

  async function handleStartNode() {
    setActionLoading(true);
    try {
      const state = await nodeApi.start();
      setNodeState(state);
    } catch (error) {
      console.error("Failed to start node:", error);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleStopNode() {
    setActionLoading(true);
    try {
      const state = await nodeApi.stop();
      setNodeState(state);
    } catch (error) {
      console.error("Failed to stop node:", error);
    } finally {
      setActionLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading...</div>
      </div>
    );
  }

  const isRunning = nodeState?.is_running ?? false;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Monitor your CHIE node status</p>
        </div>
      </div>

      {/* Node Control */}
      <div className="node-control">
        <div className="node-control-info">
          <div className="flex items-center gap-md mb-sm">
            <span
              className={`status-indicator ${isRunning ? "running" : "stopped"}`}
            >
              <span className={`status-dot ${isRunning ? "running" : "stopped"}`} />
              {isRunning ? "Running" : "Stopped"}
            </span>
            {nodeState?.node_id && (
              <span className="text-muted" style={{ fontSize: "12px" }}>
                ID: {nodeState.node_id}
              </span>
            )}
          </div>
          <p className="text-muted" style={{ fontSize: "14px" }}>
            {nodeState?.status_message || "Node is not running"}
          </p>
          {nodeState?.listen_addresses && nodeState.listen_addresses.length > 0 && (
            <p className="text-muted" style={{ fontSize: "12px", marginTop: "4px" }}>
              Listening: {nodeState.listen_addresses.join(", ")}
            </p>
          )}
        </div>
        <div className="node-control-actions">
          {isRunning ? (
            <button
              className="btn btn-danger"
              onClick={handleStopNode}
              disabled={actionLoading}
            >
              <Square size={16} />
              Stop Node
            </button>
          ) : (
            <button
              className="btn btn-success"
              onClick={handleStartNode}
              disabled={actionLoading}
            >
              <Play size={16} />
              Start Node
            </button>
          )}
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon success">
            <Activity size={20} />
          </div>
          <div className="stat-value">{nodeState?.connected_peers ?? 0}</div>
          <div className="stat-label">Connected Peers</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon primary">
            <ArrowUpRight size={20} />
          </div>
          <div className="stat-value">
            {formatBytes(nodeState?.bandwidth_served ?? 0)}
          </div>
          <div className="stat-label">Uploaded</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon info">
            <ArrowDownLeft size={20} />
          </div>
          <div className="stat-value">
            {formatBytes(nodeState?.bandwidth_received ?? 0)}
          </div>
          <div className="stat-label">Downloaded</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon warning">
            <Clock size={20} />
          </div>
          <div className="stat-value">
            {formatDuration(nodeState?.uptime_seconds ?? 0)}
          </div>
          <div className="stat-label">Uptime</div>
        </div>
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-2 gap-md">
        {/* Earnings Overview */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Earnings Overview</h3>
          </div>
          <div className="stats-grid" style={{ marginBottom: 0 }}>
            <div>
              <div className="stat-value text-success">
                {formatCurrency(earnings?.total_earnings ?? 0)}
              </div>
              <div className="stat-label">Total Earned</div>
            </div>
            <div>
              <div className="stat-value text-warning">
                {formatCurrency(earnings?.pending_earnings ?? 0)}
              </div>
              <div className="stat-label">Pending</div>
            </div>
          </div>
        </div>

        {/* Storage Overview */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Storage</h3>
            <span className="text-muted">
              {storage?.content_count ?? 0} items, {storage?.chunk_count ?? 0} chunks
            </span>
          </div>
          <div className="mb-sm">
            <div className="flex justify-between mb-sm">
              <span className="text-muted">
                {formatBytes(storage?.used_bytes ?? 0)} used
              </span>
              <span className="text-muted">
                {formatBytes(storage?.allocated_bytes ?? 0)} allocated
              </span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{
                  width: `${
                    storage?.allocated_bytes
                      ? ((storage.used_bytes / storage.allocated_bytes) * 100).toFixed(1)
                      : 0
                  }%`,
                }}
              />
            </div>
          </div>
          <div className="flex items-center gap-sm">
            <HardDrive size={16} className="text-muted" />
            <span className="text-muted">
              {formatBytes(storage?.free_bytes ?? 0)} available
            </span>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {nodeState?.last_error && (
        <div
          className="card mt-md"
          style={{ borderColor: "var(--color-danger)" }}
        >
          <div className="flex items-center gap-sm text-danger">
            <span style={{ fontWeight: 500 }}>Error:</span>
            <span>{nodeState.last_error}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
