import { useState, useEffect } from "react";
import { Users, Globe, Wifi, Clock, RefreshCw, Signal } from "lucide-react";
import { nodeApi, PeerInfo, NodeState } from "../lib/api";

function Peers() {
  const [peers, setPeers] = useState<PeerInfo[]>([]);
  const [nodeState, setNodeState] = useState<NodeState | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const [peerData, nodeData] = await Promise.all([
        nodeApi.getPeers(),
        nodeApi.getStatus(),
      ]);
      setPeers(peerData);
      setNodeState(nodeData);
    } catch (error) {
      console.error("Failed to load peers:", error);
    } finally {
      setLoading(false);
    }
  }

  function getLatencyColor(latency: number): string {
    if (latency < 50) return "var(--color-success)";
    if (latency < 150) return "var(--color-warning)";
    return "var(--color-danger)";
  }

  function getScoreColor(score: number): string {
    if (score >= 0.8) return "var(--color-success)";
    if (score >= 0.5) return "var(--color-warning)";
    return "var(--color-danger)";
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading peers...</div>
      </div>
    );
  }

  const isRunning = nodeState?.is_running ?? false;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Peers</h1>
          <p className="page-subtitle">Connected nodes in the CHIE network</p>
        </div>
        <button className="btn btn-outline" onClick={loadData}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Connection Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon success">
            <Users size={20} />
          </div>
          <div className="stat-value">{peers.length}</div>
          <div className="stat-label">Connected Peers</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon primary">
            <Globe size={20} />
          </div>
          <div className="stat-value">
            {nodeState?.listen_addresses?.length ?? 0}
          </div>
          <div className="stat-label">Listen Addresses</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon info">
            <Signal size={20} />
          </div>
          <div className="stat-value">
            {peers.length > 0
              ? `${Math.round(
                  peers.reduce((sum, p) => sum + p.latency_ms, 0) / peers.length
                )}ms`
              : "-"}
          </div>
          <div className="stat-label">Avg Latency</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon warning">
            <Wifi size={20} />
          </div>
          <div className="stat-value">
            {peers.length > 0
              ? `${(
                  (peers.reduce((sum, p) => sum + p.bandwidth_score, 0) /
                    peers.length) *
                  100
                ).toFixed(0)}%`
              : "-"}
          </div>
          <div className="stat-label">Avg Score</div>
        </div>
      </div>

      {/* Listen Addresses */}
      {nodeState?.listen_addresses && nodeState.listen_addresses.length > 0 && (
        <div className="card mb-lg">
          <div className="card-header">
            <h3 className="card-title">Your Listen Addresses</h3>
          </div>
          <div className="flex flex-col gap-sm">
            {nodeState.listen_addresses.map((addr, index) => (
              <div
                key={index}
                className="flex items-center gap-sm"
                style={{
                  padding: "8px 12px",
                  backgroundColor: "var(--bg-tertiary)",
                  borderRadius: "var(--border-radius)",
                  fontFamily: "monospace",
                  fontSize: "13px",
                }}
              >
                <Globe size={14} className="text-muted" />
                {addr}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Peers List */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Connected Peers</h3>
        </div>

        {!isRunning ? (
          <div className="empty-state">
            <Wifi />
            <h3>Node not running</h3>
            <p>Start your node to connect to peers</p>
          </div>
        ) : peers.length > 0 ? (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Peer ID</th>
                  <th>Address</th>
                  <th>Latency</th>
                  <th>Score</th>
                  <th>Connected</th>
                </tr>
              </thead>
              <tbody>
                {peers.map((peer) => (
                  <tr key={peer.peer_id}>
                    <td>
                      <div className="flex items-center gap-sm">
                        <div
                          style={{
                            width: "8px",
                            height: "8px",
                            borderRadius: "50%",
                            backgroundColor: "var(--color-success)",
                          }}
                        />
                        <span style={{ fontFamily: "monospace", fontSize: "13px" }}>
                          {peer.peer_id}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span
                        className="text-muted"
                        style={{ fontFamily: "monospace", fontSize: "12px" }}
                      >
                        {peer.address}
                      </span>
                    </td>
                    <td>
                      <span style={{ color: getLatencyColor(peer.latency_ms) }}>
                        {peer.latency_ms}ms
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-sm">
                        <div
                          className="progress-bar"
                          style={{ width: "60px", height: "6px" }}
                        >
                          <div
                            className="progress-fill"
                            style={{
                              width: `${peer.bandwidth_score * 100}%`,
                              backgroundColor: getScoreColor(peer.bandwidth_score),
                            }}
                          />
                        </div>
                        <span
                          style={{
                            fontSize: "12px",
                            color: getScoreColor(peer.bandwidth_score),
                          }}
                        >
                          {(peer.bandwidth_score * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="text-muted" style={{ fontSize: "12px" }}>
                      <div className="flex items-center gap-sm">
                        <Clock size={12} />
                        {new Date(peer.connected_since).toLocaleTimeString()}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <Users />
            <h3>No peers connected</h3>
            <p>Waiting for peer connections...</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Peers;
