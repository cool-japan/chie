import { useState, useEffect } from "react";
import { ArrowUpCircle, ArrowDownCircle, RefreshCw, ArrowLeftRight } from "lucide-react";
import { transfersApi, TransferEntry, formatBytes } from "../lib/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type FilterMode = "all" | "uploads" | "downloads";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diff = now.getTime() - date.getTime();

  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;

  return date.toLocaleDateString();
}

function formatReward(microPoints: number): string {
  return (microPoints / 1000).toFixed(3) + " pts";
}

function truncateId(id: string, maxLen = 16): string {
  if (id.length <= maxLen) return id;
  return id.substring(0, maxLen) + "…";
}

function statusClass(status: string): string {
  if (status === "completed") return "running";
  if (status === "failed") return "stopped";
  return "stopped";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function FilterBar({
  mode,
  onChange,
}: {
  mode: FilterMode;
  onChange: (m: FilterMode) => void;
}) {
  return (
    <div className="flex gap-sm mb-lg">
      <button
        className={`btn ${mode === "all" ? "btn-primary" : "btn-outline"}`}
        onClick={() => onChange("all")}
      >
        <ArrowLeftRight size={16} />
        All
      </button>
      <button
        className={`btn ${mode === "uploads" ? "btn-primary" : "btn-outline"}`}
        onClick={() => onChange("uploads")}
      >
        <ArrowUpCircle size={16} />
        Uploads
      </button>
      <button
        className={`btn ${mode === "downloads" ? "btn-primary" : "btn-outline"}`}
        onClick={() => onChange("downloads")}
      >
        <ArrowDownCircle size={16} />
        Downloads
      </button>
    </div>
  );
}

function DirectionCell({ direction }: { direction: string }) {
  if (direction === "upload") {
    return (
      <span className="flex items-center gap-sm text-success">
        <ArrowUpCircle size={14} />
        Upload
      </span>
    );
  }
  return (
    <span className="flex items-center gap-sm text-info">
      <ArrowDownCircle size={14} />
      Download
    </span>
  );
}

function TransferRow({ entry }: { entry: TransferEntry }) {
  return (
    <tr key={entry.id}>
      <td>
        <DirectionCell direction={entry.direction} />
      </td>
      <td className="text-muted" title={entry.content_id}>
        {truncateId(entry.content_id)}
      </td>
      <td className="text-muted" title={entry.peer_id}>
        {truncateId(entry.peer_id)}
      </td>
      <td>{formatBytes(entry.size)}</td>
      <td className={entry.reward > 0 ? "text-success" : "text-muted"}>
        {entry.reward > 0 ? formatReward(entry.reward) : "—"}
      </td>
      <td>
        <span className={`status-indicator ${statusClass(entry.status)}`}>
          {entry.status}
        </span>
      </td>
      <td className="text-muted" style={{ fontSize: "12px" }}>
        {formatTimestamp(entry.timestamp)}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function Transfers() {
  const [entries, setEntries] = useState<TransferEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<FilterMode>("all");

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30_000); // Auto-refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const data = await transfersApi.getHistory(200);
      setEntries(data);
    } catch (error) {
      console.error("Failed to load transfer history:", error);
    } finally {
      setLoading(false);
    }
  }

  const filtered = entries.filter((e) => {
    if (filter === "uploads") return e.direction === "upload";
    if (filter === "downloads") return e.direction === "download";
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading transfers...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Transfer History</h1>
          <p className="page-subtitle">
            Recent uploads and downloads handled by your node
          </p>
        </div>
        <button className="btn btn-outline" onClick={loadData}>
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <FilterBar mode={filter} onChange={setFilter} />

      <div className="card">
        {filtered.length > 0 ? (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Direction</th>
                  <th>Content ID</th>
                  <th>Peer ID</th>
                  <th>Size</th>
                  <th>Reward</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry) => (
                  <TransferRow key={entry.id} entry={entry} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <ArrowLeftRight />
            <h3>No transfers yet</h3>
            <p>
              {filter === "all"
                ? "Transfers will appear here once your node starts serving content"
                : filter === "uploads"
                  ? "No upload transfers found"
                  : "No download transfers found"}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Transfers;
