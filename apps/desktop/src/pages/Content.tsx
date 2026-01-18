import { useState, useEffect } from "react";
import {
  HardDrive,
  Plus,
  Trash2,
  Download,
  Upload,
  RefreshCw,
  Search,
} from "lucide-react";
import {
  contentApi,
  settingsApi,
  PinnedContent,
  TransferEntry,
  StorageStats,
  formatBytes,
  formatCurrency,
} from "../lib/api";

function Content() {
  const [pinnedContent, setPinnedContent] = useState<PinnedContent[]>([]);
  const [transfers, setTransfers] = useState<TransferEntry[]>([]);
  const [storage, setStorage] = useState<StorageStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [pinContentId, setPinContentId] = useState("");
  const [showPinModal, setShowPinModal] = useState(false);
  const [activeTab, setActiveTab] = useState<"pinned" | "transfers">("pinned");

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [contentData, transferData, storageData] = await Promise.all([
        contentApi.getPinned(),
        contentApi.getTransferHistory(50),
        settingsApi.getStorageStats(),
      ]);
      setPinnedContent(contentData);
      setTransfers(transferData);
      setStorage(storageData);
    } catch (error) {
      console.error("Failed to load content:", error);
    } finally {
      setLoading(false);
    }
  }

  async function handlePinContent() {
    if (!pinContentId.trim()) return;

    try {
      const pinned = await contentApi.pin(pinContentId);
      setPinnedContent([pinned, ...pinnedContent]);
      setPinContentId("");
      setShowPinModal(false);
    } catch (error) {
      console.error("Failed to pin content:", error);
    }
  }

  async function handleUnpinContent(contentId: string) {
    if (!confirm("Are you sure you want to unpin this content?")) return;

    try {
      await contentApi.unpin(contentId);
      setPinnedContent(pinnedContent.filter((c) => c.content_id !== contentId));
    } catch (error) {
      console.error("Failed to unpin content:", error);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading content...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Content</h1>
          <p className="page-subtitle">Manage your pinned content and transfers</p>
        </div>
        <div className="flex gap-sm">
          <button className="btn btn-outline" onClick={loadData}>
            <RefreshCw size={16} />
            Refresh
          </button>
          <button className="btn btn-primary" onClick={() => setShowPinModal(true)}>
            <Plus size={16} />
            Pin Content
          </button>
        </div>
      </div>

      {/* Storage Stats */}
      <div className="card mb-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-md">
            <div className="stat-icon primary">
              <HardDrive size={20} />
            </div>
            <div>
              <div className="stat-value">{storage?.content_count ?? 0} items</div>
              <div className="stat-label">
                {formatBytes(storage?.used_bytes ?? 0)} used of{" "}
                {formatBytes(storage?.allocated_bytes ?? 0)}
              </div>
            </div>
          </div>
          <div style={{ width: "200px" }}>
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
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-sm mb-lg">
        <button
          className={`btn ${activeTab === "pinned" ? "btn-primary" : "btn-outline"}`}
          onClick={() => setActiveTab("pinned")}
        >
          <HardDrive size={16} />
          Pinned ({pinnedContent.length})
        </button>
        <button
          className={`btn ${activeTab === "transfers" ? "btn-primary" : "btn-outline"}`}
          onClick={() => setActiveTab("transfers")}
        >
          <RefreshCw size={16} />
          Transfers ({transfers.length})
        </button>
      </div>

      {/* Pinned Content Tab */}
      {activeTab === "pinned" && (
        <div className="card">
          {pinnedContent.length > 0 ? (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Size</th>
                    <th>Chunks</th>
                    <th>Served</th>
                    <th>Earned</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pinnedContent.map((content) => (
                    <tr key={content.content_id}>
                      <td>
                        <div>
                          <div>{content.name}</div>
                          <div className="text-muted" style={{ fontSize: "12px" }}>
                            {content.content_id.substring(0, 20)}...
                          </div>
                        </div>
                      </td>
                      <td>
                        <span
                          className="status-indicator"
                          style={{
                            backgroundColor: "rgba(99, 102, 241, 0.2)",
                            color: "var(--color-primary)",
                          }}
                        >
                          {content.category}
                        </span>
                      </td>
                      <td>{formatBytes(content.size)}</td>
                      <td>{content.chunks}</td>
                      <td>{content.times_served}x</td>
                      <td className="text-success">
                        {formatCurrency(content.total_earnings)}
                      </td>
                      <td>
                        <button
                          className="btn btn-outline"
                          style={{ padding: "4px 8px" }}
                          onClick={() => handleUnpinContent(content.content_id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <HardDrive />
              <h3>No pinned content</h3>
              <p>Pin content to start earning rewards</p>
              <button
                className="btn btn-primary mt-md"
                onClick={() => setShowPinModal(true)}
              >
                <Plus size={16} />
                Pin Content
              </button>
            </div>
          )}
        </div>
      )}

      {/* Transfers Tab */}
      {activeTab === "transfers" && (
        <div className="card">
          {transfers.length > 0 ? (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Direction</th>
                    <th>Content</th>
                    <th>Peer</th>
                    <th>Size</th>
                    <th>Reward</th>
                    <th>Status</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {transfers.map((transfer) => (
                    <tr key={transfer.id}>
                      <td>
                        {transfer.direction === "upload" ? (
                          <span className="flex items-center gap-sm text-success">
                            <Upload size={14} />
                            Upload
                          </span>
                        ) : (
                          <span className="flex items-center gap-sm text-info">
                            <Download size={14} />
                            Download
                          </span>
                        )}
                      </td>
                      <td className="text-muted">
                        {transfer.content_id.substring(0, 16)}...
                      </td>
                      <td className="text-muted">
                        {transfer.peer_id.substring(0, 16)}...
                      </td>
                      <td>{formatBytes(transfer.size)}</td>
                      <td className="text-success">
                        {transfer.reward > 0 ? formatCurrency(transfer.reward) : "-"}
                      </td>
                      <td>
                        <span
                          className={`status-indicator ${
                            transfer.status === "completed" ? "running" : "stopped"
                          }`}
                        >
                          {transfer.status}
                        </span>
                      </td>
                      <td className="text-muted" style={{ fontSize: "12px" }}>
                        {new Date(transfer.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <RefreshCw />
              <h3>No transfers yet</h3>
              <p>Transfers will appear here once your node starts serving content</p>
            </div>
          )}
        </div>
      )}

      {/* Pin Content Modal */}
      {showPinModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => setShowPinModal(false)}
        >
          <div
            className="card"
            style={{ width: "400px", maxWidth: "90%" }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="card-title mb-md">Pin New Content</h3>
            <div className="form-group">
              <label className="form-label">Content ID (CID)</label>
              <div className="flex gap-sm">
                <input
                  type="text"
                  className="form-input"
                  placeholder="Qm..."
                  value={pinContentId}
                  onChange={(e) => setPinContentId(e.target.value)}
                />
              </div>
              <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
                Enter the IPFS Content ID (CID) of the content you want to pin
              </p>
            </div>
            <div className="flex justify-between mt-lg">
              <button
                className="btn btn-outline"
                onClick={() => setShowPinModal(false)}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handlePinContent}
                disabled={!pinContentId.trim()}
              >
                <Plus size={16} />
                Pin Content
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Content;
