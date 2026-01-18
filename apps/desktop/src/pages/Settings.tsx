import { useState, useEffect } from "react";
import {
  Settings as SettingsIcon,
  HardDrive,
  Wifi,
  Bell,
  Moon,
  Save,
  FolderOpen,
  Info,
} from "lucide-react";
import {
  settingsApi,
  systemApi,
  AppSettings,
  SystemInfo,
  formatBytes,
} from "../lib/api";

function Settings() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const [settingsData, sysInfo] = await Promise.all([
        settingsApi.get(),
        systemApi.getInfo(),
      ]);
      setSettings(settingsData);
      setSystemInfo(sysInfo);
    } catch (error) {
      console.error("Failed to load settings:", error);
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    if (!settings) return;

    setSaving(true);
    try {
      await settingsApi.update(settings);
      setHasChanges(false);
    } catch (error) {
      console.error("Failed to save settings:", error);
    } finally {
      setSaving(false);
    }
  }

  function updateSetting<K extends keyof AppSettings>(
    key: K,
    value: AppSettings[K]
  ) {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
    setHasChanges(true);
  }

  if (loading || !settings) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading settings...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Configure your CHIE node</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={!hasChanges || saving}
        >
          <Save size={16} />
          {saving ? "Saving..." : "Save Changes"}
        </button>
      </div>

      {/* Storage Settings */}
      <div className="card mb-lg">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <HardDrive size={20} />
            <h3 className="card-title">Storage</h3>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Storage Path</label>
          <div className="flex gap-sm">
            <input
              type="text"
              className="form-input"
              value={settings.storage_path}
              onChange={(e) => updateSetting("storage_path", e.target.value)}
            />
            <button className="btn btn-outline">
              <FolderOpen size={16} />
            </button>
          </div>
          <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
            Directory where content chunks will be stored
          </p>
        </div>

        <div className="form-group">
          <label className="form-label">
            Maximum Storage: {formatBytes(settings.max_storage_bytes)}
          </label>
          <input
            type="range"
            className="form-input"
            min={1073741824} // 1 GB
            max={1099511627776} // 1 TB
            step={1073741824} // 1 GB steps
            value={settings.max_storage_bytes}
            onChange={(e) =>
              updateSetting("max_storage_bytes", parseInt(e.target.value))
            }
            style={{ padding: 0 }}
          />
          <div className="flex justify-between text-muted" style={{ fontSize: "12px" }}>
            <span>1 GB</span>
            <span>1 TB</span>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">
            Daily Bandwidth Limit: {formatBytes(settings.max_bandwidth_per_day)}
          </label>
          <input
            type="range"
            className="form-input"
            min={1073741824} // 1 GB
            max={1099511627776} // 1 TB
            step={1073741824} // 1 GB steps
            value={settings.max_bandwidth_per_day}
            onChange={(e) =>
              updateSetting("max_bandwidth_per_day", parseInt(e.target.value))
            }
            style={{ padding: 0 }}
          />
          <div className="flex justify-between text-muted" style={{ fontSize: "12px" }}>
            <span>1 GB/day</span>
            <span>1 TB/day</span>
          </div>
        </div>
      </div>

      {/* Network Settings */}
      <div className="card mb-lg">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <Wifi size={20} />
            <h3 className="card-title">Network</h3>
          </div>
        </div>

        <div className="grid grid-2 gap-md">
          <div className="form-group">
            <label className="form-label">TCP Port</label>
            <input
              type="number"
              className="form-input"
              value={settings.tcp_port}
              onChange={(e) => updateSetting("tcp_port", parseInt(e.target.value))}
              placeholder="0 for random"
            />
            <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
              Set to 0 for automatic port selection
            </p>
          </div>

          <div className="form-group">
            <label className="form-label">QUIC Port</label>
            <input
              type="number"
              className="form-input"
              value={settings.quic_port}
              onChange={(e) => updateSetting("quic_port", parseInt(e.target.value))}
              placeholder="0 for random"
            />
            <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
              Set to 0 for automatic port selection
            </p>
          </div>
        </div>
      </div>

      {/* Behavior Settings */}
      <div className="card mb-lg">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <SettingsIcon size={20} />
            <h3 className="card-title">Behavior</h3>
          </div>
        </div>

        <div className="flex flex-col gap-md">
          <div className="flex items-center justify-between">
            <div>
              <div className="form-label" style={{ marginBottom: "4px" }}>
                Auto-start node
              </div>
              <p className="text-muted" style={{ fontSize: "12px" }}>
                Start node automatically when app launches
              </p>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.auto_start}
                onChange={(e) => updateSetting("auto_start", e.target.checked)}
              />
              <span className="toggle-slider" />
            </label>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="form-label" style={{ marginBottom: "4px" }}>
                Minimize to tray
              </div>
              <p className="text-muted" style={{ fontSize: "12px" }}>
                Keep running in system tray when closed
              </p>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.minimize_to_tray}
                onChange={(e) => updateSetting("minimize_to_tray", e.target.checked)}
              />
              <span className="toggle-slider" />
            </label>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="form-label" style={{ marginBottom: "4px" }}>
                Start minimized
              </div>
              <p className="text-muted" style={{ fontSize: "12px" }}>
                Launch app minimized to system tray
              </p>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.start_minimized}
                onChange={(e) => updateSetting("start_minimized", e.target.checked)}
              />
              <span className="toggle-slider" />
            </label>
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="card mb-lg">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <Bell size={20} />
            <h3 className="card-title">Notifications</h3>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div>
            <div className="form-label" style={{ marginBottom: "4px" }}>
              Enable notifications
            </div>
            <p className="text-muted" style={{ fontSize: "12px" }}>
              Show notifications for earnings and transfers
            </p>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              checked={settings.notifications_enabled}
              onChange={(e) =>
                updateSetting("notifications_enabled", e.target.checked)
              }
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      {/* Appearance */}
      <div className="card mb-lg">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <Moon size={20} />
            <h3 className="card-title">Appearance</h3>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Theme</label>
          <div className="flex gap-sm">
            {["system", "dark", "light"].map((theme) => (
              <button
                key={theme}
                className={`btn ${
                  settings.theme === theme ? "btn-primary" : "btn-outline"
                }`}
                onClick={() => updateSetting("theme", theme)}
              >
                {theme.charAt(0).toUpperCase() + theme.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* System Info */}
      <div className="card">
        <div className="card-header">
          <div className="flex items-center gap-sm">
            <Info size={20} />
            <h3 className="card-title">About</h3>
          </div>
        </div>

        <div className="grid grid-2 gap-md">
          <div>
            <div className="text-muted" style={{ fontSize: "12px" }}>
              App Version
            </div>
            <div>{systemInfo?.app_version ?? "Unknown"}</div>
          </div>
          <div>
            <div className="text-muted" style={{ fontSize: "12px" }}>
              Protocol Version
            </div>
            <div>{systemInfo?.protocol_version ?? "Unknown"}</div>
          </div>
          <div>
            <div className="text-muted" style={{ fontSize: "12px" }}>
              Operating System
            </div>
            <div>
              {systemInfo?.os ?? "Unknown"} ({systemInfo?.arch ?? "Unknown"})
            </div>
          </div>
          <div>
            <div className="text-muted" style={{ fontSize: "12px" }}>
              Data Directory
            </div>
            <div style={{ fontSize: "12px", wordBreak: "break-all" }}>
              {settings.storage_path}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Settings;
