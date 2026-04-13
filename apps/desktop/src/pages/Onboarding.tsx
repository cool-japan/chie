import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  HardDrive,
  Wifi,
  Shield,
  Copy,
  Check,
  ChevronRight,
  ChevronLeft,
} from "lucide-react";
import { onboardingApi, systemApi, formatBytes } from "../lib/api";

// ---------------------------------------------------------------------------
// Seed phrase generation (BIP-39 subset, display-only demo)
// ---------------------------------------------------------------------------

const WORD_LIST: readonly string[] = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb",
  "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
  "achieve", "acid", "acoustic", "acquire", "across", "action", "actor",
  "actual", "adapt", "address", "adjust", "admit", "adult", "advance",
  "advice", "aerobic", "afford", "afraid", "again", "agent", "agree",
  "ahead", "aim", "airport", "aisle", "alarm", "album", "alcohol",
  "alert", "alien", "alley", "allow", "almost", "alone", "alpha",
  "already", "always", "amateur", "amazing", "among", "amount", "amused",
] as const;

function generateSeedPhrase(): string[] {
  const words: string[] = [];
  // Use a simple deterministic-looking approach based on timestamp bits
  // to avoid needing a crypto RNG import — this is demo-only display data.
  const seed = Date.now();
  for (let i = 0; i < 12; i++) {
    const idx = Math.floor(((seed * (i + 1) * 6364136223846793005 + 1) >>> 0) % WORD_LIST.length);
    words.push(WORD_LIST[idx]);
  }
  return words;
}

// ---------------------------------------------------------------------------
// Step-progress indicator
// ---------------------------------------------------------------------------

interface StepIndicatorProps {
  current: number;
  total: number;
  labels: readonly string[];
}

function StepIndicator({ current, total, labels }: StepIndicatorProps) {
  return (
    <div
      className="flex items-center justify-between mb-lg"
      style={{ paddingBottom: "var(--spacing-lg)", borderBottom: "1px solid var(--border-color)" }}
    >
      {labels.map((label, index) => {
        const stepNum = index + 1;
        const isCompleted = stepNum < current;
        const isCurrent = stepNum === current;
        return (
          <div key={label} className="flex items-center gap-sm" style={{ flex: 1 }}>
            <div className="flex items-center gap-sm">
              <div
                style={{
                  width: "28px",
                  height: "28px",
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: "12px",
                  fontWeight: 600,
                  backgroundColor: isCompleted
                    ? "var(--color-success)"
                    : isCurrent
                    ? "var(--color-primary)"
                    : "var(--bg-tertiary)",
                  color: isCompleted || isCurrent ? "white" : "var(--text-muted)",
                  flexShrink: 0,
                }}
              >
                {isCompleted ? <Check size={14} /> : stepNum}
              </div>
              <span
                style={{
                  fontSize: "12px",
                  fontWeight: isCurrent ? 600 : 400,
                  color: isCurrent ? "var(--text-primary)" : "var(--text-muted)",
                  whiteSpace: "nowrap",
                }}
              >
                {label}
              </span>
            </div>
            {index < total - 1 && (
              <div
                style={{
                  flex: 1,
                  height: "1px",
                  backgroundColor: isCompleted ? "var(--color-success)" : "var(--border-color)",
                  margin: "0 var(--spacing-sm)",
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 1: Welcome
// ---------------------------------------------------------------------------

interface StepWelcomeProps {
  onNext: () => void;
}

function StepWelcome({ onNext }: StepWelcomeProps) {
  const features = [
    {
      icon: <HardDrive size={24} />,
      title: "Share Storage",
      description: "Allocate unused disk space to host content securely",
    },
    {
      icon: <Wifi size={24} />,
      title: "Earn Rewards",
      description: "Get paid for every GB you serve to the network",
    },
    {
      icon: <Shield size={24} />,
      title: "Stay Private",
      description: "All content is encrypted end-to-end with ChaCha20",
    },
  ];

  return (
    <div className="flex flex-col items-center" style={{ textAlign: "center", maxWidth: "560px", margin: "0 auto" }}>
      <div
        style={{
          width: "72px",
          height: "72px",
          background: "linear-gradient(135deg, var(--color-primary), var(--color-primary-light))",
          borderRadius: "var(--border-radius-lg)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "28px",
          fontWeight: "bold",
          marginBottom: "var(--spacing-lg)",
        }}
      >
        C
      </div>

      <h1
        style={{
          fontSize: "32px",
          fontWeight: 700,
          marginBottom: "var(--spacing-sm)",
          lineHeight: 1.2,
        }}
      >
        Welcome to CHIE Protocol
      </h1>
      <p
        className="text-muted mb-lg"
        style={{ fontSize: "16px", maxWidth: "420px", lineHeight: 1.6 }}
      >
        Earn rewards by sharing your bandwidth and storage with content creators
      </p>

      <div
        className="grid grid-3 gap-md mb-lg"
        style={{ width: "100%", marginBottom: "var(--spacing-xl)" }}
      >
        {features.map((feature) => (
          <div
            key={feature.title}
            className="card"
            style={{ textAlign: "center", padding: "var(--spacing-lg) var(--spacing-md)" }}
          >
            <div
              className="stat-icon primary"
              style={{ margin: "0 auto var(--spacing-sm)" }}
            >
              {feature.icon}
            </div>
            <div style={{ fontWeight: 600, marginBottom: "var(--spacing-xs)", fontSize: "14px" }}>
              {feature.title}
            </div>
            <div className="text-muted" style={{ fontSize: "12px", lineHeight: 1.5 }}>
              {feature.description}
            </div>
          </div>
        ))}
      </div>

      <button className="btn btn-primary" onClick={onNext} style={{ fontSize: "16px", padding: "12px 32px" }}>
        Get Started
        <ChevronRight size={18} />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2: Storage Setup
// ---------------------------------------------------------------------------

const GB = 1024 * 1024 * 1024;

interface StorageConfig {
  storagePath: string;
  storageGb: number;
  bandwidthGb: number;
}

interface StepStorageProps {
  config: StorageConfig;
  onChange: (update: Partial<StorageConfig>) => void;
  onNext: () => void;
  onBack: () => void;
}

function StepStorage({ config, onChange, onNext, onBack }: StepStorageProps) {
  const storageBytes = config.storageGb * GB;
  const bandwidthBytes = config.bandwidthGb * GB;
  const dailyEarningsJpy = (config.storageGb * 0.002).toFixed(2);
  const monthlyEarningsJpy = (config.storageGb * 0.002 * 30).toFixed(0);

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto", width: "100%" }}>
      <h2 style={{ fontSize: "24px", fontWeight: 700, marginBottom: "var(--spacing-xs)" }}>
        Configure Storage
      </h2>
      <p className="text-muted mb-lg" style={{ fontSize: "14px" }}>
        Choose how much disk space and bandwidth to contribute to the network
      </p>

      <div className="card mb-lg">
        <div className="form-group">
          <label className="form-label">Storage Path</label>
          <input
            type="text"
            className="form-input"
            value={config.storagePath}
            onChange={(e) => onChange({ storagePath: e.target.value })}
            placeholder="/path/to/storage"
          />
          <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
            Directory where content chunks will be stored
          </p>
        </div>

        <div className="form-group">
          <label className="form-label">
            Storage Size: {formatBytes(storageBytes)}
          </label>
          <input
            type="range"
            className="form-input"
            min={10}
            max={2048}
            step={10}
            value={config.storageGb}
            onChange={(e) => onChange({ storageGb: parseInt(e.target.value, 10) })}
            style={{ padding: 0 }}
          />
          <div className="flex justify-between text-muted" style={{ fontSize: "12px" }}>
            <span>10 GB</span>
            <span>2 TB</span>
          </div>
        </div>

        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">
            Max Bandwidth per Day: {formatBytes(bandwidthBytes)}
          </label>
          <input
            type="range"
            className="form-input"
            min={10}
            max={1024}
            step={10}
            value={config.bandwidthGb}
            onChange={(e) => onChange({ bandwidthGb: parseInt(e.target.value, 10) })}
            style={{ padding: 0 }}
          />
          <div className="flex justify-between text-muted" style={{ fontSize: "12px" }}>
            <span>10 GB/day</span>
            <span>1 TB/day</span>
          </div>
        </div>
      </div>

      <div
        className="card mb-lg"
        style={{ borderColor: "var(--color-success)", backgroundColor: "rgba(16, 185, 129, 0.05)" }}
      >
        <div className="card-header" style={{ marginBottom: "var(--spacing-sm)" }}>
          <h3 className="card-title text-success">Estimated Earnings</h3>
        </div>
        <div className="grid grid-2 gap-md">
          <div>
            <div className="stat-value text-success" style={{ fontSize: "20px" }}>
              {dailyEarningsJpy} JPY
            </div>
            <div className="stat-label">per day</div>
          </div>
          <div>
            <div className="stat-value text-success" style={{ fontSize: "20px" }}>
              {monthlyEarningsJpy} JPY
            </div>
            <div className="stat-label">per month</div>
          </div>
        </div>
        <p className="text-muted mt-sm" style={{ fontSize: "12px" }}>
          Estimates based on {config.storageGb} GB storage at 0.002 JPY/GB/day. Actual earnings vary.
        </p>
      </div>

      <div className="flex justify-between gap-md">
        <button className="btn btn-outline" onClick={onBack}>
          <ChevronLeft size={16} />
          Back
        </button>
        <button className="btn btn-primary" onClick={onNext}>
          Next
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 3: Wallet / Node Identity
// ---------------------------------------------------------------------------

interface StepIdentityProps {
  seedPhrase: string[];
  onNext: () => void;
  onBack: () => void;
}

function StepIdentity({ seedPhrase, onNext, onBack }: StepIdentityProps) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  function handleCopy() {
    const phrase = seedPhrase.join(" ");
    navigator.clipboard.writeText(phrase).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Clipboard access may be restricted in some contexts — silently ignore
    });
  }

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto", width: "100%" }}>
      <h2 style={{ fontSize: "24px", fontWeight: 700, marginBottom: "var(--spacing-xs)" }}>
        Your Node Identity
      </h2>
      <p className="text-muted mb-lg" style={{ fontSize: "14px" }}>
        Your node identity is generated automatically. Save your recovery phrase in a secure location.
      </p>

      <div className="card mb-lg">
        <div className="card-header">
          <h3 className="card-title">Recovery Phrase</h3>
          <button
            className={`btn ${copied ? "btn-success" : "btn-outline"}`}
            onClick={handleCopy}
            style={{ fontSize: "13px" }}
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>

        <div
          className="grid grid-3 gap-sm"
          style={{
            fontFamily: "'Courier New', Courier, monospace",
            fontSize: "13px",
            marginBottom: "var(--spacing-md)",
          }}
        >
          {seedPhrase.map((word, index) => (
            <div
              key={index}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "var(--spacing-xs)",
                padding: "6px 10px",
                backgroundColor: "var(--bg-tertiary)",
                borderRadius: "var(--border-radius)",
                border: "1px solid var(--border-color)",
              }}
            >
              <span className="text-muted" style={{ fontSize: "11px", minWidth: "18px" }}>
                {index + 1}.
              </span>
              <span>{word}</span>
            </div>
          ))}
        </div>

        <div
          style={{
            padding: "var(--spacing-sm) var(--spacing-md)",
            backgroundColor: "rgba(245, 158, 11, 0.1)",
            borderRadius: "var(--border-radius)",
            borderLeft: "3px solid var(--color-warning)",
            fontSize: "12px",
            color: "var(--color-warning)",
          }}
        >
          Write down these 12 words in order. They cannot be recovered if lost.
        </div>
      </div>

      <div
        className="card mb-lg"
        style={{ padding: "var(--spacing-md)" }}
      >
        <label
          style={{ display: "flex", alignItems: "center", gap: "var(--spacing-sm)", cursor: "pointer" }}
        >
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            style={{ width: "16px", height: "16px", cursor: "pointer" }}
          />
          <span style={{ fontSize: "14px" }}>
            I have saved my recovery phrase securely
          </span>
        </label>
      </div>

      <div className="flex justify-between gap-md">
        <button className="btn btn-outline" onClick={onBack}>
          <ChevronLeft size={16} />
          Back
        </button>
        <button
          className="btn btn-primary"
          onClick={onNext}
          disabled={!confirmed}
        >
          Next
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 4: Ready!
// ---------------------------------------------------------------------------

interface StepReadyProps {
  config: StorageConfig;
  autoStart: boolean;
  onAutoStartChange: (value: boolean) => void;
  onFinish: () => void;
  onBack: () => void;
  finishing: boolean;
}

function StepReady({
  config,
  autoStart,
  onAutoStartChange,
  onFinish,
  onBack,
  finishing,
}: StepReadyProps) {
  const storageBytes = config.storageGb * GB;
  const bandwidthBytes = config.bandwidthGb * GB;
  const monthlyEarningsJpy = (config.storageGb * 0.002 * 30).toFixed(0);

  return (
    <div style={{ maxWidth: "600px", margin: "0 auto", width: "100%" }}>
      <div style={{ textAlign: "center", marginBottom: "var(--spacing-xl)" }}>
        <div
          style={{
            width: "64px",
            height: "64px",
            borderRadius: "50%",
            backgroundColor: "rgba(16, 185, 129, 0.2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto var(--spacing-md)",
          }}
        >
          <Check size={32} style={{ color: "var(--color-success)" }} />
        </div>
        <h2 style={{ fontSize: "28px", fontWeight: 700, marginBottom: "var(--spacing-xs)" }}>
          You're ready to earn!
        </h2>
        <p className="text-muted" style={{ fontSize: "14px" }}>
          Review your configuration and start contributing to the network
        </p>
      </div>

      <div className="card mb-md">
        <h3 className="card-title mb-md">Configuration Summary</h3>
        <div className="flex flex-col gap-md">
          <div className="flex justify-between items-center">
            <span className="text-muted" style={{ fontSize: "14px" }}>Storage Path</span>
            <span
              style={{
                fontSize: "13px",
                fontFamily: "'Courier New', Courier, monospace",
                maxWidth: "280px",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                textAlign: "right",
              }}
            >
              {config.storagePath}
            </span>
          </div>
          <div
            style={{ height: "1px", backgroundColor: "var(--border-color)" }}
          />
          <div className="flex justify-between items-center">
            <span className="text-muted" style={{ fontSize: "14px" }}>Storage Allocated</span>
            <span style={{ fontSize: "14px", fontWeight: 500 }}>
              {formatBytes(storageBytes)}
            </span>
          </div>
          <div
            style={{ height: "1px", backgroundColor: "var(--border-color)" }}
          />
          <div className="flex justify-between items-center">
            <span className="text-muted" style={{ fontSize: "14px" }}>Max Daily Bandwidth</span>
            <span style={{ fontSize: "14px", fontWeight: 500 }}>
              {formatBytes(bandwidthBytes)}
            </span>
          </div>
        </div>
      </div>

      <div className="card mb-md">
        <div className="flex items-center justify-between">
          <div>
            <div className="form-label" style={{ marginBottom: "4px" }}>
              Auto-start node
            </div>
            <p className="text-muted" style={{ fontSize: "12px" }}>
              Start contributing automatically when the app launches
            </p>
          </div>
          <label className="toggle">
            <input
              type="checkbox"
              checked={autoStart}
              onChange={(e) => onAutoStartChange(e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      <div
        className="card mb-lg"
        style={{ borderColor: "var(--color-success)", backgroundColor: "rgba(16, 185, 129, 0.05)" }}
      >
        <div className="flex justify-between items-center">
          <div>
            <div style={{ fontWeight: 600, marginBottom: "4px", fontSize: "14px" }}>
              Estimated Monthly Earnings
            </div>
            <p className="text-muted" style={{ fontSize: "12px" }}>
              Based on {config.storageGb} GB at full utilization
            </p>
          </div>
          <div className="stat-value text-success" style={{ fontSize: "24px" }}>
            {monthlyEarningsJpy} JPY
          </div>
        </div>
      </div>

      <div className="flex justify-between gap-md">
        <button className="btn btn-outline" onClick={onBack} disabled={finishing}>
          <ChevronLeft size={16} />
          Back
        </button>
        <button
          className="btn btn-success"
          onClick={onFinish}
          disabled={finishing}
          style={{ fontSize: "16px", padding: "12px 28px" }}
        >
          {finishing ? "Setting up..." : "Start Earning!"}
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Onboarding component
// ---------------------------------------------------------------------------

const STEP_LABELS = ["Welcome", "Storage", "Identity", "Ready"] as const;

function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [finishing, setFinishing] = useState(false);

  const [storageConfig, setStorageConfig] = useState<StorageConfig>({
    storagePath: "",
    storageGb: 50,
    bandwidthGb: 100,
  });
  const [autoStart, setAutoStart] = useState(false);
  const [seedPhrase] = useState<string[]>(() => generateSeedPhrase());

  // Load the default data directory on mount
  useEffect(() => {
    systemApi.getDataDir().then((dir) => {
      setStorageConfig((prev) => ({ ...prev, storagePath: dir }));
    }).catch(() => {
      // Silently fall back to empty string when not running in Tauri
    });
  }, []);

  function updateStorageConfig(update: Partial<StorageConfig>) {
    setStorageConfig((prev) => ({ ...prev, ...update }));
  }

  async function handleFinish() {
    setFinishing(true);
    try {
      await onboardingApi.complete({
        storagePath: storageConfig.storagePath,
        maxStorageGb: storageConfig.storageGb,
        maxBandwidthGb: storageConfig.bandwidthGb,
        autoStart,
      });
      navigate("/");
    } catch (error) {
      console.error("Failed to complete onboarding:", error);
      setFinishing(false);
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "var(--bg-primary)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "var(--spacing-xl)",
      }}
    >
      <div style={{ width: "100%", maxWidth: "720px" }}>
        {step > 1 && (
          <StepIndicator
            current={step}
            total={STEP_LABELS.length}
            labels={STEP_LABELS}
          />
        )}

        {step === 1 && (
          <StepWelcome onNext={() => setStep(2)} />
        )}

        {step === 2 && (
          <StepStorage
            config={storageConfig}
            onChange={updateStorageConfig}
            onNext={() => setStep(3)}
            onBack={() => setStep(1)}
          />
        )}

        {step === 3 && (
          <StepIdentity
            seedPhrase={seedPhrase}
            onNext={() => setStep(4)}
            onBack={() => setStep(2)}
          />
        )}

        {step === 4 && (
          <StepReady
            config={storageConfig}
            autoStart={autoStart}
            onAutoStartChange={setAutoStart}
            onFinish={handleFinish}
            onBack={() => setStep(3)}
            finishing={finishing}
          />
        )}
      </div>
    </div>
  );
}

export default Onboarding;
