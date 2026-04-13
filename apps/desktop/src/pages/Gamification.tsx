import { useState, useEffect } from "react";
import { Trophy, Star, Zap, Target, Award } from "lucide-react";
import {
  gamificationApi,
  LocalGamificationState,
  LocalQuest,
  formatBytes,
} from "../lib/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatExpiresAt(iso: string): string {
  const date = new Date(iso);
  const now = new Date();
  const diff = date.getTime() - now.getTime();
  if (diff <= 0) {
    return "Expired";
  }
  const hours = Math.floor(diff / 3600_000);
  if (hours < 24) {
    return `Expires in ${hours}h`;
  }
  const days = Math.floor(hours / 24);
  return `Expires in ${days}d`;
}

function formatQuestProgress(quest: LocalQuest): string {
  if (quest.quest_type === "DailyUptime") {
    const currentHours = Math.floor(quest.current_progress / 3600);
    const targetHours = Math.floor(quest.target_progress / 3600);
    return `${currentHours}h / ${targetHours}h`;
  }
  if (quest.quest_type === "WeeklyBandwidth") {
    return `${formatBytes(quest.current_progress)} / ${formatBytes(quest.target_progress)}`;
  }
  return `${quest.current_progress} / ${quest.target_progress}`;
}

function questProgressPercent(quest: LocalQuest): number {
  if (quest.target_progress === 0) return 0;
  return Math.min(
    100,
    Math.round((quest.current_progress / quest.target_progress) * 100)
  );
}

function statusClass(status: string): string {
  if (status === "completed") return "text-success";
  if (status === "expired") return "text-danger";
  return "text-muted";
}

function statusLabel(status: string): string {
  if (status === "completed") return "Completed";
  if (status === "expired") return "Expired";
  return "Active";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function PointsSummary({
  state,
}: {
  state: LocalGamificationState;
}) {
  return (
    <div className="stats-grid">
      <div className="stat-card">
        <div className="stat-icon warning">
          <Star size={20} />
        </div>
        <div className="stat-value">{state.total_points.toLocaleString()}</div>
        <div className="stat-label">Total Points</div>
      </div>

      <div className="stat-card">
        <div className="stat-icon primary">
          <Zap size={20} />
        </div>
        <div className="stat-value">{state.monthly_points.toLocaleString()}</div>
        <div className="stat-label">Monthly Points</div>
      </div>

      <div className="stat-card">
        <div className="stat-icon success">
          <Trophy size={20} />
        </div>
        <div className="stat-value">{state.streak_days}</div>
        <div className="stat-label">Day Streak</div>
      </div>

      <div className="stat-card">
        <div className="stat-icon info">
          <Award size={20} />
        </div>
        <div className="stat-value">{state.badges.length}</div>
        <div className="stat-label">Badges Earned</div>
      </div>
    </div>
  );
}

function QuestCard({ quest }: { quest: LocalQuest }) {
  const percent = questProgressPercent(quest);

  return (
    <div
      className="card mb-md"
      style={
        quest.status === "completed"
          ? { borderColor: "var(--color-success)" }
          : undefined
      }
    >
      <div className="card-header">
        <div>
          <div className="flex items-center gap-sm mb-sm">
            <Target size={16} style={{ color: "var(--color-primary)" }} />
            <span className="card-title">{quest.title}</span>
            <span
              className={statusClass(quest.status)}
              style={{ fontSize: "12px", fontWeight: 500 }}
            >
              {statusLabel(quest.status)}
            </span>
          </div>
          <p className="text-muted" style={{ fontSize: "14px" }}>
            {quest.description}
          </p>
        </div>
        <div style={{ textAlign: "right", flexShrink: 0 }}>
          <div
            className="text-warning"
            style={{ fontWeight: 700, fontSize: "18px" }}
          >
            +{quest.reward_points}
          </div>
          <div className="text-muted" style={{ fontSize: "12px" }}>
            pts reward
          </div>
        </div>
      </div>

      <div className="mb-sm">
        <div className="flex justify-between mb-sm">
          <span className="text-muted" style={{ fontSize: "13px" }}>
            {formatQuestProgress(quest)}
          </span>
          <span className="text-muted" style={{ fontSize: "13px" }}>
            {percent}%
          </span>
        </div>
        <div className="progress-bar">
          <div
            className="progress-fill"
            style={{
              width: `${percent}%`,
              background:
                quest.status === "completed"
                  ? "linear-gradient(90deg, var(--color-success), var(--color-success-light))"
                  : undefined,
            }}
          />
        </div>
      </div>

      <div className="text-muted" style={{ fontSize: "12px" }}>
        {formatExpiresAt(quest.expires_at)}
      </div>
    </div>
  );
}

function BadgesSection({ badges }: { badges: string[] }) {
  if (badges.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Badges</h3>
        </div>
        <p className="text-muted" style={{ fontSize: "14px" }}>
          No badges earned yet — keep going!
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">Badges</h3>
        <span className="text-muted" style={{ fontSize: "13px" }}>
          {badges.length} earned
        </span>
      </div>
      <div className="flex" style={{ flexWrap: "wrap", gap: "var(--spacing-sm)" }}>
        {badges.map((badge) => (
          <span
            key={badge}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              padding: "4px 12px",
              borderRadius: "9999px",
              background: "rgba(99, 102, 241, 0.15)",
              border: "1px solid rgba(99, 102, 241, 0.35)",
              color: "var(--color-primary-light)",
              fontSize: "13px",
              fontWeight: 500,
            }}
          >
            <Award size={13} />
            {badge}
          </span>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function Gamification() {
  const [gamification, setGamification] =
    useState<LocalGamificationState | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10_000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const data = await gamificationApi.getState();
      setGamification(data);
    } catch (error) {
      console.error("Failed to load gamification state:", error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ height: "100%" }}
      >
        <div className="text-muted">Loading...</div>
      </div>
    );
  }

  if (!gamification) {
    return (
      <div
        className="flex items-center justify-center"
        style={{ height: "100%" }}
      >
        <div className="text-muted">Could not load gamification data.</div>
      </div>
    );
  }

  const activeQuests = gamification.quests.filter(
    (q) => q.status === "active"
  );
  const completedQuests = gamification.quests.filter(
    (q) => q.status === "completed"
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Rewards</h1>
          <p className="page-subtitle">
            Earn points and badges by contributing to the CHIE network
          </p>
        </div>
      </div>

      {/* Points summary */}
      <PointsSummary state={gamification} />

      {/* Active quests */}
      <div className="card-header mb-md">
        <h2 className="card-title" style={{ fontSize: "18px" }}>
          Active Quests
        </h2>
        <span className="text-muted" style={{ fontSize: "13px" }}>
          {activeQuests.length} active
        </span>
      </div>

      {activeQuests.length === 0 ? (
        <div className="card mb-lg">
          <p className="text-muted" style={{ fontSize: "14px" }}>
            No active quests right now. Check back tomorrow!
          </p>
        </div>
      ) : (
        <div className="mb-lg">
          {activeQuests.map((quest) => (
            <QuestCard key={quest.id} quest={quest} />
          ))}
        </div>
      )}

      {/* Completed quests */}
      {completedQuests.length > 0 && (
        <>
          <div className="card-header mb-md">
            <h2 className="card-title" style={{ fontSize: "18px" }}>
              Completed Quests
            </h2>
            <span className="text-muted" style={{ fontSize: "13px" }}>
              {completedQuests.length} completed
            </span>
          </div>
          <div className="mb-lg">
            {completedQuests.map((quest) => (
              <QuestCard key={quest.id} quest={quest} />
            ))}
          </div>
        </>
      )}

      {/* Badges */}
      <BadgesSection badges={gamification.badges} />
    </div>
  );
}

export default Gamification;
