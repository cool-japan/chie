import { useState, useEffect } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";
import { TrendingUp, Calendar, Download } from "lucide-react";
import {
  earningsApi,
  EarningsState,
  DailyEarning,
  ContentEarning,
  formatCurrency,
  formatBytes,
} from "../lib/api";

function Earnings() {
  const [earnings, setEarnings] = useState<EarningsState | null>(null);
  const [history, setHistory] = useState<DailyEarning[]>([]);
  const [contentEarnings, setContentEarnings] = useState<ContentEarning[]>([]);
  const [timeRange, setTimeRange] = useState(30);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, [timeRange]);

  async function loadData() {
    setLoading(true);
    try {
      const [earningsData, historyData, contentData] = await Promise.all([
        earningsApi.get(),
        earningsApi.getHistory(timeRange),
        earningsApi.getByContent(),
      ]);
      setEarnings(earningsData);
      setHistory(historyData);
      setContentEarnings(contentData);
    } catch (error) {
      console.error("Failed to load earnings:", error);
    } finally {
      setLoading(false);
    }
  }

  // Prepare chart data
  const chartData = history.map((day) => ({
    date: day.date.split("-").slice(1).join("/"), // Format as MM/DD
    amount: day.amount / 100, // Convert to display units
    bandwidth: day.bandwidth_gb,
    transfers: day.transfers,
  }));

  // Calculate period stats
  const periodTotal = history.reduce((sum, day) => sum + day.amount, 0);
  const periodBandwidth = history.reduce((sum, day) => sum + day.bandwidth_gb, 0);
  const periodTransfers = history.reduce((sum, day) => sum + day.transfers, 0);

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height: "100%" }}>
        <div className="text-muted">Loading earnings data...</div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Earnings</h1>
          <p className="page-subtitle">Track your rewards and payouts</p>
        </div>
        <button className="btn btn-outline">
          <Download size={16} />
          Export CSV
        </button>
      </div>

      {/* Summary Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon success">
            <TrendingUp size={20} />
          </div>
          <div className="stat-value text-success">
            {formatCurrency(earnings?.total_earnings ?? 0)}
          </div>
          <div className="stat-label">Total Earned</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon warning">
            <Calendar size={20} />
          </div>
          <div className="stat-value text-warning">
            {formatCurrency(earnings?.pending_earnings ?? 0)}
          </div>
          <div className="stat-label">Pending</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon primary">
            <TrendingUp size={20} />
          </div>
          <div className="stat-value">{formatCurrency(periodTotal)}</div>
          <div className="stat-label">Last {timeRange} Days</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon info">
            <Download size={20} />
          </div>
          <div className="stat-value">
            {formatCurrency(earnings?.withdrawn_earnings ?? 0)}
          </div>
          <div className="stat-label">Withdrawn</div>
        </div>
      </div>

      {/* Time Range Selector */}
      <div className="flex gap-sm mb-lg">
        {[7, 14, 30, 90].map((days) => (
          <button
            key={days}
            className={`btn ${timeRange === days ? "btn-primary" : "btn-outline"}`}
            onClick={() => setTimeRange(days)}
          >
            {days} Days
          </button>
        ))}
      </div>

      {/* Earnings Chart */}
      <div className="card mb-lg">
        <div className="card-header">
          <h3 className="card-title">Earnings Over Time</h3>
          <span className="text-muted">
            {periodTransfers} transfers, {periodBandwidth.toFixed(2)} GB served
          </span>
        </div>
        <div className="chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="date"
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
              />
              <YAxis
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
                tickFormatter={(value) => `${value}`}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1e293b",
                  border: "1px solid #334155",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#f8fafc" }}
              />
              <Line
                type="monotone"
                dataKey="amount"
                stroke="#6366f1"
                strokeWidth={2}
                dot={false}
                name="Earnings (CHIE)"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Bandwidth Chart */}
      <div className="card mb-lg">
        <div className="card-header">
          <h3 className="card-title">Bandwidth Served</h3>
        </div>
        <div className="chart-container">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="date"
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
              />
              <YAxis
                stroke="#64748b"
                fontSize={12}
                tickLine={false}
                tickFormatter={(value) => `${value} GB`}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1e293b",
                  border: "1px solid #334155",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#f8fafc" }}
              />
              <Bar
                dataKey="bandwidth"
                fill="#10b981"
                radius={[4, 4, 0, 0]}
                name="Bandwidth (GB)"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Earnings by Content */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Earnings by Content</h3>
        </div>
        {contentEarnings.length > 0 ? (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Content</th>
                  <th>Content ID</th>
                  <th>Transfers</th>
                  <th>Earned</th>
                </tr>
              </thead>
              <tbody>
                {contentEarnings.map((item) => (
                  <tr key={item.content_id}>
                    <td>{item.content_name}</td>
                    <td className="text-muted">
                      {item.content_id.substring(0, 16)}...
                    </td>
                    <td>{item.transfers}</td>
                    <td className="text-success">
                      {formatCurrency(item.total_earned)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <TrendingUp />
            <h3>No content earnings yet</h3>
            <p>Pin content to start earning rewards</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Earnings;
