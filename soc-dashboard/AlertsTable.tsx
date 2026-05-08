"use client";

import { useState, useEffect, useCallback } from "react";
import { api, Alert } from "@/lib/api";

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase() ?? "low";
  return (
    <span className={`badge-${s} text-[10px] font-bold px-2 py-0.5 rounded-sm uppercase tracking-widest`}>
      {s}
    </span>
  );
}

export default function AlertsTable() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const data = await api.getAlerts(100);
      setAlerts(data);
      setLastRefresh(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch alerts");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const filtered =
    filter === "all"
      ? alerts
      : alerts.filter((a) => a.severity?.toLowerCase() === filter);

  const counts = {
    critical: alerts.filter((a) => a.severity?.toLowerCase() === "critical").length,
    high: alerts.filter((a) => a.severity?.toLowerCase() === "high").length,
    medium: alerts.filter((a) => a.severity?.toLowerCase() === "medium").length,
    low: alerts.filter((a) => a.severity?.toLowerCase() === "low").length,
  };

  return (
    <div className="panel h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a1a]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[#444] tracking-widest uppercase">◈</span>
          <h2 className="text-[11px] font-bold tracking-[0.2em] uppercase text-[#00ff88]">
            ALERTS
          </h2>
          <span className="text-[10px] text-[#333] tracking-widest">
            [{alerts.length.toString().padStart(4, "0")}]
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="text-[9px] text-[#333] tracking-widest"
            suppressHydrationWarning
          >
            {lastRefresh
              ? lastRefresh.toLocaleTimeString("en-US", { hour12: false })
              : ""}
          </span>
          <button
            onClick={load}
            className="text-[9px] px-2 py-1 border border-[#252525] text-[#555] hover:text-[#00ff88] hover:border-[#00ff88] transition-colors tracking-widest uppercase"
          >
            ↻ SYNC
          </button>
        </div>
      </div>

      {/* Severity filter chips */}
      <div className="flex gap-1 px-4 py-2 border-b border-[#1a1a1a]">
        {["all", "critical", "high", "medium", "low"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`text-[9px] px-2 py-1 rounded-sm uppercase tracking-widest transition-all ${
              filter === s
                ? s === "all"
                  ? "bg-[#1a1a1a] text-[#00ff88] border border-[#00ff88]/30"
                  : `badge-${s}`
                : "text-[#333] border border-[#1a1a1a] hover:text-[#555]"
            }`}
          >
            {s === "all" ? `ALL (${alerts.length})` : `${s} (${counts[s as keyof typeof counts] ?? 0})`}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-[#333] text-[11px] tracking-widest">
            <span className="typing-dots">LOADING</span>
          </div>
        ) : error ? (
          <div className="p-4">
            <div className="text-[#ff3366] text-[10px] tracking-widest border border-[#ff3366]/20 p-3 bg-[#ff3366]/5">
              ✗ {error}
              <br />
              <span className="text-[#444]">Backend: http://localhost:8001</span>
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2 text-[#333]">
            <span className="text-[20px]">◌</span>
            <span className="text-[10px] tracking-widest uppercase">No alerts found</span>
          </div>
        ) : (
          <table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-[#0d0d0d]">
              <tr className="border-b border-[#1a1a1a]">
                {["RULE", "SEV", "USER", "HOST", "TIME"].map((h) => (
                  <th
                    key={h}
                    className="text-left px-4 py-2 text-[#333] tracking-widest font-normal border-b border-[#1a1a1a]"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((alert, i) => (
                <tr
                  key={`${alert.rule_id}-${i}`}
                  className="border-b border-[#111] hover:bg-[#111] transition-colors animate-fade-in group"
                >
                  <td className="px-4 py-2.5 text-[#00cc6a] font-medium max-w-[140px]">
                    <div className="truncate group-hover:text-[#00ff88] transition-colors">
                      {alert.rule_id || "—"}
                    </div>
                    {alert.tactic && (
                      <div className="text-[#333] text-[9px] truncate mt-0.5">
                        {alert.tactic}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4 py-2.5 text-[#666] max-w-[100px]">
                    <div className="truncate">{alert.user || "—"}</div>
                  </td>
                  <td className="px-4 py-2.5 text-[#555] max-w-[100px]">
                    <div className="truncate">{alert.host || "—"}</div>
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-[#666]">
                    {alert.time || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
