"use client";

import { useState, useEffect, useCallback } from "react";
import { api, Chain } from "@/lib/api";

function RiskBar({ score }: { score: number }) {
  const clamped = Math.min(100, Math.max(0, score));
  const color =
    clamped >= 80
      ? "#ff3366"
      : clamped >= 60
      ? "#ff6633"
      : clamped >= 40
      ? "#ffaa00"
      : "#00ff88";

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-[#1a1a1a] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${clamped}%`, background: color, boxShadow: `0 0 6px ${color}50` }}
        />
      </div>
      <span
        className="text-[11px] font-bold tabular-nums w-8 text-right"
        style={{ color }}
      >
        {score}
      </span>
    </div>
  );
}

function StageSequence({ stages }: { stages: string[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1 mt-2">
      {stages.map((stage, i) => (
        <div key={i} className="flex items-center gap-1">
          <span className="text-[9px] px-2 py-0.5 bg-[#111] border border-[#222] text-[#666] rounded-sm uppercase tracking-wider">
            {stage}
          </span>
          {i < stages.length - 1 && (
            <span className="text-[#333] text-[10px]">→</span>
          )}
        </div>
      ))}
    </div>
  );
}

export default function ChainsPanel() {
  const [chains, setChains] = useState<Chain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const data = await api.getChains(20);
      setChains(data.chains);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch chains");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 45000);
    return () => clearInterval(interval);
  }, [load]);

  return (
    <div className="panel h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a1a]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[#444] tracking-widest">◈</span>
          <h2 className="text-[11px] font-bold tracking-[0.2em] uppercase text-[#00ff88]">
            ATTACK CHAINS
          </h2>
          <span className="text-[10px] text-[#333]">[{chains.length.toString().padStart(3, "0")}]</span>
        </div>
        <button
          onClick={load}
          className="text-[9px] px-2 py-1 border border-[#252525] text-[#555] hover:text-[#00ff88] hover:border-[#00ff88]/50 transition-colors tracking-widest uppercase"
        >
          ↻ SYNC
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto px-3 py-3 space-y-2">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-[#333] text-[11px] tracking-widest">
            <span className="typing-dots">CORRELATING</span>
          </div>
        ) : error ? (
          <div className="text-[#ff3366] text-[10px] tracking-widest border border-[#ff3366]/20 p-3 bg-[#ff3366]/5 rounded-sm">
            ✗ {error}
          </div>
        ) : chains.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2 text-[#333]">
            <span className="text-[24px] opacity-30">⬡</span>
            <span className="text-[10px] tracking-widest uppercase">No chains detected</span>
            <span className="text-[9px] text-[#222]">Ingest logs to trigger correlation</span>
          </div>
        ) : (
          chains.map((chain, i) => {
            const id = chain.chain_id ?? `chain-${i}`;
            const sev = chain.severity?.toLowerCase() ?? "low";
            const isOpen = expanded === id;

            return (
              <div
                key={id}
                className={`border rounded-sm overflow-hidden transition-all cursor-pointer ${
                  isOpen
                    ? "border-[#252525] bg-[#111]"
                    : "border-[#1a1a1a] bg-[#0f0f0f] hover:border-[#252525] hover:bg-[#111]"
                }`}
                onClick={() => setExpanded(isOpen ? null : id)}
              >
                <div className="px-3 py-2.5">
                  {/* Top row */}
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                          sev === "critical"
                            ? "bg-[#ff3366] shadow-[0_0_4px_#ff3366]"
                            : sev === "high"
                            ? "bg-[#ff6633] shadow-[0_0_4px_#ff6633]"
                            : sev === "medium"
                            ? "bg-[#ffaa00] shadow-[0_0_4px_#ffaa00]"
                            : "bg-[#00ff88] shadow-[0_0_4px_#00ff88]"
                        }`}
                      />
                      <span className="text-[11px] font-semibold text-[#ccc] truncate">
                        {chain.pattern_name}
                      </span>
                    </div>
                    <span className={`badge-${sev} text-[9px] px-1.5 py-0.5 uppercase tracking-widest flex-shrink-0`}>
                      {sev}
                    </span>
                  </div>

                  {/* Risk bar */}
                  <RiskBar score={chain.risk_score} />

                  {/* Stages preview */}
                  {!isOpen && (
                    <div className="mt-2 flex items-center gap-1 overflow-hidden">
                      {chain.stage_sequence?.slice(0, 3).map((s, si) => (
                        <div key={si} className="flex items-center gap-1">
                          <span className="text-[9px] text-[#444] truncate max-w-[80px]">{s}</span>
                          {si < Math.min(2, chain.stage_sequence.length - 1) && (
                            <span className="text-[#2a2a2a]">→</span>
                          )}
                        </div>
                      ))}
                      {chain.stage_sequence?.length > 3 && (
                        <span className="text-[#333] text-[9px]">+{chain.stage_sequence.length - 3}</span>
                      )}
                    </div>
                  )}

                  {/* Expanded view */}
                  {isOpen && (
                    <div className="mt-3 pt-3 border-t border-[#1a1a1a] animate-fade-in">
                      <div className="text-[9px] text-[#444] tracking-widest uppercase mb-1">Kill Chain</div>
                      <StageSequence stages={chain.stage_sequence ?? []} />

                      <div className="grid grid-cols-2 gap-3 mt-3">
                        {chain.confidence !== undefined && (
                          <div>
                            <div className="text-[9px] text-[#333] tracking-widest uppercase mb-0.5">Confidence</div>
                            <div className="text-[11px] text-[#666]">
                              {Math.round(chain.confidence * 100)}%
                            </div>
                          </div>
                        )}
                        {chain.detected_at && (
                          <div>
                            <div className="text-[9px] text-[#333] tracking-widest uppercase mb-0.5">Detected</div>
                            <div
                              className="text-[10px] text-[#555]"
                              suppressHydrationWarning
                            >
                              {new Date(chain.detected_at).toLocaleTimeString("en-US", { hour12: false })}
                            </div>
                          </div>
                        )}
                        {chain.chain_id && (
                          <div className="col-span-2">
                            <div className="text-[9px] text-[#333] tracking-widest uppercase mb-0.5">Chain ID</div>
                            <div className="text-[9px] text-[#444] font-mono break-all">{chain.chain_id}</div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
