"use client";

import { useState } from "react";
import { api } from "@/lib/api";

function formatAnalysis(text: string) {
  const lines = text.split("\n");
  return lines.map((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return <div key={i} className="h-2" />;

    if (
      trimmed.startsWith("##") ||
      trimmed.startsWith("**") ||
      /^[A-Z\s]{4,}:?\s*$/.test(trimmed) ||
      (trimmed.endsWith(":") && trimmed.length < 60)
    ) {
      const clean = trimmed.replace(/^#+\s*/, "").replace(/\*\*/g, "").replace(/:$/, "");
      return (
        <div key={i} className="mt-4 mb-1 first:mt-0">
          <span className="text-[9px] tracking-[0.25em] uppercase text-[#00ff88]/60 border-b border-[#00ff88]/10 pb-0.5">
            {clean}
          </span>
        </div>
      );
    }

    if (trimmed.startsWith("- ") || trimmed.startsWith("• ") || trimmed.startsWith("* ")) {
      const content = trimmed.replace(/^[-•*]\s*/, "").replace(/\*\*/g, "");
      return (
        <div key={i} className="flex gap-2 py-0.5">
          <span className="text-[#00ff88]/30 mt-0.5 flex-shrink-0">▸</span>
          <span className="text-[10px] text-[#888] leading-relaxed">{content}</span>
        </div>
      );
    }

    if (/^\d+\.\s/.test(trimmed)) {
      const [num, ...rest] = trimmed.split(/\.\s/);
      const content = rest.join(". ").replace(/\*\*/g, "");
      return (
        <div key={i} className="flex gap-2 py-0.5">
          <span className="text-[#00ff88]/30 text-[9px] flex-shrink-0 w-4 text-right">{num}.</span>
          <span className="text-[10px] text-[#888] leading-relaxed">{content}</span>
        </div>
      );
    }

    const clean = trimmed.replace(/\*\*/g, "");
    return (
      <p key={i} className="text-[10px] text-[#777] leading-relaxed py-0.5">
        {clean}
      </p>
    );
  });
}

export default function AIPanel() {
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [chainInfo, setChainInfo] = useState<{ pattern_name?: string; severity?: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timestamp, setTimestamp] = useState<string | null>(null);

  const analyze = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.analyzeChain();
      setAnalysis(res.analysis ?? "No analysis returned.");
      setChainInfo(res.chain ?? null);
      setTimestamp(new Date().toLocaleTimeString("en-US", { hour12: false }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel flex flex-col" style={{ minHeight: 280 }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a1a]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[#444]">◈</span>
          <h2 className="text-[11px] font-bold tracking-[0.2em] uppercase text-[#00ff88]">
            AI ANALYSIS
          </h2>
          {chainInfo && (
            <span className="text-[9px] text-[#333] truncate max-w-[140px]">
              // {chainInfo.pattern_name}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {timestamp && (
            <span className="text-[9px] text-[#333]" suppressHydrationWarning>
              {timestamp}
            </span>
          )}
          <button
            onClick={analyze}
            disabled={loading}
            className={`text-[9px] px-3 py-1.5 border tracking-widest uppercase transition-all font-bold ${
              loading
                ? "border-[#1a1a1a] text-[#333] cursor-not-allowed"
                : "border-[#00ff88]/40 text-[#00ff88] hover:bg-[#00ff88]/5 hover:border-[#00ff88] hover:shadow-neon-sm"
            }`}
          >
            {loading ? (
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-1.5 h-1.5 bg-[#333] rounded-full animate-pulse" />
                <span className="typing-dots">ANALYZING</span>
              </span>
            ) : (
              "⚡ ANALYZE ATTACK"
            )}
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto px-4 py-3">
        {error ? (
          <div className="text-[#ff3366] text-[10px] border border-[#ff3366]/20 p-3 bg-[#ff3366]/5 rounded-sm">
            <div className="font-bold mb-1">ANALYSIS FAILED</div>
            <div className="text-[#ff3366]/70">{error}</div>
            {error.includes("404") && (
              <div className="mt-2 text-[#444]">→ No attack chains found. Ingest logs first.</div>
            )}
            {error.includes("rate") && (
              <div className="mt-2 text-[#444]">→ Rate limit hit. Try again shortly.</div>
            )}
          </div>
        ) : analysis ? (
          <div className="animate-fade-in">
            {chainInfo && (
              <div className="flex gap-4 mb-4 pb-3 border-b border-[#1a1a1a]">
                <div>
                  <div className="text-[9px] text-[#333] tracking-widest uppercase mb-0.5">Pattern</div>
                  <div className="text-[10px] text-[#666]">{chainInfo.pattern_name}</div>
                </div>
                {chainInfo.severity && (
                  <div>
                    <div className="text-[9px] text-[#333] tracking-widest uppercase mb-0.5">Severity</div>
                    <span className={`badge-${chainInfo.severity?.toLowerCase()} text-[9px] px-1.5 py-0.5 uppercase`}>
                      {chainInfo.severity}
                    </span>
                  </div>
                )}
              </div>
            )}
            <div className="space-y-0.5">{formatAnalysis(analysis)}</div>
          </div>
        ) : !loading ? (
          <div className="flex flex-col items-center justify-center h-24 gap-3 text-[#222]">
            <span className="text-[28px]">⬡</span>
            <span className="text-[10px] tracking-widest uppercase text-[#2a2a2a]">
              Click ANALYZE ATTACK to run AI threat analysis
            </span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
