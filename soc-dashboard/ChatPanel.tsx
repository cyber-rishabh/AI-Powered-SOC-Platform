"use client";

import { useState, useRef, useEffect, KeyboardEvent } from "react";
import { api } from "@/lib/api";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  cached?: boolean;
  timestamp: Date;
  error?: boolean;
}

const SUGGESTED_QUERIES = [
  "What are the most critical threats right now?",
  "Any lateral movement indicators?",
  "Summarize the latest attack chain",
  "Which hosts are most at risk?",
];

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === "user";

  return (
    <div
      className={`flex gap-2 animate-slide-up ${isUser ? "flex-row-reverse" : "flex-row"}`}
    >
      {/* Avatar */}
      <div
        className={`w-6 h-6 flex-shrink-0 flex items-center justify-center text-[9px] border rounded-sm mt-0.5 ${
          isUser
            ? "border-[#252525] text-[#555] bg-[#111]"
            : msg.error
            ? "border-[#ff3366]/30 text-[#ff3366] bg-[#ff3366]/5"
            : "border-[#00ff88]/20 text-[#00ff88] bg-[#00ff88]/5"
        }`}
      >
        {isUser ? "YOU" : msg.error ? "✗" : "AI"}
      </div>

      {/* Bubble */}
      <div className={`max-w-[85%] ${isUser ? "items-end" : "items-start"} flex flex-col gap-1`}>
        <div
          className={`px-3 py-2 rounded-sm text-[10px] leading-relaxed ${
            isUser
              ? "bg-[#111] border border-[#252525] text-[#888]"
              : msg.error
              ? "bg-[#ff3366]/5 border border-[#ff3366]/20 text-[#ff3366]/80"
              : "bg-[#0f1a14] border border-[#00ff88]/10 text-[#aaa]"
          }`}
        >
          <pre className="whitespace-pre-wrap font-mono break-words">{msg.content}</pre>
        </div>
        <div className={`flex items-center gap-2 ${isUser ? "flex-row-reverse" : ""}`}>
          <span className="text-[8px] text-[#2a2a2a]" suppressHydrationWarning>
            {msg.timestamp.toLocaleTimeString("en-US", { hour12: false })}
          </span>
          {msg.cached !== undefined && !isUser && (
            <span
              className={`text-[8px] px-1.5 py-0.5 rounded-sm uppercase tracking-wider ${
                msg.cached
                  ? "bg-[#ffaa00]/10 text-[#ffaa00]/60 border border-[#ffaa00]/10"
                  : "bg-[#00ff88]/5 text-[#00ff88]/40 border border-[#00ff88]/10"
              }`}
            >
              {msg.cached ? "CACHED" : "LIVE"}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ChatPanel() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initialize welcome message client-side only to avoid hydration mismatch
  useEffect(() => {
    setMessages([
      {
        id: "welcome",
        role: "assistant",
        content:
          "SOC COPILOT ONLINE.\n\nI have access to live attack chains and alerts from your environment. Ask me anything about current threats, suspicious activity, or recommended actions.",
        timestamp: new Date(),
      },
    ]);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async (query?: string) => {
    const text = (query ?? input).trim();
    if (!text || loading) return;

    const userMsg: Message = {
      id: `u-${Date.now()}`,
      role: "user",
      content: text,
      timestamp: new Date(),
    };

    setMessages((m) => [...m, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await api.chat(text);
      const aiMsg: Message = {
        id: `a-${Date.now()}`,
        role: "assistant",
        content: res.response ?? "No response received.",
        cached: res.cached,
        timestamp: new Date(),
      };
      setMessages((m) => [...m, aiMsg]);
    } catch (e) {
      const errMsg: Message = {
        id: `e-${Date.now()}`,
        role: "assistant",
        content: e instanceof Error ? e.message : "Request failed. Check backend connection.",
        timestamp: new Date(),
        error: true,
      };
      setMessages((m) => [...m, errMsg]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="panel flex flex-col" style={{ minHeight: 320 }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a1a]">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[#444]">◈</span>
          <h2 className="text-[11px] font-bold tracking-[0.2em] uppercase text-[#00ff88]">
            SOC COPILOT
          </h2>
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              loading
                ? "bg-[#ffaa00] animate-pulse shadow-[0_0_4px_#ffaa00]"
                : "bg-[#00ff88] shadow-[0_0_4px_#00ff88]"
            }`}
          />
          <span className="text-[9px] text-[#333]">
            {loading ? "PROCESSING" : "READY"}
          </span>
        </div>
        <button
          onClick={() =>
            setMessages([
              {
                id: "welcome-reset",
                role: "assistant",
                content: "Chat cleared. Ready for new queries.",
                timestamp: new Date(),
              },
            ])
          }
          className="text-[9px] text-[#333] hover:text-[#555] transition-colors tracking-widest uppercase"
        >
          CLR
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-auto px-4 py-3 space-y-3 min-h-0">
        {messages.map((msg) => (
          <MessageBubble key={msg.id} msg={msg} />
        ))}

        {/* Typing indicator */}
        {loading && (
          <div className="flex gap-2 animate-fade-in">
            <div className="w-6 h-6 flex-shrink-0 flex items-center justify-center text-[9px] border border-[#00ff88]/20 text-[#00ff88] bg-[#00ff88]/5 rounded-sm mt-0.5">
              AI
            </div>
            <div className="px-3 py-2 bg-[#0f1a14] border border-[#00ff88]/10 rounded-sm">
              <div className="flex gap-1 items-center h-4">
                {[0, 1, 2].map((i) => (
                  <div
                    key={i}
                    className="w-1 h-1 bg-[#00ff88]/40 rounded-full animate-pulse"
                    style={{ animationDelay: `${i * 0.2}s` }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Suggested queries */}
      {messages.length <= 1 && !loading && (
        <div className="px-4 pb-2">
          <div className="text-[9px] text-[#2a2a2a] tracking-widest uppercase mb-2">SUGGESTED</div>
          <div className="grid grid-cols-2 gap-1">
            {SUGGESTED_QUERIES.map((q, i) => (
              <button
                key={i}
                onClick={() => send(q)}
                className="text-left text-[9px] px-2 py-1.5 border border-[#1a1a1a] text-[#333] hover:text-[#555] hover:border-[#252525] transition-colors rounded-sm leading-tight"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="px-3 pb-3 pt-2 border-t border-[#1a1a1a]">
        <div className="flex gap-2 items-end">
          <div className="flex-1 relative">
            <span className="absolute left-2.5 top-2 text-[#333] text-[10px] select-none">›</span>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask about threats, alerts, attack chains..."
              rows={1}
              disabled={loading}
              className="w-full bg-[#111] border border-[#252525] text-[#888] text-[10px] px-2 py-2 pl-6 resize-none focus:outline-none focus:border-[#00ff88]/30 focus:text-[#aaa] placeholder-[#2a2a2a] rounded-sm transition-colors disabled:opacity-40 leading-relaxed"
              style={{ minHeight: "36px", maxHeight: "100px" }}
              onInput={(e) => {
                const t = e.target as HTMLTextAreaElement;
                t.style.height = "auto";
                t.style.height = Math.min(t.scrollHeight, 100) + "px";
              }}
            />
          </div>
          <button
            onClick={() => send()}
            disabled={!input.trim() || loading}
            className={`flex-shrink-0 px-3 py-2 text-[9px] font-bold tracking-widest uppercase border rounded-sm transition-all h-[36px] ${
              input.trim() && !loading
                ? "border-[#00ff88]/40 text-[#00ff88] hover:bg-[#00ff88]/5 hover:border-[#00ff88]"
                : "border-[#1a1a1a] text-[#2a2a2a] cursor-not-allowed"
            }`}
          >
            SEND
          </button>
        </div>
        <div className="text-[8px] text-[#222] mt-1.5 px-0.5">
          ENTER to send · SHIFT+ENTER for newline
        </div>
      </div>
    </div>
  );
}
