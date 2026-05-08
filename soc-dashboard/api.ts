const BASE = "http://192.168.241.130:8001";

export interface Alert {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  user: string;
  host: string;
  timestamp: string;
  tactic?: string;
  technique?: string;
  description?: string;
  title?: string;
}

export interface Chain {
  chain_id?: string;
  pattern_name: string;
  stage_sequence: string[];
  risk_score: number;
  severity: string;
  confidence?: number;
  detected_at?: string;
}

export interface ChainsResponse {
  total: number;
  chains: Chain[];
}

export interface AnalysisResponse {
  chain: Chain | null;
  analysis: string | null;
  ai_status: Record<string, unknown>;
}

export interface ChatResponse {
  response: string;
  cached: boolean;
  context_used?: { chains: number; alerts: number };
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "Unknown error");
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
  getAlerts: (limit = 50) =>
    apiFetch<Alert[]>(`/alerts?limit=${limit}`),

  getChains: (limit = 20) =>
    apiFetch<ChainsResponse>(`/chains?limit=${limit}`),

  analyzeChain: (chainId?: string) =>
    apiFetch<AnalysisResponse>(
      `/ai/analyze${chainId ? `?chain_id=${chainId}` : ""}`
    ),

  chat: (query: string) =>
    apiFetch<ChatResponse>("/chat", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),
};
