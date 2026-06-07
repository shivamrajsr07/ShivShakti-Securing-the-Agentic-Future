import type { AgentIdentity, Analytics, SecurityEvent } from "../types/security";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init
  });
  if (!response.ok) {
    throw new Error(`API ${response.status}: ${await response.text()}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  agents: () => request<AgentIdentity[]>("/api/agents"),
  events: () => request<SecurityEvent[]>("/api/events?limit=40"),
  analytics: () => request<Analytics>("/api/analytics"),
  simulate: (attackType: string) =>
    request<SecurityEvent>("/api/demo/simulate", {
      method: "POST",
      body: JSON.stringify({ attack_type: attackType })
    }),
  scanPrompt: (prompt: string) =>
    request<SecurityEvent>("/api/scan/prompt", {
      method: "POST",
      body: JSON.stringify({ agent_id: "planner-01", prompt })
    }),
  scanNetwork: (content: string) =>
    request<SecurityEvent>("/api/scan/network", {
      method: "POST",
      body: JSON.stringify({ agent_id: "analyst-01", content })
    })
};
