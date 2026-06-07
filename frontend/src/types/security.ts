export type Severity = "low" | "medium" | "high" | "critical";
export type Decision = "allowed" | "blocked" | "review_required";
export type EventType = "prompt" | "credential" | "tool" | "browser" | "network" | "identity" | "system";

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: EventType;
  title: string;
  severity: Severity;
  decision: Decision;
  agent_id?: string;
  rule: string;
  confidence: number;
  summary: string;
  mitigation: string;
  metadata: Record<string, unknown>;
}

export interface AgentIdentity {
  agent_id: string;
  display_name: string;
  role: string;
  permissions: string[];
  trust_score: number;
  signed_session_token: string;
  status: string;
}

export interface Analytics {
  total_events: number;
  blocked_events: number;
  block_rate: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}
