import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import { localAgents, localAnalytics } from "../services/localSecurity";
import type { AgentIdentity, Analytics, SecurityEvent } from "../types/security";

export function useSecurityStream() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [agents, setAgents] = useState<AgentIdentity[]>(localAgents);
  const [analytics, setAnalytics] = useState<Analytics>({
    total_events: 0,
    blocked_events: 0,
    block_rate: 0,
    by_type: {},
    by_severity: {}
  });
  const [connected, setConnected] = useState(false);

  async function refresh() {
    try {
      const [nextEvents, nextAgents, nextAnalytics] = await Promise.all([api.events(), api.agents(), api.analytics()]);
      setEvents(nextEvents);
      setAgents(nextAgents);
      setAnalytics(nextAnalytics);
      setConnected(true);
    } catch (error) {
      setConnected(false);
      throw error;
    }
  }

  function recordLocalEvent(event: SecurityEvent) {
    setEvents((current) => {
      const nextEvents = [event, ...current].slice(0, 40);
      setAnalytics(localAnalytics(nextEvents));
      return nextEvents;
    });
    setAgents((current) => (current.length ? current : localAgents));
  }

  useEffect(() => {
    refresh().catch(console.error);
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const sameOriginWsBase = `${protocol}://${window.location.host}`;
    const httpApiBase = import.meta.env.VITE_API_BASE_URL as string | undefined;
    const apiBase =
      import.meta.env.VITE_WS_BASE_URL ??
      (httpApiBase ? httpApiBase.replace(/^http/, "ws") : sameOriginWsBase);
    const socket = new WebSocket(`${apiBase}/api/ws/events`);
    socket.onopen = () => setConnected(true);
    socket.onclose = () => refresh().catch(console.error);
    socket.onerror = () => refresh().catch(console.error);
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as SecurityEvent;
      setEvents((current) => [event, ...current].slice(0, 40));
      api.analytics().then(setAnalytics).catch(console.error);
    };
    return () => socket.close();
  }, []);

  const chartData = useMemo(
    () => Object.entries(analytics.by_type).map(([name, value]) => ({ name, value })),
    [analytics.by_type]
  );

  return { events, agents, analytics, chartData, connected, refresh, recordLocalEvent };
}
