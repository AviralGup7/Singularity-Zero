import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  getTriageState,
  recordTriageAction,
  triageWebSocketUrl,
  type AnalystPresence,
  type TriageFindingState,
} from '@/api/triage';

export function getTriageAnalyst() {
  const key = 'triage_analyst_identity';
  const existing = localStorage.getItem(key);
  if (existing) {
    try {
      return JSON.parse(existing) as { analyst_id: string; analyst_name: string };
    } catch {
      localStorage.removeItem(key);
    }
  }
  const analyst = {
    analyst_id: `analyst-${crypto.randomUUID()}`,
    analyst_name: `Analyst ${crypto.randomUUID().slice(0, 4).toUpperCase()}`,
  };
  localStorage.setItem(key, JSON.stringify(analyst));
  return analyst;
}

interface TriageMessage {
  type: string;
  analysts?: AnalystPresence[];
  state?: TriageFindingState;
  event?: { finding_id?: string };
}

export function useTriageCollaboration(runId: string, findingId: string) {
  const analyst = useMemo(() => getTriageAnalyst(), []);
  const [state, setState] = useState<TriageFindingState | null>(null);
  const [presence, setPresence] = useState<AnalystPresence[]>([]);
  const [connected, setConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!runId || !findingId) return;
    const controller = new AbortController();
    getTriageState(runId, findingId, controller.signal)
      .then(setState)
      .catch(() => undefined);
    return () => controller.abort();
  }, [runId, findingId]);

  useEffect(() => {
    if (!runId) return;
    const socket = new WebSocket(triageWebSocketUrl(runId, analyst));
    socketRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      socket.send(JSON.stringify({ type: 'presence', finding_id: findingId, cursor: { area: 'comments' } }));
    };
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data) as TriageMessage;
      if (message.type === 'presence' && message.analysts) {
        setPresence(message.analysts);
      }
      if (message.type === 'triage_event' && message.state && message.event?.finding_id === findingId) {
        setState(message.state);
      }
    };

    return () => {
      socket.close();
      if (socketRef.current === socket) socketRef.current = null;
    };
  }, [analyst, findingId, runId]);

  const broadcastCursor = useCallback((cursor: Record<string, unknown>) => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type: 'cursor', finding_id: findingId, cursor }));
  }, [findingId]);

  const sendAction = useCallback(async (action: string, payload: Record<string, unknown>) => {
    const optimistic = socketRef.current;
    if (optimistic && optimistic.readyState === WebSocket.OPEN) {
      optimistic.send(JSON.stringify({ type: 'triage_action', finding_id: findingId, action, payload }));
      return;
    }
    const result = await recordTriageAction(runId, findingId, action, payload, analyst);
    setState(result.state);
  }, [analyst, findingId, runId]);

  return {
    analyst,
    state,
    setState,
    presence,
    connected,
    broadcastCursor,
    sendAction,
  };
}
