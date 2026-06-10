import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  assignFinding,
  getTriageState,
  lockFinding,
  recordTriageAction,
  triageWebSocketUrl,
  unlockFinding,
  type AnalystPresence,
  type TriageFindingState,
  type TriageLockConflict,
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
  cursor?: Record<string, unknown>;
  user_id?: string;
}

const TRIAGE_MIN_DELAY = 1000;
const TRIAGE_MAX_DELAY = 30000;
const TRIAGE_BACKOFF_FACTOR = 2;

export function useTriageCollaboration(runId: string, findingId: string) {
  const analyst = useMemo(() => getTriageAnalyst(), []);
  const [state, setState] = useState<TriageFindingState | null>(null);
  const [presence, setPresence] = useState<AnalystPresence[]>([]);
  const [connected, setConnected] = useState(false);
  const [lockConflict, setLockConflict] = useState<TriageLockConflict | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(TRIAGE_MIN_DELAY);
  const mountedRef = useRef(true);
  const hasConnectedRef = useRef(false);

  useEffect(() => {
    if (!runId || !findingId) return;
    const controller = new AbortController();
    getTriageState(runId, findingId, controller.signal)
      .then(setState)
      .catch((err) => {
        console.error('Failed to fetch triage state:', err);
      });
    return () => controller.abort();
  }, [runId, findingId]);

  const connectRef = useRef<() => void>(() => {});

  const cleanupSocket = useCallback(() => {
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    if (socketRef.current) {
      socketRef.current.onclose = null;
      socketRef.current.onerror = null;
      socketRef.current.onmessage = null;
      socketRef.current.close();
      socketRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!runId || !mountedRef.current) return;

    cleanupSocket();

    const socket = new WebSocket(triageWebSocketUrl(runId, analyst));
    socketRef.current = socket;

    socket.onopen = () => {
      if (!mountedRef.current) return;
      hasConnectedRef.current = true;
      backoffRef.current = TRIAGE_MIN_DELAY;
      setConnected(true);
      socket.send(JSON.stringify({ type: 'presence', finding_id: findingId, cursor: { area: 'comments' } }));
    };

    socket.onclose = () => {
      if (!mountedRef.current) return;
      setConnected(false);

      // Reconnect with exponential backoff
      const delay = backoffRef.current;
      backoffRef.current = Math.min(backoffRef.current * TRIAGE_BACKOFF_FACTOR, TRIAGE_MAX_DELAY);
      retryTimeoutRef.current = setTimeout(() => {
        if (mountedRef.current) {
          connectRef.current();
        }
      }, delay);
    };

    socket.onerror = () => {
      if (!mountedRef.current) return;
      setConnected(false);
    };

    socket.onmessage = (event) => {
      if (!mountedRef.current) return;
      let message: TriageMessage | null = null;
      try {
        message = JSON.parse(event.data) as TriageMessage;
      } catch (err) {
        console.warn('[TriageCollaboration] failed to parse WebSocket message', err);
      }
      if (!message) return;

      if (message.type === 'connected') {
        // Server ack — connection is fully established
        return;
      }

      if (message.type === 'presence' && message.analysts) {
        setPresence(message.analysts);
      }

      if (message.type === 'cursor' && message.user_id !== analyst.analyst_id) {
        // Cursor broadcast from another analyst — consumers can use this
        // to show remote cursors. Forward through presence or a dedicated
        // cursor state if needed.
        setPresence((prev) =>
          prev.map((p) =>
            p.analyst_id === message!.user_id
              ? { ...p, cursor: message!.cursor }
              : p
          )
        );
      }

      if (message.type === 'triage_event' && message.state && message.event?.finding_id === findingId) {
        setState(message.state);
        setLockConflict(null);
      }
      if (message.type === 'triage_lock_conflict' && message.event?.finding_id === findingId) {
        setLockConflict((message as unknown as { conflict: TriageLockConflict }).conflict);
      }
    };
  }, [analyst, findingId, runId, cleanupSocket]);

  useEffect(() => {
    mountedRef.current = true;
    hasConnectedRef.current = false;
    backoffRef.current = TRIAGE_MIN_DELAY;

    connectRef.current = connect;

    Promise.resolve().then(() => {
      if (runId) {
        connect();
      }
    });

    return () => {
      mountedRef.current = false;
      cleanupSocket();
    };
  }, [runId, connect, cleanupSocket]);

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

  const assignToMe = useCallback(async () => {
    if (!runId || !findingId) return { conflict: undefined as TriageLockConflict | undefined };
    const result = await assignFinding(
      runId,
      findingId,
      analyst.analyst_id,
      analyst.analyst_name,
      analyst,
    );
    if (result.state) setState(result.state);
    if (result.conflict) setLockConflict(result.conflict);
    return { conflict: result.conflict };
  }, [analyst, findingId, runId]);

  const assignTo = useCallback(
    async (analystId: string, analystName: string) => {
      if (!runId || !findingId) return { conflict: undefined as TriageLockConflict | undefined };
      const result = await assignFinding(
        runId,
        findingId,
        analystId,
        analystName,
        analyst,
      );
      if (result.state) setState(result.state);
      if (result.conflict) setLockConflict(result.conflict);
      return { conflict: result.conflict };
    },
    [analyst, findingId, runId],
  );

  const lockForMe = useCallback(async () => {
    if (!runId || !findingId) return { conflict: undefined as TriageLockConflict | undefined };
    const result = await lockFinding(runId, findingId, analyst);
    if (result.state) setState(result.state);
    if (result.conflict) setLockConflict(result.conflict);
    return { conflict: result.conflict };
  }, [analyst, findingId, runId]);

  const releaseLock = useCallback(async () => {
    if (!runId || !findingId) return;
    const result = await unlockFinding(runId, findingId, analyst);
    if (result.state) setState(result.state);
  }, [analyst, findingId, runId]);

  const dismissConflict = useCallback(() => setLockConflict(null), []);

  return {
    analyst,
    state,
    setState,
    presence,
    connected,
    lockConflict,
    dismissConflict,
    broadcastCursor,
    sendAction,
    assignToMe,
    assignTo,
    lockForMe,
    releaseLock,
  };
}
