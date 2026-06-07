import { useEffect, useRef, useState, useCallback } from 'react';
import { getStreamSubprotocols } from '@/api/streamAuth';
import {
  useMountedRef,
  useReconnectBackoff,
  useDedupSet,
} from './realtime/shared';

export type WSConnectionState = 'connected' | 'reconnecting' | 'disconnected';

interface UseWebSocketOptions {
  jobId: string | undefined;
  enabled?: boolean;
  onMessage: (data: unknown) => void;
  onFallback?: () => void;
}

interface UseWebSocketReturn {
  connectionState: WSConnectionState;
  reconnect: () => void;
  disconnect: () => void;
}

const MIN_DELAY = 1000;
const MAX_DELAY = 30000;
const BACKOFF_FACTOR = 2;
const DEDUP_MAX = 5000;
const DEDUP_PRUNE = 2000;

/**
 * WebSocket consumer for the `/ws/logs/{jobId}` endpoint. Logs stream at
 * high rates during a 12-hour scan, so we:
 *   - reconnect with exponential backoff capped at 30s
 *   - dedup by server-issued `id` / `update_id` (FIFO cap 5000)
 *   - guard every async callback with the shared `mountedRef` so a torn-down
 *     component never receives a setState
 *
 * R6: the mounted-ref, reconnect-backoff, and dedup-set primitives now
 * come from `./realtime/shared`, matching `useSSEProgress` byte-for-byte
 * so future behavioural changes only have to be made once.
 */
export function useWebSocket({
  jobId,
  enabled = true,
  onMessage,
  onFallback,
}: UseWebSocketOptions): UseWebSocketReturn {

  const [connectionState, setConnectionState] = useState<WSConnectionState>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasConnectedRef = useRef(false);

  // R6: shared primitives.
  const { mountedRef } = useMountedRef();
  const backoff = useReconnectBackoff({ minDelayMs: MIN_DELAY, maxDelayMs: MAX_DELAY, factor: BACKOFF_FACTOR });
  const seenIds = useDedupSet({ maxSize: DEDUP_MAX, pruneChunk: DEDUP_PRUNE });

  const onMessageRef = useRef(onMessage);
  const onFallbackRef = useRef(onFallback);

  useEffect(() => {
    onMessageRef.current = onMessage;
    onFallbackRef.current = onFallback;
  }, [onMessage, onFallback]);

  const connectRef = useRef<() => void>(() => {});

  const cleanup = useCallback(() => {
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!jobId || !enabled || !mountedRef.current) return;

    cleanup();

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/logs/${jobId}`;

    try {
      // Pass token via subprotocol to avoid URL exposure. The auth transport
      // is centralised in `@/api/streamAuth` so swapping to a short-lived
      // stream token only requires editing one module.
      const protocols = getStreamSubprotocols();
      const ws = new WebSocket(wsUrl, protocols);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        hasConnectedRef.current = true;
        backoff.reset();
        setConnectionState('connected');
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const data = JSON.parse(event.data);

          // Support multiple formats including raw strings from older backends
          if (typeof data === 'string') {
            onMessageRef.current({ type: 'log', line: data });
            return;
          }

          const id = data.id || data.update_id || `${data.timestamp}-${data.type}`;
          if (id && !seenIds.add(String(id))) return;
          onMessageRef.current(data);
        } catch {
          // If not JSON, treat as raw log line
          onMessageRef.current({ type: 'log', line: event.data });
        }
      };

      let fallbackCalled = false;

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setConnectionState('disconnected');
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        const neverConnected = !hasConnectedRef.current;
        if (neverConnected) {
          setConnectionState('disconnected');
          if (!fallbackCalled) {
            fallbackCalled = true;
            onFallbackRef.current?.();
          }
          return;
        }

        setConnectionState('reconnecting');
        if (!fallbackCalled) {
          fallbackCalled = true;
          onFallbackRef.current?.();
        }

        const delay = backoff.delayMs();
        backoff.bump();
        retryTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) {
            connectRef.current();
          }
        }, delay);
      };
    } catch {
      setConnectionState('disconnected');
      onFallbackRef.current?.();
    }

  }, [jobId, enabled, cleanup, mountedRef, backoff, seenIds]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const reconnect = useCallback(() => {
    backoff.reset();
    connect();
  }, [connect, backoff]);

  const disconnect = useCallback(() => {
    cleanup();
    setConnectionState('disconnected');
  }, [cleanup]);

  useEffect(() => {
    mountedRef.current = true;
    hasConnectedRef.current = false;

    // Defer connection logic to avoid synchronous state updates in effect
    Promise.resolve().then(() => {
      if (enabled && jobId) {
        connect();
      } else {
        setConnectionState('disconnected');
      }
    });

    return () => {
      mountedRef.current = false;
      cleanup();
    };
  }, [jobId, enabled, connect, cleanup, mountedRef]);

  return { connectionState, reconnect, disconnect };
}
