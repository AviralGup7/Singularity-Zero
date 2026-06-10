import { useEffect, useRef, useState, useCallback } from 'react';
import { getStreamSubprotocols } from '@/api/streamAuth';
import {
  useMountedRef,
  useReconnectBackoff,
  useDedupSet,
} from './realtime/shared';

export type WSConnectionState = 'connected' | 'reconnecting' | 'disconnected';

/** All WebSocket message types matching the backend protocol. */
export type WSMessageType =
  | 'progress'
  | 'status'
  | 'log'
  | 'error'
  | 'heartbeat'
  | 'ack'
  | 'subscribe'
  | 'unsubscribe'
  | 'telemetry'
  | 'backpressure';

export interface WSProgressMessage {
  type: 'progress';
  id: string;
  sequence: number;
  timestamp: number;
  job_id: string;
  stage: string;
  stage_label: string;
  percent: number;
  processed: number | null;
  total: number | null;
  message: string;
  target: string;
}

export interface WSStatusMessage {
  type: 'status';
  id: string;
  sequence: number;
  timestamp: number;
  job_id: string;
  status: string;
  previous_status: string;
  stage: string;
  stage_label: string;
  progress_percent: number;
  error: string | null;
  target: string;
  metadata: Record<string, unknown>;
}

export interface WSLogMessage {
  type: 'log';
  id: string;
  sequence: number;
  timestamp: number;
  job_id: string;
  line: string;
  source: string;
  level: string;
}

export interface WSErrorMessage {
  type: 'error';
  id: string;
  sequence: number;
  timestamp: number;
  code: string;
  message: string;
  details: Record<string, unknown>;
  recoverable: boolean;
}

export interface WSHeartbeatMessage {
  type: 'heartbeat';
  id: string;
  sequence: number;
  timestamp: number;
  server_time: number;
  interval: number;
}

export interface WSAckMessage {
  type: 'ack';
  id: string;
  sequence: number;
  timestamp: number;
  ack_id: string;
  accepted: boolean;
  reason: string;
}

export interface WSTelemetryMessage {
  type: 'telemetry';
  id: string;
  sequence: number;
  timestamp: number;
  model_id: string;
  weight_drift: number;
  l2_norm: number;
  action_distribution: number[];
  metadata: Record<string, unknown>;
}

export interface WSBackpressureMessage {
  type: 'backpressure';
  id: string;
  sequence: number;
  timestamp: number;
  scope: string;
  target: string;
  dropped: number;
  queue_depth: number;
  watermark: number;
  connection_id: string;
}

export type WSMessage =
  | WSProgressMessage
  | WSStatusMessage
  | WSLogMessage
  | WSErrorMessage
  | WSHeartbeatMessage
  | WSAckMessage
  | WSTelemetryMessage
  | WSBackpressureMessage;

interface UseWebSocketOptions {
  jobId: string | undefined;
  enabled?: boolean;
  onMessage: (data: unknown) => void;
  onFallback?: () => void;
  /** Channel to subscribe to on connect (e.g. "job:<id>"). */
  subscribeChannel?: string;
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
  subscribeChannel,
}: UseWebSocketOptions): UseWebSocketReturn {

  const [connectionState, setConnectionState] = useState<WSConnectionState>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasConnectedRef = useRef(false);
  const lastSequenceRef = useRef(0);

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
      const protocols = getStreamSubprotocols();
      const ws = new WebSocket(wsUrl, protocols);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        hasConnectedRef.current = true;
        backoff.reset();
        setConnectionState('connected');

        // Send SubscribeMessage to register on the appropriate channel.
        // On reconnect, include resume_from so the server can replay
        // buffered messages we missed.
        try {
          const channel = subscribeChannel || `logs:${jobId}`;
          const subscribePayload: Record<string, unknown> = {
            type: 'subscribe',
            channel,
            job_id: jobId,
          };
          if (lastSequenceRef.current > 0) {
            subscribePayload.resume_from = lastSequenceRef.current;
          }
          ws.send(JSON.stringify(subscribePayload));
        } catch {
          // Subscribe send failure is non-fatal; the server may already
          // have us on a default subscription.
        }
      };

      ws.onmessage = (event) => {
        if (!mountedRef.current) return;
        try {
          const data = JSON.parse(event.data) as Record<string, unknown>;

          if (typeof data === 'string') {
            onMessageRef.current({ type: 'log', line: data });
            return;
          }

          const msgType = typeof data.type === 'string' ? data.type : '';

          // Track sequence for reconnect resume_from
          if (typeof data.sequence === 'number' && data.sequence > lastSequenceRef.current) {
            lastSequenceRef.current = data.sequence;
          }

          // Dedup by server-issued id or composite key
          const id = (data.id as string) || `${data.timestamp}-${msgType}`;
          if (id && !seenIds.add(String(id))) return;

          // Route all message types through onMessage for consumer flexibility
          onMessageRef.current(data);
        } catch {
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

  }, [jobId, enabled, cleanup, mountedRef, backoff, seenIds, subscribeChannel]);

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
