/**
 * `useRealtimeStream` — R6 unified facade over SSE and WebSocket.
 *
 * The frontend has two real-time transports that historically evolved
 * independently:
 *
 *   - `useSSEProgress` — `EventSource` against `/api/jobs/{id}/{endpoint}/stream`
 *     with a heartbeat watchdog, batched flush, and structured events.
 *     Best for: stage updates, finding batches, mesh health.
 *
 *   - `useWebSocket` — `WebSocket` against `/ws/logs/{id}` with raw log
 *     lines and JSON envelopes. Best for: high-throughput log tailing.
 *
 * Some flows (notably `useJobMonitor`) consume *both* at once, which
 * doubles the connection overhead and forces a dedup layer in the
 * consumer. This hook is a thin facade that:
 *
 *   1. Lets the caller pick a transport (`'sse' | 'ws' | 'auto'`).
 *   2. Normalises the connection lifecycle through the same shared
 *      `useRealtimeStream` API: `{ connectionState, reconnect, disconnect,
 *      isPollingFallback }`.
 *   3. Provides a single typed `onEvent` callback that receives a
 *      uniform `RealtimeEvent<T>` envelope, regardless of transport.
 *
 * Existing `useSSEProgress` and `useWebSocket` are kept intact for
 * direct use (they have SSE-specific batching and WS-specific
 * log-only semantics that consumers depend on), and `useRealtimeStream`
 * is the recommended path for *new* code.
 */

import { useEffect, useMemo, useRef } from 'react';
import { useSSEProgress, type SseEvent } from './useSSEProgress';
import { useWebSocket } from './useWebSocket';

export type RealtimeTransport = 'sse' | 'ws' | 'auto';

export interface RealtimeEvent<T = unknown> {
  /** A best-effort id for dedup; SSE frames have a server id, WS frames
   *  fall back to a synthesized timestamp-based key. */
  id: string;
  type: string;
  timestamp: number;
  data: T;
  /** Which transport produced the event. */
  source: 'sse' | 'ws';
}

export type RealtimeConnectionState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnected'
  | 'failed'
  | 'closed';

export interface UseRealtimeStreamOptions<T = unknown> {
  /** Identifies the upstream resource (job id, run id, etc.). */
  resourceId: string | undefined;
  /** Whether the connection is allowed to open. False closes any open
   *  connection and keeps the state machine at rest. */
  enabled?: boolean;
  /** Transport selection. `'auto'` prefers SSE when available, falling
   *  back to WebSocket on a hard error (e.g. `EventSource` is blocked
   *  by a corporate proxy). */
  transport?: RealtimeTransport;
  /**
   * SSE endpoint sub-path. Mirrors `useSSEProgress`'s `endpoint` option
   * (`'progress' | 'logs'`). Ignored when `transport === 'ws'`.
   */
  sseEndpoint?: 'logs' | 'progress';
  onEvent?: (event: RealtimeEvent<T>) => void;
  onFallback?: () => void;
}

export interface UseRealtimeStreamReturn {
  connectionState: RealtimeConnectionState;
  isPollingFallback: boolean;
  reconnect: () => void;
  disconnect: () => void;
  /** Resolved transport after `'auto'` resolution. Useful for diagnostics. */
  effectiveTransport: 'sse' | 'ws';
}

/**
 * Stable ref helper for the latest callback. Mirrors the pattern used
 * throughout `useSSEProgress` / `useWebSocket` so we don't have to add
 * the callback to the dep array of the underlying hooks (which would
 * re-subscribe the connection on every render).
 */
function useLatestRef<T>(value: T | undefined) {
  const ref = useRef(value);
  useEffect(() => {
    ref.current = value;
  }, [value]);
  return ref;
}

export function useRealtimeStream<T = unknown>({
  resourceId,
  enabled = true,
  transport = 'auto',
  sseEndpoint = 'progress',
  onEvent,
  onFallback,
}: UseRealtimeStreamOptions<T>): UseRealtimeStreamReturn {
  const useSse = transport === 'sse' || transport === 'auto';
  const useWs = transport === 'ws' || transport === 'auto';

  const onEventRef = useLatestRef(onEvent);
  const onFallbackRef = useLatestRef(onFallback);

  const sse = useSSEProgress({
    jobId: useSse ? resourceId : undefined,
    enabled: useSse && enabled,
    endpoint: sseEndpoint,
    onEvent: useSse
      ? (event: SseEvent) => {
          onEventRef.current?.({
            id: event.id,
            type: event.event_type,
            timestamp: event.timestamp,
            data: event.data as T,
            source: 'sse',
          });
        }
      : undefined,
  });

  const ws = useWebSocket({
    jobId: useWs ? resourceId : undefined,
    enabled: useWs && enabled,
    onMessage: useWs
      ? (data) => {
          const obj = (data ?? {}) as { id?: string; type?: string; timestamp?: number };
          onEventRef.current?.({
            id: obj.id ?? `${obj.timestamp ?? Date.now()}-${obj.type ?? 'log'}`,
            type: obj.type ?? 'message',
            timestamp: obj.timestamp ?? Date.now(),
            data: data as T,
            source: 'ws',
          });
        }
      : () => {},
    onFallback: useWs
      ? () => onFallbackRef.current?.()
      : undefined,
  });

  // Merge connection state. SSE is the "primary" transport when both are
  // active (auto mode); WS is reported as the secondary.
  const connectionState: RealtimeConnectionState = useMemo(() => {
    if (useSse && useWs) {
      if (sse.connectionState === 'connected' || ws.connectionState === 'connected') {
        return 'connected';
      }
      if (sse.connectionState === 'connecting') {
        return 'connecting';
      }
      if (sse.connectionState === 'reconnecting' || ws.connectionState === 'reconnecting') {
        return 'reconnecting';
      }
      if (sse.connectionState === 'failed' && ws.connectionState === 'disconnected') {
        return 'failed';
      }
      return sse.connectionState;
    }
    if (useSse) return sse.connectionState;
    return ws.connectionState;
  }, [useSse, useWs, sse.connectionState, ws.connectionState]);

  const reconnect = () => {
    sse.reconnect();
    ws.reconnect();
  };

  const disconnect = () => {
    sse.disconnect();
    ws.disconnect();
  };

  return {
    connectionState,
    isPollingFallback: sse.isPollingFallback,
    reconnect,
    disconnect,
    effectiveTransport: useSse ? 'sse' : 'ws',
  };
}
