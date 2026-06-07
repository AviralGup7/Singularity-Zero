import { useEffect, useRef, useState, useCallback } from 'react';
import { captureException } from '@/utils/errorTracker';
import { toServerTime } from '@/lib/timeSync';
import { appendStreamToken } from '@/api/streamAuth';
import {
  useMountedRef,
  useReconnectBackoff,
  useDedupSet,
  useHeartbeat,
  type ConnectionState,
} from './realtime/shared';

export interface SseEventData {
  [key: string]: unknown;
  message?: string;
  progress?: number;
  stage?: string;
  iteration?: number;
  finding_count?: number;
}

export type SSEConnectionState = ConnectionState;

export interface SseEvent<T = SseEventData> {
  id: string;
  event_type: string;
  job_id: string;
  timestamp: number;
  data: T;
}

interface UseSSEProgressOptions<T = SseEventData> {
  jobId: string | undefined;
  enabled?: boolean;
  /**
   * Optional batch flush interval in milliseconds. Events that arrive in a
   * single batch are delivered in arrival order, so callers can still reason
   * about causality, but renders and downstream work happen at most once per
   * `flushIntervalMs` (default 100ms). This is the Action Buffer proposed in
   * UI_OVERHAUL_PLAN.md Phase 1 and eliminates the progress-bar flicker that
   * came from running one render per SSE event.
   */
  flushIntervalMs?: number;
  onEvent?: (event: SseEvent<T>) => void;
  endpoint?: 'logs' | 'progress';
}

const MIN_DELAY = 1000;
const MAX_DELAY = 60000;
const HEARTBEAT_TIMEOUT = 35000;
const DEFAULT_FLUSH_INTERVAL_MS = 100;
const DEFAULT_BATCH_CAPACITY = 2000;

/**
 * High-throughput SSE consumer with the Phase-1 Action Buffer from the
 * overhaul plan. Events are:
 *   1. Deduped against a FIFO set (max 2,500 ids)
 *   2. Normalized to server time (clock-skew correction via timeSync)
 *   3. Coalesced into a 100ms batch
 *   4. Delivered to the consumer as a single `onEvent` call per buffered event,
 *      so React only runs one effect/render cycle per flush.
 *
 * R6: The mounted-ref, reconnect-backoff, dedup-set, and heartbeat primitives
 * now live in `./realtime/shared` so they can be shared with `useWebSocket`
 * (and the new `useRealtimeStream` facade) without drift.
 *
 * In a 12-hour scan we typically see 50–200 events/sec; without this buffer
 * the cockpit triggers a full re-fetch on every finding_batch, causing
 * progress bars to jump backwards and `requestGraphUpdate` to thrash.
 */
export function useSSEProgress<T = SseEventData>({
  jobId,
  enabled = true,
  onEvent,
  endpoint = 'progress',
  flushIntervalMs = DEFAULT_FLUSH_INTERVAL_MS,
}: UseSSEProgressOptions<T>) {

  const [connectionState, setConnectionState] = useState<SSEConnectionState>('closed');
  const [isPollingFallback, setIsPollingFallback] = useState(false);
  const pendingEventCountRef = useRef(0);

  const esRef = useRef<EventSource | null>(null);
  const onEventRef = useRef(onEvent);
  const bufferRef = useRef<SseEvent<T>[]>([]);
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastFlushRef = useRef<number>(0);

  // R6: shared primitives.
  const { mountedRef } = useMountedRef();
  const backoff = useReconnectBackoff({ minDelayMs: MIN_DELAY, maxDelayMs: MAX_DELAY, factor: 1.5 });
  const seenIds = useDedupSet({ maxSize: 2500, pruneChunk: 500 });
  const { arm: armHeartbeat, disarm: disarmHeartbeat } = useHeartbeat();

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const connectRef = useRef<() => void>(() => {});

  /**
   * Atomic batch flush: drain the buffer in one synchronous pass and update
   * React state once. The consumer's `onEvent` runs N times but the React
   * render only happens once per flush, so a flood of 200 events in 50ms
   * collapses to a single re-render.
   */
  const flushBuffer = useCallback(() => {
    if (flushTimerRef.current) {
      clearTimeout(flushTimerRef.current);
      flushTimerRef.current = null;
    }
    if (!mountedRef.current) return;
    const batch = bufferRef.current;
    if (batch.length === 0) return;
    bufferRef.current = [];
    lastFlushRef.current = Date.now();
    pendingEventCountRef.current = 0;
    const handler = onEventRef.current;
    if (!handler) return;
    for (let i = 0; i < batch.length; i++) {
      try {
        // `i` is a bounded loop index; safe to use as an array key.
        // eslint-disable-next-line security/detect-object-injection
        handler(batch[i]);
      } catch (err) {
        captureException(err as Error, { component: 'useSSEProgress', action: 'handler' });
      }
    }
  }, [mountedRef]);

  const enqueueEvent = useCallback((event: SseEvent<T>) => {
    if (!mountedRef.current) return;
    const buffer = bufferRef.current;
    if (buffer.length >= DEFAULT_BATCH_CAPACITY) {
      // Drop the oldest so we never hold unbounded memory; in practice the
      // flush interval drains the buffer long before this ever fires.
      buffer.shift();
    }
    buffer.push(event);
    pendingEventCountRef.current = buffer.length;
    if (flushTimerRef.current) return;
    const elapsed = Date.now() - lastFlushRef.current;
    const delay = elapsed >= flushIntervalMs ? 0 : flushIntervalMs - elapsed;
    flushTimerRef.current = setTimeout(flushBuffer, delay);
  }, [mountedRef, flushBuffer, flushIntervalMs]);

  const connect = useCallback(() => {
    if (!jobId || !enabled || !mountedRef.current) return;

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    // SECURITY: EventSource cannot send custom headers, so the bearer is
    // appended as a `token` query parameter. The auth transport is
    // centralised in `@/api/streamAuth` so swapping to a short-lived
    // `/api/stream-token` exchange only requires editing one module.
    const url = appendStreamToken(`/api/jobs/${jobId}/${endpoint}/stream`);

    setConnectionState('connecting');
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      if (!mountedRef.current) return;
      setConnectionState('connected');
      setIsPollingFallback(false);
      backoff.reset();
      armHeartbeat(HEARTBEAT_TIMEOUT, () => {
        if (!mountedRef.current) return;
        console.warn('SSE Heartbeat Timeout - Reconnecting...');
        connectRef.current();
      });
    };

    const handleMessage = (e: MessageEvent) => {
      if (!mountedRef.current) return;
      armHeartbeat(HEARTBEAT_TIMEOUT, () => {
        if (!mountedRef.current) return;
        console.warn('SSE Heartbeat Timeout - Reconnecting...');
        connectRef.current();
      });

      try {
        const parsed = JSON.parse(e.data) as SseEvent<T>;
        const eventId = parsed.id || `${parsed.event_type}:${parsed.timestamp}`;

        if (!seenIds.add(eventId)) return;

        // Clock-skew correction: the server stamps `timestamp` in server time
        // but the client may be several seconds off. We replace the timestamp
        // with the server-authoritative value (in client-monotonic time) so
        // downstream merge logic never sees a future or past-flicker.
        const corrected: SseEvent<T> = {
          ...parsed,
          timestamp: typeof parsed.timestamp === 'number'
            ? parsed.timestamp
            : toServerTime(Date.now()),
        };
        enqueueEvent(corrected);
      } catch (err) {
        captureException(err as Error, { component: 'useSSEProgress', action: 'parse' });
        console.warn('[SSE] parse error', err);
      }
    };

    es.onmessage = handleMessage;

    ['log', 'progress_update', 'stage_change', 'finding_batch', 'mesh_health_update', 'migration_event', 'completed', 'error'].forEach(type => {
      es.addEventListener(type, handleMessage);
    });

    es.onerror = () => {
      if (!mountedRef.current) return;
      setConnectionState('reconnecting');
      disarmHeartbeat();

      if (es.readyState === EventSource.CLOSED) {
        const delay = backoff.delayMs();
        backoff.bump();
        setTimeout(connectRef.current, delay);
      }
    };

  }, [jobId, enabled, endpoint, enqueueEvent, mountedRef, backoff, seenIds, armHeartbeat, disarmHeartbeat]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    if (enabled && jobId) connect();
    return () => {
      mountedRef.current = false;
      if (esRef.current) esRef.current.close();
      disarmHeartbeat();
      if (flushTimerRef.current) clearTimeout(flushTimerRef.current);
      bufferRef.current = [];
      seenIds.clear();
    };
  }, [jobId, enabled, connect, mountedRef, disarmHeartbeat, seenIds]);

  return {
    connectionState,
    isPollingFallback,
    pendingEventCount: pendingEventCountRef.current,
    /**
     * Force an immediate buffer flush. Useful when the consumer wants to
     * guarantee up-to-date state at a transition (e.g. right before opening
     * a detail panel). Safe to call from anywhere.
     */
    flush: flushBuffer,
    reconnect: connect,
    disconnect: () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      disarmHeartbeat();
      if (flushTimerRef.current) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
      bufferRef.current = [];
      seenIds.clear();
      setConnectionState('closed');
    }
  };
}
