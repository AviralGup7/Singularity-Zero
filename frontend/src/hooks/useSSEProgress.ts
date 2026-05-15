import { useEffect, useRef, useState, useCallback } from 'react';

export interface SseEventData {
  [key: string]: unknown;
  message?: string;
  progress?: number;
  stage?: string;
  iteration?: number;
  finding_count?: number;
}

export type SSEConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'failed' | 'closed';

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
  onEvent?: (event: SseEvent<T>) => void;
  endpoint?: 'logs' | 'progress';
}

const MIN_DELAY = 1000;
const MAX_DELAY = 60000;
const HEARTBEAT_TIMEOUT = 35000;

export function useSSEProgress<T = SseEventData>({
  jobId,
  enabled = true,
  onEvent,
  endpoint = 'progress',
}: UseSSEProgressOptions<T>) {
  const [connectionState, setConnectionState] = useState<SSEConnectionState>('closed');
  const [isPollingFallback, setIsPollingFallback] = useState(false);

  const esRef = useRef<EventSource | null>(null);
  const backoffRef = useRef(MIN_DELAY);
  const mountedRef = useRef(true);
  const onEventRef = useRef(onEvent);
  const heartbeatRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const seenIdsRef = useRef<Set<string>>(new Set());

  // --- High-Performance Lifecycle Management ---
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const connectRef = useRef<() => void>(() => {});

  const resetHeartbeat = useCallback(() => {
    if (heartbeatRef.current) clearTimeout(heartbeatRef.current);
    heartbeatRef.current = setTimeout(() => {
      console.warn('SSE Heartbeat Timeout - Reconnecting...');
      connectRef.current();
    }, HEARTBEAT_TIMEOUT);
  }, []);

  const connect = useCallback(() => {
    if (!jobId || !enabled || !mountedRef.current) return;

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    const token = sessionStorage.getItem('auth_token');
    // SECURITY: Passing token in query string is non-ideal but standard EventSource lacks header support.
    // Ensure the backend logs are configured to redact this parameter.
    const url = `/api/jobs/${jobId}/${endpoint}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;

    setConnectionState('connecting');
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => {
      if (!mountedRef.current) return;
      setConnectionState('connected');
      setIsPollingFallback(false);
      backoffRef.current = MIN_DELAY;
      resetHeartbeat();
    };

    const handleMessage = (e: MessageEvent) => {
      if (!mountedRef.current) return;
      resetHeartbeat();
      
      try {
        const parsed = JSON.parse(e.data) as SseEvent<T>;
        const eventId = parsed.id || `${parsed.event_type}:${parsed.timestamp}`;
        
        if (seenIdsRef.current.has(eventId)) return;
        seenIdsRef.current.add(eventId);
        
        // Fast FIFO prune
        if (seenIdsRef.current.size > 2000) {
          const iter = seenIdsRef.current.values();
          for(let i=0; i<500; i++) {
            const val = iter.next().value;
            if (val !== undefined) seenIdsRef.current.delete(val);
          }
        }

        onEventRef.current?.(parsed);
      } catch (_err) {
        void _err;
      }
    };

    es.onmessage = handleMessage;
    ['log', 'progress_update', 'stage_change', 'finding_batch', 'mesh_health_update', 'completed', 'error'].forEach(type => {
      es.addEventListener(type, handleMessage);
    });

    es.onerror = () => {
      if (!mountedRef.current) return;
      setConnectionState('reconnecting');
      
      if (es.readyState === EventSource.CLOSED) {
        const delay = backoffRef.current;
        backoffRef.current = Math.min(backoffRef.current * 1.5, MAX_DELAY);
        setTimeout(connectRef.current, delay);
      }
    };
  }, [jobId, enabled, endpoint, resetHeartbeat]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    mountedRef.current = true;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (enabled && jobId) connect();
    return () => {
      mountedRef.current = false;
      if (esRef.current) esRef.current.close();
      if (heartbeatRef.current) clearTimeout(heartbeatRef.current);
    };
  }, [jobId, enabled, connect]);

  return {
    connectionState,
    isPollingFallback,
    reconnect: connect,
    disconnect: () => { if (esRef.current) esRef.current.close(); setConnectionState('closed'); }
  };
}
