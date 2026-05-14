import { useEffect, useRef, useState, useCallback } from 'react';

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

export function useWebSocket({
  jobId,
  enabled = true,
  onMessage,
  onFallback,
}: UseWebSocketOptions): UseWebSocketReturn {
  const [connectionState, setConnectionState] = useState<WSConnectionState>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef(MIN_DELAY);
  const hasConnectedRef = useRef(false);
  const seenIdsRef = useRef<Set<string>>(new Set());
  const mountedRef = useRef(true);
  
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
    const token = sessionStorage.getItem('auth_token');
    const wsUrl = `${protocol}//${host}/ws/logs/${jobId}`;

    try {
      // Pass token via protocols parameter to avoid URL exposure
      const protocols = token ? ['access_token', token] : [];
      const ws = new WebSocket(wsUrl, protocols);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        hasConnectedRef.current = true;
        backoffRef.current = MIN_DELAY;
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
          if (id && seenIdsRef.current.has(String(id))) {
            return;
          }
          if (id) {
            seenIdsRef.current.add(String(id));
            if (seenIdsRef.current.size > 5000) {
              const arr = Array.from(seenIdsRef.current);
              seenIdsRef.current = new Set(arr.slice(-2000));
            }
          }
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

        retryTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) {
            backoffRef.current = Math.min(backoffRef.current * BACKOFF_FACTOR, MAX_DELAY);
            connectRef.current();
          }
        }, backoffRef.current);
      };
    } catch {
      setConnectionState('disconnected');
      onFallbackRef.current?.();
    }
  }, [jobId, enabled, cleanup]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const reconnect = useCallback(() => {
    backoffRef.current = MIN_DELAY;
    connect();
  }, [connect]);

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
  }, [jobId, enabled, connect, cleanup]);

  return { connectionState, reconnect, disconnect };
}
