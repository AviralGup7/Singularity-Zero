import { useState, useEffect, useCallback } from 'react';
import { getReadiness } from '@/api/health';
import type { ReadinessResponse } from '@/types/extended';

const HEALTH_POLL_INTERVAL = 30_000;

export function isCanceledHealthError(err: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  const name = err instanceof Error ? err.name : undefined;
  const message = err instanceof Error ? err.message : String(err ?? '');
  return name === 'CanceledError' || name === 'AbortError' || message.toLowerCase() === 'canceled' || message.toLowerCase() === 'abort';
}

export interface HealthStatusState {
  ready: boolean;
  status: string;
  degradedReasons: string[];
  subsystems: Record<string, { status: string; error?: string }>;
  loading: boolean;
  error: boolean;
  lastChecked: Date | null;
}

const initialState: HealthStatusState = {
  ready: true,
  status: 'ready',
  degradedReasons: [],
  subsystems: {},
  loading: true,
  error: false,
  lastChecked: null,
};

export function useHealthStatus(pollInterval: number = HEALTH_POLL_INTERVAL) {
  const [state, setState] = useState<HealthStatusState>(initialState);

  const checkHealth = useCallback(async (signal?: AbortSignal) => {
    try {
      const data: ReadinessResponse = await getReadiness(signal);
      setState({
        ready: data.ready,
        status: data.status || (data.ready ? 'ready' : 'degraded'),
        degradedReasons: data.degraded_reasons || [],
        subsystems: data.dependencies || {},
        loading: false,
        error: false,
        lastChecked: new Date(),
      });
    } catch (_err) {
      if (isCanceledHealthError(_err, signal)) return;
      setState(prev => ({
        ...prev,
        ready: false,
        status: 'offline',
        loading: false,
        error: true,
        lastChecked: new Date(),
      }));
      // Banner in AppLayout already covers offline; don't toast on login.
    }
  }, []);

  useEffect(() => {
    let controller = new AbortController();
    void checkHealth(controller.signal);
    const interval = setInterval(() => {
      controller.abort();
      controller = new AbortController();
      void checkHealth(controller.signal);
    }, pollInterval);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [checkHealth, pollInterval]);

  return { ...state, refetch: () => checkHealth(new AbortController().signal) };
}
