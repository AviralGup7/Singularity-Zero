import { useEffect, useState } from 'react';
import type { Job, Target, Finding } from '../types/api';
import { useApi } from './useApi';

export { usePersistedState } from './usePersistedState';
export { useJobMonitor } from './useJobMonitor';
export { useMotionPolicy } from './useMotionPolicy';
export { useRiskHistory, buildRiskDateColumns } from './useRiskHistory';
export { useFindingsTimeline } from './useFindingsTimeline';
export type { UseJobMonitorReturn } from './useJobMonitor';
export type { DurationForecastData } from './useJobMonitorReducer';

/**
 * Get jobs list with configurable refetch interval.
 * Default: 5000ms for running jobs monitoring.
 * Returns reactive { data, loading, error, refetch } state.
 */
export function useJobs(options?: { refetchInterval?: number }) {
  const result = useApi<{ jobs: Job[]; total: number }>('/api/jobs', {
    refetchInterval: options?.refetchInterval ?? 5000,
  });
  // Transform nested response to flat array for consumers
  return {
    ...result,
    data: result.data?.jobs ?? null,
  };
}

/**
 * Get targets list with reactive state.
 */
export function useTargets() {
  return useApi<{ targets: Target[] }>('/api/targets');
}

/**
 * Get single job detail with auto-refresh for running jobs.
 * Returns reactive { data, loading, error, refetch } state.
 */
export function useJobDetail(jobId: string | undefined, ttl?: number) {
  const [poll, setPoll] = useState(true);
  const result = useApi<Job>(jobId ? `/api/jobs/${jobId}` : null, {
    enabled: !!jobId,
    refetchInterval: poll ? 2000 : 0,
    ttl,
  });

  useEffect(() => {
    let isMounted = true;
    if (result.data) {
      // Defer state update to avoid cascading render warning
      Promise.resolve().then(() => {
        if (isMounted) {
          setPoll(result.data?.status === 'running');
        }
      });
    }
    return () => { isMounted = false; };
  }, [result.data]);

  return result;
}

/**
 * Get findings list with reactive state.
 */
export function useFindings() {
  // FIX: Reduced page_size from 5000 to a reasonable 100 with pagination support
  return useApi<{ findings: Finding[]; total: number }>('/api/targets/findings/list', {
    params: { page: 1, page_size: 100 },
  });
}
