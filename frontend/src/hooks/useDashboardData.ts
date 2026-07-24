import { useApi } from '../hooks/useApi';
import { useJobsContext } from '../context/JobsContext';
import type { DashboardStats as StatsType } from '../types/api';
import type { UseApiError } from './useApi';
import { DashboardStatsSchema } from '../api/schemas';

interface DashboardData {
  stats: StatsType | null;
  jobs: ReturnType<typeof useJobsContext>['jobs'];
  loading: boolean;
  error: UseApiError | null;
  refetch: () => Promise<void>;
}

export function useDashboardData(): DashboardData {
  const { jobs, loading: jobsLoading, error: jobsError, refetch: refetchJobs } = useJobsContext();
  
  const { data: stats, loading: statsLoading, error: statsError, refetch: refetchStats } = useApi<StatsType>('/api/dashboard', {
    refetchInterval: 10000,
    schema: DashboardStatsSchema,
  });

  const loading = jobsLoading || statsLoading;
  const error = jobsError || statsError;

  const refetch = async () => {
    await Promise.all([refetchJobs(), refetchStats()]);
  };

  return {
    stats,
    jobs,
    loading,
    error,
    refetch,
  };
}