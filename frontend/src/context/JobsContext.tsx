import { createContext, useContext, useMemo } from 'react';
import type {ReactNode} from 'react';
import { useJobs } from '../hooks';

interface JobsContextValue {
  jobs: ReturnType<typeof useJobs>['data'];
  loading: boolean;
  error: ReturnType<typeof useJobs>['error'];
  refetch: () => Promise<void>;
  runningJobs: ReturnType<typeof useJobs>['data'];
  completedJobs: ReturnType<typeof useJobs>['data'];
  failedJobs: ReturnType<typeof useJobs>['data'];
  stats: {
    running: number;
    completed: number;
    failed: number;
    totalFindings: number;
    avgProgress: number;
  };
}

const JobsContext = createContext<JobsContextValue | null>(null);

export function JobsProvider({ children, refetchInterval = 5000, enabled = true }: { children: ReactNode; refetchInterval?: number; enabled?: boolean }) {
  const { data: jobs, loading, error, refetch } = useJobs({ refetchInterval, enabled });

  const value = useMemo(() => {
    const runningJobs = jobs?.filter((j) => j.status === 'running') ?? [];
    const completedJobs = jobs?.filter((j) => j.status === 'completed') ?? [];
    const failedJobs = jobs?.filter((j) => j.status === 'failed') ?? [];

    const stats = {
      running: runningJobs.length,
      completed: completedJobs.length,
      failed: failedJobs.length,
      totalFindings: jobs?.reduce((sum, j) => sum + (j.findings_count ?? 0), 0) ?? 0,
      avgProgress: runningJobs.length > 0
        ? Math.round(runningJobs.reduce((sum, j) => sum + (j.progress_percent ?? 0), 0) / runningJobs.length)
        : 0,
    };

    return { jobs, loading, error, refetch, runningJobs, completedJobs, failedJobs, stats };
  }, [jobs, loading, error, refetch]);

  return (
    <JobsContext.Provider value={value}>
      {children}
    </JobsContext.Provider>
  );
}

export function useJobsContext() {
  const context = useContext(JobsContext);
  if (!context) {
    throw new Error('useJobsContext must be used within a JobsProvider');
  }
  return context;
}