import { useMemo } from 'react';
import type { Job } from '@/types/api';

export function useJobDetails(job: Job | null) {
  const displayLines = job?.latest_logs ?? [];
  const warningCount = typeof job?.warning_count === 'number' ? job.warning_count : job?.warnings?.length ?? 0;
  const fatalSignalCount = typeof job?.fatal_signal_count === 'number' ? job.fatal_signal_count : 0;
  const degradedProviders = job?.degraded_providers ?? [];
  const timeoutEvents = job?.timeout_events ?? [];

  const hasRuntimeSignals =
    warningCount > 0 ||
    fatalSignalCount > 0 ||
    degradedProviders.length > 0 ||
    timeoutEvents.length > 0 ||
    typeof job?.effective_timeout_seconds === 'number';

  return {
    displayLines,
    warningCount,
    fatalSignalCount,
    degradedProviders,
    timeoutEvents,
    hasRuntimeSignals,
  };
}

export function useJobStageTheater(job: Job | null) {
  const stageTheaterNodes = useMemo(() => {
    if (!job) return [];
    const { buildStageTheaterNodesFromJob } = require('@/lib/stageTheaterUtils');
    return buildStageTheaterNodesFromJob(job);
  }, [job]);

  return { stageTheaterNodes };
}

export function useJobThroughput(job: Job | null) {
  const throughput = useMemo(() => {
    const telemetry = job?.progress_telemetry;
    const jobsPerSecond = Number(telemetry?.requests_per_second ?? 0);
    const findingsPerSecond = Number(telemetry?.throughput_per_second ?? 0);
    const stageRatio =
      typeof job?.stage_percent === 'number'
        ? Math.max(0, Math.min(100, job.stage_percent)) / 100
        : Math.max(0, Math.min(100, job?.progress_percent ?? 0)) / 100;
    const scanVelocity = jobsPerSecond * 0.6 + findingsPerSecond * 0.4 + stageRatio;
    return {
      jobsPerSecond,
      findingsPerSecond,
      scanVelocity,
      activeTasks: Number(telemetry?.active_task_count ?? 0),
    };
  }, [job]);

  return throughput;
}
