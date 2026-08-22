import { useMemo } from 'react';
import type { Job } from '@/types/api';
import { buildStageTheaterNodesFromJob, stageGraphForJob } from '@/lib/stageTheaterUtils';

export function finiteCount(value: unknown, fallback = 0): number {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function sanitizeImportTargetName(filename: string): string {
  const base = filename.replace(/^.*[\\/]/, '').replace(/\.[^/.]+$/, '').trim();
  return base || 'imported-target';
}

export function useJobDetails(job: Job | null) {
  const displayLines = job?.latest_logs ?? [];
  const warningCount = finiteCount(job?.warning_count, Array.isArray(job?.warnings) ? job.warnings.length : 0);
  const fatalSignalCount = finiteCount(job?.fatal_signal_count, 0);
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
    return buildStageTheaterNodesFromJob(job);
  }, [job]);
  const stageGraph = useMemo(() => stageGraphForJob(job), [job]);

  return { stageTheaterNodes, stageGraph };
}

export function useJobThroughput(job: Job | null) {
  const throughput = useMemo(() => {
    const telemetry = job?.progress_telemetry;
    const jobsPerSecond = finiteCount(telemetry?.requests_per_second, 0);
    const findingsPerSecond = finiteCount(telemetry?.throughput_per_second, 0);
    const stageRatio =
      typeof job?.stage_percent === 'number'
        ? Math.max(0, Math.min(100, job.stage_percent)) / 100
        : Math.max(0, Math.min(100, job?.progress_percent ?? 0)) / 100;
    const scanVelocity = jobsPerSecond * 0.6 + findingsPerSecond * 0.4 + stageRatio;
    return {
      jobsPerSecond,
      findingsPerSecond,
      scanVelocity,
      activeTasks: finiteCount(telemetry?.active_task_count, 0),
    };
  }, [job]);

  return throughput;
}
