import type { Job } from '../types/api';

export const LIVE_PIPELINE_CONNECTION_LABELS: Record<string, string> = {
  connecting: 'Connecting...',
  connected: 'Live',
  reconnecting: 'Reconnecting...',
  failed: 'Offline',
  closed: 'Closed',
};

export function selectJobsByStatus(jobs: Job[] | null | undefined, status: string): Job[] {
  return (jobs ?? []).filter((job) => job.status === status);
}

export function summarizeJobStages(
  runningJobs: Job[],
  limit = 3,
): Array<[string, { count: number; maxPercent: number }]> {
  const stageMap = new Map<string, { count: number; maxPercent: number }>();
  for (const job of runningJobs) {
    const stage = job.stage || 'unknown';
    const current = stageMap.get(stage) ?? { count: 0, maxPercent: 0 };
    current.count += 1;
    current.maxPercent = Math.max(current.maxPercent, job.progress_percent ?? 0);
    stageMap.set(stage, current);
  }
  return [...stageMap.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, Math.max(0, limit));
}

export function pickSlowestJob(runningJobs: Job[]): Job | null {
  return runningJobs.reduce<Job | null>((slow, job) => {
    if (!slow) return job;
    return (job.progress_percent ?? 0) < (slow.progress_percent ?? 0) ? job : slow;
  }, null);
}

export function liveConnectionLabel(state: string, isPollingFallback: boolean): string {
  if (isPollingFallback) return 'Polling';
  return LIVE_PIPELINE_CONNECTION_LABELS[state] || 'Unknown';
}
