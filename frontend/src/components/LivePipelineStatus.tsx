import { useMemo } from 'react';
import { useJobs } from '../hooks';
import type { Job } from '../types/api';
import { useSSEProgress } from '../hooks/useSSEProgress';

const CONNECTION_LABELS: Record<string, string> = {
  connecting: 'Connecting...',
  connected: 'Live',
  reconnecting: 'Reconnecting...',
  failed: 'Offline',
  closed: 'Closed',
};

const CONNECTION_COLORS: Record<string, string> = {
  connecting: 'var(--color-warning, #f59e0b)',
  connected: 'var(--color-success, #22c55e)',
  reconnecting: 'var(--color-warning, #f59e0b)',
  failed: 'var(--color-error, #ef4444)',
  closed: 'var(--color-muted, #6b7280)',
};

export function LivePipelineStatus() {
  const { data: jobs, loading } = useJobs({ refetchInterval: 5000 });

  const runningJobs = useMemo(() => {
    return (jobs ?? []).filter((j: Job) => j.status === 'running');
  }, [jobs]);

  const failedJobs = useMemo(() => {
    return (jobs ?? []).filter((j: Job) => j.status === 'failed');
  }, [jobs]);

  // Count stages across all running jobs
  const stageSummary = useMemo(() => {
    const stageMap: Record<string, { count: number; maxPercent: number }> = {};
    for (const job of runningJobs) {
      const stage = job.stage || 'unknown';
      if (!Reflect.get(stageMap, stage)) {
        Reflect.set(stageMap, stage, { count: 0, maxPercent: 0 });
      }
      const stageInfo = Reflect.get(stageMap, stage);
      stageInfo.count += 1;
      stageInfo.maxPercent = Math.max(stageInfo.maxPercent, job.progress_percent ?? 0);
    }
    // Sort by active count desc
    return Object.entries(stageMap)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 3);
  }, [runningJobs]);

  // Find slowest running job
  const slowestJob = useMemo(() => {
    return runningJobs.reduce<Job | null>((slow, job) => {
      if (!slow) return job;
      const p1 = job.progress_percent ?? 0;
      const p2 = slow.progress_percent ?? 0;
      return p1 < p2 ? job : slow;
    }, null);
  }, [runningJobs]);

  // Use dummy SSE to track global connection health
  const { connectionState: sseState, isPollingFallback } = useSSEProgress({
    jobId: undefined,
    enabled: runningJobs.length > 0,
    endpoint: 'logs',
  });

  if (loading || runningJobs.length === 0) {
    return null;
  }

  const connLabel = (Reflect.get(CONNECTION_LABELS, sseState) as string) || 'Unknown';
  const connColor = (Reflect.get(CONNECTION_COLORS, sseState) as string) || CONNECTION_COLORS.closed;

  const totalFindings = runningJobs.reduce((sum, j) => sum + (j.findings_count ?? 0), 0);

  return (
    <div className="live-pipeline-status" role="status" aria-label="Live pipeline status">
      <div className="live-status-section">
        <span className="live-status-dot" style={{ backgroundColor: connColor }} />
        <span className="live-status-label">{isPollingFallback ? 'Polling' : connLabel}</span>
      </div>
      <div className="live-status-divider" />
      <div className="live-status-section">
        <span className="live-status-count">{runningJobs.length} running</span>
      </div>
      <div className="live-status-divider" />
      {stageSummary.length > 0 && (
        <>
          <div className="live-status-section">
            <span className="live-status-stages">
              {stageSummary.map(([stage, info], index) => (
                <span key={stage} className="live-stage-chip" title={`${info.count} job(s) in ${stage}`}>
                  {index > 0 ? ', ' : ''}
                  {stage} ({info.count})
                </span>
              ))}
            </span>
          </div>
          <div className="live-status-divider" />
        </>
      )}
      {slowestJob && (
        <>
          <div className="live-status-section">
            <span className="live-status-slowest" title={`Slowest: ${slowestJob.base_url}`}>
              {Math.round(slowestJob.progress_percent ?? 0)}% slowest
            </span>
          </div>
          <div className="live-status-divider" />
        </>
      )}
      {totalFindings > 0 && (
        <>
          <div className="live-status-section">
            <span className="live-status-findings">{totalFindings} findings</span>
          </div>
          <div className="live-status-divider" />
        </>
      )}
      {failedJobs.length > 0 && (
        <div className="live-status-section">
          <span className="live-status-failed">{failedJobs.length} failed</span>
        </div>
      )}
    </div>
  );
}
