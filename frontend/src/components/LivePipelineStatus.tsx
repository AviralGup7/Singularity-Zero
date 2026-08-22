import { useMemo } from 'react';
import { useJobsContext } from '../context/JobsContext';
import { useSSEProgress } from '../hooks/useSSEProgress';
import {
  liveConnectionLabel,
  pickSlowestJob,
  selectJobsByStatus,
  summarizeJobStages,
} from './livePipelineStatus';

const CONNECTION_COLORS: Record<string, string> = {
  connecting: 'var(--warn)',
  connected: 'var(--ok)',
  reconnecting: 'var(--warn)',
  failed: 'var(--bad)',
  closed: 'var(--text-tertiary)',
};

export function LivePipelineStatus() {
  const { jobs, loading } = useJobsContext();

  const runningJobs = useMemo(() => selectJobsByStatus(jobs, 'running'), [jobs]);
  const failedJobs = useMemo(() => selectJobsByStatus(jobs, 'failed'), [jobs]);
  const stageSummary = useMemo(() => summarizeJobStages(runningJobs), [runningJobs]);
  const slowestJob = useMemo(() => pickSlowestJob(runningJobs), [runningJobs]);

  // Use dummy SSE to track global connection health
  const { connectionState: sseState, isPollingFallback } = useSSEProgress({
    jobId: undefined,
    enabled: runningJobs.length > 0,
    endpoint: 'logs',
  });

  if (loading || runningJobs.length === 0) {
    return null;
  }

  const connLabel = liveConnectionLabel(sseState, isPollingFallback);
  const connColor = CONNECTION_COLORS[sseState] || CONNECTION_COLORS.closed;

  const totalFindings = runningJobs.reduce((sum, j) => sum + (j.findings_count ?? 0), 0);

  return (
    <div className="live-pipeline-status" role="status" aria-label="Live pipeline status">
      <div className="live-status-section">
        <span className="live-status-dot" style={{ backgroundColor: connColor }} />
        <span className="live-status-label">{connLabel}</span>
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
