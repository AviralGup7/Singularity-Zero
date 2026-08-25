import { Link } from 'react-router-dom';
import { ROUTES } from '@/config/paths';
import { Icon } from '../ui/Icon';
import { StatePulse } from '../motion/StatePulse';
import type { Job } from '../../types/api';

interface JobStatusHeaderProps {
  job: Job;
  connectionState: string;
  sseState: string;
  wsFailed: boolean;
  actionLoading: string | null;
  onReconnect: () => void;
  onStop: () => void;
  onRestart: () => void;
}

export function JobStatusHeader({
  job,
  connectionState,
  sseState,
  wsFailed,
  actionLoading,
  onReconnect,
  onStop,
  onRestart,
}: JobStatusHeaderProps) {
  const statusClass = job.status.toLowerCase();

  const pulseState =
    job.status === 'running'
      ? 'loading'
      : job.status === 'completed'
        ? 'success'
        : job.status === 'failed'
          ? 'error'
          : 'empty';

  return (
    <div className="page-header page-header--job-detail" role="banner">
      <div className="job-header-main">
        <Link to={ROUTES.JOBS} className="back-link focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded">Back to Jobs</Link>
        <h2 data-focus-heading className="job-header-title">
          <span className={`status-badge status-${statusClass}`} role="status">{job.status}</span>
          <span>Job {job.id}</span>
          <StatePulse state={pulseState} className="job-status-pulse" aria-hidden="true" />
        </h2>

        <div className="job-connection-badges" role="status" aria-live="polite">
          {job.status === 'running' && (
            <span className={`ws-status ws-${connectionState}`}>
              <Icon name="activity" size={12} aria-hidden="true" />
              {connectionState === 'connected' && 'WS Live'}
              {connectionState === 'reconnecting' && 'WS Reconnecting'}
              {connectionState === 'disconnected' && (wsFailed ? 'Polling Mode' : 'WS Disconnected')}
            </span>
          )}
          {job.status === 'running' && (
            <span className={`sse-status sse-${sseState}`}>
              <Icon name="zap" size={12} aria-hidden="true" />
              {sseState === 'connected' && 'SSE Live'}
              {sseState === 'reconnecting' && 'SSE Reconnecting'}
              {sseState === 'failed' && 'SSE Failed'}
            </span>
          )}
          {job.status === 'running' && (sseState === 'failed' || sseState === 'reconnecting') && (
            <button className="btn btn-sm focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none" onClick={onReconnect}>Retry Stream</button>
          )}
        </div>
      </div>

      <div className="job-actions">
        {job.status === 'running' && (
          <button
            className="btn btn-danger focus-visible:ring-2 focus-visible:ring-bad/50 focus-visible:outline-none"
            onClick={onStop}
            disabled={actionLoading === 'stop'}
          >
            {actionLoading === 'stop' ? 'Stopping...' : 'Stop Job'}
          </button>
        )}
        {(job.status === 'failed' || job.status === 'stopped') && (
          <button
            className="btn btn-secondary focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none"
            onClick={onRestart}
            disabled={actionLoading === 'restart'}
          >
            {actionLoading === 'restart' ? 'Restarting...' : 'Restart'}
          </button>
        )}
      </div>
    </div>
  );
}

