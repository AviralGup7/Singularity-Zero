import { Link } from 'react-router-dom';
import { Icon } from '../Icon';
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
    <div className="page-header page-header--job-detail">
      <div className="job-header-main">
        <Link to="/jobs" className="back-link">Back to Jobs</Link>
        <h2 data-focus-heading className="job-header-title">
          <span className={`status-badge status-${statusClass}`}>{job.status}</span>
          <span>Job {job.id}</span>
          <StatePulse state={pulseState} className="job-status-pulse" />
        </h2>

        <div className="job-connection-badges">
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
            <button className="btn btn-sm" onClick={onReconnect}>Retry Stream</button>
          )}
        </div>
      </div>

      <div className="job-actions">
        {job.status === 'running' && (
          <button
            className="btn btn-danger"
            onClick={onStop}
            disabled={actionLoading === 'stop'}
          >
            {actionLoading === 'stop' ? 'Stopping...' : 'Stop Job'}
          </button>
        )}
        {(job.status === 'failed' || job.status === 'stopped') && (
          <button
            className="btn btn-secondary"
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

