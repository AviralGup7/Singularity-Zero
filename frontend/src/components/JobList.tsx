import { useState, useEffect, useCallback, memo } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAutoAnimate } from '@formkit/auto-animate/react';
import { getJobs, stopJob, restartJob } from '../api/client';
import { useToast } from './Toast';
import { ConfirmDialog } from './ui/ConfirmDialog';
import { EmptyState } from './ui/EmptyState';
import { Skeleton } from './ui/Skeleton';
import { CopyButton } from './CopyButton';
import { Icon } from './Icon';
import VirtualizedJobGrid from './VirtualizedJobGrid';
import { useMotionPolicy } from '../hooks/useMotionPolicy';
import { MicroPulseValue } from './motion/MicroPulseValue';
import type { Job } from '../types/api';

const STAGE_LABELS: Record<string, string> = {
  startup: 'Preparing run',
  subdomains: 'Enumerating subdomains',
  live_hosts: 'Probing live hosts',
  urls: 'Collecting URLs',
  recon_validation: 'Validating recon output',
  parameters: 'Mapping parameters',
  ranking: 'Ranking targets',
  passive_scan: 'Passive analysis',
  active_scan: 'Active probing',
  semgrep: 'Static analysis',
  nuclei: 'Template scan',
  access_control: 'Access control checks',
  validation: 'Validation runtime',
  intelligence: 'Signal correlation',
  reporting: 'Report generation',
};

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

function normalizeStageName(stageName?: string): string | undefined {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return undefined;
  return STAGE_ALIASES[normalized] ?? normalized;
}

function stageName(stageLabel?: string, stage?: string): string {
  const normalizedStage = normalizeStageName(stage);
  if (stageLabel) return stageLabel;
  if (normalizedStage && STAGE_LABELS[normalizedStage]) return STAGE_LABELS[normalizedStage];
  return normalizedStage || 'Unknown stage';
}

const JobCard = memo(function JobCard({ job, onRefresh }: { job: Job; onRefresh: () => void }) {
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [showConfirmStop, setShowConfirmStop] = useState(false);
  const [showConfirmRestart, setShowConfirmRestart] = useState(false);
  const toast = useToast();
  const { policy, strategy } = useMotionPolicy('card');

  const executeStop = useCallback(async () => {
    setActionLoading('stop');
    try {
      await stopJob(job.id);
      toast.success(`Job ${job.id} stopped`);
      onRefresh();
    } catch {
      toast.error(`Failed to stop job ${job.id}`);
    } finally {
      setActionLoading(null);
    }
  }, [job.id, toast, onRefresh]);

  const executeRestart = useCallback(async () => {
    setActionLoading('restart');
    try {
      await restartJob(job.id);
      toast.success(`Job ${job.id} restarted`);
      onRefresh();
    } catch {
      toast.error(`Failed to restart job ${job.id}`);
    } finally {
      setActionLoading(null);
    }
  }, [job.id, toast, onRefresh]);

  const statusClass = (job.status ?? '').toLowerCase();
  const telemetry = job.progress_telemetry;
  const failedSummary = [job.failed_stage, job.failure_reason_code, job.failure_reason]
    .filter(Boolean)
    .join(' · ');

  const card = (
    <div className={`card job-card job-card--${statusClass}`}>
      <div className="job-header">
        <Link to={`/jobs/${job.id}`} className="job-id-link flex items-center gap-2">
          <Icon name="activity" size={14} aria-hidden="true" />
          {job.id}
        </Link>
        <CopyButton text={job.id} />
        <span className={`job-status ${statusClass}`}>{job.status}</span>
      </div>

      <div className="job-url flex items-center gap-1" title={job.base_url}>
        <span className="truncate flex-1">{job.base_url ?? '-'}</span>
        {job.base_url && <CopyButton text={job.base_url} />}
      </div>

      <div className="job-stage">
        Stage: {stageName(job.stage_label, job.stage)} · Mode: {job.mode ?? '-'}
      </div>

      <div className="progress-bar">
        <div
          className={`progress-fill${job.status === 'running' ? ' running' : ''}`}
          style={{ width: `${Math.min(100, job.progress_percent ?? 0)}%` }}
        />
      </div>

      <div className="job-metrics-inline">
        <span><MicroPulseValue value={`${Math.round(job.progress_percent ?? 0)}%`} /></span>
        {job.has_eta && <span>ETA {job.eta_label ?? '--'}</span>}
        {job.stalled && <span className="job-metric-bad">Stalled</span>}
      </div>

      {job.status_message && <div className="job-status-text">{job.status_message}</div>}

      {job.status === 'running' && telemetry?.bottleneck_stage && (
        <div className="job-status-text">
          Bottleneck: {telemetry.bottleneck_stage}
          {typeof telemetry.bottleneck_seconds === 'number' ? ` (${Math.round(telemetry.bottleneck_seconds)}s)` : ''}
        </div>
      )}

      {job.status === 'running' && telemetry?.next_best_action && (
        <div className="job-status-text">Next action: {telemetry.next_best_action}</div>
      )}

      {job.status === 'failed' && failedSummary && (
        <div className="job-error-text" title={failedSummary}>Failure: {failedSummary}</div>
      )}

      {job.status === 'failed' && job.error && (
        <div className="job-error-text" title={job.error}>
          Error: {job.error.length > 180 ? `${job.error.slice(0, 180)}...` : job.error}
        </div>
      )}

      <div className="job-started-text">Started: {job.started_at ?? '-'}</div>

      {job.enabled_modules && job.enabled_modules.length > 0 && (
        <div className="job-modules-text">Modules: {job.enabled_modules.join(', ')}</div>
      )}

      <div className="job-actions">
        {job.status === 'running' && (
          <button className="stop-btn" onClick={() => setShowConfirmStop(true)} disabled={actionLoading === 'stop'}>
            {actionLoading === 'stop' ? 'Stopping...' : 'Stop'}
          </button>
        )}
        {(job.status === 'completed' || job.status === 'failed' || job.status === 'stopped') && (
          <button className="restart-btn" onClick={() => setShowConfirmRestart(true)} disabled={actionLoading === 'restart'}>
            {actionLoading === 'restart' ? 'Restarting...' : 'Restart'}
          </button>
        )}
      </div>

      <ConfirmDialog
        isOpen={showConfirmStop}
        title="Stop Job"
        message={`Are you sure you want to stop job ${job.id}? This action cannot be undone.`}
        confirmText="Stop Job"
        onConfirm={() => { setShowConfirmStop(false); void executeStop(); }}
        onCancel={() => setShowConfirmStop(false)}
        variant="danger"
      />
      <ConfirmDialog
        isOpen={showConfirmRestart}
        title="Restart Job"
        message={`Restart job ${job.id}? This will re-run the scan.`}
        confirmText="Restart"
        onConfirm={() => { setShowConfirmRestart(false); void executeRestart(); }}
        onCancel={() => setShowConfirmRestart(false)}
        variant="warning"
      />
    </div>
  );

  if (!policy.allowFramer) return card;

  return (
    <motion.div
      initial={{ opacity: 0, y: strategy.distance }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: strategy.duration, ease: 'easeOut' }}
      layout
    >
      {card}
    </motion.div>
  );
}, (prev, next) => prev.job?.id === next.job?.id && prev.onRefresh === next.onRefresh);

export default function JobList({ jobs: propJobs, onRefresh: propOnRefresh }: { jobs?: Job[]; onRefresh?: () => void }) {
  const [jobs, setJobs] = useState<Job[]>(propJobs || []);
  const [loading, setLoading] = useState(!propJobs);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'running' | 'completed' | 'failed'>('all');
  const toast = useToast();
  const [gridRef] = useAutoAnimate({ duration: 220, easing: 'ease-out' });

  const fetchJobs = useCallback(async (signal?: AbortSignal) => {
    try {
      const data = await getJobs(signal);
      setJobs(data ?? []);
      setError(null);
    } catch {
      if (signal?.aborted) return;
      const msg = 'Failed to load jobs. Verify that the API server is reachable.';
      setError(msg);
      toast.error(msg);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [toast]);

  const onRefresh = propOnRefresh || fetchJobs;

  useEffect(() => {
    if (propJobs) {
      setJobs(propJobs);
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    void fetchJobs(controller.signal);
    const interval = setInterval(() => void fetchJobs(controller.signal), 5000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [propJobs, fetchJobs]);

  if (loading) {
    return (
      <div className="section">
        <div className="section-title">Pipeline Jobs</div>
        <div className="grid grid-2">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      </div>
    );
  }

  if (error) return <div className="banner error">{error}</div>;

  const filteredJobs = jobs.filter(j => {
    if (filter === 'all') return true;
    return j.status === filter;
  });

  const runningCount = jobs.filter(j => j?.status === 'running').length;

  return (
    <div className="section section-jobs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div className="section-title !mb-0">
          Pipeline Jobs ({runningCount} running, {jobs.length - runningCount} closed)
        </div>
        
        <div className="flex items-center gap-3">
          <label htmlFor="job-status-filter" className="text-[10px] font-black text-muted uppercase tracking-widest">Filter</label>
          <select 
            id="job-status-filter"
            value={filter}
            onChange={(e) => setFilter(e.target.value as any)}
            className="bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-text focus:border-accent/50 outline-none appearance-none cursor-pointer min-w-[120px]"
          >
            <option value="all">All Jobs</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {filteredJobs.length === 0 ? (
        <EmptyState
          title={filter === 'all' ? "No jobs yet" : `No ${filter} jobs`}
          description={filter === 'all' ? "Start a scan from the dashboard to populate this queue." : "Try adjusting your filter settings."}
          icon="zap"
        />
      ) : filteredJobs.length > 50 ? (
        <VirtualizedJobGrid
          jobs={filteredJobs.filter(Boolean)}
          renderItem={(job) => <JobCard job={job} onRefresh={onRefresh} />}
        />
      ) : (
        <div ref={gridRef} className="grid grid-2">
          {filteredJobs.filter(Boolean).map(job => (
            <JobCard key={job.id} job={job} onRefresh={onRefresh} />
          ))}
        </div>
      )}
    </div>
  );
}
