import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useJobs } from '../hooks';
import { SkeletonCard, SkeletonText } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';
import { StageDurationHeatmap } from '../components/charts/StageDurationHeatmap';
import { PipelineStageTimeline } from '../components/PipelineStageTimeline';
import { StageTheater } from '../components/ops/StageTheater';
import { buildStageTheaterNodesFromJobs } from '../lib/stageTheaterUtils';
import { ThroughputStrip } from '../components/ops/ThroughputStrip';
import { VisualProvider } from '@/context/VisualContext';
import { mapJobsToVisualState } from '@/lib/mapToVisualState';
import type { Job, StageProgressEntry } from '../types/api';

const STAGE_ORDER = [
  'startup', 'subdomains', 'live_hosts', 'urls', 'recon_validation', 'parameters', 'ranking',
  'passive_scan', 'active_scan', 'semgrep', 'nuclei', 'access_control', 'validation', 'intelligence', 'reporting',
];

const STAGE_ALIASES: Record<string, string> = {
  priority: 'ranking',
};

function normalizeStageName(stageName: string | undefined): string {
  const normalized = String(stageName || '').trim().toLowerCase();
  if (!normalized) return '';
  return STAGE_ALIASES[normalized] ?? normalized;
}

const STATUS_COLORS: Record<string, string> = {
  running: 'var(--color-running, #3b82f6)',
  completed: 'var(--color-success, #22c55e)',
  error: 'var(--color-error, #ef4444)',
  pending: 'var(--color-muted, #6b7280)',
};

const STATUS_BG: Record<string, string> = {
  running: 'rgba(59, 130, 246, 0.15)',
  completed: 'rgba(34, 197, 94, 0.12)',
  error: 'rgba(239, 68, 68, 0.15)',
  pending: 'rgba(107, 114, 128, 0.08)',
};

export function PipelineOverviewPage() {
  const { data: allJobs, loading, error } = useJobs({ refetchInterval: 5000 });

  const runningJobs = useMemo(() => {
    return (allJobs ?? []).filter((j: Job) => j.status === 'running');
  }, [allJobs]);

  const recentJobs = useMemo(() => {
    return (allJobs ?? [])
      .filter((j: Job) => j.status === 'completed' || j.status === 'failed')
      .slice(0, 20);
  }, [allJobs]);

  const stats = useMemo(() => {
    const jobs = allJobs ?? [];
    const running = jobs.filter((j: Job) => j.status === 'running');
    const completed = jobs.filter((j: Job) => j.status === 'completed');
    const failed = jobs.filter((j: Job) => j.status === 'failed');
    const totalFindings = jobs.reduce((sum, j: Job) => sum + (j.findings_count ?? 0), 0);
    const avgProgress = running.length > 0
      ? Math.round(running.reduce((sum, j: Job) => sum + (j.progress_percent ?? 0), 0) / running.length)
      : 0;

    return { running: running.length, completed: completed.length, failed: failed.length, totalFindings, avgProgress };
  }, [allJobs]);

  const stageTheaterNodes = useMemo(() => {
    const sourceJobs = runningJobs.length > 0 ? runningJobs : recentJobs;
    return buildStageTheaterNodesFromJobs(sourceJobs);
  }, [runningJobs, recentJobs]);

  const throughput = useMemo(() => {
    const totals = runningJobs.reduce(
      (acc, job) => {
        const telemetry = job.progress_telemetry;
        acc.jobsPerSecond += Number(telemetry?.requests_per_second ?? 0);
        acc.findingsPerSecond += Number(telemetry?.throughput_per_second ?? 0);
        acc.activeTasks += Number(telemetry?.active_task_count ?? 0);
        return acc;
      },
      { jobsPerSecond: 0, findingsPerSecond: 0, activeTasks: 0 }
    );
    const scanVelocity = totals.jobsPerSecond * 0.6 + totals.findingsPerSecond * 0.4;
    return { ...totals, scanVelocity };
  }, [runningJobs]);
  const visualState = useMemo(
    () => mapJobsToVisualState(runningJobs.length > 0 ? runningJobs : recentJobs),
    [recentJobs, runningJobs]
  );

  if (loading) {
    return (
      <div>
        <div className="page-header"><SkeletonText lines={1} /></div>
        <div className="stats-grid">
          {Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (error) {
    return (
      <div className="card error">
        <h2>Error loading pipeline overview</h2>
        <p>{error.message}</p>
      </div>
    );
  }

  return (
    <VisualProvider initialValue={visualState}>
      <div className="pipeline-overview-page ops-pipeline-overview">
      <div className="page-header">
        <h2 className="section-title">Pipeline Overview</h2>
        <span className="page-subtitle">Observe stage flow, bottlenecks, and failure pressure in one view.</span>
      </div>

      <div className="pipeline-stats-grid">
        <StatCard label="Running Jobs" value={stats.running} color="var(--color-running, #3b82f6)" />
        <StatCard label="Avg Progress" value={stats.avgProgress > 0 ? `${stats.avgProgress}%` : '--'} color="var(--color-success, #22c55e)" />
        <StatCard label="Completed" value={stats.completed} color="var(--color-success, #22c55e)" />
        <StatCard label="Failed" value={stats.failed} color={stats.failed > 0 ? 'var(--color-error, #ef4444)' : 'var(--color-muted, #6b7280)'} />
        <StatCard label="Total Findings" value={stats.totalFindings.toLocaleString()} color="var(--color-warning, #f59e0b)" />
      </div>

      <div className="card ops-card">
        <ThroughputStrip
          jobsPerSecond={throughput.jobsPerSecond}
          findingsPerSecond={throughput.findingsPerSecond}
          scanVelocity={throughput.scanVelocity}
          activeTasks={throughput.activeTasks}
        />
      </div>

      {(runningJobs.length > 0 || recentJobs.length > 0) && (
        <div className="card ops-card">
          <h3>Stage Theater</h3>
          <StageTheater nodes={stageTheaterNodes} />
        </div>
      )}

      {runningJobs.length > 0 && (
        <div className="card ops-card">
          <h3>Stage Timeline</h3>
          <PipelineStageTimeline jobs={runningJobs} />
        </div>
      )}

      {runningJobs.length > 0 && (
        <div className="card ops-card">
          <h3>Active Jobs - Stage Progress</h3>
          <div className="active-jobs-grid">
            {runningJobs.map((job: Job) => (
              <JobStageCard key={job.id} job={job} />
            ))}
          </div>
        </div>
      )}

      {recentJobs.length >= 2 && (
        <div className="card ops-card">
          <h3>Stage Duration Heatmap (Recent {recentJobs.length} jobs)</h3>
          <StageDurationHeatmap jobs={recentJobs} />
        </div>
      )}

      {runningJobs.length === 0 && recentJobs.length === 0 && (
        <EmptyState
          icon="activity"
          title="No pipeline activity"
          description="Start a scan job to stream pipeline telemetry here."
        />
      )}
      </div>
    </VisualProvider>
  );
}

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="pipeline-stat-card">
      <span className="stat-value" style={{ color }}>{typeof value === 'number' ? value.toLocaleString() : value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function JobStageCard({ job }: { job: Job }) {
  const stages = buildStageList(job);

  return (
    <div className="job-stage-card">
      <div className="job-stage-card-header">
        <Link to={`/jobs/${job.id}`} className="job-stage-card-title">
          {job.target_name || job.base_url || job.id}
        </Link>
        <span className="job-stage-card-progress">{Math.round(job.progress_percent ?? 0)}%</span>
      </div>
      <div className="job-stage-card-bar">
        <div className="job-stage-card-fill" style={{ width: `${Math.min(100, job.progress_percent ?? 0)}%` }} />
      </div>
      <div className="job-stage-card-stages">
        {stages.map((stage) => {
          const color = STATUS_COLORS[stage.status] || STATUS_COLORS.pending;
          const bg = STATUS_BG[stage.status] || STATUS_BG.pending;
          const isActive = stage.status === 'running';
          return (
            <div
              key={stage.stage}
              className={`stage-chip ${isActive ? 'active' : ''}`}
              style={{ borderColor: color, backgroundColor: bg }}
              title={`${stage.stage_label}: ${stage.percent}% ${stage.processed > 0 ? `(${stage.processed}${stage.total ? '/' + stage.total : ''})` : ''}`}
            >
              <span className="stage-chip-label">{stage.stage_label}</span>
              {stage.percent > 0 && <span className="stage-chip-percent">{stage.percent}%</span>}
            </div>
          );
        })}
        {job.failed_stage && (
          <div className="current-stage-marker current-stage-marker--error">
            Failed: {job.failed_stage} {job.failure_reason_code ? `(${job.failure_reason_code})` : ''}
          </div>
        )}
        {job.stage_label && !job.failed_stage && (
          <div className="current-stage-marker">Current: {job.stage_label}</div>
        )}
      </div>
    </div>
  );
}

function buildStageList(job: Job): StageProgressEntry[] {
  const stageOrder = [...STAGE_ORDER];
  const seen = new Set(stageOrder);
  const addStage = (stageName: string | undefined) => {
    const normalized = normalizeStageName(stageName);
    if (!normalized || seen.has(normalized)) return;
    if (normalized === 'recon_validation') {
      const urlsIndex = stageOrder.indexOf('urls');
      if (urlsIndex >= 0) {
        stageOrder.splice(urlsIndex + 1, 0, normalized);
      } else {
        stageOrder.push(normalized);
      }
      seen.add(normalized);
      return;
    }
    stageOrder.push(normalized);
    seen.add(normalized);
  };

  const currentStage = normalizeStageName(job.stage);
  addStage(currentStage);
  for (const entry of job.stage_progress ?? []) {
    addStage(entry.stage);
  }

  const stageMap = new Map<string, StageProgressEntry>();
  for (const entry of job.stage_progress ?? []) {
    const normalized = normalizeStageName(entry.stage);
    if (!normalized) continue;
    stageMap.set(normalized, {
      ...entry,
      stage: normalized,
    });
  }

  const currentStageIdx = stageOrder.indexOf(currentStage);

  const filled: StageProgressEntry[] = [];

  for (let i = 0; i < stageOrder.length; i++) {
    const stageName = stageOrder[i];
    const existing = stageMap.get(stageName);
    if (existing) {
      filled.push(existing);
    } else {
      let status: 'pending' | 'running' | 'completed' = 'pending';
      if (i < currentStageIdx) status = 'completed';
      else if (i === currentStageIdx) status = 'running';
      filled.push({
        stage: stageName,
        stage_label: stageName.replace(/_/g, ' '),
        status,
        processed: 0,
        total: null,
        percent: i < currentStageIdx ? 100 : 0,
      });
    }
  }

  return filled;
}
