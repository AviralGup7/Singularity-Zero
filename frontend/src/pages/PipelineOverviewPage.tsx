import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Activity } from 'lucide-react';
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
import { PageHeader, GlassCard, AnimatedCounter, GlowProgress } from '../components/ui';

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
  return (Reflect.get(STAGE_ALIASES, normalized) as string | undefined) ?? normalized;
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

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 15 },
  show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } },
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
      <div className="space-y-6">
        <div className="page-header"><SkeletonText lines={1} /></div>
        <div className="stats-grid grid grid-cols-1 md:grid-cols-5 gap-4">
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
      <div className="pipeline-overview-page ops-pipeline-overview space-y-6">
        <PageHeader
          icon={<Activity size={20} />}
          title="Pipeline Overview"
          subtitle="Observe stage flow, bottlenecks, and failure pressure in one view."
        />

        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="show"
          className="pipeline-stats-grid grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4"
        >
          <StatCard label="Running Jobs" value={stats.running} color="var(--color-running, #3b82f6)" delay={0.05} />
          <StatCard label="Avg Progress" value={stats.avgProgress > 0 ? `${stats.avgProgress}%` : '--'} color="var(--color-success, #22c55e)" delay={0.1} />
          <StatCard label="Completed" value={stats.completed} color="var(--color-success, #22c55e)" delay={0.15} />
          <StatCard label="Failed" value={stats.failed} color={stats.failed > 0 ? 'var(--color-error, #ef4444)' : 'var(--color-muted, #6b7280)'} delay={0.2} />
          <StatCard label="Total Findings" value={stats.totalFindings} color="var(--color-warning, #f59e0b)" delay={0.25} />
        </motion.div>

        <motion.div variants={itemVariants} className="card ops-card">
          <ThroughputStrip
            jobsPerSecond={throughput.jobsPerSecond}
            findingsPerSecond={throughput.findingsPerSecond}
            scanVelocity={throughput.scanVelocity}
            activeTasks={throughput.activeTasks}
          />
        </motion.div>

        {(runningJobs.length > 0 || recentJobs.length > 0) && (
          <motion.div variants={itemVariants} className="card ops-card">
            <h3>Stage Theater</h3>
            <StageTheater nodes={stageTheaterNodes} />
          </motion.div>
        )}

        {runningJobs.length > 0 && (
          <motion.div variants={itemVariants} className="card ops-card">
            <h3>Stage Timeline</h3>
            <PipelineStageTimeline jobs={runningJobs} />
          </motion.div>
        )}

        {runningJobs.length > 0 && (
          <motion.div variants={itemVariants} className="card ops-card">
            <h3>Active Jobs - Stage Progress</h3>
            <div className="active-jobs-grid grid grid-cols-1 md:grid-cols-2 gap-4">
              {runningJobs.map((job: Job) => (
                <JobStageCard key={job.id} job={job} />
              ))}
            </div>
          </motion.div>
        )}

        {recentJobs.length >= 2 && (
          <motion.div variants={itemVariants} className="card ops-card">
            <h3>Stage Duration Heatmap (Recent {recentJobs.length} jobs)</h3>
            <StageDurationHeatmap jobs={recentJobs} />
          </motion.div>
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

function StatCard({ label, value, color, delay }: { label: string; value: string | number; color: string; delay?: number }) {
  const isNumeric = typeof value === 'number';
  const numericVal = isNumeric ? value : parseFloat(String(value));
  const isPercent = typeof value === 'string' && value.endsWith('%');

  return (
    <GlassCard variant="glow" delay={delay} className="pipeline-stat-card flex flex-col justify-center items-center py-5">
      <span className="stat-value text-3xl font-extrabold tracking-tight" style={{ color }}>
        {isPercent ? (
          <AnimatedCounter value={numericVal} suffix="%" />
        ) : isNumeric ? (
          <AnimatedCounter value={numericVal} />
        ) : (
          value
        )}
      </span>
      <span className="stat-label text-xs uppercase font-semibold text-[var(--text-secondary)] mt-1.5 tracking-wider font-mono">{label}</span>
    </GlassCard>
  );
}

function JobStageCard({ job }: { job: Job }) {
  const stages = buildStageList(job);

  return (
    <GlassCard variant="default" className="job-stage-card p-4 space-y-4">
      <div className="job-stage-card-header flex items-center justify-between">
        <Link to={`/jobs/${job.id}`} className="job-stage-card-title font-bold text-[var(--accent)] hover:underline truncate mr-2">
          {job.target_name || job.base_url || job.id}
        </Link>
        <span className="job-stage-card-progress text-xs font-mono font-bold bg-[var(--accent-soft)] text-[var(--accent)] px-2 py-0.5 rounded-full">
          {Math.round(job.progress_percent ?? 0)}%
        </span>
      </div>

      <GlowProgress
        value={job.progress_percent ?? 0}
        variant="cyber"
        animated={job.status === 'running'}
        size="sm"
      />

      <div className="job-stage-card-stages flex flex-wrap gap-2 pt-2">
        {stages.map((stage) => {
          const color = STATUS_COLORS[stage.status] || STATUS_COLORS.pending;
          const bg = STATUS_BG[stage.status] || STATUS_BG.pending;
          const isActive = stage.status === 'running';
          return (
            <div
              key={stage.stage}
              className={`stage-chip text-xs border rounded px-2 py-0.5 ${isActive ? 'active animate-[glow-pulse_2s_ease-in-out_infinite]' : ''}`}
              style={{ borderColor: color, backgroundColor: bg }}
              title={`${stage.stage_label}: ${stage.percent}% ${stage.processed > 0 ? `(${stage.processed}${stage.total ? '/' + stage.total : ''})` : ''}`}
            >
              <span className="stage-chip-label font-mono">{stage.stage_label}</span>
              {stage.percent > 0 && <span className="stage-chip-percent ml-1 font-bold">{stage.percent}%</span>}
            </div>
          );
        })}
        {job.failed_stage && (
          <div className="current-stage-marker current-stage-marker--error text-xs font-semibold px-2 py-0.5 rounded bg-[var(--bad-soft)] text-[var(--bad)] border border-[var(--bad)]/20 mt-1 w-full">
            Failed: {job.failed_stage} {job.failure_reason_code ? `(${job.failure_reason_code})` : ''}
          </div>
        )}
        {job.stage_label && !job.failed_stage && (
          <div className="current-stage-marker text-xs font-semibold px-2 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/20 mt-1 w-full">
            Current: {job.stage_label}
          </div>
        )}
      </div>
    </GlassCard>
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
    const stageName = stageOrder.at(i) ?? '';
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
