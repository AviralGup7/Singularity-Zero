import { useCallback, useEffect, useMemo, useRef, useState, Suspense, lazy } from 'react';
import { Link, useNavigate, useParams, Navigate } from 'react-router-dom';
import { ROUTES } from '@/config/paths';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { DetailSkeleton } from '@/components/ui/Skeleton';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { StalledExplainerPanel } from '@/components/StalledExplainerPanel';
import { ScanSummaryCard } from '@/components/targets/ScanSummaryCard';
import { IterationProgressBar } from '@/components/IterationProgressBar';
import { PluginProgressGrid } from '@/components/PluginProgressGrid';
import { LiveTerminalFeed } from '@/components/LiveTerminalFeed';
import { DurationForecast } from '@/components/DurationForecast';
const ModulePerformanceChart = lazy(() =>
  import('@/components/charts/ModulePerformanceChart').then(m => ({ default: m.ModulePerformanceChart }))
);
import { JobStatusHeader } from '@/components/jobs/JobStatusHeader';
import { JobLogViewer } from '@/components/jobs/JobLogViewer';
import { JobTimelineComponent } from '@/components/jobs/JobTimelineComponent';
import { StageProgressBars } from '@/components/StageProgressBars';
import { StageTheater } from '@/components/ops/StageTheater';
import { ThroughputStrip } from '@/components/ops/ThroughputStrip';
import { VisualProvider } from '@/context/VisualContext';
import { mapToVisualState } from '@/lib/mapToVisualState';
import { useJobMonitor } from '@/hooks/useJobMonitor';
import { GlassCard } from '@/components/ui/GlassCard';
import { GlowProgress } from '@/components/ui/GlowProgress';
import { InfoItem, formatDurationLabel } from '@/components/jobs/JobInfoItem';
import { useJobDetails, useJobStageTheater, useJobThroughput } from '@/hooks/useJobDetails';
import { useJobRemediation, useJobTracePanel } from '@/hooks/useJobTracePanel';
import { ReportFab } from '@/components/report/ReportFab';
import {
  containerVariants,
  itemVariants,
  EASE_OUT,
  JOB_ID_RE,
  computeStageDeltas,
  TracePanel,
  ProgressTelemetrySection,
  StreamingFindingsSection,
  FailureSection,
} from './index';

export function JobDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();

  const [warningsExpanded, setWarningsExpanded] = useState(true);
  const [logsExpanded, setLogsExpanded] = useState(true);
  const prevStageRef = useRef<Record<string, number>>({});
  const [stageDeltas, setStageDeltas] = useState<Array<{ stage: string; delta: number; status: string }>>([]);

  const [exportStamp, setExportStamp] = useState<string>('');
  useEffect(() => { setExportStamp(String(Date.now())); }, []);

  const navigate = useNavigate();
  const handleRestarted = useCallback((newJobId: string) => { navigate(`${ROUTES.JOBS}/${newJobId}`); }, [navigate]);
  const monitor = useJobMonitor(jobId, { onRestarted: handleRestarted });

  const {
    job, loading, error, sseError, wsFailed, durationForecast, durationLoading,
    isPollingFallback, connectionState, sseState, actionLoading,
    showConfirmStop, showConfirmRestart, setShowConfirmStop, setShowConfirmRestart,
    reconnect, stopJob, executeStop, restartJob, executeRestart, clearSseError,
  } = monitor;

  const { displayLines, warningCount, fatalSignalCount, degradedProviders, timeoutEvents, hasRuntimeSignals } =
    useJobDetails(job ?? null);
  const { stageTheaterNodes } = useJobStageTheater(job ?? null);
  const throughput = useJobThroughput(job ?? null);
  const { remediation, remediationLoading } = useJobRemediation(jobId, job?.status === 'failed' || job?.status === 'stopped');
  const { tracePanel, traceLoading, openTracePanel, setTracePanel } = useJobTracePanel(jobId);

  useEffect(() => {
    const deltas = computeStageDeltas(job?.stage_progress, prevStageRef);
    if (deltas.length > 0) setStageDeltas(deltas);
  }, [job?.stage_progress]);

  const visualState = useMemo(() => mapToVisualState(job, { sseError }), [job, sseError]);

  if (loading) return <DetailSkeleton />;
  if (jobId && !JOB_ID_RE.test(jobId)) return <Navigate to={ROUTES.JOBS} replace />;
  if (error || !job) {
    return (
      <div className="card error">
        <h2>Error</h2>
        <p>{error || 'Job not found'}</p>
        <Link to={ROUTES.JOBS} className="btn btn-primary">Back to Jobs</Link>
      </div>
    );
  }

  return (
    <VisualProvider initialValue={visualState}>
      <motion.div variants={containerVariants} initial="hidden" animate="show" className="job-detail-page space-y-6">
        <JobStatusHeader
          job={job}
          connectionState={connectionState}
          sseState={sseState}
          wsFailed={wsFailed}
          actionLoading={actionLoading}
          onReconnect={reconnect}
          onStop={stopJob}
          onRestart={restartJob}
        />

        {sseError && (
          <div className="banner error" role="alert">
            <strong>Pipeline Error:</strong> {sseError}
            <button className="dismiss-btn" onClick={clearSseError}>Dismiss</button>
          </div>
        )}

        {(job.status === 'failed' || job.status === 'stopped') && (
          <FailureSection
            job={job}
            sseError={sseError}
            remediation={remediation}
            remediationLoading={remediationLoading}
            traceLoading={traceLoading}
            onOpenTrace={openTracePanel}
          />
        )}

        {job.status === 'running' && isPollingFallback && (
          <div className="banner warning">
            Real-time updates unavailable. Progress is polling at reduced frequency.
          </div>
        )}

        <motion.div variants={itemVariants} className="card">
          <h3>Job Information</h3>
          <div className="info-grid">
            <InfoItem label="Target" value={job.base_url} />
            <InfoItem label="Hostname" value={job.hostname} />
            <InfoItem label="Mode" value={job.mode} />
            <InfoItem label="Stage" value={job.stage_label} />
            <InfoItem label="Started" value={job.started_at} />
            <InfoItem label="Status Message" value={job.status_message} />
            <InfoItem label="Scope Entries" value={job.scope_entries?.join(', ')} />
            {job.returncode !== null && job.returncode !== undefined && (
              <InfoItem label="Exit Code" value={String(job.returncode)} />
            )}
            {job.finished_at_label && <InfoItem label="Finished" value={job.finished_at_label} />}
          </div>
        </motion.div>

        {hasRuntimeSignals && (
          <motion.div variants={itemVariants} className="card">
            <h3>Runtime Signals</h3>
            <div className="info-grid">
              {warningCount > 0 && <InfoItem label="Warnings" value={`${warningCount}`} />}
              {fatalSignalCount > 0 && <InfoItem label="Fatal Signals" value={`${fatalSignalCount}`} />}
              {typeof job.effective_timeout_seconds === 'number' && (
                <InfoItem label="Effective Timeout" value={formatDurationLabel(job.effective_timeout_seconds)} />
              )}
              {degradedProviders.length > 0 && <InfoItem label="Degraded Providers" value={`${degradedProviders.length}`} />}
              {timeoutEvents.length > 0 && <InfoItem label="Timeout Events" value={`${timeoutEvents.length}`} />}
            </div>
            {degradedProviders.length > 0 && (
              <>
                <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Degraded Providers</h4>
                <div className="modules-list flex flex-wrap gap-2 mt-2">
                  {degradedProviders.map((provider) => <span key={provider} className="module-tag">{provider}</span>)}
                </div>
              </>
            )}
            {timeoutEvents.length > 0 && (
              <>
                <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Timeout Events</h4>
                <ul className="warnings-list mt-2 space-y-1">
                  {timeoutEvents.map((event) => <li key={event}>{event}</li>)}
                </ul>
              </>
            )}
          </motion.div>
        )}

        {job.execution_options && Object.values(job.execution_options).some(Boolean) && (
          <motion.div variants={itemVariants} className="card">
            <h3>Execution Options</h3>
            <div className="info-grid">
              {Object.entries(job.execution_options).map(([key, value]) => (
                value ? <InfoItem key={key} label={key.replace(/_/g, ' ')} value="Enabled" /> : null
              ))}
            </div>
          </motion.div>
        )}

        {(job.config_href || job.scope_href || job.stdout_href || job.stderr_href || job.target_href) && (
          <motion.div variants={itemVariants} className="card">
            <h3>Job Files</h3>
            <div className="job-files-grid">
              {job.config_href && <a href={job.config_href} target="_blank" rel="noopener noreferrer" className="file-link">config.json</a>}
              {job.scope_href && <a href={job.scope_href} target="_blank" rel="noopener noreferrer" className="file-link">scope.txt</a>}
              {job.stdout_href && <a href={job.stdout_href} target="_blank" rel="noopener noreferrer" className="file-link">stdout.txt</a>}
              {job.stderr_href && <a href={job.stderr_href} target="_blank" rel="noopener noreferrer" className="file-link">stderr.txt</a>}
              {job.target_href && <a href={job.target_href} target="_blank" rel="noopener noreferrer" className="file-link">Report</a>}
            </div>
          </motion.div>
        )}

        {job.status === 'running' && (
          <motion.div variants={itemVariants} className="card">
            <h3>Progress</h3>
            <div className="progress-section space-y-3">
              <GlowProgress value={job.progress_percent ?? 0} variant="cyber" animated size="lg" />
              <div className="progress-details flex justify-between text-xs text-[var(--text-secondary)] font-mono">
                <span>{Math.round(job.progress_percent ?? 0)}% complete</span>
                {job.has_eta && <span>ETA: {job.eta_label ?? '--'}</span>}
              </div>
            </div>
            <StageProgressBars stages={job.stage_progress ?? []} />
            {job.stage === 'analysis' && job.iteration_current && (
              <IterationProgressBar currentIteration={job.iteration_current} maxIterations={job.iteration_total || 3} stagePercent={job.stage_percent || 0} />
            )}
            <div className="mt-4">
              <PluginProgressGrid plugins={[]} loading={loading && job.status === 'running'} />
            </div>
            <div className="mt-4">
              <LiveTerminalFeed jobId={job.id} />
            </div>
          </motion.div>
        )}

        <motion.div variants={itemVariants} className="card ops-card">
          <h3>Stage Theater</h3>
          {stageDeltas.length > 0 && (
            <div className="stage-delta-badges" role="status" aria-live="polite">
              {stageDeltas.map(d => (
                <span key={d.stage} className={`stage-delta-badge stage-delta-badge--${d.status}`}>
                  <span className="stage-delta-badge-arrow" aria-hidden="true">▲</span>
                  {d.stage}
                  <span className="stage-delta-badge-value">+{Math.round(d.delta)}%</span>
                </span>
              ))}
            </div>
          )}
          <StageTheater nodes={stageTheaterNodes} />
          <ThroughputStrip
            className="throughput-strip--embedded"
            jobsPerSecond={throughput.jobsPerSecond}
            findingsPerSecond={throughput.findingsPerSecond}
            scanVelocity={throughput.scanVelocity}
            activeTasks={throughput.activeTasks}
          />
        </motion.div>

        {job.progress_telemetry && <ProgressTelemetrySection telemetry={job.progress_telemetry} />}

        {(job.status === 'running' && (durationLoading || durationForecast)) && (
          <DurationForecast durations={durationForecast} loading={durationLoading} />
        )}

        {job.stalled && (
          <StalledExplainerPanel
            stalled
            stage={job.stage ?? ''}
            stageLabel={job.stage_label}
            secondsSinceUpdate={job.elapsed_seconds || 0}
            elapsedLabel={job.elapsed_label ?? ''}
            stalledContext={job.stalled_context ?? null}
          />
        )}

        {job.streaming_findings && job.streaming_findings.length > 0 && job.status === 'running' && (
          <StreamingFindingsSection findings={job.streaming_findings} />
        )}

        {job.status === 'completed' && <ScanSummaryCard job={job} />}

        {job.enabled_modules && job.enabled_modules.length > 0 && (
          <motion.div variants={itemVariants} className="card">
            <h3>Enabled Modules</h3>
            <div className="modules-list flex flex-wrap gap-2 mt-2">
              {job.enabled_modules.map((mod) => <span key={mod} className="module-tag">{mod}</span>)}
            </div>
          </motion.div>
        )}

        {job.per_module_stats && Object.keys(job.per_module_stats).length > 0 && (
          <motion.div variants={itemVariants}>
            <Suspense fallback={<div className="h-32 bg-white/5 rounded-lg animate-pulse" />}>
              <ModulePerformanceChart
                data={Object.entries(job.per_module_stats).map(([module, stats]) => ({
                  module, duration: stats.duration_sec ?? 0, findings: stats.findings_count ?? 0,
                }))}
              />
            </Suspense>
          </motion.div>
        )}

        {job.error && (
          <motion.div variants={itemVariants} className="card error-card">
            <h3>Error</h3>
            {job.failure_reason_code === 'circuit_breaker_open' ? (
              <p className="text-sm text-[var(--text-secondary)]">
                Circuit breaker is open for <strong>{job.failed_stage || 'a tool'}</strong>. Stage was skipped.
                Visit <Link to={ROUTES.SELF_HEALING} className="underline">Self-Healing</Link> to manage circuit breakers.
              </p>
            ) : (
              <pre className="error-text">{job.error}</pre>
            )}
          </motion.div>
        )}

        {job.warnings && job.warnings.length > 0 && (
          <motion.div variants={itemVariants} className="card warning-card">
            <button type="button" onClick={() => setWarningsExpanded(!warningsExpanded)} className="w-full flex items-center justify-between text-left focus:outline-none">
              <h3>Warnings ({job.warnings.length})</h3>
              <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${warningsExpanded ? 'rotate-180 text-[var(--bad)]' : ''}`} />
            </button>
            <AnimatePresence initial={false}>
              {warningsExpanded && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25, ease: EASE_OUT }} className="overflow-hidden">
                  <ul className="warnings-list mt-4 space-y-1.5">
                    {job.warnings.map((w, idx) => <li key={w.substring(0, 40) + idx}>{w}</li>)}
                  </ul>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        <motion.div variants={itemVariants} className="card">
          <button type="button" onClick={() => setLogsExpanded(!logsExpanded)} className="w-full flex items-center justify-between text-left focus:outline-none">
            <h3>Job Logs</h3>
            <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${logsExpanded ? 'rotate-180 text-[var(--accent)]' : ''}`} />
          </button>
          <AnimatePresence initial={false}>
            {logsExpanded && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25, ease: EASE_OUT }} className="overflow-hidden">
                <div className="pt-4">
                  <JobLogViewer displayLines={displayLines} wsFailed={wsFailed} jobStatus={job.status} />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        <motion.div variants={itemVariants} className="card">
          <h3>Job Timeline</h3>
          <JobTimelineComponent jobId={jobId || ''} />
        </motion.div>

        <ConfirmDialog isOpen={showConfirmStop} title="Stop Job" message={`Are you sure you want to stop job ${jobId}?`} confirmText="Stop Job" onConfirm={() => { setShowConfirmStop(false); executeStop(); }} onCancel={() => setShowConfirmStop(false)} variant="danger" />
        <ConfirmDialog isOpen={showConfirmRestart} title="Restart Job" message={`Restart job ${jobId}?`} confirmText="Restart" onConfirm={() => { setShowConfirmRestart(false); executeRestart(); }} onCancel={() => setShowConfirmRestart(false)} variant="warning" />

        {tracePanel && <TracePanel tracePanel={tracePanel} onClose={() => setTracePanel(null)} />}

        <ReportFab
          findings={job.streaming_findings ?? []}
          filenameBase={`job-${jobId || 'unknown'}-${exportStamp}`}
          targetName={job.target_name}
          context={{ target: job.target_name, jobId }}
        />
      </motion.div>
    </VisualProvider>
  );
}
