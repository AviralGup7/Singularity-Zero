import { useCallback, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ExternalLink, X, ChevronDown } from 'lucide-react';
import { DetailSkeleton } from '@/components/ui/Skeleton';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { StalledExplainerPanel } from '@/components/StalledExplainerPanel';
import { ScanSummaryCard } from '@/components/ScanSummaryCard';
import { IterationProgressBar } from '@/components/IterationProgressBar';
import { PluginProgressGrid } from '@/components/PluginProgressGrid';
import { DurationForecast } from '@/components/DurationForecast';
import { ModulePerformanceChart } from '@/components/charts/ModulePerformanceChart';
import { JobStatusHeader } from '@/components/jobs/JobStatusHeader';
import { JobLogViewer } from '@/components/jobs/JobLogViewer';
import { JobTimelineComponent } from '@/components/jobs/JobTimelineComponent';
import { StageProgressBars } from '@/components/StageProgressBars';
import { StageTheater } from '@/components/ops/StageTheater';
import { ThroughputStrip } from '@/components/ops/ThroughputStrip';
import { VisualProvider } from '@/context/VisualContext';
import { mapToVisualState } from '@/lib/mapToVisualState';
import { useJobMonitor } from '@/hooks/useJobMonitor';
import { RemediationSuggestions } from '@/components/RemediationSuggestions';
import { GlassCard, GlowProgress } from '@/components/ui';
import { InfoItem, formatDurationLabel } from '@/components/jobs/JobInfoItem';
import { useJobDetails, useJobStageTheater, useJobThroughput } from '@/hooks/useJobDetails';
import { useJobRemediation, useJobTracePanel } from '@/hooks/useJobTracePanel';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.05 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 15 },
  show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } },
};

export function JobDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const [warningsExpanded, setWarningsExpanded] = useState(true);
  const [logsExpanded, setLogsExpanded] = useState(true);

  const navigate = useNavigate();
  const handleRestarted = useCallback((newJobId: string) => {
    navigate(`/jobs/${newJobId}`);
  }, [navigate]);
  const monitor = useJobMonitor(jobId, { onRestarted: handleRestarted });

  const {
    job,
    loading,
    error,
    sseError,
    wsFailed,
    durationForecast,
    durationLoading,
    isPollingFallback,
    connectionState,
    sseState,
    actionLoading,
    showConfirmStop,
    showConfirmRestart,
    setShowConfirmStop,
    setShowConfirmRestart,
    reconnect,
    stopJob,
    executeStop,
    restartJob,
    executeRestart,
    clearSseError,
  } = monitor;

  const { displayLines, warningCount, fatalSignalCount, degradedProviders, timeoutEvents, hasRuntimeSignals } =
    useJobDetails(job ?? null);
  const { stageTheaterNodes } = useJobStageTheater(job ?? null);
  const throughput = useJobThroughput(job ?? null);
  const { remediation, remediationLoading } = useJobRemediation(jobId, job?.status === 'failed' || job?.status === 'stopped');
  const { tracePanel, traceLoading, openTracePanel, setTracePanel } = useJobTracePanel(jobId);

  const visualState = useMemo(
    () => mapToVisualState(job, { sseError }),
    [job, sseError],
  );

  if (loading) return <DetailSkeleton />;

  if (error || !job) {
    return (
      <div className="card error">
        <h2>Error</h2>
        <p>{error || 'Job not found'}</p>
        <Link to="/jobs" className="btn btn-primary">Back to Jobs</Link>
      </div>
    );
  }

  return (
    <VisualProvider initialValue={visualState}>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="show"
        className="job-detail-page space-y-6"
      >
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
          <motion.div variants={itemVariants} className="card error-card" role="alert">
            <h3>Job Failure Details</h3>
            <div className="info-grid">
              {job.failed_stage && <InfoItem label="Stage" value={job.failed_stage} />}
              {job.failure_reason_code && <InfoItem label="Reason Code" value={job.failure_reason_code} />}
              {job.failure_step && <InfoItem label="Failure Step" value={job.failure_step} />}
            </div>
            {(job.failure_reason || job.error || sseError) && (
              <pre className="error-text mt-4">{job.failure_reason || job.error || sseError}</pre>
            )}
          </motion.div>
        )}

        {(job.status === 'failed' || job.status === 'stopped') && (
          <motion.div variants={itemVariants} className="card">
            <div className="trace-actions-header flex items-center justify-between gap-4">
              <h3>Debug Actions</h3>
              <button className="btn btn-secondary btn-sm flex items-center gap-1.5" onClick={openTracePanel} disabled={traceLoading}>
                <ExternalLink size={14} aria-hidden="true" />
                <span>{traceLoading ? 'Opening...' : 'Open Jaeger Trace'}</span>
              </button>
            </div>
            <RemediationSuggestions suggestions={remediation} loading={remediationLoading} />
          </motion.div>
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
            {job.finished_at_label && (
              <InfoItem label="Finished" value={job.finished_at_label} />
            )}
          </div>
        </motion.div>

        {hasRuntimeSignals && (
          <motion.div variants={itemVariants} className="card">
            <h3>Runtime Signals</h3>
            <div className="info-grid">
              {warningCount > 0 && (
                <InfoItem label="Warnings" value={`${warningCount}`} />
              )}
              {fatalSignalCount > 0 && (
                <InfoItem label="Fatal Signals" value={`${fatalSignalCount}`} />
              )}
              {typeof job.effective_timeout_seconds === 'number' && (
                <InfoItem
                  label="Effective Timeout"
                  value={formatDurationLabel(job.effective_timeout_seconds)}
                />
              )}
              {degradedProviders.length > 0 && (
                <InfoItem label="Degraded Providers" value={`${degradedProviders.length}`} />
              )}
              {timeoutEvents.length > 0 && (
                <InfoItem label="Timeout Events" value={`${timeoutEvents.length}`} />
              )}
            </div>
            {degradedProviders.length > 0 && (
              <>
                <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Degraded Providers</h4>
                <div className="modules-list flex flex-wrap gap-2 mt-2">
                  {degradedProviders.map((provider) => (
                    <span key={provider} className="module-tag">{provider}</span>
                  ))}
                </div>
              </>
            )}
            {timeoutEvents.length > 0 && (
              <>
                <h4 className="mt-4 text-xs font-bold text-[var(--text-secondary)] font-mono uppercase tracking-wider">Timeout Events</h4>
                <ul className="warnings-list mt-2 space-y-1">
                  {timeoutEvents.map((event) => (
                    <li key={event}>{event}</li>
                  ))}
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
              <GlowProgress
                value={job.progress_percent ?? 0}
                variant="cyber"
                animated={job.status === 'running'}
                size="lg"
              />
              <div className="progress-details flex justify-between text-xs text-[var(--text-secondary)] font-mono">
                <span>{Math.round(job.progress_percent ?? 0)}% complete</span>
                {job.has_eta && <span>ETA: {job.eta_label ?? '--'}</span>}
              </div>
            </div>
            <StageProgressBars stages={job.stage_progress ?? []} />
            {job.stage === 'analysis' && job.iteration_current && (
              <IterationProgressBar
                currentIteration={job.iteration_current}
                maxIterations={job.iteration_total || 3}
                stagePercent={job.stage_percent || 0}
              />
            )}
            <div className="mt-4">
              <PluginProgressGrid
                plugins={[]}
                loading={loading && job.status === 'running'}
              />
            </div>
          </motion.div>
        )}

        <motion.div variants={itemVariants} className="card ops-card">
          <h3>Stage Theater</h3>
          <StageTheater nodes={stageTheaterNodes} />
          <ThroughputStrip
            className="throughput-strip--embedded"
            jobsPerSecond={throughput.jobsPerSecond}
            findingsPerSecond={throughput.findingsPerSecond}
            scanVelocity={throughput.scanVelocity}
            activeTasks={throughput.activeTasks}
          />
        </motion.div>

        {job.progress_telemetry && (
          <motion.div variants={itemVariants} className="card">
            <div className="pt-4 space-y-4">
              <div className="info-grid">
                <InfoItem label="Active Tasks" value={String(job.progress_telemetry.active_task_count ?? 0)} />
                {typeof job.progress_telemetry.requests_per_second === 'number' && (
                  <InfoItem label="Requests/sec" value={job.progress_telemetry.requests_per_second.toFixed(2)} />
                )}
                {typeof job.progress_telemetry.throughput_per_second === 'number' && (
                  <InfoItem label="Throughput/sec" value={job.progress_telemetry.throughput_per_second.toFixed(2)} />
                )}
                {typeof job.progress_telemetry.vulnerability_likelihood_score === 'number' && (
                  <InfoItem
                    label="Vuln Likelihood"
                    value={`${Math.round(job.progress_telemetry.vulnerability_likelihood_score * 100)}%`}
                  />
                )}
                {typeof job.progress_telemetry.confidence_score === 'number' && (
                  <InfoItem label="Confidence" value={`${Math.round(job.progress_telemetry.confidence_score * 100)}%`} />
                )}
                {typeof job.progress_telemetry.high_value_target_count === 'number' && (
                  <InfoItem label="High-Value Targets" value={String(job.progress_telemetry.high_value_target_count)} />
                )}
                {typeof job.progress_telemetry.retry_count === 'number' && (
                  <InfoItem label="Retries" value={String(job.progress_telemetry.retry_count)} />
                )}
                {typeof job.progress_telemetry.failure_count === 'number' && (
                  <InfoItem label="Failures Seen" value={String(job.progress_telemetry.failure_count)} />
                )}
                {job.progress_telemetry.targets && (
                  <InfoItem
                    label="Target State"
                    value={`queued ${job.progress_telemetry.targets.queued ?? 0} · scanning ${job.progress_telemetry.targets.scanning ?? 0} · done ${job.progress_telemetry.targets.done ?? 0}`}
                  />
                )}
                {job.progress_telemetry.drop_off && (
                  <InfoItem
                    label="Drop-Off"
                    value={`input ${job.progress_telemetry.drop_off.input} · kept ${job.progress_telemetry.drop_off.kept} · dropped ${job.progress_telemetry.drop_off.dropped}`}
                  />
                )}
                {job.progress_telemetry.deduplication && (
                  <InfoItem
                    label="Dedup"
                    value={`removed ${job.progress_telemetry.deduplication.removed} · remaining ${job.progress_telemetry.deduplication.remaining}`}
                  />
                )}
                {typeof job.progress_telemetry.signal_noise_ratio === 'number' && (
                  <InfoItem label="Signal/Noise Ratio" value={job.progress_telemetry.signal_noise_ratio.toFixed(2)} />
                )}
                {job.progress_telemetry.bottleneck_stage && (
                  <InfoItem
                    label="Bottleneck"
                    value={`${job.progress_telemetry.bottleneck_stage}${typeof job.progress_telemetry.bottleneck_seconds === 'number' ? ` (${Math.round(job.progress_telemetry.bottleneck_seconds)}s)` : ''}`}
                  />
                )}
                {job.progress_telemetry.next_best_action && (
                  <InfoItem label="Next Best Action" value={job.progress_telemetry.next_best_action} />
                )}
              </div>

              {job.progress_telemetry.learning_feedback && (
                <GlassCard variant="glow" delay={0.1} className="mt-4 p-4 border border-[var(--accent)]/30">
                  <h4 className="text-xs font-bold uppercase tracking-widest text-[var(--accent)] mb-2 font-mono">Neural Engine Feedback</h4>
                  <p className="text-xs italic text-[var(--text-secondary)] leading-relaxed font-sans">
                    {typeof job.progress_telemetry.learning_feedback === 'string'
                      ? job.progress_telemetry.learning_feedback
                      : JSON.stringify(job.progress_telemetry.learning_feedback)}
                  </p>
                </GlassCard>
              )}

              {job.progress_telemetry.skipped_stages && job.progress_telemetry.skipped_stages.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)] font-mono mb-2">Skipped Stages</h4>
                  <div className="flex flex-wrap gap-2">
                    {job.progress_telemetry.skipped_stages.map((s) => (
                      <span key={s.stage} className="px-2 py-1 bg-white/5 border border-white/10 rounded text-[10px] font-mono" title={s.reason}>
                        {s.stage}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {job.progress_telemetry.top_active_targets && job.progress_telemetry.top_active_targets.length > 0 && (
                <div className="modules-list mt-4 flex flex-wrap gap-2">
                  {job.progress_telemetry.top_active_targets.map((item) => (
                    <span key={item} className="module-tag">{item}</span>
                  ))}
                </div>
              )}
              {job.progress_telemetry.event_triggers && job.progress_telemetry.event_triggers.length > 0 && (
                <ul className="warnings-list mt-4 space-y-1">
                  {job.progress_telemetry.event_triggers.slice(-5).map((trigger) => (
                    <li key={trigger}>{trigger}</li>
                  ))}
                </ul>
              )}
            </div>
          </motion.div>
        )}

        {job.status === 'running' && (durationLoading || durationForecast) && (
          <DurationForecast
            durations={durationForecast}
            loading={durationLoading}
          />
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
          <motion.div variants={itemVariants} className="card">
            <h3>Findings Discovered ({job.streaming_findings.length})</h3>
            <div className="streaming-findings space-y-2 mt-4">
              <AnimatePresence initial={false}>
                {job.streaming_findings.slice(-5).reverse().map((f, idx) => (
                  <motion.div
                    key={f.id || `${f.type}-${f.target}-${idx}`}
                    initial={{ opacity: 0, x: -20, scale: 0.95 }}
                    animate={{ opacity: 1, x: 0, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.3, ease: EASE_OUT }}
                    className={`finding-min-card sev-${f.severity} flex items-center gap-3 p-3 rounded-lg border`}
                  >
                    <span className={`sev-badge text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                      f.severity === 'critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                      f.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                      'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    }`}>{f.severity}</span>
                    <span className="finding-min-title font-bold text-sm text-[var(--text-primary)] flex-1 truncate">{f.type || 'Unknown'}</span>
                    <span className="finding-min-target text-xs text-[var(--text-tertiary)] truncate max-w-sm">{f.target || f.url?.substring(0, 50) || ''}</span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
            <Link to="/findings" className="view-all-findings-link text-xs text-[var(--accent)] hover:underline mt-3 block">View all findings</Link>
          </motion.div>
        )}

        {job.status === 'completed' && <ScanSummaryCard job={job} />}

        {job.enabled_modules && job.enabled_modules.length > 0 && (
          <motion.div variants={itemVariants} className="card">
            <h3>Enabled Modules</h3>
            <div className="modules-list flex flex-wrap gap-2 mt-2">
              {job.enabled_modules.map((mod) => (
                <span key={mod} className="module-tag">{mod}</span>
              ))}
            </div>
          </motion.div>
        )}

        {job.per_module_stats && Object.keys(job.per_module_stats).length > 0 && (
          <motion.div variants={itemVariants}>
            <ModulePerformanceChart
              data={Object.entries(job.per_module_stats).map(([module, stats]) => ({
                module,
                duration: stats.duration_sec ?? 0,
                findings: stats.findings_count ?? 0,
              }))}
            />
          </motion.div>
        )}

        {job.error && (
          <motion.div variants={itemVariants} className="card error-card">
            <h3>Error</h3>
            <pre className="error-text">{job.error}</pre>
          </motion.div>
        )}

        {job.warnings && job.warnings.length > 0 && (
          <motion.div variants={itemVariants} className="card warning-card">
            <button
              type="button"
              onClick={() => setWarningsExpanded(!warningsExpanded)}
              className="w-full flex items-center justify-between text-left focus:outline-none"
            >
              <h3>Warnings ({job.warnings.length})</h3>
              <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${warningsExpanded ? 'rotate-180 text-[var(--bad)]' : ''}`} />
            </button>
            <AnimatePresence initial={false}>
              {warningsExpanded && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.25, ease: EASE_OUT }}
                  className="overflow-hidden"
                >
                  <ul className="warnings-list mt-4 space-y-1.5">
                    {job.warnings.map((w, idx) => (
                      <li key={w.substring(0, 40) + idx}>{w}</li>
                    ))}
                  </ul>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        <motion.div variants={itemVariants} className="card">
          <button
            type="button"
            onClick={() => setLogsExpanded(!logsExpanded)}
            className="w-full flex items-center justify-between text-left focus:outline-none"
          >
            <h3>Job Logs</h3>
            <ChevronDown size={18} className={`transform transition-transform duration-200 text-[var(--text-secondary)] ${logsExpanded ? 'rotate-180 text-[var(--accent)]' : ''}`} />
          </button>
          <AnimatePresence initial={false}>
            {logsExpanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25, ease: EASE_OUT }}
                className="overflow-hidden"
              >
                <div className="pt-4">
                  <JobLogViewer
                    displayLines={displayLines}
                    wsFailed={wsFailed}
                    jobStatus={job.status}
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        <motion.div variants={itemVariants} className="card">
          <h3>Job Timeline</h3>
          <JobTimelineComponent jobId={jobId || ''} />
        </motion.div>

        <ConfirmDialog
          isOpen={showConfirmStop}
          title="Stop Job"
          message={`Are you sure you want to stop job ${jobId}? This will terminate the running scan.`}
          confirmText="Stop Job"
          onConfirm={() => { setShowConfirmStop(false); executeStop(); }}
          onCancel={() => setShowConfirmStop(false)}
          variant="danger"
        />
        <ConfirmDialog
          isOpen={showConfirmRestart}
          title="Restart Job"
          message={`Restart job ${jobId}? This will re-run the scan from the beginning.`}
          confirmText="Restart"
          onConfirm={() => { setShowConfirmRestart(false); executeRestart(); }}
          onCancel={() => setShowConfirmRestart(false)}
          variant="warning"
        />

        {tracePanel && (
          <div className="fixed inset-0 z-50 flex justify-end">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setTracePanel(null)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />

            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', stiffness: 260, damping: 30 }}
              className="relative h-full w-full max-w-3xl bg-[var(--surface)] border-l border-[var(--border)] shadow-2xl flex flex-col"
              role="dialog"
              aria-modal="true"
              aria-label="Jaeger trace"
            >
              <div className="trace-side-panel-header p-4 border-b border-[var(--border)] flex justify-between items-center bg-[var(--surface-2)]">
                <div>
                  <h3 className="font-bold text-lg text-[var(--text-primary)]">Jaeger Trace</h3>
                  <span className="text-xs text-[var(--text-secondary)] font-mono">{tracePanel.mode === 'trace' ? tracePanel.trace_id : `Search for ${tracePanel.job_id}`}</span>
                </div>
                <button className="btn btn-ghost btn-sm p-1.5 hover:bg-white/5 rounded" onClick={() => setTracePanel(null)} aria-label="Close trace panel">
                  <X size={18} aria-hidden="true" />
                </button>
              </div>
              <iframe title="Jaeger trace" src={tracePanel.trace_url} className="flex-1 w-full border-none" />
              <div className="p-4 border-t border-[var(--border)] bg-[var(--surface-2)] flex justify-end">
                <a className="btn btn-secondary text-xs flex items-center gap-1.5" href={tracePanel.trace_url} target="_blank" rel="noopener noreferrer">
                  <span>Open in Jaeger</span>
                  <ExternalLink size={12} />
                </a>
              </div>
            </motion.div>
          </div>
        )}
      </motion.div>
    </VisualProvider>
  );
}
