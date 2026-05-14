import { Link, useNavigate, useParams } from 'react-router-dom';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { ExternalLink, X } from 'lucide-react';
import { DetailSkeleton } from '../components/ui/Skeleton';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { StalledExplainerPanel } from '../components/StalledExplainerPanel';
import { ScanSummaryCard } from '../components/ScanSummaryCard';
import { IterationProgressBar } from '../components/IterationProgressBar';
import { PluginProgressGrid } from '../components/PluginProgressGrid';
import { DurationForecast } from '../components/DurationForecast';
import { ModulePerformanceChart } from '../components/charts/ModulePerformanceChart';
import { JobStatusHeader } from '../components/jobs/JobStatusHeader';
import { JobLogViewer } from '../components/jobs/JobLogViewer';
import { JobTimelineComponent } from '../components/JobTimelineComponent';
import { StageProgressBars } from '../components/StageProgressBars';
import { StageTheater, buildStageTheaterNodesFromJob } from '../components/ops/StageTheater';
import { ThroughputStrip } from '../components/ops/ThroughputStrip';
import { VisualProvider } from '@/context/VisualContext';
import { mapToVisualState } from '@/lib/mapToVisualState';
import { useJobMonitor } from '../hooks/useJobMonitor';
import { getJobRemediation, getJobTraceLink } from '../api/jobs';
import { RemediationSuggestions } from '../components/RemediationSuggestions';
import type { RemediationSuggestion, TraceLink } from '../types/api';

const RECON_FAILURE_STAGES = new Set(['subdomains', 'live_hosts', 'urls', 'recon_validation']);

export function JobDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const [tracePanel, setTracePanel] = useState<TraceLink | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [remediation, setRemediation] = useState<RemediationSuggestion[]>([]);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const navigate = useNavigate();
  const handleRestarted = useCallback((newJobId: string) => {
    navigate(`/jobs/${newJobId}`);
  }, [navigate]);
  const monitor = useJobMonitor(jobId, { onRestarted: handleRestarted });

  const {
    job, loading, error,
    allLogLines, pluginProgress, streamingFindings,
    sseError, wsFailed, durationForecast, durationLoading,
    isPollingFallback, connectionState, sseState, actionLoading,
    showConfirmStop, showConfirmRestart,
    setShowConfirmStop, setShowConfirmRestart,
    reconnect, stopJob, executeStop,
    restartJob, executeRestart, clearSseError,
  } = monitor;

  const stageTheaterNodes = useMemo(() => (job ? buildStageTheaterNodesFromJob(job) : []), [job]);
  const throughput = useMemo(() => {
    const telemetry = job?.progress_telemetry;
    const jobsPerSecond = Number(telemetry?.requests_per_second ?? 0);
    const findingsPerSecond = Number(telemetry?.throughput_per_second ?? 0);
    const stageRatio = typeof job?.stage_percent === 'number'
      ? Math.max(0, Math.min(100, job.stage_percent)) / 100
      : Math.max(0, Math.min(100, job?.progress_percent ?? 0)) / 100;
    const scanVelocity = jobsPerSecond * 0.6 + findingsPerSecond * 0.4 + stageRatio;
    return {
      jobsPerSecond,
      findingsPerSecond,
      scanVelocity,
      activeTasks: Number(telemetry?.active_task_count ?? 0),
    };
  }, [job?.progress_telemetry, job?.progress_percent, job?.stage_percent]);
  const visualState = useMemo(
    () => mapToVisualState(job, { sseError }),
    [job, sseError]
  );
  const isFailedJob = job?.status === 'failed' || job?.status === 'stopped';

  useEffect(() => {
    if (!jobId || !isFailedJob) {
      return;
    }
    const controller = new AbortController();
    setRemediationLoading(true);
    getJobRemediation(jobId, controller.signal)
      .then((response) => setRemediation(response.suggestions ?? []))
      .catch(() => setRemediation([]))
      .finally(() => setRemediationLoading(false));
    return () => controller.abort();
  }, [jobId, isFailedJob]);

  const openTracePanel = useCallback(async () => {
    if (!jobId) return;
    setTraceLoading(true);
    try {
      const link = await getJobTraceLink(jobId);
      setTracePanel(link);
    } finally {
      setTraceLoading(false);
    }
  }, [jobId]);

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

  const displayLines = allLogLines.length > 0 ? allLogLines : (job.latest_logs ?? []);
  const failedStage = (job.failed_stage || '').trim().toLowerCase();
  const isReconFailure =
    (job.status === 'failed' || job.status === 'stopped') &&
    RECON_FAILURE_STAGES.has(failedStage);
  const reconFailureText = job.failure_reason || job.error || sseError || '';
  const telemetry = job.progress_telemetry;
  const warningCount = typeof job.warning_count === 'number'
    ? job.warning_count
    : job.warnings?.length ?? 0;
  const fatalSignalCount = typeof job.fatal_signal_count === 'number'
    ? job.fatal_signal_count
    : 0;
  const degradedProviders = job.degraded_providers ?? [];
  const timeoutEvents = job.timeout_events ?? [];
  const hasRuntimeSignals =
    warningCount > 0 ||
    fatalSignalCount > 0 ||
    degradedProviders.length > 0 ||
    timeoutEvents.length > 0 ||
    typeof job.effective_timeout_seconds === 'number';

  return (
    <VisualProvider initialValue={visualState}>
      <div className="job-detail-page">
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

      {isReconFailure && (
        <div className="card error-card" role="alert">
          <h3>Recon Failure</h3>
          <div className="info-grid">
            <InfoItem label="Stage" value={job.failed_stage} />
            <InfoItem label="Reason Code" value={job.failure_reason_code} />
            <InfoItem label="Failure Step" value={job.failure_step} />
          </div>
          {reconFailureText && <pre className="error-text">{reconFailureText}</pre>}
        </div>
      )}

      {isFailedJob && (
        <div className="card">
          <div className="trace-actions-header">
            <h3>Debug Actions</h3>
            <button className="btn btn-secondary btn-sm" onClick={openTracePanel} disabled={traceLoading}>
              <ExternalLink size={14} aria-hidden="true" />
              {traceLoading ? 'Opening...' : 'Open Jaeger Trace'}
            </button>
          </div>
          <RemediationSuggestions suggestions={remediation} loading={remediationLoading} />
        </div>
      )}

      {job.status === 'running' && isPollingFallback && (
        <div className="banner warning">
          Real-time updates unavailable. Progress is polling at reduced frequency.
        </div>
      )}

      <div className="card">
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
      </div>

      {hasRuntimeSignals && (
        <div className="card">
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
              <h4>Degraded Providers</h4>
              <div className="modules-list">
                {degradedProviders.map((provider) => (
                  <span key={provider} className="module-tag">{provider}</span>
                ))}
              </div>
            </>
          )}
          {timeoutEvents.length > 0 && (
            <>
              <h4>Timeout Events</h4>
              <ul className="warnings-list">
                {timeoutEvents.map((event) => (
                  <li key={event}>{event}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {job.execution_options && Object.values(job.execution_options).some(Boolean) && (
        <div className="card">
          <h3>Execution Options</h3>
          <div className="info-grid">
            {Object.entries(job.execution_options).map(([key, value]) => (
              value ? <InfoItem key={key} label={key.replace(/_/g, ' ')} value="Enabled" /> : null
            ))}
          </div>
        </div>
      )}

      {(job.config_href || job.scope_href || job.stdout_href || job.stderr_href || job.target_href) && (
        <div className="card">
          <h3>Job Files</h3>
          <div className="job-files-grid">
            {job.config_href && <a href={job.config_href} target="_blank" rel="noopener noreferrer" className="file-link">config.json</a>}
            {job.scope_href && <a href={job.scope_href} target="_blank" rel="noopener noreferrer" className="file-link">scope.txt</a>}
            {job.stdout_href && <a href={job.stdout_href} target="_blank" rel="noopener noreferrer" className="file-link">stdout.txt</a>}
            {job.stderr_href && <a href={job.stderr_href} target="_blank" rel="noopener noreferrer" className="file-link">stderr.txt</a>}
            {job.target_href && <a href={job.target_href} target="_blank" rel="noopener noreferrer" className="file-link">Report</a>}
          </div>
        </div>
      )}

      {job.status === 'running' && (
        <div className="card">
          <h3>Progress</h3>
          <div className="progress-section">
            <div className="progress-bar large">
              <div
                className="progress-fill running"
                style={{ width: `${Math.min(100, job.progress_percent ?? 0)}%` }}
              />
            </div>
            <div className="progress-details">
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
              plugins={pluginProgress}
              loading={loading && job.status === 'running'}
            />
          </div>
        </div>
      )}

      <div className="card ops-card">
        <h3>Stage Theater</h3>
        <StageTheater nodes={stageTheaterNodes} />
        <ThroughputStrip
          className="throughput-strip--embedded"
          jobsPerSecond={throughput.jobsPerSecond}
          findingsPerSecond={throughput.findingsPerSecond}
          scanVelocity={throughput.scanVelocity}
          activeTasks={throughput.activeTasks}
        />
      </div>

      {telemetry && (
        <div className="card">
          <h3>Pipeline Telemetry</h3>
          <div className="info-grid">
            <InfoItem label="Active Tasks" value={String(telemetry.active_task_count ?? 0)} />
            {typeof telemetry.requests_per_second === 'number' && (
              <InfoItem label="Requests/sec" value={telemetry.requests_per_second.toFixed(2)} />
            )}
            {typeof telemetry.throughput_per_second === 'number' && (
              <InfoItem label="Throughput/sec" value={telemetry.throughput_per_second.toFixed(2)} />
            )}
            {typeof telemetry.vulnerability_likelihood_score === 'number' && (
              <InfoItem
                label="Vuln Likelihood"
                value={`${Math.round(telemetry.vulnerability_likelihood_score * 100)}%`}
              />
            )}
            {typeof telemetry.confidence_score === 'number' && (
              <InfoItem label="Confidence" value={`${Math.round(telemetry.confidence_score * 100)}%`} />
            )}
            {typeof telemetry.high_value_target_count === 'number' && (
              <InfoItem label="High-Value Targets" value={String(telemetry.high_value_target_count)} />
            )}
            {typeof telemetry.retry_count === 'number' && (
              <InfoItem label="Retries" value={String(telemetry.retry_count)} />
            )}
            {typeof telemetry.failure_count === 'number' && (
              <InfoItem label="Failures Seen" value={String(telemetry.failure_count)} />
            )}
            {telemetry.targets && (
              <InfoItem
                label="Target State"
                value={`queued ${telemetry.targets.queued ?? 0} · scanning ${telemetry.targets.scanning ?? 0} · done ${telemetry.targets.done ?? 0}`}
              />
            )}
            {telemetry.drop_off && (
              <InfoItem
                label="Drop-Off"
                value={`input ${telemetry.drop_off.input} · kept ${telemetry.drop_off.kept} · dropped ${telemetry.drop_off.dropped}`}
              />
            )}
            {telemetry.deduplication && (
              <InfoItem
                label="Dedup"
                value={`removed ${telemetry.deduplication.removed} · remaining ${telemetry.deduplication.remaining}`}
              />
            )}
            {telemetry.bottleneck_stage && (
              <InfoItem
                label="Bottleneck"
                value={`${telemetry.bottleneck_stage}${typeof telemetry.bottleneck_seconds === 'number' ? ` (${Math.round(telemetry.bottleneck_seconds)}s)` : ''}`}
              />
            )}
            {telemetry.next_best_action && (
              <InfoItem label="Next Best Action" value={telemetry.next_best_action} />
            )}
          </div>
          {telemetry.top_active_targets && telemetry.top_active_targets.length > 0 && (
            <div className="modules-list">
              {telemetry.top_active_targets.map((item) => (
                <span key={item} className="module-tag">{item}</span>
              ))}
            </div>
          )}
          {telemetry.event_triggers && telemetry.event_triggers.length > 0 && (
            <ul className="warnings-list">
              {telemetry.event_triggers.slice(-5).map((trigger) => (
                <li key={trigger}>{trigger}</li>
              ))}
            </ul>
          )}
        </div>
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

      {streamingFindings.length > 0 && job.status === 'running' && (
        <div className="card">
          <h3>Findings Discovered ({streamingFindings.length})</h3>
          <div className="streaming-findings">
            {streamingFindings.slice(-5).reverse().map((f) => (
              <div key={f.id || `${f.type}-${f.target}`} className={`finding-min-card sev-${f.severity}`}>
                <span className="sev-badge">{f.severity}</span>
                <span className="finding-min-title">{f.type || 'Unknown'}</span>
                <span className="finding-min-target">{f.target || f.url?.substring(0, 50) || ''}</span>
              </div>
            ))}
          </div>
          <Link to="/findings" className="view-all-findings-link">View all findings</Link>
        </div>
      )}

      {job.status === 'completed' && <ScanSummaryCard job={job} />}

      {job.enabled_modules && job.enabled_modules.length > 0 && (
        <div className="card">
          <h3>Enabled Modules</h3>
          <div className="modules-list">
            {job.enabled_modules.map((mod) => (
              <span key={mod} className="module-tag">{mod}</span>
            ))}
          </div>
        </div>
      )}

      {job.per_module_stats && Object.keys(job.per_module_stats).length > 0 && (
        <ModulePerformanceChart
          data={Object.entries(job.per_module_stats).map(([module, stats]) => ({
            module,
            duration: stats.duration_sec ?? 0,
            findings: stats.findings_count ?? 0,
          }))}
        />
      )}

      {job.error && (
        <div className="card error-card">
          <h3>Error</h3>
          <pre className="error-text">{job.error}</pre>
        </div>
      )}

      {job.warnings && job.warnings.length > 0 && (
        <div className="card warning-card">
          <h3>Warnings ({job.warnings.length})</h3>
          <ul className="warnings-list">
            {job.warnings.map((w) => (
              <li key={w.substring(0, 40)}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <JobLogViewer
        displayLines={displayLines}
        wsFailed={wsFailed}
        jobStatus={job.status}
      />

      <div className="card">
        <h3>Job Timeline</h3>
        <JobTimelineComponent jobId={jobId || ''} />
      </div>

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
        <div className="trace-side-panel" role="dialog" aria-modal="false" aria-label="Jaeger trace">
          <div className="trace-side-panel-header">
            <div>
              <h3>Jaeger Trace</h3>
              <span>{tracePanel.mode === 'trace' ? tracePanel.trace_id : `Search for ${tracePanel.job_id}`}</span>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setTracePanel(null)} aria-label="Close trace panel">
              <X size={16} aria-hidden="true" />
            </button>
          </div>
          <iframe title="Jaeger trace" src={tracePanel.trace_url} />
          <a className="file-link" href={tracePanel.trace_url} target="_blank" rel="noopener noreferrer">
            Open in Jaeger
          </a>
        </div>
      )}
      </div>
    </VisualProvider>
  );
}

function InfoItem({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="info-item">
      <span className="info-label">{label}:</span>
      <span className="info-value">{value}</span>
    </div>
  );
}

function formatDurationLabel(seconds: number): string {
  const roundedSeconds = Math.max(0, Math.round(seconds));
  const minutes = Math.floor(roundedSeconds / 60);
  const remainingSeconds = roundedSeconds % 60;

  if (minutes === 0) {
    return `${roundedSeconds}s`;
  }

  if (remainingSeconds === 0) {
    return `${minutes}m`;
  }

  return `${minutes}m ${remainingSeconds}s`;
}
