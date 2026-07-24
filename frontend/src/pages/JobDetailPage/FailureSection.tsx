import { motion } from 'framer-motion';
import { ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';
import { InfoItem } from '@/components/jobs/JobInfoItem';
import { RemediationSuggestions } from '@/features/findings/components/RemediationSuggestions';
import { itemVariants } from './helpers';
import type { Job, RemediationSuggestion } from '@/types/api';

const CLASSIFICATION_LABELS: Record<string, string> = {
  oom_error: 'Out of memory (OOM) — the tool was killed by the OS due to insufficient memory',
  executable_not_found: 'Tool not found — the required executable is missing or not installed',
  permission_denied: 'Permission denied — the tool lacks execute permission',
  sigint_or_sigterm: 'Interrupted — the process was stopped by a signal (SIGINT/SIGTERM)',
};

interface FailureSectionProps {
  job: Job;
  sseError: string | null;
  remediation: RemediationSuggestion[];
  remediationLoading: boolean;
  traceLoading: boolean;
  onOpenTrace: () => void;
}

export function FailureSection({ job, sseError, remediation, remediationLoading, traceLoading, onOpenTrace }: FailureSectionProps) {
  return (
    <>
      <motion.div variants={itemVariants} className="card error-card" role="alert">
        <h3>Job Failure Details</h3>
        {job.failure_reason_code === 'circuit_breaker_open' ? (
          <div className="flex items-start gap-3 p-3 rounded-lg bg-warn/8">
            <span className="text-lg" aria-hidden="true">⚡</span>
            <div>
              <p className="font-medium text-sm text-warn">
                Stage Skipped: Circuit Breaker Open
              </p>
              <p className="text-xs text-text-secondary mt-1">
                The <strong>{job.failed_stage || 'tool'}</strong> stage was skipped because its circuit breaker is open
                due to repeated failures. The tool may be temporarily unavailable or misconfigured.
              </p>
              <p className="text-xs text-text-tertiary mt-2">
                 Visit <Link to="/security?tab=self-healing" className="underline focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none rounded" aria-label="Go to Self-Healing to reset circuit breaker">Self-Healing</Link> to reset the circuit breaker
                or check tool availability in Settings.
              </p>
            </div>
          </div>
        ) : (
          <>
            <div className="info-grid">
              {job.failed_stage && <InfoItem label="Stage" value={job.failed_stage} />}
              {job.failure_reason_code && <InfoItem label="Reason Code" value={job.failure_reason_code} />}
              {job.failure_step && <InfoItem label="Failure Step" value={job.failure_step} />}
            </div>
            {job.classification && (
              <div className="mt-3 p-3 rounded-lg bg-warn/8">
                <p className="font-medium text-sm text-warn">
                  {CLASSIFICATION_LABELS[job.classification] || job.classification}
                </p>
              </div>
            )}
            {(job.failure_reason || job.error || sseError) && (
              <pre className="error-text mt-4">{job.failure_reason || job.error || sseError}</pre>
            )}
          </>
        )}
      </motion.div>

      <motion.div variants={itemVariants} className="card">
        <div className="trace-actions-header flex items-center justify-between gap-4">
          <h3>Debug Actions</h3>
          <button className="btn btn-secondary btn-sm flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:outline-none" onClick={onOpenTrace} disabled={traceLoading}>
            <ExternalLink size={14} aria-hidden="true" />
            <span>{traceLoading ? 'Opening...' : 'Open Jaeger Trace'}</span>
          </button>
        </div>
        <RemediationSuggestions suggestions={remediation} loading={remediationLoading} />
      </motion.div>
    </>
  );
}
