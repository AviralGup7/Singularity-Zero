import { memo } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ExternalLink } from 'lucide-react';
import { InfoItem } from '@/components/jobs/JobInfoItem';
import { RemediationSuggestions } from '@/components/findings/RemediationSuggestions';
import type { RemediationSuggestion } from '@/types/api';

interface JobFailureCardProps {
  job: {
    status: string;
    failed_stage?: string;
    failure_reason_code?: string;
    failure_step?: string;
    failure_reason?: string;
    error?: string | null;
  };
  sseError: string | null;
  remediation: RemediationSuggestion[];
  remediationLoading: boolean;
  onOpenTrace: () => void;
  traceLoading: boolean;
}

function JobFailureCardBase({ job, sseError, remediation, remediationLoading, onOpenTrace, traceLoading }: JobFailureCardProps) {
  if (job.status !== 'failed' && job.status !== 'stopped') return null;

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        className="card error-card"
        role="alert"
      >
        <h3>Job Failure Details</h3>
        {job.failure_reason_code === 'circuit_breaker_open' ? (
          <div className="flex items-start gap-3 p-3 rounded-lg" style={{ background: 'var(--warning-bg, rgba(234, 179, 8, 0.08))' }}>
            <span className="text-lg" aria-hidden="true">⚡</span>
            <div>
              <p className="font-medium text-sm" style={{ color: 'var(--warning-text, #eab308)' }}>
                Stage Skipped: Circuit Breaker Open
              </p>
              <p className="text-xs text-[var(--text-secondary)] mt-1">
                The <strong>{job.failed_stage || 'tool'}</strong> stage was skipped because its circuit breaker is open
                due to repeated failures. The tool may be temporarily unavailable or misconfigured.
              </p>
              <p className="text-xs text-[var(--text-tertiary)] mt-2">
                Visit <Link to="/self-healing" className="underline">Self-Healing</Link> to reset the circuit breaker
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
            {(job.failure_reason || job.error || sseError) && (
              <pre className="error-text mt-4">{job.failure_reason || job.error || sseError}</pre>
            )}
          </>
        )}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="trace-actions-header flex items-center justify-between gap-4">
          <h3>Debug Actions</h3>
          <button className="btn btn-secondary btn-sm flex items-center gap-1.5" onClick={onOpenTrace} disabled={traceLoading}>
            <ExternalLink size={14} aria-hidden="true" />
            <span>{traceLoading ? 'Opening...' : 'Open Jaeger Trace'}</span>
          </button>
        </div>
        <RemediationSuggestions suggestions={remediation} loading={remediationLoading} />
      </motion.div>
    </>
  );
}

export const JobFailureCard = memo(JobFailureCardBase);
