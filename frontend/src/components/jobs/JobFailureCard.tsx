import { memo } from 'react';
import type { Job, RemediationSuggestion } from '@/types/api';
import { FailureSection } from '@/pages/JobDetailPage/FailureSection';

interface JobFailureCardProps {
  job: Job;
  sseError: string | null;
  remediation: RemediationSuggestion[];
  remediationLoading: boolean;
  onOpenTrace: () => void;
  traceLoading: boolean;
}

function JobFailureCardBase({ job, sseError, remediation, remediationLoading, onOpenTrace, traceLoading }: JobFailureCardProps) {
  if (job.status !== 'failed' && job.status !== 'stopped') return null;

  return (
    <FailureSection
      job={job}
      sseError={sseError}
      remediation={remediation}
      remediationLoading={remediationLoading}
      traceLoading={traceLoading}
      onOpenTrace={onOpenTrace}
    />
  );
}

export const JobFailureCard = memo(JobFailureCardBase);
