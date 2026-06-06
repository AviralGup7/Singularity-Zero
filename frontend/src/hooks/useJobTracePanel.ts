import { useState, useCallback, useEffect } from 'react';
import type { RemediationSuggestion, TraceLink } from '@/types/api';
import { getJobRemediation, getJobTraceLink } from '@/api/jobs';

export function useJobRemediation(jobId: string | undefined, isFailedJob: boolean) {
  const [remediation, setRemediation] = useState<RemediationSuggestion[]>([]);
  const [remediationLoading, setRemediationLoading] = useState(false);

  useEffect(() => {
    if (!jobId || !isFailedJob) {
      setRemediation([]);
      return;
    }
    const controller = new AbortController();
    const tid = setTimeout(() => setRemediationLoading(true), 0);
    getJobRemediation(jobId, controller.signal)
      .then((response) => setRemediation(response.suggestions ?? []))
      .catch(() => setRemediation([]))
      .finally(() => {
        clearTimeout(tid);
        setRemediationLoading(false);
      });
    return () => {
      controller.abort();
      clearTimeout(tid);
    };
  }, [jobId, isFailedJob]);

  return { remediation, remediationLoading };
}

export function useJobTracePanel(jobId: string | undefined) {
  const [tracePanel, setTracePanel] = useState<TraceLink | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);

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

  return { tracePanel, setTracePanel, traceLoading, openTracePanel };
}
