import { useEffect, useState, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuthStore } from '@/stores/authStore';
import { useApi } from '@/hooks/useApi';
import { useRealtimeStream } from '@/hooks/useRealtimeStream';
import { applyLiveScanEvent, mergePolledScanState } from '@/components/scanStatusMerge';
import type { Job } from '@/types/api';

interface ActiveScanState {
  jobId: string;
  targetName: string;
  progress: number;
  status: string;
  etaLabel: string;
  findingsCount: number;
  urlsFound: number;
}

export function ScanStatusBar() {
  const location = useLocation();
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const { data: jobsResponse } = useApi<{ jobs: Job[]; total: number }>('/api/jobs', {
    refetchInterval: 5000,
    enabled: !!user,
  });
  const [activeScan, setActiveScan] = useState<ActiveScanState | null>(null);
  const runningJobId = (jobsResponse?.jobs ?? []).find((job) => job.status === 'running')?.id;

  useRealtimeStream({
    resourceId: runningJobId,
    enabled: Boolean(runningJobId),
    transport: 'sse',
    sseEndpoint: 'progress',
    onEvent: (event) => {
      const data = (event.data ?? {}) as Record<string, unknown>;
      const progress = typeof data.progress === 'number'
        ? data.progress
        : typeof data.progress_percent === 'number'
          ? data.progress_percent
          : undefined;
      const status = typeof data.message === 'string'
        ? data.message
        : typeof data.stage === 'string'
          ? data.stage
          : event.type;
      const findingsCount = typeof data.finding_count === 'number'
        ? data.finding_count
        : typeof data.findings_count === 'number'
          ? data.findings_count
          : undefined;
      const urlsFound = typeof data.urls_found === 'number'
        ? data.urls_found
        : typeof data.stage_processed === 'number'
          ? data.stage_processed
          : undefined;
      setActiveScan((prev) => applyLiveScanEvent(prev, runningJobId, {
        progress,
        status,
        findingsCount,
        urlsFound,
      }));
    },
  });

  useEffect(() => {
    const running = (jobsResponse?.jobs ?? []).find(j => j.status === 'running');
    if (running) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActiveScan((prev) => mergePolledScanState(prev, {
        jobId: running.id,
        targetName: running.target_name,
        progress: running.progress_percent,
        status: running.stage_label || 'Scanning',
        etaLabel: running.eta_label || '',
        findingsCount: running.findings_count ?? 0,
        urlsFound: running.stage_processed ?? 0,
      }));
    } else {
      setActiveScan(null);
    }
  }, [jobsResponse]);

  const isOnCockpit = location.pathname === '/cockpit';

  const handleClick = useCallback(() => {
    if (!isOnCockpit && activeScan) {
      const url = `/cockpit?job_id=${activeScan.jobId}&target=${encodeURIComponent(activeScan.targetName)}`;
      navigate(url);
    }
  }, [activeScan, isOnCockpit, navigate]);

  if (!activeScan) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ y: 50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: 50, opacity: 0 }}
        className="fixed bottom-0 left-0 right-0 z-40 border-t border-accent/20 bg-panel backdrop-blur-xl"
        role="region"
        aria-label={`Active scan: ${activeScan.targetName}`}
        aria-live="polite"
      >
        <button
          type="button"
          onClick={handleClick}
          className={`w-full px-6 py-2 flex items-center gap-6 text-xs font-mono ${!isOnCockpit ? 'cursor-pointer hover:bg-accent/5 transition-colors' : 'cursor-default'}`}
          aria-label={`Scan in progress: ${activeScan.targetName}, ${Math.round(activeScan.progress)}%, ${activeScan.status}${activeScan.etaLabel ? `, ETA ${activeScan.etaLabel}` : ''}`}
          disabled={isOnCockpit}
        >
          <div className="flex items-center gap-2 shrink-0">
            <span className="relative flex h-2 w-2" aria-hidden="true">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-accent" />
            </span>
            <span className="font-bold text-accent uppercase tracking-wider">
              {activeScan.targetName}
            </span>
          </div>

          <div className="flex-1 flex items-center gap-4">
            <div className="flex-1 max-w-xs">
              <div
                className="h-1.5 bg-surface-2 rounded-full overflow-hidden"
                role="progressbar"
                aria-valuenow={Math.round(activeScan.progress)}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={`Scan progress: ${Math.round(activeScan.progress)}%`}
              >
                <motion.div
                  className="h-full bg-accent rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${activeScan.progress}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
            <span className="text-muted font-semibold tabular-nums w-12">
              {Math.round(activeScan.progress)}%
            </span>
            <span className="text-muted/70">{activeScan.status}</span>
            {activeScan.etaLabel && (
              <span className="text-accent/80 font-semibold tabular-nums">ETA {activeScan.etaLabel}</span>
            )}
          </div>

          <div className="flex items-center gap-4 shrink-0 text-muted/70">
            <span className="tabular-nums">{activeScan.findingsCount} findings</span>
            <span className="tabular-nums">{activeScan.urlsFound} URLs</span>
          </div>

          {!isOnCockpit && (
            <span className="text-accent/60 text-[10px] uppercase tracking-wider shrink-0" aria-hidden="true">
              Click to open Cockpit
            </span>
          )}
        </button>
      </motion.div>
    </AnimatePresence>
  );
}
