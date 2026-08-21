export interface ActiveScanSnapshot {
  jobId: string;
  targetName: string;
  progress: number;
  status: string;
  etaLabel: string;
  findingsCount: number;
  urlsFound: number;
}

export function mergePolledScanState(
  prev: ActiveScanSnapshot | null,
  next: ActiveScanSnapshot | null,
): ActiveScanSnapshot | null {
  if (!next) return null;
  if (!prev || prev.jobId !== next.jobId) return next;
  return {
    ...next,
    progress: Math.max(prev.progress ?? 0, next.progress ?? 0),
    findingsCount: Math.max(prev.findingsCount ?? 0, next.findingsCount ?? 0),
    urlsFound: Math.max(prev.urlsFound ?? 0, next.urlsFound ?? 0),
    status: next.status || prev.status,
  };
}

export function applyLiveScanEvent(
  prev: ActiveScanSnapshot | null,
  jobId: string | undefined,
  patch: Partial<ActiveScanSnapshot>,
): ActiveScanSnapshot | null {
  if (!prev) return prev;
  if (jobId && prev.jobId !== jobId) return prev;
  return {
    ...prev,
    progress: patch.progress ?? prev.progress,
    status: patch.status || prev.status,
    findingsCount: patch.findingsCount ?? prev.findingsCount,
    urlsFound: patch.urlsFound ?? prev.urlsFound,
  };
}
