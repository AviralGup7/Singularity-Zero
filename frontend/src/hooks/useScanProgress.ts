import { useState, useCallback, useMemo } from 'react';

export function clampScanProgress(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

export type ScanProgressStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface ScanProgress {
  targetName: string;
  jobId: string;
  status: ScanProgressStatus;
  progress: number;
}

export function useScanProgress() {
  const [scanProgress, setScanProgress] = useState(new Map<string, ScanProgress>());
  const [isScanning, setIsScanning] = useState(false);

  const updateProgress = useCallback((targetName: string, update: Partial<Omit<ScanProgress, 'targetName'>>) => {
    setScanProgress((prev) => {
      const next = new Map(prev);
      const current = next.get(targetName) || { targetName, jobId: '', status: 'pending' as const, progress: 0 };
      const merged = { ...current, ...update };
      next.set(targetName, { ...merged, progress: clampScanProgress(merged.progress) });
      return next;
    });
  }, []);

  const startScan = useCallback((targetNames: string[]) => {
    const progress = new Map<string, ScanProgress>();
    targetNames.forEach((name) => {
      progress.set(name, { targetName: name, jobId: '', status: 'pending' as const, progress: 0 });
    });
    setScanProgress(progress);
    setIsScanning(true);
  }, []);

  const completeScan = useCallback(() => {
    setScanProgress(new Map());
    setIsScanning(false);
  }, []);

  const progressList = useMemo(() => Array.from(scanProgress.values()), [scanProgress]);

  return {
    scanProgress,
    isScanning,
    progressList,
    updateProgress,
    startScan,
    completeScan,
    setScanProgress,
    setIsScanning,
  };
}
