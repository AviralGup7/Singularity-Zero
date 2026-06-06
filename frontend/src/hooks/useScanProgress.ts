import { useMemo } from 'react';

export function useScanProgress() {
  const [scanProgress, setScanProgress] = useState(new Map<string, { targetName: string; jobId: string; status: string; progress: number }>());
  const [isScanning, setIsScanning] = useState(false);

  const updateProgress = useCallback((targetName: string, update: Partial<{ jobId: string; status: string; progress: number }>) => {
    setScanProgress((prev) => {
      const next = new Map(prev);
      const current = next.get(targetName) || { targetName, jobId: '', status: 'pending', progress: 0 };
      next.set(targetName, { ...current, ...update });
      return next;
    });
  }, []);

  const startScan = useCallback((targetNames: string[]) => {
    const progress = new Map<string, { targetName: string; jobId: string; status: string; progress: number }>();
    targetNames.forEach((name) => {
      progress.set(name, { targetName: name, jobId: '', status: 'pending', progress: 0 });
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
