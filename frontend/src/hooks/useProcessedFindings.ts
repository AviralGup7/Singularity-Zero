import { useState, useEffect, useRef } from 'react';
import type { Finding } from '../types/api';

interface FilterOptions {
  severity?: string[];
  search?: string;
  target?: string;
}

interface SortOptions {
  key: keyof Finding;
  direction: 'asc' | 'desc';
}

/**
 * Shared Web Worker instance — created once at module level and reused
 * across all mounts of useProcessedFindings. This prevents the
 * memory/CPU churn of creating and terminating a worker on every mount.
 */
let sharedWorker: Worker | null = null;
let sharedWorkerRefCount = 0;

function getSharedWorker(): Worker {
  if (!sharedWorker) {
    sharedWorker = new Worker(
      new URL('../workers/findingsProcessor.ts', import.meta.url),
      { type: 'module' }
    );
  }
  sharedWorkerRefCount++;
  return sharedWorker;
}

function releaseSharedWorker(): void {
  sharedWorkerRefCount--;
  if (sharedWorkerRefCount <= 0 && sharedWorker) {
    sharedWorker.terminate();
    sharedWorker = null;
    sharedWorkerRefCount = 0;
  }
}

export function useProcessedFindings(
  rawFindings: Finding[],
  filters: FilterOptions,
  sort: SortOptions
) {
  const [processed, setProcessed] = useState<Finding[]>(rawFindings);
  const [isProcessing, setIsProcessing] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    workerRef.current = getSharedWorker();
    return () => {
      releaseSharedWorker();
      workerRef.current = null;
    };
  }, []);

  const lastRawFindingsRef = useRef<Finding[]>([]);

  useEffect(() => {
    if (!workerRef.current) return;

    let isCurrent = true;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsProcessing(true);

    workerRef.current.onmessage = (event) => {
      if (isCurrent && event.data.type === 'PROCESS_COMPLETE') {
        setProcessed(event.data.result);
        setIsProcessing(false);
      }
    };

    const lastRaw = lastRawFindingsRef.current;
    let rawChanged = lastRaw.length !== rawFindings.length;
    if (!rawChanged) {
      for (let i = 0; i < rawFindings.length; i++) {
        // eslint-disable-next-line security/detect-object-injection
        const f = rawFindings[i];
        // eslint-disable-next-line security/detect-object-injection
        const prev = lastRaw[i];
        if (!f || !prev || f.id !== prev.id || f.timestamp !== prev.timestamp) {
          rawChanged = true;
          break;
        }
      }
    }

    workerRef.current.postMessage({
      type: 'PROCESS_FINDINGS',
      findings: rawChanged ? rawFindings : undefined,
      filters,
      sort
    });

    if (rawChanged) {
      lastRawFindingsRef.current = rawFindings;
    }

    return () => {
      isCurrent = false;
    };
  }, [rawFindings, filters, sort]);

  return { processed, isProcessing };
}
