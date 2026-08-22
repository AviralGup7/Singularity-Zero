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

type WorkerListener = (event: MessageEvent) => void;

/**
 * Shared Web Worker instance — created once at module level and reused
 * across all mounts of useProcessedFindings. Messages fan out to every
 * subscriber so the last mount cannot steal PROCESS_COMPLETE events.
 */
let sharedWorker: Worker | null = null;
let sharedWorkerRefCount = 0;
const workerListeners = new Set<WorkerListener>();
let nextRequestId = 1;

function dispatchWorkerMessage(event: MessageEvent): void {
  workerListeners.forEach((fn) => fn(event));
}

function dispatchWorkerError(): void {
  workerListeners.forEach((fn) => {
    fn({ data: { type: 'PROCESS_ERROR', error: 'Findings worker failed' } } as MessageEvent);
  });
}

function getSharedWorker(): Worker {
  if (!sharedWorker) {
    sharedWorker = new Worker(
      new URL('../workers/findingsProcessor.ts', import.meta.url),
      { type: 'module' }
    );
    sharedWorker.onmessage = dispatchWorkerMessage;
    sharedWorker.onerror = dispatchWorkerError;
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
    workerListeners.clear();
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
    const requestId = nextRequestId++;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsProcessing(true);

    const onMessage = (event: MessageEvent) => {
      if (!isCurrent) return;
      if (event.data?.requestId != null && event.data.requestId !== requestId) return;
      if (event.data?.type === 'PROCESS_COMPLETE') {
        setProcessed(event.data.result);
        setIsProcessing(false);
        return;
      }
      if (event.data?.type === 'PROCESS_ERROR') {
        setIsProcessing(false);
      }
    };
    workerListeners.add(onMessage);

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
      sort,
      requestId,
    });

    if (rawChanged) {
      lastRawFindingsRef.current = rawFindings;
    }

    return () => {
      isCurrent = false;
      workerListeners.delete(onMessage);
    };
  }, [rawFindings, filters, sort]);

  return { processed, isProcessing };
}
