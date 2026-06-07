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

export function useProcessedFindings(
  rawFindings: Finding[],
  filters: FilterOptions,
  sort: SortOptions
) {
   
  const [processed, setProcessed] = useState<Finding[]>(rawFindings);
   
  const [isProcessing, setIsProcessing] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    // Vite-specific worker initialization
    workerRef.current = new Worker(
      new URL('../workers/findingsProcessor.ts', import.meta.url),
      { type: 'module' }
    );

    return () => {
      workerRef.current?.terminate();
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
        const f = rawFindings[i];
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
