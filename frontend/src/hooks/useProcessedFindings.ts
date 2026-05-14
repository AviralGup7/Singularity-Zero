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
  const [processed, setProcessed] = useState<Finding[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    // Vite-specific worker initialization
    workerRef.current = new Worker(
      new URL('../workers/findingsProcessor.ts', import.meta.url),
      { type: 'module' }
    );

    workerRef.current.onmessage = (event) => {
      if (event.data.type === 'PROCESS_COMPLETE') {
        setProcessed(event.data.result);
        setIsProcessing(false);
      }
    };

    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  useEffect(() => {
    if (!workerRef.current) return;

    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsProcessing(true);
    workerRef.current.postMessage({
      type: 'PROCESS_FINDINGS',
      findings: rawFindings,
      filters,
      sort
    });
  }, [rawFindings, filters, sort]);

  return { processed, isProcessing };
}
