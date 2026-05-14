/**
 * High-Performance Findings Processor Web Worker
 * Handles heavy sorting, filtering, and deduplication off the main UI thread.
 */

import type { Finding } from '../types/api';

interface ProcessRequest {
  type: 'PROCESS_FINDINGS';
  findings: Finding[];
  filters: {
    severity?: string[];
    search?: string;
    target?: string;
  };
  sort: {
    key: keyof Finding;
    direction: 'asc' | 'desc';
  };
}

self.onmessage = (event: MessageEvent<ProcessRequest>) => {
  try {
    const { type, findings, filters, sort } = event.data;

    if (type === 'PROCESS_FINDINGS') {
      let result = [...findings];

      // 1. Filtering
      if (filters.severity && filters.severity.length > 0) {
        result = result.filter(f => filters.severity!.includes(f.severity));
      }

      if (filters.target) {
        result = result.filter(f => f.target === filters.target);
      }

      if (filters.search) {
        const q = filters.search.toLowerCase();
        result = result.filter(f => 
          f.title.toLowerCase().includes(q) || 
          f.type.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.url?.toLowerCase().includes(q)
        );
      }

      // 2. Deduplication (Use finding ID for accurate identity)
      const seen = new Set<string>();
      result = result.filter(f => {
        if (seen.has(f.id)) return false;
        seen.add(f.id);
        return true;
      });

      // 3. Sorting (Combined pass for efficiency)
      const severityWeights = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      
      result.sort((a, b) => {
        if (sort.key === 'severity') {
          const wA = severityWeights[a.severity] ?? 0;
          const wB = severityWeights[b.severity] ?? 0;
          if (wA !== wB) return sort.direction === 'asc' ? wA - wB : wB - wA;
        }
        
        const valA = a[sort.key] ?? '';
        const valB = b[sort.key] ?? '';
        
        if (valA < valB) return sort.direction === 'asc' ? -1 : 1;
        if (valA > valB) return sort.direction === 'asc' ? 1 : -1;
        return 0;
      });

      self.postMessage({ type: 'PROCESS_COMPLETE', result });
    }
  } catch (error) {
    self.postMessage({ 
      type: 'PROCESS_ERROR', 
      error: error instanceof Error ? error.message : String(error)
    });
  }
};
