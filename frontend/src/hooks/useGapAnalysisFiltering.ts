import { useState, useMemo } from 'react';
import type { DetectionGapResponse } from '@/types/api';

export type StatusFilter = 'all' | 'complete' | 'partial' | 'missing';

export function useGapAnalysisFiltering(data: DetectionGapResponse | null) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    if (!data || !data.results) return [];

    let result = [...data.results].filter(
      (r) => r && typeof r === 'object' && typeof r.module === 'string' && typeof r.status === 'string'
    );

    if (statusFilter !== 'all') {
      result = result.filter((r) => r.status === statusFilter);
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (r) =>
          (r.module || '').toLowerCase().includes(q) ||
          (r.category || '').toLowerCase().includes(q)
      );
    }

    return result;
  }, [data, statusFilter, searchQuery]);

  const toggleExpand = (module: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(module)) next.delete(module);
      else next.add(module);
      return next;
    });
  };

  return {
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
    expandedRows,
    toggleExpand,
    filtered,
  };
}
