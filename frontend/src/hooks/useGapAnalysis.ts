import { useState, useMemo, useCallback } from 'react';
import type { DetectionGapResponse } from '@/types/api';

export type SortKey = 'module' | 'coverage_percent' | 'status';
export type SortDir = 'asc' | 'desc';

const STATUS_ORDER = { complete: 0, partial: 1, missing: 2 };

interface UseGapAnalysisSortingProps {
  data: DetectionGapResponse | null;
}

export function useGapAnalysisSorting({ data }: UseGapAnalysisSortingProps) {
  const [sortKey, setSortKey] = useState<SortKey>('module');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const handleSort = useCallback((key: SortKey) => {
    setSortDir((prev) => (sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'asc'));
    setSortKey(key);
  }, [sortKey]);

  const filtered = useMemo(() => {
    if (!data || !data.results) return [];
    return [...data.results]
      .filter((r) => r && typeof r === 'object' && typeof r.module === 'string' && typeof r.status === 'string')
      .sort((a, b) => {
        let cmp = 0;
        if (sortKey === 'module') cmp = (a.module || '').localeCompare(b.module || '');
        else if (sortKey === 'coverage_percent')
          cmp = (a.coverage_percent || 0) - (b.coverage_percent || 0);
        else if (sortKey === 'status') {
          const orderA = STATUS_ORDER[a.status as keyof typeof STATUS_ORDER] ?? 3;
          const orderB = STATUS_ORDER[b.status as keyof typeof STATUS_ORDER] ?? 3;
          cmp = orderA - orderB;
        }
        return sortDir === 'asc' ? cmp : -cmp;
      });
  }, [data, sortKey, sortDir]);

  return { filtered, sortKey, sortDir, handleSort };
}

interface UseGapAnalysisFilteringProps {
  filtered: { module: string; category: string; status: string }[];
}

export function useGapAnalysisFiltering({ filtered }: UseGapAnalysisFilteringProps) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const filteredAndSearched = useMemo(() => {
    let result = [...filtered];
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
  }, [filtered, statusFilter, searchQuery]);

  const toggleExpand = useCallback((module: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(module)) next.delete(module);
      else next.add(module);
      return next;
    });
  }, []);

  return {
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
    expandedRows,
    toggleExpand,
    filtered: filteredAndSearched,
  };
}
