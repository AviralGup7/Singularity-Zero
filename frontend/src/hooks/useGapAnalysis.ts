import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import type { DetectionGapResponse, GapAnalysisResult } from '@/types/api';
import { getGapAnalysis, refreshGapAnalysis, getTargets } from '@/api/client';

export type StatusFilter = 'all' | 'complete' | 'partial' | 'missing';

export function useGapAnalysis() {
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [data, setData] = useState<DetectionGapResponse | null>(null);
  const [targets, setTargets] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async (targetVal?: string) => {
    setLoading(true);
    setError(null);
    try {
      const targetsRes = await getTargets();
      const targetNames = (targetsRes.targets || []).map(t => t.name || '');
      setTargets(targetNames);

      const targetToFetch = targetVal !== undefined ? targetVal : selectedTarget;
      const res = await getGapAnalysis(targetToFetch || null);
      setData(res);
    } catch (err) {
      setError('Failed to load gap analysis data');
    } finally {
      setLoading(false);
    }
  }, [selectedTarget]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refreshGapAnalysis();
      await loadData();
    } catch (err) {
      setError((err as Error).message || 'Failed to refresh');
    } finally {
      setRefreshing(false);
    }
  }, [loadData]);

  useEffect(() => {
    loadData();
  }, [selectedTarget]);

  return {
    data,
    targets,
    selectedTarget,
    setSelectedTarget,
    loading,
    refreshing,
    error,
    loadData,
    handleRefresh,
  };
}

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
  filtered: GapAnalysisResult[];
}

export function useGapAnalysisFiltering({ filtered }: UseGapAnalysisFilteringProps) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    debounceTimerRef.current = setTimeout(() => {
      setDebouncedSearchQuery(searchQuery);
    }, 300);
    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
  }, [searchQuery]);

  const filteredAndSearched = useMemo(() => {
    let result = [...filtered];
    if (statusFilter !== 'all') {
      result = result.filter((r) => r.status === statusFilter);
    }
    if (debouncedSearchQuery) {
      const q = debouncedSearchQuery.toLowerCase();
      result = result.filter(
        (r) =>
          (r.module || '').toLowerCase().includes(q) ||
          (r.category || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [filtered, statusFilter, debouncedSearchQuery]);

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
