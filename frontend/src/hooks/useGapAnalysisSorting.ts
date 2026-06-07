import { useState } from 'react';
import type { DetectionGapResponse } from '@/types/api';

export function useGapAnalysisSorting() {
  const [sortKey, setSortKey] = useState<'module' | 'coverage_percent' | 'status'>('module');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const handleSort = (key: 'module' | 'coverage_percent' | 'status') => {
    setSortDir((prev) => (sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'asc'));
    setSortKey(key);
  };

  const sortResults = (results: DetectionGapResponse['results']) => {
    const statusOrder = { complete: 0, partial: 1, missing: 2 };
    return [...results].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'module') cmp = (a.module || '').localeCompare(b.module || '');
      else if (sortKey === 'coverage_percent') cmp = (a.coverage_percent || 0) - (b.coverage_percent || 0);
      else if (sortKey === 'status') {
        const orderA = statusOrder[a.status as keyof typeof statusOrder] ?? 3;
        const orderB = statusOrder[b.status as keyof typeof statusOrder] ?? 3;
        cmp = orderA - orderB;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  };

  return { sortKey, sortDir, handleSort, sortResults };
}
