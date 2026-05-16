import { useMemo } from 'react';
import { useApi } from './useApi';
import type { RiskFactorsResponse, RiskHistoryEntry } from '@/types/extended';

export interface RiskHistoryFilters {
  days: number;
  targetIds?: string[];
  startDate?: string;
  endDate?: string;
}

function toDay(value: string): string {
  return value.slice(0, 10);
}

export function useRiskHistory(filters: RiskHistoryFilters) {
  const history = useApi<RiskHistoryEntry[]>('/api/risk/history', {
    params: { days: filters.days, group_by: 'target' },
  });
  const factors = useApi<RiskFactorsResponse>('/api/risk/factors');

  const filteredHistory = useMemo(() => {
    const selected = new Set(filters.targetIds ?? []);
    return (history.data ?? []).filter((entry) => {
      if (selected.size > 0 && !selected.has(entry.target_id)) return false;
      const day = toDay(entry.timestamp);
      if (filters.startDate && day < filters.startDate) return false;
      if (filters.endDate && day > filters.endDate) return false;
      return true;
    });
   
  }, [history.data, filters.endDate, filters.startDate, filters.targetIds]);

  return {
    history: filteredHistory,
    factors: factors.data,
    loading: history.loading || factors.loading,
    error: history.error ?? factors.error,
    refetch: history.refetch,
  };
}

   
export function buildRiskDateColumns(history: RiskHistoryEntry[]): string[] {
  return Array.from(new Set(history.map((entry) => toDay(entry.timestamp)))).sort();
}
