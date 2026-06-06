import { useState, useMemo, useCallback } from 'react';
import { useApi } from '@/hooks/useApi';
import { useToast } from '@/hooks/useToast';
import type { TargetFilters } from '@/hooks/useTargetFilters';

export interface TargetsResponse {
  targets: Target[];
}

export function useTargets() {
  const { data, loading, error, refetch } = useApi<TargetsResponse>('/api/targets');
  const toast = useToast();

  const [filter, setFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [filters, setFilters] = useState<TargetFilters>(emptyFilters());
  const [selectedTargets, setSelectedTargets] = useState(new Set<string>());
  const [isScanning, setIsScanning] = useState(false);

  const toggleSeverity = useCallback((sev: string) => {
    setFilters((prev) => {
      const next = new Set(prev.severities);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return { ...prev, severities: next };
    });
    setCurrentPage(1);
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters(emptyFilters());
    setCurrentPage(1);
  }, []);

  const toggleTargetSelection = useCallback((name: string) => {
    setSelectedTargets((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedTargets(new Set());
  }, []);

  return {
    data,
    loading,
    error,
    refetch,
    filter,
    setFilter,
    currentPage,
    setCurrentPage,
    filters,
    setFilters,
    selectedTargets,
    setSelectedTargets,
    isScanning,
    setIsScanning,
    toggleSeverity,
    clearAllFilters,
    toggleTargetSelection,
    clearSelection,
  };
}
