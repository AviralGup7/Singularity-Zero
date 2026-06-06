import { useState, useMemo, useCallback, useEffect } from 'react';
import type { Target } from '@/types/api';

export interface TargetFilters {
  severities: Set<string>;
  status: 'all' | 'active' | 'inactive';
  minFindings: number;
  maxFindings: number;
  lastScanAfter: string;
  lastScanBefore: string;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function emptyFilters(): TargetFilters {
  return {
    severities: new Set(),
    status: 'all',
    minFindings: 0,
    maxFindings: Infinity,
    lastScanAfter: '',
    lastScanBefore: '',
  };
}

export function hasActiveFilters(f: TargetFilters): boolean {
  return (
    f.severities.size > 0 ||
    f.status !== 'all' ||
    f.minFindings > 0 ||
    f.maxFindings !== Infinity ||
    f.lastScanAfter !== '' ||
    f.lastScanBefore !== ''
  );
}

export function targetHasSeverity(t: Target, severities: Set<string>): boolean {
  if (severities.size === 0) return true;
  for (const sev of severities) {
    if (Number(Reflect.get(t.severity_counts || {}, sev) ?? 0) > 0) return true;
  }
  return false;
}

export function targetIsActive(t: Target): boolean {
  return t.latest_run !== '' && t.latest_run !== '—';
}

export function useTargetFilters() {
  const [filters, setFilters] = useState<TargetFilters>(emptyFilters());
  const [showFilters, setShowFilters] = useState(false);

  const toggleSeverity = useCallback((sev: string) => {
    setFilters((prev) => {
      const next = new Set(prev.severities);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return { ...prev, severities: next };
    });
  }, []);

  const clearAllFilters = useCallback(() => {
    setFilters(emptyFilters());
  }, []);

  const activeFilterChips: { label: string; onRemove: () => void }[] = [];

  filters.severities.forEach((sev) => {
    activeFilterChips.push({
      label: `Severity: ${sev}`,
      onRemove: () => toggleSeverity(sev),
    });
  });

  if (filters.status !== 'all') {
    activeFilterChips.push({
      label: `Status: ${filters.status}`,
      onRemove: () => setFilters((prev) => ({ ...prev, status: 'all' })),
    });
  }

  if (filters.minFindings > 0) {
    activeFilterChips.push({
      label: `Min findings: ${filters.minFindings}`,
      onRemove: () => setFilters((prev) => ({ ...prev, minFindings: 0 })),
    });
  }

  if (filters.maxFindings !== Infinity) {
    activeFilterChips.push({
      label: `Max findings: ${filters.maxFindings}`,
      onRemove: () => setFilters((prev) => ({ ...prev, maxFindings: Infinity })),
    });
  }

  if (filters.lastScanAfter) {
    activeFilterChips.push({
      label: `Scanned after: ${filters.lastScanAfter}`,
      onRemove: () => setFilters((prev) => ({ ...prev, lastScanAfter: '' })),
    });
  }

  if (filters.lastScanBefore) {
    activeFilterChips.push({
      label: `Scanned before: ${filters.lastScanBefore}`,
      onRemove: () => setFilters((prev) => ({ ...prev, lastScanBefore: '' })),
    });
  }

  return {
    filters,
    setFilters,
    showFilters,
    setShowFilters,
    toggleSeverity,
    clearAllFilters,
    activeFilterChips,
  };
}

export function useFilteredTargets(targets: Target[], filters: TargetFilters, searchQuery: string) {
  return useMemo(() => {
    return targets.filter((t) => {
      if (
        searchQuery &&
        !(t.name || '').toLowerCase().includes(searchQuery.toLowerCase()) &&
        !(t.top_finding_title || '').toLowerCase().includes(searchQuery.toLowerCase())
      ) {
        return false;
      }

      if (!targetHasSeverity(t, filters.severities)) return false;

      if (filters.status === 'active' && !targetIsActive(t)) return false;
      if (filters.status === 'inactive' && targetIsActive(t)) return false;

      if ((t.finding_count ?? 0) < filters.minFindings) return false;
      if ((t.finding_count ?? 0) > filters.maxFindings) return false;

      if (filters.lastScanAfter && t.latest_generated_at) {
        if (new Date(t.latest_generated_at) < new Date(filters.lastScanAfter)) return false;
      }
      if (filters.lastScanBefore && t.latest_generated_at) {
        if (new Date(t.latest_generated_at) > new Date(filters.lastScanBefore)) return false;
      }

      return true;
    });
  }, [targets, filters, searchQuery]);
}
