import { useState, useMemo, useCallback } from 'react';
import type { Finding } from '../../../types/api';

type SortKey = 'severity' | 'type' | 'target' | 'status' | 'date';
type SortDir = 'asc' | 'desc';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type StatusFilter = 'all' | 'open' | 'closed' | 'accepted';
type ViewMode = 'table' | 'kanban';
type KanbanColumn = 'new' | 'in-progress' | 'resolved';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const PAGE_SIZE = 20;

function computeDuplicateKey(f: Finding): string {
  const evStr = typeof f.evidence === 'string' ? f.evidence : '';
  return `${f.type}::${f.target}::${evStr.substring(0, 50).toLowerCase()}`;
}

interface UseFindingsTableInput {
  findings: Finding[];
}

export function useFindingsTable({ findings }: UseFindingsTableInput) {
   
  const [sortKey, setSortKey] = useState<SortKey>('severity');
   
  const [sortDir, setSortDir] = useState<SortDir>('desc');
   
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
   
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
   
  const [targetFilter, setTargetFilter] = useState('');
   
  const [searchQuery, setSearchQuery] = useState('');
   
  const [page, setPage] = useState(1);
   
  const [viewMode, setViewMode] = useState<ViewMode>('table');
   
  const [expandedDuplicates, setExpandedDuplicates] = useState<Set<string>>(new Set());
  const pageSize = PAGE_SIZE;

  const handleSort = useCallback((key: SortKey) => {
    setSortDir(prev => sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'asc');
    setSortKey(key);
   
  }, [sortKey]);

  const dedupMap = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = computeDuplicateKey(f);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(f);
    }
    return map;
   
  }, [findings]);

  const primaryFindings = useMemo(() => {
    const seen = new Set<string>();
   
    const primaries: Finding[] = [];
    for (const f of findings) {
      const key = computeDuplicateKey(f);
      if (!seen.has(key)) {
        seen.add(key);
        const group = dedupMap.get(key) || [];
        const duplicates = group.filter(d => d.id !== f.id).map(d => d.id);
        if (duplicates.length > 0) {
          primaries.push({ ...f, duplicates });
        } else {
          primaries.push(f);
        }
      }
    }
    return primaries;
   
  }, [findings, dedupMap]);

  const filtered = useMemo(() => {
   
    let result = [...primaryFindings];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(f =>
        (f.id || '').toLowerCase().includes(q) ||
        (f.type || '').toLowerCase().includes(q) ||
        (f.target || '').toLowerCase().includes(q) ||
        (f.url || '').toLowerCase().includes(q) ||
        (f.severity || '').toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q) ||
        (f.status || '').toLowerCase().includes(q)
      );
    }
    if (severityFilter !== 'all') result = result.filter(f => f.severity === severityFilter);
    if (statusFilter !== 'all') result = result.filter(f => f.status === statusFilter);
    if (targetFilter) result = result.filter(f => f.target?.toLowerCase().includes(targetFilter.toLowerCase()));
    result.sort((a, b) => {
      let cmp = 0;
   
      if (sortKey === 'severity') cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
      else if (sortKey === 'type') cmp = (a.type || '').localeCompare(b.type || '');
      else if (sortKey === 'target') cmp = (a.target || '').localeCompare(b.target || '');
      else if (sortKey === 'status') cmp = (a.status || '').localeCompare(b.status || '');
      else if (sortKey === 'date') {
        const timeA = typeof a.timestamp === 'number' ? (a.timestamp > 9999999999 ? a.timestamp : a.timestamp * 1000) : new Date(a.timestamp || 0).getTime();
        const timeB = typeof b.timestamp === 'number' ? (b.timestamp > 9999999999 ? b.timestamp : b.timestamp * 1000) : new Date(b.timestamp || 0).getTime();
        cmp = timeA - timeB;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return result;
   
  }, [primaryFindings, severityFilter, statusFilter, targetFilter, sortKey, sortDir, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
   
  const paginated = useMemo(() => filtered.slice((page - 1) * pageSize, page * pageSize), [filtered, page, pageSize]);

  const kanbanFindings = useMemo(() => {
   
    const cols: Record<KanbanColumn, Finding[]> = { 'new': [], 'in-progress': [], 'resolved': [] };
    for (const f of filtered) {
      const col = f.kanbanStatus || 'new';
  // eslint-disable-next-line security/detect-object-injection
      if (cols[col]) cols[col].push(f);
    }
    return cols;
   
  }, [filtered]);

   
  const uniqueTargets = useMemo(() => [...new Set(findings.map(f => f.target).filter(Boolean))], [findings]);
  const uniqueAssignees = useMemo(() => {
    const assignees = findings.map(f => f.assignedTo).filter((a): a is string => typeof a === 'string' && a.length > 0);
   
    return [...new Set(assignees)].sort() as string[];
   
  }, [findings]);

  const toggleDuplicateExpand = useCallback((id: string) => {
    setExpandedDuplicates(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const getDuplicateById = useCallback((id: string) => {
    return findings.find(f => f.id === id);
   
  }, [findings]);

  const setSeverityFilterAndReset = useCallback((val: SeverityFilter) => { setSeverityFilter(val); setPage(1); }, []);
  const setStatusFilterAndReset = useCallback((val: StatusFilter) => { setStatusFilter(val); setPage(1); }, []);
  const setTargetFilterAndReset = useCallback((val: string) => { setTargetFilter(val); setPage(1); }, []);
  const setSearchQueryAndReset = useCallback((val: string) => { setSearchQuery(val); setPage(1); }, []);

  return {
    sortKey, sortDir, severityFilter, statusFilter, targetFilter, searchQuery, page, viewMode,
    expandedDuplicates, pageSize, filtered, totalPages, paginated,
    primaryFindings, kanbanFindings, uniqueTargets, uniqueAssignees,
    handleSort, toggleDuplicateExpand, getDuplicateById,
    setSeverityFilter: setSeverityFilterAndReset,
    setStatusFilter: setStatusFilterAndReset,
    setTargetFilter: setTargetFilterAndReset,
    setSearchQuery: setSearchQueryAndReset,
    setPage, setViewMode,
  };
}
