import { useState, useCallback, useEffect, useMemo, useRef, lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import { exportFindings, getFindingById, bulkUpdateFindings } from '../../api/client';
import { useApi } from '../../hooks/useApi';
import { useProcessedFindings } from '../../hooks/useProcessedFindings';
import { useDebouncedFilter } from '../../hooks/useDebouncedFilter';
import { VirtualizedFindingsList } from './components/VirtualizedFindingsList';
import { FindingsTablePane } from './components/FindingsTablePane';
import { FindingsKanbanPane } from './components/FindingsKanbanPane';
import { FindingComparisonPanel } from './components/FindingComparisonPanel';
import { Skeleton } from '../../components/ui/Skeleton';
import { EmptyState } from '../../components/ui/EmptyState';
import { SavedFilterPresets } from '../../components/ui/SavedFilterPresets';
import { FindingsFilterBar } from './components/FindingsFilterBar';
import { useOptionalFeatures } from '../../hooks/useOptionalFeatures';
import { useToast } from '../../hooks/useToast';
import { usePersistedState } from '../../hooks/usePersistedState';
import { normalizeFindingsViewMode, type FindingsViewMode } from './findingsViewMode';
import { offlineQueue } from '../../utils/offlineQueue';
import { buildFailedBulkAction, type FailedBulkAction } from './bulkRetry';
import { visibleFindingIds } from '@/features/notifications/unread';
import { acknowledgeNewFindings, detectFreshFindingIds, withoutFindingParam } from './newFindingsFeed';
import { sanitizeSeverityFilters } from './severityFilter';
import { applyFilterPreset } from './filterPreset';
import { pruneSelection } from './selection';
import { toggleIdInSet } from './hooks/useBulkActions';
import { unreadAfterDismiss } from '@/features/notifications/unread';
import { compareSelectionKey } from '@/utils/normalizeScale';
import type { Finding } from '../../types/api';
import { FindingDetailPanel } from './components/FindingDetailPanel';
import { LayoutGrid, List as ListIcon, Columns3, Shield, Filter, Search, Loader2, X, AlertOctagon, TrendingUp, DollarSign, CheckSquare, UserPlus, Trash2, Tag, RefreshCw, ArrowUpDown } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
const ReportFab = lazy(() => import('../../components/report/ReportFab').then(m => ({ default: m.ReportFab })));
const OnboardingTour = lazy(() => import('../../components/OnboardingTour').then(m => ({ default: m.OnboardingTour })));

export function FindingsPage() {
  const toast = useToast();
  const features = useOptionalFeatures();

  const [searchParams, setSearchParams] = useSearchParams();

  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);

  const { data: findingsData, loading } = useApi<{ findings: Finding[]; total: number }>('/api/targets/findings/list', {
    refetchInterval: detailFinding ? undefined : 5000,
  });

  const { filter: searchQuery, setFilter: setSearchQuery, debouncedFilter: debouncedSearch } = useDebouncedFilter(300);

  // Capture the export timestamp once at mount via an effect so render output
  // stays stable. Empty string is fine for the filename before mount completes.
  const [exportStamp, setExportStamp] = useState<string>('');
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setExportStamp(String(Date.now()));
  }, []);

  const [severityFilter, setSeverityFilter] = useState<string[]>([]);

  const [sortKey, setSortKey] = useState<keyof Finding | 'bounty_value' | 'remediation_priority'>('severity');

  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const [viewMode, setViewMode] = usePersistedState<FindingsViewMode>('findings-view-mode', 'grid');
  const safeViewMode = normalizeFindingsViewMode(viewMode);
  const [compareDismissed, setCompareDismissed] = useState(false);

  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());
  const [bulkActionMode, setBulkActionMode] = useState<string | null>(null);
  const [bulkAssignee, setBulkAssignee] = useState('');

  // Live findings: discover new arrivals between polls and offer a "Load" button
  // so the user can pull them in without waiting for the next 5s refresh.
  const [newFindingIds, setNewFindingIds] = useState<string[]>([]);
  const lastSeenIdsRef = useRef<Set<string>>(new Set());
  const initializedRef = useRef(false);

  useEffect(() => {
    if (!findingsData?.findings) return;
    const currentIds = new Set(findingsData.findings.map((f: Finding) => f.id).filter(Boolean) as string[]);
    if (!initializedRef.current) {
      lastSeenIdsRef.current = currentIds;
      initializedRef.current = true;
      return;
    }
    const fresh = detectFreshFindingIds(lastSeenIdsRef.current, currentIds);
    if (fresh.length > 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNewFindingIds(prev => Array.from(new Set([...prev, ...fresh])));
    }
  }, [findingsData?.findings]);

  const loadNewFindings = useCallback(() => {
    lastSeenIdsRef.current = new Set(acknowledgeNewFindings(lastSeenIdsRef.current, newFindingIds));
    setNewFindingIds([]);
  }, [newFindingIds]);

  const dismissNewFindings = useCallback(() => {
    lastSeenIdsRef.current = new Set(acknowledgeNewFindings(lastSeenIdsRef.current, newFindingIds));
    setNewFindingIds([]);
  }, [newFindingIds]);

  const toggleFindingSelection = useCallback((findingId: string) => {
    setSelectedFindingIds((prev) => toggleIdInSet(prev, findingId));
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedFindingIds(new Set());
    setBulkActionMode(null);
  }, []);

  const [failedBulkAction, setFailedBulkAction] = useState<FailedBulkAction | null>(null);

  const executeBulkUpdate = useCallback(async (
    ids: string[],
    data: Partial<Finding>,
    successMsg: string,
    actionLabel: string,
  ) => {
    try {
      await bulkUpdateFindings(ids, data);
      toast.success(successMsg);
      setFailedBulkAction(null);
      clearSelection();
    } catch {
      setFailedBulkAction(buildFailedBulkAction(ids, data, successMsg, actionLabel));
      if (!navigator.onLine) {
        offlineQueue.enqueue({
          execute: () => bulkUpdateFindings(ids, data),
          rollback: () => {},
          description: actionLabel,
        });
        toast.info(`${actionLabel} queued — will sync when back online`);
      } else {
        toast.error(`${actionLabel} failed`);
      }
    }
  }, [clearSelection, toast]);

  const handleBulkStatus = useCallback(async (status: 'open' | 'closed' | 'accepted') => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    executeBulkUpdate(ids, { status }, `${ids.length} finding(s) updated to ${status}`, 'Bulk status update');
  }, [selectedFindingIds, executeBulkUpdate]);

  const handleBulkFalsePositive = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    executeBulkUpdate(
      ids,
      { falsePositive: true, fpStatus: 'approved', fpJustification: 'Bulk marked as false positive' },
      `${ids.length} finding(s) marked as false positive`,
      'Bulk false positive marking',
    );
  }, [selectedFindingIds, executeBulkUpdate]);

  const handleBulkAssign = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0 || !bulkAssignee.trim()) return;
    executeBulkUpdate(
      ids,
      { assignedTo: bulkAssignee.trim() },
      `${ids.length} finding(s) assigned to ${bulkAssignee.trim()}`,
      'Bulk assign',
    );
  }, [selectedFindingIds, bulkAssignee, executeBulkUpdate]);

  const handleBulkDelete = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    if (!window.confirm(`Delete ${ids.length} finding(s)? This cannot be undone.`)) return;
    executeBulkUpdate(ids, { _deleted: true }, `${ids.length} finding(s) deleted`, 'Bulk delete');
  }, [selectedFindingIds, executeBulkUpdate]);

  const retryFailedBulk = useCallback(() => {
    if (!failedBulkAction) return;
    const { ids, action, data, successMsg } = failedBulkAction;
    setFailedBulkAction(null);
    executeBulkUpdate(ids, data, successMsg, action);
  }, [failedBulkAction, executeBulkUpdate]);

  // Initialize filters from URL params
  useEffect(() => {
    let mounted = true;
    const severity = searchParams.get('severity');
    if (severity) {
      // Defer state update to avoid cascading render warning
      Promise.resolve().then(() => {
        if (mounted) {
          setSeverityFilter(sanitizeSeverityFilters(severity.split(',')));
        }
      });
    }

    const fid = searchParams.get('finding');
    if (fid) {
      // Check if we already have it in the list
      const existing = findingsData?.findings.find((f: Finding) => f.id === fid);
      if (existing) {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setDetailFinding(existing);
      } else {
        // Fetch from the new singular endpoint
        getFindingById(fid)
          .then((finding: Finding | null) => {
            if (mounted && finding) setDetailFinding(finding);
          })
          .catch(() => {
            console.error('Failed to deep-link to finding:', fid);
          });
      }
    }

    return () => { mounted = false; };

  }, [searchParams, findingsData?.findings]);

  // --- Overhaul: Off-Main-Thread Processing ---
   
  const emptyFindings = useMemo(() => [], []);
   
  const filters = useMemo(() => ({ search: debouncedSearch, severity: severityFilter }), [debouncedSearch, severityFilter]);
   
  const sort = useMemo(() => ({ key: sortKey, direction: sortDir }), [sortKey, sortDir]);

  const { processed: allFindings, isProcessing } = useProcessedFindings(
    findingsData?.findings || emptyFindings,
    filters,
    sort
  );

  const findings = useMemo(() => {
    const allowed = new Set(visibleFindingIds(allFindings.map((item) => item.id), newFindingIds));
    return allFindings.filter((item) => allowed.has(item.id));
  }, [allFindings, newFindingIds]);

  const visibleIds = useMemo(() => findings.map((item) => item.id), [findings]);
  useEffect(() => {
    setSelectedFindingIds((prev) => {
      const next = pruneSelection(prev, visibleIds);
      if (next.length === prev.size && next.every((id) => prev.has(id))) return prev;
      return new Set(next);
    });
  }, [visibleIds]);

  const comparePair = useMemo(() => {
    if (selectedFindingIds.size !== 2) return null;
    const [idA, idB] = Array.from(selectedFindingIds);
    const findingA = findings.find((finding) => finding.id === idA);
    const findingB = findings.find((finding) => finding.id === idB);
    return findingA && findingB ? { findingA, findingB } : null;
  }, [selectedFindingIds, findings]);

  const selectionKey = compareSelectionKey(selectedFindingIds);
  useEffect(() => {
    setCompareDismissed(false);
  }, [selectionKey]);

  const selectAllFindings = useCallback(() => {
    setSelectedFindingIds(new Set(findings.map((f: Finding) => f.id).filter(Boolean) as string[]));
  }, [findings]);

  const handleExport = useCallback(async (format: 'csv' | 'json') => {
    try {
      const blob = await exportFindings({ format });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `findings-${Date.now()}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error('Export sequence failed');
    }

  }, [toast]);

  const handleSortToggle = useCallback((key: keyof Finding | 'bounty_value' | 'remediation_priority') => {
    setSortKey((prev) => {
      if (prev === key) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        return prev;
      }
      setSortDir('desc');
      return key;
    });
  }, []);

  const currentFilters = useMemo(() => ({
    search: searchQuery,
    severity: severityFilter.join(','),
  }), [searchQuery, severityFilter]);

  const handleLoadPreset = useCallback((filters: Record<string, string>) => {
    const next = applyFilterPreset({ search: searchQuery, severity: sanitizeSeverityFilters(severityFilter) }, filters);
    setSearchQuery(next.search);
    setSeverityFilter(next.severity);
  }, [searchQuery, severityFilter, setSearchQuery, setSeverityFilter]);

  if (loading && !findingsData) return (
    <div className="p-10 space-y-4">
      <Skeleton className="h-12 w-1/4" />
      <Skeleton className="h-[600px] w-full" />
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-bg font-sans">
      {/* ── Cyber Page Header ────────────────────────────────────── */}
      <div className="px-8 py-6 border-b border-line flex items-center justify-between glass-panel sticky top-0 z-20">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-accent/10 rounded-lg border border-accent/20">
            <Shield size={20} className="text-accent" />
          </div>
          <div>
            <h2 className="text-xl font-black text-text uppercase tracking-tighter">Aggregated Findings</h2>
            <div className="flex items-center gap-2 text-[10px] text-muted font-mono">
              <div className={`w-1.5 h-1.5 rounded-full ${isProcessing ? 'bg-warn animate-pulse' : 'bg-accent'}`} />
              {isProcessing ? 'Processing Engine Active...' : `${findings.length} Findings Synchronized`}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 p-1 rounded-xl border border-line bg-surface-2">
             <button
               type="button"
               onClick={() => handleSortToggle('severity')}
               className={`btn btn-sm ${sortKey === 'severity' ? 'btn-primary' : 'btn-ghost'} flex items-center gap-1.5`}
               aria-pressed={sortKey === 'severity'}
               title="Sort by severity"
             >
               <AlertOctagon size={12} />
               <span>Severity</span>
               {sortKey === 'severity' && <span className="ml-0.5">{sortDir === 'asc' ? '↑' : '↓'}</span>}
             </button>
             <button
               type="button"
               onClick={() => handleSortToggle('remediation_priority')}
               className={`btn btn-sm ${sortKey === 'remediation_priority' ? 'btn-primary' : 'btn-ghost'} flex items-center gap-1.5`}
               aria-pressed={sortKey === 'remediation_priority'}
               title="Sort by composite remediation priority"
             >
               <TrendingUp size={12} />
               <span>Priority</span>
               {sortKey === 'remediation_priority' && <span className="ml-0.5">{sortDir === 'asc' ? '↑' : '↓'}</span>}
             </button>
             <button
               type="button"
               onClick={() => handleSortToggle('bounty_value')}
               className={`btn btn-sm ${sortKey === 'bounty_value' ? 'btn-primary' : 'btn-ghost'} flex items-center gap-1.5`}
               aria-pressed={sortKey === 'bounty_value'}
               title="Sort by bounty value"
             >
               <DollarSign size={12} />
               <span>Bounty</span>
               {sortKey === 'bounty_value' && <span className="ml-0.5">{sortDir === 'asc' ? '↑' : '↓'}</span>}
             </button>
          </div>
          <div className="flex bg-zinc-900/50 p-1 rounded-lg border border-line">
             <button type="button" aria-label="Grid view" aria-pressed={safeViewMode === 'grid'} onClick={() => setViewMode('grid')} className={`p-1.5 rounded ${safeViewMode === 'grid' ? 'bg-accent text-black' : 'text-muted hover:text-text-primary'}`}>
                <LayoutGrid size={16} />
             </button>
             <button type="button" aria-label="Table view" aria-pressed={safeViewMode === 'table'} onClick={() => setViewMode('table')} className={`p-1.5 rounded ${safeViewMode === 'table' ? 'bg-accent text-black' : 'text-muted hover:text-text-primary'}`}>
                <ListIcon size={16} />
             </button>
             <button type="button" aria-label="Kanban view" aria-pressed={safeViewMode === 'kanban'} onClick={() => setViewMode('kanban')} className={`p-1.5 rounded ${safeViewMode === 'kanban' ? 'bg-accent text-black' : 'text-muted hover:text-text-primary'}`}>
                <Columns3 size={16} />
             </button>
          </div>
          {comparePair && (
            <button
              type="button"
              onClick={() => setCompareDismissed(false)}
              className="btn-secondary btn-small flex items-center gap-1.5"
            >
              <ArrowUpDown size={12} />
              Compare
            </button>
          )}
          <div className="flex gap-2">
            <button onClick={() => handleExport('json')} className="btn-secondary btn-small">Export JSON</button>
            <button onClick={() => handleExport('csv')} className="btn-secondary btn-small">Export CSV</button>
          </div>
        </div>
      </div>

      {/* ── New Findings Notification Banner ─────────────────────── */}
      <AnimatePresence>
        {newFindingIds.length > 0 && (
          <div className="px-8 pt-4">
            <motion.div
              initial={{ opacity: 0, y: -20, height: 0 }}
              animate={{ opacity: 1, y: 0, height: 'auto' }}
              exit={{ opacity: 0, y: -20, height: 0 }}
              transition={{ type: 'spring', stiffness: 200, damping: 20 }}
              className="w-full flex items-center justify-between gap-4 px-6 py-3 border border-accent/30 bg-accent/10 rounded-xl shadow-glow-accent-md"
              role="status"
              aria-live="polite"
            >
              <div className="flex items-center gap-3">
                <div className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-accent"></span>
                </div>
                <div className="text-xs font-mono uppercase tracking-wider text-text">
                  <span className="text-accent font-black">{newFindingIds.length} new finding{newFindingIds.length === 1 ? '' : 's'}</span> detected in the background
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={loadNewFindings}
                  className="px-4 py-1.5 rounded-lg bg-accent text-black font-black text-xs uppercase tracking-widest hover:bg-accent-dim transition-all shadow-glow-accent-sm cursor-pointer"
                  aria-label="Load new findings"
                >
                  Load Feed
                </button>
                <button
                  type="button"
                  onClick={dismissNewFindings}
                  className="p-1 rounded-lg text-text-secondary hover:text-text-primary transition-colors cursor-pointer"
                  aria-label="Dismiss banner"
                >
                  <X size={16} aria-hidden="true" />
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Failed Bulk Action Retry Banner ────────────────────────── */}
      <AnimatePresence>
        {failedBulkAction && (
          <div className="px-8 pt-4">
            <motion.div
              initial={{ opacity: 0, y: -12, height: 0 }}
              animate={{ opacity: 1, y: 0, height: 'auto' }}
              exit={{ opacity: 0, y: -12, height: 0 }}
              className="w-full flex items-center justify-between gap-4 px-6 py-3 border border-warn/30 bg-warn/10 rounded-xl"
            >
              <div className="flex items-center gap-3 text-xs font-mono text-text">
                <RefreshCw size={14} className="text-warn" />
                <span>
                  <span className="text-warn font-black">Bulk action failed</span> — {failedBulkAction.action} for {failedBulkAction.ids.length} finding(s)
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={retryFailedBulk}
                  className="px-4 py-1.5 rounded-lg bg-warn text-black font-black text-xs uppercase tracking-widest hover:bg-warn/80 transition-all cursor-pointer"
                >
                  Retry
                </button>
                <button
                  type="button"
                  onClick={() => setFailedBulkAction(null)}
                  className="p-1 rounded-lg text-muted hover:text-text-primary transition-colors cursor-pointer"
                >
                  <X size={14} />
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Tactical Filters ─────────────────────────────────────── */}
      {features.compactFindingsFilters && (
        <div className="px-8 pt-4">
          <FindingsFilterBar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityToggle={(sev) => {
              setSeverityFilter((prev) => {
                const next = prev.includes(sev) ? prev.filter((item) => item !== sev) : [...prev, sev];
                setSearchParams((current) => {
                  const params = new URLSearchParams(current);
                  if (next.length > 0) params.set('severity', next.join(','));
                  else params.delete('severity');
                  return params;
                }, { replace: true });
                return next;
              });
            }}
            onClearFilters={() => {
              setSearchQuery('');
              setSeverityFilter([]);
              setSearchParams((current) => {
                const params = new URLSearchParams(current);
                params.delete('severity');
                return params;
              }, { replace: true });
            }}
            totalResults={findings.length}
          />
        </div>
      )}
      <div className="px-8 py-4 card mx-4 mt-4 flex items-center gap-6 flex-wrap">
        <div className="relative flex-1 max-w-md">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input 
            type="text"
            placeholder="FILTER BY CVE, CWE, URL, TYPE..."
            aria-label="Filter findings by CVE, CWE, URL or type"
            className="w-full bg-surface-hover border border-line rounded-lg py-2 pl-10 pr-4 text-xs font-mono text-text focus:border-accent/50 outline-none transition-all uppercase"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2">
           <Filter size={14} className="text-muted" />
           <div className="flex gap-2">
             {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
               const dotColor = 
                 sev === 'critical' ? 'bg-critical' :
                 sev === 'high' ? 'bg-high' :
                 sev === 'medium' ? 'bg-medium' :
                 sev === 'low' ? 'bg-low' : 'bg-info';
               return (
           <button 
                   key={sev}
                   onClick={() => {
                     setSeverityFilter(prev => {
                       const next = prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev];
                       setSearchParams(prev => {
                         const params = new URLSearchParams(prev);
                         if (next.length > 0) {
                           params.set('severity', next.join(','));
                         } else {
                           params.delete('severity');
                         }
                         return params;
                       }, { replace: true });
                       return next;
                     });
                   }}
                  className={`px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-widest border transition-all flex items-center gap-2 cursor-pointer ${
                    severityFilter.includes(sev) 
                      ? 'bg-surface-2 border-line text-text-primary' 
                      : 'border-line text-muted hover:border-line hover:text-text'
                  }`}
                 >
                   <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                   <span>{sev}</span>
                 </button>
               );
             })}
           </div>
        </div>

        <SavedFilterPresets
          currentFilters={currentFilters}
          onLoadPreset={handleLoadPreset}
        />
      </div>

      {/* ── Virtualized Data Grid ─────────────────────────────────── */}
      <div className="flex-1 min-h-0 relative">
        {isProcessing && findings.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center bg-bg/50 z-10">
            <Loader2 className="animate-spin text-accent" />
          </div>
        )}
        
        {!isProcessing && findings.length === 0 ? (
          <div className="flex items-center justify-center h-full p-8">
            <EmptyState
              title={searchQuery || severityFilter.length > 0 ? 'No findings match your filters' : 'No findings yet'}
              description={searchQuery || severityFilter.length > 0
                ? 'Try adjusting your search query or severity filters.'
                : 'Run a scan from Targets. An empty grid does not mean the scanners failed.'}
              ctaLabel={searchQuery || severityFilter.length > 0 ? undefined : 'Go to Targets'}
              ctaHref={searchQuery || severityFilter.length > 0 ? undefined : '/targets'}
            />
          </div>
        ) : safeViewMode === 'kanban' ? (
          <FindingsKanbanPane
            findings={findings}
            onOpenDetail={setDetailFinding}
          />
        ) : safeViewMode === 'table' ? (
          <FindingsTablePane
            findings={findings}
            selectedIds={selectedFindingIds}
            onToggleSelect={toggleFindingSelection}
            onSelectAll={selectAllFindings}
            onClearSelection={clearSelection}
            onOpenDetail={setDetailFinding}
            bulkActionMode={bulkActionMode}
            setBulkActionMode={setBulkActionMode}
            bulkAssignee={bulkAssignee}
            setBulkAssignee={setBulkAssignee}
            handleBulkStatus={handleBulkStatus}
            handleBulkFalsePositive={handleBulkFalsePositive}
            handleBulkAssign={handleBulkAssign}
            handleBulkDelete={handleBulkDelete}
            sortKey={String(sortKey)}
            sortDir={sortDir}
            onSort={(key) => handleSortToggle(key === 'date' ? 'timestamp' : key)}
          />
        ) : (
          <VirtualizedFindingsList 
            findings={findings}
            height="100%"
            onSelect={setDetailFinding}
            selectedIds={selectedFindingIds}
            onToggleSelect={toggleFindingSelection}
            selectionMode={selectedFindingIds.size > 0}
          />
        )}
      </div>

      {/* ── Bulk Action Bar (Grid View) ───────────────────────────── */}
      <div aria-live="polite" aria-atomic="true">
      <AnimatePresence>
        {selectedFindingIds.size > 0 && safeViewMode === 'grid' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 px-6 py-3 rounded-2xl border border-line bg-surface/90 backdrop-blur-xl shadow-overlay-lg"
            role="toolbar"
            aria-label="Bulk actions for selected findings"
          >
            <div className="flex items-center gap-2 pr-4 border-r border-line">
              <span className="text-xs font-black text-accent">{selectedFindingIds.size}</span>
              <span className="text-[10px] text-text-secondary uppercase tracking-widest">selected</span>
            </div>
            <button
              type="button"
              onClick={selectAllFindings}
              className="text-[10px] font-black uppercase tracking-widest text-text-secondary hover:text-text-primary transition-colors px-2 py-1"
            >
              Select All
            </button>
            <button
              type="button"
              onClick={clearSelection}
              className="text-[10px] font-black uppercase tracking-widest text-text-secondary hover:text-text-primary transition-colors px-2 py-1"
            >
              Clear
            </button>
            <div className="w-px h-6 bg-surface-2" />
            {bulkActionMode === 'status' ? (
              <div className="flex items-center gap-2">
                <button onClick={() => handleBulkStatus('open')} className="btn-secondary btn-small text-[9px]">New</button>
                <button onClick={() => handleBulkStatus('accepted')} className="btn-secondary btn-small text-[9px]">In Progress</button>
                <button onClick={() => handleBulkStatus('closed')} className="btn-secondary btn-small text-[9px]">Resolved</button>
                <button onClick={() => setBulkActionMode(null)} className="btn-ghost btn-small text-[9px]">Cancel</button>
              </div>
            ) : bulkActionMode === 'assign' ? (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Assignee..."
                  aria-label="Assignee name for bulk assignment"
                  value={bulkAssignee}
                  onChange={e => setBulkAssignee(e.target.value)}
                  className="bg-surface-hover border border-line rounded px-2 py-1 text-[10px] font-mono text-text w-28 focus:border-accent/50 outline-none"
                />
                <button onClick={handleBulkAssign} disabled={!bulkAssignee.trim()} className="btn-primary btn-small text-[9px] disabled:opacity-40">Assign</button>
                <button onClick={() => { setBulkActionMode(null); setBulkAssignee(''); }} className="btn-ghost btn-small text-[9px]">Cancel</button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <button onClick={() => setBulkActionMode('status')} className="btn-secondary btn-small text-[9px] flex items-center gap-1">
                  <CheckSquare size={12} /> Status
                </button>
                <button onClick={handleBulkFalsePositive} className="btn-secondary btn-small text-[9px] flex items-center gap-1">
                  <Tag size={12} /> Mark FP
                </button>
                <button onClick={() => setBulkActionMode('assign')} className="btn-secondary btn-small text-[9px] flex items-center gap-1">
                  <UserPlus size={12} /> Assign
                </button>
                <button onClick={handleBulkDelete} className="btn-secondary btn-small text-[9px] flex items-center gap-1 text-rose-400 hover:text-rose-300">
                  <Trash2 size={12} /> Delete
                </button>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
      </div>

      {/* ── Side Detail Panel ─────────────────────────────────────── */}
      <AnimatePresence>
        {detailFinding && (
          <FindingDetailPanel
            finding={detailFinding}
            onClose={() => {
              setDetailFinding(null);
              setSearchParams((prev) => withoutFindingParam(prev), { replace: true });
            }}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {comparePair && !compareDismissed && (
          <FindingComparisonPanel
            findingA={comparePair.findingA}
            findingB={comparePair.findingB}
            onClose={() => setCompareDismissed(true)}
          />
        )}
      </AnimatePresence>

      {/* ── One-click Report FAB (P2-5) ─────────────────────────────── */}
      <Suspense fallback={null}>
        <ReportFab
          findings={findings}
          filenameBase={`findings-${exportStamp}`}
          context={{}}
        />
        <OnboardingTour />
      </Suspense>
    </div>
  );
}
