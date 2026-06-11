import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { exportFindings, getFindingById, bulkUpdateFindings } from '../../api/client';
import { useApi } from '../../hooks/useApi';
import { useProcessedFindings } from '../../hooks/useProcessedFindings';
import { useDebouncedFilter } from '../../hooks/useDebouncedFilter';
import { VirtualizedFindingsList } from '../../components/findings/VirtualizedFindingsList';
import { Skeleton } from '../../components/ui/Skeleton';
import { EmptyState } from '../../components/ui/EmptyState';
import { SavedFilterPresets } from '../../components/ui/SavedFilterPresets';
import { useToast } from '../../hooks/useToast';
import type { Finding } from '../../types/api';
import { FindingDetailPanel } from './components/FindingDetailPanel';
import { LayoutGrid, List as ListIcon, Shield, Filter, Search, Loader2, X, AlertOctagon, TrendingUp, DollarSign, CheckSquare, UserPlus, Trash2, Tag } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import { ReportFab } from '../../components/report/ReportFab';

export function FindingsPage() {
  const toast = useToast();

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

  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');

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
    const currentIds = new Set(findingsData.findings.map(f => f.id).filter(Boolean) as string[]);
    if (!initializedRef.current) {
      lastSeenIdsRef.current = currentIds;
      initializedRef.current = true;
      return;
    }
    const fresh: string[] = [];
    currentIds.forEach(id => {
      if (!lastSeenIdsRef.current.has(id)) fresh.push(id);
    });
    if (fresh.length > 0) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNewFindingIds(prev => Array.from(new Set([...prev, ...fresh])));
    }
    lastSeenIdsRef.current = currentIds;
  }, [findingsData?.findings]);

  const loadNewFindings = useCallback(() => {
    setNewFindingIds([]);
  }, []);

  const dismissNewFindings = useCallback(() => {
    setNewFindingIds([]);
  }, []);

  const toggleFindingSelection = useCallback((findingId: string) => {
    setSelectedFindingIds(prev => {
      const next = new Set(prev);
      if (next.has(findingId)) {
        next.delete(findingId);
      } else {
        next.add(findingId);
      }
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedFindingIds(new Set());
    setBulkActionMode(null);
  }, []);

  const handleBulkStatus = useCallback(async (status: 'open' | 'closed' | 'accepted') => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    try {
      await bulkUpdateFindings(ids, { lifecycle_state: status });
      toast.success(`${ids.length} finding(s) updated to ${status}`);
      clearSelection();
    } catch {
      toast.error('Bulk status update failed');
    }
  }, [selectedFindingIds, toast, clearSelection]);

  const handleBulkFalsePositive = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    try {
      await bulkUpdateFindings(ids, { falsePositive: true, fpStatus: 'approved', fpJustification: 'Bulk marked as false positive' });
      toast.success(`${ids.length} finding(s) marked as false positive`);
      clearSelection();
    } catch {
      toast.error('Bulk false positive marking failed');
    }
  }, [selectedFindingIds, toast, clearSelection]);

  const handleBulkAssign = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0 || !bulkAssignee.trim()) return;
    try {
      await bulkUpdateFindings(ids, { assignee: bulkAssignee.trim() });
      toast.success(`${ids.length} finding(s) assigned to ${bulkAssignee.trim()}`);
      clearSelection();
    } catch {
      toast.error('Bulk assign failed');
    }
  }, [selectedFindingIds, bulkAssignee, toast, clearSelection]);

  const handleBulkDelete = useCallback(async () => {
    const ids = Array.from(selectedFindingIds);
    if (ids.length === 0) return;
    if (!window.confirm(`Delete ${ids.length} finding(s)? This cannot be undone.`)) return;
    try {
      await bulkUpdateFindings(ids, { deleted: true });
      toast.success(`${ids.length} finding(s) deleted`);
      clearSelection();
    } catch {
      toast.error('Bulk delete failed');
    }
  }, [selectedFindingIds, toast, clearSelection]);

  // Initialize filters from URL params
  useEffect(() => {
    let mounted = true;
    const severity = searchParams.get('severity');
    if (severity) {
      // Defer state update to avoid cascading render warning
      Promise.resolve().then(() => {
        if (mounted) {
          setSeverityFilter(severity.split(','));
        }
      });
    }

    const fid = searchParams.get('finding');
    if (fid) {
      // Check if we already have it in the list
      const existing = findingsData?.findings.find(f => f.id === fid);
      if (existing) {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setDetailFinding(existing);
      } else {
        // Fetch from the new singular endpoint
        getFindingById(fid)
          .then((finding) => {
            if (mounted) setDetailFinding(finding);
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

  const { processed: findings, isProcessing } = useProcessedFindings(
    findingsData?.findings || emptyFindings,
    filters,
    sort
  );

  const selectAllFindings = useCallback(() => {
    setSelectedFindingIds(new Set(findings.map(f => f.id).filter(Boolean) as string[]));
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
    if (filters.search) setSearchQuery(filters.search);
    if (filters.severity) setSeverityFilter(filters.severity.split(',').filter(Boolean));
  }, [setSearchQuery, setSeverityFilter]);

  if (loading && !findingsData) return (
    <div className="p-10 space-y-4">
      <Skeleton className="h-12 w-1/4" />
      <Skeleton className="h-[600px] w-full" />
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-bg font-sans">
      {/* ── Cyber Page Header ────────────────────────────────────── */}
      <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between glass-panel sticky top-0 z-20">
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
          <div className="flex items-center gap-1 p-1 rounded-xl border border-[var(--border)] bg-[var(--surface-2)]">
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
          <div className="flex bg-zinc-900/50 p-1 rounded-lg border border-white/5">
             <button onClick={() => setViewMode('grid')} className={`p-1.5 rounded ${viewMode === 'grid' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}>
                <LayoutGrid size={16} />
             </button>
             <button onClick={() => setViewMode('table')} className={`p-1.5 rounded ${viewMode === 'table' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}>
                <ListIcon size={16} />
             </button>
          </div>
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
              className="w-full flex items-center justify-between gap-4 px-6 py-3 border border-accent/30 bg-accent/10 rounded-xl shadow-[0_0_20px_rgba(0,255,65,0.1)]"
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
                  className="px-4 py-1.5 rounded-lg bg-accent text-black font-black text-xs uppercase tracking-widest hover:bg-accent-dim transition-all shadow-[0_0_15px_rgba(0,255,65,0.3)] cursor-pointer"
                  aria-label="Load new findings"
                >
                  Load Feed
                </button>
                <button
                  type="button"
                  onClick={dismissNewFindings}
                  className="p-1 rounded-lg text-muted hover:text-white transition-colors cursor-pointer"
                  aria-label="Dismiss banner"
                >
                  <X size={16} aria-hidden="true" />
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── Tactical Filters ─────────────────────────────────────── */}
      <div className="px-8 py-4 card mx-4 mt-4 flex items-center gap-6 flex-wrap">
        <div className="relative flex-1 max-w-md">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input 
            type="text"
            placeholder="FILTER BY CVE, CWE, URL, TYPE..."
            className="w-full bg-white/5 border border-white/10 rounded-lg py-2 pl-10 pr-4 text-xs font-mono text-text focus:border-accent/50 outline-none transition-all uppercase"
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
                      ? 'bg-white/10 border-white/25 text-white' 
                      : 'border-white/5 text-muted hover:border-white/15 hover:text-text'
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
        
        {!isProcessing && findings.length === 0 && (searchQuery || severityFilter.length > 0) ? (
          <div className="flex items-center justify-center h-full p-8">
            <EmptyState
              title="No findings match your filters"
              description="Try adjusting your search query or severity filters to find what you're looking for."
              icon="shield"
            />
          </div>
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
      <AnimatePresence>
        {selectedFindingIds.size > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 px-6 py-3 rounded-2xl border border-white/10 bg-black/90 backdrop-blur-xl shadow-[0_0_30px_rgba(0,0,0,0.5)]"
            role="toolbar"
            aria-label="Bulk actions for selected findings"
          >
            <div className="flex items-center gap-2 pr-4 border-r border-white/10">
              <span className="text-xs font-black text-accent">{selectedFindingIds.size}</span>
              <span className="text-[10px] text-muted uppercase tracking-widest">selected</span>
            </div>
            <button
              type="button"
              onClick={selectAllFindings}
              className="text-[10px] font-black uppercase tracking-widest text-muted hover:text-white transition-colors px-2 py-1"
            >
              Select All
            </button>
            <button
              type="button"
              onClick={clearSelection}
              className="text-[10px] font-black uppercase tracking-widest text-muted hover:text-white transition-colors px-2 py-1"
            >
              Clear
            </button>
            <div className="w-px h-6 bg-white/10" />
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
                  value={bulkAssignee}
                  onChange={e => setBulkAssignee(e.target.value)}
                  className="bg-white/5 border border-white/10 rounded px-2 py-1 text-[10px] font-mono text-text w-28 focus:border-accent/50 outline-none"
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

      {/* ── Side Detail Panel ─────────────────────────────────────── */}
      <AnimatePresence>
        {detailFinding && (
          <FindingDetailPanel
            finding={detailFinding}
            onClose={() => setDetailFinding(null)}
          />
        )}
      </AnimatePresence>

      {/* ── One-click Report FAB (P2-5) ─────────────────────────────── */}
      <ReportFab
        findings={findings}
        filenameBase={`findings-${exportStamp}`}
        context={{}}
      />
    </div>
  );
}
