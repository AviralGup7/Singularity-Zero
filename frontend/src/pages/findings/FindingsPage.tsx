import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { exportFindings, getFindingById } from '../../api/client';
import { useApi } from '../../hooks/useApi';
import { useProcessedFindings } from '../../hooks/useProcessedFindings';
import { VirtualizedFindingsList } from '../../components/findings/VirtualizedFindingsList';
import { Skeleton } from '../../components/ui/Skeleton';
import { useToast } from '../../hooks/useToast';
import type { Finding } from '../../types/api';
import { FindingDetailPanel } from './components/FindingDetailPanel';
import { LayoutGrid, List as ListIcon, Shield, Filter, Search, Loader2, Radio, X } from 'lucide-react';
import { AnimatePresence } from 'framer-motion';
import { ReportFab } from '../../components/report/ReportFab';

export function FindingsPage() {
  const toast = useToast();

  const [searchParams] = useSearchParams();

  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);

  const { data: findingsData, loading } = useApi<{ findings: Finding[]; total: number }>('/api/targets/findings/list', {
    refetchInterval: detailFinding ? undefined : 5000,
  });

  const [searchQuery, setSearchQuery] = useState('');

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
   
  const filters = useMemo(() => ({ search: searchQuery, severity: severityFilter }), [searchQuery, severityFilter]);
   
  const sort = useMemo(() => ({ key: sortKey, direction: sortDir }), [sortKey, sortDir]);

  const { processed: findings, isProcessing } = useProcessedFindings(
    findingsData?.findings || emptyFindings,
    filters,
    sort
  );

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
              {isProcessing ? 'Processing Engine Active...' : `${findings.length} Signals Synchronized`}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center bg-zinc-900/50 p-1 rounded-lg border border-white/5">
             <button
               type="button"
               onClick={() => handleSortToggle('severity')}
               className={`px-2.5 py-1 rounded text-[10px] font-black uppercase tracking-widest transition-all ${sortKey === 'severity' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}
               aria-pressed={sortKey === 'severity'}
               title="Sort by severity"
             >
               Severity
               {sortKey === 'severity' && <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>}
             </button>
             <button
               type="button"
               onClick={() => handleSortToggle('remediation_priority')}
               className={`px-2.5 py-1 rounded text-[10px] font-black uppercase tracking-widest transition-all ${sortKey === 'remediation_priority' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}
               aria-pressed={sortKey === 'remediation_priority'}
               title="Sort by composite remediation priority (modern risk + attack chain + EPSS + asset criticality)"
             >
               Priority
               {sortKey === 'remediation_priority' && <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>}
             </button>
             <button
               type="button"
               onClick={() => handleSortToggle('bounty_value')}
               className={`px-2.5 py-1 rounded text-[10px] font-black uppercase tracking-widest transition-all ${sortKey === 'bounty_value' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}
               aria-pressed={sortKey === 'bounty_value'}
               title="Sort by bounty value (operator-estimated payout)"
             >
               Bounty
               {sortKey === 'bounty_value' && <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>}
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

      {/* ── Tactical Filters ─────────────────────────────────────── */}
      <div className="px-8 py-4 bg-black/40 border-b border-white/5 flex items-center gap-6 flex-wrap">
        {newFindingIds.length > 0 && (
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-accent/30 bg-accent/5 text-[10px] font-mono uppercase tracking-widest"
            role="status"
            aria-live="polite"
          >
            <Radio size={12} className="text-accent animate-pulse" aria-hidden="true" />
            <span className="text-accent">{newFindingIds.length} new finding{newFindingIds.length === 1 ? '' : 's'}</span>
            <span className="text-muted">since last view</span>
            <button
              type="button"
              onClick={loadNewFindings}
              className="ml-1 px-2 py-0.5 rounded bg-accent/20 text-accent hover:bg-accent/30"
              aria-label="Load new findings"
            >
              Load
            </button>
            <button
              type="button"
              onClick={dismissNewFindings}
              className="ml-0.5 text-muted hover:text-text"
              aria-label="Dismiss new findings banner"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </div>
        )}
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
             {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
               <button 
                key={sev}
   
                onClick={() => setSeverityFilter(prev => prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev])}
   
                className={`px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-widest border transition-all ${
                  severityFilter.includes(sev) 
                    ? 'bg-white/10 border-white/20 text-white' 
                    : 'border-white/5 text-muted hover:border-white/10'
                }`}
               >
                 {sev}
               </button>
             ))}
           </div>
        </div>
      </div>

      {/* ── Virtualized Data Grid ─────────────────────────────────── */}
      <div className="flex-1 min-h-0 relative">
        {isProcessing && findings.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center bg-bg/50 z-10">
            <Loader2 className="animate-spin text-accent" />
          </div>
        )}
        
        <VirtualizedFindingsList 
          findings={findings}
          height="100%"
          onSelect={setDetailFinding}
        />
      </div>

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
