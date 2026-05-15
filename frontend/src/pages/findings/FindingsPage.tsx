import { useState, useCallback, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { exportFindings } from '../../api/client';
import { useApi } from '../../hooks/useApi';
import { useProcessedFindings } from '../../hooks/useProcessedFindings';
import { VirtualizedFindingsList } from '../../components/VirtualizedFindingsList';
import { Skeleton } from '../../components/ui/Skeleton';
import { useToast } from '../../hooks/useToast';
import type { Finding } from '../../types/api';
import { FindingDetailPanel } from './components/FindingDetailPanel';
import { LayoutGrid, List as ListIcon, Shield, Filter, Search, Loader2 } from 'lucide-react';
import { AnimatePresence } from 'framer-motion';

export function FindingsPage() {
  const toast = useToast();
  const [searchParams] = useSearchParams();
  
  const { data: findingsData, loading } = useApi<{ findings: Finding[]; total: number }>('/api/targets/findings/list', {
    refetchInterval: 15000,
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [sortKey] = useState<keyof Finding>('severity');
  const [sortDir] = useState<'asc' | 'desc'>('desc');
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);

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
    return () => { mounted = false; };
  }, [searchParams]);

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
          <div className="flex bg-zinc-900/50 p-1 rounded-lg border border-white/5">
             <button onClick={() => setViewMode('grid')} className={`p-1.5 rounded ${viewMode === 'grid' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}>
                <LayoutGrid size={16} />
             </button>
             <button onClick={() => setViewMode('table')} className={`p-1.5 rounded ${viewMode === 'table' ? 'bg-accent text-black' : 'text-muted hover:text-white'}`}>
                <ListIcon size={16} />
             </button>
          </div>
          <button onClick={() => handleExport('json')} className="btn-secondary btn-small">Export Intel</button>
        </div>
      </div>

      {/* ── Tactical Filters ─────────────────────────────────────── */}
      <div className="px-8 py-4 bg-black/40 border-b border-white/5 flex items-center gap-6">
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
    </div>
  );
}
