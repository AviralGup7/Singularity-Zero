import { useState, useMemo, useCallback, useEffect } from 'react';
import { getGapAnalysis, refreshGapAnalysis } from '../api/client';
import type { DetectionGapResponse } from '../types/api';
import { Skeleton } from '../components/ui/Skeleton';
import { EmptyState } from '../components/ui/EmptyState';
import { Icon } from '../components/Icon';
import { motion, AnimatePresence } from 'framer-motion';

type SortKey = 'module' | 'coverage_percent' | 'status';
type SortDir = 'asc' | 'desc';
type StatusFilter = 'all' | 'complete' | 'partial' | 'missing';

const STATUS_ORDER = { complete: 0, partial: 1, missing: 2 };

export function GapAnalysisPage() {
   
  const [data, setData] = useState<DetectionGapResponse | null>(null);
   
  const [loading, setLoading] = useState(true);
   
  const [refreshing, setRefreshing] = useState(false);
   
  const [error, setError] = useState<string | null>(null);
   
  const [sortKey, setSortKey] = useState<SortKey>('module');
   
  const [sortDir, setSortDir] = useState<SortDir>('asc');
   
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
   
  const [searchQuery, setSearchQuery] = useState('');
   
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const loadData = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await getGapAnalysis(signal);
      setData(result);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') return;
      setError('Failed to load gap analysis data. Infrastructure mesh may be desynchronized.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    loadData(controller.signal);
    return () => controller.abort();
   
  }, [loadData]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshGapAnalysis();
      await loadData();
    } catch {
      setError('Failed to trigger analysis refresh.');
    } finally {
      setRefreshing(false);
    }
  };

  const handleSort = (key: SortKey) => {
    setSortDir(prev => sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'asc');
    setSortKey(key);
  };

  const toggleExpand = (module: string) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(module)) next.delete(module);
      else next.add(module);
      return next;
    });
  };

  const filtered = useMemo(() => {
    if (!data || !data.results) return [];
   
    let result = [...data.results];
    
    if (statusFilter !== 'all') {
      result = result.filter(r => r && r.status === statusFilter);
    }
    
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(r => 
        r && (
          (r.module || '').toLowerCase().includes(q) || 
          (r.category || '').toLowerCase().includes(q)
        )
      );
    }

    result.sort((a, b) => {
      if (!a || !b) return 0;
      let cmp = 0;
      if (sortKey === 'module') cmp = (a.module || '').localeCompare(b.module || '');
      else if (sortKey === 'coverage_percent') cmp = (a.coverage_percent || 0) - (b.coverage_percent || 0);
   
      else if (sortKey === 'status') cmp = (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3);
      return sortDir === 'asc' ? cmp : -cmp;
    });
    
    return result;
   
  }, [data, statusFilter, searchQuery, sortKey, sortDir]);

  if (loading && !data) return (
    <div className="p-6 space-y-6">
      <Skeleton className="h-10 w-48" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
      <Skeleton className="h-96" />
    </div>
  );

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Icon name="shieldCheck" size={24} className="text-accent" />
            Detection Gap Analysis
          </h2>
          <p className="text-muted text-sm mt-1">
            Compare active module capabilities against the global vulnerability registry.
          </p>
        </div>
        <button 
          onClick={handleRefresh}
          disabled={refreshing}
          className={`btn btn-secondary flex items-center gap-2 ${refreshing ? 'animate-pulse' : ''}`}
        >
          <Icon name="refresh" size={16} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? 'Analyzing...' : 'Refresh Analysis'}
        </button>
      </header>

      {error && (
        <div className="p-4 bg-bad/10 border border-bad/20 rounded-lg text-bad text-sm flex items-center gap-3">
          <Icon name="alertTriangle" size={18} />
          {error}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-panel border border-white/5 p-6 rounded-xl cyber-glow-sm"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Overall Coverage</div>
            <div className={`text-4xl font-black ${
              data.overall_coverage > 80 ? 'text-ok' : data.overall_coverage > 50 ? 'text-warn' : 'text-bad'
            }`}>
              {data.overall_coverage}%
            </div>
            <div className="mt-4 h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-1000 ${
                  data.overall_coverage > 80 ? 'bg-ok' : data.overall_coverage > 50 ? 'bg-warn' : 'bg-bad'
                }`}
                style={{ width: `${data.overall_coverage}%` }}
              />
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-panel border border-white/5 p-6 rounded-xl"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Module Integrity</div>
            <div className="text-4xl font-black text-text">
              {data.total_modules - data.modules_with_gaps}<span className="text-lg text-muted font-normal ml-2">/ {data.total_modules} OK</span>
            </div>
            <div className="text-xs text-muted mt-2 italic">
              Modules meeting 100% of detection registry requirements.
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-panel border border-white/5 p-6 rounded-xl"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Identified Gaps</div>
            <div className={`text-4xl font-black ${data.modules_with_gaps > 0 ? 'text-warn' : 'text-ok'}`}>
              {data.modules_with_gaps}
            </div>
            <div className="text-xs text-muted mt-2">
              Requires immediate action to reach full security posture.
            </div>
          </motion.div>
        </div>
      )}

      <div className="bg-panel border border-white/5 rounded-xl overflow-hidden shadow-2xl">
        <div className="p-4 border-b border-white/5 bg-white/5 flex flex-col md:flex-row gap-4 justify-between items-center">
          <div className="relative w-full md:w-96">
            <Icon name="search" size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input 
              type="text" 
              placeholder="Filter by module or category..."
              className="w-full bg-black/40 border border-white/10 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-accent/50 transition-colors"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          
          <div className="flex items-center gap-3 w-full md:w-auto">
            <label htmlFor="status-filter" className="text-xs text-muted font-bold uppercase whitespace-nowrap">Filter Status</label>
            <select 
              id="status-filter"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value as StatusFilter)}
              className="bg-black/40 border border-white/10 rounded-lg py-2 px-4 text-xs focus:outline-none focus:border-accent/50 appearance-none cursor-pointer"
            >
              <option value="all">All Statuses</option>
              <option value="complete">Complete</option>
              <option value="partial">Partial</option>
              <option value="missing">Missing</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 text-[10px] uppercase tracking-tighter font-black text-muted border-b border-white/5">
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('module')}>
                  Module {sortKey === 'module' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4">Category</th>
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('coverage_percent')}>
                  Coverage {sortKey === 'coverage_percent' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4">Check Integrity</th>
                <th className="p-4 cursor-pointer hover:text-text transition-colors" onClick={() => handleSort('status')}>
                  Status {sortKey === 'status' && (sortDir === 'asc' ? '↑' : '↓')}
                </th>
                <th className="p-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filtered.map((row) => (
   
                <tr key={row.module} className="group hover:bg-white/[0.02] transition-colors">
                  <td className="p-4">
                    <div className="font-bold text-sm text-text">{row.module}</div>
                  </td>
                  <td className="p-4">
                    <span className="text-[10px] font-mono text-accent bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                      {row.category}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className={`text-sm font-black ${
                      row.coverage_percent === 100 ? 'text-ok' : row.coverage_percent > 0 ? 'text-warn' : 'text-bad'
                    }`}>
                      {row.coverage_percent}%
                    </div>
                  </td>
                  <td className="p-4 w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${
                            row.coverage_percent === 100 ? 'bg-ok' : row.coverage_percent > 0 ? 'bg-warn' : 'bg-bad'
                          }`}
                          style={{ width: `${row.coverage_percent}%` }}
                        />
                      </div>
                      <span className="text-[9px] font-mono text-muted tabular-nums">
                        {row.covered_checks}/{row.total_checks}
                      </span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      row.status === 'complete' ? 'bg-ok/10 text-ok border border-ok/20' :
                      row.status === 'partial' ? 'bg-warn/10 text-warn border border-warn/20' :
                      'bg-bad/10 text-bad border border-bad/20'
                    }`}>
                      {row.status}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    {row.missing_checks > 0 && (
                      <button 
                        onClick={() => toggleExpand(row.module)}
                        className="p-1 hover:bg-white/10 rounded transition-colors text-muted hover:text-text"
                      >
                        <Icon name={expandedRows.has(row.module) ? 'chevronUp' : 'chevronDown'} size={16} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {filtered.length === 0 && (
            <div className="py-20">
              <EmptyState 
                title="No modules found" 
                description="Adjust your filters or search query to find specific detection modules." 
                icon="shield" 
              />
            </div>
          )}
        </div>
      </div>

      <AnimatePresence>
        {filtered.filter(r => r.missing_checks > 0 && expandedRows.has(r.module)).length > 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-bold flex items-center gap-2 px-2">
              <Icon name="alertTriangle" size={18} className="text-warn" />
              Critical Coverage Deficiencies
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filtered.filter(r => r.missing_checks > 0 && expandedRows.has(r.module)).map(row => (
                <motion.div
                  key={row.module}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="bg-panel border border-warn/20 p-4 rounded-xl relative overflow-hidden group"
                >
                  <div className="absolute top-0 right-0 w-32 h-32 bg-warn/5 -rotate-45 translate-x-16 -translate-y-16 pointer-events-none" />
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h4 className="font-bold text-text">{row.module}</h4>
                      <p className="text-[10px] text-muted uppercase tracking-wider">Module deficiency report</p>
                    </div>
                    <div className="bg-warn/10 text-warn text-[10px] font-bold px-2 py-0.5 rounded border border-warn/20">
                      -{row.missing_checks} Checks
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    {Array.from({ length: row.missing_checks }).map((_, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs text-muted/80 font-mono">
                        <span className="text-warn opacity-50">•</span>
                        <span>[CORE_CAP_ERR_{row.category.toUpperCase()}_{i + 1}] Missing coverage for edge-case validation</span>
                      </div>
                    ))}
                  </div>
                  
                  <div className="mt-4 pt-4 border-t border-white/5">
                    <button className="text-[10px] text-accent hover:underline font-bold uppercase tracking-widest">
                      View Mitigation Guide
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
