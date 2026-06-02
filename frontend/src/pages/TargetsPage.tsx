import { useState, useMemo, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import type { Target } from '../types/api';
import { SkeletonTable } from '../components/ui/Skeleton';
import { Pagination } from '../components/ui/Pagination';
import { useApi } from '../hooks/useApi';
import { startJob, apiClient } from '../api/client';
import { useToast } from '../hooks/useToast';
import { UrlCollectionSystem } from '../components/UrlCollectionSystem';
import { Target as TargetIcon, ChevronDown, RefreshCw, AlertTriangle, X, Upload } from 'lucide-react';
import { PageHeader, GlassCard, AnimatedCounter, GlowProgress } from '../components/ui';

const PAGE_SIZE = 10;
   
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

interface TargetsResponse {
  targets: Target[];
}

interface TargetFilters {
  severities: Set<string>;
  status: 'all' | 'active' | 'inactive';
  minFindings: number;
  maxFindings: number;
  lastScanAfter: string;
  lastScanBefore: string;
}

interface ScanProgress {
  targetName: string;
  jobId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
}

function emptyFilters(): TargetFilters {
  return {
    severities: new Set(),
    status: 'all',
    minFindings: 0,
    maxFindings: Infinity,
    lastScanAfter: '',
    lastScanBefore: '',
  };
}

function hasActiveFilters(f: TargetFilters): boolean {
  return (
    f.severities.size > 0 ||
    f.status !== 'all' ||
    f.minFindings > 0 ||
    f.maxFindings !== Infinity ||
    f.lastScanAfter !== '' ||
    f.lastScanBefore !== ''
  );
}

function targetHasSeverity(t: Target, severities: Set<string>): boolean {
  if (severities.size === 0) return true;
  for (const sev of severities) {
    if (Number(Reflect.get(t.severity_counts || {}, sev) ?? 0) > 0) return true;
  }
  return false;
}

function targetIsActive(t: Target): boolean {
  return t.latest_run !== '' && t.latest_run !== '—';
}

export function TargetsPage() {
  const { data, loading, error, refetch } = useApi<TargetsResponse>('/api/targets');
   
  const [filter, setFilter] = useState('');
   
  const [debouncedFilter, setDebouncedFilter] = useState('');
   
  const [currentPage, setCurrentPage] = useState(1);
   
  const [filters, setFilters] = useState<TargetFilters>(emptyFilters());
   
  const [showFilters, setShowFilters] = useState(false);
   
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
   
  const [scanProgress, setScanProgress] = useState<Map<string, ScanProgress>>(new Map());
   
  const [isScanning, setIsScanning] = useState(false);
  const toast = useToast();

  // Semgrep Import Modal State
  const [showImportModal, setShowImportModal] = useState(false);
  const [importTargetName, setImportTargetName] = useState('');
  const [importFile, setImportFile] = useState<File | null>(null);
  const [isImporting, setIsImporting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedFilter(filter), 300);
    return () => clearTimeout(timer);
   
  }, [filter]);

  const filtered = useMemo(() => {
    const targets = data?.targets ?? [];
    return targets.filter((t) => {
      if (
        debouncedFilter &&
        !(t.name || '').toLowerCase().includes(debouncedFilter.toLowerCase()) &&
        !(t.top_finding_title || '').toLowerCase().includes(debouncedFilter.toLowerCase())
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
   
  }, [data?.targets, debouncedFilter, filters]);

  const paginatedTargets = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filtered.slice(start, start + PAGE_SIZE);
   
  }, [filtered, currentPage]);

  const toggleSeverity = useCallback((sev: string) => {
    setFilters(prev => {
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
    setSelectedTargets(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const selectAllOnPage = useCallback(() => {
    setSelectedTargets(prev => {
      const next = new Set(prev);
      const allSelected = paginatedTargets.every(t => next.has(t.name || ''));
      if (allSelected) {
        paginatedTargets.forEach(t => next.delete(t.name || ''));
      } else {
        paginatedTargets.forEach(t => next.add(t.name || ''));
      }
      return next;
    });
   
  }, [paginatedTargets]);

  const clearSelection = useCallback(() => {
    setSelectedTargets(new Set());
  }, []);

  // FIX-1: Replace N+1 sequential `await` loop with parallel `Promise.allSettled`
  // so bulk rescans fire concurrently. For >20 targets consider adding a
  // concurrency pool (e.g. `p-limit`) to avoid overwhelming the backend.
  const handleBulkRescan = useCallback(async () => {
    if (selectedTargets.size === 0) return;
    setIsScanning(true);
    const progress = new Map<string, ScanProgress>();
    selectedTargets.forEach(name => {
      progress.set(name, { targetName: name, jobId: '', status: 'pending', progress: 0 });
    });
    setScanProgress(progress);

    const targetList = Array.from(selectedTargets);
    targetList.forEach(name => {
      const p = progress.get(name);
      if (p) {
        progress.set(name, { ...p, status: 'running', progress: 10 });
      }
    });
    setScanProgress(new Map(progress));

    await Promise.allSettled(
      targetList.map(name =>
        (async () => {
          try {
            const job = await startJob({
              base_url: `https://${name}`,
              mode: 'quick',
       
              modules: ['subdomain_enum', 'url_discovery', 'port_scan', 'httpx', 'nuclei'],
            });
            const p = progress.get(name);
            if (p) {
              progress.set(name, { ...p, jobId: job.id, status: 'running', progress: 50 });
            }
            setScanProgress(new Map(progress));
            toast.info(`Scan started for ${name}: ${job.id}`);
          } catch (err) {
            const p = progress.get(name);
            if (p) {
              progress.set(name, { ...p, status: 'failed', progress: 0 });
            }
            setScanProgress(new Map(progress));
            toast.error(`Failed to scan ${name}: ${err instanceof Error ? err.message : 'Unknown error'}`);
          }
        })()
      )
    );

    targetList.forEach(name => {
      const p = progress.get(name);
      if (p && p.status === 'running') {
        progress.set(name, { ...p, status: 'completed', progress: 100 });
      }
    });
    setScanProgress(new Map(progress));
    setIsScanning(false);
    setSelectedTargets(new Set());
    refetch();
   
  }, [selectedTargets, toast, refetch]);

  const allOnPageSelected = paginatedTargets.length > 0 && paginatedTargets.every(t => selectedTargets.has(t.name || ''));

  const activeFilterChips: { label: string; onRemove: () => void }[] = [];

  filters.severities.forEach(sev => {
    activeFilterChips.push({
      label: `Severity: ${sev}`,
      onRemove: () => toggleSeverity(sev),
    });
  });

  if (filters.status !== 'all') {
    activeFilterChips.push({
      label: `Status: ${filters.status}`,
      onRemove: () => setFilters(prev => ({ ...prev, status: 'all' })),
    });
  }

  if (filters.minFindings > 0) {
    activeFilterChips.push({
      label: `Min findings: ${filters.minFindings}`,
      onRemove: () => setFilters(prev => ({ ...prev, minFindings: 0 })),
    });
  }

  if (filters.maxFindings !== Infinity) {
    activeFilterChips.push({
      label: `Max findings: ${filters.maxFindings}`,
      onRemove: () => setFilters(prev => ({ ...prev, maxFindings: Infinity })),
    });
  }

  if (filters.lastScanAfter) {
    activeFilterChips.push({
      label: `Scanned after: ${filters.lastScanAfter}`,
      onRemove: () => setFilters(prev => ({ ...prev, lastScanAfter: '' })),
    });
  }

  if (filters.lastScanBefore) {
    activeFilterChips.push({
      label: `Scanned before: ${filters.lastScanBefore}`,
      onRemove: () => setFilters(prev => ({ ...prev, lastScanBefore: '' })),
    });
  }

  const handleFileChangeForImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportFile(file);
    const defaultName = file.name.replace(/\.[^/.]+$/, "");
    setImportTargetName(defaultName);
    setShowImportModal(true);
    e.target.value = '';
  };

  const executeSemgrepImport = async () => {
    if (!importFile || !importTargetName.trim()) return;
    setIsImporting(true);
    const formData = new FormData();
    formData.append('file', importFile);

    try {
      await apiClient.post(`/api/imports/semgrep?target_name=${encodeURIComponent(importTargetName.trim())}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      toast.success(`Successfully imported Semgrep results for ${importTargetName}`);
      refetch();
      setShowImportModal(false);
      setImportFile(null);
      setImportTargetName('');
    } catch (err) {
      toast.error(`Import failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsImporting(false);
    }
  };

  const getGlowProgressVariant = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'failed': return 'danger';
      case 'running': return 'cyber';
      default: return 'default';
    }
  };

  // KPI calculations
  const targetsCount = data?.targets?.length ?? 0;
  const criticalFindings = useMemo(() => {
    return (data?.targets ?? []).reduce((acc, t) => {
      return acc + (Number(t.severity_counts?.critical) || 0);
    }, 0);
  }, [data?.targets]);
  const avgFindings = useMemo(() => {
    const targets = data?.targets ?? [];
    if (!targets.length) return 0;
    const totalFindings = targets.reduce((acc, t) => acc + (t.finding_count ?? 0), 0);
    return Math.round(totalFindings / targets.length);
  }, [data?.targets]);

  if (loading) return <SkeletonTable rows={5} />;

  if (error) {
    return (
      <div className="card error">
        <h2><AlertTriangle size={16} className="inline-block mr-1" /> Error</h2>
        <p>{error.message}</p>
        <button onClick={() => { void refetch(); }} className="btn btn-primary">Retry</button>
      </div>
    );
  }

  return (
    <div className="targets-page space-y-6">
      <PageHeader
        icon={<TargetIcon size={20} />}
        title="Targets"
        subtitle="Manage scan targets and view results"
        actions={
          <div className="flex items-center gap-3">
            <label className="btn btn-sm btn-secondary cursor-pointer flex items-center gap-1.5">
              <Upload size={14} />
              <span>Import Semgrep</span>
              <input type="file" accept=".json" className="hidden" onChange={handleFileChangeForImport} />
            </label>
            <input
              type="text"
              placeholder="Filter targets..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="search-input"
              aria-label="Filter targets by name or finding title"
              data-testid="targets-filter"
            />
            <button
              type="button"
              className={`btn btn-sm ${showFilters ? 'btn-primary' : ''} flex items-center gap-1`}
              onClick={() => setShowFilters(!showFilters)}
            >
              <ChevronDown size={14} className={`transform transition-transform duration-200 ${showFilters ? 'rotate-180' : ''}`} />
              <span>Filters</span>
            </button>
          </div>
        }
      />

      {/* 3-column KPI summary row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <GlassCard variant="glow" delay={0.05}>
          <div className="flex flex-col">
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">Total Targets</span>
            <span className="text-3xl font-bold mt-1 text-[var(--text-primary)]">
              <AnimatedCounter value={targetsCount} />
            </span>
          </div>
        </GlassCard>
        <GlassCard variant="glow" delay={0.1}>
          <div className="flex flex-col">
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">Critical Findings</span>
            <span className="text-3xl font-bold mt-1 text-[var(--bad)]">
              <AnimatedCounter value={criticalFindings} />
            </span>
          </div>
        </GlassCard>
        <GlassCard variant="glow" delay={0.15}>
          <div className="flex flex-col">
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">Average Findings</span>
            <span className="text-3xl font-bold mt-1 text-[var(--accent)]">
              <AnimatedCounter value={avgFindings} />
            </span>
          </div>
        </GlassCard>
      </div>

      <UrlCollectionSystem />

      <AnimatePresence>
        {selectedTargets.size > 0 && (
          <motion.div
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.25, ease: EASE_OUT }}
          >
            <div className="bulk-action-bar">
              <div className="bulk-action-info">
                <span>{selectedTargets.size} target{selectedTargets.size > 1 ? 's' : ''} selected</span>
                <button className="btn btn-sm btn-primary flex items-center gap-1.5" onClick={handleBulkRescan} disabled={isScanning}>
                  {isScanning ? (
                    <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                  ) : (
                    <RefreshCw size={14} />
                  )}
                  <span>{isScanning ? 'Scanning...' : 'Re-scan Selected'}</span>
                </button>
                <button className="bulk-clear-btn" onClick={clearSelection}>Clear selection</button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {scanProgress.size > 0 && (
        <div className="scan-progress-panel space-y-3">
          <h4 className="scan-progress-title">Scan Progress</h4>
          {Array.from(scanProgress.values()).map(p => (
            <div key={p.targetName} className="scan-progress-item flex items-center gap-4 p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)]">
              <span className="scan-progress-target font-medium w-36 truncate">{p.targetName}</span>
              <div className="flex-1">
                <GlowProgress
                  value={p.progress}
                  variant={getGlowProgressVariant(p.status)}
                  animated={p.status === 'running'}
                  size="sm"
                  showLabel
                />
              </div>
              <span className={`scan-progress-status text-xs font-semibold px-2 py-0.5 rounded-full capitalize ${
                p.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' :
                p.status === 'failed' ? 'bg-rose-500/10 text-rose-400' :
                p.status === 'running' ? 'bg-cyan-500/10 text-cyan-400 animate-pulse' :
                'bg-gray-500/10 text-gray-400'
              }`}>{p.status}</span>
              {p.jobId && <span className="scan-progress-job text-xs text-[var(--text-tertiary)] tabular-nums">{p.jobId}</span>}
            </div>
          ))}
        </div>
      )}

      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: EASE_OUT }}
            className="overflow-hidden"
          >
            <div className="card card-padded multi-filter-panel mb-6">
              <div className="multi-filter-grid">
                <div className="filter-group">
                  <span className="filter-group-label">Severity</span>
                  <div className="filter-checkboxes">
                    {SEVERITIES.map(sev => (
                      <label key={sev} className="filter-checkbox-label">
                        <input
                          type="checkbox"
                          checked={filters.severities.has(sev)}
                          onChange={() => toggleSeverity(sev)}
                        />
                        <span className={`severity-dot severity-${sev}`}>{sev}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="filter-group">
                  <span className="filter-group-label">Status</span>
                  <div className="filter-radio-group">
                    {(['all', 'active', 'inactive'] as const).map(status => (
                      <label key={status} className="filter-radio-label">
                        <input
                          type="radio"
                          name="target-status"
                          checked={filters.status === status}
                          onChange={() => setFilters(prev => ({ ...prev, status }))}
                        />
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </label>
                    ))}
                  </div>
                </div>

                <div className="filter-group">
                  <span className="filter-group-label">Finding Count</span>
                  <div className="filter-range-row">
                    <input
                      id="filter-min-findings"
                      type="number"
                      min={0}
                      placeholder="Min"
                      value={filters.minFindings || ''}
                      onChange={e => setFilters(prev => ({ ...prev, minFindings: parseInt(e.target.value, 10) || 0 }))}
                      className="form-input form-input-sm"
                      aria-label="Minimum findings"
                    />
                    <span className="filter-range-sep">to</span>
                    <input
                      id="filter-max-findings"
                      type="number"
                      min={0}
                      placeholder="Max"
                      value={filters.maxFindings === Infinity ? '' : filters.maxFindings}
                      onChange={e => setFilters(prev => ({ ...prev, maxFindings: parseInt(e.target.value, 10) || Infinity }))}
                      className="form-input form-input-sm"
                      aria-label="Maximum findings"
                    />
                  </div>
                </div>

                <div className="filter-group">
                  <span className="filter-group-label">Last Scan Date</span>
                  <div className="filter-date-row">
                    <input
                      type="date"
                      value={filters.lastScanAfter}
                      onChange={e => setFilters(prev => ({ ...prev, lastScanAfter: e.target.value }))}
                      className="form-input form-input-sm"
                      aria-label="Scan date from"
                    />
                    <span className="filter-range-sep">to</span>
                    <input
                      type="date"
                      value={filters.lastScanBefore}
                      onChange={e => setFilters(prev => ({ ...prev, lastScanBefore: e.target.value }))}
                      className="form-input form-input-sm"
                      aria-label="Scan date to"
                    />
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {activeFilterChips.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="active-filters-bar flex items-center justify-between mb-6"
          >
            <div className="active-filters-chips flex flex-wrap gap-2">
              <AnimatePresence>
                {activeFilterChips.map((chip) => (
                  <motion.span
                    key={chip.label}
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    className="filter-chip flex items-center gap-1"
                  >
                    <span>{chip.label}</span>
                    <button
                      type="button"
                      className="filter-chip-remove flex items-center justify-center hover:text-[var(--bad)] transition-colors"
                      onClick={chip.onRemove}
                      aria-label={`Remove filter: ${chip.label}`}
                    >
                      <X size={12} />
                    </button>
                  </motion.span>
                ))}
              </AnimatePresence>
            </div>
            <button
              type="button"
              className="btn btn-sm btn-danger"
              onClick={clearAllFilters}
            >
              Clear all filters
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {filtered.length === 0 ? (
        <div className="card empty">
          <p>No targets found{hasActiveFilters(filters) ? ' matching the active filters' : ''}.</p>
        </div>
      ) : (
        <>
          <div className="targets-table-container">
            <table className="targets-table">
              <thead>
                <tr>
                  <th className="bulk-select-col">
                    <input
                      type="checkbox"
                      checked={allOnPageSelected}
                      onChange={selectAllOnPage}
                      aria-label="Select all on page"
                    />
                  </th>
                  <th>Target</th>
                  <th>Latest Run</th>
                  <th>Findings</th>
                  <th>URLs</th>
                  <th>Severity</th>
                  <th>Attack Chains</th>
                  <th>Validated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedTargets.map((target, index) => (
                  <tr
                    key={target.name || target.href || `target-${currentPage}-${index}`}
                    className={`transition-all duration-200 hover:-translate-y-0.5 hover:bg-white/5 ${
                      selectedTargets.has(target.name || '') ? 'row-selected bg-white/5' : ''
                    }`}
                  >
                    <td className="bulk-select-col">
                      <input
                        type="checkbox"
                        checked={selectedTargets.has(target.name || '')}
                        onChange={() => toggleTargetSelection(target.name || '')}
                        aria-label={`Select ${target.name || 'unknown'}`}
                      />
                    </td>
                    <td className="target-name-cell">
                      <span className="target-name">{target.name || '—'}</span>
                      {(target.new_findings || 0) > 0 && (
                        <span className="new-badge">+{target.new_findings} new</span>
                      )}
                    </td>
                    <td>{target.latest_run || '—'}</td>
                    <td className="findings-cell">
                      <span className="findings-count">{target.finding_count ?? '—'}</span>
                    </td>
                    <td>{target.url_count ?? '—'}</td>
                    <td>
                      <div className="severity-inline">
                        {Object.entries(target.severity_counts || {})
             
                          .filter(([, count]) => count > 0)
     
                          .map(([sev, count]) => (
                            <span key={sev} className={`severity-dot severity-${sev}`} aria-label={`${sev}: ${count}`}>
                              {sev[0].toUpperCase()}: {count}
                            </span>
                          ))}
                      </div>
                    </td>
                    <td>{(target.attack_chain_count || 0) > 0 ? `${target.attack_chain_count} (${target.max_attack_chain_confidence || '—'})` : '—'}</td>
                    <td>{target.validated_leads ?? '—'}</td>
                    <td className="actions-cell">
                      {target.name && (
                        <div className="flex gap-2">
                          <Link to={`/cockpit?target=${target.name}`} className="btn btn-small btn-accent-outline" title="View 3D Threat Graph">
                            Cockpit
                          </Link>
                          <button 
                            type="button"
                            onClick={async () => {
                              try {
                                const token = sessionStorage.getItem('auth_token');
                                const headers: Record<string, string> = {};
                                if (token) {
                                  headers['Authorization'] = `Bearer ${token}`;
                                }
                                const response = await fetch(`/api/reports/compliance/pdf?target=${encodeURIComponent(target.name!)}`, { headers });
                                if (!response.ok) {
                                  throw new Error('Compliance download failed');
                                }
                                const blob = await response.blob();
                                const url = window.URL.createObjectURL(blob);
                                const link = document.createElement('a');
                                link.href = url;
                                link.download = `${target.name}-compliance.pdf`;
                                link.click();
                                window.URL.revokeObjectURL(url);
                              } catch (err) {
                                console.error('Failed to download compliance report:', err);
                                toast.error('Failed to download compliance report');
                              }
                            }}
                            className="btn btn-small btn-secondary" 
                            title="Download SOC 2 / PCI-DSS Attestation"
                          >
                            Compliance
                          </button>
                          <button 
                            className="btn btn-small btn-secondary" 
                            title="Export CSV Findings"
                            onClick={async () => {
                              try {
                                const { exportTargetFindings } = await import('../api/client');
                                const blob = await exportTargetFindings(target.name!, 'csv');
                                const url = window.URL.createObjectURL(blob);
                                const link = document.createElement('a');
                                link.href = url;
                                link.download = `${target.name}-findings.csv`;
                                link.click();
                                window.URL.revokeObjectURL(url);
                              } catch (_err) {
                                toast.error('Export failed');
                              }
                            }}
                          >
                            Export
                          </button>
                        </div>
                      )}
                      {target.href && (
                        <a href={target.href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
                          Runs
                        </a>
                      )}
                      {target.latest_report_href && (
                        <a href={target.latest_report_href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
                          Report
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={currentPage}
            total={filtered.length}
            onPageChange={setCurrentPage}
            pageSize={PAGE_SIZE}
          />
        </>
      )}

      {/* Import Semgrep Modal */}
      <AnimatePresence>
        {showImportModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => {
                if (!isImporting) {
                  setShowImportModal(false);
                  setImportFile(null);
                  setImportTargetName('');
                }
              }}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            
            {/* Modal Card */}
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              transition={{ duration: 0.3, ease: EASE_OUT }}
              className="relative w-full max-w-md overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2xl"
              style={{ backdropFilter: 'blur(20px)' }}
            >
              <button
                type="button"
                onClick={() => {
                  setShowImportModal(false);
                  setImportFile(null);
                  setImportTargetName('');
                }}
                disabled={isImporting}
                className="absolute top-4 right-4 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              >
                <X size={18} />
              </button>

              <div className="flex items-center gap-3 mb-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                  <Upload size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-[var(--text-primary)]">Import Semgrep Results</h3>
                  <p className="text-xs text-[var(--text-secondary)]">Upload scan results JSON to create/update target</p>
                </div>
              </div>

              <div className="space-y-4">
                {importFile && (
                  <div className="p-3 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-xs text-[var(--text-secondary)]">
                    <span className="font-semibold block text-[var(--text-primary)] mb-1">Selected File:</span>
                    <span className="truncate block font-mono">{importFile.name}</span>
                    <span className="text-[10px] text-[var(--text-tertiary)]">({(importFile.size / 1024).toFixed(1)} KB)</span>
                  </div>
                )}

                <div className="space-y-1.5">
                  <label htmlFor="import-target-name" className="text-xs font-semibold text-[var(--text-secondary)]">Target Name</label>
                  <input
                    id="import-target-name"
                    type="text"
                    placeholder="e.g. example.com"
                    value={importTargetName}
                    onChange={(e) => setImportTargetName(e.target.value)}
                    className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--accent)] focus:shadow-[0_0_0_2px_var(--accent-soft)] transition-all duration-200"
                    disabled={isImporting}
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowImportModal(false);
                      setImportFile(null);
                      setImportTargetName('');
                    }}
                    disabled={isImporting}
                    className="btn btn-sm btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={executeSemgrepImport}
                    disabled={isImporting || !importTargetName.trim()}
                    className="btn btn-sm btn-primary flex items-center gap-1.5"
                  >
                    {isImporting ? (
                      <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full" />
                    ) : (
                      <Upload size={14} />
                    )}
                    <span>{isImporting ? 'Importing...' : 'Import'}</span>
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
