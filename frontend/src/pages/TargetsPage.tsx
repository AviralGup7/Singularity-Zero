import { motion, AnimatePresence } from 'framer-motion';
import { useState, useCallback, useMemo } from 'react';
import { SkeletonTable } from '@/components/ui/Skeleton';
import { Pagination } from '@/components/ui/Pagination';
import { useApi } from '@/hooks/useApi';
import { useDebouncedFilter } from '@/hooks/useDebouncedFilter';
import { UrlCollectionSystem } from '@/components/targets/UrlCollectionSystem';
import { Target as TargetIcon, ChevronDown, AlertTriangle, X, Upload, ShieldCheck } from 'lucide-react';
import { PageHeader, GlassCard, AnimatedCounter } from '@/components/ui';
import { useTargetsKPIs } from '@/hooks/useTargetsKPIs';
import type { TargetsResponse } from '@/hooks/useTargets';
import { PAGE_SIZE } from '@/hooks/useTargetPagination';
import { useTargetPagination } from '@/hooks/useTargetPagination';
import { useTargetFilters, hasActiveFilters, useFilteredTargets } from '@/hooks/useTargetFilters';
import { useScanProgress } from '@/hooks/useScanProgress';
import { TargetsFilterPanel } from '@/components/targets/TargetsFilterPanel';
import { TargetsBulkActionBar } from '@/components/targets/TargetsBulkActionBar';
import { ScanProgressPanel } from '@/components/targets/ScanProgressPanel';
import { TargetTableRow } from '@/components/targets/TargetTableRow';
import { ImportModal } from '@/components/targets/ImportModal';
import { useSemgrepImport } from '@/hooks/useSemgrepImport';
import { ScopeImportModal } from '@/components/scope/ScopeImportModal';
import { useScopeStore } from '@/stores/scopeStore';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function TargetsPage() {
  const { data, loading, error, refetch } = useApi<TargetsResponse>('/api/targets');
  const { targetsCount, criticalFindings, avgFindings } = useTargetsKPIs(data || undefined);
  const { filters, setFilters, showFilters, setShowFilters, toggleSeverity, clearAllFilters, activeFilterChips } =
    useTargetFilters();
  const { filter, setFilter, debouncedFilter } = useDebouncedFilter();
  const { isScanning, progressList, startScan, updateProgress } =
    useScanProgress();
  const { importTargetName, setImportTargetName, importFile, handleFileChange, executeImport, resetImport, isImporting } =
    useSemgrepImport();

  const [scopeModalOpen, setScopeModalOpen] = useState(false);
  const scopeImported = useScopeStore((s) => Boolean(s.parsed));
  const scopeProgram = useScopeStore((s) => s.programHandle);

  const filtered = useFilteredTargets(data?.targets ?? [], filters, debouncedFilter);
  const { currentPage: pagingCurrentPage, setCurrentPage: setPagingCurrentPage, paginated: paging } = useTargetPagination(filtered.length, PAGE_SIZE);
  const paginatedTargets = filtered.slice(paging.start, paging.end);

  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());

  const toggleTargetSelection = useCallback((name: string) => {
    setSelectedTargets((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedTargets(new Set());
  }, []);

  const allOnPageSelected = useMemo(() => {
    if (paginatedTargets.length === 0) return false;
    return paginatedTargets.every((t) => selectedTargets.has(t.name || ''));
  }, [paginatedTargets, selectedTargets]);

  const selectAllOnPage = useCallback(() => {
    setSelectedTargets((prev) => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        paginatedTargets.forEach((t) => next.delete(t.name || ''));
      } else {
        paginatedTargets.forEach((t) => next.add(t.name || ''));
      }
      return next;
    });
  }, [paginatedTargets, allOnPageSelected]);

  const handleBulkRescan = useCallback(async () => {
    if (selectedTargets.size === 0) return;
    const targetsArray = Array.from(selectedTargets);
    startScan(targetsArray);
    try {
      const { startJob } = await import('@/api/jobs');
      for (const name of targetsArray) {
        try {
          const job = await startJob({ base_url: name, mode: 'safe', modules: ['subdomain_enum', 'url_discovery', 'port_scan', 'httpx'] });
          updateProgress(name, { jobId: job.id, status: 'running', progress: 10 });
        } catch {
          updateProgress(name, { status: 'failed', progress: 0 });
        }
      }
      clearSelection();
    } catch (err) {
      console.error('Bulk rescan error:', err);
    }
  }, [selectedTargets, startScan, updateProgress, clearSelection]);

  return (
    <div className="targets-page space-y-6">
      <PageHeader
        icon={<TargetIcon size={20} />}
        title="Targets"
        subtitle="Manage scan targets and view results"
        actions={
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setScopeModalOpen(true)}
              className={`btn btn-sm ${scopeImported ? 'btn-accent-outline' : 'btn-secondary'} flex items-center gap-1.5`}
              data-testid="import-scope-btn"
              title={scopeImported ? `Scope loaded for ${scopeProgram || 'program'}` : 'Import program scope (HackerOne, Bugcrowd, Intigriti)'}
            >
              <ShieldCheck size={14} />
              <span>{scopeImported ? 'Scope Loaded' : 'Import Scope'}</span>
            </button>
            <label className="btn btn-sm btn-secondary cursor-pointer flex items-center gap-1.5">
              <Upload size={14} />
              <span>Import Semgrep</span>
              <input
                type="file"
                accept=".json"
                className="hidden"
                onChange={handleFileChange}
              />
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

      <TargetsBulkActionBar
        selectedTargets={selectedTargets}
        isScanning={isScanning}
        onClearSelection={clearSelection}
        onBulkRescan={handleBulkRescan}
      />

      <ScanProgressPanel scanProgress={progressList} />

      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: EASE_OUT }}
            className="overflow-hidden"
          >
            <TargetsFilterPanel
              filters={filters}
              toggleSeverity={toggleSeverity}
              setFilters={setFilters}
            />
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

      {loading ? (
        <SkeletonTable rows={5} />
      ) : error ? (
        <div className="card error">
          <h2><AlertTriangle size={16} className="inline-block mr-1" /> Error</h2>
          <p>{error.message}</p>
          <button onClick={() => { void refetch(); }} className="btn btn-primary">Retry</button>
        </div>
      ) : filtered.length === 0 ? (
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
                  <TargetTableRow
                    key={target.name || target.href || `target-${pagingCurrentPage}-${index}`}
                    target={target}
                    selectedTargets={selectedTargets}
                    toggleTargetSelection={toggleTargetSelection}
                    currentPage={pagingCurrentPage}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={pagingCurrentPage}
            total={filtered.length}
            onPageChange={setPagingCurrentPage}
            pageSize={PAGE_SIZE}
          />
        </>
      )}

      <ImportModal
        importFile={importFile}
        importTargetName={importTargetName}
        setImportTargetName={setImportTargetName}
        onClose={resetImport}
        onConfirm={() => executeImport(refetch)}
        isImporting={isImporting}
      />
      <ScopeImportModal
        open={scopeModalOpen}
        onClose={() => setScopeModalOpen(false)}
      />
    </div>
  );
}
