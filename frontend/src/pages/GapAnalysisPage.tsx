import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { Icon } from '../components/ui/Icon';
import { EmptyState } from '../components/ui';
import { useGapAnalysis, useGapAnalysisSorting, useGapAnalysisFiltering } from '../hooks/useGapAnalysis';
import { GapDeficiencies } from '../components/gap-analysis/GapAnalysisComponents';
import { MitigationModal } from '../components/gap-analysis/MitigationModal';
import { ROUTES } from '@/config/paths';


export function GapAnalysisPage() {
  const { data, targets, selectedTarget, setSelectedTarget, loading, refreshing, error, loadData, handleRefresh } =
    useGapAnalysis();
  const { filtered: sortedFiltered, sortKey, sortDir, handleSort } = useGapAnalysisSorting({ data });
  const {
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
    expandedRows,
    toggleExpand,
    filtered,
  } = useGapAnalysisFiltering({ filtered: sortedFiltered });

  const [activeMitigation, setActiveMitigation] = useState<{ module: string; category: string; missing: string[] } | null>(null);
  const [copied, setCopied] = useState(false);

  const handleCopyPatch = useCallback((patchText: string) => {
    navigator.clipboard.writeText(patchText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  if (loading && !data) {
    return (
      <div className="p-6 space-y-6">
        <div className="h-10 w-48 animate-pulse rounded bg-surface-2" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="h-32 animate-pulse rounded bg-surface-2" />
          <div className="h-32 animate-pulse rounded bg-surface-2" />
          <div className="h-32 animate-pulse rounded bg-surface-2" />
        </div>
        <div className="h-96 animate-pulse rounded bg-surface-2" />
      </div>
    );
  }

  const isNoTelemetryState =
    data &&
    data.results.length > 0 &&
    data.overall_coverage === 0 &&
    data.modules_with_gaps === data.total_modules;

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

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center gap-2 bg-surface-2 border border-line rounded-lg px-3 py-1.5 focus-within:border-accent/50 transition-colors">
            <span className="text-[10px] text-muted font-bold uppercase tracking-wider whitespace-nowrap">Select Target:</span>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="bg-transparent text-sm font-bold text-text focus:outline-none cursor-pointer pr-6 appearance-none"
              style={{
                backgroundImage:
                  'url("data:image/svg+xml,%3csvg xmlns=\'http://www.w3.org/2000/svg\' fill=\'none\' viewBox=\'0 0 20 20\'%3e%3cpath stroke=\'%23a3a3a3\' stroke-linecap=\'round\' stroke-linejoin=\'round\' stroke-width=\'1.5\' d=\'M6 8l4 4 4-4\'/%3e%3c/svg%3e")',
                backgroundPosition: 'right center',
                backgroundSize: '1.2em 1.2em',
                backgroundRepeat: 'no-repeat',
              }}
            >
              <option value="all" className="bg-panel text-text font-bold">
                All Targets (Aggregated)
              </option>
              {targets.map((t) => (
                <option key={t} value={t} className="bg-panel text-text">
                  {t}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className={`btn btn-secondary flex items-center gap-2 ${refreshing ? 'animate-pulse' : ''}`}
          >
            <Icon name="refresh" size={16} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Analyzing...' : 'Refresh Analysis'}
          </button>
        </div>
      </header>

      {error && (
        <div className="p-4 bg-bad/10 border border-bad/20 rounded-xl text-bad text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg backdrop-blur-md animate-in fade-in duration-300">
          <div className="flex items-center gap-3">
            <Icon name="alertTriangle" size={18} className="text-bad animate-bounce" />
            <span className="font-medium">{error}</span>
          </div>
          <button
            onClick={() => loadData()}
            className="btn btn-secondary px-3 py-1.5 text-xs font-bold uppercase tracking-wider bg-bad/10 hover:bg-bad/20 text-bad border border-bad/25 hover:border-bad/40 rounded-lg transition-all duration-200 flex items-center gap-1.5 self-end sm:self-auto"
          >
            <Icon name="refresh" size={12} />
            Try Again
          </button>
        </div>
      )}

      {isNoTelemetryState && (
        <div className="glass-panel p-8 rounded-2xl border border-warn/20 bg-warn/5 text-center space-y-4">
          <div className="flex justify-center">
            <div className="p-3 rounded-full bg-warn/10 border border-warn/20 text-warn">
              <Icon name="activity" size={28} />
            </div>
          </div>
          <div>
            <h3 className="text-lg font-bold text-text">No Scan Telemetry Available</h3>
            <p className="text-sm text-muted mt-2 max-w-xl mx-auto leading-relaxed">
              Gap analysis compares completed scan runs against the global detection registry.
              Right now there are no scan results with coverage data for the selected target,
              so every module appears as <span className="font-mono text-bad">missing</span> by default.
              This does <span className="font-semibold text-text">not</span> mean all 46 modules are broken —
              it means there is nothing to compare yet.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="btn btn-primary flex items-center gap-2"
            >
              <Icon name="refresh" size={16} className={refreshing ? 'animate-spin' : ''} />
              {refreshing ? 'Analyzing...' : 'Run / Refresh Analysis'}
            </button>
            <Link
              to={ROUTES.TARGETS}
              className="btn btn-secondary flex items-center gap-2"
            >
              <Icon name="target" size={16} />
              Go to Targets
            </Link>
          </div>
          <p className="text-[11px] text-muted">
            After a scan completes, re-open this page or press <span className="font-mono bg-surface-2 px-1.5 py-0.5 rounded border border-line">Refresh Analysis</span> to see real coverage data.
          </p>
        </div>
      )}

      {data && !isNoTelemetryState && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-stat-card"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Overall Coverage</div>
            <div
              className={`font-semibold ${
                data.overall_coverage > 80 ? 'text-ok' : data.overall_coverage > 50 ? 'text-warn' : 'text-bad'
              }`}
              style={{ fontSize: 'var(--text-card-value)' }}
            >
              {data.overall_coverage}%
            </div>
            <div className="mt-4 h-1.5 w-full bg-surface-hover rounded-full overflow-hidden">
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
            className="glass-stat-card"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Module Integrity</div>
            <div className="font-semibold text-text" style={{ fontSize: 'var(--text-card-value)' }}>
              {data.total_modules - data.modules_with_gaps}
              <span className="text-lg text-muted font-normal ml-2">/ {data.total_modules} OK</span>
            </div>
            <div className="text-xs text-muted mt-2 italic">
              Modules meeting 100% of detection registry requirements.
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-stat-card"
          >
            <div className="text-muted text-xs uppercase tracking-widest font-bold mb-2">Identified Gaps</div>
            <div className={`font-semibold ${data.modules_with_gaps > 0 ? 'text-warn' : 'text-ok'}`} style={{ fontSize: 'var(--text-card-value)' }}>
              {data.modules_with_gaps}
            </div>
            <div className="text-xs text-muted mt-2">
              Requires immediate action to reach full security posture.
            </div>
          </motion.div>
        </div>
      )}

      {data && !isNoTelemetryState && (
      <div className="bg-panel border border-line rounded-xl overflow-hidden shadow-2xl">
        <div className="p-4 border-b border-line bg-surface-hover flex flex-col md:flex-row gap-4 justify-between items-center">
          <div className="relative w-full md:w-96">
            <Icon name="search" size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              placeholder="Filter by module or category..."
              className="w-full bg-surface-2 border border-line rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-accent/50 transition-colors"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <label htmlFor="status-filter" className="text-xs text-muted font-bold uppercase whitespace-nowrap">
              Filter Status
            </label>
            <select
              id="status-filter"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as 'all' | 'complete' | 'partial' | 'missing')}
              className="bg-surface-2 border border-line rounded-lg py-2 px-4 text-xs focus:outline-none focus:border-accent/50 appearance-none cursor-pointer"
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
              <tr className="bg-surface-hover text-[10px] uppercase tracking-tighter font-black text-muted border-b border-line">
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
                <tr key={row.module} className="group hover:bg-surface-hover transition-colors">
                  <td className="p-4">
                    <div className="font-bold text-sm text-text">{row.module}</div>
                  </td>
                  <td className="p-4">
                    <span className="text-[10px] font-mono text-accent bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                      {row.category}
                    </span>
                  </td>
                  <td className="p-4">
                    <div
                      className={`text-sm font-black ${
                        row.coverage_percent === 100 ? 'text-ok' : row.coverage_percent > 0 ? 'text-warn' : 'text-bad'
                      }`}
                    >
                      {row.coverage_percent}%
                    </div>
                  </td>
                  <td className="p-4 w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1 bg-surface-hover rounded-full overflow-hidden">
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
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                        row.status === 'complete'
                          ? 'bg-ok/10 text-ok border border-ok/20'
                          : row.status === 'partial'
                          ? 'bg-warn/10 text-warn border border-warn/20'
                          : 'bg-bad/10 text-bad border border-bad/20'
                      }`}
                    >
                      {row.status}
                    </span>
                  </td>
                  <td className="p-4 text-right">
                    {row.missing_checks > 0 && (
                      <button
                        onClick={() => toggleExpand(row.module)}
                        className="p-1 hover:bg-surface-2 rounded transition-colors text-muted hover:text-text"
                      >
                        <Icon name={expandedRows.has(row.module) ? 'chevronUp' : 'chevronDown'} size={16} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filtered.length === 0 && !error && (
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
      )}

      {data && !isNoTelemetryState && (
      <GapDeficiencies filtered={filtered} expandedRows={expandedRows} setActiveMitigation={setActiveMitigation} />
      )}

      <MitigationModal
        activeMitigation={activeMitigation}
        selectedTarget={selectedTarget}
        onClose={() => setActiveMitigation(null)}
        onCopyPatch={handleCopyPatch}
        copied={copied}
      />
    </div>
  );
}
