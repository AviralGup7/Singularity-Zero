import { useState, useMemo } from 'react';
import { Icon } from '@/components/ui/Icon';
import { EmptyState } from '@/components/ui/EmptyState';

export type StatusFilter = 'all' | 'complete' | 'partial' | 'missing';

interface GapFiltersProps {
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  statusFilter: StatusFilter;
  setStatusFilter: (filter: StatusFilter) => void;
}

export function GapFilters({ searchQuery, setSearchQuery, statusFilter, setStatusFilter }: GapFiltersProps) {
  return (
    <div className="p-4 border-b border-white/5 bg-white/5 flex flex-col md:flex-row gap-4 justify-between items-center">
      <div className="relative w-full md:w-96">
        <Icon name="search" size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="text"
          placeholder="Filter by module or category..."
          className="w-full bg-black/40 border border-white/10 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-accent/50 transition-colors"
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
          onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          className="bg-black/40 border border-white/10 rounded-lg py-2 px-4 text-xs focus:outline-none focus:border-accent/50 appearance-none cursor-pointer"
        >
          <option value="all">All Statuses</option>
          <option value="complete">Complete</option>
          <option value="partial">Partial</option>
          <option value="missing">Missing</option>
        </select>
      </div>
    </div>
  );
}

interface GapTableProps {
  filtered: {
    module: string;
    category: string;
    coverage_percent: number;
    covered_checks: number;
    total_checks: number;
    status: string;
    missing_checks: number;
    missing_check_details?: string[];
  }[];
  sortKey: string;
  sortDir: 'asc' | 'desc';
  handleSort: (key: string) => void;
  toggleExpand: (module: string) => void;
  expandedRows: Set<string>;
}

export function GapTable({ filtered, sortKey, sortDir, handleSort, toggleExpand, expandedRows }: GapTableProps) {
  return (
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
  );
}

interface GapDeficienciesProps {
  filtered: {
    module: string;
    category: string;
    missing_checks: number;
    missing_check_details?: string[];
  }[];
  expandedRows: Set<string>;
  setActiveMitigation: (mitigation: { module: string; category: string; missing: string[] }) => void;
}

export function GapDeficiencies({ filtered, expandedRows, setActiveMitigation }: GapDeficienciesProps) {
  const deficientRows = filtered.filter((r) => r.missing_checks > 0 && expandedRows.has(r.module));
  if (deficientRows.length === 0) return null;

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-bold flex items-center gap-2 px-2">
        <Icon name="alertTriangle" size={18} className="text-warn" />
        Critical Coverage Deficiencies
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {deficientRows.map((row) => (
          <div
            key={row.module}
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
              {row.missing_check_details && row.missing_check_details.length > 0 ? (
                row.missing_check_details.map((check, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 text-xs text-muted/80 font-mono bg-black/25 p-2 rounded border border-white/5"
                  >
                    <span className="text-warn mt-0.5">•</span>
                    <span className="text-left leading-relaxed">{check}</span>
                  </div>
                ))
              ) : (
                Array.from({ length: row.missing_checks }).map((_, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 text-xs text-muted/80 font-mono bg-black/25 p-2 rounded border border-white/5"
                  >
                    <span className="text-warn opacity-50">•</span>
                    <span>Missing capability validation check {i + 1}</span>
                  </div>
                ))
              )}
            </div>

            <div className="mt-4 pt-4 border-t border-white/5">
              <button
                onClick={() =>
                  setActiveMitigation({
                    module: row.module,
                    category: row.category,
                    missing: row.missing_check_details || [],
                  })
                }
                className="text-[10px] text-accent hover:underline font-bold uppercase tracking-widest flex items-center gap-1.5"
              >
                <Icon name="zap" size={10} />
                View Mitigation Guide & Patch
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
