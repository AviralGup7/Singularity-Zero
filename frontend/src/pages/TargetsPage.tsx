import { useState, useMemo, useEffect, useCallback } from 'react';
import type { Target } from '../types/api';
import { SkeletonTable } from '../components/ui/Skeleton';
import { Pagination } from '../components/ui/Pagination';
import { useApi } from '../hooks/useApi';
import { startJob } from '../api/client';
import { useToast } from '../components/Toast';
import { UrlCollectionSystem } from '../components/UrlCollectionSystem';

const PAGE_SIZE = 10;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

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
    if (((t.severity_counts?.[sev]) || 0) > 0) return true;
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

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedFilter(filter), 300);
    return () => clearTimeout(timer);
  }, [filter]);

  const targets = data?.targets ?? [];

  // FIX: Removed dead debug useEffect (commented-out console.logs with no side effects)

  const filtered = useMemo(() => {
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
  }, [targets, debouncedFilter, filters]);

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

  const handleBulkRescan = useCallback(async () => {
    if (selectedTargets.size === 0) return;
    setIsScanning(true);
    const progress = new Map<string, ScanProgress>();
    selectedTargets.forEach(name => {
      progress.set(name, { targetName: name, jobId: '', status: 'pending', progress: 0 });
    });
    setScanProgress(progress);

    const targetList = Array.from(selectedTargets);
    for (const name of targetList) {
      progress.set(name, { targetName: name, jobId: '', status: 'running', progress: 10 });
      setScanProgress(new Map(progress));
      try {
        const job = await startJob({
          base_url: `https://${name}`,
          mode: 'quick',
          modules: ['subdomain_enum', 'url_discovery', 'port_scan', 'httpx', 'nuclei'],
        });
        progress.set(name, { targetName: name, jobId: job.id, status: 'running', progress: 50 });
        setScanProgress(new Map(progress));
        toast.info(`Scan started for ${name}: ${job.id}`);
      } catch (err) {
        progress.set(name, { targetName: name, jobId: '', status: 'failed', progress: 0 });
        setScanProgress(new Map(progress));
        toast.error(`Failed to scan ${name}: ${err instanceof Error ? err.message : 'Unknown error'}`);
      }
    }

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

  if (loading) return <SkeletonTable rows={5} />;

  if (error) {
    return (
      <div className="card error">
        <h2>⚠️ Error</h2>
        <p>{error.message}</p>
        <button onClick={() => { refetch(); }} className="btn btn-primary">Retry</button>
      </div>
    );
  }

  return (
    <div className="targets-page">
      <div className="page-header">
        <h2 data-focus-heading>🎯 Targets</h2>
        <div className="targets-header-actions">
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
            className={`btn btn-sm ${showFilters ? 'btn-primary' : ''}`}
            onClick={() => setShowFilters(!showFilters)}
          >
            🔽 Filters
          </button>
        </div>
      </div>

      <UrlCollectionSystem />

      {selectedTargets.size > 0 && (
        <div className="bulk-action-bar">
          <div className="bulk-action-info">
            <span>{selectedTargets.size} target{selectedTargets.size > 1 ? 's' : ''} selected</span>
            <button className="btn btn-sm btn-primary" onClick={handleBulkRescan} disabled={isScanning}>
              {isScanning ? 'Scanning...' : '🔄 Re-scan Selected'}
            </button>
            <button className="bulk-clear-btn" onClick={clearSelection}>Clear selection</button>
          </div>
        </div>
      )}

      {scanProgress.size > 0 && (
        <div className="scan-progress-panel">
          <h4 className="scan-progress-title">Scan Progress</h4>
          {Array.from(scanProgress.values()).map(p => (
            <div key={p.targetName} className="scan-progress-item">
              <span className="scan-progress-target">{p.targetName}</span>
              <div className="scan-progress-bar">
                <div
                  className={`scan-progress-fill scan-progress-${p.status}`}
                  style={{ width: `${p.progress}%` }}
                />
              </div>
              <span className="scan-progress-status">{p.status}</span>
              {p.jobId && <span className="scan-progress-job">{p.jobId}</span>}
            </div>
          ))}
        </div>
      )}

      {showFilters && (
        <div className="card card-padded multi-filter-panel">
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
      )}

      {activeFilterChips.length > 0 && (
        <div className="active-filters-bar">
          <div className="active-filters-chips">
            {activeFilterChips.map((chip, i) => (
              <span key={i} className="filter-chip">
                {chip.label}
                <button
                  type="button"
                  className="filter-chip-remove"
                  onClick={chip.onRemove}
                  aria-label={`Remove filter: ${chip.label}`}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={clearAllFilters}
          >
            Clear all filters
          </button>
        </div>
      )}

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
                  <tr key={target.name || target.href || `target-${currentPage}-${index}`} className={selectedTargets.has(target.name || '') ? 'row-selected' : ''}>
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
                      {target.href && (
                        <a href={target.href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
                          Runs
                        </a>
                      )}
                      {target.latest_report_href && (
                        <a href={target.latest_report_href} className="btn btn-small" target="_blank" rel="noopener noreferrer">
                          Latest Report
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
    </div>
  );
}
