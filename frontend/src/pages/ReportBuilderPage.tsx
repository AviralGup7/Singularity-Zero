import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FileText, Download, Filter, Search, Shield, X, CheckSquare, Square, FileJson, FileCode2 } from 'lucide-react';

import { getFindings, bulkUpdateFindings } from '@/api/findings';
import { ApiError } from '@/api/core';
import type { Finding } from '@/types/api';
import { GlassCard, PageHeader } from '@/components/ui';
import { exportReportBundle, type ReportFormat } from '@/utils/findingExport';

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';

function shortId(id: string): string {
  if (!id) return '—';
  return id.length > 10 ? `${id.slice(0, 8)}…` : id;
}

export function ReportBuilderPage() {
  const [searchParams] = useSearchParams();
  const initialFindingId = searchParams.get('finding');

  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState<ReportFormat | null>(null);
  const [meta, setMeta] = useState({
    title: '',
    author: '',
    scope: '',
  });

  useEffect(() => {
    if (initialFindingId && findings.length > 0) {
      setSelected(new Set([initialFindingId]));
      const f = findings.find(x => x.id === initialFindingId);
      if (f) {
        setMeta(m => ({
          title: m.title || `Report for ${f.title}`,
          author: m.author || 'Security Team',
          scope: m.scope || f.target || '',
        }));
      }
    }
  }, [initialFindingId, findings]);

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError('');
    try {
      const data = await getFindings(signal);
      setFindings(data);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setError(err instanceof ApiError ? err.message : 'Unable to load findings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter(f => {
      if (severity !== 'all' && (f.severity || '').toLowerCase() !== severity) return false;
      if (!q) return true;
      return (
        (f.title || '').toLowerCase().includes(q) ||
        (f.target || '').toLowerCase().includes(q) ||
        (f.type || '').toLowerCase().includes(q)
      );
    });
  }, [findings, search, severity]);

  const selectedFindings = useMemo(
    () => findings.filter(f => selected.has(f.id)),
    [findings, selected],
  );

  const counts = useMemo(() => {
    const acc: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    selectedFindings.forEach(f => {
      const k = (f.severity || 'info').toLowerCase();
      // eslint-disable-next-line security/detect-object-injection
      if (k in acc) acc[k] += 1;
    });
    return acc;
  }, [selectedFindings]);

  const toggle = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const toggleAll = useCallback(() => {
    setSelected(prev => {
      const allInView = filtered.every(f => prev.has(f.id));
      if (allInView && filtered.length > 0) {
        const next = new Set(prev);
        filtered.forEach(f => next.delete(f.id));
        return next;
      }
      const next = new Set(prev);
      filtered.forEach(f => next.add(f.id));
      return next;
    });
  }, [filtered]);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

  const markAllSelectedAsReviewed = useCallback(async () => {
    if (selectedFindings.length === 0) return;
    try {
      const updated = await bulkUpdateFindings(
        selectedFindings.map(f => f.id),
        { status: 'reviewed' },
      );
      setFindings(prev => prev.map(f => {
        const u = updated.find(x => x.id === f.id);
        return u || f;
      }));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to mark findings as reviewed');
    }
  }, [selectedFindings]);

  const handleExport = useCallback((format: ReportFormat) => {
    if (selectedFindings.length === 0) return;
    setExporting(format);
    try {
      const reportMeta = {
        title: meta.title.trim() || undefined,
        author: meta.author.trim() || undefined,
        scope: meta.scope.trim() || undefined,
        generatedAt: new Date().toISOString(),
      };
      exportReportBundle(selectedFindings, format, reportMeta);
    } finally {
      setExporting(null);
    }
  }, [selectedFindings, meta]);

  const allSelectedInView = filtered.length > 0 && filtered.every(f => selected.has(f.id));

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<FileText size={20} />}
        title="Report Builder"
        subtitle="Compose multi-finding Markdown / HTML / JSON reports"
        actions={
          <div className="flex items-center gap-2 text-xs text-muted">
            <span>{selected.size} selected</span>
            <span>·</span>
            <span>{findings.length} total</span>
          </div>
        }
      />

      {error && (
        <GlassCard variant="error" hoverable={false}>
          <p className="text-sm text-bad">{error}</p>
        </GlassCard>
      )}

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <motion.section
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: EASE_OUT }}
        >
          <GlassCard variant="default" hoverable={false}>
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="flex items-center gap-2 flex-1">
                <div className="relative flex-1 max-w-md">
                  <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none" aria-hidden="true" />
                  <input
                    type="search"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="Search title, target, type…"
                    className="form-input pl-9 w-full"
                    aria-label="Search findings"
                  />
                </div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted">
                  <Filter size={12} aria-hidden="true" />
                  <select
                    value={severity}
                    onChange={e => setSeverity(e.target.value as SeverityFilter)}
                    className="form-input"
                    aria-label="Filter by severity"
                  >
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </label>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={toggleAll}
                  disabled={filtered.length === 0}
                >
                  {allSelectedInView ? <CheckSquare size={14} aria-hidden="true" /> : <Square size={14} aria-hidden="true" />}
                  {allSelectedInView ? 'Deselect visible' : 'Select visible'}
                </button>
                {selected.size > 0 && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={clearSelection}
                    aria-label="Clear selection"
                  >
                    <X size={14} aria-hidden="true" />
                    Clear
                  </button>
                )}
              </div>
            </div>

            <div className="table-container mt-4" role="region" aria-label="Findings list">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-10" aria-label="Select" />
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Target</th>
                    <th>ID</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <tr>
                      <td colSpan={5} className="text-center py-12 text-[var(--text-secondary)]">Loading findings…</td>
                    </tr>
                  )}
                  {!loading && filtered.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-center py-12 text-[var(--text-secondary)]">No findings match the current filters.</td>
                    </tr>
                  )}
                  {!loading && filtered.map(f => {
                    const isSelected = selected.has(f.id);
                    return (
                      <tr
                        key={f.id}
                        className={`transition-all duration-150 hover:bg-white/5 cursor-pointer ${isSelected ? 'bg-accent/5' : ''}`}
                        onClick={() => toggle(f.id)}
                      >
                        <td onClick={e => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggle(f.id)}
                            aria-label={`Select ${f.title || f.id}`}
                            className="accent-[var(--accent)]"
                          />
                        </td>
                        <td className="font-medium">{f.title || 'Untitled finding'}</td>
                        <td>
                          <span className={`status-badge status-${(f.severity || 'info')}`}>
                            <Shield size={10} aria-hidden="true" />
                            {(f.severity || 'info').toUpperCase()}
                          </span>
                        </td>
                        <td className="text-muted text-xs">{f.target || '—'}</td>
                        <td><code className="text-xs text-muted">{shortId(f.id)}</code></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </GlassCard>
        </motion.section>

        <motion.aside
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1, ease: EASE_OUT }}
          className="space-y-4"
        >
          <GlassCard variant="glow" hoverable={false}>
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Report metadata</h3>
            <label className="block text-xs text-muted mb-2">
              Title
              <input
                type="text"
                value={meta.title}
                onChange={e => setMeta(m => ({ ...m, title: e.target.value }))}
                placeholder="Q3 Pentest Report"
                className="form-input mt-1 w-full"
              />
            </label>
            <label className="block text-xs text-muted mb-2">
              Author
              <input
                type="text"
                value={meta.author}
                onChange={e => setMeta(m => ({ ...m, author: e.target.value }))}
                placeholder="Security Team"
                className="form-input mt-1 w-full"
              />
            </label>
            <label className="block text-xs text-muted mb-2">
              Scope
              <input
                type="text"
                value={meta.scope}
                onChange={e => setMeta(m => ({ ...m, scope: e.target.value }))}
                placeholder="api.example.com, app.example.com"
                className="form-input mt-1 w-full"
              />
            </label>
          </GlassCard>

          <GlassCard variant="default" hoverable={false}>
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Selection</h3>
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted">Findings</span>
                <span className="font-semibold">{selectedFindings.length}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                  const c = sev === 'critical' ? counts.critical
                    : sev === 'high' ? counts.high
                    : sev === 'medium' ? counts.medium
                    : sev === 'low' ? counts.low
                    : counts.info;
                  return (
                    <span
                      key={sev}
                      className={`pill pill--${sev} ${c === 0 ? 'opacity-40' : ''}`}
                    >
                      {c} {sev}
                    </span>
                  );
                })}
              </div>
            </div>
          </GlassCard>

          <GlassCard variant="default" hoverable={false}>
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Export</h3>
            <div className="space-y-2">
              <button
                type="button"
                className="btn btn-primary w-full inline-flex items-center justify-center gap-2"
                onClick={() => handleExport('markdown')}
                disabled={selectedFindings.length === 0 || exporting !== null}
              >
                <FileCode2 size={14} aria-hidden="true" />
                {exporting === 'markdown' ? 'Exporting…' : 'Markdown (.md)'}
              </button>
              <button
                type="button"
                className="btn btn-secondary w-full inline-flex items-center justify-center gap-2"
                onClick={() => handleExport('html')}
                disabled={selectedFindings.length === 0 || exporting !== null}
              >
                <FileText size={14} aria-hidden="true" />
                {exporting === 'html' ? 'Exporting…' : 'HTML (.html)'}
              </button>
              <button
                type="button"
                className="btn btn-secondary w-full inline-flex items-center justify-center gap-2"
                onClick={() => handleExport('json')}
                disabled={selectedFindings.length === 0 || exporting !== null}
              >
                <FileJson size={14} aria-hidden="true" />
                {exporting === 'json' ? 'Exporting…' : 'JSON (.json)'}
              </button>
            </div>
            <div className="mt-3 pt-3 border-t border-[var(--border)]">
              <button
                type="button"
                className="btn btn-ghost btn-sm w-full inline-flex items-center justify-center gap-2"
                onClick={() => void markAllSelectedAsReviewed()}
                disabled={selectedFindings.length === 0}
                title="Mark all selected findings as reviewed"
              >
                <Download size={12} aria-hidden="true" />
                Mark selected as reviewed
              </button>
            </div>
          </GlassCard>
        </motion.aside>
      </div>
    </div>
  );
}

export default ReportBuilderPage;
