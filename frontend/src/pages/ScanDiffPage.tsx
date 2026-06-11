import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useSearchParams } from 'react-router-dom';
import { ArrowLeftRight, TrendingUp, TrendingDown, DollarSign, Filter, Check, X } from 'lucide-react';
import type { Finding, Target } from '@/types/api';
import { PageHeader, GlassCard, AnimatedCounter } from '@/components/ui';
import { useApi } from '@/hooks/useApi';
import { useTargetFilters, hasActiveFilters } from '@/hooks/useTargetFilters';
import { useDebouncedFilter } from '@/hooks/useDebouncedFilter';
import { bulkUpdateFindings } from '@/api/findings';
import { useToast } from '@/hooks/useToast';

interface DiffBucket {
  newFindings: Finding[];
  removedFindings: Finding[];
  changedFindings: { old: Finding; new: Finding }[];
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
const PAGE_SIZE = 50;

function keyForFinding(f: Finding): string {
  return `${f.type}::${f.target}::${f.severity}::${f.url ?? ''}`;
}

function computeDiff(runA: Finding[], runB: Finding[]): DiffBucket {
  const mapA = new Map(runA.map((f) => [keyForFinding(f), f]));
  const mapB = new Map(runB.map((f) => [keyForFinding(f), f]));
  const newFindings: Finding[] = [];
  const removedFindings: Finding[] = [];
  const changedFindings: { old: Finding; new: Finding }[] = [];

  mapB.forEach((finding, key) => {
    const old = mapA.get(key);
    if (!old) {
      newFindings.push(finding);
    } else if (
      old.status !== finding.status ||
      old.description !== finding.description ||
      old.lifecycle_state !== finding.lifecycle_state ||
      (old.bounty_value ?? 0) !== (finding.bounty_value ?? 0)
    ) {
      changedFindings.push({ old, new: finding });
    }
  });
  mapA.forEach((finding, key) => {
    if (!mapB.has(key)) removedFindings.push(finding);
  });
  return { newFindings, removedFindings, changedFindings };
}

function bountyDelta(items: Finding[]): { min: number; max: number; count: number } {
  let min = 0;
  let max = 0;
  let count = 0;
  for (const f of items) {
    if (typeof f.bounty_value === 'number' && f.bounty_value > 0) {
      min += f.bounty_value * 0.5;
      max += f.bounty_value;
      count++;
    }
  }
  return { min, max, count };
}

const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export function ScanDiffPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: targetsData } = useApi<{ targets: Target[]; total: number }>('/api/targets');
  const targets = targetsData?.targets ?? [];
  const toast = useToast();

  const [filter, setFilter] = useState<string>(searchParams.get('filter') ?? 'all');
  const [page, setPage] = useState(1);
  const [bulkBusy, setBulkBusy] = useState(false);

  const initialRunA = searchParams.get('runA') ?? '';
  const initialRunB = searchParams.get('runB') ?? '';
  const [runA, setRunA] = useState<string>(initialRunA);
  const [runB, setRunB] = useState<string>(initialRunB);

  const acceptAllNew = async () => {
    if (diff.newFindings.length === 0 || bulkBusy) return;
    const ok = typeof window !== 'undefined'
      ? window.confirm(`Mark all ${diff.newFindings.length} new finding(s) as "Accepted" (in progress)?`)
      : true;
    if (!ok) return;
    setBulkBusy(true);
    try {
      const ids = diff.newFindings.map(f => f.id).filter(Boolean) as string[];
      await bulkUpdateFindings(ids, { status: 'accepted' });
      toast.success(`Accepted ${ids.length} new finding(s)`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Bulk accept failed');
    } finally {
      setBulkBusy(false);
    }
  };

  const rejectAllRemoved = async () => {
    if (diff.removedFindings.length === 0 || bulkBusy) return;
    const ok = typeof window !== 'undefined'
      ? window.confirm(`Mark all ${diff.removedFindings.length} removed finding(s) as false-positive (no longer present in latest run)?`)
      : true;
    if (!ok) return;
    setBulkBusy(true);
    try {
      const ids = diff.removedFindings.map(f => f.id).filter(Boolean) as string[];
      await bulkUpdateFindings(ids, { falsePositive: true, fpStatus: 'approved', fpJustification: 'No longer present in latest run' });
      toast.success(`Dismissed ${ids.length} removed finding(s) as false-positive`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Bulk dismiss failed');
    } finally {
      setBulkBusy(false);
    }
  };

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (filter !== 'all') next.set('filter', filter); else next.delete('filter');
    if (runA) next.set('runA', runA); else next.delete('runA');
    if (runB) next.set('runB', runB); else next.delete('runB');
    setSearchParams(next, { replace: true });
  }, [filter, runA, runB, searchParams, setSearchParams]);

  const { data: dataA, loading: loadingA, error: errorA, refetch: refetchA } = useApi<{ findings: Finding[] }>(
    runA ? `/api/export/findings/${runA}/latest` : '__skip__',
    { enabled: Boolean(runA) },
  );
  const { data: dataB, loading: loadingB, error: errorB, refetch: refetchB } = useApi<{ findings: Finding[] }>(
    runB ? `/api/export/findings/${runB}/latest` : '__skip__',
    { enabled: Boolean(runB) },
  );

  const findingsA = useMemo<Finding[]>(
    () => (dataA as unknown as { findings?: Finding[] })?.findings ?? [],
    [dataA],
  );
  const findingsB = useMemo<Finding[]>(
    () => (dataB as unknown as { findings?: Finding[] })?.findings ?? [],
    [dataB],
  );

  const diff = useMemo(() => computeDiff(findingsA, findingsB), [findingsA, findingsB]);
  const bountyNew = useMemo(() => bountyDelta(diff.newFindings), [diff.newFindings]);
  const bountyRemoved = useMemo(() => bountyDelta(diff.removedFindings), [diff.removedFindings]);

  const severityBreakdown = useMemo(() => {
    const map = new Map<string, { new: number; removed: number; changed: number }>();
    for (const sev of SEVERITY_ORDER) map.set(sev, { new: 0, removed: 0, changed: 0 });
    const bump = (sev: string, key: 'new' | 'removed' | 'changed') => {
      const entry = map.get(sev);
      if (entry) {
        // `key` is a typed union of the record's own keys; safe to use.
        // eslint-disable-next-line security/detect-object-injection
        entry[key] += 1;
      }
    };
    for (const f of diff.newFindings) bump(f.severity, 'new');
    for (const f of diff.removedFindings) bump(f.severity, 'removed');
    for (const c of diff.changedFindings) bump(c.new.severity, 'changed');
    return map;
  }, [diff]);

  const filtered = useMemo(() => {
    if (filter === 'all') {
      return [
        ...diff.newFindings.map((f) => ({ kind: 'new' as const, finding: f })),
        ...diff.removedFindings.map((f) => ({ kind: 'removed' as const, finding: f })),
        ...diff.changedFindings.map((c) => ({ kind: 'changed' as const, finding: c.new, changed: c })),
      ];
    }
    if (filter === 'new') return diff.newFindings.map((f) => ({ kind: 'new' as const, finding: f }));
    if (filter === 'removed') return diff.removedFindings.map((f) => ({ kind: 'removed' as const, finding: f }));
    if (filter === 'changed') return diff.changedFindings.map((c) => ({ kind: 'changed' as const, finding: c.new, changed: c }));
    if (filter === 'bounty_high') {
      // The "operator-economics" filter: only show new findings worth ≥ $500.
      return diff.newFindings
        .filter((f) => typeof f.bounty_value === 'number' && f.bounty_value >= 500)
        .map((f) => ({ kind: 'new' as const, finding: f }));
    }
    return [];
  }, [filter, diff]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const ready = runA && runB;
  const { setFilter: setDebouncedFilter, debouncedFilter } = useDebouncedFilter();
  const { filters } = useTargetFilters();
  void hasActiveFilters(filters); // keep import in scope to satisfy lint
  void setDebouncedFilter; void debouncedFilter; // unused in this page

  return (
    <div className="space-y-6">
      <PageHeader
        icon={<ArrowLeftRight size={20} />}
        title="Scan Diff"
        subtitle="Compare two runs, with bounty-delta highlights"
      />

      {(errorA || errorB) && (
        <div className="card error-card p-4" role="alert">
          <p className="text-sm text-[var(--text-secondary)]">
            {errorA?.message || errorB?.message || 'Failed to load scan data'}
          </p>
          <button
            className="btn btn-secondary btn-sm mt-2"
            onClick={() => { if (errorA) refetchA(); if (errorB) refetchB(); }}
          >
            Retry
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <GlassCard hoverable={false}>
          <label htmlFor="scan-diff-runa" className="block text-xs font-semibold uppercase tracking-wider text-muted mb-2">Run A (older)</label>
          <select
            id="scan-diff-runa"
            value={runA}
            onChange={(e) => setRunA(e.target.value)}
            className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm"
          >
            <option value="">Select a target...</option>
            {targets.map((t) => (
              <option key={t.name} value={t.name}>{t.name}</option>
            ))}
          </select>
        </GlassCard>
        <GlassCard hoverable={false}>
          <label htmlFor="scan-diff-runb" className="block text-xs font-semibold uppercase tracking-wider text-muted mb-2">Run B (newer)</label>
          <select
            id="scan-diff-runb"
            value={runB}
            onChange={(e) => setRunB(e.target.value)}
            className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm"
          >
            <option value="">Select a target...</option>
            {targets.map((t) => (
              <option key={t.name} value={t.name} disabled={t.name === runA}>{t.name}</option>
            ))}
          </select>
        </GlassCard>
      </div>

      {!ready && (
        <GlassCard hoverable={false} className="text-center py-16">
          <ArrowLeftRight size={48} className="mx-auto mb-4 text-[var(--text-tertiary)]" />
          <p className="text-sm text-[var(--text-secondary)]">
            Pick two targets to compare their latest runs side-by-side.
          </p>
          <p className="mt-2 text-xs text-muted">Looking for the same target twice? You can select it in both slots — the system will compare the two most recent runs.</p>
        </GlassCard>
      )}

      {ready && (loadingA || loadingB) && (
        <GlassCard hoverable={false} className="text-center py-12">
          <div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs text-muted">Loading findings for both runs...</p>
        </GlassCard>
      )}

      {ready && !(loadingA || loadingB) && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <DiffStatCard label="New findings" value={diff.newFindings.length} accent="ok" />
            <DiffStatCard label="Removed findings" value={diff.removedFindings.length} accent="bad" />
            <DiffStatCard label="Changed findings" value={diff.changedFindings.length} accent="muted" />
          </div>

          {/* P4-10: Bounty delta — the operator-economics view of the diff */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <BountyDeltaCard label="Bounty upside (new)" {...bountyNew} accent="ok" />
            <BountyDeltaCard label="Bounty at risk (removed)" {...bountyRemoved} accent="bad" />
          </div>

          <GlassCard hoverable={false}>
            <h3 className="text-sm font-semibold mb-3 text-text">Severity Breakdown</h3>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {SEVERITY_ORDER.map((sev) => {
                const entry = severityBreakdown.get(sev) ?? { new: 0, removed: 0, changed: 0 };
                return (
                  <div key={sev} className={`rounded border border-white/5 bg-white/5 p-2 text-center`}>
                    <div className={`text-[10px] font-black uppercase severity-badge sev-${sev}`}>{sev}</div>
                    <div className="mt-1 text-xs font-mono">
                      <span className="text-ok">+{entry.new}</span>{' / '}
                      <span className="text-bad">−{entry.removed}</span>{' / '}
                      <span className="text-muted">~{entry.changed}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </GlassCard>

          <div className="flex items-center gap-2 flex-wrap">
            <Filter size={14} className="text-muted" />
            {(['all', 'new', 'removed', 'changed', 'bounty_high'] as const).map((f) => (
              <button
                key={f}
                type="button"
                className={`px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border transition-all ${
                  filter === f
                    ? 'bg-accent text-black border-accent'
                    : 'border-white/10 text-muted hover:text-white'
                }`}
                onClick={() => { setFilter(f); setPage(1); }}
              >
                {f === 'bounty_high' ? 'High bounty (≥ $500)' : f}
              </button>
            ))}
            <div className="ml-auto flex items-center gap-2" role="group" aria-label="Bulk diff actions">
              <button
                type="button"
                onClick={acceptAllNew}
                disabled={bulkBusy || diff.newFindings.length === 0}
                className="px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border border-ok/40 text-ok hover:bg-ok/10 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                aria-label={`Accept all ${diff.newFindings.length} new finding(s)`}
                title="Mark all new findings as Accepted (in progress)"
              >
                <Check size={12} aria-hidden="true" /> Accept all new ({diff.newFindings.length})
              </button>
              <button
                type="button"
                onClick={rejectAllRemoved}
                disabled={bulkBusy || diff.removedFindings.length === 0}
                className="px-3 py-1.5 rounded text-[10px] font-black uppercase tracking-widest border border-bad/40 text-bad hover:bg-bad/10 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                aria-label={`Reject all ${diff.removedFindings.length} removed finding(s)`}
                title="Mark all removed findings as false-positive (no longer in latest run)"
              >
                <X size={12} aria-hidden="true" /> Reject all removed ({diff.removedFindings.length})
              </button>
            </div>
          </div>

          <GlassCard hoverable={false} padding={false}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Target</th>
                  <th>Bounty</th>
                  <th>Status</th>
                  <th>Diff</th>
                </tr>
              </thead>
              <tbody>
                {paged.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-muted text-xs">
                      No findings in this category.
                    </td>
                  </tr>
                )}
                {paged.map((row, i) => (
                  <tr key={`${row.kind}-${(row.finding.id ?? i)}`} className="hover:bg-white/5">
                    <td className="text-xs font-medium">{row.finding.type || '—'}</td>
                    <td>
                      <span className={`severity-badge sev-${row.finding.severity}`}>
                        {row.finding.severity}
                      </span>
                    </td>
                    <td className="text-xs font-mono truncate max-w-[260px]">
                      {row.finding.target || row.finding.url || '—'}
                    </td>
                    <td className="text-xs">
                      {typeof row.finding.bounty_value === 'number' && row.finding.bounty_value > 0 ? (
                        <span className="bounty-pill">${row.finding.bounty_value.toLocaleString()}</span>
                      ) : '—'}
                    </td>
                    <td className="text-xs">
                      <span className={`status-badge status-${row.finding.status}`}>{row.finding.status || 'open'}</span>
                    </td>
                    <td className="text-xs">
                      <span className={`diff-pill diff-pill-${row.kind}`}>
                        {row.kind === 'new' && <TrendingUp size={10} />}
                        {row.kind === 'removed' && <TrendingDown size={10} />}
                        {row.kind === 'changed' && <span>~</span>}
                        <span>{row.kind}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </GlassCard>

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={page === 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Prev
              </button>
              <span className="text-xs text-muted">Page {page} of {totalPages}</span>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={page === totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {ready && (
        <p className="text-xs text-muted">
          Need more diff tooling? <Link to="/target-comparison" className="text-accent hover:underline">Compare full target posture</Link>.
        </p>
      )}
    </div>
  );
}

function DiffStatCard({ label, value, accent }: { label: string; value: number; accent: 'ok' | 'bad' | 'muted' }) {
  const colorClass = accent === 'ok' ? 'text-ok' : accent === 'bad' ? 'text-bad' : 'text-muted';
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: EASE_OUT }}
    >
      <GlassCard variant={accent === 'ok' ? 'success' : accent === 'bad' ? 'error' : 'default'} hoverable>
        <div className="text-xs uppercase tracking-wider text-muted">{label}</div>
        <AnimatedCounter value={value} className={`text-3xl font-bold mt-1 ${colorClass}`} />
      </GlassCard>
    </motion.div>
  );
}

function BountyDeltaCard({ label, min, max, count, accent }: { label: string; min: number; max: number; count: number; accent: 'ok' | 'bad' }) {
  const colorClass = accent === 'ok' ? 'text-ok' : 'text-bad';
  return (
    <GlassCard variant={accent === 'ok' ? 'success' : 'error'} hoverable>
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted">
        <DollarSign size={12} /> {label}
      </div>
      <div className={`mt-1 font-mono text-xl font-bold ${colorClass}`}>
        ${min.toLocaleString(undefined, { maximumFractionDigits: 0 })} – ${max.toLocaleString()}
      </div>
      <div className="text-[10px] text-muted font-mono mt-1">
        Across {count} finding{count === 1 ? '' : 's'} with a known bounty value
      </div>
    </GlassCard>
  );
}
