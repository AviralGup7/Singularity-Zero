import { useState, useEffect, useCallback, memo } from 'react';
import { getTargets } from '../api/client';
import { useToast } from '../hooks/useToast';
import { EmptyState } from './ui/EmptyState';
import type { Target } from '../types/api';

const SeverityBadge = memo(function SeverityBadge({ severity, count }: { severity: string; count: number }) {
  if (count === 0) return null;
  const severityIcons: Record<string, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '🔵',
  };
   
  const icon = severityIcons[severity.toLowerCase()] || '⚪';
  return (
    <span className={`sev ${severity.toLowerCase()}`} role="status" aria-label={`${severity} severity: ${count} findings`}>
      {icon} {severity}: {count}
    </span>
  );
}, (prev, next) => prev.severity === next.severity && prev.count === next.count);

const TargetCard = memo(function TargetCard({ target }: { target: Target }) {
  const severityEntries = Object.entries(target.severity_counts || {});

  return (
    <div className="card target-card">
      <div className="target-name">{target.name ?? '—'}</div>

      <div className="target-stats">
        <div>
          Findings: <span className="stat-value">{target.finding_count ?? 0}</span>
        </div>
        <div>
          URLs: <span className="stat-value">{target.url_count ?? 0}</span>
        </div>
        <div>
          Parameters: <span className="stat-value">{target.parameter_count ?? 0}</span>
        </div>
        <div>
          Runs: <span className="stat-value">{target.run_count ?? 0}</span>
        </div>
        <div>
          Validated: <span className="stat-value">{target.validated_leads ?? 0}</span>
        </div>
        <div>
          Attack Chains: <span className="stat-value">{target.attack_chain_count ?? 0}</span>
        </div>
      </div>

      {target.top_finding_title && (
        <div className="top-finding-text">
          Top: {target.top_finding_title}
        </div>
      )}

      {severityEntries.length > 0 && (
        <div className="severity-badges">
  // eslint-disable-next-line security/detect-object-injection
          {severityEntries.map(([sev, count]) => (
            <SeverityBadge key={sev} severity={sev} count={count} />
          ))}
        </div>
      )}

      {target.latest_generated_at && (
        <div className="last-run-text">
          Last: {target.latest_generated_at}
        </div>
      )}

      {target.href && (
        <a
          href={target.href}
          className="target-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          View Runs
        </a>
      )}

      {target.latest_report_href && (
        <a
          href={target.latest_report_href}
          className="target-link"
          target="_blank"
          rel="noopener noreferrer"
        >
          Latest Report
        </a>
      )}
    </div>
  );
}, (prev, next) => prev.target?.name === next.target?.name
  && prev.target?.finding_count === next.target?.finding_count
  && JSON.stringify(prev.target?.severity_counts) === JSON.stringify(next.target?.severity_counts));

export default function TargetList({ targets: propTargets }: { targets?: Target[] }) {
   
  const [targets, setTargets] = useState<Target[]>(propTargets || []);
   
  const [loading, setLoading] = useState(!propTargets);
   
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();

  const getTargetsLoadErrorMessage = (err: unknown): string => {
    const status = (err as { status?: number })?.status;
    const message = ((err as { message?: string })?.message || '').toLowerCase();

    if (status === 401 || status === 403) {
      return 'Failed to load targets: authentication required. Please sign in again.';
    }

    if (message.includes('network error')) {
      return 'Failed to load targets: cannot reach backend. Check that the dashboard API is running.';
    }

    return 'Failed to load targets. Please refresh and try again.';
  };

  const fetchTargets = useCallback(async (signal?: AbortSignal) => {
    try {
      const res = await getTargets(signal);
      setTargets(res?.targets ?? []);
      setError(null);
    } catch (err: unknown) {
      if (signal?.aborted) return;
      const msg = getTargetsLoadErrorMessage(err);
      setError(msg);
      toast.error(msg);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
   
  }, [toast]);

  useEffect(() => {
    if (propTargets) {
      setTargets(propTargets);
      setLoading(false);
      return;
    }

    const controller = new AbortController();
    fetchTargets(controller.signal);
    return () => controller.abort();
   
  }, [propTargets, fetchTargets]);

  if (loading) return <div className="loading">Loading targets</div>;
  if (error) return <div className="banner error">{error}</div>;

  if (targets.length === 0) {
    return (
      <div className="section">
        <div className="section-title">🎯 Scanned Targets</div>
        <EmptyState
          title="No targets scanned yet"
          description="Run a pipeline scan from the dashboard to see targets here."
          icon="🎯"
        />
      </div>
    );
  }

  const totalFindings = targets.reduce((sum, t) => sum + (t?.finding_count ?? 0), 0);
  const totalUrls = targets.reduce((sum, t) => sum + (t?.url_count ?? 0), 0);
  const totalParams = targets.reduce((sum, t) => sum + (t?.parameter_count ?? 0), 0);
  const totalRuns = targets.reduce((sum, t) => sum + (t?.run_count ?? 0), 0);

  return (
    <div className="section">
      <div className="section-title">
        🎯 Scanned Targets ({targets.length} targets, {totalFindings} findings)
      </div>

      <div className="hero-stats hero-stats-mb-24">
        <div className="hero-stat">
          <strong>{targets.length}</strong>
          <span>Targets</span>
        </div>
        <div className="hero-stat stat-critical">
          <strong>{totalFindings}</strong>
          <span>Findings</span>
        </div>
        <div className="hero-stat">
          <strong>{totalUrls}</strong>
          <span>URLs</span>
        </div>
        <div className="hero-stat">
          <strong>{totalParams}</strong>
          <span>Parameters</span>
        </div>
        <div className="hero-stat">
          <strong>{totalRuns}</strong>
          <span>Total Runs</span>
        </div>
      </div>

      <div className="grid grid-3">
        {targets.map(target => (
          <TargetCard key={target.name} target={target} />
        ))}
      </div>
    </div>
  );
}
