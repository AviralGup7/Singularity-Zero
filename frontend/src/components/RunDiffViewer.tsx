import { useState, useMemo } from 'react';
import type { Finding } from '../types/api';

interface RunData {
  runId: string;
  target: string;
  date: string;
  findings: Finding[];
}

interface RunDiffViewerProps {
  runA: RunData;
  runB: RunData;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

function computeFindingKey(f: Finding): string {
  return `${f.type}::${f.target}::${f.severity}`;
}

export function RunDiffViewer({ runA, runB }: RunDiffViewerProps) {
  const [filter, setFilter] = useState<'all' | 'new' | 'removed' | 'changed'>('all');

  const diff = useMemo(() => {
    const mapA = new Map(runA.findings.map(f => [computeFindingKey(f), f]));
    const mapB = new Map(runB.findings.map(f => [computeFindingKey(f), f]));

    const newFindings: Finding[] = [];
    const removedFindings: Finding[] = [];
    const changedFindings: { old: Finding; new: Finding }[] = [];

    mapB.forEach((finding, key) => {
      if (!mapA.has(key)) {
        newFindings.push(finding);
      } else {
        const oldFinding = mapA.get(key)!;
        if (oldFinding.status !== finding.status || oldFinding.description !== finding.description) {
          changedFindings.push({ old: oldFinding, new: finding });
        }
      }
    });

    mapA.forEach((finding, key) => {
      if (!mapB.has(key)) {
        removedFindings.push(finding);
      }
    });

    return { newFindings, removedFindings, changedFindings };
  }, [runA, runB]);

  const severityBreakdown = useMemo(() => {
    const breakdown: Record<string, { new: number; removed: number; changed: number }> = {};
    for (const sev of SEVERITY_ORDER) {
      breakdown[sev] = { new: 0, removed: 0, changed: 0 };
    }
    for (const f of diff.newFindings) {
      if (breakdown[f.severity]) breakdown[f.severity].new++;
    }
    for (const f of diff.removedFindings) {
      if (breakdown[f.severity]) breakdown[f.severity].removed++;
    }
    for (const c of diff.changedFindings) {
      if (breakdown[c.new.severity]) breakdown[c.new.severity].changed++;
    }
    return breakdown;
  }, [diff]);

  const filteredItems = useMemo(() => {
    const items: Array<{ type: 'new' | 'removed' | 'changed'; finding: Finding; changed?: { old: Finding; new: Finding } }> = [];
    if (filter === 'all' || filter === 'new') {
      for (const f of diff.newFindings) items.push({ type: 'new', finding: f });
    }
    if (filter === 'all' || filter === 'removed') {
      for (const f of diff.removedFindings) items.push({ type: 'removed', finding: f });
    }
    if (filter === 'all' || filter === 'changed') {
      for (const c of diff.changedFindings) items.push({ type: 'changed', finding: c.new, changed: c });
    }
    return items;
  }, [diff, filter]);

  return (
    <div className="run-diff-viewer">
      <div className="run-diff-header">
        <h3 className="run-diff-title">Run Comparison</h3>
        <div className="run-diff-runs">
          <span className="run-diff-run-label">{runA.runId} ({runA.date})</span>
          <span className="run-diff-vs">vs</span>
          <span className="run-diff-run-label">{runB.runId} ({runB.date})</span>
        </div>
      </div>

      <div className="run-diff-summary">
        <div className="run-diff-stat stat-new">
          <span className="run-diff-stat-value">{diff.newFindings.length}</span>
          <span className="run-diff-stat-label">New</span>
        </div>
        <div className="run-diff-stat stat-removed">
          <span className="run-diff-stat-value">{diff.removedFindings.length}</span>
          <span className="run-diff-stat-label">Removed</span>
        </div>
        <div className="run-diff-stat stat-changed">
          <span className="run-diff-stat-value">{diff.changedFindings.length}</span>
          <span className="run-diff-stat-label">Changed</span>
        </div>
      </div>

      <div className="run-diff-severity-breakdown">
        <h4 className="run-diff-subtitle">Severity Breakdown</h4>
        <div className="severity-diff-grid">
          {SEVERITY_ORDER.map(sev => (
            <div key={sev} className={`severity-diff-row severity-diff-${sev}`}>
              <span className="severity-diff-name">{sev}</span>
              <span className="severity-diff-new">+{severityBreakdown[sev].new}</span>
              <span className="severity-diff-removed">-{severityBreakdown[sev].removed}</span>
              <span className="severity-diff-changed">~{severityBreakdown[sev].changed}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="run-diff-filters">
        {(['all', 'new', 'removed', 'changed'] as const).map(f => (
          <button
            key={f}
            className={`run-diff-filter-btn ${filter === f ? 'active' : ''}`}
            onClick={() => setFilter(f)}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      <div className="run-diff-results">
        {filteredItems.length === 0 ? (
          <div className="run-diff-empty">No findings in this category.</div>
        ) : (
          filteredItems.map((item, idx) => (
            <div
              key={idx}
              className={`run-diff-item run-diff-item-${item.type}`}
            >
              <div className="run-diff-item-header">
                <span className={`severity-badge sev-${item.finding.severity}`}>
                  {item.finding.severity}
                </span>
                <span className="run-diff-item-type">{item.finding.type}</span>
                <span className="run-diff-item-target">{item.finding.target}</span>
              </div>
              {item.type === 'changed' && item.changed && (
                <div className="run-diff-changed-details">
                  <div className="run-diff-change">
                    <span className="run-diff-change-label">Status:</span>
                    <span className="run-diff-change-old">{item.changed.old.status}</span>
                    <span className="run-diff-change-arrow">→</span>
                    <span className="run-diff-change-new">{item.changed.new.status}</span>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
