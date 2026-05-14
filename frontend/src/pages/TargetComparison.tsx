import { useState, useMemo } from 'react';
import type { Target } from '../types/api';
import { useTargets } from '../hooks';

interface TargetComparisonProps {
  targets?: Target[];
}

export function TargetComparison({ targets: propTargets }: TargetComparisonProps) {
  const [targetA, setTargetA] = useState('');
  const [targetB, setTargetB] = useState('');

  // Fetch targets if not provided via props
  const { data: fetchedTargets } = useTargets();
  const safeTargets = useMemo(() => {
    return Array.isArray(propTargets) ? propTargets : (fetchedTargets?.targets ?? []);
  }, [propTargets, fetchedTargets?.targets]);

  const selectedA = useMemo(() => safeTargets.find(t => t.name === targetA), [safeTargets, targetA]);
  const selectedB = useMemo(() => safeTargets.find(t => t.name === targetB), [safeTargets, targetB]);

  const severityTotals = useMemo(() => {
    const calc = (t: Target) => {
      return Object.values(t.severity_counts ?? {}).reduce((sum, v) => sum + (v || 0), 0);
    };
    return { a: selectedA ? calc(selectedA) : null, b: selectedB ? calc(selectedB) : null };
  }, [selectedA, selectedB]);

  const highestSeverity = useMemo(() => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const calc = (t: Target): string => {
      const counts = t.severity_counts ?? {};
      for (const sev of order) {
        if ((counts[sev] || 0) > 0) return sev;
      }
      return 'info';
    };
    return { a: selectedA ? calc(selectedA) : null, b: selectedB ? calc(selectedB) : null };
  }, [selectedA, selectedB]);

  if (safeTargets.length < 2) {
    return (
      <div className="card empty">
        <p>At least 2 targets are needed for comparison.</p>
      </div>
    );
  }

  return (
    <div className="target-comparison">
      <h2 className="target-comparison-title" data-focus-heading>🔀 Target Comparison</h2>

      <div className="target-comparison-selectors">
        <div className="form-group">
          <label htmlFor="target-comparison-a" className="form-label-accent">Target A</label>
          <select
            id="target-comparison-a"
            className="form-select target-comparison-select"
            value={targetA}
            onChange={e => setTargetA(e.target.value)}
          >
            <option value="">Select target...</option>
            {safeTargets.map(t => (
              <option key={t.name} value={t.name} disabled={t.name === targetB}>{t.name}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="target-comparison-b" className="form-label-accent">Target B</label>
          <select
            id="target-comparison-b"
            className="form-select target-comparison-select"
            value={targetB}
            onChange={e => setTargetB(e.target.value)}
          >
            <option value="">Select target...</option>
            {safeTargets.map(t => (
              <option key={t.name} value={t.name} disabled={t.name === targetA}>{t.name}</option>
            ))}
          </select>
        </div>
      </div>

      {selectedA && selectedB ? (
        <div className="target-comparison-grid">
          <div className="target-comparison-column">
            <h3 className="target-comparison-col-title">{selectedA.name}</h3>
            <div className="target-comparison-stats">
              <div className="tc-stat">
                <span className="tc-stat-label">Findings</span>
                <span className={`tc-stat-value ${severityTotals.a !== null && severityTotals.b !== null ? (severityTotals.a > severityTotals.b ? 'tc-worse' : severityTotals.a < severityTotals.b ? 'tc-better' : '') : ''}`}>
                  {selectedA.finding_count}
                </span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Highest Severity</span>
                <span className={`tc-stat-value severity-badge sev-${highestSeverity.a}`}>
                  {highestSeverity.a}
                </span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">URLs</span>
                <span className="tc-stat-value">{selectedA.url_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Parameters</span>
                <span className="tc-stat-value">{selectedA.parameter_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Attack Chains</span>
                <span className="tc-stat-value">{selectedA.attack_chain_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Scan Runs</span>
                <span className="tc-stat-value">{selectedA.run_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Last Scan</span>
                <span className="tc-stat-value">{selectedA.latest_run || '—'}</span>
              </div>
            </div>
            <div className="tc-severity-breakdown">
              <h4 className="tc-subtitle">Severity Breakdown</h4>
              {Object.entries(selectedA.severity_counts ?? {}).map(([sev, count]) => (
                <div key={sev} className="tc-sev-row">
                  <span className={`tc-sev-dot severity-dot severity-${sev}`}>{sev}</span>
                  <span className="tc-sev-count">{count}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="target-comparison-column">
            <h3 className="target-comparison-col-title">{selectedB.name}</h3>
            <div className="target-comparison-stats">
              <div className="tc-stat">
                <span className="tc-stat-label">Findings</span>
                <span className={`tc-stat-value ${severityTotals.a !== null && severityTotals.b !== null ? (severityTotals.b > severityTotals.a ? 'tc-worse' : severityTotals.b < severityTotals.a ? 'tc-better' : '') : ''}`}>
                  {selectedB.finding_count}
                </span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Highest Severity</span>
                <span className={`tc-stat-value severity-badge sev-${highestSeverity.b}`}>
                  {highestSeverity.b}
                </span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">URLs</span>
                <span className="tc-stat-value">{selectedB.url_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Parameters</span>
                <span className="tc-stat-value">{selectedB.parameter_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Attack Chains</span>
                <span className="tc-stat-value">{selectedB.attack_chain_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Scan Runs</span>
                <span className="tc-stat-value">{selectedB.run_count}</span>
              </div>
              <div className="tc-stat">
                <span className="tc-stat-label">Last Scan</span>
                <span className="tc-stat-value">{selectedB.latest_run || '—'}</span>
              </div>
            </div>
            <div className="tc-severity-breakdown">
              <h4 className="tc-subtitle">Severity Breakdown</h4>
              {Object.entries(selectedB.severity_counts ?? {}).map(([sev, count]) => (
                <div key={sev} className="tc-sev-row">
                  <span className={`tc-sev-dot severity-dot severity-${sev}`}>{sev}</span>
                  <span className="tc-sev-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="card empty">
          <p>Select two targets to compare their security posture side by side.</p>
        </div>
      )}
    </div>
  );
}
