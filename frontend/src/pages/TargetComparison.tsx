import { useState, useMemo, useEffect } from 'react';
import type { Target } from '../types/api';
import { useTargets } from '../hooks';
import { compareTargets } from '@/api/client';

interface TargetComparisonProps {
  targets?: Target[];
}

export function TargetComparison({ targets: propTargets }: TargetComparisonProps) {
   
  const [targetA, setTargetA] = useState('');
  const [targetB, setTargetB] = useState('');
  const [comparisonData, setComparisonData] = useState<{ target_a: Target; target_b: Target } | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  // Fetch targets if not provided via props
  const { data: fetchedTargets } = useTargets();
  const safeTargets = useMemo(() => {
    return Array.isArray(propTargets) ? propTargets : (fetchedTargets?.targets ?? []);
  }, [propTargets, fetchedTargets?.targets]);

  useEffect(() => {
    if (!targetA || !targetB) {
      return;
    }

    const controller = new AbortController();

    compareTargets(targetA, targetB, controller.signal)
      .then((data) => {
        setComparisonData(data);
      })
      .catch((err: { message?: string; name?: string }) => {
        if (err.name !== 'AbortError') {
          setCompareError(err.message || 'Failed to fetch comparison data');
        }
      })
      .finally(() => {
        setCompareLoading(false);
      });

    return () => {
      controller.abort();
    };
  }, [targetA, targetB]);

  const selectedA = comparisonData?.target_a;
  const selectedB = comparisonData?.target_b;

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
        if (((Reflect.get(counts, sev) as number | undefined) || 0) > 0) return sev;
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
            onChange={e => {
              const val = e.target.value;
              setTargetA(val);
              if (val && targetB) {
                setCompareLoading(true);
                setCompareError(null);
              } else {
                setComparisonData(null);
                setCompareError(null);
                setCompareLoading(false);
              }
            }}
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
            onChange={e => {
              const val = e.target.value;
              setTargetB(val);
              if (targetA && val) {
                setCompareLoading(true);
                setCompareError(null);
              } else {
                setComparisonData(null);
                setCompareError(null);
                setCompareLoading(false);
              }
            }}
          >
            <option value="">Select target...</option>
            {safeTargets.map(t => (
              <option key={t.name} value={t.name} disabled={t.name === targetA}>{t.name}</option>
            ))}
          </select>
        </div>
      </div>

      {compareLoading && (
        <div className="card empty flex flex-col justify-center items-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[var(--accent)] mb-3" />
          <p className="text-sm text-[var(--muted)]">Comparing security postures...</p>
        </div>
      )}

      {compareError && (
        <div className="banner error py-4 my-2 text-center text-sm" role="status">
          <span>{compareError}</span>
        </div>
      )}

      {!compareLoading && !compareError && selectedA && selectedB ? (
        <div className="target-comparison-grid">
          <div className="target-comparison-column">
            <h3 className="target-comparison-col-title">{selectedA.name}</h3>
            <div className="target-comparison-stats">
              <div className="tc-stat">
                <span className="tc-stat-label">Risk Index (CSI)</span>
                <span className={`tc-stat-value ${selectedA.risk_score !== undefined && selectedB.risk_score !== undefined ? (selectedA.risk_score > selectedB.risk_score ? 'tc-worse' : selectedA.risk_score < selectedB.risk_score ? 'tc-better' : '') : ''}`}>
                  {selectedA.risk_score?.toFixed(1) ?? '—'}
                </span>
              </div>
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
                <span className="tc-stat-label">Risk Index (CSI)</span>
                <span className={`tc-stat-value ${selectedA.risk_score !== undefined && selectedB.risk_score !== undefined ? (selectedB.risk_score > selectedA.risk_score ? 'tc-worse' : selectedB.risk_score < selectedA.risk_score ? 'tc-better' : '') : ''}`}>
                  {selectedB.risk_score?.toFixed(1) ?? '—'}
                </span>
              </div>
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
      ) : null}

      {!compareLoading && !compareError && (!selectedA || !selectedB) ? (
        <div className="card empty">
          <p>Select two targets to compare their security posture side by side.</p>
        </div>
      ) : null}
    </div>
  );
}
