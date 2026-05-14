import { useState, useMemo, useCallback, memo } from 'react';
import { cn } from '@/lib/utils';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import type { Finding } from '@/types/api';

const CVSS_V3_LABELS: Record<string, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
};

const CVSS_V3_VALUES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { N: 'None', L: 'Low', H: 'High' },
  I: { N: 'None', L: 'Low', H: 'High' },
  A: { N: 'None', L: 'Low', H: 'High' },
};

const CVSS_V4_LABELS: Record<string, string> = {
  AV: 'Attack Vector',
  AC: 'Attack Complexity',
  AT: 'Attack Requirements',
  PR: 'Privileges Required',
  UI: 'User Interaction',
  VC: 'Vuln Confidentiality',
  VI: 'Vuln Integrity',
  VA: 'Vuln Availability',
  SC: 'Sub Confidentiality',
  SI: 'Sub Integrity',
  SA: 'Sub Availability',
};

const CVSS_V4_VALUES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  AT: { N: 'None', P: 'Present' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', P: 'Passive', A: 'Active' },
  VC: { H: 'High', L: 'Low', N: 'None' },
  VI: { H: 'High', L: 'Low', N: 'None' },
  VA: { H: 'High', L: 'Low', N: 'None' },
  SC: { H: 'High', L: 'Low', N: 'None' },
  SI: { H: 'High', L: 'Low', N: 'None' },
  SA: { H: 'High', L: 'Low', N: 'None' },
};

const ENV_VALUES = ['N', 'L', 'M', 'H'] as const;
const ENV_LABELS: Record<string, string> = {
  CR: 'Confidentiality Requirement',
  IR: 'Integrity Requirement',
  AR: 'Availability Requirement',
};
const ENV_VALUE_LABELS: Record<string, string> = {
  N: 'Low',
  L: 'Low',
  M: 'Medium',
  H: 'High',
};

function getSeverityColor(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function getSeverityLabel(score: number): string {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

function parseVectorV3(vector: string): Record<string, string> {
  const parts = vector.replace(/^CVSS:3\.1\//, '').split('/');
  const result: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value && /^[A-Z]+$/.test(key)) result[key] = value;
  }
  return result;
}

function parseVectorV4(vector: string): Record<string, string> {
  const parts = vector.replace(/^CVSS:4\.0\//, '').split('/');
  const result: Record<string, string> = {};
  for (const part of parts) {
    const [key, value] = part.split(':');
    if (key && value && /^[A-Z]+$/.test(key)) result[key] = value;
  }
  return result;
}

function calculateEnvironmentalScore(
  baseScore: number,
  metrics: Record<string, string>,
  envSettings: Record<string, string>
): number {
  const cr = envSettings.CR || 'H';
  const ir = envSettings.IR || 'H';
  const ar = envSettings.AR || 'H';
  const c = metrics.C || 'N';
  const i = metrics.I || 'N';
  const a = metrics.A || 'N';
  const s = metrics.S || 'U';

  const envWeight: Record<string, number> = { N: 0, L: 0.1, M: 0.5, H: 1 };
  const impactWeight: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

  const getWeight = (weightMap: Record<string, number>, key: string, fallback: number): number => {
    return Object.prototype.hasOwnProperty.call(weightMap, key) ? weightMap[key] : fallback;
  };

  const eImpact =
    1 -
    (1 - getWeight(impactWeight, c, 0) * getWeight(envWeight, cr, 1)) *
    (1 - getWeight(impactWeight, i, 0) * getWeight(envWeight, ir, 1)) *
    (1 - getWeight(impactWeight, a, 0) * getWeight(envWeight, ar, 1));

  const iss = 1 - (1 - getWeight(impactWeight, c, 0)) * (1 - getWeight(impactWeight, i, 0)) * (1 - getWeight(impactWeight, a, 0));
  const baseImpact = s === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  if (baseImpact <= 0) return 0;
  const envImpact = s === 'U' ? 6.42 * eImpact : 7.52 * (eImpact - 0.029) - 3.25 * Math.pow(eImpact - 0.02, 15);

  const ratio = envImpact / baseImpact;
  const envScore = Math.min(10, Math.round(baseScore * ratio * 10) / 10);
  return Math.max(0, envScore);
}

interface MetricBarProps {
  label: string;
  value: string;
  valueLabel: string;
  metricKey: string;
}

const MetricBar = memo(function MetricBar({ label, value, valueLabel }: MetricBarProps) {
  const levelMap: Record<string, number> = { N: 0, L: 1, M: 2, H: 3, None: 0, Low: 1, Medium: 2, High: 3 };
  const level = Object.prototype.hasOwnProperty.call(levelMap, value) ? levelMap[value] : 0;
  const barWidth = `${((level + 1) / 4) * 100}%`;
  const barColor =
    level >= 3 ? 'var(--severity-critical)' :
    level >= 2 ? 'var(--severity-high)' :
    level >= 1 ? 'var(--severity-medium)' : 'var(--severity-low)';

  return (
    <div className="cvss-metric-bar">
      <div className="cvss-metric-bar-header">
        <span className="cvss-metric-label">{label}</span>
        <span className="cvss-metric-value" title={metricKey}>{valueLabel}</span>
      </div>
      <div className="cvss-metric-bar-track">
        <div
          className="cvss-metric-bar-fill"
          style={{ width: barWidth, backgroundColor: barColor }}
        />
      </div>
    </div>
  );
});

interface ScoreRadarProps {
  scores: { label: string; score: number; max: number }[];
}

const ScoreRadar = memo(function ScoreRadar({ scores }: ScoreRadarProps) {
  return (
    <div className="cvss-radar">
      {scores.map(({ label, score, max }) => (
        <div key={label} className="cvss-radar-item">
          <div className="cvss-radar-label">{label}</div>
          <div className="cvss-radar-bar-track">
            <div
              className="cvss-radar-bar-fill"
              style={{
                width: `${(score / max) * 100}%`,
                backgroundColor:
                  score >= 9 ? 'var(--severity-critical)' :
                  score >= 7 ? 'var(--severity-high)' :
                  score >= 4 ? 'var(--severity-medium)' :
                  score > 0 ? 'var(--severity-low)' : 'var(--muted)',
              }}
            />
          </div>
          <div className="cvss-radar-value">{score.toFixed(1)}</div>
        </div>
      ))}
    </div>
  );
});

export interface CVSSDetailProps {
  finding: Finding;
  className?: string;
}

export function CVSSDetail({ finding, className }: CVSSDetailProps) {
  const [activeTab, setActiveTab] = useState<'v3' | 'v4' | 'environmental'>('v3');
  const [envSettings, setEnvSettings] = useState<Record<string, string>>({
    CR: 'H',
    IR: 'H',
    AR: 'H',
  });

  const v3Metrics = useMemo(() => {
    if (!finding.cvss_vector) return null;
    return parseVectorV3(finding.cvss_vector);
  }, [finding.cvss_vector]);

  const v4Metrics = useMemo(() => {
    if (!finding.cvss_v4_vector) return null;
    return parseVectorV4(finding.cvss_v4_vector);
  }, [finding.cvss_v4_vector]);

  const environmentalScore = useMemo(() => {
    if (!finding.cvss_score || !v3Metrics) return null;
    return calculateEnvironmentalScore(finding.cvss_score, v3Metrics, envSettings);
  }, [finding.cvss_score, v3Metrics, envSettings]);

  const handleEnvChange = useCallback((key: string, value: string) => {
    setEnvSettings(prev => ({ ...prev, [key]: value }));
  }, []);

  const hasV3 = finding.cvss_score !== undefined && finding.cvss_vector !== undefined;
  const hasV4 = finding.cvss_v4_score !== undefined && finding.cvss_v4_vector !== undefined;

  if (!hasV3 && !hasV4) {
    return (
      <div className={cn('cvss-detail', className)}>
        <div className="cvss-empty">
          <span className="cvss-empty-icon">⚠</span>
          <span>CVSS scores not available for this finding</span>
        </div>
      </div>
    );
  }

  const baseScore = finding.cvss_score ?? 0;
  const sevColor = getSeverityColor(baseScore);
  const sevLabel = getSeverityLabel(baseScore);

  return (
    <div className={cn('cvss-detail', className)}>
      <div className="cvss-header">
        <div className="cvss-score-display">
          <span className={cn('cvss-score-value', `sev-${sevColor}`)}>
            {baseScore.toFixed(1)}
          </span>
          <SeverityBadge severity={sevColor as 'critical' | 'high' | 'medium' | 'low' | 'info'} showIcon={false} />
          <span className="cvss-severity-label">{sevLabel}</span>
        </div>
        {finding.cvss_vector && (
          <div className="cvss-vector-string">
            <code>{finding.cvss_vector}</code>
          </div>
        )}
        {finding.cvss_explanation && (
          <p className="cvss-explanation">{finding.cvss_explanation}</p>
        )}
      </div>

      <div className="cvss-tabs">
        {hasV3 && (
          <button
            className={cn('cvss-tab', activeTab === 'v3' && 'active')}
            onClick={() => setActiveTab('v3')}
          >
            CVSS v3.1
          </button>
        )}
        {hasV4 && (
          <button
            className={cn('cvss-tab', activeTab === 'v4' && 'active')}
            onClick={() => setActiveTab('v4')}
          >
            CVSS v4.0
          </button>
        )}
        <button
          className={cn('cvss-tab', activeTab === 'environmental' && 'active')}
          onClick={() => setActiveTab('environmental')}
        >
          Environmental
        </button>
      </div>

      <div className="cvss-content">
        {activeTab === 'v3' && v3Metrics && (
          <div className="cvss-v3-panel">
            <div className="cvss-metrics-grid">
              {Object.entries(CVSS_V3_LABELS).map(([key, label]) => {
                const value = v3Metrics[key] || 'N';
                const valueLabel = CVSS_V3_VALUES[key]?.[value] || value;
                return (
                  <MetricBar
                    key={key}
                    label={label}
                    value={value}
                    valueLabel={valueLabel}
                    metricKey={key}
                  />
                );
              })}
            </div>
            <ScoreRadar
              scores={[
                { label: 'Base', score: finding.cvss_score ?? 0, max: 10 },
                ...(finding.cvss_v4_score ? [{ label: 'v4.0', score: finding.cvss_v4_score, max: 10 }] : []),
                ...(environmentalScore !== null ? [{ label: 'Environmental', score: environmentalScore, max: 10 }] : []),
              ]}
            />
          </div>
        )}

        {activeTab === 'v4' && v4Metrics && (
          <div className="cvss-v4-panel">
            <div className="cvss-score-display cvss-v4-score">
              <span className={cn('cvss-score-value', `sev-${getSeverityColor(finding.cvss_v4_score ?? 0)}`)}>
                {(finding.cvss_v4_score ?? 0).toFixed(1)}
              </span>
              <span className="cvss-version-tag">v4.0</span>
            </div>
            <div className="cvss-vector-string">
              <code>{finding.cvss_v4_vector}</code>
            </div>
            <div className="cvss-metrics-grid">
              {Object.entries(CVSS_V4_LABELS).map(([key, label]) => {
                const value = v4Metrics[key] || 'N';
                const valueLabel = CVSS_V4_VALUES[key]?.[value] || value;
                return (
                  <MetricBar
                    key={key}
                    label={label}
                    value={value}
                    valueLabel={valueLabel}
                    metricKey={key}
                  />
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'environmental' && v3Metrics && (
          <div className="cvss-env-panel">
            <div className="cvss-env-controls">
              <h4>Environmental Metrics</h4>
              <p className="cvss-env-desc">
                Adjust security requirements based on your environment to recalculate the score.
              </p>
              {ENV_LABELS && Object.entries({ CR: 'Confidentiality Requirement', IR: 'Integrity Requirement', AR: 'Availability Requirement' }).map(([key, label]) => (
                <div key={key} className="cvss-env-control">
                  <label>{label}</label>
                  <div className="cvss-env-options">
                    {ENV_VALUES.map(val => (
                      <button
                        key={val}
                        className={cn('cvss-env-btn', envSettings[key] === val && 'active')}
                        onClick={() => handleEnvChange(key, val)}
                      >
                        {ENV_VALUE_LABELS[val]}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            {environmentalScore !== null && (
              <div className="cvss-env-result">
                <div className="cvss-env-score">
                  <span className="cvss-env-score-value">{environmentalScore.toFixed(1)}</span>
                  <span className={cn('cvss-env-severity', `sev-${getSeverityColor(environmentalScore)}`)}>
                    {getSeverityLabel(environmentalScore)}
                  </span>
                </div>
                <ScoreRadar
                  scores={[
                    { label: 'Base', score: finding.cvss_score ?? 0, max: 10 },
                    { label: 'Environmental', score: environmentalScore, max: 10 },
                  ]}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
