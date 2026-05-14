import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { scaleLinear } from 'd3-scale';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Activity, Crosshair, RefreshCw, ShieldAlert } from 'lucide-react';
import { buildRiskDateColumns, useRiskHistory, useTargets } from '@/hooks';
import type { RiskHistoryEntry } from '@/types/extended';

const TARGET_COLORS = ['#2FD8F8', '#FF9A3D', '#2ECC71', '#A55CFF', '#F2C94C', '#4FA3FF'];

function formatDateInput(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function daysBetween(startDate: string, endDate: string): number {
  const start = new Date(`${startDate}T00:00:00Z`).getTime();
  const end = new Date(`${endDate}T00:00:00Z`).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return 30;
  return Math.min(120, Math.max(1, Math.round((end - start) / 86400000) + 1));
}

function scoreLabel(score: number): string {
  if (score >= 8) return 'Critical';
  if (score >= 6.5) return 'High';
  if (score >= 4) return 'Medium';
  if (score >= 2) return 'Low';
  return 'Minimal';
}

export function RiskScorePage() {
  const today = useMemo(() => new Date(), []);
  const defaultStart = useMemo(() => {
    const start = new Date(today);
    start.setDate(start.getDate() - 29);
    return start;
  }, [today]);
  const [startDate, setStartDate] = useState(formatDateInput(defaultStart));
  const [endDate, setEndDate] = useState(formatDateInput(today));
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [selectedPoint, setSelectedPoint] = useState<RiskHistoryEntry | null>(null);

  const days = daysBetween(startDate, endDate);
  const { data: targetsData } = useTargets();
  const { history, factors, loading, error, refetch } = useRiskHistory({
    days,
    startDate,
    endDate,
    targetIds: selectedTargets,
  });

  const allTargets = useMemo(() => {
    const names = new Set<string>();
    for (const target of targetsData?.targets ?? []) names.add(target.name);
    for (const entry of history) names.add(entry.target_id);
    return Array.from(names).sort();
  }, [history, targetsData?.targets]);
  const visibleTargets = selectedTargets.length > 0 ? selectedTargets : allTargets;
  const columns = useMemo(() => {
    try {
      return buildRiskDateColumns(history);
    } catch {
      return [];
    }
  }, [history]);

  const heatColor = useMemo(
    () => scaleLinear<string>()
      .domain([0, 3, 6.5, 10])
      .range(['#0B1728', '#10b981', '#f59e0b', '#ff0055']) // Use theme-consistent hexes
      .clamp(true),
    [],
  );

  const heatmapByTargetDay = useMemo(() => {
    const map = new Map<string, RiskHistoryEntry>();
    for (const entry of history) {
      if (entry && entry.target_id && entry.timestamp) {
        map.set(`${entry.target_id}:${entry.timestamp.slice(0, 10)}`, entry);
      }
    }
    return map;
  }, [history]);

  const hottestPoint = useMemo(
    () => {
      if (!history.length) return null;
      return [...history].sort((a, b) => (b.csi_value || 0) - (a.csi_value || 0) || (b.timestamp || '').localeCompare(a.timestamp || ''))[0];
    },
    [history],
  );

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (!selectedPoint && hottestPoint) setSelectedPoint(hottestPoint);
    if (selectedPoint && !history.some((entry) => entry.target_id === selectedPoint.target_id && entry.timestamp === selectedPoint.timestamp)) {
      setSelectedPoint(hottestPoint);
    }
  }, [selectedPoint, history, hottestPoint]);

  const lineData = useMemo(() => columns.map((day) => {
    const row: Record<string, string | number> = { day: day.slice(5) };
    for (const target of visibleTargets) row[target] = heatmapByTargetDay.get(`${target}:${day}`)?.csi_value ?? 0;
    return row;
  }), [columns, heatmapByTargetDay, visibleTargets]);

  const factorData = useMemo(() => {
    const definitions = factors?.factors ?? [
      { key: 'cvss' as const, label: 'CVSS' },
      { key: 'confidence' as const, label: 'Confidence' },
      { key: 'exploitability' as const, label: 'Exploitability' },
      { key: 'mesh_consensus' as const, label: 'Mesh Consensus' },
    ];
    return definitions.map((definition) => ({
      label: definition.label,
      value: selectedPoint?.factors?.[definition.key] ?? 0,
      weight: Math.round((factors?.weights?.[definition.key] ?? 0) * 100),
    }));
  }, [factors, selectedPoint]);

  return (
    <div className="risk-score-page">
      <section className="page-header">
        <div>
          <h2>Risk Score</h2>
          <p className="page-subtitle">Composite Security Index history by target, day, and contributing factor.</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void refetch()}>
          <RefreshCw size={14} aria-hidden="true" />
          Refresh
        </button>
      </section>

      <section className="risk-filter-bar card" aria-label="Risk score filters">
        <label>
          <span>Start</span>
          <input className="form-input" type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} />
        </label>
        <label>
          <span>End</span>
          <input className="form-input" type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} />
        </label>
        <label className="risk-target-picker">
          <span>Targets</span>
          <select
            className="form-select"
            multiple
            value={selectedTargets}
            onChange={(event) => setSelectedTargets(Array.from(event.target.selectedOptions, option => option.value))}
          >
            {allTargets.map((target) => <option key={target} value={target}>{target}</option>)}
          </select>
        </label>
        <button type="button" className="btn btn-ghost" onClick={() => setSelectedTargets([])}>All targets</button>
      </section>

      {loading && <div className="card empty">Loading risk history...</div>}
      {error && <div className="card error">Unable to load risk history: {error.message}</div>}

      {!loading && !error && (
        <>
          <section className="risk-kpi-grid">
            <div className="card risk-kpi-card">
              <ShieldAlert size={22} aria-hidden="true" />
              <span>Peak CSI</span>
              <strong>{hottestPoint?.csi_value.toFixed(1) ?? '0.0'}</strong>
              <small>{hottestPoint ? `${hottestPoint.target} - ${scoreLabel(hottestPoint.csi_value)}` : 'No signal'}</small>
            </div>
            <div className="card risk-kpi-card">
              <Crosshair size={22} aria-hidden="true" />
              <span>Targets</span>
              <strong>{visibleTargets.length}</strong>
              <small>{columns.length} day columns in range</small>
            </div>
            <div className="card risk-kpi-card">
              <Activity size={22} aria-hidden="true" />
              <span>Events</span>
              <strong>{history.length}</strong>
              <small>Filesystem data with seeded fallback</small>
            </div>
          </section>

          <section className="card risk-heatmap-card">
            <div className="risk-section-head">
              <div>
                <h3>Target Heatmap</h3>
                <p>Rows are targets, columns are calendar days, and color follows CSI intensity.</p>
              </div>
              <div className="risk-legend" aria-label="CSI color legend">
                <span style={{ background: heatColor(2) }} /> Low
                <span style={{ background: heatColor(5) }} /> Medium
                <span style={{ background: heatColor(8.5) }} /> High
              </div>
            </div>
            <div className="risk-heatmap-scroll" data-testid="risk-heatmap">
              <div className="risk-heatmap-grid" style={{ gridTemplateColumns: `180px repeat(${Math.max(columns.length, 1)}, 34px)` }}>
                <div className="risk-heatmap-label">Target</div>
                {columns.map((day) => <div key={day} className="risk-heatmap-day">{day.slice(8)}</div>)}
                {visibleTargets.map((target) => (
                  <div key={target} className="risk-heatmap-row">
                    <div className="risk-heatmap-target" title={target}>{target}</div>
                    {columns.map((day) => {
                      const point = heatmapByTargetDay.get(`${target}:${day}`);
                      return (
                        <button
                          key={`${target}-${day}`}
                          type="button"
                          className={`risk-heat-cell ${selectedPoint === point ? 'risk-heat-cell--active' : ''}`}
                          style={{ backgroundColor: point ? heatColor(point.csi_value) : '#0B1728' }}
                          title={point ? `${target} ${day}: CSI ${point.csi_value}` : `${target} ${day}: no data`}
                          onClick={() => point && setSelectedPoint(point)}
                          aria-label={point ? `${target} ${day} CSI ${point.csi_value}` : `${target} ${day} no data`}
                        >
                          {point ? point.csi_value.toFixed(0) : ''}
                        </button>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="risk-analysis-grid">
            <div className="card risk-chart-card">
              <div className="risk-section-head"><h3>CSI Trend</h3></div>
              <ResponsiveContainer width="100%" height={320}>
                <LineChart data={lineData} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(143, 163, 184, 0.16)" />
                  <XAxis dataKey="day" stroke="#8FA3B8" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 10]} stroke="#8FA3B8" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: '#0B1728', border: '1px solid #2D5676', borderRadius: 8 }} />
                  <Legend />
                  {visibleTargets.slice(0, 6).map((target, index) => (
                    <Line key={target} type="monotone" dataKey={target} stroke={TARGET_COLORS[index % TARGET_COLORS.length]} strokeWidth={2} dot={false} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="card risk-chart-card">
              <div className="risk-section-head">
                <div>
                  <h3>Risk Factors</h3>
                  <p>{selectedPoint ? `${selectedPoint.target} on ${selectedPoint.timestamp.slice(0, 10)}` : 'Select a heatmap cell'}</p>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={320}>
                <BarChart data={factorData} layout="vertical" margin={{ top: 8, right: 16, left: 36, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(143, 163, 184, 0.16)" />
                  <XAxis type="number" domain={[0, 10]} stroke="#8FA3B8" tick={{ fontSize: 11 }} />
                  <YAxis type="category" dataKey="label" stroke="#8FA3B8" tick={{ fontSize: 11 }} width={112} />
                  <Tooltip contentStyle={{ background: '#0B1728', border: '1px solid #2D5676', borderRadius: 8 }} />
                  <Bar dataKey="value" fill="#2FD8F8" radius={[0, 8, 8, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <div className="risk-factor-weights">
                {factorData.map((factor) => <span key={factor.label}>{factor.label}: {factor.weight}%</span>)}
              </div>
            </div>
          </section>

          {selectedPoint && (
            <aside className="risk-detail-drawer" aria-label="Selected risk cell detail">
              <div>
                <h3>{selectedPoint.target}</h3>
                <p>{selectedPoint.timestamp.slice(0, 10)} - CSI {selectedPoint.csi_value.toFixed(1)} ({scoreLabel(selectedPoint.csi_value)})</p>
              </div>
              <div className="risk-severity-breakdown">
                {Object.entries(selectedPoint.severity_breakdown).map(([severity, count]) => (
                  <span key={severity} className={`status-pill status-${severity}`}>{severity}: {count}</span>
                ))}
              </div>
              <div className="risk-top-findings">
                {selectedPoint.top_findings.map((finding) => (
                  <Link key={finding.id} to={`/findings?finding=${encodeURIComponent(finding.id)}`}>
                    <strong>{finding.title}</strong>
                    <span>{finding.severity} - {finding.url}</span>
                  </Link>
                ))}
              </div>
            </aside>
          )}
        </>
      )}
    </div>
  );
}
