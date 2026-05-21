import { useEffect, useMemo, useState, Suspense } from 'react';
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
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Html, Line as DreiLine } from '@react-three/drei';
import { buildRiskDateColumns, useRiskHistory, useTargets } from '@/hooks';

import type { ComponentType } from 'react';

interface ThreeProps {
  [key: string]: unknown;
}

const ThreeMesh = 'mesh' as unknown as ComponentType<ThreeProps>;
const ThreeSphereGeometry = 'sphereGeometry' as unknown as ComponentType<ThreeProps>;
const ThreeMeshStandardMaterial = 'meshStandardMaterial' as unknown as ComponentType<ThreeProps>;
const ThreeAmbientLight = 'ambientLight' as unknown as ComponentType<ThreeProps>;
const ThreePointLight = 'pointLight' as unknown as ComponentType<ThreeProps>;
const ThreeGroup = 'group' as unknown as ComponentType<ThreeProps>;

interface NodeData {
  name: string;
  value: number;
  weight: number;
  position: [number, number, number];
  color: string;
}

function RiskGraphNode({ name, value, weight, position, color, isCenter }: NodeData & { isCenter?: boolean }) {
  const [hovered, setHovered] = useState(false);

  const baseRadius = isCenter ? 0.45 : 0.35;
  const scale = hovered ? 1.25 : 1.0;
  const radius = baseRadius * (0.6 + (value / 10) * 0.7) * scale;

  return (
    <ThreeGroup position={position}>
      <ThreeMesh
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
      >
        <ThreeSphereGeometry args={[radius, 32, 32]} />
        <ThreeMeshStandardMaterial
          color={hovered ? '#FF9A3D' : color}
          roughness={0.15}
          metalness={0.8}
          emissive={color}
          emissiveIntensity={hovered ? 0.7 : 0.3}
        />
      </ThreeMesh>
      <Html distanceFactor={6} position={[0, isCenter ? 0.8 : 0.6, 0]} center>
        <div className={`px-2 py-1 rounded border font-mono text-[9px] pointer-events-none select-none transition-all duration-200 whitespace-nowrap ${
          hovered 
            ? 'bg-[var(--accent)] text-[var(--bg)] border-[var(--accent)] scale-110 shadow-lg' 
            : 'bg-[#0B1728]/95 text-[var(--text)] border-[#2D5676] shadow-md'
        }`}>
          <div className="font-bold">{name}</div>
          <div>Score: {value.toFixed(1)}</div>
          {!isCenter && <div className="text-[7px] opacity-80">Weight: {weight}%</div>}
        </div>
      </Html>
    </ThreeGroup>
  );
}

function Risk3DGraph({ centerNode, factorNodes }: { centerNode: NodeData; factorNodes: NodeData[] }) {
  return (
    <div className="w-full h-[260px] bg-[#070e17] rounded border border-[#2D5676]/30 overflow-hidden relative">
      <Canvas camera={{ position: [0, 0, 4.5], fov: 60 }}>
        <ThreeAmbientLight intensity={0.5} />
        <ThreePointLight position={[10, 10, 10]} intensity={1.5} />
        <ThreePointLight position={[-10, -10, -10]} intensity={0.6} />
        
        <Suspense fallback={null}>
          <ThreeGroup>
            <RiskGraphNode {...centerNode} isCenter />

            {factorNodes.map((fn, idx) => (
              <RiskGraphNode key={idx} {...fn} />
            ))}

            {factorNodes.map((fn, idx) => (
              <DreiLine
                key={`line-${idx}`}
                points={[[0, 0, 0], fn.position]}
                color="#2FD8F8"
                lineWidth={1.5}
                opacity={0.4}
                transparent
              />
            ))}
          </ThreeGroup>
          <OrbitControls 
            enableZoom={true} 
            maxDistance={8} 
            minDistance={2} 
            autoRotate={true}
            autoRotateSpeed={0.8}
          />
        </Suspense>
      </Canvas>
      <div className="absolute bottom-2 left-2 text-[10px] font-mono text-[var(--muted)] pointer-events-none select-none bg-[#0B1728]/85 px-2 py-1 rounded border border-[#2D5676]/20">
        Drag to rotate • Scroll to zoom
      </div>
    </div>
  );
}
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
  const [viewMode3D, setViewMode3D] = useState(false);

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
    for (const target of visibleTargets) {
      Reflect.set(row, target, heatmapByTargetDay.get(`${target}:${day}`)?.csi_value ?? 0);
    }
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
                <div className="flex justify-between items-center w-full">
                  <div>
                    <h3>Risk Factors</h3>
                    <p>{selectedPoint ? `${selectedPoint.target} on ${selectedPoint.timestamp.slice(0, 10)}` : 'Select a heatmap cell'}</p>
                  </div>
                  <div className="flex items-center gap-1 bg-[var(--bg)] border border-[var(--line)] rounded p-0.5" style={{ height: 'fit-content' }}>
                    <button
                      type="button"
                      className={`px-2 py-0.5 rounded text-xs transition-colors ${!viewMode3D ? 'bg-[var(--accent)] text-[var(--bg)] font-semibold' : 'text-[var(--muted)] hover:text-[var(--text)]'}`}
                      onClick={() => setViewMode3D(false)}
                    >
                      2D
                    </button>
                    <button
                      type="button"
                      className={`px-2 py-0.5 rounded text-xs transition-colors ${viewMode3D ? 'bg-[var(--accent)] text-[var(--bg)] font-semibold' : 'text-[var(--muted)] hover:text-[var(--text)]'}`}
                      onClick={() => setViewMode3D(true)}
                    >
                      3D
                    </button>
                  </div>
                </div>
              </div>
              
              {viewMode3D && selectedPoint ? (
                <div className="p-4">
                  <Risk3DGraph 
                    centerNode={{
                      name: 'CSI Score',
                      value: selectedPoint.csi_value,
                      weight: 100,
                      position: [0, 0, 0],
                      color: heatColor(selectedPoint.csi_value),
                    }}
                    factorNodes={factorData.map((fd, idx) => {
                      const angle = (idx * 2 + 1) * (Math.PI / 4);
                      const R = 2.1;
                      const x = Math.cos(angle) * R;
                      const y = Math.sin(angle) * R;
                      return {
                        name: fd.label,
                        value: fd.value,
                        weight: fd.weight,
                        position: [x, y, 0],
                        color: '#2FD8F8',
                      };
                    })}
                  />
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={factorData} layout="vertical" margin={{ top: 8, right: 16, left: 36, bottom: 0 }}>
                    <CartesianGrid stroke="rgba(143, 163, 184, 0.16)" />
                    <XAxis type="number" domain={[0, 10]} stroke="#8FA3B8" tick={{ fontSize: 11 }} />
                    <YAxis type="category" dataKey="label" stroke="#8FA3B8" tick={{ fontSize: 11 }} width={112} />
                    <Tooltip contentStyle={{ background: '#0B1728', border: '1px solid #2D5676', borderRadius: 8 }} />
                    <Bar dataKey="value" fill="#2FD8F8" radius={[0, 8, 8, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
              
              <div className="risk-factor-details space-y-3 px-4 pb-4">
                {factors?.factors.map((f) => (
                  <div key={f.key} className="text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <strong className="text-accent">{f.label}</strong>
                      <span className="text-muted font-mono">{Math.round((factors?.weights?.[f.key] ?? 0) * 100)}% Weight</span>
                    </div>
                    <p className="text-muted/70 leading-relaxed italic">{f.description}</p>
                  </div>
                ))}
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
