import { useState, useEffect, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import { appendClientMetrics, clampUnitInterval, type MetricRecord } from './performanceMetrics';

function getNavMetrics(): MetricRecord[] {
  const navEntries = performance.getEntriesByType('navigation');
  if (navEntries.length === 0) return [];
   
  const nav = navEntries[0] as PerformanceNavigationTiming;
  return [
    { name: 'TTFB', value: nav.responseStart, timestamp: new Date().toISOString() },
    { name: 'DCL', value: nav.domContentLoadedEventEnd, timestamp: new Date().toISOString() },
    { name: 'Load', value: nav.loadEventEnd, timestamp: new Date().toISOString() },
  ];
}

interface CircularProgressProps {
  value: number;
  label: string;
  color?: string;
}

function CircularProgress({ value, label, color = 'var(--neon-cyan)' }: CircularProgressProps) {
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const safeValue = clampUnitInterval(value);
  const percentage = Math.round(safeValue * 100);
  const strokeDashoffset = circumference - (safeValue * circumference);

  return (
    <div className="flex flex-col items-center justify-center p-4 rounded-xl border border-accent/20 bg-surface/45 shadow-sm backdrop-blur-md" role="meter" aria-label={`${label}: ${percentage}%`} aria-valuenow={percentage} aria-valuemin={0} aria-valuemax={100}>
      <div className="relative w-20 h-20 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" aria-hidden="true">
          <circle
            cx="40"
            cy="40"
            r={radius}
            className="stroke-slate-800"
            strokeWidth="5"
            fill="transparent"
          />
          <circle
            cx="40"
            cy="40"
            r={radius}
            stroke={color}
            strokeWidth="5"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            style={{ filter: `drop-shadow(0 0 5px ${color}44)` }}
          />
        </svg>
        <span className="absolute text-sm font-black text-text-primary tabular-nums">{percentage}%</span>
      </div>
      <span className="mt-2 text-[9px] font-black uppercase tracking-[0.18em] text-slate-400 text-center">{label}</span>
    </div>
  );
}

interface LearningKpis {
  precision?: number;
  recall?: number;
  f1_score?: number;
  fp_pattern_count?: number;
  threshold_convergence?: boolean;
}

export function PerformanceDashboard() {
  const [metrics, setMetrics] = useState<MetricRecord[]>(getNavMetrics);
  const onReportRef = useRef<((m: MetricRecord) => void) | null>(null);

  const { data: kpis } = useApi<LearningKpis>('/api/learning/kpis', {
    refetchInterval: 12000
  });

  useEffect(() => {
    onReportRef.current = (m: MetricRecord) => {
      setMetrics((prev) => appendClientMetrics(prev, [m]));
    };
  }, []);

  useEffect(() => {
    let observer: PerformanceObserver | null = null;
    try {
      observer = new PerformanceObserver((list) => {
        const incoming = list.getEntries().map((entry) => {
          let value: number;
          if (entry.entryType === 'layout-shift') {
            value = (entry as unknown as { value: number }).value;
          } else if (entry.entryType === 'largest-contentful-paint') {
            value = (entry as PerformanceEntry & { startTime: number }).startTime;
          } else {
            value = entry.startTime;
          }
          return {
            name: entry.entryType === 'largest-contentful-paint' ? 'LCP' : entry.name,
            value,
            timestamp: new Date().toISOString(),
          };
        });
        setMetrics((prev) => appendClientMetrics(prev, incoming));
      });

      try {
        observer.observe({ type: 'largest-contentful-paint', buffered: true });
      } catch (e) {
        console.debug('LCP observation not supported:', e);
      }
      try {
        observer.observe({ type: 'layout-shift', buffered: true });
      } catch (e) {
        console.debug('CLS observation not supported:', e);
      }
    } catch (e) {
      console.debug('PerformanceObserver not supported:', e);
    }
    return () => {
      observer?.disconnect();
    };
  }, []);

  const formatMs = (ms: number): string => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="performance-dashboard space-y-6" role="region" aria-label="Performance dashboard">
      <div>
        <h3 className="text-sm font-semibold text-text mb-4">Performance Metrics</h3>
        <div className="metrics-grid grid grid-cols-1 sm:grid-cols-3 gap-4" role="list" aria-label="Navigation metrics">
          {metrics.map((m, i) => (
            <div key={`${m.name}-${m.timestamp}-${i}`} className="metric-card p-3 rounded-lg border border-border bg-surface-2" role="listitem" aria-label={`${m.name}: ${m.name === 'CLS' ? m.value.toFixed(4) : formatMs(m.value)}`}>
              <span className="metric-name block text-xs text-muted mb-1">{m.name}</span>
              <span className="metric-value text-lg font-semibold text-text tabular-nums">{m.name === 'CLS' ? m.value.toFixed(4) : formatMs(m.value)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t border-border/60 pt-6">
        <h3 className="text-sm font-semibold text-text mb-4">ML Intelligence & Calibration</h3>
        <div className="grid grid-cols-3 gap-4">
          <CircularProgress value={clampUnitInterval(kpis?.precision)} label="Precision" color="var(--neon-cyan)" />
          <CircularProgress value={clampUnitInterval(kpis?.recall)} label="Recall" color="var(--severity-high)" />
          <CircularProgress value={clampUnitInterval(kpis?.f1_score)} label="F1 Score" color="var(--severity-low)" />
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-surface-2 p-3 flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-wider text-slate-400">Threshold State</span>
            <span className={`text-[9px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${kpis?.threshold_convergence ? 'bg-ok/10 text-ok' : 'bg-accent/10 text-accent motion-safe:animate-pulse'}`} role="status" aria-live="polite">
              {kpis?.threshold_convergence ? 'Converged' : 'Calibrating'}
            </span>
          </div>
          <div className="rounded-xl border border-cyan-500/20 bg-surface-2 p-3 flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-wider text-slate-400">Suppression Patterns</span>
            <span className="text-xs font-black text-text-primary tabular-nums">{kpis?.fp_pattern_count ?? 0} active</span>
          </div>
        </div>
      </div>
    </div>
  );
}
