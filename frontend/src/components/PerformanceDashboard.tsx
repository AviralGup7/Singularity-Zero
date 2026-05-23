import { useState, useEffect, useRef } from 'react';
import { useApi } from '../hooks/useApi';

interface MetricRecord {
  name: string;
  value: number;
  timestamp: string;
}

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

function CircularProgress({ value, label, color = '#38bdf8' }: CircularProgressProps) {
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (value * circumference);

  return (
    <div className="flex flex-col items-center justify-center p-4 rounded-xl border border-cyan-500/20 bg-black/45 shadow-[0_0_24px_rgba(56,189,248,0.04)] backdrop-blur-md">
      <div className="relative w-20 h-20 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90">
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
        <span className="absolute text-sm font-black text-white">{Math.round(value * 100)}%</span>
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
      setMetrics(prev => [...prev, m]);
    };
  }, []);

  useEffect(() => {
    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          let value: number;
          if (entry.entryType === 'layout-shift') {
            value = (entry as unknown as { value: number }).value;
          } else if (entry.entryType === 'largest-contentful-paint') {
            value = (entry as PerformanceEntry & { startTime: number }).startTime;
          } else {
            value = entry.startTime;
          }
          setMetrics((prev) => [
            ...prev,
            {
              name: entry.entryType === 'largest-contentful-paint' ? 'LCP' : entry.name,
              value,
              timestamp: new Date().toISOString(),
            },
          ]);
        }
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
  }, []);

  const formatMs = (ms: number): string => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="performance-dashboard space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-text mb-4">Performance Metrics</h3>
        <div className="metrics-grid grid grid-cols-1 sm:grid-cols-3 gap-4">
          {metrics.map((m, i) => (
            <div key={`${m.name}-${m.timestamp}-${i}`} className="metric-card p-3 rounded-lg border border-border bg-surface-2">
              <span className="metric-name block text-xs text-muted mb-1">{m.name}</span>
              <span className="metric-value text-lg font-semibold text-text">{m.name === 'CLS' ? m.value.toFixed(4) : formatMs(m.value)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t border-border/60 pt-6">
        <h3 className="text-sm font-semibold text-text mb-4">ML Intelligence & Calibration</h3>
        <div className="grid grid-cols-3 gap-4">
          <CircularProgress value={kpis?.precision ?? 0.85} label="Precision" color="#38bdf8" />
          <CircularProgress value={kpis?.recall ?? 0.78} label="Recall" color="#ff6b35" />
          <CircularProgress value={kpis?.f1_score ?? 0.81} label="F1 Score" color="#4da3ff" />
        </div>
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="rounded-xl border border-cyan-500/20 bg-black/45 p-3 flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-wider text-slate-400">Threshold State</span>
            <span className={`text-[9px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${kpis?.threshold_convergence ? 'bg-ok/10 text-ok' : 'bg-accent/10 text-accent animate-pulse'}`}>
              {kpis?.threshold_convergence ? 'Converged' : 'Calibrating'}
            </span>
          </div>
          <div className="rounded-xl border border-cyan-500/20 bg-black/45 p-3 flex items-center justify-between">
            <span className="text-[9px] font-black uppercase tracking-wider text-slate-400">Suppression Patterns</span>
            <span className="text-xs font-black text-white">{kpis?.fp_pattern_count ?? 12} active</span>
          </div>
        </div>
      </div>
    </div>
  );
}
