import { useState, useEffect, useRef } from 'react';

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

export function PerformanceDashboard() {
  const [metrics, setMetrics] = useState<MetricRecord[]>(getNavMetrics);
  const onReportRef = useRef<((m: MetricRecord) => void) | null>(null);

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
      } catch (_e) { /* not supported */ }
      try {
        observer.observe({ type: 'layout-shift', buffered: true });
      } catch (_e) { /* not supported */ }
    } catch (_e) { /* not supported */ }
  }, []);

  const formatMs = (ms: number): string => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  return (
    <div className="performance-dashboard">
      <h3>Performance Metrics</h3>
      <div className="metrics-grid">
        {metrics.map((m, i) => (
          <div key={`${m.name}-${m.timestamp}-${i}`} className="metric-card">
            <span className="metric-name">{m.name}</span>
            <span className="metric-value">{formatMs(m.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
