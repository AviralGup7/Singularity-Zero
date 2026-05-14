import { useState, useEffect, useRef } from 'react';

interface MetricRecord {
  name: string;
  value: number;
  timestamp: string;
}

export function PerformanceDashboard() {
  const [metrics, setMetrics] = useState<MetricRecord[]>([]);
  const onReportRef = useRef<((m: MetricRecord) => void) | null>(null);
  onReportRef.current = (m: MetricRecord) => {
    setMetrics(prev => [...prev, m]);
  };

  useEffect(() => {
    const navEntries = performance.getEntriesByType('navigation');
    if (navEntries.length > 0) {
      const nav = navEntries[0] as PerformanceNavigationTiming;
      // FIX: Use correct metric values (not loadEventEnd for LCP)
      setMetrics([
        { name: 'TTFB', value: nav.responseStart, timestamp: new Date().toISOString() },
        { name: 'DCL', value: nav.domContentLoadedEventEnd, timestamp: new Date().toISOString() },
        { name: 'Load', value: nav.loadEventEnd, timestamp: new Date().toISOString() },
      ]);
    }

    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          // FIX: Use correct value per entry type
          let value: number;
          if (entry.entryType === 'layout-shift') {
            value = (entry as any).value;
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
      } catch { /* not supported */ }
      try {
        observer.observe({ type: 'layout-shift', buffered: true });
      } catch { /* not supported */ }
    } catch { /* not supported */ }
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
