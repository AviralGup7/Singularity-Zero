import { getStoredWebVitals } from '@/utils/webVitals';

export function WebVitalsDashboard() {
  const vitals = getStoredWebVitals();

  const getThresholds = (metric: string): { good: number; needsImprovement: number } => {
    switch (metric) {
      case 'CLS': return { good: 0.1, needsImprovement: 0.25 };
      case 'FID': return { good: 100, needsImprovement: 300 };
      case 'LCP': return { good: 2500, needsImprovement: 4000 };
      case 'FCP': return { good: 1800, needsImprovement: 3000 };
      case 'TTFB': return { good: 800, needsImprovement: 1800 };
      default: return { good: 0, needsImprovement: 0 };
    }
  };

  const getRating = (metric: string, value: number): 'good' | 'needs-improvement' | 'poor' => {
    const thresholds = getThresholds(metric);
    if (value <= thresholds.good) return 'good';
    if (value <= thresholds.needsImprovement) return 'needs-improvement';
    return 'poor';
  };

  const renderMetric = (name: string, value: number | null, unit: string) => {
    const rating = value !== null ? getRating(name, value) : null;
    const color =
      rating === 'good'
        ? 'text-[var(--ok)]'
        : rating === 'needs-improvement'
          ? 'text-[var(--warn)]'
          : rating === 'poor'
            ? 'text-[var(--bad)]'
            : 'text-[var(--muted)]';

    return (
      <div className="vital-metric">
        <span className="vital-name">{name}</span>
        <span className={`vital-value ${color}`}>
          {value !== null ? `${value.toFixed(2)}${unit}` : 'N/A'}
        </span>
        {rating && <span className={`vital-rating vital-${rating}`}>{rating}</span>}
      </div>
    );
  };

  return (
    <div className="web-vitals-dashboard">
      <h4 className="vitals-title">Web Vitals</h4>
      <div className="vitals-grid">
        {renderMetric('CLS', vitals.CLS, '')}
        {renderMetric('LCP', vitals.LCP, 'ms')}
        {renderMetric('FCP', vitals.FCP, 'ms')}
        {renderMetric('TTFB', vitals.TTFB, 'ms')}
      </div>
    </div>
  );
}
