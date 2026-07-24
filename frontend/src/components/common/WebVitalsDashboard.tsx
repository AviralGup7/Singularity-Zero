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
        ? 'text-ok'
        : rating === 'needs-improvement'
          ? 'text-warn'
          : rating === 'poor'
            ? 'text-bad'
            : 'text-muted';

    const thresholds = getThresholds(name);

    return (
      <div className="vital-metric" role="group" aria-label={`${name}: ${value !== null ? `${value.toFixed(2)}${unit}` : 'N/A'}, rating: ${rating ?? 'unknown'}`}>
        <span className="vital-name">{name}</span>
        <span className={`vital-value ${color} tabular-nums`}>
          {value !== null ? `${value.toFixed(2)}${unit}` : 'N/A'}
        </span>
        {rating && (
          <span className={`vital-rating vital-${rating}`} aria-label={rating.replace('-', ' ')}>
            {rating}
          </span>
        )}
        {value !== null && (
          <span className="sr-only">
            Good threshold: {thresholds.good}{unit}, needs improvement above: {thresholds.needsImprovement}{unit}
          </span>
        )}
      </div>
    );
  };

  return (
    <div className="web-vitals-dashboard" role="region" aria-label="Web Vitals dashboard">
      <h4 className="vitals-title">Web Vitals</h4>
      <div className="vitals-grid" role="list">
        {renderMetric('CLS', vitals.CLS, '')}
        {renderMetric('LCP', vitals.LCP, 'ms')}
        {renderMetric('FCP', vitals.FCP, 'ms')}
        {renderMetric('TTFB', vitals.TTFB, 'ms')}
      </div>
    </div>
  );
}
