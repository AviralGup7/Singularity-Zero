import { onCLS, onLCP, onFCP, onTTFB } from 'web-vitals';

interface Metric {
  name: 'CLS' | 'FID' | 'LCP' | 'FCP' | 'TTFB';
  value: number;
  delta: number;
  id: string;
}

interface WebVitalsState {
  CLS: number | null;
  FID: number | null;
  LCP: number | null;
  FCP: number | null;
  TTFB: number | null;
}

const STORAGE_KEY = 'cyber-pipeline-web-vitals';

function getThresholds(metric: string): { good: number; needsImprovement: number } {
  switch (metric) {
    case 'CLS':
      return { good: 0.1, needsImprovement: 0.25 };
    case 'FID':
      return { good: 100, needsImprovement: 300 };
    case 'LCP':
      return { good: 2500, needsImprovement: 4000 };
    case 'FCP':
      return { good: 1800, needsImprovement: 3000 };
    case 'TTFB':
      return { good: 800, needsImprovement: 1800 };
    default:
      return { good: 0, needsImprovement: 0 };
  }
}

function getRating(metric: string, value: number): 'good' | 'needs-improvement' | 'poor' {
  const thresholds = getThresholds(metric);
  if (value <= thresholds.good) return 'good';
  if (value <= thresholds.needsImprovement) return 'needs-improvement';
  return 'poor';
}

function storeMetric(metric: Metric): void {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const data: Record<string, unknown> = raw ? JSON.parse(raw) : {};
    data[metric.name] = {
      value: metric.value,
      rating: getRating(metric.name, metric.value),
      timestamp: new Date().toISOString(),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    /* ignore */
  }
}

export function getStoredWebVitals(): WebVitalsState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { CLS: null, FID: null, LCP: null, FCP: null, TTFB: null };
    const data = JSON.parse(raw);
    return {
      CLS: data.CLS?.value ?? null,
      FID: data.FID?.value ?? null,
      LCP: data.LCP?.value ?? null,
      FCP: data.FCP?.value ?? null,
      TTFB: data.TTFB?.value ?? null,
    };
  } catch {
    return { CLS: null, FID: null, LCP: null, FCP: null, TTFB: null };
  }
}

export function initWebVitals(): void {
  const reportMetric = (metric: Metric) => {
    console.info(`[WebVitals] ${metric.name}:`, {
      value: metric.value,
      rating: getRating(metric.name, metric.value),
      delta: metric.delta,
    });
    storeMetric(metric);
  };

  onCLS(reportMetric);
  onLCP(reportMetric);
  onFCP(reportMetric);
  onTTFB(reportMetric);
}
