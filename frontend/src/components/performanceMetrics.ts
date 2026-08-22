export interface MetricRecord {
  name: string;
  value: number;
  timestamp: string;
}

export const MAX_CLIENT_METRICS = 40;

export function isRenderableMetric(metric: MetricRecord): boolean {
  return Boolean(metric.name) && Number.isFinite(metric.value);
}

export function appendClientMetrics(current: MetricRecord[], incoming: MetricRecord[], max = MAX_CLIENT_METRICS): MetricRecord[] {
  return [...current, ...incoming.filter(isRenderableMetric)].slice(-max);
}

export function formatDurationMs(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function clampUnitInterval(value: number | undefined, fallback = 0): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  if (n > 1 && n <= 100) return n / 100;
  return Math.min(1, Math.max(0, n));
}
