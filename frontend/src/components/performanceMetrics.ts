export interface MetricRecord {
  name: string;
  value: number;
  timestamp: string;
}

export const MAX_CLIENT_METRICS = 40;

export function appendClientMetrics(current: MetricRecord[], incoming: MetricRecord[], max = MAX_CLIENT_METRICS): MetricRecord[] {
  return [...current, ...incoming].slice(-max);
}

export function clampUnitInterval(value: number | undefined, fallback = 0): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  return Math.min(1, Math.max(0, n));
}
