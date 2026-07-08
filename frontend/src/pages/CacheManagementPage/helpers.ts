export function formatBytes(bytes?: number | null): string {
  const value = bytes ?? 0;
  if (value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatRatio(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return `${Math.round(value * 100)}%`;
}

export function ttlLabel(ttl?: number | null): string {
  if (ttl === null || ttl === undefined) return 'No expiry';
  if (ttl <= 0) return 'Expired';
  if (ttl < 60) return `${ttl}s`;
  if (ttl < 3600) return `${Math.round(ttl / 60)}m`;
  return `${(ttl / 3600).toFixed(1)}h`;
}

export function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, value));
}
