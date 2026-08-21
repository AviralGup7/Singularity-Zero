export function normalizeConfidence(value: number | undefined | null): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value <= 1) return value;
  if (value <= 100) return value / 100;
  return 1;
}

export function confidencePercent(value: number | undefined | null): number {
  return Math.round(normalizeConfidence(value) * 100);
}

export function normalizeProgressPercent(value: number | undefined | null): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value <= 1) return value * 100;
  return Math.min(100, value);
}

export function compareSelectionKey(ids: Iterable<string>): string {
  return [...ids].sort().join('|');
}
