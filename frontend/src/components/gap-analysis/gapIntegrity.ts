export function moduleIntegrity(total: number, withGaps: number): { ok: number; total: number } {
  const safeTotal = Math.max(0, total);
  const safeGaps = Math.min(Math.max(0, withGaps), safeTotal);
  return { ok: safeTotal - safeGaps, total: safeTotal };
}
