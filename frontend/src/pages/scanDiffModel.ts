import type { Finding } from '@/types/api';
import { normalizeScanDiffFilter } from './scanDiffFilters';

export interface DiffBucket {
  newFindings: Finding[];
  removedFindings: Finding[];
  changedFindings: { old: Finding; new: Finding }[];
}

export function keyForFinding(f: Finding): string {
  if (f.id) return `id:${f.id}`;
  return `anon:${f.type}::${f.target}::${f.severity}::${f.url ?? ''}::${f.title ?? ''}`;
}

export function bountyDelta(items: Finding[]): { min: number; max: number; count: number } {
  let min = 0;
  let max = 0;
  let count = 0;
  for (const finding of items) {
    if (typeof finding.bounty_value === 'number' && Number.isFinite(finding.bounty_value) && finding.bounty_value > 0) {
      min += finding.bounty_value * 0.5;
      max += finding.bounty_value;
      count++;
    }
  }
  return { min, max, count };
}

export function computeDiff(runA: Finding[], runB: Finding[]): DiffBucket {
  const mapA = new Map(runA.map((f) => [keyForFinding(f), f]));
  const mapB = new Map(runB.map((f) => [keyForFinding(f), f]));
  const newFindings: Finding[] = [];
  const removedFindings: Finding[] = [];
  const changedFindings: { old: Finding; new: Finding }[] = [];

  mapB.forEach((finding, key) => {
    const old = mapA.get(key);
    if (!old) {
      newFindings.push(finding);
    } else if (
      old.status !== finding.status ||
      old.description !== finding.description ||
      old.lifecycle_state !== finding.lifecycle_state ||
      (old.bounty_value ?? 0) !== (finding.bounty_value ?? 0)
    ) {
      changedFindings.push({ old, new: finding });
    }
  });
  mapA.forEach((finding, key) => {
    if (!mapB.has(key)) removedFindings.push(finding);
  });
  return { newFindings, removedFindings, changedFindings };
}

export function nextScanDiffSearch(
  current: URLSearchParams,
  filter: string,
  runA: string,
  runB: string,
): string {
  const next = new URLSearchParams(current);
  const safeFilter = normalizeScanDiffFilter(filter);
  if (safeFilter !== 'all') next.set('filter', safeFilter); else next.delete('filter');
  if (runA) next.set('runA', runA); else next.delete('runA');
  if (runB) next.set('runB', runB); else next.delete('runB');
  return next.toString();
}
