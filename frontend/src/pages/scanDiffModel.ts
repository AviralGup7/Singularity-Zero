import type { Finding } from '@/types/api';

export interface DiffBucket {
  newFindings: Finding[];
  removedFindings: Finding[];
  changedFindings: { old: Finding; new: Finding }[];
}

export function keyForFinding(f: Finding): string {
  if (f.id) return `id:${f.id}`;
  return `anon:${f.type}::${f.target}::${f.severity}::${f.url ?? ''}::${f.title ?? ''}`;
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
  if (filter !== 'all') next.set('filter', filter); else next.delete('filter');
  if (runA) next.set('runA', runA); else next.delete('runA');
  if (runB) next.set('runB', runB); else next.delete('runB');
  return next.toString();
}
