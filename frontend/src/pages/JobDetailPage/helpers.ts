import type { Job } from '@/types/api';

export const EASE_OUT = [0.16, 1, 0.3, 1] as const;

export const JOB_ID_RE = /^[a-zA-Z0-9_-]+$/;

export function safeHref(href: string | undefined | null): string | undefined {
  if (!href) return undefined;
  if (/^\s*javascript:/i.test(href)) return '#';
  return href;
}

export const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

export const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100, damping: 15 } },
};

export function computeStageDeltas(
  stageProgress: Job['stage_progress'],
  prevRef: React.MutableRefObject<Record<string, number>>,
): Array<{ stage: string; delta: number; status: string }> {
  if (!stageProgress) return [];
  const prev = prevRef.current;
  const next: Record<string, number> = {};
  const deltas: Array<{ stage: string; delta: number; status: string }> = [];
  for (const entry of stageProgress) {
    const stageKey = entry.stage || 'unknown';
    const progress = typeof entry.percent === 'number' ? entry.percent : 0;
    next[stageKey] = progress;
    const prevProgress = stageKey in prev ? prev[stageKey] : -1;
    if (prevProgress >= 0 && progress > prevProgress) {
      deltas.push({ stage: stageKey, delta: progress - prevProgress, status: entry.status || 'running' });
    } else if (!(stageKey in prev) && progress > 0) {
      deltas.push({ stage: stageKey, delta: progress, status: entry.status || 'running' });
    }
  }
  prevRef.current = next;
  return deltas;
}
