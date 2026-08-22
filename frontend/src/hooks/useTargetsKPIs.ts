import { useMemo } from 'react';
import type { Target } from '@/types/api';

export function averageFindingCount(targets: Array<{ finding_count?: number }>): number {
  if (!targets.length) return 0;
  const total = targets.reduce((acc, target) => {
    const count = Number(target.finding_count);
    return acc + (Number.isFinite(count) ? Math.max(0, count) : 0);
  }, 0);
  return Math.round(total / targets.length);
}

export function useTargetsKPIs(data: { targets: Target[] } | undefined) {
  const targetsCount = data?.targets?.length ?? 0;
  const criticalFindings = useMemo(() => {
    return (data?.targets ?? []).reduce((acc, t) => {
      return acc + (Number(t.severity_counts?.critical) || 0);
    }, 0);
  }, [data?.targets]);
  const avgFindings = useMemo(() => {
    const targets = data?.targets ?? [];
    return averageFindingCount(targets);
  }, [data?.targets]);

  return { targetsCount, criticalFindings, avgFindings };
}
