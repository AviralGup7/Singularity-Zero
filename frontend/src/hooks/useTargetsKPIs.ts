import { useMemo } from 'react';
import type { Target } from '@/types/api';

export function useTargetsKPIs(data: { targets: Target[] } | undefined) {
  const targetsCount = data?.targets?.length ?? 0;
  const criticalFindings = useMemo(() => {
    return (data?.targets ?? []).reduce((acc, t) => {
      return acc + (Number(t.severity_counts?.critical) || 0);
    }, 0);
  }, [data?.targets]);
  const avgFindings = useMemo(() => {
    const targets = data?.targets ?? [];
    if (!targets.length) return 0;
    const totalFindings = targets.reduce((acc, t) => acc + (t.finding_count ?? 0), 0);
    return Math.round(totalFindings / targets.length);
  }, [data?.targets]);

  return { targetsCount, criticalFindings, avgFindings };
}
