import { useCallback, useRef } from 'react';
import type { CockpitNode, CockpitEdge } from '@/api/cockpit';

interface GraphUpdateOptions {
  signal?: AbortSignal;
}

export function useCockpitGraph(
  applyGraph: (data: { nodes: CockpitNode[]; edges: CockpitEdge[] }) => void,
  target: string,
  run: string | undefined,
  jobId: string | undefined,
  activeJobId: string | undefined
) {
  const graphRequestTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const graphRequestAbortControllerRef = useRef<AbortController | null>(null);

  const requestGraphUpdate = useCallback(
    (nextTarget: string, nextRun: string | undefined, nextJobId: string | undefined) => {
      graphRequestAbortControllerRef.current?.abort();
      const controller = new AbortController();
      graphRequestAbortControllerRef.current = controller;

      if (graphRequestTimerRef.current) clearTimeout(graphRequestTimerRef.current);
      const existing = document.getElementById('graph-request-timer');
      if (existing) existing.remove();

      import('@/api/cockpit')
        .then(({ cockpitApi }) =>
          cockpitApi.getGraph(nextTarget, nextRun, nextJobId, { signal: controller.signal })
        )
        .then((res) => applyGraph(res.data))
        .catch((err) => {
          if ((err as Error)?.name === 'AbortError') return;
          console.error('Failed to update graph on telemetry:', err);
        });
    },
    [applyGraph]
  );

  return {
    graphRequestTimerRef,
    graphRequestAbortControllerRef,
    requestGraphUpdate,
  };
}
