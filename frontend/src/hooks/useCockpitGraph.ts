import { useCallback, useRef } from 'react';
import type { CockpitNode, CockpitEdge } from '@/api/cockpit';

interface GraphUpdateOptions {
  signal?: AbortSignal;
  /**
   * Coalesce multiple `requestGraphUpdate` calls into one fetch within this
   * window. Defaults to 250ms, which is short enough to keep the cockpit
   * feeling live during a 12-hour scan but long enough to absorb the bursts
   * of `finding_batch` events the SSE Action Buffer produces.
   */
  debounceMs?: number;
}

export function useCockpitGraph(
  applyGraph: (data: { nodes: CockpitNode[]; edges: CockpitEdge[] }) => void,
  target: string,
  run: string | undefined,
  jobId: string | undefined,
  activeJobId: string | undefined,
  options: GraphUpdateOptions = {}
) {
  const debounceMs = options.debounceMs ?? 250;
  const graphRequestTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const graphRequestAbortControllerRef = useRef<AbortController | null>(null);
  const pendingArgsRef = useRef<{ target: string; run: string | undefined; jobId: string | undefined } | null>(null);
  const inFlightRef = useRef<boolean>(false);

  const performFetch = useCallback(
    (nextTarget: string, nextRun: string | undefined, nextJobId: string | undefined) => {
      graphRequestAbortControllerRef.current?.abort();
      const controller = new AbortController();
      graphRequestAbortControllerRef.current = controller;
      inFlightRef.current = true;

      import('@/api/cockpit')
        .then(({ cockpitApi }) =>
          cockpitApi.getGraph(nextTarget, nextRun, nextJobId, { signal: controller.signal })
        )
        .then((res) => applyGraph(res.data))
        .catch((err) => {
          if ((err as Error)?.name === 'AbortError') return;
          console.error('Failed to update graph on telemetry:', err);
        })
        .finally(() => {
          inFlightRef.current = false;
          // If a request came in while we were in flight, fire it now.
          const pending = pendingArgsRef.current;
          if (pending) {
            pendingArgsRef.current = null;
            performFetch(pending.target, pending.run, pending.jobId);
          }
        });
    },
    [applyGraph]
  );

  const requestGraphUpdate = useCallback(
    (nextTarget: string, nextRun: string | undefined, nextJobId: string | undefined) => {
      if (!nextTarget) return;
      pendingArgsRef.current = { target: nextTarget, run: nextRun, jobId: nextJobId };

      if (inFlightRef.current) return; // performFetch will pick up the pending args

      if (graphRequestTimerRef.current) clearTimeout(graphRequestTimerRef.current);
      graphRequestTimerRef.current = setTimeout(() => {
        graphRequestTimerRef.current = null;
        const args = pendingArgsRef.current;
        pendingArgsRef.current = null;
        if (args) performFetch(args.target, args.run, args.jobId);
      }, debounceMs);
    },
    [performFetch, debounceMs]
  );

  return {
    graphRequestTimerRef,
    graphRequestAbortControllerRef,
    requestGraphUpdate,
  };
}
